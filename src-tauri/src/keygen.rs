//! Key generation (both interop profiles), expiry re-signing, revocation
//! certificates, passphrase changes and expiry extension.
//!
//! Expiry in OpenPGP is not a field on the key: it is a `KeyExpirationTime`
//! subpacket inside self-signatures. rPGP's `SecretKeyParamsBuilder` does not
//! expose it, so we generate the key first and then re-sign the primary
//! self-certifications (v4) / direct key signature (v6) and every subkey
//! binding with the requested expiry added - mirroring exactly what rPGP's
//! own `KeyDetails::sign` does internally. Expiry is stored relative to each
//! component's creation time, keeping the effective expiry deterministic.

use pgp::composed::{
    ArmorOptions, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::{
    aead::AeadAlgorithm, ecc_curve::ECCCurve, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm,
};
use pgp::packet::{
    PacketTrait as _, RevocationCode, Signature, SignatureConfig, SignatureType, Subpacket,
    SubpacketData,
};
use pgp::types::{KeyDetails as _, KeyVersion, Password, Timestamp};
use rand::rngs::ThreadRng;

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// v4 packets, iterated-salted S2K, SEIPD v1 - reads everywhere.
    Compatible,
    /// v6 packets, Argon2 + AEAD, SEIPD v2 - experimental, modern libs only.
    Rfc9580,
}

impl Profile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Profile::Compatible => "compatible",
            Profile::Rfc9580 => "rfc9580",
        }
    }
    pub fn parse(s: &str) -> AppResult<Self> {
        match s {
            "compatible" | "" => Ok(Profile::Compatible),
            "rfc9580" => Ok(Profile::Rfc9580),
            other => Err(AppError::input(format!("unknown profile '{other}'"))),
        }
    }
    fn key_version(&self) -> KeyVersion {
        match self {
            Profile::Compatible => KeyVersion::V4,
            Profile::Rfc9580 => KeyVersion::V6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    Ecc,
    Rsa3072,
    Rsa4096,
}

impl Algo {
    pub fn parse(s: &str) -> AppResult<Self> {
        match s {
            "ecc" | "" => Ok(Algo::Ecc),
            "rsa3072" => Ok(Algo::Rsa3072),
            "rsa4096" => Ok(Algo::Rsa4096),
            other => Err(AppError::input(format!("unknown algorithm '{other}'"))),
        }
    }
}

pub struct GenerateOptions<'a> {
    pub name: String,
    pub email: String,
    pub comment: Option<String>,
    pub passphrase: Option<&'a str>,
    /// Unix seconds the key should expire at, or None for "never".
    pub expires_at: Option<u64>,
    pub algo: Algo,
    pub profile: Profile,
}

/// Generate a fully self-signed, passphrase-protected key with an expiry and
/// a revocation certificate. Returns (key, armored public, armored secret,
/// armored revocation certificate).
pub fn generate_key(
    opts: &GenerateOptions,
) -> AppResult<(SignedSecretKey, String, String, String)> {
    let mut rng = rand::thread_rng();
    let version = opts.profile.key_version();

    let uid = build_uid(&opts.name, &opts.email, opts.comment.as_deref())?;

    let (primary_type, subkey_type) = match (opts.algo, version) {
        (Algo::Ecc, KeyVersion::V4) => (
            KeyType::Ed25519Legacy,
            KeyType::ECDH(ECCCurve::Curve25519Legacy),
        ),
        (Algo::Ecc, KeyVersion::V6) => (KeyType::Ed25519, KeyType::X25519),
        (Algo::Rsa3072, _) => (KeyType::Rsa(3072), KeyType::Rsa(3072)),
        (Algo::Rsa4096, _) => (KeyType::Rsa(4096), KeyType::Rsa(4096)),
        _ => return Err(AppError::input("unsupported algorithm for this profile")),
    };

    let mut builder = SecretKeyParamsBuilder::default();
    builder
        .version(version)
        .key_type(primary_type)
        .can_sign(true)
        .can_certify(true)
        .primary_user_id(uid)
        .preferred_symmetric_algorithms(smallvec::smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec::smallvec![
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha256,
        ])
        // plan: no compression by default
        .preferred_compression_algorithms(smallvec::smallvec![]);

    match version {
        KeyVersion::V4 => {
            builder.feature_seipd_v1(true);
            builder.feature_seipd_v2(false);
        }
        KeyVersion::V6 => {
            // v6 keys can receive both container generations; advertise both.
            builder.feature_seipd_v1(true);
            builder.feature_seipd_v2(true);
            builder.preferred_aead_algorithms(smallvec::smallvec![
                (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb),
                (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Eax),
            ]);
        }
        _ => return Err(AppError::input("unsupported key version")),
    }

    // The passphrase must lock EVERY secret packet: primary AND subkeys
    // (rPGP's builder takes per-component passphrases; a missing one leaves
    // that component's secret material in the clear - plan §7 rule 5).
    if let Some(pw) = opts.passphrase {
        builder.passphrase(Some(pw.to_string()));
    }

    let mut subkey_params = SubkeyParamsBuilder::default();
    subkey_params
        .version(version)
        .key_type(subkey_type)
        .can_encrypt(EncryptionCaps::All);
    if let Some(pw) = opts.passphrase {
        subkey_params.passphrase(Some(pw.to_string()));
    }

    builder.subkeys(vec![subkey_params.build().map_err(|e| {
        AppError::input(format!("invalid subkey parameters: {e}"))
    })?]);

    let params = builder
        .build()
        .map_err(|e| AppError::input(format!("invalid key parameters: {e}")))?;

    let mut key: SignedSecretKey = params
        .generate(&mut rng)
        .map_err(|e| AppError::crypto(format!("key generation failed: {e}")))?;

    // --- expiry --------------------------------------------------------------
    let pw = opts
        .passphrase
        .map(|p| Password::from(p.to_string()))
        .unwrap_or_else(Password::empty);

    if let Some(exp) = opts.expires_at {
        let now = Timestamp::now().as_secs() as u64;
        if exp <= now {
            return Err(AppError::input("expiry date must be in the future"));
        }
        apply_expiry(&mut key, &pw, Some(exp), &mut rng)
            .map_err(|e| AppError::crypto(format!("could not sign key expiry: {e}")))?;
    }

    key.verify_bindings()
        .map_err(|e| AppError::crypto(format!("generated key failed self-verification: {e}")))?;

    // --- revocation certificate ---------------------------------------------
    let rev = create_revocation_certificate(&key, &pw)
        .map_err(|e| AppError::crypto(format!("revocation certificate failed: {e}")))?;

    let pub_armored = key
        .to_public_key()
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| AppError::crypto(format!("armoring public key failed: {e}")))?;
    let sec_armored = key
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| AppError::crypto(format!("armoring secret key failed: {e}")))?;

    Ok((key, pub_armored, sec_armored, rev))
}

pub fn build_uid(name: &str, email: &str, comment: Option<&str>) -> AppResult<String> {
    if name.trim().is_empty() {
        return Err(AppError::input("a name is required"));
    }
    let mut uid = name.trim().to_string();
    if let Some(c) = comment.map(str::trim).filter(|c| !c.is_empty()) {
        uid.push_str(" (");
        uid.push_str(c);
        uid.push(')');
    }
    if !email.trim().is_empty() {
        uid.push_str(" <");
        uid.push_str(email.trim());
        uid.push('>');
    }
    Ok(uid)
}

// ---------------------------------------------------------------------------
// Expiry re-signing
// ---------------------------------------------------------------------------

/// Re-sign the primary self-signatures and all subkey bindings so that every
/// component expires at `expires_at` (unix seconds, or None for "never").
/// Mirrors `composed::key::shared::KeyDetails::sign`. Expiry is stored as a
/// duration relative to each component's own creation time, which keeps the
/// result deterministic regardless of signing latency.
fn apply_expiry(
    key: &mut SignedSecretKey,
    key_pw: &Password,
    expires_at: Option<u64>,
    rng: &mut ThreadRng,
) -> pgp::errors::Result<()> {
    let primary_pub = key.primary_key.public_key().clone();
    let is_v4_or_less = key.primary_key.version() <= KeyVersion::V4;
    let primary_created = key.primary_key.created_at().as_secs() as u64;

    // ---- v4: re-certify each user id ---------------------------------------
    for user in std::mem::take(&mut key.details.users) {
        let Some(old) = user.signatures.iter().find(|s| {
            matches!(
                s.typ(),
                Some(
                    SignatureType::CertGeneric
                        | SignatureType::CertPersona
                        | SignatureType::CertCasual
                        | SignatureType::CertPositive
                )
            )
        }) else {
            // Keep un-self-signed users untouched.
            key.details.users.push(user);
            continue;
        };

        let mut config =
            SignatureConfig::from_key(&mut *rng, &key.primary_key, SignatureType::CertPositive)?;
        config.hashed_subpackets = refresh_expiry_subpackets(old, primary_created, expires_at);
        if is_v4_or_less {
            config.unhashed_subpackets = issuer_subpackets(&key.primary_key);
        }

        let sig = config.sign_certification(
            &key.primary_key,
            &primary_pub,
            key_pw,
            user.id.tag(),
            &user.id,
        )?;

        let mut signed_user = user;
        signed_user.signatures = vec![sig];
        key.details.users.push(signed_user);
    }

    // ---- v6: re-sign the direct key signature ------------------------------
    if key.primary_key.version() == KeyVersion::V6 {
        let direct = std::mem::take(&mut key.details.direct_signatures);
        key.details.direct_signatures = direct
            .into_iter()
            .map(|old| {
                let mut config =
                    SignatureConfig::from_key(&mut *rng, &key.primary_key, SignatureType::Key)?;
                config.hashed_subpackets =
                    refresh_expiry_subpackets(&old, primary_created, expires_at);
                config.sign_key(&key.primary_key, key_pw, &primary_pub)
            })
            .collect::<pgp::errors::Result<Vec<_>>>()?;
    }

    // ---- subkeys: re-bind with expiry ---------------------------------------
    let secret_subkeys = std::mem::take(&mut key.secret_subkeys);
    key.secret_subkeys = secret_subkeys
        .into_iter()
        .map(|mut sub| {
            let sub_created = sub.key.created_at().as_secs() as u64;
            resign_subkey(
                &mut sub,
                key,
                key_pw,
                sub_created,
                expires_at,
                rng,
                &primary_pub,
            )
            .map(|_| sub)
        })
        .collect::<pgp::errors::Result<Vec<_>>>()?;

    let public_subkeys = std::mem::take(&mut key.public_subkeys);
    key.public_subkeys = public_subkeys
        .into_iter()
        .map(|mut sub| {
            let sub_created = sub.key.created_at().as_secs() as u64;
            resign_subkey(
                &mut sub,
                key,
                key_pw,
                sub_created,
                expires_at,
                rng,
                &primary_pub,
            )
            .map(|_| sub)
        })
        .collect::<pgp::errors::Result<Vec<_>>>()?;

    Ok(())
}

/// Local helper trait so `resign_subkey` can work on secret and public subkey
/// containers uniformly. Crucially it exposes the PUBLIC packet form: rPGP
/// computes subkey binding hashes over the public subkey packet only (the
/// secret material is not hashed), so re-signing must use the same form.
trait SubkeyLike {
    fn public_packet(&self) -> &pgp::packet::PublicSubkey;
    fn signatures(&self) -> &Vec<Signature>;
    fn signatures_mut(&mut self) -> &mut Vec<Signature>;
}

impl SubkeyLike for pgp::composed::SignedSecretSubKey {
    fn public_packet(&self) -> &pgp::packet::PublicSubkey {
        self.key.public_key()
    }
    fn signatures(&self) -> &Vec<Signature> {
        &self.signatures
    }
    fn signatures_mut(&mut self) -> &mut Vec<Signature> {
        &mut self.signatures
    }
}

impl SubkeyLike for pgp::composed::SignedPublicSubKey {
    fn public_packet(&self) -> &pgp::packet::PublicSubkey {
        &self.key
    }
    fn signatures(&self) -> &Vec<Signature> {
        &self.signatures
    }
    fn signatures_mut(&mut self) -> &mut Vec<Signature> {
        &mut self.signatures
    }
}

#[allow(clippy::too_many_arguments)]
fn resign_subkey<C: SubkeyLike>(
    sub: &mut C,
    key: &SignedSecretKey,
    key_pw: &Password,
    subkey_created: u64,
    expires_at: Option<u64>,
    rng: &mut ThreadRng,
    primary_pub: &pgp::packet::PublicKey,
) -> pgp::errors::Result<()> {
    // Phase 1: read the old binding signature (immutable borrow ends here).
    let hashed = match sub.signatures().first() {
        Some(old) => refresh_expiry_subpackets(old, subkey_created, expires_at),
        None => return Ok(()),
    };

    // Phase 2: produce the fresh binding (borrows sub immutably).
    let mut config =
        SignatureConfig::from_key(&mut *rng, &key.primary_key, SignatureType::SubkeyBinding)?;
    config.hashed_subpackets = hashed;
    if key.primary_key.version() <= KeyVersion::V4 {
        config.unhashed_subpackets = issuer_subpackets(&key.primary_key);
    }
    let sig =
        config.sign_subkey_binding(&key.primary_key, primary_pub, key_pw, sub.public_packet())?;

    // Phase 3: swap it in (mutable borrow).
    *sub.signatures_mut() = vec![sig];
    Ok(())
}

/// Copy a signature's hashed subpackets, refresh the creation time, and set
/// the requested expiration (or drop it entirely for `None`). The expiration
/// is stored relative to `created` (the component's own creation time), so
/// the resulting effective expiry is exactly `expires_at`.
fn refresh_expiry_subpackets(
    old: &Signature,
    created: u64,
    expires_at: Option<u64>,
) -> Vec<Subpacket> {
    let mut out: Vec<Subpacket> = old
        .config()
        .map(|c| c.hashed_subpackets().cloned().collect())
        .unwrap_or_default();

    out.retain(|p| {
        !matches!(p.data, SubpacketData::SignatureCreationTime(_))
            && !matches!(p.data, SubpacketData::KeyExpirationTime(_))
    });

    out.push(
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
            .expect("valid subpacket"),
    );
    if let Some(exp) = expires_at {
        // OpenPGP stores expiry as a u32-seconds value relative to creation.
        let secs = exp.saturating_sub(created).min(u32::MAX as u64) as u32;
        out.push(
            Subpacket::regular(SubpacketData::KeyExpirationTime(
                pgp::types::Duration::from_secs(secs),
            ))
            .expect("valid subpacket"),
        );
    }
    out
}

fn issuer_subpackets(primary: &pgp::packet::SecretKey) -> Vec<Subpacket> {
    vec![
        Subpacket::regular(SubpacketData::IssuerKeyId(primary.legacy_key_id()))
            .expect("valid subpacket"),
    ]
}

fn is_cert_sig(s: &pgp::packet::Signature) -> bool {
    matches!(
        s.typ(),
        Some(
            SignatureType::CertGeneric
                | SignatureType::CertPersona
                | SignatureType::CertCasual
                | SignatureType::CertPositive
        )
    )
}

// ---------------------------------------------------------------------------
// Rename (new primary User ID)
// ---------------------------------------------------------------------------

/// Rename a key: add a freshly self-signed User ID marked as primary and
/// demote the previous one - the OpenPGP-native way names work, matching
/// `gpg --quick-add-uid`. The fingerprint and secret material are untouched;
/// peers only see the new name once you share the updated public key.
///
/// The new UID's self-certification carries over the key's existing metadata
/// (key flags, features, algorithm preferences) so it advertises exactly the
/// same properties as the key itself.
pub fn rename_key(key: &mut SignedSecretKey, key_pw: &Password, uid: String) -> AppResult<()> {
    let mut rng = rand::thread_rng();
    let primary_pub = key.primary_key.public_key().clone();
    let is_v4_or_less = key.primary_key.version() <= KeyVersion::V4;

    let metadata: Vec<Subpacket> = key
        .details
        .users
        .iter()
        .flat_map(|u| u.signatures.iter())
        .find(|s| is_cert_sig(s))
        .and_then(|s| s.config())
        .map(|c| c.hashed_subpackets().cloned().collect())
        .unwrap_or_default();
    if metadata.is_empty() {
        return Err(AppError::crypto(
            "the key has no self-signature to carry preferences from",
        ));
    }

    // Certify a UID packet with the key's metadata, optionally as primary.
    // (Closures capture disjoint fields, so this borrows the key immutably
    // while the user list is rebuilt below.)
    let mut certify = |uid_pkt: &pgp::packet::UserId,
                       with_primary: bool|
     -> pgp::errors::Result<pgp::packet::Signature> {
        let mut config =
            SignatureConfig::from_key(&mut rng, &key.primary_key, SignatureType::CertPositive)?;
        let mut hashed: Vec<Subpacket> = metadata
            .iter()
            .filter(|p| {
                !matches!(p.data, SubpacketData::IsPrimary(_))
                    && !matches!(p.data, SubpacketData::SignatureCreationTime(_))
            })
            .cloned()
            .collect();
        hashed.push(Subpacket::regular(SubpacketData::SignatureCreationTime(
            Timestamp::now(),
        ))?);
        if with_primary {
            hashed.push(Subpacket::regular(SubpacketData::IsPrimary(true))?);
        }
        config.hashed_subpackets = hashed;
        if is_v4_or_less {
            config.unhashed_subpackets = issuer_subpackets(&key.primary_key);
        }
        config.sign_certification(
            &key.primary_key,
            &primary_pub,
            key_pw,
            uid_pkt.tag(),
            uid_pkt,
        )
    };

    let new_uid_pkt = pgp::packet::UserId::from_str(Default::default(), uid)
        .map_err(|e| AppError::crypto(format!("could not build the new user id: {e}")))?;

    let old_users = std::mem::take(&mut key.details.users);
    let mut users = Vec::with_capacity(old_users.len() + 1);

    // The new primary UID goes first (it is what every listing displays).
    let new_sig = certify(&new_uid_pkt, true)
        .map_err(|e| AppError::crypto(format!("signing the new name failed: {e}")))?;
    users.push(new_uid_pkt.into_signed(new_sig));

    // Existing UIDs are re-signed without the primary flag; UIDs without a
    // self-certification are kept untouched.
    for user in old_users {
        let has_self_sig = user.signatures.iter().any(|s| is_cert_sig(s));
        if !has_self_sig {
            users.push(user);
            continue;
        }
        let uid_pkt = user.id;
        let sig = certify(&uid_pkt, false)
            .map_err(|e| AppError::crypto(format!("re-signing the previous name failed: {e}")))?;
        users.push(uid_pkt.into_signed(sig));
    }
    key.details.users = users;

    key.verify_bindings()
        .map_err(|e| AppError::crypto(format!("renamed key failed self-verification: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Revocation certificate
// ---------------------------------------------------------------------------

/// Create an armored revocation certificate for the primary key. The output
/// is a "PGP PUBLIC KEY BLOCK" containing a single key-revocation signature,
/// shaped like GnuPG's own revocation exports.
pub fn create_revocation_certificate(
    key: &SignedSecretKey,
    key_pw: &Password,
) -> pgp::errors::Result<String> {
    create_revocation_inner(
        key,
        key_pw,
        RevocationCode::NoReason,
        None,
        &mut rand::thread_rng(),
    )
}

/// Extended variant used by the on-demand command (reason + text).
pub fn create_revocation_certificate_reasoned(
    key: &SignedSecretKey,
    key_pw: &Password,
    code: RevocationCode,
    text: Option<String>,
) -> pgp::errors::Result<String> {
    create_revocation_inner(key, key_pw, code, text, &mut rand::thread_rng())
}

fn create_revocation_inner(
    key: &SignedSecretKey,
    key_pw: &Password,
    code: RevocationCode,
    text: Option<String>,
    rng: &mut ThreadRng,
) -> pgp::errors::Result<String> {
    use pgp::armor::{write as armor_write, BlockType};
    use pgp::composed::DetachedSignature;

    let mut config =
        SignatureConfig::from_key(&mut *rng, &key.primary_key, SignatureType::KeyRevocation)?;
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            key.primary_key.fingerprint(),
        ))?,
        Subpacket::regular(SubpacketData::RevocationReason(
            code,
            text.unwrap_or_default().into_bytes().into(),
        ))?,
    ];

    if key.primary_key.version() <= KeyVersion::V4 {
        config.unhashed_subpackets = issuer_subpackets(&key.primary_key);
    }

    let sig = config.sign_key(&key.primary_key, key_pw, key.primary_key.public_key())?;

    let mut headers = pgp::armor::Headers::new();
    headers.insert(
        "Comment".into(),
        vec!["PocketPGP revocation certificate".into()],
    );

    // Serialize through DetachedSignature: its Serialize impl writes the
    // signature packet WITH its packet header. Serializing the bare
    // `Signature` would emit only the body, which GnuPG cannot parse.
    let ds = DetachedSignature::new(sig);

    let mut buf = Vec::new();
    armor_write(&ds, BlockType::PublicKey, &mut buf, Some(&headers), true)?;

    String::from_utf8(buf).map_err(|e| pgp::errors::Error::Utf8Error {
        source: e.utf8_error(),
        backtrace: None,
    })
}

// ---------------------------------------------------------------------------
// Passphrase change & expiry extension
// ---------------------------------------------------------------------------

/// Re-lock every secret packet of the key with `new_passphrase`
/// (after verifying `old_passphrase`). The plaintext secret never touches
/// disk: this works on the in-memory parsed key, and only the re-locked
/// armored form is written back by the caller.
pub fn change_passphrase(
    key: &mut SignedSecretKey,
    old_passphrase: Option<&str>,
    new_passphrase: Option<&str>,
) -> AppResult<()> {
    let old = old_passphrase
        .map(|p| Password::from(p.to_string()))
        .unwrap_or_else(Password::empty);
    let new = new_passphrase
        .map(|p| Password::from(p.to_string()))
        .unwrap_or_else(Password::empty);

    let version = key.primary_key.version();
    let s2k = pgp::types::S2kParams::new_default(&mut rand::thread_rng(), version);

    key.primary_key
        .remove_password(&old)
        .map_err(|_| AppError::crypto("current passphrase is wrong"))?;
    key.primary_key
        .set_password_with_s2k(&new, s2k.clone())
        .map_err(|e| AppError::crypto(format!("re-locking primary key failed: {e}")))?;

    for sub in &mut key.secret_subkeys {
        sub.key
            .remove_password(&old)
            .map_err(|_| AppError::crypto("current passphrase is wrong"))?;
        sub.key
            .set_password_with_s2k(&new, s2k.clone())
            .map_err(|e| AppError::crypto(format!("re-locking subkey failed: {e}")))?;
    }

    Ok(())
}

/// Extend (or remove) expiry for the primary key and all subkeys.
pub fn extend_expiry(
    key: &mut SignedSecretKey,
    key_pw: &Password,
    expires_at: Option<u64>,
) -> AppResult<()> {
    let mut rng = rand::thread_rng();
    apply_expiry(key, key_pw, expires_at, &mut rng)
        .map_err(|e| AppError::crypto(format!("re-signing expiry failed: {e}")))?;

    key.verify_bindings()
        .map_err(|e| AppError::crypto(format!("re-signed key failed verification: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::composed::{
        CleartextSignedMessage, Deserializable, DetachedSignature, Message, MessageBuilder,
    };
    use pgp::crypto::sym::SymmetricKeyAlgorithm;

    fn opts<'a>(
        profile: Profile,
        expires_at: Option<u64>,
        passphrase: Option<&'a str>,
    ) -> GenerateOptions<'a> {
        GenerateOptions {
            name: "Pocket Tester".into(),
            email: "pocket@example.com".into(),
            comment: Some("test key".into()),
            passphrase,
            expires_at,
            algo: Algo::Ecc,
            profile,
        }
    }

    #[test]
    fn v4_generate_expiry_roundtrip() {
        let exp = crate::pgputil::now_secs() + 86400;
        let (key, pub_armored, sec_armored, rev) =
            generate_key(&opts(Profile::Compatible, Some(exp), Some("correct horse"))).unwrap();

        // The generated key must pass its own binding checks.
        key.verify_bindings().unwrap();

        // Armor round trips.
        let (sec, _) = SignedSecretKey::from_string(&sec_armored).unwrap();
        sec.verify_bindings().unwrap();

        // EVERY secret packet must be passphrase-encrypted at rest
        // (plan §7 rule 5) - primary AND subkeys.
        use pgp::types::SecretParams;
        assert!(
            matches!(sec.primary_key.secret_params(), SecretParams::Encrypted(_)),
            "primary secret must be encrypted at rest"
        );
        for sub in &sec.secret_subkeys {
            assert!(
                matches!(sub.key.secret_params(), SecretParams::Encrypted(_)),
                "subkey secret must be encrypted at rest"
            );
        }

        let (pubkey, _) = pgp::composed::SignedPublicKey::from_string(&pub_armored).unwrap();
        pubkey.verify_bindings().unwrap();
        assert_eq!(
            key.primary_key.fingerprint(),
            pubkey.primary_key.fingerprint()
        );

        // Expiry made it into the self-signature - exactly the requested date.
        let parsed_exp = crate::pgputil::primary_expiry(&pubkey).unwrap();
        assert_eq!(parsed_exp, exp);

        // Subkey expiry matches too.
        let binding = pubkey.public_subkeys[0].signatures[0].clone();
        let sub_created = pubkey.public_subkeys[0].key.created_at().as_secs() as u64;
        assert!(crate::pgputil::subkey_expiry(&binding, sub_created).is_some());

        // Revocation certificate is a well-formed armored block.
        assert!(rev.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(rev.contains("-----END PGP PUBLIC KEY BLOCK-----"));

        // The armored secret key must not contain plaintext secret material
        // (it is passphrase-encrypted at rest; here: not the literal MPI
        // bytes of the known secret scalar).
        assert!(!sec_armored.contains("Secret Key"));
    }

    #[test]
    fn v6_generate_roundtrip() {
        let (key, pub_armored, _, _) =
            generate_key(&opts(Profile::Rfc9580, None, Some("pw"))).unwrap();
        assert_eq!(key.primary_key.version(), KeyVersion::V6);
        key.verify_bindings().unwrap();

        let (pubkey, _) = pgp::composed::SignedPublicKey::from_string(&pub_armored).unwrap();
        pubkey.verify_bindings().unwrap();
        assert_eq!(pubkey.primary_key.version(), KeyVersion::V6);
    }

    #[test]
    fn rsa4096_generate_roundtrip() {
        let mut o = opts(Profile::Compatible, None, Some("pw"));
        o.algo = Algo::Rsa4096;
        let (key, pub_armored, _, _) = generate_key(&o).unwrap();
        key.verify_bindings().unwrap();
        let (pubkey, _) = pgp::composed::SignedPublicKey::from_string(&pub_armored).unwrap();
        assert!(pubkey.primary_key.algorithm() == pgp::crypto::public_key::PublicKeyAlgorithm::RSA);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_v4() {
        let (_, pub_armored, sec_armored, _) =
            generate_key(&opts(Profile::Compatible, None, Some("pw"))).unwrap();
        let (pubkey, _) = pgp::composed::SignedPublicKey::from_string(&pub_armored).unwrap();
        let (sec, _) = SignedSecretKey::from_string(&sec_armored).unwrap();

        let mut rng = rand::thread_rng();
        let mut b = MessageBuilder::from_bytes("t.txt", b"hello roundtrip".to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        b.encrypt_to_key(&mut rng, &pubkey.public_subkeys[0])
            .unwrap();
        let armored = b
            .to_armored_string(&mut rng, ArmorOptions::default())
            .unwrap();

        let (msg, _) = Message::from_string(&armored).unwrap();
        let pw = Password::from("pw".to_string());
        let mut dec = msg.decrypt(&pw, &sec).unwrap();
        let text = dec.as_data_string().unwrap();
        assert_eq!(text, "hello roundtrip");
    }

    #[test]
    fn sign_cleartext_and_verify_roundtrip() {
        let (_, _, sec_armored, _) =
            generate_key(&opts(Profile::Compatible, None, Some("pw"))).unwrap();
        let (sec, _) = SignedSecretKey::from_string(&sec_armored).unwrap();

        let text = "line one\nline two\n- dash escaped\n";
        let signed = crate::msgops::sign_cleartext(&sec, Some("pw"), text).unwrap();
        assert!(signed.starts_with("-----BEGIN PGP SIGNED MESSAGE-----"));

        let (csm, _) = CleartextSignedMessage::from_string(&signed).unwrap();
        csm.verify(&sec.to_public_key().primary_key).unwrap();
    }

    #[test]
    fn rename_key_replaces_primary_uid() {
        let (mut sec, _, _, _) =
            generate_key(&opts(Profile::Compatible, None, Some("pw"))).unwrap();
        let pw = Password::from("pw".to_string());

        rename_key(&mut sec, &pw, "Renamed Person <renamed@example.com>".into()).unwrap();
        sec.verify_bindings().unwrap();

        // New name first, old name kept but demoted.
        assert_eq!(sec.details.users.len(), 2);
        assert_eq!(
            sec.details.users[0].id.as_str().unwrap(),
            "Renamed Person <renamed@example.com>"
        );

        // Armor round-trip preserves the new primary order.
        let armored = sec.to_armored_string(ArmorOptions::default()).unwrap();
        let (re, _) = SignedSecretKey::from_string(&armored).unwrap();
        re.verify_bindings().unwrap();
        assert_eq!(
            re.details.users[0].id.as_str().unwrap(),
            "Renamed Person <renamed@example.com>"
        );
        assert_eq!(
            re.details.users[1].id.as_str().unwrap(),
            "Pocket Tester (test key) <pocket@example.com>"
        );

        // Exactly one UID carries the primary flag: the new one.
        let is_primary = |u: &pgp::types::SignedUser| {
            u.signatures.iter().any(|s| {
                s.config()
                    .map(|c| {
                        c.hashed_subpackets()
                            .any(|p| matches!(p.data, SubpacketData::IsPrimary(true)))
                    })
                    .unwrap_or(false)
            })
        };
        assert!(is_primary(&re.details.users[0]));
        assert!(!is_primary(&re.details.users[1]));

        // The new UID's cert carries the key flags (metadata was inherited).
        assert!(crate::pgputil::key_flags_of_sig(&re.details.users[0].signatures[0]).is_some());

        // Encryption still works after the rename.
        let mut b = MessageBuilder::from_bytes("t.txt", b"after rename".to_vec())
            .seipd_v1(&mut rand::thread_rng(), SymmetricKeyAlgorithm::AES256);
        b.encrypt_to_key(
            &mut rand::thread_rng(),
            &re.to_public_key().public_subkeys[0],
        )
        .unwrap();
        let armored_msg = b
            .to_armored_string(&mut rand::thread_rng(), ArmorOptions::default())
            .unwrap();
        let (mut msg, _) = Message::from_string(&armored_msg).unwrap();
        let mut dec = msg.decrypt(&pw, &re).unwrap();
        assert_eq!(dec.as_data_string().unwrap(), "after rename");
    }

    #[test]
    fn sign_and_encrypt_then_decrypt_and_verify_roundtrip() {
        // The exact flow the GnuPG interop matrix case A3 exercises:
        // a Text-type data signature must be made over the CRLF-canonical
        // form (Utf8 literal), or verifying implementations that
        // canonicalize (GnuPG) will reject it.
        let (sec, _, sec_armored, _) =
            generate_key(&opts(Profile::Compatible, None, Some("pw"))).unwrap();
        let pubkey = sec.to_public_key();
        let (sec_re, _) = SignedSecretKey::from_string(&sec_armored).unwrap();

        let params = crate::msgops::EncryptParams {
            message: "hello with signature\nsecond line\n".into(),
            recipients: vec![pubkey],
            sign_with: Some(&sec_re),
            sign_passphrase: Some("pw".into()),
            profile: Profile::Compatible,
            armor: true,
            compress: false,
        };
        let (armored, _binary, _) = crate::msgops::encrypt(&params).unwrap();
        assert!(armored.starts_with("-----BEGIN PGP MESSAGE-----"));

        // Round-trip through a scratch store so decrypt can find the keys.
        let dir = std::env::temp_dir().join(format!("pocketpgp-test-ses-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fpr = crate::pgputil::fpr_hex(&sec.primary_key.fingerprint());
        std::env::set_var("POCKETPGP_DATA_DIR", &dir);
        let st = crate::store::Store::init().unwrap();
        {
            use pgp::composed::ArmorOptions;
            let pub_armored = sec
                .to_public_key()
                .to_armored_string(ArmorOptions::default())
                .unwrap();
            let sec_armored_out = sec.to_armored_string(ArmorOptions::default()).unwrap();
            st.save_key(&fpr, &pub_armored, Some(&sec_armored_out), None)
                .unwrap();
        }

        let (text, sigs, _) = crate::msgops::decrypt(&st, &armored, Some("pw")).unwrap();
        assert!(
            text.contains("hello with signature"),
            "plaintext mismatch: {text:?}"
        );
        assert_eq!(sigs.len(), 1, "expected one signature");
        assert!(sigs[0].valid, "embedded signature did not verify");
        assert_eq!(sigs[0].key_source, "own");
    }

    #[test]
    fn sign_detached_and_verify_roundtrip() {
        let (_, pub_armored, sec_armored, _) =
            generate_key(&opts(Profile::Compatible, None, Some("pw"))).unwrap();
        let (pubkey, _) = pgp::composed::SignedPublicKey::from_string(&pub_armored).unwrap();
        let (sec, _) = SignedSecretKey::from_string(&sec_armored).unwrap();

        let text = "detached payload\n";
        let sig_text = crate::msgops::sign_detached(&sec, Some("pw"), text).unwrap();
        let (sig, _) = DetachedSignature::from_string(&sig_text).unwrap();
        sig.verify(&pubkey.primary_key, text.as_bytes()).unwrap();
    }

    #[test]
    fn change_passphrase_and_reuse() {
        let (_, pub_armored, sec_armored, _) =
            generate_key(&opts(Profile::Compatible, None, Some("old pw"))).unwrap();
        let (mut sec, _) = SignedSecretKey::from_string(&sec_armored).unwrap();

        change_passphrase(&mut sec, Some("old pw"), Some("new pw")).unwrap();
        sec.verify_bindings().unwrap();
        let armored = sec.to_armored_string(ArmorOptions::default()).unwrap();

        // Old passphrase must now fail, new one must work.
        let (relocked, _) = SignedSecretKey::from_string(&armored).unwrap();
        let pw_old = Password::from("old pw".to_string());
        let pw_new = Password::from("new pw".to_string());
        assert!(relocked.primary_key.unlock(&pw_old, |_, _| Ok(())).is_err());
        assert!(relocked.primary_key.unlock(&pw_new, |_, _| Ok(())).is_ok());
        let _ = pub_armored;
    }

    #[test]
    fn extend_expiry_rewrites_self_signature() {
        let (_, pub_armored, sec_armored, _) = generate_key(&opts(
            Profile::Compatible,
            Some(crate::pgputil::now_secs() + 3600),
            Some("pw"),
        ))
        .unwrap();
        let (mut sec, _) = SignedSecretKey::from_string(&sec_armored).unwrap();
        let (pubkey0, _) = pgp::composed::SignedPublicKey::from_string(&pub_armored).unwrap();
        let exp0 = crate::pgputil::primary_expiry(&pubkey0).unwrap();

        let pw = Password::from("pw".to_string());
        extend_expiry(&mut sec, &pw, Some(crate::pgputil::now_secs() + 86400 * 30)).unwrap();

        let armored = sec.to_armored_string(ArmorOptions::default()).unwrap();
        let (sec1, _) = SignedSecretKey::from_string(&armored).unwrap();
        let pubkey1 = sec1.to_public_key();
        let exp1 = crate::pgputil::primary_expiry(&pubkey1).unwrap();
        assert!(exp1 > exp0);
    }
}
