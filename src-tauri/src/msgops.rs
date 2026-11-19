//! Encrypt / decrypt / sign / verify (plan §§5, 9).
//!
//! Every decryption is followed by signature verification
//! (decrypt-then-verify), and every verification is reported with the signer's
//! fingerprint plus a key *source* (own / imported / unknown) - never a bare
//! green checkmark.

use pgp::composed::{
    ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, Message,
    MessageBuilder, SignedPublicKey, SignedSecretKey, VerificationResult,
};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::Signature;
use pgp::types::{KeyDetails as _, KeyVersion, Password, SigningKey as _};

use crate::error::{AppError, AppResult};
use crate::keygen::Profile;
use crate::pgputil;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SignatureInfo {
    /// Signer primary fingerprint (uppercase hex) or best-effort marker.
    pub fpr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_uid: Option<String>,
    /// "own" | "imported" | "unknown"
    pub key_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<u64>,
    pub valid: bool,
    pub revoked: bool,
}

fn sig_fpr(sig: &Signature) -> Option<String> {
    sig.issuer_fingerprint()
        .first()
        .map(|f| pgputil::fpr_hex(f))
}

fn unknown_info(sig: &Signature) -> SignatureInfo {
    SignatureInfo {
        fpr: sig_fpr(sig).unwrap_or_else(|| "unknown".into()),
        key_uid: None,
        key_source: "unknown",
        signed_at: sig.created().map(|t| t.as_secs() as u64),
        valid: false,
        revoked: false,
    }
}

/// A concrete verifier packet. Several rPGP verification APIs take
/// `&impl VerifyingKey` (a sized generic), so candidates are carried
/// concretely and only widened to `&dyn` where an API accepts it.
pub enum VerifierPacket<'a> {
    Primary(&'a pgp::packet::PublicKey),
    Sub(&'a pgp::packet::PublicSubkey),
}

impl VerifierPacket<'_> {
    /// Verify a detached signature over `content` with this packet.
    pub fn verify_detached(
        &self,
        sig: &DetachedSignature,
        content: &[u8],
    ) -> pgp::errors::Result<()> {
        match self {
            VerifierPacket::Primary(k) => sig.verify(*k, content),
            VerifierPacket::Sub(k) => sig.verify(*k, content),
        }
    }

    /// Verify a cleartext signature with this packet.
    pub fn verify_cleartext<'a>(
        &self,
        csm: &'a CleartextSignedMessage,
    ) -> pgp::errors::Result<&'a Signature> {
        match self {
            VerifierPacket::Primary(k) => csm.verify(*k),
            VerifierPacket::Sub(k) => csm.verify(*k),
        }
    }
}

/// All stored public keys plus the metadata needed to attribute a successful
/// verification to its owner. Owns the keys so candidates can borrow safely.
pub struct VerifierSet {
    pub keys: Vec<SignedPublicKey>,
    /// Whether the owning key's secret half is in the keyring ("own").
    pub has_secret: Vec<bool>,
    /// (key_index, subkey_index) for each candidate verifier slot.
    pub slots: Vec<(usize, Option<usize>)>,
}

impl VerifierSet {
    pub fn load(store: &crate::store::Store) -> AppResult<Self> {
        let mut keys = Vec::new();
        let mut has_secret = Vec::new();
        for fpr in store.stored_fprs() {
            if let Ok(key) = store.load_public(&fpr) {
                has_secret.push(store.has_secret(&fpr));
                keys.push(key);
            }
        }

        let mut slots = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            slots.push((i, None));
            for s in 0..key.public_subkeys.len() {
                slots.push((i, Some(s)));
            }
        }
        Ok(VerifierSet {
            keys,
            has_secret,
            slots,
        })
    }

    /// Concrete verifier packet for slot `idx`.
    pub fn packet_at(&self, idx: usize) -> VerifierPacket<'_> {
        let (ki, si) = self.slots[idx];
        match si {
            None => VerifierPacket::Primary(&self.keys[ki].primary_key),
            Some(s) => VerifierPacket::Sub(&self.keys[ki].public_subkeys[s].key),
        }
    }

    /// Borrowing `&dyn` view of all candidate packets (for `verify_nested`).
    pub fn packets_dyn(&self) -> Vec<&(dyn pgp::types::VerifyingKey + '_)> {
        self.slots
            .iter()
            .map(|(ki, si)| match si {
                None => &self.keys[*ki].primary_key as &(dyn pgp::types::VerifyingKey + '_),
                Some(s) => {
                    &self.keys[*ki].public_subkeys[*s].key as &(dyn pgp::types::VerifyingKey + '_)
                }
            })
            .collect()
    }

    /// Info for a signature that verified against candidate `idx`.
    pub fn info_at(&self, idx: usize, sig: &Signature) -> SignatureInfo {
        let (ki, _) = self.slots[idx];
        let key = &self.keys[ki];
        let uid = key.details.users.first().and_then(|u| u.id.as_str());
        let revoked = pgputil::is_revoked(key);
        SignatureInfo {
            fpr: sig_fpr(sig).unwrap_or_else(|| pgputil::fpr_hex(&key.primary_key.fingerprint())),
            key_uid: uid.map(str::to_string),
            key_source: if self.has_secret[ki] {
                "own"
            } else {
                "imported"
            },
            signed_at: sig.created().map(|t| t.as_secs() as u64),
            valid: true,
            revoked,
        }
    }
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

pub struct EncryptParams<'a> {
    pub message: String,
    /// Resolved (loaded) recipient public keys, incl. one-offs.
    pub recipients: Vec<SignedPublicKey>,
    pub sign_with: Option<&'a SignedSecretKey>,
    pub sign_passphrase: Option<String>,
    pub profile: Profile,
    pub armor: bool,
    pub compress: bool,
}

pub fn encrypt(params: &EncryptParams) -> AppResult<(String, bool, Vec<String>)> {
    let mut warnings = Vec::new();

    if params.recipients.is_empty() {
        return Err(AppError::input(
            "no recipients selected - pick at least one key or paste a one-off public key",
        ));
    }

    for k in &params.recipients {
        if pgputil::is_revoked(k) {
            return Err(AppError::policy("cannot encrypt to a revoked key"));
        }
        if pgputil::encryption_component(k).is_none() {
            let fpr = pgputil::fpr_hex(&k.primary_key.fingerprint());
            return Err(AppError::policy(format!(
                "recipient {fpr} has no usable encryption subkey"
            )));
        }
    }

    // Profile rules (plan §4): RFC 9580 output (SEIPD v2) cannot be read by
    // v4 keys at all; Compatible output (SEIPD v1) is readable by everyone.
    let v6_count = params
        .recipients
        .iter()
        .filter(|k| k.primary_key.version() == KeyVersion::V6)
        .count();

    match params.profile {
        Profile::Rfc9580 => {
            if v6_count != params.recipients.len() {
                return Err(AppError::policy(
                    "RFC 9580 output (SEIPD v2) cannot be decrypted by v4 keys. \
                     Switch to the Compatible profile, or remove v4 recipients.",
                ));
            }
        }
        Profile::Compatible => {
            if v6_count > 0 {
                warnings.push(
                    "One or more recipients use v6 keys: they will need an RFC 9580 \
                     capable client (GnuPG >= 2.5.23 with --allow-9980, or a modern \
                     OpenPGP library) to decrypt this Compatible-profile message."
                        .into(),
                );
            }
        }
    }

    if let Some(signer) = params.sign_with {
        if pgputil::is_revoked(&signer.to_public_key()) {
            return Err(AppError::policy("cannot sign with a revoked key"));
        }
    }

    // A type-Text data signature is verified against the CRLF-canonical form
    // of the text. rPGP's builder hashes the payload verbatim, so the signed
    // payload itself must be CRLF (carried in a Utf8 literal packet) - or
    // GnuPG (which canonicalizes when verifying) reports a bad signature.
    // Unsigned messages keep the user's bytes untouched in a binary literal.
    let message_bytes = if params.sign_with.is_some() {
        let normalized = params.message.replace("\r\n", "\n").replace('\n', "\r\n");
        normalized.into_bytes()
    } else {
        params.message.as_bytes().to_vec()
    };

    let mut base = MessageBuilder::from_bytes("message.txt", message_bytes);
    if params.sign_with.is_some() {
        base.data_mode(pgp::packet::DataMode::Utf8)
            .map_err(|e| AppError::crypto(format!("setting text data mode failed: {e}")))?;
        base.sign_text();
    }
    if params.compress {
        use pgp::types::CompressionAlgorithm;
        base.compression(CompressionAlgorithm::ZLIB);
    }
    if let Some(signer) = params.sign_with {
        let pw = params
            .sign_passphrase
            .clone()
            .map(Password::from)
            .unwrap_or_else(Password::empty);
        base.sign(
            pgputil::signing_component(signer),
            pw,
            signer.primary_key.hash_alg(),
        );
    }

    let (output, binary) = match params.profile {
        Profile::Compatible => {
            let mut b = base.seipd_v1(&mut rand::thread_rng(), SymmetricKeyAlgorithm::AES256);
            for recipient in &params.recipients {
                let sub = pgputil::encryption_component(recipient).ok_or_else(|| {
                    AppError::policy("recipient lost its encryption subkey mid-flight")
                })?;
                b.encrypt_to_key(&mut rand::thread_rng(), sub)
                    .map_err(|e| {
                        AppError::crypto(format!("encrypting to recipient failed: {e}"))
                    })?;
            }
            serialize(b, params.armor)?
        }
        Profile::Rfc9580 => {
            let mut b = base.seipd_v2(
                &mut rand::thread_rng(),
                SymmetricKeyAlgorithm::AES256,
                AeadAlgorithm::Ocb,
                ChunkSize::C1MiB,
            );
            for recipient in &params.recipients {
                let sub = pgputil::encryption_component(recipient).ok_or_else(|| {
                    AppError::policy("recipient lost its encryption subkey mid-flight")
                })?;
                b.encrypt_to_key(&mut rand::thread_rng(), sub)
                    .map_err(|e| {
                        AppError::crypto(format!("encrypting to recipient failed: {e}"))
                    })?;
            }
            serialize(b, params.armor)?
        }
    };

    Ok((output, binary, warnings))
}

fn serialize<R: std::io::Read, E: pgp::composed::Encryption>(
    b: MessageBuilder<'_, R, E>,
    armor: bool,
) -> AppResult<(String, bool)> {
    if armor {
        let armored = b
            .to_armored_string(&mut rand::thread_rng(), ArmorOptions::default())
            .map_err(|e| AppError::crypto(format!("armoring message failed: {e}")))?;
        Ok((armored, false))
    } else {
        use base64::Engine as _;
        let bytes = b
            .to_vec(&mut rand::thread_rng())
            .map_err(|e| AppError::crypto(format!("serializing message failed: {e}")))?;
        Ok((
            base64::engine::general_purpose::STANDARD.encode(bytes),
            true,
        ))
    }
}

// ---------------------------------------------------------------------------
// Decrypt (always followed by verification)
// ---------------------------------------------------------------------------

pub fn decrypt(
    store: &crate::store::Store,
    input: &str,
    passphrase: Option<&str>,
) -> AppResult<(String, Vec<SignatureInfo>, Vec<String>)> {
    let normalized = crate::armorfix::normalize_armor(input);
    let mut warnings = Vec::new();

    // Parse (armored, or base64-wrapped binary). The Vec must outlive `msg`,
    // since Message borrows the buffer it was parsed from.
    let binary_bytes: Vec<u8> =
        if crate::armorfix::sniff(&normalized) == crate::armorfix::SniffedKind::NotArmored {
            crate::armorfix::maybe_base64_binary(&normalized)
                .ok_or_else(|| AppError::input("the input is not an OpenPGP message"))?
        } else {
            Vec::new()
        };

    let msg: Message = if binary_bytes.is_empty() {
        let (msg, _) = Message::from_string(&normalized)
            .map_err(|e| AppError::crypto(format!("parsing message failed: {e}")))?;
        msg
    } else {
        Message::from_bytes(&binary_bytes[..])
            .map_err(|e| AppError::crypto(format!("parsing binary message failed: {e}")))?
    };

    // Gather the whole keyring for decryption.
    let secret_keys: Vec<SignedSecretKey> = store
        .stored_fprs()
        .iter()
        .filter_map(|fpr| store.load_secret(fpr).ok())
        .collect();
    if secret_keys.is_empty() {
        return Err(AppError::crypto(
            "you have no private keys yet, so this message cannot be decrypted. \
             Generate or import one first (Keys tab).",
        ));
    }

    let pw = passphrase
        .map(|p| Password::from(p.to_string()))
        .unwrap_or_else(Password::empty);
    let key_refs: Vec<&SignedSecretKey> = secret_keys.iter().collect();
    let pw_refs: Vec<&Password> = vec![&pw];

    let decrypted = msg.decrypt_with_keys(pw_refs, key_refs).map_err(|e| {
        AppError::crypto(format!(
            "could not decrypt this message - it may not be encrypted to any key in your \
                 keyring, or the passphrase may be wrong (technical detail: {e})"
        ))
    })?;

    // Flatten compression so the outer structure can be verified afterwards.
    let mut decrypted = decrypted
        .decompress()
        .map_err(|e| AppError::crypto(format!("decompressing message failed: {e}")))?;

    // Read the plaintext fully (also completes the signature hash state).
    let text = decrypted
        .as_data_string()
        .map_err(|e| AppError::crypto(format!("reading decrypted message failed: {e}")))?;

    // --- decrypt-then-verify (plan §9) --------------------------------------
    let verifiers = VerifierSet::load(store)?;
    let packets = verifiers.packets_dyn();
    let results = decrypted
        .verify_nested(&packets)
        .map_err(|e| AppError::crypto(format!("verification pass failed: {e}")))?;

    let mut signatures: Vec<SignatureInfo> = Vec::new();
    let mut matched_any = false;

    for (idx, res) in results.iter().enumerate() {
        if let VerificationResult::Valid(sig) = res {
            matched_any = true;
            let mut info = verifiers.info_at(idx, sig);
            info.valid = true;
            if info.revoked {
                warnings.push(format!(
                    "the message is signed with a REVOKED key ({}). Treat it with caution.",
                    info.fpr
                ));
            }
            signatures.push(info);
        }
    }

    // Signatures by unknown signers are reported as such - never silently
    // presented as an unsigned message.
    if !matched_any {
        let unknown = collect_signatures(&decrypted);
        if !unknown.is_empty() {
            for sig in unknown {
                signatures.push(unknown_info(&sig));
            }
            warnings.push(
                "the message is signed, but the signing key is not in your keyring, \
                 so the signature could not be verified."
                    .into(),
            );
        }
    }

    Ok((text, signatures, warnings))
}

/// Extract all signature packets of a fully-read message (for unknown-signer
/// reporting). Returns an empty vec when the signature details were not
/// retained by the reader (rare one-pass edge cases).
fn collect_signatures(msg: &Message) -> Vec<Signature> {
    let mut out = Vec::new();
    if let Message::Signed { reader, .. } = msg {
        if let Some(all) = reader.signatures() {
            for full in all {
                out.push(full.signature().clone());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Sign (cleartext / detached)
// ---------------------------------------------------------------------------

pub fn sign_cleartext(
    key: &SignedSecretKey,
    passphrase: Option<&str>,
    text: &str,
) -> AppResult<String> {
    let pw = passphrase
        .map(|p| Password::from(p.to_string()))
        .unwrap_or_else(Password::empty);
    // CleartextSignedMessage::sign takes &impl SigningKey; wrap the dyn ref.
    let boxed: Box<&dyn pgp::types::SigningKey> = Box::new(pgputil::signing_component(key));
    let signed = CleartextSignedMessage::sign(&mut rand::thread_rng(), text, &boxed, &pw)
        .map_err(|e| AppError::crypto(format!("signing failed: {e}")))?;
    signed
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| AppError::crypto(format!("armoring failed: {e}")))
}

pub fn sign_detached(
    key: &SignedSecretKey,
    passphrase: Option<&str>,
    text: &str,
) -> AppResult<String> {
    let pw = passphrase
        .map(|p| Password::from(p.to_string()))
        .unwrap_or_else(Password::empty);
    let hash = pgputil::signing_component(key).hash_alg();
    let boxed: Box<&dyn pgp::types::SigningKey> = Box::new(pgputil::signing_component(key));
    let sig = DetachedSignature::sign_text_data(
        &mut rand::thread_rng(),
        &boxed,
        &pw,
        hash,
        text.as_bytes(),
    )
    .map_err(|e| AppError::crypto(format!("signing failed: {e}")))?;
    sig.to_armored_string(ArmorOptions::default())
        .map_err(|e| AppError::crypto(format!("armoring failed: {e}")))
}

// ---------------------------------------------------------------------------
// Verify (cleartext, embedded, detached)
// ---------------------------------------------------------------------------

pub fn verify(
    store: &crate::store::Store,
    input: &str,
    detached: Option<&str>,
) -> AppResult<(Option<String>, Vec<SignatureInfo>, Vec<String>)> {
    let verifiers = VerifierSet::load(store)?;
    let mut warnings = Vec::new();

    // ---- detached mode ------------------------------------------------------
    if let Some(sig_text) = detached {
        let normalized_sig = crate::armorfix::normalize_armor(sig_text);
        let (sig, _) = DetachedSignature::from_string(&normalized_sig)
            .map_err(|e| AppError::crypto(format!("parsing detached signature failed: {e}")))?;

        let content = input.as_bytes();
        let mut infos = Vec::new();
        let mut matched = false;

        for idx in 0..verifiers.slots.len() {
            if verifiers
                .packet_at(idx)
                .verify_detached(&sig, content)
                .is_ok()
            {
                matched = true;
                infos.push(verifiers.info_at(idx, &sig.signature));
            }
        }
        if !matched {
            infos.push(unknown_info(&sig.signature));
            warnings.push(
                "the signature did not match any key in your keyring (or it is invalid)".into(),
            );
        }
        return Ok((None, infos, warnings));
    }

    // ---- sniff the paste surface --------------------------------------------
    match crate::armorfix::sniff(input) {
        crate::armorfix::SniffedKind::Cleartext => {
            let (csm, _) = CleartextSignedMessage::from_string(input)
                .map_err(|e| AppError::crypto(format!("parsing signed message failed: {e}")))?;

            let mut infos = Vec::new();
            let mut matched = false;
            for idx in 0..verifiers.slots.len() {
                if let Ok(sig) = verifiers.packet_at(idx).verify_cleartext(&csm) {
                    matched = true;
                    infos.push(verifiers.info_at(idx, sig));
                }
            }
            if !matched {
                for sig in csm.signatures() {
                    infos.push(unknown_info(sig));
                }
                warnings.push(
                    "the signature did not match any key in your keyring (or it is invalid)".into(),
                );
            }
            Ok((Some(csm.signed_text()), infos, warnings))
        }
        crate::armorfix::SniffedKind::Message => {
            let normalized = crate::armorfix::normalize_armor(input);
            let (mut msg, _) = Message::from_string(&normalized)
                .map_err(|e| AppError::crypto(format!("parsing message failed: {e}")))?;

            // Drain fully so the signature hash state is complete.
            let text = msg
                .as_data_string()
                .map_err(|e| AppError::crypto(format!("reading message failed: {e}")))?;

            let packets = verifiers.packets_dyn();
            let results = msg
                .verify_nested(&packets)
                .map_err(|e| AppError::crypto(format!("verification pass failed: {e}")))?;

            let mut infos = Vec::new();
            let mut matched = false;
            for (idx, res) in results.iter().enumerate() {
                if let VerificationResult::Valid(sig) = res {
                    matched = true;
                    infos.push(verifiers.info_at(idx, sig));
                }
            }
            if !matched {
                let unknown = collect_signatures(&msg);
                if !unknown.is_empty() {
                    for sig in unknown {
                        infos.push(unknown_info(&sig));
                    }
                    warnings.push(
                        "the message is signed, but the signing key is not in your \
                         keyring (or the signature is invalid)."
                            .into(),
                    );
                }
            }
            Ok((Some(text), infos, warnings))
        }
        _ => Err(AppError::input(
            "this does not look like a signed message. Paste a cleartext-signed block \
             or an OpenPGP message, or provide a detached signature.",
        )),
    }
}
