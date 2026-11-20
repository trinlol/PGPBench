//! Key metadata extraction, policy enforcement and component selection.

use pgp::composed::{SignedPublicKey, SignedSecretKey};
use pgp::packet::{Signature, SubpacketData};
use pgp::types::{Fingerprint, KeyDetails, KeyVersion};

use crate::store::{IndexEntry, Store};

/// Uppercase hex fingerprint, no separators.
pub fn fpr_hex(fp: &Fingerprint) -> String {
    format!("{fp}").to_uppercase()
}

/// The public-facing algorithm label for a key packet.
pub fn algo_label(key: &impl KeyDetails) -> String {
    use pgp::types::PublicParams;
    use rsa::traits::PublicKeyParts;
    match key.public_params() {
        PublicParams::RSA(p) => format!("RSA {}", p.key.n().bits()),
        PublicParams::EdDSALegacy(_) => "Ed25519 (ECC Curve25519)".into(),
        PublicParams::Ed25519(_) => "Ed25519 (ECC)".into(),
        PublicParams::X25519(_) => "X25519 (ECC)".into(),
        PublicParams::ECDH(p) => format!("ECDH ({})", p.curve().name()),
        PublicParams::ECDSA(p) => format!("ECDSA ({})", p.curve().name()),
        _ => format!("{:?}", key.algorithm()),
    }
}

/// Capability letters for a signature's key flags (S/E/A/C).
pub fn caps_of_sig(sig: &Signature) -> String {
    let mut out = String::new();
    let Some(cfg) = sig.config() else {
        return out;
    };
    for sub in cfg.hashed_subpackets() {
        if let SubpacketData::KeyFlags(flags) = &sub.data {
            if flags.sign() {
                out.push('S');
            }
            if flags.encrypt_comms() || flags.encrypt_storage() {
                out.push('E');
            }
            if flags.authentication() {
                out.push('A');
            }
            if flags.certify() {
                out.push('C');
            }
            break;
        }
    }
    out
}

/// Extract key flags from a signature, if present.
pub fn key_flags_of_sig(sig: &Signature) -> Option<pgp::packet::KeyFlags> {
    let cfg = sig.config()?;
    for sub in cfg.hashed_subpackets() {
        if let SubpacketData::KeyFlags(flags) = &sub.data {
            return Some(flags.clone());
        }
    }
    None
}

/// Primary key expiry in unix seconds, read from the strongest self-signature
/// (v4: newest primary-uid certification; v6: direct key signature).
pub fn primary_expiry(pub_key: &SignedPublicKey) -> Option<u64> {
    let created = pub_key.primary_key.created_at().as_secs() as u64;

    // v6: direct signatures carry the metadata
    for sig in &pub_key.details.direct_signatures {
        if let Some(d) = sig.key_expiration_time() {
            return Some(created + d.as_secs() as u64);
        }
    }
    // v4: primary user id self-certification
    for user in &pub_key.details.users {
        for sig in &user.signatures {
            if let Some(d) = sig.key_expiration_time() {
                return Some(created + d.as_secs() as u64);
            }
        }
    }
    None
}

/// Subkey expiry in unix seconds, from its binding signature.
pub fn subkey_expiry(sig: &Signature, subkey_created: u64) -> Option<u64> {
    sig.key_expiration_time()
        .map(|d| subkey_created + d.as_secs() as u64)
}

/// True when the key carries a primary key revocation signature.
pub fn is_revoked(pub_key: &SignedPublicKey) -> bool {
    !pub_key.details.revocation_signatures.is_empty()
}

/// One index/cache entry for a stored key. `source` comes from the store
/// (own = generated here, imported = pasted in).
pub fn index_entry(store: &Store, key: &SignedPublicKey) -> IndexEntry {
    let fpr = fpr_hex(&key.primary_key.fingerprint());
    IndexEntry {
        uids: key
            .details
            .users
            .iter()
            .map(|u| u.id.as_str().unwrap_or_default().to_string())
            .collect(),
        algo: algo_label(&key.primary_key),
        created: key.primary_key.created_at().as_secs() as u64,
        expires: primary_expiry(key),
        has_secret: store.has_secret(&fpr),
        profile: if key.primary_key.version() == KeyVersion::V6 {
            "rfc9580".into()
        } else {
            "compatible".into()
        },
        // Derivable from the files themselves, so index.json stays a pure
        // cache: a key whose secret half is present is "own", otherwise it
        // entered the keyring as a pasted public key ("imported").
        source: if store.has_secret(&fpr) {
            "own".into()
        } else {
            "imported".into()
        },
        revoked: is_revoked(key),
        fpr,
    }
}

/// Policy checks applied on import (plan §9). Returns warnings; hard failures
/// are returned as an error with a clear message.
pub fn policy_check(pub_key: &SignedPublicKey, allow_legacy: bool) -> Result<Vec<String>, String> {
    use pgp::types::PublicParams;

    let mut warnings = Vec::new();

    // --- Hard rejects -------------------------------------------------------
    let check_pkt = |params: &PublicParams, what: &str| -> Result<(), String> {
        match params {
            PublicParams::DSA(_) => Err(format!(
                "{what} uses DSA, which is deprecated and rejected by this app"
            )),
            PublicParams::Elgamal(_) => Err(format!(
                "{what} uses Elgamal, which is deprecated and rejected by this app"
            )),
            PublicParams::ECDH(p) if p.curve() == pgp::crypto::ecc_curve::ECCCurve::Secp256k1 => {
                Err(format!(
                    "{what} uses secp256k1, which is rejected by this app"
                ))
            }
            PublicParams::ECDSA(p) if p.curve() == pgp::crypto::ecc_curve::ECCCurve::Secp256k1 => {
                Err(format!(
                    "{what} uses secp256k1, which is rejected by this app"
                ))
            }
            PublicParams::EdDSALegacy(p)
                if p.curve() == pgp::crypto::ecc_curve::ECCCurve::Secp256k1 =>
            {
                Err(format!(
                    "{what} uses secp256k1, which is rejected by this app"
                ))
            }
            _ => Ok(()),
        }
    };

    check_pkt(pub_key.primary_key.public_params(), "The primary key")?;
    for (i, sub) in pub_key.public_subkeys.iter().enumerate() {
        check_pkt(sub.key.public_params(), &format!("Subkey #{}", i + 1))?;
    }

    // Keys missing key-flag subpackets: legacy keys, hard reject unless the
    // user overrides under Advanced.
    let has_flags = pub_key
        .details
        .users
        .iter()
        .flat_map(|u| u.signatures.iter())
        .any(|s| key_flags_of_sig(s).is_some())
        || pub_key
            .details
            .direct_signatures
            .iter()
            .any(|s| key_flags_of_sig(s).is_some());
    if !has_flags {
        if allow_legacy {
            warnings.push(
                "This key has no key-flag subpackets (legacy key). Accepted with the \
                 legacy override; many peers may refuse it."
                    .into(),
            );
        } else {
            return Err(
                "The key's self-signature is missing key-flag subpackets (a pre-RFC-4880 \
                 legacy key). PGPBench rejects it by default - enable the legacy \
                 override under Advanced to import anyway."
                    .into(),
            );
        }
    }

    // --- Warnings -----------------------------------------------------------
    if pub_key.primary_key.version() == KeyVersion::V6 {
        warnings.push(
            "This is a v6 (RFC 9580) key. Stock GnuPG/Thunderbird cannot \
             read it (GnuPG needs >= 2.5.23 plus the --allow-9980 option)."
                .into(),
        );
    }
    if pub_key.primary_key.version() == KeyVersion::V2
        || pub_key.primary_key.version() == KeyVersion::V3
    {
        return Err("v2/v3 keys are ancient and unsafe to use; import rejected".into());
    }

    Ok(warnings)
}

/// The best encryption component of a key: newest valid encryption subkey,
/// or (rare) the primary itself when it carries encryption flags.
pub fn encryption_component<'a>(
    key: &'a SignedPublicKey,
) -> Option<&'a pgp::composed::SignedPublicSubKey> {
    let mut best: Option<(&pgp::composed::SignedPublicSubKey, u32)> = None;
    for sub in &key.public_subkeys {
        let Some(binding) = sub.signatures.first() else {
            continue;
        };
        let Some(flags) = key_flags_of_sig(binding) else {
            continue;
        };
        if !(flags.encrypt_comms() || flags.encrypt_storage()) {
            continue;
        }
        // Skip expired subkeys
        if let Some(exp) = subkey_expiry(binding, sub.key.created_at().as_secs() as u64) {
            if exp <= now_secs() {
                continue;
            }
        }
        match best {
            Some((_, t)) if t >= sub.key.created_at().as_secs() => {}
            _ => best = Some((sub, sub.key.created_at().as_secs())),
        }
    }
    best.map(|(s, _)| s)
}

/// The best signing component of a secret key: newest valid signing subkey,
/// else the primary.
pub fn signing_component<'a>(key: &'a SignedSecretKey) -> &'a dyn pgp::types::SigningKey {
    let mut best: Option<(&pgp::packet::SecretSubkey, u32)> = None;
    for sub in &key.secret_subkeys {
        let Some(binding) = sub.signatures.first() else {
            continue;
        };
        let Some(flags) = key_flags_of_sig(binding) else {
            continue;
        };
        if !flags.sign() {
            continue;
        }
        if let Some(exp) = subkey_expiry(binding, sub.key.created_at().as_secs() as u64) {
            if exp <= now_secs() {
                continue;
            }
        }
        match best {
            Some((_, t)) if t >= sub.key.created_at().as_secs() => {}
            _ => best = Some((&sub.key, sub.key.created_at().as_secs())),
        }
    }
    match best {
        Some((sub, _)) => sub,
        None => &key.primary_key,
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
