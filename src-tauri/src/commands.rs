//! Tauri command layer (plan §3): least-privilege, fully local, no network.
//!
//! The webview receives only public material, metadata, results and
//! verification outcomes. Private key material never crosses this boundary:
//! `copy_key_to_clipboard(kind = "private")` reads and clips the armored
//! secret key file entirely inside Rust.

use tauri::{AppHandle, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use zeroize::Zeroize;

use pgp::composed::Deserializable;

use crate::error::{AppError, AppResult};
use crate::keygen::{self, Algo, Profile};
use crate::pgputil;
use crate::store::{Store, MAX_PASTE_BYTES};

pub struct AppState(pub std::sync::Mutex<Store>);

fn with_store<T>(state: &State<AppState>, f: impl FnOnce(&Store) -> AppResult<T>) -> AppResult<T> {
    let store = state.0.lock().map_err(|_| AppError::internal("store lock poisoned"))?;
    f(&store)
}

fn cap_paste(s: &str) -> AppResult<()> {
    if s.len() > MAX_PASTE_BYTES {
        return Err(AppError::input(
            "the pasted input is larger than the 1 MB limit PGPBench accepts",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Init / settings
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn app_init(state: State<AppState>) -> AppResult<serde_json::Value> {
    with_store(&state, |store| {
        Ok(serde_json::json!({
            "settings": {
                "theme": store.settings.theme,
                "clipboard_clear_seconds": store.settings.clipboard_clear_seconds,
                "default_profile": store.settings.default_profile,
                "check_updates_on_launch": store.settings.check_updates_on_launch,
            },
            "acl_ok": store.acl_note.is_none(),
            "acl_note": store.acl_note,
            "data_dir": store.root.to_string_lossy(),
        }))
    })
}

#[tauri::command]
pub fn save_settings(
    state: State<AppState>,
    theme: String,
    clipboard_clear_seconds: u64,
    default_profile: String,
    check_updates_on_launch: Option<bool>,
) -> AppResult<serde_json::Value> {
    let mut store = state.0.lock().map_err(|_| AppError::internal("store lock poisoned"))?;
    store.settings.theme = match theme.as_str() {
        "dark" => "dark".to_string(),
        "light" => "light".to_string(),
        // "system" (and anything else) follows the Windows theme.
        _ => "system".to_string(),
    };
    store.settings.clipboard_clear_seconds = clipboard_clear_seconds.min(3600);
    store.settings.default_profile = Profile::parse(&default_profile)?.as_str().into();
    if let Some(check) = check_updates_on_launch {
        store.settings.check_updates_on_launch = check;
    }
    store.save_settings()?;

    Ok(serde_json::json!({
        "theme": store.settings.theme,
        "clipboard_clear_seconds": store.settings.clipboard_clear_seconds,
        "default_profile": store.settings.default_profile,
        "check_updates_on_launch": store.settings.check_updates_on_launch,
    }))
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn list_keys(state: State<AppState>) -> AppResult<Vec<serde_json::Value>> {
    with_store(&state, |store| {
        let mut out = Vec::new();
        for fpr in store.stored_fprs() {
            if let Ok(key) = store.load_public(&fpr) {
                out.push(summary_json(store, &key));
            }
        }
        Ok(out)
    })
}

#[tauri::command]
pub fn key_details(state: State<AppState>, fpr: String) -> AppResult<serde_json::Value> {
    with_store(&state, |store| {
        use pgp::types::KeyDetails as _;
        let fpr = fpr.to_uppercase();
        let key = store.load_public(&fpr)?;
        let mut subkeys = Vec::new();
        for sub in &key.public_subkeys {
            let binding = sub.signatures.first();
            let created = sub.key.created_at().as_secs() as u64;
            let expires = binding.and_then(|b| pgputil::subkey_expiry(b, created));
            let caps = binding.map(pgputil::caps_of_sig).unwrap_or_default();
            let revoked = binding
                .map(|b| b.typ() == Some(pgp::packet::SignatureType::SubkeyRevocation))
                .unwrap_or(false);
            subkeys.push(serde_json::json!({
                "fpr": pgputil::fpr_hex(&sub.key.fingerprint()),
                "algo": pgputil::algo_label(&sub.key),
                "created": created,
                "expires": expires,
                "capabilities": caps.chars().collect::<Vec<_>>(),
                "revoked": revoked,
                "expired": expires.map(|e| e <= pgputil::now_secs()).unwrap_or(false),
            }));
        }

        let summary = summary_json(store, &key);
        let mut warnings: Vec<String> = Vec::new();
        if summary["expired"].as_bool().unwrap_or(false) {
            warnings.push("This key has expired. You can extend its expiry from the details panel if you hold the private key.".into());
        }
        if summary["revoked"].as_bool().unwrap_or(false) {
            warnings.push("This key is revoked. It cannot be used to encrypt.".into());
        }

        Ok(serde_json::json!({
            "summary": summary,
            "subkeys": subkeys,
            "warnings": warnings,
        }))
    })
}

fn summary_json(store: &Store, key: &pgp::composed::SignedPublicKey) -> serde_json::Value {
    use pgp::types::KeyDetails as _;
    let fpr = pgputil::fpr_hex(&key.primary_key.fingerprint());
    let expires = pgputil::primary_expiry(key);
    let expired = expires.map(|e| e <= pgputil::now_secs()).unwrap_or(false);
    let can_encrypt = pgputil::encryption_component(key).is_some();
    serde_json::json!({
        "fpr": fpr,
        "uids": key.details.users.iter().map(|u| u.id.as_str().unwrap_or_default().to_string()).collect::<Vec<_>>(),
        "algo": pgputil::algo_label(&key.primary_key),
        "created": key.primary_key.created_at().as_secs() as u64,
        "expires": expires,
        "has_secret": store.has_secret(&fpr),
        "profile": if key.primary_key.version() == pgp::types::KeyVersion::V6 { "rfc9580" } else { "compatible" },
        "source": if store.has_secret(&fpr) { "own" } else { "imported" },
        "revoked": pgputil::is_revoked(key),
        "expired": expired,
        "can_encrypt": can_encrypt && !pgputil::is_revoked(key) && !expired,
    })
}

#[derive(serde::Deserialize)]
pub struct GenerateArgs {
    pub name: String,
    pub email: String,
    pub comment: Option<String>,
    pub passphrase: Option<String>,
    pub algo: String,
    pub profile: String,
    /// ISO date "YYYY-MM-DD" or null for "never".
    pub expires: Option<String>,
}

#[tauri::command]
pub fn generate_key(state: State<AppState>, args: GenerateArgs) -> AppResult<serde_json::Value> {
    let expires_at = match args.expires.as_deref() {
        None => None,
        Some("") => None,
        Some(date) => Some(parse_iso_date(date)?),
    };

    let mut passphrase = args.passphrase.clone().unwrap_or_default();
    let opts = keygen::GenerateOptions {
        name: args.name.clone(),
        email: args.email.clone(),
        comment: args.comment.clone(),
        passphrase: if args.passphrase.is_none() { None } else { Some(passphrase.as_str()) },
        expires_at,
        algo: Algo::parse(&args.algo)?,
        profile: Profile::parse(&args.profile)?,
    };

    let (key, pub_armored, sec_armored, rev_armored) = keygen::generate_key(&opts)?;
    passphrase.zeroize();

    let fpr = with_store(&state, |store| {
        use pgp::types::KeyDetails as _;
        let fpr = pgputil::fpr_hex(&key.primary_key.fingerprint());
        store.save_key(&fpr, &pub_armored, Some(&sec_armored), Some(&rev_armored))?;
        store.rebuild_index()?;
        Ok(fpr)
    })?;

    Ok(serde_json::json!({
        "key": with_store(&state, |store| {
            Ok(summary_json(store, &key.to_public_key()))
        })?,
        "public_key": pub_armored,
        "revocation_cert": rev_armored,
        "fpr": fpr,
    }))
}

#[derive(serde::Deserialize)]
pub struct ImportArgs {
    pub armored: String,
    pub dry_run: bool,
    /// Legacy override for keys without key-flag subpackets (Advanced).
    pub allow_legacy: bool,
}

#[tauri::command]
pub fn import_key(state: State<AppState>, args: ImportArgs) -> AppResult<serde_json::Value> {
    cap_paste(&args.armored)?;
    let normalized = crate::armorfix::normalize_armor(&args.armored);
    let kind = crate::armorfix::sniff(&normalized);

    use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};

    let (public, secret): (SignedPublicKey, Option<SignedSecretKey>) = match kind {
        crate::armorfix::SniffedKind::PublicKey => {
            let (k, _) = SignedPublicKey::from_string(&normalized)
                .map_err(|e| AppError::crypto(format!("not a valid public key block: {e}")))?;
            (k, None)
        }
        crate::armorfix::SniffedKind::PrivateKey => {
            let (k, _) = SignedSecretKey::from_string(&normalized)
                .map_err(|e| AppError::crypto(format!("not a valid private key block: {e}")))?;
            // Verify the secret key's bindings with a dummy unlock attempt
            // (structure check; the passphrase is not needed for that).
            k.verify_bindings()
                .map_err(|e| AppError::crypto(format!("private key failed self-verification: {e}")))?;
            let public = k.to_public_key();
            (public, Some(k))
        }
        _ => {
            return Err(AppError::input(
                "this is not a public or private key block. Use Decrypt & Verify for messages.",
            ))
        }
    };

    // Parse + verify self-signatures (plan §7 rule 6).
    public
        .verify_bindings()
        .map_err(|e| AppError::crypto(format!("key failed self-signature verification: {e}")))?;

    // Policy.
    let warnings = pgputil::policy_check(&public, args.allow_legacy).map_err(AppError::policy)?;

    use pgp::types::KeyDetails as _;
    let fpr = pgputil::fpr_hex(&public.primary_key.fingerprint());

    let would_replace = with_store(&state, |store| Ok(store.pub_path(&fpr).exists()))?;

    let summary = with_store(&state, |store| Ok(summary_json(store, &public)))?;

    if args.dry_run {
        return Ok(serde_json::json!({
            "ok": true,
            "error": null,
            "key": summary,
            "secret": secret.is_some(),
            "warnings": warnings,
            "would_replace": would_replace,
        }));
    }

    // Confirm-time write.
    with_store(&state, |store| {
        use pgp::composed::ArmorOptions;
        let pub_armored = public
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| AppError::crypto(format!("armoring public key failed: {e}")))?;
        let sec_armored = match &secret {
            Some(sec) => Some(
                sec.to_armored_string(ArmorOptions::default())
                    .map_err(|e| AppError::crypto(format!("armoring secret key failed: {e}")))?,
            ),
            None => None,
        };
        // An existing revocation certificate is left untouched on replace;
        // a fresh import has none until the user generates one.
        store.save_key(&fpr, &pub_armored, sec_armored.as_deref(), None)?;
        store.rebuild_index()?;
        Ok(())
    })?;

    Ok(serde_json::json!({
        "ok": true,
        "error": null,
        "key": summary,
        "secret": secret.is_some(),
        "warnings": warnings,
        "would_replace": would_replace,
    }))
}

#[tauri::command]
pub fn export_public(state: State<AppState>, fpr: String) -> AppResult<String> {
    with_store(&state, |store| {
        store.read_armored_file(&store.pub_path(&fpr.to_uppercase()))
    })
}

/// Open the key store in Windows Explorer. With a fingerprint, Explorer
/// opens the keys\ folder with that key's .pub.asc selected; without one,
/// it opens the store root (the path shown in the app header).
/// Purely local: shells out to explorer.exe with a path we constructed from
/// the store (no user-controlled strings reach the command line).
#[tauri::command]
pub fn open_key_folder(state: State<AppState>, fpr: Option<String>) -> AppResult<bool> {
    with_store(&state, |store| {
        use std::path::PathBuf;
        use std::process::Command;

        // Sanitize to a bare hex fingerprint before building any path.
        let select: Option<PathBuf> = fpr.map(|f| {
            let clean: String = f
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .take(64)
                .collect::<String>()
                .to_uppercase();
            store.pub_path(&clean)
        });

        // Prefer highlighting the key's .pub.asc in Explorer; without a
        // fingerprint, open the store root (the path shown in the header).
        // explorer.exe reports odd exit codes even on success, so we only
        // check that the file/dir exists.
        let (path, selecting): (PathBuf, bool) = match &select {
            Some(p) if p.exists() => (p.clone(), true),
            _ => (store.root.clone(), false),
        };
        if !path.exists() {
            return Err(AppError::io("the key store folder does not exist yet"));
        }

        let mut cmd = Command::new("explorer");
        if selecting {
            cmd.arg(format!("/select,{}", path.to_string_lossy()));
        } else {
            cmd.arg(&path);
        }
        crate::store::hide_console(&mut cmd);
        let result = cmd.spawn();
        result
            .map(|_| true)
            .map_err(|e| AppError::io(format!("could not open the key folder: {e}")))
    })
}

#[derive(serde::Deserialize)]
pub struct RenameKeyArgs {
    pub fpr: String,
    pub name: String,
    /// May be empty.
    pub email: String,
    /// May be empty or absent.
    pub comment: Option<String>,
    pub passphrase: Option<String>,
}

/// Rename a key: add a new primary User ID (self-signed) and demote the old
/// one - the OpenPGP-native way names work. Fingerprint and secret material
/// are untouched; peers only see the new name once the updated public key is
/// shared with them.
#[tauri::command]
pub fn rename_key(
    state: State<AppState>,
    mut args: RenameKeyArgs,
) -> AppResult<serde_json::Value> {
    let uid = keygen::build_uid(&args.name, &args.email, args.comment.as_deref())?;

    let summary = with_store(&state, |store| {
        use pgp::composed::ArmorOptions;
        let mut key = store.load_secret(&args.fpr.to_uppercase())?;
        let pw = args
            .passphrase
            .clone()
            .map(pgp::types::Password::from)
            .unwrap_or_else(pgp::types::Password::empty);
        keygen::rename_key(&mut key, &pw, uid)?;

        let pub_armored = key
            .to_public_key()
            .to_armored_string(ArmorOptions::default())
            .map_err(AppError::from)?;
        let sec_armored = key
            .to_armored_string(ArmorOptions::default())
            .map_err(AppError::from)?;
        // Keep an existing revocation certificate; nothing else to preserve.
        store.save_key(&args.fpr.to_uppercase(), &pub_armored, Some(&sec_armored), None)?;
        store.rebuild_index()?;

        let pubkey = store.load_public(&args.fpr.to_uppercase())?;
        Ok(summary_json(store, &pubkey))
    })?;
    args.passphrase.zeroize();
    Ok(summary)
}

#[derive(serde::Deserialize)]
pub struct DeleteArgs {
    pub fpr: String,
    /// Confirmation token typed/accepted in the UI ("delete").
    pub confirm: bool,
}

#[tauri::command]
pub fn delete_key(state: State<AppState>, args: DeleteArgs) -> AppResult<bool> {
    if !args.confirm {
        return Err(AppError::input("deletion requires confirmation"));
    }
    with_store(&state, |store| {
        store.delete_key(&args.fpr.to_uppercase())?;
        store.rebuild_index()?;
        Ok(true)
    })
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt / sign / verify
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct EncryptArgs {
    pub message: String,
    pub recipient_fprs: Vec<String>,
    pub one_off_public_keys: Vec<String>,
    pub sign_with_fpr: Option<String>,
    pub sign_passphrase: Option<String>,
    pub profile: String,
    pub armor: bool,
    pub compress: bool,
}

#[tauri::command]
pub fn encrypt(state: State<AppState>, args: EncryptArgs) -> AppResult<serde_json::Value> {
    cap_paste(&args.message)?;
    let profile = Profile::parse(&args.profile)?;

    let (recipients, sign_key) = with_store(&state, |store| {
        let mut recipients = Vec::new();
        for fpr in &args.recipient_fprs {
            recipients.push(store.load_public(&fpr.to_uppercase())?);
        }
        for one_off in &args.one_off_public_keys {
            cap_paste(one_off)?;
            let normalized = crate::armorfix::normalize_armor(one_off);
            let (k, _) = pgp::composed::SignedPublicKey::from_string(&normalized)
                .map_err(|e| AppError::crypto(format!("one-off public key is not valid: {e}")))?;
            k.verify_bindings()
                .map_err(|e| AppError::crypto(format!("one-off public key failed self-verification: {e}")))?;
            recipients.push(k);
        }

        let sign_key = match &args.sign_with_fpr {
            Some(fpr) => Some(store.load_secret(&fpr.to_uppercase())?),
            None => None,
        };
        Ok((recipients, sign_key))
    })?;

    let params = crate::msgops::EncryptParams {
        message: args.message.clone(),
        recipients,
        sign_with: sign_key.as_ref(),
        sign_passphrase: args.sign_passphrase.clone(),
        profile,
        armor: args.armor,
        compress: args.compress,
    };

    let (output, binary, warnings) = crate::msgops::encrypt(&params)?;

    Ok(serde_json::json!({
        "output": output,
        "binary": binary,
        "warnings": warnings,
    }))
}

#[derive(serde::Deserialize)]
pub struct DecryptArgs {
    pub input: String,
    pub passphrase: Option<String>,
}

#[tauri::command]
pub fn decrypt(state: State<AppState>, mut args: DecryptArgs) -> AppResult<serde_json::Value> {
    cap_paste(&args.input)?;
    let result = with_store(&state, |store| {
        crate::msgops::decrypt(store, &args.input, args.passphrase.as_deref())
    })?;
    args.passphrase.zeroize();

    let (plaintext, signatures, warnings) = result;
    Ok(serde_json::json!({
        "plaintext": plaintext,
        "signatures": signatures,
        "warnings": warnings,
    }))
}

#[derive(serde::Deserialize)]
pub struct SignArgs {
    pub message: String,
    pub fpr: String,
    pub passphrase: Option<String>,
    pub mode: String, // "cleartext" | "detached"
}

#[tauri::command]
pub fn sign(state: State<AppState>, mut args: SignArgs) -> AppResult<serde_json::Value> {
    cap_paste(&args.message)?;
    let output = with_store(&state, |store| {
        let key = store.load_secret(&args.fpr.to_uppercase())?;
        match args.mode.as_str() {
            "detached" => crate::msgops::sign_detached(&key, args.passphrase.as_deref(), &args.message),
            _ => crate::msgops::sign_cleartext(&key, args.passphrase.as_deref(), &args.message),
        }
    })?;
    args.passphrase.zeroize();

    Ok(serde_json::json!({ "output": output }))
}

#[derive(serde::Deserialize)]
pub struct VerifyArgs {
    pub input: String,
    pub detached: Option<String>,
}

#[tauri::command]
pub fn verify(state: State<AppState>, args: VerifyArgs) -> AppResult<serde_json::Value> {
    cap_paste(&args.input)?;
    if let Some(d) = args.detached.as_deref() {
        cap_paste(d)?;
    }
    let (signed_text, signatures, warnings) = with_store(&state, |store| {
        crate::msgops::verify(store, &args.input, args.detached.as_deref())
    })?;

    Ok(serde_json::json!({
        "ok": signatures.iter().any(|s| s.valid),
        "error": if signatures.is_empty() { "no signatures found".to_string() } else { String::new() },
        "signed_text": signed_text,
        "signatures": signatures,
        "warnings": warnings,
    }))
}

// ---------------------------------------------------------------------------
// Revocation / passphrase / expiry
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct RevocationArgs {
    pub fpr: String,
    pub passphrase: Option<String>,
    pub reason: String, // "none" | "compromised" | "superseded" | "retired"
    pub reason_text: Option<String>,
}

#[tauri::command]
pub fn generate_revocation(
    state: State<AppState>,
    mut args: RevocationArgs,
) -> AppResult<serde_json::Value> {
    use pgp::packet::RevocationCode;

    let code = match args.reason.as_str() {
        "compromised" => RevocationCode::KeyCompromised,
        "superseded" => RevocationCode::KeySuperseded,
        "retired" => RevocationCode::KeyRetired,
        _ => RevocationCode::NoReason,
    };

    let rev = with_store(&state, |store| {
        let key = store.load_secret(&args.fpr.to_uppercase())?;
        let pw = args
            .passphrase
            .clone()
            .map(pgp::types::Password::from)
            .unwrap_or_else(pgp::types::Password::empty);
        keygen::create_revocation_certificate_reasoned(&key, &pw, code, args.reason_text.clone())
            .map_err(AppError::from)
    })?;
    args.passphrase.zeroize();

    with_store(&state, |store| {
        store
            .atomic_write(&store.rev_path(&args.fpr.to_uppercase()), &rev)
            .map_err(AppError::from)
    })?;

    Ok(serde_json::json!({ "revocation_cert": rev }))
}

#[derive(serde::Deserialize)]
pub struct ChangePassphraseArgs {
    pub fpr: String,
    pub old_passphrase: Option<String>,
    pub new_passphrase: Option<String>,
}

#[tauri::command]
pub fn change_passphrase(
    state: State<AppState>,
    mut args: ChangePassphraseArgs,
) -> AppResult<bool> {
    let new_armored = with_store(&state, |store| {
        use pgp::composed::ArmorOptions;
        let mut key = store.load_secret(&args.fpr.to_uppercase())?;
        keygen::change_passphrase(
            &mut key,
            args.old_passphrase.as_deref(),
            args.new_passphrase.as_deref(),
        )?;
        key.verify_bindings()
            .map_err(|e| AppError::crypto(format!("re-locked key failed verification: {e}")))?;
        key.to_armored_string(ArmorOptions::default())
            .map_err(AppError::from)
    })?;
    args.old_passphrase.zeroize();
    args.new_passphrase.zeroize();

    with_store(&state, |store| {
        store
            .atomic_write(&store.sec_path(&args.fpr.to_uppercase()), &new_armored)
            .map_err(AppError::from)?;
        Ok(true)
    })
}

#[derive(serde::Deserialize)]
pub struct ExtendExpiryArgs {
    pub fpr: String,
    pub passphrase: Option<String>,
    /// ISO date "YYYY-MM-DD" or null for "never".
    pub expires: Option<String>,
}

#[tauri::command]
pub fn extend_expiry(state: State<AppState>, mut args: ExtendExpiryArgs) -> AppResult<serde_json::Value> {
    let expires_at = match args.expires.as_deref() {
        None | Some("") => None,
        Some(date) => Some(parse_iso_date(date)?),
    };

    let (pub_armored, sec_armored) = with_store(&state, |store| {
        use pgp::composed::ArmorOptions;
        let mut key = store.load_secret(&args.fpr.to_uppercase())?;
        let pw = args
            .passphrase
            .clone()
            .map(pgp::types::Password::from)
            .unwrap_or_else(pgp::types::Password::empty);
        keygen::extend_expiry(&mut key, &pw, expires_at)?;

        let pub_armored = key
            .to_public_key()
            .to_armored_string(ArmorOptions::default())
            .map_err(AppError::from)?;
        let sec_armored = key
            .to_armored_string(ArmorOptions::default())
            .map_err(AppError::from)?;
        store
            .save_key(&args.fpr.to_uppercase(), &pub_armored, Some(&sec_armored), None)?;
        store.rebuild_index()?;
        Ok((pub_armored, sec_armored))
    })?;
    args.passphrase.zeroize();
    let _ = (pub_armored, sec_armored);

    with_store(&state, |store| {
        let key = store.load_public(&args.fpr.to_uppercase())?;
        Ok(summary_json(store, &key))
    })
}

// ---------------------------------------------------------------------------
// Clipboard (all writes happen here, in Rust - plan §8)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct CopyKeyArgs {
    pub fpr: String,
    pub kind: String, // "public" | "private" | "revocation"
}

#[tauri::command]
pub fn copy_key_to_clipboard(
    app: AppHandle,
    state: State<AppState>,
    args: CopyKeyArgs,
) -> AppResult<serde_json::Value> {
    let (content, label) = with_store(&state, |store| {
        let fpr = args.fpr.to_uppercase();
        match args.kind.as_str() {
            "public" => Ok((
                store.read_armored_file(&store.pub_path(&fpr))?,
                format!("Public key {fpr}"),
            )),
            "private" => {
                let path = store.sec_path(&fpr);
                if !path.exists() {
                    return Err(AppError::io("this key has no private half in the keyring"));
                }
                Ok((
                    store.read_armored_file(&path)?,
                    format!("Private key {fpr} (passphrase-protected)"),
                ))
            }
            "revocation" => {
                let path = store.rev_path(&fpr);
                if !path.exists() {
                    return Err(AppError::io(
                        "no revocation certificate stored for this key - generate one first",
                    ));
                }
                Ok((
                    store.read_armored_file(&path)?,
                    format!("Revocation certificate {fpr}"),
                ))
            }
            other => Err(AppError::input(format!("unknown copy kind '{other}'"))),
        }
    })?;

    clipboard_write_secret(&app, &state, content, label)
}

#[tauri::command]
pub fn copy_text_secret(
    app: AppHandle,
    state: State<AppState>,
    content: String,
    label: String,
) -> AppResult<serde_json::Value> {
    clipboard_write_secret(&app, &state, content, label)
}

fn clipboard_write_secret(
    app: &AppHandle,
    state: &State<AppState>,
    content: String,
    label: String,
) -> AppResult<serde_json::Value> {
    // write_secret hints to Windows that the content should be kept out of
    // the clipboard history (Win+V) and cloud sync (plan §8).
    app.clipboard()
        .write_secret(&content)
        .map_err(|e| AppError::io(format!("writing to the clipboard failed: {e}")))?;

    let seconds = with_store(state, |store| Ok(store.settings.clipboard_clear_seconds))?;

    if seconds > 0 {
        // Best-effort auto-clear: only clears if the clipboard still holds
        // exactly what we wrote (never clobbers a newer copy).
        let expected = content;
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
            let matches = app
                .clipboard()
                .read_text()
                .map(|cur| cur == expected)
                .unwrap_or(false);
            if matches {
                let _ = app.clipboard().clear();
            }
        });
    }

    Ok(serde_json::json!({
        "label": label,
        "auto_clear_seconds": seconds,
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse "YYYY-MM-DD" into unix seconds (UTC midnight).
fn parse_iso_date(date: &str) -> AppResult<u64> {
    let naive = chrono::NaiveDate::parse_from_str(date.trim(), "%Y-%m-%d")
        .map_err(|_| AppError::input(format!("invalid date '{date}' - expected YYYY-MM-DD")))?;
    let dt = naive
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| AppError::input("invalid date"))?;
    Ok(dt.and_utc().timestamp().max(0) as u64)
}
