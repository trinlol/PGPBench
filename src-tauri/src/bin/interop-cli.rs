//! interop-cli - a thin command-line harness into PocketPGP's Rust core.
//!
//! Used ONLY by the interop test matrix (tests/interop.ps1) to exercise the
//! exact same keygen / encrypt / decrypt / sign / verify / import code the
//! app uses, against real GnuPG. Keyring state is isolated via the
//! POCKETPGP_DATA_DIR environment variable.

use std::io::Read;

use pgp::composed::{ArmorOptions, Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::types::KeyDetails as _;
use pocketpgp_lib::{armorfix, keygen, msgops, pgputil, store};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match run(&args) {
        Ok(msg) => {
            if !msg.is_empty() {
                // --out=<path> writes byte-exact output (no shell stream
                // line-ending mangling); otherwise stdout.
                match args.iter().find_map(|a| a.strip_prefix("--out=")) {
                    Some(path) => {
                        if let Err(e) = std::fs::write(path, &msg) {
                            eprintln!("ERROR: cannot write {path}: {e}");
                            std::process::exit(1);
                        }
                    }
                    None => println!("{msg}"),
                }
            }
            0
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            1
        }
    };
    std::process::exit(code);
}

/// Input resolver: supports `--in=<path>` anywhere in the args (reads the
/// file raw, byte-exact) so test harnesses can avoid shell pipe mangling;
/// otherwise reads stdin.
fn input_text(args: &[String]) -> String {
    for a in args {
        if let Some(path) = a.strip_prefix("--in=") {
            let s = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {path}: {e}"))
                .unwrap_or_default();
            if s.len() > store::MAX_PASTE_BYTES {
                eprintln!("ERROR: the input is larger than the 1 MB limit PocketPGP accepts");
                std::process::exit(1);
            }
            return s;
        }
    }
    let mut s = String::new();
    let _ = std::io::stdin().read_to_string(&mut s);
    if s.len() > store::MAX_PASTE_BYTES {
        eprintln!("ERROR: the input is larger than the 1 MB limit PocketPGP accepts");
        std::process::exit(1);
    }
    s
}

fn run(args: &[String]) -> Result<String, String> {
    let data_dir = std::env::var("POCKETPGP_DATA_DIR")
        .expect("POCKETPGP_DATA_DIR must be set for interop-cli");

    let st = store::Store::init().map_err(|e| e.to_string())?;
    let _ = data_dir;

    match args.first().map(String::as_str) {
        Some("generate") => {
            // generate <name> <email> <algo> <profile> [passphrase] [expiry_days]
            let name = args.get(1).ok_or("generate: name")?;
            let email = args.get(2).ok_or("generate: email")?;
            let algo = keygen::Algo::parse(args.get(3).map(|s| s.as_str()).unwrap_or("ecc"))
                .map_err(|e| e.to_string())?;
            let profile =
                keygen::Profile::parse(args.get(4).map(|s| s.as_str()).unwrap_or("compatible"))
                    .map_err(|e| e.to_string())?;
            let passphrase = args.get(5).cloned().filter(|p| !p.is_empty());
            // 0 (or absent) = never expire.
            let expiry_days: Option<u64> =
                args.get(6).and_then(|d| d.parse().ok()).filter(|d| *d > 0);
            let expires_at = expiry_days.map(|d| pgputil::now_secs() + d * 86400);
            let opts = keygen::GenerateOptions {
                name: name.clone(),
                email: email.clone(),
                comment: None,
                passphrase: passphrase.as_deref(),
                expires_at,
                algo,
                profile,
            };
            let (key, pub_armored, sec_armored, rev) =
                keygen::generate_key(&opts).map_err(|e| e.to_string())?;

            let fpr = pgputil::fpr_hex(&key.primary_key.fingerprint());
            st.save_key(&fpr, &pub_armored, Some(&sec_armored), Some(&rev))
                .map_err(|e| e.to_string())?;
            st.rebuild_index().map_err(|e| e.to_string())?;
            Ok(fpr)
        }

        Some("export-public") => {
            let fpr = args.get(1).ok_or("export-public: fpr")?;
            st.read_armored_file(&st.pub_path(fpr))
                .map_err(|e| e.to_string())
        }
        Some("export-secret") => {
            let fpr = args.get(1).ok_or("export-secret: fpr")?;
            st.read_armored_file(&st.sec_path(fpr))
                .map_err(|e| e.to_string())
        }
        Some("export-revocation") => {
            let fpr = args.get(1).ok_or("export-revocation: fpr")?;
            st.read_armored_file(&st.rev_path(fpr))
                .map_err(|e| e.to_string())
        }

        Some("import") => {
            let armored = input_text(args);
            let fpr = import_public_or_secret(&st, &armored)?;
            let _ = fpr;
            st.rebuild_index().map_err(|e| e.to_string())?;
            Ok("imported".into())
        }

        Some("rename") => {
            // rename <fpr> <passphrase> <full new uid>
            let fpr = args.get(1).ok_or("rename: fpr")?;
            let pw = args.get(2).cloned().unwrap_or_default();
            let uid = args.iter().skip(3).cloned().collect::<Vec<_>>().join(" ");
            if uid.trim().is_empty() {
                return Err("rename: new uid required".into());
            }
            use pgp::composed::ArmorOptions;
            let mut key = st.load_secret(fpr).map_err(|e| e.to_string())?;
            let pw = pgp::types::Password::from(pw);
            keygen::rename_key(&mut key, &pw, uid).map_err(|e| e.to_string())?;
            let pub_armored = key
                .to_public_key()
                .to_armored_string(ArmorOptions::default())
                .map_err(|e| e.to_string())?;
            let sec_armored = key
                .to_armored_string(ArmorOptions::default())
                .map_err(|e| e.to_string())?;
            st.save_key(&fpr.to_uppercase(), &pub_armored, Some(&sec_armored), None)
                .map_err(|e| e.to_string())?;
            st.rebuild_index().map_err(|e| e.to_string())?;
            Ok("renamed".into())
        }

        Some("list") => {
            let entries = st.rebuild_index().map_err(|e| e.to_string())?;
            let mut out = String::new();
            for e in entries {
                out.push_str(&format!(
                    "{} {} expires={} secret={} revoked={} uids={}\n",
                    e.fpr,
                    e.algo,
                    e.expires.map(|x| x.to_string()).unwrap_or("never".into()),
                    e.has_secret,
                    e.revoked,
                    e.uids.join(";")
                ));
            }
            Ok(out)
        }

        Some("encrypt") => {
            // encrypt <profile> <fpr>... (message on stdin, optional +sign:<fpr>:<passphrase>)
            let profile =
                keygen::Profile::parse(args.get(1).map(|s| s.as_str()).unwrap_or("compatible"))
                    .map_err(|e| e.to_string())?;
            let mut recipients = Vec::new();
            let mut sign_with: Option<(String, String)> = None;
            for a in args
                .iter()
                .skip(2)
                .filter(|a| !a.starts_with("--in=") && !a.starts_with("--out="))
            {
                if let Some(rest) = a.strip_prefix("+sign:") {
                    let mut parts = rest.splitn(2, ':');
                    let fpr = parts.next().unwrap_or_default().to_string();
                    let pw = parts.next().unwrap_or_default().to_string();
                    sign_with = Some((fpr, pw));
                } else {
                    recipients.push(a.clone());
                }
            }
            let message = input_text(args);
            let mut keys = Vec::new();
            for fpr in &recipients {
                keys.push(st.load_public(fpr).map_err(|e| e.to_string())?);
            }
            let (sign_key, sign_pw) = match &sign_with {
                Some((fpr, pw)) => (
                    Some(st.load_secret(fpr).map_err(|e| e.to_string())?),
                    pw.clone(),
                ),
                None => (None, String::new()),
            };
            let params = msgops::EncryptParams {
                message,
                recipients: keys,
                sign_with: sign_key.as_ref(),
                sign_passphrase: if sign_key.is_some() {
                    Some(sign_pw)
                } else {
                    None
                },
                profile,
                armor: true,
                compress: false,
            };
            let (output, _binary, warnings) =
                msgops::encrypt(&params).map_err(|e| e.to_string())?;
            for w in warnings {
                eprintln!("WARNING: {w}");
            }
            Ok(output)
        }

        Some("decrypt") => {
            // decrypt [passphrase] [--in=<file>] [--out=<file>]
            let passphrase = args
                .get(1)
                .filter(|a| !a.starts_with("--in=") && !a.starts_with("--out="))
                .cloned();
            let input = input_text(args);
            let (text, sigs, warnings) =
                msgops::decrypt(&st, &input, passphrase.as_deref()).map_err(|e| e.to_string())?;
            for w in warnings {
                eprintln!("WARNING: {w}");
            }
            for s in &sigs {
                eprintln!(
                    "SIG: fpr={} source={} valid={} signed_at={}",
                    s.fpr,
                    s.key_source,
                    s.valid,
                    s.signed_at.map(|t| t.to_string()).unwrap_or_default()
                );
            }
            Ok(text)
        }

        Some("sign-cleartext") => {
            // sign-cleartext <fpr> [passphrase] [--in=<file>] [--out=<file>]
            let fpr = args.get(1).ok_or("sign-cleartext: fpr")?;
            let passphrase = args
                .get(2)
                .filter(|a| !a.starts_with("--in=") && !a.starts_with("--out="))
                .cloned();
            let text = input_text(args);
            let key = st.load_secret(fpr).map_err(|e| e.to_string())?;
            msgops::sign_cleartext(&key, passphrase.as_deref(), &text).map_err(|e| e.to_string())
        }

        Some("verify") => {
            // verify [--in=<file>]  |  verify --detached <sigfile> [--in=<file>]
            let (input, detached) = if args.get(1).map(|s| s.as_str()) == Some("--detached") {
                let sig_path = args.get(2).ok_or("verify --detached: sig file")?;
                let sig = std::fs::read_to_string(sig_path).map_err(|e| e.to_string())?;
                (input_text(args), Some(sig))
            } else {
                (input_text(args), None)
            };
            let (signed_text, sigs, warnings) =
                msgops::verify(&st, &input, detached.as_deref()).map_err(|e| e.to_string())?;
            for w in warnings {
                eprintln!("WARNING: {w}");
            }
            for s in &sigs {
                eprintln!(
                    "SIG: fpr={} source={} valid={} signed_at={}",
                    s.fpr,
                    s.key_source,
                    s.valid,
                    s.signed_at.map(|t| t.to_string()).unwrap_or_default()
                );
            }
            let _ = signed_text;
            Ok("verified".into())
        }

        Some("copy-private") => {
            // copy-private <fpr> - reads the armored secret from the store
            // (harness-only; the app never crosses this boundary.)
            let fpr = args.get(1).ok_or("copy-private: fpr")?;
            st.read_armored_file(&st.sec_path(fpr))
                .map_err(|e| e.to_string())
        }

        Some(other) => Err(format!("unknown command: {other}")),
        None => Err("usage: interop-cli <command> ...".into()),
    }
}

/// Shared import path with the Tauri command layer: sniff, parse, verify
/// self-signatures, apply policy, store. Mirrors commands::import_key.
fn import_public_or_secret(st: &store::Store, armored: &str) -> Result<String, String> {
    let normalized = armorfix::normalize_armor(armored);
    let kind = armorfix::sniff(&normalized);

    let (public, secret_armored): (SignedPublicKey, Option<String>) = match kind {
        armorfix::SniffedKind::PublicKey => {
            let (k, _) = SignedPublicKey::from_string(&normalized).map_err(|e| e.to_string())?;
            (k, None)
        }
        armorfix::SniffedKind::PrivateKey => {
            let (k, _) = SignedSecretKey::from_string(&normalized).map_err(|e| e.to_string())?;
            k.verify_bindings().map_err(|e| e.to_string())?;
            let public = k.to_public_key();
            let sec_armored = k
                .to_armored_string(ArmorOptions::default())
                .map_err(|e| e.to_string())?;
            (public, Some(sec_armored))
        }
        _ => return Err("not a public or private key block".into()),
    };

    public.verify_bindings().map_err(|e| e.to_string())?;
    let warnings = pgputil::policy_check(&public, false).map_err(|e| e.to_string())?;
    for w in warnings {
        eprintln!("WARNING: {w}");
    }

    let fpr = pgputil::fpr_hex(&public.primary_key.fingerprint());
    let pub_armored = public
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| e.to_string())?;
    st.save_key(&fpr, &pub_armored, secret_armored.as_deref(), None)
        .map_err(|e| e.to_string())?;
    Ok(fpr)
}
