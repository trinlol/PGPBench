//! Keyring storage: %LOCALAPPDATA%\PGPBench
//!
//! Layout (plan §7):
//!   keys\<FPR>.pub.asc    armored public key (exactly what you'd paste into an email)
//!   keys\<FPR>.sec.asc    passphrase-encrypted armored secret key
//!   keys\<FPR>.rev.asc    revocation certificate
//!   index.json            rebuildable cache (never source of truth)
//!   settings.json         theme, clipboard auto-clear, default profile
//!
//! Rules honored here:
//! - index.json is only a cache; every listing re-scans keys\.
//! - Atomic writes: temp file in the same directory -> fsync -> rename over the
//!   target; one .bak of the previous content is kept.
//! - Per-user ACL on the directory is verified at startup (profile dirs are
//!   per-user by default; we check rather than rewrite).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

/// Hard cap for pasted input (plan §8: ~1 MB).
pub const MAX_PASTE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub fpr: String,
    pub uids: Vec<String>,
    pub algo: String,
    pub created: u64,
    pub expires: Option<u64>,
    pub has_secret: bool,
    pub profile: String,
    pub source: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub theme: String, // "light" | "dark"
    pub clipboard_clear_seconds: u64,
    pub default_profile: String, // "compatible" | "rfc9580"
    /// Optional signature-verified update check on launch (the app's only
    /// possible network call; see README security notes).
    #[serde(default = "default_true")]
    pub check_updates_on_launch: bool,
}

fn default_true() -> bool {
    true
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            // Follow the Windows theme until the user picks one explicitly.
            theme: "system".into(),
            clipboard_clear_seconds: 60,
            default_profile: "compatible".into(),
            check_updates_on_launch: true,
        }
    }
}

pub struct Store {
    pub root: PathBuf,
    pub keys_dir: PathBuf,
    pub settings: Settings,
    /// Set when the ACL verification finds something suspicious; surfaced to
    /// the UI as a persistent warning banner.
    pub acl_note: Option<String>,
}

impl Store {
    /// Resolve %LOCALAPPDATA%\PGPBench (or $PGPBENCH_DATA_DIR / legacy
    /// $POCKETPGP_DATA_DIR when overridden - used by the interop test harness
    /// to isolate keyring state), migrating a legacy %LOCALAPPDATA%\PocketPGP
    /// folder if present, create it, verify the ACL, and load settings.
    pub fn init() -> AppResult<Self> {
        let root = match std::env::var_os("PGPBENCH_DATA_DIR")
            .or_else(|| std::env::var_os("POCKETPGP_DATA_DIR"))
        {
            Some(dir) => PathBuf::from(dir),
            None => {
                let local = std::env::var_os("LOCALAPPDATA")
                    .map(PathBuf::from)
                    .ok_or_else(|| AppError::io("cannot resolve %LOCALAPPDATA%"))?;
                let target = local.join("PGPBench");
                let legacy = local.join("PocketPGP");
                if !target.exists() && legacy.exists() {
                    if fs::rename(&legacy, &target).is_ok() {
                        target
                    } else {
                        legacy
                    }
                } else {
                    target
                }
            }
        };
        let keys_dir = root.join("keys");

        fs::create_dir_all(&keys_dir)?;

        let acl_note = check_acl(&root)?;

        let settings = load_settings(&root)?;

        let store = Store {
            root,
            keys_dir,
            settings,
            acl_note,
        };
        store.rebuild_index()?; // cache is rebuilt on every start
        Ok(store)
    }

    // ------------------------------------------------------------- paths ----

    pub fn pub_path(&self, fpr: &str) -> PathBuf {
        self.keys_dir.join(format!("{fpr}.pub.asc"))
    }
    pub fn sec_path(&self, fpr: &str) -> PathBuf {
        self.keys_dir.join(format!("{fpr}.sec.asc"))
    }
    pub fn rev_path(&self, fpr: &str) -> PathBuf {
        self.keys_dir.join(format!("{fpr}.rev.asc"))
    }
    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }
    fn settings_path(&self) -> PathBuf {
        self.root.join("settings.json")
    }

    // ------------------------------------------------------------ listing ----

    /// Every primary fingerprint present in the store (from file names,
    /// sorted for stable listings).
    pub fn stored_fprs(&self) -> Vec<String> {
        let mut fprs: Vec<String> = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.keys_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(fpr) = name
                    .strip_suffix(".pub.asc")
                    .or_else(|| name.strip_suffix(".sec.asc"))
                {
                    let fpr = fpr.to_uppercase();
                    if !fprs.contains(&fpr) {
                        fprs.push(fpr);
                    }
                }
            }
        }
        fprs.sort();
        fprs
    }

    pub fn has_secret(&self, fpr: &str) -> bool {
        self.sec_path(fpr).exists()
    }

    pub fn load_public(&self, fpr: &str) -> AppResult<SignedPublicKey> {
        let path = self.pub_path(fpr);
        let armored = fs::read_to_string(&path)
            .map_err(|_| AppError::io(format!("public key {fpr} is not in the keyring")))?;
        let (key, _) = SignedPublicKey::from_string(&armored)?;
        Ok(key)
    }

    pub fn load_secret(&self, fpr: &str) -> AppResult<SignedSecretKey> {
        let path = self.sec_path(fpr);
        let armored = fs::read_to_string(&path)
            .map_err(|_| AppError::io(format!("private key {fpr} is not in the keyring")))?;
        let (key, _) = SignedSecretKey::from_string(&armored)?;
        Ok(key)
    }

    pub fn read_armored_file(&self, path: &Path) -> AppResult<String> {
        fs::read_to_string(path).map_err(|e| AppError::io(format!("cannot read key file: {e}")))
    }

    // ------------------------------------------------------------ writing ----

    /// Atomic write with one .bak kept (plan §7 rule 3):
    /// temp file in the same directory -> fsync -> rename over the target.
    /// On Windows, rename cannot replace an existing file, so the old target
    /// is moved aside to `.bak` right before the swap.
    pub fn atomic_write(&self, path: &Path, contents: &str) -> AppResult<()> {
        let dir = path.parent().ok_or_else(|| AppError::io("bad path"))?;
        let tmp = dir.join(format!(
            ".tmp-{}",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("key")
        ));

        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(contents.as_bytes())?;
            f.sync_all()?;
        }

        if path.exists() {
            let bak = path.with_extension("bak");
            let _ = fs::remove_file(&bak);
            let _ = fs::rename(path, &bak);
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Write the three files for a key and refresh the index cache.
    pub fn save_key(
        &self,
        fpr: &str,
        public_armored: &str,
        secret_armored: Option<&str>,
        revocation_armored: Option<&str>,
    ) -> AppResult<()> {
        self.atomic_write(&self.pub_path(fpr), public_armored)?;
        if let Some(sec) = secret_armored {
            self.atomic_write(&self.sec_path(fpr), sec)?;
        }
        if let Some(rev) = revocation_armored {
            self.atomic_write(&self.rev_path(fpr), rev)?;
        }
        Ok(())
    }

    pub fn delete_key(&self, fpr: &str) -> AppResult<()> {
        for path in [self.pub_path(fpr), self.sec_path(fpr), self.rev_path(fpr)] {
            if path.exists() {
                let bak = path.with_extension("bak");
                let _ = fs::remove_file(&bak);
                fs::remove_file(&path)?;
            }
        }
        Ok(())
    }

    // -------------------------------------------------------------- index ----

    pub fn rebuild_index(&self) -> AppResult<Vec<IndexEntry>> {
        let mut entries = Vec::new();
        for fpr in self.stored_fprs() {
            if let Ok(key) = self.load_public(&fpr) {
                entries.push(crate::pgputil::index_entry(self, &key));
            }
        }
        let json = serde_json::to_string_pretty(&entries)?;
        let _ = self.atomic_write(&self.index_path(), &json); // cache; failure is non-fatal
        Ok(entries)
    }

    // ----------------------------------------------------------- settings ----

    pub fn save_settings(&self) -> AppResult<()> {
        let json = serde_json::to_string_pretty(&self.settings)?;
        self.atomic_write(&self.settings_path(), &json)
    }
}

/// Keep GUI-spawned console programs from flashing a console window on
/// Windows (icacls etc. are console apps; a GUI process spawning them without
/// CREATE_NO_WINDOW makes Windows briefly show a command prompt).
pub(crate) fn hide_console(cmd: &mut std::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = cmd;
}

fn load_settings(root: &Path) -> AppResult<Settings> {
    let path = root.join("settings.json");
    if !path.exists() {
        return Ok(Settings::default());
    }
    let raw = fs::read_to_string(&path)?;
    let s: Settings = serde_json::from_str(&raw).unwrap_or_default();
    Ok(s)
}

/// Verify the key store directory has a per-user profile ACL (plan §7 rule 4).
/// We do not rewrite the ACL - profile directories are per-user by default;
/// if something has opened the directory up we report it as a persistent
/// warning instead of hiding it.
fn check_acl(dir: &Path) -> AppResult<Option<String>> {
    let mut cmd = Command::new("icacls");
    cmd.arg(dir);
    hide_console(&mut cmd);
    let output = cmd
        .output()
        .map_err(|e| AppError::io(format!("ACL verification failed to run: {e}")))?;

    let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
    let too_open = text.contains("everyone")
        || text.contains("builtin\\users")
        || text.contains("authenticated users");
    if too_open {
        return Ok(Some(
            "The PGPBench key store is accessible to other users (unexpected ACL). \
             Consider tightening it: icacls \"%LOCALAPPDATA%\\PGPBench\""
                .into(),
        ));
    }
    Ok(None)
}
