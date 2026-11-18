//! PocketPGP - a minimal, modern, fully-offline OpenPGP app for Windows.
//!
//! Architecture (plan §3):
//!   webview (Workbench / Keys) -> Tauri command layer -> rPGP Rust core
//!
//! All secrets live only in the Rust core, memory-scoped per operation.
//! Zero network calls. Single engine: rPGP.

mod armorfix;
mod commands;
mod error;
mod keygen;
mod msgops;
mod pgputil;
mod store;

pub use error::{AppError, AppResult};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Fail fast and loudly if the key store cannot be established safely.
    let store = match store::Store::init() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("PocketPGP: refusing to start: {e}");
            std::process::exit(1);
        }
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(commands::AppState(std::sync::Mutex::new(store)))
        .invoke_handler(tauri::generate_handler![
            commands::app_init,
            commands::save_settings,
            commands::list_keys,
            commands::key_details,
            commands::generate_key,
            commands::import_key,
            commands::export_public,
            commands::delete_key,
            commands::encrypt,
            commands::decrypt,
            commands::sign,
            commands::verify,
            commands::generate_revocation,
            commands::change_passphrase,
            commands::extend_expiry,
            commands::copy_key_to_clipboard,
            commands::copy_text_secret,
        ])
        .run(tauri::generate_context!())
        .expect("error while running PocketPGP");
}
