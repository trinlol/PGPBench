# PocketPGP 0.1.3

A small fix release, delivered in-app to v0.1.1/v0.1.2 users.

## Fixed

- **Real error messages instead of `[object Object]`.** Tauri command failures arrive in the UI as structured `{ kind, message }` objects, and several error displays stringified them into "[object Object]", hiding the actual explanation. Every surface (Workbench, Keys, Settings) now shows the real message.
- **Actionable decryption errors.** A failed decrypt now says what to check: *"could not decrypt this message, it may not be encrypted to any key in your keyring, or the passphrase may be wrong"* (plus the technical detail), instead of a generic failure.

## Install

Already on v0.1.1 or later? Click **Update now** in the notification banner, signature-verified, installed, relaunch automatic. Otherwise grab the assets below.

| File | What |
|---|---|
| `PocketPGP_0.1.3_x64-setup.exe` | Installer, per-user, no admin prompt |
| `PocketPGP-0.1.3-win64-portable.zip` | Portable build, one exe |

## License

MIT OR Apache-2.0, your choice.
