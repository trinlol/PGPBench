# PocketPGP 0.1.1

Maintenance release, brings the recent feature work into the released app and adds **in-app updates**.

## New in this version

- **In-app updates (new).** When a newer release exists, the app shows a notification with an *Update now* button: the update is downloaded from GitHub, verified against a minisign public key baked into the app, installed silently, and the app relaunches into the new version. The check runs on launch and can be disabled in Settings (there is also a *Check for updates now* button). This is the app's single possible network call, nothing is ever transmitted but the request itself, no telemetry, no identifiers, and your keys never touch the network.
  *(Updaters start with this version: if you installed v0.1.0, grab this one manually one last time; from v0.1.1 onward updates arrive in-app.)*
- **Key renaming.** Keys tab → *Details* → *Rename*: adds a freshly self-signed primary User ID and demotes the old one, the OpenPGP-native way names work, matching `gpg --quick-add-uid`. The fingerprint never changes; peers see the new name once you share the updated public key. Verified against GnuPG 2.5.24 (it recognizes the new name as primary immediately).
- **"Open key folder" buttons.** Keys automatically save to `%LOCALAPPDATA%\PocketPGP\keys\`, now you can jump straight there from the header path, the post-generation panel, and each key's details. The header path itself became clickable.
- **Theme follows Windows.** The app now defaults to your Windows light/dark setting and follows it live; the header toggle pins an explicit choice, and Settings can return it to automatic.
- **README badge fix** and verified dark-mode screenshots (demo keyring - no real key material).

## Downloads

| File | What |
|---|---|
| `PocketPGP_0.1.1_x64-setup.exe` | Installer, per-user, no admin prompt, Start-menu entries + uninstaller |
| `PocketPGP-0.1.1-win64-portable.zip` | Portable build, one exe, no install, needs the WebView2 Runtime |

## Security posture (unchanged where it matters)

- Private keys stay passphrase-encrypted **at rest, every packet** (primary + subkeys); plaintext secrets never touch disk.
- Decrypt-then-verify always; verification shows fingerprint + key source, no invented trust model.
- Clipboard writes keep the Windows "secret" hint (excluded from Win+V history and cloud sync) and auto-clear.
- Hard rejects unchanged: DSA/Elgamal, secp256k1, v2/v3 keys, legacy keys without key-flag subpackets (overridable under Advanced).
- The interop test matrix still passes all 14 cases against GnuPG 2.5.24; the full Rust test suite (now 14 tests, including rename round-trips) runs on every push via CI.

## License

MIT OR Apache-2.0, your choice.
