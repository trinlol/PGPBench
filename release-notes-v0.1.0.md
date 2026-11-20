# PocketPGP 0.1.0

First public release. A minimal, modern, **fully-offline** OpenPGP app for Windows, clipboard-first, with no UI bloat.

![no network](https://img.shields.io/badge/network-calls-0%20ever-success)

## What's inside

- **Workbench**, one paste surface that auto-detects what you pasted:
  - `-----BEGIN PGP MESSAGE-----` → *Decrypt & Verify* (in-app passphrase modal → plaintext + signature banner)
  - `-----BEGIN PGP SIGNED MESSAGE-----` → *Verify* (signer fingerprint, key source, date)
  - public/private key blocks → *Import* (parse → verify self-signatures → preview → confirm)
  - plain text → compose: pick recipients (encrypt-to-self on by default), *Encrypt & copy*
  - whitespace-mangled armor from chat apps still parses, even a CRC24 checksum fused into the base64 is recovered
- **Keys**, flat searchable keyring with filter chips; generate keys with an always-asked expiry (ECC Curve25519 default, RSA-3072/4096 under Advanced); copy public/private in one click; change passphrase, extend expiry, generate revocation certificates; every generated key is offered its revocation certificate immediately
- **Interoperability profiles**, Compatible (v4) by default so your keys work everywhere (GnuPG, Thunderbird, Mailvelope); RFC 9580 (v6) as an experimental opt-in
- **Theme follows Windows** out of the box; pin light/dark with one click
- **Open key folder** buttons, keys auto-save to `%LOCALAPPDATA%\PocketPGP\keys\` as human-readable armored files, and you can jump straight there from the UI

## Security posture

- Zero network calls. Keys enter only by paste/import.
- Single engine: [rPGP](https://github.com/rpgp/rpgp) 0.21 (native Rust), no JS crypto, no WASM in the CSP.
- Private keys passphrase-encrypted **at rest**, every packet (primary + subkeys); plaintext secrets never touch disk.
- Decrypt-then-verify always; verification shows fingerprint + key source, no invented trust model.
- Clipboard writes use the Windows "secret" hint (excluded from Win+V history and cloud sync) and auto-clear after a configurable timer; the clipboard is only read on an explicit click.
- Hard rejects with clear messages: DSA/Elgamal, secp256k1, v2/v3 keys, legacy keys without key-flag subpackets (overridable under Advanced).
- Atomic keyring writes with one `.bak`; store ACL verified at startup.

## Interop-tested

All 14 cases of the interop matrix pass against **GnuPG 2.5.24**, key imports both directions, sign+encrypt round-trips, clearsign, old RSA keys, bumped subkey expiry, revoked-key blocking, oversized/garbled paste rejection, and mangled armor. Run it yourself: `powershell -File tests\interop.ps1`.

## Downloads

| File | What |
|---|---|
| `PocketPGP_0.1.0_x64-setup.exe` | Installer, per-user, no admin prompt, adds Start-menu entries + uninstaller |
| `PocketPGP-0.1.0-win64-portable.zip` | Portable build, one exe, no install, needs the WebView2 Runtime (preinstalled on current Windows 10/11) |

## Known limitations (v1)

No symmetric/password-only mode, no smartcards/YubiKey, no X.509/S-MIME, no web-of-trust UI, no file/archive encryption, no keyserver/WKD lookups. Binary output is base64-wrapped for clipboard transport. No "remember passphrase", every operation prompts.

## License

MIT OR Apache-2.0, your choice.
