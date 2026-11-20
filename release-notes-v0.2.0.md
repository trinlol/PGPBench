# PGPBench 0.2.0

PocketPGP has been renamed to **PGPBench** to avoid a name collision with an existing project. Everything else works the same, and existing keyrings migrate automatically.

## Changed

- Renamed the application, installer, portable executable, repository, and Tauri bundle identifier (`com.pgpbench.desktop`) to **PGPBench**.
- Moved the default keyring directory from `%LOCALAPPDATA%\PocketPGP` to `%LOCALAPPDATA%\PGPBench`, with automatic one-time migration on startup if an existing `PocketPGP` folder is found.
- Renamed the store override environment variable to `PGPBENCH_DATA_DIR` (with `POCKETPGP_DATA_DIR` still honored as a fallback).

## Install

| File | What |
|---|---|
| `PGPBench_0.2.0_x64-setup.exe` | Installer, per-user, no admin prompt |
| `PGPBench-0.2.0-win64-portable.zip` | Portable build, one exe |

Note: because the Windows installer product name and bundle identifier changed, upgrading via the new `PGPBench_0.2.0_x64-setup.exe` installer installs PGPBench alongside any previous PocketPGP install; you can safely uninstall the old PocketPGP entry from Windows Settings afterwards (your keys remain intact under `%LOCALAPPDATA%\PGPBench`).

## License

MIT OR Apache-2.0, your choice.
