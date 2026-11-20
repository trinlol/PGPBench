# PocketPGP 0.1.2

A small fix release, the first one delivered **in-app**: if you're on v0.1.1, PocketPGP will offer this update on its own (Settings → *Check for updates now*, or wait for the launch check).

## Fixed

- **No more console window flash on launch.** The startup ACL verification shells out to `icacls.exe`, a console program, spawned without `CREATE_NO_WINDOW` it made Windows briefly show a command prompt. All process spawns now run hidden.

## Install

Already on v0.1.1? Click **Update now** in the banner (or Settings → *Check for updates now*), the update is downloaded, signature-verified, installed, and the app relaunches by itself.

Coming from v0.1.0 or the portable build? Grab the assets below as usual:

| File | What |
|---|---|
| `PocketPGP_0.1.2_x64-setup.exe` | Installer, per-user, no admin prompt, Start-menu entries + uninstaller |
| `PocketPGP-0.1.2-win64-portable.zip` | Portable build, one exe, needs the WebView2 Runtime |

## License

MIT OR Apache-2.0, your choice.
