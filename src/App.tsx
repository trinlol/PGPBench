/**
 * App shell: two stable surfaces (Workbench + Keys), light/dark theme,
 * ACL warning banner. No menu proliferation (plan §10).
 */

import { useEffect, useState } from "react";
import { appInit, openKeyFolder, saveSettings } from "./ipc";
import { checkForUpdates, installUpdate, type UpdateInfo } from "./updater";
import {
  applyTheme,
  watchSystemTheme,
  type ResolvedTheme,
  type ThemePref,
} from "./theme";
import type { InitInfo, Profile, Settings } from "./types";
import { errText } from "./errors";
import { Banner, Button, Field, inputClass, Modal, Spinner } from "./components/ui";
import { Workbench } from "./workbench/Workbench";
import { Keys } from "./keys/Keys";

type Tab = "workbench" | "keys";

export default function App() {
  const [tab, setTab] = useState<Tab>("workbench");
  /** The stored preference: "system" follows Windows until the user picks. */
  const [themePref, setThemePref] = useState<ThemePref>("system");
  /** What is actually displayed right now. */
  const [resolved, setResolved] = useState<ResolvedTheme>("light");
  const [init, setInit] = useState<InitInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [clearSeconds, setClearSeconds] = useState(60);
  const [defaultProfile, setDefaultProfile] = useState<Profile>("compatible");
  const [checkUpdates, setCheckUpdates] = useState(true);
  /** Update banner state. */
  const [updateAvailable, setUpdateAvailable] = useState<UpdateInfo | null>(null);
  const [updating, setUpdating] = useState(false);
  const [updateProgress, setUpdateProgress] = useState<string | null>(null);
  const [updateError, setUpdateError] = useState<string | null>(null);
  const [manualCheckResult, setManualCheckResult] = useState<string | null>(null);

  useEffect(() => {
    appInit()
      .then((info) => {
        setInit(info);
        setThemePref(info.settings.theme);
        setClearSeconds(info.settings.clipboard_clear_seconds);
        setDefaultProfile(info.settings.default_profile);
        setCheckUpdates(info.settings.check_updates_on_launch);
      })
      .catch((e) => setError(String(e)));
  }, []);

  // Optional launch-time update check: the app's only network call, off by
  // a Settings toggle. Silent on failure (offline, no manifest yet).
  useEffect(() => {
    if (!init?.settings.check_updates_on_launch) return;
    void checkForUpdates().then((info) => {
      if (info) setUpdateAvailable(info);
    });
  }, [init]);

  // Apply the preference; while it is "system", keep following Windows live
  // (the webview's prefers-color-scheme tracks the OS app-mode setting).
  useEffect(() => {
    setResolved(applyTheme(themePref));
    if (themePref !== "system") return;
    return watchSystemTheme((r) => setResolved(r));
  }, [themePref]);

  const persist = (patch: Partial<Settings>) => {
    const next: Settings = {
      theme: themePref,
      clipboard_clear_seconds: clearSeconds,
      default_profile: defaultProfile,
      check_updates_on_launch: checkUpdates,
      ...patch,
    };
    if (patch.theme !== undefined) setThemePref(patch.theme);
    if (patch.check_updates_on_launch !== undefined) setCheckUpdates(patch.check_updates_on_launch);
    setClearSeconds(next.clipboard_clear_seconds);
    setDefaultProfile(next.default_profile);
    return saveSettings(next).catch(() => {
      /* settings stay applied locally even if persisting fails */
    });
  };

  /** Run the update: download + verify signature + install + relaunch. */
  const runUpdate = async () => {
    setUpdating(true);
    setUpdateError(null);
    setUpdateProgress("Downloading update...");
    try {
      await installUpdate((downloaded, total) => {
        const mb = (n: number) => (n / (1024 * 1024)).toFixed(1);
        setUpdateProgress(
          total && total > 0
            ? `Downloading update... ${mb(downloaded)} / ${mb(total)} MB`
            : `Downloading update... ${mb(downloaded)} MB`,
        );
      });
      // On success the app relaunches; nothing after this line runs.
    } catch (err) {
      setUpdateError(errText(err));
      setUpdating(false);
      setUpdateProgress(null);
    }
  };

  /** Manual check from the Settings dialog. */
  const runManualCheck = async () => {
    setManualCheckResult("Checking...");
    const info = await checkForUpdates();
    if (info) {
      setManualCheckResult(null);
      setUpdateAvailable(info);
      setSettingsOpen(false);
    } else {
      setManualCheckResult("You are up to date.");
    }
  };

  /** Manual toggle: pin the opposite of what is currently displayed. */
  const flipTheme = () => {
    void persist({ theme: resolved === "dark" ? "light" : "dark" });
  };

  return (
    <div className="mx-auto flex h-full max-w-5xl flex-col px-4 py-4">
      {/* Header */}
      <header className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-500 to-purple-500 text-white shadow-sm">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4">
              <circle cx="8" cy="8" r="4.2" />
              <path d="M11.5 11.5L20 20M17 17v3M20.5 17v2.2" />
            </svg>
          </div>
          <div>
            <h1 className="text-base font-semibold leading-tight">PocketPGP</h1>
            <p className="text-[11px] leading-tight text-neutral-500 dark:text-neutral-400">
              offline OpenPGP · clipboard-first
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {init ? (
            <button
              className="hidden max-w-[260px] items-center gap-1 truncate rounded px-1.5 py-1 text-[11px] text-neutral-400 transition-colors hover:bg-neutral-100 hover:text-neutral-700 dark:text-neutral-500 dark:hover:bg-neutral-800 dark:hover:text-neutral-300 sm:flex"
              title={`${init.data_dir} — click to open`}
              onClick={() => void openKeyFolder(null)}
            >
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="shrink-0">
                <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" />
              </svg>
              <span className="truncate">{init.data_dir}</span>
            </button>
          ) : null}
          <button
            className="rounded-lg p-2 text-neutral-500 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-neutral-800"
            onClick={() => setSettingsOpen(true)}
            aria-label="Settings"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.9 2.9l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.2a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.9-2.9l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.2a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.9-2.9l.1.1a1.7 1.7 0 0 0 1.9.3h.1a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.2a1.7 1.7 0 0 0 1 1.5h.1a1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.9 2.9l-.1.1a1.7 1.7 0 0 0-.3 1.9v.1a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.2a1.7 1.7 0 0 0-1.5 1z" />
            </svg>
          </button>
          <button
            className="rounded-lg p-2 text-neutral-500 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-neutral-800"
            onClick={flipTheme}
            aria-label="Toggle theme"
            title={
              themePref === "system"
                ? `Following your Windows theme (${resolved}). Click to pin ${resolved === "dark" ? "light" : "dark"} mode.`
                : `Switch to ${resolved === "dark" ? "light" : "dark"} mode`
            }
          >
            {resolved === "dark" ? (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="4" />
                <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
              </svg>
            ) : (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z" />
              </svg>
            )}
          </button>
        </div>
      </header>

      {/* Tab bar */}
      <nav className="mb-4 flex gap-1 rounded-xl bg-neutral-100 p-1 dark:bg-neutral-800/70">
        {(
          [
            ["workbench", "Workbench"],
            ["keys", "Keys"],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            className={
              "flex-1 rounded-lg px-3 py-2 text-sm font-medium transition-colors " +
              (tab === id
                ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-900 dark:text-neutral-100"
                : "text-neutral-500 hover:text-neutral-800 dark:text-neutral-400 dark:hover:text-neutral-200")
            }
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </nav>

      {/* Update notification (when a newer signed release exists) */}
      {updateAvailable && !updating ? (
        <div className="mb-4">
          <Banner
            tone="info"
            title={`PocketPGP ${updateAvailable.version} is available`}
          >
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <Button variant="primary" onClick={() => void runUpdate()}>
                Update now
              </Button>
              <Button variant="ghost" onClick={() => setUpdateAvailable(null)}>
                Not now
              </Button>
            </div>
            <p className="mt-1 text-[11px] opacity-70">
              Downloads from github.com/trinlol/PocketPGP and verifies a cryptographic
              signature before installing.
            </p>
          </Banner>
        </div>
      ) : null}
      {updating ? (
        <div className="mb-4">
          <Banner tone="info" title={updateProgress ?? "Updating..."}>
            <div className="mt-1 flex items-center gap-2 text-xs">
              <Spinner /> The app will restart automatically when the update is
              installed. Do not close the window.
            </div>
          </Banner>
        </div>
      ) : null}
      {updateError ? (
        <div className="mb-4">
          <Banner tone="danger" title="Update failed">
            {updateError}
            <div className="mt-1">
              <Button onClick={() => setUpdateError(null)}>Dismiss</Button>
            </div>
          </Banner>
        </div>
      ) : null}

      {/* ACL warning (persistent until the user fixes the directory) */}
      {init && !init.acl_ok ? (
        <div className="mb-4">
          <Banner tone="danger" title="Key store ACL warning">
            {init.acl_note}
          </Banner>
        </div>
      ) : null}

      {/* Settings: clipboard auto-clear + default profile (plan §8) */}
      <Modal open={settingsOpen} onClose={() => setSettingsOpen(false)} title="Settings">
        <div className="space-y-4">
          <Field
            label="Theme"
            hint={
              themePref === "system"
                ? `Currently following your Windows theme (${resolved} mode).`
                : undefined
            }
          >
            <select
              className={inputClass}
              value={themePref}
              onChange={(e) => void persist({ theme: e.target.value as Settings["theme"] })}
            >
              <option value="system">Match Windows theme</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          </Field>
          <Field label="Updates">
            <div className="space-y-2">
              <label className="flex items-center gap-2 text-sm text-neutral-700 dark:text-neutral-300">
                <input
                  type="checkbox"
                  className="h-4 w-4 accent-indigo-600"
                  checked={checkUpdates}
                  onChange={(e) => void persist({ check_updates_on_launch: e.target.checked })}
                />
                Check for updates on launch
              </label>
              <div className="flex items-center gap-2">
                <Button onClick={() => void runManualCheck()} disabled={manualCheckResult === "Checking..."}>
                  Check for updates now
                </Button>
                {manualCheckResult ? (
                  <span className="text-xs text-neutral-500 dark:text-neutral-400">
                    {manualCheckResult}
                  </span>
                ) : null}
              </div>
              {manualCheckResult && manualCheckResult !== "Checking..." ? (
                <button
                  className="text-[11px] text-neutral-400 underline underline-offset-2 hover:text-neutral-600 dark:hover:text-neutral-300"
                  onClick={() => setManualCheckResult(null)}
                >
                  clear
                </button>
              ) : null}
            </div>
          </Field>
          <Field
            label="Clipboard auto-clear (seconds)"
            hint="Sensitive copies (ciphertext, keys, decrypted text) are written with the Windows 'secret' hint and cleared automatically after this many seconds. 0 disables auto-clear."
          >
            <input
              type="number"
              min={0}
              max={3600}
              className={inputClass}
              value={clearSeconds}
              onChange={(e) => setClearSeconds(Math.max(0, Math.min(3600, Number(e.target.value) || 0)))}
              onBlur={() => void persist({})}
            />
          </Field>
          <Field label="Default profile" hint="Pre-selected in the Workbench Advanced panel and the generate dialog.">
            <select
              className={inputClass}
              value={defaultProfile}
              onChange={(e) => void persist({ default_profile: e.target.value as Profile })}
            >
              <option value="compatible">Compatible (v4, works everywhere)</option>
              <option value="rfc9580">RFC 9580 (v6, experimental)</option>
            </select>
          </Field>
          <div className="flex justify-end">
            <Button variant="primary" onClick={() => setSettingsOpen(false)}>
              Done
            </Button>
          </div>
        </div>
      </Modal>

      {/* Surfaces */}
      <main className="min-h-0 flex-1">
        {error ? (
          <Banner tone="danger" title="Startup error">
            {error}
          </Banner>
        ) : !init ? (
          <div className="flex h-full items-center justify-center text-neutral-400">
            <Spinner />
          </div>
        ) : tab === "workbench" ? (
          <Workbench defaultProfile={init.settings.default_profile} onOpenKeys={() => setTab("keys")} />
        ) : (
          <Keys defaultProfile={init.settings.default_profile} />
        )}
      </main>
    </div>
  );
}
