/**
 * App shell: two stable surfaces (Workbench + Keys), light/dark theme,
 * ACL warning banner. No menu proliferation (plan §10).
 */

import { useEffect, useState } from "react";
import { appInit, saveSettings } from "./ipc";
import { applyTheme, toggleTheme, type Theme } from "./theme";
import type { InitInfo } from "./types";
import { Banner, Spinner } from "./components/ui";
import { Workbench } from "./workbench/Workbench";
import { Keys } from "./keys/Keys";

type Tab = "workbench" | "keys";

export default function App() {
  const [tab, setTab] = useState<Tab>("workbench");
  const [theme, setTheme] = useState<Theme>("light");
  const [init, setInit] = useState<InitInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    appInit()
      .then((info) => {
        setInit(info);
        setTheme(info.settings.theme);
        applyTheme(info.settings.theme);
      })
      .catch((e) => setError(String(e)));
  }, []);

  const flipTheme = async () => {
    const next = toggleTheme(theme);
    setTheme(next);
    applyTheme(next);
    try {
      await saveSettings({
        theme: next,
        clipboard_clear_seconds: init?.settings.clipboard_clear_seconds ?? 60,
        default_profile: init?.settings.default_profile ?? "compatible",
      });
    } catch {
      /* theme stays applied locally even if persisting fails */
    }
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
            <span
              className="hidden max-w-[220px] truncate text-[11px] text-neutral-400 dark:text-neutral-500 sm:block"
              title={init.data_dir}
            >
              {init.data_dir}
            </span>
          ) : null}
          <button
            className="rounded-lg p-2 text-neutral-500 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-neutral-800"
            onClick={flipTheme}
            aria-label="Toggle theme"
          >
            {theme === "dark" ? (
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

      {/* ACL warning (persistent until the user fixes the directory) */}
      {init && !init.acl_ok ? (
        <div className="mb-4">
          <Banner tone="danger" title="Key store ACL warning">
            {init.acl_note}
          </Banner>
        </div>
      ) : null}

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
