/**
 * Theme handling. "system" follows the Windows theme (via the webview's
 * prefers-color-scheme, which tracks the OS app-mode setting) until the
 * user explicitly picks Light or Dark. The class lives on <html> so the
 * Tailwind `dark:` variant (custom class strategy in styles.css) applies.
 */

import type { Settings } from "./types";

export type ThemePref = Settings["theme"];
export type ResolvedTheme = "light" | "dark";

/** Resolve a preference to a concrete theme. */
export function resolvedTheme(pref: ThemePref): ResolvedTheme {
  if (pref !== "system") return pref;
  if (typeof window !== "undefined" && window.matchMedia) {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  return "light";
}

/** Apply a preference; returns the resolved theme. */
export function applyTheme(pref: ThemePref): ResolvedTheme {
  const resolved = resolvedTheme(pref);
  const root = document.documentElement;
  root.classList.toggle("dark", resolved === "dark");
  return resolved;
}

/** Subscribe to OS theme changes while in "system" mode. Returns cleanup. */
export function watchSystemTheme(onChange: (resolved: ResolvedTheme) => void): () => void {
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  const listener = () => onChange(resolvedTheme("system"));
  mq.addEventListener?.("change", listener);
  return () => mq.removeEventListener?.("change", listener);
}
