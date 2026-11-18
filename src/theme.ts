/**
 * Light/dark theme handling. The class lives on <html> so the Tailwind
 * `dark:` variant (custom class strategy in styles.css) applies everywhere.
 */

import type { Settings } from "./types";

export type Theme = Settings["theme"];

export function applyTheme(theme: Theme) {
  const root = document.documentElement;
  root.classList.toggle("dark", theme === "dark");
}

export function toggleTheme(current: Theme): Theme {
  return current === "dark" ? "light" : "dark";
}
