/**
 * Small, dependency-free helpers shared by the Keys surface components.
 * Parsing stays intentionally loose - a user id is "Name (comment) <email>"
 * but we never trust that shape.
 */

import type { KeySummary } from "../types";

export function parseUid(uid: string): { name: string; email: string | null } {
  const m = uid.match(/^(.*?)\s*<([^>]*)>\s*$/);
  if (m) {
    const name = m[1].trim();
    const email = m[2].trim();
    return { name: name || uid.trim(), email: email || null };
  }
  return { name: uid.trim(), email: null };
}

/** Preferred short label for a key (first uid's name, falling back to fpr). */
export function keyLabel(key: KeySummary): string {
  const first = key.uids[0];
  if (first) {
    const { name, email } = parseUid(first);
    if (name) return name;
    if (email) return email;
  }
  return key.fpr.slice(-8);
}

export function keyStatus(key: Pick<KeySummary, "revoked" | "expired">): "valid" | "expired" | "revoked" {
  if (key.revoked) return "revoked";
  if (key.expired) return "expired";
  return "valid";
}

/** Expires in the future and within `days`; "never" keys never expire. */
export function isExpiringSoon(key: KeySummary, days = 90): boolean {
  if (key.expires === null) return false;
  const now = Math.floor(Date.now() / 1000);
  const window = days * 86400;
  return key.expires > now && key.expires - now <= window;
}

export function matchesQuery(key: KeySummary, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  const fprQuery = q.replace(/\s+/g, "");
  if (fprQuery && key.fpr.toLowerCase().includes(fprQuery)) return true;
  return key.uids.some((uid) => uid.toLowerCase().includes(q));
}

/** yyyy-mm-dd in local time, for <input type="date"> min attributes. */
export function todayIso(): string {
  const now = new Date();
  return new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
}

/** Trimmed string or null - the IPC contract uses null for "absent". */
export function trimmedOrNull(value: string): string | null {
  const t = value.trim();
  return t.length > 0 ? t : null;
}

export type StrengthLabel = "weak" | "fair" | "good" | "strong";

export interface PassphraseStrength {
  score: number;
  label: StrengthLabel;
  /** Tailwind background class for the meter bars. */
  barClass: string;
  /** Tailwind text class for the label. */
  textClass: string;
}

/**
 * Deliberately simple heuristic: length milestones plus character classes.
 * Not a real entropy estimate - just enough to nudge better passphrases.
 */
export function passphraseStrength(pw: string): PassphraseStrength {
  let score = 0;
  if (pw.length >= 8) score += 1;
  if (pw.length >= 12) score += 1;
  if (pw.length >= 16) score += 1;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  if (classes >= 2) score += 1;
  if (classes >= 3) score += 1;
  score = Math.min(score, 4);

  if (!pw) {
    return { score: 0, label: "weak", barClass: "bg-neutral-300 dark:bg-neutral-700", textClass: "text-neutral-400" };
  }
  if (score <= 1) {
    return { score, label: "weak", barClass: "bg-red-500", textClass: "text-red-600 dark:text-red-400" };
  }
  if (score === 2) {
    return { score, label: "fair", barClass: "bg-amber-500", textClass: "text-amber-600 dark:text-amber-400" };
  }
  if (score === 3) {
    return { score, label: "good", barClass: "bg-sky-500", textClass: "text-sky-600 dark:text-sky-400" };
  }
  return { score, label: "strong", barClass: "bg-emerald-500", textClass: "text-emerald-600 dark:text-emerald-400" };
}
