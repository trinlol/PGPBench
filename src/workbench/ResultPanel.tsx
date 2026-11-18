/**
 * Result panel: monospace, scrollable output with an explicit [Copy] button.
 *
 * Ciphertext panels pass `autoClearSeconds` (they were auto-copied on produce);
 * plaintext panels never auto-copy - the copy only happens on the click, so
 * the label passed to `copyTextSecret` is what the Rust side records.
 */

import type { ReactNode } from "react";
import { Banner, CopyChip } from "../components/ui";
import { copyTextSecret } from "../ipc";

export function ResultPanel({
  title,
  value,
  copyLabel,
  autoClearSeconds = null,
  copyFailed = false,
  breakAll = false,
  note,
}: {
  title: string;
  value: string;
  /** Clipboard label (never the content) for the copy call. */
  copyLabel: string;
  /** Seconds until the clipboard self-clears, when the text was auto-copied. */
  autoClearSeconds?: number | null;
  copyFailed?: boolean;
  /** Break long unbroken tokens (ciphertext) instead of wrapping at words. */
  breakAll?: boolean;
  note?: ReactNode;
}) {
  return (
    <section className="rounded-xl border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-900">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold">{title}</h3>
        <div className="flex items-center gap-2">
          {autoClearSeconds !== null ? (
            <span className="text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
              auto-copied
            </span>
          ) : null}
          <CopyChip
            label="Copy"
            onCopy={async () => {
              await copyTextSecret(value, copyLabel);
            }}
          />
        </div>
      </div>

      <pre
        className={`max-h-72 overflow-auto whitespace-pre-wrap ${
          breakAll ? "break-all" : "break-words"
        } rounded-lg border border-neutral-200 bg-neutral-50 p-2.5 font-mono text-[12px] leading-relaxed text-neutral-800 dark:border-neutral-800 dark:bg-neutral-950 dark:text-neutral-200`}
      >
        {value}
      </pre>

      {autoClearSeconds !== null ? (
        <p className="mt-1.5 text-[11px] text-neutral-500 dark:text-neutral-400">
          Copied to clipboard (auto-clears
          {autoClearSeconds > 0 ? ` in ${autoClearSeconds}s` : " disabled"}).
        </p>
      ) : null}

      {copyFailed ? (
        <div className="mt-1.5">
          <Banner tone="warning">
            The clipboard write failed. Use the Copy button above, or check clipboard permissions.
          </Banner>
        </div>
      ) : null}

      {note}
    </section>
  );
}
