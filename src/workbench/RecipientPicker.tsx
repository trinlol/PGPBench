/**
 * Recipient picker for compose mode: multi-select over the keyring plus an
 * optional one-off pasted public key that is never stored.
 */

import type { KeySummary } from "../types";
import { Badge, Disclosure, Fingerprint, Spinner, StatusDot, inputClass } from "../components/ui";

function statusOf(key: KeySummary): "valid" | "expired" | "revoked" {
  if (key.revoked) return "revoked";
  if (key.expired) return "expired";
  return "valid";
}

export function RecipientPicker({
  keys,
  loading,
  selected,
  onToggle,
  selfFpr,
  oneOff,
  onOneOff,
  disabled,
}: {
  keys: KeySummary[];
  loading: boolean;
  selected: Set<string>;
  onToggle: (fpr: string) => void;
  /** The own key used for encrypt-to-self (highlighted, not special-cased). */
  selfFpr: string | null;
  oneOff: string;
  onOneOff: (value: string) => void;
  disabled: boolean;
}) {
  return (
    <section className="rounded-xl border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-900">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h3 className="text-sm font-semibold">Recipients</h3>
        <span className="text-[11px] text-neutral-500 dark:text-neutral-400">
          {selected.size} selected
        </span>
      </div>

      {loading ? (
        <div className="flex items-center gap-2 py-2 text-xs text-neutral-500 dark:text-neutral-400">
          <Spinner />
          Loading keyring…
        </div>
      ) : keys.length === 0 ? (
        <p className="py-1 text-xs text-neutral-500 dark:text-neutral-400">
          Your keyring is empty. Generate or import a key in the <strong>Keys</strong> tab, or paste a
          one-off public key below.
        </p>
      ) : (
        <div className="max-h-64 space-y-1 overflow-y-auto pr-0.5">
          {keys.map((key) => {
            const usable = key.can_encrypt && !key.expired && !key.revoked;
            const checked = selected.has(key.fpr);
            return (
              <label
                key={key.fpr}
                className={
                  "flex items-start gap-2.5 rounded-lg border px-2 py-1.5 transition-colors " +
                  (usable
                    ? "cursor-pointer border-transparent hover:border-neutral-200 hover:bg-neutral-50 dark:hover:border-neutral-700 dark:hover:bg-neutral-800/60"
                    : "cursor-not-allowed border-transparent opacity-60")
                }
              >
                <input
                  type="checkbox"
                  className="mt-1 accent-indigo-600"
                  checked={checked}
                  disabled={disabled || !usable}
                  onChange={() => onToggle(key.fpr)}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="truncate text-sm font-medium text-neutral-800 dark:text-neutral-200">
                      {key.uids[0] ?? key.fpr}
                    </span>
                    {key.fpr === selfFpr ? <Badge tone="indigo">you</Badge> : null}
                    <Badge>{key.algo}</Badge>
                    <Badge tone={key.source === "own" ? "emerald" : "neutral"}>{key.source}</Badge>
                    {key.expired ? <Badge tone="amber">expired</Badge> : null}
                    {key.revoked ? <Badge tone="red">revoked</Badge> : null}
                    {!key.can_encrypt ? <Badge tone="amber">no encryption key</Badge> : null}
                  </div>
                  <div className="mt-0.5 flex items-center gap-1.5">
                    <StatusDot status={statusOf(key)} />
                    <Fingerprint fpr={key.fpr} />
                  </div>
                </div>
              </label>
            );
          })}
        </div>
      )}

      <div className="mt-2">
        <Disclosure
          label={
            <span className="text-xs">
              Paste one-off public key
              {oneOff.trim() ? " · included" : ""}
            </span>
          }
        >
          <textarea
            className={`${inputClass} min-h-[90px] font-mono text-[11px] leading-relaxed`}
            spellCheck={false}
            placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
            value={oneOff}
            disabled={disabled}
            onChange={(e) => onOneOff(e.target.value)}
          />
          <p className="mt-1 text-[11px] text-neutral-500 dark:text-neutral-400">
            Used for this message only, never saved to the keyring.
          </p>
        </Disclosure>
      </div>
    </section>
  );
}
