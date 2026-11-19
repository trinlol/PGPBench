/**
 * One key in the flat list. Owns only its own "copied" feedback for the
 * public-key copy; private copy and delete require a confirmation owned by
 * the Keys surface (exactly one prompt, plan §10).
 */

import { useEffect, useRef, useState } from "react";
import type { KeySummary } from "../types";
import { copyKeyToClipboard, copyTextSecret } from "../ipc";
import { Badge, Fingerprint, Spinner, StatusDot, formatDate } from "../components/ui";
import { errText } from "../errors";
import { isExpiringSoon, keyStatus, parseUid } from "./keyUtils";

export function KeyRow({
  keySummary,
  expanded,
  busy,
  onToggleDetails,
  onCopyPrivate,
  onDelete,
  onError,
}: {
  keySummary: KeySummary;
  expanded: boolean;
  busy: boolean;
  onToggleDetails: () => void;
  onCopyPrivate: () => void;
  onDelete: () => void;
  onError: (message: string) => void;
}) {
  const [copiedPublic, setCopiedPublic] = useState(false);
  const copyTimer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(copyTimer.current), []);

  const uid = keySummary.uids[0] ?? "";
  const { name, email } = parseUid(uid);
  const status = keyStatus(keySummary);
  const expiring = isExpiringSoon(keySummary);

  const copyPublic = async () => {
    try {
      await copyKeyToClipboard(keySummary.fpr, "public");
      setCopiedPublic(true);
      window.clearTimeout(copyTimer.current);
      copyTimer.current = window.setTimeout(() => setCopiedPublic(false), 1500);
    } catch (err) {
      onError(`Could not copy the public key: ${errText(err)}`);
    }
  };

  return (
    <div className="flex flex-wrap items-start gap-x-3 gap-y-2.5 px-4 py-3.5">
      <div className="mt-1.5">
        {busy ? <Spinner /> : <StatusDot status={status} />}
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="max-w-full truncate text-sm font-semibold" title={keySummary.uids.join("\n") || keySummary.fpr}>
            {name || "unnamed key"}
          </span>
          {email ? (
            <span className="max-w-full truncate text-xs text-neutral-500 dark:text-neutral-400" title={uid}>
              &lt;{email}&gt;
            </span>
          ) : null}

          <Badge>{keySummary.algo}</Badge>

          {keySummary.profile === "rfc9580" ? (
            <span title="RFC 9580 (v6) - experimental; not every OpenPGP tool can read v6 keys.">
              <Badge tone="amber">RFC 9580</Badge>
            </span>
          ) : (
            <span title="Compatible (v4) - works with every widely used OpenPGP implementation.">
              <Badge tone="neutral">v4</Badge>
            </span>
          )}

          {status === "revoked" ? <Badge tone="red">revoked</Badge> : null}
          {status === "expired" ? <Badge tone="amber">expired</Badge> : null}
          {status === "valid" && expiring ? (
            <span title="Expires within the next 90 days.">
              <Badge tone="amber">expiring soon</Badge>
            </span>
          ) : null}

          {keySummary.has_secret ? (
            <span
              className="inline-flex items-center text-neutral-400 dark:text-neutral-500"
              title="Private key stored on this device"
              aria-label="Private key stored on this device"
            >
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="8" cy="8" r="4.2" />
                <path d="M11.5 11.5L20 20M17 17v3M20.5 17v2.2" />
              </svg>
            </span>
          ) : null}
        </div>

        <div className="mt-1.5 flex flex-wrap items-center gap-x-2.5 gap-y-1">
          <Fingerprint
            fpr={keySummary.fpr}
            onCopy={async () => {
              await copyTextSecret(keySummary.fpr, "Fingerprint");
            }}
          />
          <span className="text-xs text-neutral-300 dark:text-neutral-600">·</span>
          <span
            className={
              "text-xs " +
              (status === "expired"
                ? "text-amber-600 dark:text-amber-400"
                : status === "revoked"
                  ? "text-red-600 dark:text-red-400"
                  : expiring
                    ? "text-amber-600 dark:text-amber-400"
                    : "text-neutral-500 dark:text-neutral-400")
            }
          >
            {keySummary.expires === null
              ? "never expires"
              : status === "expired"
                ? `expired ${formatDate(keySummary.expires)}`
                : `expires ${formatDate(keySummary.expires)}`}
          </span>
          <span className="text-xs text-neutral-300 dark:text-neutral-600">·</span>
          <span className="text-xs text-neutral-500 dark:text-neutral-400">
            created {formatDate(keySummary.created)}
          </span>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-end gap-1">
        <RowAction onClick={() => void copyPublic()} disabled={busy}>
          {copiedPublic ? (
            <>
              <svg width="12" height="12" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M2 8l3.5 3.5L12 3.5" />
              </svg>
              Copied
            </>
          ) : (
            <>Copy public</>
          )}
        </RowAction>

        {keySummary.has_secret ? (
          <RowAction onClick={onCopyPrivate} disabled={busy}>
            Copy private
          </RowAction>
        ) : null}

        <RowAction onClick={onToggleDetails} disabled={busy} aria-expanded={expanded}>
          {expanded ? "Hide details" : "Details"}
        </RowAction>

        <RowAction onClick={onDelete} disabled={busy} tone="danger">
          Delete
        </RowAction>
      </div>
    </div>
  );
}

function RowAction({
  onClick,
  disabled,
  children,
  tone = "neutral",
  ...rest
}: {
  onClick: () => void;
  disabled?: boolean;
  children: React.ReactNode;
  tone?: "neutral" | "danger";
} & Pick<React.ButtonHTMLAttributes<HTMLButtonElement>, "aria-expanded">) {
  return (
    <button
      className={
        "inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium transition-colors disabled:pointer-events-none disabled:opacity-50 " +
        (tone === "danger"
          ? "text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-950/40"
          : "text-neutral-600 hover:bg-neutral-100 dark:text-neutral-300 dark:hover:bg-neutral-800")
      }
      onClick={onClick}
      disabled={disabled}
      {...rest}
    >
      {children}
    </button>
  );
}
