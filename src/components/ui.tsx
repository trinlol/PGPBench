/**
 * Thin, hand-rolled UI primitives (plan: no heavy component library).
 * Everything is Tailwind classes on plain elements - deliberately boring,
 * deliberately small.
 */

import { useEffect, useRef, useState } from "react";

// ---------------------------------------------------------------------------
// Button
// ---------------------------------------------------------------------------

type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";

export function Button({
  variant = "secondary",
  className = "",
  children,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  const base =
    "inline-flex items-center justify-center gap-1.5 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors disabled:opacity-50 disabled:pointer-events-none select-none";
  const styles: Record<ButtonVariant, string> = {
    primary: "bg-indigo-600 text-white hover:bg-indigo-500 active:bg-indigo-700",
    secondary:
      "bg-neutral-100 text-neutral-800 hover:bg-neutral-200 dark:bg-neutral-800 dark:text-neutral-200 dark:hover:bg-neutral-700 border border-neutral-200 dark:border-neutral-700",
    danger: "bg-red-600 text-white hover:bg-red-500 active:bg-red-700",
    ghost:
      "text-neutral-600 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-neutral-800",
  };
  return (
    <button className={`${base} ${styles[variant]} ${className}`} {...rest}>
      {children}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Banner (verification results, warnings, ACL note)
// ---------------------------------------------------------------------------

export type BannerTone = "success" | "warning" | "danger" | "info";

export function Banner({
  tone,
  title,
  children,
}: {
  tone: BannerTone;
  title?: React.ReactNode;
  children?: React.ReactNode;
}) {
  const styles: Record<BannerTone, string> = {
    success:
      "bg-emerald-50 text-emerald-900 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-100 dark:border-emerald-900",
    warning:
      "bg-amber-50 text-amber-900 border-amber-200 dark:bg-amber-950/60 dark:text-amber-100 dark:border-amber-900",
    danger:
      "bg-red-50 text-red-900 border-red-200 dark:bg-red-950/60 dark:text-red-100 dark:border-red-900",
    info: "bg-sky-50 text-sky-900 border-sky-200 dark:bg-sky-950/60 dark:text-sky-100 dark:border-sky-900",
  };
  return (
    <div className={`rounded-lg border px-3.5 py-2.5 text-sm ${styles[tone]}`}>
      {title ? <div className="font-semibold">{title}</div> : null}
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Modal (passphrase prompts etc. - always in-app, never external pinentry)
// ---------------------------------------------------------------------------

export function Modal({
  open,
  onClose,
  title,
  children,
  wide = false,
}: {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  children: React.ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div
        className={`max-h-[90vh] w-full ${wide ? "max-w-2xl" : "max-w-md"} overflow-y-auto rounded-xl bg-white p-5 shadow-2xl dark:bg-neutral-900 dark:text-neutral-100`}
      >
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-base font-semibold">{title}</h2>
          <button
            className="rounded p-1 text-neutral-400 hover:bg-neutral-100 hover:text-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-200"
            onClick={onClose}
            aria-label="Close"
          >
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M1 1l12 12M13 1L1 13" />
            </svg>
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Fields
// ---------------------------------------------------------------------------

export function Field({
  label,
  hint,
  children,
}: {
  label: React.ReactNode;
  hint?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <div className="mb-1 text-xs font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
        {label}
      </div>
      {children}
      {hint ? <div className="mt-1 text-xs text-neutral-500 dark:text-neutral-400">{hint}</div> : null}
    </label>
  );
}

export const inputClass =
  "w-full rounded-lg border border-neutral-300 bg-white px-3 py-2 text-sm text-neutral-900 outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-100 placeholder:text-neutral-400";

// ---------------------------------------------------------------------------
// Copy button (fires a copy + shows a short "Copied" state)
// ---------------------------------------------------------------------------

export function CopyChip({
  onCopy,
  label = "Copy",
  className = "",
}: {
  onCopy: () => Promise<void> | void;
  label?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  return (
    <button
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-800 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-neutral-200 ${className}`}
      onClick={async (e) => {
        e.stopPropagation();
        try {
          await onCopy();
          setCopied(true);
          window.clearTimeout(timer.current);
          timer.current = window.setTimeout(() => setCopied(false), 1400);
        } catch (err) {
          console.error(err);
        }
      }}
    >
      {copied ? (
        <>
          <svg width="12" height="12" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M2 8l3.5 3.5L12 3.5" />
          </svg>
          Copied
        </>
      ) : (
        <>
          <svg width="12" height="12" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="4.5" y="4.5" width="8" height="8" rx="1.5" />
            <path d="M9.5 4.5v-2a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2" />
          </svg>
          {label}
        </>
      )}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Fingerprint (Signal-style chunked, copyable)
// ---------------------------------------------------------------------------

export function chunkFingerprint(fpr: string): string {
  return (fpr.match(/.{1,4}/g) ?? []).join("  ");
}

export function Fingerprint({ fpr, onCopy }: { fpr: string; onCopy?: () => Promise<void> | void }) {
  return (
    <div className="group inline-flex items-center gap-1.5">
      <code className="font-mono text-xs text-neutral-600 dark:text-neutral-300">
        {chunkFingerprint(fpr)}
      </code>
      {onCopy ? <CopyChip onCopy={onCopy} label="" /> : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Status dot & capability badges
// ---------------------------------------------------------------------------

export function StatusDot({ status }: { status: "valid" | "expired" | "revoked" }) {
  const color =
    status === "valid" ? "bg-emerald-500" : status === "expired" ? "bg-amber-500" : "bg-red-500";
  return <span className={`inline-block h-2.5 w-2.5 shrink-0 rounded-full ${color}`} />;
}

export function Badge({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: "neutral" | "indigo" | "amber" | "red" | "emerald";
}) {
  const tones = {
    neutral:
      "bg-neutral-100 text-neutral-600 dark:bg-neutral-800 dark:text-neutral-300",
    indigo: "bg-indigo-100 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300",
    amber: "bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-300",
    red: "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300",
    emerald: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300",
  } as const;
  return (
    <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium leading-4 ${tones[tone]}`}>
      {children}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Disclosure (the "Advanced" pattern, plan §§5-6)
// ---------------------------------------------------------------------------

export function Disclosure({
  label,
  children,
  defaultOpen = false,
}: {
  label: React.ReactNode;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-lg border border-neutral-200 dark:border-neutral-800">
      <button
        className="flex w-full items-center justify-between px-3 py-2 text-sm text-neutral-600 hover:bg-neutral-50 dark:text-neutral-300 dark:hover:bg-neutral-800/60"
        onClick={() => setOpen((o) => !o)}
      >
        <span className="font-medium">{label}</span>
        <svg
          width="12"
          height="12"
          viewBox="0 0 12 12"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          className={`transition-transform ${open ? "rotate-180" : ""}`}
        >
          <path d="M2 4l4 4 4-4" />
        </svg>
      </button>
      {open ? <div className="border-t border-neutral-200 px-3 py-3 dark:border-neutral-800">{children}</div> : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Confirm (single inline confirmation - plan §10)
// ---------------------------------------------------------------------------

export function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel,
  onConfirm,
  onCancel,
  danger = true,
}: {
  open: boolean;
  title: React.ReactNode;
  body?: React.ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
  danger?: boolean;
}) {
  return (
    <Modal open={open} onClose={onCancel} title={title}>
      {body ? <div className="mb-4 text-sm text-neutral-600 dark:text-neutral-300">{body}</div> : null}
      <div className="flex justify-end gap-2">
        <Button onClick={onCancel}>Cancel</Button>
        <Button variant={danger ? "danger" : "primary"} onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

export function formatDate(unix: number | null): string {
  if (unix === null) return "never";
  return new Date(unix * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export function Spinner() {
  return (
    <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" className="opacity-25" />
      <path d="M22 12a10 10 0 0 0-10-10" stroke="currentColor" strokeWidth="4" />
    </svg>
  );
}
