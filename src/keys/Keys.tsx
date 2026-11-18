/**
 * Keys surface: flat searchable list, filter chips, generate/import flows,
 * inline details and exactly one confirmation per destructive action.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import type { CopyResult, GenerateResult, KeySummary, Profile } from "../types";
import { copyKeyToClipboard, deleteKey, listKeys } from "../ipc";
import {
  Badge,
  Banner,
  Button,
  ConfirmDialog,
  Spinner,
  chunkFingerprint,
  inputClass,
} from "../components/ui";
import { KeyRow } from "./KeyRow";
import { DetailsPanel } from "./DetailsPanel";
import { GenerateDialog, PostGeneratePanel } from "./GenerateDialog";
import { ImportFlow } from "./ImportFlow";
import { isExpiringSoon, keyLabel, matchesQuery } from "./keyUtils";

type FilterId = "all" | "own" | "imported" | "expiring";

const FILTERS: { id: FilterId; label: string }[] = [
  { id: "all", label: "All" },
  { id: "own", label: "My keys" },
  { id: "imported", label: "Imported" },
  { id: "expiring", label: "Expiring" },
];

interface PendingAction {
  kind: "delete" | "copyPrivate";
  key: KeySummary;
}

function copyNotice(result: CopyResult, what: string): string {
  return result.auto_clear_seconds > 0
    ? `${what} copied - the clipboard clears in ${result.auto_clear_seconds} seconds.`
    : `${what} copied to the clipboard.`;
}

export function Keys({ defaultProfile }: { defaultProfile: Profile }) {
  const [keys, setKeys] = useState<KeySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<FilterId>("all");
  const [expandedFpr, setExpandedFpr] = useState<string | null>(null);
  const [busyFpr, setBusyFpr] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingAction | null>(null);

  const [generateOpen, setGenerateOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [postGen, setPostGen] = useState<GenerateResult | null>(null);

  const load = useCallback(async (options?: { quiet?: boolean }) => {
    if (!options?.quiet) setLoading(true);
    try {
      const list = await listKeys();
      setKeys(list);
      setError(null);
    } catch (err) {
      setError(`Could not load the keyring: ${String(err)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Drop the expanded panel if its key disappears (deleted or replaced).
  useEffect(() => {
    if (expandedFpr && !keys.some((k) => k.fpr === expandedFpr)) setExpandedFpr(null);
  }, [keys, expandedFpr]);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(null), 6000);
    return () => window.clearTimeout(timer);
  }, [notice]);

  const counts = useMemo(
    () => ({
      all: keys.length,
      own: keys.filter((k) => k.has_secret).length,
      imported: keys.filter((k) => !k.has_secret).length,
      expiring: keys.filter((k) => isExpiringSoon(k)).length,
    }),
    [keys],
  );

  const visible = useMemo(() => {
    const searched = keys.filter((k) => matchesQuery(k, query));
    switch (filter) {
      case "own":
        return searched.filter((k) => k.has_secret);
      case "imported":
        return searched.filter((k) => !k.has_secret);
      case "expiring":
        return searched.filter((k) => isExpiringSoon(k));
      default:
        return searched;
    }
  }, [keys, query, filter]);

  const selectFilter = (id: FilterId) => {
    setFilter((current) => (current === id && id !== "all" ? "all" : id));
  };

  const handleGenerated = (result: GenerateResult) => {
    setGenerateOpen(false);
    setPostGen(result);
    void load({ quiet: true });
  };

  const runCopyPrivate = async () => {
    const key = pending?.key;
    if (!key) return;
    setPending(null);
    setBusyFpr(key.fpr);
    try {
      const result = await copyKeyToClipboard(key.fpr, "private");
      setNotice(copyNotice(result, `Private key for ${keyLabel(key)}`));
    } catch (err) {
      setError(`Could not copy the private key: ${String(err)}`);
    } finally {
      setBusyFpr(null);
    }
  };

  const runDelete = async () => {
    const key = pending?.key;
    if (!key) return;
    setPending(null);
    setBusyFpr(key.fpr);
    try {
      const deleted = await deleteKey(key.fpr);
      if (!deleted) throw new Error("the backend reported that nothing was deleted");
      if (expandedFpr === key.fpr) setExpandedFpr(null);
      setNotice(`${keyLabel(key)} was removed from your keyring.`);
      await load({ quiet: true });
    } catch (err) {
      setError(`Could not delete the key: ${String(err)}`);
    } finally {
      setBusyFpr(null);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold">Keyring</h2>
          <p className="text-[11px] text-neutral-500 dark:text-neutral-400">
            {keys.length === 0
              ? "No keys yet"
              : `${keys.length} key${keys.length === 1 ? "" : "s"} · ${counts.own} with private material`}
          </p>
        </div>

        {keys.length > 0 ? (
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="primary" onClick={() => setGenerateOpen(true)}>
              Generate key
            </Button>
            <Button onClick={() => setImportOpen(true)}>Import key</Button>
          </div>
        ) : null}
      </div>

      {keys.length > 0 ? (
        <>
          <div className="relative">
            <svg
              className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-neutral-400"
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <circle cx="10.5" cy="10.5" r="6.5" />
              <path d="M15.5 15.5L21 21" />
            </svg>
            <input
              className={`${inputClass} pl-8`}
              value={query}
              placeholder="Search by name, email or fingerprint"
              onChange={(e) => setQuery(e.target.value)}
              aria-label="Search keys"
            />
          </div>

          <div className="inline-flex w-fit flex-wrap rounded-lg bg-neutral-100 p-0.5 dark:bg-neutral-800/70">
            {FILTERS.map((f) => {
              const active = filter === f.id;
              return (
                <button
                  key={f.id}
                  className={
                    "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-colors " +
                    (active
                      ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-900 dark:text-neutral-100"
                      : "text-neutral-500 hover:text-neutral-800 dark:text-neutral-400 dark:hover:text-neutral-200")
                  }
                  aria-pressed={active}
                  onClick={() => selectFilter(f.id)}
                >
                  {f.label}
                  <span className={active ? "text-neutral-400" : "text-neutral-400 dark:text-neutral-500"}>
                    {counts[f.id]}
                  </span>
                </button>
              );
            })}
          </div>
        </>
      ) : null}

      {notice ? (
        <div className="flex items-start gap-2">
          <div className="flex-1">
            <Banner tone="success">{notice}</Banner>
          </div>
          <DismissButton onClick={() => setNotice(null)} />
        </div>
      ) : null}

      {error ? (
        <div className="flex items-start gap-2">
          <div className="flex-1">
            <Banner tone="danger" title="Something went wrong">
              {error}
            </Banner>
          </div>
          <DismissButton onClick={() => setError(null)} />
        </div>
      ) : null}

      <div className="min-h-0 flex-1 overflow-y-auto pr-0.5">
        {loading && keys.length === 0 ? (
          <div className="flex h-full items-center justify-center gap-2 text-sm text-neutral-400">
            <Spinner /> Loading keys...
          </div>
        ) : keys.length === 0 ? (
          <EmptyState
            onGenerate={() => setGenerateOpen(true)}
            onImport={() => setImportOpen(true)}
          />
        ) : visible.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-2 text-center">
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              No keys match this search or filter.
            </p>
            <Button
              variant="ghost"
              onClick={() => {
                setQuery("");
                setFilter("all");
              }}
            >
              Clear search and filters
            </Button>
          </div>
        ) : (
          <div className="space-y-2 pb-1">
            {visible.map((key) => {
              const expanded = expandedFpr === key.fpr;
              return (
                <div
                  key={key.fpr}
                  className={
                    "rounded-xl border bg-white transition-colors dark:bg-neutral-900 " +
                    (expanded
                      ? "border-indigo-300 dark:border-indigo-800"
                      : "border-neutral-200 dark:border-neutral-800")
                  }
                >
                  <KeyRow
                    keySummary={key}
                    expanded={expanded}
                    busy={busyFpr === key.fpr}
                    onToggleDetails={() => setExpandedFpr(expanded ? null : key.fpr)}
                    onCopyPrivate={() => setPending({ kind: "copyPrivate", key })}
                    onDelete={() => setPending({ kind: "delete", key })}
                    onError={setError}
                  />
                  {expanded ? (
                    <DetailsPanel fpr={key.fpr} onChanged={() => void load({ quiet: true })} />
                  ) : null}
                </div>
              );
            })}
          </div>
        )}
      </div>

      <GenerateDialog
        open={generateOpen}
        defaultProfile={defaultProfile}
        onClose={() => setGenerateOpen(false)}
        onGenerated={handleGenerated}
      />

      <ImportFlow
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImported={() => void load({ quiet: true })}
      />

      <PostGeneratePanel result={postGen} onClose={() => setPostGen(null)} />

      <ConfirmDialog
        open={pending?.kind === "delete"}
        title="Delete this key?"
        body={
          pending?.kind === "delete" ? (
            <>
              <p>
                <strong>{keyLabel(pending.key)}</strong> will be removed from your keyring, including
                its private key. This cannot be undone.
              </p>
              <p className="mt-2 font-mono text-[11px] text-neutral-500 dark:text-neutral-400">
                {chunkFingerprint(pending.key.fpr)}
              </p>
            </>
          ) : null
        }
        confirmLabel="Delete key"
        onConfirm={() => void runDelete()}
        onCancel={() => setPending(null)}
      />

      <ConfirmDialog
        open={pending?.kind === "copyPrivate"}
        title="Copy the private key?"
        body={
          pending?.kind === "copyPrivate" ? (
            <>
              <p>
                This exports the <strong>passphrase-protected secret key</strong> for{" "}
                <strong>{keyLabel(pending.key)}</strong> to the clipboard. Any app on this machine can
                read it until the clipboard is cleared.
              </p>
              <p className="mt-2 font-mono text-[11px] text-neutral-500 dark:text-neutral-400">
                {chunkFingerprint(pending.key.fpr)}
              </p>
            </>
          ) : null
        }
        confirmLabel="Copy private key"
        danger={false}
        onConfirm={() => void runCopyPrivate()}
        onCancel={() => setPending(null)}
      />
    </div>
  );
}

function DismissButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      className="mt-1 rounded p-1 text-neutral-400 hover:bg-neutral-100 hover:text-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-200"
      onClick={onClick}
      aria-label="Dismiss"
    >
      <svg width="12" height="12" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M1 1l12 12M13 1L1 13" />
      </svg>
    </button>
  );
}

function EmptyState({ onGenerate, onImport }: { onGenerate: () => void; onImport: () => void }) {
  return (
    <div className="flex h-full items-center justify-center">
      <div className="flex w-full max-w-md flex-col items-center gap-4 rounded-xl border border-dashed border-neutral-300 bg-white px-6 py-10 text-center dark:border-neutral-700 dark:bg-neutral-900">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-indigo-50 text-indigo-600 dark:bg-indigo-950/60 dark:text-indigo-300">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="8" cy="8" r="4.2" />
            <path d="M11.5 11.5L20 20M17 17v3M20.5 17v2.2" />
          </svg>
        </div>
        <div>
          <h3 className="text-base font-semibold">Your keyring is empty</h3>
          <p className="mx-auto mt-1 max-w-sm text-sm text-neutral-500 dark:text-neutral-400">
            Generate a key to start signing and encrypting, or import an existing public or private
            key.
          </p>
        </div>
        <div className="flex flex-wrap items-center justify-center gap-2">
          <Button variant="primary" onClick={onGenerate}>
            Generate key
          </Button>
          <Button onClick={onImport}>Import key</Button>
        </div>
        <Badge tone="neutral">Everything stays on this device</Badge>
      </div>
    </div>
  );
}
