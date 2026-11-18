/**
 * Import flow: paste -> dry-run preview -> explicit save.
 *
 * The hard-reject explanation from the backend is shown verbatim; the only
 * escape hatch is the explicit "allow legacy keys" opt-in, which re-runs the
 * dry run so the user sees the result before saving.
 */

import { useEffect, useState } from "react";
import type { ImportPreview } from "../types";
import { copyTextSecret, importKey } from "../ipc";
import {
  Badge,
  Banner,
  Button,
  Fingerprint,
  Modal,
  Spinner,
  formatDate,
  inputClass,
} from "../components/ui";

export function ImportFlow({
  open,
  onClose,
  onImported,
}: {
  open: boolean;
  onClose: () => void;
  onImported: () => void;
}) {
  const [armored, setArmored] = useState("");
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [allowLegacy, setAllowLegacy] = useState(false);
  const [busy, setBusy] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!open) return;
    setArmored("");
    setPreview(null);
    setAllowLegacy(false);
    setBusy(false);
    setSaving(false);
    setError(null);
    setSaved(false);
  }, [open]);

  const runDryRun = async (legacy: boolean) => {
    if (!armored.trim()) {
      setError("Paste an armored key block first.");
      return;
    }
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      const result = await importKey({ armored, dryRun: true, allowLegacy: legacy });
      setPreview(result);
      setAllowLegacy(legacy);
    } catch (err) {
      setPreview(null);
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const toggleLegacy = (next: boolean) => {
    setAllowLegacy(next);
    void runDryRun(next);
  };

  const save = async () => {
    if (!preview || !preview.ok) return;
    setSaving(true);
    setError(null);
    try {
      const result = await importKey({ armored, dryRun: false, allowLegacy });
      if (!result.ok) {
        setPreview(result);
        setError(result.error ?? "The key was rejected.");
        return;
      }
      setPreview(result);
      setSaved(true);
      onImported();
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  };

  const cancel = () => {
    setArmored("");
    setPreview(null);
    setAllowLegacy(false);
    setError(null);
    setSaved(false);
  };

  const rejected = preview !== null && !preview.ok;
  const key = preview?.key ?? null;

  return (
    <Modal open={open} onClose={() => (busy || saving ? undefined : onClose())} title="Import a key" wide>
      <div className="space-y-3.5">
        <p className="text-sm text-neutral-600 dark:text-neutral-300">
          Paste an armored public or private key block. You will see a preview before anything is
          saved.
        </p>

        <textarea
          className={`${inputClass} min-h-[9rem] resize-y font-mono text-xs leading-relaxed`}
          value={armored}
          spellCheck={false}
          placeholder={"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n...\n-----END PGP PUBLIC KEY BLOCK-----"}
          onChange={(e) => {
            setArmored(e.target.value);
            setPreview(null);
            setSaved(false);
            setError(null);
          }}
        />

        {error ? (
          <Banner tone="danger" title="Import failed">
            {error}
          </Banner>
        ) : null}

        {rejected && preview ? (
          <div className="space-y-2.5">
            <Banner tone="danger" title="This key was rejected">
              {preview.error ?? "The backend rejected this key."}
            </Banner>
            <label className="flex items-start gap-2 text-sm text-neutral-700 dark:text-neutral-300">
              <input
                type="checkbox"
                className="mt-0.5 h-4 w-4 accent-indigo-600"
                checked={allowLegacy}
                disabled={busy}
                onChange={(e) => toggleLegacy(e.target.checked)}
              />
              <span>
                Allow legacy keys without key-flags <span className="text-neutral-500 dark:text-neutral-400">(Advanced)</span>
              </span>
            </label>
            {busy ? (
              <div className="flex items-center gap-2 text-xs text-neutral-500 dark:text-neutral-400">
                <Spinner /> Checking again...
              </div>
            ) : null}
          </div>
        ) : null}

        {saved ? (
          <Banner tone="success" title="Saved to keyring">
            The key is now available everywhere in PocketPGP.
          </Banner>
        ) : null}

        {key ? (
          <div className="rounded-lg border border-neutral-200 p-3 dark:border-neutral-800">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className="text-sm font-semibold" title={key.uids.join("\n")}>
                {key.uids[0] ?? key.fpr}
              </span>
              <Badge>{key.algo}</Badge>
              {key.profile === "rfc9580" ? <Badge tone="amber">RFC 9580</Badge> : <Badge>v4</Badge>}
              {preview?.secret ? <Badge tone="amber">Private key block</Badge> : null}
            </div>

            <div className="mt-1.5">
              <Fingerprint
                fpr={key.fpr}
                onCopy={async () => {
                  await copyTextSecret(key.fpr, "Fingerprint");
                }}
              />
            </div>

            {key.uids.length > 1 ? (
              <ul className="mt-1.5 space-y-0.5 text-xs text-neutral-500 dark:text-neutral-400">
                {key.uids.slice(1).map((uid) => (
                  <li key={uid} className="break-all">
                    {uid}
                  </li>
                ))}
              </ul>
            ) : null}

            <div className="mt-1.5 text-xs text-neutral-500 dark:text-neutral-400">
              created {formatDate(key.created)} · expires {formatDate(key.expires)}
            </div>

            {preview?.would_replace ? (
              <div className="mt-2.5">
                <Banner tone="warning">
                  This will replace an existing key with the same fingerprint.
                </Banner>
              </div>
            ) : null}

            {preview?.warnings.map((w) => (
              <div className="mt-2" key={w}>
                <Banner tone="warning">{w}</Banner>
              </div>
            ))}
          </div>
        ) : null}

        <div className="flex flex-wrap items-center justify-end gap-2 pt-1">
          <Button variant="ghost" onClick={cancel} disabled={busy || saving} title="Clear the paste box">
            Cancel
          </Button>
          <div className="flex gap-2">
            <Button onClick={() => void runDryRun(allowLegacy)} disabled={busy || saving}>
              {busy ? (
                <>
                  <Spinner /> Checking...
                </>
              ) : (
                "Import"
              )}
            </Button>
            {preview?.ok ? (
              saved ? (
                <Button variant="primary" onClick={onClose}>
                  Done
                </Button>
              ) : (
                <Button variant="primary" onClick={() => void save()} disabled={saving}>
                  {saving ? (
                    <>
                      <Spinner /> Saving...
                    </>
                  ) : (
                    "Save to keyring"
                  )}
                </Button>
              )
            ) : null}
          </div>
        </div>
      </div>
    </Modal>
  );
}
