/**
 * Inline details panel for one key: summary, subkeys/capabilities, and the
 * maintenance actions (change passphrase, extend expiry, revocation cert).
 *
 * Every action funnels through exactly one passphrase prompt - no double
 * confirmation steps.
 */

import { useCallback, useEffect, useState } from "react";
import type { KeyDetails, RevocationReason, SubkeyInfo } from "../types";
import {
  changePassphrase,
  copyTextSecret,
  extendExpiry,
  generateRevocation,
  keyDetails,
  openKeyFolder,
} from "../ipc";
import {
  Badge,
  Banner,
  Button,
  CopyChip,
  Field,
  Fingerprint,
  Modal,
  Spinner,
  StatusDot,
  formatDate,
  inputClass,
} from "../components/ui";
import { PassphraseModal } from "../components/PassphraseModal";
import { keyStatus, todayIso, trimmedOrNull } from "./keyUtils";

const CAPABILITY_TITLES: Record<string, string> = {
  S: "Sign",
  E: "Encrypt",
  A: "Authenticate",
  C: "Certify",
};

const REVOCATION_REASONS: { value: RevocationReason; label: string }[] = [
  { value: "none", label: "No stated reason" },
  { value: "compromised", label: "Key was compromised" },
  { value: "superseded", label: "Key was superseded" },
  { value: "retired", label: "Key is retired" },
];

type PassPrompt = "extend" | "revoke";

export function DetailsPanel({
  fpr,
  onChanged,
}: {
  fpr: string;
  /** Refresh the surrounding key list after a change that alters the summary. */
  onChanged: () => void;
}) {
  const [details, setDetails] = useState<KeyDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setLoadError(null);
    keyDetails(fpr)
      .then((d) => {
        if (!cancelled) setDetails(d);
      })
      .catch((err) => {
        if (!cancelled) {
          setDetails(null);
          setLoadError(String(err));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [fpr, reloadToken]);

  const reload = useCallback(() => setReloadToken((n) => n + 1), []);

  // --- change passphrase ---------------------------------------------------
  const [pwOpen, setPwOpen] = useState(false);
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");
  const [pwBusy, setPwBusy] = useState(false);
  const [pwError, setPwError] = useState<string | null>(null);

  const openChangePw = () => {
    setOldPw("");
    setNewPw("");
    setNewPw2("");
    setPwError(null);
    setPwOpen(true);
  };

  const submitChangePw = async () => {
    if (!oldPw) {
      setPwError("Enter the current passphrase.");
      return;
    }
    if (!newPw) {
      setPwError("Enter a new passphrase.");
      return;
    }
    if (newPw !== newPw2) {
      setPwError("The new passphrases do not match.");
      return;
    }
    if (newPw === oldPw) {
      setPwError("The new passphrase must differ from the current one.");
      return;
    }
    setPwBusy(true);
    setPwError(null);
    try {
      await changePassphrase({ fpr, old_passphrase: oldPw, new_passphrase: newPw });
      setPwOpen(false);
      setOldPw("");
      setNewPw("");
      setNewPw2("");
      setNotice("Passphrase changed.");
    } catch (err) {
      setPwError(String(err));
    } finally {
      setPwBusy(false);
    }
  };

  // --- extend expiry -------------------------------------------------------
  const [extendOpen, setExtendOpen] = useState(false);
  const [extendDate, setExtendDate] = useState("");
  const [extendNever, setExtendNever] = useState(false);
  const [extendError, setExtendError] = useState<string | null>(null);
  const [passPrompt, setPassPrompt] = useState<PassPrompt | null>(null);
  const [passBusy, setPassBusy] = useState(false);
  const [passError, setPassError] = useState<string | null>(null);

  const openExtend = () => {
    setExtendDate("");
    setExtendNever(false);
    setExtendError(null);
    setExtendOpen(true);
  };

  const requestExtend = () => {
    if (!extendNever) {
      if (!extendDate) {
        setExtendError("Pick a date or choose Never.");
        return;
      }
      if (extendDate < todayIso()) {
        setExtendError("The new expiry must be in the future.");
        return;
      }
    }
    setExtendError(null);
    setPassError(null);
    setPassPrompt("extend");
  };

  // --- revocation certificate ---------------------------------------------
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [reason, setReason] = useState<RevocationReason>("none");
  const [reasonText, setReasonText] = useState("");
  const [revCert, setRevCert] = useState<string | null>(null);

  const openRevoke = () => {
    setReason("none");
    setReasonText("");
    setRevCert(null);
    setRevokeOpen(true);
  };

  const requestRevocation = () => {
    setPassError(null);
    setPassPrompt("revoke");
  };

  const handlePassphrase = async (pw: string) => {
    setPassBusy(true);
    setPassError(null);
    try {
      if (passPrompt === "extend") {
        const updated = await extendExpiry({
          fpr,
          passphrase: pw,
          expires: extendNever ? null : extendDate,
        });
        setPassPrompt(null);
        setExtendOpen(false);
        setNotice(`Expiry updated: ${formatDate(updated.expires)}.`);
        reload();
        onChanged();
      } else if (passPrompt === "revoke") {
        const result = await generateRevocation({
          fpr,
          passphrase: pw,
          reason,
          reason_text: trimmedOrNull(reasonText),
        });
        setPassPrompt(null);
        setRevCert(result.revocation_cert);
        setNotice("Revocation certificate generated and saved to disk.");
      }
    } catch (err) {
      setPassError(String(err));
    } finally {
      setPassBusy(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 border-t border-neutral-200 px-4 py-6 text-xs text-neutral-500 dark:border-neutral-800 dark:text-neutral-400">
        <Spinner /> Loading key details...
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="border-t border-neutral-200 px-4 py-4 dark:border-neutral-800">
        <Banner tone="danger" title="Could not load key details">
          {loadError}
        </Banner>
      </div>
    );
  }

  if (!details) return null;

  const summary = details.summary;
  const status = keyStatus(summary);
  const hasSecret = summary.has_secret;

  return (
    <div className="border-t border-neutral-200 bg-neutral-50/60 px-4 py-4 dark:border-neutral-800 dark:bg-neutral-900/40">
      {notice ? (
        <div className="mb-3">
          <Banner tone="success">{notice}</Banner>
        </div>
      ) : null}

      {details.warnings.map((w) => (
        <div className="mb-2" key={w}>
          <Banner tone="warning">
            {w}
          </Banner>
        </div>
      ))}

      <dl className="grid gap-x-6 gap-y-2.5 text-xs sm:grid-cols-2">
        <div className="sm:col-span-2">
          <dt className="mb-0.5 text-[11px] font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            {summary.uids.length > 1 ? "User IDs" : "User ID"}
          </dt>
          <dd className="space-y-0.5">
            {summary.uids.length === 0 ? (
              <span className="text-neutral-500 dark:text-neutral-400">(none)</span>
            ) : (
              summary.uids.map((uid) => (
                <div key={uid} className="break-all text-neutral-800 dark:text-neutral-200">
                  {uid}
                </div>
              ))
            )}
          </dd>
        </div>

        <div className="sm:col-span-2">
          <dt className="mb-0.5 text-[11px] font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            Fingerprint
          </dt>
          <dd className="flex flex-wrap items-center gap-2">
            <Fingerprint
              fpr={summary.fpr}
              onCopy={async () => {
                await copyTextSecret(summary.fpr, "Fingerprint");
              }}
            />
            <button
              className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-800 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-neutral-200"
              onClick={() => void openKeyFolder(summary.fpr)}
              title="Open the folder that holds this key's files in Windows Explorer"
            >
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" />
              </svg>
              Open key folder
            </button>
          </dd>
        </div>

        <Detail label="Algorithm">{summary.algo}</Detail>
        <Detail label="Profile">
          {summary.profile === "rfc9580" ? (
            <span className="inline-flex items-center gap-1.5">
              RFC 9580 (v6) <Badge tone="amber">experimental</Badge>
            </span>
          ) : (
            "Compatible (v4)"
          )}
        </Detail>
        <Detail label="Created">{formatDate(summary.created)}</Detail>
        <Detail label="Expires">{formatDate(summary.expires)}</Detail>
        <Detail label="Status">
          <span className="inline-flex items-center gap-1.5">
            <StatusDot status={status} />
            <span className="capitalize">{status}</span>
          </span>
        </Detail>
        <Detail label="Key material">{hasSecret ? "Private key on this device" : "Public key only"}</Detail>
      </dl>

      {/* Subkeys */}
      <div className="mt-4">
        <h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
          Subkeys ({details.subkeys.length})
        </h3>
        {details.subkeys.length === 0 ? (
          <p className="text-xs text-neutral-500 dark:text-neutral-400">No subkeys.</p>
        ) : (
          <div className="divide-y divide-neutral-200 rounded-lg border border-neutral-200 bg-white dark:divide-neutral-800 dark:border-neutral-800 dark:bg-neutral-900">
            {details.subkeys.map((sub) => (
              <SubkeyRow key={sub.fpr} sub={sub} />
            ))}
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="mt-4 border-t border-neutral-200 pt-3.5 dark:border-neutral-800">
        <h3 className="mb-2 text-[11px] font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
          Key maintenance
        </h3>

        {!hasSecret ? (
          <p className="text-xs text-neutral-500 dark:text-neutral-400">
            This key has no private material on this device, so passphrase, expiry and revocation
            operations are unavailable.
          </p>
        ) : (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <Button onClick={openChangePw}>Change passphrase</Button>
              <Button onClick={() => (extendOpen ? setExtendOpen(false) : openExtend())}>
                Extend expiry
              </Button>
              <Button onClick={() => (revokeOpen ? setRevokeOpen(false) : openRevoke())}>
                Generate revocation certificate
              </Button>
            </div>

            {extendOpen ? (
              <div className="rounded-lg border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-900">
                <div className="flex flex-wrap items-end gap-3">
                  <div className="min-w-[180px] flex-1">
                    <Field label="New expiry">
                      <input
                        type="date"
                        className={inputClass}
                        min={todayIso()}
                        value={extendDate}
                        disabled={extendNever}
                        onChange={(e) => setExtendDate(e.target.value)}
                      />
                    </Field>
                  </div>
                  <label className="flex items-center gap-2 pb-2 text-sm text-neutral-700 dark:text-neutral-300">
                    <input
                      type="checkbox"
                      className="h-4 w-4 accent-indigo-600"
                      checked={extendNever}
                      onChange={(e) => {
                        setExtendNever(e.target.checked);
                        if (e.target.checked) setExtendDate("");
                        setExtendError(null);
                      }}
                    />
                    Never
                  </label>
                  <div className="flex gap-2 pb-2">
                    <Button variant="primary" onClick={requestExtend}>
                      Apply
                    </Button>
                    <Button variant="ghost" onClick={() => setExtendOpen(false)}>
                      Cancel
                    </Button>
                  </div>
                </div>
                {extendError ? (
                  <p className="mt-2 text-xs text-red-600 dark:text-red-400">{extendError}</p>
                ) : (
                  <p className="mt-2 text-xs text-neutral-500 dark:text-neutral-400">
                    Applies to the primary key and all subkeys. Requires the current passphrase.
                  </p>
                )}
              </div>
            ) : null}

            {revokeOpen ? (
              <div className="rounded-lg border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-900">
                <div className="flex flex-wrap items-end gap-3">
                  <div className="min-w-[180px]">
                    <Field label="Reason">
                      <select
                        className={inputClass}
                        value={reason}
                        onChange={(e) => setReason(e.target.value as RevocationReason)}
                      >
                        {REVOCATION_REASONS.map((r) => (
                          <option key={r.value} value={r.value}>
                            {r.label}
                          </option>
                        ))}
                      </select>
                    </Field>
                  </div>
                  <div className="min-w-[180px] flex-1">
                    <Field label="Reason text" hint="Optional, shown to anyone who inspects the certificate.">
                      <input
                        className={inputClass}
                        value={reasonText}
                        placeholder="e.g. laptop stolen"
                        onChange={(e) => setReasonText(e.target.value)}
                      />
                    </Field>
                  </div>
                  <div className="flex gap-2 pb-2">
                    <Button variant="primary" onClick={requestRevocation}>
                      Generate
                    </Button>
                    <Button variant="ghost" onClick={() => setRevokeOpen(false)}>
                      Cancel
                    </Button>
                  </div>
                </div>

                {revCert ? (
                  <div className="mt-3 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                        Revocation certificate
                      </span>
                      <CopyChip
                        label="Copy certificate"
                        onCopy={async () => {
                          await copyTextSecret(revCert, "Revocation certificate");
                        }}
                      />
                    </div>
                    <pre className="max-h-48 overflow-auto rounded-lg border border-neutral-200 bg-neutral-50 p-2.5 font-mono text-[11px] leading-relaxed text-neutral-700 dark:border-neutral-800 dark:bg-neutral-950 dark:text-neutral-300">
                      {revCert}
                    </pre>
                    <Banner tone="warning">
                      A copy has been saved to{" "}
                      <code className="font-mono text-[11px]">
                        %LOCALAPPDATA%\PocketPGP\keys\{fpr}.rev.asc
                      </code>
                      . Store a second copy somewhere safe. Anyone holding this certificate can revoke
                      your key.
                    </Banner>
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        )}
      </div>

      {/* Change passphrase modal (old + new + repeat) */}
      <Modal open={pwOpen} onClose={() => (pwBusy ? undefined : setPwOpen(false))} title="Change passphrase">
        <p className="mb-3 text-sm text-neutral-600 dark:text-neutral-300">
          Re-wraps the private key with a new passphrase. The key itself does not change.
        </p>
        <div className="space-y-3">
          <Field label="Current passphrase">
            <input
              type="password"
              className={inputClass}
              value={oldPw}
              autoComplete="off"
              autoFocus
              onChange={(e) => setOldPw(e.target.value)}
            />
          </Field>
          <Field label="New passphrase">
            <input
              type="password"
              className={inputClass}
              value={newPw}
              autoComplete="new-password"
              onChange={(e) => setNewPw(e.target.value)}
            />
          </Field>
          <Field label="Repeat new passphrase">
            <input
              type="password"
              className={inputClass}
              value={newPw2}
              autoComplete="new-password"
              onChange={(e) => setNewPw2(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !pwBusy) void submitChangePw();
              }}
            />
          </Field>
        </div>
        {pwError ? (
          <p className="mt-2 text-sm text-red-600 dark:text-red-400">{pwError}</p>
        ) : null}
        <div className="mt-4 flex justify-end gap-2">
          <Button onClick={() => setPwOpen(false)} disabled={pwBusy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={() => void submitChangePw()} disabled={pwBusy}>
            {pwBusy ? (
              <>
                <Spinner /> Saving...
              </>
            ) : (
              "Save"
            )}
          </Button>
        </div>
      </Modal>

      <PassphraseModal
        open={passPrompt !== null}
        title="Passphrase required"
        explain={
          passPrompt === "extend"
            ? `Confirm the current passphrase to re-sign the key with a new expiry (${extendNever ? "never" : extendDate || "no date"}). Leave empty if the key has no passphrase.`
            : `Confirm the current passphrase to sign this revocation certificate (reason: ${
                REVOCATION_REASONS.find((r) => r.value === reason)?.label ?? reason
              }). Leave empty if the key has no passphrase.`
        }
        confirmLabel={passPrompt === "extend" ? "Update expiry" : "Create certificate"}
        busy={passBusy}
        error={passError}
        allowEmpty={true}
        onPassphrase={(pw) => void handlePassphrase(pw)}
        onCancel={() => {
          if (passBusy) return;
          setPassPrompt(null);
          setPassError(null);
        }}
      />
    </div>
  );
}

function Detail({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="mb-0.5 text-[11px] font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
        {label}
      </dt>
      <dd className="text-neutral-800 dark:text-neutral-200">{children}</dd>
    </div>
  );
}

function SubkeyRow({ sub }: { sub: SubkeyInfo }) {
  const caps = sub.capabilities.map((c) => c.trim().toUpperCase()).filter((c) => c.length > 0);

  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-3 py-2.5">
      <div className="flex items-center gap-1">
        {caps.length === 0 ? (
          <Badge tone="neutral">-</Badge>
        ) : (
          caps.map((c) => (
            <span key={c} title={CAPABILITY_TITLES[c] ?? c}>
              <Badge tone={CAPABILITY_TITLES[c] ? "indigo" : "neutral"}>{c}</Badge>
            </span>
          ))
        )}
      </div>
      <div className="min-w-0 flex-1">
        <Fingerprint
          fpr={sub.fpr}
          onCopy={async () => {
            await copyTextSecret(sub.fpr, "Subkey fingerprint");
          }}
        />
        <div className="mt-0.5 text-[11px] text-neutral-500 dark:text-neutral-400">
          {sub.algo} · created {formatDate(sub.created)} · expires {formatDate(sub.expires)}
        </div>
      </div>
      <div className="flex items-center gap-1.5">
        {sub.revoked ? <Badge tone="red">revoked</Badge> : null}
        {sub.expired ? <Badge tone="amber">expired</Badge> : null}
      </div>
    </div>
  );
}
