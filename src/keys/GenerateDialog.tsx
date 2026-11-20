/**
 * Key generation: one deliberate form (expiry always visible), plus the
 * post-generation panel that hands over the public key and the revocation
 * certificate. The revocation certificate is the one legitimate "save this
 * somewhere else" moment in the app.
 */

import { useEffect, useState } from "react";
import type { Algo, GenerateResult, Profile } from "../types";
import { copyKeyToClipboard, copyTextSecret, generateKey, openKeyFolder } from "../ipc";
import {
  Badge,
  Banner,
  Button,
  ConfirmDialog,
  CopyChip,
  Disclosure,
  Field,
  Fingerprint,
  Modal,
  Spinner,
  formatDate,
  inputClass,
} from "../components/ui";
import { errText } from "../errors";
import { keyLabel, parseUid, passphraseStrength, todayIso, trimmedOrNull } from "./keyUtils";

const ALGOS: { value: Algo; label: string }[] = [
  { value: "ecc", label: "ECC Curve25519 (recommended)" },
  { value: "rsa3072", label: "RSA-3072" },
  { value: "rsa4096", label: "RSA-4096" },
];

export function GenerateDialog({
  open,
  defaultProfile,
  onClose,
  onGenerated,
}: {
  open: boolean;
  defaultProfile: Profile;
  onClose: () => void;
  onGenerated: (result: GenerateResult) => void;
}) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [passphrase2, setPassphrase2] = useState("");
  const [expiryDate, setExpiryDate] = useState("");
  const [neverExpires, setNeverExpires] = useState(false);
  const [algo, setAlgo] = useState<Algo>("ecc");
  const [comment, setComment] = useState("");
  const [profile, setProfile] = useState<Profile>(defaultProfile);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fresh form whenever the dialog is opened; advanced defaults follow settings.
  useEffect(() => {
    if (!open) return;
    setName("");
    setEmail("");
    setPassphrase("");
    setPassphrase2("");
    setExpiryDate("");
    setNeverExpires(false);
    setAlgo("ecc");
    setComment("");
    setProfile(defaultProfile);
    setError(null);
    setBusy(false);
  }, [open, defaultProfile]);

  const strength = passphraseStrength(passphrase);
  const mismatch = passphrase2.length > 0 && passphrase !== passphrase2;
  const dateInPast = !neverExpires && expiryDate !== "" && expiryDate < todayIso();
  const expiryMissing = !neverExpires && expiryDate === "";
  const canSubmit =
    !busy &&
    name.trim().length > 0 &&
    passphrase.length > 0 &&
    !mismatch &&
    !dateInPast &&
    !expiryMissing;

  const submit = async () => {
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const result = await generateKey({
        name: name.trim(),
        email: email.trim(),
        comment: trimmedOrNull(comment),
        passphrase,
        algo,
        profile,
        expires: neverExpires ? null : expiryDate,
      });
      onGenerated(result);
    } catch (err) {
      setError(errText(err));
      setBusy(false);
    }
  };

  return (
    <Modal open={open} onClose={() => (busy ? undefined : onClose())} title="Generate a new key" wide>
      <div className="space-y-3.5">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Name">
            <input
              className={inputClass}
              value={name}
              placeholder="Alice Example"
              autoFocus
              onChange={(e) => setName(e.target.value)}
            />
          </Field>
          <Field label="Email">
            <input
              className={inputClass}
              value={email}
              placeholder="alice@example.com"
              onChange={(e) => setEmail(e.target.value)}
            />
          </Field>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Passphrase" hint="Protects the private key. It is never stored.">
            <input
              type="password"
              className={inputClass}
              value={passphrase}
              autoComplete="new-password"
              onChange={(e) => setPassphrase(e.target.value)}
            />
          </Field>
          <Field label="Repeat passphrase">
            <input
              type="password"
              className={inputClass}
              value={passphrase2}
              autoComplete="new-password"
              onChange={(e) => setPassphrase2(e.target.value)}
            />
          </Field>
        </div>

        {passphrase ? (
          <div className="flex items-center gap-2">
            <div className="flex flex-1 gap-1">
              {[1, 2, 3, 4].map((n) => (
                <div
                  key={n}
                  className={
                    "h-1 flex-1 rounded-full " +
                    (n <= strength.score ? strength.barClass : "bg-neutral-200 dark:bg-neutral-800")
                  }
                />
              ))}
            </div>
            <span className={`w-12 text-right text-[11px] font-medium capitalize ${strength.textClass}`}>
              {strength.label}
            </span>
          </div>
        ) : null}

        {mismatch ? (
          <p className="text-xs text-red-600 dark:text-red-400">The passphrases do not match.</p>
        ) : null}

        <div className="rounded-lg border border-neutral-200 p-3 dark:border-neutral-800">
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[180px] flex-1">
              <Field label="Expiry">
                <input
                  type="date"
                  className={inputClass}
                  min={todayIso()}
                  value={expiryDate}
                  disabled={neverExpires}
                  onChange={(e) => setExpiryDate(e.target.value)}
                />
              </Field>
            </div>
            <label className="flex items-center gap-2 pb-2 text-sm text-neutral-700 dark:text-neutral-300">
              <input
                type="checkbox"
                className="h-4 w-4 accent-indigo-600"
                checked={neverExpires}
                onChange={(e) => {
                  setNeverExpires(e.target.checked);
                  if (e.target.checked) setExpiryDate("");
                }}
              />
              Never expires
            </label>
          </div>
          {dateInPast ? (
            <p className="mt-2 text-xs text-red-600 dark:text-red-400">
              The expiry date must be in the future.
            </p>
          ) : expiryMissing ? (
            <p className="mt-2 text-xs text-neutral-500 dark:text-neutral-400">
              Pick an expiry date, or tick "Never expires".
            </p>
          ) : (
            <p className="mt-2 text-xs text-neutral-500 dark:text-neutral-400">
              You can extend the expiry later from the key details.
            </p>
          )}
        </div>

        <Disclosure label="Advanced">
          <div className="space-y-3">
            <Field label="Algorithm" hint="Curve25519 is fast and widely supported. RSA is for older systems.">
              <select className={inputClass} value={algo} onChange={(e) => setAlgo(e.target.value as Algo)}>
                {ALGOS.map((a) => (
                  <option key={a.value} value={a.value}>
                    {a.label}
                  </option>
                ))}
              </select>
            </Field>

            <Field label="Comment" hint="Added to the user id, e.g. 'work laptop'.">
              <input
                className={inputClass}
                value={comment}
                placeholder="optional"
                onChange={(e) => setComment(e.target.value)}
              />
            </Field>

            <div>
              <div className="mb-1 text-xs font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                Profile
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                <ProfileOption
                  selected={profile === "compatible"}
                  onSelect={() => setProfile("compatible")}
                  title="Compatible"
                  subtitle="v4, works everywhere"
                />
                <ProfileOption
                  selected={profile === "rfc9580"}
                  onSelect={() => setProfile("rfc9580")}
                  title="RFC 9580"
                  subtitle="v6, experimental"
                  badge
                />
              </div>
            </div>
          </div>
        </Disclosure>

        {error ? (
          <Banner tone="danger" title="Key generation failed">
            {error}
          </Banner>
        ) : null}

        <div className="flex items-center justify-between gap-2 pt-1">
          <span className="text-[11px] text-neutral-500 dark:text-neutral-400">
            {algo === "ecc" ? "Generation is instant." : "RSA generation can take a few seconds."}
          </span>
          <div className="flex gap-2">
            <Button onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" onClick={() => void submit()} disabled={!canSubmit}>
              {busy ? (
                <>
                  <Spinner /> Generating...
                </>
              ) : (
                "Generate key"
              )}
            </Button>
          </div>
        </div>
      </div>
    </Modal>
  );
}

function ProfileOption({
  selected,
  onSelect,
  title,
  subtitle,
  badge = false,
}: {
  selected: boolean;
  onSelect: () => void;
  title: string;
  subtitle: string;
  badge?: boolean;
}) {
  return (
    <button
      type="button"
      className={
        "rounded-lg border p-2.5 text-left transition-colors " +
        (selected
          ? "border-indigo-500 bg-indigo-50/60 dark:border-indigo-500 dark:bg-indigo-950/30"
          : "border-neutral-200 hover:bg-neutral-50 dark:border-neutral-800 dark:hover:bg-neutral-800/60")
      }
      onClick={onSelect}
      aria-pressed={selected}
    >
      <div className="flex items-center gap-1.5 text-sm font-medium">
        {title}
        {badge ? <Badge tone="amber">experimental</Badge> : null}
      </div>
      <div className="text-[11px] text-neutral-500 dark:text-neutral-400">{subtitle}</div>
    </button>
  );
}

export function PostGeneratePanel({
  result,
  onClose,
}: {
  result: GenerateResult | null;
  onClose: () => void;
}) {
  const [copiedPublic, setCopiedPublic] = useState(false);
  const [copiedPrivate, setCopiedPrivate] = useState(false);
  const [confirmPrivate, setConfirmPrivate] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [openedFolder, setOpenedFolder] = useState(false);

  useEffect(() => {
    setCopiedPublic(false);
    setCopiedPrivate(false);
    setConfirmPrivate(false);
    setError(null);
    setBusy(false);
    setOpenedFolder(false);
  }, [result]);

  if (!result) return null;

  const key = result.key;
  const label = keyLabel(key);
  const { email } = parseUid(key.uids[0] ?? "");
  const keysPath = `%LOCALAPPDATA%\\PGPBench\\keys\\`;
  const revPath = `${keysPath}${key.fpr}.rev.asc`;

  const copyPublic = async () => {
    setError(null);
    try {
      await copyKeyToClipboard(key.fpr, "public");
      setCopiedPublic(true);
    } catch (err) {
      setError(errText(err));
    }
  };

  const openFolder = async () => {
    setError(null);
    try {
      await openKeyFolder(key.fpr);
      setOpenedFolder(true);
    } catch (err) {
      setError(errText(err));
    }
  };

  const copyPrivate = async () => {
    setConfirmPrivate(false);
    setBusy(true);
    setError(null);
    try {
      await copyKeyToClipboard(key.fpr, "private");
      setCopiedPrivate(true);
    } catch (err) {
      setError(errText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal open onClose={onClose} title="Key generated" wide>
      <div className="space-y-4">
        <Banner tone="success" title={`${label} is ready`}>
          The key was saved to this device in <code className="font-mono text-[11px]">{keysPath}</code> - a
          public file, a passphrase-encrypted private file, and the revocation certificate below. Copy the
          public key wherever you need it; the private key never leaves this device.
        </Banner>

        <div className="rounded-lg border border-neutral-200 p-3 dark:border-neutral-800">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="text-sm font-semibold">{label}</span>
            {email ? (
              <span className="text-xs text-neutral-500 dark:text-neutral-400">&lt;{email}&gt;</span>
            ) : null}
            <Badge>{key.algo}</Badge>
            {key.profile === "rfc9580" ? <Badge tone="amber">RFC 9580</Badge> : <Badge>v4</Badge>}
          </div>
          <div className="mt-1.5">
            <Fingerprint
              fpr={key.fpr}
              onCopy={async () => {
                await copyTextSecret(key.fpr, "Fingerprint");
              }}
            />
          </div>
          <div className="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
            created {formatDate(key.created)} · expires {formatDate(key.expires)}
          </div>
        </div>

        {error ? (
          <Banner tone="danger" title="Copy failed">
            {error}
          </Banner>
        ) : null}

        <div className="flex flex-wrap gap-2">
          <Button variant="primary" onClick={() => void copyPublic()} disabled={busy}>
            {copiedPublic ? "Public key copied" : "Copy public key"}
          </Button>
          <Button onClick={() => setConfirmPrivate(true)} disabled={busy}>
            {busy ? (
              <>
                <Spinner /> Copying...
              </>
            ) : copiedPrivate ? (
              "Private key copied"
            ) : (
              "Copy private key"
            )}
          </Button>
          <Button onClick={() => void openFolder()} disabled={busy}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" />
              <path d="M12 11v6M9.5 14.5 12 17l2.5-2.5" />
            </svg>
            {openedFolder ? "Folder opened" : "Open key folder"}
          </Button>
        </div>

        <div className="rounded-lg border border-amber-200 bg-amber-50/60 p-3 dark:border-amber-900 dark:bg-amber-950/30">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-sm font-semibold text-amber-900 dark:text-amber-100">
              Revocation certificate
            </h3>
            <CopyChip
              label="Copy revocation certificate"
              onCopy={async () => {
                await copyTextSecret(result.revocation_cert, "Revocation certificate");
              }}
            />
          </div>
          <p className="mt-1 text-xs text-amber-900/80 dark:text-amber-100/80">
            Keep this safe. It is the only way to invalidate the key if it is lost or compromised.
          </p>
          <pre className="mt-2 max-h-44 overflow-auto rounded-lg border border-amber-200 bg-white p-2.5 font-mono text-[11px] leading-relaxed text-neutral-800 dark:border-amber-900 dark:bg-neutral-950 dark:text-neutral-200">
            {result.revocation_cert}
          </pre>
          <p className="mt-2 text-xs text-amber-900/90 dark:text-amber-100/90">
            A copy has been saved to <code className="font-mono text-[11px]">{revPath}</code> - store a
            second copy somewhere safe (print it, password manager). Anyone holding this certificate can
            revoke your key.
          </p>
        </div>

        <div className="flex justify-end">
          <Button onClick={onClose}>Done</Button>
        </div>
      </div>

      <ConfirmDialog
        open={confirmPrivate}
        title="Copy the private key?"
        body={
          <>
            This exports the <strong>passphrase-protected secret key</strong> for{" "}
            <strong>{label}</strong> to the clipboard. The clipboard is cleared automatically after a
            short delay, but any app running on this machine can read it before then.
          </>
        }
        confirmLabel="Copy private key"
        danger={false}
        onConfirm={() => void copyPrivate()}
        onCancel={() => setConfirmPrivate(false)}
      />
    </Modal>
  );
}
