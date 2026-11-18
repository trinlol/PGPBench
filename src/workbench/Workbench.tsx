/**
 * Workbench: one paste/type surface for everything OpenPGP.
 *
 * The surface detects what was pasted (message, signed message, key block,
 * detached signature, plain text) and offers exactly one primary action for
 * it. Ciphertext is auto-copied on produce (Rust marks it as secret and
 * auto-clears it); decrypted plaintext is only copied when the user asks.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import type { ImportPreview, KeySummary, Profile, SignatureInfo } from "../types";
import {
  copyTextSecret,
  decrypt,
  encrypt,
  importKey,
  listKeys,
  readClipboardText,
  sign,
  verify,
} from "../ipc";
import { Badge, Banner, Button, Spinner } from "../components/ui";
import { PassphraseModal } from "../components/PassphraseModal";
import { detect, normalizeKeyBlocks } from "./detect";
import { AdvancedPanel, defaultAdvanced, type AdvancedOptions } from "./AdvancedPanel";
import { RecipientPicker } from "./RecipientPicker";
import { ResultPanel } from "./ResultPanel";
import { SignatureList, Warnings } from "./SignatureBanners";
import { ImportPreviewCard } from "./ImportPreviewCard";

type Busy = "paste" | "decrypt" | "verify" | "import" | "save" | "encrypt" | "sign" | null;

type Outcome =
  | {
      kind: "decrypt";
      plaintext: string;
      signatures: SignatureInfo[];
      warnings: string[];
    }
  | {
      kind: "verify";
      signedText: string | null;
      signatures: SignatureInfo[];
      warnings: string[];
      error: string | null;
    }
  | {
      kind: "encrypt";
      output: string;
      binary: boolean;
      warnings: string[];
      autoClear: number | null;
      copyFailed: boolean;
    }
  | {
      kind: "sign";
      output: string;
      mode: "cleartext" | "detached";
      autoClear: number | null;
      copyFailed: boolean;
    };

interface PassphraseRequest {
  title: string;
  explain: string;
  confirmLabel: string;
  resolve: (passphrase: string | undefined) => void;
}

function errorText(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

/** Copy produced ciphertext with the Rust-side secret hint; never throws. */
async function autoCopy(
  content: string,
  label: string,
): Promise<{ autoClear: number | null; error: boolean }> {
  try {
    const res = await copyTextSecret(content, label);
    return { autoClear: res.auto_clear_seconds, error: false };
  } catch {
    return { autoClear: null, error: true };
  }
}

const BADGE_TONE = {
  message: "indigo",
  cleartext: "indigo",
  public_key: "indigo",
  private_key: "indigo",
  detached_signature: "indigo",
  text: "neutral",
  empty: "neutral",
} as const;

export function Workbench({
  defaultProfile,
  onOpenKeys,
}: {
  defaultProfile: Profile;
  /** Jump to the Keys tab (used by the "no private key" banner). */
  onOpenKeys?: () => void;
}) {
  /* ---------------------------------------------------------------- state */

  const [input, setInput] = useState("");
  const [debounced, setDebounced] = useState("");
  const [keys, setKeys] = useState<KeySummary[]>([]);
  const [keysLoading, setKeysLoading] = useState(true);
  const [busy, setBusy] = useState<Busy>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);

  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [previewArmored, setPreviewArmored] = useState<string | null>(null);
  const [allowLegacy, setAllowLegacy] = useState(false);

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [oneOff, setOneOff] = useState("");
  const [signerFpr, setSignerFpr] = useState<string | null>(null);
  const [advanced, setAdvanced] = useState<AdvancedOptions>(() => defaultAdvanced(defaultProfile));

  const [decryptNoPass, setDecryptNoPass] = useState(false);
  const [composeNoPass, setComposeNoPass] = useState(false);

  const [pwRequest, setPwRequest] = useState<PassphraseRequest | null>(null);
  const preselected = useRef(false);

  /* -------------------------------------------------------------- derived */

  // Detection is debounced so pasting a large block does not run the regex on
  // every keystroke; action handlers re-detect from the live input.
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(input), 250);
    return () => window.clearTimeout(timer);
  }, [input]);

  const detection = useMemo(() => detect(debounced), [debounced]);
  // The live emptiness check keeps the empty hint honest while the debounced
  // detection is still catching up (e.g. right after an import clears the box).
  const isEmpty = input.trim() === "";

  const ownKeys = useMemo(() => keys.filter((k) => k.has_secret), [keys]);

  /** Encrypt-to-self: the first usable own key, in keyring order. */
  const selfKey = useMemo(
    () => keys.find((k) => k.has_secret && k.can_encrypt && !k.expired && !k.revoked) ?? null,
    [keys],
  );

  const hasSecretKey = keys.some((k) => k.has_secret);

  const uidFor = (fpr: string) => keys.find((k) => k.fpr === fpr)?.uids[0] ?? fpr.slice(-8);

  /* -------------------------------------------------------------- loading */

  const refreshKeys = async () => {
    setKeysLoading(true);
    try {
      setKeys(await listKeys());
    } catch (err) {
      setError(errorText(err));
    } finally {
      setKeysLoading(false);
    }
  };

  useEffect(() => {
    void refreshKeys();
  }, []);

  // Default signer: the first own key, kept valid as the keyring changes.
  useEffect(() => {
    setSignerFpr((current) => {
      if (current && ownKeys.some((k) => k.fpr === current)) return current;
      return ownKeys[0]?.fpr ?? null;
    });
  }, [ownKeys]);

  // Encrypt-to-self default ON, once the keyring arrives.
  useEffect(() => {
    if (preselected.current || keys.length === 0) return;
    preselected.current = true;
    if (selfKey) setSelected(new Set([selfKey.fpr]));
  }, [keys, selfKey]);

  /* --------------------------------------------------------- passphrases */

  const askPassphrase = (opts: Omit<PassphraseRequest, "resolve">) =>
    new Promise<string | undefined>((resolve) => setPwRequest({ ...opts, resolve }));

  const settlePassphrase = (value: string | undefined) => {
    const request = pwRequest;
    setPwRequest(null);
    request?.resolve(value);
  };

  /* --------------------------------------------------------------- input */

  const handleInputChange = (value: string) => {
    setInput(value);
    setOutcome(null);
    setPreview(null);
    setPreviewArmored(null);
    setError(null);
    setNotice(null);
  };

  const handleClear = () => {
    setInput("");
    setOutcome(null);
    setPreview(null);
    setPreviewArmored(null);
    setAllowLegacy(false);
    setError(null);
    setNotice(null);
  };

  const handlePasteFromClipboard = async () => {
    setBusy("paste");
    setError(null);
    try {
      const text = await readClipboardText();
      setInput(text);
      setOutcome(null);
      setPreview(null);
      setPreviewArmored(null);
      setNotice(null);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(null);
    }
  };

  /* ------------------------------------------------------- decrypt/verify */

  const handleDecrypt = async () => {
    const live = detect(input);
    let passphrase: string | null = null;
    if (!decryptNoPass) {
      const typed = await askPassphrase({
        title: "Passphrase for decryption",
        explain:
          "Decrypting uses your stored private key. The passphrase is used for this operation only and is never saved.",
        confirmLabel: "Decrypt",
      });
      if (typed === undefined) return;
      passphrase = typed;
    }

    setBusy("decrypt");
    setError(null);
    setNotice(null);
    setOutcome(null);
    try {
      const res = await decrypt({ input: live.payload, passphrase });
      setOutcome({
        kind: "decrypt",
        plaintext: res.plaintext,
        signatures: res.signatures,
        warnings: res.warnings,
      });
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(null);
    }
  };

  const handleVerify = async () => {
    const live = detect(input);
    const detached = live.kind === "detached_signature";
    if (detached && !(live.signedContent ?? "").trim()) {
      setError(
        "Paste the signed content together with the -----BEGIN PGP SIGNATURE----- block, then verify again.",
      );
      return;
    }

    setBusy("verify");
    setError(null);
    setNotice(null);
    setOutcome(null);
    try {
      const res = detached
        ? await verify({
            input: live.signedContent ?? "",
            detached: live.signatureBlock ?? null,
          })
        : await verify({ input: live.payload, detached: null });

      setOutcome({
        kind: "verify",
        signedText: res.signed_text,
        signatures: res.signatures,
        warnings: res.warnings,
        error: res.ok ? null : (res.error ?? "The signature could not be verified."),
      });
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(null);
    }
  };

  /* --------------------------------------------------------------- import */

  const runDryRun = async (legacy: boolean) => {
    const live = detect(input);
    setBusy("import");
    setError(null);
    setNotice(null);
    setOutcome(null);
    try {
      const res = await importKey({ armored: live.payload, dryRun: true, allowLegacy: legacy });
      setPreview(res);
      setAllowLegacy(legacy);
      setPreviewArmored(res.ok ? live.payload : null);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(null);
    }
  };

  const handleSaveImport = async () => {
    if (!previewArmored) return;
    setBusy("save");
    setError(null);
    setNotice(null);
    try {
      const res = await importKey({ armored: previewArmored, dryRun: false, allowLegacy });
      if (!res.ok) {
        setError(res.error ?? "The key was rejected.");
        return;
      }
      const uid = res.key?.uids[0] ?? "key";
      setPreview(null);
      setPreviewArmored(null);
      setAllowLegacy(false);
      setInput("");
      setNotice(`Saved ${uid} to your keyring.`);
      await refreshKeys();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(null);
    }
  };

  /* -------------------------------------------------------------- compose */

  const toggleRecipient = (fpr: string) => {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(fpr)) next.delete(fpr);
      else next.add(fpr);
      return next;
    });
  };

  const handleEncrypt = async () => {
    const message = input;
    if (!message.trim()) {
      setError("Type or paste a message before encrypting.");
      return;
    }

    const recipientFprs = Array.from(selected).filter((fpr) => keys.some((k) => k.fpr === fpr));
    const trimmedOneOff = oneOff.trim();
    if (trimmedOneOff && detect(trimmedOneOff).kind !== "public_key") {
      setError("The one-off recipient is not a public key block.");
      return;
    }
    const oneOffKeys = trimmedOneOff ? [normalizeKeyBlocks(trimmedOneOff)] : [];
    if (recipientFprs.length === 0 && oneOffKeys.length === 0) {
      setError("Choose at least one recipient, or paste a one-off public key.");
      return;
    }

    let signWithFpr: string | null = null;
    let signPassphrase: string | null = null;
    if (advanced.sign) {
      if (!selfKey) {
        setError(
          "Sign while encrypting needs your own private key. Add or import one in the Keys tab, or turn signing off in Advanced.",
        );
        return;
      }
      signWithFpr = selfKey.fpr;
      if (!composeNoPass) {
        const typed = await askPassphrase({
          title: "Passphrase for signing",
          explain: `Signing uses your own key ${uidFor(selfKey.fpr)}. The passphrase is used for this operation only and is never saved.`,
          confirmLabel: "Encrypt",
        });
        if (typed === undefined) return;
        signPassphrase = typed;
      }
    }

    setBusy("encrypt");
    setError(null);
    setNotice(null);
    setOutcome(null);
    try {
      const res = await encrypt({
        message,
        recipient_fprs: recipientFprs,
        one_off_public_keys: oneOffKeys,
        sign_with_fpr: signWithFpr,
        sign_passphrase: signPassphrase,
        profile: advanced.profile,
        armor: advanced.armor,
        compress: advanced.compress,
      });
      const copy = await autoCopy(res.output, "Encrypted message");
      setOutcome({
        kind: "encrypt",
        output: res.output,
        binary: res.binary,
        warnings: res.warnings,
        autoClear: copy.autoClear,
        copyFailed: copy.error,
      });
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(null);
    }
  };

  const handleSign = async () => {
    const fpr = signerFpr ?? ownKeys[0]?.fpr ?? null;
    if (!fpr) {
      setError("Signing needs a private key in your keyring. Add one in the Keys tab.");
      return;
    }

    let passphrase: string | null = null;
    if (!composeNoPass) {
      const typed = await askPassphrase({
        title: "Passphrase for signing",
        explain: `Signing uses your own key ${uidFor(fpr)}. The passphrase is used for this operation only and is never saved.`,
        confirmLabel: "Sign",
      });
      if (typed === undefined) return;
      passphrase = typed;
    }

    const mode = advanced.detachedSignature ? "detached" : "cleartext";
    setBusy("sign");
    setError(null);
    setNotice(null);
    setOutcome(null);
    try {
      const res = await sign({ message: input, fpr, passphrase, mode });
      const copy = await autoCopy(
        res.output,
        mode === "detached" ? "Detached signature" : "Signed message",
      );
      setOutcome({
        kind: "sign",
        output: res.output,
        mode,
        autoClear: copy.autoClear,
        copyFailed: copy.error,
      });
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(null);
    }
  };

  /* ---------------------------------------------------------------- views */

  const noPassphraseToggle = (checked: boolean, onChange: (next: boolean) => void) => (
    <label className="flex items-center gap-1.5 text-[11px] text-neutral-500 dark:text-neutral-400">
      <input
        type="checkbox"
        className="accent-indigo-600"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      my key has no passphrase
    </label>
  );

  return (
    <div className="flex h-full flex-col gap-3 overflow-y-auto pb-4 pr-0.5">
      {/* Paste surface -------------------------------------------------- */}
      <section className="rounded-xl border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-900">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold">Workbench</h2>
            <p className="text-[11px] text-neutral-500 dark:text-neutral-400">
              Paste anything OpenPGP, or type a message to encrypt.
            </p>
          </div>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              className="px-2 py-1 text-xs"
              onClick={handlePasteFromClipboard}
              disabled={busy !== null}
              title="Reads the clipboard once — the clipboard is never watched or polled"
            >
              {busy === "paste" ? (
                <>
                  <Spinner />
                  Reading…
                </>
              ) : (
                "Paste from clipboard"
              )}
            </Button>
            <Button
              variant="ghost"
              className="px-2 py-1 text-xs"
              onClick={handleClear}
              disabled={busy !== null || input.length === 0}
            >
              Clear
            </Button>
          </div>
        </div>

        <textarea
          aria-label="Paste or type OpenPGP content"
          className="mt-2 w-full resize-y rounded-lg border border-neutral-300 bg-white px-3 py-2.5 font-mono text-[12.5px] leading-relaxed text-neutral-900 outline-none placeholder:font-sans placeholder:text-neutral-400 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-100"
          rows={7}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          readOnly={busy !== null}
          placeholder="Paste an OpenPGP message, a signed message, a public or private key block, or a detached signature. Plain text composes a new message."
          value={input}
          onChange={(e) => handleInputChange(e.target.value)}
        />

        <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-1.5">
            {isEmpty ? (
              <span className="text-[11px] text-neutral-400 dark:text-neutral-500">
                Waiting for input…
              </span>
            ) : detection.kind !== "empty" ? (
              <Badge tone={BADGE_TONE[detection.kind]}>{detection.label}</Badge>
            ) : null}
          </div>
          <span className="text-[11px] tabular-nums text-neutral-400 dark:text-neutral-500">
            {input.length.toLocaleString()} chars
          </span>
        </div>
      </section>

      {/* Errors / notices ---------------------------------------------- */}
      {error ? (
        <Banner tone="danger" title="Something went wrong">
          {error}
        </Banner>
      ) : null}
      {notice ? <Banner tone="success">{notice}</Banner> : null}

      {/* Empty hint ---------------------------------------------------- */}
      {isEmpty ? (
        <div className="rounded-xl border border-dashed border-neutral-300 px-4 py-6 text-center dark:border-neutral-700">
          <p className="text-sm font-medium text-neutral-600 dark:text-neutral-300">
            One surface, no modes
          </p>
          <ul className="mx-auto mt-2 max-w-sm space-y-0.5 text-[12px] text-neutral-500 dark:text-neutral-400">
            <li>OpenPGP message → decrypt &amp; verify</li>
            <li>Signed message or detached signature → verify</li>
            <li>Public or private key block → import</li>
            <li>Plain text → encrypt or sign for recipients</li>
          </ul>
        </div>
      ) : null}

      {/* Encrypted message --------------------------------------------- */}
      {!isEmpty && detection.kind === "message" ? (
        <section className="rounded-xl border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-900">
          {keysLoading ? (
            <div className="flex items-center gap-2 text-xs text-neutral-500 dark:text-neutral-400">
              <Spinner />
              Checking the keyring…
            </div>
          ) : hasSecretKey ? (
            <div className="flex flex-wrap items-center gap-3">
              <Button variant="primary" onClick={handleDecrypt} disabled={busy !== null}>
                {busy === "decrypt" ? (
                  <>
                    <Spinner />
                    Decrypting…
                  </>
                ) : (
                  "Decrypt & Verify"
                )}
              </Button>
              {noPassphraseToggle(decryptNoPass, setDecryptNoPass)}
            </div>
          ) : (
            <Banner tone="warning" title="No private key to decrypt with">
              Decryption needs a secret key in your keyring.{" "}
              {onOpenKeys ? (
                <button
                  className="font-semibold text-indigo-600 underline underline-offset-2 hover:text-indigo-500 dark:text-indigo-400"
                  onClick={onOpenKeys}
                >
                  Go to the Keys tab
                </button>
              ) : (
                <>Generate or import one in the <strong>Keys</strong> tab</>
              )}
              , then paste the message again.
            </Banner>
          )}
        </section>
      ) : null}

      {/* Signed message / detached signature --------------------------- */}
      {!isEmpty && (detection.kind === "cleartext" || detection.kind === "detached_signature") ? (
        <section className="rounded-xl border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-900">
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="primary" onClick={handleVerify} disabled={busy !== null}>
              {busy === "verify" ? (
                <>
                  <Spinner />
                  Verifying…
                </>
              ) : detection.kind === "detached_signature" ? (
                "Verify detached"
              ) : (
                "Verify"
              )}
            </Button>
            <span className="text-[11px] text-neutral-500 dark:text-neutral-400">
              {detection.kind === "detached_signature"
                ? "signature block found — the surrounding text is verified"
                : "signed text found — signer must be in the keyring"}
            </span>
          </div>
        </section>
      ) : null}

      {/* Key import ---------------------------------------------------- */}
      {!isEmpty && (detection.kind === "public_key" || detection.kind === "private_key") ? (
        <section className="rounded-xl border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-900">
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="primary" onClick={() => void runDryRun(allowLegacy)} disabled={busy !== null}>
              {busy === "import" ? (
                <>
                  <Spinner />
                  Inspecting…
                </>
              ) : (
                "Import"
              )}
            </Button>
            <span className="text-[11px] text-neutral-500 dark:text-neutral-400">
              nothing is saved until you review and confirm
            </span>
          </div>
        </section>
      ) : null}

      {preview && !preview.ok ? (
        <div className="space-y-2">
          <Banner tone="danger" title="This key can't be imported">
            {preview.error ?? "The key was rejected."}
          </Banner>
          <label className="flex items-start gap-2 rounded-lg border border-neutral-200 px-3 py-2 text-[11px] text-neutral-600 dark:border-neutral-800 dark:text-neutral-300">
            <input
              type="checkbox"
              className="mt-0.5 accent-indigo-600"
              checked={allowLegacy}
              disabled={busy !== null}
              onChange={(e) => {
                const next = e.target.checked;
                setAllowLegacy(next);
                if (next) void runDryRun(true);
              }}
            />
            <span>
              Allow legacy keys without key-flags (Advanced)
              <span className="mt-0.5 block text-neutral-500 dark:text-neutral-400">
                Only for keys you trust that predate key-flag subpackets.
              </span>
            </span>
          </label>
        </div>
      ) : null}

      {preview ? (
        <ImportPreviewCard
          preview={preview}
          busy={busy === "save"}
          onSave={() => void handleSaveImport()}
          onCancel={() => {
            setPreview(null);
            setPreviewArmored(null);
            setAllowLegacy(false);
          }}
        />
      ) : null}

      {/* Compose ------------------------------------------------------- */}
      {!isEmpty && detection.kind === "text" ? (
        <>
          <RecipientPicker
            keys={keys}
            loading={keysLoading}
            selected={selected}
            onToggle={toggleRecipient}
            selfFpr={selfKey?.fpr ?? null}
            oneOff={oneOff}
            onOneOff={setOneOff}
            disabled={busy !== null}
          />

          <section className="rounded-xl border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-900">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <Button variant="primary" onClick={handleEncrypt} disabled={busy !== null}>
                  {busy === "encrypt" ? (
                    <>
                      <Spinner />
                      Encrypting…
                    </>
                  ) : (
                    "Encrypt & copy"
                  )}
                </Button>
                <Button
                  onClick={handleSign}
                  disabled={busy !== null || ownKeys.length === 0}
                  title={
                    ownKeys.length === 0
                      ? "Signing needs a private key — add one in the Keys tab"
                      : undefined
                  }
                >
                  {busy === "sign" ? (
                    <>
                      <Spinner />
                      Signing…
                    </>
                  ) : (
                    "Sign"
                  )}
                </Button>
                {ownKeys.length > 1 ? (
                  <label className="flex items-center gap-1.5 text-[11px] text-neutral-500 dark:text-neutral-400">
                    sign as
                    <select
                      className="rounded-md border border-neutral-300 bg-white px-1.5 py-1 text-[11px] text-neutral-800 outline-none dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-200"
                      value={signerFpr ?? ""}
                      disabled={busy !== null}
                      onChange={(e) => setSignerFpr(e.target.value)}
                    >
                      {ownKeys.map((key) => (
                        <option key={key.fpr} value={key.fpr}>
                          {key.uids[0] ?? key.fpr.slice(-8)}
                        </option>
                      ))}
                    </select>
                  </label>
                ) : null}
              </div>
              {noPassphraseToggle(composeNoPass, setComposeNoPass)}
            </div>
            <p className="mt-2 text-[11px] text-neutral-500 dark:text-neutral-400">
              The ciphertext is copied automatically (and auto-clears).{" "}
              {advanced.sign
                ? `Signing with ${selfKey ? uidFor(selfKey.fpr) : "your own key"}.`
                : "Turn on Sign while encrypting in Advanced to sign too."}
            </p>
          </section>
        </>
      ) : null}

      {/* Advanced ------------------------------------------------------ */}
      {!isEmpty ? <AdvancedPanel value={advanced} onChange={setAdvanced} /> : null}

      {/* Results ------------------------------------------------------- */}
      {outcome?.kind === "decrypt" ? (
        <div className="space-y-2">
          <SignatureList signatures={outcome.signatures} />
          {outcome.signatures.length === 0 ? (
            <Banner tone="info">
              Decrypted, but the message is unsigned — authenticity was not verified.
            </Banner>
          ) : null}
          <Warnings items={outcome.warnings} />
          <ResultPanel
            title="Decrypted message"
            value={outcome.plaintext}
            copyLabel="Decrypted message"
          />
        </div>
      ) : null}

      {outcome?.kind === "verify" ? (
        <div className="space-y-2">
          {outcome.error ? (
            <Banner tone="danger" title="Verification failed">
              {outcome.error}
            </Banner>
          ) : null}
          <SignatureList signatures={outcome.signatures} />
          {outcome.signedText && outcome.signedText.trim() ? (
            <ResultPanel
              title="Signed content"
              value={outcome.signedText}
              copyLabel="Signed message"
            />
          ) : null}
          <Warnings items={outcome.warnings} />
        </div>
      ) : null}

      {outcome?.kind === "encrypt" ? (
        <div className="space-y-2">
          <Warnings items={outcome.warnings} />
          <ResultPanel
            title="Encrypted message"
            value={outcome.output}
            copyLabel="Encrypted message"
            autoClearSeconds={outcome.autoClear}
            copyFailed={outcome.copyFailed}
            breakAll
            note={
              outcome.binary ? (
                <p className="mt-1.5 text-[11px] text-neutral-500 dark:text-neutral-400">
                  Base64 of binary output — armor is off, so paste at your own risk.
                </p>
              ) : undefined
            }
          />
        </div>
      ) : null}

      {outcome?.kind === "sign" ? (
        <ResultPanel
          title={outcome.mode === "detached" ? "Detached signature" : "Signed message"}
          value={outcome.output}
          copyLabel={outcome.mode === "detached" ? "Detached signature" : "Signed message"}
          autoClearSeconds={outcome.autoClear}
          copyFailed={outcome.copyFailed}
          breakAll={outcome.mode === "detached"}
        />
      ) : null}

      {/* In-app passphrase prompt (never external pinentry) ------------ */}
      <PassphraseModal
        open={pwRequest !== null}
        title={pwRequest?.title ?? "Passphrase required"}
        explain={pwRequest?.explain}
        confirmLabel={pwRequest?.confirmLabel ?? "Continue"}
        onPassphrase={(pw) => settlePassphrase(pw)}
        onCancel={() => settlePassphrase(undefined)}
      />
    </div>
  );
}
