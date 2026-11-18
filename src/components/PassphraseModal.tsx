/**
 * In-app passphrase modal (plan §5: passphrase prompts are ALWAYS in-app,
 * never external pinentry windows). Shared by Workbench and Keys surfaces.
 */

import { useEffect, useRef, useState } from "react";
import { Button, Field, inputClass, Modal } from "./ui";

export function PassphraseModal({
  open,
  title = "Passphrase required",
  explain,
  confirmLabel = "Continue",
  onPassphrase,
  onCancel,
  busy = false,
  error,
  allowEmpty = false,
}: {
  open: boolean;
  title?: string;
  explain?: React.ReactNode;
  confirmLabel?: string;
  onPassphrase: (pw: string) => void;
  onCancel: () => void;
  busy?: boolean;
  error?: string | null;
  /** Allow submitting an empty passphrase (keys stored without one). */
  allowEmpty?: boolean;
}) {
  const [pw, setPw] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setPw("");
      // Focus after the modal mounts.
      setTimeout(() => inputRef.current?.focus(), 30);
    }
  }, [open]);

  return (
    <Modal open={open} onClose={onCancel} title={title}>
      {explain ? <div className="mb-3 text-sm text-neutral-600 dark:text-neutral-300">{explain}</div> : null}
      <Field label="Passphrase">
        <input
          ref={inputRef}
          type="password"
          className={inputClass}
          value={pw}
          autoComplete="off"
          onChange={(e) => setPw(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && (pw || allowEmpty) && !busy) onPassphrase(pw);
          }}
        />
      </Field>
      {error ? <div className="mt-2 text-sm text-red-600 dark:text-red-400">{error}</div> : null}
      <div className="mt-4 flex justify-end gap-2">
        <Button onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
        <Button variant="primary" disabled={(!pw && !allowEmpty) || busy} onClick={() => onPassphrase(pw)}>
          {busy ? "Working..." : confirmLabel}
        </Button>
      </div>
    </Modal>
  );
}
