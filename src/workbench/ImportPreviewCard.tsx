/**
 * Import confirmation card: everything the Rust dry-run reported, plus the
 * single "save to keyring" step. Nothing is written until the user confirms.
 */

import type { ReactNode } from "react";
import type { ImportPreview } from "../types";
import { Badge, Banner, Button, Fingerprint, Spinner, formatDate } from "../components/ui";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <div className="w-24 shrink-0 pt-0.5 text-[11px] font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
        {label}
      </div>
      <div className="min-w-0 flex-1 text-neutral-800 dark:text-neutral-200">{children}</div>
    </div>
  );
}

export function ImportPreviewCard({
  preview,
  busy,
  onSave,
  onCancel,
}: {
  preview: ImportPreview;
  busy: boolean;
  onSave: () => void;
  onCancel: () => void;
}) {
  const key = preview.key;
  if (!preview.ok || !key) return null;

  return (
    <section className="rounded-xl border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-900">
      <div className="mb-2.5 flex flex-wrap items-center gap-1.5">
        <h3 className="text-sm font-semibold">Review key before saving</h3>
        <Badge tone={preview.secret ? "amber" : "neutral"}>
          {preview.secret ? "private key" : "public key"}
        </Badge>
        <Badge>{key.source === "own" ? "own" : "imported"}</Badge>
        {key.revoked ? <Badge tone="red">revoked</Badge> : null}
        {key.expired ? <Badge tone="amber">expired</Badge> : null}
      </div>

      <div className="space-y-2">
        <Row label="User ID">
          <div className="space-y-0.5">
            {key.uids.length > 0 ? (
              key.uids.map((uid, i) => <div key={i}>{uid}</div>)
            ) : (
              <span className="text-neutral-500">no user id</span>
            )}
          </div>
        </Row>
        <Row label="Fingerprint">
          <Fingerprint fpr={key.fpr} />
        </Row>
        <Row label="Algorithm">{key.algo}</Row>
        <Row label="Created">{formatDate(key.created)}</Row>
        <Row label="Expires">{formatDate(key.expires)}</Row>
        <Row label="Profile">
          {key.profile === "rfc9580" ? (
            <span className="flex items-center gap-1.5">
              RFC 9580 (v6) <Badge tone="amber">experimental</Badge>
            </span>
          ) : (
            "Compatible (v4)"
          )}
        </Row>
      </div>

      {preview.warnings.length > 0 ? (
        <div className="mt-2.5 space-y-1.5">
          {preview.warnings.map((warning, i) => (
            <Banner key={i} tone="warning">
              {warning}
            </Banner>
          ))}
        </div>
      ) : null}

      {preview.would_replace ? (
        <div className="mt-2.5">
          <Banner tone="warning">
            This will replace an existing key with the same fingerprint.
          </Banner>
        </div>
      ) : null}

      <div className="mt-3 flex flex-wrap justify-end gap-2">
        <Button onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
        <Button variant="primary" onClick={onSave} disabled={busy}>
          {busy ? (
            <>
              <Spinner />
              Saving…
            </>
          ) : (
            "Save to keyring"
          )}
        </Button>
      </div>
    </section>
  );
}
