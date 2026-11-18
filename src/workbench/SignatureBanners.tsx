/**
 * Verification outcome rendering: one banner per embedded signature plus the
 * amber warning list. Shared by decrypt-then-verify and plain verify.
 */

import type { SignatureInfo } from "../types";
import { Badge, Banner, Fingerprint, formatDate } from "../components/ui";

const SOURCE_LABEL: Record<SignatureInfo["key_source"], string> = {
  own: "own key",
  imported: "imported key",
  unknown: "unknown key",
};

const SOURCE_TONE: Record<SignatureInfo["key_source"], "emerald" | "indigo" | "amber"> = {
  own: "emerald",
  imported: "indigo",
  unknown: "amber",
};

function signedWhen(signedAt: number | null): string {
  return signedAt === null ? "signature date unknown" : `signed ${formatDate(signedAt)}`;
}

export function SignatureList({ signatures }: { signatures: SignatureInfo[] }) {
  if (signatures.length === 0) return null;
  return (
    <div className="space-y-1.5">
      {signatures.map((sig, i) => {
        const bad = !sig.valid || sig.revoked;
        return (
          <Banner key={`${sig.fpr}-${i}`} tone={bad ? "danger" : "success"}>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="font-semibold">
                {sig.valid ? "Signature valid" : "Signature invalid"}
              </span>
              {sig.revoked ? <Badge tone="red">REVOKED</Badge> : null}
              <Badge tone={SOURCE_TONE[sig.key_source]}>{SOURCE_LABEL[sig.key_source]}</Badge>
            </div>
            <div className="mt-1 space-y-1">
              <div className="text-xs">{sig.key_uid ?? "Unknown signer"}</div>
              <Fingerprint fpr={sig.fpr} />
              <div className="text-[11px] opacity-80">{signedWhen(sig.signed_at)}</div>
            </div>
          </Banner>
        );
      })}
    </div>
  );
}

export function Warnings({ items }: { items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div className="space-y-1.5">
      {items.map((warning, i) => (
        <Banner key={i} tone="warning">
          {warning}
        </Banner>
      ))}
    </div>
  );
}
