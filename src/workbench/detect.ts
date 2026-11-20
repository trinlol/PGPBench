/**
 * Client-side detection for the Workbench paste surface.
 *
 * Chat apps mangle OpenPGP armor in practice: they wrap long lines, indent
 * them, or collapse spacing. Detection therefore tolerates arbitrary
 * whitespace *inside* armor header lines, and blocks that survive detection
 * are rebuilt (armor headers dropped, base64 re-wrapped at 64 columns) before
 * they are handed to Rust.
 *
 * Everything here is pure and synchronous so it can run on every keystroke.
 */

import type { DetectedKind } from "../types";

/** `empty` is the only kind that is not in the shared contract. */
export type DetectionKind = DetectedKind | "empty";

export interface Detection {
  kind: DetectionKind;
  /** Short human label for the badge above the action area. */
  label: string;
  /** Normalized content to hand to the backend (armor rebuilt when possible). */
  payload: string;
  /** Detached signatures only: the content the signature covers. */
  signedContent: string | null;
  /** Detached signatures only: the normalized signature block. */
  signatureBlock: string | null;
}

const EMPTY: Detection = {
  kind: "empty",
  label: "",
  payload: "",
  signedContent: null,
  signatureBlock: null,
};

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** `-----BEGIN <label>-----` allowing any amount of whitespace between words. */
function marker(direction: "BEGIN" | "END", label: string): RegExp {
  const words = label.split(" ").map(escapeRe).join("\\s+");
  return new RegExp(`-{3,}\\s*${direction}\\s+${words}\\s*-{3,}`, "gi");
}

interface Span {
  start: number;
  end: number;
  raw: string;
}

function findSpan(input: string, beginLabel: string, endLabel: string, from = 0): Span | null {
  const begin = marker("BEGIN", beginLabel);
  begin.lastIndex = from;
  const b = begin.exec(input);
  if (!b) return null;
  const end = marker("END", endLabel);
  end.lastIndex = b.index + b[0].length;
  const e = end.exec(input);
  if (!e) return null;
  const stop = e.index + e[0].length;
  return { start: b.index, end: stop, raw: input.slice(b.index, stop) };
}

function findAll(input: string, label: string): Span[] {
  const out: Span[] = [];
  let from = 0;
  for (;;) {
    const span = findSpan(input, label, label, from);
    if (!span) break;
    out.push(span);
    from = span.end;
  }
  return out;
}

/**
 * Rebuild one armored block from mangled input: canonical header, base64 body
 * re-wrapped to 64 columns, CRC line preserved, canonical footer.
 */
function rebuildArmor(span: Span, label: string): string {
  const body: string[] = [];
  let crc: string | null = null;

  for (const rawLine of span.raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (/^-{3,}\s*(BEGIN|END)\s/i.test(line)) continue;
    // Armor headers ("Version: …", "Comment: …") are optional; drop them.
    if (/^[A-Za-z][A-Za-z0-9-]*:\s/.test(line)) continue;
    // CRC24 line, e.g. "=abcd".
    if (/^=[A-Za-z0-9+/]{4}$/.test(line)) {
      crc = line;
      continue;
    }
    body.push(line.replace(/\s+/g, ""));
  }

  const chars = body.join("");
  if (!chars) return span.raw.trim();

  const wrapped: string[] = [];
  for (let i = 0; i < chars.length; i += 64) wrapped.push(chars.slice(i, i + 64));

  return [
    `-----BEGIN ${label}-----`,
    "",
    ...wrapped,
    ...(crc ? [crc] : []),
    `-----END ${label}-----`,
  ].join("\n");
}

/**
 * Normalize every public/private key block in `input` (used for imports and
 * for the one-off recipient). Falls back to the trimmed text when no block is
 * recognizable so the backend can produce a useful error.
 */
export function normalizeKeyBlocks(input: string): string {
  const publicBlocks = findAll(input, "PGP PUBLIC KEY BLOCK");
  const privateBlocks = findAll(input, "PGP PRIVATE KEY BLOCK");
  if (publicBlocks.length === 0 && privateBlocks.length === 0) return input.trim();
  return [
    ...publicBlocks.map((s) => rebuildArmor(s, "PGP PUBLIC KEY BLOCK")),
    ...privateBlocks.map((s) => rebuildArmor(s, "PGP PRIVATE KEY BLOCK")),
  ].join("\n");
}

/** Detached signature blocks, normalized (used for one-off verification). */
export function normalizeSignatureBlock(input: string): string {
  const span = findAll(input, "PGP SIGNATURE")[0];
  return span ? rebuildArmor(span, "PGP SIGNATURE") : input.trim();
}

const CLEARTEXT_PAYLOAD_HINT = "-----BEGIN PGP SIGNED MESSAGE-----";

export function detect(input: string): Detection {
  const text = input.trim();
  if (!text) return EMPTY;

  // 1. Cleartext signed message. Checked first: it embeds a signature block,
  //    and its inner text must never be rewritten.
  if (marker("BEGIN", "PGP SIGNED MESSAGE").test(text)) {
    const span = findSpan(text, "PGP SIGNED MESSAGE", "PGP SIGNATURE");
    const payload = span
      ? span.raw
          .replace(marker("BEGIN", "PGP SIGNED MESSAGE"), CLEARTEXT_PAYLOAD_HINT)
          .replace(marker("END", "PGP SIGNATURE"), "-----END PGP SIGNATURE-----")
      : text;
    return {
      kind: "cleartext",
      label: "Signed message detected",
      payload,
      signedContent: null,
      signatureBlock: null,
    };
  }

  // 2. Encrypted OpenPGP message.
  if (marker("BEGIN", "PGP MESSAGE").test(text)) {
    const span = findAll(text, "PGP MESSAGE")[0];
    return {
      kind: "message",
      label: "OpenPGP message detected",
      payload: span ? rebuildArmor(span, "PGP MESSAGE") : text,
      signedContent: null,
      signatureBlock: null,
    };
  }

  // 3. Key material. A private block wins: importing it also carries the
  //    public half. A block with no END line is still reported as a key so the
  //    backend can explain the truncation instead of the UI offering compose.
  const privateSpans = findAll(text, "PGP PRIVATE KEY BLOCK");
  const publicSpans = findAll(text, "PGP PUBLIC KEY BLOCK");
  if (privateSpans.length > 0 || publicSpans.length > 0) {
    return {
      kind: privateSpans.length > 0 ? "private_key" : "public_key",
      label: privateSpans.length > 0 ? "Private key block detected" : "Public key block detected",
      payload: normalizeKeyBlocks(text),
      signedContent: null,
      signatureBlock: null,
    };
  }
  const danglingPrivate = marker("BEGIN", "PGP PRIVATE KEY BLOCK").test(text);
  const danglingPublic = marker("BEGIN", "PGP PUBLIC KEY BLOCK").test(text);
  if (danglingPrivate || danglingPublic) {
    return {
      kind: danglingPrivate ? "private_key" : "public_key",
      label: "Key block looks truncated (no END line)",
      payload: text,
      signedContent: null,
      signatureBlock: null,
    };
  }

  // 4. Detached signature: the signature block plus some other text.
  const signatureSpan = findAll(text, "PGP SIGNATURE")[0];
  const danglingSignature = marker("BEGIN", "PGP SIGNATURE").exec(text);
  if (signatureSpan || danglingSignature) {
    const start = signatureSpan ? signatureSpan.start : (danglingSignature?.index ?? text.length);
    const end = signatureSpan ? signatureSpan.end : text.length;
    // Keep a single trailing newline (detached signatures usually cover the
    // text including its final newline); drop the blank separator line.
    const before = text.slice(0, start).replace(/\s+$/, "\n");
    const after = signatureSpan ? text.slice(end).replace(/^\s+/, "") : "";
    return {
      kind: "detached_signature",
      label: signatureSpan
        ? "Detached signature detected"
        : "Signature block looks truncated (no END line)",
      payload: text,
      signedContent: (before + after).replace(/^\n+/, ""),
      signatureBlock: signatureSpan
        ? rebuildArmor(signatureSpan, "PGP SIGNATURE")
        : text.slice(start),
    };
  }

  return {
    kind: "text",
    label: "Plain text, compose a message",
    payload: text,
    signedContent: null,
    signatureBlock: null,
  };
}
