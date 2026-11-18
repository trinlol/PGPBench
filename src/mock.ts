/**
 * Dev-only mock backend for browser-based UI development and smoke tests.
 *
 * Outside Tauri (no `__TAURI_INTERNALS__`) the ipc layer routes every command
 * here. The mock keeps an in-memory keyring with two canned keys so all four
 * Workbench flows and the Keys tab can be exercised end to end.
 *
 * NOTE: this file never ships behavior into production builds - it is only
 * imported dynamically when `isTauri()` is false.
 */

import type {
  CopyResult,
  DecryptRequest,
  DecryptResult,
  EncryptRequest,
  EncryptResult,
  GenerateRequest,
  GenerateResult,
  ImportRequest,
  ImportPreview,
  InitInfo,
  KeyDetails,
  KeySummary,
  Settings,
  SignRequest,
  SignResult,
  VerifyRequest,
  VerifyResult,
  ClipboardKind,
} from "./types";

const FPR_A = "AA11B22C33D44E55F66A77B88C99D00EE11F22A3";
const FPR_B = "BB22C33D44E55F66A77B88C99D00EE11F22A33B4";

const settings: Settings = {
  theme: "light",
  clipboard_clear_seconds: 60,
  default_profile: "compatible",
};

const keys: KeySummary[] = [
  {
    fpr: FPR_A,
    uids: ["Alice Mock <alice@example.com>"],
    algo: "Ed25519 (ECC Curve25519)",
    created: Math.floor(Date.UTC(2026, 0, 1) / 1000),
    expires: Math.floor(Date.UTC(2027, 0, 1) / 1000),
    has_secret: true,
    profile: "compatible",
    source: "own",
    revoked: false,
    expired: false,
    can_encrypt: true,
  },
  {
    fpr: FPR_B,
    uids: ["Bob Mock <bob@example.com>"],
    algo: "RSA 3072",
    created: Math.floor(Date.UTC(2025, 5, 1) / 1000),
    expires: null,
    has_secret: false,
    profile: "compatible",
    source: "imported",
    revoked: false,
    expired: false,
    can_encrypt: true,
  },
];

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function app_init(): Promise<InitInfo> {
  return {
    settings: { ...settings },
    acl_ok: true,
    acl_note: null,
    data_dir: "C:\\Users\\dev\\AppData\\Local\\PocketPGP (mock)",
  };
}

export async function save_settings(a: {
  theme: string;
  clipboard_clear_seconds: number;
  default_profile: string;
}): Promise<Settings> {
  settings.theme = a.theme === "dark" ? "dark" : "light";
  settings.clipboard_clear_seconds = a.clipboard_clear_seconds;
  settings.default_profile = a.default_profile as Settings["default_profile"];
  return { ...settings };
}

export async function list_keys(): Promise<KeySummary[]> {
  return keys.map((k) => ({ ...k }));
}

export async function key_details(a: { fpr: string }): Promise<KeyDetails> {
  const summary = keys.find((k) => k.fpr === a.fpr.toUpperCase());
  if (!summary) throw new Error("no such key");
  return {
    summary: { ...summary },
    subkeys:
      summary.fpr === FPR_A
        ? [
            {
              fpr: "CC33" + summary.fpr.slice(4),
              algo: "X25519 (ECC)",
              created: summary.created,
              expires: summary.expires,
              capabilities: ["E"],
              revoked: false,
              expired: false,
            },
          ]
        : [],
    warnings: [],
  };
}

export async function generate_key(a: { args: GenerateRequest }): Promise<GenerateResult> {
  await sleep(600);
  const fpr = Array.from({ length: 20 }, (_, i) =>
    String.fromCharCode("A".charCodeAt(0) + ((Date.now() + i * 7) % 26)),
  )
    .join("")
    .slice(0, 40);
  const key: KeySummary = {
    fpr,
    uids: [`${a.args.name} <${a.args.email}>`],
    algo: a.args.algo === "ecc" ? "Ed25519 (ECC Curve25519)" : `RSA ${a.args.algo === "rsa3072" ? 3072 : 4096}`,
    created: Math.floor(Date.now() / 1000),
    expires: a.args.expires ? Math.floor(Date.now() / 1000) + 86400 * 90 : null,
    has_secret: true,
    profile: a.args.profile,
    source: "own",
    revoked: false,
    expired: false,
    can_encrypt: true,
  };
  keys.unshift(key);
  return {
    key: { ...key },
    public_key: `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmock-public-${fpr}\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----\n`,
    revocation_cert: `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmock-revocation-${fpr}\n=BBBB\n-----END PGP PUBLIC KEY BLOCK-----\n`,
    fpr,
  } as GenerateResult;
}

export async function import_key(a: { args: ImportRequest }): Promise<ImportPreview> {
  const armored = a.args.armored.toUpperCase();
  if (armored.includes("BEGIN PGP PRIVATE KEY BLOCK")) {
    const key: KeySummary = {
      fpr: "DD44" + FPR_A.slice(4),
      uids: ["Carol Mock (imported) <carol@example.com>"],
      algo: "Ed25519 (ECC Curve25519)",
      created: Math.floor(Date.now() / 1000),
      expires: null,
      has_secret: true,
      profile: "compatible",
      source: "own",
      revoked: false,
      expired: false,
      can_encrypt: true,
    };
    if (!a.args.dryRun) keys.push(key);
    return {
      ok: true,
      error: null,
      key: { ...key },
      secret: true,
      warnings: ["This is a mock import - nothing was actually written."],
      would_replace: false,
    };
  }
  if (armored.includes("BEGIN PGP PUBLIC KEY BLOCK")) {
    const key: KeySummary = {
      fpr: "EE55" + FPR_B.slice(4),
      uids: ["Dave Mock <dave@example.com>"],
      algo: "RSA 4096",
      created: Math.floor(Date.now() / 1000),
      expires: null,
      has_secret: false,
      profile: "compatible",
      source: "imported",
      revoked: false,
      expired: false,
      can_encrypt: true,
    };
    if (!a.args.dryRun) keys.push(key);
    return {
      ok: true,
      error: null,
      key: { ...key },
      secret: false,
      warnings: [],
      would_replace: false,
    };
  }
  return {
    ok: false,
    error: "not a public or private key block",
    key: null,
    secret: false,
    warnings: [],
    would_replace: false,
  };
}

export async function export_public(a: { fpr: string }): Promise<string> {
  return `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmock-public-${a.fpr}\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----\n`;
}

export async function delete_key(a: { args: { fpr: string; confirm: boolean } }): Promise<boolean> {
  const i = keys.findIndex((k) => k.fpr === a.args.fpr.toUpperCase());
  if (i >= 0) keys.splice(i, 1);
  return true;
}

export async function encrypt(a: { args: EncryptRequest }): Promise<EncryptResult> {
  await sleep(300);
  const msg = a.args.message.replace(/\n/g, "\\n");
  return {
    output: `-----BEGIN PGP MESSAGE-----\n\nmockCiphertext(${a.args.profile})\nrecipients=[${a.args.recipient_fprs.join(", ")}]\n\n${msg}\n=CAF3\n-----END PGP MESSAGE-----\n`,
    binary: false,
    warnings: [],
  };
}

export async function decrypt(a: { args: DecryptRequest }): Promise<DecryptResult> {
  await sleep(300);
  if (!a.args.input.includes("BEGIN PGP MESSAGE")) {
    throw new Error("the input is not an OpenPGP message");
  }
  const inner = a.args.input.split("\n").find((l) => l.startsWith("mockCiphertext"));
  const warnings: string[] = [];
  const signatures = inner
    ? []
    : [
        {
          fpr: FPR_A,
          key_uid: "Alice Mock <alice@example.com>",
          key_source: "own" as const,
          signed_at: Math.floor(Date.now() / 1000),
          valid: true,
          revoked: false,
        },
      ];
  return {
    plaintext: `mock-plaintext of your paste\n(${inner ?? "unknown container"})\npassphrase=${a.args.passphrase ? "provided" : "none"}`,
    signatures,
    warnings,
  };
}

export async function sign(a: { args: SignRequest }): Promise<SignResult> {
  await sleep(300);
  return {
    output:
      a.args.mode === "detached"
        ? `-----BEGIN PGP SIGNATURE-----\n\nmockDetachedSig(${a.args.fpr})\n=ABCD\n-----END PGP SIGNATURE-----\n`
        : `-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n${a.args.message}\n-----BEGIN PGP SIGNATURE-----\n\nmockSig(${a.args.fpr})\n=ABCD\n-----END PGP SIGNATURE-----\n`,
  };
}

export async function verify(a: { args: VerifyRequest }): Promise<VerifyResult> {
  await sleep(300);
  const input = a.args.input.toUpperCase();
  if (!input.includes("BEGIN PGP SIGNED MESSAGE") && !a.args.detached) {
    return {
      ok: false,
      error: "this does not look like a signed message",
      signed_text: null,
      signatures: [],
      warnings: [],
    };
  }
  return {
    ok: true,
    error: null,
    signed_text: a.args.input.replace("-----BEGIN PGP SIGNED MESSAGE-----\n", "").split("-----BEGIN PGP SIGNATURE-----")[0],
    signatures: [
      {
        fpr: FPR_A,
        key_uid: "Alice Mock <alice@example.com>",
        key_source: "own" as const,
        signed_at: Math.floor(Date.now() / 1000),
        valid: true,
        revoked: false,
      },
    ],
    warnings: [],
  };
}

export async function generate_revocation(a: {
  args: { fpr: string; passphrase: string | null; reason: string; reason_text: string | null };
}): Promise<{ revocation_cert: string }> {
  await sleep(300);
  return {
    revocation_cert: `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmock-revocation-${a.args.fpr}(${a.args.reason})\n=EEEE\n-----END PGP PUBLIC KEY BLOCK-----\n`,
  };
}

export async function change_passphrase(): Promise<boolean> {
  await sleep(200);
  return true;
}

export async function extend_expiry(a: { args: { fpr: string; expires: string | null } }): Promise<KeySummary> {
  await sleep(200);
  const key = keys.find((k) => k.fpr === a.args.fpr.toUpperCase());
  if (!key) throw new Error("no such key");
  key.expires = a.args.expires ? Math.floor(Date.now() / 1000) + 86400 * 365 : null;
  return { ...key };
}

export async function copy_key_to_clipboard(a: {
  args: { fpr: string; kind: ClipboardKind };
}): Promise<CopyResult> {
  return { label: `mock copy of ${a.args.kind} ${a.args.fpr}`, auto_clear_seconds: settings.clipboard_clear_seconds };
}

export async function copy_text_secret(a: { content: string; label: string }): Promise<CopyResult> {
  return { label: a.label, auto_clear_seconds: settings.clipboard_clear_seconds };
}
