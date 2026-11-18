/**
 * Typed IPC layer over the Tauri command surface.
 *
 * When the frontend runs outside Tauri (plain browser during development or
 * UI smoke tests), every call routes to a dev-only mock instead, so the whole
 * UI can be exercised without the Rust backend. The mock is imported
 * dynamically and only in dev builds.
 */

import type {
  ChangePassphraseRequest,
  CopyResult,
  DecryptRequest,
  DecryptResult,
  EncryptRequest,
  EncryptResult,
  ExtendExpiryRequest,
  GenerateRequest,
  GenerateResult,
  ImportPreview,
  ImportRequest,
  InitInfo,
  KeyDetails,
  KeySummary,
  RevocationRequest,
  RevocationResult,
  Settings,
  SignRequest,
  SignResult,
  VerifyRequest,
  VerifyResult,
  ClipboardKind,
} from "./types";

/** True when running inside a real Tauri webview. */
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
type AnyFn = (...args: any[]) => Promise<any>;
const mockCache: Record<string, AnyFn> = {};

async function mock(): Promise<typeof import("./mock")> {
  if (!mockCache.mod) mockCache.mod = (await import("./mock")) as never;
  return mockCache.mod as unknown as typeof import("./mock");
}

function snake<T>(v: T): T {
  // The Rust side speaks snake_case; the TS contract types in types.ts are
  // written snake_case as well, so this is a pass-through placeholder kept
  // for clarity.
  return v;
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (isTauri()) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<T>(command, snake(args ?? {}));
  }
  const m = await mock();
  const fn = (m as unknown as Record<string, AnyFn>)[command];
  if (typeof fn !== "function") {
    throw new Error(`mock backend missing command: ${command}`);
  }
  return fn(args ?? {}) as Promise<T>;
}

// ---------------------------------------------------------------------------
// Settings / init
// ---------------------------------------------------------------------------

export const appInit = () => call<InitInfo>("app_init");

export const saveSettings = (settings: Settings) =>
  call<Settings>("save_settings", {
    theme: settings.theme,
    clipboard_clear_seconds: settings.clipboard_clear_seconds,
    default_profile: settings.default_profile,
  });

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

export const listKeys = () => call<KeySummary[]>("list_keys");

export const keyDetails = (fpr: string) => call<KeyDetails>("key_details", { fpr });

export const generateKey = (req: GenerateRequest) => call<GenerateResult>("generate_key", { args: req });

export const importKey = (req: ImportRequest) => call<ImportPreview>("import_key", { args: req });

export const exportPublic = (fpr: string) => call<string>("export_public", { fpr });

export const deleteKey = (fpr: string) => call<boolean>("delete_key", { args: { fpr, confirm: true } });

// ---------------------------------------------------------------------------
// Message operations
// ---------------------------------------------------------------------------

export const encrypt = (req: EncryptRequest) => call<EncryptResult>("encrypt", { args: req });

export const decrypt = (req: DecryptRequest) => call<DecryptResult>("decrypt", { args: req });

export const sign = (req: SignRequest) => call<SignResult>("sign", { args: req });

export const verify = (req: VerifyRequest) => call<VerifyResult>("verify", { args: req });

// ---------------------------------------------------------------------------
// Key maintenance
// ---------------------------------------------------------------------------

export const generateRevocation = (req: RevocationRequest) =>
  call<RevocationResult>("generate_revocation", { args: req });

export const changePassphrase = (req: ChangePassphraseRequest) =>
  call<boolean>("change_passphrase", { args: req });

export const extendExpiry = (req: ExtendExpiryRequest) =>
  call<KeySummary>("extend_expiry", { args: req });

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------

export const copyKeyToClipboard = (fpr: string, kind: ClipboardKind) =>
  call<CopyResult>("copy_key_to_clipboard", { args: { fpr, kind } });

export const copyTextSecret = (content: string, label: string) =>
  call<CopyResult>("copy_text_secret", { content, label });

/**
 * Read the clipboard - ONLY ever call this from an explicit
 * "Paste from clipboard" button handler (plan §8: never watch, never poll).
 * Capped at 1 MB.
 */
export async function readClipboardText(): Promise<string> {
  const { readText } = await import("@tauri-apps/plugin-clipboard-manager");
  const text = await readText();
  if (text.length > 1024 * 1024) {
    throw new Error("clipboard content exceeds the 1 MB paste limit");
  }
  return text;
}
