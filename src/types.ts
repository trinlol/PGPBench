/**
 * PocketPGP IPC contract — shared between the Rust command layer (serde) and
 * the webview UI. Rust structs MUST serialize exactly as defined here.
 *
 * Security rule (plan §3): only public material, metadata, results and
 * verification outcomes cross this boundary. Private key material never does
 * (copying a private key to the clipboard happens entirely inside Rust).
 */

export type Profile = "compatible" | "rfc9580";
export type KeySource = "own" | "imported";
export type Algo = "ecc" | "rsa3072" | "rsa4096";
export type RevocationReason = "none" | "compromised" | "superseded" | "retired";

/** A key as shown in the flat list / index.json cache. */
export interface KeySummary {
  /** Uppercase hex primary fingerprint, no separators. */
  fpr: string;
  /** Full user id strings, e.g. "Alice <alice@example.com>". */
  uids: string[];
  /** Human label, e.g. "Ed25519 (ECC Curve25519)" or "RSA 4096". */
  algo: string;
  /** Unix seconds (UTC). */
  created: number;
  /** Unix seconds or null for "never". */
  expires: number | null;
  has_secret: boolean;
  profile: Profile;
  source: KeySource;
  revoked: boolean;
  /** True when evaluated at list time (now > expires). */
  expired: boolean;
  /** True if the key has a usable (non-revoked, non-expired) encryption subkey. */
  can_encrypt: boolean;
}

export interface SubkeyInfo {
  /** Fingerprint of this subkey. */
  fpr: string;
  algo: string;
  created: number;
  expires: number | null;
  /** Capability letters among S (sign), E (encrypt), A (authenticate), C (certify). */
  capabilities: string[];
  revoked: boolean;
  expired: boolean;
}

export interface KeyDetails {
  summary: KeySummary;
  subkeys: SubkeyInfo[];
  /** Policy warnings (missing key-flag subpackets, SHA-1 artifacts, ...). */
  warnings: string[];
}

/** What `import_key({ dryRun: true })` shows before the user confirms. */
export interface ImportPreview {
  ok: boolean;
  /** Hard-reject reason when `ok` is false. */
  error: string | null;
  key: KeySummary | null;
  /** True when the pasted block was a private key block. */
  secret: boolean;
  /** Soft warnings the user should see before confirming. */
  warnings: string[];
  /** True if saving would replace an already-stored key with the same fingerprint. */
  would_replace: boolean;
}

export interface ImportRequest {
  armored: string;
  dryRun: boolean;
  /** Advanced: allow legacy keys without key-flag subpackets. */
  allowLegacy: boolean;
}

export interface GenerateRequest {
  name: string;
  email: string;
  comment: string | null;
  /** Passphrase used only for this operation; never persisted. */
  passphrase: string | null;
  algo: Algo;
  profile: Profile;
  /** ISO-8601 date ("2027-11-18") or null for "never". */
  expires: string | null;
}

export interface GenerateResult {
  key: KeySummary;
  /** Armored public key — safe to display. */
  public_key: string;
  /** Armored revocation certificate — public material by design. */
  revocation_cert: string;
}

export interface SignatureInfo {
  /** Signer primary fingerprint (uppercase hex). */
  fpr: string;
  /** Best-effort display: signer's user id, when the key is known to us. */
  key_uid: string | null;
  key_source: "own" | "imported" | "unknown";
  /** Unix seconds of signature creation, if present. */
  signed_at: number | null;
  valid: boolean;
  /** The signing key is revoked — shown as a red flag even if the signature itself checks out. */
  revoked: boolean;
}

export interface DecryptResult {
  plaintext: string;
  /** Embedded signatures, verified after decryption (decrypt-then-verify). Empty if unsigned. */
  signatures: SignatureInfo[];
  warnings: string[];
}

export interface VerifyResult {
  ok: boolean;
  error: string | null;
  /** For cleartext / message signatures: the canonical signed text. */
  signed_text: string | null;
  signatures: SignatureInfo[];
  warnings: string[];
}

export interface EncryptRequest {
  message: string;
  /** Fingerprints of keyring recipients. */
  recipient_fprs: string[];
  /** One-off pasted public keys (armored). */
  one_off_public_keys: string[];
  /** Encrypt-to-self default is resolved by the UI (it passes the own fpr here). */
  sign_with_fpr: string | null;
  /** Passphrase for the signing key, when signing. */
  sign_passphrase: string | null;
  profile: Profile;
  /** v4 contexts require armor for clipboard transport; binary is base64-wrapped for display. */
  armor: boolean;
  compress: boolean;
}

export interface EncryptResult {
  /** Armored ciphertext, or base64 of binary output when `armor` is false. */
  output: string;
  binary: boolean;
  /** Soft warnings (e.g. v6 recipients inside a Compatible-profile message). */
  warnings: string[];
}

export interface SignRequest {
  message: string;
  fpr: string;
  passphrase: string | null;
  mode: "cleartext" | "detached";
}

export interface SignResult {
  output: string;
}

export interface DecryptRequest {
  input: string;
  passphrase: string | null;
}

export interface VerifyRequest {
  input: string;
  /** Detached signature block, when verifying a detached signature. */
  detached: string | null;
}

export interface RevocationRequest {
  fpr: string;
  passphrase: string | null;
  reason: RevocationReason;
  reason_text: string | null;
}

export interface RevocationResult {
  /** Armored revocation certificate; also persisted as keys/<FPR>.rev.asc. */
  revocation_cert: string;
}

export interface ChangePassphraseRequest {
  fpr: string;
  old_passphrase: string | null;
  new_passphrase: string | null;
}

export interface RenameKeyRequest {
  fpr: string;
  name: string;
  /** May be empty. */
  email: string;
  /** May be empty or absent. */
  comment: string | null;
  /** Passphrase for the re-signing operation; never persisted. */
  passphrase: string | null;
}

export interface ExtendExpiryRequest {
  fpr: string;
  passphrase: string | null;
  /** ISO-8601 date or null for "never". Applies to the primary key and all subkeys. */
  expires: string | null;
}

export interface Settings {
  /** "system" follows the Windows theme until the user picks one. */
  theme: "light" | "dark" | "system";
  /** 0 disables auto-clear. Default 60. */
  clipboard_clear_seconds: number;
  default_profile: Profile;
  /**
   * Optional signature-verified update check on launch - the app's only
   * possible network call. Can be disabled in Settings.
   */
  check_updates_on_launch: boolean;
}

export interface InitInfo {
  settings: Settings;
  /** True when the data-directory ACL looks like a per-user profile dir. */
  acl_ok: boolean;
  acl_note: string | null;
  /** Human-readable path of the key store, for display only. */
  data_dir: string;
}

/** Which pre-shaped text block the Workbench detected in the paste surface. */
export type DetectedKind =
  | "message"
  | "cleartext"
  | "public_key"
  | "private_key"
  | "detached_signature"
  | "text";

export interface CopyResult {
  label: string;
  auto_clear_seconds: number;
}

export type ClipboardKind = "public" | "private" | "revocation";
