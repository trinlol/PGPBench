/**
 * Human-readable text for any thrown value.
 *
 * Tauri command failures arrive in the webview as serialized AppError objects
 * ({ kind, message }) rather than Error instances - naive String(err) turns
 * those into "[object Object]" and hides the actual explanation. Always use
 * this to display errors.
 */
export function errText(err: unknown): string {
  if (typeof err === "string") return err;
  if (err instanceof Error) return err.message || err.name;
  if (err && typeof err === "object") {
    const obj = err as Record<string, unknown>;
    if (typeof obj.message === "string" && obj.message) return obj.message;
    if (typeof obj.error === "string" && obj.error) return obj.error;
    try {
      const asJson = JSON.stringify(err);
      if (asJson && asJson !== "{}" && asJson !== "null") return asJson;
    } catch {
      /* fall through */
    }
  }
  return String(err);
}
