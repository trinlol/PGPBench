/**
 * Signature-verified in-app updates (Tauri updater plugin).
 *
 * This is the ONLY feature that can cause a network call, and it is
 * deliberate: it downloads from the project's GitHub releases and verifies a
 * minisign signature baked into the app before installing anything. The
 * check can be disabled entirely in Settings, and in browser-dev (mock)
 * mode it is a no-op.
 */

import { isTauri } from "./ipc";

export interface UpdateInfo {
  version: string;
  notes?: string;
  pubDate?: string;
}

/** Returns update info when a newer signed release exists, else null. */
export async function checkForUpdates(): Promise<UpdateInfo | null> {
  if (!isTauri()) return null;
  try {
    const { check } = await import("@tauri-apps/plugin-updater");
    const update = await check();
    if (!update) return null;
    return {
      version: update.version,
      notes: update.body ?? undefined,
      pubDate: update.date ?? undefined,
    };
  } catch {
    // Offline, endpoint unreachable, or no release manifest yet - stay quiet.
    return null;
  }
}

/**
 * Download and install the latest signed release, then relaunch the app.
 * onProgress receives the cumulative bytes downloaded (and total, when the
 * server advertises it).
 */
export async function installUpdate(
  onProgress?: (downloaded: number, total: number | null) => void,
): Promise<void> {
  if (!isTauri()) throw new Error("updates are only available in the app");
  const { check } = await import("@tauri-apps/plugin-updater");
  const { relaunch } = await import("@tauri-apps/plugin-process");

  const update = await check();
  if (!update) throw new Error("no update available");

  let total: number | null = null;
  let received = 0;
  await update.downloadAndInstall((event) => {
    switch (event.event) {
      case "Started":
        total = event.data.contentLength ?? null;
        received = 0;
        break;
      case "Progress":
        received += event.data.chunkLength;
        break;
      case "Finished":
        break;
    }
    if (onProgress) onProgress(received, total);
  });

  await relaunch();
}
