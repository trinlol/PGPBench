/**
 * Keys surface - Phase 2 Agent B replaces this file entirely.
 * Contract: default export named `Keys`, props: { defaultProfile }.
 */

import type { Profile } from "../types";

export function Keys({ defaultProfile }: { defaultProfile: Profile }) {
  return (
    <div className="rounded-xl border border-dashed border-neutral-300 p-8 text-center text-sm text-neutral-500 dark:border-neutral-700 dark:text-neutral-400">
      Keys surface - under construction (default profile: {defaultProfile}).
    </div>
  );
}
