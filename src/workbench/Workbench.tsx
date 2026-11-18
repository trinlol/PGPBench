/**
 * Workbench surface - Phase 2 Agent A replaces this file entirely.
 * Contract: default export named `Workbench`, props: { defaultProfile }.
 */

import type { Profile } from "../types";

export function Workbench({ defaultProfile }: { defaultProfile: Profile }) {
  return (
    <div className="rounded-xl border border-dashed border-neutral-300 p-8 text-center text-sm text-neutral-500 dark:border-neutral-700 dark:text-neutral-400">
      Workbench surface - under construction (default profile: {defaultProfile}).
    </div>
  );
}
