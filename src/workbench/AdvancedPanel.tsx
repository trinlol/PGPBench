/**
 * Collapsed "Advanced" options for the Workbench (plan §5).
 *
 * Defaults are deliberately boring: Compatible/v4 profile, armor on,
 * compression off, no extra signing.
 */

import type { Profile } from "../types";
import { Badge, Disclosure } from "../components/ui";

export interface AdvancedOptions {
  profile: Profile;
  /** Sign the composed message while encrypting it. */
  sign: boolean;
  /** Armor the ciphertext (binary is base64-wrapped for display). */
  armor: boolean;
  compress: boolean;
  /** Sign with a detached signature instead of a cleartext one. */
  detachedSignature: boolean;
}

export function defaultAdvanced(profile: Profile): AdvancedOptions {
  return {
    profile,
    sign: false,
    armor: true,
    compress: false,
    detachedSignature: false,
  };
}

function ToggleRow({
  checked,
  onChange,
  label,
  hint,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
  hint?: string;
}) {
  return (
    <label className="flex cursor-pointer items-start gap-2">
      <input
        type="checkbox"
        className="mt-0.5 accent-indigo-600"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span className="min-w-0">
        <span className="block text-sm text-neutral-800 dark:text-neutral-200">{label}</span>
        {hint ? (
          <span className="block text-[11px] leading-snug text-neutral-500 dark:text-neutral-400">
            {hint}
          </span>
        ) : null}
      </span>
    </label>
  );
}

function ProfileOption({
  value,
  current,
  onSelect,
  title,
  subtitle,
  experimental = false,
}: {
  value: Profile;
  current: Profile;
  onSelect: (next: Profile) => void;
  title: string;
  subtitle: string;
  experimental?: boolean;
}) {
  return (
    <label className="flex cursor-pointer items-start gap-2">
      <input
        type="radio"
        name="workbench-profile"
        className="mt-0.5 accent-indigo-600"
        checked={current === value}
        onChange={() => onSelect(value)}
      />
      <span className="min-w-0">
        <span className="flex flex-wrap items-center gap-1.5">
          <span className="text-sm text-neutral-800 dark:text-neutral-200">{title}</span>
          {experimental ? <Badge tone="amber">experimental</Badge> : null}
        </span>
        <span className="block text-[11px] leading-snug text-neutral-500 dark:text-neutral-400">
          {subtitle}
        </span>
      </span>
    </label>
  );
}

export function AdvancedPanel({
  value,
  onChange,
}: {
  value: AdvancedOptions;
  onChange: (next: AdvancedOptions) => void;
}) {
  const set = <K extends keyof AdvancedOptions>(key: K, next: AdvancedOptions[K]) =>
    onChange({ ...value, [key]: next });

  return (
    <Disclosure label={<span className="text-xs">Advanced</span>}>
      <div className="space-y-3">
        <div>
          <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            OpenPGP profile
          </div>
          <div className="space-y-2">
            <ProfileOption
              value="compatible"
              current={value.profile}
              onSelect={(p) => set("profile", p)}
              title="Compatible (v4, works everywhere)"
              subtitle="Interoperates with GnuPG, Thunderbird and older clients."
            />
            <ProfileOption
              value="rfc9580"
              current={value.profile}
              onSelect={(p) => set("profile", p)}
              title="RFC 9580 (v6, experimental)"
              subtitle="Modern v6 keys; other clients may not read the output yet."
              experimental
            />
          </div>
        </div>

        <div className="space-y-2 border-t border-neutral-200 pt-2.5 dark:border-neutral-800">
          <ToggleRow
            checked={value.sign}
            onChange={(next) => set("sign", next)}
            label="Sign while encrypting"
            hint="Uses your own (encrypt-to-self) key and asks for its passphrase."
          />
          <ToggleRow
            checked={value.armor}
            onChange={(next) => set("armor", next)}
            label="ASCII armor output"
            hint="Off produces binary, shown as base64 for the clipboard."
          />
          <ToggleRow
            checked={value.compress}
            onChange={(next) => set("compress", next)}
            label="Compress before encrypting"
            hint="Off by default — short messages gain nothing."
          />
          <ToggleRow
            checked={value.detachedSignature}
            onChange={(next) => set("detachedSignature", next)}
            label="Detached signature when signing"
            hint="Off produces a cleartext signed message instead."
          />
        </div>
      </div>
    </Disclosure>
  );
}
