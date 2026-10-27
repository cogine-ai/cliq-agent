import { types } from 'node:util';

// Fixed diagnostics only. No request, identifier, path, exception text, time,
// retry permission or evidence of an upgrade operation is carried here.
export const INSTALLED_RUNTIME_UPGRADE_PHASES = ['read_schema', 'recover_selection', 'source_open', 'source_services',
  'source_control', 'stage_original', 'stage_source', 'stage_cas', 'stage_owner_history', 'stage_native',
  'stop_original', 'credential_exclusion', 'conversion', 'publish_selection', 'target_open', 'target_services',
  'target_control', 'output', 'unknown'] as const;
export type InstalledRuntimeUpgradePhase = typeof INSTALLED_RUNTIME_UPGRADE_PHASES[number];
const codes = ['ARTIFACT_MISMATCH', 'RECOVERY_REQUIRED', 'LEASE_FENCED', 'STATE_TRANSITION_INVALID',
  'UNSUPPORTED_PLATFORM', 'CLOCK_UNTRUSTED', 'BUDGET_EXHAUSTED', 'ENOENT', 'EACCES', 'unclassified'] as const;
const prefix = 'CLIQ_INSTALLED_UPGRADE_FAILURE_V1:';
const markers = new Map(INSTALLED_RUNTIME_UPGRADE_PHASES.flatMap(phase => codes.map(code => {
  const marker = `${prefix}${phase}:${code}`; return [marker, marker] as const;
})));

export function installedRuntimeUpgradeFailureMarker(phase: unknown, error: unknown): string {
  const fixedPhase = typeof phase === 'string' && (INSTALLED_RUNTIME_UPGRADE_PHASES as readonly string[]).includes(phase) ? phase : 'unknown';
  let code: string = 'unclassified';
  if (typeof error === 'object' && error !== null && !types.isProxy(error)) {
    const property = Object.getOwnPropertyDescriptor(error, 'code');
    if (property && 'value' in property && typeof property.value === 'string' && (codes as readonly string[]).includes(property.value)) code = property.value;
  }
  return `${prefix}${fixedPhase}:${code}\n`;
}

/** Read only the original source's exact fixed line after the caller's complete
 * secret scan. Duplicate/foreign lines never replace the actual exit refusal. */
export function readInstalledRuntimeUpgradeFailureMarker(bytes: Buffer): Buffer | undefined {
  if (types.isProxy(bytes) || !Buffer.isBuffer(bytes) || bytes.length > 2 * 1024 * 1024) return undefined;
  let found: string | undefined, position = 0;
  while (position < bytes.length) {
    const newline = bytes.indexOf(10, position), end = newline < 0 ? bytes.length : newline;
    const length = end - position;
    if (length >= prefix.length && length <= 128) {
      const value = bytes.subarray(position, end).toString('utf8'), fixed = markers.get(value);
      if (fixed) { if (found !== undefined) return undefined; found = fixed; }
    }
    position = end + 1;
  }
  return found === undefined ? undefined : Buffer.from(found + '\n');
}
