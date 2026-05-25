import type { PolicyMode } from './types.js';

/**
 * The ordered list of valid {@link PolicyMode} strings. The CLI, slash
 * commands, headless contract, and workspace config validator all share
 * this single source of truth so adding/removing a preset in one place
 * keeps the others in sync.
 *
 * Ordering is the canonical public order used by CLI help, config
 * validation, headless validation, and TUI slash help.
 */
export const POLICY_MODES = [
  'default',
  'accept-edits',
  'plan',
  'yolo'
] as const satisfies readonly PolicyMode[];

export const POLICY_MODE_LIST = POLICY_MODES.join(', ');

const LEGACY_POLICY_MODE_HINTS: Record<string, string> = {
  auto: 'auto has been replaced by yolo',
  'confirm-write': 'confirm-write has been replaced by default',
  'read-only': 'read-only has been replaced by plan',
  'confirm-bash': 'confirm-bash has been replaced by accept-edits',
  'confirm-all': 'confirm-all is no longer available; use default for normal approvals or plan for inspection-only work'
};

export function isPolicyMode(value: string): value is PolicyMode {
  return (POLICY_MODES as readonly string[]).includes(value);
}

export function policyModeMigrationHint(value: string): string | undefined {
  return LEGACY_POLICY_MODE_HINTS[value];
}

export function formatPolicyModeError(value: string, subject = 'policy mode'): string {
  const migration = policyModeMigrationHint(value);
  const prefix = migration ? `${migration}; ` : `Unknown ${subject}: ${value}; `;
  return `${prefix}expected one of: ${POLICY_MODE_LIST}`;
}
