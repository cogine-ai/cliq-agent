import type { PolicyMode } from './types.js';

/**
 * The ordered list of valid {@link PolicyMode} strings. The CLI, slash
 * commands, headless contract, and workspace config validator all share
 * this single source of truth so adding/removing a preset in one place
 * keeps the others in sync.
 *
 * Ordering reflects "safest → most permissive" for any caller that wants
 * to display them as a menu (notably the TUI policy-rotation cycle in
 * src/tui/policy-rotation.ts uses a curated subset).
 */
export const POLICY_MODES = [
  'auto',
  'confirm-write',
  'read-only',
  'confirm-bash',
  'confirm-all'
] as const satisfies readonly PolicyMode[];

export const POLICY_MODE_LIST = POLICY_MODES.join(', ');

export function isPolicyMode(value: string): value is PolicyMode {
  return (POLICY_MODES as readonly string[]).includes(value);
}
