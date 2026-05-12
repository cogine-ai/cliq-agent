import type { PolicyMode } from '../policy/types.js';

// Shift+Tab cycles through this list. Ordered safest → most dangerous so the
// keystroke nudges the user toward more friction first; pressing it again
// loosens. confirm-all is intentionally not in the cycle: it is the most
// cautious mode and the TUI's default starting point, but cycling through
// "ask for every read" gets annoying fast. Reach it explicitly via
// `/policy confirm-all`.
export const POLICY_ROTATION: readonly PolicyMode[] = [
  'read-only',
  'confirm-write',
  'confirm-bash',
  'auto'
];

export function nextPolicyMode(current: PolicyMode): PolicyMode {
  const idx = POLICY_ROTATION.indexOf(current);
  if (idx === -1) {
    // confirm-all (or any mode not in the cycle) — enter at the safest end.
    return POLICY_ROTATION[0]!;
  }
  return POLICY_ROTATION[(idx + 1) % POLICY_ROTATION.length]!;
}
