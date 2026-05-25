import type { PolicyMode } from '../policy/types.js';

// Shift+Tab cycles through this list. Ordered safest -> most dangerous so the
// keystroke moves through progressively lower-friction modes.
export const POLICY_ROTATION: readonly PolicyMode[] = [
  'plan',
  'default',
  'accept-edits',
  'yolo'
];

export function nextPolicyMode(current: PolicyMode): PolicyMode {
  const idx = POLICY_ROTATION.indexOf(current);
  if (idx === -1) {
    // Any mode not in the cycle enters at the safest end.
    return POLICY_ROTATION[0]!;
  }
  return POLICY_ROTATION[(idx + 1) % POLICY_ROTATION.length]!;
}
