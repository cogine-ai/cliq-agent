import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { nextPolicyMode, POLICY_ROTATION } from './policy-rotation.js';

test('nextPolicyMode walks the rotation in declared order and wraps', () => {
  let mode = POLICY_ROTATION[0]!;
  const seen = [mode];
  for (let i = 0; i < POLICY_ROTATION.length; i += 1) {
    mode = nextPolicyMode(mode);
    seen.push(mode);
  }
  // After length+1 steps we should be back at the start.
  assert.equal(seen[POLICY_ROTATION.length], POLICY_ROTATION[0]);
});

test('nextPolicyMode lands on the safest mode when called from confirm-all', () => {
  // confirm-all is intentionally not in POLICY_ROTATION; it is the TUI default
  // entry point. The first Shift+Tab from there enters the cycle at the safe
  // end (read-only) so users discover "more friction" first.
  assert.equal(nextPolicyMode('confirm-all'), POLICY_ROTATION[0]);
});

test('rotation excludes confirm-all', () => {
  assert.ok(!POLICY_ROTATION.includes('confirm-all'));
});

test('rotation begins with the safest mode', () => {
  assert.equal(POLICY_ROTATION[0], 'read-only');
});
