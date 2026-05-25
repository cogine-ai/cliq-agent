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

test('rotation includes every canonical TUI mode', () => {
  assert.deepEqual(POLICY_ROTATION, ['plan', 'default', 'accept-edits', 'yolo']);
});

test('rotation includes yolo as the most dangerous mode', () => {
  assert.equal(POLICY_ROTATION[POLICY_ROTATION.length - 1], 'yolo');
});

test('rotation begins with the safest mode', () => {
  assert.equal(POLICY_ROTATION[0], 'plan');
});
