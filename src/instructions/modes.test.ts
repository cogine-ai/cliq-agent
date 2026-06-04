import assert from 'node:assert/strict';
import test from 'node:test';

import { buildPolicyModeInstructionMessages } from './modes.js';

test('buildPolicyModeInstructionMessages returns plan-mode guidance only in plan mode', () => {
  assert.deepEqual(buildPolicyModeInstructionMessages('default'), []);
  assert.deepEqual(buildPolicyModeInstructionMessages('yolo'), []);

  const messages = buildPolicyModeInstructionMessages('plan');
  assert.equal(messages.length, 1);
  assert.equal(messages[0]?.role, 'system');
  assert.equal(messages[0]?.layer, 'core');
  assert.equal(messages[0]?.source, 'mode:plan');
  assert.match(messages[0]?.content ?? '', /Plan Mode is active/);
  assert.match(messages[0]?.content ?? '', /must not modify source files/);
  assert.match(messages[0]?.content ?? '', /plan\.md as editable only while the artifact is draft/);
});
