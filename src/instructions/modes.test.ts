import assert from 'node:assert/strict';
import test from 'node:test';

import { buildPolicyModeInstructionMessages } from './modes.js';

test('buildPolicyModeInstructionMessages injects plan constraints only in plan mode', () => {
  for (const mode of ['default', 'accept-edits', 'yolo'] as const) {
    assert.deepEqual(buildPolicyModeInstructionMessages(mode), []);
  }

  const messages = buildPolicyModeInstructionMessages('plan');
  assert.equal(messages.length, 1);
  assert.deepEqual(messages[0], {
    role: 'system',
    layer: 'core',
    source: 'mode:plan',
    content: [
      'Plan Mode is active.',
      'Inspect and analyze the workspace, then produce a concrete plan before implementation.',
      'You must not modify source files.',
      'You must not run bash/exec or other side-effecting commands.',
      'If the user asks you to implement, provide the plan and explain that execution requires switching out of Plan Mode.'
    ].join('\n')
  });
});
