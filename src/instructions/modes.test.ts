import assert from 'node:assert/strict';
import test from 'node:test';

import { buildPolicyModeInstructionMessages } from './modes.js';
import { POLICY_MODES } from '../policy/modes.js';

test('buildPolicyModeInstructionMessages returns plan guidance only in plan mode', () => {
  for (const mode of POLICY_MODES) {
    const messages = buildPolicyModeInstructionMessages(mode);
    if (mode === 'plan') {
      assert.equal(messages.length, 1);
      assert.deepEqual(messages[0], {
        role: 'system',
        layer: 'core',
        source: 'mode:plan',
        content: messages[0]?.content
      });
      assert.match(messages[0]?.content ?? '', /Plan Mode is active/);
      assert.match(messages[0]?.content ?? '', /must not modify source files/i);
      assert.match(messages[0]?.content ?? '', /must not run bash\/exec/i);
      assert.match(messages[0]?.content ?? '', /switches out of Plan Mode/i);
      continue;
    }

    assert.deepEqual(messages, [], mode);
  }
});
