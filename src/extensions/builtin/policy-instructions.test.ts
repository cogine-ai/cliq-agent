import assert from 'node:assert/strict';
import test from 'node:test';

import { createSession } from '../../session/store.js';
import { policyInstructionsExtension } from './policy-instructions.js';

test('policy-instructions extension injects plan-mode guidance only in plan mode', async () => {
  const source = policyInstructionsExtension.instructionSources?.[0];
  assert.ok(source);

  const ctx = { cwd: '/tmp/workspace', session: createSession('/tmp/workspace') };

  assert.deepEqual(await source({ ...ctx, policyMode: 'default' }), []);
  assert.deepEqual(await source({ ...ctx, policyMode: 'accept-edits' }), []);
  assert.deepEqual(await source({ ...ctx, policyMode: 'yolo' }), []);

  const messages = await source({ ...ctx, policyMode: 'plan' });
  assert.equal(messages.length, 1);
  assert.equal(messages[0]?.role, 'system');
  assert.equal(messages[0]?.layer, 'extension');
  assert.equal(messages[0]?.source, 'policy-instructions');
  assert.match(messages[0]?.content ?? '', /Current policy mode is plan/);
  assert.match(messages[0]?.content ?? '', /write or exec step would be blocked/);
});
