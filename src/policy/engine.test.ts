import assert from 'node:assert/strict';
import test from 'node:test';

import { createPolicyEngine } from './engine.js';
import type { ToolAccess } from './types.js';

function definition(name: string, access: ToolAccess) {
  return { name, access };
}

test('read-only denies write and exec access', async () => {
  const policy = createPolicyEngine({ mode: 'read-only' });

  assert.deepEqual(await policy.authorize(definition('read', 'read')), { allowed: true });
  assert.deepEqual(await policy.authorize(definition('edit', 'write')), {
    allowed: false,
    reason: 'policy mode read-only blocks write tools'
  });
  assert.deepEqual(await policy.authorize(definition('bash', 'exec')), {
    allowed: false,
    reason: 'policy mode read-only blocks exec tools'
  });
});

test('confirm-write only prompts for write tools', async () => {
  const prompts: string[] = [];
  const policy = createPolicyEngine({
    mode: 'confirm-write',
    confirm: async (prompt) => {
      prompts.push(prompt);
      return false;
    }
  });

  assert.deepEqual(await policy.authorize(definition('read', 'read')), { allowed: true });
  assert.deepEqual(await policy.authorize(definition('edit', 'write')), {
    allowed: false,
    reason: 'user declined confirmation'
  });
  assert.equal(prompts.length, 1);
  assert.match(prompts[0] ?? '', /edit/i);
});
