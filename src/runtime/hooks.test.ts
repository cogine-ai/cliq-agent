import test from 'node:test';
import assert from 'node:assert/strict';

import { runHooks, type RuntimeHook } from './hooks.js';

test('runHooks continues after a hook throws', async () => {
  const events: string[] = [];
  const hooks: RuntimeHook[] = [
    {
      async beforeTurn() {
        events.push('first');
        throw new Error('boom');
      }
    },
    {
      async beforeTurn() {
        events.push('second');
      }
    }
  ];

  await runHooks(hooks, 'beforeTurn', {} as never, 'prompt');
  assert.deepEqual(events, ['first', 'second']);
});
