import assert from 'node:assert/strict';
import test from 'node:test';

import { emitModelErrorEvent } from './events.js';

test('emitModelErrorEvent suppresses events when the request signal is already aborted', async () => {
  const controller = new AbortController();
  controller.abort();
  const events: unknown[] = [];

  await emitModelErrorEvent(
    {
      signal: controller.signal,
      onEvent: async (event) => {
        events.push(event);
      }
    },
    new Error('provider failed')
  );

  assert.deepEqual(events, []);
});

test('emitModelErrorEvent forwards Error messages and stringifies non-Error failures', async () => {
  const events: Array<{ type: string; message: string }> = [];

  await emitModelErrorEvent(
    {
      onEvent: async (event) => {
        if (event.type === 'error') events.push(event);
      }
    },
    new Error('provider failed')
  );
  await emitModelErrorEvent(
    {
      onEvent: async (event) => {
        if (event.type === 'error') events.push(event);
      }
    },
    'plain failure'
  );

  assert.deepEqual(events, [
    { type: 'error', message: 'provider failed' },
    { type: 'error', message: 'plain failure' }
  ]);
});

test('emitModelErrorEvent swallows sink failures to preserve the original provider error', async () => {
  await assert.doesNotReject(() =>
    emitModelErrorEvent(
      {
        onEvent: async () => {
          throw new Error('sink exploded');
        }
      },
      new Error('provider failed')
    )
  );
});
