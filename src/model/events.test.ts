import assert from 'node:assert/strict';
import test from 'node:test';

import { emitModelErrorEvent } from './events.js';
import type { ModelCompleteOptions } from './types.js';

test('emitModelErrorEvent suppresses errors when the request signal is already aborted', async () => {
  const controller = new AbortController();
  controller.abort();

  let called = false;
  await emitModelErrorEvent(
    {
      signal: controller.signal,
      onEvent: async () => {
        called = true;
      }
    },
    new Error('provider failed')
  );

  assert.equal(called, false);
});

test('emitModelErrorEvent forwards Error messages to the event sink', async () => {
  const events: Array<{ type: string; message: string }> = [];
  const options: ModelCompleteOptions = {
    onEvent: async (event) => {
      if (event.type === 'error') {
        events.push(event);
      }
    }
  };

  await emitModelErrorEvent(options, new Error('upstream timeout'));
  assert.deepEqual(events, [{ type: 'error', message: 'upstream timeout' }]);
});

test('emitModelErrorEvent stringifies non-Error failures', async () => {
  const events: Array<{ type: string; message: string }> = [];
  await emitModelErrorEvent(
    {
      onEvent: async (event) => {
        if (event.type === 'error') {
          events.push(event);
        }
      }
    },
    'plain failure'
  );

  assert.deepEqual(events, [{ type: 'error', message: 'plain failure' }]);
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
