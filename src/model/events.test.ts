import assert from 'node:assert/strict';
import test from 'node:test';

import { emitModelErrorEvent } from './events.js';
import type { ModelStreamEvent } from './types.js';

test('emitModelErrorEvent forwards Error messages to the runtime event sink', async () => {
  const events: ModelStreamEvent[] = [];
  await emitModelErrorEvent(
    {
      onEvent: async (event) => {
        events.push(event);
      }
    },
    new Error('provider exploded')
  );
  assert.deepEqual(events, [{ type: 'error', message: 'provider exploded' }]);
});

test('emitModelErrorEvent stringifies non-Error failures', async () => {
  const events: ModelStreamEvent[] = [];
  await emitModelErrorEvent(
    {
      onEvent: async (event) => {
        events.push(event);
      }
    },
    'socket reset'
  );
  assert.deepEqual(events, [{ type: 'error', message: 'socket reset' }]);
});

test('emitModelErrorEvent is a no-op when the request signal is already aborted', async () => {
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
    new Error('late failure')
  );
  assert.equal(called, false);
});

test('emitModelErrorEvent swallows sink failures without masking the original provider error', async () => {
  let sinkCalls = 0;
  await emitModelErrorEvent(
    {
      onEvent: async () => {
        sinkCalls += 1;
        throw new Error('sink failed');
      }
    },
    new Error('provider exploded')
  );
  assert.equal(sinkCalls, 1);
});
