import assert from 'node:assert/strict';
import test from 'node:test';

import { emitModelErrorEvent } from './events.js';
import type { ModelCompleteOptions } from './types.js';

test('emitModelErrorEvent forwards Error messages to the runtime event sink', async () => {
  const events: Array<{ type: string; message: string }> = [];
  const options: ModelCompleteOptions = {
    onEvent: async (event) => {
      if (event.type === 'error') events.push(event);
    }
  };

  await emitModelErrorEvent(options, new Error('provider unavailable'));

  assert.deepEqual(events, [{ type: 'error', message: 'provider unavailable' }]);
});

test('emitModelErrorEvent stringifies non-Error failures', async () => {
  const events: Array<{ type: string; message: string }> = [];
  const options: ModelCompleteOptions = {
    onEvent: async (event) => {
      if (event.type === 'error') events.push(event);
    }
  };

  await emitModelErrorEvent(options, 503);

  assert.deepEqual(events, [{ type: 'error', message: '503' }]);
});

test('emitModelErrorEvent is a no-op when the request signal is already aborted', async () => {
  const controller = new AbortController();
  controller.abort();

  let called = false;
  const options: ModelCompleteOptions = {
    signal: controller.signal,
    onEvent: async () => {
      called = true;
    }
  };

  await emitModelErrorEvent(options, new Error('late failure'));

  assert.equal(called, false);
});

test('emitModelErrorEvent swallows sink failures without throwing', async () => {
  const options: ModelCompleteOptions = {
    onEvent: async () => {
      throw new Error('sink unavailable');
    }
  };

  await assert.doesNotReject(() => emitModelErrorEvent(options, new Error('provider failure')));
});
