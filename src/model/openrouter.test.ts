import test, { mock } from 'node:test';
import assert from 'node:assert/strict';

import { createOpenRouterClient } from './openrouter.js';

test('openrouter client passes an abort signal to fetch', async () => {
  const originalKey = process.env.OPENROUTER_API_KEY;
  process.env.OPENROUTER_API_KEY = 'test-key';

  let capturedSignal: AbortSignal | undefined;
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    capturedSignal = init?.signal as AbortSignal | undefined;
    return {
      ok: true,
      async json() {
        return {
          choices: [{ message: { role: 'assistant', content: 'ok' } }]
        };
      }
    } as Response;
  });

  try {
    const client = createOpenRouterClient();
    const result = await client.complete([{ role: 'user', content: 'hello' }]);
    assert.equal(result, 'ok');
    assert.equal(capturedSignal instanceof AbortSignal, true);
  } finally {
    fetchMock.mock.restore();
    if (originalKey === undefined) {
      delete process.env.OPENROUTER_API_KEY;
    } else {
      process.env.OPENROUTER_API_KEY = originalKey;
    }
  }
});

test('openrouter client throws when choices content is missing', async () => {
  const originalKey = process.env.OPENROUTER_API_KEY;
  process.env.OPENROUTER_API_KEY = 'test-key';

  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], _init?: Parameters<typeof fetch>[1]) => {
    return {
      ok: true,
      async json() {
        return { choices: [] };
      }
    } as Response;
  });

  try {
    const client = createOpenRouterClient();
    await assert.rejects(
      () => client.complete([{ role: 'user', content: 'hello' }]),
      /missing choices\/content|missing choices|missing content/i
    );
  } finally {
    fetchMock.mock.restore();
    if (originalKey === undefined) {
      delete process.env.OPENROUTER_API_KEY;
    } else {
      process.env.OPENROUTER_API_KEY = originalKey;
    }
  }
});
