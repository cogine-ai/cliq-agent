import test, { mock } from 'node:test';
import assert from 'node:assert/strict';

import { createOpenRouterClient } from './openrouter.js';

function withOpenRouterClient(
  fetchImpl: (url: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => Promise<Response>
) {
  const fetchMock = mock.method(globalThis, 'fetch', fetchImpl);

  return {
    client: createOpenRouterClient({
      provider: 'openrouter',
      model: 'anthropic/claude-sonnet-4.6',
      baseUrl: 'https://openrouter.ai/api/v1',
      apiKey: 'test-key',
      streaming: 'off'
    }),
    restore() {
      fetchMock.mock.restore();
    }
  };
}

test('openrouter client passes an abort signal to fetch', async () => {
  let capturedSignal: AbortSignal | undefined;
  const fixture = withOpenRouterClient(async (_url: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
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
    const result = await fixture.client.complete([{ role: 'user', content: 'hello' }]);
    assert.deepEqual(result, {
      content: 'ok',
      provider: 'openrouter',
      model: 'anthropic/claude-sonnet-4.6'
    });
    assert.equal(capturedSignal instanceof AbortSignal, true);
  } finally {
    fixture.restore();
  }
});

test('openrouter client throws when choices content is missing', async () => {
  const fixture = withOpenRouterClient(async (_url: Parameters<typeof fetch>[0], _init?: Parameters<typeof fetch>[1]) => {
    return {
      ok: true,
      async json() {
        return { choices: [] };
      }
    } as Response;
  });

  try {
    await assert.rejects(
      () => fixture.client.complete([{ role: 'user', content: 'hello' }]),
      /missing choices\/content|missing choices|missing content/i
    );
  } finally {
    fixture.restore();
  }
});

test('openrouter client emits model error event when api key is missing', async () => {
  const client = createOpenRouterClient({
    provider: 'openrouter',
    model: 'anthropic/claude-sonnet-4.6',
    baseUrl: 'https://openrouter.ai/api/v1',
    streaming: 'off'
  });
  const events: string[] = [];

  await assert.rejects(
    () =>
      client.complete([{ role: 'user', content: 'hello' }], {
        onEvent(event) {
          if (event.type === 'error') {
            events.push(event.message);
          }
        }
      }),
    /OPENROUTER_API_KEY is required/
  );

  assert.deepEqual(events, ['OPENROUTER_API_KEY is required']);
});
