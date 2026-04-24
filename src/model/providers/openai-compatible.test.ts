import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { createOpenAICompatibleClient } from './openai-compatible.js';

test('openai-compatible client sends chat completions request', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    assert.equal(String(_url), 'http://localhost:4000/v1/chat/completions');
    assert.equal(init?.method, 'POST');
    assert.match(String(init?.body), /"model":"local-model"/);
    return Response.json({ choices: [{ message: { content: '{"message":"ok"}' } }] });
  });

  try {
    const client = createOpenAICompatibleClient({
      provider: 'openai-compatible',
      model: 'local-model',
      baseUrl: 'http://localhost:4000/v1',
      apiKey: 'local-key',
      streaming: 'off'
    });

    assert.deepEqual(await client.complete([{ role: 'user', content: 'hello' }]), {
      content: '{"message":"ok"}',
      provider: 'openai-compatible',
      model: 'local-model'
    });
  } finally {
    fetchMock.mock.restore();
  }
});
