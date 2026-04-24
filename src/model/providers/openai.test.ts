import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { createOpenAIClient } from './openai.js';

test('openai client uses OpenAI base URL and bearer token', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    assert.equal(String(_url), 'https://api.openai.com/v1/chat/completions');
    assert.equal((init?.headers as Record<string, string>).authorization, 'Bearer openai-key');
    return Response.json({ choices: [{ message: { content: '{"message":"ok"}' } }] });
  });

  try {
    const client = createOpenAIClient({
      provider: 'openai',
      model: 'gpt-5.2',
      baseUrl: 'https://api.openai.com/v1',
      apiKey: 'openai-key',
      streaming: 'off'
    });

    const result = await client.complete([{ role: 'user', content: 'hello' }]);
    assert.equal(result.content, '{"message":"ok"}');
    assert.equal(result.provider, 'openai');
  } finally {
    fetchMock.mock.restore();
  }
});
