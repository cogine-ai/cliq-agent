import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { createOllamaClient } from './ollama.js';

test('ollama client sends native chat request', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    assert.equal(String(_url), 'http://localhost:11434/api/chat');
    assert.match(String(init?.body), /"model":"qwen3:14b"/);
    assert.match(String(init?.body), /"stream":false/);
    return Response.json({ message: { content: '{"message":"ok"}' } });
  });

  try {
    const client = createOllamaClient({
      provider: 'ollama',
      model: 'qwen3:14b',
      baseUrl: 'http://localhost:11434',
      streaming: 'off'
    });

    const result = await client.complete([{ role: 'user', content: 'hello' }]);
    assert.deepEqual(result, {
      content: '{"message":"ok"}',
      provider: 'ollama',
      model: 'qwen3:14b'
    });
  } finally {
    fetchMock.mock.restore();
  }
});
