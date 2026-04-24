import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { createModelClient } from './index.js';

test('createModelClient resolves registered provider clients', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () =>
    Response.json({ message: { content: '{"message":"ok"}' } })
  );

  try {
    const client = createModelClient({
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
