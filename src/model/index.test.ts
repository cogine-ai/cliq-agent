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

test('createModelClient routes Zhipu through the OpenAI-compatible client', async () => {
  let requestUrl = '';
  const fetchMock = mock.method(globalThis, 'fetch', async (input: RequestInfo | URL) => {
    requestUrl = String(input);
    return Response.json({
      choices: [{ message: { content: '{"message":"ok"}' } }]
    });
  });

  try {
    const client = createModelClient({
      provider: 'zhipu',
      model: 'glm-5.2',
      baseUrl: 'https://open.bigmodel.cn/api/coding/paas/v4',
      apiKey: 'zhipu-key',
      streaming: 'off'
    });
    const result = await client.complete([{ role: 'user', content: 'hello' }]);
    assert.deepEqual(result, {
      content: '{"message":"ok"}',
      provider: 'zhipu',
      model: 'glm-5.2'
    });
    assert.match(requestUrl, /open\.bigmodel\.cn\/api\/coding\/paas\/v4\/chat\/completions/);
  } finally {
    fetchMock.mock.restore();
  }
});
