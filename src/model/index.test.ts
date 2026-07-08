import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { createModelClient } from './index.js';

test('createModelClient routes zhipu through the OpenAI-compatible client', async () => {
  let requestedUrl = '';
  const fetchMock = mock.method(globalThis, 'fetch', async (input: RequestInfo | URL) => {
    requestedUrl = String(input);
    return Response.json({
      choices: [{ message: { content: '{"message":"ok"}' } }]
    });
  });

  try {
    const client = createModelClient({
      provider: 'zhipu',
      model: 'glm-5.2',
      baseUrl: 'https://open.bigmodel.cn/api/coding/paas/v4',
      apiKey: 'zhipu-test-key',
      streaming: 'off'
    });
    const result = await client.complete([{ role: 'user', content: 'hello' }]);

    assert.match(requestedUrl, /open\.bigmodel\.cn\/api\/coding\/paas\/v4\/chat\/completions/);
    assert.deepEqual(result, {
      content: '{"message":"ok"}',
      provider: 'zhipu',
      model: 'glm-5.2'
    });
  } finally {
    fetchMock.mock.restore();
  }
});

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
