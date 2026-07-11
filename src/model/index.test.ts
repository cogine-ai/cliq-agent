import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { createModelClient } from './index.js';

test('createModelClient routes zhipu through the openai-compatible client', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    assert.equal(String(_url), 'https://open.bigmodel.cn/api/coding/paas/v4/chat/completions');
    assert.equal(init?.method, 'POST');
    assert.equal((init?.headers as Record<string, string>).authorization, 'Bearer zhipu-key');
    assert.match(String(init?.body), /"model":"glm-5\.2"/);
    return Response.json({ choices: [{ message: { content: '{"message":"ok"}' } }] });
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
