import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { createAnthropicClient } from './anthropic.js';

test('anthropic client sends messages request', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    assert.equal(String(_url), 'https://api.anthropic.com/v1/messages');
    const headers = init?.headers as Record<string, string>;
    assert.equal(headers['x-api-key'], 'anthropic-key');
    assert.equal(headers['anthropic-version'], '2023-06-01');
    const body = JSON.parse(String(init?.body)) as { model: string; max_tokens: number };
    assert.equal(body.model, 'claude-sonnet-4-20250514');
    assert.equal(body.max_tokens, 2048);
    return Response.json({ content: [{ type: 'text', text: '{"message":"ok"}' }] });
  });

  try {
    const client = createAnthropicClient({
      provider: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      baseUrl: 'https://api.anthropic.com',
      apiKey: 'anthropic-key',
      streaming: 'off',
      maxOutputTokens: 2048
    });

    const result = await client.complete([{ role: 'user', content: 'hello' }]);
    assert.equal(result.content, '{"message":"ok"}');
    assert.equal(result.provider, 'anthropic');
  } finally {
    fetchMock.mock.restore();
  }
});

test('anthropic client fails before request when api key is missing', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => Response.json({}));

  try {
    const client = createAnthropicClient({
      provider: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      baseUrl: 'https://api.anthropic.com',
      streaming: 'off'
    });

    await assert.rejects(() => client.complete([{ role: 'user', content: 'hello' }]), /ANTHROPIC_API_KEY is required/);
    assert.equal(fetchMock.mock.callCount(), 0);
  } finally {
    fetchMock.mock.restore();
  }
});

test('anthropic client accepts base url with v1 path', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0]) => {
    assert.equal(String(_url), 'https://api.anthropic.com/v1/messages');
    return Response.json({ content: [{ type: 'text', text: '{"message":"ok"}' }] });
  });

  try {
    const client = createAnthropicClient({
      provider: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      baseUrl: 'https://api.anthropic.com/v1',
      apiKey: 'anthropic-key',
      streaming: 'off'
    });

    const result = await client.complete([{ role: 'user', content: 'hello' }]);
    assert.equal(result.content, '{"message":"ok"}');
  } finally {
    fetchMock.mock.restore();
  }
});
