import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { fetchWithTimeout, joinUrl, readJsonResponse } from './http.js';

test('joinUrl normalizes trailing and leading slashes', () => {
  assert.equal(joinUrl('https://api.example.com/v1/', '/chat/completions'), 'https://api.example.com/v1/chat/completions');
  assert.equal(joinUrl('https://api.example.com/v1', 'chat/completions'), 'https://api.example.com/v1/chat/completions');
  assert.equal(joinUrl('https://api.example.com///', '///models'), 'https://api.example.com/models');
});

test('fetchWithTimeout surfaces timeout failures distinctly from cancellation', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    await new Promise<void>((_resolve, reject) => {
      const onAbort = () => reject(Object.assign(new Error('Aborted'), { name: 'AbortError' }));
      if (init?.signal?.aborted) {
        onAbort();
        return;
      }
      init?.signal?.addEventListener('abort', onAbort, { once: true });
    });
    return new Response('never');
  });

  try {
    await assert.rejects(
      fetchWithTimeout('https://example.com/slow', {}, 50),
      /Model request timed out after 50ms/
    );

    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      fetchWithTimeout('https://example.com/cancelled', { signal: controller.signal }, 5_000),
      /Model request cancelled/
    );
  } finally {
    fetchMock.mock.restore();
  }
});

test('fetchWithTimeout returns the underlying fetch response on success', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => {
    return new Response('ok', { status: 200 });
  });

  try {
    const response = await fetchWithTimeout('https://example.com/ok', { method: 'GET' }, 1_000);
    assert.equal(response.status, 200);
    assert.equal(await response.text(), 'ok');
  } finally {
    fetchMock.mock.restore();
  }
});

test('readJsonResponse throws provider-scoped errors with response bodies', async () => {
  await assert.rejects(
    readJsonResponse(new Response('rate limited', { status: 429 }), 'OpenRouter'),
    /OpenRouter error 429: rate limited/
  );

  const payload = await readJsonResponse<{ id: string }>(
    new Response(JSON.stringify({ id: 'resp_123' }), { status: 200 }),
    'OpenAI'
  );
  assert.deepEqual(payload, { id: 'resp_123' });
});
