import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { fetchWithTimeout, joinUrl, readJsonResponse } from './http.js';

test('joinUrl normalizes trailing and leading slashes', () => {
  assert.equal(joinUrl('https://api.example.com/v1/', '/chat/completions'), 'https://api.example.com/v1/chat/completions');
  assert.equal(joinUrl('https://api.example.com/v1', 'chat/completions'), 'https://api.example.com/v1/chat/completions');
  assert.equal(joinUrl('https://api.example.com///', '///models'), 'https://api.example.com/models');
});

test('fetchWithTimeout rejects with timeout message when the request exceeds the limit', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    return await new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener(
        'abort',
        () => {
          const error = new Error('aborted');
          error.name = 'AbortError';
          reject(error);
        },
        { once: true }
      );
    });
  });

  try {
    await assert.rejects(
      () => fetchWithTimeout('https://example.test/slow', { method: 'GET' }, 25),
      /Model request timed out after 25ms/
    );
  } finally {
    fetchMock.mock.restore();
  }
});

test('fetchWithTimeout rejects with cancellation message when the external signal aborts', async () => {
  const controller = new AbortController();
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    return await new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener(
        'abort',
        () => {
          const error = new Error('aborted');
          error.name = 'AbortError';
          reject(error);
        },
        { once: true }
      );
    });
  });

  try {
    const promise = fetchWithTimeout('https://example.test/cancel', { method: 'GET', signal: controller.signal }, 5_000);
    controller.abort();
    await assert.rejects(promise, /Model request cancelled/);
  } finally {
    fetchMock.mock.restore();
  }
});

test('readJsonResponse throws provider-scoped errors for non-OK responses', async () => {
  await assert.rejects(
    () => readJsonResponse(new Response('bad gateway', { status: 502 }), 'zhipu'),
    /zhipu error 502: bad gateway/
  );
});

test('readJsonResponse parses JSON bodies for successful responses', async () => {
  const json = await readJsonResponse<{ ok: boolean }>(
    Response.json({ ok: true }),
    'openai-compatible'
  );
  assert.deepEqual(json, { ok: true });
});
