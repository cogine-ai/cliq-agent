import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { fetchWithTimeout, joinUrl, readJsonResponse } from './http.js';

test('joinUrl normalizes trailing and leading slashes', () => {
  assert.equal(joinUrl('https://api.example.com/v1/', '/chat/completions'), 'https://api.example.com/v1/chat/completions');
  assert.equal(joinUrl('https://api.example.com', 'chat/completions'), 'https://api.example.com/chat/completions');
});

test('readJsonResponse parses success bodies and surfaces provider errors', async () => {
  const ok = await readJsonResponse<{ ok: boolean }>(
    new Response(JSON.stringify({ ok: true }), { status: 200 }),
    'TestProvider'
  );
  assert.deepEqual(ok, { ok: true });

  await assert.rejects(
    readJsonResponse(new Response('rate limited', { status: 429 }), 'OpenRouter'),
    /OpenRouter error 429: rate limited/
  );
});

test('fetchWithTimeout rejects with timeout message when the timer fires first', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', () => new Promise<Response>(() => {}));

  try {
    await assert.rejects(fetchWithTimeout('https://example.test/slow', {}, 25), /Model request timed out after 25ms/);
  } finally {
    fetchMock.mock.restore();
  }
});

test('fetchWithTimeout rejects with cancellation message when aborted externally', async () => {
  const controller = new AbortController();
  const fetchMock = mock.method(globalThis, 'fetch', (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    return new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener(
        'abort',
        () => {
          reject(new DOMException('The operation was aborted.', 'AbortError'));
        },
        { once: true }
      );
    });
  });

  try {
    controller.abort();
    await assert.rejects(
      fetchWithTimeout('https://example.test/cancel', { signal: controller.signal }, 5_000),
      /Model request cancelled/
    );
  } finally {
    fetchMock.mock.restore();
  }
});
