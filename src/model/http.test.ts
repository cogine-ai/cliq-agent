import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { fetchWithTimeout, joinUrl, readJsonResponse } from './http.js';

test('joinUrl normalizes trailing and leading slashes', () => {
  assert.equal(joinUrl('http://localhost:4000/v1/', '/chat/completions'), 'http://localhost:4000/v1/chat/completions');
  assert.equal(joinUrl('http://localhost:4000/v1', 'chat/completions'), 'http://localhost:4000/v1/chat/completions');
  assert.equal(joinUrl('http://localhost:4000/v1///', '///chat/completions'), 'http://localhost:4000/v1/chat/completions');
});

test('fetchWithTimeout reports timeout when the request does not complete in time', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    return await new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => {
        reject(new DOMException('The operation was aborted.', 'AbortError'));
      });
    });
  });

  try {
    await assert.rejects(
      () => fetchWithTimeout('http://example.test/slow', {}, 25),
      /timed out after 25ms/
    );
  } finally {
    fetchMock.mock.restore();
  }
});

test('fetchWithTimeout reports cancellation when the caller aborts early', async () => {
  const controller = new AbortController();
  controller.abort();

  const fetchMock = mock.method(globalThis, 'fetch', async () => {
    throw new DOMException('The operation was aborted.', 'AbortError');
  });

  try {
    await assert.rejects(
      () => fetchWithTimeout('http://example.test/cancelled', { signal: controller.signal }, 25),
      /cancelled/
    );
    await assert.rejects(
      () => fetchWithTimeout('http://example.test/cancelled', { signal: controller.signal }, 25),
      (error: Error) => !/timed out/i.test(error.message)
    );
  } finally {
    fetchMock.mock.restore();
  }
});

test('readJsonResponse throws provider errors with status and body text', async () => {
  const response = new Response('invalid api key', { status: 401 });
  await assert.rejects(
    () => readJsonResponse(response, 'TestProvider'),
    /TestProvider error 401: invalid api key/
  );
});

test('readJsonResponse returns parsed JSON for successful responses', async () => {
  const response = new Response(JSON.stringify({ ok: true }), { status: 200 });
  assert.deepEqual(await readJsonResponse<{ ok: boolean }>(response, 'TestProvider'), { ok: true });
});
