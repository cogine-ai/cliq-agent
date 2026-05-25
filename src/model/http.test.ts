import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { fetchWithTimeout, joinUrl } from './http.js';

test('joinUrl normalizes trailing and leading slashes', () => {
  assert.equal(joinUrl('https://api.example.com/', '/v1/messages'), 'https://api.example.com/v1/messages');
  assert.equal(joinUrl('https://api.example.com', 'v1/messages'), 'https://api.example.com/v1/messages');
});

test('fetchWithTimeout reports a timeout instead of a caller cancellation', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    return new Promise((_resolve, reject) => {
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
    await assert.rejects(
      () => fetchWithTimeout('http://example.test/slow', {}, 50),
      /Model request timed out after 50ms/
    );
  } finally {
    fetchMock.mock.restore();
  }
});

test('fetchWithTimeout reports caller cancellation before the timeout elapses', async () => {
  const controller = new AbortController();
  const fetchMock = mock.method(globalThis, 'fetch', (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    return new Promise((_resolve, reject) => {
      if (init?.signal?.aborted) {
        reject(new DOMException('The operation was aborted.', 'AbortError'));
        return;
      }
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
      () => fetchWithTimeout('http://example.test', { signal: controller.signal }, 60_000),
      /Model request cancelled/
    );
  } finally {
    fetchMock.mock.restore();
  }
});
