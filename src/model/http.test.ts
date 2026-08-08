import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import {
  fetchWithTimeout,
  joinUrl,
  readJsonResponse,
  readNdjsonDeltas,
  readSseDeltas,
  readTextStream
} from './http.js';

test('joinUrl normalizes trailing and leading slashes', () => {
  assert.equal(joinUrl('https://api.example.com/v1/', '/chat/completions'), 'https://api.example.com/v1/chat/completions');
  assert.equal(joinUrl('https://api.example.com/v1', 'chat/completions'), 'https://api.example.com/v1/chat/completions');
  assert.equal(joinUrl('https://api.example.com/v1///', '///messages'), 'https://api.example.com/v1/messages');
});

test('readJsonResponse returns parsed JSON on success', async () => {
  const payload = await readJsonResponse<{ ok: boolean }>(
    new Response(JSON.stringify({ ok: true }), { status: 200 }),
    'test-provider'
  );
  assert.deepEqual(payload, { ok: true });
});

test('readJsonResponse includes provider name and response body on failure', async () => {
  await assert.rejects(
    () => readJsonResponse(new Response('bad request', { status: 400 }), 'zhipu'),
    /zhipu error 400: bad request/
  );
});

test('fetchWithTimeout rejects with a timeout message when the request exceeds the limit', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    return await new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => {
        const error = new Error('The operation was aborted');
        error.name = 'AbortError';
        reject(error);
      });
    });
  });

  try {
    await assert.rejects(
      () => fetchWithTimeout('https://api.example.com/v1/chat/completions', { method: 'POST' }, 20),
      /timed out after 20ms/
    );
  } finally {
    fetchMock.mock.restore();
  }
});

test('fetchWithTimeout rejects with a cancellation message when the external signal aborts', async () => {
  const controller = new AbortController();
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    return await new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => {
        const error = new Error('The operation was aborted');
        error.name = 'AbortError';
        reject(error);
      });
    });
  });

  try {
    const promise = fetchWithTimeout(
      'https://api.example.com/v1/chat/completions',
      { method: 'POST', signal: controller.signal },
      5_000
    );
    controller.abort();
    await assert.rejects(promise, /cancelled/);
  } finally {
    fetchMock.mock.restore();
  }
});

test('fetchWithTimeout propagates non-abort fetch failures', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => {
    throw new Error('network down');
  });

  try {
    await assert.rejects(
      () => fetchWithTimeout('https://api.example.com/v1/chat/completions', { method: 'POST' }, 50),
      /network down/
    );
  } finally {
    fetchMock.mock.restore();
  }
});

test('readTextStream rejects missing bodies and non-ok responses', async () => {
  await assert.rejects(
    () => readTextStream(new Response(null, { status: 200 }), async () => {}),
    /missing a body/
  );
  await assert.rejects(
    () => readTextStream(new Response('nope', { status: 500 }), async () => {}),
    /Model stream error 500: nope/
  );
});

test('readSseDeltas extracts text deltas and skips malformed frames', async () => {
  const deltas: string[] = [];
  const warnings: string[] = [];
  const warn = console.warn;
  console.warn = (message: string) => {
    warnings.push(message);
  };

  try {
    const content = await readSseDeltas(
      new Response(
        [
          'data: {"delta":"hello"}\n\n',
          'data: not-json\n\n',
          'data: {"delta":" world"}\n\n',
          'data: [DONE]\n\n'
        ].join('')
      ),
      (json) => (json as { delta?: string }).delta ?? null,
      async (text) => {
        deltas.push(text);
      }
    );

    assert.equal(content, 'hello world');
    assert.deepEqual(deltas, ['hello', ' world']);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, /Malformed model SSE payload skipped/);
  } finally {
    console.warn = warn;
  }
});

test('readNdjsonDeltas extracts line deltas and skips malformed lines', async () => {
  const deltas: string[] = [];
  const warnings: string[] = [];
  const warn = console.warn;
  console.warn = (message: string) => {
    warnings.push(message);
  };

  try {
    const content = await readNdjsonDeltas(
      new Response('{"delta":"a"}\nnot-json\n{"delta":"b"}\n'),
      (json) => (json as { delta?: string }).delta ?? null,
      async (text) => {
        deltas.push(text);
      }
    );

    assert.equal(content, 'ab');
    assert.deepEqual(deltas, ['a', 'b']);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, /Malformed model NDJSON payload skipped/);
  } finally {
    console.warn = warn;
  }
});
