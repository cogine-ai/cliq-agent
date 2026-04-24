import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { readNdjsonDeltas, readSseDeltas } from './http.js';
import { createOpenAICompatibleClient } from './providers/openai-compatible.js';

function streamResponse(chunks: string[]) {
  const encoder = new TextEncoder();
  return new Response(
    new ReadableStream({
      start(controller) {
        for (const chunk of chunks) {
          controller.enqueue(encoder.encode(chunk));
        }
        controller.close();
      }
    }),
    { status: 200 }
  );
}

test('openai-compatible client streams deltas and returns buffered content', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    assert.equal(String(_url), 'http://localhost:4000/v1/chat/completions');
    assert.equal((JSON.parse(String(init?.body)) as { stream?: boolean }).stream, true);
    return streamResponse([
      'data: {"choices":[{"delta":{"content":"{\\"message\\":\\""}}]}\n\n',
      'data: {"choices":[{"delta":{"content":"ok\\"}"}}]}\n\n',
      'data: [DONE]\n\n'
    ]);
  });

  try {
    const events: string[] = [];
    const client = createOpenAICompatibleClient({
      provider: 'openai-compatible',
      model: 'local-model',
      baseUrl: 'http://localhost:4000/v1',
      streaming: 'on'
    });

    const result = await client.complete([{ role: 'user', content: 'hello' }], {
      onEvent(event) {
        if (event.type === 'text-delta') events.push(event.text);
      }
    });

    assert.equal(result.content, '{"message":"ok"}');
    assert.deepEqual(events, ['{"message":"', 'ok"}']);
  } finally {
    fetchMock.mock.restore();
  }
});

test('openai-compatible client accepts compact sse frames with crlf separators', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    assert.equal(String(_url), 'http://localhost:4000/v1/chat/completions');
    assert.equal((JSON.parse(String(init?.body)) as { stream?: boolean }).stream, true);
    return streamResponse([
      'data:{"choices":[{"delta":{"content":"{\\"message\\":\\""}}]}\r\n\r\n',
      'data:{"choices":[{"delta":{"content":"ok\\"}"}}]}\r\n\r\n',
      'data:[DONE]\r\n\r\n'
    ]);
  });

  try {
    const events: string[] = [];
    const client = createOpenAICompatibleClient({
      provider: 'openai-compatible',
      model: 'local-model',
      baseUrl: 'http://localhost:4000/v1',
      streaming: 'on'
    });

    const result = await client.complete([{ role: 'user', content: 'hello' }], {
      onEvent(event) {
        if (event.type === 'text-delta') events.push(event.text);
      }
    });

    assert.equal(result.content, '{"message":"ok"}');
    assert.deepEqual(events, ['{"message":"', 'ok"}']);
  } finally {
    fetchMock.mock.restore();
  }
});

test('readSseDeltas skips malformed payloads and keeps valid deltas', async () => {
  const warnMock = mock.method(console, 'warn', () => {});
  const deltas: string[] = [];

  try {
    const content = await readSseDeltas(
      streamResponse(['data:not-json\n\n', 'data:{"delta":"ok"}\n\n']),
      (json) => (json as { delta?: string }).delta ?? null,
      async (text) => {
        deltas.push(text);
      }
    );

    assert.equal(content, 'ok');
    assert.deepEqual(deltas, ['ok']);
    assert.equal(warnMock.mock.callCount(), 1);
    assert.match(String(warnMock.mock.calls[0]?.arguments[0]), /Malformed model SSE payload skipped/);
  } finally {
    warnMock.mock.restore();
  }
});

test('readNdjsonDeltas skips malformed payloads and keeps valid deltas', async () => {
  const warnMock = mock.method(console, 'warn', () => {});
  const deltas: string[] = [];

  try {
    const content = await readNdjsonDeltas(
      streamResponse(['not-json\n', '{"message":{"content":"ok"}}\n']),
      (json) => (json as { message?: { content?: string } }).message?.content ?? null,
      async (text) => {
        deltas.push(text);
      }
    );

    assert.equal(content, 'ok');
    assert.deepEqual(deltas, ['ok']);
    assert.equal(warnMock.mock.callCount(), 1);
    assert.match(String(warnMock.mock.calls[0]?.arguments[0]), /Malformed model NDJSON payload skipped/);
  } finally {
    warnMock.mock.restore();
  }
});
