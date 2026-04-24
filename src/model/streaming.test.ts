import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

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
  const fetchMock = mock.method(globalThis, 'fetch', async () =>
    streamResponse([
      'data: {"choices":[{"delta":{"content":"{\\"message\\":\\""}}]}\n\n',
      'data: {"choices":[{"delta":{"content":"ok\\"}"}}]}\n\n',
      'data: [DONE]\n\n'
    ])
  );

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
  const fetchMock = mock.method(globalThis, 'fetch', async () =>
    streamResponse([
      'data:{"choices":[{"delta":{"content":"{\\"message\\":\\""}}]}\r\n\r\n',
      'data:{"choices":[{"delta":{"content":"ok\\"}"}}]}\r\n\r\n',
      'data:[DONE]\r\n\r\n'
    ])
  );

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
