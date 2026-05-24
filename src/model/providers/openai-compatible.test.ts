import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { createOpenAICompatibleClient } from './openai-compatible.js';

async function expectModelCancellation(promise: Promise<unknown>) {
  await assert.rejects(
    Promise.race([
      promise,
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error('stream did not cancel')), 250);
      })
    ]),
    /Model request cancelled/
  );
}

test('openai-compatible client sends chat completions request', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    assert.equal(String(_url), 'http://localhost:4000/v1/chat/completions');
    assert.equal(init?.method, 'POST');
    assert.equal((init?.headers as Record<string, string>).authorization, 'Bearer local-key');
    assert.match(String(init?.body), /"model":"local-model"/);
    return Response.json({ choices: [{ message: { content: '{"message":"ok"}' } }] });
  });

  try {
    const client = createOpenAICompatibleClient({
      provider: 'openai-compatible',
      model: 'local-model',
      baseUrl: 'http://localhost:4000/v1',
      apiKey: 'local-key',
      streaming: 'off'
    });

    assert.deepEqual(await client.complete([{ role: 'user', content: 'hello' }]), {
      content: '{"message":"ok"}',
      provider: 'openai-compatible',
      model: 'local-model'
    });
  } finally {
    fetchMock.mock.restore();
  }
});

test('openai-compatible streaming cancels provider response body on abort', async () => {
  let cancelled = false;
  const fetchMock = mock.method(globalThis, 'fetch', async () => {
    return new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'));
        },
        cancel() {
          cancelled = true;
        }
      })
    );
  });

  try {
    const controller = new AbortController();
    const deltas: string[] = [];
    const client = createOpenAICompatibleClient({
      provider: 'openai-compatible',
      model: 'local-model',
      baseUrl: 'http://localhost:4000/v1',
      streaming: 'on'
    });

    await expectModelCancellation(
      client.complete([{ role: 'user', content: 'hello' }], {
        signal: controller.signal,
        onEvent(event) {
          if (event.type !== 'text-delta') return;
          deltas.push(event.text);
          controller.abort();
        }
      })
    );

    assert.deepEqual(deltas, ['partial']);
    assert.equal(cancelled, true);
  } finally {
    fetchMock.mock.restore();
  }
});

test('openai-compatible client rejects missing choices array', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => Response.json({ choices: {} }));

  try {
    const client = createOpenAICompatibleClient({
      provider: 'openai-compatible',
      model: 'local-model',
      baseUrl: 'http://localhost:4000/v1',
      streaming: 'off'
    });

    await assert.rejects(
      () => client.complete([{ role: 'user', content: 'hello' }]),
      /openai-compatible response missing choices\/content/
    );
  } finally {
    fetchMock.mock.restore();
  }
});

test('openai-compatible client preserves original error when error event handler fails', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => Response.json({ choices: {} }));

  try {
    let sawErrorEvent = false;
    const client = createOpenAICompatibleClient({
      provider: 'openai-compatible',
      model: 'local-model',
      baseUrl: 'http://localhost:4000/v1',
      streaming: 'off'
    });

    await assert.rejects(
      () =>
        client.complete([{ role: 'user', content: 'hello' }], {
          onEvent(event) {
            if (event.type === 'error') {
              sawErrorEvent = true;
              throw new Error('event handler failed');
            }
          }
        }),
      /openai-compatible response missing choices\/content/
    );
    assert.equal(sawErrorEvent, true);
  } finally {
    fetchMock.mock.restore();
  }
});

test('openai-compatible auto streaming falls back when streaming is rejected before body consumption', async () => {
  const seenStreamFlags: boolean[] = [];
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { stream?: boolean };
    seenStreamFlags.push(body.stream ?? false);

    if (body.stream) {
      return new Response('streaming unsupported', { status: 400 });
    }

    return Response.json({ choices: [{ message: { content: '{"message":"ok"}' } }] });
  });

  try {
    const starts: boolean[] = [];
    const client = createOpenAICompatibleClient({
      provider: 'openai-compatible',
      model: 'local-model',
      baseUrl: 'http://localhost:4000/v1',
      streaming: 'auto'
    });

    assert.deepEqual(
      await client.complete([{ role: 'user', content: 'hello' }], {
        onEvent(event) {
          if (event.type === 'start') starts.push(event.streaming);
        }
      }),
      {
      content: '{"message":"ok"}',
      provider: 'openai-compatible',
      model: 'local-model'
      }
    );
    assert.deepEqual(seenStreamFlags, [true, false]);
    assert.deepEqual(starts, [false]);
  } finally {
    fetchMock.mock.restore();
  }
});

test('openai-compatible streaming on does not fall back when streaming is rejected', async () => {
  const seenStreamFlags: boolean[] = [];
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { stream?: boolean };
    seenStreamFlags.push(body.stream ?? false);
    return new Response('streaming unsupported', { status: 400 });
  });

  try {
    const client = createOpenAICompatibleClient({
      provider: 'openai-compatible',
      model: 'local-model',
      baseUrl: 'http://localhost:4000/v1',
      streaming: 'on'
    });

    await assert.rejects(
      () => client.complete([{ role: 'user', content: 'hello' }]),
      /retry with --streaming off/i
    );
    assert.deepEqual(seenStreamFlags, [true]);
  } finally {
    fetchMock.mock.restore();
  }
});
