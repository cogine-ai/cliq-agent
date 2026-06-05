import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import type { ModelCapabilities, ResolvedModelConfig } from '../types.js';
import { buildModelPromptRequest } from '../prompt.js';
import { createToolRegistry } from '../../tools/registry.js';
import { createOllamaClient } from './ollama.js';

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

const ollamaConfig: ResolvedModelConfig = {
  provider: 'ollama',
  model: 'qwen3:14b',
  baseUrl: 'http://localhost:11434',
  streaming: 'auto'
};

const ollamaWeakCapabilities: ModelCapabilities = {
  input: ['text'],
  output: ['text'],
  streaming: true,
  reasoning: false,
  toolCalling: false
};

function ollamaPrompt() {
  return buildModelPromptRequest({
    modelConfig: ollamaConfig,
    modelCapabilities: ollamaWeakCapabilities,
    instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
    input: [{ kind: 'message', role: 'user', content: 'hello' }],
    registry: createToolRegistry()
  });
}

test('ollama client sends native chat request', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    assert.equal(String(_url), 'http://localhost:11434/api/chat');
    assert.match(String(init?.body), /"model":"qwen3:14b"/);
    assert.match(String(init?.body), /"stream":false/);
    return Response.json({ message: { content: '{"message":"ok"}' } });
  });

  try {
    const client = createOllamaClient({
      provider: 'ollama',
      model: 'qwen3:14b',
      baseUrl: 'http://localhost:11434',
      streaming: 'off'
    });

    const result = await client.complete([{ role: 'user', content: 'hello' }]);
    assert.deepEqual(result, {
      content: '{"message":"ok"}',
      provider: 'ollama',
      model: 'qwen3:14b'
    });
  } finally {
    fetchMock.mock.restore();
  }
});

test('ollama typed prompt uses structured format before weak-model text-action fallback', async () => {
  const seen: { body?: Record<string, unknown> } = {};
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    seen.body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return new Response('{"message":{"content":"{\\"type\\":\\"final\\",\\"message\\":\\"ok\\"}"}}\n');
  });

  try {
    const client = createOllamaClient(ollamaConfig);
    const result = await client.complete(ollamaPrompt());

    const messages = seen.body?.messages as Array<{ role: string; content: string }>;
    assert.equal(seen.body?.stream, true);
    assert.equal((seen.body?.format as { type?: string }).type, 'object');
    assert.equal(messages.some((message) => message.content.includes('STRUCTURED TOOL SCHEMA MODE') && message.content.includes('bash')), true);
    assert.deepEqual(result.structuredOutput, { type: 'final', message: 'ok' });
    assert.equal(result.effectiveRequest?.mode, 'structured-output');
    assert.equal(result.effectiveRequest?.streaming, true);
    assert.equal(result.effectiveRequest?.textActionFallback?.maxAttempts, 2);
  } finally {
    fetchMock.mock.restore();
  }
});

test('ollama streaming cancels provider response body on abort', async () => {
  let cancelled = false;
  const fetchMock = mock.method(globalThis, 'fetch', async () => {
    return new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"message":{"content":"partial"}}\n'));
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
    const client = createOllamaClient({
      provider: 'ollama',
      model: 'qwen3:14b',
      baseUrl: 'http://localhost:11434',
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

test('ollama client preserves original provider error when error event handler fails', async () => {
  const originalError = new Error('ollama unavailable');
  const fetchMock = mock.method(globalThis, 'fetch', async () => {
    throw originalError;
  });

  try {
    const client = createOllamaClient({
      provider: 'ollama',
      model: 'qwen3:14b',
      baseUrl: 'http://localhost:11434',
      streaming: 'off'
    });

    await assert.rejects(
      () =>
        client.complete([{ role: 'user', content: 'hello' }], {
          onEvent(event) {
            if (event.type === 'error') {
              throw new Error('event sink failed');
            }
          }
        }),
      /ollama unavailable/
    );
  } finally {
    fetchMock.mock.restore();
  }
});
