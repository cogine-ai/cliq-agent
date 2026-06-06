import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import type { ModelCapabilities, ResolvedModelConfig } from '../types.js';
import { buildModelPromptRequest } from '../prompt.js';
import { createToolRegistry } from '../../tools/registry.js';
import { createOpenRouterClient } from './openrouter.js';

const typedOpenRouterConfig: ResolvedModelConfig = {
  provider: 'openrouter',
  model: 'openai/gpt-4o-mini',
  baseUrl: 'https://openrouter.ai/api/v1',
  apiKey: 'openrouter-key',
  streaming: 'on'
};

const typedOpenRouterCapabilities: ModelCapabilities = {
  input: ['text'],
  output: ['text'],
  streaming: true,
  reasoning: false,
  toolCalling: true
};

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

test('openrouter streaming cancels provider response body on abort', async () => {
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
    const client = createOpenRouterClient({
      provider: 'openrouter',
      model: 'openai/gpt-4o-mini',
      baseUrl: 'https://openrouter.ai/api/v1',
      apiKey: 'openrouter-key',
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

test('openrouter typed streaming surfaces non-2xx response details before SSE parsing', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => {
    return new Response('{"error":"bad auth"}', { status: 401, statusText: 'Unauthorized' });
  });

  try {
    const prompt = buildModelPromptRequest({
      modelConfig: typedOpenRouterConfig,
      modelCapabilities: typedOpenRouterCapabilities,
      instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
      input: [{ kind: 'message', role: 'user', content: 'hello' }],
      registry: createToolRegistry()
    });
    const client = createOpenRouterClient(typedOpenRouterConfig);
    const errors: string[] = [];

    await assert.rejects(
      () =>
        client.complete(prompt, {
          onEvent(event) {
            if (event.type === 'error') {
              errors.push(event.message);
            }
          }
        }),
      /OpenRouter stream error 401 Unauthorized: \{"error":"bad auth"\}/
    );
    assert.deepEqual(errors, ['OpenRouter stream error 401 Unauthorized: {"error":"bad auth"}']);
  } finally {
    fetchMock.mock.restore();
  }
});
