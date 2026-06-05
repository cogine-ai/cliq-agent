import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import type { ModelCapabilities, ResolvedModelConfig } from '../types.js';
import { buildModelPromptRequest } from '../prompt.js';
import { createToolRegistry } from '../../tools/registry.js';
import { createAnthropicClient } from './anthropic.js';

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

const typedAnthropicConfig: ResolvedModelConfig = {
  provider: 'anthropic',
  model: 'claude-sonnet-4-20250514',
  baseUrl: 'https://api.anthropic.com',
  apiKey: 'anthropic-key',
  streaming: 'off'
};

const typedAnthropicCapabilities: ModelCapabilities = {
  input: ['text'],
  output: ['text'],
  streaming: true,
  reasoning: false,
  toolCalling: true
};

test('anthropic client sends messages request', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    assert.equal(String(_url), 'https://api.anthropic.com/v1/messages');
    const headers = init?.headers as Record<string, string>;
    assert.equal(headers['x-api-key'], 'anthropic-key');
    assert.equal(headers['anthropic-version'], '2023-06-01');
    const body = JSON.parse(String(init?.body)) as { model: string; max_tokens: number };
    assert.equal(body.model, 'claude-sonnet-4-20250514');
    assert.equal(body.max_tokens, 2048);
    return Response.json({ content: [{ type: 'text', text: '{"message":"ok"}' }] });
  });

  try {
    const client = createAnthropicClient({
      provider: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      baseUrl: 'https://api.anthropic.com',
      apiKey: 'anthropic-key',
      streaming: 'off',
      maxOutputTokens: 2048
    });

    const events: string[] = [];
    const result = await client.complete([{ role: 'user', content: 'hello' }], {
      onEvent(event) {
        if (event.type === 'error') events.push(event.message);
      }
    });
    assert.equal(result.content, '{"message":"ok"}');
    assert.equal(result.provider, 'anthropic');
    assert.equal(result.model, 'claude-sonnet-4-20250514');
    assert.deepEqual(events, []);
  } finally {
    fetchMock.mock.restore();
  }
});

test('anthropic typed prompt serializes native tool history as content blocks', async () => {
  const seen: { body?: Record<string, unknown> } = {};
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    seen.body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return Response.json({ content: [{ type: 'text', text: '{"type":"final","message":"ok"}' }] });
  });

  try {
    const prompt = buildModelPromptRequest({
      modelConfig: typedAnthropicConfig,
      modelCapabilities: typedAnthropicCapabilities,
      instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
      input: [
        {
          kind: 'message',
          role: 'assistant',
          content: '',
          toolCalls: [{ id: 'call_1', name: 'bash', arguments: { command: 'pwd' } }]
        },
        {
          kind: 'tool_result',
          toolName: 'bash',
          status: 'ok',
          content: 'TOOL_RESULT bash OK\n/Users/example',
          callId: 'call_1'
        }
      ],
      registry: createToolRegistry()
    });
    const client = createAnthropicClient(typedAnthropicConfig);
    const result = await client.complete(prompt);

    const messages = seen.body?.messages as Array<{ role: string; content: Array<Record<string, unknown>> }>;
    assert.equal((seen.body?.tools as Array<{ name: string }>)[0]?.name, 'bash');
    assert.deepEqual(messages[0], {
      role: 'assistant',
      content: [{ type: 'tool_use', id: 'call_1', name: 'bash', input: { command: 'pwd' } }]
    });
    assert.deepEqual(messages[1], {
      role: 'user',
      content: [{ type: 'tool_result', tool_use_id: 'call_1', content: 'TOOL_RESULT bash OK\n/Users/example' }]
    });
    assert.equal(result.effectiveRequest?.mode, 'native-tools');
  } finally {
    fetchMock.mock.restore();
  }
});

test('anthropic streaming cancels provider response body on abort', async () => {
  let cancelled = false;
  const fetchMock = mock.method(globalThis, 'fetch', async () => {
    return new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(
            new TextEncoder().encode(
              'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"partial"}}\n\n'
            )
          );
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
    const client = createAnthropicClient({
      provider: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      baseUrl: 'https://api.anthropic.com',
      apiKey: 'anthropic-key',
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

test('anthropic client fails before request when api key is missing', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => Response.json({}));

  try {
    const client = createAnthropicClient({
      provider: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      baseUrl: 'https://api.anthropic.com',
      streaming: 'off'
    });

    const events: string[] = [];
    await assert.rejects(
      () =>
        client.complete([{ role: 'user', content: 'hello' }], {
          onEvent(event) {
            if (event.type === 'error') events.push(event.message);
          }
        }),
      /ANTHROPIC_API_KEY is required/
    );
    assert.equal(fetchMock.mock.callCount(), 0);
    assert.deepEqual(events, ['ANTHROPIC_API_KEY is required']);
  } finally {
    fetchMock.mock.restore();
  }
});

test('anthropic client rejects invalid content array shape', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => Response.json({ content: {} }));

  try {
    const client = createAnthropicClient({
      provider: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      baseUrl: 'https://api.anthropic.com',
      apiKey: 'anthropic-key',
      streaming: 'off'
    });

    await assert.rejects(
      () => client.complete([{ role: 'user', content: 'hello' }]),
      /Anthropic response missing or invalid content array/
    );
  } finally {
    fetchMock.mock.restore();
  }
});

test('anthropic client accepts base url with v1 path', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0]) => {
    assert.equal(String(_url), 'https://api.anthropic.com/v1/messages');
    return Response.json({ content: [{ type: 'text', text: '{"message":"ok"}' }] });
  });

  try {
    const client = createAnthropicClient({
      provider: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      baseUrl: 'https://api.anthropic.com/v1',
      apiKey: 'anthropic-key',
      streaming: 'off'
    });

    const result = await client.complete([{ role: 'user', content: 'hello' }]);
    assert.equal(result.content, '{"message":"ok"}');
  } finally {
    fetchMock.mock.restore();
  }
});
