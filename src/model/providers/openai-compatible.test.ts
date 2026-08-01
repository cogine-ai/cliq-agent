import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import type { ModelCapabilities, ResolvedModelConfig } from '../types.js';
import { buildModelPromptRequest, resolveProviderPromptCapabilities } from '../prompt.js';
import { createToolRegistry } from '../../tools/registry.js';
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

const typedConfig: ResolvedModelConfig = {
  provider: 'openai-compatible',
  model: 'local-model',
  baseUrl: 'http://localhost:4000/v1',
  apiKey: 'local-key',
  streaming: 'auto'
};

const textModelCapabilities: ModelCapabilities = {
  input: ['text'],
  output: ['text'],
  streaming: true,
  reasoning: false,
  toolCalling: true
};

function typedPrompt(capabilities: ModelCapabilities = textModelCapabilities) {
  return buildModelPromptRequest({
    modelConfig: typedConfig,
    modelCapabilities: capabilities,
    instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
    input: [{ kind: 'message', role: 'user', content: 'hello' }],
    registry: createToolRegistry()
  });
}

function sseResponse(...payloads: unknown[]) {
  return new Response(
    payloads.map((payload) => `data: ${typeof payload === 'string' ? payload : JSON.stringify(payload)}\n\n`).join('') +
      'data: [DONE]\n\n'
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

test('openai-compatible typed prompt sends native tool schemas and parses structured tool calls', async () => {
  const seen: { body?: Record<string, unknown> } = {};
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    seen.body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return sseResponse({
      choices: [
        {
          delta: {
            tool_calls: [
              {
                index: 0,
                id: 'call_1',
                function: {
                  name: 'bash',
                  arguments: '{"command":"pwd"}'
                }
              }
            ]
          }
        }
      ]
    });
  });

  try {
    const client = createOpenAICompatibleClient(typedConfig);
    const result = await client.complete(typedPrompt());

    assert.equal((seen.body?.tools as Array<{ function: { name: string } }>)[0]?.function.name, 'bash');
    assert.equal(seen.body?.tool_choice, 'auto');
    assert.equal(seen.body?.stream, true);
    assert.deepEqual(result.toolCalls, [{ id: 'call_1', name: 'bash', arguments: { command: 'pwd' } }]);
    assert.equal(result.effectiveRequest?.mode, 'native-tools');
    assert.equal(result.effectiveRequest?.streaming, true);
  } finally {
    fetchMock.mock.restore();
  }
});

test('openai-compatible typed prompt uses JSON schema when native tool calling is unavailable', async () => {
  const seen: { body?: Record<string, unknown> } = {};
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    seen.body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return sseResponse({ choices: [{ delta: { content: '{"type":"final","message":"ok"}' } }] });
  });

  try {
    const client = createOpenAICompatibleClient(typedConfig);
    const result = await client.complete(
      typedPrompt({
        ...textModelCapabilities,
        toolCalling: false
      })
    );

    const responseFormat = seen.body?.response_format as { type?: string; json_schema?: { name?: string } };
    const messages = seen.body?.messages as Array<{ role: string; content: string }>;
    assert.equal(responseFormat.type, 'json_schema');
    assert.equal(responseFormat.json_schema?.name, 'cliq_response');
    assert.equal(messages.some((message) => message.content.includes('STRUCTURED TOOL SCHEMA MODE') && message.content.includes('bash')), true);
    assert.equal(seen.body?.stream, true);
    assert.deepEqual(result.structuredOutput, { type: 'final', message: 'ok' });
    assert.equal(result.effectiveRequest?.mode, 'structured-output');
    assert.equal(result.effectiveRequest?.streaming, true);
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

test('openai-compatible typed prompt uses text-action fallback for Zhipu without native tools or schema', async () => {
  const seen: { body?: Record<string, unknown> } = {};
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    seen.body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return Response.json({
      choices: [{ message: { content: '{"type":"tool","tool":"bash","arguments":{"command":"pwd"}}' } }]
    });
  });

  try {
    const zhipuConfig: ResolvedModelConfig = {
      provider: 'zhipu',
      model: 'glm-5.2',
      baseUrl: 'https://open.bigmodel.cn/api/coding/paas/v4',
      apiKey: 'zhipu-key',
      streaming: 'off'
    };
    const request = buildModelPromptRequest({
      modelConfig: zhipuConfig,
      modelCapabilities: textModelCapabilities,
      providerCapabilities: resolveProviderPromptCapabilities({
        modelConfig: zhipuConfig,
        modelCapabilities: textModelCapabilities
      }),
      instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
      input: [{ kind: 'message', role: 'user', content: 'hello' }],
      registry: createToolRegistry()
    });
    const client = createOpenAICompatibleClient(zhipuConfig);
    const result = await client.complete(request);

    const messages = seen.body?.messages as Array<{ role: string; content: string }>;
    assert.equal(seen.body?.tools, undefined);
    assert.equal(seen.body?.response_format, undefined);
    assert.equal(messages.some((message) => message.content.includes('TEXT ACTION FALLBACK MODE')), true);
    assert.deepEqual(result.structuredOutput, {
      type: 'tool',
      tool: 'bash',
      arguments: { command: 'pwd' }
    });
    assert.equal(result.effectiveRequest?.mode, 'text-action');
    assert.equal(result.effectiveRequest?.streaming, false);
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
