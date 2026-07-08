import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import type { ResolvedModelConfig } from '../types.js';
import {
  CliqModelsRuntimeError,
  cliqModelIdToRuntimeTag,
  createCliqModelsClient
} from './cliq-models.js';

const cliqModelsConfig: ResolvedModelConfig = {
  provider: 'cliq-models',
  model: 'cliq-models/qwen3.5:4b',
  baseUrl: 'http://127.0.0.1:11435',
  streaming: 'off'
};

test('cliq-models translates Cliq model ids to managed runtime tags safely', () => {
  assert.equal(cliqModelIdToRuntimeTag('cliq-models/qwen3.5:4b'), 'qwen3.5:4b');
  assert.equal(cliqModelIdToRuntimeTag('qwen3.5:4b'), 'qwen3.5:4b');
  assert.equal(cliqModelIdToRuntimeTag('team/model_1:latest'), 'team/model_1:latest');

  assert.throws(() => cliqModelIdToRuntimeTag(''), /requires a model id/);
  assert.throws(() => cliqModelIdToRuntimeTag('qwen3.5:4b;rm -rf .'), /unsafe model id/);
});

test('cliq-models client checks readiness, sends translated model, and preserves provider identity', async () => {
  const requests: Array<{ url: string; body?: Record<string, unknown> }> = [];
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = String(_url);
    requests.push({
      url,
      ...(init?.body ? { body: JSON.parse(String(init.body)) as Record<string, unknown> } : {})
    });

    if (url === 'http://127.0.0.1:11435/api/version') {
      return Response.json({ version: '0.5.0-cliq', distribution: 'cliq-managed' });
    }
    if (url === 'http://127.0.0.1:11435/api/tags') {
      return Response.json({ models: [{ name: 'qwen3.5:4b' }] });
    }
    if (url === 'http://127.0.0.1:11435/api/chat') {
      assert.equal((requests.at(-1)?.body as { model?: string }).model, 'qwen3.5:4b');
      return Response.json({ message: { content: 'managed ok' } });
    }

    throw new Error(`unexpected URL ${url}`);
  });

  try {
    const events: unknown[] = [];
    const client = createCliqModelsClient(cliqModelsConfig);
    const result = await client.complete([{ role: 'user', content: 'hello' }], {
      onEvent(event) {
        events.push(event);
      }
    });

    assert.deepEqual(result, {
      content: 'managed ok',
      provider: 'cliq-models',
      model: 'cliq-models/qwen3.5:4b'
    });
    assert.deepEqual(
      requests.map((request) => request.url),
      [
        'http://127.0.0.1:11435/api/version',
        'http://127.0.0.1:11435/api/tags',
        'http://127.0.0.1:11435/api/chat'
      ]
    );
    assert.deepEqual(events[0], {
      type: 'start',
      provider: 'cliq-models',
      model: 'cliq-models/qwen3.5:4b',
      streaming: false
    });
  } finally {
    fetchMock.mock.restore();
  }
});

test('cliq-models client reports missing managed runtime with provider-specific guidance', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => {
    throw new Error('connect ECONNREFUSED 127.0.0.1:11435');
  });

  try {
    const client = createCliqModelsClient(cliqModelsConfig);
    await assert.rejects(
      () => client.complete([{ role: 'user', content: 'hello' }]),
      (error) => {
        assert.ok(error instanceof CliqModelsRuntimeError);
        assert.equal(error.code, 'CLIQ_MODELS_RUNTIME_UNAVAILABLE');
        assert.match(error.message, /Cliq Models managed runtime is unavailable/i);
        assert.match(error.message, /127\.0\.0\.1:11435/);
        return true;
      }
    );
  } finally {
    fetchMock.mock.restore();
  }
});

test('cliq-models client reports missing managed model before generation', async () => {
  let chatCalls = 0;
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0]) => {
    const url = String(_url);
    if (url.endsWith('/api/version')) {
      return Response.json({ version: '0.5.0-cliq' });
    }
    if (url.endsWith('/api/tags')) {
      return Response.json({ models: [{ name: 'llama3.2:latest' }] });
    }
    if (url.endsWith('/api/chat')) {
      chatCalls += 1;
    }
    throw new Error(`unexpected URL ${url}`);
  });

  try {
    const client = createCliqModelsClient(cliqModelsConfig);
    await assert.rejects(
      () => client.complete([{ role: 'user', content: 'hello' }]),
      (error) => {
        assert.ok(error instanceof CliqModelsRuntimeError);
        assert.equal(error.code, 'CLIQ_MODELS_MODEL_MISSING');
        assert.match(error.message, /Cliq Models model is not available/i);
        assert.match(error.message, /qwen3\.5:4b/);
        return true;
      }
    );
    assert.equal(chatCalls, 0);
  } finally {
    fetchMock.mock.restore();
  }
});

test('cliq-models client reports generation failures without leaking prompt content', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0]) => {
    const url = String(_url);
    if (url.endsWith('/api/version')) {
      return Response.json({ version: '0.5.0-cliq' });
    }
    if (url.endsWith('/api/tags')) {
      return Response.json({ models: [{ name: 'qwen3.5:4b' }] });
    }
    return new Response('runtime crash while handling prompt: hello secret prompt', { status: 500 });
  });

  try {
    const client = createCliqModelsClient(cliqModelsConfig);
    await assert.rejects(
      () => client.complete([{ role: 'user', content: 'hello secret prompt' }]),
      (error) => {
        assert.ok(error instanceof CliqModelsRuntimeError);
        assert.equal(error.code, 'CLIQ_MODELS_GENERATION_FAILED');
        assert.match(error.message, /Cliq Models generation failed/i);
        assert.match(error.message, /HTTP 500/);
        assert.doesNotMatch(error.message, /hello secret prompt/);
        return true;
      }
    );
  } finally {
    fetchMock.mock.restore();
  }
});
