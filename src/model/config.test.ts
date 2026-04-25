import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { resolveModelConfig } from './config.js';

const MODEL_ENV_KEYS = [
  'CLIQ_MODEL_PROVIDER',
  'CLIQ_MODEL',
  'CLIQ_MODEL_BASE_URL',
  'CLIQ_MODEL_STREAMING',
  'CLIQ_MODEL_API_KEY',
  'OPENROUTER_API_KEY',
  'ANTHROPIC_API_KEY',
  'OPENAI_API_KEY',
  'OPENAI_COMPATIBLE_API_KEY'
] as const;

async function withEnv<T>(env: Record<string, string | undefined>, fn: () => T | Promise<T>) {
  const previous = new Map<string, string | undefined>();
  for (const key of MODEL_ENV_KEYS) {
    previous.set(key, process.env[key]);
    delete process.env[key];
  }

  for (const [key, value] of Object.entries(env)) {
    previous.set(key, process.env[key]);
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }

  try {
    return await fn();
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

test('resolveModelConfig defaults to a discovered local Ollama model', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0]) => {
    assert.equal(String(_url), 'http://localhost:11434/api/tags');
    return Response.json({ models: [{ name: 'llama3.2:latest' }, { name: 'qwen3:4b' }] });
  });

  try {
    await withEnv({}, async () => {
      assert.deepEqual(await resolveModelConfig({ workspace: {}, cli: {} }), {
        provider: 'ollama',
        model: 'qwen3:4b',
        baseUrl: 'http://localhost:11434',
        streaming: 'auto'
      });
    });
  } finally {
    fetchMock.mock.restore();
  }
});

test('resolveModelConfig falls back to the first local Ollama model when no qwen model exists', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () =>
    Response.json({ models: [{ name: 'llama3.2:latest' }, { name: 'mistral:latest' }] })
  );

  try {
    await withEnv({}, async () => {
      assert.deepEqual(await resolveModelConfig({ workspace: {}, cli: {} }), {
        provider: 'ollama',
        model: 'llama3.2:latest',
        baseUrl: 'http://localhost:11434',
        streaming: 'auto'
      });
    });
  } finally {
    fetchMock.mock.restore();
  }
});

test('resolveModelConfig explains how to configure a model when local Ollama has no models', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => Response.json({ models: [] }));

  try {
    await withEnv({}, async () => {
      await assert.rejects(
        () => resolveModelConfig({ workspace: {}, cli: {} }),
        /No model provider or local Ollama model configured[\s\S]*ollama pull/i
      );
    });
  } finally {
    fetchMock.mock.restore();
  }
});

test('resolveModelConfig preserves explicit OpenRouter configuration', async () => {
  await withEnv({ OPENROUTER_API_KEY: 'or-key' }, async () => {
    assert.deepEqual(await resolveModelConfig({ workspace: {}, cli: { provider: 'openrouter' } }), {
      provider: 'openrouter',
      model: 'anthropic/claude-sonnet-4.6',
      baseUrl: 'https://openrouter.ai/api/v1',
      apiKey: 'or-key',
      streaming: 'auto'
    });
  });
});

test('resolveModelConfig applies CLI over workspace over env', async () => {
  await withEnv(
    {
      CLIQ_MODEL_PROVIDER: 'openai',
      CLIQ_MODEL: 'gpt-env',
      OPENAI_API_KEY: 'openai-key'
    },
    async () => {
      const result = await resolveModelConfig({
        workspace: { model: { provider: 'anthropic', model: 'workspace-model' } },
        cli: { provider: 'ollama', model: 'qwen3:14b', streaming: 'off' }
      });

      assert.deepEqual(result, {
        provider: 'ollama',
        model: 'qwen3:14b',
        baseUrl: 'http://localhost:11434',
        streaming: 'off'
      });
    }
  );
});

test('resolveModelConfig requires model and baseUrl for openai-compatible', async () => {
  await withEnv({}, async () => {
    await assert.rejects(
      () => resolveModelConfig({ workspace: {}, cli: { provider: 'openai-compatible', model: 'local' } }),
      /baseUrl is required/i
    );

    await assert.rejects(
      () =>
        resolveModelConfig({
          workspace: {},
          cli: { provider: 'openai-compatible', baseUrl: 'http://localhost:4000/v1' }
        }),
      /model is required/i
    );
  });
});

test('resolveModelConfig validates streaming mode', async () => {
  await withEnv({ OPENROUTER_API_KEY: 'or-key' }, async () => {
    await assert.rejects(
      () => resolveModelConfig({ workspace: {}, cli: { streaming: 'sometimes' } }),
      /Invalid streaming mode/i
    );
  });
});
