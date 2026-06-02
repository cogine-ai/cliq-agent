import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test, { mock } from 'node:test';

import { loadProviderAuthStore, upsertProviderAuth } from './auth-store.js';
import {
  formatModelSetupMessage,
  isModelSetupRequiredError,
  ModelSetupRequiredError,
  resolveModelConfig
} from './config.js';

const MODEL_ENV_KEYS = [
  'CLIQ_MODEL_PROVIDER',
  'CLIQ_MODEL',
  'CLIQ_MODEL_BASE_URL',
  'CLIQ_MODEL_STREAMING',
  'CLIQ_MODEL_API_KEY',
  'CLIQ_HOME',
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
    if (!previous.has(key)) {
      previous.set(key, process.env[key]);
    }
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
        /Cliq needs a model provider before chat can start[\s\S]*ollama pull qwen3\.5:4b/i
      );
    });
  } finally {
    fetchMock.mock.restore();
  }
});

test('resolveModelConfig exposes typed setup state when local Ollama has no models', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => Response.json({ models: [] }));

  try {
    await withEnv({}, async () => {
      await assert.rejects(
        () => resolveModelConfig({ workspace: {}, cli: {} }),
        (error) => {
          assert.ok(error instanceof ModelSetupRequiredError);
          assert.ok(isModelSetupRequiredError(error));
          assert.equal(error.reason, 'no-local-model');
          assert.equal(error.provider, 'ollama');
          assert.equal(error.baseUrl, 'http://localhost:11434');

          const message = formatModelSetupMessage(error);
          assert.match(message, /Cliq needs a model provider before chat can start/i);
          assert.match(message, /Provider configuration/i);
          assert.match(message, /Model selection/i);
          assert.match(message, /ollama pull qwen3\.5:4b/);
          assert.match(message, /OpenAI/i);
          assert.doesNotMatch(message, /No model provider or local Ollama model configured/);
          return true;
        }
      );
    });
  } finally {
    fetchMock.mock.restore();
  }
});

test('resolveModelConfig exposes typed setup state for selected provider missing credentials', async () => {
  await withEnv({}, async () => {
    await assert.rejects(
      () => resolveModelConfig({ workspace: {}, cli: { provider: 'openrouter', model: 'test-model' } }),
      (error) => {
        assert.ok(error instanceof ModelSetupRequiredError);
        assert.equal(error.reason, 'missing-provider-api-key');
        assert.equal(error.provider, 'openrouter');
        assert.equal(error.missingEnvVar, 'OPENROUTER_API_KEY');
        const message = formatModelSetupMessage(error);
        assert.match(message, /OpenRouter provider is selected/i);
        assert.match(message, /OPENROUTER_API_KEY/);
        assert.match(message, /Provider configuration/i);
        assert.match(message, /Model selection/i);
        return true;
      }
    );
  });
});

test('resolveModelConfig exposes typed setup state when a selected provider still needs a model', async () => {
  await withEnv({}, async () => {
    await assert.rejects(
      () => resolveModelConfig({ workspace: {}, cli: { provider: 'openai-compatible', baseUrl: 'http://localhost:4000/v1' } }),
      (error) => {
        assert.ok(error instanceof ModelSetupRequiredError);
        assert.equal(error.reason, 'missing-model');
        assert.equal(error.provider, 'openai-compatible');
        const message = formatModelSetupMessage(error);
        assert.match(message, /OpenAI-compatible provider is selected/i);
        assert.match(message, /model id/i);
        assert.match(message, /--model <model>/);
        return true;
      }
    );
  });
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

test('resolveModelConfig can use the active provider credential from local auth', async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-auth-config-'));
  try {
    await upsertProviderAuth(
      {
        provider: 'openai',
        apiKey: 'sk-secret',
        model: 'gpt-auth',
        streaming: 'off'
      },
      { cliqHome: home }
    );

    await withEnv({}, async () => {
      assert.deepEqual(await resolveModelConfig({ workspace: {}, cli: {}, auth: await loadProviderAuthStore({ cliqHome: home }) }), {
        provider: 'openai',
        model: 'gpt-auth',
        baseUrl: 'https://api.openai.com/v1',
        apiKey: 'sk-secret',
        streaming: 'off'
      });
    });
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('resolveModelConfig prefers env model settings over local auth', async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-auth-config-env-'));
  try {
    await upsertProviderAuth(
      {
        provider: 'openai',
        apiKey: 'sk-auth',
        model: 'gpt-auth',
        baseUrl: 'https://auth.example.test/v1',
        streaming: 'off'
      },
      { cliqHome: home }
    );

    await withEnv(
      {
        CLIQ_MODEL: 'gpt-env',
        CLIQ_MODEL_BASE_URL: 'https://env.example.test/v1',
        CLIQ_MODEL_STREAMING: 'on',
        OPENAI_API_KEY: 'sk-env'
      },
      async () => {
        assert.deepEqual(await resolveModelConfig({ workspace: {}, cli: {}, auth: await loadProviderAuthStore({ cliqHome: home }) }), {
          provider: 'openai',
          model: 'gpt-env',
          baseUrl: 'https://env.example.test/v1',
          apiKey: 'sk-env',
          streaming: 'on'
        });
      }
    );
  } finally {
    await rm(home, { recursive: true, force: true });
  }
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
      (error) => {
        assert.ok(error instanceof ModelSetupRequiredError);
        assert.equal(error.reason, 'missing-base-url');
        assert.equal(error.provider, 'openai-compatible');
        assert.match(formatModelSetupMessage(error), /base URL/i);
        return true;
      }
    );

    await assert.rejects(
      () =>
        resolveModelConfig({
          workspace: {},
          cli: { provider: 'openai-compatible', baseUrl: 'http://localhost:4000/v1' }
        }),
      (error) => {
        assert.ok(error instanceof ModelSetupRequiredError);
        assert.equal(error.reason, 'missing-model');
        assert.equal(error.provider, 'openai-compatible');
        assert.match(formatModelSetupMessage(error), /model id/i);
        return true;
      }
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
