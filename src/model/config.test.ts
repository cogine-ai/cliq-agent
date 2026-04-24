import assert from 'node:assert/strict';
import test from 'node:test';

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

function withEnv(env: Record<string, string | undefined>, fn: () => void) {
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
    fn();
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

test('resolveModelConfig defaults to OpenRouter', () => {
  withEnv({ OPENROUTER_API_KEY: 'or-key' }, () => {
    assert.deepEqual(resolveModelConfig({ workspace: {}, cli: {} }), {
      provider: 'openrouter',
      model: 'anthropic/claude-sonnet-4.6',
      baseUrl: 'https://openrouter.ai/api/v1',
      apiKey: 'or-key',
      streaming: 'auto'
    });
  });
});

test('resolveModelConfig applies CLI over workspace over env', () => {
  withEnv(
    {
      CLIQ_MODEL_PROVIDER: 'openai',
      CLIQ_MODEL: 'gpt-env',
      OPENAI_API_KEY: 'openai-key'
    },
    () => {
      const result = resolveModelConfig({
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

test('resolveModelConfig requires model and baseUrl for openai-compatible', () => {
  withEnv({}, () => {
    assert.throws(
      () => resolveModelConfig({ workspace: {}, cli: { provider: 'openai-compatible', model: 'local' } }),
      /baseUrl is required/i
    );

    assert.throws(
      () =>
        resolveModelConfig({
          workspace: {},
          cli: { provider: 'openai-compatible', baseUrl: 'http://localhost:4000/v1' }
        }),
      /model is required/i
    );
  });
});

test('resolveModelConfig validates streaming mode', () => {
  withEnv({ OPENROUTER_API_KEY: 'or-key' }, () => {
    assert.throws(
      () => resolveModelConfig({ workspace: {}, cli: { streaming: 'sometimes' } }),
      /Invalid streaming mode/i
    );
  });
});
