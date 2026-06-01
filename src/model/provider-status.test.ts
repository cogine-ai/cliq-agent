import assert from 'node:assert/strict';
import test from 'node:test';

import type { PartialModelConfig } from './config.js';
import {
  buildProviderSetupSummary,
  buildProviderStatusReport,
  formatProviderStatusReport,
  formatProviderStatusRow,
  validateProviderStatus
} from './provider-status.js';
import type { OllamaModelSummary } from './providers/ollama-discovery.js';

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

const unavailableOllama = async (): Promise<OllamaModelSummary[]> => {
  throw new Error('connect ECONNREFUSED 127.0.0.1:11434');
};

test('provider status puts the active provider first and reports safe configuration sources', async () => {
  await withEnv({ OPENAI_API_KEY: 'sk-secret', OPENROUTER_API_KEY: 'or-secret' }, async () => {
    const report = await buildProviderStatusReport({
      workspace: { model: { provider: 'openai', model: 'gpt-workspace' } },
      cli: {},
      discoverOllamaModels: unavailableOllama
    });

    assert.equal(report.activeProvider, 'openai');
    assert.equal(report.credentialPersistence.mode, 'external-only');
    assert.equal(report.credentialPersistence.supportsManagedCredentials, false);

    const current = report.providers[0]!;
    assert.equal(current.provider, 'openai');
    assert.equal(current.current, true);
    assert.equal(current.state, 'configured');
    assert.deepEqual(current.sources, ['ENV', 'Workspace']);
    assert.equal(current.model, 'gpt-workspace');
    assert.ok(current.setup.some((line) => /OPENAI_API_KEY/.test(line)));

    const openrouter = report.providers.find((provider) => provider.provider === 'openrouter');
    assert.equal(openrouter?.state, 'configured');
    assert.deepEqual(openrouter?.sources, ['ENV']);

    const rendered = formatProviderStatusReport(report);
    assert.match(formatProviderStatusRow(current), /OpenAI\s+Current · Configured · ENV, Workspace · using gpt-workspace/);
    assert.doesNotMatch(rendered, /Connected/);
    assert.doesNotMatch(JSON.stringify(report), /sk-secret|or-secret/);
    assert.doesNotMatch(rendered, /sk-secret|or-secret/);
  });
});

test('provider status reports structured missing requirements for OpenAI-compatible config', async () => {
  await withEnv(
    {
      CLIQ_MODEL_PROVIDER: 'openai-compatible',
      CLIQ_MODEL: 'local-model'
    },
    async () => {
      const report = await buildProviderStatusReport({
        workspace: {},
        cli: {},
        discoverOllamaModels: unavailableOllama
      });

      const compatible = report.providers[0]!;
      assert.equal(compatible.provider, 'openai-compatible');
      assert.equal(compatible.current, true);
      assert.equal(compatible.state, 'not-configured');
      assert.deepEqual(compatible.issues.map((issue) => issue.code), ['missing-base-url']);
      assert.match(formatProviderStatusRow(compatible), /Not configured · needs base URL/);

      const setup = buildProviderSetupSummary(report, 'openai-compatible');
      assert.equal(setup.provider, 'openai-compatible');
      assert.deepEqual(setup.instructions, ['Set a base URL and model id for the OpenAI-compatible endpoint.']);
      assert.equal(setup.credentialPersistence.mode, 'external-only');

      const validation = validateProviderStatus(report, 'openai-compatible');
      assert.equal(validation.ok, false);
      if (!validation.ok) {
        assert.equal(validation.provider, 'openai-compatible');
        assert.equal(validation.state, 'not-configured');
        assert.deepEqual(validation.issues.map((issue) => issue.code), ['missing-base-url']);
      }
    }
  );
});

test('provider status represents local Ollama as local service availability, not credentials', async () => {
  await withEnv({}, async () => {
    const report = await buildProviderStatusReport({
      workspace: {},
      cli: {},
      discoverOllamaModels: async () => [{ name: 'llama3.2:latest' }, { name: 'qwen3:4b' }]
    });

    const ollama = report.providers[0]!;
    assert.equal(ollama.provider, 'ollama');
    assert.equal(ollama.current, true);
    assert.equal(ollama.state, 'configured');
    assert.deepEqual(ollama.sources, ['Local service']);
    assert.equal(ollama.modelCount, 2);
    assert.equal(ollama.model, 'qwen3:4b');
    assert.match(formatProviderStatusRow(ollama), /Ollama\s+Current · Configured · Local service · 2 models · using qwen3:4b/);
  });
});

test('provider status distinguishes unavailable local Ollama from missing remote credentials', async () => {
  await withEnv({}, async () => {
    const report = await buildProviderStatusReport({
      workspace: {},
      cli: {},
      discoverOllamaModels: unavailableOllama
    });

    const ollama = report.providers[0]!;
    assert.equal(ollama.provider, 'ollama');
    assert.equal(ollama.state, 'unavailable');
    assert.deepEqual(ollama.issues.map((issue) => issue.code), ['local-service-unavailable']);
    assert.match(formatProviderStatusRow(ollama), /Unavailable · local service unavailable/);

    const openai = report.providers.find((provider) => provider.provider === 'openai');
    assert.equal(openai?.state, 'not-configured');
    assert.deepEqual(openai?.issues.map((issue) => issue.code), ['missing-api-key']);
  });
});
