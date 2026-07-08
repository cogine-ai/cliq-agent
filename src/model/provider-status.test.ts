import assert from 'node:assert/strict';
import test from 'node:test';

import type { ProviderAuthStore } from './auth-store.js';
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
  'OPENAI_COMPATIBLE_API_KEY',
  'ZHIPU_API_KEY',
  'ZHIPUAI_API_KEY'
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
    assert.equal(report.credentialPersistence.mode, 'local-auth-file');
    assert.equal(report.credentialPersistence.supportsManagedCredentials, true);

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

test('provider status reports local auth credentials as managed without leaking secrets', async () => {
  await withEnv({}, async () => {
    const auth: ProviderAuthStore = {
      version: 1,
      activeProvider: 'openai',
      providers: {
        openai: {
          apiKey: 'sk-secret',
          model: 'gpt-auth'
        }
      }
    };

    const report = await buildProviderStatusReport({
      workspace: {},
      cli: {},
      auth,
      discoverOllamaModels: unavailableOllama
    });

    assert.equal(report.activeProvider, 'openai');
    assert.equal(report.credentialPersistence.mode, 'local-auth-file');
    assert.equal(report.credentialPersistence.supportsManagedCredentials, true);

    const current = report.providers[0]!;
    assert.equal(current.provider, 'openai');
    assert.equal(current.state, 'configured');
    assert.deepEqual(current.sources, ['Managed credential']);
    assert.equal(current.model, 'gpt-auth');

    const rendered = formatProviderStatusReport(report);
    assert.match(rendered, /Managed credential/);
    assert.doesNotMatch(JSON.stringify(report), /sk-secret/);
    assert.doesNotMatch(rendered, /sk-secret/);
  });
});

test('provider status can use the current runtime model as the active provider', async () => {
  await withEnv({}, async () => {
    const auth: ProviderAuthStore = {
      version: 1,
      activeProvider: 'ollama',
      providers: {
        openai: {
          apiKey: 'sk-session-only',
          model: 'gpt-session'
        }
      }
    };

    const report = await buildProviderStatusReport({
      workspace: {},
      cli: {},
      auth,
      currentModel: {
        provider: 'openai',
        model: 'gpt-session',
        baseUrl: 'https://api.openai.com/v1'
      },
      discoverOllamaModels: async () => [{ name: 'qwen3:4b' }]
    });

    assert.equal(report.activeProvider, 'openai');
    assert.equal(auth.activeProvider, 'ollama');
    const current = report.providers[0]!;
    assert.equal(current.provider, 'openai');
    assert.equal(current.current, true);
    assert.equal(current.state, 'configured');
    assert.equal(current.model, 'gpt-session');
    const ollama = report.providers.find((provider) => provider.provider === 'ollama');
    assert.equal(ollama?.current, false);
  });
});

test('provider status does not label session-only auth as a managed credential source', async () => {
  await withEnv({}, async () => {
    const auth: ProviderAuthStore = {
      version: 1,
      activeProvider: 'ollama',
      providers: {
        openai: {
          apiKey: 'sk-session-only',
          model: 'gpt-session',
          transient: true
        }
      }
    };

    const report = await buildProviderStatusReport({
      workspace: {},
      cli: {},
      auth,
      currentModel: {
        provider: 'openai',
        model: 'gpt-session',
        baseUrl: 'https://api.openai.com/v1'
      },
      discoverOllamaModels: async () => [{ name: 'qwen3:4b' }]
    });

    const current = report.providers[0]!;
    assert.equal(current.provider, 'openai');
    assert.equal(current.state, 'configured');
    assert.deepEqual(current.sources, []);
  });
});

test('provider status does not label transient API keys as persisted credential sources', async () => {
  await withEnv({}, async () => {
    const auth: ProviderAuthStore = {
      version: 1,
      providers: {
        openai: {
          apiKey: 'sk-session-only',
          transientApiKey: true
        }
      }
    };

    const report = await buildProviderStatusReport({
      workspace: {},
      cli: {},
      auth,
      currentModel: {
        provider: 'openai',
        model: 'gpt-session',
        baseUrl: 'https://api.openai.com/v1'
      },
      discoverOllamaModels: async () => [{ name: 'qwen3:4b' }]
    });

    const current = report.providers[0]!;
    assert.equal(current.provider, 'openai');
    assert.equal(current.state, 'configured');
    assert.deepEqual(current.sources, []);
  });
});

test('provider status prefers env model settings over local auth', async () => {
  await withEnv(
    {
      CLIQ_MODEL: 'gpt-env',
      CLIQ_MODEL_BASE_URL: 'https://env.example.test/v1',
      OPENAI_API_KEY: 'sk-env'
    },
    async () => {
      const auth: ProviderAuthStore = {
        version: 1,
        activeProvider: 'openai',
        providers: {
          openai: {
            apiKey: 'sk-auth',
            model: 'gpt-auth',
            baseUrl: 'https://user:pass@auth.example.test/v1?token=secret#fragment'
          }
        }
      };

      const report = await buildProviderStatusReport({
        workspace: {},
        cli: {},
        auth,
        discoverOllamaModels: unavailableOllama
      });

      const current = report.providers[0]!;
      assert.equal(report.activeProvider, 'openai');
      assert.equal(report.activeModel, 'gpt-env');
      assert.equal(current.provider, 'openai');
      assert.equal(current.state, 'configured');
      assert.deepEqual(current.sources, ['ENV', 'Managed credential']);
      assert.equal(current.model, 'gpt-env');
      assert.equal(current.baseUrl, 'https://env.example.test/v1');

      const rendered = formatProviderStatusReport(report);
      assert.doesNotMatch(JSON.stringify(report), /sk-auth|sk-env|user:pass|token=secret|fragment|auth\.example/);
      assert.doesNotMatch(rendered, /sk-auth|sk-env|user:pass|token=secret|fragment|auth\.example/);
    }
  );
});

test('provider status sanitizes auth-store base URLs before report output', async () => {
  await withEnv({}, async () => {
    const auth: ProviderAuthStore = {
      version: 1,
      activeProvider: 'openai-compatible',
      providers: {
        'openai-compatible': {
          model: 'local-model',
          baseUrl: 'https://user:pass@example.test/v1?token=secret#fragment'
        }
      }
    };

    const report = await buildProviderStatusReport({
      workspace: {},
      cli: {},
      auth,
      discoverOllamaModels: unavailableOllama
    });

    const compatible = report.providers.find((provider) => provider.provider === 'openai-compatible');
    assert.equal(compatible?.baseUrl, 'https://example.test/v1');

    const serialized = JSON.stringify(report);
    const rendered = formatProviderStatusReport(report);
    assert.doesNotMatch(serialized, /user:pass|token=secret|fragment/);
    assert.doesNotMatch(rendered, /user:pass|token=secret|fragment/);
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
      assert.deepEqual(setup.instructions, [
        'Set a base URL, then choose a discovered or custom model for the OpenAI-compatible endpoint.'
      ]);
      assert.equal(setup.credentialPersistence.mode, 'local-auth-file');

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

test('provider status exposes Cliq Models as a managed local provider distinct from raw Ollama', async () => {
  await withEnv({ CLIQ_MODEL_PROVIDER: 'cliq-models' }, async () => {
    const report = await buildProviderStatusReport({
      workspace: {},
      cli: {},
      discoverOllamaModels: unavailableOllama
    });

    assert.equal(report.activeProvider, 'cliq-models');
    const cliqModels = report.providers[0]!;
    assert.equal(cliqModels.provider, 'cliq-models');
    assert.equal(cliqModels.displayName, 'Cliq Models');
    assert.equal(cliqModels.current, true);
    assert.equal(cliqModels.state, 'runtime-missing');
    assert.deepEqual(cliqModels.issues.map((issue) => issue.code), ['local-runtime-missing']);
    assert.match(formatProviderStatusRow(cliqModels), /Cliq Models\s+Current · Runtime missing · needs Cliq Models runtime/);
    assert.ok(cliqModels.setup.some((line) => /Cliq Models runtime/i.test(line)));

    const ollama = report.providers.find((provider) => provider.provider === 'ollama');
    assert.equal(ollama?.displayName, 'Ollama');
    assert.equal(ollama?.state, 'unavailable');
  });
});

test('provider status renders Cliq Models ready state when a local runtime has models', async () => {
  await withEnv({ CLIQ_MODEL_PROVIDER: 'cliq-models' }, async () => {
    const report = await buildProviderStatusReport({
      workspace: {},
      cli: {},
      discoverOllamaModels: async () => [{ name: 'llama3.2:latest' }, { name: 'qwen3:4b' }]
    });

    const cliqModels = report.providers[0]!;
    assert.equal(cliqModels.provider, 'cliq-models');
    assert.equal(cliqModels.state, 'ready');
    assert.deepEqual(cliqModels.sources, ['Existing Ollama runtime']);
    assert.equal(cliqModels.modelCount, 2);
    assert.equal(cliqModels.model, 'qwen3:4b');
    assert.match(formatProviderStatusRow(cliqModels), /Cliq Models\s+Current · Ready · Existing Ollama runtime · 2 models · using qwen3:4b/);

    const validation = validateProviderStatus(report, 'cliq-models');
    assert.equal(validation.ok, true);
  });
});

test('provider status reports Zhipu env credentials and default model without leaking secrets', async () => {
  await withEnv({ ZHIPU_API_KEY: 'zhipu-secret' }, async () => {
    const report = await buildProviderStatusReport({
      workspace: {},
      cli: { provider: 'zhipu' },
      discoverOllamaModels: unavailableOllama
    });

    const zhipu = report.providers[0]!;
    assert.equal(report.activeProvider, 'zhipu');
    assert.equal(report.activeModel, 'glm-5.2');
    assert.equal(zhipu.provider, 'zhipu');
    assert.equal(zhipu.current, true);
    assert.equal(zhipu.state, 'configured');
    assert.deepEqual(zhipu.sources, ['ENV', 'CLI']);
    assert.equal(zhipu.model, 'glm-5.2');
    assert.equal(zhipu.baseUrl, 'https://open.bigmodel.cn/api/coding/paas/v4');
    assert.match(formatProviderStatusRow(zhipu), /Zhipu AI\s+Current · Configured · ENV, CLI · using glm-5\.2/);
    assert.doesNotMatch(JSON.stringify(report), /zhipu-secret/);
  });
});
