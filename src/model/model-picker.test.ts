import assert from 'node:assert/strict';
import test from 'node:test';

import type { ProviderAuthStore } from './auth-store.js';
import type { PartialModelConfig } from './config.js';
import { buildModelPickerSnapshot } from './model-picker.js';
import type { ProviderStatusReport } from './provider-status.js';

const report: ProviderStatusReport = {
  activeProvider: 'openai',
  activeModel: 'gpt-auth',
  providers: [
    {
      provider: 'openai',
      displayName: 'OpenAI',
      current: true,
      state: 'configured',
      sources: ['Managed credential'],
      issues: [],
      setup: [],
      model: 'gpt-auth',
      baseUrl: 'https://api.openai.com/v1'
    },
    {
      provider: 'openai-compatible',
      displayName: 'OpenAI-compatible',
      current: false,
      state: 'not-configured',
      sources: [],
      issues: [{ code: 'missing-base-url', requirement: 'base URL', message: 'Base URL required.' }],
      setup: []
    },
    {
      provider: 'ollama',
      displayName: 'Ollama',
      current: false,
      state: 'configured',
      sources: ['Local service'],
      issues: [],
      setup: [],
      modelCount: 2,
      model: 'qwen3.5:4b',
      baseUrl: 'http://localhost:11434'
    }
  ],
  credentialPersistence: {
    mode: 'local-auth-file',
    supportsManagedCredentials: true,
    message: 'local auth'
  }
};

test('model picker defaults provider selection to current runtime provider', () => {
  const snapshot = buildModelPickerSnapshot({
    report,
    auth: { version: 1, activeProvider: 'openai', providers: { openai: { model: 'gpt-auth' } } },
    currentModel: { provider: 'ollama', model: 'qwen3.5:4b' },
    workspaceModel: {},
    cliModel: {},
    env: {},
    ollamaModels: [{ name: 'qwen3.5:4b' }, { name: 'llama3.2:latest' }]
  });

  assert.equal(snapshot.selectedProvider, 'ollama');
  assert.equal(snapshot.providers.find((provider) => provider.provider === 'ollama')?.stateLabel, 'Configured');
});

test('model picker labels current, startup default, provider default, catalog, local, configured, and custom rows', () => {
  const auth: ProviderAuthStore = {
    version: 1,
    activeProvider: 'openai',
    providers: {
      openai: { model: 'gpt-auth' },
      'openai-compatible': { model: 'custom-compatible', baseUrl: 'http://localhost:4000/v1' }
    }
  };

  const snapshot = buildModelPickerSnapshot({
    report,
    auth,
    currentModel: { provider: 'openai', model: 'gpt-auth' },
    workspaceModel: { provider: 'openai-compatible', model: 'workspace-compatible' },
    cliModel: {},
    env: {},
    ollamaModels: [{ name: 'qwen3.5:4b' }, { name: 'llama3.2:latest' }]
  });

  const openai = snapshot.modelsByProvider.openai ?? [];
  assert.deepEqual(openai.find((row) => row.model === 'gpt-auth')?.labels, [
    'Current',
    'Startup default',
    'Configured'
  ]);
  assert.ok(openai.some((row) => row.labels.includes('Catalog')));

  const compatible = snapshot.modelsByProvider['openai-compatible'] ?? [];
  assert.deepEqual(compatible.find((row) => row.model === 'custom-compatible')?.labels, [
    'Provider default',
    'Configured'
  ]);
  assert.deepEqual(compatible.find((row) => row.model === 'workspace-compatible')?.labels, ['Configured']);
  assert.equal(compatible.at(-1)?.kind, 'custom');

  const ollama = snapshot.modelsByProvider.ollama ?? [];
  assert.deepEqual(ollama.find((row) => row.model === 'qwen3.5:4b')?.labels, ['Local']);
});

test('model picker does not label session-only auth as a saved default', () => {
  const auth: ProviderAuthStore = {
    version: 1,
    activeProvider: 'ollama',
    providers: {
      'openai-compatible': {
        model: 'session-compatible',
        baseUrl: 'http://localhost:4000/v1',
        transient: true
      }
    }
  };

  const snapshot = buildModelPickerSnapshot({
    report,
    auth,
    currentModel: { provider: 'openai-compatible', model: 'session-compatible' },
    workspaceModel: {},
    cliModel: {},
    env: {},
    ollamaModels: []
  });

  const compatible = snapshot.modelsByProvider['openai-compatible'] ?? [];
  const current = compatible.find((row) => row.model === 'session-compatible');
  assert.deepEqual(current?.labels, ['Current', 'Configured']);
});

test('model picker treats provider-scoped cli and env model ids as configured rows only for that provider', () => {
  const workspaceModel: PartialModelConfig = { provider: 'openai', model: 'workspace-openai' };
  const snapshot = buildModelPickerSnapshot({
    report,
    auth: { version: 1, providers: {} },
    currentModel: { provider: 'openai', model: 'gpt-auth' },
    workspaceModel,
    cliModel: { provider: 'anthropic', model: 'cli-anthropic' },
    env: { CLIQ_MODEL_PROVIDER: 'openai-compatible', CLIQ_MODEL: 'env-compatible' },
    ollamaModels: []
  });

  assert.ok(snapshot.modelsByProvider.openai?.some((row) => row.model === 'workspace-openai'));
  assert.equal(snapshot.modelsByProvider.openai?.some((row) => row.model === 'cli-anthropic'), false);
  assert.ok(snapshot.modelsByProvider['openai-compatible']?.some((row) => row.model === 'env-compatible'));
});
