import assert from 'node:assert/strict';
import test from 'node:test';

import {
  listProviderCatalog,
  mapOpenClawProviderToCatalogEntry,
  mapPiModelToCatalogEntry,
  resolveModelMetadata
} from './index.js';

test('provider catalog covers every built-in provider with setup metadata', () => {
  const providers = listProviderCatalog();
  const byId = new Map(providers.map((provider) => [provider.id, provider]));

  for (const id of ['openrouter', 'anthropic', 'openai', 'openai-compatible', 'ollama'] as const) {
    const provider = byId.get(id);
    assert.ok(provider, `missing provider catalog entry for ${id}`);
    assert.equal(typeof provider.displayName, 'string');
    assert.notEqual(provider.displayName.trim(), '');
    assert.ok(provider.configSources.length > 0);
    assert.ok(provider.setup.primary.length > 0);
  }

  assert.deepEqual(byId.get('openrouter')?.auth, {
    kind: 'api-key',
    envVar: 'OPENROUTER_API_KEY',
    required: true
  });
  assert.equal(byId.get('ollama')?.auth.kind, 'none');
});

test('model metadata resolves known hosted models without crossing provider boundaries', () => {
  const openrouter = resolveModelMetadata('openrouter', 'anthropic/claude-sonnet-4.6');
  const anthropic = resolveModelMetadata('anthropic', 'claude-sonnet-4-20250514');
  const openai = resolveModelMetadata('openai', 'gpt-5.2');

  assert.equal(openrouter?.capabilities.contextWindow, 200_000);
  assert.equal(openrouter?.capabilities.reasoning, true);
  assert.equal(anthropic?.capabilities.contextWindow, 200_000);
  assert.equal(openai?.capabilities.contextWindow, 128_000);
  assert.equal(resolveModelMetadata('anthropic', 'anthropic/claude-sonnet-4.6'), null);
});

test('Pi model rows map to CLIQ model metadata entries with explicit provider ids', () => {
  const mapped = mapPiModelToCatalogEntry({
    provider: 'openrouter',
    id: 'openai/gpt-5.2',
    name: 'OpenAI: GPT-5.2',
    api: 'openai-completions',
    baseUrl: 'https://openrouter.ai/api/v1',
    reasoning: true,
    input: ['text', 'image'],
    cost: { input: 1.75, output: 14, cacheRead: 0.175, cacheWrite: 0 },
    contextWindow: 128_000,
    maxTokens: 16_384
  });

  assert.deepEqual(mapped, {
    provider: 'openrouter',
    model: 'openai/gpt-5.2',
    displayName: 'OpenAI: GPT-5.2',
    capabilities: {
      input: ['text', 'image'],
      output: ['text'],
      streaming: true,
      reasoning: true,
      toolCalling: true,
      contextWindow: 128_000,
      maxOutputTokens: 16_384
    },
    routing: {
      api: 'openai-completions',
      baseUrl: 'https://openrouter.ai/api/v1'
    },
    pricing: { input: 1.75, output: 14, cacheRead: 0.175, cacheWrite: 0 },
    source: {
      kind: 'pi',
      confidence: 'medium',
      upstreamProvider: 'openrouter',
      upstreamModelId: 'openai/gpt-5.2'
    }
  });

  assert.equal(
    mapPiModelToCatalogEntry({
      provider: 'github-copilot',
      id: 'gpt-5.2',
      name: 'GPT-5.2',
      api: 'openai-responses',
      reasoning: true,
      input: ['text'],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 128_000,
      maxTokens: 16_384
    }),
    null
  );
});

test('Pi model rows omit pricing when upstream cost metadata is incomplete', () => {
  const mapped = mapPiModelToCatalogEntry({
    provider: 'openai',
    id: 'gpt-5.2-mini',
    name: 'GPT-5.2 Mini',
    api: 'openai-responses',
    reasoning: true,
    input: ['text'],
    cost: { input: 0.25, output: 2 },
    contextWindow: 128_000,
    maxTokens: 16_384
  });

  assert.equal(mapped?.pricing, undefined);
});

test('OpenClaw provider rows map to CLIQ provider catalog entries', () => {
  assert.deepEqual(
    mapOpenClawProviderToCatalogEntry({
      id: 'openrouter',
      name: 'OpenRouter',
      docs: '/providers/openrouter',
      categories: ['cloud', 'llm'],
      authChoices: [
        {
          method: 'api-key',
          optionKey: 'openRouterApiKey',
          cliOption: '--openrouter-api-key <key>',
          choiceHint: 'Use an OpenRouter API key.'
        }
      ]
    }),
    {
      id: 'openrouter',
      displayName: 'OpenRouter',
      kind: 'aggregator',
      auth: {
        kind: 'api-key',
        envVar: 'OPENROUTER_API_KEY',
        required: true
      },
      configSources: ['ENV', 'Workspace', 'Global', 'CLI'],
      setup: {
        primary: ['Set OPENROUTER_API_KEY or configure an OpenRouter credential.'],
        docsUrl: '/providers/openrouter'
      },
      modelListSource: {
        kind: 'snapshot',
        description: 'Static CLIQ catalog generated from upstream metadata.'
      },
      defaultModelId: 'anthropic/claude-sonnet-4.6',
      visibleModelLimit: 12,
      source: {
        kind: 'openclaw',
        confidence: 'medium',
        upstreamProvider: 'openrouter'
      }
    }
  );
});

test('OpenAI-compatible OpenClaw rows use user-config model list semantics', () => {
  assert.deepEqual(
    mapOpenClawProviderToCatalogEntry({
      id: 'openai-compatible',
      name: 'OpenAI-compatible',
      docs: '/providers/openai-compatible',
      categories: ['custom', 'llm'],
      authChoices: [
        {
          method: 'api-key',
          optionKey: 'modelApiKey',
          cliOption: '--api-key <key>',
          choiceHint: 'Use an optional compatible endpoint API key.'
        }
      ]
    }),
    {
      id: 'openai-compatible',
      displayName: 'OpenAI-compatible',
      kind: 'openai-compatible',
      auth: {
        kind: 'api-key',
        envVar: 'CLIQ_MODEL_API_KEY',
        required: false
      },
      configSources: ['ENV', 'Workspace', 'Global', 'CLI'],
      setup: {
        primary: ['Set a base URL and model id for the OpenAI-compatible endpoint.'],
        docsUrl: '/providers/openai-compatible'
      },
      modelListSource: {
        kind: 'user-config',
        description: 'User or workspace configuration supplies the model id.'
      },
      visibleModelLimit: 0,
      source: {
        kind: 'openclaw',
        confidence: 'medium',
        upstreamProvider: 'openai-compatible'
      }
    }
  );
});
