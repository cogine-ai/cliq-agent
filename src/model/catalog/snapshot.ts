import type { CatalogSnapshot } from './schema.js';

export const CATALOG_SNAPSHOT = {
  version: 1,
  generatedAt: '2026-06-01T00:00:00.000Z',
  providers: [
    {
      id: 'openrouter',
      displayName: 'OpenRouter',
      kind: 'aggregator',
      auth: { kind: 'api-key', envVar: 'OPENROUTER_API_KEY', required: true },
      configSources: ['ENV', 'Workspace', 'Global', 'CLI'],
      setup: {
        primary: ['Set OPENROUTER_API_KEY or configure an OpenRouter credential.'],
        docsUrl: 'https://openrouter.ai/docs'
      },
      modelListSource: {
        kind: 'snapshot',
        description: 'Static CLIQ catalog generated from upstream metadata.'
      },
      defaultModelId: 'anthropic/claude-sonnet-4.6',
      visibleModelLimit: 12,
      source: { kind: 'cliq-overlay', confidence: 'high' }
    },
    {
      id: 'anthropic',
      displayName: 'Anthropic',
      kind: 'hosted-api',
      auth: { kind: 'api-key', envVar: 'ANTHROPIC_API_KEY', required: true },
      configSources: ['ENV', 'Workspace', 'Global', 'CLI'],
      setup: {
        primary: ['Set ANTHROPIC_API_KEY, then choose an Anthropic model.'],
        docsUrl: 'https://docs.anthropic.com'
      },
      modelListSource: {
        kind: 'snapshot',
        description: 'Static CLIQ catalog generated from upstream metadata.'
      },
      defaultModelId: 'claude-sonnet-4-20250514',
      visibleModelLimit: 8,
      source: { kind: 'cliq-overlay', confidence: 'high' }
    },
    {
      id: 'openai',
      displayName: 'OpenAI',
      kind: 'hosted-api',
      auth: { kind: 'api-key', envVar: 'OPENAI_API_KEY', required: true },
      configSources: ['ENV', 'Workspace', 'Global', 'CLI'],
      setup: {
        primary: ['Set OPENAI_API_KEY, then choose an OpenAI model.'],
        docsUrl: 'https://platform.openai.com/docs'
      },
      modelListSource: {
        kind: 'snapshot',
        description: 'Static CLIQ catalog generated from upstream metadata.'
      },
      defaultModelId: 'gpt-5.2',
      visibleModelLimit: 8,
      source: { kind: 'cliq-overlay', confidence: 'high' }
    },
    {
      id: 'openai-compatible',
      displayName: 'OpenAI-compatible',
      kind: 'openai-compatible',
      auth: { kind: 'api-key', envVar: 'CLIQ_MODEL_API_KEY', required: false },
      configSources: ['ENV', 'Workspace', 'Global', 'CLI'],
      setup: {
        primary: ['Set a base URL and model id for the OpenAI-compatible endpoint.']
      },
      modelListSource: {
        kind: 'user-config',
        description: 'User or workspace configuration supplies the model id.'
      },
      visibleModelLimit: 0,
      source: { kind: 'cliq-overlay', confidence: 'high' }
    },
    {
      id: 'ollama',
      displayName: 'Ollama',
      kind: 'local-runtime',
      auth: { kind: 'none' },
      configSources: ['Local service', 'Workspace', 'Global', 'CLI'],
      setup: {
        primary: ['Run Ollama locally and pull a model such as qwen3.5:4b.'],
        docsUrl: 'https://ollama.com'
      },
      modelListSource: {
        kind: 'ollama-tags',
        description: 'Local Ollama /api/tags discovery.'
      },
      visibleModelLimit: 8,
      source: { kind: 'cliq-overlay', confidence: 'high' }
    }
  ],
  models: [
    {
      provider: 'openrouter',
      model: 'anthropic/claude-sonnet-4.6',
      displayName: 'Claude Sonnet 4.6 via OpenRouter',
      capabilities: {
        input: ['text'],
        output: ['text'],
        streaming: true,
        reasoning: true,
        toolCalling: true,
        contextWindow: 200_000,
        maxOutputTokens: 64_000
      },
      routing: {
        api: 'openai-completions',
        baseUrl: 'https://openrouter.ai/api/v1'
      },
      pricing: {
        input: 3,
        output: 15,
        cacheRead: 0.3,
        cacheWrite: 3.75
      },
      source: {
        kind: 'pi',
        confidence: 'medium',
        upstreamProvider: 'openrouter',
        upstreamModelId: 'anthropic/claude-sonnet-4.6'
      }
    },
    {
      provider: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      displayName: 'Claude Sonnet 4',
      capabilities: {
        input: ['text', 'image'],
        output: ['text'],
        streaming: true,
        reasoning: true,
        toolCalling: true,
        contextWindow: 200_000,
        maxOutputTokens: 64_000
      },
      routing: {
        api: 'anthropic-messages',
        baseUrl: 'https://api.anthropic.com'
      },
      pricing: {
        input: 3,
        output: 15,
        cacheRead: 0.3,
        cacheWrite: 3.75
      },
      source: {
        kind: 'pi',
        confidence: 'medium',
        upstreamProvider: 'anthropic',
        upstreamModelId: 'claude-sonnet-4-20250514'
      }
    },
    {
      provider: 'openai',
      model: 'gpt-5.2',
      displayName: 'GPT-5.2',
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
        api: 'openai-responses',
        baseUrl: 'https://api.openai.com/v1'
      },
      pricing: {
        input: 1.75,
        output: 14,
        cacheRead: 0.175,
        cacheWrite: 0
      },
      source: {
        kind: 'pi',
        confidence: 'medium',
        upstreamProvider: 'openai',
        upstreamModelId: 'gpt-5.2'
      }
    }
  ]
} satisfies CatalogSnapshot;
