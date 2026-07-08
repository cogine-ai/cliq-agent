import {
  CLIQ_MODELS_DEFAULT_BASE_URL,
  DEFAULT_MODEL_BASE_URL,
  DEFAULT_MODEL_PROVIDER,
  MODEL,
  OLLAMA_DEFAULT_BASE_URL
} from '../config.js';
import { getProviderCatalogEntry, listModelDescriptors, resolveModelMetadata, toModelDescriptor } from './catalog/index.js';
import type {
  ModelClient,
  ModelDescriptor,
  ProviderName,
  ResolvedModelConfig,
  StreamingMode
} from './types.js';

export type ModelProvider = {
  name: ProviderName;
  displayName: string;
  defaultBaseUrl: string;
  apiKeyEnv?: string;
  requiresApiKey: boolean;
  getDefaultModel(): string | null;
  getKnownModels(): ModelDescriptor[];
  createClient(config: ResolvedModelConfig): ModelClient;
};

type ModelProviderDefinition = Omit<ModelProvider, 'createClient'>;

export type DefaultModelConfig = {
  provider: ProviderName;
  model: string;
  baseUrl: string;
  streaming: StreamingMode;
};

export const DEFAULT_MODEL_CONFIG: DefaultModelConfig = {
  provider: DEFAULT_MODEL_PROVIDER,
  model: MODEL,
  baseUrl: DEFAULT_MODEL_BASE_URL,
  streaming: 'auto'
};

const PROVIDERS: Record<ProviderName, ModelProviderDefinition> = {
  openrouter: {
    name: 'openrouter',
    displayName: getProviderCatalogEntry('openrouter')?.displayName ?? 'OpenRouter',
    defaultBaseUrl: 'https://openrouter.ai/api/v1',
    apiKeyEnv: 'OPENROUTER_API_KEY',
    requiresApiKey: true,
    getDefaultModel: () => MODEL,
    getKnownModels: () => listModelDescriptors('openrouter')
  },
  anthropic: {
    name: 'anthropic',
    displayName: getProviderCatalogEntry('anthropic')?.displayName ?? 'Anthropic',
    defaultBaseUrl: 'https://api.anthropic.com',
    apiKeyEnv: 'ANTHROPIC_API_KEY',
    requiresApiKey: true,
    getDefaultModel: () => 'claude-sonnet-4-20250514',
    getKnownModels: () => listModelDescriptors('anthropic')
  },
  openai: {
    name: 'openai',
    displayName: getProviderCatalogEntry('openai')?.displayName ?? 'OpenAI',
    defaultBaseUrl: 'https://api.openai.com/v1',
    apiKeyEnv: 'OPENAI_API_KEY',
    requiresApiKey: true,
    getDefaultModel: () => 'gpt-5.2',
    getKnownModels: () => listModelDescriptors('openai')
  },
  'openai-compatible': {
    name: 'openai-compatible',
    displayName: getProviderCatalogEntry('openai-compatible')?.displayName ?? 'OpenAI-compatible',
    defaultBaseUrl: '',
    apiKeyEnv: 'OPENAI_COMPATIBLE_API_KEY',
    requiresApiKey: false,
    getDefaultModel: () => null,
    getKnownModels: () => []
  },
  zhipu: {
    name: 'zhipu',
    displayName: getProviderCatalogEntry('zhipu')?.displayName ?? 'Zhipu AI',
    defaultBaseUrl: 'https://open.bigmodel.cn/api/coding/paas/v4',
    apiKeyEnv: 'ZHIPU_API_KEY',
    requiresApiKey: true,
    getDefaultModel: () => 'glm-5.2',
    getKnownModels: () => listModelDescriptors('zhipu')
  },
  ollama: {
    name: 'ollama',
    displayName: getProviderCatalogEntry('ollama')?.displayName ?? 'Ollama',
    defaultBaseUrl: OLLAMA_DEFAULT_BASE_URL,
    requiresApiKey: false,
    getDefaultModel: () => null,
    getKnownModels: () => []
  },
  'cliq-models': {
    name: 'cliq-models',
    displayName: getProviderCatalogEntry('cliq-models')?.displayName ?? 'Cliq Models',
    defaultBaseUrl: CLIQ_MODELS_DEFAULT_BASE_URL,
    requiresApiKey: false,
    getDefaultModel: () => null,
    getKnownModels: () => []
  }
};

const factories = new Map<ProviderName, (config: ResolvedModelConfig) => ModelClient>();

export function registerModelClientFactory(provider: ProviderName, factory: (config: ResolvedModelConfig) => ModelClient) {
  factories.set(provider, factory);
}

export function isProviderName(value: string): value is ProviderName {
  return Object.hasOwn(PROVIDERS, value);
}

export function getModelProvider(provider: ProviderName): ModelProvider {
  const definition = PROVIDERS[provider];
  return {
    ...definition,
    createClient(config) {
      const factory = factories.get(provider);
      if (!factory) {
        throw new Error(`Model provider ${provider} is not registered`);
      }

      return factory(config);
    }
  };
}

export function findKnownModelDescriptor(provider: ProviderName, model: string): ModelDescriptor | null {
  const metadata = resolveModelMetadata(provider, model);
  return metadata ? toModelDescriptor(metadata) : null;
}

export function listModelProviders(): ModelProvider[] {
  return (Object.keys(PROVIDERS) as ProviderName[]).map((provider) => getModelProvider(provider));
}
