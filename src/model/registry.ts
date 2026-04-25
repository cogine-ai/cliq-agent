import { DEFAULT_MODEL_BASE_URL, DEFAULT_MODEL_PROVIDER, MODEL, OLLAMA_DEFAULT_BASE_URL } from '../config.js';
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

const TEXT_TO_TEXT = {
  input: ['text'],
  output: ['text'],
  streaming: true,
  reasoning: false,
  toolCalling: false
} satisfies ModelDescriptor['capabilities'];

const TEXT_TO_TEXT_REASONING = {
  ...TEXT_TO_TEXT,
  reasoning: true
} satisfies ModelDescriptor['capabilities'];

export const DEFAULT_MODEL_CONFIG: DefaultModelConfig = {
  provider: DEFAULT_MODEL_PROVIDER,
  model: MODEL,
  baseUrl: DEFAULT_MODEL_BASE_URL,
  streaming: 'auto'
};

const PROVIDERS: Record<ProviderName, ModelProviderDefinition> = {
  openrouter: {
    name: 'openrouter',
    displayName: 'OpenRouter',
    defaultBaseUrl: 'https://openrouter.ai/api/v1',
    apiKeyEnv: 'OPENROUTER_API_KEY',
    requiresApiKey: true,
    getDefaultModel: () => MODEL,
    getKnownModels: () => [
      {
        provider: 'openrouter',
        model: MODEL,
        displayName: 'Claude Sonnet 4.6 via OpenRouter',
        capabilities: TEXT_TO_TEXT_REASONING
      }
    ]
  },
  anthropic: {
    name: 'anthropic',
    displayName: 'Anthropic',
    defaultBaseUrl: 'https://api.anthropic.com',
    apiKeyEnv: 'ANTHROPIC_API_KEY',
    requiresApiKey: true,
    getDefaultModel: () => 'claude-sonnet-4-20250514',
    getKnownModels: () => [
      {
        provider: 'anthropic',
        model: 'claude-sonnet-4-20250514',
        displayName: 'Claude Sonnet 4',
        capabilities: TEXT_TO_TEXT_REASONING
      }
    ]
  },
  openai: {
    name: 'openai',
    displayName: 'OpenAI',
    defaultBaseUrl: 'https://api.openai.com/v1',
    apiKeyEnv: 'OPENAI_API_KEY',
    requiresApiKey: true,
    getDefaultModel: () => 'gpt-5.2',
    getKnownModels: () => [
      {
        provider: 'openai',
        model: 'gpt-5.2',
        displayName: 'GPT-5.2',
        capabilities: TEXT_TO_TEXT_REASONING
      }
    ]
  },
  'openai-compatible': {
    name: 'openai-compatible',
    displayName: 'OpenAI-compatible',
    defaultBaseUrl: '',
    apiKeyEnv: 'OPENAI_COMPATIBLE_API_KEY',
    requiresApiKey: false,
    getDefaultModel: () => null,
    getKnownModels: () => []
  },
  ollama: {
    name: 'ollama',
    displayName: 'Ollama',
    defaultBaseUrl: OLLAMA_DEFAULT_BASE_URL,
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

export function listModelProviders(): ModelProvider[] {
  return (Object.keys(PROVIDERS) as ProviderName[]).map((provider) => getModelProvider(provider));
}
