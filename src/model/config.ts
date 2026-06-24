import { OLLAMA_DEFAULT_MODEL_HINT } from '../config.js';
import { EMPTY_PROVIDER_AUTH_STORE, getProviderAuthEntry, type ProviderAuthStore } from './auth-store.js';
import { discoverOllamaModels, selectDefaultOllamaModel } from './providers/ollama-discovery.js';
import { DEFAULT_MODEL_CONFIG, getModelProvider, isProviderName } from './registry.js';
import type { ProviderName, ResolvedModelConfig, StreamingMode } from './types.js';

export type PartialModelConfig = {
  provider?: string;
  model?: string;
  baseUrl?: string;
  streaming?: string;
};

export type ModelConfigInput = {
  workspace: {
    model?: PartialModelConfig;
  };
  cli: PartialModelConfig;
  auth?: ProviderAuthStore;
};

export type ModelSetupReason =
  | 'no-local-model'
  | 'missing-provider-api-key'
  | 'missing-model'
  | 'missing-base-url';

export type ModelSetupDetails = {
  reason: ModelSetupReason;
  provider: ProviderName;
  baseUrl?: string;
  missingEnvVar?: string;
  causeMessage?: string;
};

export class ModelSetupRequiredError extends Error {
  readonly code = 'MODEL_SETUP_REQUIRED';
  readonly reason: ModelSetupReason;
  readonly provider: ProviderName;
  readonly baseUrl?: string;
  readonly missingEnvVar?: string;
  readonly causeMessage?: string;

  constructor(details: ModelSetupDetails, options: { cause?: unknown } = {}) {
    super(formatModelSetupMessage(details), options);
    this.name = 'ModelSetupRequiredError';
    this.reason = details.reason;
    this.provider = details.provider;
    this.baseUrl = details.baseUrl;
    this.missingEnvVar = details.missingEnvVar;
    this.causeMessage = details.causeMessage;
  }
}

export function isModelSetupRequiredError(error: unknown): error is ModelSetupRequiredError {
  if (error instanceof ModelSetupRequiredError) {
    return true;
  }
  if (!error || typeof error !== 'object') {
    return false;
  }

  const candidate = error as {
    code?: unknown;
    reason?: unknown;
    provider?: unknown;
    message?: unknown;
  };
  return (
    candidate.code === 'MODEL_SETUP_REQUIRED' &&
    isModelSetupReason(candidate.reason) &&
    typeof candidate.provider === 'string' &&
    isProviderName(candidate.provider) &&
    typeof candidate.message === 'string'
  );
}

export function formatModelSetupMessage(details: ModelSetupDetails): string {
  const status = formatSetupStatus(details);
  return [
    'Cliq needs a model provider before chat can start.',
    '',
    'Current status:',
    `  ${status}`,
    ...(details.causeMessage ? [`  Ollama discovery error: ${details.causeMessage}`] : []),
    '',
    'Provider configuration:',
    '  Local Ollama:',
    `    ollama pull ${OLLAMA_DEFAULT_MODEL_HINT}`,
    `    cliq --provider ollama --model ${OLLAMA_DEFAULT_MODEL_HINT}`,
    '  OpenAI:',
    '    cliq providers auth set openai --api-key --model gpt-5.2',
    '    export OPENAI_API_KEY=...',
    '    cliq --provider openai --model gpt-5.2',
    '  Anthropic:',
    '    cliq providers auth set anthropic --api-key --model claude-sonnet-4-20250514',
    '    export ANTHROPIC_API_KEY=...',
    '    cliq --provider anthropic --model claude-sonnet-4-20250514',
    '  OpenRouter:',
    `    cliq providers auth set openrouter --api-key --model ${DEFAULT_MODEL_CONFIG.model}`,
    '    export OPENROUTER_API_KEY=...',
    `    cliq --provider openrouter --model ${DEFAULT_MODEL_CONFIG.model}`,
    '  Zhipu AI:',
    '    cliq providers auth set zhipu --api-key --model glm-5.2',
    '    export ZHIPU_API_KEY=...  # preferred',
    '    export ZHIPUAI_API_KEY=...  # supported alias',
    '    cliq --provider zhipu --model glm-5.2',
    '  OpenAI-compatible:',
    '    cliq providers auth set openai-compatible --base-url http://localhost:4000/v1 --model <model> [--api-key]',
    '    cliq --provider openai-compatible --base-url http://localhost:4000/v1 --model <model>',
    '',
    'Model selection:',
    '  Use cliq providers auth set, --model <model>, CLIQ_MODEL, or .cliq/config model.model.',
    '  Configure a provider/model, then run cliq again.'
  ].join('\n');
}

export function isStreamingMode(value: string): value is StreamingMode {
  return value === 'auto' || value === 'on' || value === 'off';
}

function isModelSetupReason(value: unknown): value is ModelSetupReason {
  return (
    value === 'no-local-model' ||
    value === 'missing-provider-api-key' ||
    value === 'missing-model' ||
    value === 'missing-base-url'
  );
}

function firstDefined(...values: Array<string | undefined | null>): string | undefined {
  for (const value of values) {
    if (value !== undefined && value !== null && value !== '') {
      return value;
    }
  }

  return undefined;
}

function getProviderApiKey(provider: ProviderName, auth: ProviderAuthStore) {
  if (provider === 'openrouter') return firstDefined(process.env.OPENROUTER_API_KEY, getProviderAuthEntry(auth, provider)?.apiKey);
  if (provider === 'anthropic') return firstDefined(process.env.ANTHROPIC_API_KEY, getProviderAuthEntry(auth, provider)?.apiKey);
  if (provider === 'openai') return firstDefined(process.env.OPENAI_API_KEY, getProviderAuthEntry(auth, provider)?.apiKey);
  if (provider === 'zhipu') {
    return firstDefined(process.env.ZHIPU_API_KEY, process.env.ZHIPUAI_API_KEY, getProviderAuthEntry(auth, provider)?.apiKey);
  }
  if (provider === 'openai-compatible') {
    return firstDefined(
      process.env.CLIQ_MODEL_API_KEY,
      process.env.OPENAI_COMPATIBLE_API_KEY,
      getProviderAuthEntry(auth, provider)?.apiKey
    );
  }

  return getProviderAuthEntry(auth, provider)?.apiKey;
}

function formatSetupStatus(details: ModelSetupDetails) {
  const displayName = getModelProvider(details.provider).displayName;
  switch (details.reason) {
    case 'no-local-model':
      return [
        'No provider/model is configured.',
        `Cliq checked local Ollama at ${details.baseUrl ?? 'http://localhost:11434'}, but no local model could be selected.`
      ].join(' ');
    case 'missing-provider-api-key':
      return `${displayName} provider is selected, but ${details.missingEnvVar ?? 'the required API key'} is not set.`;
    case 'missing-model':
      return `${displayName} provider is selected, but no model id was configured.`;
    case 'missing-base-url':
      return `${displayName} provider is selected, but no base URL was configured.`;
    default: {
      const _exhaustive: never = details.reason;
      return _exhaustive;
    }
  }
}

function requireApiKey(provider: ProviderName, apiKey: string | undefined) {
  const providerDef = getModelProvider(provider);
  if (providerDef.requiresApiKey && !apiKey) {
    throw new ModelSetupRequiredError({
      reason: 'missing-provider-api-key',
      provider,
      missingEnvVar: providerDef.apiKeyEnv
    });
  }
}

function buildNoLocalModelConfiguredError(baseUrl: string, cause?: unknown) {
  const causeMessage = cause instanceof Error ? cause.message : cause ? String(cause) : '';
  return new ModelSetupRequiredError(
    {
      reason: 'no-local-model',
      provider: 'ollama',
      baseUrl,
      ...(causeMessage ? { causeMessage } : {})
    },
    { cause }
  );
}

async function discoverDefaultOllamaModel(baseUrl: string) {
  let models: Awaited<ReturnType<typeof discoverOllamaModels>>;
  try {
    models = await discoverOllamaModels(baseUrl);
  } catch (error) {
    throw buildNoLocalModelConfiguredError(baseUrl, error);
  }

  const selected = selectDefaultOllamaModel(models);
  if (!selected) {
    throw buildNoLocalModelConfiguredError(baseUrl);
  }

  return selected;
}

export async function resolveModelConfig({ workspace, cli, auth = EMPTY_PROVIDER_AUTH_STORE }: ModelConfigInput): Promise<ResolvedModelConfig> {
  const rawProvider = firstDefined(cli.provider, workspace.model?.provider, process.env.CLIQ_MODEL_PROVIDER, auth.activeProvider);
  let provider: ProviderName;
  if (rawProvider) {
    if (!isProviderName(rawProvider)) {
      throw new Error(`Unknown model provider: ${rawProvider}`);
    }
    provider = rawProvider;
  } else {
    provider = 'ollama';
  }

  const providerDef = getModelProvider(provider);
  const authEntry = getProviderAuthEntry(auth, provider);
  const rawStreaming = firstDefined(
    cli.streaming,
    workspace.model?.streaming,
    process.env.CLIQ_MODEL_STREAMING,
    authEntry?.streaming,
    DEFAULT_MODEL_CONFIG.streaming
  );
  if (!rawStreaming || !isStreamingMode(rawStreaming)) {
    throw new Error(`Invalid streaming mode: ${rawStreaming ?? ''}`);
  }

  let model = firstDefined(cli.model, workspace.model?.model, process.env.CLIQ_MODEL, authEntry?.model, providerDef.getDefaultModel());
  const baseUrl = firstDefined(
    cli.baseUrl,
    workspace.model?.baseUrl,
    process.env.CLIQ_MODEL_BASE_URL,
    authEntry?.baseUrl,
    providerDef.defaultBaseUrl
  );
  if (!baseUrl) {
    throw new ModelSetupRequiredError({
      reason: 'missing-base-url',
      provider
    });
  }

  if (!model && provider === 'ollama') {
    model = await discoverDefaultOllamaModel(baseUrl);
  }

  if (!model) {
    throw new ModelSetupRequiredError({
      reason: 'missing-model',
      provider,
      baseUrl
    });
  }

  const apiKey = getProviderApiKey(provider, auth);
  requireApiKey(provider, apiKey);

  return {
    provider,
    model,
    baseUrl,
    ...(apiKey ? { apiKey } : {}),
    streaming: rawStreaming
  };
}
