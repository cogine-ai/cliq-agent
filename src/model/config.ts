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
};

export function isStreamingMode(value: string): value is StreamingMode {
  return value === 'auto' || value === 'on' || value === 'off';
}

function firstDefined(...values: Array<string | undefined | null>): string | undefined {
  for (const value of values) {
    if (value !== undefined && value !== null && value !== '') {
      return value;
    }
  }

  return undefined;
}

function getProviderApiKey(provider: ProviderName) {
  if (provider === 'openrouter') return process.env.OPENROUTER_API_KEY;
  if (provider === 'anthropic') return process.env.ANTHROPIC_API_KEY;
  if (provider === 'openai') return process.env.OPENAI_API_KEY;
  if (provider === 'openai-compatible') {
    return firstDefined(process.env.CLIQ_MODEL_API_KEY, process.env.OPENAI_COMPATIBLE_API_KEY);
  }

  return undefined;
}

function requireApiKey(provider: ProviderName, apiKey: string | undefined) {
  if (provider === 'ollama' || provider === 'openai-compatible') {
    return;
  }

  if (!apiKey) {
    throw new Error(`${provider} API key is required`);
  }
}

export function resolveModelConfig({ workspace, cli }: ModelConfigInput): ResolvedModelConfig {
  const rawProvider = firstDefined(
    cli.provider,
    workspace.model?.provider,
    process.env.CLIQ_MODEL_PROVIDER,
    DEFAULT_MODEL_CONFIG.provider
  );
  if (!rawProvider || !isProviderName(rawProvider)) {
    throw new Error(`Unknown model provider: ${rawProvider ?? ''}`);
  }

  const provider = rawProvider;
  const providerDef = getModelProvider(provider);
  const rawStreaming = firstDefined(
    cli.streaming,
    workspace.model?.streaming,
    process.env.CLIQ_MODEL_STREAMING,
    DEFAULT_MODEL_CONFIG.streaming
  );
  if (!rawStreaming || !isStreamingMode(rawStreaming)) {
    throw new Error(`Invalid streaming mode: ${rawStreaming ?? ''}`);
  }

  const model = firstDefined(cli.model, workspace.model?.model, process.env.CLIQ_MODEL, providerDef.getDefaultModel());
  if (!model) {
    throw new Error(`model is required for provider ${provider}`);
  }

  const baseUrl = firstDefined(
    cli.baseUrl,
    workspace.model?.baseUrl,
    process.env.CLIQ_MODEL_BASE_URL,
    providerDef.defaultBaseUrl
  );
  if (!baseUrl) {
    throw new Error(`baseUrl is required for provider ${provider}`);
  }

  const apiKey = getProviderApiKey(provider);
  requireApiKey(provider, apiKey);

  return {
    provider,
    model,
    baseUrl,
    ...(apiKey ? { apiKey } : {}),
    streaming: rawStreaming
  };
}
