import { OLLAMA_DEFAULT_MODEL_HINT } from '../config.js';
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

function buildNoLocalModelConfiguredError(baseUrl: string, cause?: unknown) {
  const causeMessage = cause instanceof Error ? cause.message : cause ? String(cause) : '';
  return new Error(
    [
      'No model provider or local Ollama model configured.',
      '',
      `Cliq defaults to local Ollama at ${baseUrl} when no model provider is configured, but no local model could be selected.`,
      '',
      'Options:',
      `  - Install a local model: ollama pull ${OLLAMA_DEFAULT_MODEL_HINT}`,
      '  - Select an existing local model: cliq --provider ollama --model <model> "task"',
      '  - Configure a remote provider with --provider, --model, and the required API key',
      ...(causeMessage ? ['', `Ollama discovery error: ${causeMessage}`] : [])
    ].join('\n')
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

export async function resolveModelConfig({ workspace, cli }: ModelConfigInput): Promise<ResolvedModelConfig> {
  const rawProvider = firstDefined(cli.provider, workspace.model?.provider, process.env.CLIQ_MODEL_PROVIDER);
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
  const rawStreaming = firstDefined(
    cli.streaming,
    workspace.model?.streaming,
    process.env.CLIQ_MODEL_STREAMING,
    DEFAULT_MODEL_CONFIG.streaming
  );
  if (!rawStreaming || !isStreamingMode(rawStreaming)) {
    throw new Error(`Invalid streaming mode: ${rawStreaming ?? ''}`);
  }

  let model = firstDefined(cli.model, workspace.model?.model, process.env.CLIQ_MODEL, providerDef.getDefaultModel());
  const baseUrl = firstDefined(
    cli.baseUrl,
    workspace.model?.baseUrl,
    process.env.CLIQ_MODEL_BASE_URL,
    providerDef.defaultBaseUrl
  );
  if (!baseUrl) {
    throw new Error(`baseUrl is required for provider ${provider}`);
  }

  if (!model && provider === 'ollama') {
    model = await discoverDefaultOllamaModel(baseUrl);
  }

  if (!model) {
    throw new Error(`model is required for provider ${provider}`);
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
