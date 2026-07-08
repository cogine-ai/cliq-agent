import { CLIQ_MODELS_DISCOVERY_TIMEOUT_MS } from '../../config.js';
import { emitModelErrorEvent } from '../events.js';
import { fetchWithTimeout, joinUrl, readJsonResponse } from '../http.js';
import { isModelPromptRequest } from '../prompt.js';
import type {
  ModelClient,
  ModelCompleteOptions,
  ModelCompleteRequest,
  ModelCompletion,
  ModelPromptRequest,
  ModelStreamEvent,
  ResolvedModelConfig
} from '../types.js';
import { createOllamaClient } from './ollama.js';
import type { OllamaModelSummary } from './ollama-discovery.js';

export type CliqModelsRuntimeErrorCode =
  | 'CLIQ_MODELS_MODEL_ID_INVALID'
  | 'CLIQ_MODELS_RUNTIME_UNAVAILABLE'
  | 'CLIQ_MODELS_MODEL_MISSING'
  | 'CLIQ_MODELS_GENERATION_FAILED';

export class CliqModelsRuntimeError extends Error {
  readonly provider = 'cliq-models';
  readonly code: CliqModelsRuntimeErrorCode;
  readonly model: string;
  readonly runtimeModel?: string;
  readonly baseUrl: string;
  readonly runtimeVersion?: string;
  readonly runtimeDistribution?: string;

  constructor(
    code: CliqModelsRuntimeErrorCode,
    message: string,
    details: {
      model: string;
      baseUrl: string;
      runtimeModel?: string;
      runtimeVersion?: string;
      runtimeDistribution?: string;
      cause?: unknown;
    }
  ) {
    super(message, details.cause === undefined ? undefined : { cause: details.cause });
    this.name = 'CliqModelsRuntimeError';
    this.code = code;
    this.model = details.model;
    this.baseUrl = details.baseUrl;
    this.runtimeModel = details.runtimeModel;
    this.runtimeVersion = details.runtimeVersion;
    this.runtimeDistribution = details.runtimeDistribution;
  }
}

type RuntimeVersionResponse = {
  version?: unknown;
  distribution?: unknown;
};

type RuntimeTagsResponse = {
  models?: Array<{
    name?: unknown;
  }>;
};

type RuntimeMetadata = {
  version?: string;
  distribution?: string;
};

const CLIQ_MODELS_PREFIX = 'cliq-models/';
const SAFE_RUNTIME_TAG = /^(?:[A-Za-z0-9][A-Za-z0-9._-]*\/)*[A-Za-z0-9][A-Za-z0-9._-]*(?::[A-Za-z0-9][A-Za-z0-9._-]*)?$/;

export function cliqModelIdToRuntimeTag(modelId: string): string {
  const trimmed = modelId.trim();
  if (!trimmed) {
    throw new Error('cliq-models requires a model id');
  }

  const runtimeTag = trimmed.startsWith(CLIQ_MODELS_PREFIX) ? trimmed.slice(CLIQ_MODELS_PREFIX.length) : trimmed;
  if (!SAFE_RUNTIME_TAG.test(runtimeTag)) {
    throw new Error(`unsafe model id for cliq-models managed runtime: ${modelId}`);
  }

  return runtimeTag;
}

function safeBaseUrlForMessage(baseUrl: string): string {
  try {
    const url = new URL(baseUrl);
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString().replace(/\/$/, '');
  } catch {
    return baseUrl.replace(/\/\/[^/@\s]+@/, '//').replace(/[?#].*$/, '');
  }
}

function runtimeModelForConfig(config: ResolvedModelConfig) {
  try {
    return cliqModelIdToRuntimeTag(config.model);
  } catch (error) {
    throw new CliqModelsRuntimeError(
      'CLIQ_MODELS_MODEL_ID_INVALID',
      `Cliq Models cannot route unsafe model id "${config.model}". Use a managed model id such as cliq-models/qwen3.5:4b.`,
      {
        model: config.model,
        baseUrl: config.baseUrl,
        cause: error
      }
    );
  }
}

async function readCliqModelsRuntimeVersion(baseUrl: string): Promise<RuntimeMetadata> {
  const response = await fetchWithTimeout(
    joinUrl(baseUrl, '/api/version'),
    {
      method: 'GET'
    },
    CLIQ_MODELS_DISCOVERY_TIMEOUT_MS
  );
  const json = await readJsonResponse<RuntimeVersionResponse>(response, 'Cliq Models');
  return {
    ...(typeof json.version === 'string' ? { version: json.version } : {}),
    ...(typeof json.distribution === 'string' ? { distribution: json.distribution } : {})
  };
}

export async function discoverCliqModelsRuntimeModels(baseUrl: string): Promise<OllamaModelSummary[]> {
  const response = await fetchWithTimeout(
    joinUrl(baseUrl, '/api/tags'),
    {
      method: 'GET'
    },
    CLIQ_MODELS_DISCOVERY_TIMEOUT_MS
  );
  const json = await readJsonResponse<RuntimeTagsResponse>(response, 'Cliq Models');
  if (!Array.isArray(json.models)) {
    throw new Error('Cliq Models managed runtime returned an invalid /api/tags response');
  }

  return json.models
    .map((model) => model.name)
    .filter((name): name is string => typeof name === 'string' && name.length > 0)
    .map((name) => ({ name }));
}

function runtimeUnavailableError(config: ResolvedModelConfig, runtimeModel: string | undefined, cause: unknown) {
  return new CliqModelsRuntimeError(
    'CLIQ_MODELS_RUNTIME_UNAVAILABLE',
    [
      `Cliq Models managed runtime is unavailable at ${safeBaseUrlForMessage(config.baseUrl)}.`,
      'Start the Cliq-managed model runtime, then retry the request.'
    ].join(' '),
    {
      model: config.model,
      baseUrl: config.baseUrl,
      ...(runtimeModel ? { runtimeModel } : {}),
      cause
    }
  );
}

function missingModelError(
  config: ResolvedModelConfig,
  runtimeModel: string,
  runtime: RuntimeMetadata,
  availableModels: OllamaModelSummary[]
) {
  const available = availableModels.length > 0 ? ` Available managed models: ${availableModels.map((model) => model.name).join(', ')}.` : '';
  return new CliqModelsRuntimeError(
    'CLIQ_MODELS_MODEL_MISSING',
    [
      `Cliq Models model is not available in the managed runtime: ${runtimeModel}.`,
      `Selected model id: ${config.model}.`,
      'Select an installed Cliq Models model or use the dedicated model-management flow to import one.',
      available
    ]
      .filter(Boolean)
      .join(' '),
    {
      model: config.model,
      baseUrl: config.baseUrl,
      runtimeModel,
      ...(runtime.version ? { runtimeVersion: runtime.version } : {}),
      ...(runtime.distribution ? { runtimeDistribution: runtime.distribution } : {})
    }
  );
}

async function checkCliqModelsRuntimeReadiness(config: ResolvedModelConfig, runtimeModel: string): Promise<RuntimeMetadata> {
  let runtime: RuntimeMetadata;
  let models: OllamaModelSummary[];
  try {
    runtime = await readCliqModelsRuntimeVersion(config.baseUrl);
    models = await discoverCliqModelsRuntimeModels(config.baseUrl);
  } catch (error) {
    throw runtimeUnavailableError(config, runtimeModel, error);
  }

  if (!models.some((model) => model.name === runtimeModel)) {
    throw missingModelError(config, runtimeModel, runtime, models);
  }

  return runtime;
}

function mapStartEvent(event: ModelStreamEvent, originalModel: string): ModelStreamEvent {
  if (event.type !== 'start') {
    return event;
  }

  return {
    ...event,
    model: originalModel
  };
}

function withoutInnerErrorEvents(options: ModelCompleteOptions | undefined, originalModel: string): ModelCompleteOptions | undefined {
  if (!options) {
    return undefined;
  }

  return {
    ...options,
    async onEvent(event) {
      if (event.type === 'error') {
        return;
      }
      await options.onEvent?.(mapStartEvent(event, originalModel));
    }
  };
}

function requestWithRuntimeModel(request: ModelCompleteRequest, runtimeModel: string): ModelCompleteRequest {
  if (!isModelPromptRequest(request)) {
    return request;
  }

  return {
    ...request,
    model: {
      ...request.model,
      model: runtimeModel
    }
  } satisfies ModelPromptRequest;
}

function completionWithCliqIdentity(completion: ModelCompletion, originalModel: string): ModelCompletion {
  return {
    ...completion,
    model: originalModel,
    ...(completion.effectiveRequest
      ? {
          effectiveRequest: {
            ...completion.effectiveRequest,
            model: originalModel
          }
        }
      : {})
  };
}

function httpStatusFromError(error: unknown): string | null {
  if (!(error instanceof Error)) {
    return null;
  }

  return /(?:error|stream error) (\d{3})/i.exec(error.message)?.[1] ?? null;
}

function generationFailedError(
  config: ResolvedModelConfig,
  runtimeModel: string | undefined,
  runtime: RuntimeMetadata | undefined,
  cause: unknown
) {
  const status = httpStatusFromError(cause);
  return new CliqModelsRuntimeError(
    'CLIQ_MODELS_GENERATION_FAILED',
    [
      `Cliq Models generation failed for ${config.model} at ${safeBaseUrlForMessage(config.baseUrl)}.`,
      runtimeModel ? `Runtime model: ${runtimeModel}.` : '',
      status ? `Runtime response: HTTP ${status}.` : '',
      'Check the Cliq-managed runtime health and selected model readiness.'
    ]
      .filter(Boolean)
      .join(' '),
    {
      model: config.model,
      baseUrl: config.baseUrl,
      ...(runtimeModel ? { runtimeModel } : {}),
      ...(runtime?.version ? { runtimeVersion: runtime.version } : {}),
      ...(runtime?.distribution ? { runtimeDistribution: runtime.distribution } : {}),
      cause
    }
  );
}

function mapCliqModelsError(
  config: ResolvedModelConfig,
  runtimeModel: string | undefined,
  runtime: RuntimeMetadata | undefined,
  error: unknown
) {
  if (error instanceof CliqModelsRuntimeError) {
    return error;
  }

  return generationFailedError(config, runtimeModel, runtime, error);
}

export function createCliqModelsClient(config: ResolvedModelConfig): ModelClient {
  return {
    async complete(request: ModelCompleteRequest, options?: ModelCompleteOptions) {
      let runtimeModel: string | undefined;
      let runtime: RuntimeMetadata | undefined;
      try {
        runtimeModel = runtimeModelForConfig(config);
        runtime = await checkCliqModelsRuntimeReadiness(config, runtimeModel);

        const runtimeClient = createOllamaClient({
          ...config,
          model: runtimeModel
        });
        const completion = await runtimeClient.complete(
          requestWithRuntimeModel(request, runtimeModel),
          withoutInnerErrorEvents(options, config.model)
        );
        return completionWithCliqIdentity(completion, config.model);
      } catch (error) {
        const mapped = mapCliqModelsError(config, runtimeModel, runtime, error);
        await emitModelErrorEvent(options, mapped);
        throw mapped;
      }
    }
  };
}
