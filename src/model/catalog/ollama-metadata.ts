import { OLLAMA_DISCOVERY_TIMEOUT_MS } from '../../config.js';
import { fetchWithTimeout, joinUrl, readJsonResponse } from '../http.js';
import type { ModelCatalogEntry, ContextWindowSource } from './schema.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parsePositiveInteger(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isInteger(value) && value > 0) {
    return value;
  }
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) {
    const parsed = Number(value.trim());
    return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
  }
  return undefined;
}

function extractModelInfoContextWindow(value: unknown): number | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  for (const [key, raw] of Object.entries(value)) {
    if (!key.toLowerCase().endsWith('context_length')) {
      continue;
    }
    const parsed = parsePositiveInteger(raw);
    if (parsed !== undefined) {
      return parsed;
    }
  }
  return undefined;
}

function extractParameterNumCtx(value: unknown): number | undefined {
  if (typeof value === 'string') {
    const match = value.match(/(?:^|\n)\s*num_ctx\s+(\d+)\s*(?:\n|$)/);
    return parsePositiveInteger(match?.[1]);
  }

  if (isRecord(value)) {
    return parsePositiveInteger(value.num_ctx);
  }

  return undefined;
}

function extractRunningContextWindow(value: unknown, model: string): number | undefined {
  if (!isRecord(value) || !Array.isArray(value.models)) {
    return undefined;
  }

  for (const item of value.models) {
    if (!isRecord(item)) {
      continue;
    }
    const name = typeof item.name === 'string' ? item.name : typeof item.model === 'string' ? item.model : undefined;
    if (name !== model) {
      continue;
    }
    const parsed = parsePositiveInteger(item.context_length);
    if (parsed !== undefined) {
      return parsed;
    }
  }

  return undefined;
}

async function readShow(baseUrl: string, model: string): Promise<unknown> {
  const response = await fetchWithTimeout(
    joinUrl(baseUrl, '/api/show'),
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({ model })
    },
    OLLAMA_DISCOVERY_TIMEOUT_MS
  );
  return readJsonResponse<unknown>(response, 'Ollama show');
}

async function readPs(baseUrl: string): Promise<unknown> {
  const response = await fetchWithTimeout(
    joinUrl(baseUrl, '/api/ps'),
    {
      method: 'GET'
    },
    OLLAMA_DISCOVERY_TIMEOUT_MS
  );
  return readJsonResponse<unknown>(response, 'Ollama ps');
}

function buildEntry({
  model,
  contextWindowSources,
  sourceKind
}: {
  model: string;
  contextWindowSources: ContextWindowSource[];
  sourceKind: 'ollama-show' | 'ollama-unavailable';
}): ModelCatalogEntry {
  const effectiveContextWindow = contextWindowSources.at(-1)?.contextWindow;
  return {
    provider: 'ollama',
    model,
    displayName: model,
    capabilities: {
      input: ['text'],
      output: ['text'],
      streaming: true,
      reasoning: false,
      toolCalling: false,
      ...(effectiveContextWindow !== undefined ? { contextWindow: effectiveContextWindow } : {})
    },
    source: {
      kind: sourceKind,
      confidence: effectiveContextWindow === undefined ? 'low' : 'medium',
      upstreamProvider: 'ollama',
      upstreamModelId: model
    },
    contextWindowSources
  };
}

export async function inspectOllamaModelMetadata(baseUrl: string, model: string): Promise<ModelCatalogEntry> {
  try {
    const show = await readShow(baseUrl, model);
    const sources: ContextWindowSource[] = [];

    if (isRecord(show)) {
      const rawContextWindow = extractModelInfoContextWindow(show.model_info);
      if (rawContextWindow !== undefined) {
        sources.push({
          kind: 'ollama-show-model-info',
          contextWindow: rawContextWindow,
          confidence: 'low'
        });
      }

      const parameterNumCtx = extractParameterNumCtx(show.parameters);
      if (parameterNumCtx !== undefined) {
        sources.push({
          kind: 'ollama-show-parameters',
          contextWindow: parameterNumCtx,
          confidence: 'high'
        });
      }
    }

    try {
      const ps = await readPs(baseUrl);
      const runningContextWindow = extractRunningContextWindow(ps, model);
      if (runningContextWindow !== undefined) {
        sources.push({
          kind: 'ollama-ps',
          contextWindow: runningContextWindow,
          confidence: 'high'
        });
      }
    } catch {
      // /api/ps is an optional refinement; /api/show metadata is still useful.
    }

    return buildEntry({ model, contextWindowSources: sources, sourceKind: 'ollama-show' });
  } catch {
    return buildEntry({ model, contextWindowSources: [], sourceKind: 'ollama-unavailable' });
  }
}
