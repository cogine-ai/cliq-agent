import { OLLAMA_DEFAULT_BASE_URL, OLLAMA_DISCOVERY_TIMEOUT_MS } from '../../config.js';
import { fetchWithTimeout, joinUrl, readJsonResponse } from '../http.js';

export type OllamaModelSummary = {
  name: string;
  modified_at?: string;
  size?: number;
  digest?: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizeOllamaModel(value: unknown): OllamaModelSummary | null {
  if (!isRecord(value) || typeof value.name !== 'string' || value.name.trim() === '') {
    return null;
  }

  return {
    name: value.name,
    ...(typeof value.modified_at === 'string' ? { modified_at: value.modified_at } : {}),
    ...(typeof value.size === 'number' ? { size: value.size } : {}),
    ...(typeof value.digest === 'string' ? { digest: value.digest } : {})
  };
}

export function selectDefaultOllamaModel(models: OllamaModelSummary[]) {
  return models.find((model) => model.name.toLowerCase().includes('qwen'))?.name ?? models[0]?.name ?? null;
}

export async function discoverOllamaModels(baseUrl = OLLAMA_DEFAULT_BASE_URL): Promise<OllamaModelSummary[]> {
  const response = await fetchWithTimeout(
    joinUrl(baseUrl, '/api/tags'),
    {
      method: 'GET'
    },
    OLLAMA_DISCOVERY_TIMEOUT_MS
  );
  const json = await readJsonResponse<unknown>(response, 'Ollama discovery');

  if (!isRecord(json) || !Array.isArray(json.models)) {
    throw new Error(`Ollama discovery response missing models array: ${JSON.stringify(json)}`);
  }

  return json.models.flatMap((model) => {
    const normalized = normalizeOllamaModel(model);
    return normalized ? [normalized] : [];
  });
}
