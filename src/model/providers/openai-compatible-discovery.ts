import { OPENAI_COMPATIBLE_DISCOVERY_TIMEOUT_MS } from '../../config.js';
import { fetchWithTimeout, joinUrl, readJsonResponse } from '../http.js';

export type OpenAICompatibleModelSummary = {
  id: string;
  owned_by?: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizeOpenAICompatibleModel(value: unknown): OpenAICompatibleModelSummary | null {
  if (!isRecord(value) || typeof value.id !== 'string' || value.id.trim() === '') {
    return null;
  }

  return {
    id: value.id,
    ...(typeof value.owned_by === 'string' ? { owned_by: value.owned_by } : {})
  };
}

export async function discoverOpenAICompatibleModels(
  baseUrl: string,
  apiKey?: string
): Promise<OpenAICompatibleModelSummary[]> {
  const response = await fetchWithTimeout(
    joinUrl(baseUrl, '/models'),
    {
      method: 'GET',
      headers: {
        ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {})
      }
    },
    OPENAI_COMPATIBLE_DISCOVERY_TIMEOUT_MS
  );
  const json = await readJsonResponse<unknown>(response, 'OpenAI-compatible discovery');

  if (!isRecord(json) || !Array.isArray(json.data)) {
    throw new Error(`OpenAI-compatible discovery response missing data array: ${JSON.stringify(json)}`);
  }

  return json.data.flatMap((model) => {
    const normalized = normalizeOpenAICompatibleModel(model);
    return normalized ? [normalized] : [];
  });
}
