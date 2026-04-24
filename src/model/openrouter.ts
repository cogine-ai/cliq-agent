import { DEFAULT_MODEL_CONFIG } from './registry.js';
import type { ModelClient, ResolvedModelConfig } from './types.js';
import { createOpenRouterClient as createOpenRouterProviderClient } from './providers/openrouter.js';

export function createOpenRouterClient(config?: ResolvedModelConfig): ModelClient {
  const resolved = config ?? {
    ...DEFAULT_MODEL_CONFIG,
    apiKey: process.env.OPENROUTER_API_KEY
  };

  return createOpenRouterProviderClient(resolved);
}
