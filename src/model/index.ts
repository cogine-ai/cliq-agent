import { getModelProvider, registerModelClientFactory } from './registry.js';
import type { ModelClient, ResolvedModelConfig } from './types.js';
import { createAnthropicClient } from './providers/anthropic.js';
import { createOllamaClient } from './providers/ollama.js';
import { createOpenAIClient } from './providers/openai.js';
import { createOpenAICompatibleClient } from './providers/openai-compatible.js';
import { createOpenRouterClient } from './providers/openrouter.js';

let registered = false;

export function registerBuiltInModelProviders() {
  if (registered) {
    return;
  }

  registerModelClientFactory('openrouter', createOpenRouterClient);
  registerModelClientFactory('anthropic', createAnthropicClient);
  registerModelClientFactory('openai', createOpenAIClient);
  registerModelClientFactory('openai-compatible', createOpenAICompatibleClient);
  registerModelClientFactory('ollama', createOllamaClient);
  registered = true;
}

export function createModelClient(config: ResolvedModelConfig): ModelClient {
  registerBuiltInModelProviders();
  return getModelProvider(config.provider).createClient(config);
}
