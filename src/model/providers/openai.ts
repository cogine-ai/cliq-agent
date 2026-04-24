import type { ModelClient, ResolvedModelConfig } from '../types.js';
import { createOpenAICompatibleClient } from './openai-compatible.js';

export function createOpenAIClient(config: ResolvedModelConfig): ModelClient {
  return createOpenAICompatibleClient(config);
}
