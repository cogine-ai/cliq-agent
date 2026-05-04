export type ProviderName =
  | 'openrouter'
  | 'anthropic'
  | 'openai'
  | 'openai-compatible'
  | 'ollama';

export type ModelModality = 'text' | 'image' | 'audio' | 'video';

export type StreamingMode = 'auto' | 'on' | 'off';

export type ChatMessage = {
  role: 'system' | 'user' | 'assistant';
  content: string;
};

export type ModelCapabilities = {
  input: ModelModality[];
  output: ModelModality[];
  streaming: boolean;
  reasoning: boolean;
  toolCalling: boolean;
  contextWindow?: number;
  maxOutputTokens?: number;
};

export type ModelDescriptor = {
  provider: ProviderName;
  model: string;
  displayName: string;
  capabilities: ModelCapabilities;
};

export type ResolvedModelConfig = {
  provider: ProviderName;
  model: string;
  baseUrl: string;
  apiKey?: string;
  streaming: StreamingMode;
  maxOutputTokens?: number;
};

export type ModelCompletion = {
  content: string;
  provider: ProviderName;
  model: string;
};

export type ModelStreamEvent =
  | { type: 'start'; provider: ProviderName; model: string; streaming: boolean }
  | { type: 'text-delta'; text: string }
  | { type: 'end' }
  | { type: 'error'; message: string };

export type ModelCompleteOptions = {
  onEvent?: (event: ModelStreamEvent) => void | Promise<void>;
  signal?: AbortSignal;
};

export type ModelClient = {
  complete(messages: ChatMessage[], options?: ModelCompleteOptions): Promise<ModelCompletion>;
};
