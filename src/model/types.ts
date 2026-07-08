export type ProviderName =
  | 'openrouter'
  | 'anthropic'
  | 'openai'
  | 'openai-compatible'
  | 'zhipu'
  | 'ollama'
  | 'cliq-models';

export type ModelModality = 'text' | 'image' | 'audio' | 'video';

export type StreamingMode = 'auto' | 'on' | 'off';

export type ChatMessage = {
  role: 'system' | 'user' | 'assistant';
  content: string;
};

export type JsonSchema = {
  type?: string | string[];
  description?: string;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  additionalProperties?: boolean | JsonSchema;
  items?: JsonSchema;
  enum?: unknown[];
  oneOf?: JsonSchema[];
  anyOf?: JsonSchema[];
  const?: unknown;
  [key: string]: unknown;
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
  toolCalls?: ModelToolCall[];
  structuredOutput?: ModelStructuredOutput;
  effectiveRequest?: EffectiveModelRequest;
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

export type ModelToolSpec = {
  name: string;
  description: string;
  inputSchema: JsonSchema;
};

export type ModelToolCall = {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
};

export type ModelStructuredOutput =
  | {
      type: 'final';
      message: string;
    }
  | {
      type: 'tool';
      tool: string;
      arguments: Record<string, unknown>;
      callId?: string;
    };

export type ModelPromptInputItem =
  | {
      kind: 'message';
      role: ChatMessage['role'];
      content: string;
      toolCalls?: ModelToolCall[];
    }
  | {
      kind: 'tool_result';
      toolName: string;
      status: 'ok' | 'error';
      content: string;
      callId?: string;
      meta?: Record<string, string | number | boolean | null>;
    };

export type ModelBaseInstructions = {
  messages: ChatMessage[];
  text: string;
};

export type ModelOutputSchema = {
  name: string;
  schema: JsonSchema;
  strict: boolean;
};

export type ModelProviderCapabilities = {
  nativeToolCalling: boolean;
  structuredOutput: boolean;
  streaming: boolean;
};

export type TextActionFallback = {
  mode: 'disabled' | 'bounded';
  maxAttempts: number;
  reason?: string;
};

export type ModelRequestMode = 'native-tools' | 'structured-output' | 'text-action';

export type EffectiveModelRequest = {
  provider: ProviderName;
  model: string;
  mode: ModelRequestMode;
  streaming: boolean;
  baseInstructionChars: number;
  inputItemCount: number;
  toolNames: string[];
  outputSchema?: string;
  textActionFallback?: TextActionFallback;
};

export type ModelPromptRequest = {
  kind: 'model-prompt-request';
  model: ResolvedModelConfig;
  baseInstructions: ModelBaseInstructions;
  input: ModelPromptInputItem[];
  toolSpecs: ModelToolSpec[];
  outputSchema: ModelOutputSchema;
  providerCapabilities: ModelProviderCapabilities;
  streaming: {
    mode: StreamingMode;
  };
  textActionFallback: TextActionFallback;
};

export type ModelCompleteRequest = ChatMessage[] | ModelPromptRequest;

export type ModelClient = {
  complete(request: ModelCompleteRequest, options?: ModelCompleteOptions): Promise<ModelCompletion>;
};
