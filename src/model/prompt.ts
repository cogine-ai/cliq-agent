import type { InstructionMessage } from '../instructions/types.js';
import type {
  ChatMessage,
  JsonSchema,
  ModelCapabilities,
  ModelCompleteRequest,
  ModelOutputSchema,
  ModelPromptInputItem,
  ModelPromptRequest,
  ModelProviderCapabilities,
  ModelToolSpec,
  ResolvedModelConfig,
  TextActionFallback
} from './types.js';

type ToolRegistryWithSpecs = {
  modelVisibleToolSpecs?: () => ModelToolSpec[];
};

export const CLIQ_RESPONSE_SCHEMA: ModelOutputSchema = {
  name: 'cliq_response',
  strict: true,
  schema: {
    type: 'object',
    oneOf: [
      {
        type: 'object',
        properties: {
          type: { const: 'final' },
          message: { type: 'string' }
        },
        required: ['type', 'message'],
        additionalProperties: false
      },
      {
        type: 'object',
        properties: {
          type: { const: 'tool' },
          tool: { type: 'string' },
          arguments: { type: 'object' },
          callId: { type: 'string' }
        },
        required: ['type', 'tool', 'arguments'],
        additionalProperties: false
      }
    ]
  }
};

export function isModelPromptRequest(request: ModelCompleteRequest): request is ModelPromptRequest {
  return !Array.isArray(request) && request.kind === 'model-prompt-request';
}

function baseInstructionsFromMessages(instructions: InstructionMessage[]) {
  const messages = instructions.map<ChatMessage>((message) => ({
    role: message.role,
    content: message.content
  }));
  return {
    messages,
    text: messages.map((message) => message.content).join('\n\n')
  };
}

export function resolveProviderPromptCapabilities({
  modelConfig,
  modelCapabilities
}: {
  modelConfig: ResolvedModelConfig;
  modelCapabilities: ModelCapabilities;
}): ModelProviderCapabilities {
  const canUseNativeTools = modelCapabilities.toolCalling;
  switch (modelConfig.provider) {
    case 'openai':
    case 'openai-compatible':
    case 'openrouter':
      return {
        nativeToolCalling: canUseNativeTools,
        structuredOutput: true,
        streaming: modelCapabilities.streaming
      };
    case 'anthropic':
      return {
        nativeToolCalling: canUseNativeTools,
        structuredOutput: false,
        streaming: modelCapabilities.streaming
      };
    case 'ollama':
      return {
        nativeToolCalling: canUseNativeTools,
        structuredOutput: true,
        streaming: modelCapabilities.streaming
      };
    default: {
      const _exhaustive: never = modelConfig.provider;
      return _exhaustive;
    }
  }
}

function textActionFallbackFor({
  modelConfig,
  providerCapabilities
}: {
  modelConfig: ResolvedModelConfig;
  providerCapabilities: ModelProviderCapabilities;
}): TextActionFallback {
  const maxAttempts = modelConfig.provider === 'ollama' ? 2 : 1;
  if (providerCapabilities.nativeToolCalling || providerCapabilities.structuredOutput) {
    return {
      mode: 'disabled',
      maxAttempts
    };
  }
  return {
    mode: 'bounded',
    maxAttempts,
    reason: 'provider has no native tool-calling or structured-output capability'
  };
}

export function buildModelPromptRequest({
  modelConfig,
  modelCapabilities,
  instructions,
  input,
  registry,
  providerCapabilities = resolveProviderPromptCapabilities({ modelConfig, modelCapabilities })
}: {
  modelConfig: ResolvedModelConfig;
  modelCapabilities: ModelCapabilities;
  instructions: InstructionMessage[];
  input: ModelPromptInputItem[];
  registry: ToolRegistryWithSpecs;
  providerCapabilities?: ModelProviderCapabilities;
}): ModelPromptRequest {
  return {
    kind: 'model-prompt-request',
    model: modelConfig,
    baseInstructions: baseInstructionsFromMessages(instructions),
    input,
    toolSpecs: registry.modelVisibleToolSpecs?.() ?? [],
    outputSchema: CLIQ_RESPONSE_SCHEMA,
    providerCapabilities,
    streaming: {
      mode: modelConfig.streaming
    },
    textActionFallback: textActionFallbackFor({ modelConfig, providerCapabilities })
  };
}

function schemaForPrompt(schema: JsonSchema) {
  return JSON.stringify(schema);
}

function toolSchemaLines(request: ModelPromptRequest) {
  if (request.toolSpecs.length === 0) {
    return ['- No runtime tools are available for this request.'];
  }
  const toolLines = request.toolSpecs.map((tool) => {
    return `- ${tool.name}: ${tool.description}; arguments JSON schema: ${schemaForPrompt(tool.inputSchema)}`;
  });
  return toolLines;
}

export function buildStructuredToolInstructions(request: ModelPromptRequest) {
  return [
    'STRUCTURED TOOL SCHEMA MODE',
    'When the structured output schema asks for {"type":"tool","tool":"<tool name>","arguments":{...}}, choose only one of these runtime tools and match its argument schema:',
    ...toolSchemaLines(request)
  ].join('\n');
}

export function buildTextActionFallbackInstructions(request: ModelPromptRequest) {
  return [
    'TEXT ACTION FALLBACK MODE',
    'Native tool calling and structured output are unavailable for this request.',
    'Return exactly one JSON object with one of these shapes:',
    '- {"type":"final","message":"<final response>"}',
    '- {"type":"tool","tool":"<tool name>","arguments":{...}}',
    'Available tools come from the runtime registry:',
    ...toolSchemaLines(request),
    `The runtime will stop this fallback path after ${request.textActionFallback.maxAttempts} invalid text-action attempts.`
  ].join('\n');
}

export function parseStructuredOutput(content: string) {
  const parsed = JSON.parse(content) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`structured output must be an object: ${content}`);
  }
  const value = parsed as Record<string, unknown>;
  if (value.type === 'final' && typeof value.message === 'string') {
    return {
      type: 'final' as const,
      message: value.message
    };
  }
  if (value.type === 'tool' && typeof value.tool === 'string' && value.arguments && typeof value.arguments === 'object') {
    return {
      type: 'tool' as const,
      tool: value.tool,
      arguments: value.arguments as Record<string, unknown>,
      ...(typeof value.callId === 'string' ? { callId: value.callId } : {})
    };
  }
  throw new Error(`structured output does not match Cliq response schema: ${content}`);
}
