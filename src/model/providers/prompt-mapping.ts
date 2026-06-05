import type {
  EffectiveModelRequest,
  ModelPromptInputItem,
  ModelPromptRequest,
  ModelRequestMode,
  ModelStructuredOutput,
  ModelToolCall,
  ModelToolSpec
} from '../types.js';
import { buildStructuredToolInstructions, buildTextActionFallbackInstructions, parseStructuredOutput } from '../prompt.js';

type OpenAIChatMessage = {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  tool_call_id?: string;
  tool_calls?: Array<{
    id: string;
    type: 'function';
    function: {
      name: string;
      arguments: string;
    };
  }>;
};

type AnthropicContentBlock =
  | {
      type: 'text';
      text: string;
    }
  | {
      type: 'tool_use';
      id: string;
      name: string;
      input: Record<string, unknown>;
    }
  | {
      type: 'tool_result';
      tool_use_id: string;
      content: string;
      is_error?: boolean;
    };

type AnthropicMessage = {
  role: 'user' | 'assistant';
  content: string | AnthropicContentBlock[];
};

export type OpenAIToolCallDeltaAccumulator = Map<
  number,
  {
    id?: string;
    name?: string;
    arguments: string;
  }
>;

export function selectTypedRequestMode(request: ModelPromptRequest): ModelRequestMode {
  if (request.providerCapabilities.nativeToolCalling && request.toolSpecs.length > 0) {
    return 'native-tools';
  }
  if (request.providerCapabilities.structuredOutput) {
    return 'structured-output';
  }
  return 'text-action';
}

export function effectiveTypedRequest(
  request: ModelPromptRequest,
  mode: ModelRequestMode,
  streaming: boolean
): EffectiveModelRequest {
  return {
    provider: request.model.provider,
    model: request.model.model,
    mode,
    streaming,
    baseInstructionChars: request.baseInstructions.text.length,
    inputItemCount: request.input.length,
    toolNames: request.toolSpecs.map((tool) => tool.name),
    outputSchema: mode === 'structured-output' ? request.outputSchema.name : undefined,
    textActionFallback: request.textActionFallback
  };
}

function toolCallArguments(call: ModelToolCall) {
  return JSON.stringify(call.arguments);
}

function modelInputToOpenAIMessage(item: ModelPromptInputItem, mode: ModelRequestMode): OpenAIChatMessage {
  if (item.kind === 'tool_result') {
    if (mode === 'native-tools' && item.callId) {
      return {
        role: 'tool',
        tool_call_id: item.callId,
        content: item.content
      };
    }
    return {
      role: 'user',
      content: item.content
    };
  }

  if (mode === 'native-tools' && item.role === 'assistant' && item.toolCalls?.length) {
    return {
      role: 'assistant',
      content: item.content,
      tool_calls: item.toolCalls.map((call) => ({
        id: call.id,
        type: 'function',
        function: {
          name: call.name,
          arguments: toolCallArguments(call)
        }
      }))
    };
  }

  return {
    role: item.role,
    content: item.content
  };
}

export function typedPromptToOpenAIMessages(request: ModelPromptRequest, mode: ModelRequestMode): OpenAIChatMessage[] {
  return [
    ...request.baseInstructions.messages.map<OpenAIChatMessage>((message) => ({
      role: message.role,
      content: message.content
    })),
    ...(mode === 'text-action'
      ? [
          {
            role: 'system' as const,
            content: buildTextActionFallbackInstructions(request)
          }
        ]
      : []),
    ...(mode === 'structured-output'
      ? [
          {
            role: 'system' as const,
            content: buildStructuredToolInstructions(request)
          }
        ]
      : []),
    ...request.input.map((item) => modelInputToOpenAIMessage(item, mode))
  ];
}

export function toolSpecsToOpenAIChatTools(toolSpecs: ModelToolSpec[]) {
  return toolSpecs.map((tool) => ({
    type: 'function' as const,
    function: {
      name: tool.name,
      description: tool.description,
      parameters: tool.inputSchema
    }
  }));
}

export function toolSpecsToAnthropicTools(toolSpecs: ModelToolSpec[]) {
  return toolSpecs.map((tool) => ({
    name: tool.name,
    description: tool.description,
    input_schema: tool.inputSchema
  }));
}

export function openAIJsonSchemaResponseFormat(request: ModelPromptRequest) {
  return {
    type: 'json_schema',
    json_schema: {
      name: request.outputSchema.name,
      strict: request.outputSchema.strict,
      schema: request.outputSchema.schema
    }
  };
}

function parseToolArguments(value: unknown): Record<string, unknown> {
  if (typeof value === 'string') {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

export function captureOpenAIToolCallDeltas(json: unknown, accumulator: OpenAIToolCallDeltaAccumulator): string | null {
  const choice = (json as {
    choices?: Array<{
      delta?: {
        content?: string;
        tool_calls?: Array<{
          index?: number;
          id?: string;
          function?: {
            name?: string;
            arguments?: string;
          };
        }>;
      };
    }>;
  }).choices?.[0];
  const delta = choice?.delta;
  for (const call of delta?.tool_calls ?? []) {
    const index = typeof call.index === 'number' ? call.index : accumulator.size;
    const existing = accumulator.get(index) ?? { arguments: '' };
    accumulator.set(index, {
      ...existing,
      ...(typeof call.id === 'string' ? { id: call.id } : {}),
      ...(typeof call.function?.name === 'string' ? { name: call.function.name } : {}),
      arguments: existing.arguments + (call.function?.arguments ?? '')
    });
  }
  return delta?.content ?? null;
}

export function openAIToolCallsFromDeltaParts(accumulator: OpenAIToolCallDeltaAccumulator): ModelToolCall[] {
  const tool_calls = [...accumulator.entries()]
    .sort(([left], [right]) => left - right)
    .map(([, call]) => ({
      id: call.id,
      function: {
        name: call.name,
        arguments: call.arguments
      }
    }));
  return parseOpenAIToolCalls({ tool_calls });
}

export function parseOpenAIToolCalls(message: {
  tool_calls?: Array<{
    id?: string;
    function?: {
      name?: string;
      arguments?: unknown;
    };
  }>;
}): ModelToolCall[] {
  return (message.tool_calls ?? [])
    .filter((call) => typeof call.id === 'string' && typeof call.function?.name === 'string')
    .map((call) => ({
      id: call.id!,
      name: call.function!.name!,
      arguments: parseToolArguments(call.function?.arguments)
    }));
}

export function parseOllamaToolCalls(message: {
  tool_calls?: Array<{
    id?: string;
    function?: {
      name?: string;
      arguments?: unknown;
    };
  }>;
}): ModelToolCall[] {
  return (message.tool_calls ?? [])
    .filter((call) => typeof call.function?.name === 'string')
    .map((call, index) => ({
      id: typeof call.id === 'string' ? call.id : `ollama_call_${index + 1}`,
      name: call.function!.name!,
      arguments: parseToolArguments(call.function?.arguments)
    }));
}

export function maybeParseStructuredOutput(mode: ModelRequestMode, content: string): ModelStructuredOutput | undefined {
  if (mode !== 'structured-output' && mode !== 'text-action') {
    return undefined;
  }
  return parseStructuredOutput(content);
}

function modelInputToAnthropicMessage(item: ModelPromptInputItem, mode: ModelRequestMode): AnthropicMessage {
  if (item.kind === 'tool_result') {
    if (mode === 'native-tools' && item.callId) {
      return {
        role: 'user',
        content: [
          {
            type: 'tool_result',
            tool_use_id: item.callId,
            content: item.content,
            ...(item.status === 'error' ? { is_error: true } : {})
          }
        ]
      };
    }
    return { role: 'user', content: item.content };
  }

  if (mode === 'native-tools' && item.role === 'assistant' && item.toolCalls?.length) {
    const content: AnthropicContentBlock[] = [
      ...(item.content.trim() ? [{ type: 'text' as const, text: item.content }] : []),
      ...item.toolCalls.map((call) => ({
        type: 'tool_use' as const,
        id: call.id,
        name: call.name,
        input: call.arguments
      }))
    ];
    return {
      role: 'assistant',
      content
    };
  }

  return {
    role: item.role === 'system' ? 'user' : item.role,
    content: item.content
  };
}

export function typedPromptToAnthropicInput(request: ModelPromptRequest, mode: ModelRequestMode) {
  const system = [
    request.baseInstructions.text,
    ...(mode === 'structured-output' ? [buildStructuredToolInstructions(request)] : []),
    ...(mode === 'text-action' ? [buildTextActionFallbackInstructions(request)] : [])
  ]
    .filter(Boolean)
    .join('\n\n');
  const messages = request.input.map((item) => modelInputToAnthropicMessage(item, mode));
  return { system, messages };
}
