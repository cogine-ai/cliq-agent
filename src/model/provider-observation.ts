import { canonicalJsonBytes } from '../kernel/canonical.js';
import { assertBoundedJsonValue, parseJsonStrict } from '../kernel/json.js';
import type { ProviderName } from '../kernel/types.js';
import {
  type AgentModelStreamEvent,
  type AgentNegotiatedMode,
  type ModelResponseMediaType
} from '../protocol/agent-ir.js';
import {
  MODEL_RESPONSE_LIMIT_BYTES,
  type ObservedModelResponse,
  type ObservedToolCall,
  type ObservedUsage,
  type ProviderObservedStopReason
} from './attempt.js';

export type ObserveProviderResponseInput = {
  provider: ProviderName;
  model: string;
  negotiatedMode: AgentNegotiatedMode;
  status: number;
  mediaType: string | undefined;
  bytes: Uint8Array;
  observedAt: string;
};

export type ObservedProviderResponse = {
  observation: ObservedModelResponse;
  events: AgentModelStreamEvent[];
};

type DecodedResponse = Extract<ObservedModelResponse, { kind: 'decoded' }>;
type DecodedFields = Omit<DecodedResponse, 'kind' | 'provider' | 'model' | 'mediaType' | 'bytes' | 'observedAt'>;

type StreamParser<T> = { push(record: T): AgentModelStreamEvent[]; finish(): ParsedProviderResponse };

type ParsedProviderResponse = {
  fields: DecodedFields;
  events: AgentModelStreamEvent[];
  streaming: boolean;
};

type MutableToolCall = {
  wireIndex: number;
  wireCallId?: string;
  toolName?: string;
  argumentsUtf8: string;
};

class ProviderRejection extends Error {}
class ProviderIdentityMismatch extends Error {}
class IncompleteResponse extends Error {}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOwn(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function safeCount(value: unknown): number | null {
  return Number.isSafeInteger(value) && (value as number) >= 0 ? (value as number) : null;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function normalizeMediaType(value: string | undefined): ModelResponseMediaType {
  const base = value?.split(';', 1)[0]?.trim().toLowerCase();
  if (base === 'application/json') return 'application/json';
  if (base === 'text/event-stream') return 'text/event-stream';
  if (base === 'application/x-ndjson' || base === 'application/ndjson') return 'application/x-ndjson';
  return 'unknown';
}

function startEvent(input: ObserveProviderResponseInput, streaming: boolean): AgentModelStreamEvent {
  return { type: 'start', provider: input.provider, model: input.model, streaming };
}

function failure(
  input: ObserveProviderResponseInput,
  mediaType: ModelResponseMediaType,
  kind: 'malformed' | 'capability_shape_mismatch' | 'provider_rejection' | 'prefix_over_limit',
  streaming: boolean,
  includeStart = true
): ObservedProviderResponse {
  const observation =
    kind === 'prefix_over_limit'
      ? {
          kind,
          provider: input.provider,
          model: input.model,
          mediaType,
          bytes: input.bytes.slice(0, MODEL_RESPONSE_LIMIT_BYTES + 1),
          observedAt: input.observedAt,
          responseLimitBytes: MODEL_RESPONSE_LIMIT_BYTES
        }
      : {
          kind,
          provider: input.provider,
          model: input.model,
          mediaType,
          bytes: input.bytes,
          observedAt: input.observedAt
        };
  const code =
    kind === 'provider_rejection'
      ? 'provider_rejected_response'
      : kind === 'capability_shape_mismatch'
        ? 'capability_shape_mismatch'
        : kind === 'prefix_over_limit'
          ? 'response_too_large'
          : 'malformed_transport_payload';
  return {
    observation,
    events: [...(includeStart ? [startEvent(input, streaming)] : []), { type: 'error', code }]
  };
}

function assertExpectedModel(value: unknown, expected: string): void {
  if (value !== undefined && value !== null && (typeof value !== 'string' || value !== expected)) {
    throw new ProviderIdentityMismatch('provider returned a different model identity');
  }
}

function parseInput(value: unknown): ObservedToolCall['input'] {
  if (typeof value !== 'string') {
    assertBoundedJsonValue(value, 'provider tool input');
    canonicalJsonBytes(value);
    return { encoding: 'jcs_json', value };
  }
  try {
    const parsed = parseJsonStrict(value);
    canonicalJsonBytes(parsed);
    return { encoding: 'jcs_json', value: parsed };
  } catch {
    return { encoding: 'utf8_json_fragment', utf8: value };
  }
}

function parseOpenAiUsage(value: unknown): ObservedUsage | undefined {
  if (value === undefined || value === null) return undefined;
  if (!isRecord(value)) throw new TypeError('OpenAI usage must be an object');
  const inputTokens = safeCount(value.prompt_tokens);
  const outputTokens = safeCount(value.completion_tokens);
  if (inputTokens === null || outputTokens === null) throw new TypeError('OpenAI usage is partial or invalid');
  const promptDetails = value.prompt_tokens_details;
  const cacheReadTokens =
    promptDetails === undefined || promptDetails === null
      ? 0
      : isRecord(promptDetails) &&
          (promptDetails.cached_tokens === undefined || safeCount(promptDetails.cached_tokens) !== null)
        ? (safeCount(promptDetails.cached_tokens) ?? 0)
        : null;
  if (cacheReadTokens === null) throw new TypeError('OpenAI cached token usage is invalid');
  return { inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens: 0 };
}

type AnthropicUsageParts = {
  inputTokens?: number;
  outputTokens?: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
};

function mergeAnthropicUsage(value: unknown, previous?: AnthropicUsageParts): AnthropicUsageParts | undefined {
  if (value === undefined || value === null) return previous;
  if (!isRecord(value)) throw new TypeError('Anthropic usage must be an object');
  const read = (key: string): number | undefined => {
    if (!hasOwn(value, key)) return undefined;
    const count = safeCount(value[key]);
    if (count === null) throw new TypeError(`Anthropic ${key} is invalid`);
    return count;
  };
  const inputTokens = read('input_tokens');
  const outputTokens = read('output_tokens');
  const cacheReadTokens = read('cache_read_input_tokens');
  const cacheWriteTokens = read('cache_creation_input_tokens');
  return {
    ...previous,
    ...(inputTokens === undefined ? {} : { inputTokens }),
    ...(outputTokens === undefined ? {} : { outputTokens }),
    ...(cacheReadTokens === undefined ? {} : { cacheReadTokens }),
    ...(cacheWriteTokens === undefined ? {} : { cacheWriteTokens })
  };
}

function completeAnthropicUsage(value: AnthropicUsageParts | undefined): ObservedUsage | undefined {
  if (value === undefined) return undefined;
  if (value.inputTokens === undefined || value.outputTokens === undefined) {
    throw new TypeError('Anthropic usage is partial');
  }
  return {
    inputTokens: value.inputTokens,
    outputTokens: value.outputTokens,
    cacheReadTokens: value.cacheReadTokens ?? 0,
    cacheWriteTokens: value.cacheWriteTokens ?? 0
  };
}

function parseOllamaUsage(value: Record<string, unknown>, previous?: ObservedUsage): ObservedUsage | undefined {
  const hasInput = hasOwn(value, 'prompt_eval_count');
  const hasOutput = hasOwn(value, 'eval_count');
  if (!hasInput && !hasOutput) return previous;
  if (!hasInput || !hasOutput) throw new TypeError('Ollama usage is partial');
  const inputTokens = safeCount(value.prompt_eval_count);
  const outputTokens = safeCount(value.eval_count);
  if (inputTokens === null || outputTokens === null) throw new TypeError('Ollama usage is invalid');
  return { inputTokens, outputTokens, cacheReadTokens: 0, cacheWriteTokens: 0 };
}

function openAiStopReason(value: unknown): ProviderObservedStopReason {
  if (value === 'stop') return 'end';
  if (value === 'tool_calls' || value === 'function_call') return 'tool_calls';
  if (value === 'length' || value === 'max_tokens') return 'length';
  if (value === 'content_filter') return 'content_filter';
  return 'unknown';
}

function anthropicStopReason(value: unknown): ProviderObservedStopReason {
  if (value === 'end_turn' || value === 'stop_sequence') return 'end';
  if (value === 'tool_use') return 'tool_calls';
  if (value === 'max_tokens') return 'length';
  if (value === 'refusal') return 'content_filter';
  return 'unknown';
}

function ollamaStopReason(value: unknown, toolCallCount: number): ProviderObservedStopReason {
  if (toolCallCount > 0 && (value === undefined || value === null || value === 'stop' || value === 'tool_calls')) {
    return 'tool_calls';
  }
  if (value === 'stop' || value === 'end_turn') return 'end';
  if (value === 'length' || value === 'max_tokens') return 'length';
  if (value === 'content_filter') return 'content_filter';
  return 'unknown';
}

function fullResponseEvents(fields: DecodedFields): AgentModelStreamEvent[] {
  const events: AgentModelStreamEvent[] = [];
  if (fields.text.length > 0) events.push({ type: 'text_delta', text: fields.text });
  if (fields.reasoning !== undefined && fields.reasoning.length > 0) {
    events.push({ type: 'reasoning_delta', text: fields.reasoning });
  }
  for (const call of fields.toolCalls) {
    const index = call.wireIndex ?? events.length;
    events.push({
      type: 'tool_call_start',
      index,
      ...(call.wireCallId === undefined ? {} : { wireCallId: call.wireCallId }),
      ...(call.toolName === undefined ? {} : { toolName: call.toolName })
    });
    const utf8 =
      call.input.encoding === 'utf8_json_fragment'
        ? call.input.utf8
        : canonicalJsonBytes(call.input.value).toString('utf8');
    events.push({ type: 'tool_call_arguments_delta', index, utf8 });
    events.push({
      type: 'tool_call_complete',
      index,
      ...(call.wireCallId === undefined ? {} : { wireCallId: call.wireCallId }),
      ...(call.toolName === undefined ? {} : { toolName: call.toolName })
    });
  }
  if (fields.usage !== undefined) events.push({ type: 'usage', ...fields.usage });
  events.push({ type: 'end', stopReason: fields.stopReason });
  return events;
}

function parseOpenAiToolCalls(value: unknown): ObservedToolCall[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new TypeError('OpenAI tool_calls must be an array');
  return value.map((entry, index) => {
    if (!isRecord(entry)) throw new TypeError('OpenAI tool call must be an object');
    const fn = entry.function;
    if (!isRecord(fn)) throw new TypeError('OpenAI tool call function must be an object');
    return {
      wireIndex: index,
      ...(typeof entry.id === 'string' ? { wireCallId: entry.id } : {}),
      ...(typeof fn.name === 'string' ? { toolName: fn.name } : {}),
      input: parseInput(hasOwn(fn, 'arguments') ? fn.arguments : '')
    };
  });
}

function parseOpenAiJson(rootValue: unknown, expectedModel: string): ParsedProviderResponse {
  if (!isRecord(rootValue)) throw new TypeError('OpenAI response must be an object');
  if (hasOwn(rootValue, 'error')) throw new ProviderRejection('OpenAI returned an error response');
  assertExpectedModel(rootValue.model, expectedModel);
  if (!Array.isArray(rootValue.choices) || rootValue.choices.length !== 1) {
    throw new TypeError('OpenAI response must contain exactly one choice');
  }
  const choice = rootValue.choices[0];
  if (!isRecord(choice) || !isRecord(choice.message)) throw new TypeError('OpenAI choice message is invalid');
  if (choice.index !== undefined && choice.index !== 0) throw new TypeError('OpenAI choice index must be zero');
  const message = choice.message;
  const content = message.content === undefined || message.content === null ? '' : message.content;
  if (typeof content !== 'string') throw new TypeError('OpenAI message content must be a string or null');
  const hasRefusal = message.refusal !== undefined && message.refusal !== null;
  if (hasRefusal && typeof message.refusal !== 'string') {
    throw new TypeError('OpenAI message refusal must be a string or null');
  }
  const reasoningValue = message.reasoning_content ?? message.reasoning;
  if (reasoningValue !== undefined && reasoningValue !== null && typeof reasoningValue !== 'string') {
    throw new TypeError('OpenAI reasoning content must be a string or null');
  }
  const usage = parseOpenAiUsage(rootValue.usage);
  const fields: DecodedFields = {
    ...(typeof rootValue.id === 'string' ? { responseId: rootValue.id } : {}),
    stopReason: hasRefusal ? 'content_filter' : openAiStopReason(choice.finish_reason),
    text: content,
    ...(typeof reasoningValue === 'string' ? { reasoning: reasoningValue } : {}),
    toolCalls: parseOpenAiToolCalls(message.tool_calls),
    ...(usage === undefined ? {} : { usage })
  };
  return { fields, events: fullResponseEvents(fields), streaming: false };
}

type SseMessage = { event?: string; data: string };

function appendOptionalFragment(current: string | undefined, value: unknown, label: string): string | undefined {
  if (value === undefined || value === null) return current;
  if (typeof value !== 'string') throw new TypeError(`${label} fragment must be a string`);
  return `${current ?? ''}${value}`;
}

function createOpenAiStream(expectedModel: string): StreamParser<SseMessage> {
  let responseId: string | undefined;
  let text = '';
  let reasoning = '';
  let stopReason: ProviderObservedStopReason = 'unknown';
  let usage: ObservedUsage | undefined;
  const calls = new Map<number, MutableToolCall>();
  const events: AgentModelStreamEvent[] = [];
  let jsonMessageCount = 0;
  let sawDone = false;
  let sawStopReason = false;
  let sawUsage = false;
  let sawRefusal = false;

  return {
    push(message) {
      if (message.data === '[DONE]') {
        if (sawDone) throw new TypeError('OpenAI stream contains multiple terminal markers');
        sawDone = true;
        return events.splice(0);
      }
      if (sawDone) throw new TypeError('OpenAI stream contains data after its terminal marker');
      const rootValue = parseJsonStrict(message.data);
      if (!isRecord(rootValue)) throw new TypeError('OpenAI stream event must be an object');
      if (hasOwn(rootValue, 'error')) throw new ProviderRejection('OpenAI stream returned an error');
      jsonMessageCount += 1;
      assertExpectedModel(rootValue.model, expectedModel);
      if (typeof rootValue.id === 'string') {
        if (responseId !== undefined && rootValue.id !== responseId)
          throw new TypeError('OpenAI stream response id changed');
        responseId = rootValue.id;
      } else if (rootValue.id !== undefined && rootValue.id !== null) {
        throw new TypeError('OpenAI stream response id is invalid');
      }
      const eventUsage = parseOpenAiUsage(rootValue.usage);
      if (eventUsage !== undefined) {
        if (sawUsage) throw new TypeError('OpenAI stream contains multiple usage payloads');
        sawUsage = true;
        usage = eventUsage;
      }
      if (!Array.isArray(rootValue.choices)) throw new TypeError('OpenAI stream choices must be an array');
      if (rootValue.choices.length === 0) return events.splice(0);
      if (sawStopReason) throw new TypeError('OpenAI stream contains choices after its finish reason');
      if (rootValue.choices.length !== 1) throw new TypeError('OpenAI stream must contain at most one choice');
      const choice = rootValue.choices[0];
      if (!isRecord(choice)) throw new TypeError('OpenAI stream choice must be an object');
      if (choice.index !== undefined && choice.index !== 0)
        throw new TypeError('OpenAI stream choice index must be zero');
      if (!isRecord(choice.delta)) throw new TypeError('OpenAI stream delta must be an object');
      const delta = choice.delta;
      if (delta.refusal !== undefined && delta.refusal !== null) {
        if (typeof delta.refusal !== 'string') throw new TypeError('OpenAI refusal delta must be a string or null');
        sawRefusal = true;
      }
      if (delta.content !== undefined && delta.content !== null) {
        if (typeof delta.content !== 'string') throw new TypeError('OpenAI content delta must be a string');
        text += delta.content;
        events.push({ type: 'text_delta', text: delta.content });
      }
      const reasoningDelta = delta.reasoning_content ?? delta.reasoning;
      if (reasoningDelta !== undefined && reasoningDelta !== null) {
        if (typeof reasoningDelta !== 'string') throw new TypeError('OpenAI reasoning delta must be a string');
        reasoning += reasoningDelta;
        events.push({ type: 'reasoning_delta', text: reasoningDelta });
      }
      if (delta.tool_calls !== undefined && delta.tool_calls !== null) {
        if (!Array.isArray(delta.tool_calls)) throw new TypeError('OpenAI tool call delta must be an array');
        for (const entry of delta.tool_calls) {
          if (!isRecord(entry)) throw new TypeError('OpenAI tool call delta entry must be an object');
          const index = safeCount(entry.index);
          if (index === null) throw new TypeError('OpenAI streamed tool call index is required');
          let call = calls.get(index);
          if (call === undefined) {
            call = { wireIndex: index, argumentsUtf8: '' };
            calls.set(index, call);
            events.push({
              type: 'tool_call_start',
              index,
              ...(typeof entry.id === 'string' ? { wireCallId: entry.id } : {})
            });
          }
          call.wireCallId = appendOptionalFragment(call.wireCallId, entry.id, 'OpenAI call id');
          if (entry.function !== undefined && entry.function !== null) {
            if (!isRecord(entry.function)) throw new TypeError('OpenAI streamed function must be an object');
            call.toolName = appendOptionalFragment(call.toolName, entry.function.name, 'OpenAI tool name');
            if (entry.function.arguments !== undefined && entry.function.arguments !== null) {
              if (typeof entry.function.arguments !== 'string') {
                throw new TypeError('OpenAI argument delta must be a string');
              }
              call.argumentsUtf8 += entry.function.arguments;
              events.push({ type: 'tool_call_arguments_delta', index, utf8: entry.function.arguments });
            }
          }
        }
      }
      if (choice.finish_reason !== undefined && choice.finish_reason !== null) {
        if (sawStopReason) throw new TypeError('OpenAI stream contains multiple finish reasons');
        sawStopReason = true;
        stopReason = openAiStopReason(choice.finish_reason);
      }
      return events.splice(0);
    },
    finish() {
      if (jsonMessageCount === 0 || !sawDone || !sawStopReason) {
        throw new IncompleteResponse('OpenAI stream is incomplete');
      }
      if (sawRefusal) stopReason = 'content_filter';
      const toolCalls = [...calls.values()]
        .sort((left, right) => left.wireIndex - right.wireIndex)
        .map((call) => ({
          wireIndex: call.wireIndex,
          ...(call.wireCallId === undefined ? {} : { wireCallId: call.wireCallId }),
          ...(call.toolName === undefined ? {} : { toolName: call.toolName }),
          input: parseInput(call.argumentsUtf8)
        }));
      for (const call of toolCalls) {
        events.push({
          type: 'tool_call_complete',
          index: call.wireIndex!,
          ...(call.wireCallId === undefined ? {} : { wireCallId: call.wireCallId }),
          ...(call.toolName === undefined ? {} : { toolName: call.toolName })
        });
      }
      if (usage !== undefined) events.push({ type: 'usage', ...usage });
      events.push({ type: 'end', stopReason });
      return {
        fields: {
          ...(responseId === undefined ? {} : { responseId }),
          stopReason,
          text,
          ...(reasoning.length === 0 ? {} : { reasoning }),
          toolCalls,
          ...(usage === undefined ? {} : { usage })
        },
        events,
        streaming: true
      };
    }
  };
}

function parseAnthropicContent(value: unknown): Pick<DecodedFields, 'text' | 'reasoning' | 'toolCalls'> {
  if (!Array.isArray(value)) throw new TypeError('Anthropic content must be an array');
  let text = '';
  let reasoning = '';
  const toolCalls: ObservedToolCall[] = [];
  for (const block of value) {
    if (!isRecord(block) || typeof block.type !== 'string') throw new TypeError('Anthropic content block is invalid');
    if (block.type === 'text') {
      if (typeof block.text !== 'string') throw new TypeError('Anthropic text block is invalid');
      text += block.text;
    } else if (block.type === 'thinking') {
      if (typeof block.thinking !== 'string') throw new TypeError('Anthropic thinking block is invalid');
      reasoning += block.thinking;
    } else if (block.type === 'redacted_thinking') {
      if (typeof block.data !== 'string') throw new TypeError('Anthropic redacted thinking block is invalid');
    } else if (block.type === 'tool_use') {
      toolCalls.push({
        wireIndex: toolCalls.length,
        ...(typeof block.id === 'string' ? { wireCallId: block.id } : {}),
        ...(typeof block.name === 'string' ? { toolName: block.name } : {}),
        input: parseInput(hasOwn(block, 'input') ? block.input : '')
      });
    } else {
      throw new TypeError(`unsupported Anthropic content block ${block.type}`);
    }
  }
  return { text, ...(reasoning.length === 0 ? {} : { reasoning }), toolCalls };
}

function parseAnthropicJson(rootValue: unknown, expectedModel: string): ParsedProviderResponse {
  if (!isRecord(rootValue)) throw new TypeError('Anthropic response must be an object');
  if (rootValue.type === 'error' || hasOwn(rootValue, 'error'))
    throw new ProviderRejection('Anthropic returned an error');
  assertExpectedModel(rootValue.model, expectedModel);
  const content = parseAnthropicContent(rootValue.content);
  const continuation = (rootValue.content as Record<string, unknown>[]).filter(
    (block) => block.type === 'thinking' || block.type === 'redacted_thinking'
  );
  const usage = completeAnthropicUsage(mergeAnthropicUsage(rootValue.usage));
  const fields: DecodedFields = {
    ...(typeof rootValue.id === 'string' ? { responseId: rootValue.id } : {}),
    stopReason: anthropicStopReason(rootValue.stop_reason),
    ...(continuation.length
      ? { continuation: { provider: 'anthropic' as const, model: expectedModel, items: continuation } }
      : {}),
    ...content,
    ...(usage === undefined ? {} : { usage })
  };
  return { fields, events: fullResponseEvents(fields), streaming: false };
}

type AnthropicStreamBlock =
  | { kind: 'text'; text: string }
  | { kind: 'thinking'; text: string; signature: string }
  | { kind: 'redacted_thinking'; data: string }
  | {
      kind: 'tool';
      callIndex: number;
      wireCallId?: string;
      toolName?: string;
      initialInput?: unknown;
      argumentsUtf8: string;
    };

function createAnthropicStream(expectedModel: string): StreamParser<SseMessage> {
  let responseId: string | undefined;
  let stopReason: ProviderObservedStopReason = 'unknown';
  let usageParts: AnthropicUsageParts | undefined;
  let sawMessage = false;
  let sawMessageStop = false;
  let sawStopReason = false;
  let sawMessageDelta = false;
  const blocks = new Map<number, AnthropicStreamBlock>();
  const stoppedBlocks = new Set<number>();
  const events: AgentModelStreamEvent[] = [];
  let nextCallIndex = 0;

  return {
    push(message) {
      const rootValue = parseJsonStrict(message.data);
      if (!isRecord(rootValue) || typeof rootValue.type !== 'string') {
        throw new TypeError('Anthropic stream event is invalid');
      }
      if (message.event !== undefined && message.event !== rootValue.type) {
        throw new TypeError('Anthropic event name does not match its payload');
      }
      if (rootValue.type === 'error') throw new ProviderRejection('Anthropic stream returned an error');
      if (rootValue.type === 'ping') return events.splice(0);
      if (sawMessageStop) throw new TypeError('Anthropic stream contains events after message_stop');
      if (rootValue.type === 'message_start') {
        if (sawMessage || !isRecord(rootValue.message)) throw new TypeError('Anthropic message_start is invalid');
        sawMessage = true;
        assertExpectedModel(rootValue.message.model, expectedModel);
        if (typeof rootValue.message.id === 'string') responseId = rootValue.message.id;
        else if (rootValue.message.id !== undefined && rootValue.message.id !== null) {
          throw new TypeError('Anthropic response id is invalid');
        }
        usageParts = mergeAnthropicUsage(rootValue.message.usage, usageParts);
        return events.splice(0);
      }
      if (!sawMessage) throw new TypeError('Anthropic stream event precedes message_start');
      if (rootValue.type === 'content_block_start') {
        const index = safeCount(rootValue.index);
        if (index === null || index !== blocks.size || blocks.has(index) || !isRecord(rootValue.content_block)) {
          throw new TypeError('Anthropic content_block_start is invalid');
        }
        const block = rootValue.content_block;
        if (block.type === 'text') {
          const initial = block.text ?? '';
          if (typeof initial !== 'string') throw new TypeError('Anthropic initial text is invalid');
          blocks.set(index, { kind: 'text', text: initial });
          if (initial.length > 0) events.push({ type: 'text_delta', text: initial });
        } else if (block.type === 'thinking') {
          const initial = block.thinking ?? '';
          if (typeof initial !== 'string') throw new TypeError('Anthropic initial thinking is invalid');
          blocks.set(index, { kind: 'thinking', text: initial, signature: optionalString(block.signature) ?? '' });
          if (initial.length > 0) events.push({ type: 'reasoning_delta', text: initial });
        } else if (block.type === 'redacted_thinking') {
          if (typeof block.data !== 'string') throw new TypeError('invalid redacted thinking');
          blocks.set(index, { kind: 'redacted_thinking', data: block.data });
        } else if (block.type === 'tool_use') {
          if (hasOwn(block, 'input')) {
            const inputBytes = canonicalJsonBytes(block.input);
            if (inputBytes.toString('utf8') !== '{}') {
              throw new TypeError('Anthropic streamed tool input must start empty');
            }
          }
          const callIndex = nextCallIndex++;
          const toolBlock: AnthropicStreamBlock = {
            kind: 'tool',
            callIndex,
            ...(typeof block.id === 'string' ? { wireCallId: block.id } : {}),
            ...(typeof block.name === 'string' ? { toolName: block.name } : {}),
            ...(hasOwn(block, 'input') ? { initialInput: block.input } : {}),
            argumentsUtf8: ''
          };
          blocks.set(index, toolBlock);
          events.push({
            type: 'tool_call_start',
            index: callIndex,
            ...(toolBlock.wireCallId === undefined ? {} : { wireCallId: toolBlock.wireCallId }),
            ...(toolBlock.toolName === undefined ? {} : { toolName: toolBlock.toolName })
          });
        } else {
          throw new TypeError('unsupported Anthropic streamed content block');
        }
        return events.splice(0);
      }
      if (rootValue.type === 'content_block_delta') {
        const index = safeCount(rootValue.index);
        const block = index === null ? undefined : blocks.get(index);
        if (
          block === undefined ||
          stoppedBlocks.has(index!) ||
          !isRecord(rootValue.delta) ||
          typeof rootValue.delta.type !== 'string'
        ) {
          throw new TypeError('Anthropic content_block_delta is invalid');
        }
        const delta = rootValue.delta;
        if (delta.type === 'text_delta' && block.kind === 'text' && typeof delta.text === 'string') {
          block.text += delta.text;
          events.push({ type: 'text_delta', text: delta.text });
        } else if (delta.type === 'thinking_delta' && block.kind === 'thinking' && typeof delta.thinking === 'string') {
          block.text += delta.thinking;
          events.push({ type: 'reasoning_delta', text: delta.thinking });
        } else if (
          delta.type === 'input_json_delta' &&
          block.kind === 'tool' &&
          typeof delta.partial_json === 'string'
        ) {
          block.argumentsUtf8 += delta.partial_json;
          events.push({ type: 'tool_call_arguments_delta', index: block.callIndex, utf8: delta.partial_json });
        } else if (
          delta.type !== 'signature_delta' ||
          block.kind !== 'thinking' ||
          typeof delta.signature !== 'string'
        ) {
          throw new TypeError('Anthropic delta does not match its content block');
        } else {
          block.signature += delta.signature;
        }
        return events.splice(0);
      }
      if (rootValue.type === 'content_block_stop') {
        const index = safeCount(rootValue.index);
        const block = index === null ? undefined : blocks.get(index);
        if (block === undefined) throw new TypeError('Anthropic content_block_stop has no matching block');
        if (stoppedBlocks.has(index!)) throw new TypeError('Anthropic content block stopped more than once');
        stoppedBlocks.add(index!);
        if (block.kind === 'tool') {
          events.push({
            type: 'tool_call_complete',
            index: block.callIndex,
            ...(block.wireCallId === undefined ? {} : { wireCallId: block.wireCallId }),
            ...(block.toolName === undefined ? {} : { toolName: block.toolName })
          });
        }
        return events.splice(0);
      }
      if (rootValue.type === 'message_delta') {
        if (sawMessageDelta || stoppedBlocks.size !== blocks.size || !isRecord(rootValue.delta)) {
          throw new TypeError('Anthropic message_delta is invalid');
        }
        sawMessageDelta = true;
        if (rootValue.delta.stop_reason !== undefined && rootValue.delta.stop_reason !== null) {
          if (sawStopReason) throw new TypeError('Anthropic stream contains multiple stop reasons');
          sawStopReason = true;
          stopReason = anthropicStopReason(rootValue.delta.stop_reason);
        }
        usageParts = mergeAnthropicUsage(rootValue.usage, usageParts);
        return events.splice(0);
      }
      if (rootValue.type !== 'message_stop') throw new TypeError(`unsupported Anthropic event ${rootValue.type}`);
      if (sawMessageStop) throw new TypeError('Anthropic stream stopped more than once');
      if (!sawMessageDelta || !sawStopReason || stoppedBlocks.size !== blocks.size) {
        throw new TypeError('Anthropic message_stop arrived before a complete message delta');
      }
      sawMessageStop = true;
      return events.splice(0);
    },
    finish() {
      if (!sawMessage || !sawMessageStop || !sawMessageDelta || stoppedBlocks.size !== blocks.size) {
        throw new IncompleteResponse('Anthropic stream is incomplete');
      }
      const usage = completeAnthropicUsage(usageParts);

      let text = '';
      let reasoning = '';
      const toolCalls: ObservedToolCall[] = [];
      for (const [, block] of [...blocks.entries()].sort(([left], [right]) => left - right)) {
        if (block.kind === 'text') text += block.text;
        else if (block.kind === 'thinking') reasoning += block.text;
        else if (block.kind === 'tool') {
          const input =
            block.argumentsUtf8.length > 0 ? parseInput(block.argumentsUtf8) : parseInput(block.initialInput ?? '');
          toolCalls.push({
            wireIndex: block.callIndex,
            ...(block.wireCallId === undefined ? {} : { wireCallId: block.wireCallId }),
            ...(block.toolName === undefined ? {} : { toolName: block.toolName }),
            input
          });
        }
      }
      if (usage !== undefined) events.push({ type: 'usage', ...usage });
      events.push({ type: 'end', stopReason });
      return {
        fields: {
          ...(responseId === undefined ? {} : { responseId }),
          stopReason,
          text,
          ...(reasoning.length === 0 ? {} : { reasoning }),
          toolCalls,
          ...([...blocks.values()].some((block) => block.kind === 'thinking' || block.kind === 'redacted_thinking')
            ? {
                continuation: {
                  provider: 'anthropic' as const,
                  model: expectedModel,
                  items: [...blocks.values()].flatMap((block): unknown[] =>
                    block.kind === 'thinking'
                      ? [{ type: 'thinking', thinking: block.text, signature: block.signature }]
                      : block.kind === 'redacted_thinking'
                        ? [{ type: 'redacted_thinking', data: block.data }]
                        : []
                  )
                }
              }
            : {}),
          ...(usage === undefined ? {} : { usage })
        },
        events,
        streaming: true
      };
    }
  };
}

function parseOllamaMessage(
  value: unknown,
  startingIndex = 0
): Pick<DecodedFields, 'text' | 'reasoning' | 'toolCalls'> {
  if (!isRecord(value)) throw new TypeError('Ollama message must be an object');
  const content = value.content ?? '';
  if (typeof content !== 'string') throw new TypeError('Ollama message content must be a string');
  const thinking = value.thinking;
  if (thinking !== undefined && thinking !== null && typeof thinking !== 'string') {
    throw new TypeError('Ollama thinking must be a string');
  }
  const rawCalls = value.tool_calls ?? [];
  if (!Array.isArray(rawCalls)) throw new TypeError('Ollama tool_calls must be an array');
  const toolCalls = rawCalls.map((entry, offset) => {
    if (!isRecord(entry) || !isRecord(entry.function)) throw new TypeError('Ollama tool call is invalid');
    return {
      wireIndex: startingIndex + offset,
      ...(typeof entry.function.name === 'string' ? { toolName: entry.function.name } : {}),
      input: parseInput(hasOwn(entry.function, 'arguments') ? entry.function.arguments : '')
    };
  });
  return {
    text: content,
    ...(typeof thinking === 'string' && thinking.length > 0 ? { reasoning: thinking } : {}),
    toolCalls
  };
}

function parseOllamaJson(rootValue: unknown, expectedModel: string): ParsedProviderResponse {
  if (!isRecord(rootValue)) throw new TypeError('Ollama response must be an object');
  if (hasOwn(rootValue, 'error')) throw new ProviderRejection('Ollama returned an error');
  assertExpectedModel(rootValue.model, expectedModel);
  if (rootValue.done !== true) throw new TypeError('Ollama non-streaming response is incomplete');
  const message = parseOllamaMessage(rootValue.message);
  const usage = parseOllamaUsage(rootValue);
  const fields: DecodedFields = {
    stopReason: ollamaStopReason(rootValue.done_reason, message.toolCalls.length),
    ...message,
    ...(usage === undefined ? {} : { usage })
  };
  return { fields, events: fullResponseEvents(fields), streaming: false };
}

function createOllamaStream(expectedModel: string): StreamParser<unknown> {
  let text = '';
  let reasoning = '';
  let stopReason: ProviderObservedStopReason = 'unknown';
  let usage: ObservedUsage | undefined;
  let sawDone = false;
  const toolCalls: ObservedToolCall[] = [];
  const events: AgentModelStreamEvent[] = [];
  return {
    push(rootValue) {
      if (!isRecord(rootValue)) throw new TypeError('Ollama stream entry must be an object');
      if (sawDone) throw new TypeError('Ollama stream contains data after its terminal entry');
      if (hasOwn(rootValue, 'error')) throw new ProviderRejection('Ollama stream returned an error');
      assertExpectedModel(rootValue.model, expectedModel);
      const message = parseOllamaMessage(rootValue.message, toolCalls.length);
      text += message.text;
      if (message.text.length > 0) events.push({ type: 'text_delta', text: message.text });
      if (message.reasoning !== undefined) {
        reasoning += message.reasoning;
        events.push({ type: 'reasoning_delta', text: message.reasoning });
      }
      for (const call of message.toolCalls) {
        toolCalls.push(call);
        const index = call.wireIndex!;
        events.push({
          type: 'tool_call_start',
          index,
          ...(call.toolName === undefined ? {} : { toolName: call.toolName })
        });
        const utf8 =
          call.input.encoding === 'utf8_json_fragment'
            ? call.input.utf8
            : canonicalJsonBytes(call.input.value).toString('utf8');
        events.push({ type: 'tool_call_arguments_delta', index, utf8 });
        events.push({
          type: 'tool_call_complete',
          index,
          ...(call.toolName === undefined ? {} : { toolName: call.toolName })
        });
      }
      usage = parseOllamaUsage(rootValue, usage);
      if (rootValue.done === true) {
        sawDone = true;
        stopReason = ollamaStopReason(rootValue.done_reason, toolCalls.length);
      } else if (rootValue.done !== undefined && rootValue.done !== false) {
        throw new TypeError('Ollama done flag is invalid');
      }
      return events.splice(0);
    },
    finish() {
      if (!sawDone) throw new IncompleteResponse('Ollama stream is missing its terminal entry');
      if (usage !== undefined) events.push({ type: 'usage', ...usage });
      events.push({ type: 'end', stopReason });
      return {
        fields: {
          stopReason,
          text,
          ...(reasoning.length === 0 ? {} : { reasoning }),
          toolCalls,
          ...(usage === undefined ? {} : { usage })
        },
        events,
        streaming: true
      };
    }
  };
}

function parseResponsesJson(value: unknown, expectedModel: string): ParsedProviderResponse {
  if (!isRecord(value)) throw new TypeError('Responses payload must be an object');
  if (value.error != null || value.status === 'failed') throw new ProviderRejection('Responses request failed');
  assertExpectedModel(value.model, expectedModel);
  if (!Array.isArray(value.output)) throw new TypeError('Responses output must be an array');
  let text = '';
  let refused = false;
  const toolCalls: ObservedToolCall[] = [];
  const reasoning: unknown[] = [];
  for (const item of value.output) {
    if (!isRecord(item)) throw new TypeError('invalid Responses output item');
    if (item.type === 'reasoning') {
      reasoning.push(item);
    } else if (item.type === 'function_call') {
      toolCalls.push({
        wireIndex: toolCalls.length,
        ...(typeof item.call_id === 'string' ? { wireCallId: item.call_id } : {}),
        ...(typeof item.name === 'string' ? { toolName: item.name } : {}),
        input: parseInput(item.arguments ?? '')
      });
    } else if (item.type === 'message') {
      if (!Array.isArray(item.content) || (item.role !== undefined && item.role !== 'assistant')) {
        throw new TypeError('invalid Responses message');
      }
      for (const block of item.content) {
        if (!isRecord(block)) throw new TypeError('invalid Responses content');
        if (block.type === 'output_text' && typeof block.text === 'string') text += block.text;
        else if (block.type === 'refusal' && typeof block.refusal === 'string') refused = true;
        else throw new TypeError('unsupported Responses message content');
      }
    } else throw new TypeError('unsupported Responses output item');
  }
  let stopReason: ProviderObservedStopReason = 'unknown';
  if (value.status === 'completed') stopReason = toolCalls.length ? 'tool_calls' : 'end';
  if (value.status === 'incomplete' && isRecord(value.incomplete_details)) {
    if (value.incomplete_details.reason === 'max_output_tokens') stopReason = 'length';
    if (value.incomplete_details.reason === 'content_filter') stopReason = 'content_filter';
  }
  if (refused) stopReason = 'content_filter';
  let usage: ObservedUsage | undefined;
  if (value.usage != null) {
    if (!isRecord(value.usage)) throw new TypeError('invalid Responses usage');
    usage = parseOpenAiUsage({
      prompt_tokens: value.usage.input_tokens,
      completion_tokens: value.usage.output_tokens,
      prompt_tokens_details: value.usage.input_tokens_details
    });
  }
  const fields: DecodedFields = {
    ...(typeof value.id === 'string' ? { responseId: value.id } : {}),
    stopReason,
    text,
    toolCalls,
    ...(usage === undefined ? {} : { usage }),
    ...(reasoning.length ? { continuation: { provider: 'openai', model: expectedModel, items: reasoning } } : {})
  };
  return { fields, events: fullResponseEvents(fields), streaming: false };
}

function createResponsesStream(expectedModel: string): StreamParser<SseMessage> {
  let responseId: string | undefined;
  let completed: ParsedProviderResponse | undefined;
  const items = new Map<number, Record<string, unknown>>();
  const doneItems = new Set<number>();
  const calls = new Map<number, number>();
  const argumentsByItem = new Map<number, string>();
  let text = '';
  const assertItemIdentity = (prior: Record<string, unknown>, next: unknown): void => {
    if (
      !isRecord(next) ||
      ['id', 'type', 'call_id', 'name'].some((key) => prior[key] !== undefined && prior[key] !== next[key])
    )
      throw new TypeError('Responses item identity changed');
  };
  return {
    push(message) {
      if (completed) throw new TypeError('Responses event follows terminal response');
      const event = parseJsonStrict(message.data);
      if (!isRecord(event) || typeof event.type !== 'string') throw new TypeError('invalid Responses event');
      if (message.event !== undefined && message.event !== event.type)
        throw new TypeError('Responses event name mismatch');
      const type = event.type;
      if (type === 'error' || type === 'response.failed') throw new ProviderRejection('Responses stream failed');
      if (isRecord(event.response)) {
        assertExpectedModel(event.response.model, expectedModel);
        if (typeof event.response.id !== 'string') throw new TypeError('Responses response id missing');
        if (responseId !== undefined && responseId !== event.response.id) throw new TypeError('Responses id changed');
        responseId = event.response.id;
      }
      if (type === 'response.created' || type === 'response.in_progress') return [];
      if (type === 'response.completed' || type === 'response.incomplete') {
        completed = parseResponsesJson(event.response, expectedModel);
        const output = (event.response as { output: unknown[] }).output;
        for (const [index, item] of items) assertItemIdentity(item, output[index]);
        if (text && completed.fields.text !== text)
          throw new TypeError('Responses text disagrees with terminal response');
        for (const [index, args] of argumentsByItem) {
          const item = (event.response as { output: Record<string, unknown>[] }).output[index];
          if (item?.arguments !== args) throw new TypeError('Responses arguments disagree with terminal response');
        }
        return [];
      }
      const index = safeCount(event.output_index);
      if (type === 'response.output_item.added') {
        if (index === null || index !== items.size || !isRecord(event.item))
          throw new TypeError('invalid Responses item start');
        if (!['message', 'function_call', 'reasoning'].includes(String(event.item.type)))
          throw new TypeError('unsupported Responses item');
        items.set(index, event.item);
        if (event.item.type === 'function_call') {
          const callIndex = calls.size;
          calls.set(index, callIndex);
          return [
            {
              type: 'tool_call_start',
              index: callIndex,
              ...(typeof event.item.call_id === 'string' ? { wireCallId: event.item.call_id } : {}),
              ...(typeof event.item.name === 'string' ? { toolName: event.item.name } : {})
            }
          ];
        }
        return [];
      }
      if (type === 'response.output_item.done') {
        if (index === null || !isRecord(event.item) || !items.has(index) || doneItems.has(index))
          throw new TypeError('invalid Responses item end');
        const prior = items.get(index)!;
        assertItemIdentity(prior, event.item);
        if (argumentsByItem.has(index) && event.item.arguments !== argumentsByItem.get(index)) {
          throw new TypeError('Responses arguments disagree with completed item');
        }
        items.set(index, event.item);
        doneItems.add(index);
        return [];
      }
      if (type === 'response.output_text.delta') {
        if (
          index === null ||
          items.get(index)?.type !== 'message' ||
          doneItems.has(index) ||
          typeof event.delta !== 'string'
        )
          throw new TypeError('invalid text delta');
        if (event.item_id !== undefined && event.item_id !== items.get(index)?.id)
          throw new TypeError('text delta identity changed');
        text += event.delta;
        return [{ type: 'text_delta', text: event.delta }];
      }
      if (type === 'response.function_call_arguments.delta') {
        if (index === null || !calls.has(index) || doneItems.has(index) || typeof event.delta !== 'string')
          throw new TypeError('invalid argument delta');
        if (event.item_id !== undefined && event.item_id !== items.get(index)?.id)
          throw new TypeError('argument delta identity changed');
        argumentsByItem.set(index, (argumentsByItem.get(index) ?? '') + event.delta);
        return [{ type: 'tool_call_arguments_delta', index: calls.get(index)!, utf8: event.delta }];
      }
      if (type === 'response.reasoning_summary_text.delta' || type === 'response.reasoning_text.delta') {
        if (
          index === null ||
          items.get(index)?.type !== 'reasoning' ||
          doneItems.has(index) ||
          typeof event.delta !== 'string'
        )
          throw new TypeError('invalid reasoning delta');
        return [{ type: 'reasoning_delta', text: event.delta }];
      }
      if (
        [
          'response.content_part.added',
          'response.content_part.done',
          'response.output_text.done',
          'response.function_call_arguments.done',
          'response.reasoning_summary_part.added',
          'response.reasoning_summary_part.done',
          'response.reasoning_summary_text.done',
          'response.reasoning_text.done',
          'response.refusal.delta',
          'response.refusal.done'
        ].includes(type)
      )
        return [];
      throw new TypeError('unsupported Responses event');
    },
    finish() {
      if (!completed) throw new IncompleteResponse('Responses stream ended before terminal response');
      const streamedArguments = new Set([...argumentsByItem.keys()].map((index) => calls.get(index)!));
      return {
        ...completed,
        streaming: true,
        events: completed.events.filter(
          (event) =>
            event.type === 'tool_call_complete' ||
            event.type === 'usage' ||
            event.type === 'end' ||
            (event.type === 'text_delta' && text.length === 0) ||
            (event.type === 'tool_call_start' && event.index >= calls.size) ||
            (event.type === 'tool_call_arguments_delta' && !streamedArguments.has(event.index))
        )
      };
    }
  };
}

export type ProviderResponseHead = Omit<ObserveProviderResponseInput, 'bytes' | 'observedAt'>;
export type ProviderResponseObserver = {
  /** Capture and parse bytes incrementally. Returned events are non-authoritative UI observations. */
  push(bytes: Uint8Array): AgentModelStreamEvent[];
  /** Stop reading when true: only the exact limit+1 prefix is retained. */
  readonly overLimit: boolean;
  finish(observedAt: string, aborted?: boolean): ObservedProviderResponse;
};

export function createProviderResponseObserver(head: ProviderResponseHead): ProviderResponseObserver {
  const input = { ...head };
  if (!Number.isSafeInteger(input.status) || input.status < 100 || input.status > 599 || !input.model) {
    throw new TypeError('invalid provider response head');
  }
  const mediaType = normalizeMediaType(input.mediaType);
  const streaming = mediaType === 'text/event-stream' || mediaType === 'application/x-ndjson';
  // Strip only the wire-leading BOM from decoded text; captured bytes remain unchanged.
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });
  let captured = Buffer.allocUnsafe(4096);
  let length = 0;
  let pending = '';
  let scanOffset = 0;
  let eventName: string | undefined;
  let data: string[] = [];
  let closed = false;
  let started = false;
  let error: 'malformed' | 'capability_shape_mismatch' | 'provider_rejection' | undefined =
    input.status < 200 || input.status >= 300 ? 'provider_rejection' : undefined;
  let parser: StreamParser<SseMessage> | undefined;
  let ndjson: StreamParser<unknown> | undefined;
  if (mediaType === 'text/event-stream' && input.provider !== 'ollama') {
    parser =
      input.provider === 'openai'
        ? createResponsesStream(input.model)
        : input.provider === 'anthropic'
          ? createAnthropicStream(input.model)
          : createOpenAiStream(input.model);
  } else if (mediaType === 'application/x-ndjson' && input.provider === 'ollama') {
    ndjson = createOllamaStream(input.model);
  } else if (mediaType !== 'application/json') error = 'malformed';
  const classify = (caught: unknown) => {
    error =
      caught instanceof ProviderRejection
        ? 'provider_rejection'
        : caught instanceof ProviderIdentityMismatch
          ? 'capability_shape_mismatch'
          : 'malformed';
  };
  const drain = (last: boolean): AgentModelStreamEvent[] => {
    const events: AgentModelStreamEvent[] = [];
    const dispatch = () => {
      if (data.length)
        events.push(
          ...parser!.push({ ...(eventName === undefined ? {} : { event: eventName }), data: data.join('\n') })
        );
      data = [];
      eventName = undefined;
    };
    const line = (value: string) => {
      if (ndjson) {
        if (value.trim()) events.push(...ndjson.push(parseJsonStrict(value)));
        return;
      }
      if (value === '') {
        dispatch();
        return;
      }
      if (value.startsWith(':')) return;
      const colon = value.indexOf(':');
      const field = colon === -1 ? value : value.slice(0, colon);
      const raw = colon === -1 ? '' : value.slice(colon + 1);
      const content = raw.startsWith(' ') ? raw.slice(1) : raw;
      if (field === 'data') data.push(content);
      else if (field === 'event') eventName = content;
    };
    while (true) {
      const match = /[\r\n]/u.exec(pending.slice(scanOffset));
      if (!match) {
        scanOffset = pending.length;
        break;
      }
      const position = scanOffset + match.index;
      if (!last && match[0] === '\r' && position === pending.length - 1) {
        scanOffset = position;
        break;
      }
      const count = pending.slice(position, position + 2) === '\r\n' ? 2 : 1;
      line(pending.slice(0, position));
      pending = pending.slice(position + count);
      scanOffset = 0;
    }
    if (last) {
      if (pending.length) line(pending);
      pending = '';
      if (parser) dispatch();
    }
    return events;
  };
  return {
    get overLimit() {
      return length > MODEL_RESPONSE_LIMIT_BYTES;
    },
    push(bytes) {
      if (closed) throw new TypeError('response observer is closed');
      if (bytes.byteLength === 0 || length > MODEL_RESPONSE_LIMIT_BYTES) return [];
      const count = Math.min(bytes.byteLength, MODEL_RESPONSE_LIMIT_BYTES + 1 - length);
      if (length + count > captured.byteLength) {
        const grown = Buffer.allocUnsafe(
          Math.min(MODEL_RESPONSE_LIMIT_BYTES + 1, Math.max(length + count, captured.byteLength * 2))
        );
        captured.copy(grown, 0, 0, length);
        captured = grown;
      }
      captured.set(bytes.subarray(0, count), length);
      const retained = captured.subarray(length, length + count);
      length += count;
      const events: AgentModelStreamEvent[] = started
        ? []
        : [startEvent({ ...input, bytes: retained, observedAt: '' }, streaming)];
      started = true;
      if (length > MODEL_RESPONSE_LIMIT_BYTES || error !== undefined) return events;
      try {
        pending += decoder.decode(retained, { stream: true });
        if (streaming) events.push(...drain(false));
      } catch (caught) {
        classify(caught);
      }
      return events;
    },
    finish(observedAt, aborted = false) {
      if (closed) throw new TypeError('response observer is closed');
      closed = true;
      const bytes = captured.subarray(0, length);
      const full = { ...input, bytes, observedAt };
      if (length > MODEL_RESPONSE_LIMIT_BYTES)
        return failure(full, mediaType, 'prefix_over_limit', streaming, !started);
      if (error !== undefined) return failure(full, mediaType, error, streaming, !started);
      let decodedUtf8 = false;
      let decodedWire = false;
      try {
        const trailing = decoder.decode();
        decodedUtf8 = true;
        let parsed: ParsedProviderResponse;
        let events: AgentModelStreamEvent[] = [];
        if (streaming) {
          pending += trailing;
          // An abort must not interpret a partial SSE record as a completed observation.
          events = aborted ? [] : drain(true);
          parsed = (parser ?? ndjson)!.finish();
        } else {
          const root = parseJsonStrict(pending + trailing);
          decodedWire = true;
          parsed =
            input.provider === 'openai'
              ? parseResponsesJson(root, input.model)
              : input.provider === 'anthropic'
                ? parseAnthropicJson(root, input.model)
                : input.provider === 'ollama'
                  ? parseOllamaJson(root, input.model)
                  : parseOpenAiJson(root, input.model);
        }
        return {
          observation: {
            kind: 'decoded',
            provider: input.provider,
            model: input.model,
            mediaType,
            bytes,
            observedAt,
            ...parsed.fields
          },
          events: [...(!started ? [startEvent(full, streaming)] : []), ...events, ...parsed.events]
        };
      } catch (caught) {
        if (aborted && (!decodedUtf8 || caught instanceof IncompleteResponse || (!streaming && !decodedWire))) {
          return {
            observation: { ...full, mediaType, kind: 'decoded', stopReason: 'cancelled', text: '', toolCalls: [] },
            events: [...(!started ? [startEvent(full, streaming)] : []), { type: 'end', stopReason: 'cancelled' }]
          };
        }
        classify(caught);
        return failure(full, mediaType, error!, streaming, !started);
      }
    }
  };
}

/** Buffered callers and fixtures use exactly the same incremental implementation. */
export function observeProviderResponse(input: ObserveProviderResponseInput): ObservedProviderResponse {
  const observer = createProviderResponseObserver(input);
  const events = observer.push(input.bytes);
  const result = observer.finish(input.observedAt);
  return { ...result, events: [...events, ...result.events.filter((event) => event.type !== 'start')] };
}
