import { canonicalJsonBytes } from '../kernel/canonical.js';
import { assertBoundedJsonValue, parseJsonStrict } from '../kernel/json.js';
import type { ProviderName } from '../kernel/types.js';
import {
  CONSTRAINED_MODEL_TURN_FORMAT,
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

export { CONSTRAINED_MODEL_TURN_FORMAT } from '../protocol/agent-ir.js';

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

const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const OPENAI_FAMILY = new Set<ProviderName>(['openai', 'openrouter', 'openai-compatible', 'zhipu']);

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOwn(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}

function safeCount(value: unknown): number | null {
  return Number.isSafeInteger(value) && (value as number) >= 0 ? (value as number) : null;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function decodeUtf8(bytes: Uint8Array): string {
  return UTF8_DECODER.decode(bytes);
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
  priorEvents: AgentModelStreamEvent[] = []
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
    events: [startEvent(input, streaming), ...priorEvents, { type: 'error', code }]
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
      : isRecord(promptDetails) && (promptDetails.cached_tokens === undefined || safeCount(promptDetails.cached_tokens) !== null)
        ? safeCount(promptDetails.cached_tokens) ?? 0
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
    const utf8 = call.input.encoding === 'utf8_json_fragment' ? call.input.utf8 : canonicalJsonBytes(call.input.value).toString('utf8');
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

function parseSse(source: string): SseMessage[] {
  const messages: SseMessage[] = [];
  let event: string | undefined;
  let data: string[] = [];
  const flush = (): void => {
    if (data.length > 0) messages.push({ ...(event === undefined ? {} : { event }), data: data.join('\n') });
    event = undefined;
    data = [];
  };
  for (const line of source.split(/\r\n|\r|\n/u)) {
    if (line.length === 0) {
      flush();
      continue;
    }
    if (line.startsWith(':')) continue;
    const colon = line.indexOf(':');
    const field = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') event = value;
    else if (field === 'data') data.push(value);
  }
  flush();
  return messages;
}

function appendOptionalFragment(current: string | undefined, value: unknown, label: string): string | undefined {
  if (value === undefined || value === null) return current;
  if (typeof value !== 'string') throw new TypeError(`${label} fragment must be a string`);
  return `${current ?? ''}${value}`;
}

function parseOpenAiStream(source: string, expectedModel: string): ParsedProviderResponse {
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

  for (const message of parseSse(source)) {
    if (message.data === '[DONE]') {
      if (sawDone) throw new TypeError('OpenAI stream contains multiple terminal markers');
      sawDone = true;
      continue;
    }
    if (sawDone) throw new TypeError('OpenAI stream contains data after its terminal marker');
    const rootValue = parseJsonStrict(message.data);
    if (!isRecord(rootValue)) throw new TypeError('OpenAI stream event must be an object');
    if (hasOwn(rootValue, 'error')) throw new ProviderRejection('OpenAI stream returned an error');
    jsonMessageCount += 1;
    assertExpectedModel(rootValue.model, expectedModel);
    if (typeof rootValue.id === 'string') {
      if (responseId !== undefined && rootValue.id !== responseId) throw new TypeError('OpenAI stream response id changed');
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
    if (rootValue.choices.length === 0) continue;
    if (sawStopReason) throw new TypeError('OpenAI stream contains choices after its finish reason');
    if (rootValue.choices.length !== 1) throw new TypeError('OpenAI stream must contain at most one choice');
    const choice = rootValue.choices[0];
    if (!isRecord(choice)) throw new TypeError('OpenAI stream choice must be an object');
    if (choice.index !== undefined && choice.index !== 0) throw new TypeError('OpenAI stream choice index must be zero');
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
  }
  if (jsonMessageCount === 0 || !sawDone || !sawStopReason) {
    throw new TypeError('OpenAI stream is incomplete');
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
  if (rootValue.type === 'error' || hasOwn(rootValue, 'error')) throw new ProviderRejection('Anthropic returned an error');
  assertExpectedModel(rootValue.model, expectedModel);
  const content = parseAnthropicContent(rootValue.content);
  const usage = completeAnthropicUsage(mergeAnthropicUsage(rootValue.usage));
  const fields: DecodedFields = {
    ...(typeof rootValue.id === 'string' ? { responseId: rootValue.id } : {}),
    stopReason: anthropicStopReason(rootValue.stop_reason),
    ...content,
    ...(usage === undefined ? {} : { usage })
  };
  return { fields, events: fullResponseEvents(fields), streaming: false };
}

type AnthropicStreamBlock =
  | { kind: 'text'; text: string }
  | { kind: 'thinking'; text: string }
  | { kind: 'redacted_thinking' }
  | { kind: 'tool'; callIndex: number; wireCallId?: string; toolName?: string; initialInput?: unknown; argumentsUtf8: string };

function parseAnthropicStream(source: string, expectedModel: string): ParsedProviderResponse {
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

  for (const message of parseSse(source)) {
    const rootValue = parseJsonStrict(message.data);
    if (!isRecord(rootValue) || typeof rootValue.type !== 'string') {
      throw new TypeError('Anthropic stream event is invalid');
    }
    if (message.event !== undefined && message.event !== rootValue.type) {
      throw new TypeError('Anthropic event name does not match its payload');
    }
    if (rootValue.type === 'error') throw new ProviderRejection('Anthropic stream returned an error');
    if (rootValue.type === 'ping') continue;
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
      continue;
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
        blocks.set(index, { kind: 'thinking', text: initial });
        if (initial.length > 0) events.push({ type: 'reasoning_delta', text: initial });
      } else if (block.type === 'redacted_thinking') {
        blocks.set(index, { kind: 'redacted_thinking' });
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
      continue;
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
      } else if (delta.type === 'input_json_delta' && block.kind === 'tool' && typeof delta.partial_json === 'string') {
        block.argumentsUtf8 += delta.partial_json;
        events.push({ type: 'tool_call_arguments_delta', index: block.callIndex, utf8: delta.partial_json });
      } else if (
        delta.type !== 'signature_delta' ||
        block.kind !== 'thinking' ||
        typeof delta.signature !== 'string'
      ) {
        throw new TypeError('Anthropic delta does not match its content block');
      }
      continue;
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
      continue;
    }
    if (rootValue.type === 'message_delta') {
      if (
        sawMessageDelta ||
        stoppedBlocks.size !== blocks.size ||
        !isRecord(rootValue.delta)
      ) {
        throw new TypeError('Anthropic message_delta is invalid');
      }
      sawMessageDelta = true;
      if (rootValue.delta.stop_reason !== undefined && rootValue.delta.stop_reason !== null) {
        if (sawStopReason) throw new TypeError('Anthropic stream contains multiple stop reasons');
        sawStopReason = true;
        stopReason = anthropicStopReason(rootValue.delta.stop_reason);
      }
      usageParts = mergeAnthropicUsage(rootValue.usage, usageParts);
      continue;
    }
    if (rootValue.type !== 'message_stop') throw new TypeError(`unsupported Anthropic event ${rootValue.type}`);
    if (sawMessageStop) throw new TypeError('Anthropic stream stopped more than once');
    if (!sawMessageDelta || !sawStopReason || stoppedBlocks.size !== blocks.size) {
      throw new TypeError('Anthropic message_stop arrived before a complete message delta');
    }
    sawMessageStop = true;
  }
  if (!sawMessage || !sawMessageStop || !sawMessageDelta || stoppedBlocks.size !== blocks.size) {
    throw new TypeError('Anthropic stream is incomplete');
  }
  const usage = completeAnthropicUsage(usageParts);

  let text = '';
  let reasoning = '';
  const toolCalls: ObservedToolCall[] = [];
  for (const [, block] of [...blocks.entries()].sort(([left], [right]) => left - right)) {
    if (block.kind === 'text') text += block.text;
    else if (block.kind === 'thinking') reasoning += block.text;
    else if (block.kind === 'tool') {
      const input = block.argumentsUtf8.length > 0 ? parseInput(block.argumentsUtf8) : parseInput(block.initialInput ?? '');
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
      ...(usage === undefined ? {} : { usage })
    },
    events,
    streaming: true
  };
}

function parseOllamaMessage(value: unknown, startingIndex = 0): Pick<DecodedFields, 'text' | 'reasoning' | 'toolCalls'> {
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

function parseNdjson(source: string): unknown[] {
  const lines = source.split(/\r\n|\r|\n/u).filter((line) => line.length > 0);
  if (lines.length === 0) throw new TypeError('NDJSON response is empty');
  return lines.map((line) => parseJsonStrict(line));
}

function parseOllamaStream(source: string, expectedModel: string): ParsedProviderResponse {
  let text = '';
  let reasoning = '';
  let stopReason: ProviderObservedStopReason = 'unknown';
  let usage: ObservedUsage | undefined;
  let sawDone = false;
  const toolCalls: ObservedToolCall[] = [];
  const events: AgentModelStreamEvent[] = [];
  for (const rootValue of parseNdjson(source)) {
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
      events.push({ type: 'tool_call_start', index, ...(call.toolName === undefined ? {} : { toolName: call.toolName }) });
      const utf8 = call.input.encoding === 'utf8_json_fragment' ? call.input.utf8 : canonicalJsonBytes(call.input.value).toString('utf8');
      events.push({ type: 'tool_call_arguments_delta', index, utf8 });
      events.push({ type: 'tool_call_complete', index, ...(call.toolName === undefined ? {} : { toolName: call.toolName }) });
    }
    usage = parseOllamaUsage(rootValue, usage);
    if (rootValue.done === true) {
      sawDone = true;
      stopReason = ollamaStopReason(rootValue.done_reason, toolCalls.length);
    } else if (rootValue.done !== undefined && rootValue.done !== false) {
      throw new TypeError('Ollama done flag is invalid');
    }
  }
  if (!sawDone) throw new TypeError('Ollama stream is missing its terminal entry');
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

function normalizeConstrained(fields: DecodedFields): DecodedFields {
  if (fields.stopReason === 'tool_calls' || fields.toolCalls.length !== 0) {
    throw new ProviderIdentityMismatch('constrained output arrived through a native tool shape');
  }
  if (fields.stopReason !== 'end') return fields;
  let value: unknown;
  try {
    value = parseJsonStrict(fields.text);
  } catch {
    throw new ProviderIdentityMismatch('constrained output is not strict JSON');
  }
  if (!isRecord(value) || !exactKeys(value, ['schemaVersion', 'format', 'turn'])) {
    throw new ProviderIdentityMismatch('constrained output has the wrong envelope');
  }
  if (value.schemaVersion !== 1 || value.format !== CONSTRAINED_MODEL_TURN_FORMAT || !isRecord(value.turn)) {
    throw new ProviderIdentityMismatch('constrained output has the wrong version or turn');
  }
  const turn = value.turn;
  if (!exactKeys(turn, ['stopReason', 'text', 'toolCalls']) || typeof turn.text !== 'string') {
    throw new ProviderIdentityMismatch('constrained turn has the wrong shape');
  }
  if (!Array.isArray(turn.toolCalls)) throw new ProviderIdentityMismatch('constrained toolCalls must be an array');
  if (turn.stopReason === 'end') {
    if (turn.text.length === 0 || turn.toolCalls.length !== 0) {
      throw new ProviderIdentityMismatch('constrained end must contain text and no tool calls');
    }
    return { ...fields, stopReason: 'end', text: turn.text, toolCalls: [], constrainedOutputAcknowledged: true };
  }
  if (turn.stopReason !== 'tool_calls' || turn.toolCalls.length === 0) {
    throw new ProviderIdentityMismatch('constrained tool_calls must be nonempty');
  }
  const toolCalls = turn.toolCalls.map((call, index): ObservedToolCall => {
    if (!isRecord(call) || !exactKeys(call, ['toolName', 'input']) || typeof call.toolName !== 'string') {
      throw new ProviderIdentityMismatch('constrained tool call has the wrong shape');
    }
    return { wireIndex: index, toolName: call.toolName, input: { encoding: 'jcs_json', value: call.input } };
  });
  return {
    ...fields,
    stopReason: 'tool_calls',
    text: turn.text,
    toolCalls,
    constrainedOutputAcknowledged: true
  };
}

function parseForProvider(input: ObserveProviderResponseInput, mediaType: ModelResponseMediaType, source: string): ParsedProviderResponse {
  if (OPENAI_FAMILY.has(input.provider)) {
    if (mediaType === 'application/json') return parseOpenAiJson(parseJsonStrict(source), input.model);
    if (mediaType === 'text/event-stream') return parseOpenAiStream(source, input.model);
    throw new TypeError('OpenAI-family response uses an unsupported media type');
  }
  if (input.provider === 'anthropic') {
    if (mediaType === 'application/json') return parseAnthropicJson(parseJsonStrict(source), input.model);
    if (mediaType === 'text/event-stream') return parseAnthropicStream(source, input.model);
    throw new TypeError('Anthropic response uses an unsupported media type');
  }
  if (mediaType === 'application/json') return parseOllamaJson(parseJsonStrict(source), input.model);
  if (mediaType === 'application/x-ndjson') return parseOllamaStream(source, input.model);
  throw new TypeError('Ollama response uses an unsupported media type');
}

export function observeProviderResponse(input: ObserveProviderResponseInput): ObservedProviderResponse {
  const snapshot: ObserveProviderResponseInput = { ...input, bytes: input.bytes.slice() };
  const mediaType = normalizeMediaType(snapshot.mediaType);
  const streaming = mediaType === 'text/event-stream' || mediaType === 'application/x-ndjson';
  if (!Number.isSafeInteger(snapshot.status) || snapshot.status < 100 || snapshot.status > 599) {
    throw new TypeError('provider response status must be an HTTP status');
  }
  if (snapshot.model.length === 0) throw new TypeError('provider model must be nonempty');
  if (snapshot.bytes.byteLength > MODEL_RESPONSE_LIMIT_BYTES) {
    return failure(snapshot, mediaType, 'prefix_over_limit', streaming);
  }
  if (snapshot.status < 200 || snapshot.status > 299) {
    return failure(snapshot, mediaType, 'provider_rejection', streaming);
  }

  let parsed: ParsedProviderResponse;
  try {
    parsed = parseForProvider(snapshot, mediaType, decodeUtf8(snapshot.bytes));
    if (snapshot.negotiatedMode === 'constrained-ir') {
      parsed = { ...parsed, fields: normalizeConstrained(parsed.fields), events: [] };
    }
  } catch (error) {
    if (error instanceof ProviderRejection) return failure(snapshot, mediaType, 'provider_rejection', streaming);
    if (error instanceof ProviderIdentityMismatch) {
      return failure(snapshot, mediaType, 'capability_shape_mismatch', streaming);
    }
    return failure(snapshot, mediaType, 'malformed', streaming);
  }

  const events = snapshot.negotiatedMode === 'constrained-ir' ? fullResponseEvents(parsed.fields) : parsed.events;
  return {
    observation: {
      kind: 'decoded',
      provider: snapshot.provider,
      model: snapshot.model,
      mediaType,
      bytes: snapshot.bytes,
      observedAt: snapshot.observedAt,
      ...parsed.fields
    },
    events: [startEvent(snapshot, parsed.streaming), ...events]
  };
}
