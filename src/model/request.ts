import { canonicalJsonBytes, canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import { planArtifactBytes, planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { assertArtifactRef, digestOmitting } from '../kernel/identity.js';
import { assertBoundedJsonValue } from '../kernel/json.js';
import type { ArtifactRef, ProviderName } from '../kernel/types.js';
import type {
  AgentNegotiatedMode,
  ModelTextV1,
  ProviderContinuation,
  ObservedToolArguments
} from '../protocol/agent-ir.js';
import { verifyModelText } from './attempt.js';
import { createModelRequestReservation, type ModelRequestReservation, type ValidatedModelPricing } from './pricing.js';

export const MODEL_REQUEST_BODY_LIMIT_BYTES = 1_048_576;
export const MODEL_VISIBLE_PROMPT_FORMAT = 'cliq-model-visible-prompt-v1';
export const MODEL_VISIBLE_COMPACTION_FORMAT = 'cliq-compaction-prompt-v1';
export const MISSING_TOOL_NAME = '__cliq_missing_tool_name';

export type NormalPromptToolCallV1 = {
  callId: string;
  index: number;
  toolName: string;
  inputRef: ArtifactRef;
  inputDigest: string;
  arguments: ObservedToolArguments;
};

export type NormalPromptMessageV1 =
  | {
      index: number;
      role: 'system' | 'user';
      sourceKind:
        | 'assembly_instructions'
        | 'session_terminal'
        | 'session_summary'
        | 'parent_context'
        | 'additional_context'
        | 'run_objective'
        | 'run_summary'
        | 'user_input'
        | 'verifier_repair'
        | 'child_result';
      sourceId: string;
      contentUtf8: string;
    }
  | {
      index: number;
      role: 'assistant';
      sourceItemId: string;
      contentUtf8: string;
      toolCalls: NormalPromptToolCallV1[];
      continuation?: ProviderContinuation;
    }
  | {
      index: number;
      role: 'tool';
      sourceItemId: string;
      toolCallId: string;
      contentUtf8: string;
    };

export type NormalPromptProjectionV1 = {
  schemaVersion: 1;
  format: 'cliq-normal-prompt-projection-v1';
  runId: string;
  basedOnRunRevision: number;
  frontierDigest: string;
  runSpecRef: ArtifactRef;
  assemblyRef: ArtifactRef;
  assemblyDigest: string;
  contextManifestRef: ArtifactRef;
  contextManifestDigest: string;
  messages: NormalPromptMessageV1[];
  tools: Array<{
    index: number;
    name: string;
    description: string;
    inputSchemaRef: ArtifactRef;
    inputSchemaDigest: string;
    inputSchema: unknown;
  }>;
  projectionDigest: string;
};

export type CompactionPromptEnvelopeV1 = {
  schemaVersion: 1;
  format: 'cliq-compaction-prompt-envelope-v1';
  systemInstructionRef: ArtifactRef;
  systemInstructionDigest: string;
  userPrefixRef: ArtifactRef;
  userPrefixDigest: string;
  sourcePlaceholder: '{{CLIQ_SOURCE_CONTEXT_UTF8}}';
  userSuffixRef: ArtifactRef;
  userSuffixDigest: string;
  resultContract: {
    toolsAllowed: false;
    requiredStopReason: 'end';
    mediaType: 'text/markdown; charset=utf-8';
    summaryFormat: 'cliq-context-summary-markdown-v1';
  };
  envelopeDigest: string;
};

type ModelVisibleToolCall = {
  callId: string;
  index: number;
  toolName: string;
  arguments: ObservedToolArguments;
};

type ModelVisibleMessage =
  | { role: 'system' | 'user'; contentUtf8: string }
  | { role: 'assistant'; contentUtf8: string; toolCalls: ModelVisibleToolCall[]; continuation?: ProviderContinuation }
  | { role: 'tool'; toolCallId: string; contentUtf8: string };

type ModelVisibleTool = {
  index: number;
  name: string;
  description: string;
  inputSchema: unknown;
};

type ModelVisibleResponseContract =
  | { mode: AgentNegotiatedMode; toolCallsAllowed: boolean }
  | CompactionPromptEnvelopeV1['resultContract'];

export type ModelVisiblePromptV1 = {
  format: typeof MODEL_VISIBLE_PROMPT_FORMAT | typeof MODEL_VISIBLE_COMPACTION_FORMAT;
  messages: ModelVisibleMessage[];
  tools: ModelVisibleTool[];
  responseContract: ModelVisibleResponseContract;
};

export type ModelRequestV1 = {
  schemaVersion: 1;
  format: 'cliq-model-request-v1';
  kind: 'normal' | 'context_compaction';
  runId: string;
  opId: string;
  attempt: number;
  assemblyRef: ArtifactRef;
  assemblyDigest: string;
  provider: ProviderName;
  model: string;
  negotiatedMode: AgentNegotiatedMode;
  promptProjectionRef: ArtifactRef;
  promptProjectionDigest: string;
  compactionPlanRef?: ArtifactRef;
  requestPath: string;
  mediaType: 'application/json';
  bodyBytesRef: ArtifactRef;
  bodyByteCount: number;
  streaming: boolean;
  maximumOutputTokens: number;
  estimatedInputTokens: number;
  reservation: ModelRequestReservation;
  requestDigest: string;
};

export type ModelAttemptAuthority = {
  assemblyRef: ArtifactRef;
  assemblyDigest: string;
  provider: ProviderName;
  model: string;
  negotiatedMode: AgentNegotiatedMode;
  streaming: boolean;
  contextLimitTokens: number;
  maximumOutputTokens: number;
  maximumCompactionOutputTokens: number;
  exposedTools: NormalPromptProjectionV1['tools'];
  pricing: ValidatedModelPricing;
  compactionEnvelope: CompactionPromptEnvelopeMaterial;
};

export type PrepareNormalModelAttemptInput = {
  authority: ModelAttemptAuthority;
  invocation: { runId: string; opId: string; attempt: number };
  projectionRef: ArtifactRef;
  projection: NormalPromptProjectionV1;
};
export type PreparedModelAttemptData = {
  artifacts: PlannedArtifact[];
  request: ModelRequestV1;
  requestRef: ArtifactRef;
  outbound: { requestPath: string; mediaType: 'application/json'; bodyBytesRef: ArtifactRef; bodyBytes: Uint8Array };
};
export type CompactionPromptEnvelopeMaterial = {
  ref: ArtifactRef;
  value: CompactionPromptEnvelopeV1;
  systemInstruction: { ref: ArtifactRef; value: ModelTextV1 };
  userPrefix: { ref: ArtifactRef; value: ModelTextV1 };
  userSuffix: { ref: ArtifactRef; value: ModelTextV1 };
};
export type PrepareCompactionModelAttemptInput = {
  authority: ModelAttemptAuthority;
  invocation: { runId: string; opId: string; attempt: number };
  compactionPlanRef: ArtifactRef;
  sourceContextUtf8: string;
};

const PROJECTION_KEYS = [
  'schemaVersion',
  'format',
  'runId',
  'basedOnRunRevision',
  'frontierDigest',
  'runSpecRef',
  'assemblyRef',
  'assemblyDigest',
  'contextManifestRef',
  'contextManifestDigest',
  'messages',
  'tools',
  'projectionDigest'
] as const;
const TEXT_MESSAGE_KEYS = ['index', 'role', 'sourceKind', 'sourceId', 'contentUtf8'] as const;
const ASSISTANT_MESSAGE_KEYS = ['index', 'role', 'sourceItemId', 'contentUtf8', 'toolCalls'] as const;
const TOOL_MESSAGE_KEYS = ['index', 'role', 'sourceItemId', 'toolCallId', 'contentUtf8'] as const;
const PROJECTION_TOOL_CALL_KEYS = ['callId', 'index', 'toolName', 'inputRef', 'inputDigest', 'arguments'] as const;
const PROJECTION_TOOL_KEYS = [
  'index',
  'name',
  'description',
  'inputSchemaRef',
  'inputSchemaDigest',
  'inputSchema'
] as const;
const COMPACTION_ENVELOPE_KEYS = [
  'schemaVersion',
  'format',
  'systemInstructionRef',
  'systemInstructionDigest',
  'userPrefixRef',
  'userPrefixDigest',
  'sourcePlaceholder',
  'userSuffixRef',
  'userSuffixDigest',
  'resultContract',
  'envelopeDigest'
] as const;
const COMPACTION_RESULT_KEYS = ['toolsAllowed', 'requiredStopReason', 'mediaType', 'summaryFormat'] as const;
const NORMAL_PROMPT_SOURCE_KINDS = new Set<string>([
  'assembly_instructions',
  'session_terminal',
  'session_summary',
  'parent_context',
  'additional_context',
  'run_objective',
  'run_summary',
  'user_input',
  'verifier_repair',
  'child_result'
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function nonempty(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && !value.includes('\0');
}

function nonnegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function canonicalText(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try {
    return normalizeCanonicalText(value) === value;
  } catch {
    return false;
  }
}

function exactUnicodeText(value: unknown): value is string {
  if (typeof value !== 'string' || value.includes('\0')) return false;
  try {
    canonicalJsonBytes(value);
    return true;
  } catch {
    return false;
  }
}

function artifactRef(value: unknown): value is ArtifactRef {
  if (typeof value !== 'string') return false;
  try {
    assertArtifactRef(value);
    return true;
  } catch {
    return false;
  }
}

function validateStringIdentity(value: string, label: string, maxBytes = 512): void {
  if (!nonempty(value) || Buffer.byteLength(value, 'utf8') > maxBytes) {
    throw new TypeError(`${label} must be nonempty bounded UTF-8`);
  }
  canonicalJsonBytes(value);
}

function expectedNormalResponseContract(mode: AgentNegotiatedMode): ModelVisibleResponseContract {
  return { mode, toolCallsAllowed: mode !== 'text-only' };
}

function validateNormalMessageSequence(messages: readonly ModelVisibleMessage[]): void {
  if (messages.length === 0 || messages[0]?.role !== 'system') {
    throw new TypeError('normal prompt must begin with its single system message');
  }
  let pendingCallIds: string[] = [];
  for (const [index, message] of messages.entries()) {
    if (message.role === 'system') {
      if (index !== 0 || pendingCallIds.length > 0) {
        throw new TypeError('normal prompt system message is out of sequence');
      }
      continue;
    }
    if (message.role === 'tool') {
      if (pendingCallIds[0] !== message.toolCallId) {
        throw new TypeError('normal prompt tool results must close the preceding call batch in order');
      }
      pendingCallIds = pendingCallIds.slice(1);
      continue;
    }
    if (pendingCallIds.length > 0) {
      throw new TypeError('normal prompt cannot continue before every preceding tool call has a result');
    }
    if (message.role === 'assistant') {
      const callIds = message.toolCalls.map((call) => call.callId);
      if (new Set(callIds).size !== callIds.length) {
        throw new TypeError('normal prompt assistant call ids must be unique within the batch');
      }
      pendingCallIds = callIds;
    }
  }
  if (pendingCallIds.length > 0) {
    throw new TypeError('normal prompt ends with an unclosed tool-call batch');
  }
}

function openAiMessages(messages: readonly ModelVisibleMessage[]): unknown[] {
  return messages.map((message) => {
    if (message.role === 'system' || message.role === 'user') {
      return { role: message.role, content: message.contentUtf8 };
    }
    if (message.role === 'tool') {
      return { role: 'tool', tool_call_id: message.toolCallId, content: message.contentUtf8 };
    }
    if (!('toolCalls' in message)) throw new TypeError('model-visible assistant message is invalid');
    return {
      role: 'assistant',
      content: message.contentUtf8,
      ...(message.toolCalls.length === 0
        ? {}
        : {
            tool_calls: message.toolCalls.map((call) => ({
              id: call.callId,
              type: 'function',
              function: { name: call.toolName || MISSING_TOOL_NAME, arguments: providerStringArguments(call.arguments) }
            }))
          })
    };
  });
}

function openAiTools(tools: readonly ModelVisibleTool[]): unknown[] {
  return tools.map((tool) => ({
    type: 'function',
    function: {
      name: tool.name,
      description: tool.description,
      parameters: tool.inputSchema
    }
  }));
}

function ollamaMessages(messages: readonly ModelVisibleMessage[]): unknown[] {
  const pendingCalls = new Map<string, { name: string; index: number }>();
  return messages.map((message) => {
    if (message.role === 'system' || message.role === 'user') {
      return { role: message.role, content: message.contentUtf8 };
    }
    if (message.role === 'tool') {
      const call = pendingCalls.get(message.toolCallId);
      if (call === undefined) throw new TypeError('Ollama tool result has no matching assistant call');
      pendingCalls.delete(message.toolCallId);
      return { role: 'tool', tool_name: call.name, content: message.contentUtf8 };
    }
    if (!('toolCalls' in message)) throw new TypeError('model-visible assistant message is invalid');
    for (const call of message.toolCalls) {
      if (pendingCalls.has(call.callId)) throw new TypeError('Ollama assistant call id is duplicated');
      pendingCalls.set(call.callId, { name: call.toolName || MISSING_TOOL_NAME, index: call.index });
    }
    return {
      role: 'assistant',
      content: message.contentUtf8,
      ...(message.toolCalls.length === 0
        ? {}
        : {
            tool_calls: message.toolCalls.map((call) => ({
              type: 'function',
              function: {
                index: call.index,
                name: call.toolName || MISSING_TOOL_NAME,
                arguments: providerObjectArguments(call.arguments)
              }
            }))
          })
    };
  });
}

type AnthropicBlock =
  | { type: 'text'; text: string }
  | { type: 'tool_use'; id: string; name: string; input: unknown }
  | { type: 'tool_result'; tool_use_id: string; content: string };

type AnthropicMessage = { role: 'user' | 'assistant'; content: AnthropicBlock[] };

function providerStringArguments(input: ObservedToolArguments): string {
  return input.encoding === 'jcs_json' ? canonicalJsonBytes(input.value).toString('utf8') : input.utf8;
}

function providerObjectArguments(input: ObservedToolArguments): Record<string, unknown> {
  if (input.encoding === 'jcs_json' && isRecord(input.value)) return input.value;
  return { __cliqRetainedInput: { format: 'cliq-retained-provider-tool-input-v1', ...input } };
}

function anthropicInput(messages: readonly ModelVisibleMessage[]): { system?: string; messages: AnthropicMessage[] } {
  const system: string[] = [];
  const result: AnthropicMessage[] = [];
  let sawConversation = false;
  const append = (role: 'user' | 'assistant', blocks: AnthropicBlock[]): void => {
    const previous = result.at(-1);
    if (previous?.role === role) previous.content.push(...blocks);
    else result.push({ role, content: blocks });
  };
  for (const message of messages) {
    if (message.role === 'system') {
      if (sawConversation) throw new TypeError('Anthropic system messages must precede conversation messages');
      system.push(message.contentUtf8);
      continue;
    }
    sawConversation = true;
    if (message.role === 'user') {
      append('user', [{ type: 'text', text: message.contentUtf8 }]);
    } else if (message.role === 'tool') {
      append('user', [{ type: 'tool_result', tool_use_id: message.toolCallId, content: message.contentUtf8 }]);
    } else if ('toolCalls' in message) {
      const blocks: AnthropicBlock[] = [...(message.continuation?.items ?? [])] as AnthropicBlock[];
      if (message.contentUtf8.length > 0) blocks.push({ type: 'text', text: message.contentUtf8 });
      for (const call of message.toolCalls) {
        blocks.push({
          type: 'tool_use',
          id: call.callId,
          name: call.toolName || MISSING_TOOL_NAME,
          input: providerObjectArguments(call.arguments)
        });
      }
      if (blocks.length === 0) blocks.push({ type: 'text', text: '' });
      append('assistant', blocks);
    } else {
      throw new TypeError('model-visible message role is invalid');
    }
  }
  return { ...(system.length === 0 ? {} : { system: system.join('\n\n') }), messages: result };
}

/** This is a context-management estimate, never token or cost settlement authority. */
export function estimateTextTokens(text: string): number {
  return Math.ceil(Buffer.byteLength(text, 'utf8') / 3);
}

export function estimatePromptTokens(prompt: ModelVisiblePromptV1): number {
  return (
    prompt.messages.reduce(
      (total, message) =>
        total +
        4 +
        estimateTextTokens(message.contentUtf8) +
        (message.role === 'assistant'
          ? message.toolCalls.reduce(
              (sum, call) => sum + estimateTextTokens(call.toolName + providerStringArguments(call.arguments)),
              0
            ) + estimateTextTokens(JSON.stringify(message.continuation?.items ?? []))
          : 0),
      0
    ) + estimateTextTokens(JSON.stringify(prompt.tools))
  );
}

function responsesInput(messages: readonly ModelVisibleMessage[]): unknown[] {
  return messages.flatMap((message): unknown[] => {
    if (message.role === 'system' || message.role === 'user') {
      return [{ role: message.role, content: message.contentUtf8 }];
    }
    if (message.role === 'tool')
      return [{ type: 'function_call_output', call_id: message.toolCallId, output: message.contentUtf8 }];
    if (!('toolCalls' in message)) throw new TypeError('invalid assistant message');
    return [
      ...(message.continuation?.items ?? []),
      ...(message.contentUtf8
        ? [{ role: 'assistant', content: [{ type: 'output_text', text: message.contentUtf8 }] }]
        : []),
      ...message.toolCalls.map((call) => ({
        type: 'function_call',
        call_id: call.callId,
        name: call.toolName || MISSING_TOOL_NAME,
        arguments: providerStringArguments(call.arguments)
      }))
    ];
  });
}

/** Internal wire adapter. The caller already validated the typed projection. */
function serializeRequest(
  authority: ModelAttemptAuthority,
  prompt: ModelVisiblePromptV1,
  output: number,
  mode: AgentNegotiatedMode
) {
  const { provider, model, streaming: stream } = authority;
  let requestPath: string;
  let body: unknown;
  const native = mode === 'native-tools';
  if (provider === 'openai') {
    requestPath = '/responses';
    body = {
      model,
      input: responsesInput(prompt.messages),
      stream,
      store: false,
      max_output_tokens: output,
      truncation: 'disabled',
      include: ['reasoning.encrypted_content'],
      ...(native
        ? {
            tools: prompt.tools.map((tool) => ({
              type: 'function',
              name: tool.name,
              description: tool.description,
              parameters: tool.inputSchema,
              strict: false
            })),
            tool_choice: 'auto'
          }
        : {})
    };
  } else if (provider === 'anthropic') {
    requestPath = '/v1/messages';
    body = {
      model,
      ...anthropicInput(prompt.messages),
      max_tokens: output,
      stream,
      ...(native
        ? {
            tools: prompt.tools.map((tool) => ({
              name: tool.name,
              description: tool.description,
              input_schema: tool.inputSchema
            }))
          }
        : {})
    };
  } else if (provider === 'ollama') {
    requestPath = '/api/chat';
    body = {
      model,
      messages: ollamaMessages(prompt.messages),
      stream,
      options: { num_predict: output, num_ctx: authority.contextLimitTokens },
      ...(native ? { tools: openAiTools(prompt.tools) } : {})
    };
  } else {
    requestPath = '/chat/completions';
    body = {
      model,
      messages: openAiMessages(prompt.messages),
      stream,
      ...(provider === 'openrouter' ? { max_completion_tokens: output } : { max_tokens: output }),
      ...(stream ? { stream_options: { include_usage: true } } : {}),
      ...(native ? { tools: openAiTools(prompt.tools), tool_choice: 'auto' } : {})
    };
  }
  const bodyBytes = canonicalJsonBytes(body);
  if (bodyBytes.byteLength > MODEL_REQUEST_BODY_LIMIT_BYTES) throw new RangeError('native request body exceeds 1 MiB');
  return { requestPath, bodyBytes };
}

function validateProjection(input: PrepareNormalModelAttemptInput): void {
  const { projection } = input;
  if (!isRecord(projection) || !hasExactKeys(projection, PROJECTION_KEYS)) {
    throw new TypeError('normal prompt projection schema is invalid');
  }
  if (
    projection.schemaVersion !== 1 ||
    projection.format !== 'cliq-normal-prompt-projection-v1' ||
    projection.runId !== input.invocation.runId ||
    projection.assemblyRef !== input.authority.assemblyRef ||
    projection.assemblyDigest !== input.authority.assemblyDigest ||
    !nonnegativeSafeInteger(projection.basedOnRunRevision) ||
    !Array.isArray(projection.messages) ||
    !Array.isArray(projection.tools)
  ) {
    throw new TypeError('normal prompt projection values are invalid');
  }
  const systemMessage = projection.messages[0];
  if (
    systemMessage?.role !== 'system' ||
    systemMessage.sourceKind !== 'assembly_instructions' ||
    systemMessage.sourceId !== projection.assemblyRef
  ) {
    throw new TypeError('normal prompt must begin with the frozen assembly instruction message');
  }
  for (const ref of [
    input.projectionRef,
    projection.frontierDigest,
    projection.runSpecRef,
    projection.assemblyRef,
    projection.assemblyDigest,
    projection.contextManifestRef,
    projection.contextManifestDigest,
    projection.projectionDigest
  ]) {
    assertArtifactRef(ref);
  }
  if (
    digestOmitting(projection, 'projectionDigest') !== projection.projectionDigest ||
    planCanonicalArtifact(projection, projection.format).ref !== input.projectionRef
  ) {
    throw new TypeError('normal prompt projection does not rehash');
  }
  for (const [index, message] of projection.messages.entries()) {
    if (!isRecord(message) || message.index !== index || typeof message.role !== 'string') {
      throw new TypeError('normal prompt message index or shape is invalid');
    }
    if (message.role === 'system' || message.role === 'user') {
      if (
        !hasExactKeys(message, TEXT_MESSAGE_KEYS) ||
        !NORMAL_PROMPT_SOURCE_KINDS.has(message.sourceKind as string) ||
        !nonempty(message.sourceId) ||
        !canonicalText(message.contentUtf8)
      ) {
        throw new TypeError('normal prompt text message is invalid');
      }
      continue;
    }
    if (message.role === 'assistant') {
      if (
        !hasExactKeys(
          message,
          message.continuation === undefined ? ASSISTANT_MESSAGE_KEYS : [...ASSISTANT_MESSAGE_KEYS, 'continuation']
        ) ||
        !nonempty(message.sourceItemId) ||
        !canonicalText(message.contentUtf8) ||
        !Array.isArray(message.toolCalls)
      ) {
        throw new TypeError('normal prompt assistant message is invalid');
      }
      if (message.continuation !== undefined) {
        const continuation = message.continuation;
        if (
          !isRecord(continuation) ||
          !hasExactKeys(continuation, ['provider', 'model', 'items']) ||
          continuation.provider !== input.authority.provider ||
          continuation.model !== input.authority.model ||
          !Array.isArray(continuation.items)
        )
          throw new TypeError('continuation identity mismatch');
        assertBoundedJsonValue(continuation.items, 'provider continuation');
        if (
          continuation.items.some(
            (item: unknown) =>
              !isRecord(item) ||
              !(input.authority.provider === 'openai'
                ? item.type === 'reasoning'
                : input.authority.provider === 'anthropic' &&
                  ['thinking', 'redacted_thinking'].includes(String(item.type)))
          )
        ) {
          throw new TypeError('continuation must contain only provider-owned reasoning items');
        }
      }
      const callIds = new Set<string>();
      for (const [callIndex, call] of message.toolCalls.entries()) {
        if (
          !isRecord(call) ||
          !hasExactKeys(call, PROJECTION_TOOL_CALL_KEYS) ||
          call.index !== callIndex ||
          !nonempty(call.callId) ||
          callIds.has(call.callId) ||
          typeof call.toolName !== 'string' ||
          call.toolName.includes('\0') ||
          !artifactRef(call.inputRef) ||
          !artifactRef(call.inputDigest) ||
          !isRecord(call.arguments)
        ) {
          throw new TypeError('normal prompt assistant tool call is invalid');
        }
        const args = call.arguments;
        if (args.encoding === 'jcs_json' && hasExactKeys(args, ['encoding', 'value'])) {
          assertBoundedJsonValue(args.value, 'tool arguments');
          canonicalJsonBytes(args.value);
        } else if (
          args.encoding === 'utf8_json_fragment' &&
          hasExactKeys(args, ['encoding', 'utf8']) &&
          typeof args.utf8 === 'string'
        ) {
          canonicalJsonBytes(args.utf8);
        } else throw new TypeError('normal prompt tool arguments are invalid');
        callIds.add(call.callId);
      }
      if (input.authority.negotiatedMode === 'text-only' && message.toolCalls.length > 0) {
        throw new TypeError('text-only prompt history cannot contain tool calls');
      }
      continue;
    }
    if (
      message.role !== 'tool' ||
      !hasExactKeys(message, TOOL_MESSAGE_KEYS) ||
      !nonempty(message.sourceItemId) ||
      !nonempty(message.toolCallId) ||
      !canonicalText(message.contentUtf8)
    ) {
      throw new TypeError('normal prompt tool message is invalid');
    }
    if (input.authority.negotiatedMode === 'text-only') {
      throw new TypeError('text-only prompt history cannot contain tool results');
    }
  }
  const names = new Set<string>();
  for (const [index, tool] of projection.tools.entries()) {
    if (
      !isRecord(tool) ||
      !hasExactKeys(tool, PROJECTION_TOOL_KEYS) ||
      tool.index !== index ||
      !nonempty(tool.name) ||
      names.has(tool.name) ||
      !canonicalText(tool.description) ||
      !artifactRef(tool.inputSchemaRef) ||
      !artifactRef(tool.inputSchemaDigest)
    ) {
      throw new TypeError('normal prompt tool is invalid');
    }
    assertBoundedJsonValue(tool.inputSchema, 'normal prompt tool schema');
    canonicalJsonBytes(tool.inputSchema);
    names.add(tool.name);
  }
  if (!canonicalJsonBytes(projection.tools).equals(canonicalJsonBytes(input.authority.exposedTools))) {
    throw new TypeError('prompt tool definitions do not equal the frozen manifest');
  }
  if (input.authority.negotiatedMode === 'text-only' && projection.tools.length !== 0) {
    throw new TypeError('text-only prompt projection must not expose tools');
  }
  validateNormalMessageSequence(projectModelVisiblePrompt(projection, input.authority.negotiatedMode).messages);
}

export function projectModelVisiblePrompt(
  projection: NormalPromptProjectionV1,
  mode: AgentNegotiatedMode
): ModelVisiblePromptV1 {
  const messages: ModelVisibleMessage[] = projection.messages.map((message) => {
    if (message.role === 'system' || message.role === 'user') {
      return { role: message.role, contentUtf8: message.contentUtf8 };
    }
    if (message.role === 'tool') {
      return { role: 'tool', toolCallId: message.toolCallId, contentUtf8: message.contentUtf8 };
    }
    if (!('toolCalls' in message)) throw new TypeError('normal prompt assistant message is invalid');
    return {
      role: 'assistant',
      contentUtf8: message.contentUtf8,
      ...(message.continuation === undefined ? {} : { continuation: message.continuation }),
      toolCalls: message.toolCalls.map((call) => ({
        callId: call.callId,
        index: call.index,
        toolName: call.toolName,
        arguments: call.arguments
      }))
    };
  });
  const tools: ModelVisibleTool[] = projection.tools.map((tool) => ({
    index: tool.index,
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema
  }));
  return {
    format: MODEL_VISIBLE_PROMPT_FORMAT,
    messages,
    tools,
    responseContract: expectedNormalResponseContract(mode)
  };
}

function prepare(
  authority: ModelAttemptAuthority,
  invocation: PrepareNormalModelAttemptInput['invocation'],
  prompt: ModelVisiblePromptV1,
  source: { ref: ArtifactRef; digest: string; compactionPlanRef?: ArtifactRef }
): PreparedModelAttemptData {
  if (!isRecord(invocation) || !hasExactKeys(invocation, ['runId', 'opId', 'attempt'])) {
    throw new TypeError('model invocation has an invalid shape');
  }
  validateStringIdentity(invocation.runId, 'Run id');
  validateStringIdentity(invocation.opId, 'operation id');
  if (!nonnegativeSafeInteger(invocation.attempt)) {
    throw new TypeError('attempt must be a nonnegative safe integer');
  }
  const compact = source.compactionPlanRef !== undefined;
  const mode = compact ? 'text-only' : authority.negotiatedMode;
  const maximumOutputTokens = compact ? authority.maximumCompactionOutputTokens : authority.maximumOutputTokens;
  const estimatedInputTokens = estimatePromptTokens(prompt);
  if (estimatedInputTokens > authority.contextLimitTokens - maximumOutputTokens) {
    throw new RangeError('estimated prompt exceeds the admitted context window');
  }
  const serialized = serializeRequest(authority, prompt, maximumOutputTokens, mode);
  const body = planArtifactBytes(serialized.bodyBytes, 'application/json', 'cliq-provider-native-request-wire-v1');
  const value = {
    schemaVersion: 1 as const,
    format: 'cliq-model-request-v1' as const,
    kind: compact ? ('context_compaction' as const) : ('normal' as const),
    ...invocation,
    assemblyRef: authority.assemblyRef,
    assemblyDigest: authority.assemblyDigest,
    provider: authority.provider,
    model: authority.model,
    negotiatedMode: mode,
    promptProjectionRef: source.ref,
    promptProjectionDigest: source.digest,
    ...(source.compactionPlanRef === undefined ? {} : { compactionPlanRef: source.compactionPlanRef }),
    requestPath: serialized.requestPath,
    mediaType: 'application/json' as const,
    bodyBytesRef: body.ref,
    bodyByteCount: body.bytes.byteLength,
    streaming: authority.streaming,
    maximumOutputTokens,
    estimatedInputTokens,
    reservation: createModelRequestReservation(authority.contextLimitTokens, maximumOutputTokens, authority.pricing)
  };
  const request = { ...value, requestDigest: canonicalSha256(value) };
  const artifact = planCanonicalArtifact(request, request.format);
  return {
    request,
    requestRef: artifact.ref,
    artifacts: [body, artifact],
    outbound: {
      requestPath: serialized.requestPath,
      mediaType: 'application/json',
      bodyBytesRef: body.ref,
      bodyBytes: body.bytes
    }
  };
}

export function prepareNormalModelAttempt(input: PrepareNormalModelAttemptInput): PreparedModelAttemptData {
  validateProjection(input);
  return prepare(
    input.authority,
    input.invocation,
    projectModelVisiblePrompt(input.projection, input.authority.negotiatedMode),
    { ref: input.projectionRef, digest: input.projection.projectionDigest }
  );
}

function verifyTextMaterial(
  material: { ref: ArtifactRef; value: ModelTextV1 },
  expectedRef: ArtifactRef,
  expectedDigest: string,
  label: string
): void {
  assertArtifactRef(material.ref);
  if (material.ref !== expectedRef || material.value.textDigest !== expectedDigest) {
    throw new TypeError(`${label} identity does not match the compaction envelope`);
  }
  verifyModelText(material.value);
  if (planCanonicalArtifact(material.value, material.value.format).ref !== material.ref) {
    throw new TypeError(`${label} artifact does not rehash`);
  }
}

function validateCompactionEnvelope(material: CompactionPromptEnvelopeMaterial): void {
  assertArtifactRef(material.ref);
  const envelope = material.value;
  if (!isRecord(envelope) || !hasExactKeys(envelope, COMPACTION_ENVELOPE_KEYS)) {
    throw new TypeError('compaction prompt envelope schema is invalid');
  }
  if (
    envelope.schemaVersion !== 1 ||
    envelope.format !== 'cliq-compaction-prompt-envelope-v1' ||
    envelope.sourcePlaceholder !== '{{CLIQ_SOURCE_CONTEXT_UTF8}}' ||
    !isRecord(envelope.resultContract) ||
    !hasExactKeys(envelope.resultContract, COMPACTION_RESULT_KEYS) ||
    envelope.resultContract.toolsAllowed !== false ||
    envelope.resultContract.requiredStopReason !== 'end' ||
    envelope.resultContract.mediaType !== 'text/markdown; charset=utf-8' ||
    envelope.resultContract.summaryFormat !== 'cliq-context-summary-markdown-v1'
  ) {
    throw new TypeError('compaction prompt envelope values are invalid');
  }
  for (const ref of [
    envelope.systemInstructionRef,
    envelope.systemInstructionDigest,
    envelope.userPrefixRef,
    envelope.userPrefixDigest,
    envelope.userSuffixRef,
    envelope.userSuffixDigest,
    envelope.envelopeDigest
  ]) {
    assertArtifactRef(ref);
  }
  if (
    digestOmitting(envelope, 'envelopeDigest') !== envelope.envelopeDigest ||
    planCanonicalArtifact(envelope, envelope.format).ref !== material.ref
  ) {
    throw new TypeError('compaction prompt envelope does not rehash');
  }
  verifyTextMaterial(
    material.systemInstruction,
    envelope.systemInstructionRef,
    envelope.systemInstructionDigest,
    'compaction system instruction'
  );
  verifyTextMaterial(material.userPrefix, envelope.userPrefixRef, envelope.userPrefixDigest, 'compaction user prefix');
  verifyTextMaterial(material.userSuffix, envelope.userSuffixRef, envelope.userSuffixDigest, 'compaction user suffix');
  const fixed = [material.systemInstruction.value.utf8, material.userPrefix.value.utf8, material.userSuffix.value.utf8];
  if (
    fixed.some((text) => text.includes(envelope.sourcePlaceholder)) ||
    fixed.reduce((count, text) => count + Buffer.byteLength(text, 'utf8'), 0) > 262_144
  ) {
    throw new TypeError('compaction prompt fixed text violates its bounds');
  }
}

export function prepareCompactionModelAttempt(input: PrepareCompactionModelAttemptInput): PreparedModelAttemptData {
  assertArtifactRef(input.compactionPlanRef);
  if (!exactUnicodeText(input.sourceContextUtf8) || !input.sourceContextUtf8.length) {
    throw new TypeError('compaction source must be nonempty UTF-8 without NUL');
  }
  const envelope = input.authority.compactionEnvelope;
  const prompt: ModelVisiblePromptV1 = {
    format: MODEL_VISIBLE_COMPACTION_FORMAT,
    messages: [
      { role: 'system', contentUtf8: envelope.systemInstruction.value.utf8 },
      {
        role: 'user',
        contentUtf8: envelope.userPrefix.value.utf8 + input.sourceContextUtf8 + envelope.userSuffix.value.utf8
      }
    ],
    tools: [],
    responseContract: envelope.value.resultContract
  };
  const projection = planCanonicalArtifact(prompt, prompt.format);
  const prepared = prepare(input.authority, input.invocation, prompt, {
    ref: projection.ref,
    digest: projection.ref,
    compactionPlanRef: input.compactionPlanRef
  });
  return { ...prepared, artifacts: [projection, ...prepared.artifacts] };
}

export function compactionEnvelopeEstimate(material: CompactionPromptEnvelopeMaterial): number {
  validateCompactionEnvelope(material);
  return (
    estimateTextTokens(material.systemInstruction.value.utf8) +
    estimateTextTokens(material.userPrefix.value.utf8 + material.userSuffix.value.utf8) +
    8
  );
}
