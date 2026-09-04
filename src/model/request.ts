import { canonicalJsonBytes, canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import { planArtifactBytes, planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { assertArtifactRef, digestOmitting } from '../kernel/identity.js';
import { assertBoundedJsonValue, parseJsonStrict } from '../kernel/json.js';
import type { ArtifactRef, ProviderName } from '../kernel/types.js';
import {
  CONSTRAINED_MODEL_TURN_FORMAT,
  type AgentNegotiatedMode,
  type ModelTextV1
} from '../protocol/agent-ir.js';
import { verifyModelText } from './attempt.js';
import { createModelRequestReservation, type ModelRequestReservation, type ValidatedModelPricing } from './pricing.js';
import {
  createByteBpeTokenizer,
  type ByteBpeTokenizer,
  type ByteBpeTokenizerAuthority
} from './tokenizer.js';

export const MODEL_REQUEST_BODY_LIMIT_BYTES = 1_048_576;
export const MODEL_VISIBLE_PROMPT_FORMAT = 'cliq-model-visible-prompt-v1';
export const MODEL_VISIBLE_COMPACTION_FORMAT = 'cliq-compaction-prompt-v1';

export type PromptSerializationProfileV1 = {
  schemaVersion: 1;
  format: 'cliq-prompt-serialization-profile-v1';
  provider: ProviderName;
  model: string;
  algorithm: 'cliq-jcs-framed-chat-v1';
  normalPrefixUtf8: string;
  normalSuffixUtf8: string;
  compactionPrefixUtf8: string;
  compactionSuffixUtf8: string;
  goldenVectors: Array<{ payloadJcsUtf8: string; renderedBytesBase64url: string }>;
  profileDigest: string;
};

export type ProviderNativeRequestAlgorithm =
  | 'cliq-openai-chat-completions-json-v1'
  | 'cliq-anthropic-messages-json-v1'
  | 'cliq-openrouter-chat-completions-json-v1'
  | 'cliq-openai-compatible-chat-completions-json-v1'
  | 'cliq-zhipu-chat-completions-json-v1'
  | 'cliq-ollama-chat-json-v1';

export type ProviderNativeRequestProfileV1 = {
  schemaVersion: 1;
  format: 'cliq-provider-native-request-profile-v1';
  provider: ProviderName;
  model: string;
  algorithm: ProviderNativeRequestAlgorithm;
  requestPath: string;
  mediaType: 'application/json';
  goldenVectors: Array<{
    requestKind: 'normal' | 'compaction';
    negotiatedMode: AgentNegotiatedMode;
    maximumOutputTokens: number;
    sourceJcsUtf8: string;
    bodyBytesBase64url: string;
    inputTokenCount: number;
  }>;
  profileDigest: string;
};

export type ProviderNativeRequestBodyV1 = {
  schemaVersion: 1;
  format: 'cliq-provider-native-request-body-v1';
  provider: ProviderName;
  model: string;
  negotiatedMode: AgentNegotiatedMode;
  profileRef: ArtifactRef;
  profileDigest: string;
  source:
    | { kind: 'normal'; promptProjectionRef: ArtifactRef; promptProjectionDigest: string }
    | {
        kind: 'compaction';
        compactionPlanRef: ArtifactRef;
        promptEnvelopeRef: ArtifactRef;
        promptEnvelopeDigest: string;
        renderedPromptRef: ArtifactRef;
        renderedPromptDigest: string;
      };
  requestPath: string;
  mediaType: 'application/json';
  bodyBytesRef: ArtifactRef;
  bodyBytesDigest: string;
  bodyByteCount: number;
  inputTokenCount: number;
  nativeRequestDigest: string;
};

export type NormalPromptToolCallV1 = {
  callId: string;
  index: number;
  toolName: string;
  inputRef: ArtifactRef;
  inputDigest: string;
  argumentsUtf8: string;
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

export type NormalModelRequestV1 = {
  schemaVersion: 1;
  format: 'cliq-normal-model-request-v1';
  runId: string;
  opId: string;
  attempt: number;
  provider: ProviderName;
  model: string;
  negotiatedMode: AgentNegotiatedMode;
  promptProjectionRef: ArtifactRef;
  promptProjectionDigest: string;
  promptSerializationRef: ArtifactRef;
  promptSerializationDigest: string;
  nativeRequestRef: ArtifactRef;
  nativeRequestDigest: string;
  tokenizerRef: ArtifactRef;
  tokenizerDigest: string;
  maximumOutputTokens: number;
  inputTokenCount: number;
  reservation: ModelRequestReservation;
  requestDigest: string;
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

export type CompactionModelRequestV1 = {
  schemaVersion: 1;
  format: 'cliq-compaction-model-request-v1';
  runId: string;
  opId: string;
  attempt: number;
  compactionPlanRef: ArtifactRef;
  promptEnvelopeRef: ArtifactRef;
  promptEnvelopeDigest: string;
  renderedPromptRef: ArtifactRef;
  renderedPromptDigest: string;
  nativeRequestRef: ArtifactRef;
  nativeRequestDigest: string;
  tokenizerRef: ArtifactRef;
  tokenizerDigest: string;
  inputTokenCount: number;
  maximumOutputTokens: number;
  reservation: ModelRequestReservation;
  requestDigest: string;
};

type ModelVisibleToolCall = {
  callId: string;
  index: number;
  toolName: string;
  argumentsUtf8: string;
};

type ModelVisibleMessage =
  | { role: 'system' | 'user'; contentUtf8: string }
  | { role: 'assistant'; contentUtf8: string; toolCalls: ModelVisibleToolCall[] }
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

export type NativeRequestSerializerInput = {
  algorithm: ProviderNativeRequestAlgorithm;
  requestKind: 'normal' | 'compaction';
  provider: ProviderName;
  model: string;
  negotiatedMode: AgentNegotiatedMode;
  maximumOutputTokens: number;
  sourceJcsUtf8: string;
};

export type NativeRequestSerializerOutput = {
  requestPath: string;
  mediaType: 'application/json';
  bodyBytes: Uint8Array;
};

export type NormalModelAttemptAuthority = {
  provider: ProviderName;
  model: string;
  negotiatedMode: AgentNegotiatedMode;
  contextLimitTokens: number;
  maximumOutputTokens: number;
  maximumCompactionOutputTokens: number;
  exposedToolNames: string[];
  pricing: ValidatedModelPricing;
  promptSerializationRef: ArtifactRef;
  promptSerializationDigest: string;
  promptSerializationProfileRef: ArtifactRef;
  promptSerializationProfile: PromptSerializationProfileV1;
  nativeRequestProfileRef: ArtifactRef;
  nativeRequestProfile: ProviderNativeRequestProfileV1;
  tokenizerRef: ArtifactRef;
  tokenizerDigest: string;
  tokenizer: ByteBpeTokenizerAuthority;
};

export type PrepareNormalModelAttemptInput = {
  authority: NormalModelAttemptAuthority;
  invocation: { runId: string; opId: string; attempt: number };
  projectionRef: ArtifactRef;
  projection: NormalPromptProjectionV1;
};

export type PreparedNormalModelAttempt = {
  artifacts: PlannedArtifact[];
  request: NormalModelRequestV1;
  requestRef: ArtifactRef;
  nativeRequest: ProviderNativeRequestBodyV1;
  nativeRequestRef: ArtifactRef;
  outbound: {
    requestPath: string;
    mediaType: 'application/json';
    bodyBytesRef: ArtifactRef;
    bodyBytes: Uint8Array;
  };
  renderedPromptBytes: Uint8Array;
};

export type CompactionPromptEnvelopeMaterial = {
  ref: ArtifactRef;
  value: CompactionPromptEnvelopeV1;
  systemInstruction: { ref: ArtifactRef; value: ModelTextV1 };
  userPrefix: { ref: ArtifactRef; value: ModelTextV1 };
  userSuffix: { ref: ArtifactRef; value: ModelTextV1 };
};

export type PrepareCompactionModelAttemptInput = {
  authority: NormalModelAttemptAuthority;
  invocation: { runId: string; opId: string; attempt: number };
  compactionPlanRef: ArtifactRef;
  envelope: CompactionPromptEnvelopeMaterial;
  sourceContextUtf8: string;
};

export type PreparedCompactionModelAttempt = {
  artifacts: PlannedArtifact[];
  request: CompactionModelRequestV1;
  requestRef: ArtifactRef;
  nativeRequest: ProviderNativeRequestBodyV1;
  nativeRequestRef: ArtifactRef;
  outbound: {
    requestPath: string;
    mediaType: 'application/json';
    bodyBytesRef: ArtifactRef;
    bodyBytes: Uint8Array;
  };
  renderedPromptRef: ArtifactRef;
  renderedPromptBytes: Uint8Array;
};

const PROVIDERS: readonly ProviderName[] = [
  'openai',
  'anthropic',
  'openrouter',
  'openai-compatible',
  'zhipu',
  'ollama'
];
const NEGOTIATED_MODES: readonly AgentNegotiatedMode[] = ['native-tools', 'constrained-ir', 'text-only'];
const PROMPT_PROFILE_KEYS = [
  'schemaVersion',
  'format',
  'provider',
  'model',
  'algorithm',
  'normalPrefixUtf8',
  'normalSuffixUtf8',
  'compactionPrefixUtf8',
  'compactionSuffixUtf8',
  'goldenVectors',
  'profileDigest'
] as const;
const PROMPT_VECTOR_KEYS = ['payloadJcsUtf8', 'renderedBytesBase64url'] as const;
const NATIVE_PROFILE_KEYS = [
  'schemaVersion',
  'format',
  'provider',
  'model',
  'algorithm',
  'requestPath',
  'mediaType',
  'goldenVectors',
  'profileDigest'
] as const;
const NATIVE_VECTOR_KEYS = [
  'requestKind',
  'negotiatedMode',
  'maximumOutputTokens',
  'sourceJcsUtf8',
  'bodyBytesBase64url',
  'inputTokenCount'
] as const;
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
const PROJECTION_TOOL_CALL_KEYS = ['callId', 'index', 'toolName', 'inputRef', 'inputDigest', 'argumentsUtf8'] as const;
const PROJECTION_TOOL_KEYS = ['index', 'name', 'description', 'inputSchemaRef', 'inputSchemaDigest', 'inputSchema'] as const;
const VISIBLE_PROMPT_KEYS = ['format', 'messages', 'tools', 'responseContract'] as const;
const VISIBLE_TEXT_MESSAGE_KEYS = ['role', 'contentUtf8'] as const;
const VISIBLE_ASSISTANT_KEYS = ['role', 'contentUtf8', 'toolCalls'] as const;
const VISIBLE_TOOL_MESSAGE_KEYS = ['role', 'toolCallId', 'contentUtf8'] as const;
const VISIBLE_CALL_KEYS = ['callId', 'index', 'toolName', 'argumentsUtf8'] as const;
const VISIBLE_TOOL_KEYS = ['index', 'name', 'description', 'inputSchema'] as const;
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
const COMPACTION_RESULT_KEYS = [
  'toolsAllowed',
  'requiredStopReason',
  'mediaType',
  'summaryFormat'
] as const;
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

const ALGORITHM_PROVIDER: Readonly<Record<ProviderNativeRequestAlgorithm, ProviderName>> = {
  'cliq-openai-chat-completions-json-v1': 'openai',
  'cliq-anthropic-messages-json-v1': 'anthropic',
  'cliq-openrouter-chat-completions-json-v1': 'openrouter',
  'cliq-openai-compatible-chat-completions-json-v1': 'openai-compatible',
  'cliq-zhipu-chat-completions-json-v1': 'zhipu',
  'cliq-ollama-chat-json-v1': 'ollama'
};

const ALGORITHM_PATH: Readonly<Record<ProviderNativeRequestAlgorithm, string>> = {
  'cliq-openai-chat-completions-json-v1': '/chat/completions',
  'cliq-anthropic-messages-json-v1': '/v1/messages',
  'cliq-openrouter-chat-completions-json-v1': '/chat/completions',
  'cliq-openai-compatible-chat-completions-json-v1': '/chat/completions',
  'cliq-zhipu-chat-completions-json-v1': '/chat/completions',
  'cliq-ollama-chat-json-v1': '/api/chat'
};

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

function positiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1;
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

function decodeBase64url(value: unknown, label: string): Buffer {
  if (typeof value !== 'string') throw new TypeError(`${label} must be canonical base64url`);
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) throw new TypeError(`${label} is not canonical base64url`);
  return decoded;
}

function parseCanonicalJcs(source: string, label: string): unknown {
  const value = parseJsonStrict(source);
  if (canonicalJsonBytes(value).toString('utf8') !== source) throw new TypeError(`${label} must be exact JCS`);
  return value;
}

function validateStringIdentity(value: string, label: string, maxBytes = 512): void {
  if (!nonempty(value) || Buffer.byteLength(value, 'utf8') > maxBytes) {
    throw new TypeError(`${label} must be nonempty bounded UTF-8`);
  }
  canonicalJsonBytes(value);
}

function constrainedResponseSchema(tools: readonly ModelVisibleTool[]): unknown {
  const end = {
    type: 'object',
    additionalProperties: false,
    required: ['stopReason', 'text', 'toolCalls'],
    properties: {
      stopReason: { const: 'end' },
      text: { type: 'string', minLength: 1 },
      toolCalls: { type: 'array', maxItems: 0 }
    }
  };
  const turn =
    tools.length === 0
      ? end
      : {
          anyOf: [
            end,
            {
              type: 'object',
              additionalProperties: false,
              required: ['stopReason', 'text', 'toolCalls'],
              properties: {
                stopReason: { const: 'tool_calls' },
                text: { type: 'string' },
                toolCalls: {
                  type: 'array',
                  minItems: 1,
                  items: {
                    anyOf: tools.map((tool) => ({
                      type: 'object',
                      additionalProperties: false,
                      required: ['toolName', 'input'],
                      properties: {
                        toolName: { const: tool.name },
                        input: tool.inputSchema
                      }
                    }))
                  }
                }
              }
            }
          ]
        };
  return {
    type: 'object',
    additionalProperties: false,
    required: ['schemaVersion', 'format', 'turn'],
    properties: {
      schemaVersion: { const: 1 },
      format: { const: CONSTRAINED_MODEL_TURN_FORMAT },
      turn
    }
  };
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

function validateVisiblePrompt(value: unknown, input: Pick<NativeRequestSerializerInput, 'requestKind' | 'negotiatedMode'>): ModelVisiblePromptV1 {
  if (!isRecord(value) || !hasExactKeys(value, VISIBLE_PROMPT_KEYS)) {
    throw new TypeError('model-visible prompt schema is invalid');
  }
  const expectedFormat = input.requestKind === 'normal' ? MODEL_VISIBLE_PROMPT_FORMAT : MODEL_VISIBLE_COMPACTION_FORMAT;
  if (value.format !== expectedFormat || !Array.isArray(value.messages) || !Array.isArray(value.tools)) {
    throw new TypeError('model-visible prompt kind is invalid');
  }
  const messages: ModelVisibleMessage[] = value.messages.map((message) => {
    if (!isRecord(message) || typeof message.role !== 'string') throw new TypeError('model-visible message is invalid');
    if (message.role === 'system' || message.role === 'user') {
      const validContent =
        expectedFormat === MODEL_VISIBLE_COMPACTION_FORMAT && message.role === 'user'
          ? exactUnicodeText(message.contentUtf8)
          : canonicalText(message.contentUtf8);
      if (!hasExactKeys(message, VISIBLE_TEXT_MESSAGE_KEYS) || !validContent) {
        throw new TypeError('model-visible text message is invalid');
      }
      return message as ModelVisibleMessage;
    }
    if (message.role === 'assistant') {
      if (!hasExactKeys(message, VISIBLE_ASSISTANT_KEYS) || !canonicalText(message.contentUtf8) || !Array.isArray(message.toolCalls)) {
        throw new TypeError('model-visible assistant message is invalid');
      }
      for (const [index, call] of message.toolCalls.entries()) {
        if (
          !isRecord(call) ||
          !hasExactKeys(call, VISIBLE_CALL_KEYS) ||
          !nonempty(call.callId) ||
          call.index !== index ||
          !nonempty(call.toolName) ||
          typeof call.argumentsUtf8 !== 'string'
        ) {
          throw new TypeError('model-visible assistant tool call is invalid');
        }
        canonicalJsonBytes(call.argumentsUtf8);
      }
      return message as ModelVisibleMessage;
    }
    if (
      message.role !== 'tool' ||
      !hasExactKeys(message, VISIBLE_TOOL_MESSAGE_KEYS) ||
      !nonempty(message.toolCallId) ||
      !canonicalText(message.contentUtf8)
    ) {
      throw new TypeError('model-visible tool message is invalid');
    }
    return message as ModelVisibleMessage;
  });
  const tools: ModelVisibleTool[] = value.tools.map((tool, index) => {
    if (
      !isRecord(tool) ||
      !hasExactKeys(tool, VISIBLE_TOOL_KEYS) ||
      tool.index !== index ||
      !nonempty(tool.name) ||
      !canonicalText(tool.description)
    ) {
      throw new TypeError('model-visible tool is invalid');
    }
    assertBoundedJsonValue(tool.inputSchema, 'model-visible tool schema');
    canonicalJsonBytes(tool.inputSchema);
    return tool as ModelVisibleTool;
  });
  if (new Set(tools.map((tool) => tool.name)).size !== tools.length) {
    throw new TypeError('model-visible tool names must be unique');
  }
  if (input.negotiatedMode === 'text-only' && tools.length !== 0) {
    throw new TypeError('text-only prompts cannot expose tools');
  }
  const expectedContract: ModelVisibleResponseContract =
    input.requestKind === 'normal'
      ? expectedNormalResponseContract(input.negotiatedMode)
      : {
          toolsAllowed: false,
          requiredStopReason: 'end',
          mediaType: 'text/markdown; charset=utf-8',
          summaryFormat: 'cliq-context-summary-markdown-v1'
        };
  if (!isRecord(value.responseContract) || !canonicalJsonBytes(value.responseContract).equals(canonicalJsonBytes(expectedContract))) {
    throw new TypeError('model-visible response contract does not match the negotiated mode');
  }
  if (input.requestKind === 'compaction') {
    if (
      input.negotiatedMode !== 'text-only' ||
      tools.length !== 0 ||
      messages.length !== 2 ||
      messages[0]?.role !== 'system' ||
      messages[1]?.role !== 'user'
    ) {
      throw new TypeError('compaction requires exactly one system and one user message');
    }
  } else {
    validateNormalMessageSequence(messages);
  }
  return { format: expectedFormat, messages, tools, responseContract: expectedContract };
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
              function: { name: call.toolName, arguments: call.argumentsUtf8 }
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
      pendingCalls.set(call.callId, { name: call.toolName, index: call.index });
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
                name: call.toolName,
                arguments: providerObjectArguments(call.argumentsUtf8)
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

function providerObjectArguments(source: string): Record<string, unknown> {
  try {
    const value = parseJsonStrict(source);
    if (isRecord(value)) return value;
    return {
      __cliqRetainedInput: {
        format: 'cliq-retained-provider-tool-input-v1',
        encoding: 'jcs_json',
        value
      }
    };
  } catch {
    return {
      __cliqRetainedInput: {
        format: 'cliq-retained-provider-tool-input-v1',
        encoding: 'utf8_json_fragment',
        utf8: source
      }
    };
  }
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
      const blocks: AnthropicBlock[] = [];
      if (message.contentUtf8.length > 0) blocks.push({ type: 'text', text: message.contentUtf8 });
      for (const call of message.toolCalls) {
        blocks.push({
          type: 'tool_use',
          id: call.callId,
          name: call.toolName,
          input: providerObjectArguments(call.argumentsUtf8)
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

function serializeOpenAi(input: NativeRequestSerializerInput, prompt: ModelVisiblePromptV1): unknown {
  if (input.provider === 'zhipu' && input.negotiatedMode === 'constrained-ir') {
    throw new TypeError('Zhipu v1 adapter does not implement constrained IR');
  }
  return {
    model: input.model,
    messages: openAiMessages(prompt.messages),
    ...(input.provider === 'openai' || input.provider === 'openrouter'
      ? { max_completion_tokens: input.maximumOutputTokens }
      : { max_tokens: input.maximumOutputTokens }),
    stream: false,
    ...(input.negotiatedMode === 'native-tools'
      ? { tools: openAiTools(prompt.tools), tool_choice: 'auto' }
      : {}),
    ...(input.negotiatedMode === 'constrained-ir'
      ? {
          response_format: {
            type: 'json_schema',
            json_schema: {
              name: 'cliq_constrained_model_turn_v1',
              strict: true,
              schema: constrainedResponseSchema(prompt.tools)
            }
          }
        }
      : {})
  };
}

function serializeAnthropic(input: NativeRequestSerializerInput, prompt: ModelVisiblePromptV1): unknown {
  if (input.negotiatedMode === 'constrained-ir') {
    throw new TypeError('Anthropic v1 adapter does not implement constrained IR');
  }
  const mapped = anthropicInput(prompt.messages);
  return {
    model: input.model,
    max_tokens: input.maximumOutputTokens,
    stream: false,
    ...mapped,
    ...(input.negotiatedMode === 'native-tools'
      ? {
          tools: prompt.tools.map((tool) => ({
            name: tool.name,
            description: tool.description,
            input_schema: tool.inputSchema
          }))
        }
      : {})
  };
}

function serializeOllama(input: NativeRequestSerializerInput, prompt: ModelVisiblePromptV1): unknown {
  return {
    model: input.model,
    messages: ollamaMessages(prompt.messages),
    stream: false,
    options: { num_predict: input.maximumOutputTokens },
    ...(input.negotiatedMode === 'native-tools' ? { tools: openAiTools(prompt.tools) } : {}),
    ...(input.negotiatedMode === 'constrained-ir' ? { format: constrainedResponseSchema(prompt.tools) } : {})
  };
}

export function serializeNativeRequestV1(input: NativeRequestSerializerInput): NativeRequestSerializerOutput {
  if (!PROVIDERS.includes(input.provider)) throw new TypeError('native request provider is invalid');
  if (!Object.hasOwn(ALGORITHM_PROVIDER, input.algorithm)) {
    throw new TypeError('native request algorithm is invalid');
  }
  if (input.requestKind !== 'normal' && input.requestKind !== 'compaction') {
    throw new TypeError('native request kind is invalid');
  }
  if (!NEGOTIATED_MODES.includes(input.negotiatedMode)) {
    throw new TypeError('native request negotiated mode is invalid');
  }
  if (ALGORITHM_PROVIDER[input.algorithm] !== input.provider) {
    throw new TypeError('native request algorithm does not match provider');
  }
  validateStringIdentity(input.model, 'model');
  if (!positiveSafeInteger(input.maximumOutputTokens)) throw new TypeError('maximum output tokens must be positive');
  if (input.requestKind === 'compaction' && input.negotiatedMode !== 'text-only') {
    throw new TypeError('compaction native requests must be text-only');
  }
  const prompt = validateVisiblePrompt(parseCanonicalJcs(input.sourceJcsUtf8, 'native request source'), input);
  let body: unknown;
  if (input.provider === 'anthropic') body = serializeAnthropic(input, prompt);
  else if (input.provider === 'ollama') body = serializeOllama(input, prompt);
  else body = serializeOpenAi(input, prompt);
  const bodyBytes = canonicalJsonBytes(body);
  if (bodyBytes.byteLength > MODEL_REQUEST_BODY_LIMIT_BYTES) throw new RangeError('native request body exceeds 1 MiB');
  return {
    requestPath: ALGORITHM_PATH[input.algorithm],
    mediaType: 'application/json',
    bodyBytes
  };
}

function renderPrompt(
  profile: PromptSerializationProfileV1,
  requestKind: 'normal' | 'compaction',
  sourceJcsUtf8: string
): Buffer {
  parseCanonicalJcs(sourceJcsUtf8, 'prompt source');
  const prefix = requestKind === 'normal' ? profile.normalPrefixUtf8 : profile.compactionPrefixUtf8;
  const suffix = requestKind === 'normal' ? profile.normalSuffixUtf8 : profile.compactionSuffixUtf8;
  const rendered = Buffer.from(`${prefix}${sourceJcsUtf8}${suffix}`, 'utf8');
  if (rendered.byteLength > MODEL_REQUEST_BODY_LIMIT_BYTES) throw new RangeError('rendered prompt exceeds 1 MiB');
  return rendered;
}

function validatePromptProfile(authority: NormalModelAttemptAuthority): void {
  const profile = authority.promptSerializationProfile;
  if (!isRecord(profile) || !hasExactKeys(profile, PROMPT_PROFILE_KEYS)) {
    throw new TypeError('prompt serialization profile schema is invalid');
  }
  if (
    profile.schemaVersion !== 1 ||
    profile.format !== 'cliq-prompt-serialization-profile-v1' ||
    !PROVIDERS.includes(profile.provider) ||
    profile.provider !== authority.provider ||
    profile.model !== authority.model ||
    profile.algorithm !== 'cliq-jcs-framed-chat-v1' ||
    !canonicalText(profile.normalPrefixUtf8) ||
    !canonicalText(profile.normalSuffixUtf8) ||
    !canonicalText(profile.compactionPrefixUtf8) ||
    !canonicalText(profile.compactionSuffixUtf8) ||
    !Array.isArray(profile.goldenVectors) ||
    profile.goldenVectors.length < 8 ||
    profile.goldenVectors.length > 64
  ) {
    throw new TypeError('prompt serialization profile values are invalid');
  }
  if (
    digestOmitting(profile, 'profileDigest') !== profile.profileDigest ||
    planCanonicalArtifact(profile, profile.format).ref !== authority.promptSerializationProfileRef
  ) {
    throw new TypeError('prompt serialization profile does not match authority');
  }
  const coveredKinds = new Set<'normal' | 'compaction'>();
  const vectors = new Set<string>();
  for (const vector of profile.goldenVectors) {
    if (!isRecord(vector) || !hasExactKeys(vector, PROMPT_VECTOR_KEYS)) {
      throw new TypeError('prompt serialization golden vector is invalid');
    }
    if (Buffer.byteLength(vector.payloadJcsUtf8, 'utf8') > MODEL_REQUEST_BODY_LIMIT_BYTES) {
      throw new TypeError('prompt golden source exceeds 1 MiB');
    }
    const value = parseCanonicalJcs(vector.payloadJcsUtf8, 'prompt golden source');
    if (!isRecord(value) || (value.format !== MODEL_VISIBLE_PROMPT_FORMAT && value.format !== MODEL_VISIBLE_COMPACTION_FORMAT)) {
      throw new TypeError('prompt golden source has an unknown kind');
    }
    const requestKind = value.format === MODEL_VISIBLE_PROMPT_FORMAT ? 'normal' : 'compaction';
    coveredKinds.add(requestKind);
    const expected = decodeBase64url(vector.renderedBytesBase64url, 'rendered prompt golden bytes');
    if (expected.byteLength > MODEL_REQUEST_BODY_LIMIT_BYTES) {
      throw new TypeError('rendered prompt golden bytes exceed 1 MiB');
    }
    const vectorKey = canonicalSha256({
      payloadJcsUtf8: vector.payloadJcsUtf8,
      renderedBytesBase64url: vector.renderedBytesBase64url
    });
    if (vectors.has(vectorKey)) throw new TypeError('prompt serialization golden vectors must be unique');
    vectors.add(vectorKey);
    if (!renderPrompt(profile, requestKind, vector.payloadJcsUtf8).equals(expected)) {
      throw new TypeError('prompt serialization golden vector does not match');
    }
  }
  if (!coveredKinds.has('normal') || !coveredKinds.has('compaction')) {
    throw new TypeError('prompt serialization golden vectors must cover normal and compaction prompts');
  }
}

function validateNativeProfile(
  authority: NormalModelAttemptAuthority,
  tokenizer: ByteBpeTokenizer
): void {
  const profile = authority.nativeRequestProfile;
  if (!isRecord(profile) || !hasExactKeys(profile, NATIVE_PROFILE_KEYS)) {
    throw new TypeError('native request profile schema is invalid');
  }
  if (
    profile.schemaVersion !== 1 ||
    profile.format !== 'cliq-provider-native-request-profile-v1' ||
    profile.provider !== authority.provider ||
    profile.model !== authority.model ||
    ALGORITHM_PROVIDER[profile.algorithm] !== profile.provider ||
    profile.requestPath !== ALGORITHM_PATH[profile.algorithm] ||
    profile.mediaType !== 'application/json' ||
    !Array.isArray(profile.goldenVectors) ||
    profile.goldenVectors.length < 8 ||
    profile.goldenVectors.length > 64
  ) {
    throw new TypeError('native request profile values are invalid');
  }
  if (
    digestOmitting(profile, 'profileDigest') !== profile.profileDigest ||
    planCanonicalArtifact(profile, profile.format).ref !== authority.nativeRequestProfileRef
  ) {
    throw new TypeError('native request profile does not match authority');
  }
  let coversNormalMode = false;
  let coversCompaction = false;
  const vectors = new Set<string>();
  for (const vector of profile.goldenVectors) {
    if (
      !isRecord(vector) ||
      !hasExactKeys(vector, NATIVE_VECTOR_KEYS) ||
      (vector.requestKind !== 'normal' && vector.requestKind !== 'compaction') ||
      !['native-tools', 'constrained-ir', 'text-only'].includes(vector.negotiatedMode as string) ||
      !positiveSafeInteger(vector.maximumOutputTokens) ||
      !nonnegativeSafeInteger(vector.inputTokenCount)
    ) {
      throw new TypeError('native request golden vector is invalid');
    }
    if (Buffer.byteLength(vector.sourceJcsUtf8, 'utf8') > MODEL_REQUEST_BODY_LIMIT_BYTES) {
      throw new TypeError('native request golden source exceeds 1 MiB');
    }
    const serialized = serializeNativeRequestV1({
      algorithm: profile.algorithm,
      requestKind: vector.requestKind,
      provider: profile.provider,
      model: profile.model,
      negotiatedMode: vector.negotiatedMode,
      maximumOutputTokens: vector.maximumOutputTokens,
      sourceJcsUtf8: vector.sourceJcsUtf8
    });
    const expectedBody = decodeBase64url(vector.bodyBytesBase64url, 'native request golden body');
    if (expectedBody.byteLength > MODEL_REQUEST_BODY_LIMIT_BYTES) {
      throw new TypeError('native request golden body exceeds 1 MiB');
    }
    const vectorKey = canonicalSha256(vector);
    if (vectors.has(vectorKey)) throw new TypeError('native request golden vectors must be unique');
    vectors.add(vectorKey);
    if (
      serialized.requestPath !== profile.requestPath ||
      serialized.mediaType !== profile.mediaType ||
      !Buffer.from(serialized.bodyBytes).equals(expectedBody)
    ) {
      throw new TypeError('native request golden body does not match');
    }
    const rendered = renderPrompt(authority.promptSerializationProfile, vector.requestKind, vector.sourceJcsUtf8);
    if (tokenizer.count(rendered) !== vector.inputTokenCount) {
      throw new TypeError('native request golden token count does not match');
    }
    if (vector.requestKind === 'normal' && vector.negotiatedMode === authority.negotiatedMode) {
      coversNormalMode = true;
    }
    if (vector.requestKind === 'compaction' && vector.negotiatedMode === 'text-only') {
      coversCompaction = true;
    }
  }
  if (!coversNormalMode || !coversCompaction) {
    throw new TypeError('native request golden vectors do not cover the selected normal and compaction modes');
  }
}

function validateAuthority(authority: NormalModelAttemptAuthority): ByteBpeTokenizer {
  validateStringIdentity(authority.model, 'authority model');
  if (!PROVIDERS.includes(authority.provider)) throw new TypeError('authority provider is invalid');
  if (!NEGOTIATED_MODES.includes(authority.negotiatedMode)) throw new TypeError('negotiated mode is invalid');
  if (!positiveSafeInteger(authority.contextLimitTokens) || authority.contextLimitTokens < 32_768) {
    throw new TypeError('authority context limit is invalid');
  }
  if (
    !positiveSafeInteger(authority.maximumOutputTokens) ||
    authority.maximumOutputTokens > Math.floor(authority.contextLimitTokens / 4)
  ) {
    throw new TypeError('authority output limit is invalid');
  }
  if (
    !positiveSafeInteger(authority.maximumCompactionOutputTokens) ||
    authority.maximumCompactionOutputTokens > authority.maximumOutputTokens
  ) {
    throw new TypeError('authority compaction output limit is invalid');
  }
  for (const ref of [
    authority.promptSerializationRef,
    authority.promptSerializationDigest,
    authority.promptSerializationProfileRef,
    authority.nativeRequestProfileRef,
    authority.tokenizerRef,
    authority.tokenizerDigest
  ]) {
    assertArtifactRef(ref);
  }
  if (
    new Set(authority.exposedToolNames).size !== authority.exposedToolNames.length ||
    authority.exposedToolNames.some((name) => !nonempty(name))
  ) {
    throw new TypeError('authority exposed tool names must be ordered and unique');
  }
  validatePromptProfile(authority);
  const tokenizer = createByteBpeTokenizer(authority.tokenizer);
  if (authority.tokenizer.profile.provider !== authority.provider || authority.tokenizer.profile.model !== authority.model) {
    throw new TypeError('tokenizer identity does not match provider authority');
  }
  validateNativeProfile(authority, tokenizer);
  return tokenizer;
}

export function validateNormalModelAttemptAuthority(authority: NormalModelAttemptAuthority): void {
  validateAuthority(authority);
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
        !hasExactKeys(message, ASSISTANT_MESSAGE_KEYS) ||
        !nonempty(message.sourceItemId) ||
        !canonicalText(message.contentUtf8) ||
        !Array.isArray(message.toolCalls)
      ) {
        throw new TypeError('normal prompt assistant message is invalid');
      }
      const callIds = new Set<string>();
      for (const [callIndex, call] of message.toolCalls.entries()) {
        if (
          !isRecord(call) ||
          !hasExactKeys(call, PROJECTION_TOOL_CALL_KEYS) ||
          call.index !== callIndex ||
          !nonempty(call.callId) ||
          callIds.has(call.callId) ||
          !nonempty(call.toolName) ||
          !artifactRef(call.inputRef) ||
          !artifactRef(call.inputDigest) ||
          typeof call.argumentsUtf8 !== 'string'
        ) {
          throw new TypeError('normal prompt assistant tool call is invalid');
        }
        canonicalJsonBytes(call.argumentsUtf8);
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
  const actualNames = projection.tools.map((tool) => tool.name);
  if (
    actualNames.length !== input.authority.exposedToolNames.length ||
    actualNames.some((name, index) => name !== input.authority.exposedToolNames[index])
  ) {
    throw new TypeError('prompt tools do not equal the frozen exposed-tool sequence');
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
      toolCalls: message.toolCalls.map((call) => ({
        callId: call.callId,
        index: call.index,
        toolName: call.toolName,
        argumentsUtf8: call.argumentsUtf8
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

export function prepareNormalModelAttempt(input: PrepareNormalModelAttemptInput): PreparedNormalModelAttempt {
  validateStringIdentity(input.invocation.runId, 'Run id');
  validateStringIdentity(input.invocation.opId, 'operation id');
  if (!positiveSafeInteger(input.invocation.attempt)) throw new TypeError('attempt must be a positive safe integer');
  const tokenizer = validateAuthority(input.authority);
  validateProjection(input);

  const visiblePrompt = projectModelVisiblePrompt(input.projection, input.authority.negotiatedMode);
  const sourceJcsUtf8 = canonicalJsonBytes(visiblePrompt).toString('utf8');
  const renderedPromptBytes = renderPrompt(input.authority.promptSerializationProfile, 'normal', sourceJcsUtf8);
  const inputTokenCount = tokenizer.count(renderedPromptBytes);
  if (inputTokenCount > input.authority.contextLimitTokens - input.authority.maximumOutputTokens) {
    throw new RangeError('prepared model request exceeds the frozen context limit');
  }

  const serialized = serializeNativeRequestV1({
    algorithm: input.authority.nativeRequestProfile.algorithm,
    requestKind: 'normal',
    provider: input.authority.provider,
    model: input.authority.model,
    negotiatedMode: input.authority.negotiatedMode,
    maximumOutputTokens: input.authority.maximumOutputTokens,
    sourceJcsUtf8
  });
  if (
    serialized.requestPath !== input.authority.nativeRequestProfile.requestPath ||
    serialized.mediaType !== input.authority.nativeRequestProfile.mediaType
  ) {
    throw new TypeError('native serializer output does not match its frozen profile');
  }
  const bodyBytesArtifact = planArtifactBytes(
    serialized.bodyBytes,
    'application/json',
    'cliq-provider-native-request-wire-v1'
  );
  const nativeWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-provider-native-request-body-v1' as const,
    provider: input.authority.provider,
    model: input.authority.model,
    negotiatedMode: input.authority.negotiatedMode,
    profileRef: input.authority.nativeRequestProfileRef,
    profileDigest: input.authority.nativeRequestProfile.profileDigest,
    source: {
      kind: 'normal' as const,
      promptProjectionRef: input.projectionRef,
      promptProjectionDigest: input.projection.projectionDigest
    },
    requestPath: serialized.requestPath,
    mediaType: serialized.mediaType,
    bodyBytesRef: bodyBytesArtifact.ref,
    bodyBytesDigest: bodyBytesArtifact.ref,
    bodyByteCount: bodyBytesArtifact.bytes.byteLength,
    inputTokenCount
  };
  const nativeRequest: ProviderNativeRequestBodyV1 = {
    ...nativeWithoutDigest,
    nativeRequestDigest: canonicalSha256(nativeWithoutDigest)
  };
  const nativeArtifact = planCanonicalArtifact(nativeRequest, nativeRequest.format);
  const reservation = createModelRequestReservation(
    inputTokenCount,
    input.authority.maximumOutputTokens,
    input.authority.pricing
  );
  const requestWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-normal-model-request-v1' as const,
    runId: input.invocation.runId,
    opId: input.invocation.opId,
    attempt: input.invocation.attempt,
    provider: input.authority.provider,
    model: input.authority.model,
    negotiatedMode: input.authority.negotiatedMode,
    promptProjectionRef: input.projectionRef,
    promptProjectionDigest: input.projection.projectionDigest,
    promptSerializationRef: input.authority.promptSerializationRef,
    promptSerializationDigest: input.authority.promptSerializationDigest,
    nativeRequestRef: nativeArtifact.ref,
    nativeRequestDigest: nativeRequest.nativeRequestDigest,
    tokenizerRef: input.authority.tokenizerRef,
    tokenizerDigest: input.authority.tokenizerDigest,
    maximumOutputTokens: input.authority.maximumOutputTokens,
    inputTokenCount,
    reservation
  };
  const request: NormalModelRequestV1 = {
    ...requestWithoutDigest,
    requestDigest: canonicalSha256(requestWithoutDigest)
  };
  const requestArtifact = planCanonicalArtifact(request, request.format);
  return {
    artifacts: [bodyBytesArtifact, nativeArtifact, requestArtifact],
    request,
    requestRef: requestArtifact.ref,
    nativeRequest,
    nativeRequestRef: nativeArtifact.ref,
    outbound: {
      requestPath: serialized.requestPath,
      mediaType: serialized.mediaType,
      bodyBytesRef: bodyBytesArtifact.ref,
      bodyBytes: bodyBytesArtifact.bytes.slice()
    },
    renderedPromptBytes: renderedPromptBytes.slice()
  };
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

export function prepareCompactionModelAttempt(
  input: PrepareCompactionModelAttemptInput
): PreparedCompactionModelAttempt {
  validateStringIdentity(input.invocation.runId, 'Run id');
  validateStringIdentity(input.invocation.opId, 'operation id');
  if (!positiveSafeInteger(input.invocation.attempt)) throw new TypeError('attempt must be a positive safe integer');
  assertArtifactRef(input.compactionPlanRef);
  const tokenizer = validateAuthority(input.authority);
  validateCompactionEnvelope(input.envelope);
  if (!exactUnicodeText(input.sourceContextUtf8) || Buffer.byteLength(input.sourceContextUtf8, 'utf8') === 0) {
    throw new TypeError('compaction source context must be nonempty exact UTF-8 without NUL');
  }

  const visiblePrompt: ModelVisiblePromptV1 = {
    format: MODEL_VISIBLE_COMPACTION_FORMAT,
    messages: [
      { role: 'system', contentUtf8: input.envelope.systemInstruction.value.utf8 },
      {
        role: 'user',
        contentUtf8: `${input.envelope.userPrefix.value.utf8}${input.sourceContextUtf8}${input.envelope.userSuffix.value.utf8}`
      }
    ],
    tools: [],
    responseContract: { ...input.envelope.value.resultContract }
  };
  const sourceJcsUtf8 = canonicalJsonBytes(visiblePrompt).toString('utf8');
  const renderedPromptBytes = renderPrompt(
    input.authority.promptSerializationProfile,
    'compaction',
    sourceJcsUtf8
  );
  const renderedPromptArtifact = planArtifactBytes(
    renderedPromptBytes,
    'application/octet-stream',
    'cliq-rendered-compaction-prompt-v1'
  );
  const inputTokenCount = tokenizer.count(renderedPromptBytes);
  if (inputTokenCount > input.authority.contextLimitTokens - input.authority.maximumCompactionOutputTokens) {
    throw new RangeError('prepared compaction request exceeds the frozen context limit');
  }

  const serialized = serializeNativeRequestV1({
    algorithm: input.authority.nativeRequestProfile.algorithm,
    requestKind: 'compaction',
    provider: input.authority.provider,
    model: input.authority.model,
    negotiatedMode: 'text-only',
    maximumOutputTokens: input.authority.maximumCompactionOutputTokens,
    sourceJcsUtf8
  });
  if (
    serialized.requestPath !== input.authority.nativeRequestProfile.requestPath ||
    serialized.mediaType !== input.authority.nativeRequestProfile.mediaType
  ) {
    throw new TypeError('native compaction serializer output does not match its frozen profile');
  }
  const bodyBytesArtifact = planArtifactBytes(
    serialized.bodyBytes,
    'application/json',
    'cliq-provider-native-request-wire-v1'
  );
  const nativeWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-provider-native-request-body-v1' as const,
    provider: input.authority.provider,
    model: input.authority.model,
    negotiatedMode: 'text-only' as const,
    profileRef: input.authority.nativeRequestProfileRef,
    profileDigest: input.authority.nativeRequestProfile.profileDigest,
    source: {
      kind: 'compaction' as const,
      compactionPlanRef: input.compactionPlanRef,
      promptEnvelopeRef: input.envelope.ref,
      promptEnvelopeDigest: input.envelope.value.envelopeDigest,
      renderedPromptRef: renderedPromptArtifact.ref,
      renderedPromptDigest: renderedPromptArtifact.ref
    },
    requestPath: serialized.requestPath,
    mediaType: serialized.mediaType,
    bodyBytesRef: bodyBytesArtifact.ref,
    bodyBytesDigest: bodyBytesArtifact.ref,
    bodyByteCount: bodyBytesArtifact.bytes.byteLength,
    inputTokenCount
  };
  const nativeRequest: ProviderNativeRequestBodyV1 = {
    ...nativeWithoutDigest,
    nativeRequestDigest: canonicalSha256(nativeWithoutDigest)
  };
  const nativeArtifact = planCanonicalArtifact(nativeRequest, nativeRequest.format);
  const reservation = createModelRequestReservation(
    inputTokenCount,
    input.authority.maximumCompactionOutputTokens,
    input.authority.pricing
  );
  const requestWithoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-compaction-model-request-v1' as const,
    runId: input.invocation.runId,
    opId: input.invocation.opId,
    attempt: input.invocation.attempt,
    compactionPlanRef: input.compactionPlanRef,
    promptEnvelopeRef: input.envelope.ref,
    promptEnvelopeDigest: input.envelope.value.envelopeDigest,
    renderedPromptRef: renderedPromptArtifact.ref,
    renderedPromptDigest: renderedPromptArtifact.ref,
    nativeRequestRef: nativeArtifact.ref,
    nativeRequestDigest: nativeRequest.nativeRequestDigest,
    tokenizerRef: input.authority.tokenizerRef,
    tokenizerDigest: input.authority.tokenizerDigest,
    inputTokenCount,
    maximumOutputTokens: input.authority.maximumCompactionOutputTokens,
    reservation
  };
  const request: CompactionModelRequestV1 = {
    ...requestWithoutDigest,
    requestDigest: canonicalSha256(requestWithoutDigest)
  };
  const requestArtifact = planCanonicalArtifact(request, request.format);
  return {
    artifacts: [renderedPromptArtifact, bodyBytesArtifact, nativeArtifact, requestArtifact],
    request,
    requestRef: requestArtifact.ref,
    nativeRequest,
    nativeRequestRef: nativeArtifact.ref,
    outbound: {
      requestPath: serialized.requestPath,
      mediaType: serialized.mediaType,
      bodyBytesRef: bodyBytesArtifact.ref,
      bodyBytes: bodyBytesArtifact.bytes.slice()
    },
    renderedPromptRef: renderedPromptArtifact.ref,
    renderedPromptBytes: renderedPromptArtifact.bytes.slice()
  };
}
