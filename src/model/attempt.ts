import { canonicalJsonBytes, canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import { planArtifactBytes, planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { assertArtifactRef, digestOmitting, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { assertBoundedJsonValue } from '../kernel/json.js';
import type { ArtifactRef, ProviderName } from '../kernel/types.js';
import type {
  AgentModelTurn,
  AgentNegotiatedMode,
  AgentToolCall,
  AgentUsage,
  ModelResponseMediaType,
  ModelUnusableResponseFailureCode,
  ModelUnusableResponseV1,
  ModelTextV1,
  ObservedToolCallInputV1,
  ToolCallInputV1
} from '../protocol/agent-ir.js';

export const MODEL_RESPONSE_LIMIT_BYTES = 1_048_576;
export const COMPACTION_SUMMARY_LIMIT_BYTES = 262_144;

export type ProviderObservedStopReason =
  | 'end'
  | 'tool_calls'
  | 'length'
  | 'content_filter'
  | 'cancelled'
  | 'unknown';

export type ObservedToolCall = {
  wireIndex?: number;
  wireCallId?: string;
  toolName?: string;
  input:
    | { encoding: 'jcs_json'; value: unknown }
    | { encoding: 'utf8_json_fragment'; utf8: string };
};

export type ObservedUsage = {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
};

type ObservedResponseBase = {
  provider: ProviderName;
  model: string;
  mediaType: ModelResponseMediaType;
  bytes: Uint8Array;
  observedAt: string;
};

export type ObservedModelResponse =
  | (ObservedResponseBase & {
      kind: 'decoded';
      responseId?: string;
      stopReason: ProviderObservedStopReason;
      text: string;
      reasoning?: string;
      toolCalls: ObservedToolCall[];
      usage?: ObservedUsage;
      constrainedOutputAcknowledged?: boolean;
    })
  | (ObservedResponseBase & {
      kind: 'malformed';
    })
  | (ObservedResponseBase & {
      kind: 'capability_shape_mismatch';
    })
  | (ObservedResponseBase & {
      kind: 'provider_rejection';
    })
  | (ObservedResponseBase & {
      kind: 'prefix_over_limit';
      responseLimitBytes: number;
    });

export type ToolInputResolution =
  | {
      kind: 'resolved';
      inputSchemaRef: ArtifactRef;
      inputSchemaDigest: string;
      value: Record<string, unknown>;
    }
  | {
      kind: 'unknown_tool';
      diagnostic: PlannedArtifact;
      diagnosticDigest: string;
    }
  | {
      kind: 'invalid_input';
      inputSchemaRef: ArtifactRef;
      inputSchemaDigest: string;
      diagnostic: PlannedArtifact;
      diagnosticDigest: string;
    };

export type ResolveToolInput = (input: {
  callId: string;
  index: number;
  toolName: string;
  observedInput: ObservedToolCallInputV1;
}) => ToolInputResolution;

type CompileModelObservationInputBase = {
  runId: string;
  opId: string;
  attempt: number;
  provider: ProviderName;
  model: string;
  negotiatedMode: AgentNegotiatedMode;
  promptProjectionRef: ArtifactRef;
  promptProjectionDigest: string;
  reservedModelTokens: number;
  abortStopIntentRef?: ArtifactRef;
  observation: ObservedModelResponse;
  resolveToolInput: ResolveToolInput;
  calculateUsageCostMicros: (usage: ObservedUsage) => number;
};

export type CompileModelObservationInput = CompileModelObservationInputBase &
  (
    | {
        request: { kind: 'normal'; requestRef: ArtifactRef; requestDigest: string };
        compaction?: never;
      }
    | {
        request: { kind: 'context_compaction'; requestRef: ArtifactRef; requestDigest: string };
        compaction: {
          maximumOutputTokens: number;
          countOutputTokens: (utf8: Uint8Array) => number;
        };
      }
  );

export type CompiledModelObservation =
  | {
      kind: 'usable';
      artifacts: PlannedArtifact[];
      turn: AgentModelTurn;
      turnRef: ArtifactRef;
    }
  | {
      kind: 'unusable';
      artifacts: PlannedArtifact[];
      response: ModelUnusableResponseV1;
      responseRef: ArtifactRef;
    };

function requireNonempty(value: string, label: string): void {
  if (value.length === 0) throw new TypeError(`${label} must be nonempty`);
}

function validateTrustedInput(input: CompileModelObservationInput): void {
  requireNonempty(input.runId, 'runId');
  requireNonempty(input.opId, 'opId');
  requireNonempty(input.model, 'model');
  if (!Number.isSafeInteger(input.attempt) || input.attempt < 1) {
    throw new TypeError('attempt must be a positive safe integer');
  }
  if (!Number.isSafeInteger(input.reservedModelTokens) || input.reservedModelTokens < 0) {
    throw new TypeError('reservedModelTokens must be a nonnegative safe integer');
  }
  assertArtifactRef(input.request.requestRef);
  assertArtifactRef(input.request.requestDigest);
  assertArtifactRef(input.promptProjectionRef);
  assertArtifactRef(input.promptProjectionDigest);
  if (input.abortStopIntentRef !== undefined) assertArtifactRef(input.abortStopIntentRef);
  if (input.request.kind === 'context_compaction') {
    if (
      input.compaction === undefined ||
      !Number.isSafeInteger(input.compaction.maximumOutputTokens) ||
      input.compaction.maximumOutputTokens < 1 ||
      typeof input.compaction.countOutputTokens !== 'function'
    ) {
      throw new TypeError('context compaction token authority must be complete');
    }
  } else if (input.compaction !== undefined) {
    throw new TypeError('normal model attempts cannot carry compaction token authority');
  }
  parseCanonicalTime(input.observation.observedAt);
}

function normalizedModelText(value: string): string {
  return normalizeCanonicalText(value.replace(/\r\n?/gu, '\n'));
}

function createModelText(value: string): { artifact: PlannedArtifact; value: ModelTextV1 } {
  const utf8 = normalizedModelText(value);
  const byteCount = Buffer.byteLength(utf8, 'utf8');
  if (byteCount > MODEL_RESPONSE_LIMIT_BYTES) {
    throw new RangeError('model text exceeds the response limit');
  }
  const withoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-model-text-v1' as const,
    utf8,
    byteCount
  };
  const text: ModelTextV1 = {
    ...withoutDigest,
    textDigest: canonicalSha256(withoutDigest)
  };
  return {
    value: text,
    artifact: planCanonicalArtifact(text, text.format)
  };
}

function base64urlSha256(value: unknown): string {
  return Buffer.from(canonicalSha256(value), 'hex').toString('base64url');
}

function normalizeCallId(
  input: CompileModelObservationInput,
  call: ObservedToolCall,
  index: number
): string | null {
  if (input.negotiatedMode === 'constrained-ir') {
    return base64urlSha256({
      protocol: 'cliq-constrained-ir-call-v1',
      opId: input.opId,
      index
    });
  }
  if (input.provider === 'ollama') {
    return base64urlSha256({
      protocol: 'cliq-ollama-native-call-v1',
      runId: input.runId,
      opId: input.opId,
      attempt: input.attempt,
      index
    });
  }
  if (typeof call.wireCallId !== 'string' || call.wireCallId.length === 0) return null;
  canonicalJsonBytes(call.wireCallId);
  if (call.wireCallId.includes('\0')) return null;
  const callId = call.wireCallId;
  return Buffer.byteLength(callId, 'utf8') <= 512 ? callId : null;
}

function createObservedInput(call: ObservedToolCall): {
  artifact: PlannedArtifact;
  value: ObservedToolCallInputV1;
} {
  if (call.input.encoding === 'jcs_json') {
    assertBoundedJsonValue(call.input.value, 'observed tool input');
    const encodedValue = canonicalJsonBytes(call.input.value);
    if (encodedValue.byteLength > MODEL_RESPONSE_LIMIT_BYTES) {
      throw new RangeError('observed tool input exceeds the response limit');
    }
    const withoutDigest = {
      schemaVersion: 1 as const,
      format: 'cliq-observed-tool-call-input-v1' as const,
      byteCount: encodedValue.byteLength,
      encoding: 'jcs_json' as const,
      value: call.input.value
    };
    const value: ObservedToolCallInputV1 = {
      ...withoutDigest,
      observedInputDigest: canonicalSha256(withoutDigest)
    };
    return {
      value,
      artifact: planCanonicalArtifact(value, value.format)
    };
  }

  canonicalJsonBytes(call.input.utf8);
  const utf8 = call.input.utf8;
  const byteCount = Buffer.byteLength(utf8, 'utf8');
  if (byteCount > MODEL_RESPONSE_LIMIT_BYTES) {
    throw new RangeError('observed tool input exceeds the response limit');
  }
  const withoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-observed-tool-call-input-v1' as const,
    byteCount,
    encoding: 'utf8_json_fragment' as const,
    utf8
  };
  const value: ObservedToolCallInputV1 = {
    ...withoutDigest,
    observedInputDigest: canonicalSha256(withoutDigest)
  };
  return {
    value,
    artifact: planCanonicalArtifact(value, value.format)
  };
}

function assertResolutionArtifact(artifact: PlannedArtifact, digest: string): void {
  assertArtifactRef(artifact.ref);
  assertArtifactRef(digest);
  if (sha256Bytes(artifact.bytes) !== artifact.ref) {
    throw new TypeError('tool diagnostic artifact does not rehash');
  }
  if (artifact.bytes.byteLength > MODEL_RESPONSE_LIMIT_BYTES) {
    throw new TypeError('tool diagnostic artifact exceeds the response limit');
  }
}

function createToolInput(
  callId: string,
  index: number,
  toolName: string,
  observed: { artifact: PlannedArtifact; value: ObservedToolCallInputV1 },
  resolution: ToolInputResolution
): { artifact: PlannedArtifact; value: ToolCallInputV1; dependencies: PlannedArtifact[] } {
  const base = {
    schemaVersion: 1 as const,
    format: 'cliq-tool-call-input-v1' as const,
    callId,
    index,
    toolName,
    observedInputRef: observed.artifact.ref,
    observedInputDigest: observed.value.observedInputDigest
  };

  let withoutDigest: Omit<ToolCallInputV1, 'inputDigest'>;
  let dependencies: PlannedArtifact[] = [observed.artifact];
  if (resolution.kind === 'resolved') {
    assertArtifactRef(resolution.inputSchemaRef);
    assertArtifactRef(resolution.inputSchemaDigest);
    if (
      resolution.value === null ||
      typeof resolution.value !== 'object' ||
      Array.isArray(resolution.value) ||
      (Object.getPrototypeOf(resolution.value) !== Object.prototype && Object.getPrototypeOf(resolution.value) !== null)
    ) {
      throw new TypeError('resolved tool input must be a plain object');
    }
    assertBoundedJsonValue(resolution.value, 'resolved tool input');
    canonicalJsonBytes(resolution.value);
    withoutDigest = {
      ...base,
      disposition: 'resolved',
      inputSchemaRef: resolution.inputSchemaRef,
      inputSchemaDigest: resolution.inputSchemaDigest,
      value: resolution.value
    };
  } else if (resolution.kind === 'unknown_tool') {
    assertResolutionArtifact(resolution.diagnostic, resolution.diagnosticDigest);
    dependencies = [...dependencies, resolution.diagnostic];
    withoutDigest = {
      ...base,
      disposition: 'rejected_unknown_tool',
      diagnosticRef: resolution.diagnostic.ref,
      diagnosticDigest: resolution.diagnosticDigest
    };
  } else {
    assertArtifactRef(resolution.inputSchemaRef);
    assertArtifactRef(resolution.inputSchemaDigest);
    assertResolutionArtifact(resolution.diagnostic, resolution.diagnosticDigest);
    dependencies = [...dependencies, resolution.diagnostic];
    withoutDigest = {
      ...base,
      disposition: 'rejected_invalid_input',
      inputSchemaRef: resolution.inputSchemaRef,
      inputSchemaDigest: resolution.inputSchemaDigest,
      diagnosticRef: resolution.diagnostic.ref,
      diagnosticDigest: resolution.diagnosticDigest
    };
  }

  const value: ToolCallInputV1 = {
    ...withoutDigest,
    inputDigest: canonicalSha256(withoutDigest)
  } as ToolCallInputV1;
  return {
    value,
    artifact: planCanonicalArtifact(value, value.format),
    dependencies
  };
}

function validatedUsage(input: CompileModelObservationInput, usage: ObservedUsage | undefined): AgentUsage | undefined {
  if (usage === undefined) return undefined;
  const values = [usage.inputTokens, usage.outputTokens, usage.cacheReadTokens, usage.cacheWriteTokens];
  if (values.some((value) => !Number.isSafeInteger(value) || value < 0)) {
    return undefined;
  }
  const usedModelTokens = usage.inputTokens + usage.outputTokens;
  if (!Number.isSafeInteger(usedModelTokens) || usedModelTokens > input.reservedModelTokens) {
    return undefined;
  }
  let costMicros: number;
  try {
    costMicros = input.calculateUsageCostMicros(usage);
  } catch {
    return undefined;
  }
  if (!Number.isSafeInteger(costMicros) || costMicros < 0) return undefined;
  return { ...usage, costMicros };
}

function appendArtifact(target: PlannedArtifact[], seen: Set<string>, artifact: PlannedArtifact): void {
  if (seen.has(artifact.ref)) return;
  target.push(artifact);
  seen.add(artifact.ref);
}

function rawObservationArtifact(bytes: Uint8Array): PlannedArtifact {
  return planArtifactBytes(bytes, 'application/octet-stream', 'cliq-observed-model-response-bytes-v1');
}

function unusable(
  input: CompileModelObservationInput,
  failureCode: ModelUnusableResponseFailureCode,
  rawBytes: Uint8Array,
  prefixOverLimit: boolean
): CompiledModelObservation {
  const rawArtifact = rawObservationArtifact(rawBytes);
  const observation = input.observation;
  const observedResponse = prefixOverLimit
    ? {
        kind: 'prefix_over_limit' as const,
        mediaType: observation.mediaType,
        bytesRef: rawArtifact.ref,
        bytesDigest: rawArtifact.ref,
        byteCount: rawArtifact.bytes.byteLength,
        responseLimitBytes: MODEL_RESPONSE_LIMIT_BYTES
      }
    : {
        kind: 'complete' as const,
        mediaType: observation.mediaType,
        bytesRef: rawArtifact.ref,
        bytesDigest: rawArtifact.ref,
        byteCount: rawArtifact.bytes.byteLength
      };
  const withoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-model-unusable-response-v1' as const,
    runId: input.runId,
    opId: input.opId,
    attempt: input.attempt,
    request: input.request,
    provider: input.provider,
    model: input.model,
    negotiatedMode: input.negotiatedMode,
    failureCode,
    observedResponse,
    observedAt: observation.observedAt
  };
  const response: ModelUnusableResponseV1 = {
    ...withoutDigest,
    unusableDigest: canonicalSha256(withoutDigest)
  };
  const responseArtifact = planCanonicalArtifact(response, response.format);
  return {
    kind: 'unusable',
    artifacts: [rawArtifact, responseArtifact],
    response,
    responseRef: responseArtifact.ref
  };
}

function unusableFromComplete(
  input: CompileModelObservationInput,
  failureCode: ModelUnusableResponseFailureCode
): CompiledModelObservation {
  return unusable(input, failureCode, input.observation.bytes, false);
}

function responseDigest(turn: Omit<AgentModelTurn, 'responseDigest'>): string {
  return canonicalSha256({
    format: 'cliq-agent-normalized-response-v1',
    provider: turn.provider,
    model: turn.model,
    ...(turn.responseId === undefined ? {} : { responseId: turn.responseId }),
    ...(turn.usage === undefined ? {} : { usage: turn.usage }),
    usageTrusted: false,
    negotiatedMode: turn.negotiatedMode,
    requestDigest: turn.requestDigest,
    stopReason: turn.stopReason,
    textRef: turn.textRef,
    toolCalls: turn.toolCalls,
    ...('abortStopIntentRef' in turn ? { abortStopIntentRef: turn.abortStopIntentRef } : {})
  });
}

function stopFailureCode(stopReason: ProviderObservedStopReason): ModelUnusableResponseFailureCode | null {
  switch (stopReason) {
    case 'end':
    case 'tool_calls':
    case 'cancelled':
      return null;
    case 'length':
      return 'stop_reason_length';
    case 'content_filter':
      return 'stop_reason_content_filter';
    case 'unknown':
    default:
      return 'stop_reason_unknown';
  }
}

export function compileModelObservation(input: CompileModelObservationInput): CompiledModelObservation {
  validateTrustedInput(input);
  const observation = input.observation;
  if (observation.bytes.byteLength > MODEL_RESPONSE_LIMIT_BYTES || observation.kind === 'prefix_over_limit') {
    const prefix = observation.bytes.slice(0, MODEL_RESPONSE_LIMIT_BYTES + 1);
    return unusable(input, 'response_too_large', prefix, true);
  }
  if (observation.provider !== input.provider || observation.model !== input.model) {
    return unusableFromComplete(input, 'capability_shape_mismatch');
  }
  if (observation.kind === 'provider_rejection') {
    return unusableFromComplete(input, 'provider_rejected_response');
  }
  if (observation.kind === 'malformed') {
    return unusableFromComplete(input, 'malformed_transport_payload');
  }
  if (observation.kind === 'capability_shape_mismatch') {
    return unusableFromComplete(input, 'capability_shape_mismatch');
  }

  if (observation.responseId !== undefined) {
    try {
      canonicalJsonBytes(observation.responseId);
    } catch {
      return unusableFromComplete(input, 'malformed_transport_payload');
    }
    if (
      observation.responseId.length === 0 ||
      observation.responseId.includes('\0') ||
      Buffer.byteLength(observation.responseId, 'utf8') > 512
    ) {
      return unusableFromComplete(input, 'malformed_transport_payload');
    }
  }

  if (input.request.kind === 'context_compaction') {
    const compaction = input.compaction;
    let byteCount = Number.POSITIVE_INFINITY;
    let tokenCount = Number.POSITIVE_INFINITY;
    try {
      const summaryBytes = Buffer.from(normalizedModelText(observation.text), 'utf8');
      byteCount = summaryBytes.byteLength;
      tokenCount = compaction?.countOutputTokens(summaryBytes) ?? Number.POSITIVE_INFINITY;
    } catch {
      // The closed compaction failure below retains the exact wire observation.
    }
    if (
      input.negotiatedMode !== 'text-only' ||
      observation.stopReason !== 'end' ||
      observation.toolCalls.length !== 0 ||
      byteCount < 1 ||
      byteCount > COMPACTION_SUMMARY_LIMIT_BYTES ||
      !Number.isSafeInteger(tokenCount) ||
      tokenCount < 1 ||
      compaction === undefined ||
      tokenCount > compaction.maximumOutputTokens
    ) {
      return unusableFromComplete(input, 'context_compaction_requires_end_markdown');
    }
  }

  const terminalStopFailure = stopFailureCode(observation.stopReason);
  if (terminalStopFailure !== null) return unusableFromComplete(input, terminalStopFailure);
  if (input.negotiatedMode === 'text-only' && observation.toolCalls.length > 0) {
    return unusableFromComplete(input, 'tool_calls_forbidden_by_mode');
  }
  if (input.negotiatedMode === 'constrained-ir' && observation.constrainedOutputAcknowledged !== true) {
    return unusableFromComplete(input, 'capability_shape_mismatch');
  }

  if (
    (observation.stopReason === 'end' && observation.toolCalls.length > 0) ||
    (observation.stopReason === 'tool_calls' && observation.toolCalls.length === 0) ||
    (observation.stopReason === 'cancelled' &&
      (observation.toolCalls.length > 0 || input.abortStopIntentRef === undefined))
  ) {
    return unusableFromComplete(input, 'invalid_stop_call_shape');
  }

  let textResult: ReturnType<typeof createModelText>;
  try {
    textResult = createModelText(observation.text);
  } catch {
    return unusableFromComplete(input, 'malformed_transport_payload');
  }
  if (observation.stopReason === 'end' && textResult.value.byteCount === 0) {
    return unusableFromComplete(input, 'invalid_stop_call_shape');
  }

  const callIds: string[] = [];
  const uniqueCallIds = new Set<string>();
  for (const [index, call] of observation.toolCalls.entries()) {
    if (call.wireIndex !== undefined && call.wireIndex !== index) {
      return unusableFromComplete(input, 'malformed_transport_payload');
    }
    let callId: string | null;
    try {
      callId = normalizeCallId(input, call, index);
    } catch {
      callId = null;
    }
    if (callId === null || uniqueCallIds.has(callId)) {
      return unusableFromComplete(input, 'missing_or_duplicate_call_id');
    }
    callIds.push(callId);
    uniqueCallIds.add(callId);
  }

  const artifacts: PlannedArtifact[] = [];
  const artifactRefs = new Set<string>();
  appendArtifact(artifacts, artifactRefs, textResult.artifact);
  const toolCalls: AgentToolCall[] = [];
  for (const [index, call] of observation.toolCalls.entries()) {
    if (call.toolName !== undefined && typeof call.toolName !== 'string') {
      return unusableFromComplete(input, 'malformed_transport_payload');
    }
    const toolName = call.toolName ?? '';
    try {
      canonicalJsonBytes(toolName);
    } catch {
      return unusableFromComplete(input, 'malformed_transport_payload');
    }
    if (toolName.includes('\0') || Buffer.byteLength(toolName, 'utf8') > 512) {
      return unusableFromComplete(input, 'malformed_transport_payload');
    }
    let observedInput: ReturnType<typeof createObservedInput>;
    try {
      observedInput = createObservedInput(call);
    } catch {
      return unusableFromComplete(input, 'malformed_transport_payload');
    }
    const callId = callIds[index]!;
    const resolution = input.resolveToolInput({ callId, index, toolName, observedInput: observedInput.value });
    const toolInput = createToolInput(callId, index, toolName, observedInput, resolution);
    for (const dependency of toolInput.dependencies) appendArtifact(artifacts, artifactRefs, dependency);
    appendArtifact(artifacts, artifactRefs, toolInput.artifact);
    toolCalls.push({
      callId,
      index,
      toolName,
      inputRef: toolInput.artifact.ref,
      inputDigest: toolInput.value.inputDigest
    });
  }

  const usage = validatedUsage(input, observation.usage);
  if (observation.usage !== undefined && usage === undefined) {
    return unusableFromComplete(input, 'malformed_transport_payload');
  }

  const common = {
    schemaVersion: 1 as const,
    format: 'cliq-agent-model-turn-v1' as const,
    provider: input.provider,
    model: input.model,
    ...(observation.responseId === undefined ? {} : { responseId: observation.responseId }),
    ...(usage === undefined ? {} : { usage }),
    usageTrusted: false as const,
    negotiatedMode: input.negotiatedMode,
    promptProjectionRef: input.promptProjectionRef,
    promptProjectionDigest: input.promptProjectionDigest,
    requestDigest: input.request.requestDigest,
    textRef: textResult.artifact.ref
  };

  let withoutResponseDigest: Omit<AgentModelTurn, 'responseDigest'>;
  if (observation.stopReason === 'tool_calls') {
    withoutResponseDigest = {
      ...common,
      stopReason: 'tool_calls',
      toolCalls: toolCalls as [AgentToolCall, ...AgentToolCall[]]
    };
  } else if (observation.stopReason === 'cancelled') {
    withoutResponseDigest = {
      ...common,
      stopReason: 'cancelled',
      toolCalls: [],
      abortStopIntentRef: input.abortStopIntentRef!
    };
  } else {
    withoutResponseDigest = {
      ...common,
      stopReason: 'end',
      toolCalls: []
    };
  }

  const turn: AgentModelTurn = {
    ...withoutResponseDigest,
    responseDigest: responseDigest(withoutResponseDigest)
  } as AgentModelTurn;
  const turnArtifact = planCanonicalArtifact(turn, turn.format);
  appendArtifact(artifacts, artifactRefs, turnArtifact);
  return {
    kind: 'usable',
    artifacts,
    turn,
    turnRef: turnArtifact.ref
  };
}

export function verifyModelText(value: ModelTextV1): void {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
    Object.keys(value).length !== 5 ||
    !['schemaVersion', 'format', 'utf8', 'byteCount', 'textDigest'].every((key) => Object.hasOwn(value, key)) ||
    value.schemaVersion !== 1 ||
    value.format !== 'cliq-model-text-v1' ||
    typeof value.utf8 !== 'string' ||
    !Number.isSafeInteger(value.byteCount) ||
    value.byteCount < 0 ||
    typeof value.textDigest !== 'string'
  ) {
    throw new TypeError('model text has the wrong schema');
  }
  if (normalizedModelText(value.utf8) !== value.utf8) {
    throw new TypeError('model text is not canonically normalized');
  }
  if (Buffer.byteLength(value.utf8, 'utf8') !== value.byteCount) {
    throw new TypeError('model text byte count does not match');
  }
  if (value.byteCount > MODEL_RESPONSE_LIMIT_BYTES) {
    throw new TypeError('model text exceeds the response limit');
  }
  assertArtifactRef(value.textDigest);
  if (digestOmitting(value, 'textDigest') !== value.textDigest) {
    throw new TypeError('model text digest does not rehash');
  }
}
