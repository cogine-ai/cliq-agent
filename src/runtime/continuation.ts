import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { assertBoundedJsonValue } from '../kernel/json.js';
import type {
  ModelTurnItem, ToolBatchItem, ToolResultItem, ToolResultModelContentV1,
  ToolResultPayloadV1, RunFrontier, ContinuationItem
} from '../kernel/types.js';
import type { AgentModelTurn, ModelTextV1, ModelUnusableResponseV1, ObservedToolCallInputV1, ToolCallInputV1 } from '../protocol/agent-ir.js';
import { MODEL_RESPONSE_LIMIT_BYTES, modelResponseDigest, verifyModelText, type ResolveToolInput } from '../model/attempt.js';
import type { ModelRequestV1 } from '../model/request.js';

export type ModelTurnMaterial = {
  turn: AgentModelTurn;
  text: ModelTextV1;
  inputs: Array<{ value: ToolCallInputV1; observed: ObservedToolCallInputV1 }>;
};

function equal(left: unknown, right: unknown, label: string): void {
  if (canonicalSha256(left) !== canonicalSha256(right)) throw new TypeError(`${label} does not match retained authority`);
}

function exactKeys(value: object, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

export function validateUnusableModelResponse(request: ModelRequestV1, requestRef: string, response: ModelUnusableResponseV1): void {
  const failures = ['malformed_transport_payload', 'response_too_large', 'invalid_stop_call_shape', 'stop_reason_length',
    'stop_reason_content_filter', 'stop_reason_unknown', 'missing_or_duplicate_call_id', 'tool_calls_forbidden_by_mode',
    'context_compaction_requires_end_markdown', 'capability_shape_mismatch', 'provider_rejected_response'];
  if (!exactKeys(response, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'request', 'provider', 'model',
    'negotiatedMode', 'failureCode', 'observedResponse', 'observedAt', 'unusableDigest']) ||
      response.schemaVersion !== 1 || response.format !== 'cliq-model-unusable-response-v1' ||
      response.runId !== request.runId || response.opId !== request.opId || response.attempt !== request.attempt ||
      response.provider !== request.provider || response.model !== request.model || response.negotiatedMode !== request.negotiatedMode ||
      !failures.includes(response.failureCode) || digestOmitting(response, 'unusableDigest') !== response.unusableDigest) {
    throw new TypeError('unusable model response does not match its prepared request');
  }
  equal(response.request, { kind: request.kind, requestRef, requestDigest: request.requestDigest }, 'unusable request');
  parseCanonicalTime(response.observedAt);
  const observed = response.observedResponse;
  const prefix = observed.kind === 'prefix_over_limit';
  if (!exactKeys(observed, ['kind', 'mediaType', 'bytesRef', 'bytesDigest', 'byteCount', ...(prefix ? ['responseLimitBytes'] : [])]) ||
      !['complete', 'prefix_over_limit'].includes(observed.kind) || observed.bytesRef !== observed.bytesDigest ||
      !['application/json', 'text/event-stream', 'application/x-ndjson', 'unknown'].includes(observed.mediaType) ||
      !Number.isSafeInteger(observed.byteCount) || observed.byteCount < 0 ||
      (prefix ? observed.responseLimitBytes !== MODEL_RESPONSE_LIMIT_BYTES || observed.byteCount !== MODEL_RESPONSE_LIMIT_BYTES + 1 ||
        response.failureCode !== 'response_too_large' : observed.byteCount > MODEL_RESPONSE_LIMIT_BYTES || response.failureCode === 'response_too_large')) {
    throw new TypeError('unusable model response has an invalid raw observation');
  }
}

/** Independently verify the compiler's retained closure before authorizing a batch. No effects occur here. */
export function validateModelTurn(
  request: ModelRequestV1,
  material: ModelTurnMaterial,
  resolveToolInput: ResolveToolInput
): void {
  const { turn, text, inputs } = material;
  assertBoundedJsonValue(turn, 'retained model turn');
  const required = ['schemaVersion', 'format', 'provider', 'model', 'usageTrusted', 'negotiatedMode',
    'promptProjectionRef', 'promptProjectionDigest', 'requestDigest', 'responseDigest', 'stopReason', 'textRef', 'toolCalls'];
  const optional = ['responseId', 'usage', 'continuation', ...(turn.stopReason === 'cancelled' ? ['abortStopIntentRef'] : [])];
  if (required.some((key) => !Object.hasOwn(turn, key)) || Object.keys(turn).some((key) => ![...required, ...optional].includes(key)) ||
      turn.schemaVersion !== 1 || turn.format !== 'cliq-agent-model-turn-v1' || turn.usageTrusted !== false ||
      !['end', 'tool_calls', 'cancelled'].includes(turn.stopReason) ||
      turn.provider !== request.provider || turn.model !== request.model || turn.negotiatedMode !== request.negotiatedMode ||
      turn.requestDigest !== request.requestDigest || turn.promptProjectionRef !== request.promptProjectionRef ||
      turn.promptProjectionDigest !== request.promptProjectionDigest || turn.responseDigest !== modelResponseDigest(turn)) {
    throw new TypeError('model turn does not match its prepared request');
  }
  verifyModelText(text);
  if (request.kind === 'context_compaction' && (turn.stopReason !== 'end' || turn.toolCalls.length !== 0 ||
      text.byteCount > Math.min(262_144, 3 * request.maximumOutputTokens))) {
    throw new TypeError('compaction requires a complete, bounded tools-disabled summary');
  }
  equal(turn.textRef, planCanonicalArtifact(text, text.format).ref, 'model text');
  if (turn.responseId !== undefined && (typeof turn.responseId !== 'string' || !turn.responseId || turn.responseId.includes('\0') ||
      Buffer.byteLength(turn.responseId) > 512)) throw new TypeError('model response id is invalid');
  if (turn.continuation && (!exactKeys(turn.continuation, ['provider', 'model', 'items']) || !Array.isArray(turn.continuation.items) ||
      turn.continuation.provider !== turn.provider || turn.continuation.model !== turn.model)) {
    throw new TypeError('continuation belongs to a different provider or model');
  }
  if (turn.usage !== undefined) {
    const fields = ['inputTokens', 'outputTokens', 'cacheReadTokens', 'cacheWriteTokens'] as const;
    if (!exactKeys(turn.usage, [...fields, 'costMicros']) || fields.some((key) => !Number.isSafeInteger(turn.usage![key]) ||
        turn.usage![key] < 0 || turn.usage![key] > request.reservation[key]) ||
        turn.usage.outputTokens > request.maximumOutputTokens || !Number.isSafeInteger(turn.usage.costMicros) ||
        turn.usage.costMicros < 0 || turn.usage.costMicros > request.reservation.costMicros) {
      throw new TypeError('model usage exceeds its retained request ceiling');
    }
  }
  if (turn.stopReason === 'cancelled') assertArtifactRef(turn.abortStopIntentRef);
  if ((turn.stopReason === 'tool_calls') !== (turn.toolCalls.length > 0) ||
      (turn.stopReason === 'end' && text.utf8.trim().length === 0) || inputs.length !== turn.toolCalls.length ||
      (turn.toolCalls.length > 0 && request.negotiatedMode !== 'native-tools')) {
    throw new TypeError('model turn has an invalid stop/call shape');
  }
  const ids = new Set<string>();
  turn.toolCalls.forEach((call, index) => {
    if (call.index !== index || typeof call.callId !== 'string' || !call.callId || ids.has(call.callId) ||
        call.callId.includes('\0') || Buffer.byteLength(call.callId) > 512 || typeof call.toolName !== 'string' ||
        call.toolName.includes('\0') || Buffer.byteLength(call.toolName) > 512) {
      throw new TypeError('model calls must have unique ids and contiguous indices');
    }
    ids.add(call.callId);
    const { value, observed } = inputs[index]!;
    const observedBytes = observed.encoding === 'jcs_json' ? canonicalJsonBytes(observed.value)
      : observed.encoding === 'utf8_json_fragment' ? Buffer.from(observed.utf8, 'utf8') : undefined;
    if (value.schemaVersion !== 1 || value.format !== 'cliq-tool-call-input-v1' ||
        !exactKeys(call, ['callId', 'index', 'toolName', 'inputRef', 'inputDigest']) ||
        !exactKeys(observed, ['schemaVersion', 'format', 'encoding', 'byteCount', 'observedInputDigest', observed.encoding === 'jcs_json' ? 'value' : 'utf8']) ||
        observedBytes === undefined || observedBytes.byteLength !== observed.byteCount || observed.byteCount > MODEL_RESPONSE_LIMIT_BYTES ||
        observed.schemaVersion !== 1 || observed.format !== 'cliq-observed-tool-call-input-v1' ||
        value.callId !== call.callId || value.index !== index || value.toolName !== call.toolName ||
        value.inputDigest !== call.inputDigest || digestOmitting(value, 'inputDigest') !== call.inputDigest ||
        planCanonicalArtifact(value, value.format).ref !== call.inputRef ||
        planCanonicalArtifact(observed, observed.format).ref !== value.observedInputRef ||
        digestOmitting(observed, 'observedInputDigest') !== value.observedInputDigest ||
        observed.observedInputDigest !== value.observedInputDigest) {
      throw new TypeError('tool input closure does not rehash or match its call');
    }
    const resolved = resolveToolInput({ callId: call.callId, index, toolName: call.toolName, observedInput: observed });
    const base = { schemaVersion: 1, format: 'cliq-tool-call-input-v1', callId: call.callId, index,
      toolName: call.toolName, observedInputRef: value.observedInputRef, observedInputDigest: value.observedInputDigest };
    const expected = resolved.kind === 'resolved'
      ? { ...base, disposition: 'resolved', inputSchemaRef: resolved.inputSchemaRef,
          inputSchemaDigest: resolved.inputSchemaDigest, value: resolved.value }
      : { ...base, disposition: resolved.kind === 'unknown_tool' ? 'rejected_unknown_tool' : 'rejected_invalid_input',
          ...(resolved.kind === 'invalid_input' ? { inputSchemaRef: resolved.inputSchemaRef, inputSchemaDigest: resolved.inputSchemaDigest } : {}),
          diagnosticRef: resolved.diagnostic.ref, diagnosticDigest: resolved.diagnosticDigest };
    equal(value, { ...expected, inputDigest: canonicalSha256(expected) }, 'normalized tool input');
  });
}

export type ModelContinuationPlan = {
  items: ContinuationItem[];
  artifacts: PlannedArtifact[];
  frontier?: RunFrontier;
  disposition: 'tool_batch' | 'batch_rejected' | 'candidate_required' | 'stop_required' | 'context_compacted';
};

/** Ordinary error projections are deliberately ref-free. Diagnostics remain separate audit artifacts. */
function rejectedResult(batch: ToolBatchItem, input: ToolCallInputV1, invalidCallIds: string[]): {
  item: ToolResultItem; artifacts: PlannedArtifact[];
} {
  const rejected = input.disposition !== 'resolved';
  const code = input.disposition === 'rejected_unknown_tool' ? 'TOOL_NOT_FOUND' : 'TOOL_INPUT_INVALID';
  const outcome = rejected ? 'error' as const : 'batch_not_executed' as const;
  const contentBase = { schemaVersion: 1 as const, format: 'cliq-tool-result-model-content-v1' as const,
    callId: input.callId, index: input.index, toolName: input.toolName, outcome,
    content: rejected ? { code } : { code: 'BATCH_REJECTED_BEFORE_DISPATCH', invalidCallIds } };
  const content: ToolResultModelContentV1 = { ...contentBase, contentDigest: canonicalSha256(contentBase) };
  const contentArtifact = planCanonicalArtifact(content, content.format);
  const base = { schemaVersion: 1 as const, format: 'cliq-tool-result-payload-v1' as const, runId: batch.runId,
    batchItemId: batch.itemId, callId: input.callId, index: input.index, toolName: input.toolName,
    modelContentRef: contentArtifact.ref, modelContentDigest: content.contentDigest };
  const payloadBase = rejected
    ? { ...base, outcome: 'error' as const, code, diagnosticRef: input.diagnosticRef!, diagnosticDigest: input.diagnosticDigest! }
    : { ...base, outcome: 'batch_not_executed' as const, code: 'BATCH_REJECTED_BEFORE_DISPATCH' as const, invalidCallIds };
  const payload = { ...payloadBase, payloadDigest: canonicalSha256(payloadBase) } as ToolResultPayloadV1;
  const result = planCanonicalArtifact(payload, payload.format);
  const item: ToolResultItem = { schemaVersion: 1, kind: 'tool_result',
    itemId: identityHash('cliq-tool-result-item-v1', batch.runId, batch.itemId, input.callId),
    runId: batch.runId, batchItemId: batch.itemId, callId: input.callId, index: input.index,
    outcome, resultRef: result.ref, createdAt: batch.createdAt };
  return { item, artifacts: [contentArtifact, result] };
}

/** The entire response is validated before this plan is made durable or any call can be selected. */
export function planModelContinuation(input: {
  request: ModelRequestV1; turnRef: string; material: ModelTurnMaterial;
  throughItemSeq: number; createdAt: string; resolveToolInput: ResolveToolInput;
}): ModelContinuationPlan {
  const { request, material: { turn, inputs }, turnRef, createdAt } = input;
  parseCanonicalTime(createdAt);
  validateModelTurn(request, input.material, input.resolveToolInput);
  equal(turnRef, planCanonicalArtifact(turn, turn.format).ref, 'model turn artifact');
  const modelItem: ModelTurnItem = { schemaVersion: 1, kind: 'model_turn', runId: request.runId,
    itemId: identityHash('cliq-model-turn-item-v1', request.runId, request.opId, String(request.attempt)),
    modelOpId: request.opId, modelAttempt: request.attempt, modelTurnRef: turnRef,
    stopReason: turn.stopReason, textRef: turn.textRef, createdAt,
    ...(turn.stopReason === 'cancelled' ? { abortStopIntentRef: turn.abortStopIntentRef } : {}) };
  const items: ContinuationItem[] = [modelItem];
  if (turn.stopReason !== 'tool_calls') return {
    items, artifacts: [], disposition: turn.stopReason === 'end' ? 'candidate_required' : 'stop_required'
  };
  const batch: ToolBatchItem = { schemaVersion: 1, kind: 'assistant_tool_batch', runId: request.runId,
    itemId: identityHash('cliq-tool-batch-item-v1', modelItem.itemId), modelOpId: request.opId,
    modelAttempt: request.attempt, modelTurnRef: turnRef, textRef: turn.textRef, calls: turn.toolCalls, createdAt };
  items.push(batch);
  const invalidCallIds = inputs.filter(({ value }) => value.disposition !== 'resolved').map(({ value }) => value.callId)
    .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  if (invalidCallIds.length === 0) return { items, artifacts: [], disposition: 'tool_batch', frontier: {
    schemaVersion: 1, kind: 'tool', batchItemId: batch.itemId,
    orderedCallIds: batch.calls.map((call) => call.callId), nextCallIndex: 0
  } };
  const artifacts: PlannedArtifact[] = [];
  for (const { value } of inputs) {
    const result = rejectedResult(batch, value, invalidCallIds);
    items.push(result.item);
    artifacts.push(...result.artifacts);
  }
  return { items, artifacts, disposition: 'batch_rejected', frontier: {
    schemaVersion: 1, kind: 'agent', phase: 'model_turn',
    turnId: identityHash('cliq-agent-turn-v1', request.runId, batch.itemId),
    contextItemSeq: input.throughItemSeq + items.length, cause: 'tool_batch_complete'
  } };
}
