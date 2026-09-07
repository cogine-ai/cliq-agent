import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { assertArtifactRef, assertRequestId, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { ContinuationItem, InvocationJournalEntry, Run, RunCancel, StopIntent, TerminalDetail, ToolBatchItem, ToolResultItem, ToolResultModelContentV1, ToolResultPayloadV1 } from '../kernel/types.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import { exactKeys } from '../policy/runtime-authority.js';

export type ResourceStopIntent = Extract<StopIntent, { origin: 'budget' } | { runtimeSubtype: 'context_compaction_failed' | 'context_window_exhausted' }>;
export type ModelFailureStopIntent = Extract<StopIntent, { runtimeSubtype: 'runtime' }>;
export type AgentStopIntent = Extract<StopIntent, { origin: 'user_cancel' | 'deadline' }> | ResourceStopIntent | ModelFailureStopIntent;
export const stopCheckpointId = (runId: string, stopIntentRef: string) => identityHash('cliq-stop-checkpoint-v1', runId, stopIntentRef);

export function cancelRequestDigest(runId: string, input: RunCancel): string {
  assertRequestId(input.requestId);
  assertArtifactRef(input.channelIdentityRef);
  assertArtifactRef(input.channelIdentityDigest);
  if (!input.principalId || !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1) throw new TypeError('invalid cancellation identity or revision');
  return canonicalSha256({ protocolVersion: 1, requestId: input.requestId, method: 'run.cancel', runId, expectedRevision: input.expectedRunRevision });
}

/** Reject unsupported stop evidence, rather than interpreting a reason string as authority. */
export function decodeAgentStop(value: unknown, run: Run): AgentStopIntent {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new TypeError('invalid StopIntent');
  const intent = value as AgentStopIntent;
  const fields = ['schemaVersion', 'runId', 'createdAt', 'origin', 'targetStatus', 'reason'];
  if (intent.origin === 'user_cancel') {
    fields.push('requestId', 'principalId');
    assertRequestId(intent.requestId);
    if (intent.targetStatus !== 'cancelled' || intent.reason !== 'cancelled_by_user' || !intent.principalId) throw new TypeError('invalid user cancellation');
  } else if (intent.origin === 'deadline') {
    fields.push('deadlineAt');
    if (intent.targetStatus !== 'failed' || intent.reason !== 'budget_exhausted' || intent.deadlineAt !== run.deadlineAt || intent.createdAt < run.deadlineAt) throw new TypeError('deadline stop precedes the immutable deadline');
  } else if (intent.origin === 'budget') {
    fields.push('counter', 'ceiling', 'consumed', 'reserved', 'required');
    if (!['modelTokens', 'costMicros', 'toolCalls'].includes(intent.counter) ||
        [intent.ceiling, intent.consumed, intent.reserved, intent.required].some((n) => !Number.isSafeInteger(n) || n < 0) ||
        BigInt(intent.consumed) + BigInt(intent.reserved) + BigInt(intent.required) <= BigInt(intent.ceiling)) throw new TypeError('budget stop has no exhausted reservation');
    if (intent.targetStatus !== 'failed' || intent.reason !== 'budget_exhausted') throw new TypeError('invalid budget stop');
  } else if (intent.origin === 'runtime') {
    fields.push('runtimeSubtype');
    if (intent.targetStatus !== 'failed' || intent.reason !== 'runtime_failed') throw new TypeError('invalid runtime failure');
    if (intent.runtimeSubtype === 'context_compaction_failed') {
      fields.push('compactionPlanRef', 'modelOpId', 'attempt');
      assertArtifactRef(intent.compactionPlanRef);
      if (!intent.modelOpId || !Number.isSafeInteger(intent.attempt) || intent.attempt < 0) throw new TypeError('invalid failed compaction identity');
    } else if (intent.runtimeSubtype === 'context_window_exhausted') {
      fields.push('contextManifestRef', 'nextPromptTokens', 'triggerThresholdTokens', 'hardPromptTokens', 'protectedTokens', 'sourceInputTokenCap');
      assertArtifactRef(intent.contextManifestRef);
      if ([intent.nextPromptTokens, intent.triggerThresholdTokens, intent.hardPromptTokens, intent.protectedTokens, intent.sourceInputTokenCap]
        .some((n) => !Number.isSafeInteger(n) || n < 0) || intent.nextPromptTokens <= intent.triggerThresholdTokens) throw new TypeError('invalid context exhaustion');
    } else if (intent.runtimeSubtype === 'runtime') {
      fields.push('failingOpId', 'runtimeFailureRef', 'runtimeFailureDigest');
      assertArtifactRef(intent.runtimeFailureRef);
      assertArtifactRef(intent.runtimeFailureDigest);
      if (typeof intent.failingOpId !== 'string' || !intent.failingOpId) throw new TypeError('invalid failing operation');
    } else throw new TypeError('stop branch requires its owning evidence reducer');
  } else throw new TypeError('stop branch requires its owning evidence reducer');
  parseCanonicalTime(intent.createdAt);
  if (!exactKeys(intent, fields) || intent.schemaVersion !== 1 || intent.runId !== run.id || intent.createdAt < run.createdAt || intent.createdAt > run.updatedAt) throw new TypeError('StopIntent differs from its Run');
  return intent;
}

export function agentStopDetail(intent: AgentStopIntent, stopIntentRef: string, createdAt: string): TerminalDetail {
  const reasonDetail: TerminalDetail['reasonDetail'] = intent.origin !== 'runtime'
    ? { kind: intent.origin === 'user_cancel' ? 'cancelled' : 'budget_exhausted', stopIntentRef }
    : intent.runtimeSubtype === 'runtime'
      ? { kind: 'runtime', failingOpId: intent.failingOpId, runtimeFailureRef: intent.runtimeFailureRef, runtimeFailureDigest: intent.runtimeFailureDigest }
    : intent.runtimeSubtype === 'context_compaction_failed'
      ? { kind: intent.runtimeSubtype, compactionPlanRef: intent.compactionPlanRef, modelOpId: intent.modelOpId, attempt: intent.attempt, evidenceRef: stopIntentRef }
      : { kind: intent.runtimeSubtype, contextManifestRef: intent.contextManifestRef, nextPromptTokens: intent.nextPromptTokens,
          triggerThresholdTokens: intent.triggerThresholdTokens, hardPromptTokens: intent.hardPromptTokens,
          protectedTokens: intent.protectedTokens, sourceInputTokenCap: intent.sourceInputTokenCap, evidenceRef: stopIntentRef };
  return { schemaVersion: 1, runId: intent.runId, reason: intent.reason,
    reasonDetail,
    primaryEvidenceRef: intent.origin === 'runtime' && intent.runtimeSubtype === 'runtime' ? intent.runtimeFailureRef : stopIntentRef,
    publicationResultItemRefs: [], abandonedRetryInvocations: [], createdAt };
}

/** Equal precedence retains the first committed fact; supported resource stops cannot outrank cancellation. */
export function selectAgentStop(prior: AgentStopIntent | undefined, proposed: AgentStopIntent): AgentStopIntent {
  const priority = (intent: AgentStopIntent) => intent.origin === 'user_cancel' ? 3 : intent.origin === 'runtime' ? 1 : 2;
  return prior && priority(prior) >= priority(proposed) ? prior : proposed;
}

export function stopInvocationHistory(journal: readonly InvocationJournalEntry[]) {
  const attempts = new Map<string, { entry: InvocationJournalEntry; hasClaim: boolean }>();
  for (const entry of journal) {
    const key = `${entry.opId}:${entry.attempt}`;
    attempts.set(key, { entry, hasClaim: entry.phase === 'dispatch_claimed' || attempts.get(key)?.hasClaim === true });
  }
  return attempts;
}

/** One ordered prefix across the entire transcript, including the final unclosed batch. */
export function openStopBatch(items: readonly ContinuationItem[]): { batch: ToolBatchItem; next: number } | undefined {
  let pending: { batch: ToolBatchItem; next: number } | undefined;
  let model: Extract<ContinuationItem, { kind: 'model_turn' }> | undefined;
  for (const item of items) {
    if (item.kind === 'model_turn') {
      if (pending || model) throw new TypeError('model turn overtakes an open batch');
      if (item.stopReason === 'tool_calls') model = item;
    } else if (item.kind === 'assistant_tool_batch') {
      if (pending || !model || item.modelTurnRef !== model.modelTurnRef || item.calls.length === 0) throw new TypeError('tool batch has no matching model turn');
      pending = { batch: item, next: 0 };
      model = undefined;
    } else if (item.kind === 'tool_result') {
      if (!pending || item.batchItemId !== pending.batch.itemId || item.index !== pending.next || item.callId !== pending.batch.calls[pending.next]?.callId) throw new TypeError('stop transcript has a skipped or duplicate call result');
      if (++pending.next === pending.batch.calls.length) pending = undefined;
    } else if (item.kind === 'input_request' || item.kind === 'user_input') {
      if (!pending || item.batchItemId !== pending.batch.itemId || item.index !== pending.next || item.callId !== pending.batch.calls[pending.next]?.callId) throw new TypeError('input overtakes its result-less call');
    } else if (item.kind !== 'policy_decision' && item.kind !== 'context_compaction') throw new TypeError('unsupported stop transcript item');
  }
  if (model) throw new TypeError('model turn is missing its batch');
  return pending;
}

export function cancelledCall(batch: ToolBatchItem, index: number, stopIntentRef: string, createdAt: string) {
  const call = batch.calls[index]!;
  const utf8 = 'Run stopped before this call was dispatched.';
  const noticeCore = { schemaVersion: 1 as const, format: 'cliq-model-text-v1' as const, utf8, byteCount: Buffer.byteLength(utf8) };
  const notice: ModelTextV1 = { ...noticeCore, textDigest: canonicalSha256(noticeCore) };
  const noticePlan = planCanonicalArtifact(notice, notice.format);
  const modelCore = { schemaVersion: 1 as const, format: 'cliq-tool-result-model-content-v1' as const,
    callId: call.callId, index, toolName: call.toolName, outcome: 'cancelled' as const,
    content: { code: 'TOOL_CALL_CANCELLED', cancellationKind: 'undispatched_stop' } };
  const model: ToolResultModelContentV1 = { ...modelCore, contentDigest: canonicalSha256(modelCore) };
  const modelPlan = planCanonicalArtifact(model, model.format);
  const core = { schemaVersion: 1 as const, format: 'cliq-tool-result-payload-v1' as const, runId: batch.runId,
    batchItemId: batch.itemId, callId: call.callId, index, toolName: call.toolName, outcome: 'cancelled' as const,
    cancellationKind: 'undispatched_stop' as const, stopIntentRef, noticeRef: noticePlan.ref, noticeDigest: notice.textDigest,
    modelContentRef: modelPlan.ref, modelContentDigest: model.contentDigest };
  const payload: ToolResultPayloadV1 = { ...core, payloadDigest: canonicalSha256(core) };
  const result = planCanonicalArtifact(payload, payload.format);
  const item: ToolResultItem = { schemaVersion: 1, kind: 'tool_result',
    itemId: identityHash('cliq-tool-result-item-v1', batch.runId, batch.itemId, call.callId), runId: batch.runId,
    batchItemId: batch.itemId, callId: call.callId, index, outcome: 'cancelled', resultRef: result.ref, createdAt };
  return { item, artifacts: [noticePlan, modelPlan, result] };
}
