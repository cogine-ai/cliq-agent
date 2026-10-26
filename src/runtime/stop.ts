import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { assertArtifactRef, assertRequestId, identityHash, normalizeBoundedText, parseCanonicalTime } from '../kernel/identity.js';
import type { ContinuationItem, InvocationJournalEntry, Run, RunCancel, StopIntent, TerminalDetail, ToolBatchItem, ToolResultItem, ToolResultModelContentV1, ToolResultPayloadV1 } from '../kernel/types.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import { exactKeys } from '../policy/runtime-authority.js';

export type ResourceStopIntent = Extract<StopIntent, { origin: 'budget' } | { runtimeSubtype: 'context_compaction_failed' | 'context_window_exhausted' | 'result_source_limit_exceeded' | 'delivery_merge_limit_exceeded' }>;
export type ModelFailureStopIntent = Extract<StopIntent, { runtimeSubtype: 'runtime' }>;
export type VerifierStopIntent = Extract<StopIntent, { origin: 'verification' } | { origin: 'kernel_integrity'; reason: 'verifier_mutated_source' } |
  { origin: 'policy_deny'; subjectKind: 'verifier' }>;
export type DeliveryMergeStopIntent = Extract<StopIntent, { runtimeSubtype: 'delivery_merge_conflict' }>;
export type DeliveryPolicyStopIntent = Extract<StopIntent, { origin: 'policy_deny' }> & { subjectKind: 'delivery'; reason: 'runtime_failed' };
export type AgentStopIntent = Extract<StopIntent, { origin: 'user_cancel' | 'parent_cancel' | 'deadline' }> | ResourceStopIntent | ModelFailureStopIntent | VerifierStopIntent | DeliveryMergeStopIntent | DeliveryPolicyStopIntent;
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
  const identifier = (value: unknown) => typeof value === 'string' && normalizeBoundedText(value, 1, 256) === value;
  const fields = ['schemaVersion', 'runId', 'createdAt', 'origin', 'targetStatus', 'reason'];
  if (intent.origin === 'user_cancel') {
    fields.push('requestId', 'principalId');
    assertRequestId(intent.requestId);
    if (intent.targetStatus !== 'cancelled' || intent.reason !== 'cancelled_by_user' || !intent.principalId) throw new TypeError('invalid user cancellation');
  } else if (intent.origin === 'parent_cancel') {
    fields.push('sourceRunId', 'sourceStopIntentRef');
    if (intent.targetStatus !== 'cancelled' || intent.reason !== 'parent_cancelled' ||
        !identifier(intent.sourceRunId) || intent.sourceRunId !== run.parentRunId || intent.sourceRunId === run.id)
      throw new TypeError('parent cancellation differs from its immutable direct parent');
    assertArtifactRef(intent.sourceStopIntentRef);
  } else if (intent.origin === 'deadline') {
    fields.push('deadlineAt');
    if (intent.targetStatus !== 'failed' || intent.reason !== 'budget_exhausted' || intent.deadlineAt !== run.deadlineAt || intent.createdAt < run.deadlineAt) throw new TypeError('deadline stop precedes the immutable deadline');
  } else if (intent.origin === 'kernel_integrity') {
    fields.push('verifierOpId', 'integrityEvidenceRef', 'integrityEvidenceDigest');
    if (intent.targetStatus !== 'failed' || intent.reason !== 'verifier_mutated_source' || !identifier(intent.verifierOpId)) throw new TypeError('invalid verifier integrity stop');
    assertArtifactRef(intent.integrityEvidenceRef); assertArtifactRef(intent.integrityEvidenceDigest);
  } else if (intent.origin === 'verification') {
    fields.push('candidateItemId', 'verifierPlanRef');
    if (intent.targetStatus !== 'failed' || !['verification_failed', 'verifier_infrastructure_failed'].includes(intent.reason) ||
        !identifier(intent.candidateItemId)) throw new TypeError('invalid verification stop');
    assertArtifactRef(intent.verifierPlanRef);
  } else if (intent.origin === 'policy_deny') {
    fields.push('subjectKind', 'opId', 'policyChannelEvidenceRef', 'policyChannelEvidenceDigest');
    if (intent.targetStatus !== 'failed' || !identifier(intent.opId) ||
        !(intent.subjectKind === 'verifier' && intent.reason === 'verification_failed' ||
          intent.subjectKind === 'delivery' && intent.reason === 'runtime_failed'))
      throw new TypeError('invalid typed policy denial');
    assertArtifactRef(intent.policyChannelEvidenceRef); assertArtifactRef(intent.policyChannelEvidenceDigest);
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
        .some((n) => !Number.isSafeInteger(n) || n < 0)) throw new TypeError('invalid context exhaustion');
      if (intent.trigger === 'request_body_bytes') {
        fields.push('trigger', 'modelVisiblePromptDigest', 'requestBodyBytes', 'requestBodyLimitBytes');
        assertArtifactRef(intent.modelVisiblePromptDigest);
        if (intent.nextPromptTokens > intent.triggerThresholdTokens || intent.requestBodyLimitBytes !== 1_048_576 ||
            !Number.isSafeInteger(intent.requestBodyBytes) || intent.requestBodyBytes <= intent.requestBodyLimitBytes) throw new TypeError('invalid request body exhaustion');
      } else if (intent.nextPromptTokens <= intent.triggerThresholdTokens) throw new TypeError('invalid context exhaustion');
    } else if (intent.runtimeSubtype === 'result_source_limit_exceeded') {
      fields.push('sourceCheckpointId', 'workspaceStateRef', 'producingItemId', 'modelOpId', 'attempt', 'limitKind', 'observed', 'limit');
      assertArtifactRef(intent.workspaceStateRef);
      if ([intent.sourceCheckpointId, intent.producingItemId, intent.modelOpId].some(value =>
        typeof value !== 'string' || !value || value.includes('\0') || Buffer.byteLength(value) > 256) ||
          !['changed_paths', 'changed_bytes'].includes(intent.limitKind) ||
          [intent.attempt, intent.observed, intent.limit].some(value => !Number.isSafeInteger(value) || value < 0) || intent.observed <= intent.limit)
        throw new TypeError('invalid result source exhaustion');
    } else if (intent.runtimeSubtype === 'delivery_merge_limit_exceeded') {
      fields.push('sourceCheckpointId', 'workspaceStateRef', 'sourceRunResultRef', 'sourceBaseRef', 'sourceDesiredRef',
        'capturedWorkspaceRef', 'sourceProjectionRef', 'sandboxProfileRef', 'mergeAlgorithm', 'limitKind', 'observed', 'limit');
      for (const ref of [intent.workspaceStateRef, intent.sourceRunResultRef, intent.sourceBaseRef, intent.sourceDesiredRef,
        intent.capturedWorkspaceRef, intent.sourceProjectionRef, intent.sandboxProfileRef]) assertArtifactRef(ref);
      if (!identifier(intent.sourceCheckpointId) || intent.mergeAlgorithm !== 'cliq-diff3-v1' ||
          !['changed_paths', 'changed_bytes', 'generation_bytes', 'single_file_bytes', 'merged_entries'].includes(intent.limitKind) ||
          [intent.observed, intent.limit].some(value => !Number.isSafeInteger(value) || value < 0) || intent.observed <= intent.limit)
        throw new TypeError('invalid delivery merge exhaustion');
    } else if (intent.runtimeSubtype === 'delivery_merge_conflict') {
      fields.push('deliveryMergeConflictItemRef', 'conflictRef');
      assertArtifactRef(intent.deliveryMergeConflictItemRef); assertArtifactRef(intent.conflictRef);
    } else if (intent.runtimeSubtype === 'runtime') {
      fields.push('failingOpId', 'runtimeFailureRef', 'runtimeFailureDigest');
      assertArtifactRef(intent.runtimeFailureRef);
      assertArtifactRef(intent.runtimeFailureDigest);
      if (typeof intent.failingOpId !== 'string' || !intent.failingOpId) throw new TypeError('invalid failing operation');
    } else throw new TypeError('stop branch requires its owning evidence reducer');
  } else throw new TypeError('stop branch requires its owning evidence reducer');
  if (intent.registeredCheckpointId !== undefined || intent.registeredRunRevision !== undefined || intent.registeredJournalSeq !== undefined) {
    fields.push('registeredCheckpointId', 'registeredRunRevision', 'registeredJournalSeq');
    if (!identifier(intent.registeredCheckpointId) || !Number.isSafeInteger(intent.registeredRunRevision) || intent.registeredRunRevision! < 1 || intent.registeredRunRevision! >= run.revision || !Number.isSafeInteger(intent.registeredJournalSeq) || intent.registeredJournalSeq! < 0)
      throw new TypeError('invalid original Stop Checkpoint and revision');
  }
  if (intent.supersedesStopIntentRef !== undefined) { fields.push('supersedesStopIntentRef'); assertArtifactRef(intent.supersedesStopIntentRef); }
  parseCanonicalTime(intent.createdAt);
  if (!exactKeys(intent, fields) || intent.schemaVersion !== 1 || intent.runId !== run.id || intent.createdAt < run.createdAt || intent.createdAt > run.updatedAt) throw new TypeError('StopIntent differs from its Run');
  return intent;
}

export function agentStopDetail(intent: AgentStopIntent, stopIntentRef: string, createdAt: string): TerminalDetail {
  const reasonDetail: TerminalDetail['reasonDetail'] = intent.origin === 'kernel_integrity'
    ? { kind: 'verifier_source_mutation', verifierOpId: intent.verifierOpId,
        violationOrDigestEvidenceRef: intent.integrityEvidenceRef, violationOrDigestEvidenceDigest: intent.integrityEvidenceDigest }
    : intent.origin === 'verification'
      ? { kind: 'verification', candidateItemId: intent.candidateItemId, verifierPlanRef: intent.verifierPlanRef }
    : intent.origin === 'policy_deny'
      ? { kind: 'policy_denied', subjectKind: intent.subjectKind, opId: intent.opId,
          policyChannelEvidenceRef: intent.policyChannelEvidenceRef, policyChannelEvidenceDigest: intent.policyChannelEvidenceDigest }
    : intent.origin !== 'runtime'
    ? { kind: intent.origin === 'user_cancel' || intent.origin === 'parent_cancel' ? 'cancelled' : 'budget_exhausted',
        stopIntentRef: intent.origin === 'parent_cancel' ? intent.sourceStopIntentRef : stopIntentRef }
    : intent.runtimeSubtype === 'runtime'
      ? { kind: 'runtime', failingOpId: intent.failingOpId, runtimeFailureRef: intent.runtimeFailureRef, runtimeFailureDigest: intent.runtimeFailureDigest }
    : intent.runtimeSubtype === 'delivery_merge_conflict'
      ? { kind: 'delivery_merge_conflict', deliveryMergeConflictItemRef: intent.deliveryMergeConflictItemRef, conflictRef: intent.conflictRef }
    : intent.runtimeSubtype === 'context_compaction_failed'
      ? { kind: intent.runtimeSubtype, compactionPlanRef: intent.compactionPlanRef, modelOpId: intent.modelOpId, attempt: intent.attempt, evidenceRef: stopIntentRef }
    : intent.runtimeSubtype === 'result_source_limit_exceeded'
      ? { kind: intent.runtimeSubtype, sourceCheckpointId: intent.sourceCheckpointId, workspaceStateRef: intent.workspaceStateRef,
          producingItemId: intent.producingItemId, modelOpId: intent.modelOpId, attempt: intent.attempt,
          limitKind: intent.limitKind, observed: intent.observed, limit: intent.limit, evidenceRef: stopIntentRef }
    : intent.runtimeSubtype === 'delivery_merge_limit_exceeded'
      ? { kind: intent.runtimeSubtype, sourceCheckpointId: intent.sourceCheckpointId, workspaceStateRef: intent.workspaceStateRef,
          sourceRunResultRef: intent.sourceRunResultRef, sourceBaseRef: intent.sourceBaseRef, sourceDesiredRef: intent.sourceDesiredRef,
          capturedWorkspaceRef: intent.capturedWorkspaceRef, sourceProjectionRef: intent.sourceProjectionRef,
          sandboxProfileRef: intent.sandboxProfileRef, mergeAlgorithm: intent.mergeAlgorithm,
          limitKind: intent.limitKind, observed: intent.observed, limit: intent.limit, evidenceRef: stopIntentRef }
      : contextExhaustionDetail(intent, stopIntentRef);
  return { schemaVersion: 1, runId: intent.runId, reason: intent.reason,
    reasonDetail,
    primaryEvidenceRef: intent.origin === 'parent_cancel' ? intent.sourceStopIntentRef : intent.origin === 'kernel_integrity' ? intent.integrityEvidenceRef : intent.origin === 'policy_deny'
      ? intent.policyChannelEvidenceRef : intent.origin === 'runtime' && intent.runtimeSubtype === 'runtime' ? intent.runtimeFailureRef
      : stopIntentRef,
    publicationResultItemRefs: [], abandonedRetryInvocations: [], createdAt };
}

function contextExhaustionDetail(intent: Extract<AgentStopIntent, { runtimeSubtype: 'context_window_exhausted' }>, evidenceRef: string): TerminalDetail['reasonDetail'] {
  const detail = { kind: intent.runtimeSubtype, contextManifestRef: intent.contextManifestRef, nextPromptTokens: intent.nextPromptTokens,
    triggerThresholdTokens: intent.triggerThresholdTokens, hardPromptTokens: intent.hardPromptTokens,
    protectedTokens: intent.protectedTokens, sourceInputTokenCap: intent.sourceInputTokenCap, evidenceRef };
  return intent.trigger === 'request_body_bytes' ? { ...detail, trigger: intent.trigger,
    modelVisiblePromptDigest: intent.modelVisiblePromptDigest, requestBodyBytes: intent.requestBodyBytes,
    requestBodyLimitBytes: intent.requestBodyLimitBytes } : detail;
}

/** Integrity wins even after cancellation; the separate dispatch fence remains
 * monotonic. Equal precedence retains the first already committed fact. */
export function agentStopPriority(intent: AgentStopIntent): number {
  return intent.origin === 'kernel_integrity' ? 7 : intent.origin === 'user_cancel' ? 6 : intent.origin === 'parent_cancel' ? 5
    : intent.reason === 'budget_exhausted' ? 4 : intent.reason === 'verification_failed' ? 3 : intent.reason === 'verifier_infrastructure_failed' ? 2 : 1;
}
export function selectAgentStop(prior: AgentStopIntent | undefined, proposed: AgentStopIntent): AgentStopIntent {
  return prior && agentStopPriority(prior) >= agentStopPriority(proposed) ? prior : proposed;
}

/** Only the producer recording a new winner binds the actual preceding SQL
 * reference. Historical selection remains a pure precedence comparison. */
export function recordAgentStopPredecessor(intent: AgentStopIntent, priorRef: string | undefined, sourceCheckpointId?: string, sourceRunRevision?: number, registeredJournalSeq?: number): AgentStopIntent {
  if ((sourceCheckpointId === undefined) !== (sourceRunRevision === undefined) || (sourceCheckpointId === undefined) !== (registeredJournalSeq === undefined) ||
      registeredJournalSeq !== undefined && (!Number.isSafeInteger(registeredJournalSeq) || registeredJournalSeq < 0) || sourceRunRevision !== undefined &&
      (!Number.isSafeInteger(sourceRunRevision) || sourceRunRevision < 1)) throw new TypeError('Stop registration requires its exact Checkpoint/revision pair');
  if (intent.supersedesStopIntentRef !== undefined && intent.supersedesStopIntentRef !== priorRef)
    throw new TypeError('StopIntent replaced its exact original predecessor');
  if (intent.registeredCheckpointId !== undefined && intent.registeredCheckpointId !== sourceCheckpointId) throw new TypeError('StopIntent replaced its original Checkpoint');
  if (intent.registeredRunRevision !== undefined && intent.registeredRunRevision !== sourceRunRevision) throw new TypeError('StopIntent replaced its original Run revision');
  if (intent.registeredJournalSeq !== undefined && intent.registeredJournalSeq !== registeredJournalSeq) throw new TypeError('StopIntent replaced its original Journal high cut');
  return { ...intent, ...(priorRef === undefined ? {} : { supersedesStopIntentRef: priorRef }), ...(sourceCheckpointId === undefined ? {} : { registeredCheckpointId: sourceCheckpointId, registeredRunRevision: sourceRunRevision, registeredJournalSeq }) };
}

export function agentStopCause<T extends AgentStopIntent>(intent: T): Omit<T, 'supersedesStopIntentRef' | 'registeredCheckpointId' | 'registeredRunRevision' | 'registeredJournalSeq'> {
  const { supersedesStopIntentRef: _predecessor, registeredCheckpointId: _source, registeredRunRevision: _revision, registeredJournalSeq: _journal, ...cause } = intent;
  return cause;
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
    } else if (item.kind === 'final_candidate' || item.kind === 'verifier_result' || item.kind === 'verifier_stop' || item.kind === 'repair_diagnostic' ||
        item.kind === 'delivery_merge' || item.kind === 'delivery_merge_conflict' || item.kind === 'delivery_decision') {
      if (pending || model) throw new TypeError('candidate or verifier evidence overtakes an open batch');
    } else if (item.kind === 'child_handle') {
      if (!pending || pending.batch.itemId !== item.delegateBatchItemId || pending.next !== item.delegateCallIndex ||
          pending.batch.calls[pending.next]?.callId !== item.delegateCallId || pending.batch.calls[pending.next]?.toolName !== 'delegate')
        throw new TypeError('child handle overtakes its owning unresolved delegate call');
    } else if (item.kind === 'child_result' || item.kind === 'child_merge_batch' || item.kind === 'child_merge_result') {
      // Complete child history was independently validated by the owning
      // recovery cut. Audit records neither answer nor open a provider call.
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
