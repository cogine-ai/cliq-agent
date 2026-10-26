// Pure immutable output planning only. This module neither grants permission
// nor changes SQL, generations, a lease or a native/broker operation.
import { planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireRecord } from '../kernel/control-wire-data.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { ChildMergeModelDiagnostic, ChildMergeResultItem } from '../kernel/children.js';
import type { SupervisorInspectorIdentityV1 } from '../kernel/types.js';
import type { readPreparedChildMergeAuthorization } from './child-merge-authorization.js';

type Facts = ReturnType<typeof readPreparedChildMergeAuthorization>;
export type ChildMergeOutcome = 'merged' | 'conflict' | 'resource_limit' | 'denied';
export type ChildMergeReceiptV1 = {
  schemaVersion: 1; format: 'cliq-child-merge-receipt-v1'; runId: string; opId: string; requestRef: string;
  mergeBatchItemId: string; callId: string; callIndex: number; parentRunSnapshotRef: string;
  sourceCheckpointId: string; originalWorkspaceStateRef: string; resultWorkspaceStateRef: string;
  outcome: ChildMergeOutcome; inspectorIdentityRef: string; inspectorIdentityDigest: string; preparedAt: string;
  detail: { kind: 'merged'; resultSourceRef: string; diffRef: string; summaryRef: string; noOp: boolean }
    | { kind: 'conflict'; conflictsRef: string }
    | { kind: 'resource_limit'; limit: { kind: string; observed: number; limit: number } }
    | { kind: 'denied'; policyDecisionItemRef: string };
  receiptDigest: string;
};
export const childMergeCheckpointId = (runId: string, opId: string) => identityHash('cliq-child-merge-checkpoint-v1', runId, opId);
export const childMergeDispatchId = (runId: string, opId: string, requestRef: string) =>
  identityHash('cliq-child-merge-dispatch-v1', runId, opId, requestRef);
export const childMergeIdempotencyKey = (opId: string, requestDigest: string) =>
  identityHash('cliq-child-merge-key-v1', opId, requestDigest);

/** Both the producer and strict historical reader reconstruct these bytes
 * from the complete original authorized B/S/A data, not a receipt's claims. */
export function planChildMergeEffect(input: Pick<Facts, 'source' | 'request' | 'requestRef' | 'decisionItemRef' | 'disposition'> & {
  parentRunSnapshotRef: string; inspector: SupervisorInspectorIdentityV1; preparedAt: string;
}) {
  const { source, request, requestRef, inspector, preparedAt } = input;
  const inspectorPlan = planCanonicalArtifact(inspector, inspector.format), extra: PlannedArtifact[] = [];
  let detail: ChildMergeReceiptV1['detail'], outcome: ChildMergeOutcome, workspaceStateRef = source.checkpoint.workspaceStateRef;
  if (input.disposition === 'deny') {
    outcome = 'denied'; detail = { kind: 'denied', policyDecisionItemRef: input.decisionItemRef };
  } else if (source.computation.kind === 'ready') {
    if (!source.workspaceStateRef) throw new TypeError('complete merge has no published logical workspace');
    outcome = 'merged'; workspaceStateRef = source.workspaceStateRef;
    detail = { kind: 'merged', resultSourceRef: source.computation.sourceRef, diffRef: source.computation.diffRef,
      summaryRef: source.computation.summaryRef, noOp: source.computation.noOp };
  } else if (source.computation.kind === 'conflict') {
    outcome = 'conflict';
    const conflicts = planCanonicalArtifact({ schemaVersion: 1, format: 'cliq-child-merge-conflicts-v1', runId: source.run.id,
      requestRef, conflicts: source.computation.conflicts }, 'cliq-child-merge-conflicts-v1');
    extra.push(conflicts); detail = { kind: 'conflict', conflictsRef: conflicts.ref };
  } else { outcome = 'resource_limit'; detail = { kind: 'resource_limit', limit: source.computation.limit }; }
  const core = { schemaVersion: 1 as const, format: 'cliq-child-merge-receipt-v1' as const, runId: source.run.id, opId: request.opId, requestRef,
    mergeBatchItemId: source.batch.itemId, callId: source.call.callId, callIndex: source.call.index,
    parentRunSnapshotRef: input.parentRunSnapshotRef, sourceCheckpointId: source.checkpoint.id,
    originalWorkspaceStateRef: source.checkpoint.workspaceStateRef, resultWorkspaceStateRef: workspaceStateRef,
    outcome, inspectorIdentityRef: inspectorPlan.ref, inspectorIdentityDigest: inspector.identityDigest, preparedAt, detail };
  const receipt: ChildMergeReceiptV1 = { ...core, receiptDigest: canonicalSha256(core) };
  const receiptPlan = planCanonicalArtifact(receipt, receipt.format);
  const item: ChildMergeResultItem = { schemaVersion: 1, kind: 'child_merge_result',
    itemId: identityHash('cliq-child-merge-result-item-v1', source.run.id, request.opId), runId: source.run.id,
    mergeBatchItemId: source.batch.itemId, callId: source.call.callId, callIndex: source.call.index,
    opId: request.opId, requestRef, policyDecisionItemRef: input.decisionItemRef, resultRef: receiptPlan.ref, outcome, createdAt: preparedAt };
  return { receipt, receiptPlan, item, workspaceStateRef, checkpointId: childMergeCheckpointId(source.run.id, request.opId),
    plans: [inspectorPlan, ...extra, receiptPlan] };
}

/** Deliberately ref-free. Complete conflict records remain in the immutable
 * audit closure; the bounded presentation reports when paths were omitted. */
export function childMergeDiagnostic(source: Facts['source'], items: readonly ChildMergeResultItem[]): ChildMergeModelDiagnostic {
  const last = items.at(-1); if (!last) throw new TypeError('merge diagnostic has no real outcome');
  const result: ChildMergeModelDiagnostic = { outcome: last.outcome, processedCalls: items.length,
    chargedCalls: items.filter(item => item.outcome !== 'denied').length,
    appliedCalls: items.filter(item => item.outcome === 'merged').length, unattemptedCalls: source.batch.calls.length - items.length };
  if (result.unattemptedCalls < 0) throw new TypeError('merge diagnostic exceeds its original fixed batch');
  if (last.outcome === 'conflict') {
    if (source.computation.kind !== 'conflict') throw new TypeError('conflict diagnostic differs from original complete merge');
    result.conflicts = { total: source.computation.conflicts.length, truncated: source.computation.conflicts.length > 32,
      paths: source.computation.conflicts.slice(0, 32).map(row => ({ ...('path' in row ? { path: row.path } : {}), reason: row.reason })) };
  } else if (last.outcome === 'resource_limit') {
    if (source.computation.kind !== 'limited') throw new TypeError('resource diagnostic differs from original complete merge');
    result.limit = source.computation.limit;
  }
  return result;
}

export function planChildMergeModelContent(runId: string, mergeBatchItemId: string, merge: ChildMergeModelDiagnostic) {
  const core = { schemaVersion: 1, format: 'cliq-child-merge-model-content-v1', runId, mergeBatchItemId, merge };
  return planCanonicalArtifact({ ...core, contentDigest: canonicalSha256(core) }, core.format);
}

/** Strict data decoder shared by context/history; no connection or authority. */
export function decodeChildMergeModelContent(value: unknown) {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'mergeBatchItemId', 'merge', 'contentDigest']),
    merge = controlWireRecord(data.merge, ['outcome', 'processedCalls', 'chargedCalls', 'appliedCalls', 'unattemptedCalls'], ['conflicts', 'limit']);
  if (!exactKeys(data, ['schemaVersion', 'format', 'runId', 'mergeBatchItemId', 'merge', 'contentDigest']) ||
      data.schemaVersion !== 1 || data.format !== 'cliq-child-merge-model-content-v1' ||
      typeof data.runId !== 'string' || !data.runId || typeof data.mergeBatchItemId !== 'string' || !data.mergeBatchItemId ||
      data.contentDigest !== digestOmitting(data, 'contentDigest')) throw new TypeError('invalid child merge model content');
  const outcome = merge.outcome;
  if (!['merged', 'conflict', 'resource_limit', 'denied'].includes(outcome as string) ||
      !exactKeys(merge, ['outcome', 'processedCalls', 'chargedCalls', 'appliedCalls', 'unattemptedCalls',
        ...(outcome === 'conflict' ? ['conflicts'] : outcome === 'resource_limit' ? ['limit'] : [])]))
    throw new TypeError('invalid child merge model diagnostic');
  for (const key of ['processedCalls', 'chargedCalls', 'appliedCalls', 'unattemptedCalls'])
    if (!Number.isSafeInteger(merge[key]) || (merge[key] as number) < 0 || (merge[key] as number) > 64) throw new TypeError('invalid child merge model counts');
  const processed = merge.processedCalls as number, charged = merge.chargedCalls as number, applied = merge.appliedCalls as number;
  if (!processed || processed + (merge.unattemptedCalls as number) > 64 ||
      (outcome === 'merged' ? applied !== processed || charged !== processed || merge.unattemptedCalls !== 0
        : applied !== processed - 1 || charged !== processed - (outcome === 'denied' ? 1 : 0)))
    throw new TypeError('child merge model counters disagree');
  if (outcome === 'conflict') {
    const conflict = controlWireRecord(merge.conflicts, ['total', 'truncated', 'paths']);
    if (!exactKeys(conflict, ['total', 'truncated', 'paths']) || !Number.isSafeInteger(conflict.total) || (conflict.total as number) < 1 ||
        !Array.isArray(conflict.paths) || conflict.paths.length !== Math.min(conflict.total as number, 32) ||
        conflict.truncated !== ((conflict.total as number) > 32)) throw new TypeError('invalid child merge conflict presentation');
    for (const value of conflict.paths) {
      const path = controlWireRecord(value, ['reason'], ['path']), graph = path.reason === 'merged_graph';
      if (!exactKeys(path, graph ? ['reason'] : ['path', 'reason']) ||
          !['merged_graph', 'add_add', 'delete_modify', 'type_or_mode', 'non_text', 'overlapping_text'].includes(path.reason as string) ||
          !graph && (typeof path.path !== 'string' || !path.path || Buffer.byteLength(path.path) > 4096))
        throw new TypeError('invalid child merge conflict path');
    }
  } else if (outcome === 'resource_limit') {
    const limit = controlWireRecord(merge.limit, ['kind', 'observed', 'limit']);
    if (!exactKeys(limit, ['kind', 'observed', 'limit']) ||
        !['changed_paths', 'changed_bytes', 'generation_bytes', 'single_file_bytes', 'merged_entries'].includes(limit.kind as string) ||
        !Number.isSafeInteger(limit.observed) || !Number.isSafeInteger(limit.limit) || (limit.limit as number) < 0 ||
        (limit.observed as number) <= (limit.limit as number)) throw new TypeError('invalid child merge resource diagnostic');
  }
  return data as unknown as { schemaVersion: 1; format: 'cliq-child-merge-model-content-v1'; runId: string;
    mergeBatchItemId: string; merge: ChildMergeModelDiagnostic; contentDigest: string };
}
