import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { ChildMergeResultItem, ChildResultItem, ChildWaitSet, AwaitChildrenResult } from '../kernel/children.js';
import type { BudgetSettlementV1, ContinuationItem, Run, RunFrontier, ToolResultItem, ToolResultModelContentV1, ToolResultPayloadV1 } from '../kernel/types.js';
import type { ReleaseTrustKey } from '../policy/runtime-authority.js';
import { immutableSnapshot } from '../model/immutable.js';
import { prepareChildMergeAuthorization, readPreparedChildMergeAuthorization } from './child-merge-authorization.js';
import { childMergeCheckpointId, childMergeDiagnostic, childMergeDispatchId, childMergeIdempotencyKey, planChildMergeEffect, planChildMergeModelContent } from './child-merge-effect.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { planContinuationCommit } from './continuation-commit.js';
import { joinResourceOperations, KernelStorageError, stateOperation } from './errors.js';
import { addBudget, assertBudgetWithin } from './invariants.js';
import { appendInvocationJournalEntry, nextJournalSequence } from './repositories/journal.js';
import { readRun, ZERO_BUDGET } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import { readChildAwaitModelResult } from './child-await-model.js';

const COST = { ...ZERO_BUDGET, toolCalls: 1 };
const effectId = (runId: string, opId: string) => identityHash('cliq-child-merge-result-item-v1', runId, opId);
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', `child merge ${message}`); }

/** One ordinary parent continuation, no physical invocation or second runner.
 * A complete authorized CAS result and local Journal/accounting/frontier effect
 * become durable in the same transaction; there is no local UNKNOWN window. */
export const mergeChildResult = stateOperation('RECOVERY_REQUIRED', async (driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, input: { runId: string; expectedRunRevision: number; releaseKeys: readonly ReleaseTrustKey[] }, signal?: AbortSignal) => {
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const prepared = await prepareChildMergeAuthorization(driver, reads, owner, input, signal);
  if (prepared.disposition === 'waiting') return immutableSnapshot({ run: prepared.run });
  const facts = readPreparedChildMergeAuthorization(driver, owner, prepared.token);
  const { source, request } = facts, run = source.run, preparedAt = facts.preparedAt;
  const active = assertActiveStateOwner(driver, owner);
  const originalRun = planCanonicalArtifact(run, 'cliq-child-merge-parent-run-v1');
  const effect = planChildMergeEffect({ ...facts, parentRunSnapshotRef: originalRun.ref,
    inspector: supervisorInspectorIdentity(active), preparedAt });
  const prior = source.items.filter((row): row is typeof row & { item: ChildMergeResultItem } =>
    row.item.kind === 'child_merge_result' && row.item.mergeBatchItemId === source.batch.itemId).map(row => row.item);
  if (prior.length !== source.call.index || prior.some((item, index) => item.callIndex !== index || item.outcome !== 'merged'))
    invalid('current cursor is not the exact completed serial merge prefix');
  const outcomeItems = [...prior, effect.item], done = effect.item.outcome !== 'merged' || source.call.index + 1 === source.batch.calls.length;
  const items: ContinuationItem[] = [...(facts.appendDecisionItem ? [facts.decisionItem] : [])];
  const extra = [originalRun, ...effect.plans];
  let frontier: RunFrontier;
  if (done) {
    const results = source.batch.childResultItemIds.map(id => {
      const row = source.items.find(row => row.item.itemId === id)?.item;
      if (row?.kind !== 'child_result' || row.delivery.kind === 'stop_settlement') invalid('final merge lost an original model-visible child result');
      return row as ChildResultItem;
    });
    const first = source.resultItem;
    if (first.delivery.kind === 'stop_settlement' || !results.some(item => item.itemId === first.itemId && canonicalSha256(item) === canonicalSha256(first)))
      invalid('final merge has no exact original wait owner');
    const set = await reads.readCanonical<ChildWaitSet>(first.delivery.waitSetRef);
    const diagnostic = childMergeDiagnostic(source, outcomeItems);
    if (source.batch.resume.kind === 'await_tool') {
      const resume = source.batch.resume, batch = source.items.find(row => row.item.itemId === resume.batchItemId)?.item;
      if (batch?.kind !== 'assistant_tool_batch' || batch.calls[resume.callIndex]?.callId !== resume.callId)
        invalid('final merge substituted its real provider await call');
      const result: AwaitChildrenResult = await readChildAwaitModelResult(reads, results, diagnostic);
      const modelCore = { schemaVersion: 1 as const, format: 'cliq-tool-result-model-content-v1' as const,
        callId: resume.callId, index: resume.callIndex, toolName: 'await_children', outcome: 'executed' as const, content: result };
      const model: ToolResultModelContentV1 = { ...modelCore, contentDigest: canonicalSha256(modelCore) };
      const modelPlan = planCanonicalArtifact(model, model.format);
      const payload: ToolResultPayloadV1 = { schemaVersion: 1, format: 'cliq-tool-result-payload-v1', runId: run.id,
        batchItemId: resume.batchItemId, callId: resume.callId, index: resume.callIndex, toolName: 'await_children',
        outcome: 'executed', source: 'child_results', waitSetRef: first.delivery.waitSetRef,
        childResultItemRefs: results.map(item => canonicalSha256(item)), mergeResultItemRefs: outcomeItems.map(item => canonicalSha256(item)),
        modelContentRef: modelPlan.ref, modelContentDigest: model.contentDigest, payloadDigest: '' };
      payload.payloadDigest = digestOmitting(payload, 'payloadDigest');
      const payloadPlan = planCanonicalArtifact(payload, payload.format);
      const resultItem: ToolResultItem = { schemaVersion: 1, kind: 'tool_result',
        itemId: identityHash('cliq-tool-result-item-v1', run.id, resume.batchItemId, resume.callId), runId: run.id,
        batchItemId: resume.batchItemId, callId: resume.callId, index: resume.callIndex, outcome: 'executed', resultRef: payloadPlan.ref, createdAt: preparedAt };
      items.push(effect.item, resultItem); extra.push(modelPlan, payloadPlan);
      frontier = resume.callIndex + 1 < batch.calls.length
        ? { schemaVersion: 1, kind: 'tool', batchItemId: batch.itemId, orderedCallIds: batch.calls.map(call => call.callId), nextCallIndex: resume.callIndex + 1 }
        : { schemaVersion: 1, kind: 'agent', phase: 'model_turn', turnId: identityHash('cliq-agent-turn-v1', run.id, resume.batchItemId),
          contextItemSeq: source.context.throughItemSeq + items.length, cause: 'child_results' };
    } else {
      if (set.purpose.kind !== 'finalize_settlement' || set.purpose.modelTurnItemId !== source.batch.resume.modelTurnItemId)
        invalid('final merge substituted its original premature final owner');
      const modelPlan = planChildMergeModelContent(run.id, source.batch.itemId, diagnostic);
      effect.item.modelContentRef = modelPlan.ref; effect.item.modelContentDigest = canonicalSha256({
        schemaVersion: 1, format: 'cliq-child-merge-model-content-v1', runId: run.id, mergeBatchItemId: source.batch.itemId, merge: diagnostic });
      items.push(effect.item); extra.push(modelPlan);
      frontier = { schemaVersion: 1, kind: 'agent', phase: 'model_turn',
        turnId: identityHash('cliq-child-merged-results-turn-v1', run.id, source.batch.itemId),
        contextItemSeq: source.context.throughItemSeq + items.length, cause: 'child_results' };
    }
  } else {
    items.push(effect.item); frontier = { schemaVersion: 1, kind: 'tool', batchItemId: source.batch.itemId,
      orderedCallIds: source.batch.calls.map(call => call.callId), nextCallIndex: source.call.index + 1 };
  }
  const sequence = nextJournalSequence(driver, run.id), charged = facts.disposition === 'allow';
  const consumed = charged ? addBudget(run.budgetConsumed, COST) : run.budgetConsumed;
  assertBudgetWithin(consumed, run.budgetReserved, ZERO_BUDGET, source.spec.budgets);
  const settlement: BudgetSettlementV1 | undefined = charged ? { schemaVersion: 1, format: 'cliq-budget-settlement-v1',
    runId: run.id, opId: request.opId, attempt: 0, preparedJournalSeq: sequence, terminalJournalSeq: sequence + 2, terminalPhase: 'completed',
    reserved: COST, consumed: COST, released: COST, budgetConsumedBefore: run.budgetConsumed, budgetConsumedAfter: consumed,
    budgetReservedBefore: addBudget(run.budgetReserved, COST), budgetReservedAfter: run.budgetReserved, settledAt: preparedAt, settlementDigest: '' } : undefined;
  const settlementPlan = settlement && (() => { settlement.settlementDigest = digestOmitting(settlement, 'settlementDigest'); return planCanonicalArtifact(settlement, settlement.format); })();
  if (settlementPlan) extra.push(settlementPlan);
  const graph = planContinuationCommit(reads, { context: source.context, existingItems: source.items, items, frontier,
    checkpointId: childMergeCheckpointId(run.id, request.opId), workspaceStateRef: effect.workspaceStateRef });
  const metadata = await joinResourceOperations(extra.map(plan => reads.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind)));
  const continuation = await graph.publish(); reads.assertReadActive();
  let outcome: TimeFenceAdvance | undefined, updated!: Run;
  driver.transaction(connection => {
    signal?.throwIfAborted(); assertActiveStateOwner(connection, owner);
    let now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
    for (const artifact of [...facts.metadata, ...metadata, ...continuation.metadata]) insertArtifactMetadata(connection, artifact, preparedAt);
    now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
    facts.assertCommit(connection, now); // Final authority/currentness gate; no await follows.
    assertBudgetWithin(consumed, run.budgetReserved, ZERO_BUDGET, source.spec.budgets);
    if (charged) {
      const common = { runId: run.id, opId: request.opId, opKind: 'child_merge' as const, attempt: 0, leaseEpoch: 0,
        target: request.targetRef, requestRef: facts.requestRef, replayClass: 'retry' as const,
        idempotencyKey: childMergeIdempotencyKey(request.opId, request.requestDigest), grantRef: facts.grantRef!,
        timestamp: preparedAt, localCommittedAt: now };
      const claim = { dispatchId: childMergeDispatchId(run.id, request.opId, facts.requestRef),
        stateOwnerEpoch: owner.ownerEpoch, supervisorInstanceId: owner.supervisorInstanceId };
      appendInvocationJournalEntry(connection, { ...common, seq: sequence, phase: 'prepared', budgetDelta: COST });
      appendInvocationJournalEntry(connection, { ...common, ...claim, seq: sequence + 1, phase: 'dispatch_claimed', budgetDelta: ZERO_BUDGET });
      appendInvocationJournalEntry(connection, { ...common, ...claim, seq: sequence + 2, phase: 'completed',
        budgetDelta: COST, resultRef: effect.receiptPlan.ref, budgetSettlementRef: settlementPlan!.ref });
    }
    graph.commit(connection, run, charged ? sequence + 2 : source.journal.length, now);
    connection.prepare("UPDATE runs SET status='queued',waiting_reason=NULL,waiting_on_ref=NULL,budget_consumed_json=?,revision=revision+1,updated_at=? WHERE id=?")
      .run(JSON.stringify(consumed), now, run.id);
    updated = readRun(connection, run.id); appendRunStateEvent(connection, updated, now);
  });
  requireHealthyFence(outcome); return immutableSnapshot({ run: updated, itemId: effectId(run.id, request.opId) });
});
