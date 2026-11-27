// Pure immutable accounting data. None of these artifacts is an execution,
// OperationGrant, worker lease, native proof or a child admission authority.
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { assertControlWireJson } from '../kernel/control-wire-data.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { ChildAwaitReceiptV1, ChildAwaitRequestV1, ChildAwaitTargetV1 } from '../kernel/child-await.js';
import type { BudgetSettlementV1, Run, SupervisorInspectorIdentityV1 } from '../kernel/types.js';
import { addBudget } from './invariants.js';
import { ZERO_BUDGET } from './rows.js';

export const CHILD_AWAIT_COST = Object.freeze({ ...ZERO_BUDGET, toolCalls: 1 });
export const childAwaitOpId = (runId: string, batchItemId: string, callId: string, callIndex: number, inputDigest: string) =>
  identityHash('cliq-child-await-operation-v1', runId, batchItemId, callId, String(callIndex), inputDigest);
export const childAwaitDispatchId = (runId: string, opId: string, requestRef: string) => identityHash('cliq-child-await-local-claim-v1', runId, opId, requestRef);
export const childAwaitIdempotencyKey = (runId: string, opId: string) => identityHash('cliq-child-await-registration-v1', runId, opId);

export function planChildAwaitRegistration(input: { run: Run; assemblyRef: string; execution: ChildAwaitTargetV1['execution'];
  batchItemId: string; callId: string; callIndex: number; inputRef: string; inputDigest: string; waitSetRef: string; checkpointId: string;
  journalSeq: number; inspector: SupervisorInspectorIdentityV1; preparedAt: string }) {
  assertControlWireJson(input);
  const { run, preparedAt } = input;
  if (input.execution.kind !== 'supervisor_control' || input.execution.handlerId !== 'await_children') throw new TypeError('await registration requires its fixed control identity');
  const opId = childAwaitOpId(run.id, input.batchItemId, input.callId, input.callIndex, input.inputDigest),
    runPlan = planCanonicalArtifact(run, 'cliq-child-await-parent-run-v1'), inspectorPlan = planCanonicalArtifact(input.inspector, input.inspector.format);
  const target: ChildAwaitTargetV1 = { schemaVersion: 1, format: 'cliq-child-await-target-v1', runId: run.id, assemblyRef: input.assemblyRef,
    execution: input.execution, targetDigest: '' };
  target.targetDigest = digestOmitting(target, 'targetDigest');
  const targetPlan = planCanonicalArtifact(target, target.format);
  const request: ChildAwaitRequestV1 = { schemaVersion: 1, format: 'cliq-child-await-request-v1', runId: run.id, opId,
    sourceCheckpointId: run.latestCheckpointId, parentRunSnapshotRef: runPlan.ref, assemblyRef: input.assemblyRef,
    batchItemId: input.batchItemId, callId: input.callId, callIndex: input.callIndex, inputRef: input.inputRef,
    inputDigest: input.inputDigest, waitSetRef: input.waitSetRef, targetRef: targetPlan.ref, preparedAt, requestDigest: '' };
  request.requestDigest = digestOmitting(request, 'requestDigest');
  const requestPlan = planCanonicalArtifact(request, request.format);
  const receipt: ChildAwaitReceiptV1 = { schemaVersion: 1, format: 'cliq-child-await-receipt-v1', runId: run.id, opId,
    requestRef: requestPlan.ref, waitSetRef: input.waitSetRef, checkpointId: input.checkpointId,
    inspectorIdentityRef: inspectorPlan.ref, inspectorIdentityDigest: input.inspector.identityDigest, preparedAt, receiptDigest: '' };
  receipt.receiptDigest = digestOmitting(receipt, 'receiptDigest');
  const receiptPlan = planCanonicalArtifact(receipt, receipt.format), consumed = addBudget(run.budgetConsumed, CHILD_AWAIT_COST);
  const settlement: BudgetSettlementV1 = { schemaVersion: 1, format: 'cliq-budget-settlement-v1', runId: run.id, opId, attempt: 0,
    preparedJournalSeq: input.journalSeq, terminalJournalSeq: input.journalSeq + 2, terminalPhase: 'completed',
    reserved: CHILD_AWAIT_COST, consumed: CHILD_AWAIT_COST, released: CHILD_AWAIT_COST, budgetConsumedBefore: run.budgetConsumed,
    budgetConsumedAfter: consumed, budgetReservedBefore: addBudget(run.budgetReserved, CHILD_AWAIT_COST), budgetReservedAfter: run.budgetReserved,
    settledAt: preparedAt, settlementDigest: '' };
  settlement.settlementDigest = digestOmitting(settlement, 'settlementDigest');
  const settlementPlan = planCanonicalArtifact(settlement, settlement.format);
  return { opId, target, targetPlan, request, requestPlan, receipt, receiptPlan, settlementPlan, consumed,
    plans: [runPlan, inspectorPlan, targetPlan, requestPlan, receiptPlan, settlementPlan] };
}
