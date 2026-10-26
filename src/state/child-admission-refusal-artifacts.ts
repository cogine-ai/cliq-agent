// Pure no-child outcome planning. A receipt alone creates no child, allocation,
// capability, permission, physical dispatch or execution lease.
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { ChildAdmissionRefusalReason, ChildAdmissionRefusalRequestV1, ChildAdmissionRefusalReceiptV1 } from '../kernel/child-admission-refusal.js';
import type { BudgetSettlementV1, BudgetUsage, ChildAllocationV1, Run, SupervisorInspectorIdentityV1,
  ToolResultItem, ToolResultModelContentV1, ToolResultPayloadV1 } from '../kernel/types.js';
import type { ToolOperationGrantV1, ToolPolicyChannelEvidenceV1, ToolPolicyDecisionItem, ToolRequestV1, ToolTargetV1 } from '../kernel/tool-authorization.js';
import { addBudget } from './invariants.js';
import { ZERO_BUDGET } from './rows.js';

export const CHILD_ADMISSION_REFUSAL_COST = Object.freeze({ ...ZERO_BUDGET, toolCalls: 1 });
export const childAdmissionRefusalCheckpointId = (runId: string, opId: string) => identityHash('cliq-child-admission-refusal-checkpoint-v1', runId, opId);
export function planChildAdmissionRefusal(input: { parent: Run; allocations: readonly ChildAllocationV1[]; request: ToolRequestV1; target: ToolTargetV1;
  grant: ToolOperationGrantV1; evidence: ToolPolicyChannelEvidenceV1; inspector: SupervisorInspectorIdentityV1; preparedAt: string;
  reason: ChildAdmissionRefusalReason; continuationFloor: BudgetUsage; journalSeq: number }) {
  const { parent, request: toolRequest, grant, preparedAt } = input,
    parentPlan = planCanonicalArtifact(parent, 'cliq-run-snapshot-origin-v1'),
    allocationPlan = planCanonicalArtifact(input.allocations, 'cliq-child-allocation-snapshot-v1'),
    toolRequestPlan = planCanonicalArtifact(toolRequest, toolRequest.format), targetPlan = planCanonicalArtifact(input.target, input.target.format),
    grantPlan = planCanonicalArtifact(grant, grant.format), evidencePlan = planCanonicalArtifact(input.evidence, input.evidence.format),
    inspectorPlan = planCanonicalArtifact(input.inspector, input.inspector.format);
  const request: ChildAdmissionRefusalRequestV1 = { schemaVersion: 1, format: 'cliq-child-admission-refusal-request-v1', runId: parent.id,
    opId: toolRequest.opId, parentRunSnapshotRef: parentPlan.ref, parentChildAllocationsRef: allocationPlan.ref,
    sourceCheckpointId: parent.latestCheckpointId, toolRequestRef: toolRequestPlan.ref, delegateOperationGrantRef: grantPlan.ref,
    continuationFloor: input.continuationFloor, reason: input.reason, preparedAt, requestDigest: '' };
  request.requestDigest = digestOmitting(request, 'requestDigest');
  const requestPlan = planCanonicalArtifact(request, request.format), receipt: ChildAdmissionRefusalReceiptV1 = { schemaVersion: 1,
    format: 'cliq-child-admission-refusal-v1', runId: parent.id, opId: toolRequest.opId, requestRef: requestPlan.ref,
    reason: input.reason, inspectorIdentityRef: inspectorPlan.ref, inspectorIdentityDigest: input.inspector.identityDigest, preparedAt, receiptDigest: '' };
  receipt.receiptDigest = digestOmitting(receipt, 'receiptDigest');
  const receiptPlan = planCanonicalArtifact(receipt, receipt.format), consumed = addBudget(parent.budgetConsumed, CHILD_ADMISSION_REFUSAL_COST),
    settlement: BudgetSettlementV1 = { schemaVersion: 1, format: 'cliq-budget-settlement-v1', runId: parent.id, opId: toolRequest.opId, attempt: 0,
      preparedJournalSeq: input.journalSeq, terminalJournalSeq: input.journalSeq + 2, terminalPhase: 'completed', reserved: CHILD_ADMISSION_REFUSAL_COST,
      consumed: CHILD_ADMISSION_REFUSAL_COST, released: CHILD_ADMISSION_REFUSAL_COST, budgetConsumedBefore: parent.budgetConsumed,
      budgetConsumedAfter: consumed, budgetReservedBefore: addBudget(parent.budgetReserved, CHILD_ADMISSION_REFUSAL_COST),
      budgetReservedAfter: parent.budgetReserved, settledAt: preparedAt, settlementDigest: '' };
  settlement.settlementDigest = digestOmitting(settlement, 'settlementDigest');
  const settlementPlan = planCanonicalArtifact(settlement, settlement.format), modelCore = { schemaVersion: 1 as const,
    format: 'cliq-tool-result-model-content-v1' as const, callId: toolRequest.callId, index: toolRequest.callIndex, toolName: 'delegate',
    outcome: 'executed' as const, content: { schemaVersion: 1, status: 'not_admitted', reason: input.reason } },
    model: ToolResultModelContentV1 = { ...modelCore, contentDigest: canonicalSha256(modelCore) }, modelPlan = planCanonicalArtifact(model, model.format);
  const payload: ToolResultPayloadV1 = { schemaVersion: 1, format: 'cliq-tool-result-payload-v1', runId: parent.id,
    batchItemId: toolRequest.batchItemId, callId: toolRequest.callId, index: toolRequest.callIndex, toolName: 'delegate', outcome: 'executed',
    source: 'child_admission_refusal', opId: toolRequest.opId, journalResultRef: receiptPlan.ref, journalResultDigest: receipt.receiptDigest,
    modelContentRef: modelPlan.ref, modelContentDigest: model.contentDigest, payloadDigest: '' };
  payload.payloadDigest = digestOmitting(payload, 'payloadDigest');
  const payloadPlan = planCanonicalArtifact(payload, payload.format), item: ToolResultItem = { schemaVersion: 1, kind: 'tool_result',
    itemId: identityHash('cliq-tool-result-item-v1', parent.id, toolRequest.batchItemId, toolRequest.callId), runId: parent.id,
    batchItemId: toolRequest.batchItemId, callId: toolRequest.callId, index: toolRequest.callIndex, opId: toolRequest.opId,
    outcome: 'executed', resultRef: payloadPlan.ref, createdAt: preparedAt };
  const decision: ToolPolicyDecisionItem = { schemaVersion: 1, kind: 'policy_decision', subjectKind: 'tool_call',
    itemId: identityHash('cliq-tool-policy-item-v1', parent.id, toolRequest.opId, evidencePlan.ref), runId: parent.id, opId: toolRequest.opId,
    principalId: grant.principalId, decisionSource: 'direct_policy', decision: 'allow', decisionRef: evidencePlan.ref,
    policyChannelEvidenceRef: evidencePlan.ref, policyChannelEvidenceDigest: input.evidence.evidenceDigest, grantRef: grantPlan.ref, createdAt: input.evidence.evaluatedAt };
  return { request, requestPlan, receipt, receiptPlan, settlementPlan, consumed, item, payload, model, decision, grantPlan,
    plans: [parentPlan, allocationPlan, toolRequestPlan, targetPlan, grantPlan, evidencePlan, inspectorPlan, requestPlan, receiptPlan, settlementPlan, modelPlan, payloadPlan] };
}
