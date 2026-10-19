import { canonicalSha256 } from '../kernel/canonical.js';
import type { DeliveryApprovalDecisionV1, DeliveryApprovalWait, DeliveryPlanGrantV1, DeliveryPolicyChannelEvidenceV1,
  DeliveryRequestV1, DeliveryTargetV1, PublicationMaintenanceAuthorityV1, PublicationPathGrantV1, PublicationPathRequestV1 } from '../kernel/delivery-invocation.js';
import { assertArtifactRef, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { decodeDeliveryPlan, type DeliveryPlan } from '../kernel/publication.js';
import type { DeliveryDecisionItem } from '../kernel/delivery.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import type { RunAssemblyV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { assertRunPolicySnapshot, evaluateFrozenPolicyKey } from '../policy/tool-policy.js';
import { toolApprovalRequestDigest, type ToolApprovalInput } from '../policy/tool-approval.js';

export type DeliveryRequestContext = {
  runId: string; frontierRef: string; assemblyRef: string; planRef: string; plan: DeliveryPlan;
  workspaceIdentityRef: string; workspaceIdentityDigest: string;
};
export const deliveryApprovalOperationId = (runId: string, planRef: string) =>
  identityHash('cliq-delivery-approval-operation-v1', runId, planRef);
export const deliveryDecisionCheckpointId = (runId: string, planRef: string, decisionRef: string) =>
  identityHash('cliq-delivery-decision-checkpoint-v1', runId, planRef, decisionRef);
export const deliveryApprovalCheckpointId = (waitingOnRef: string) => identityHash('cliq-delivery-approval-checkpoint-v1', waitingOnRef);

/** Delivery approval authorizes a complete immutable plan through the Run's
 * absolute deadline, not a stale path frontier or a renewable execution TTL. */
export function deliveryApprovalDecision(wait: DeliveryApprovalWait, input: ToolApprovalInput,
  createdAt: string, deadlineAt: string): DeliveryApprovalDecisionV1 {
  const requestDigest = toolApprovalRequestDigest(wait.runId, input);
  for (const ref of [input.channelIdentityRef, input.channelIdentityDigest]) assertArtifactRef(ref);
  if (input.waitingOnRef !== canonicalSha256(wait) || input.expectedRunRevision !== wait.createdFromRevision + 1 ||
      parseCanonicalTime(createdAt) < parseCanonicalTime(wait.createdAt) || parseCanonicalTime(createdAt) >= parseCanonicalTime(deadlineAt))
    throw new TypeError('delivery approval does not match its exact current wait and lifetime');
  const core = { schemaVersion: 1 as const, format: 'cliq-approval-decision-v1' as const,
    decisionId: identityHash(input.principalId, wait.runId, input.waitingOnRef, input.requestId, requestDigest),
    principalId: input.principalId, channelIdentityRef: input.channelIdentityRef, channelIdentityDigest: input.channelIdentityDigest,
    runId: wait.runId, waitingSubjectRef: input.waitingOnRef, waitingSubjectDigest: canonicalSha256(wait), frontierRef: wait.frontierRef,
    subject: wait.subject, subjectDigest: canonicalSha256(wait.subject), requestId: input.requestId, requestDigest,
    expectedRunRevision: input.expectedRunRevision, decision: input.decision,
    ...(input.ttlMs === undefined ? {} : { requestedTtlMs: input.ttlMs }),
    ...(input.decision === 'deny' ? {} : { grantExpiresAt: deadlineAt }), createdAt };
  return immutableSnapshot({ ...core, decisionDigest: canonicalSha256(core) });
}

/** Fresh per-frontier child data only. The actual owner still verifies the
 * parent's committed decision/control graph and both native release gates. */
type PublicationDerivationInput = {
  context: DeliveryRequestContext; parent: DeliveryPlanGrantV1; parentRef: string; decision: DeliveryDecisionItem;
  sequence: 'forward' | 'abort'; operationIndex: number; issuedAt: string;
};
function publicationDerivation(input: PublicationDerivationInput) {
  const { context, parent, parentRef, decision, sequence, operationIndex, issuedAt } = immutableSnapshot(input);
  const { target: approvalTarget } = planDeliveryRequest(context);
  const operation = (sequence === 'forward' ? context.plan.forwardOperations : context.plan.abortOperations)[operationIndex];
  if (!operation || operation.index !== operationIndex || canonicalSha256(parent) !== parentRef || parent.maxDispatchedAttempts !== 0 ||
      parent.runId !== context.runId || parent.subject.kind !== 'delivery_plan' || parent.subject.deliveryPlanRef !== context.planRef ||
      parent.subject.deliveryPlanDigest !== approvalTarget.deliveryPlanDigest || parent.subject.operationSetDigest !== approvalTarget.operationSetDigest ||
      decision.runId !== context.runId || decision.decision !== 'allow' || decision.deliveryPlanRef !== context.planRef ||
      decision.grantRef !== parentRef || decision.approvalOpId !== parent.opId || decision.createdAt !== parent.issuedAt ||
      parseCanonicalTime(issuedAt) < parseCanonicalTime(parent.issuedAt))
    throw new TypeError('publication derivation requires its exact approved immutable plan and current operation');
  const operationDigest = canonicalSha256(operation);
  const targetCore = { schemaVersion: 1 as const, format: 'cliq-publication-path-target-v1' as const, runId: context.runId,
    workspaceIdentityRef: context.workspaceIdentityRef, workspaceIdentityDigest: context.workspaceIdentityDigest,
    deliveryPlanRef: context.planRef, sequence, operationIndex, operationId: operation.operationId, operationDigest };
  const target = { ...targetCore, targetDigest: canonicalSha256(targetCore) };
  const requestCore = { schemaVersion: 1 as const, format: 'cliq-publication-path-request-v1' as const, runId: context.runId,
    opId: identityHash('cliq-publication-operation-v1', context.runId, context.planRef, sequence, String(operationIndex), operation.operationId),
    assemblyRef: context.assemblyRef, frontierRef: context.frontierRef, deliveryPlanRef: context.planRef, sequence, operationIndex,
    operationId: operation.operationId, operationDigest, targetRef: canonicalSha256(target), targetDigest: target.targetDigest };
  const request: PublicationPathRequestV1 = { ...requestCore, requestDigest: canonicalSha256(requestCore) };
  return { context, parent, parentRef, decision, sequence, operationIndex, issuedAt, operation, operationDigest, request, target };
}

export function derivePublicationGrant(input: PublicationDerivationInput) {
  if (!exactKeys(input, ['context', 'parent', 'parentRef', 'decision', 'sequence', 'operationIndex', 'issuedAt']))
    throw new TypeError('productive publication accepts only its exact frozen derivation');
  const { context, parent, parentRef, decision, sequence, operationIndex, issuedAt, operation, operationDigest, request, target } = publicationDerivation(input);
  if (sequence !== 'forward' || operation.kind === 'abort_rmdir' || parseCanonicalTime(issuedAt) >= parseCanonicalTime(parent.expiresAt))
    throw new TypeError('productive publication cannot perform abort maintenance or extend its parent lifetime');
  const subject: PublicationPathGrantV1['subject'] = { kind: 'publication_path', deliveryPlanRef: context.planRef,
    sequence, operationIndex, operationId: operation.operationId, operationDigest };
  const core = { schemaVersion: 1 as const, format: 'cliq-operation-grant-v1' as const,
    grantId: identityHash('cliq-operation-grant-v1', context.runId, request.opId, request.requestDigest, subject, issuedAt),
    principalId: parent.principalId, runId: context.runId, policyRef: parent.policyRef, frontierRef: context.frontierRef,
    opId: request.opId, requestRef: canonicalSha256(request), requestDigest: request.requestDigest,
    targetRef: request.targetRef, targetDigest: target.targetDigest, subject,
    provenance: { kind: 'delivery_plan_derivation' as const, planAuthorizationGrantRef: parentRef, deliveryDecisionItemId: decision.itemId },
    maxDispatchedAttempts: 1, issuedAt, expiresAt: parent.expiresAt };
  const grant: PublicationPathGrantV1 = { ...core, grantDigest: canonicalSha256(core) };
  return immutableSnapshot({ operation, request, target, grant });
}

/** Closed retained-data projection only. No expiry extension, worker lease or
 * productive action is inferred from an old plan authorization. Live gates
 * independently prove Stop, original completed creator, prefix and emptiness. */
export function derivePublicationMaintenance(input: Omit<PublicationDerivationInput, 'sequence'> & {
  stopIntentRef: string; creatorReceiptRef: string;
}) {
  if (!exactKeys(input, ['context', 'parent', 'parentRef', 'decision', 'operationIndex', 'issuedAt', 'stopIntentRef', 'creatorReceiptRef']))
    throw new TypeError('publication maintenance accepts only its exact frozen derivation');
  input = immutableSnapshot(input);
  const { stopIntentRef, creatorReceiptRef, ...base } = input;
  assertArtifactRef(stopIntentRef); assertArtifactRef(creatorReceiptRef);
  const { context, parent, parentRef, decision, operationIndex, issuedAt, operation, operationDigest, request, target } =
    publicationDerivation({ ...base, sequence: 'abort' });
  if (operation.kind !== 'abort_rmdir') throw new TypeError('maintenance permits only the exact abort directory operation');
  const creator = context.plan.forwardOperations.find(candidate => candidate.operationId === operation.createdByOperationId);
  if (!creator || creator.path !== operation.path || (creator.kind !== 'mkdir' &&
      !(creator.kind === 'replace' && creator.desired.kind === 'directory')))
    throw new TypeError('maintenance lost its original planned directory creator');
  const subject: PublicationMaintenanceAuthorityV1['subject'] = { kind: 'publication_abort_maintenance',
    deliveryPlanRef: context.planRef, operationIndex, operationId: operation.operationId, operationDigest,
    createdByOperationId: creator.operationId, creatorReceiptRef, stopIntentRef };
  const core = { schemaVersion: 1 as const, format: 'cliq-publication-maintenance-authority-v1' as const,
    authorityId: identityHash('cliq-publication-maintenance-authority-v1', context.runId, request.opId,
      request.requestDigest, parentRef, decision.itemId, stopIntentRef, creatorReceiptRef, issuedAt),
    principalId: parent.principalId, runId: context.runId, policyRef: parent.policyRef, frontierRef: context.frontierRef,
    opId: request.opId, requestRef: canonicalSha256(request), requestDigest: request.requestDigest,
    targetRef: request.targetRef, targetDigest: target.targetDigest, subject,
    provenance: { kind: 'delivery_plan_maintenance' as const, planAuthorizationGrantRef: parentRef, deliveryDecisionItemId: decision.itemId },
    maxDispatchedAttempts: 1 as const, issuedAt };
  const grant: PublicationMaintenanceAuthorityV1 = { ...core, authorityDigest: canonicalSha256(core) };
  return immutableSnapshot({ operation, request, target, grant });
}

/** Fixed pure-data composition, not an approval or proof of publication. The
 * operation-set digest covers both immutable forward and abort sequences. */
export function planDeliveryRequest(input: DeliveryRequestContext) {
  const plan = decodeDeliveryPlan(input.plan);
  for (const ref of [input.frontierRef, input.assemblyRef, input.planRef, input.workspaceIdentityRef, input.workspaceIdentityDigest]) assertArtifactRef(ref);
  if (plan.deliveryRunId !== input.runId || canonicalSha256(plan) !== input.planRef)
    throw new TypeError('delivery permission selects a different complete plan');
  const operationSetDigest = canonicalSha256({ forwardOperations: plan.forwardOperations, abortOperations: plan.abortOperations });
  const core = { schemaVersion: 1 as const, format: 'cliq-delivery-target-v1' as const, runId: input.runId,
    workspaceIdentityRef: input.workspaceIdentityRef, workspaceIdentityDigest: input.workspaceIdentityDigest,
    deliveryPlanRef: input.planRef, deliveryPlanDigest: input.planRef, operationSetDigest };
  const target: DeliveryTargetV1 = { ...core, targetDigest: canonicalSha256(core) };
  const requestCore = { schemaVersion: 1 as const, format: 'cliq-delivery-request-v1' as const, runId: input.runId,
    opId: deliveryApprovalOperationId(input.runId, input.planRef), assemblyRef: input.assemblyRef, frontierRef: input.frontierRef,
    targetRef: canonicalSha256(target), targetDigest: target.targetDigest };
  const request: DeliveryRequestV1 = { ...requestCore, requestDigest: canonicalSha256(requestCore) };
  return immutableSnapshot({ request, target });
}

/** Delivery shares the same frozen named-action rule precedence as verifier
 * and tool permission. Workspace Trust and source verification are independent. */
export function loadDeliveryPolicy(input: {
  policy: RunPolicySnapshotV1; policyRef: string; assembly: RunAssemblyV1; assemblyRef: string;
  principalId: string; workspaceIdentityDigest: string; context: DeliveryRequestContext;
}) {
  const { policy, policyRef, assembly, assemblyRef, principalId, workspaceIdentityDigest, context } = immutableSnapshot(input);
  assertRunPolicySnapshot({ policy, policyRef, assembly, principalId, workspaceIdentityDigest });
  if (context.assemblyRef !== assemblyRef || context.workspaceIdentityDigest !== workspaceIdentityDigest)
    throw new TypeError('delivery policy differs from its original assembly or workspace');
  const planned = planDeliveryRequest(context);
  function evaluate(request: DeliveryRequestV1, target: DeliveryTargetV1, evaluatedAt: string): DeliveryPolicyChannelEvidenceV1 {
    parseCanonicalTime(evaluatedAt);
    if (evaluatedAt < policy.createdAt) throw new TypeError('delivery policy observation precedes its snapshot');
    requireEqual(request, planned.request, 'delivery approval request'); requireEqual(target, planned.target, 'delivery approval target');
    const identityKey = `delivery/${target.operationSetDigest}`;
    const winning = evaluateFrozenPolicyKey(policy, 'delivery', 'named-action', identityKey);
    const core = { schemaVersion: 1 as const, format: 'cliq-policy-channel-evidence-v1' as const, principalId, runId: request.runId,
      policyRef, policyDigest: policy.policyDigest, frontierRef: request.frontierRef, opId: request.opId,
      requestRef: canonicalSha256(request), requestDigest: request.requestDigest, targetRef: request.targetRef, targetDigest: request.targetDigest,
      actionClass: 'delivery' as const, decisionSource: winning.ruleId === undefined ? 'mode_fallthrough' as const : 'rule' as const,
      matchedRuleIds: winning.ruleId === undefined ? [] : [winning.ruleId], effectiveDisposition: winning.disposition,
      evaluatedAt, channel: 'named-action' as const, namedAction: { kind: 'delivery' as const,
        deliveryPlanRef: target.deliveryPlanRef, operationSetDigest: target.operationSetDigest }, identityKey };
    return immutableSnapshot({ ...core, evidenceDigest: canonicalSha256(core) });
  }
  function grant(request: DeliveryRequestV1, target: DeliveryTargetV1, evidence: DeliveryPolicyChannelEvidenceV1,
    issuedAt: string, deadlineAt: string): DeliveryPlanGrantV1 {
    requireEqual(evidence, evaluate(request, target, evidence.evaluatedAt), 'delivery policy evidence');
    if (evidence.effectiveDisposition !== 'allow' || parseCanonicalTime(issuedAt) < parseCanonicalTime(evidence.evaluatedAt) ||
        parseCanonicalTime(deadlineAt) <= parseCanonicalTime(issuedAt)) throw new TypeError('delivery parent requires the exact allow and Run lifetime');
    const decision = { policyRef, channelEvidenceRef: canonicalSha256(evidence), channelEvidenceDigest: evidence.evidenceDigest,
      actionClass: 'delivery' as const, requestDigest: request.requestDigest, targetDigest: target.targetDigest,
      matchedRuleIds: evidence.matchedRuleIds, effectiveDisposition: 'allow' as const };
    const subject: DeliveryPlanGrantV1['subject'] = { kind: 'delivery_plan', deliveryPlanRef: target.deliveryPlanRef,
      deliveryPlanDigest: target.deliveryPlanDigest, operationSetDigest: target.operationSetDigest };
    const core = { schemaVersion: 1 as const, format: 'cliq-operation-grant-v1' as const,
      grantId: identityHash('cliq-operation-grant-v1', request.runId, request.opId, request.requestDigest, subject, issuedAt),
      principalId, runId: request.runId, policyRef, frontierRef: request.frontierRef, opId: request.opId,
      requestRef: canonicalSha256(request), requestDigest: request.requestDigest, targetRef: request.targetRef, targetDigest: target.targetDigest,
      subject, provenance: { kind: 'policy_snapshot' as const, actionClass: 'delivery' as const,
      channelEvidenceRef: decision.channelEvidenceRef, channelEvidenceDigest: decision.channelEvidenceDigest,
      matchedRuleIds: evidence.matchedRuleIds, effectiveDisposition: 'allow' as const, decisionDigest: canonicalSha256(decision) },
      maxDispatchedAttempts: 0, issuedAt, expiresAt: deadlineAt };
    return immutableSnapshot({ ...core, grantDigest: canonicalSha256(core) });
  }
  function approvalWait(request: DeliveryRequestV1, target: DeliveryTargetV1, evidence: DeliveryPolicyChannelEvidenceV1,
    createdFromRevision: number): DeliveryApprovalWait {
    requireEqual(evidence, evaluate(request, target, evidence.evaluatedAt), 'delivery ask evidence');
    if (evidence.effectiveDisposition !== 'ask' || !Number.isSafeInteger(createdFromRevision) || createdFromRevision < 1)
      throw new TypeError('only an exact ask can create the current delivery wait');
    return immutableSnapshot({ schemaVersion: 1, kind: 'approval', runId: request.runId, createdFromRevision,
      createdAt: evidence.evaluatedAt, frontierRef: request.frontierRef, subject: { kind: 'delivery_plan',
        deliveryPlanRef: target.deliveryPlanRef, deliveryPlanDigest: target.deliveryPlanDigest, operationSetDigest: target.operationSetDigest,
        opId: request.opId, policyChannelEvidenceRef: canonicalSha256(evidence), policyChannelEvidenceDigest: evidence.evidenceDigest } });
  }
  function approve(request: DeliveryRequestV1, target: DeliveryTargetV1, evidence: DeliveryPolicyChannelEvidenceV1,
    wait: DeliveryApprovalWait, decision: DeliveryApprovalDecisionV1, deadlineAt: string): DeliveryPlanGrantV1 | undefined {
    requireEqual(wait, approvalWait(request, target, evidence, wait.createdFromRevision), 'delivery original ask wait');
    if (decision.principalId !== principalId) throw new TypeError('delivery decision has a different principal');
    const expected = deliveryApprovalDecision(wait, { principalId, channelIdentityRef: decision.channelIdentityRef,
      channelIdentityDigest: decision.channelIdentityDigest, requestId: decision.requestId,
      expectedRunRevision: decision.expectedRunRevision, waitingOnRef: decision.waitingSubjectRef, decision: decision.decision,
      ...(decision.requestedTtlMs === undefined ? {} : { ttlMs: decision.requestedTtlMs }) }, decision.createdAt, deadlineAt);
    requireEqual(decision, expected, 'delivery original user decision');
    if (decision.decision === 'deny') return undefined;
    const subject: DeliveryPlanGrantV1['subject'] = { kind: 'delivery_plan', deliveryPlanRef: target.deliveryPlanRef,
      deliveryPlanDigest: target.deliveryPlanDigest, operationSetDigest: target.operationSetDigest };
    const core = { schemaVersion: 1 as const, format: 'cliq-operation-grant-v1' as const,
      grantId: identityHash('cliq-operation-grant-v1', request.runId, request.opId, request.requestDigest, subject, decision.createdAt),
      principalId, runId: request.runId, policyRef, frontierRef: request.frontierRef, opId: request.opId,
      requestRef: canonicalSha256(request), requestDigest: request.requestDigest, targetRef: request.targetRef, targetDigest: target.targetDigest,
      subject, provenance: { kind: 'user_approval' as const, waitingSubjectRef: decision.waitingSubjectRef,
        decisionRef: canonicalSha256(decision), requestId: decision.requestId,
        channelEvidenceRef: canonicalSha256(evidence), channelEvidenceDigest: evidence.evidenceDigest },
      maxDispatchedAttempts: 0, issuedAt: decision.createdAt, expiresAt: deadlineAt };
    return immutableSnapshot({ ...core, grantDigest: canonicalSha256(core) });
  }
  return Object.freeze({ evaluate, grant, approvalWait, approve });
}
