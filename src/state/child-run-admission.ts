import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { addCanonicalDuration, digestOmitting, identityHash } from '../kernel/identity.js';
import type { BudgetSettlementV1, ChildAllocationV1, ContextManifest, ContinuationItem, Run, RunFrontier, RunObjectiveV1, RunSpec,
  ToolResultItem, ToolResultModelContentV1, ToolResultPayloadV1, VerifierSpec } from '../kernel/types.js';
import type { ChildAdmissionRequestV1, ChildAdmissionReceiptV1, ChildCapabilityGrantV1, ChildHandleItem, DelegateResult } from '../kernel/children.js';
import { planChildBudgetAllocation } from '../kernel/child-budget.js';
import { readChildContinuationBudgetFloor } from './child-budget-floor.js';
import type { DerivedChildUnverifiedConsentV1 } from '../kernel/child-verifier.js';
import { decodeDerivedChildUnverifiedConsent } from '../kernel/child-verifier.js';
import type { ToolOperationGrantV1, ToolPolicyChannelEvidenceV1, ToolPolicyDecisionItem, RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import { immutableSnapshot } from '../model/immutable.js';
import { decodeDelegateRequest } from '../tools/child-inputs.js';
import { loadToolPolicy, planToolRequest } from '../policy/tool-policy.js';
import { exactKeys, requireEqual, type ReleaseTrustKey } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { assertChildAncestryRelease } from './child-ancestry.js';
import { childAdmissionKey } from './child-admission.js';
import { planChildComposition } from './child-composition.js';
import { planChildAdmittedContext } from './child-context.js';
import { readChildCredentialLifetime } from './child-verifier-admission.js';
import { planContinuationCommit } from './continuation-commit.js';
import { decodeSourceManifest, decodeVerifierSpec, decodeWorkspaceState } from './decoders.js';
import { joinResourceOperations, KernelStorageError, stateOperation } from './errors.js';
import { addBudget, assertBudgetWithin, childAllocationBudgetFacts, decodeChildAllocation } from './invariants.js';
import { assertInstalledRunAdmissionCapacity } from './installed-run-capacity.js';
import { readRunAuthority } from './run-authority.js';
import { planChildForkSource } from './result-source.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import { appendInvocationJournalEntry, nextJournalSequence, readInvocationJournal } from './repositories/journal.js';
import { readCheckpoint, readRun, readSession, ZERO_BUDGET } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import { readToolApproval } from './tool-approval-recovery.js';
import { readToolCut } from './tool-cut.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import type { ChildBudgetProposal } from '../kernel/child-budget.js';
import type { ToolCut } from './tool-cut.js';
import type { ToolRequestV1, ToolTargetV1 } from '../kernel/tool-authorization.js';
import { planChildAdmissionRefusal, childAdmissionRefusalCheckpointId } from './child-admission-refusal-artifacts.js';

const COST = Object.freeze({ modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 });
const childCheckpointId = (id: string) => identityHash('cliq-checkpoint-id-v1', id, 'initial', 0);
type RefusalReason = Extract<ChildBudgetProposal, { kind: 'refused' }>['reason'];
type RefusalFacts = { driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext;
  selected: ToolCut; authority: Awaited<ReturnType<typeof readRunAuthority>>; grant: ToolOperationGrantV1; request: ToolRequestV1;
  target: ToolTargetV1; evidence: ToolPolicyChannelEvidenceV1; approved: boolean; preparedAt: string; reason: RefusalReason };
const refusedAdmissions = new WeakMap<object, RefusalFacts>();
class ChildAdmissionRefused extends KernelStorageError {
  constructor(reason: RefusalReason) { super('BUDGET_EXHAUSTED', `child allocation is refused by ${reason}`); }
}
/** Only this original producer can register a deterministic no-child cut.
 * An error message, instanceof or structurally similar object is insufficient. */
export function isChildAdmissionRefused(value: unknown): value is KernelStorageError {
  return typeof value === 'object' && value !== null && refusedAdmissions.has(value);
}

/** Complete only the deterministic refusal observed by this exact original
 * owned admission. No child/load/worker can be supplied by the caller. */
export const completeChildAdmissionRefusal = stateOperation('RECOVERY_REQUIRED', async (driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, refusal: unknown, signal?: AbortSignal) => {
  if (!isChildAdmissionRefused(refusal)) throw new TypeError('child refusal requires its genuine original admission producer');
  const facts = refusedAdmissions.get(refusal)!;
  if (facts.driver !== driver || facts.artifacts !== artifacts || facts.owner !== owner) throw new TypeError('child refusal belongs to another original owner');
  const { selected, authority, grant, request, preparedAt } = facts, { run: parent, runSpec: spec } = selected,
    reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  await authority.controlAuthority.assertAuthority(signal); reads.assertReadActive();
  const decoded = decodeDelegateRequest(selected.call.value), allocations = selected.childAllocations.filter(row => row.parentRunId === parent.id),
    continuationFloor = await readChildContinuationBudgetFloor(reads, { parentRunId: parent.id, assembly: authority.assembly, allocations, nextMode: decoded.mode }),
    proposal = planChildBudgetAllocation({ parent: { budgets: spec.budgets, consumed: parent.budgetConsumed, reserved: parent.budgetReserved, deadlineAt: parent.deadlineAt },
      requestedBudgets: decoded.requestedBudgets, createdAt: preparedAt,
      nonterminalDirectChildren: childAllocationBudgetFacts(parent.id, allocations).nonterminalDirectChildren, continuationFloor });
  if (proposal.kind !== 'refused' || proposal.reason !== facts.reason) throw new KernelStorageError('REVISION_CONFLICT', 'original no-child condition changed');
  const active = assertActiveStateOwner(driver, owner), sequence = nextJournalSequence(driver, parent.id),
    planned = planChildAdmissionRefusal({ parent, allocations, request, target: facts.target, grant, evidence: facts.evidence,
      inspector: supervisorInspectorIdentity(active), preparedAt, reason: facts.reason, continuationFloor, journalSeq: sequence });
  // A refusal is still this one authorized delegate attempt. If even that
  // cost cannot be paid, the ordinary resource-cause reader decides Stop.
  assertBudgetWithin(planned.consumed, parent.budgetReserved, ZERO_BUDGET, spec.budgets);
  const items: ContinuationItem[] = [...(facts.approved ? [] : [planned.decision]), planned.item],
    frontier: RunFrontier = selected.frontier.nextCallIndex + 1 < selected.batch.calls.length
      ? { ...selected.frontier, nextCallIndex: selected.frontier.nextCallIndex + 1 }
      : { schemaVersion: 1, kind: 'agent', phase: 'model_turn', turnId: identityHash('cliq-agent-turn-v1', parent.id, selected.batch.itemId),
        contextItemSeq: selected.context.throughItemSeq + items.length, cause: 'tool_batch_complete' },
    graph = planContinuationCommit(reads, { context: selected.context, existingItems: selected.items, items, frontier,
      checkpointId: childAdmissionRefusalCheckpointId(parent.id, request.opId), workspaceStateRef: selected.checkpoint.workspaceStateRef });
  const metadata = await joinResourceOperations(planned.plans.map(plan => reads.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind))),
    continuation = await graph.publish();
  let outcome: TimeFenceAdvance | undefined, updated!: Run;
  driver.transaction(connection => {
    signal?.throwIfAborted(); assertActiveStateOwner(connection, owner);
    let now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
    for (const item of [...metadata, ...continuation.metadata]) insertArtifactMetadata(connection, item, preparedAt);
    now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
    requireEqual(assertActiveStateOwner(connection, owner), active, 'original no-child Supervisor owner');
    requireEqual(readRun(connection, parent.id), parent, 'original deterministic refusal parent cut');
    requireEqual(readCheckpoint(connection, parent.latestCheckpointId), selected.checkpoint, 'original deterministic refusal source Checkpoint');
    requireEqual(readInvocationJournal(connection, parent.id), selected.journal, 'original deterministic refusal Journal');
    requireEqual(readChildAllocationsForRun(connection, parent.id), selected.childAllocations, 'original deterministic refusal children');
    if (sequence !== nextJournalSequence(connection, parent.id) || now < preparedAt || now < grant.issuedAt || now >= grant.expiresAt || now >= parent.deadlineAt ||
        connection.prepare("SELECT 1 FROM worker_launches WHERE run_id=? AND phase!='retired' LIMIT 1").get(parent.id))
      throw new KernelStorageError('LEASE_FENCED', 'original refusal cannot retain a worker, stale grant or new transaction cut');
    assertChildAncestryRelease(connection, parent.id, now);
    assertBudgetWithin(planned.consumed, parent.budgetReserved, ZERO_BUDGET, spec.budgets);
    const common = { runId: parent.id, opId: request.opId, opKind: 'child_admission' as const, attempt: 0, leaseEpoch: 0,
      target: request.targetRef, requestRef: planned.requestPlan.ref, replayClass: 'retry' as const, grantRef: planned.grantPlan.ref,
      idempotencyKey: childAdmissionKey(parent.id, selected.batch.itemId, selected.call.callId, selected.call.index, selected.call.inputDigest),
      timestamp: preparedAt, localCommittedAt: now }, claim = { dispatchId: identityHash('cliq-child-local-claim-v1', parent.id, request.opId, planned.requestPlan.ref),
        stateOwnerEpoch: owner.ownerEpoch, supervisorInstanceId: owner.supervisorInstanceId };
    appendInvocationJournalEntry(connection, { ...common, seq: sequence, phase: 'prepared', budgetDelta: COST });
    appendInvocationJournalEntry(connection, { ...common, ...claim, seq: sequence + 1, phase: 'dispatch_claimed', budgetDelta: ZERO_BUDGET });
    appendInvocationJournalEntry(connection, { ...common, ...claim, seq: sequence + 2, phase: 'completed', budgetDelta: COST,
      resultRef: planned.receiptPlan.ref, budgetSettlementRef: planned.settlementPlan.ref });
    continuation.commit(connection, parent, sequence + 2, now);
    connection.prepare('UPDATE runs SET budget_consumed_json=?,revision=revision+1,updated_at=? WHERE id=?').run(JSON.stringify(planned.consumed), now, parent.id);
    updated = readRun(connection, parent.id); appendRunStateEvent(connection, updated, now);
  });
  requireHealthyFence(outcome); refusedAdmissions.delete(refusal); return immutableSnapshot({ run: updated });
});

/** The owner passes only the actual Run/revision and original release roots.
 * No caller-provided spec, grant, context, budget or native proof is accepted.
 * This is one artifact-first local transaction, never physical dispatch. */
export const admitChildRun = stateOperation('INVALID_REQUEST', async (driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, input: { runId: string; expectedRunRevision: number; releaseKeys: readonly ReleaseTrustKey[] }, signal?: AbortSignal) => {
  if (!exactKeys(input, ['runId', 'expectedRunRevision', 'releaseKeys']) || !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1)
    throw new TypeError('child admission requires its original exact Run revision');
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  reads.assertReadActive();
  const authority = await readRunAuthority(driver, reads, owner, { runId: input.runId, operation: 'agent', releaseKeys: input.releaseKeys }, signal);
  await authority.controlAuthority.assertAuthority(signal);
  const selected = await readToolCut(driver, reads, input.runId, authority.toolContracts.resolveToolInput);
  const { run: parent, runSpec: parentSpec, checkpoint, context } = selected;
  if (parent.revision !== input.expectedRunRevision || parent.status !== 'queued' || parent.activeWorkerLaunchId ||
      parent.cancelRequested || parent.stopIntentRef || selected.workerLaunches.length || selected.call.toolName !== 'delegate')
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'child admission requires its exact worker-free productive delegate cut');
  const contract = authority.contracts.find(entry => entry.name === 'delegate');
  if (!contract || contract.execution.kind !== 'supervisor_operation' || contract.execution.handlerId !== 'delegate')
    throw new TypeError('child admission has no original signed Supervisor operation identity');
  const delegated = decodeDelegateRequest(selected.call.value);
  const session = readSession(driver, parent.sessionId);
  const source = decodeSourceManifest(await readCanonicalArtifact(reads, parentSpec.baseWorkspaceManifestRef));
  const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(reads, parentSpec.policyRef);
  const evaluator = loadToolPolicy({ policy, policyRef: parentSpec.policyRef, assembly: authority.assembly, assemblyRef: parentSpec.assemblyRef,
    principalId: authority.controlAuthority.principalId, workspaceIdentityRef: session.workspaceIdentityRef,
    workspaceIdentityDigest: source.workspaceIdentityDigest, contracts: authority.contracts });
  const { request: toolRequest, target } = planToolRequest({ runId: parent.id, frontierRef: parent.frontierRef!, batchItemId: selected.batch.itemId,
    assemblyRef: parentSpec.assemblyRef, assembly: authority.assembly, workspaceIdentityRef: session.workspaceIdentityRef,
    workspaceIdentityDigest: source.workspaceIdentityDigest, entry: contract, call: selected.call });
  const policyItem = selected.items.map(entry => entry.item).filter(item => item.kind === 'policy_decision' && item.opId === toolRequest.opId).at(-1);
  const approved = policyItem?.kind === 'policy_decision' && policyItem.decisionSource === 'interactive_approval' && policyItem.decision === 'allow'
    ? await readToolApproval(driver, reads, parent, evaluator, policyItem.decisionRef) : undefined;
  const preparedAt = sampleCanonicalNow();
  const evidence = evaluator.evaluate(toolRequest, target, selected.call, preparedAt);
  let grant: ToolOperationGrantV1;
  if (evidence.effectiveDisposition === 'deny') throw new KernelStorageError('INVALID_REQUEST', 'child admission is denied by the exact current delegate policy');
  if (approved?.grant && approved.grant.expiresAt > preparedAt) {
    requireEqual(approved.request, toolRequest, 'original approved child request'); grant = approved.grant;
  } else {
    if (evidence.effectiveDisposition !== 'allow') throw new KernelStorageError('INVALID_REQUEST', 'child admission requires its exact current approval');
    grant = evaluator.grant(toolRequest, target, selected.call, evidence, preparedAt, parent.deadlineAt);
  }
  const grantPlan = planCanonicalArtifact(grant, grant.format), toolRequestPlan = planCanonicalArtifact(toolRequest, toolRequest.format);
  const allocations = selected.childAllocations.filter(row => row.parentRunId === parent.id);
  const childFacts = childAllocationBudgetFacts(parent.id, allocations);
  const existing = new Map<string, typeof selected.journal[number]>();
  for (const row of selected.journal) existing.set(`${row.opId}:${row.attempt}`, row);
  if ([...existing.values()].some(row => ['prepared', 'dispatch_claimed', 'unknown'].includes(row.phase)))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'child admission cannot overtake an unresolved original invocation');
  const continuationFloor = await readChildContinuationBudgetFloor(reads, { parentRunId: parent.id,
    assembly: authority.assembly, allocations, nextMode: delegated.mode });
  const budget = planChildBudgetAllocation({ parent: { budgets: parentSpec.budgets, consumed: parent.budgetConsumed,
    reserved: parent.budgetReserved, deadlineAt: parent.deadlineAt }, requestedBudgets: delegated.requestedBudgets, createdAt: preparedAt,
    nonterminalDirectChildren: childFacts.nonterminalDirectChildren, continuationFloor });
  if (budget.kind !== 'available') {
    const error = new ChildAdmissionRefused(budget.reason);
    refusedAdmissions.set(error, { driver, artifacts, owner, selected, authority, grant, request: toolRequest, target, evidence,
      approved: approved !== undefined, preparedAt, reason: budget.reason });
    throw error;
  }
  const admissionKey = childAdmissionKey(parent.id, selected.batch.itemId, selected.call.callId, selected.call.index, selected.call.inputDigest);
  const childRunId = identityHash('cliq-run-id-v1', authority.controlAuthority.principalId, 'delegate', admissionKey);
  if (driver.prepare('SELECT 1 FROM runs WHERE id = ?').get(childRunId))
    throw new KernelStorageError('REVISION_CONFLICT', 'delegate must replay its committed original result instead of admitting another child');
  const fork = await planChildForkSource(reads, parentSpec, checkpoint.workspaceStateRef, signal);
  const composition = await planChildComposition(reads, { request: delegated, parentSpec,
    principalId: authority.controlAuthority.principalId, workspaceIdentityDigest: source.workspaceIdentityDigest,
    delegateRequestRef: toolRequestPlan.ref, grantedBudgets: budget.grantedBudgets, createdAt: preparedAt });
  const childContext = await planChildAdmittedContext(driver, reads, { parent, parentSpec, assembly: authority.assembly, context, request: delegated });
  const originalWorkspace = decodeWorkspaceState(await readCanonicalArtifact(reads, checkpoint.workspaceStateRef));
  const workspace = { ...originalWorkspace, runId: childRunId, baseWorkspaceManifestRef: fork.sourceRef, stateDigest: '' };
  workspace.stateDigest = digestOmitting(workspace, 'stateDigest');
  const workspacePlan = planCanonicalArtifact(workspace, workspace.format);
  const objective: RunObjectiveV1 = { schemaVersion: 1, format: 'cliq-run-objective-v1', utf8: delegated.objective,
    byteCount: Buffer.byteLength(delegated.objective), objectiveDigest: '' };
  objective.objectiveDigest = digestOmitting(objective, 'objectiveDigest');
  const objectivePlan = planCanonicalArtifact(objective, objective.format);
  const inheritedVerifier = decodeVerifierSpec(await readCanonicalArtifact(reads, parentSpec.verifierSpecRef));
  if (delegated.verifierMode === 'inherit_parent' && !inheritedVerifier.verifiers.some(entry => entry.gate === 'required'))
    throw new KernelStorageError('INVALID_REQUEST', 'inherit_parent requires a required verifier; an unverified helper must explicitly choose none');
  const emptyVerifier: VerifierSpec = { schemaVersion: 1, format: 'cliq-verifier-spec-v1', verifiers: [], specDigest: '' };
  emptyVerifier.specDigest = digestOmitting(emptyVerifier, 'specDigest');
  const verifierPlan = delegated.verifierMode === 'none' ? planCanonicalArtifact(emptyVerifier, emptyVerifier.format) : undefined;
  const specCore: RunSpec = { schemaVersion: 1, operation: 'agent', objectiveRef: objectivePlan.ref, admittedContextRef: childContext.plan.ref,
    baseWorkspaceManifestRef: fork.sourceRef, sourceProjectionRef: parentSpec.sourceProjectionRef, assemblyRef: composition.plans[1]!.ref,
    policyRef: composition.plans[2]!.ref, sandboxProfileRef: parentSpec.sandboxProfileRef,
    verifierSpecRef: verifierPlan?.ref ?? parentSpec.verifierSpecRef,
    ...(delegated.verifierMode === 'inherit_parent' && parentSpec.dependencyPolicyRef ? { dependencyPolicyRef: parentSpec.dependencyPolicyRef } : {}),
    credentialGrantRefs: composition.credentialGrantRefs, budgets: { ...budget.grantedBudgets } };
  const capabilityCore = { schemaVersion: 1 as const, format: 'cliq-child-capability-grant-v1' as const, parentRunId: parent.id,
    delegateBatchItemId: selected.batch.itemId, delegateCallId: selected.call.callId, delegateCallIndex: selected.call.index,
    delegateOpId: toolRequest.opId, mode: delegated.mode, parentAssemblyRef: parentSpec.assemblyRef, parentPolicyRef: parentSpec.policyRef,
    granted: composition.granted, childToolManifestRef: composition.assembly.tools.manifestRef,
    childToolManifestDigest: composition.tools.manifestDigest, childAssemblyRef: specCore.assemblyRef, childPolicyRef: specCore.policyRef,
    verifierMode: delegated.verifierMode, childVerifierSpecRef: specCore.verifierSpecRef,
    ...(specCore.dependencyPolicyRef ? { childDependencyPolicyRef: specCore.dependencyPolicyRef } : {}),
    childCredentialGrantRefs: specCore.credentialGrantRefs, grantedBudgets: specCore.budgets, childDeadlineAt: budget.childDeadlineAt };
  const grantCoreDigest = canonicalSha256(capabilityCore);
  const consentCore = { schemaVersion: 1 as const, kind: 'derived_child_unverified_consent' as const, parentRunId: parent.id, childRunId,
    delegateBatchItemId: selected.batch.itemId, delegateCallId: selected.call.callId, delegateCallIndex: selected.call.index,
    delegateOpId: toolRequest.opId, delegateOperationGrantRef: grantPlan.ref, childCapabilityGrantCoreDigest: grantCoreDigest,
    childRunSpecCoreDigest: canonicalSha256(specCore), allowUnverifiedHelper: true as const, createdAt: preparedAt };
  const consent: DerivedChildUnverifiedConsentV1 | undefined = delegated.verifierMode === 'none'
    ? { ...consentCore, consentDigest: canonicalSha256(consentCore) } : undefined;
  if (consent) decodeDerivedChildUnverifiedConsent(consent);
  const consentPlan = consent ? planCanonicalArtifact(consent, 'cliq-derived-child-unverified-consent-v1') : undefined;
  const capability: ChildCapabilityGrantV1 = { ...capabilityCore, grantCoreDigest,
    ...(consentPlan ? { derivedUnverifiedConsentRef: consentPlan.ref } : {}), grantDigest: '' };
  capability.grantDigest = digestOmitting(capability, 'grantDigest');
  const capabilityPlan = planCanonicalArtifact(capability, capability.format);
  const spec: RunSpec = { ...specCore, ...(consentPlan ? { unverifiedConsentRef: consentPlan.ref } : {}) };
  const specPlan = planCanonicalArtifact(spec, 'cliq-run-spec-v1');
  const initialContext: ContextManifest = { schemaVersion: 1, format: 'cliq-context-manifest-v1', runId: childRunId, throughItemSeq: 0,
    admittedContextRef: spec.admittedContextRef, segments: [], assemblyRef: spec.assemblyRef, projectionDigest: '' };
  initialContext.projectionDigest = digestOmitting(initialContext, 'projectionDigest');
  const initialContextPlan = planCanonicalArtifact(initialContext, initialContext.format);
  const initialFrontier: RunFrontier = { schemaVersion: 1, kind: 'agent', phase: 'model_turn',
    turnId: identityHash('cliq-turn-id-v1', childRunId, 'initial'), contextItemSeq: 0, cause: 'initial' };
  const initialFrontierPlan = planCanonicalArtifact(initialFrontier, 'cliq-run-frontier-v1');
  const allocation: ChildAllocationV1 = { schemaVersion: 1, parentRunId: parent.id, childRunId, admissionKey,
    delegateBatchItemId: selected.batch.itemId, delegateCallId: selected.call.callId, delegateCallIndex: selected.call.index,
    delegateOpId: toolRequest.opId, delegateOperationGrantRef: grantPlan.ref, capabilityGrantRef: capabilityPlan.ref, mode: delegated.mode,
    grantedAdditiveCeilings: { ...budget.grantedAdditiveCeilings }, grantedChildDepth: spec.budgets.childDepth,
    grantedChildConcurrency: spec.budgets.childConcurrency, childDeadlineAt: budget.childDeadlineAt, createdAt: preparedAt, state: 'reserved' };
  decodeChildAllocation(allocation);
  const handle: ChildHandleItem = { schemaVersion: 1, kind: 'child_handle', itemId: identityHash('cliq-child-handle-v1', parent.id, toolRequest.opId),
    runId: parent.id, delegateBatchItemId: selected.batch.itemId, delegateCallId: selected.call.callId, delegateCallIndex: selected.call.index,
    delegateOpId: toolRequest.opId, childRunId, admittedSpecRef: specPlan.ref, mode: delegated.mode, createdAt: preparedAt };
  const handlePlan = planCanonicalArtifact(handle, 'cliq-child-handle-item-v1');
  const parentSnapshotPlan = planCanonicalArtifact(parent, 'cliq-run-snapshot-origin-v1');
  const allocationSnapshotPlan = planCanonicalArtifact(allocations, 'cliq-child-allocation-snapshot-v1');
  const request: ChildAdmissionRequestV1 = { schemaVersion: 1, format: 'cliq-child-admission-request-v1', parentRunId: parent.id, childRunId,
    parentRunSnapshotRef: parentSnapshotPlan.ref, parentChildAllocationsRef: allocationSnapshotPlan.ref, parentCheckpointId: checkpoint.id,
    toolRequestRef: toolRequestPlan.ref, delegateOperationGrantRef: grantPlan.ref, capabilityGrantRef: capabilityPlan.ref, admissionKey,
    childSpecRef: specPlan.ref, childWorkspaceStateRef: workspacePlan.ref, childContextManifestRef: initialContextPlan.ref,
    childFrontierRef: initialFrontierPlan.ref, preparedAt, requestDigest: '' };
  request.requestDigest = digestOmitting(request, 'requestDigest');
  const requestPlan = planCanonicalArtifact(request, request.format);
  const active = assertActiveStateOwner(driver, owner), inspector = supervisorInspectorIdentity(active);
  const inspectorPlan = planCanonicalArtifact(inspector, inspector.format);
  const receipt: ChildAdmissionReceiptV1 = { schemaVersion: 1, format: 'cliq-child-admission-receipt-v1', parentRunId: parent.id, childRunId,
    requestRef: requestPlan.ref, childSpecRef: specPlan.ref, childHandleItemRef: handlePlan.ref,
    inspectorIdentityRef: inspectorPlan.ref, inspectorIdentityDigest: inspector.identityDigest, preparedAt, receiptDigest: '' };
  receipt.receiptDigest = digestOmitting(receipt, 'receiptDigest');
  const receiptPlan = planCanonicalArtifact(receipt, receipt.format);
  const sequence = nextJournalSequence(driver, parent.id);
  const consumed = addBudget(parent.budgetConsumed, COST), reserved = addBudget(parent.budgetReserved, allocation.grantedAdditiveCeilings);
  assertBudgetWithin(consumed, reserved, ZERO_BUDGET, parentSpec.budgets);
  const settlement: BudgetSettlementV1 = { schemaVersion: 1, format: 'cliq-budget-settlement-v1', runId: parent.id,
    opId: toolRequest.opId, attempt: 0, preparedJournalSeq: sequence, terminalJournalSeq: sequence + 2, terminalPhase: 'completed',
    reserved: COST, consumed: COST, released: COST, budgetConsumedBefore: parent.budgetConsumed, budgetConsumedAfter: consumed,
    budgetReservedBefore: addBudget(parent.budgetReserved, COST), budgetReservedAfter: parent.budgetReserved, settledAt: preparedAt, settlementDigest: '' };
  settlement.settlementDigest = digestOmitting(settlement, 'settlementDigest');
  const settlementPlan = planCanonicalArtifact(settlement, settlement.format);
  const result: DelegateResult = { schemaVersion: 1, childHandleItemId: handle.itemId, childRunId, admittedSpecRef: specPlan.ref };
  const modelCore = { schemaVersion: 1 as const, format: 'cliq-tool-result-model-content-v1' as const,
    callId: selected.call.callId, index: selected.call.index, toolName: 'delegate', outcome: 'executed' as const, content: result };
  const model: ToolResultModelContentV1 = { ...modelCore, contentDigest: canonicalSha256(modelCore) };
  const modelPlan = planCanonicalArtifact(model, model.format);
  const payload: ToolResultPayloadV1 = { schemaVersion: 1, format: 'cliq-tool-result-payload-v1', runId: parent.id,
    batchItemId: selected.batch.itemId, callId: selected.call.callId, index: selected.call.index, toolName: 'delegate',
    modelContentRef: modelPlan.ref, modelContentDigest: model.contentDigest, outcome: 'executed', source: 'child_admission',
    opId: toolRequest.opId, journalResultRef: receiptPlan.ref, journalResultDigest: receipt.receiptDigest, childHandleItemRef: handlePlan.ref, payloadDigest: '' };
  payload.payloadDigest = digestOmitting(payload, 'payloadDigest');
  const payloadPlan = planCanonicalArtifact(payload, payload.format);
  const resultItem: ToolResultItem = { schemaVersion: 1, kind: 'tool_result',
    itemId: identityHash('cliq-tool-result-item-v1', parent.id, selected.batch.itemId, selected.call.callId), runId: parent.id,
    batchItemId: selected.batch.itemId, callId: selected.call.callId, index: selected.call.index, opId: toolRequest.opId,
    outcome: 'executed', resultRef: payloadPlan.ref, createdAt: preparedAt };
  const decision: ToolPolicyDecisionItem = { schemaVersion: 1, kind: 'policy_decision', subjectKind: 'tool_call',
    itemId: identityHash('cliq-tool-policy-item-v1', parent.id, toolRequest.opId, canonicalSha256(evidence)), runId: parent.id,
    opId: toolRequest.opId, principalId: authority.controlAuthority.principalId, decisionSource: 'direct_policy', decision: 'allow',
    decisionRef: canonicalSha256(evidence), policyChannelEvidenceRef: canonicalSha256(evidence), policyChannelEvidenceDigest: evidence.evidenceDigest,
    grantRef: grantPlan.ref, createdAt: evidence.evaluatedAt };
  const items: ContinuationItem[] = [...(approved ? [] : [decision]), handle, resultItem];
  const frontier: RunFrontier = selected.frontier.nextCallIndex + 1 < selected.batch.calls.length
    ? { ...selected.frontier, nextCallIndex: selected.frontier.nextCallIndex + 1 }
    : { schemaVersion: 1, kind: 'agent', phase: 'model_turn', turnId: identityHash('cliq-agent-turn-v1', parent.id, selected.batch.itemId),
      contextItemSeq: context.throughItemSeq + items.length, cause: 'tool_batch_complete' };
  const graph = planContinuationCommit(reads, { context, existingItems: selected.items, items, frontier,
    checkpointId: identityHash('cliq-child-admission-checkpoint-v1', parent.id, toolRequest.opId), workspaceStateRef: checkpoint.workspaceStateRef });
  const plans: readonly PlannedArtifact[] = [...fork.plans, ...composition.plans, childContext.plan, ...childContext.textPlans,
    workspacePlan, objectivePlan, ...(verifierPlan ? [verifierPlan] : []), ...(consentPlan ? [consentPlan] : []), capabilityPlan,
    specPlan, initialContextPlan, initialFrontierPlan, parentSnapshotPlan, allocationSnapshotPlan, toolRequestPlan,
    planCanonicalArtifact(target, target.format), grantPlan, planCanonicalArtifact(evidence, evidence.format), requestPlan, inspectorPlan,
    receiptPlan, settlementPlan, modelPlan, payloadPlan];
  const metadata = await joinResourceOperations(plans.map(plan => reads.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind)));
  const continuation = await graph.publish();
  const credentialLifetime = await readChildCredentialLifetime(reads, { principalId: authority.controlAuthority.principalId,
    createdAt: preparedAt, deadlineAt: budget.childDeadlineAt, spec, assembly: composition.assembly });
  signal?.throwIfAborted();
  let outcome: TimeFenceAdvance | undefined, updated!: Run, child!: Run;
  driver.transaction(connection => {
    signal?.throwIfAborted(); assertActiveStateOwner(connection, owner);
    const before = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, before); if (outcome !== 'healthy') return;
    requireEqual(readRun(connection, parent.id), parent, 'original parent child admission cut');
    requireEqual(readChildAllocationsForRun(connection, parent.id), selected.childAllocations, 'exact original parent outgoing reservation cut');
    requireEqual(readCheckpoint(connection, parent.latestCheckpointId), checkpoint, 'original parent child fork Checkpoint');
    requireEqual(readInvocationJournal(connection, parent.id), selected.journal, 'original parent child Journal cut');
    if (connection.prepare("SELECT 1 FROM worker_launches WHERE run_id = ? AND phase != 'retired' LIMIT 1").get(parent.id))
      throw new KernelStorageError('LEASE_FENCED', 'local child admission cannot retain a real worker or preparation');
    const actualChildren = connection.prepare(`SELECT count(*) AS count FROM runs WHERE parent_run_id = ? AND status IN ('queued','running','waiting')`)
      .get<{ count: unknown }>(parent.id);
    if (Number(actualChildren?.count) !== childFacts.nonterminalDirectChildren || Number(actualChildren?.count) >= parentSpec.budgets.childConcurrency)
      throw new KernelStorageError('REVISION_CONFLICT', 'direct child concurrency changed before local admission');
    assertInstalledRunAdmissionCapacity(connection);
    for (const item of [...metadata, ...continuation.metadata, ...fork.metadata]) insertArtifactMetadata(connection, item, preparedAt);
    // A refusal here commits only inert metadata and the sticky clock fence.
    // No business row or operation claim precedes this actual final sample.
    const committedAt = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, committedAt); if (outcome !== 'healthy') return;
    if (committedAt < preparedAt || committedAt >= grant.expiresAt || committedAt >= parent.deadlineAt || committedAt >= budget.childDeadlineAt ||
        committedAt < credentialLifetime.createdAt || committedAt >= credentialLifetime.expiresAt)
      throw new KernelStorageError('LEASE_FENCED', 'local child admission exceeds its original grant or absolute deadline');
    assertChildAncestryRelease(connection, parent.id, committedAt);
    requireEqual(assertActiveStateOwner(connection, owner), active, 'original local child Supervisor owner');
    const common = { runId: parent.id, opId: toolRequest.opId, opKind: 'child_admission' as const, attempt: 0, leaseEpoch: 0,
      target: toolRequest.targetRef, requestRef: requestPlan.ref, replayClass: 'retry' as const, idempotencyKey: admissionKey,
      grantRef: grantPlan.ref, timestamp: preparedAt, localCommittedAt: committedAt };
    const claim = { dispatchId: identityHash('cliq-child-local-claim-v1', parent.id, toolRequest.opId, requestPlan.ref),
      supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: owner.ownerEpoch };
    appendInvocationJournalEntry(connection, { ...common, seq: sequence, phase: 'prepared', budgetDelta: COST });
    appendInvocationJournalEntry(connection, { ...common, ...claim, seq: sequence + 1, phase: 'dispatch_claimed', budgetDelta: ZERO_BUDGET });
    appendInvocationJournalEntry(connection, { ...common, ...claim, seq: sequence + 2, phase: 'completed', budgetDelta: COST,
      resultRef: receiptPlan.ref, budgetSettlementRef: settlementPlan.ref });
    connection.prepare(`INSERT INTO checkpoints (id,schema_version,run_id,based_on_run_revision,run_item_seq,context_manifest_ref,
      journal_seq,workspace_state_ref,created_at,reason) VALUES (?,1,?,0,0,?,0,?,?,'initial')`)
      .run(childCheckpointId(childRunId), childRunId, initialContextPlan.ref, workspacePlan.ref, preparedAt);
    connection.prepare(`INSERT INTO runs (id,session_id,parent_run_id,spec_ref,status,next_step,frontier_ref,waiting_reason,waiting_on_ref,
      revision,lease_epoch,active_worker_launch_id,latest_checkpoint_id,budget_reserved_json,budget_consumed_json,repair_count,
      result_ref,terminal_reason,terminal_detail_ref,stop_intent_ref,cancel_requested,created_at,deadline_at,updated_at,
      principal_id,admission_method,admission_key,admission_intent_digest,admitted_request_digest,admission_request_id)
      VALUES (?,?,?,?,'queued','agent',?,NULL,NULL,1,0,NULL,?,?,?,0,NULL,NULL,NULL,NULL,0,?,?,?,?, 'delegate',?,?,?,?)`)
      .run(childRunId, parent.sessionId, parent.id, specPlan.ref, initialFrontierPlan.ref, childCheckpointId(childRunId),
        JSON.stringify(ZERO_BUDGET), JSON.stringify(ZERO_BUDGET), preparedAt, budget.childDeadlineAt, preparedAt,
        authority.controlAuthority.principalId, admissionKey, toolRequestPlan.ref, requestPlan.ref, toolRequest.opId);
    connection.prepare('INSERT INTO child_allocations (parent_run_id,child_run_id,state,row_json) VALUES (?,?,?,?)')
      .run(parent.id, childRunId, 'reserved', JSON.stringify(allocation));
    continuation.commit(connection, parent, sequence + 2, committedAt);
    connection.prepare(`UPDATE runs SET budget_reserved_json=?,budget_consumed_json=?,revision=revision+1,updated_at=? WHERE id=?`)
      .run(JSON.stringify(reserved), JSON.stringify(consumed), committedAt, parent.id);
    updated = readRun(connection, parent.id); child = readRun(connection, childRunId);
    appendRunStateEvent(connection, updated, committedAt); appendRunStateEvent(connection, child, preparedAt);
  });
  requireHealthyFence(outcome);
  if (!updated || !child) throw new KernelStorageError('RECOVERY_REQUIRED', 'local child admission did not commit');
  return immutableSnapshot({ run: updated, child, childRunId, childHandleItemRef: handlePlan.ref });
});
