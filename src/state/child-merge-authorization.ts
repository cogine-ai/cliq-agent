// One original local merge permission. Model calls, native scopes, broker
// tokens, delegate/edit grants and retained JSON cannot create this capability.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { childMergeIdempotencyKey, childMergeOperationId, decodeChildMergeApprovalDecision, decodeChildMergeApprovalWait, decodeChildMergeGrant,
  decodeChildMergePolicyDecisionItem, decodeChildMergePolicyEvidence, decodeChildMergeRequest, decodeChildMergeTarget,
  type ChildMergeApprovalDecisionV1, type ChildMergeApprovalWait, type ChildMergeBindingV1, type ChildMergeGrantV1,
  type ChildMergePolicyDecisionItem, type ChildMergePolicyEvidenceV1, type ChildMergeRequestV1, type ChildMergeTargetV1 } from '../kernel/child-merge.js';
import { decodeInstalledControlRequest, type RunApproveRequestV1 } from '../kernel/control-wire.js';
import { decodeWireRun } from '../kernel/control-wire-data.js';
import { addCanonicalDuration, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { ChildMergeBatchItem, ChildMergeResultItem } from '../kernel/children.js';
import type { ContinuationItem, Run, RunFrontier } from '../kernel/types.js';
import type { PolicyDisposition, RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { assertRunPolicySnapshot, evaluateFrozenPolicyKey } from '../policy/tool-policy.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { assertChildAncestryRelease } from './child-ancestry.js';
import { readChildMergePlan, readRetainedChildMergePlan, type RetainedChildMergePlan } from './child-merge-plan.js';
import { assertCurrentControlFrame, readHistoricalControlChannel, validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { decodeBudgetSettlement, decodeContextManifest, decodeSourceManifest } from './decoders.js';
import { joinResourceOperations, KernelStorageError, stateOperation } from './errors.js';
import { addBudget, childAllocationBudgetFacts } from './invariants.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import { readInvocationJournal, readOperationJournal } from './repositories/journal.js';
import { readRunAuthority } from './run-authority.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readSupervisorInspector, supervisorInspectorIdentity } from './supervisor-inspector.js';
import { prepareContinuationCommit } from './continuation-commit.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import { insertControlRequest, readCheckpoint, readControlRequest, readRun, readSession, readSessionPrincipalId, ZERO_BUDGET } from './rows.js';
import { assertSqliteConnectionOwnedBy, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';

const same = (a: unknown, b: unknown) => canonicalSha256(a) === canonicalSha256(b);
const rank: Record<PolicyDisposition, number> = { allow: 0, ask: 1, deny: 2 };
const compare = (a: string, b: string) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const approvalCheckpointId = (ref: string) => identityHash('cliq-child-merge-approval-checkpoint-v1', ref);
const decisionCheckpointId = (ref: string) => identityHash('cliq-child-merge-decision-checkpoint-v1', ref);
const policyItemId = (runId: string, opId: string, ref: string) => identityHash('cliq-child-merge-policy-item-v1', runId, opId, ref);
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', `child merge authorization ${message}`); }
const immutableRun = (run: Run) => ({ id: run.id, sessionId: run.sessionId, parentRunId: run.parentRunId ?? null,
  specRef: run.specRef, createdAt: run.createdAt, deadlineAt: run.deadlineAt });

function binding(plan: RetainedChildMergePlan, parentRunSnapshotRef: string): ChildMergeBindingV1 {
  return { runId: plan.run.id, mergeBatchItemId: plan.batch.itemId, callId: plan.call.callId, callIndex: plan.call.index,
    childRunId: plan.call.childRunId, childResultItemId: plan.resultItem.itemId, patchManifestRef: plan.call.patchManifestRef,
    parentRunSnapshotRef, sourceCheckpointId: plan.checkpoint.id, workspaceStateRef: plan.checkpoint.workspaceStateRef,
    sourceBaseRef: plan.sourceBaseRef, sourceDesiredRef: plan.sourceDesiredRef, capturedWorkspaceRef: plan.capturedWorkspaceRef };
}
function requestFor(plan: RetainedChildMergePlan, original: ChildMergeBindingV1, target: ChildMergeTargetV1, frontierRef: string): ChildMergeRequestV1 {
  const core = { ...original, schemaVersion: 1 as const, format: 'cliq-child-merge-request-v1' as const,
    opId: childMergeOperationId(original), assemblyRef: plan.spec.assemblyRef, frontierRef,
    targetRef: canonicalSha256(target), targetDigest: target.targetDigest };
  return decodeChildMergeRequest({ ...core, requestDigest: canonicalSha256(core) });
}
function targetFor(plan: RetainedChildMergePlan, original: ChildMergeBindingV1, workspaceIdentityRef: string,
  workspaceIdentityDigest: string, owner: Pick<ReturnType<typeof assertActiveStateOwner>, 'supervisorEntryId' | 'supervisorEntryVersion' | 'supervisorExecutableDigest'>): ChildMergeTargetV1 {
  const core = { ...original, schemaVersion: 1 as const, format: 'cliq-child-merge-target-v1' as const,
    workspaceIdentityRef, workspaceIdentityDigest, changedPathsDigest: canonicalSha256(plan.changedPaths),
    execution: { kind: 'supervisor_operation' as const, handlerId: 'child_merge' as const,
      supervisorEntryId: owner.supervisorEntryId, supervisorEntryVersion: owner.supervisorEntryVersion,
      supervisorExecutableDigest: owner.supervisorExecutableDigest } };
  return decodeChildMergeTarget({ ...core, targetDigest: canonicalSha256(core) });
}
function pathPolicy(policy: RunPolicySnapshotV1, paths: readonly string[]) {
  const pathDecisions = paths.map(path => {
    const choice = evaluateFrozenPolicyKey(policy, 'write', 'fs-write', path);
    return { path, decisionSource: choice.ruleId ? 'rule' as const : 'mode_fallthrough' as const,
      matchedRuleIds: choice.ruleId ? [choice.ruleId] : [], effectiveDisposition: choice.disposition };
  });
  let effectiveDisposition: PolicyDisposition = pathDecisions.length ? 'allow' : policy.decisions.write;
  for (const row of pathDecisions) if (rank[row.effectiveDisposition] > rank[effectiveDisposition]) effectiveDisposition = row.effectiveDisposition;
  return { pathDecisions, effectiveDisposition };
}
function policyFor(policy: RunPolicySnapshotV1, policyRef: string, plan: RetainedChildMergePlan, principalId: string,
  workspaceIdentityDigest: string, request: ChildMergeRequestV1, target: ChildMergeTargetV1) {
  assertRunPolicySnapshot({ policy, policyRef, assembly: plan.assembly, principalId, workspaceIdentityDigest });
  return (evaluatedAt: string): ChildMergePolicyEvidenceV1 => {
    if (parseCanonicalTime(evaluatedAt) < parseCanonicalTime(policy.createdAt)) invalid('policy observation precedes its original snapshot');
    const { pathDecisions, effectiveDisposition } = pathPolicy(policy, plan.changedPaths);
    const core = { schemaVersion: 1 as const, format: 'cliq-policy-channel-evidence-v1' as const, principalId, runId: request.runId,
      policyRef, policyDigest: policy.policyDigest, frontierRef: request.frontierRef, opId: request.opId,
      requestRef: canonicalSha256(request), requestDigest: request.requestDigest, targetRef: request.targetRef, targetDigest: target.targetDigest,
      actionClass: 'write' as const, channel: 'fs-write' as const, canonicalRootRelativePaths: [...plan.changedPaths], pathDecisions,
      matchedRuleIds: [...new Set(pathDecisions.flatMap(row => row.matchedRuleIds))].sort(compare), effectiveDisposition, evaluatedAt };
    return decodeChildMergePolicyEvidence({ ...core, evidenceDigest: canonicalSha256(core) });
  };
}
function grantFor(request: ChildMergeRequestV1, target: ChildMergeTargetV1, evidence: ChildMergePolicyEvidenceV1,
  issuedAt: string, expiresAt: string, provenance?: Extract<ChildMergeGrantV1['provenance'], { kind: 'user_approval' }>): ChildMergeGrantV1 {
  if (!provenance && evidence.effectiveDisposition !== 'allow') invalid('cannot grant an ask or denied path set');
  const { schemaVersion: _version, format: _format, opId: _op, assemblyRef: _assembly, frontierRef: _frontier,
    targetRef: _target, targetDigest: _digest, requestDigest: _request, ...original } = request;
  const subject = { ...original, kind: 'child_merge' as const, changedPathsDigest: target.changedPathsDigest };
  const decision = { policyRef: evidence.policyRef, channelEvidenceRef: canonicalSha256(evidence), channelEvidenceDigest: evidence.evidenceDigest,
    actionClass: 'write' as const, requestDigest: request.requestDigest, targetDigest: target.targetDigest,
    matchedRuleIds: evidence.matchedRuleIds, effectiveDisposition: 'allow' as const };
  const core = { schemaVersion: 1 as const, format: 'cliq-operation-grant-v1' as const,
    grantId: identityHash('cliq-operation-grant-v1', request.runId, request.opId, request.requestDigest, subject, issuedAt),
    principalId: evidence.principalId, runId: request.runId, policyRef: evidence.policyRef, frontierRef: request.frontierRef,
    opId: request.opId, requestRef: canonicalSha256(request), requestDigest: request.requestDigest, targetRef: request.targetRef,
    targetDigest: target.targetDigest, subject, provenance: provenance ?? { kind: 'policy_snapshot' as const,
      actionClass: 'write' as const, channelEvidenceRef: decision.channelEvidenceRef, channelEvidenceDigest: decision.channelEvidenceDigest,
      matchedRuleIds: evidence.matchedRuleIds, effectiveDisposition: 'allow' as const, decisionDigest: canonicalSha256(decision) },
    maxDispatchedAttempts: 1 as const, issuedAt, expiresAt };
  return decodeChildMergeGrant({ ...core, grantDigest: canonicalSha256(core) });
}
function waitingFor(request: ChildMergeRequestV1, target: ChildMergeTargetV1, evidence: ChildMergePolicyEvidenceV1,
  revision: number): ChildMergeApprovalWait {
  if (evidence.effectiveDisposition !== 'ask') invalid('only the exact ask may create a merge wait');
  const { schemaVersion: _version, format: _format, opId, assemblyRef: _assembly, frontierRef, targetRef,
    targetDigest: _digest, requestDigest: _request, ...original } = request;
  return decodeChildMergeApprovalWait({ schemaVersion: 1, kind: 'approval', runId: request.runId,
    createdFromRevision: revision, createdAt: evidence.evaluatedAt, frontierRef,
    subject: { ...original, kind: 'child_merge', changedPathsDigest: target.changedPathsDigest, opId, target: targetRef,
      policyChannelEvidenceRef: canonicalSha256(evidence), policyChannelEvidenceDigest: evidence.evidenceDigest } });
}

/** Original Run counters are audited against the immutable source CP prefix,
 * not today's mutable head or a self-consistent caller-supplied snapshot. */
async function readOriginalRun(driver: SqliteDriver, artifacts: ArtifactCatalog, plan: RetainedChildMergePlan, request: ChildMergeRequestV1) {
  const original = decodeWireRun(await readCanonicalArtifact(artifacts, request.parentRunSnapshotRef));
  requireEqual(immutableRun(original), immutableRun(plan.run), 'merge original immutable parent');
  const checkpoint = plan.checkpoint;
  if (original.latestCheckpointId !== checkpoint.id || original.revision !== checkpoint.basedOnRunRevision + 1 ||
      original.updatedAt !== checkpoint.createdAt || original.status !== 'queued' || original.nextStep !== 'tool' ||
      original.frontierRef !== request.frontierRef || original.activeWorkerLaunchId || original.waitingOnRef || original.waitingReason ||
      original.stopIntentRef || original.cancelRequested || original.resultRef || original.terminalReason || original.terminalDetailRef)
    invalid('original snapshot is not its exact productive source Checkpoint');
  const frontier: RunFrontier = { schemaVersion: 1, kind: 'tool', batchItemId: plan.batch.itemId,
    orderedCallIds: plan.batch.calls.map(call => call.callId), nextCallIndex: plan.call.index };
  requireEqual(await readCanonicalArtifact(artifacts, request.frontierRef), frontier, 'merge original synthetic cursor');
  const prefix = plan.items.slice(0, checkpoint.runItemSeq);
  const repairs = prefix.filter(row => row.item.kind === 'repair_diagnostic').map(row => row.item);
  if (repairs.length !== original.repairCount || repairs.some((item, i) => item.kind !== 'repair_diagnostic' || item.repairOrdinal !== i + 1))
    invalid('original repair count does not close its exact immutable prefix');
  const journals = plan.journal.slice(0, checkpoint.journalSeq), groups = new Map<string, typeof journals>();
  if (journals.length !== checkpoint.journalSeq) invalid('source Checkpoint Journal cursor exceeds its complete prefix');
  for (const [i, row] of journals.entries()) {
    if (row.seq !== i + 1) invalid('original Journal prefix has a sequence gap');
    const key = `${row.opId}\\0${row.attempt}`, rows = groups.get(key) ?? []; rows.push(row); groups.set(key, rows);
  }
  let consumed = { ...ZERO_BUDGET, repairAttempts: original.repairCount }, reserved = { ...ZERO_BUDGET };
  for (const rows of groups.values()) {
    const prepared = rows[0]!, terminal = rows.find(row => ['completed', 'failed', 'unknown'].includes(row.phase));
    if (prepared.phase !== 'prepared' || !['completed', 'failed'].includes(rows.at(-1)!.phase)) invalid('original parent retains an unresolved own invocation');
    if (!terminal?.budgetSettlementRef) invalid('original invocation lost its exact settlement');
    const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, terminal.budgetSettlementRef));
    if (settlement.runId !== original.id || settlement.opId !== prepared.opId || settlement.attempt !== prepared.attempt ||
        settlement.preparedJournalSeq !== prepared.seq || settlement.terminalJournalSeq !== terminal.seq ||
        settlement.terminalPhase !== terminal.phase || settlement.settledAt !== terminal.timestamp ||
        !same(settlement.reserved, prepared.budgetDelta) || !same(settlement.consumed, terminal.budgetDelta) ||
        rows.slice(rows.indexOf(terminal)).some(row => row.budgetSettlementRef !== terminal.budgetSettlementRef))
      invalid('original budget settlement changed its exact Journal identity');
    consumed = addBudget(consumed, settlement.consumed);
  }
  const admitted = new Set(journals.filter(row => row.opKind === 'child_admission' && row.phase === 'completed').map(row => row.opId));
  const prior = readChildAllocationsForRun(driver, original.id).filter(row => row.parentRunId === original.id && admitted.has(row.delegateOpId));
  const allocations = prior.map(row => {
    if (row.state === 'settled' && row.parentSettlementRevision <= original.revision) {
      const item = prefix.find(value => value.item.itemId === row.childResultItemId);
      if (item?.item.kind !== 'child_result' || item.item.childRunId !== row.childRunId || row.settledAt > checkpoint.createdAt)
        invalid('original settled budget has no owned source-prefix child result');
      return row;
    }
    const { state: _state, terminal: _terminal, inclusiveBudgetUsage: _usage, terminalAt: _at, childResultItemId: _item,
      parentSettlementRevision: _revision, releasedUnusedBudget: _unused, settledAt: _settled, ...origin } = row;
    return { ...origin, state: 'reserved' as const };
  });
  const children = childAllocationBudgetFacts(original.id, allocations);
  consumed = addBudget(consumed, children.consumed); reserved = addBudget(reserved, children.reserved);
  requireEqual(consumed, original.budgetConsumed, 'merge exact original inclusive consumed budget');
  requireEqual(reserved, original.budgetReserved, 'merge exact original conservative reserved budget');
  const leases = plan.workers.flatMap(worker => worker.activatedAt && worker.leaseEpoch !== undefined &&
    worker.plannedRunRevision < original.revision ? [worker.leaseEpoch] : []);
  if (original.leaseEpoch !== Math.max(0, ...leases)) invalid('source snapshot invented a parent worker lease');
  return original;
}

/** Publish in bounded groups and join every issued sibling, including a
 * failed group. Partial CAS publication creates no grant/SQL/effect authority. */
async function publishPlans(artifacts: ArtifactCatalog, plans: readonly PlannedArtifact[]) {
  const metadata: PublishedArtifact[] = [];
  for (let i = 0; i < plans.length; i += 4) {
    artifacts.assertReadActive();
    const group = await joinResourceOperations(plans.slice(i, i + 4).map(async plan => {
      const result = await artifacts.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind);
      requireEqual(result, { ref: plan.ref, mediaType: plan.mediaType, schemaKind: plan.schemaKind, byteLength: plan.bytes.length }, 'merge exact durable artifact');
      return result;
    }));
    metadata.push(...group);
  }
  artifacts.assertReadActive(); return metadata;
}

function policyItem(evidence: ChildMergePolicyEvidenceV1, decisionRef: string, grant?: ChildMergeGrantV1,
  approval?: ChildMergeApprovalDecisionV1): ChildMergePolicyDecisionItem {
  return decodeChildMergePolicyDecisionItem({ schemaVersion: 1, kind: 'policy_decision', subjectKind: 'child_merge',
    itemId: policyItemId(evidence.runId, evidence.opId, decisionRef), runId: evidence.runId, opId: evidence.opId,
    principalId: evidence.principalId, decisionRef, policyChannelEvidenceRef: canonicalSha256(evidence), policyChannelEvidenceDigest: evidence.evidenceDigest,
    createdAt: approval?.createdAt ?? evidence.evaluatedAt,
    ...(approval ? { decisionSource: 'interactive_approval', waitingSubjectRef: approval.waitingSubjectRef } : { decisionSource: 'direct_policy' }),
    ...(grant ? { decision: 'allow', grantRef: canonicalSha256(grant) } : { decision: 'deny' }) });
}
async function verifyPublishedSource(artifacts: ArtifactCatalog, source: RetainedChildMergePlan) {
  const known = new Map(source.computation.metadata.map(row => [row.ref, row]));
  await artifacts.mapReads(source.plans, async plan => {
    const actual = await artifacts.describe(plan.ref, plan.mediaType, plan.schemaKind), expected = known.get(plan.ref);
    const length = expected?.byteLength ?? plan.bytes.length;
    if (actual.ref !== plan.ref || actual.byteLength !== length) invalid('original planned source is missing or changed');
  });
}

/** Data-only retained source. The locator must come from the actual owning
 * SQL wait/item/Journal; this function grants no permission by itself. */
async function readMaterial(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string, requestRef: string) {
  const request = decodeChildMergeRequest(await readCanonicalArtifact(artifacts, requestRef));
  if (request.runId !== runId) invalid('request belongs to another Run');
  const source = await readRetainedChildMergePlan(driver, artifacts, runId, { mergeBatchItemId: request.mergeBatchItemId,
    callIndex: request.callIndex, sourceCheckpointId: request.sourceCheckpointId });
  const original = await readOriginalRun(driver, artifacts, source, request);
  requireEqual(binding(source, request.parentRunSnapshotRef), Object.fromEntries(Object.keys(binding(source, request.parentRunSnapshotRef))
    .map(key => [key, request[key as keyof ChildMergeBindingV1]])), 'merge complete original binding');
  const session = readSession(driver, source.run.sessionId), principalId = readSessionPrincipalId(driver, session.id);
  const base = decodeSourceManifest(await readCanonicalArtifact(artifacts, source.spec.baseWorkspaceManifestRef));
  const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, source.assembly.runtime.runtimeBundleRef);
  const supervisor = bundle.entries.filter(entry => entry.role === 'supervisor');
  if (supervisor.length !== 1 || !supervisor[0]!.executable || bundle.manifestDigest !== source.assembly.runtime.runtimeBundleManifestDigest)
    invalid('source has no unique original Supervisor image');
  const expectedTarget = targetFor(source, binding(source, request.parentRunSnapshotRef), session.workspaceIdentityRef, base.workspaceIdentityDigest,
    { supervisorEntryId: supervisor[0]!.entryId, supervisorEntryVersion: supervisor[0]!.version, supervisorExecutableDigest: supervisor[0]!.digest });
  const target = decodeChildMergeTarget(await readCanonicalArtifact(artifacts, request.targetRef));
  requireEqual(target, expectedTarget, 'merge exact original target and complete path identity');
  requireEqual(request, requestFor(source, binding(source, request.parentRunSnapshotRef), target, request.frontierRef), 'merge exact original request');
  const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, source.spec.policyRef);
  const evaluate = policyFor(policy, source.spec.policyRef, source, principalId, base.workspaceIdentityDigest, request, target);
  await verifyPublishedSource(artifacts, source);
  source.assertUnchanged(driver); artifacts.assertReadActive();
  return { source, original, request, target, policy, principalId, evaluate };
}

/** A committed direct grant is registered only with its sole local effect.
 * Interactive grants can be genuinely unused; their first use is still one
 * complete atomic triplet, never a physical dispatch or a pending retry. */
async function readLocalUse(driver: SqliteDriver, artifacts: ArtifactCatalog, material: Awaited<ReturnType<typeof readMaterial>>,
  grant: ChildMergeGrantV1 | undefined, required: boolean, approvedAt?: string) {
  const { request, original, source, target } = material;
  const rows = readOperationJournal(driver, request.runId, request.opId);
  const thisGrantUsed = grant !== undefined && rows.some(row => row.grantRef === canonicalSha256(grant));
  if (!rows.length || !thisGrantUsed && !required && grant?.provenance.kind === 'user_approval') {
    if (required) invalid('registered direct grant has no original atomic local effect');
    // An expired, unused approval remains in history when a later distinct
    // approval owns the sole effect. That later grant is audited by its own
    // registered item and the effect reader; this old grant gains no use.
    return { used: false as const, operationUsed: rows.length > 0, assertUnchanged(connection: SqliteConnection) {
      requireEqual(readOperationJournal(connection, request.runId, request.opId), rows, 'merge original unused grant');
    } };
  }
  if (!grant || rows.length !== 3 || rows.map(row => row.phase).join(',') !== 'prepared,dispatch_claimed,completed')
    invalid('grant has no complete sole original local effect');
  const [prepared, claim, completed] = rows, requestRef = canonicalSha256(request), grantRef = canonicalSha256(grant);
  if (rows.some((row, index) => row.opKind !== 'child_merge' || row.runId !== request.runId || row.opId !== request.opId ||
      row.attempt !== 0 || row.leaseEpoch !== 0 || row.replayClass !== 'retry' || row.seq !== source.checkpoint.journalSeq + 1 + index ||
      row.requestRef !== requestRef || row.target !== request.targetRef || row.grantRef !== grantRef ||
      row.idempotencyKey !== childMergeIdempotencyKey(request.opId, request.requestDigest) ||
      row.timestamp !== prepared.timestamp || row.localCommittedAt !== prepared.localCommittedAt) ||
      claim.dispatchId !== identityHash('cliq-child-merge-dispatch-v1', request.runId, request.opId, requestRef) ||
      completed.dispatchId !== claim.dispatchId || completed.stateOwnerEpoch !== claim.stateOwnerEpoch ||
      completed.supervisorInstanceId !== claim.supervisorInstanceId || prepared.timestamp < grant.issuedAt ||
      prepared.localCommittedAt! >= grant.expiresAt || prepared.localCommittedAt! >= original.deadlineAt ||
      (approvedAt === undefined ? prepared.timestamp !== grant.issuedAt : prepared.timestamp < approvedAt))
    invalid('local effect changed its original request, grant, source or preparation/commit lifetime');
  const cost = { ...ZERO_BUDGET, toolCalls: 1 };
  const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, completed.budgetSettlementRef!));
  const expected = { schemaVersion: 1, format: 'cliq-budget-settlement-v1', runId: request.runId, opId: request.opId,
    attempt: 0, preparedJournalSeq: prepared.seq, terminalJournalSeq: completed.seq, terminalPhase: 'completed',
    reserved: cost, consumed: cost, released: cost, budgetConsumedBefore: original.budgetConsumed,
    budgetConsumedAfter: addBudget(original.budgetConsumed, cost), budgetReservedBefore: addBudget(original.budgetReserved, cost),
    budgetReservedAfter: original.budgetReserved, settledAt: prepared.timestamp };
  requireEqual(settlement, { ...expected, settlementDigest: canonicalSha256(expected) }, 'merge sole original inclusive settlement');
  const history = await readRetainedStateOwnerHistory(driver, artifacts, claim.stateOwnerEpoch!), owner = history.entries.at(-1)!.owner;
  if (owner.supervisorInstanceId !== claim.supervisorInstanceId || owner.acquiredAt > prepared.timestamp ||
      owner.state === 'terminal' && owner.releasedAt < prepared.localCommittedAt! ||
      owner.runtimeBundleRef !== source.assembly.runtime.runtimeBundleRef || owner.runtimeBundleManifestDigest !== source.assembly.runtime.runtimeBundleManifestDigest ||
      owner.supervisorEntryId !== target.execution.supervisorEntryId || owner.supervisorEntryVersion !== target.execution.supervisorEntryVersion ||
      owner.supervisorExecutableDigest !== target.execution.supervisorExecutableDigest)
    invalid('local effect has no original signed Supervisor owner through its real final commit');
  return { used: true as const, operationUsed: true, assertUnchanged(connection: SqliteConnection) {
    history.assertUnchanged(connection);
    requireEqual(readOperationJournal(connection, request.runId, request.opId), rows, 'merge exact original local use');
  } };
}
async function readWaitBase(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string, waitingOnRef: string) {
  const wait = decodeChildMergeApprovalWait(await readCanonicalArtifact(artifacts, waitingOnRef));
  const evidence = decodeChildMergePolicyEvidence(await readCanonicalArtifact(artifacts, wait.subject.policyChannelEvidenceRef));
  const material = await readMaterial(driver, artifacts, runId, evidence.requestRef);
  requireEqual(evidence, material.evaluate(evidence.evaluatedAt), 'merge original complete ask evidence');
  requireEqual(wait, waitingFor(material.request, material.target, evidence, wait.createdFromRevision), 'merge exact original approval subject');
  const checkpoint = readCheckpoint(driver, approvalCheckpointId(waitingOnRef));
  if (wait.createdFromRevision < material.original.revision || wait.createdAt < material.original.updatedAt || wait.createdAt >= material.original.deadlineAt ||
      checkpoint.runId !== runId || checkpoint.reason !== 'auto' || checkpoint.basedOnRunRevision !== wait.createdFromRevision ||
      checkpoint.createdAt !== wait.createdAt || checkpoint.workspaceStateRef !== material.source.checkpoint.workspaceStateRef ||
      checkpoint.journalSeq !== material.source.checkpoint.journalSeq || checkpoint.runItemSeq < material.source.checkpoint.runItemSeq)
    invalid('approval subject has no exact original source-preserving Checkpoint');
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  validateContextItems(context, material.source.items.slice(0, checkpoint.runItemSeq));
  const run: Run = { ...material.original, status: 'waiting', waitingReason: 'approval', waitingOnRef,
    revision: wait.createdFromRevision + 1, latestCheckpointId: checkpoint.id, updatedAt: wait.createdAt };
  return { ...material, wait, evidence, checkpoint, waitingRun: run };
}
async function readWait(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string, waitingOnRef: string) {
  const material = await readWaitBase(driver, artifacts, runId, waitingOnRef);
  const { wait, checkpoint } = material;
  const prior = material.source.items.slice(material.source.checkpoint.runItemSeq, checkpoint.runItemSeq);
  if (wait.createdFromRevision !== material.original.revision + 2 * prior.length)
    invalid('renewed wait does not follow its complete original approval sequence');
  const approvals = await artifacts.mapReads(prior, async (entry, index) => {
    const item = decodeChildMergePolicyDecisionItem(entry.item);
    if (item.decisionSource !== 'interactive_approval' || item.decision !== 'allow' || item.opId !== material.request.opId)
      invalid('a denial or local effect cannot be replaced by another approval wait');
    const decision = decodeChildMergeApprovalDecision(await readCanonicalArtifact(artifacts, item.decisionRef));
    const previous = await readWaitBase(driver, artifacts, runId, decision.waitingSubjectRef);
    requireEqual(previous.request, material.request, 'merge renewal preserves the complete original request');
    requireEqual(previous.wait, waitingFor(material.request, material.target, previous.evidence, material.original.revision + 2 * index),
      'merge renewal preserves the original request and approval order');
    const committed = await readApprovalCommit(driver, artifacts, previous, decision), grant = committed.grant;
    if (!grant || committed.localUse.used) invalid('only an expired unused allow may receive a fresh approval wait');
    requireEqual(await readCanonicalArtifact(artifacts, item.grantRef), grant, 'merge renewal original grant');
    requireEqual(item, committed.item, 'merge renewal original policy item');
    return { grant, wait: previous.wait };
  });
  for (const [index, previous] of approvals.entries()) {
    if (previous.grant.expiresAt > (approvals[index + 1]?.wait.createdAt ?? wait.createdAt))
      invalid('renewed wait precedes the previous grant original expiry');
  }
  return material;
}
/** Original wait/source data only. This never authenticates a new approval or
 * creates a local permission; the caller still checks its current owning Run. */
export async function readChildMergeApprovalWait(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string, waitingOnRef: string) {
  return readWait(driver, artifacts, runId, waitingOnRef);
}

/** Recovery may retain the exact wait while a real Stop only adds its fence.
 * The enclosing complete recovery independently audits that Stop's source;
 * this comparison never permits an approval, effect, or new execution. */
export function assertChildMergeApprovalWaitingRun(original: Run, current: Run): void {
  decodeWireRun(original); decodeWireRun(current);
  if (same(original, current)) return;
  if (original.status !== 'waiting' || original.waitingReason !== 'approval' || original.stopIntentRef || original.cancelRequested ||
      !current.stopIntentRef || current.revision <= original.revision || current.updatedAt < original.updatedAt)
    invalid('current waiting Run is neither its original subject nor an additive Stop');
  const stable = ({ revision: _revision, updatedAt: _updated, stopIntentRef: _stop, cancelRequested: _cancel,
    parentCancellationRef: _parentCancellation, ...rest }: Run) => rest;
  requireEqual(stable(current), stable(original), 'merge stopped wait retains every original source field');
}

function approvalGrant(material: Pick<Awaited<ReturnType<typeof readMaterial>>, 'request' | 'target' | 'principalId' | 'original'> &
  { wait: ChildMergeApprovalWait; evidence: ChildMergePolicyEvidenceV1 }, decision: ChildMergeApprovalDecisionV1) {
  const { request, target, evidence, wait, original } = material;
  const expectedExpiry = addCanonicalDuration(decision.createdAt, Math.min(decision.requestedTtlMs ?? 3_600_000,
    Date.parse(original.deadlineAt) - Date.parse(decision.createdAt)));
  if (decision.runId !== request.runId || decision.principalId !== material.principalId || decision.frontierRef !== request.frontierRef ||
      decision.waitingSubjectRef !== canonicalSha256(wait) || decision.expectedRunRevision !== wait.createdFromRevision + 1 ||
      decision.createdAt < wait.createdAt || decision.createdAt >= original.deadlineAt ||
      decision.decision === 'allow' && decision.grantExpiresAt !== expectedExpiry)
    invalid('decision does not match its original current subject, principal or TTL');
  requireEqual(decision.subject, wait.subject, 'merge original approved subject');
  return decision.decision === 'allow' ? grantFor(request, target, evidence, decision.createdAt, decision.grantExpiresAt!, {
    kind: 'user_approval', waitingSubjectRef: decision.waitingSubjectRef, decisionRef: canonicalSha256(decision), requestId: decision.requestId,
    channelEvidenceRef: canonicalSha256(evidence), channelEvidenceDigest: evidence.evidenceDigest }) : undefined;
}

/** Original response/control/owner audit. Today's channel, Session head and
 * current merge source cannot repair a missing or substituted original. */
export const readChildMergeApproval = stateOperation('RECOVERY_REQUIRED', async (driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string, decisionRef: string) => {
  const decision = decodeChildMergeApprovalDecision(await readCanonicalArtifact(artifacts, decisionRef));
  const material = await readWait(driver, artifacts, runId, decision.waitingSubjectRef);
  return readApprovalCommit(driver, artifacts, material, decision);
});
async function readApprovalCommit(driver: SqliteDriver, artifacts: ArtifactCatalog, material: Awaited<ReturnType<typeof readWaitBase>>,
  decision: ChildMergeApprovalDecisionV1) {
  const runId = material.request.runId, decisionRef = canonicalSha256(decision), grant = approvalGrant(material, decision);
  const row = readControlRequest(driver, decision.principalId, 'run.approve', decision.requestId);
  if (!row || row.requestDigest !== decision.requestDigest || row.channelIdentityRef !== decision.channelIdentityRef ||
      row.channelIdentityDigest !== decision.channelIdentityDigest || row.committedAt < decision.createdAt ||
      row.committedAt >= (decision.grantExpiresAt ?? material.original.deadlineAt)) invalid('approval has no original authenticated commit within its lifetime');
  const request = decodeInstalledControlRequest({ ...await readCanonicalArtifact<Record<string, unknown>>(artifacts, row.requestDigest), requestDigest: row.requestDigest });
  if (request.method !== 'run.approve') invalid('approval control record has another method');
  requireEqual(request, { protocolVersion: 1, method: 'run.approve', runId, requestId: decision.requestId, requestDigest: decision.requestDigest,
    expectedRevision: decision.expectedRunRevision, waitingOnRef: decision.waitingSubjectRef, decision: decision.decision,
    ...(decision.requestedTtlMs === undefined ? {} : { ttlMs: decision.requestedTtlMs }) }, 'merge original wire approval');
  const { channel } = await readHistoricalControlChannel(driver, artifacts, decision);
  const history = await readRetainedStateOwnerHistory(driver, artifacts, decision.stateOwnerEpoch), owner = history.entries.at(-1)!.owner;
  if (owner.ownerEpoch !== decision.stateOwnerEpoch || owner.supervisorInstanceId !== decision.supervisorInstanceId ||
      owner.acquiredAt > decision.createdAt || owner.state === 'terminal' && owner.releasedAt < row.committedAt ||
      channel.openedAt > decision.createdAt || !readTimeFence(driver) || row.committedAt > readTimeFence(driver)!.lastAcceptedAt)
    invalid('approval preparation and actual commit escape their original StateOwner or channel');
  await readSupervisorInspector(artifacts, owner, material.source.assembly, { ...decision, observedAt: row.committedAt });
  const expectedItem = policyItem(material.evidence, decisionRef, grant, decision);
  const items = material.source.items.filter(entry => entry.item.itemId === expectedItem.itemId);
  if (items.length !== 1) invalid('approval has no unique original policy item');
  requireEqual(items[0]!.item, expectedItem, 'merge original committed approval item');
  const checkpoint = readCheckpoint(driver, decisionCheckpointId(decisionRef));
  if (checkpoint.runId !== runId || checkpoint.reason !== 'auto' || checkpoint.basedOnRunRevision !== decision.expectedRunRevision ||
      checkpoint.createdAt !== decision.createdAt || checkpoint.workspaceStateRef !== material.checkpoint.workspaceStateRef ||
      checkpoint.journalSeq !== material.checkpoint.journalSeq || checkpoint.runItemSeq !== material.checkpoint.runItemSeq + 1 ||
      items[0]!.itemSeq !== checkpoint.runItemSeq) invalid('approval has no exact original atomic decision Checkpoint');
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  validateContextItems(context, material.source.items.slice(0, checkpoint.runItemSeq));
  const run: Run = { ...material.original, revision: decision.expectedRunRevision + 1, latestCheckpointId: checkpoint.id, updatedAt: decision.createdAt };
  const response = { protocolVersion: 1 as const, ok: true as const, result: { method: 'run.approve' as const, decisionRef,
    snapshot: { schemaVersion: 1 as const, operation: 'agent' as const, run, latestRunItemSeq: checkpoint.runItemSeq } } };
  requireEqual(await readCanonicalArtifact(artifacts, row.responseRef), response, 'merge exact original approval response');
  const localUse = await readLocalUse(driver, artifacts, material, grant, false, row.committedAt);
  material.source.assertUnchanged(driver); history.assertUnchanged(driver);
  return { ...material, decision, grant, item: expectedItem, response, control: row, localUse, assertUnchanged(connection: SqliteConnection) {
    material.source.assertUnchanged(connection); history.assertUnchanged(connection); localUse.assertUnchanged(connection);
    requireEqual(readControlRequest(connection, decision.principalId, 'run.approve', decision.requestId), row, 'merge original control commit');
    requireEqual(readCheckpoint(connection, material.checkpoint.id), material.checkpoint, 'merge original approval wait');
    requireEqual(readCheckpoint(connection, checkpoint.id), checkpoint, 'merge original approval decision');
  } };
}

export async function readChildMergeAuthorization(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string, itemId: string) {
  const row = driver.prepare('SELECT run_id,kind,payload_ref FROM items WHERE item_id = ?').get<{ run_id: string; kind: string; payload_ref: string }>(itemId);
  if (!row || row.run_id !== runId || row.kind !== 'policy_decision') invalid('grant has no owning policy item');
  const item = decodeChildMergePolicyDecisionItem(await readCanonicalArtifact(artifacts, row.payload_ref));
  if (item.runId !== runId || item.itemId !== itemId) invalid('policy item belongs to another Run');
  if (item.decisionSource === 'interactive_approval') {
    const approved = await readChildMergeApproval(driver, artifacts, runId, item.decisionRef);
    requireEqual(approved.item, item, 'merge original interactive policy item'); return approved;
  }
  const evidence = decodeChildMergePolicyEvidence(await readCanonicalArtifact(artifacts, item.policyChannelEvidenceRef));
  const material = await readMaterial(driver, artifacts, runId, evidence.requestRef);
  requireEqual(evidence, material.evaluate(evidence.evaluatedAt), 'merge complete direct path policy');
  const grant = item.decision === 'allow' ? decodeChildMergeGrant(await readCanonicalArtifact(artifacts, item.grantRef)) : undefined;
  if (grant) requireEqual(grant, grantFor(material.request, material.target, evidence, evidence.evaluatedAt, material.original.deadlineAt), 'merge exact original direct grant');
  else if (evidence.effectiveDisposition !== 'deny') invalid('direct refusal is not a denied original path set');
  requireEqual(item, policyItem(evidence, canonicalSha256(evidence), grant), 'merge exact original direct policy item');
  const localUse = await readLocalUse(driver, artifacts, material, grant, Boolean(grant));
  return { ...material, evidence, grant, item, localUse, assertUnchanged(connection: SqliteConnection) {
    material.source.assertUnchanged(connection); localUse.assertUnchanged(connection);
    requireEqual(connection.prepare('SELECT run_id,kind,payload_ref FROM items WHERE item_id = ?').get(itemId), row, 'merge original policy SQL owner');
  } };
}

async function currentMaterial(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { runId: string; expectedRunRevision: number; releaseKeys: readonly ReleaseTrustKey[] }, signal?: AbortSignal) {
  const authority = await readRunAuthority(driver, artifacts, owner, { runId: input.runId, operation: 'agent', releaseKeys: input.releaseKeys }, signal);
  await authority.controlAuthority.assertAuthority(signal);
  const run = readRun(driver, input.runId);
  if (run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'merge parent revision changed');
  if (!['queued', 'waiting'].includes(run.status) || run.nextStep !== 'tool' || !run.frontierRef || run.activeWorkerLaunchId || run.cancelRequested || run.stopIntentRef)
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'merge permission requires its exact unclaimed retired cursor');
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef);
  if (frontier.kind !== 'tool') invalid('current parent has no synthetic merge cursor');
  const batchRow = authority.recovered.items.find(row => row.itemId === frontier.batchItemId);
  const batch = batchRow && await readCanonicalArtifact<ContinuationItem>(artifacts, batchRow.payloadRef);
  if (batch?.kind !== 'child_merge_batch') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'ordinary model tools cannot request internal merge permission');
  const call = batch.calls[frontier.nextCallIndex];
  if (!call || call.index !== frontier.nextCallIndex) invalid('current merge call is missing');
  const policies: Array<Awaited<ReturnType<typeof readChildMergeAuthorization>>> = [];
  for (const row of authority.recovered.items) {
    const item = await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef);
    if (item.kind !== 'policy_decision' || item.subjectKind !== 'child_merge') continue;
    const actual = await readChildMergeAuthorization(driver, artifacts, run.id, item.itemId);
    if (actual.request.mergeBatchItemId !== batch.itemId || actual.request.callIndex !== call.index) continue;
    if (actual.request.callId !== call.callId || actual.request.childRunId !== call.childRunId || actual.request.patchManifestRef !== call.patchManifestRef)
      invalid('registered permission changes the same merge call');
    if (actual.localUse.operationUsed) invalid('current cursor cannot reuse its already committed local effect');
    if (policies.length) requireEqual(actual.request, policies[0]!.request, 'merge original request cannot drift across approvals');
    policies.push(actual);
  }
  if (run.status === 'waiting') {
    if (run.waitingReason !== 'approval' || !run.waitingOnRef) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'merge has a different owning wait');
    const original = await readWait(driver, artifacts, run.id, run.waitingOnRef);
    requireEqual(original.waitingRun, run, 'merge exact current approval Run');
    if (policies.length) requireEqual(original.request, policies[0]!.request, 'merge current wait preserves its original request');
    if (original.request.mergeBatchItemId !== batch.itemId || original.request.callId !== call.callId || original.request.callIndex !== call.index)
      invalid('current wait selects another synthetic call');
    return { authority, ...original, metadata: [] as PublishedArtifact[], existing: policies.at(-1), waiting: true as const };
  }
  if (policies.length) {
    const latest = policies.at(-1)!; latest.assertUnchanged(driver);
    if (latest.request.frontierRef !== run.frontierRef) invalid('original merge permission has another current frontier');
    return { authority, ...latest, metadata: [] as PublishedArtifact[], existing: latest, waiting: false as const };
  }
  const source = await readChildMergePlan(driver, artifacts, run.id, { signal });
  const sourceRunPlan = planCanonicalArtifact(run, 'cliq-child-merge-parent-run-v1');
  const base = decodeSourceManifest(await readCanonicalArtifact(artifacts, source.spec.baseWorkspaceManifestRef));
  const session = readSession(driver, run.sessionId), original = binding(source, sourceRunPlan.ref);
  const target = targetFor(source, original, session.workspaceIdentityRef, base.workspaceIdentityDigest, assertActiveStateOwner(driver, owner));
  const request = requestFor(source, original, target, run.frontierRef), policy = await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, source.spec.policyRef);
  const principalId = authority.controlAuthority.principalId;
  const metadata = await publishPlans(artifacts, [...source.plans, sourceRunPlan,
    planCanonicalArtifact(request, request.format), planCanonicalArtifact(target, target.format)]);
  await readOriginalRun(driver, artifacts, source, request);
  source.assertUnchanged(driver); assertActiveStateOwner(driver, owner); artifacts.assertReadActive();
  return { authority, source, original: run, request, target, policy, principalId,
    evaluate: policyFor(policy, source.spec.policyRef, source, principalId, base.workspaceIdentityDigest, request, target),
    metadata, existing: undefined, waiting: false as const };
}

/** Pure projection shared by the local producer and its retained effect
 * reader. A structural input never creates a prepared permission. */
export function childMergeSourceData(source: RetainedChildMergePlan) {
  const computation = source.computation.kind === 'ready' ? { kind: 'ready' as const, input: source.computation.input,
    source: source.computation.source, sourceRef: source.computation.sourceRef, entries: source.computation.entries,
    diff: source.computation.diff, diffRef: source.computation.diffRef, summary: source.computation.summary,
    summaryRef: source.computation.summaryRef, noOp: source.computation.noOp, identicalToSourceDesired: source.computation.identicalToSourceDesired }
    : source.computation.kind === 'conflict' ? { kind: 'conflict' as const, input: source.computation.input, conflicts: source.computation.conflicts }
      : { kind: 'limited' as const, input: source.computation.input, limit: source.computation.limit };
  return immutableSnapshot({ run: source.run, spec: source.spec, assembly: source.assembly, checkpoint: source.checkpoint,
    currentCheckpoint: source.currentCheckpoint, context: source.context, items: source.items, journal: source.journal,
    batch: source.batch, call: source.call, resultItem: source.resultItem, sourceBaseRef: source.sourceBaseRef,
    sourceDesiredRef: source.sourceDesiredRef, capturedWorkspaceRef: source.capturedWorkspaceRef,
    changedPaths: [...source.changedPaths], computation,
    ...(source.workspacePlan ? { workspaceStateRef: source.workspacePlan.ref } : {}) });
}
export type PreparedChildMergeAuthorization = Readonly<{ readonly __preparedChildMergeAuthorization: unique symbol }>;
type PreparedFacts = {
  driver: SqliteDriver; owner: StateOwnerContext; artifacts: ArtifactCatalog; used: boolean; source: RetainedChildMergePlan;
  request: ChildMergeRequestV1; target: ChildMergeTargetV1; evidence: ChildMergePolicyEvidenceV1; grant?: ChildMergeGrantV1;
  item?: ChildMergePolicyDecisionItem; metadata: PublishedArtifact[]; preparedAt: string;
  historical?: Awaited<ReturnType<typeof readChildMergeAuthorization>>;
};
const preparedMerges = new WeakMap<PreparedChildMergeAuthorization, PreparedFacts>();

/** Only the current owner can obtain this one-use local-commit capability.
 * All original and newly planned bytes have really finished publication. */
export const prepareChildMergeAuthorization = stateOperation('RECOVERY_REQUIRED', async (
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { runId: string; expectedRunRevision: number; releaseKeys: readonly ReleaseTrustKey[] }, signal?: AbortSignal
) => {
  if (!exactKeys(input, ['runId', 'expectedRunRevision', 'releaseKeys']) || !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1)
    throw new TypeError('merge permission requires its exact current Run revision');
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  assertActiveStateOwner(driver, owner);
  if (!readTimeFence(driver)) invalid('current canonical fence is missing');
  if (readTimeFence(driver)!.state !== 'healthy') requireHealthyFence('still_regressed');
  const material = await currentMaterial(driver, reads, owner, input, signal);
  if (material.waiting) return Object.freeze({ disposition: 'waiting' as const, run: material.source.run });
  const preparedAt = sampleCanonicalNow(); preparationTime(driver, owner, material.source, preparedAt);
  const evidence = material.evaluate(preparedAt), existing = material.existing;
  let grant: ChildMergeGrantV1 | undefined, item: ChildMergePolicyDecisionItem | undefined, historical: typeof existing;
  const metadata = [...material.metadata];
  if (existing?.item.decision === 'deny') {
    historical = existing; // A real denial is never replaced by a new policy evaluation.
  } else if (existing?.grant && preparedAt < existing.grant.expiresAt) {
    grant = existing.grant; historical = existing;
  } else if (evidence.effectiveDisposition === 'ask') {
    const wait = waitingFor(material.request, material.target, evidence, material.source.run.revision);
    const waitPlan = planCanonicalArtifact(wait, 'cliq-child-merge-approval-wait-v1');
    metadata.push(...await publishPlans(reads, [planCanonicalArtifact(evidence, evidence.format), waitPlan]));
    let outcome: ReturnType<typeof advanceTimeFence> | undefined, updated: Run | undefined;
    driver.transaction(connection => {
      reads.assertReadActive(); assertActiveStateOwner(connection, owner); material.source.assertUnchanged(connection);
      const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
      assertChildAncestryRelease(connection, input.runId, now);
      if (now < preparedAt || now >= material.original.deadlineAt) throw new KernelStorageError('LEASE_FENCED', 'merge wait exceeds its original lifetime');
      for (const row of metadata) insertArtifactMetadata(connection, row, now);
      const current = material.source.run, checkpoint = material.source.currentCheckpoint;
      connection.prepare(`INSERT INTO checkpoints(id,schema_version,run_id,based_on_run_revision,run_item_seq,context_manifest_ref,journal_seq,workspace_state_ref,created_at,reason)
        VALUES(?,1,?,?,?,?,?,?,?,'auto')`).run(approvalCheckpointId(waitPlan.ref), current.id, current.revision,
          checkpoint.runItemSeq, checkpoint.contextManifestRef, checkpoint.journalSeq, checkpoint.workspaceStateRef, preparedAt);
      connection.prepare("UPDATE runs SET status='waiting',waiting_reason='approval',waiting_on_ref=?,latest_checkpoint_id=?,revision=revision+1,updated_at=? WHERE id=?")
        .run(waitPlan.ref, approvalCheckpointId(waitPlan.ref), preparedAt, current.id);
      updated = readRun(connection, current.id); appendRunStateEvent(connection, updated, preparedAt);
    });
    requireHealthyFence(outcome);
    if (!updated) invalid('wait did not commit under its original time fence');
    return Object.freeze({ disposition: 'waiting' as const, run: updated });
  } else {
    grant = evidence.effectiveDisposition === 'allow' ? grantFor(material.request, material.target, evidence, preparedAt, material.original.deadlineAt) : undefined;
    item = policyItem(evidence, canonicalSha256(evidence), grant);
    metadata.push(...await publishPlans(reads, [planCanonicalArtifact(evidence, evidence.format),
      ...(grant ? [planCanonicalArtifact(grant, grant.format)] : []), planCanonicalArtifact(item, 'cliq-child-merge-policy-item-v1')]));
  }
  reads.assertReadActive(); material.source.assertUnchanged(driver); assertActiveStateOwner(driver, owner);
  if (historical) historical.assertUnchanged(driver);
  const token = Object.freeze(Object.create(null)) as PreparedChildMergeAuthorization;
  preparedMerges.set(token, { driver, owner, artifacts: reads, used: false, source: material.source, request: material.request,
    target: material.target, evidence: historical?.evidence ?? evidence, grant, item, metadata, preparedAt, historical });
  return Object.freeze({ disposition: 'prepared' as const, token });
});

/** Reading retained grant JSON cannot populate this registry. The final cut
 * is synchronous, one-use and shares the caller's one real canonical C. */
export function readPreparedChildMergeAuthorization(driver: SqliteDriver, owner: StateOwnerContext, token: PreparedChildMergeAuthorization) {
  const held = preparedMerges.get(token);
  if (!held || held.driver !== driver || held.owner !== owner || held.used) invalid('requires its genuine unconsumed current-owner preparation');
  assertActiveStateOwner(driver, owner); held.artifacts.assertReadActive(); held.source.assertUnchanged(driver);
  return Object.freeze({ source: childMergeSourceData(held.source), preparedAt: held.preparedAt, request: held.request, requestRef: canonicalSha256(held.request),
    target: held.target, targetRef: canonicalSha256(held.target), evidence: held.evidence,
    ...(held.grant ? { grant: held.grant, grantRef: canonicalSha256(held.grant) } : {}),
    decisionItem: held.item ?? held.historical!.item, decisionItemRef: canonicalSha256(held.item ?? held.historical!.item),
    appendDecisionItem: Boolean(held.item), metadata: immutableSnapshot(held.metadata),
    disposition: held.grant ? 'allow' as const : 'deny' as const,
    assertCommit(connection: SqliteConnection, committedAt: string) {
      if (held.used) invalid('local permission was already consumed');
      assertSqliteConnectionOwnedBy(driver, connection); held.artifacts.assertReadActive(); assertActiveStateOwner(connection, owner);
      held.source.assertUnchanged(connection); held.historical?.assertUnchanged(connection);
      const fence = readTimeFence(connection);
      if (!fence || fence.state !== 'healthy' || fence.stateOwnerEpoch !== owner.ownerEpoch || fence.lastAcceptedAt !== committedAt ||
          committedAt < held.preparedAt || committedAt >= (held.grant?.expiresAt ?? held.source.run.deadlineAt) ||
          held.source.run.status !== 'queued' || held.source.run.cancelRequested || held.source.run.stopIntentRef)
        throw new KernelStorageError('LEASE_FENCED', 'merge permission lost its exact current canonical commit or original lifetime');
      assertChildAncestryRelease(connection, held.source.run.id, committedAt); held.used = true;
    } });
}

function preparationTime(driver: SqliteDriver, owner: StateOwnerContext, source: RetainedChildMergePlan, observedAt: string,
  identity?: AuthenticatedControlIdentity, uds = false) {
  const record = assertActiveStateOwner(driver, owner);
  if (observedAt >= source.run.updatedAt && observedAt >= record.acquiredAt) return;
  let outcome: ReturnType<typeof advanceTimeFence> | undefined;
  driver.transaction(connection => {
    assertActiveStateOwner(connection, owner); source.assertUnchanged(connection);
    if (uds) assertCurrentControlFrame(owner, identity!);
    outcome = advanceTimeFence(connection, owner.ownerEpoch, observedAt);
  });
  requireHealthyFence(outcome);
  throw new KernelStorageError('LEASE_FENCED', 'merge preparation precedes its original owning cut');
}

/** Exact public run.approve, with its original authenticated frame kept
 * separate from the immutable request bytes. No caller selects a grant kind. */
export const approveChildMerge = stateOperation('INVALID_REQUEST', async (driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, input: { request: RunApproveRequestV1; identity: AuthenticatedControlIdentity; releaseKeys: readonly ReleaseTrustKey[] },
  signal?: AbortSignal) => {
  if (!exactKeys(input, ['request', 'identity', 'releaseKeys'])) throw new TypeError('child merge approval takes only its authenticated public request');
  const request = decodeInstalledControlRequest(input.request), identity = input.identity;
  if (request.method !== 'run.approve') throw new TypeError('child merge approval requires run.approve');
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  assertActiveStateOwner(driver, owner);
  let channel = await validateControlChannelClosure(reads, owner, identity);
  if (readSessionPrincipalId(driver, readRun(driver, request.runId).sessionId) !== identity.principalId)
    throw new KernelStorageError('NOT_FOUND', 'merge approval Run is unavailable');
  const replay = async () => {
    const prior = readControlRequest(driver, identity.principalId, 'run.approve', request.requestId);
    if (!prior) return undefined;
    if (prior.requestDigest !== request.requestDigest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.approve id was used with different bytes');
    const response = await readCanonicalArtifact<{ protocolVersion: 1; ok: true; result: { method: 'run.approve'; decisionRef: string } }>(reads, prior.responseRef);
    if (response.protocolVersion !== 1 || response.ok !== true || response.result?.method !== 'run.approve') invalid('original approval response is not a closed success');
    const original = await readChildMergeApproval(driver, reads, request.runId, response.result.decisionRef);
    if (original.decision.requestId !== request.requestId || original.decision.requestDigest !== request.requestDigest)
      invalid('replayed response belongs to another original approval request');
    requireEqual(original.control, prior, 'merge exact queried original control record');
    requireEqual(response, original.response, 'merge original first response');
    channel = await validateControlChannelClosure(reads, owner, identity);
    reads.assertReadActive(); assertActiveStateOwner(driver, owner);
    if (channel.channel.transport.kind === 'uds_peer') assertCurrentControlFrame(owner, identity);
    original.assertUnchanged(driver);
    return Object.freeze({ replayed: true as const, run: original.response.result.snapshot.run, response: original.response });
  };
  const prior = await replay(); if (prior) return prior;
  if (!readTimeFence(driver)) invalid('current canonical fence is missing');
  if (readTimeFence(driver)!.state !== 'healthy') requireHealthyFence('still_regressed');
  const selected = await currentMaterial(driver, reads, owner, { runId: request.runId,
    expectedRunRevision: request.expectedRevision, releaseKeys: input.releaseKeys }, signal);
  if (!selected.waiting || selected.source.run.waitingOnRef !== request.waitingOnRef || selected.principalId !== identity.principalId)
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'merge approval requires its exact current original subject');
  const createdAt = sampleCanonicalNow();
  preparationTime(driver, owner, selected.source, createdAt, identity, channel.channel.transport.kind === 'uds_peer');
  if (createdAt >= selected.original.deadlineAt) throw new KernelStorageError('LEASE_FENCED', 'merge approval has reached its original deadline');
  const actualOwner = assertActiveStateOwner(driver, owner), inspector = supervisorInspectorIdentity(actualOwner);
  const inspectorPlan = planCanonicalArtifact(inspector, inspector.format);
  const decisionCore = { schemaVersion: 1 as const, format: 'cliq-approval-decision-v1' as const,
    decisionId: identityHash(identity.principalId, request.runId, request.waitingOnRef, request.requestId, request.requestDigest),
    principalId: identity.principalId, channelIdentityRef: identity.channelIdentityRef, channelIdentityDigest: identity.channelIdentityDigest,
    stateOwnerEpoch: owner.ownerEpoch, supervisorInstanceId: actualOwner.supervisorInstanceId,
    inspectorIdentityRef: inspectorPlan.ref, inspectorIdentityDigest: inspector.identityDigest,
    runId: request.runId, waitingSubjectRef: request.waitingOnRef, waitingSubjectDigest: request.waitingOnRef,
    frontierRef: selected.request.frontierRef, subject: selected.wait.subject, subjectDigest: canonicalSha256(selected.wait.subject),
    requestId: request.requestId, requestDigest: request.requestDigest, expectedRunRevision: request.expectedRevision,
    decision: request.decision, ...(request.ttlMs === undefined ? {} : { requestedTtlMs: request.ttlMs }),
    ...(request.decision === 'allow' ? { grantExpiresAt: addCanonicalDuration(createdAt,
      Math.min(request.ttlMs ?? 3_600_000, Date.parse(selected.original.deadlineAt) - Date.parse(createdAt))) } : {}), createdAt };
  const decision = decodeChildMergeApprovalDecision({ ...decisionCore, decisionDigest: canonicalSha256(decisionCore) });
  const decisionPlan = planCanonicalArtifact(decision, decision.format), grant = approvalGrant(selected, decision);
  const item = policyItem(selected.evidence, decisionPlan.ref, grant, decision);
  const { requestDigest: _digest, ...requestCore } = request;
  const requestPlan = planCanonicalArtifact(requestCore, 'cliq-child-merge-approval-request-v1');
  if (requestPlan.ref !== request.requestDigest) invalid('wire request digest does not name its complete original bytes');
  const metadata = await publishPlans(reads, [requestPlan, inspectorPlan, decisionPlan, ...(grant ? [planCanonicalArtifact(grant, grant.format)] : [])]);
  await readSupervisorInspector(reads, actualOwner, selected.source.assembly, { ...decision, observedAt: createdAt });
  const frontier: RunFrontier = { schemaVersion: 1, kind: 'tool', batchItemId: selected.source.batch.itemId,
    orderedCallIds: selected.source.batch.calls.map(call => call.callId), nextCallIndex: selected.source.call.index };
  const plan = await prepareContinuationCommit(reads, { context: selected.source.context, existingItems: selected.source.items,
    items: [item], frontier, checkpointId: decisionCheckpointId(decisionPlan.ref), workspaceStateRef: selected.source.currentCheckpoint.workspaceStateRef });
  const { waitingOnRef: _wait, waitingReason: _reason, ...current } = selected.source.run;
  const next: Run = { ...current, ...plan.runUpdate, revision: current.revision + 1, status: 'queued', updatedAt: createdAt };
  const response = { protocolVersion: 1 as const, ok: true as const, result: { method: 'run.approve' as const,
    decisionRef: decisionPlan.ref, snapshot: { schemaVersion: 1 as const, operation: 'agent' as const, run: next, latestRunItemSeq: plan.throughItemSeq } } };
  const responsePlan = planCanonicalArtifact(response, 'cliq-control-application-response-v1');
  metadata.push(...await publishPlans(reads, [responsePlan]));
  channel = await validateControlChannelClosure(reads, owner, identity);
  let outcome: ReturnType<typeof advanceTimeFence> | undefined, committed = false;
  driver.transaction(connection => {
    reads.assertReadActive(); const live = assertActiveStateOwner(connection, owner);
    if (channel.channel.transport.kind === 'uds_peer') assertCurrentControlFrame(owner, identity);
    if (readControlRequest(connection, identity.principalId, 'run.approve', request.requestId)) return;
    selected.source.assertUnchanged(connection);
    const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
    assertChildAncestryRelease(connection, request.runId, now);
    if (now < createdAt || now >= (decision.grantExpiresAt ?? selected.original.deadlineAt) || live.acquiredAt > createdAt || channel.channel.openedAt > createdAt)
      throw new KernelStorageError('LEASE_FENCED', 'merge approval cannot extend its original prepared TTL or owner interval');
    for (const row of [...metadata, ...plan.metadata, ...channel.metadata]) insertArtifactMetadata(connection, row, now);
    // P is the immutable logical decision/response time. C is independently
    // retained by control_requests and is the only time advancing the fence.
    plan.commit(connection, selected.source.run, selected.source.journal.length, createdAt);
    connection.prepare("UPDATE runs SET status='queued',waiting_reason=NULL,waiting_on_ref=NULL,revision=revision+1,updated_at=? WHERE id=?")
      .run(createdAt, request.runId);
    requireEqual(readRun(connection, request.runId), next, 'merge original committed approval snapshot');
    appendRunStateEvent(connection, next, createdAt);
    insertControlRequest(connection, { ...identity, method: 'run.approve', requestId: request.requestId,
      requestDigest: request.requestDigest, responseRef: responsePlan.ref, committedAt: now }); committed = true;
  });
  requireHealthyFence(outcome);
  if (committed) return Object.freeze({ replayed: false as const, run: next, response });
  const raced = await replay(); if (raced) return raced;
  throw new KernelStorageError('REVISION_CONFLICT', 'merge approval lost its original control commit');
});

/** Called by ordinary recovery without reopening its parent. It validates
 * only registered child-merge source/approval data, never a future permit. */
export async function validateChildMergeAuthorizationHistory(driver: SqliteDriver, artifacts: ArtifactCatalog,
  input: { run: Run; items: ReadonlyMap<string, ContinuationItem> }) {
  requireEqual(readRun(driver, input.run.id), input.run, 'merge owning recovery Run');
  const policies = driver.prepare("SELECT item_id,payload_ref FROM items WHERE run_id=? AND kind='policy_decision' ORDER BY item_seq")
    .all<{ item_id: string; payload_ref: string }>(input.run.id);
  if ([...input.items.values()].filter(item => item.kind === 'policy_decision').length !== policies.length)
    invalid('recovery omitted or added a registered policy item');
  for (const row of policies) {
    const item = input.items.get(row.item_id);
    if (item?.kind !== 'policy_decision' || item.runId !== input.run.id || canonicalSha256(item) !== row.payload_ref)
      invalid('recovery policy item is not its exact owning SQL content');
  }
  for (const item of input.items.values()) {
    if (item.kind !== 'policy_decision' || item.subjectKind !== 'child_merge') continue;
    const original = await readChildMergeAuthorization(driver, artifacts, input.run.id, item.itemId);
    requireEqual(original.item, item, 'merge exact original recovery decision'); original.assertUnchanged(driver);
  }
  if (input.run.status === 'waiting' && input.run.waitingReason === 'approval' && input.run.waitingOnRef) {
    const wait = await readCanonicalArtifact<{ subject?: { kind?: string } }>(artifacts, input.run.waitingOnRef);
    if (wait.subject?.kind === 'child_merge') {
      const original = await readWait(driver, artifacts, input.run.id, input.run.waitingOnRef);
      assertChildMergeApprovalWaitingRun(original.waitingRun, input.run); original.source.assertUnchanged(driver);
    }
  }
  requireEqual(readRun(driver, input.run.id), input.run, 'merge completed original recovery Run');
}

/** Original pending-cost data only. The Stop producer binds these immutable
 * locators to its own registered source and tests the complete budget equation.
 * No current/past Run is fabricated, and no permission or local effect is made. */
const readPendingMergeBudgetData = stateOperation('RECOVERY_REQUIRED', async (
  driver: SqliteDriver, artifacts: ArtifactCatalog,
  input: { runId: string; sourceCheckpointId: string; sourceRunRevision: number; observedAt: string; sourceJournalSeq: number }
) => {
  if (!exactKeys(input, ['runId', 'sourceCheckpointId', 'sourceRunRevision', 'observedAt', 'sourceJournalSeq']) ||
      !Number.isSafeInteger(input.sourceRunRevision) || input.sourceRunRevision < 1 ||
      !Number.isSafeInteger(input.sourceJournalSeq) || input.sourceJournalSeq < 0) invalid('budget source locators are not closed');
  parseCanonicalTime(input.observedAt);
  const run = readRun(driver, input.runId), checkpoint = readCheckpoint(driver, input.sourceCheckpointId);
  const journal = readInvocationJournal(driver, run.id);
  const latest = driver.prepare('SELECT id FROM checkpoints WHERE run_id=? AND based_on_run_revision<? ORDER BY based_on_run_revision DESC,rowid DESC LIMIT 1')
    .get<{ id: string }>(run.id, input.sourceRunRevision);
  if (input.sourceRunRevision > run.revision || checkpoint.runId !== run.id || checkpoint.createdAt > input.observedAt ||
      latest?.id !== checkpoint.id || checkpoint.journalSeq > input.sourceJournalSeq || input.sourceJournalSeq > journal.length ||
      input.sourceRunRevision === run.revision && (checkpoint.id !== run.latestCheckpointId || input.sourceJournalSeq !== journal.length) ||
      journal.slice(0, input.sourceJournalSeq).some((row, i) => row.seq !== i + 1 || row.timestamp > input.observedAt))
    invalid('budget source is not its exact original Checkpoint/revision/Journal cut');
  const rows = driver.prepare('SELECT item_id,item_seq,kind,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: unknown; kind: string; payload_ref: string; created_at: string }>(run.id);
  if (checkpoint.runItemSeq > rows.length) invalid('budget source item prefix is incomplete');
  const items = await artifacts.mapReads(rows, async (row, index) => {
    const item = await readCanonicalArtifact<ContinuationItem>(artifacts, row.payload_ref);
    if (Number(row.item_seq) !== index + 1 || item.runId !== run.id || item.itemId !== row.item_id ||
        item.kind !== row.kind || item.createdAt !== row.created_at) invalid('budget source item changed its original SQL owner');
    return item;
  });
  const prefix = items.slice(0, checkpoint.runItemSeq);
  const batch = prefix.filter((item): item is ChildMergeBatchItem => item.kind === 'child_merge_batch').at(-1);
  if (!batch) return undefined;
  if (!exactKeys(batch, ['schemaVersion', 'kind', 'itemId', 'runId', 'resume', 'childResultItemIds', 'calls', 'createdAt']) ||
      batch.schemaVersion !== 1 || !Array.isArray(batch.calls) || !batch.calls.length) invalid('budget source has an invalid synthetic batch');
  const outcomes = prefix.filter((item): item is ChildMergeResultItem => item.kind === 'child_merge_result' && item.mergeBatchItemId === batch.itemId);
  if (outcomes.length > batch.calls.length || outcomes.some((item, i) => item.callIndex !== i || item.callId !== batch.calls[i]?.callId ||
      i < outcomes.length - 1 && item.outcome !== 'merged')) invalid('budget source has an invalid serial merge prefix');
  if (outcomes.length === batch.calls.length || outcomes.length && outcomes.at(-1)!.outcome !== 'merged') return undefined;
  const source = await readRetainedChildMergePlan(driver, artifacts, run.id, { mergeBatchItemId: batch.itemId,
    callIndex: outcomes.length, sourceCheckpointId: checkpoint.id });
  requireEqual(source.run, run, 'merge budget actual current Run cut');
  requireEqual(source.items.map(row => row.item), items, 'merge budget exact original item graph');
  const checkpointIds = driver.prepare('SELECT id FROM checkpoints WHERE run_id=? ORDER BY rowid').all<{ id: string }>(run.id);
  const checkpoints = checkpointIds.map(row => readCheckpoint(driver, row.id));
  const mergedAwaitResults = await (await import('./child-merge-history.js')).validateChildMergeHistory(driver, artifacts,
    { run, items: new Map(items.map(item => [item.itemId, item])), journal, checkpoints });
  await (await import('./child-wait-history.js')).validateChildWaitHistory(driver, artifacts, { run, spec: source.spec,
    items: new Map(items.map(item => [item.itemId, item])), journal, checkpoints, mergedAwaitResults,
    context: source.context, workspaceGenerations: source.generations });
  if (items.some(item => item.kind === 'child_merge_result' && item.mergeBatchItemId === batch.itemId && item.callIndex === source.call.index))
    return undefined;
  const policies: Array<Awaited<ReturnType<typeof readChildMergeAuthorization>>> = [];
  for (const item of prefix) {
    if (item.kind !== 'policy_decision' || item.subjectKind !== 'child_merge') continue;
    const evidence = decodeChildMergePolicyEvidence(await readCanonicalArtifact(artifacts, item.policyChannelEvidenceRef));
    const request = decodeChildMergeRequest(await readCanonicalArtifact(artifacts, evidence.requestRef));
    if (request.mergeBatchItemId !== batch.itemId || request.callIndex !== source.call.index) continue;
    if (request.callId !== source.call.callId || request.childRunId !== source.call.childRunId ||
        request.patchManifestRef !== source.call.patchManifestRef) invalid('budget permission changed the same original merge call');
    const actual = await readChildMergeAuthorization(driver, artifacts, run.id, item.itemId);
    if (policies.length) requireEqual(actual.request, policies[0]!.request, 'budget merge request cannot drift across approvals');
    if (actual.localUse.operationUsed) return undefined;
    requireEqual(actual.source.batch, source.batch, 'budget approved original synthetic batch');
    requireEqual(actual.source.call, source.call, 'budget approved original call');
    if (actual.source.checkpoint.workspaceStateRef !== checkpoint.workspaceStateRef || actual.request.sourceBaseRef !== source.sourceBaseRef ||
        actual.request.sourceDesiredRef !== source.sourceDesiredRef || actual.request.capturedWorkspaceRef !== source.capturedWorkspaceRef)
      invalid('budget approval cannot substitute a later workspace for original A');
    policies.push(actual);
  }
  const registered = policies.at(-1);
  if (registered) {
    if (registered.item.decision !== 'allow' || !registered.grant || registered.grant.issuedAt > input.observedAt ||
        registered.grant.expiresAt <= input.observedAt) return undefined;
  } else {
    const session = readSession(driver, run.sessionId), principalId = readSessionPrincipalId(driver, session.id);
    const base = decodeSourceManifest(await readCanonicalArtifact(artifacts, source.spec.baseWorkspaceManifestRef));
    const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, source.spec.policyRef);
    assertRunPolicySnapshot({ policy, policyRef: source.spec.policyRef, assembly: source.assembly, principalId, workspaceIdentityDigest: base.workspaceIdentityDigest });
    if (policy.createdAt > input.observedAt) invalid('budget observation precedes its original frozen policy');
    if (pathPolicy(policy, source.changedPaths).effectiveDisposition !== 'allow') return undefined;
  }
  const assertUnchanged = (connection: SqliteConnection) => {
    assertSqliteConnectionOwnedBy(driver, connection); artifacts.assertReadActive(); source.assertUnchanged(connection);
    requireEqual(connection.prepare('SELECT id FROM checkpoints WHERE run_id=? AND based_on_run_revision<? ORDER BY based_on_run_revision DESC,rowid DESC LIMIT 1')
      .get(run.id, input.sourceRunRevision), latest, 'budget original latest Checkpoint at its registered revision');
    for (const original of checkpoints) requireEqual(readCheckpoint(connection, original.id), original, 'budget original Checkpoint history');
    requireEqual(connection.prepare('SELECT id FROM checkpoints WHERE run_id=? ORDER BY rowid').all(run.id), checkpointIds, 'budget complete original Checkpoint set');
    for (const original of policies) original.assertUnchanged(connection);
  };
  assertUnchanged(driver);
  return Object.freeze({ required: 1 as const, assertUnchanged });
});

export async function readChildMergePendingBudgetData(driver: SqliteDriver, artifacts: ArtifactCatalog,
  input: Parameters<typeof readPendingMergeBudgetData>[2]) {
  try { return await readPendingMergeBudgetData(driver, artifacts, input); }
  catch (error) {
    if (error instanceof KernelStorageError && ['NOT_FOUND', 'ARTIFACT_MISMATCH', 'INVALID_REQUEST'].includes(error.code))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'child merge budget source is missing or invalid', { cause: error });
    throw error; // Preserve real cancellation and resource-retirement failures.
  }
}
