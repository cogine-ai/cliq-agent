import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { DeliveryDecisionItem } from '../kernel/delivery.js';
import type { DeliveryApprovalDecisionV1, DeliveryApprovalWait, DeliveryPlanGrantV1, DeliveryPolicyChannelEvidenceV1,
  DeliveryPolicyDecisionItem } from '../kernel/delivery-invocation.js';
import { identityHash } from '../kernel/identity.js';
import type { ContextManifest, ContinuationItem, RecoveryClosureV1, Run, RunFrontier } from '../kernel/types.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import { immutableSnapshot } from '../model/immutable.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { toolApprovalRequestDigest, type ToolApprovalInput } from '../policy/tool-approval.js';
import { contextSourceDigest, validateContextItems } from '../runtime/context-compaction.js';
import { decodeAgentStop, type AgentStopIntent } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { prepareContinuationCommit } from './continuation-commit.js';
import { readHistoricalControlChannel, validateControlChannelClosure } from './control-channel.js';
import { decodeContextManifest, decodeWorkspaceIdentity } from './decoders.js';
import { deliveryApprovalCheckpointId, deliveryApprovalDecision, deliveryDecisionCheckpointId,
  loadDeliveryPolicy, planDeliveryRequest } from './delivery-policy.js';
import { KernelStorageError, RunTerminalError, stateOperation } from './errors.js';
import { addBudget, isZeroBudget } from './invariants.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import type { RunAuthority } from './run-authority.js';
import { readDeliveryVerification } from './run-result-recovery.js';
import { insertControlRequest, readCheckpoint, readControlRequest, readRun, readSession, readSessionPrincipalId, ZERO_BUDGET } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

type ApprovalFrontier = Extract<RunFrontier, { kind: 'delivery'; phase: 'approval' }>;
type ApprovalResponse = { protocolVersion: 1; ok: true; result: { method: 'run.approve'; decisionRef: string;
  snapshot: { schemaVersion: 1; operation: 'delivery'; run: Run; latestRunItemSeq: number } } };
const same = (left: unknown, right: unknown) => canonicalSha256(left) === canonicalSha256(right);
export const deliveryDecisionItemId = (runId: string, planRef: string, decisionRef: string) =>
  identityHash('cliq-delivery-decision-item-v1', runId, planRef, decisionRef);
const policyItemId = (runId: string, opId: string, decisionRef: string) => identityHash('cliq-delivery-policy-item-v1', runId, opId, decisionRef);

/** Complete retained data only. The supplied cut is not a live publication
 * permit, and this reader never recursively reads its own RecoveryClosure. */
export async function readDeliveryApprovalContext(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: RecoveryClosureV1, frontierRef: string) {
  if (cut.runSpec.operation !== 'delivery') throw new TypeError('only delivery can own plan approval');
  const frontier = await readCanonicalArtifact<ApprovalFrontier>(artifacts, frontierRef);
  if (frontier.kind !== 'delivery' || frontier.phase !== 'approval') throw new TypeError('approval requires its original delivery frontier');
  const verified = await readDeliveryVerification(driver, artifacts, cut, frontier.verificationClosureRef);
  if (!verified.deliveryPlan.forwardOperations.length)
    throw new TypeError('no-op delivery cannot acquire a plan approval or publication grant');
  requireEqual(frontier, { schemaVersion: 1, kind: 'delivery', phase: 'approval',
    sourceRunResultRef: verified.admission.request.expectedRunResultRef, candidateItemId: verified.candidate.itemId,
    resultSourceRef: verified.candidate.resultSourceRef, verifierPlanRef: verified.planRef,
    verificationClosureRef: canonicalSha256(verified.closure), deliveryPlanRef: verified.deliveryPlanRef }, 'delivery approval carried verification');
  const target = verified.admission.target;
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, target.workspaceIdentityRef));
  if (workspace.kind !== 'live' || workspace.identityDigest !== target.workspaceIdentityDigest)
    throw new TypeError('delivery approval lost its exact live workspace identity');
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, cut.runSpec.assemblyRef));
  const context = { runId: cut.run.id, frontierRef, assemblyRef: cut.runSpec.assemblyRef,
    planRef: verified.deliveryPlanRef, plan: verified.deliveryPlan,
    workspaceIdentityRef: target.workspaceIdentityRef, workspaceIdentityDigest: target.workspaceIdentityDigest };
  const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, cut.runSpec.policyRef);
  const evaluator = loadDeliveryPolicy({ policy, policyRef: cut.runSpec.policyRef, assembly, assemblyRef: cut.runSpec.assemblyRef,
    principalId: workspace.ownerPrincipalId, workspaceIdentityDigest: workspace.identityDigest, context });
  return { frontier, frontierRef, verified, workspace, context, evaluator, ...planDeliveryRequest(context) };
}
type ApprovalContext = Awaited<ReturnType<typeof readDeliveryApprovalContext>>;

function originalApprovalRun(driver: SqliteDriver, cut: RecoveryClosureV1, selected: ApprovalContext): Run {
  const checkpoint = selected.verified.checkpoint;
  const consumed = cut.journal.filter(row => row.seq <= checkpoint.journalSeq && ['completed', 'failed', 'unknown'].includes(row.phase))
    .reduce((sum, row) => addBudget(sum, row.budgetDelta, 'delivery approval original consumption'), ZERO_BUDGET);
  // Revision ordering, not wall-clock inequality: a later publication worker
  // may legitimately be born in the same canonical millisecond.
  const leaseEpoch = Math.max(0, ...readWorkerLaunchesForRun(driver, cut.run.id).flatMap(launch =>
    launch.activatedAt && launch.leaseEpoch !== undefined && launch.plannedRunRevision < checkpoint.basedOnRunRevision + 1 ? [launch.leaseEpoch] : []));
  return { id: cut.run.id, sessionId: cut.run.sessionId, specRef: cut.run.specRef, status: 'queued', nextStep: 'delivery',
    frontierRef: selected.frontierRef, revision: checkpoint.basedOnRunRevision + 1, leaseEpoch,
    latestCheckpointId: checkpoint.id, budgetReserved: ZERO_BUDGET, budgetConsumed: consumed, repairCount: 0,
    cancelRequested: false, createdAt: cut.run.createdAt, deadlineAt: cut.run.deadlineAt, updatedAt: checkpoint.createdAt };
}
function denial(selected: ApprovalContext, createdAt: string, decision?: DeliveryApprovalDecisionV1): AgentStopIntent {
  return decision ? { schemaVersion: 1, runId: selected.context.runId, createdAt, origin: 'user_cancel', targetStatus: 'cancelled',
    reason: 'cancelled_by_user', requestId: decision.requestId, principalId: decision.principalId }
    : { schemaVersion: 1, runId: selected.context.runId, createdAt, origin: 'policy_deny', subjectKind: 'delivery',
      targetStatus: 'failed', reason: 'runtime_failed', opId: selected.request.opId,
      policyChannelEvidenceRef: canonicalSha256(selected.evaluator.evaluate(selected.request, selected.target, createdAt)),
      policyChannelEvidenceDigest: selected.evaluator.evaluate(selected.request, selected.target, createdAt).evidenceDigest };
}
function decisionItems(selected: ApprovalContext, evidence: DeliveryPolicyChannelEvidenceV1,
  decisionRef: string, createdAt: string, grant?: DeliveryPlanGrantV1, interactive?: DeliveryApprovalDecisionV1) {
  const grantRef = grant && canonicalSha256(grant), stop = grant ? undefined : denial(selected, createdAt, interactive);
  const common = { schemaVersion: 1 as const, kind: 'policy_decision' as const, subjectKind: 'delivery_plan' as const,
    itemId: policyItemId(selected.context.runId, selected.request.opId, decisionRef), runId: selected.context.runId,
    opId: selected.request.opId, principalId: selected.workspace.ownerPrincipalId, decisionRef,
    policyChannelEvidenceRef: canonicalSha256(evidence), policyChannelEvidenceDigest: evidence.evidenceDigest, createdAt };
  const source = interactive ? { decisionSource: 'interactive_approval' as const, waitingSubjectRef: interactive.waitingSubjectRef }
    : { decisionSource: 'direct_policy' as const };
  const policy: DeliveryPolicyDecisionItem = grantRef ? { ...common, ...source, decision: 'allow', grantRef }
    : { ...common, ...source, decision: 'deny', denialOutcome: { kind: 'delivery_stopped', subjectKind: 'delivery_plan', stopIntentRef: canonicalSha256(stop) } };
  const delivery: DeliveryDecisionItem = { schemaVersion: 1, kind: 'delivery_decision',
    itemId: deliveryDecisionItemId(selected.context.runId, selected.context.planRef, decisionRef), runId: selected.context.runId,
    deliveryPlanRef: selected.context.planRef, approvalOpId: selected.request.opId, decision: grant ? 'allow' : 'deny',
    decisionRef, ...(grantRef ? { grantRef } : {}), createdAt };
  const frontier: RunFrontier = grant ? { ...selected.frontier, phase: 'publish', nextPathOperationIndex: 0 } : selected.frontier;
  return { policy, delivery, stop, frontier, items: [policy, delivery] as ContinuationItem[] };
}
async function readWait(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1, selected: ApprovalContext, ref: string) {
  const wait = await readCanonicalArtifact<DeliveryApprovalWait>(artifacts, ref);
  const evidence = await readCanonicalArtifact<DeliveryPolicyChannelEvidenceV1>(artifacts, wait.subject.policyChannelEvidenceRef);
  requireEqual(evidence, selected.evaluator.evaluate(selected.request, selected.target, evidence.evaluatedAt), 'delivery original ask evidence');
  requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(selected.request)), selected.request, 'delivery original ask request');
  requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(selected.target)), selected.target, 'delivery original ask target');
  const original = originalApprovalRun(driver, cut, selected);
  requireEqual(wait, selected.evaluator.approvalWait(selected.request, selected.target, evidence, original.revision), 'delivery exact original wait');
  if (canonicalSha256(wait) !== ref || wait.createdAt < original.updatedAt || wait.createdAt >= original.deadlineAt)
    throw new TypeError('delivery approval wait has a foreign identity or lifetime');
  const checkpoint = readCheckpoint(driver, deliveryApprovalCheckpointId(ref));
  requireEqual(checkpoint, { ...selected.verified.checkpoint, id: deliveryApprovalCheckpointId(ref), reason: 'auto',
    basedOnRunRevision: original.revision, createdAt: wait.createdAt }, 'delivery original worker-free wait Checkpoint');
  return { wait, evidence, checkpoint, original };
}

/** An unconsumed ask remains a complete retained decision, not absence of
 * authorization history. Cancellation locators come only from the real
 * authenticated run.cancel response; no path or CAS enumeration recovers one. */
async function readUndecidedDeliveryWait(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  currentFrontier: RunFrontier | undefined) {
  const pending = cut.run.waitingReason === 'approval';
  if (pending && (cut.run.status !== 'waiting' || !cut.run.waitingOnRef || !cut.run.frontierRef ||
      currentFrontier?.kind !== 'delivery' || currentFrontier.phase !== 'approval'))
    throw new TypeError('delivery ask lost its original approval frontier');
  async function snapshot(actual: Run) {
    if (actual.status !== 'waiting' || actual.waitingReason !== 'approval' || !actual.waitingOnRef || !actual.frontierRef)
      throw new TypeError('delivery ask has no original waiting Run snapshot');
    const selected = await readDeliveryApprovalContext(driver, artifacts, cut, actual.frontierRef);
    const proof = await readWait(driver, artifacts, cut, selected, actual.waitingOnRef);
    const expected: Run = { ...proof.original, status: 'waiting', waitingReason: 'approval', waitingOnRef: actual.waitingOnRef,
      revision: proof.original.revision + 1, latestCheckpointId: proof.checkpoint.id, updatedAt: proof.wait.createdAt };
    const { revision, updatedAt, stopIntentRef, cancelRequested, ...stable } = actual;
    const { revision: originalRevision, updatedAt: originalUpdatedAt, cancelRequested: _cancel, ...originalStable } = expected;
    requireEqual(stable, originalStable, 'delivery pending ask immutable Run snapshot');
    if (revision < originalRevision || revision > cut.run.revision || updatedAt < originalUpdatedAt || updatedAt > cut.run.updatedAt ||
        cut.items.length !== proof.checkpoint.runItemSeq || cut.journal.length !== proof.checkpoint.journalSeq ||
        readWorkerLaunchesForRun(driver, cut.run.id).some(launch => launch.phase !== 'retired') ||
        readWorkspaceGenerationsForRun(driver, cut.run.id).some(generation => !['sealed', 'retired'].includes(generation.phase)))
      throw new TypeError('delivery ask advanced without its original decision or worker-free Checkpoint');
    if (stopIntentRef) {
      const stop = decodeAgentStop(await readCanonicalArtifact(artifacts, stopIntentRef), actual);
      if (revision <= originalRevision || stop.createdAt < originalUpdatedAt || stop.createdAt > updatedAt ||
          !(cancelRequested ? stop.origin === 'user_cancel' || stop.origin === 'kernel_integrity' : stop.origin === 'deadline'))
        throw new TypeError('delivery pending ask changed without an exact supported stop');
    } else requireEqual(actual, expected, 'delivery unchanged pending ask Run');
    return proof;
  }
  const current = pending ? await snapshot(cut.run) : undefined;
  let retainedWait = false;
  if (cut.run.cancelRequested) {
    if (!cut.run.stopIntentRef) throw new TypeError('delivery cancellation lost its original stop');
    const stop = decodeAgentStop(await readCanonicalArtifact(artifacts, cut.run.stopIntentRef), cut.run);
    const { readCancelResponse } = await import('./stop-recovery.js');
    const principalId = readSessionPrincipalId(driver, cut.run.sessionId);
    const controls = stop.origin === 'user_cancel' ? [{ request_id: stop.requestId }]
      : stop.origin === 'kernel_integrity' ? driver.prepare("SELECT request_id FROM control_requests WHERE principal_id=? AND method='run.cancel'")
        .all<{ request_id: string }>(principalId) : [];
    for (const row of controls) {
      if (stop.origin === 'kernel_integrity') {
        const control = readControlRequest(driver, principalId, 'run.cancel', row.request_id)!;
        const response = await readCanonicalArtifact<{ result?: { snapshot?: { run?: { id?: string } } } }>(artifacts, control.responseRef);
        if (response.result?.snapshot?.run?.id !== cut.run.id) continue;
      }
      const { response, row: control } = await readCancelResponse(driver, artifacts, cut.run, principalId, row.request_id);
      if (stop.origin === 'user_cancel' && (stop.principalId !== principalId || control.committedAt !== stop.createdAt ||
          response.result.snapshot.run.stopIntentRef !== cut.run.stopIntentRef))
        throw new TypeError('delivery cancellation lacks its exact original control-row owner');
      const original = response.result.snapshot.run;
      if (original.waitingReason !== 'approval') continue;
      const proof = await snapshot(original);
      if (response.result.snapshot.latestRunItemSeq !== proof.checkpoint.runItemSeq ||
          current && canonicalSha256(current.wait) !== canonicalSha256(proof.wait))
        throw new TypeError('delivery cancellation changed the original pending ask');
      retainedWait = true;
    }
    if (pending && !retainedWait) throw new TypeError('cancelled delivery ask lacks its original authenticated run.cancel snapshot');
  }
  // A cleared, unreferenced historical ask cannot release anything. Candidate
  // existence does not prove that an ask ever existed; the independent stop
  // recovery reader still reproduces the terminal StopIntent and retirement.
}

export async function readDeliveryAuthorization(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  if (cut.runSpec.operation !== 'delivery') throw new TypeError('Agent Run cannot own delivery authorization');
  const decoded = await artifacts.mapReads(cut.items, async row => ({ row, item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) }));
  const decisions = decoded.filter(({ item }) => item.kind === 'delivery_decision');
  const policies = decoded.filter(({ item }) => item.kind === 'policy_decision' && item.subjectKind === 'delivery_plan');
  const currentFrontier = cut.run.frontierRef ? await readCanonicalArtifact<RunFrontier>(artifacts, cut.run.frontierRef) : undefined;
  const requiresAllow = cut.journal.some(entry => entry.opKind === 'publish') || decoded.some(({ item }) =>
    item.kind === 'publication_path_progress' || item.kind === 'publication_path_result') ||
    currentFrontier?.kind === 'delivery' && ['publish', 'abort_cleanup'].includes(currentFrontier.phase);
  if (decisions.length === 0 && policies.length === 0) {
    if (requiresAllow) throw new TypeError('publication lost its original complete delivery allow');
    await readUndecidedDeliveryWait(driver, artifacts, cut, currentFrontier);
    return undefined;
  }
  if (decisions.length !== 1 || policies.length !== 1) throw new TypeError('delivery plan requires its unique atomic policy and delivery decision');
  const policy = policies[0]!.item as DeliveryPolicyDecisionItem, delivery = decisions[0]!.item as DeliveryDecisionItem;
  const evidence = await readCanonicalArtifact<DeliveryPolicyChannelEvidenceV1>(artifacts, policy.policyChannelEvidenceRef);
  const selected = await readDeliveryApprovalContext(driver, artifacts, cut, evidence.frontierRef);
  requireEqual(evidence, selected.evaluator.evaluate(selected.request, selected.target, evidence.evaluatedAt), 'delivery retained named-action evidence');
  requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(selected.request)), selected.request, 'delivery original approval request');
  requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(selected.target)), selected.target, 'delivery original approval target');
  let grant: DeliveryPlanGrantV1 | undefined, interactive: DeliveryApprovalDecisionV1 | undefined;
  let before = originalApprovalRun(driver, cut, selected);
  if (policy.decisionSource === 'interactive_approval') {
    interactive = await readCanonicalArtifact<DeliveryApprovalDecisionV1>(artifacts, policy.decisionRef);
    const proof = await readWait(driver, artifacts, cut, selected, interactive.waitingSubjectRef);
    requireEqual(evidence, proof.evidence, 'delivery approved original ask');
    grant = selected.evaluator.approve(selected.request, selected.target, evidence, proof.wait, interactive, cut.run.deadlineAt);
    before = { ...before, status: 'waiting', waitingReason: 'approval', waitingOnRef: interactive.waitingSubjectRef,
      revision: before.revision + 1, latestCheckpointId: proof.checkpoint.id, updatedAt: proof.wait.createdAt };
  } else if (policy.decisionSource === 'direct_policy') {
    if (evidence.effectiveDisposition === 'ask' || policy.decisionRef !== canonicalSha256(evidence)) throw new TypeError('direct delivery cannot bypass an ask');
    if (evidence.effectiveDisposition === 'allow') grant = selected.evaluator.grant(selected.request, selected.target, evidence, policy.createdAt, cut.run.deadlineAt);
    if (policy.createdAt !== evidence.evaluatedAt) throw new TypeError('direct delivery decision changed its original observation');
  } else throw new TypeError('unknown delivery decision source');
  const expected = decisionItems(selected, evidence, policy.decisionRef, policy.createdAt, grant, interactive);
  requireEqual(policy, expected.policy, 'delivery closed policy decision'); requireEqual(delivery, expected.delivery, 'delivery closed plan decision');
  if (requiresAllow && !grant) throw new TypeError('publication lost its original complete delivery allow');
  if (cut.run.waitingReason === 'approval') throw new TypeError('delivery consumed its approval but retained a pending ask');
  if (policy.createdAt < before.updatedAt || policy.createdAt >= cut.run.deadlineAt ||
      policies[0]!.row.itemSeq !== selected.verified.checkpoint.runItemSeq + 1 || decisions[0]!.row.itemSeq !== policies[0]!.row.itemSeq + 1 ||
      policies[0]!.row.createdAt !== policy.createdAt || decisions[0]!.row.createdAt !== policy.createdAt)
    throw new TypeError('delivery decision changed its original order or lifetime');
  if (grant) requireEqual(await readCanonicalArtifact(artifacts, delivery.grantRef!), grant, 'delivery parent grant');
  if (expected.stop) requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(expected.stop)), expected.stop, 'delivery original denial stop');
  const checkpointId = deliveryDecisionCheckpointId(cut.run.id, selected.context.planRef, policy.decisionRef);
  const checkpoint = readCheckpoint(driver, checkpointId), original = selected.verified.checkpoint;
  if (checkpoint.runId !== cut.run.id || checkpoint.reason !== 'auto' || checkpoint.basedOnRunRevision !== before.revision ||
      checkpoint.runItemSeq !== decisions[0]!.row.itemSeq || checkpoint.journalSeq !== original.journalSeq ||
      checkpoint.workspaceStateRef !== original.workspaceStateRef || checkpoint.createdAt !== policy.createdAt)
    throw new TypeError('delivery decision lost its exact original atomic Checkpoint');
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  const base = decodeContextManifest(await readCanonicalArtifact(artifacts, original.contextManifestRef));
  const additions = [policies[0]!, decisions[0]!].map(({ row, item }) => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef, item }));
  const appended: ContextManifest = { ...base, segments: [...base.segments, ...additions.map(entry => ({ kind: 'excluded_control' as const,
    fromItemSeq: entry.itemSeq, throughItemSeq: entry.itemSeq, sourceItemsDigest: contextSourceDigest([entry]) }))],
    throughItemSeq: checkpoint.runItemSeq, projectionDigest: '' };
  const { projectionDigest: _digest, ...core } = appended; appended.projectionDigest = canonicalSha256(core);
  requireEqual(context, appended, 'delivery original decision context');
  validateContextItems(context, decoded.filter(({ row }) => row.itemSeq <= checkpoint.runItemSeq)
    .map(({ row, item }) => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef, item })));
  const { waitingOnRef: _wait, waitingReason: _reason, ...withoutWait } = before;
  const next: Run = { ...withoutWait, status: 'queued', revision: before.revision + 1, latestCheckpointId: checkpointId,
    frontierRef: canonicalSha256(expected.frontier), updatedAt: policy.createdAt,
    ...(expected.stop ? { stopIntentRef: canonicalSha256(expected.stop), cancelRequested: expected.stop.origin === 'user_cancel' } : {}) };
  requireEqual(await readCanonicalArtifact(artifacts, next.frontierRef!), expected.frontier, 'delivery post-decision frontier');
  let response: ApprovalResponse | undefined;
  if (interactive) {
    const row = readControlRequest(driver, interactive.principalId, 'run.approve', interactive.requestId);
    if (!row || row.requestDigest !== interactive.requestDigest || row.channelIdentityRef !== interactive.channelIdentityRef ||
        row.channelIdentityDigest !== interactive.channelIdentityDigest || row.committedAt !== interactive.createdAt)
      throw new TypeError('delivery approval lacks its original authenticated control transaction');
    const { channel } = await readHistoricalControlChannel(driver, artifacts, interactive);
    if (channel.openedAt > interactive.createdAt) throw new TypeError('delivery approval preceded its authenticated channel');
    response = { protocolVersion: 1, ok: true, result: { method: 'run.approve', decisionRef: policy.decisionRef,
      snapshot: { schemaVersion: 1, operation: 'delivery', run: next, latestRunItemSeq: checkpoint.runItemSeq } } };
    requireEqual(await readCanonicalArtifact(artifacts, row.responseRef), response, 'delivery exact committed approval response');
  }
  return { ...selected, grant, grantRef: delivery.grantRef, decision: delivery, policyDecision: policy,
    interactive, stop: expected.stop, checkpoint, response, next };
}

/** Every retained denial, including one later outranked by integrity, is
 * validated through the same original control/evidence/decision closure. */
export async function readDeliveryPolicyDenial(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  if (cut.runSpec.operation !== 'delivery') return undefined;
  const authority = await readDeliveryAuthorization(driver, artifacts, cut);
  return authority?.stop;
}

export function loadDeliveryApproval(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  authority: Pick<RunAuthority['controlAuthority'], 'run' | 'spec' | 'principalId' | 'assertAuthority'>) {
  const runId = authority.run.id;
  const itemRows = (connection: SqliteConnection) => connection.prepare(
    'SELECT item_id,session_id,run_id,item_seq,kind,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
    .all<{ item_id: string; session_id: string | null; run_id: string; item_seq: bigint; kind: string; payload_ref: string; created_at: string }>(runId)
    .map(row => ({ ...row, item_seq: Number(row.item_seq) }));
  const sessionIdentity = (session: ReturnType<typeof readSession>) => ({ id: session.id,
    workspaceIdentityRef: session.workspaceIdentityRef, createdAt: session.createdAt,
    ...(session.parentSessionId === undefined ? {} : { parentSessionId: session.parentSessionId, forkedThroughItemSeq: session.forkedThroughItemSeq }) });
  type CutBinding = { ownedRows: ReturnType<typeof itemRows>; launches: ReturnType<typeof readWorkerLaunchesForRun>;
    generations: ReturnType<typeof readWorkspaceGenerationsForRun>; sourceRun: Run; sourceSession: ReturnType<typeof sessionIdentity> };
  async function current(expected: number) {
    if (authority.spec.operation !== 'delivery') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'only delivery can approve publication');
    assertActiveStateOwner(driver, owner); await authority.assertAuthority();
    const cut = await readRecoveryClosure(driver, artifacts, runId), run = cut.run;
    if (run.revision !== expected) throw new KernelStorageError('REVISION_CONFLICT', 'delivery approval revision changed');
    if (['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(run.status)) throw new RunTerminalError();
    if (run.specRef !== authority.run.specRef || run.createdAt !== authority.run.createdAt || run.deadlineAt !== authority.run.deadlineAt ||
        run.nextStep !== 'delivery' || !run.frontierRef || !['queued', 'waiting'].includes(run.status) ||
        run.activeWorkerLaunchId || run.stopIntentRef || run.cancelRequested || !isZeroBudget(run.budgetReserved) ||
        readWorkerLaunchesForRun(driver, runId).some(launch => launch.phase !== 'retired') ||
        readWorkspaceGenerationsForRun(driver, runId).some(generation => !['sealed', 'retired'].includes(generation.phase)))
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'delivery approval requires its unstopped worker-free verified cut');
    const ownedRows = itemRows(driver), launches = readWorkerLaunchesForRun(driver, runId),
      generations = readWorkspaceGenerationsForRun(driver, runId);
    const selected = await readDeliveryApprovalContext(driver, artifacts, cut, run.frontierRef);
    if (selected.workspace.ownerPrincipalId !== authority.principalId || !selected.context.plan.forwardOperations.length)
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'delivery approval requires the owning principal and a nonempty plan');
    // Never turn same-count row replacement or phase-only resource drift
    // during the asynchronous retained-source walk into the accepted cut.
    const decoded = await artifacts.mapReads(cut.items, async row => ({ ...row,
      item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) }));
    requireEqual(ownedRows, decoded.map(row => ({ item_id: row.itemId, session_id: null, run_id: runId,
      item_seq: row.itemSeq, kind: row.item.kind, payload_ref: row.payloadRef, created_at: row.createdAt })), 'delivery approval original item rows');
    const binding = immutableSnapshot({ ownedRows, launches, generations,
      sourceRun: selected.verified.admission.source.run,
      sourceSession: sessionIdentity(selected.verified.admission.source.session) });
    assertCut(driver, cut, binding);
    return { cut, selected, binding };
  }
  function assertCut(connection: SqliteConnection, cut: RecoveryClosureV1, binding: CutBinding) {
    assertActiveStateOwner(connection, owner);
    if (!same(readRun(connection, runId), cut.run) || !same(readInvocationJournal(connection, runId), cut.journal) ||
        !same(readCheckpoint(connection, cut.run.latestCheckpointId), cut.latestCheckpoint) ||
        !same(itemRows(connection), binding.ownedRows) ||
        !same(readWorkerLaunchesForRun(connection, runId), binding.launches) ||
        !same(readWorkspaceGenerationsForRun(connection, runId), binding.generations) ||
        !same(readRun(connection, binding.sourceRun.id), binding.sourceRun) ||
        !same(sessionIdentity(readSession(connection, binding.sourceSession.id)), binding.sourceSession) ||
        readSessionPrincipalId(connection, binding.sourceSession.id) !== authority.principalId ||
        connection.prepare('SELECT 1 FROM child_allocations WHERE parent_run_id=? OR child_run_id=? LIMIT 1').get(runId, runId) ||
        connection.prepare('SELECT 1 FROM runs WHERE parent_run_id=? LIMIT 1').get(runId))
      throw new KernelStorageError('REVISION_CONFLICT', 'delivery approval current owner or continuation changed');
  }
  function accept(connection: SqliteConnection, cut: RecoveryClosureV1, binding: CutBinding, createdAt: string) {
    assertCut(connection, cut, binding); const now = sampleCanonicalNow(), fence = readTimeFence(connection);
    if (!fence) throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery approval canonical fence is missing');
    if (now < createdAt || now < fence.lastAcceptedAt) return advanceTimeFence(connection, owner.ownerEpoch, now);
    if (createdAt < fence.lastAcceptedAt) return undefined;
    if (createdAt >= cut.run.deadlineAt || now >= cut.run.deadlineAt) throw new KernelStorageError('LEASE_FENCED', 'delivery approval deadline elapsed');
    return advanceTimeFence(connection, owner.ownerEpoch, createdAt);
  }
  async function graph(cut: RecoveryClosureV1, items: ContinuationItem[], frontier: RunFrontier, checkpointId: string,
    additional: Parameters<typeof prepareContinuationCommit>[1]['artifacts']) {
    return prepareContinuationCommit(artifacts, { context: decodeContextManifest(await readCanonicalArtifact(artifacts, cut.latestCheckpoint.contextManifestRef)),
      existingItems: await artifacts.mapReads(cut.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
        item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) })), items, frontier, checkpointId,
      workspaceStateRef: cut.latestCheckpoint.workspaceStateRef, artifacts: additional });
  }
  return {
    prepareDeliveryApproval: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision']) || !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1)
        throw new TypeError('delivery approval accepts only its exact current revision');
      const { cut, selected, binding } = await current(input.expectedRunRevision);
      if (cut.run.status !== 'queued') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'delivery already owns its approval wait');
      requireEqual(cut.run, originalApprovalRun(driver, cut, selected), 'delivery original approval Run');
      for (let retry = 0; retry < 8; retry++) {
        const at = sampleCanonicalNow(), evidence = selected.evaluator.evaluate(selected.request, selected.target, at);
        const common = [planCanonicalArtifact(selected.request, selected.request.format), planCanonicalArtifact(selected.target, selected.target.format),
          planCanonicalArtifact(evidence, evidence.format)];
        let waitingOnRef: string | undefined, grant: DeliveryPlanGrantV1 | undefined;
        let items: ContinuationItem[] = [], frontier: RunFrontier = selected.frontier, stop: AgentStopIntent | undefined, checkpointId: string;
        if (evidence.effectiveDisposition === 'ask') {
          const wait = selected.evaluator.approvalWait(selected.request, selected.target, evidence, cut.run.revision);
          const planned = planCanonicalArtifact(wait, 'cliq-waiting-subject-v1'); common.push(planned);
          waitingOnRef = planned.ref; checkpointId = deliveryApprovalCheckpointId(planned.ref);
        } else {
          if (evidence.effectiveDisposition === 'allow') grant = selected.evaluator.grant(selected.request, selected.target, evidence, at, cut.run.deadlineAt);
          const result = decisionItems(selected, evidence, canonicalSha256(evidence), at, grant);
          ({ items, frontier, stop } = result); checkpointId = deliveryDecisionCheckpointId(runId, selected.context.planRef, canonicalSha256(evidence));
          if (grant) common.push(planCanonicalArtifact(grant, grant.format));
          if (stop) common.push(planCanonicalArtifact(stop, 'cliq-stop-intent-v1'));
        }
        const planned = await graph(cut, items, frontier, checkpointId, common);
        let outcome: TimeFenceAdvance | undefined, updated: Run | undefined;
        driver.transaction(connection => {
          outcome = accept(connection, cut, binding, at); if (outcome !== 'healthy') return;
          for (const artifact of planned.metadata) insertArtifactMetadata(connection, artifact, at);
          planned.commit(connection, cut.run, cut.journal.length, at);
          connection.prepare('UPDATE runs SET status=?,waiting_reason=?,waiting_on_ref=?,stop_intent_ref=?,revision=revision+1,updated_at=? WHERE id=?')
            .run(waitingOnRef ? 'waiting' : 'queued', waitingOnRef ? 'approval' : null, waitingOnRef ?? null, stop ? canonicalSha256(stop) : null, at, runId);
          updated = readRun(connection, runId); appendRunStateEvent(connection, updated, at);
        });
        requireHealthyFence(outcome);
        if (updated) return immutableSnapshot({ disposition: waitingOnRef ? 'waiting' as const : grant ? 'approved' as const : 'denied' as const,
          run: updated, ...(waitingOnRef ? { waitingOnRef } : {}), ...(grant ? { grantRef: canonicalSha256(grant) } : {}) });
      }
      throw new KernelStorageError('REVISION_CONFLICT', 'delivery approval time fence kept changing');
    }),
    approveDelivery: stateOperation('INVALID_REQUEST', async (input: ToolApprovalInput) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['principalId', 'channelIdentityRef', 'channelIdentityDigest', 'requestId', 'expectedRunRevision',
        'waitingOnRef', 'decision', ...(input.ttlMs === undefined ? [] : ['ttlMs'])])) throw new TypeError('unknown delivery run.approve field');
      const requestDigest = toolApprovalRequestDigest(runId, input);
      if (input.principalId !== authority.principalId) throw new KernelStorageError('ARTIFACT_MISMATCH', 'delivery approval has a foreign principal');
      const channel = await validateControlChannelClosure(artifacts, owner, input);
      const replay = async () => {
        const row = readControlRequest(driver, input.principalId, 'run.approve', input.requestId); if (!row) return undefined;
        if (row.requestDigest !== requestDigest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'delivery approval requestId was reused');
        const cut = await readRecoveryClosure(driver, artifacts, runId), retained = await readDeliveryAuthorization(driver, artifacts, cut);
        if (!retained?.interactive || retained.interactive.requestId !== input.requestId || !retained.response || row.responseRef !== canonicalSha256(retained.response))
          throw new TypeError('delivery replay lacks its complete original approval closure');
        return immutableSnapshot({ replayed: true, run: retained.response.result.snapshot.run, response: retained.response });
      };
      const existing = await replay(); if (existing) return existing;
      const { cut, selected, binding } = await current(input.expectedRunRevision).catch(error => {
        // This public decision can arrive after its wait disappeared. Refuse
        // that business precondition without disguising storage/authority or
        // retirement failures as an invalid request.
        if (error instanceof KernelStorageError && error.code === 'STATE_TRANSITION_INVALID')
          throw new KernelStorageError('INVALID_REQUEST', 'delivery approval has no current eligible wait');
        throw error;
      });
      if (cut.run.status !== 'waiting' || cut.run.waitingReason !== 'approval' || cut.run.waitingOnRef !== input.waitingOnRef)
        throw new KernelStorageError('INVALID_REQUEST', 'delivery approval requires its exact original wait');
      const proof = await readWait(driver, artifacts, cut, selected, input.waitingOnRef);
      requireEqual(cut.run, { ...proof.original, status: 'waiting', waitingReason: 'approval', waitingOnRef: input.waitingOnRef,
        revision: proof.original.revision + 1, latestCheckpointId: proof.checkpoint.id, updatedAt: proof.wait.createdAt }, 'delivery exact current wait Run');
      for (let retry = 0; retry < 8; retry++) {
        const at = sampleCanonicalNow(), decision = deliveryApprovalDecision(proof.wait, input, at, cut.run.deadlineAt);
        const grant = selected.evaluator.approve(selected.request, selected.target, proof.evidence, proof.wait, decision, cut.run.deadlineAt);
        const decisionPlan = planCanonicalArtifact(decision, decision.format), expected = decisionItems(selected, proof.evidence, decisionPlan.ref, at, grant, decision);
        const additional = [decisionPlan, ...(grant ? [planCanonicalArtifact(grant, grant.format)] : []),
          ...(expected.stop ? [planCanonicalArtifact(expected.stop, 'cliq-stop-intent-v1')] : [])];
        const checkpointId = deliveryDecisionCheckpointId(runId, selected.context.planRef, decisionPlan.ref);
        const planned = await graph(cut, expected.items, expected.frontier, checkpointId, additional);
        const { waitingOnRef: _wait, waitingReason: _reason, ...previous } = cut.run;
        const next: Run = { ...previous, ...planned.runUpdate, status: 'queued', revision: previous.revision + 1, updatedAt: at,
          ...(expected.stop ? { stopIntentRef: canonicalSha256(expected.stop), cancelRequested: true } : {}) };
        const response: ApprovalResponse = { protocolVersion: 1, ok: true, result: { method: 'run.approve', decisionRef: decisionPlan.ref,
          snapshot: { schemaVersion: 1, operation: 'delivery', run: next, latestRunItemSeq: planned.throughItemSeq } } };
        const published = await artifacts.publishCanonical(response, 'cliq-control-application-response-v1');
        let outcome: TimeFenceAdvance | undefined, committed = false;
        driver.transaction(connection => {
          if (readControlRequest(connection, input.principalId, 'run.approve', input.requestId)) return;
          outcome = accept(connection, cut, binding, at); if (outcome !== 'healthy') return;
          for (const artifact of [...channel.metadata, ...planned.metadata, published]) insertArtifactMetadata(connection, artifact, at);
          planned.commit(connection, cut.run, cut.journal.length, at);
          connection.prepare("UPDATE runs SET status='queued',waiting_reason=NULL,waiting_on_ref=NULL,stop_intent_ref=?,cancel_requested=?,revision=revision+1,updated_at=? WHERE id=?")
            .run(expected.stop ? canonicalSha256(expected.stop) : null, expected.stop ? 1n : 0n, at, runId);
          requireEqual(readRun(connection, runId), next, 'delivery original committed approval snapshot');
          appendRunStateEvent(connection, next, at);
          insertControlRequest(connection, { principalId: input.principalId, method: 'run.approve', requestId: input.requestId,
            channelIdentityRef: input.channelIdentityRef, channelIdentityDigest: input.channelIdentityDigest,
            requestDigest, responseRef: published.ref, committedAt: at }); committed = true;
        });
        requireHealthyFence(outcome); if (committed) return immutableSnapshot({ replayed: false, run: next, response });
        const raced = await replay(); if (raced) return raced;
      }
      throw new KernelStorageError('REVISION_CONFLICT', 'delivery approval control cut kept changing');
    })
  };
}
