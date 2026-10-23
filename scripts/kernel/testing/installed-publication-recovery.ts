// Independent bounded data reader for one real installed cleanup-crash case.
// This issues no permission, StateOwner, native proof, SQL write or retry.
import assert from 'node:assert/strict';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { decodeInstalledControlEnvelope } from '../../../src/kernel/control-wire.js';
import { addCanonicalDuration, digestOmitting, identityHash, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeDeliveryMergeItem, type DeliveryDecisionItem } from '../../../src/kernel/delivery.js';
import { decodeDeliveryCaptureTopology, decodeDeliveryPlan, decodeDeliveryTerminalProjectionEvidence, decodePublicationArenaBirth, decodePublicationPathProgressItem,
  decodePublicationPathResultItem, decodePublicationProof, publicationArenaId, decodePublicationLateObservationItem,
  publicationLateObservationCheckpointId, type PublicationArenaBirthV1 } from '../../../src/kernel/publication.js';
import type { InvocationJournalEntry, StateOwnerRecordV1 } from '../../../src/kernel/types.js';
import { decodeBudgetSettlement, decodePlatformProcessIdentity, decodeRunSpec, decodeStateOwnerAcquisitionEvidence,
  decodeStateOwnerTransitionEvidence } from '../../../src/state/decoders.js';
import { decodeContextManifest, decodeSourceManifest, decodeWorkspaceEntries, decodeWorkspaceIdentity, decodeWorkspaceState } from '../../../src/state/decoders.js';
import { decodeFinalCandidateItem, decodeRunResult, decodeVerificationClosure, decodeWorkspaceDiff } from '../../../src/state/result-artifacts.js';
import { decodeRetainedRunAssembly } from '../../../src/model/run-assembly.js';
import { derivePublicationGrant, loadDeliveryPolicy, planDeliveryRequest } from '../../../src/state/delivery-policy.js';
import type { DeliveryPlanGrantV1 } from '../../../src/kernel/delivery-invocation.js';
import { decodePublicationInspectionTarget, decodePublicationPathWait, decodePublicationProbeEvidence, decodePublicationProbeClosure,
  decodePublicationRecoveryOrigin } from '../../../src/state/publication-reconciliation-artifacts.js';
import { publicationEnvelopeLocations, publicationProgressCheckpointId, publicationProgressItemId,
  publicationResultItemId, deliveryPublicationTerminalCheckpointId } from '../../../src/state/delivery-publication-progress.js';
import { supervisorInspectorIdentity } from '../../../src/state/supervisor-inspector.js';
import { publicationRetirementDiagnosticKey } from '../../../src/state/publication-retirement-diagnostics.js';
import { contextSourceDigest, validateContextItems } from '../../../src/runtime/context-compaction.js';

type ReadInput = { cut: Record<string, any>; readRetainedArtifact(ref: string): Promise<Buffer>;
  readOwnerHistory(): Promise<readonly StateOwnerRecordV1[]> };
const ZERO = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, ONE = { ...ZERO, toolCalls: 1 };
const same = (left: unknown, right: unknown) => assert.equal(canonicalSha256(left), canonicalSha256(right));
function graph(input: ReadInput) {
  const envelope = decodeInstalledControlEnvelope({ protocolVersion: 1, ok: true, result: input.cut }, 'run.get');
  assert(envelope.ok); const cut = envelope.result;
  assert.equal(cut.snapshot.operation, 'delivery');
  assert(cut.items.length <= 1000 && cut.journal.length <= 1000 && cut.checkpoints.length <= 1000);
  assert.equal(cut.items.length, cut.highWaterItemSeq); assert.equal(cut.nextItemSeq, cut.highWaterItemSeq);
  assert.equal(cut.journal.length, cut.highWaterJournalSeq); assert.equal(cut.nextJournalSeq, cut.highWaterJournalSeq);
  assert.equal(cut.nextCheckpointCursor, cut.highWaterCheckpointCursor);
  const objects = new Map<string, Buffer>();
  const bytes = async (ref: string) => {
    assert.match(ref, /^[0-9a-f]{64}$/u); let value = objects.get(ref);
    if (!value) {
      assert(objects.size < 256); value = Buffer.from(await input.readRetainedArtifact(ref));
      assert(value.length <= 1_048_576); assert.equal(sha256Bytes(value), ref); objects.set(ref, value);
    }
    return value;
  };
  const object = async (ref: string): Promise<any> => {
    const value = await bytes(ref), data = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(value));
    assert(canonicalJsonBytes(data).equals(value)); return data;
  };
  const items = async () => Promise.all(cut.items.map(async (row, index) => {
    assert.equal(row.itemSeq, index + 1); assert.equal(row.payloadRef, row.payloadDigest);
    const item = await object(row.payloadRef);
    assert.equal(item.runId, cut.snapshot.run.id); assert.equal(item.itemId, row.itemId); assert.equal(item.createdAt, row.createdAt);
    return { row, item };
  }));
  cut.journal.forEach((row, index) => { assert.equal(row.seq, index + 1); assert.equal(row.runId, cut.snapshot.run.id); });
  return { cut, object, bytes, items };
}

async function original(input: ReadInput) {
  const g = graph(input), { cut, object } = g, run = cut.snapshot.run;
  const spec = decodeRunSpec(await object(run.specRef)); assert.equal(spec.operation, 'delivery');
  const items = await g.items(), merges = items.filter(row => row.item.kind === 'delivery_merge'); assert.equal(merges.length, 1);
  const merge = decodeDeliveryMergeItem(merges[0]!.item), plan = decodeDeliveryPlan(await object(merge.deliveryPlanRef));
  assert.equal(plan.deliveryRunId, run.id); assert.equal(plan.capturedWorkspaceRef, spec.baseWorkspaceManifestRef);
  assert.equal(plan.sourceRunResultRef, merge.sourceRunResultRef); assert.equal(plan.forwardOperations.length, 1); assert.equal(plan.abortOperations.length, 0);
  const operation = plan.forwardOperations[0]!; assert(operation.kind === 'replace' && operation.expected.kind === 'file' && operation.desired.kind === 'file');
  const topology = decodeDeliveryCaptureTopology(await object(plan.captureTopologyRef));
  assert.equal(topology.topologyDigest, plan.captureTopologyDigest); assert.equal(topology.capturedWorkspaceRef, plan.capturedWorkspaceRef);
  const claims = cut.journal.filter(row => row.phase === 'dispatch_claimed'); assert.equal(claims.length, 1);
  const claim = claims[0]!; assert.equal(claim.opKind, 'publish'); assert.equal(claim.attempt, 0); assert.equal(claim.replayClass, 'reconcile');
  const history = cut.journal.filter(row => row.opId === claim.opId && row.attempt === claim.attempt);
  assert.equal(history.length, cut.journal.length); const prepared = history[0]!;
  assert.equal(prepared.phase, 'prepared'); assert.equal(history[1], claim);
  for (const row of history) {
    for (const field of ['runId', 'opId', 'opKind', 'attempt', 'leaseEpoch', 'requestRef', 'target', 'grantRef', 'replayClass'] as const) assert.equal(row[field], prepared[field]);
    assert.equal(row.idempotencyKey, undefined); assert.equal(row.sandboxLaunchSpecRef, undefined); assert.equal(row.brokerFenceTokenDigest, undefined);
    if (row !== prepared) for (const field of ['dispatchId', 'supervisorInstanceId', 'stateOwnerEpoch'] as const) assert.equal(row[field], claim[field]);
  }
  same(prepared.budgetDelta, ONE); same(claim.budgetDelta, ZERO);
  assert(claim.evidenceRef && claim.evidenceDigest && claim.dispatchId && claim.stateOwnerEpoch && claim.supervisorInstanceId);
  const birth = decodePublicationArenaBirth(await object(claim.evidenceRef));
  assert.equal(birth.birthDigest, claim.evidenceDigest); assert.equal(birth.deliveryRunId, run.id); assert.equal(birth.deliveryPlanRef, merge.deliveryPlanRef);
  assert.equal(birth.workspaceIdentityRef, topology.workspaceIdentityRef); assert.equal(birth.workspaceIdentityDigest, topology.workspaceIdentityDigest);
  assert.equal(birth.opId, claim.opId); assert.equal(birth.attempt, 0); assert.equal(birth.dispatchId, claim.dispatchId);
  assert.equal(birth.sequence, 'forward'); assert.equal(birth.operationIndex, 0); assert.equal(birth.operationId, operation.operationId);
  assert.equal(birth.arenaId, publicationArenaId(run.id, operation.operationId, claim.opId, 0, claim.dispatchId));
  assert(birth.observedAt >= prepared.timestamp && birth.observedAt <= claim.timestamp);
  const owners = await input.readOwnerHistory(), owner = owners.find(row => row.ownerEpoch === claim.stateOwnerEpoch); assert(owner);
  assert.equal(owner.rowDigest, digestOmitting(owner, 'rowDigest')); assert.equal(owner.supervisorInstanceId, claim.supervisorInstanceId);
  same(await object(birth.inspectorIdentityRef), supervisorInspectorIdentity(owner));
  assert.equal(birth.inspectorIdentityDigest, supervisorInspectorIdentity(owner).identityDigest);
  const process = decodePlatformProcessIdentity(await object(owner.processIdentityRef));
  assert.equal(process.identityDigest, owner.processIdentityDigest); assert.equal(process.executableImageDigest, owner.supervisorExecutableDigest);
  const policyRows = items.filter(row => row.item.kind === 'policy_decision' && row.item.subjectKind === 'delivery_plan');
  const decisionRows = items.filter(row => row.item.kind === 'delivery_decision');
  assert.equal(policyRows.length, 1); assert.equal(decisionRows.length, 1);
  const policyItem = policyRows[0]!.item, decision = decisionRows[0]!.item as DeliveryDecisionItem;
  assert.deepEqual(Object.keys(decision).sort(), ['schemaVersion', 'itemId', 'runId', 'kind', 'deliveryPlanRef', 'approvalOpId', 'decision', 'decisionRef', 'grantRef', 'createdAt'].sort());
  assert.equal(policyItem.decisionSource, 'direct_policy'); assert.equal(policyItem.decision, 'allow'); assert.equal(decision.decision, 'allow');
  const parent = await object(policyItem.grantRef) as DeliveryPlanGrantV1, channel = await object(policyItem.policyChannelEvidenceRef);
  const assembly = decodeRetainedRunAssembly(await object(spec.assemblyRef));
  const workspace = decodeWorkspaceIdentity(await object(topology.workspaceIdentityRef)); assert.equal(workspace.kind, 'live');
  assert(workspace.kind === 'live'); assert.equal(policyItem.principalId, workspace.ownerPrincipalId);
  const context = { runId: run.id, frontierRef: parent.frontierRef, assemblyRef: spec.assemblyRef, planRef: merge.deliveryPlanRef, plan,
    workspaceIdentityRef: topology.workspaceIdentityRef, workspaceIdentityDigest: topology.workspaceIdentityDigest };
  const policy = await object(spec.policyRef), evaluator = loadDeliveryPolicy({ policy, policyRef: spec.policyRef, assembly, assemblyRef: spec.assemblyRef,
    principalId: workspace.ownerPrincipalId, workspaceIdentityDigest: workspace.identityDigest, context });
  const planned = planDeliveryRequest(context);
  same(await object(parent.requestRef), planned.request); same(await object(parent.targetRef), planned.target);
  same(channel, evaluator.evaluate(planned.request, planned.target, channel.evaluatedAt));
  same(parent, evaluator.grant(planned.request, planned.target, channel, parent.issuedAt, run.deadlineAt));
  assert.equal(policyItem.grantRef, decision.grantRef); assert.equal(decision.deliveryPlanRef, birth.deliveryPlanRef);
  assert.equal(policyItem.decisionRef, canonicalSha256(channel)); assert.equal(decision.decisionRef, policyItem.decisionRef);
  assert.equal(policyItem.policyChannelEvidenceDigest, channel.evidenceDigest); assert.equal(decision.approvalOpId, parent.opId);
  assert.equal(parent.issuedAt, policyItem.createdAt); assert.equal(decision.createdAt, policyItem.createdAt);
  assert(policyRows[0]!.row.itemSeq < decisionRows[0]!.row.itemSeq);
  const request = await object(prepared.requestRef), derived = derivePublicationGrant({ context: { ...context, frontierRef: request.frontierRef },
    parent, parentRef: policyItem.grantRef, decision, sequence: 'forward', operationIndex: 0, issuedAt: (await object(prepared.grantRef!)).issuedAt });
  same(request, derived.request); same(await object(prepared.grantRef!), derived.grant); same(await object(prepared.target), derived.target);
  assert(prepared.timestamp >= derived.grant.issuedAt && claim.timestamp < derived.grant.expiresAt);
  return { ...g, items, spec, plan, operation, topology, claim, prepared, birth, owner, owners, process, history };
}

/** An actual public claim/birth may arm only the external test observer. It
 * cannot supply native publication or cleanup authority. Terminal is a miss. */
export async function readInstalledPublicationCrashBirth(input: ReadInput): Promise<PublicationArenaBirthV1> {
  const value = await original(input);
  assert.equal(value.history.length, 2); assert.equal(value.cut.snapshot.run.status, 'running');
  assert(!value.cut.snapshot.run.resultRef && !value.cut.snapshot.run.cancelRequested && !value.cut.snapshot.run.stopIntentRef);
  assert(!value.items.some(row => row.item.kind === 'publication_path_result' ||
    row.item.kind === 'publication_late_observation' || row.item.kind === 'publication_path_progress' && row.item.state === 'received_handoff'));
  return value.birth;
}

type Original = Awaited<ReturnType<typeof original>>;
type NamespaceInput = { receiptRef: string; namespaceEvidenceRef: string;
  dispatch: { probeStartedAt: string; owningSupervisorInstanceId: string };
  progress: ReturnType<typeof decodePublicationPathProgressItem>;
  before: Extract<ReturnType<typeof decodePublicationProof>, { kind: 'path_observation' }>;
  desired: Extract<ReturnType<typeof decodePublicationProof>, { kind: 'path_observation' }> };

// Shared full retained association, never a native observer. The caller applies
// its own fixed timing rule: in-deadline resolution or expired audit, not a flag
// that can promote a late fact into a new probe result.
async function namespaceReceipt(v: Original, input: NamespaceInput) {
  const { object, bytes, birth, claim, owner, operation } = v, run = v.cut.snapshot.run;
  assert(operation.kind === 'replace' && operation.expected.kind === 'file' && operation.desired.kind === 'file');
  assert(input.progress.state === 'desired_committed_cleanup_pending');
  const receipt = decodePublicationProof(await object(input.receiptRef)); assert.equal(receipt.kind, 'terminal_receipt');
  assert(receipt.kind === 'terminal_receipt' && receipt.namespaceRetirementEvidenceRef && receipt.recoveryOriginRef && receipt.recoveryOriginDigest);
  assert.equal(input.namespaceEvidenceRef, receipt.namespaceRetirementEvidenceRef);
  const namespace = decodePublicationProof(await object(receipt.namespaceRetirementEvidenceRef)); assert.equal(namespace.kind, 'arena_namespace_absence');
  assert(namespace.kind === 'arena_namespace_absence');
  const destination = decodePublicationProof(await object(namespace.destinationObservationRef)); assert.equal(destination.kind, 'path_observation');
  assert(destination.kind === 'path_observation');
  for (const observed of [destination, namespace, receipt]) {
    assert.equal(observed.deliveryRunId, run.id); assert.equal(observed.deliveryPlanRef, birth.deliveryPlanRef);
    assert.equal(observed.workspaceIdentityRef, birth.workspaceIdentityRef); assert.equal(observed.workspaceIdentityDigest, birth.workspaceIdentityDigest);
    assert.equal(observed.recoveryOriginRef, receipt.recoveryOriginRef); assert.equal(observed.recoveryOriginDigest, receipt.recoveryOriginDigest);
    assert.equal(observed.inspectorIdentityRef, receipt.inspectorIdentityRef); assert.equal(observed.inspectorIdentityDigest, receipt.inspectorIdentityDigest);
    assert(observed.observedAt >= input.dispatch.probeStartedAt && observed.observedAt <= receipt.observedAt);
  }
  assert.equal(receipt.sequence, 'forward'); assert.equal(receipt.operationIndex, 0); assert.equal(receipt.operationId, operation.operationId);
  assert.equal(receipt.opId, claim.opId); assert.equal(receipt.attempt, 0);
  same(receipt.before, input.before.observation); same(receipt.after, destination.observation);
  for (const key of ['location', 'state', 'parentDeviceId', 'parentFileId', 'entryDeviceId', 'entryFileId', 'entryLinkCount'] as const)
    same(destination.observation[key], input.desired.observation[key]);
  same(destination.observation.state, operation.desired); assert.equal(destination.observation.entryLinkCount, 1);
  await bytes(operation.desired.digest);
  assert.equal(receipt.preservedPreimageRef, input.progress.preservedPreimageRef);
  assert.equal(namespace.arenaId, birth.arenaId); same(namespace.registeredArenaIdentity, birth.arenaIdentity); same(namespace.namespaceParentIdentity, birth.parentIdentity);
  assert.equal(namespace.stateRootIdentityRef, birth.stateRootIdentityRef); assert.equal(namespace.stateRootIdentityDigest, birth.stateRootIdentityDigest);
  same(namespace.coveredLocations, publicationEnvelopeLocations({ birth, operation }));
  assert(namespace.arenaAbsent && namespace.arenaParentFsyncCompleted && namespace.workspaceParentFsyncCompleted && namespace.namespaceHandlesJoined);
  const origin = decodePublicationRecoveryOrigin(await object(receipt.recoveryOriginRef));
  assert.equal(origin.originDigest, receipt.recoveryOriginDigest); assert.equal(origin.deliveryRunId, run.id); assert.equal(origin.deliveryPlanRef, birth.deliveryPlanRef);
  assert.equal(origin.opId, claim.opId); assert.equal(origin.attempt, 0); assert.equal(origin.dispatchId, claim.dispatchId); assert.equal(origin.claimJournalSeq, claim.seq);
  assert.equal(origin.arenaBirthRef, claim.evidenceRef); assert.equal(origin.arenaBirthDigest, birth.birthDigest);
  assert.equal(origin.inspectorIdentityRef, receipt.inspectorIdentityRef); assert.equal(origin.inspectorIdentityDigest, receipt.inspectorIdentityDigest);
  assert(origin.ownerDeathAcquisitionEvidenceRef && origin.ownerDeathAcquisitionEvidenceDigest,
    'this exact crash cut requires takeover after actual original owner death, never the separate graceful branch');
  const acquisition = decodeStateOwnerAcquisitionEvidence(await object(origin.ownerDeathAcquisitionEvidenceRef));
  assert.equal(acquisition.kind, 'takeover_after_owner_death'); assert.equal(acquisition.evidenceDigest, origin.ownerDeathAcquisitionEvidenceDigest);
  const successor = v.owners.find(row => row.acquisitionEvidenceRef === origin.ownerDeathAcquisitionEvidenceRef); assert(successor);
  assert.equal(successor.rowDigest, digestOmitting(successor, 'rowDigest'));
  assert.equal(acquisition.evidenceDigest, successor.acquisitionEvidenceDigest);
  for (const key of ['ownerEpoch', 'supervisorInstanceId', 'runtimeBundleRef', 'runtimeBundleManifestDigest', 'processIdentityRef', 'processIdentityDigest',
    'stateLockIdentityRef', 'stateLockIdentityDigest', 'instanceNonceDigest', 'acquiredAt'] as const) assert.equal(acquisition[key], successor[key]);
  assert(successor.ownerEpoch > owner.ownerEpoch); assert.equal(successor.supervisorInstanceId, input.dispatch.owningSupervisorInstanceId);
  assert.equal(acquisition.priorOwnerEpoch, owner.ownerEpoch); assert.equal(acquisition.priorTerminalRowDigest, owner.rowDigest);
  assert.equal(owner.state, 'terminal'); assert.equal(owner.terminalReason, 'superseded_after_owner_death');
  same(await object(receipt.inspectorIdentityRef), supervisorInspectorIdentity(successor));
  const transition = decodeStateOwnerTransitionEvidence(await object(owner.transitionEvidenceRef!));
  assert.equal(transition.kind, 'superseded_after_owner_death'); assert.equal(transition.successorOwnerEpoch, successor.ownerEpoch);
  assert.equal(transition.priorProcessObservation, 'absent_or_start_token_mismatch'); assert.equal(transition.priorProcessIdentityRef, owner.processIdentityRef);
  assert.equal(transition.evidenceDigest, owner.transitionEvidenceDigest); assert.equal(transition.observedAt, successor.acquiredAt);
  assert(origin.observedAt >= successor.acquiredAt && origin.observedAt <= namespace.observedAt);
  return { receipt, namespace, destination, origin, successor };
}

type LateInput = Omit<ReadInput, 'cut'> & { originalBirth: PublicationArenaBirthV1;
  beforeCut: Record<string, any>; auditCut: Record<string, any> };

/** Only a caller-captured public-cut delta can establish that the fixed audit
 * left the original wait untouched. No reconstructed pre-audit cut is accepted.
 * This reads retained facts, not physical resources, authority or a new result. */
export async function assertInstalledPublicationLateAudit(input: LateInput) {
  const v = await original({ ...input, cut: input.beforeCut }), after = graph({ ...input, cut: input.auditCut });
  const { cut, object, bytes, items, history, claim, prepared, birth, operation } = v, run = cut.snapshot.run;
  same(birth, input.originalBirth); same(history.map(row => row.phase), ['prepared', 'dispatch_claimed', 'unknown']);
  assert.equal(run.status, 'waiting'); assert.equal(run.waitingReason, 'reconciliation'); assert.equal(run.nextStep, 'delivery');
  assert(run.waitingOnRef && run.frontierRef && !run.resultRef);
  assert(!items.some(row => row.item.kind === 'publication_late_observation' || row.item.state === 'received_handoff'));
  const afterItems = await after.items(), lateRows = afterItems.filter(row => row.item.kind === 'publication_late_observation');
  assert.equal(lateRows.length, 1); assert.equal(afterItems.length, items.length + 1);
  same(after.cut.items.slice(0, -1), cut.items); same(after.cut.journal, cut.journal);
  const row = lateRows[0]!.row, item = decodePublicationLateObservationItem(lateRows[0]!.item);
  assert.equal(row.itemSeq, afterItems.length); assert.equal(item.disposition, 'received');
  assert(item.disposition === 'received' && 'kind' in item.retirement && item.retirement.kind === 'current_namespace');
  assert.equal(item.deliveryPlanRef, birth.deliveryPlanRef); assert.equal(item.sequence, 'forward'); assert.equal(item.operationIndex, 0);
  assert.equal(item.operationId, operation.operationId); assert.equal(item.opId, claim.opId); assert.equal(item.attempt, 0);
  assert.equal(item.dispatchId, claim.dispatchId); assert.equal(item.claimJournalSeq, claim.seq); assert.equal(item.probeWaitingSubjectRef, run.waitingOnRef);
  const previous = cut.checkpoints.find(value => value.id === run.latestCheckpointId); assert(previous);
  const checkpointId = publicationLateObservationCheckpointId(run.id, claim.opId, 0, item.probeDispatchDigest, item.evidenceRef);
  const checkpoint = after.cut.checkpoints.find(value => value.id === checkpointId); assert(checkpoint);
  assert.equal(after.cut.checkpoints.length, cut.checkpoints.length + 1);
  same(after.cut.checkpoints.filter(value => value.id !== checkpointId), cut.checkpoints);
  same(checkpoint, { schemaVersion: 1, id: checkpointId, runId: run.id, basedOnRunRevision: run.revision,
    runItemSeq: row.itemSeq, contextManifestRef: checkpoint.contextManifestRef, journalSeq: history.length,
    workspaceStateRef: previous.workspaceStateRef, createdAt: checkpoint.createdAt, reason: 'auto' });
  assert.equal(previous.runItemSeq, cut.items.length); assert.equal(previous.journalSeq, history.length);
  assert(checkpoint.createdAt >= item.createdAt && checkpoint.createdAt >= previous.createdAt && checkpoint.createdAt >= run.updatedAt);
  same(after.cut.snapshot.run, { ...run, latestCheckpointId: checkpointId, revision: run.revision + 1, updatedAt: checkpoint.createdAt });
  const context = decodeContextManifest(await after.object(checkpoint.contextManifestRef)), beforeContext = decodeContextManifest(await object(previous.contextManifestRef));
  assert.equal(context.runId, run.id); assert.equal(context.throughItemSeq, afterItems.length);
  same(context, { ...beforeContext, throughItemSeq: afterItems.length, segments: [...beforeContext.segments,
    { kind: 'excluded_control', fromItemSeq: row.itemSeq, throughItemSeq: row.itemSeq,
      sourceItemsDigest: contextSourceDigest([{ itemSeq: row.itemSeq, itemRef: row.payloadRef, item }]) }],
    projectionDigest: context.projectionDigest });
  validateContextItems(context, afterItems.map(value => ({ itemSeq: value.row.itemSeq, itemRef: value.row.payloadRef, item: value.item })));
  const unknown = history[2]!; assert(unknown.budgetSettlementRef); same(unknown.budgetDelta, ONE); same(run.budgetConsumed, ONE); same(run.budgetReserved, ZERO);
  const settlement = decodeBudgetSettlement(await object(unknown.budgetSettlementRef));
  same(settlement, { schemaVersion: 1, format: 'cliq-budget-settlement-v1', runId: run.id, opId: claim.opId, attempt: 0,
    preparedJournalSeq: prepared.seq, terminalJournalSeq: unknown.seq, terminalPhase: 'unknown', reserved: ONE, consumed: ONE, released: ONE,
    budgetConsumedBefore: ZERO, budgetConsumedAfter: ONE, budgetReservedBefore: ONE, budgetReservedAfter: ZERO,
    settledAt: unknown.timestamp, settlementDigest: settlement.settlementDigest });
  const progressRows = items.filter(value => value.item.kind === 'publication_path_progress'); assert.equal(progressRows.length, 1);
  const progress = decodePublicationPathProgressItem(progressRows[0]!.item); assert(progress.state === 'desired_committed_cleanup_pending');
  assert.equal(progress.itemId, publicationProgressItemId(run.id, claim.opId, 0)); assert.equal(progress.deliveryPlanRef, birth.deliveryPlanRef);
  assert.equal(progress.opId, claim.opId); assert.equal(progress.attempt, 0); assert.equal(progress.operationId, operation.operationId); assert.equal(progress.operationIndex, 0);
  const barrier = cut.checkpoints.find(value => value.id === publicationProgressCheckpointId(run.id, claim.opId, 0)); assert(barrier);
  assert.equal(barrier.runItemSeq, progressRows[0]!.row.itemSeq); assert.equal(barrier.journalSeq, claim.seq);
  assert(barrier.createdAt >= progress.createdAt && barrier.createdAt <= unknown.timestamp);
  const before = decodePublicationProof(await object(progress.beforeObservationRef)), desired = decodePublicationProof(await object(progress.destinationEvidenceRef));
  assert(before.kind === 'path_observation' && desired.kind === 'path_observation');
  assert(operation.kind === 'replace' && operation.expected.kind === 'file' && operation.desired.kind === 'file');
  same(before.observation.state, operation.expected); same(desired.observation.state, operation.desired);
  assert.equal(progress.preservedPreimageRef, operation.expected.digest); await bytes(progress.preservedPreimageRef!);
  assert.equal(before.inspectorIdentityRef, birth.inspectorIdentityRef); assert.equal(desired.inspectorIdentityRef, birth.inspectorIdentityRef);
  const resultRows = items.filter(value => value.item.kind === 'publication_path_result'); assert.equal(resultRows.length, 1);
  const unresolved = decodePublicationPathResultItem(resultRows[0]!.item); assert.equal(unresolved.outcome, 'unknown');
  assert.equal(unresolved.evidenceRef, unknown.evidenceRef); assert.equal(unresolved.createdAt, unknown.timestamp);
  const ambiguity = decodePublicationProof(await object(unresolved.evidenceRef)); assert(ambiguity.kind === 'path_ambiguity');
  assert.equal(ambiguity.proofDigest, unknown.evidenceDigest); assert.equal(ambiguity.launchDispatchId, claim.dispatchId);
  assert.equal(ambiguity.opId, claim.opId); assert.equal(ambiguity.operationId, operation.operationId); assert.equal(ambiguity.attempt, 0);
  const wait = decodePublicationPathWait(await object(run.waitingOnRef)); assert(wait.probeState.phase === 'automatic_in_flight');
  const dispatch = wait.probeState.dispatch; assert.equal(dispatch.subjectKind, 'publication'); assert.equal(dispatch.dispatchDigest, item.probeDispatchDigest);
  assert.equal(wait.runId, run.id); assert.equal(wait.frontierRef, run.frontierRef); assert(wait.createdFromRevision < run.revision);
  same(wait.subject, { kind: 'publication_path', deliveryPlanRef: birth.deliveryPlanRef, pathOperationId: operation.operationId, attempt: 0 });
  same(await object(canonicalSha256(dispatch)), dispatch);
  const target = decodePublicationInspectionTarget(await object(dispatch.inspectionTargetDigest));
  same(target, { schemaVersion: 1, format: 'cliq-publication-inspection-target-v1', runId: run.id, subject: wait.subject,
    preparedJournalSeq: prepared.seq, claimJournalSeq: claim.seq, unknownJournalSeq: unknown.seq,
    unknownEvidenceRef: unknown.evidenceRef, unknownBudgetSettlementRef: unknown.budgetSettlementRef,
    progress: { itemRef: progressRows[0]!.row.payloadRef, checkpointId: barrier.id } });
  const pending = decodePublicationPathWait(await object(dispatch.previousWaitingSubjectRef));
  assert(pending.probeState.phase === 'automatic_pending' && pending.probeState.automaticProbeCount === 0);
  same({ ...pending, probeState: wait.probeState }, wait); assert(dispatch.probeStartedAt >= pending.probeState.nextProbeAt);
  assert(wait.createdAt >= unknown.timestamp && dispatch.probeStartedAt <= run.updatedAt);
  const value = await namespaceReceipt(v, { receiptRef: item.evidenceRef, namespaceEvidenceRef: item.retirement.namespaceEvidenceRef, dispatch, progress, before, desired });
  assert.equal(value.receipt.proofDigest, item.evidenceDigest); assert(item.completedAt > dispatch.probeDeadlineAt);
  assert(value.receipt.observedAt <= item.completedAt); assert(value.successor.acquiredAt <= dispatch.probeStartedAt);
  assert(value.successor.state !== 'terminal' || checkpoint.createdAt <= value.successor.releasedAt);
  return Object.freeze({ diagnosticOnly: true, runId: run.id, opId: claim.opId, dispatchId: claim.dispatchId,
    expiredProbeDigest: dispatch.dispatchDigest, expiredProbeNonceDigest: dispatch.probeNonceDigest,
    lateItemRef: row.payloadRef, lateCheckpointId: checkpoint.id, lateEvidenceRef: item.evidenceRef,
    originalUnknownSettlementRef: unknown.budgetSettlementRef, originalWaitUnchanged: true });
}

/** Complete retained recovery association only; the owner fixture separately
 * verifies pidfd kill/death, retired SQL resources and actual complete files. */
type RecoveryInput = ReadInput & { originalBirth: PublicationArenaBirthV1;
  expectedFiles: readonly { path: string; text: string }[]; sourceResultRef: string };
export async function assertInstalledPublicationCleanupRecovery(input: RecoveryInput) {
  const v = await original(input);
  assert(!v.items.some(row => row.item.kind === 'publication_late_observation'));
  return completedCleanupRecovery(input, v);
}

/** The exact first-late/second-automatic campaign. The new probe must have
 * genuinely closed the old task and retained the original backoff, while its
 * fresh observation (never the audit fact) completes the usual full closure. */
export async function assertInstalledPublicationLateAuditRecovery(input: RecoveryInput & LateInput) {
  const audit = await assertInstalledPublicationLateAudit(input), v = await original(input);
  const { cut, object, items } = v;
  same(cut.items.slice(0, input.auditCut.items.length), input.auditCut.items);
  same(cut.journal.slice(0, input.auditCut.journal.length), input.auditCut.journal);
  for (const checkpoint of input.auditCut.checkpoints)
    same(cut.checkpoints.find(value => value.id === checkpoint.id), checkpoint);
  const lateRows = items.filter(value => value.item.kind === 'publication_late_observation'); assert.equal(lateRows.length, 1);
  assert.equal(lateRows[0]!.row.payloadRef, audit.lateItemRef);
  const completed = items.filter(value => value.item.kind === 'publication_path_result' && value.item.outcome === 'completed');
  assert.equal(completed.length, 1);
  const result = decodePublicationPathResultItem(completed[0]!.item); assert(result.outcome === 'completed' && result.reconciliationEvidenceRef);
  assert.notEqual(result.evidenceRef, audit.lateEvidenceRef);
  const wrapper = decodePublicationProbeEvidence(await object(result.reconciliationEvidenceRef)); assert(wrapper.outcome === 'subject_observation');
  const wait = decodePublicationPathWait(await object(wrapper.waitingSubjectRef)); assert(wait.probeState.phase === 'automatic_in_flight');
  const dispatch = wait.probeState.dispatch; assert.equal(wait.probeState.automaticProbeCount, 2); assert.equal(dispatch.subjectKind, 'publication');
  assert.notEqual(dispatch.dispatchDigest, audit.expiredProbeDigest); assert.notEqual(dispatch.probeNonceDigest, audit.expiredProbeNonceDigest);
  const pending = decodePublicationPathWait(await object(dispatch.previousWaitingSubjectRef));
  assert(pending.probeState.phase === 'automatic_pending' && pending.probeState.automaticProbeCount === 1);
  same({ ...pending, probeState: wait.probeState }, wait);
  const timeout = decodePublicationProbeEvidence(await object(pending.probeState.lastProbeEvidenceRef)); assert(timeout.outcome === 'probe_timeout');
  assert.equal(timeout.evidenceDigest, pending.probeState.lastProbeEvidenceDigest);
  const late = decodePublicationLateObservationItem(lateRows[0]!.item);
  const expired = decodePublicationPathWait(await object(late.probeWaitingSubjectRef)); assert(expired.probeState.phase === 'automatic_in_flight');
  const old = expired.probeState.dispatch; assert.equal(old.subjectKind, 'publication');
  same({ ...expired, probeState: pending.probeState }, pending);
  assert.equal(timeout.waitingSubjectRef, late.probeWaitingSubjectRef); assert.equal(timeout.probeDispatchDigest, old.dispatchDigest);
  assert.equal(timeout.probeNonceDigest, old.probeNonceDigest); assert.equal(timeout.probeOrdinal, 1); assert.equal(timeout.probeKind, 'automatic');
  assert.equal(timeout.probeStartedAt, old.probeStartedAt); assert.equal(timeout.probeDeadlineAt, old.probeDeadlineAt);
  assert(timeout.observedAt >= late.createdAt); assert.equal(pending.probeState.nextProbeAt, addCanonicalDuration(timeout.observedAt, 1000));
  assert(dispatch.probeStartedAt >= pending.probeState.nextProbeAt); assert.equal(dispatch.inspectionTargetDigest, old.inspectionTargetDigest);
  const closure = decodePublicationProbeClosure(await object(timeout.timeoutClosureRef));
  same(closure, { schemaVersion: 1, format: 'cliq-reconciliation-probe-timeout-closure-v1', runId: cut.snapshot.run.id,
    waitingSubjectRef: timeout.waitingSubjectRef, probeKind: 'automatic', probeOrdinal: 1, probeNonceDigest: old.probeNonceDigest,
    probeDispatchDigest: old.dispatchDigest, probeDeadlineAt: old.probeDeadlineAt, inspectorIdentityRef: timeout.inspectorIdentityRef,
    inspectorIdentityDigest: timeout.inspectorIdentityDigest, closedAt: timeout.observedAt, closureDigest: timeout.timeoutClosureDigest,
    subjectKind: 'publication', deliveryPlanRef: late.deliveryPlanRef, pathOperationId: late.operationId, attempt: 0,
    inspectorTaskId: old.inspectorTaskId, taskClosure: { closureKind: 'cancelled_and_joined', inspectorTaskCancelledAndJoined: true } });
  const inspector = await object(timeout.inspectorIdentityRef), owner = v.owners.find(value => value.ownerEpoch === inspector.stateOwnerEpoch); assert(owner);
  same(inspector, supervisorInspectorIdentity(owner)); assert.equal(inspector.identityDigest, timeout.inspectorIdentityDigest);
  assert.equal(owner.supervisorInstanceId, old.owningSupervisorInstanceId); assert(owner.acquiredAt <= old.probeStartedAt);
  assert(owner.state !== 'terminal' || timeout.observedAt <= owner.releasedAt);
  const resolved = await completedCleanupRecovery(input, v);
  return Object.freeze({ ...resolved, ...audit, currentProbeDigest: dispatch.dispatchDigest });
}

async function completedCleanupRecovery(input: RecoveryInput, v: Original) {
  const { cut, object, bytes, items, history, claim, prepared, birth, owner, operation, plan } = v;
  assert(operation.kind === 'replace' && operation.expected.kind === 'file' && operation.desired.kind === 'file');
  same(birth, input.originalBirth);
  const run = cut.snapshot.run; assert.equal(run.status, 'succeeded'); assert.equal(run.terminalReason, 'verified');
  assert(run.resultRef && !run.cancelRequested && !run.stopIntentRef && !run.activeWorkerLaunchId && run.nextStep === null && !run.frontierRef);
  same(history.map(row => row.phase), ['prepared', 'dispatch_claimed', 'unknown', 'completed']);
  const unknown = history[2]!, completed = history[3]!;
  assert(unknown.budgetSettlementRef); assert.equal(completed.budgetSettlementRef, unknown.budgetSettlementRef);
  same(unknown.budgetDelta, ONE); same(completed.budgetDelta, ZERO); same(run.budgetConsumed, ONE); same(run.budgetReserved, ZERO);
  const settlement = decodeBudgetSettlement(await object(unknown.budgetSettlementRef));
  assert.equal(settlement.terminalPhase, 'unknown'); assert.equal(settlement.runId, run.id); assert.equal(settlement.opId, claim.opId);
  assert.equal(settlement.attempt, 0); assert.equal(settlement.preparedJournalSeq, prepared.seq); assert.equal(settlement.terminalJournalSeq, unknown.seq);
  assert.equal(settlement.settledAt, unknown.timestamp); same(settlement.reserved, ONE); same(settlement.released, ONE); same(settlement.consumed, ONE);
  same(settlement.budgetConsumedBefore, ZERO); same(settlement.budgetConsumedAfter, ONE);
  same(settlement.budgetReservedBefore, ONE); same(settlement.budgetReservedAfter, ZERO);
  const progressRows = items.filter(row => row.item.kind === 'publication_path_progress'); assert.equal(progressRows.length, 2);
  const progress = decodePublicationPathProgressItem(progressRows[0]!.item), handoff = decodePublicationPathProgressItem(progressRows[1]!.item);
  assert(progress.state === 'desired_committed_cleanup_pending' && handoff.state === 'received_handoff');
  assert.equal(progress.itemId, publicationProgressItemId(run.id, claim.opId, 0));
  assert.equal(progress.deliveryPlanRef, birth.deliveryPlanRef); assert.equal(progress.opId, claim.opId); assert.equal(progress.attempt, 0);
  const checkpoints = (id: string) => { const rows = cut.checkpoints.filter(row => row.id === id); assert.equal(rows.length, 1); return rows[0]!; };
  const barrier = checkpoints(publicationProgressCheckpointId(run.id, claim.opId, 0));
  assert.equal(barrier.runItemSeq, progressRows[0]!.row.itemSeq); assert.equal(barrier.journalSeq, claim.seq);
  assert(barrier.createdAt >= progress.createdAt && barrier.createdAt <= unknown.timestamp);
  const before = decodePublicationProof(await object(progress.beforeObservationRef)), desired = decodePublicationProof(await object(progress.destinationEvidenceRef));
  assert(before.kind === 'path_observation' && desired.kind === 'path_observation');
  same(before.observation.state, operation.expected); same(desired.observation.state, operation.desired);
  assert.equal(progress.preservedPreimageRef, operation.expected.digest); await bytes(progress.preservedPreimageRef!);
  assert.equal(before.inspectorIdentityRef, birth.inspectorIdentityRef); assert.equal(desired.inspectorIdentityRef, birth.inspectorIdentityRef);
  const resultRows = items.filter(row => row.item.kind === 'publication_path_result'); assert.equal(resultRows.length, 2);
  const first = decodePublicationPathResultItem(resultRows[0]!.item), result = decodePublicationPathResultItem(resultRows[1]!.item);
  assert.equal(first.outcome, 'unknown'); assert.equal(first.evidenceRef, unknown.evidenceRef); assert.equal(first.createdAt, unknown.timestamp);
  const ambiguity = decodePublicationProof(await object(first.evidenceRef)); assert.equal(ambiguity.kind, 'path_ambiguity');
  assert.equal(ambiguity.deliveryRunId, run.id); assert.equal(ambiguity.deliveryPlanRef, birth.deliveryPlanRef);
  assert.equal(ambiguity.launchDispatchId, claim.dispatchId); assert.equal(ambiguity.operationId, operation.operationId);
  assert.equal(ambiguity.opId, claim.opId); assert.equal(ambiguity.attempt, 0); assert.equal(ambiguity.proofDigest, unknown.evidenceDigest);
  assert(ambiguity.observedAt >= claim.timestamp && ambiguity.observedAt <= unknown.timestamp);
  assert.equal(result.outcome, 'completed'); assert.equal(result.evidenceRef, completed.evidenceRef); assert.equal(result.receiptRef, completed.receiptRef);
  assert.equal(result.itemId, publicationResultItemId(run.id, claim.opId, 0, result.evidenceRef));
  assert.equal(result.opId, claim.opId); assert.equal(result.attempt, 0); assert.equal(result.sequence, 'forward');
  assert('kind' in result.retirement && result.retirement.kind === 'current_namespace');
  same(handoff.retirement, result.retirement); assert.equal(handoff.receiptRef, result.receiptRef);
  assert.equal(handoff.claimJournalSeq, claim.seq); assert.equal(handoff.dispatchId, claim.dispatchId);
  assert(handoff.generationResources.kind === 'genuinely_retired_from_verified_checkpoint');
  assert(result.reconciliationEvidenceRef && result.reconciliationEvidenceDigest);
  assert.equal(handoff.reconciliationEvidenceRef, result.reconciliationEvidenceRef); assert.equal(handoff.reconciliationEvidenceDigest, result.reconciliationEvidenceDigest);
  const wrapper = decodePublicationProbeEvidence(await object(result.reconciliationEvidenceRef));
  assert.equal(wrapper.evidenceDigest, result.reconciliationEvidenceDigest); assert(wrapper.outcome === 'subject_observation');
  assert.equal(wrapper.subjectEvidenceKind, 'publication'); assert.equal(wrapper.runId, run.id); assert.equal(wrapper.subjectEvidenceRef, result.receiptRef);
  const wait = decodePublicationPathWait(await object(wrapper.waitingSubjectRef));
  assert(wait.probeState.phase === 'automatic_in_flight'); const dispatch = wait.probeState.dispatch;
  assert.equal(dispatch.subjectKind, 'publication');
  assert.equal(wrapper.probeDispatchDigest, dispatch.dispatchDigest); assert.equal(wrapper.probeNonceDigest, dispatch.probeNonceDigest);
  assert.equal(wrapper.probeOrdinal, dispatch.probeOrdinal); assert.equal(wrapper.probeKind, 'automatic');
  assert.equal(wrapper.probeStartedAt, dispatch.probeStartedAt); assert.equal(wrapper.probeDeadlineAt, dispatch.probeDeadlineAt);
  same(await object(canonicalSha256(dispatch)), dispatch);
  const target = decodePublicationInspectionTarget(await object(dispatch.inspectionTargetDigest));
  assert.equal(target.preparedJournalSeq, prepared.seq); assert.equal(target.claimJournalSeq, claim.seq); assert.equal(target.unknownJournalSeq, unknown.seq);
  assert.equal(target.unknownBudgetSettlementRef, unknown.budgetSettlementRef); assert.equal(target.unknownEvidenceRef, unknown.evidenceRef);
  same(target.progress, { itemRef: progressRows[0]!.row.payloadRef, checkpointId: barrier.id });
  same(target.subject, { kind: 'publication_path', deliveryPlanRef: birth.deliveryPlanRef, pathOperationId: operation.operationId, attempt: 0 });
  same(wait.subject, target.subject);
  const { receipt, successor } = await namespaceReceipt(v, { receiptRef: result.receiptRef!,
    namespaceEvidenceRef: result.retirement.namespaceEvidenceRef, dispatch, progress, before, desired });
  assert.equal(receipt.proofDigest, completed.evidenceDigest); assert.equal(wrapper.subjectEvidenceDigest, receipt.proofDigest);
  assert.equal(receipt.inspectorIdentityRef, wrapper.inspectorIdentityRef); assert.equal(receipt.inspectorIdentityDigest, wrapper.inspectorIdentityDigest);
  assert(receipt.observedAt <= dispatch.probeDeadlineAt);
  assert.equal(wrapper.observedAt, receipt.observedAt);
  // Correct UNKNOWN-resolution causality: real receipt -> item -> same atomic
  // terminal Journal/CP. Ordinary first completions keep their separate reader.
  const terminal = checkpoints(deliveryPublicationTerminalCheckpointId(run.id, birth.deliveryPlanRef));
  assert(receipt.observedAt <= result.createdAt && wrapper.observedAt <= result.createdAt && result.createdAt <= completed.timestamp);
  assert.equal(terminal.createdAt, completed.timestamp); assert.equal(terminal.journalSeq, completed.seq); assert.equal(terminal.runItemSeq, resultRows[1]!.row.itemSeq);
  assert.equal(terminal.runItemSeq, cut.items.length); assert.equal(terminal.journalSeq, cut.journal.length);
  // Final publication and RunResult are distinct Checkpoints in the same
  // transaction; neither the path receipt nor run.result may stand in for it.
  const merged = decodeDeliveryMergeItem(items.find(row => row.item.kind === 'delivery_merge')!.item);
  const candidates = items.filter(row => row.item.kind === 'final_candidate'); assert.equal(candidates.length, 1);
  const candidate = decodeFinalCandidateItem(candidates[0]!.item), final = decodeRunResult(await object(run.resultRef));
  assert.equal(input.sourceResultRef, plan.sourceRunResultRef); assert.equal(merged.sourceRunResultRef, input.sourceResultRef);
  assert.equal(candidate.runId, run.id); assert.equal(candidate.operation, 'delivery'); assert.equal(candidate.producingItemId, merged.itemId);
  assert.equal(final.runId, run.id); assert.equal(final.baseSourceRef, plan.capturedWorkspaceRef);
  assert.equal(final.resultSourceRef, plan.desiredSourceRef); assert.equal(final.resultSourceRef, merged.resultSourceRef);
  for (const key of ['baseSourceRef', 'resultSourceRef', 'diffRef', 'summaryRef'] as const) assert.equal(final[key], candidate[key]);
  assert.equal(final.diffRef, merged.diffRef); assert.equal(final.summaryRef, merged.summaryRef);
  const source = decodeSourceManifest(await object(final.resultSourceRef)), entries = decodeWorkspaceEntries(await object(source.entriesRef));
  assert.equal(source.role, 'result'); assert.equal(source.treeDigest, entries.treeDigest); assert.equal(source.manifestDigest, candidate.sourceDigest);
  const expected = [...input.expectedFiles].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  same(entries.entries.map(entry => ({ path: entry.path, kind: entry.kind })), expected.map(entry => ({ path: entry.path, kind: 'file' })));
  for (const [index, entry] of entries.entries.entries()) {
    assert.equal(entry.kind, 'file'); assert(entry.kind === 'file');
    const actual = await bytes(entry.blobRef), wanted = Buffer.from(expected[index]!.text);
    assert.equal(entry.mode, 0o644); assert.equal(entry.size, wanted.length); assert(actual.equals(wanted));
  }
  const diff = decodeWorkspaceDiff(await object(final.diffRef));
  assert.equal(diff.baseSourceRef, final.baseSourceRef); assert.equal(diff.resultSourceRef, final.resultSourceRef);
  assert.equal(diff.operations.length, 1); assert.equal(diff.operations[0]!.kind, 'modify'); assert.equal(diff.operations[0]!.path, operation.path);
  const closure = decodeVerificationClosure(await object(final.verificationClosureRef));
  assert.equal(closure.runId, run.id); assert.equal(closure.candidateItemId, candidate.itemId); assert.equal(closure.resultSourceRef, final.resultSourceRef);
  assert.equal(closure.verification.kind, 'inherited_verified'); assert(closure.verification.kind === 'inherited_verified');
  assert.equal(closure.verification.sourceRunResultRef, input.sourceResultRef);
  assert(final.deliveryTerminalProjectionEvidenceRef);
  const projection = decodeDeliveryTerminalProjectionEvidence(await object(final.deliveryTerminalProjectionEvidenceRef));
  assert.equal(projection.deliveryRunId, run.id); assert.equal(projection.deliveryPlanRef, birth.deliveryPlanRef);
  assert.equal(projection.selectedBranch, 'forward_finalize'); assert.equal(projection.observedSourceRef, final.resultSourceRef);
  same(projection.forwardResultItemRefs, [resultRows[1]!.row.payloadRef]); same(projection.unstartedForwardOperationIds, []); same(projection.abortResultItemRefs, []);
  assert.equal(projection.observedPathStates.length, 1);
  const path = projection.observedPathStates[0]!; assert.equal(path.path, operation.path); same(path.state, operation.desired);
  const pathProof = decodePublicationProof(await object(path.evidenceRef)); assert.equal(pathProof.kind, 'path_observation');
  assert(pathProof.kind === 'path_observation'); assert.equal(pathProof.observation.location.kind, 'workspace');
  assert(pathProof.observation.location.kind === 'workspace'); assert.equal(pathProof.observation.location.path, operation.path);
  same(pathProof.observation.state, path.state);
  const aggregate = decodePublicationProof(await object(projection.transientAbsenceEvidenceRef)); assert.equal(aggregate.kind, 'transient_absence');
  assert(aggregate.kind === 'transient_absence' && aggregate.envelopeRetirements !== undefined);
  same(aggregate.transientLocations, publicationEnvelopeLocations({ birth, operation }));
  same(aggregate.envelopeRetirements, [{ arenaId: birth.arenaId, retirement: result.retirement }]);
  const projectionProof = decodePublicationProof(await object(projection.projectionClosureEvidenceRef)); assert.equal(projectionProof.kind, 'projection_closure');
  assert(projectionProof.kind === 'projection_closure'); assert.equal(projectionProof.selectedBranch, projection.selectedBranch);
  assert.equal(projectionProof.observedSourceRef, projection.observedSourceRef); same(projectionProof.observedPathEvidenceRefs, [path.evidenceRef]);
  for (const key of ['forwardResultItemRefs', 'unstartedForwardOperationIds', 'abortResultItemRefs'] as const) same(projectionProof[key], projection[key]);
  const git = decodePublicationProof(await object(projection.gitIndexUnchangedEvidenceRef)); assert.equal(git.kind, 'git_index_unchanged');
  assert(git.kind === 'git_index_unchanged'); assert.equal(git.repositoryKind, 'non_git'); assert.equal(source.git, undefined);
  for (const proof of [pathProof, aggregate, projectionProof, git]) {
    assert.equal(proof.deliveryRunId, run.id); assert.equal(proof.deliveryPlanRef, birth.deliveryPlanRef);
    assert.equal(proof.workspaceIdentityRef, birth.workspaceIdentityRef); assert.equal(proof.workspaceIdentityDigest, birth.workspaceIdentityDigest);
    assert.equal(proof.inspectorIdentityRef, receipt.inspectorIdentityRef); assert.equal(proof.inspectorIdentityDigest, receipt.inspectorIdentityDigest);
    assert(proof.observedAt >= receipt.observedAt && proof.observedAt <= projection.observedAt);
  }
  assert.equal(projectionProof.observedAt, projection.observedAt);
  assert(projection.observedAt <= final.createdAt && final.createdAt <= run.updatedAt);
  const finalCheckpoint = checkpoints(run.latestCheckpointId!);
  assert.equal(finalCheckpoint.id, identityHash('cliq-run-result-checkpoint-v1', run.id, candidate.itemId, run.resultRef));
  for (const key of ['contextManifestRef', 'workspaceStateRef', 'createdAt', 'runItemSeq', 'journalSeq'] as const) assert.equal(finalCheckpoint[key], terminal[key]);
  assert.equal(finalCheckpoint.createdAt, run.updatedAt); assert.equal(terminal.basedOnRunRevision + 1, finalCheckpoint.basedOnRunRevision);
  assert.equal(finalCheckpoint.basedOnRunRevision, run.revision - 1);
  const context = decodeContextManifest(await object(finalCheckpoint.contextManifestRef));
  assert.equal(context.runId, run.id); assert.equal(context.throughItemSeq, cut.items.length);
  assert.equal(context.assemblyRef, v.spec.assemblyRef); assert.equal(context.admittedContextRef, v.spec.admittedContextRef);
  validateContextItems(context, items.map(value => ({ itemSeq: value.row.itemSeq, itemRef: value.row.payloadRef, item: value.item })));
  const state = decodeWorkspaceState(await object(finalCheckpoint.workspaceStateRef));
  assert.equal(state.runId, run.id); assert.equal(state.entriesRef, source.entriesRef); assert.equal(state.baseWorkspaceManifestRef, plan.capturedWorkspaceRef);
  assert.equal(state.sourceProjectionDigest, source.sourceProjectionDigest); assert.equal(state.privateGitStateRef, undefined); same(state.invalidatedEphemeralPaths, []);
  return Object.freeze({ diagnosticOnly: true, runId: run.id, opId: claim.opId, dispatchId: claim.dispatchId,
    originalOwnerEpoch: owner.ownerEpoch, successorOwnerEpoch: successor.ownerEpoch,
    inspectorIdentityRef: receipt.inspectorIdentityRef, inspectorIdentityDigest: receipt.inspectorIdentityDigest,
    arenaBirthRef: claim.evidenceRef, progressRef: progressRows[0]!.row.payloadRef,
    namespaceEvidenceRef: result.retirement.namespaceEvidenceRef,
    originalUnknownSettlementRef: unknown.budgetSettlementRef, originalDurableReceiptAssociationAbsent: true,
    sameOriginalClaim: true, resolutionBudgetDeltaZero: true, redispatchCount: 0,
    resultRef: run.resultRef, diffRef: final.diffRef, projectionRef: final.deliveryTerminalProjectionEvidenceRef,
    verificationClosureRef: final.verificationClosureRef, resultSourceRef: final.resultSourceRef,
    probeStartedAt: dispatch.probeStartedAt, probeDeadlineAt: dispatch.probeDeadlineAt,
    retirementDiagnosticKey: publicationRetirementDiagnosticKey({ runId: run.id, planRef: birth.deliveryPlanRef,
      opId: claim.opId, attempt: claim.attempt, dispatchId: claim.dispatchId!, probeNonceDigest: dispatch.probeNonceDigest }),
    generationResources: handoff.generationResources });
}
