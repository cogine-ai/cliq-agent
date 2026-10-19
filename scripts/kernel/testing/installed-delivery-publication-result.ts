// Retained data assertions for the fixed installed Delivery campaign, never
// a StateOwner, release/cleanup token or proof of a live process observation.
// WorkerLaunch SQL association, signed installation and independent PID/death
// observations remain the campaign's separate real readonly diagnostics.
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { decodeInstalledControlEnvelope } from '../../../src/kernel/control-wire.js';
import { assertControlWireJson } from '../../../src/kernel/control-wire-data.js';
import { decodeDeliveryMergeItem, type DeliveryDecisionItem } from '../../../src/kernel/delivery.js';
import type { DeliveryPlanGrantV1 } from '../../../src/kernel/delivery-invocation.js';
import { digestOmitting, identityHash, parseCanonicalTime, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeDeliveryCaptureTopology, decodeDeliveryPlan, decodeDeliveryTerminalProjectionEvidence,
  decodePublicationArenaBirth, decodePublicationPathProgressItem, decodePublicationPathResultItem, decodePublicationProof } from '../../../src/kernel/publication.js';
import type { Checkpoint, ContinuationItem, InvocationJournalEntry, StateOwnerRecordV1 } from '../../../src/kernel/types.js';
import { decodeRetainedRunAssembly } from '../../../src/model/run-assembly.js';
import { contextSourceDigest, validateContextItems } from '../../../src/runtime/context-compaction.js';
import { decodeBudgetSettlement, decodeContextManifest, decodePlatformProcessIdentity, decodeRunSpec, decodeSourceManifest,
  decodeStateLockIdentity, decodeStateOwnerAcquisitionEvidence, decodeStateOwnerRecord, decodeStateRootIdentity,
  decodeWorkspaceEntries, decodeWorkspaceGenerationSnapshotEvidence, decodeWorkspaceIdentity, decodeWorkspaceState } from '../../../src/state/decoders.js';
import { derivePublicationGrant, deliveryDecisionCheckpointId, loadDeliveryPolicy, planDeliveryRequest } from '../../../src/state/delivery-policy.js';
import { publicationEnvelopeLocations, publicationProgressCheckpointId, publicationProgressItemId,
  publicationReceivedHandoffItemId, publicationResultItemId, deliveryPublicationCheckpointId,
  deliveryPublicationTerminalCheckpointId } from '../../../src/state/delivery-publication-progress.js';
import { decodeRunResult, decodeVerificationClosure } from '../../../src/state/result-artifacts.js';
import { verificationCheckpointId } from '../../../src/state/run-result-recovery.js';
import { supervisorInspectorIdentity } from '../../../src/state/supervisor-inspector.js';

const ZERO = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
const ONE = { ...ZERO, toolCalls: 1 };
function check(condition: unknown): asserts condition {
  if (!condition) throw new Error('installed Delivery publication graph refused');
}
function same(left: unknown, right: unknown): void { check(canonicalSha256(left) === canonicalSha256(right)); }

export type InstalledDeliveryPublicationInput = {
  cut: Record<string, any>;
  readRetainedArtifact: (ref: string) => Promise<Buffer>;
  /** Actual readonly SQL history from this same fixture, not owners inferred
   * from an inspector's self-asserted epoch or a caller-chosen CAS pathname. */
  readOwnerHistory: () => Promise<readonly StateOwnerRecordV1[]>;
};
export type InstalledDeliveryPublicationSummary = Readonly<{
  planRef: string; projectionRef: string; publishClaims: number; progressCount: number;
  receiptCount: number; slotObservationCount: number; arenaRetirementCount: number;
  /** Retained association only. The installed campaign must independently
   * match these fields to its real readonly SQL retirement and PID checks. */
  publicationWorkerRetirement: Readonly<{ launchId: string; supervisorInstanceId: string; leaseEpoch: number;
    workspaceGenerationRef: string; snapshotEvidenceRef: string; snapshotEvidenceDigest: string; retiredAt: string }> | null;
}>;

/** Full-hash each reachable object once per actual cut. The deliberately fixed
 * successful campaign supports zero paths or one regular-file replacement;
 * it is not a second recovery engine or a generic publication verifier. */
export async function assertInstalledDeliveryPublication(input: InstalledDeliveryPublicationInput): Promise<InstalledDeliveryPublicationSummary> {
  try { return await inspect(input); }
  catch { throw new Error('installed Delivery publication graph refused'); }
}

async function inspect(input: InstalledDeliveryPublicationInput): Promise<InstalledDeliveryPublicationSummary> {
  assertControlWireJson(input.cut);
  const response = decodeInstalledControlEnvelope({ protocolVersion: 1, ok: true, result: input.cut }, 'run.get');
  check(response.ok); const cut = response.result, run = cut.snapshot.run;
  check(cut.snapshot.operation === 'delivery' && run.status === 'succeeded' && run.terminalReason === 'verified' &&
    run.resultRef && !run.stopIntentRef && !run.cancelRequested && !run.activeWorkerLaunchId && run.nextStep === null && !run.frontierRef);
  check(cut.items.length > 0 && cut.items.length <= 1000 && cut.journal.length <= 1000 && cut.checkpoints.length <= 1000 &&
    cut.items.length === cut.highWaterItemSeq && cut.nextItemSeq === cut.highWaterItemSeq &&
    cut.journal.length === cut.highWaterJournalSeq && cut.nextJournalSeq === cut.highWaterJournalSeq &&
    cut.nextCheckpointCursor === cut.highWaterCheckpointCursor);
  const cache = new Map<string, Buffer>();
  const bytes = async (ref: string) => {
    check(typeof ref === 'string' && /^[a-f0-9]{64}$/u.test(ref));
    let value = cache.get(ref);
    if (!value) {
      check(cache.size < 256); value = await input.readRetainedArtifact(ref);
      check(Buffer.isBuffer(value) && value.length <= 1_048_576 && sha256Bytes(value) === ref);
      value = Buffer.from(value); cache.set(ref, value);
    }
    return value;
  };
  const object = async (ref: string): Promise<any> => {
    const value = await bytes(ref), data = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(value));
    check(canonicalJsonBytes(data).equals(value)); return data;
  };
  const items = [];
  for (const [index, row] of cut.items.entries()) {
    check(row.itemSeq === index + 1 && row.payloadRef === row.payloadDigest);
    const item = await object(row.payloadRef);
    check(item.runId === run.id && item.itemId === row.itemId && item.createdAt === row.createdAt);
    items.push({ row, item });
  }
  cut.journal.forEach((row, index) => check(row.seq === index + 1 && row.runId === run.id));
  const checkpoint = (id: string): Checkpoint => {
    const selected = cut.checkpoints.filter(value => value.id === id); check(selected.length === 1);
    const value = selected[0]!; check(value.runId === run.id && value.basedOnRunRevision < run.revision); return value;
  };
  const spec = decodeRunSpec(await object(run.specRef)), result = decodeRunResult(await object(run.resultRef));
  check(spec.operation === 'delivery' && result.runId === run.id && result.deliveryTerminalProjectionEvidenceRef);
  const merges = items.filter(value => value.item.kind === 'delivery_merge'); check(merges.length === 1);
  const merged = decodeDeliveryMergeItem(merges[0]!.item), planRef = merged.deliveryPlanRef;
  const plan = decodeDeliveryPlan(await object(planRef));
  check(plan.deliveryRunId === run.id && plan.sourceRunResultRef === merged.sourceRunResultRef &&
    plan.sourceBaseRef === merged.sourceBaseRef && plan.sourceDesiredRef === merged.sourceDesiredRef &&
    plan.capturedWorkspaceRef === merged.capturedWorkspaceRef && plan.capturedWorkspaceRef === spec.baseWorkspaceManifestRef &&
    plan.desiredSourceRef === merged.resultSourceRef && result.baseSourceRef === plan.capturedWorkspaceRef &&
    result.resultSourceRef === plan.desiredSourceRef && result.diffRef === merged.diffRef && result.summaryRef === merged.summaryRef);
  check(plan.abortOperations.length === 0 && plan.forwardOperations.length <= 1);
  const operation = plan.forwardOperations[0];
  check(!operation || operation.kind === 'replace' && operation.path === 'example.txt' && operation.expected.kind === 'file' &&
    operation.desired.kind === 'file' && operation.parent.kind === 'existing_directory');
  const topology = decodeDeliveryCaptureTopology(await object(plan.captureTopologyRef));
  check(topology.topologyDigest === plan.captureTopologyDigest && topology.capturedWorkspaceRef === plan.capturedWorkspaceRef);
  const workspace = decodeWorkspaceIdentity(await object(topology.workspaceIdentityRef));
  check(workspace.kind === 'live' && workspace.identityDigest === topology.workspaceIdentityDigest);
  for (const field of ['deviceId', 'fileId', 'ownerUid'] as const) check(workspace.rootIdentity[field] === topology.rootIdentity[field]);
  const captured = decodeSourceManifest(await object(plan.capturedWorkspaceRef));
  check(captured.workspaceIdentityDigest === topology.workspaceIdentityDigest);
  const capturedEntries = decodeWorkspaceEntries(await object(captured.entriesRef));
  check(captured.treeDigest === capturedEntries.treeDigest);
  const capturedFiles = capturedEntries.entries.filter(entry => entry.kind === 'file');
  same(topology.fileModes.map(entry => entry.path), capturedFiles.map(entry => entry.path));
  for (const [index, entry] of capturedFiles.entries()) check(((topology.fileModes[index]!.mode & 0o111) ? 0o755 : 0o644) === entry.mode);
  const observedSource = decodeSourceManifest(await object(plan.desiredSourceRef));
  const observedEntries = decodeWorkspaceEntries(await object(observedSource.entriesRef));
  check(observedSource.treeDigest === observedEntries.treeDigest && observedSource.role === 'result' && observedSource.git === undefined);
  for (const key of ['workspaceIdentityDigest', 'sourceProjectionRef', 'sourceProjectionDigest', 'frozenIgnoreRulesRef', 'frozenIgnoreRulesDigest'] as const)
    check(observedSource[key] === captured[key]);
  for (const entry of observedEntries.entries) if (entry.kind === 'file') {
    const value = await bytes(entry.blobRef); check(value.length === entry.size);
  }
  const assembly = decodeRetainedRunAssembly(await object(spec.assemblyRef));
  const bundle = await object(assembly.runtime.runtimeBundleRef);
  check(bundle.manifestDigest === assembly.runtime.runtimeBundleManifestDigest && Array.isArray(bundle.entries));
  const supervisorEntries = bundle.entries.filter((value: any) => value.role === 'supervisor'); check(supervisorEntries.length === 1);
  const supervisor = supervisorEntries[0];
  const ownerValues = await input.readOwnerHistory(); check(Array.isArray(ownerValues) && ownerValues.length > 0 && ownerValues.length <= 1000);
  const owners = ownerValues.map(value => decodeStateOwnerRecord(value));
  owners.forEach((value, index) => check(value.ownerEpoch === index + 1 && (index === owners.length - 1 || value.state === 'terminal')));
  let originalRoot: string | undefined;
  const inspector = async (proof: { inspectorIdentityRef: string; inspectorIdentityDigest: string; observedAt: string }, claim?: InvocationJournalEntry) => {
    const identity = await object(proof.inspectorIdentityRef);
    const owner = owners.find(value => value.ownerEpoch === identity.stateOwnerEpoch); check(owner);
    same(identity, supervisorInspectorIdentity(owner)); check(identity.identityDigest === proof.inspectorIdentityDigest);
    check(owner.runtimeBundleRef === assembly.runtime.runtimeBundleRef && owner.runtimeBundleManifestDigest === assembly.runtime.runtimeBundleManifestDigest &&
      owner.supervisorEntryId === supervisor.entryId && owner.supervisorEntryVersion === supervisor.version &&
      owner.supervisorExecutableDigest === supervisor.digest && supervisor.executable === true &&
      owner.acquiredAt <= proof.observedAt && (owner.state !== 'terminal' || owner.releasedAt >= proof.observedAt));
    if (claim) check(owner.ownerEpoch === claim.stateOwnerEpoch && owner.supervisorInstanceId === claim.supervisorInstanceId && claim.timestamp <= proof.observedAt);
    const process = decodePlatformProcessIdentity(await object(owner.processIdentityRef));
    const lock = decodeStateLockIdentity(await object(owner.stateLockIdentityRef));
    const root = decodeStateRootIdentity(await object(lock.stateRootIdentityRef));
    const acquired = decodeStateOwnerAcquisitionEvidence(await object(owner.acquisitionEvidenceRef));
    check(process.identityDigest === owner.processIdentityDigest && process.executableImageDigest === owner.supervisorExecutableDigest &&
      lock.identityDigest === owner.stateLockIdentityDigest && root.identityDigest === lock.stateRootIdentityDigest &&
      process.ownerUid === root.ownerUid && lock.ownerUid === root.ownerUid && lock.deviceId === root.deviceId &&
      root.deviceId === topology.rootIdentity.deviceId && root.ownerUid === topology.rootIdentity.ownerUid);
    for (const key of ['ownerEpoch', 'supervisorInstanceId', 'runtimeBundleRef', 'runtimeBundleManifestDigest', 'processIdentityRef',
      'processIdentityDigest', 'stateLockIdentityRef', 'stateLockIdentityDigest', 'instanceNonceDigest', 'acquiredAt'] as const) check(acquired[key] === owner[key]);
    check(acquired.evidenceDigest === owner.acquisitionEvidenceDigest);
    if (originalRoot === undefined) originalRoot = lock.stateRootIdentityRef;
    else check(originalRoot === lock.stateRootIdentityRef);
    return { owner, lock, root };
  };
  const proof = async (ref: string, claim?: InvocationJournalEntry) => {
    const value = decodePublicationProof(await object(ref));
    check(value.deliveryRunId === run.id && value.deliveryPlanRef === planRef &&
      value.workspaceIdentityRef === topology.workspaceIdentityRef && value.workspaceIdentityDigest === topology.workspaceIdentityDigest);
    await inspector(value, claim); return value;
  };
  const pathItems = items.filter(value => ['publication_path_progress', 'publication_path_result'].includes(value.item.kind));
  const histories = cut.journal.filter(value => value.opKind === 'publish');
  const policyItems = items.filter(value => value.item.kind === 'policy_decision' && value.item.subjectKind === 'delivery_plan');
  const decisionItems = items.filter(value => value.item.kind === 'delivery_decision');
  const projectionRef = result.deliveryTerminalProjectionEvidenceRef;
  const projection = decodeDeliveryTerminalProjectionEvidence(await object(projectionRef));
  const publicationCP = checkpoint(operation ? deliveryPublicationTerminalCheckpointId(run.id, planRef)
    : deliveryPublicationCheckpointId(run.id, planRef));
  const state = decodeWorkspaceState(await object(publicationCP.workspaceStateRef));
  check(state.runId === run.id && state.baseWorkspaceManifestRef === plan.capturedWorkspaceRef && state.entriesRef === observedSource.entriesRef &&
    publicationCP.reason === 'auto' && publicationCP.runItemSeq === items.length && publicationCP.journalSeq === cut.journal.length &&
    publicationCP.createdAt >= projection.observedAt && publicationCP.createdAt < run.deadlineAt &&
    parseCanonicalTime(publicationCP.createdAt) - parseCanonicalTime(projection.observedAt) <= 5000);
  const closure = decodeVerificationClosure(await object(result.verificationClosureRef));
  check(closure.runId === run.id && closure.resultSourceRef === result.resultSourceRef);
  const expectedFrontier = { schemaVersion: 1, kind: 'delivery', sourceRunResultRef: merged.sourceRunResultRef,
    candidateItemId: closure.candidateItemId, resultSourceRef: result.resultSourceRef,
    verifierPlanRef: closure.verifierPlanRef, verificationClosureRef: result.verificationClosureRef, deliveryPlanRef: planRef };
  const terminalContext = decodeContextManifest(await object(publicationCP.contextManifestRef));
  validateContextItems(terminalContext, items.map(({ row, item }) => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef, item } as {itemSeq:number;itemRef:string;item:ContinuationItem})));
  let slotRefs: string[] = [], arenaRefs: string[] = [], locations: Array<{kind:'publication_arena';arenaId:string;component:string}> = [];
  let resultRefs: string[] = [], progressCount = 0;
  let publicationWorkerRetirement: InstalledDeliveryPublicationSummary['publicationWorkerRetirement'] = null;
  if (!operation) {
    check(!histories.length && !pathItems.length && !policyItems.length && !decisionItems.length);
    const normalized = { ...captured, role: 'result', manifestDigest: '' };
    normalized.manifestDigest = digestOmitting(normalized, 'manifestDigest'); same(observedSource, normalized);
    const candidateCP = checkpoint(verificationCheckpointId(run.id, closure.candidateItemId, result.verificationClosureRef));
    check(candidateCP.basedOnRunRevision === publicationCP.basedOnRunRevision && candidateCP.createdAt === publicationCP.createdAt &&
      candidateCP.runItemSeq === publicationCP.runItemSeq && candidateCP.journalSeq === publicationCP.journalSeq &&
      candidateCP.contextManifestRef === publicationCP.contextManifestRef && candidateCP.workspaceStateRef === publicationCP.workspaceStateRef);
  } else {
    check(operation.expected.kind === 'file' && operation.desired.kind === 'file' && operation.parent.kind === 'existing_directory');
    check(histories.length === 3 && policyItems.length === 1 && decisionItems.length === 1 && pathItems.length === 3);
    const policyItem = policyItems[0]!.item, decision = decisionItems[0]!.item as DeliveryDecisionItem;
    check(policyItem.decisionSource === 'direct_policy' && policyItem.decision === 'allow' && decision.decision === 'allow' &&
      decision.runId === run.id && decision.deliveryPlanRef === planRef && decision.grantRef === policyItem.grantRef &&
      decision.decisionRef === policyItem.decisionRef && policyItems[0]!.row.itemSeq < decisionItems[0]!.row.itemSeq);
    const parent = await object(policyItem.grantRef) as DeliveryPlanGrantV1, channel = await object(policyItem.policyChannelEvidenceRef);
    same(await object(parent.frontierRef), { ...expectedFrontier, phase: 'approval' });
    const context = { runId: run.id, frontierRef: parent.frontierRef, assemblyRef: spec.assemblyRef, planRef, plan,
      workspaceIdentityRef: topology.workspaceIdentityRef, workspaceIdentityDigest: topology.workspaceIdentityDigest };
    const policy = await object(spec.policyRef);
    const evaluator = loadDeliveryPolicy({ policy, policyRef: spec.policyRef, assembly, assemblyRef: spec.assemblyRef,
      principalId: workspace.ownerPrincipalId, workspaceIdentityDigest: topology.workspaceIdentityDigest, context });
    const planned = planDeliveryRequest(context);
    same(await object(parent.requestRef), planned.request); same(await object(parent.targetRef), planned.target);
    same(channel, evaluator.evaluate(planned.request, planned.target, channel.evaluatedAt));
    same(parent, evaluator.grant(planned.request, planned.target, channel, parent.issuedAt, run.deadlineAt));
    check(parent.principalId === policyItem.principalId && policyItem.decisionRef === canonicalSha256(channel) &&
      policyItem.policyChannelEvidenceDigest === channel.evidenceDigest && decision.approvalOpId === parent.opId &&
      decision.createdAt === parent.issuedAt && policyItem.createdAt === parent.issuedAt);
    same(policyItem, { schemaVersion: 1, itemId: identityHash('cliq-delivery-policy-item-v1', run.id, parent.opId, canonicalSha256(channel)),
      runId: run.id, kind: 'policy_decision', subjectKind: 'delivery_plan', opId: parent.opId, principalId: workspace.ownerPrincipalId,
      decisionRef: canonicalSha256(channel), policyChannelEvidenceRef: canonicalSha256(channel), policyChannelEvidenceDigest: channel.evidenceDigest,
      createdAt: parent.issuedAt, decisionSource: 'direct_policy', decision: 'allow', grantRef: canonicalSha256(parent) });
    same(decision, { schemaVersion: 1, itemId: identityHash('cliq-delivery-decision-item-v1', run.id, planRef, canonicalSha256(channel)),
      runId: run.id, kind: 'delivery_decision', deliveryPlanRef: planRef, approvalOpId: parent.opId, decision: 'allow',
      decisionRef: canonicalSha256(channel), grantRef: canonicalSha256(parent), createdAt: parent.issuedAt });
    const [prepared, claim, terminal] = histories; check(prepared && claim && terminal);
    same(histories.map(value => value.phase), ['prepared', 'dispatch_claimed', 'completed']);
    const request = await object(prepared.requestRef), grant = await object(prepared.grantRef!);
    same(await object(request.frontierRef), { ...expectedFrontier, phase: 'publish', nextPathOperationIndex: 0 });
    const derived = derivePublicationGrant({ context: { ...context, frontierRef: request.frontierRef }, parent,
      parentRef: policyItem.grantRef, decision, sequence: 'forward', operationIndex: 0, issuedAt: grant.issuedAt });
    same(request, derived.request); same(grant, derived.grant); same(await object(prepared.target), derived.target);
    check(prepared.opId === request.opId && prepared.attempt === 0 && prepared.leaseEpoch > 0 && prepared.replayClass === 'reconcile' &&
      prepared.requestRef === canonicalSha256(request) && prepared.grantRef === canonicalSha256(grant) &&
      prepared.timestamp >= grant.issuedAt && prepared.timestamp < grant.expiresAt && claim.timestamp >= prepared.timestamp &&
      claim.timestamp < grant.expiresAt && terminal.timestamp >= claim.timestamp && claim.dispatchId && claim.stateOwnerEpoch && claim.supervisorInstanceId);
    for (const row of histories) {
      for (const key of ['opId', 'opKind', 'attempt', 'leaseEpoch', 'requestRef', 'target', 'grantRef', 'replayClass'] as const) check(row[key] === prepared[key]);
      check(row.idempotencyKey === undefined && row.sandboxLaunchSpecRef === undefined && row.brokerFenceTokenDigest === undefined);
    }
    for (const key of ['dispatchId', 'supervisorInstanceId', 'stateOwnerEpoch'] as const) check(terminal[key] === claim[key]);
    same(prepared.budgetDelta, ONE); same(claim.budgetDelta, ZERO); same(terminal.budgetDelta, ONE);
    const settlement = decodeBudgetSettlement(await object(terminal.budgetSettlementRef!));
    check(settlement.runId === run.id && settlement.opId === prepared.opId && settlement.attempt === 0 &&
      settlement.preparedJournalSeq === prepared.seq && settlement.terminalJournalSeq === terminal.seq &&
      settlement.terminalPhase === 'completed' && settlement.settledAt === terminal.timestamp);
    same(settlement.reserved, ONE); same(settlement.consumed, ONE); same(settlement.released, ONE);
    check(claim.evidenceRef && claim.evidenceDigest);
    const birth = decodePublicationArenaBirth(await object(claim.evidenceRef));
    const birthOwner = await inspector(birth);
    check(birthOwner.owner.ownerEpoch === claim.stateOwnerEpoch && birthOwner.owner.supervisorInstanceId === claim.supervisorInstanceId &&
      birth.deliveryRunId === run.id && birth.deliveryPlanRef === planRef && birth.workspaceIdentityRef === topology.workspaceIdentityRef &&
      birth.workspaceIdentityDigest === topology.workspaceIdentityDigest && birth.sequence === 'forward' && birth.operationIndex === 0 &&
      birth.operationId === operation.operationId && birth.opId === claim.opId && birth.attempt === 0 && birth.dispatchId === claim.dispatchId &&
      birth.birthDigest === claim.evidenceDigest && birth.stateRootIdentityRef === birthOwner.lock.stateRootIdentityRef &&
      birth.stateRootIdentityDigest === birthOwner.lock.stateRootIdentityDigest && birth.arenaIdentity.deviceId === birthOwner.root.deviceId &&
      birth.arenaIdentity.ownerUid === birthOwner.root.ownerUid && birth.observedAt >= prepared.timestamp && birth.observedAt <= claim.timestamp &&
      parseCanonicalTime(claim.timestamp) - parseCanonicalTime(birth.observedAt) <= 5000);
    locations = publicationEnvelopeLocations({ birth, operation }) as typeof locations;
    const progressRow = pathItems[0]!, handoffRow = pathItems[1]!, resultRow = pathItems[2]!;
    const progress = decodePublicationPathProgressItem(progressRow.item), handoff = decodePublicationPathProgressItem(handoffRow.item);
    const pathResult = decodePublicationPathResultItem(resultRow.item);
    check(progress.state === 'desired_committed_cleanup_pending' && handoff.state === 'received_handoff');
    for (const item of [progress, handoff, pathResult]) check(item.deliveryPlanRef === planRef && item.runId === run.id &&
      item.operationIndex === 0 && item.operationId === operation.operationId && item.opId === claim.opId && item.attempt === 0);
    check(progress.itemId === publicationProgressItemId(run.id, claim.opId, 0) && pathResult.sequence === 'forward' &&
      pathResult.outcome === 'completed' && !pathResult.abortStopIntentRef && pathResult.evidenceRef === pathResult.receiptRef &&
      pathResult.itemId === publicationResultItemId(run.id, claim.opId, 0, pathResult.evidenceRef) &&
      handoffRow.row.itemSeq === progressRow.row.itemSeq + 1 && resultRow.row.itemSeq === handoffRow.row.itemSeq + 1 &&
      handoff.itemId === publicationReceivedHandoffItemId(run.id, claim.opId) && handoff.sequence === 'forward' &&
      handoff.dispatchId === claim.dispatchId && handoff.claimJournalSeq === claim.seq &&
      handoff.receiptRef === pathResult.receiptRef && handoff.receiptDigest === terminal.evidenceDigest &&
      handoff.createdAt >= progress.createdAt && handoff.createdAt <= terminal.timestamp);
    same(handoff.retirement, pathResult.retirement);
    const decisionCP = checkpoint(deliveryDecisionCheckpointId(run.id, planRef, decision.decisionRef));
    const progressCP = checkpoint(publicationProgressCheckpointId(run.id, claim.opId, 0));
    const resourceCP = checkpoint(deliveryPublicationCheckpointId(run.id, planRef));
    check(decisionCP.runItemSeq === decisionItems[0]!.row.itemSeq && prepared.seq > decisionCP.journalSeq && prepared.timestamp >= decisionCP.createdAt &&
      progressRow.row.itemSeq === decisionCP.runItemSeq + 1 && progressCP.journalSeq === claim.seq && progressCP.reason === 'auto' &&
      progressCP.runItemSeq === progressRow.row.itemSeq && progressCP.basedOnRunRevision > decisionCP.basedOnRunRevision &&
      resourceCP.basedOnRunRevision > progressCP.basedOnRunRevision && publicationCP.basedOnRunRevision > resourceCP.basedOnRunRevision &&
      resourceCP.runItemSeq === handoffRow.row.itemSeq && resourceCP.journalSeq === claim.seq && resourceCP.reason === 'auto' &&
      resourceCP.createdAt >= handoff.createdAt && resourceCP.createdAt <= terminal.timestamp &&
      progressCP.createdAt >= progress.createdAt &&
      progressCP.createdAt >= claim.timestamp && progressCP.createdAt <= terminal.timestamp &&
      progressCP.workspaceStateRef === decisionCP.workspaceStateRef && resourceCP.workspaceStateRef === progressCP.workspaceStateRef &&
      publicationCP.workspaceStateRef === resourceCP.workspaceStateRef);
    // This journey covers the normal, genuinely sealed original M branch.
    // A recovered UNKNOWN has a different complete provenance/resource graph;
    // it cannot be counted as this journey merely because its bytes match.
    check(handoff.generationResources.kind === 'sealed');
    const sealed = handoff.generationResources;
    const snapshot = decodeWorkspaceGenerationSnapshotEvidence(await object(sealed.snapshotEvidenceRef));
    check(snapshot.purpose === 'sealed_to_checkpoint' && snapshot.runId === run.id &&
      snapshot.generationRef === sealed.generationRef && snapshot.checkpointId === resourceCP.id &&
      snapshot.workspaceStateRef === resourceCP.workspaceStateRef && snapshot.workspaceStateDigest === state.stateDigest &&
      snapshot.entriesRef === observedSource.entriesRef && snapshot.treeDigest === observedSource.treeDigest &&
      snapshot.privateGitStateRef === undefined && snapshot.observedAt >= claim.timestamp && snapshot.observedAt <= handoff.createdAt);
    publicationWorkerRetirement = Object.freeze({ launchId: sealed.workerLaunchId,
      supervisorInstanceId: claim.supervisorInstanceId!, leaseEpoch: claim.leaseEpoch,
      workspaceGenerationRef: snapshot.generationRef, snapshotEvidenceRef: sealed.snapshotEvidenceRef,
      snapshotEvidenceDigest: snapshot.evidenceDigest, retiredAt: resourceCP.createdAt });
    const appendContext = async (previous: Checkpoint, next: Checkpoint, value: typeof progressRow) => {
      const before = decodeContextManifest(await object(previous.contextManifestRef));
      const after = decodeContextManifest(await object(next.contextManifestRef));
      const core = { ...before, segments: [...before.segments, { kind: 'excluded_control' as const,
        fromItemSeq: value.row.itemSeq, throughItemSeq: value.row.itemSeq,
        sourceItemsDigest: contextSourceDigest([{ itemSeq: value.row.itemSeq, itemRef: value.row.payloadRef, item: value.item }]) }],
        throughItemSeq: value.row.itemSeq };
      same(after, { ...core, projectionDigest: digestOmitting(core, 'projectionDigest') });
    };
    await appendContext(decisionCP, progressCP, progressRow); await appendContext(progressCP, resourceCP, handoffRow);
    await appendContext(resourceCP, publicationCP, resultRow);
    const before = await proof(progress.beforeObservationRef, claim);
    const destination = await proof(progress.destinationEvidenceRef, claim), transient = await proof(progress.transientObservationRef!, claim);
    check(before.kind === 'path_observation' && destination.kind === 'path_observation' && transient.kind === 'path_observation');
    check(before.observation.location.kind === 'workspace' && before.observation.location.path === operation.path &&
      before.observedAt >= claim.timestamp && before.observedAt <= progress.createdAt);
    same(before.observation.state, operation.expected);
    check(destination.observation.location.kind === 'workspace' && destination.observation.location.path === operation.path &&
      destination.observedAt <= progress.createdAt && transient.observedAt <= progress.createdAt &&
      progress.preservedPreimageRef === operation.expected.digest && transient.observation.state.kind !== 'absent');
    same(destination.observation.state, operation.desired); same(transient.observation.state, operation.expected);
    same(transient.observation.location, { kind: 'publication_arena', arenaId: birth.arenaId, component: operation.quarantineName });
    const preimage = await bytes(progress.preservedPreimageRef!);
    const old = capturedEntries.entries.find(value => value.path === operation.path); check(old?.kind === 'file');
    check(old.blobRef === operation.expected.digest && old.size === preimage.length &&
      topology.fileModes.find(entry => entry.path === operation.path)?.mode === operation.expected.mode);
    const parentIdentity = topology.rootIdentity;
    check(operation.parent.expectedIdentityDigest === parentIdentity.identityDigest);
    const receipt = await proof(pathResult.receiptRef, claim); check(receipt.kind === 'terminal_receipt');
    check(receipt.sequence === 'forward' && receipt.operationIndex === 0 && receipt.operationId === operation.operationId &&
      receipt.opId === claim.opId && receipt.attempt === 0 && receipt.observedAt <= handoff.createdAt && terminal.timestamp <= pathResult.createdAt &&
      terminal.receiptRef === pathResult.receiptRef && terminal.evidenceRef === pathResult.evidenceRef && terminal.evidenceDigest === receipt.proofDigest &&
      (terminal.resultRef === undefined || terminal.resultRef === pathResult.receiptRef) && receipt.preservedPreimageRef === progress.preservedPreimageRef &&
      receipt.before.location.kind === 'workspace' && receipt.before.location.path === operation.path &&
      receipt.after.location.kind === 'workspace' && receipt.after.location.path === operation.path &&
      receipt.before.entryLinkCount === 1 && receipt.after.entryLinkCount === 1 &&
      receipt.parentIdentityBeforeDigest === parentIdentity.identityDigest && receipt.parentIdentityAfterDigest === parentIdentity.identityDigest);
    same(receipt.before.state, operation.expected); same(receipt.after.state, operation.desired);
    same(receipt.before, before.observation);
    for (const observed of [destination.observation, receipt.before, receipt.after]) check(observed.parentDeviceId === parentIdentity.deviceId && observed.parentFileId === parentIdentity.fileId);
    check(transient.observation.parentDeviceId === birth.arenaIdentity.deviceId && transient.observation.parentFileId === birth.arenaIdentity.fileId);
    // This campaign deliberately qualifies the uninterrupted original-owner
    // path. Successor namespace recovery has its own original-death campaign;
    // accepting that union here would not exercise this journey's contract.
    check(!('kind' in pathResult.retirement) && receipt.namespaceRetirementEvidenceRef === undefined);
    slotRefs = pathResult.retirement.slotObservationRefs; arenaRefs = [pathResult.retirement.arenaRetirementRef];
    check(slotRefs.length === locations.length);
    const arena = await proof(arenaRefs[0]!, claim); check(arena.kind === 'arena_retirement');
    check(arena.arenaId === birth.arenaId && arena.stateRootIdentityRef === birth.stateRootIdentityRef && arena.stateRootIdentityDigest === birth.stateRootIdentityDigest &&
      arena.inspectorIdentityRef === birth.inspectorIdentityRef && arena.inspectorIdentityDigest === birth.inspectorIdentityDigest &&
      arena.observedAt >= birth.observedAt && arena.observedAt <= receipt.observedAt &&
      arena.retirementObservation.kind === (birthOwner.root.platform === 'linux' ? 'linux_unlinked' : 'darwin_unlinked'));
    same(arena.arenaIdentity, birth.arenaIdentity); same(arena.parentIdentity, birth.parentIdentity);
    const observations = [];
    for (const [index, ref] of slotRefs.entries()) {
      const slot = await proof(ref, claim); check(slot.kind === 'path_observation' && slot.observation.state.kind === 'absent' &&
        slot.inspectorIdentityRef === birth.inspectorIdentityRef && slot.inspectorIdentityDigest === birth.inspectorIdentityDigest &&
        slot.observedAt >= progressCP.createdAt && slot.observedAt <= arena.observedAt &&
        slot.observation.parentDeviceId === birth.arenaIdentity.deviceId && slot.observation.parentFileId === birth.arenaIdentity.fileId);
      same(slot.observation.location, locations[index]); observations.push(slot.observation);
    }
    same(receipt.transientFinalObservations, observations);
    resultRefs = [resultRow.row.payloadRef]; progressCount = 1;
  }
  check(projection.deliveryRunId === run.id && projection.deliveryPlanRef === planRef && projection.selectedBranch === 'forward_finalize' &&
    projection.observedSourceRef === plan.desiredSourceRef);
  same(projection.forwardResultItemRefs, resultRefs); same(projection.abortResultItemRefs, []); same(projection.unstartedForwardOperationIds, []);
  same(projection.observedPathStates.map(value => value.path), operation ? [operation.path] : []);
  const absence = await proof(projection.transientAbsenceEvidenceRef), closed = await proof(projection.projectionClosureEvidenceRef), git = await proof(projection.gitIndexUnchangedEvidenceRef);
  check(absence.kind === 'transient_absence' && closed.kind === 'projection_closure' && git.kind === 'git_index_unchanged' &&
    closed.observedAt === projection.observedAt && absence.observedAt <= projection.observedAt && git.observedAt <= projection.observedAt);
  for (const value of [absence, git]) check(value.inspectorIdentityRef === closed.inspectorIdentityRef && value.inspectorIdentityDigest === closed.inspectorIdentityDigest);
  const terminalOwner = await inspector(closed);
  check(publicationCP.createdAt >= terminalOwner.owner.acquiredAt &&
    (terminalOwner.owner.state !== 'terminal' || publicationCP.createdAt <= terminalOwner.owner.releasedAt));
  check(absence.observationRefs !== undefined && absence.arenaRetirementRefs !== undefined && absence.envelopeRetirements === undefined);
  same(absence.transientLocations, locations); same(absence.observationRefs, slotRefs); same(absence.arenaRetirementRefs, arenaRefs);
  for (const ref of [...slotRefs, ...arenaRefs]) check((await proof(ref)).observedAt <= absence.observedAt);
  check(closed.selectedBranch === projection.selectedBranch && closed.observedSourceRef === projection.observedSourceRef);
  for (const key of ['forwardResultItemRefs', 'abortResultItemRefs', 'unstartedForwardOperationIds'] as const) same(closed[key], projection[key]);
  same(closed.observedPathEvidenceRefs, projection.observedPathStates.map(value => value.evidenceRef));
  for (const path of projection.observedPathStates) {
    const observed = await proof(path.evidenceRef); check(observed.kind === 'path_observation' && observed.observation.location.kind === 'workspace' &&
      observed.observation.location.path === path.path && observed.observedAt <= projection.observedAt &&
      observed.inspectorIdentityRef === closed.inspectorIdentityRef && observed.inspectorIdentityDigest === closed.inspectorIdentityDigest);
    same(observed.observation.state, path.state);
    check(operation && operation.desired.kind === 'file'); same(path.state, operation.desired);
    check(observed.observation.parentDeviceId === topology.rootIdentity.deviceId &&
      observed.observation.parentFileId === topology.rootIdentity.fileId && observed.observation.entryLinkCount === 1);
  }
  return Object.freeze({ planRef, projectionRef, publishClaims: operation ? 1 : 0, progressCount,
    receiptCount: resultRefs.length, slotObservationCount: slotRefs.length, arenaRetirementCount: arenaRefs.length,
    publicationWorkerRetirement });
}
