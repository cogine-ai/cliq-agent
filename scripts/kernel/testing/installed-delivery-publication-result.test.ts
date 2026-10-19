// Inert graph regressions only: these fixtures create no installed runtime,
// StateOwner, native observation, SQL claim or permission.
import assert from 'node:assert/strict';
import test from 'node:test';
import { assertInstalledDeliveryPublication } from './installed-delivery-publication-result.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { encodeControlCheckpointCursor } from '../../../src/kernel/control-wire.js';
import { digestOmitting, identityHash, sha256Bytes } from '../../../src/kernel/identity.js';
import { decodePublicationProof, publicationArenaId, publicationDirectoryIdentityDigest } from '../../../src/kernel/publication.js';
import type { StateOwnerRecordV1 } from '../../../src/kernel/types.js';
import { testFixture } from '../../../src/model/testing/fixtures.js';
import { BUILTIN_POLICY_RULES, modeDecisions } from '../../../src/policy/tool-policy.js';
import { contextSourceDigest } from '../../../src/runtime/context-compaction.js';
import { derivePublicationGrant, deliveryDecisionCheckpointId, loadDeliveryPolicy, planDeliveryRequest } from '../../../src/state/delivery-policy.js';
import { deliveryPublicationCheckpointId, deliveryPublicationTerminalCheckpointId, publicationProgressCheckpointId,
  publicationProgressItemId, publicationReceivedHandoffItemId, publicationResultItemId } from '../../../src/state/delivery-publication-progress.js';
import { verificationCheckpointId } from '../../../src/state/run-result-recovery.js';
import { supervisorInspectorIdentity } from '../../../src/state/supervisor-inspector.js';

const zero = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, one = { ...zero, toolCalls: 1 };
const at = (ms = 0) => `2026-10-18T00:00:00.${String(ms).padStart(3, '0')}Z`;
const seal = (value: any, field: string): any => ({ ...value, [field]: digestOmitting(value, field) });
type Mutations = { proof?: (kind: string, value: any) => void; birth?: (value: any) => void;
  claim?: (value: any) => void; progress?: (value: any) => void; handoff?: (value: any) => void;
  snapshot?: (value: any) => void; result?: (value: any) => void; cut?: (value: any) => void };

function graph(withPath = false, mutations: Mutations = {}, capturedText = 'before\n') {
  const objects = new Map<string, Buffer>(), ref = canonicalSha256;
  const put = (value: unknown) => { const bytes = canonicalJsonBytes(value), id = sha256Bytes(bytes); objects.set(id, bytes); return id; };
  const blob = (text: string) => { const bytes = Buffer.from(text), id = sha256Bytes(bytes); objects.set(id, bytes); return id; };
  const runId = identityHash('inert-delivery-data'), sourceResultRef = ref('original verified source result');
  const workspace = seal({ schemaVersion: 1, format: 'cliq-workspace-identity-v1', ownerPrincipalId: 'principal',
    platform: 'linux', kind: 'live', canonicalRootPath: '/inert-workspace',
    rootIdentity: { deviceId: '1', fileId: '20', ownerUid: 1000 } }, 'identityDigest');
  const workspaceRef = put(workspace);
  const capturedParent = { ...workspace.rootIdentity, mode: 0o755,
    identityDigest: publicationDirectoryIdentityDigest(workspace.identityDigest, { ...workspace.rootIdentity, mode: 0o755 }) };
  const beforeBlob = blob('before\n'), afterBlob = withPath ? blob('after\n') : beforeBlob;
  const entries = (bytesRef: string) => {
    const rows = [{ path: 'example.txt', kind: 'file', mode: 0o644, size: objects.get(bytesRef)!.length, blobRef: bytesRef }];
    return { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: rows, entryCount: 1,
      byteCount: rows[0]!.size, treeDigest: ref({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: rows }) };
  };
  const source = (role: string, data: ReturnType<typeof entries>) => seal({ schemaVersion: 1, format: 'cliq-source-manifest-v1', role,
    workspaceIdentityDigest: workspace.identityDigest, sourceProjectionRef: ref('projection'), sourceProjectionDigest: ref('projection digest'),
    frozenIgnoreRulesRef: ref('frozen rules'), frozenIgnoreRulesDigest: ref('frozen rules digest'), entriesRef: put(data), treeDigest: data.treeDigest }, 'manifestDigest');
  const captured = source('base', entries(capturedText === 'before\n' ? beforeBlob : blob(capturedText))), desired = source('result', entries(afterBlob));
  const capturedRef = put(captured), desiredRef = put(desired);
  const topology = seal({ schemaVersion: 1, format: 'cliq-delivery-capture-topology-v1', inspectionId: identityHash('original-apply-inspection'),
    capturedWorkspaceRef: capturedRef, workspaceIdentityRef: workspaceRef, workspaceIdentityDigest: workspace.identityDigest,
    rootIdentity: capturedParent, directories: [], fileModes: [{ path: 'example.txt', mode: 0o644 }], capturedAt: at() }, 'topologyDigest');
  const operation = { index: 0, operationId: identityHash('inert-regular-replace'), path: 'example.txt',
    parent: { kind: 'existing_directory', expectedIdentityDigest: capturedParent.identityDigest }, kind: 'replace',
    expected: { kind: 'file', mode: 0o644, digest: beforeBlob }, desired: { kind: 'file', mode: 0o644, digest: afterBlob },
    stagingName: 'desired', stagingExpected: { kind: 'absent' }, quarantineName: 'preimage', quarantineExpected: { kind: 'absent' } };
  const plan = { schemaVersion: 1, deliveryRunId: runId, sourceRunResultRef: sourceResultRef,
    sourceBaseRef: ref('B'), sourceDesiredRef: desiredRef, capturedWorkspaceRef: capturedRef,
    captureTopologyRef: put(topology), captureTopologyDigest: topology.topologyDigest, desiredSourceRef: desiredRef, diffRef: ref('diff'),
    mergeAlgorithm: 'cliq-diff3-v1', publicationStateMachine: 'cliq-publish-v1', forwardOperations: withPath ? [operation] : [], abortOperations: [] };
  const planRef = put(plan), assembly = structuredClone(testFixture().assembly);
  const supervisor = { entryId: 'supervisor', version: '1', role: 'supervisor', executable: true, digest: ref('supervisor image') };
  const bundle = { entries: [supervisor], manifestDigest: ref('original bundle manifest') };
  assembly.runtime.runtimeBundleRef = put(bundle); assembly.runtime.runtimeBundleManifestDigest = bundle.manifestDigest;
  assembly.assemblyDigest = digestOmitting(assembly, 'assemblyDigest');
  const assemblyRef = put(assembly);
  const policy = seal({ schemaVersion: 1, format: 'cliq-run-policy-v1', principalId: 'principal', workspaceIdentityDigest: workspace.identityDigest,
    mode: 'yolo', engine: { id: 'cliq-policy-v1', version: '1', runtimeBundleRef: assembly.runtime.runtimeBundleRef,
      profileEntryId: 'policy', profileRef: ref('profile'), profileDigest: ref('profile digest') }, toolManifestRef: assembly.tools.manifestRef,
    toolManifestDigest: assembly.tools.manifestDigest, decisions: modeDecisions('yolo'), decisionRules: [...BUILTIN_POLICY_RULES],
    repositoryRequestRefs: [], createdAt: at() }, 'policyDigest');
  const policyRef = put(policy);
  const root = seal({ schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux', canonicalAbsolutePath: '/inert-state',
    ownerUid: 1000, deviceId: '1', directoryFileId: '10', mode: 0o700, openedNoFollow: true, layoutVersion: 1 }, 'identityDigest');
  const rootRef = put(root), lock = seal({ schemaVersion: 1, format: 'cliq-state-lock-identity-v1', stateRootIdentityRef: rootRef,
    stateRootIdentityDigest: root.identityDigest, canonicalRootRelativePath: 'runtime/state-owner.lock', deviceId: '1', fileId: '11',
    ownerUid: 1000, mode: 0o600, linkCount: 1 }, 'identityDigest');
  const process = seal({ schemaVersion: 1, format: 'cliq-platform-process-identity-v1', platform: 'linux', pid: 999,
    processStartToken: 'inert-start', ownerUid: 1000, executableImageDigest: supervisor.digest, observedAt: at() }, 'identityDigest');
  const ownerCore = { ownerEpoch: 1, supervisorInstanceId: 'original-supervisor', runtimeBundleRef: assembly.runtime.runtimeBundleRef,
    runtimeBundleManifestDigest: assembly.runtime.runtimeBundleManifestDigest, processIdentityRef: put(process), processIdentityDigest: process.identityDigest,
    stateLockIdentityRef: put(lock), stateLockIdentityDigest: lock.identityDigest, instanceNonceDigest: ref('nonce'), acquiredAt: at() };
  const acquisition = seal({ schemaVersion: 1, format: 'cliq-state-owner-acquisition-evidence-v1', ...ownerCore, kind: 'genesis',
    kernelGenerationIdentityRef: ref('kernel genesis'), kernelGenerationIdentityDigest: ref('kernel genesis digest'), ownerTableObservation: 'empty' }, 'evidenceDigest');
  const owner = seal({ schemaVersion: 1, ...ownerCore, supervisorEntryId: supervisor.entryId, supervisorEntryVersion: supervisor.version,
    supervisorExecutableDigest: supervisor.digest, acquisitionEvidenceRef: put(acquisition), acquisitionEvidenceDigest: acquisition.evidenceDigest,
    state: 'active', rowVersion: 1 }, 'rowDigest') as StateOwnerRecordV1;
  const inspector = supervisorInspectorIdentity(owner), inspectorRef = put(inspector);
  const proof = (kind: string, fields: Record<string, unknown>, ms: number) => {
    const value = { schemaVersion: 1, format: 'cliq-publication-proof-v1', deliveryRunId: runId, deliveryPlanRef: planRef,
      workspaceIdentityRef: workspaceRef, workspaceIdentityDigest: workspace.identityDigest,
      inspectorIdentityRef: inspectorRef, inspectorIdentityDigest: inspector.identityDigest, kind, ...fields, observedAt: at(ms) };
    mutations.proof?.(kind, value); return { value: seal(value, 'proofDigest'), get ref() { return put(this.value); } };
  };
  const merged = { schemaVersion: 1, itemId: 'merge', runId, kind: 'delivery_merge', sourceRunResultRef: sourceResultRef,
    sourceBaseRef: plan.sourceBaseRef, sourceDesiredRef: desiredRef, capturedWorkspaceRef: capturedRef, resultSourceRef: desiredRef,
    diffRef: plan.diffRef, summaryRef: ref('summary'), deliveryPlanRef: planRef, createdAt: at() };
  const candidate = { schemaVersion: 1, itemId: 'candidate', runId, kind: 'final_candidate', operation: 'delivery', producingItemId: 'merge',
    baseSourceRef: capturedRef, resultSourceRef: desiredRef, diffRef: plan.diffRef, summaryRef: merged.summaryRef,
    sourceDigest: desired.manifestDigest, diffDigest: ref('diff digest'), createdAt: at() };
  const rawItems: any[] = [merged, candidate], journal: any[] = [], checkpoints: any[] = [];
  const addItem = (item: any) => { rawItems.push(item); return put(item); };
  const rows = () => rawItems.map((item, index) => ({ schemaVersion: 1,
    itemSeq: index + 1, itemId: item.itemId, payloadRef: put(item), payloadDigest: put(item), createdAt: item.createdAt }));
  const context = (through: number) => seal({ schemaVersion: 1, format: 'cliq-context-manifest-v1', runId, admittedContextRef: ref('admitted'), assemblyRef,
    throughItemSeq: through, segments: rawItems.slice(0, through).map((item, index) => ({ kind: 'excluded_control', fromItemSeq: index + 1,
      throughItemSeq: index + 1, sourceItemsDigest: contextSourceDigest([{ itemSeq: index + 1, itemRef: put(item), item }]) })) }, 'projectionDigest');
  const workspaceState = seal({ schemaVersion: 1, format: 'cliq-workspace-state-v1', runId, baseWorkspaceManifestRef: capturedRef,
    entriesRef: desired.entriesRef, invalidatedEphemeralPaths: [], sourceProjectionDigest: desired.sourceProjectionDigest }, 'stateDigest');
  const workspaceStateRef = put(workspaceState);
  const cp = (id: string, revision: number, through: number, journalSeq: number, ms: number) => ({ id, schemaVersion: 1, runId,
    basedOnRunRevision: revision, runItemSeq: through, contextManifestRef: put(context(through)), journalSeq, workspaceStateRef,
    createdAt: at(ms), reason: 'auto' });
  const closure = seal({ schemaVersion: 1, format: 'cliq-verification-closure-v1', runId, candidateItemId: candidate.itemId,
    resultSourceRef: desiredRef, verifierPlanRef: ref('verifier plan'), dependency: { kind: 'none' }, verification: { kind: 'inherited_verified',
      sourceRunId: 'source', sourceRunResultRef: sourceResultRef, sourceVerificationClosureRef: ref('source closure'), inheritedProvenanceRef: ref('provenance') },
    createdAt: at() }, 'closureDigest');
  const closureRef = put(closure), frontierCore = { schemaVersion: 1, kind: 'delivery', sourceRunResultRef: sourceResultRef,
    candidateItemId: candidate.itemId, resultSourceRef: desiredRef, verifierPlanRef: closure.verifierPlanRef,
    verificationClosureRef: closureRef, deliveryPlanRef: planRef };
  let pathRefs: string[] = [], slotRefs: string[] = [], arenaRefs: string[] = [], locations: any[] = [], terminalPath: any[] = [];
  let publicationWorkerRetirement: Record<string, unknown> | null = null;
  if (withPath) {
    const approvalFrontierRef = put({ ...frontierCore, phase: 'approval' });
    const context = { runId, frontierRef: approvalFrontierRef, assemblyRef, planRef, plan,
      workspaceIdentityRef: workspaceRef, workspaceIdentityDigest: workspace.identityDigest };
    const evaluator = loadDeliveryPolicy({ policy, policyRef, assembly, assemblyRef, principalId: 'principal', workspaceIdentityDigest: workspace.identityDigest, context } as any);
    const planned = planDeliveryRequest(context as any), evidence = evaluator.evaluate(planned.request, planned.target, at());
    const parent = evaluator.grant(planned.request, planned.target, evidence, at(), '2026-10-18T00:05:00.000Z');
    put(planned.request); put(planned.target);
    const policyItem = { schemaVersion: 1, itemId: identityHash('cliq-delivery-policy-item-v1', runId, parent.opId, put(evidence)), runId, kind: 'policy_decision', subjectKind: 'delivery_plan', opId: parent.opId,
      principalId: 'principal', decisionSource: 'direct_policy', decision: 'allow', decisionRef: put(evidence), policyChannelEvidenceRef: put(evidence),
      policyChannelEvidenceDigest: evidence.evidenceDigest, grantRef: put(parent), createdAt: at() };
    const decision = { schemaVersion: 1, itemId: identityHash('cliq-delivery-decision-item-v1', runId, planRef, put(evidence)), runId, kind: 'delivery_decision', deliveryPlanRef: planRef,
      approvalOpId: parent.opId, decision: 'allow', decisionRef: put(evidence), grantRef: put(parent), createdAt: at() };
    addItem(policyItem); addItem(decision);
    checkpoints.push(cp(deliveryDecisionCheckpointId(runId, planRef, decision.decisionRef), 2, 4, 0, 0));
    const publishFrontierRef = put({ ...frontierCore, phase: 'publish', nextPathOperationIndex: 0 });
    const child = derivePublicationGrant({ context: { ...context, frontierRef: publishFrontierRef }, parent, parentRef: put(parent),
      decision, sequence: 'forward', operationIndex: 0, issuedAt: at() } as any);
    put(child.target); const requestRef = put(child.request), grantRef = put(child.grant), opId = child.request.opId;
    const birth: any = { schemaVersion: 1, format: 'cliq-publication-arena-birth-v1', deliveryRunId: runId, deliveryPlanRef: planRef,
      workspaceIdentityRef: workspaceRef, workspaceIdentityDigest: workspace.identityDigest, stateRootIdentityRef: rootRef, stateRootIdentityDigest: root.identityDigest,
      inspectorIdentityRef: inspectorRef, inspectorIdentityDigest: inspector.identityDigest, sequence: 'forward', operationIndex: 0,
      operationId: operation.operationId, opId, attempt: 0, dispatchId: 'original-dispatch',
      arenaId: publicationArenaId(runId, operation.operationId, opId, 0, 'original-dispatch'),
      arenaIdentity: { deviceId: '1', fileId: '30', ownerUid: 1000, mode: 0o700 }, parentIdentity: { deviceId: '1', fileId: '31', ownerUid: 1000, mode: 0o700 }, observedAt: at(1) };
    mutations.birth?.(birth); const sealedBirth = seal(birth, 'birthDigest');
    const common = { runId, opId, opKind: 'publish', attempt: 0, leaseEpoch: 1, requestRef, grantRef, target: child.request.targetRef, replayClass: 'reconcile' };
    journal.push({ ...common, seq: 1, phase: 'prepared', budgetDelta: one, timestamp: at() });
    const claim: any = { ...common, seq: 2, phase: 'dispatch_claimed', budgetDelta: zero, timestamp: at(2), dispatchId: 'original-dispatch',
      supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: 1, evidenceRef: put(sealedBirth), evidenceDigest: sealedBirth.birthDigest };
    mutations.claim?.(claim); journal.push(claim);
    const observation = (location: any, state: any, fileId = '40') => ({ location, state, parentDeviceId: '1', parentFileId: location.kind === 'workspace' ? '20' : '30',
      parentLinkCount: 2, ...(state.kind === 'absent' ? {} : { entryDeviceId: '1', entryFileId: fileId, entryLinkCount: 1 }) });
    const after = observation({ kind: 'workspace', path: 'example.txt' }, operation.desired, '41');
    const before = observation({ kind: 'workspace', path: 'example.txt' }, operation.expected);
    const originalBefore = proof('path_observation', { observation: before }, 2);
    const destination = proof('path_observation', { observation: after }, 3);
    const transient = proof('path_observation', { observation: observation({ kind: 'publication_arena', arenaId: birth.arenaId, component: 'preimage' }, operation.expected) }, 3);
    const progress: any = { schemaVersion: 1, itemId: publicationProgressItemId(runId, opId, 0), runId, kind: 'publication_path_progress',
      deliveryPlanRef: planRef, operationIndex: 0, operationId: operation.operationId, opId, attempt: 0, state: 'desired_committed_cleanup_pending',
      beforeObservationRef: originalBefore.ref, destinationEvidenceRef: destination.ref, preservedPreimageRef: beforeBlob,
      transientObservationRef: transient.ref, createdAt: at(3) };
    mutations.progress?.(progress); addItem(progress);
    checkpoints.push(cp(publicationProgressCheckpointId(runId, opId, 0), 3, 5, 2, 4));
    locations = ['desired', 'preimage'].map(component => ({ kind: 'publication_arena', arenaId: birth.arenaId, component }));
    const slots = locations.map(location => proof('path_observation', { observation: observation(location, { kind: 'absent' }) }, 5));
    slotRefs = slots.map(value => value.ref);
    const arena = proof('arena_retirement', { arenaId: birth.arenaId, stateRootIdentityRef: rootRef, stateRootIdentityDigest: root.identityDigest,
      arenaIdentity: birth.arenaIdentity, parentIdentity: birth.parentIdentity, arenaAbsent: true, arenaParentFsyncCompleted: true,
      retirementObservation: { kind: 'linux_unlinked', linkCount: 0 } }, 6); arenaRefs = [arena.ref];
    const receipt = proof('terminal_receipt', { sequence: 'forward', operationIndex: 0, operationId: operation.operationId, opId, attempt: 0,
      before, after, preservedPreimageRef: beforeBlob, transientFinalObservations: slots.map(value => value.value.observation),
      parentIdentityBeforeDigest: capturedParent.identityDigest, parentIdentityAfterDigest: capturedParent.identityDigest, directoryFsyncCompleted: true }, 7);
    const snapshot: any = { schemaVersion: 1, format: 'cliq-workspace-generation-snapshot-evidence-v1', purpose: 'sealed_to_checkpoint',
      runId, generationRef: ref('original M generation'), generationIdentityDigest: ref('original M identity'),
      checkpointId: deliveryPublicationCheckpointId(runId, planRef), workspaceStateRef, workspaceStateDigest: workspaceState.stateDigest,
      entriesRef: desired.entriesRef, treeDigest: desired.treeDigest, quiescenceEvidenceRef: ref('original M quiescence'),
      descriptorRewalkComplete: true, fileFsyncComplete: true, directoryFsyncComplete: true, observedAt: at(7) };
    mutations.snapshot?.(snapshot); const sealedSnapshot = seal(snapshot, 'evidenceDigest');
    const handoff: any = { schemaVersion: 1, itemId: publicationReceivedHandoffItemId(runId, opId), runId, kind: 'publication_path_progress',
      deliveryPlanRef: planRef, operationIndex: 0, operationId: operation.operationId, opId, attempt: 0,
      state: 'received_handoff', sequence: 'forward', dispatchId: claim.dispatchId, claimJournalSeq: claim.seq,
      receiptRef: receipt.ref, receiptDigest: receipt.value.proofDigest,
      retirement: { slotObservationRefs: slotRefs, arenaRetirementRef: arena.ref },
      generationResources: { kind: 'sealed', workerLaunchId: 'original-M-worker', generationRef: snapshot.generationRef,
        snapshotEvidenceRef: put(sealedSnapshot) }, createdAt: at(7) };
    mutations.handoff?.(handoff); addItem(handoff);
    checkpoints.push(cp(deliveryPublicationCheckpointId(runId, planRef), 4, 6, claim.seq, 7));
    publicationWorkerRetirement = { launchId: 'original-M-worker', supervisorInstanceId: claim.supervisorInstanceId,
      leaseEpoch: claim.leaseEpoch, workspaceGenerationRef: snapshot.generationRef, snapshotEvidenceRef: put(sealedSnapshot),
      snapshotEvidenceDigest: sealedSnapshot.evidenceDigest, retiredAt: at(7) };
    const settlement = seal({ schemaVersion: 1, format: 'cliq-budget-settlement-v1', runId, opId, attempt: 0, preparedJournalSeq: 1, terminalJournalSeq: 3,
      terminalPhase: 'completed', reserved: one, consumed: one, released: one, budgetConsumedBefore: zero, budgetConsumedAfter: one,
      budgetReservedBefore: one, budgetReservedAfter: zero, settledAt: at(8) }, 'settlementDigest');
    journal.push({ ...claim, seq: 3, phase: 'completed', timestamp: at(8), budgetDelta: one, budgetSettlementRef: put(settlement),
      evidenceRef: receipt.ref, evidenceDigest: receipt.value.proofDigest, receiptRef: receipt.ref });
    const item: any = { schemaVersion: 1, itemId: publicationResultItemId(runId, opId, 0, receipt.ref), runId, kind: 'publication_path_result',
      deliveryPlanRef: planRef, sequence: 'forward', operationIndex: 0, operationId: operation.operationId, opId, attempt: 0,
      outcome: 'completed', evidenceRef: receipt.ref, receiptRef: receipt.ref, retirement: { slotObservationRefs: slotRefs, arenaRetirementRef: arena.ref }, createdAt: at(8) };
    mutations.result?.(item); pathRefs = [addItem(item)];
    terminalPath = [{ path: 'example.txt', state: operation.desired, evidenceRef: proof('path_observation', { observation: after }, 9).ref }];
  }
  const absence = proof('transient_absence', { transientLocations: locations, observationRefs: slotRefs, arenaRetirementRefs: arenaRefs }, 9);
  const closed = proof('projection_closure', { selectedBranch: 'forward_finalize', observedSourceRef: desiredRef,
    observedPathEvidenceRefs: terminalPath.map(value => value.evidenceRef), forwardResultItemRefs: pathRefs, unstartedForwardOperationIds: [], abortResultItemRefs: [] }, 9);
  const git = proof('git_index_unchanged', { repositoryKind: 'non_git' }, 9);
  const projection = seal({ schemaVersion: 1, deliveryRunId: runId, deliveryPlanRef: planRef, selectedBranch: 'forward_finalize',
    observedSourceRef: desiredRef, observedPathStates: terminalPath, forwardResultItemRefs: pathRefs, unstartedForwardOperationIds: [], abortResultItemRefs: [],
    transientAbsenceEvidenceRef: absence.ref, projectionClosureEvidenceRef: closed.ref, gitIndexUnchangedEvidenceRef: git.ref, observedAt: at(9) }, 'evidenceDigest');
  const projectionRef = put(projection), result = { schemaVersion: 1, runId, baseSourceRef: capturedRef, resultSourceRef: desiredRef,
    diffRef: plan.diffRef, verificationClosureRef: closureRef, verificationReceiptRefs: [], summaryRef: merged.summaryRef,
    deliveryTerminalProjectionEvidenceRef: projectionRef, createdAt: at(10) };
  const spec = { schemaVersion: 1, operation: 'delivery', objectiveRef: ref('objective'), admittedContextRef: ref('admitted'),
    baseWorkspaceManifestRef: capturedRef, assemblyRef, policyRef };
  const publicationCP = cp(withPath ? deliveryPublicationTerminalCheckpointId(runId, planRef) : deliveryPublicationCheckpointId(runId, planRef),
    withPath ? 5 : 2, rawItems.length, journal.length, 10);
  if (!withPath) checkpoints.push({ ...publicationCP, id: verificationCheckpointId(runId, candidate.itemId, closureRef) });
  checkpoints.push(publicationCP);
  const cursor = encodeControlCheckpointCursor(runId, { createdAt: publicationCP.createdAt, checkpointId: publicationCP.id });
  const cut: any = { method: 'run.get', snapshot: { schemaVersion: 1, operation: 'delivery', latestRunItemSeq: rawItems.length, run: {
    id: runId, sessionId: 'session', specRef: put(spec), status: 'succeeded', terminalReason: 'verified', nextStep: null,
    revision: withPath ? 7 : 4, leaseEpoch: withPath ? 1 : 0, latestCheckpointId: publicationCP.id, budgetReserved: zero,
    budgetConsumed: withPath ? one : zero, repairCount: 0, cancelRequested: false, createdAt: at(), updatedAt: at(10),
    deadlineAt: '2026-10-18T00:05:00.000Z', resultRef: put(result) } }, items: rows(), journal, checkpoints,
    highWaterItemSeq: rawItems.length, highWaterJournalSeq: journal.length, highWaterCheckpointCursor: cursor,
    nextItemSeq: rawItems.length, nextJournalSeq: journal.length, nextCheckpointCursor: cursor };
  mutations.cut?.(cut);
  return { cut, owners: [owner], objects, planRef, projectionRef, publicationWorkerRetirement,
    input: { cut, readRetainedArtifact: async (ref: string) => { const bytes = objects.get(ref); assert.ok(bytes, 'fixture reference must exist'); return Buffer.from(bytes); },
      readOwnerHistory: async () => [owner] } };
}

test('publication data requires the original complete successful public cut before artifact or owner reads', async () => {
  let reads = 0;
  for (const cut of [{}, { method: 'run.get', snapshot: { operation: 'delivery', run: { status: 'failed' } } }]) {
    await assert.rejects(assertInstalledDeliveryPublication({ cut,
      readRetainedArtifact: async () => { reads++; throw new Error('untrusted private detail'); },
      readOwnerHistory: async () => { reads++; return []; } }),
    error => error instanceof Error && error.message === 'installed Delivery publication graph refused');
  }
  assert.equal(reads, 0);
});

test('the complete no-op retained projection and one-path publication data are traversable without claiming native qualification', async () => {
  for (const withPath of [false, true]) {
    const data = graph(withPath), result = await assertInstalledDeliveryPublication(data.input);
    assert.deepEqual(result, { planRef: data.planRef, projectionRef: data.projectionRef,
      publishClaims: withPath ? 1 : 0, progressCount: withPath ? 1 : 0, receiptCount: withPath ? 1 : 0,
      slotObservationCount: withPath ? 2 : 0, arenaRetirementCount: withPath ? 1 : 0,
      publicationWorkerRetirement: data.publicationWorkerRetirement });
  }
});

test('a separately valid retired-arena descriptor cannot replace the original claim birth', async () => {
  const data = graph(true, { proof(kind, value) { if (kind === 'arena_retirement') value.arenaIdentity = { ...value.arenaIdentity, fileId: '900' }; } });
  // The old shallow assertion only decoded this kind. Its shape and digest
  // really remain valid; the refusal below comes from the original-birth edge.
  const arena = [...data.objects.values()].map(bytes => { try { return JSON.parse(bytes.toString()); } catch { return null; } })
    .find(value => value?.kind === 'arena_retirement');
  assert.equal(decodePublicationProof(arena).kind, 'arena_retirement');
  await assert.rejects(assertInstalledDeliveryPublication(data.input), /publication graph refused/u);
});

test('publication rejects rehashed substitutions of claim, child grant, progress, cleanup barrier, receipt and terminal graph', async () => {
  const mutations: Mutations[] = [
    { birth: value => { value.dispatchId = 'different-permanent-dispatch'; } },
    { birth: value => { value.stateRootIdentityDigest = canonicalSha256('another root digest'); } },
    { birth: value => { value.observedAt = at(3); } },
    { claim: value => { value.stateOwnerEpoch = 2; } },
    { claim: value => { value.target = canonicalSha256('another path target'); } },
    { claim: value => { value.leaseEpoch = 2; } },
    { claim: value => { value.evidenceDigest = canonicalSha256('another birth'); } },
    { progress: value => { value.preservedPreimageRef = canonicalSha256('unrelated bytes'); } },
    { progress: value => { value.beforeObservationRef = value.destinationEvidenceRef; } },
    { handoff: value => { value.dispatchId = 'different-permanent-dispatch'; } },
    { handoff: value => { value.claimJournalSeq = 1; } },
    { handoff: value => { value.receiptDigest = canonicalSha256('different receipt'); } },
    { handoff: value => { value.retirement.slotObservationRefs = [...value.retirement.slotObservationRefs].reverse(); } },
    { handoff: value => { value.generationResources.generationRef = canonicalSha256('foreign generation'); } },
    { handoff: value => { value.createdAt = at(6); } },
    { snapshot: value => { value.checkpointId = 'foreign checkpoint'; } },
    { snapshot: value => { value.workspaceStateDigest = canonicalSha256('foreign state'); } },
    { snapshot: value => { value.observedAt = at(8); } },
    { snapshot: value => { value.purpose = 'materialized_from_checkpoint'; delete value.quiescenceEvidenceRef; } },
    { proof: (kind, value) => { if (kind === 'terminal_receipt') value.opId = 'different-operation'; } },
    { proof: (kind, value) => { if (kind === 'terminal_receipt') value.parentIdentityBeforeDigest = canonicalSha256('foreign parent'); } },
    { proof: (kind, value) => { if (kind === 'terminal_receipt') value.before = { ...value.before, entryLinkCount: 2 }; } },
    { proof: (kind, value) => { if (kind === 'path_observation' && value.observation.location.kind === 'publication_arena')
      value.observation = { ...value.observation, parentFileId: 'foreign-arena' }; } },
    { proof: (kind, value) => { if (kind === 'path_observation' && value.observedAt === at(5)) value.observedAt = at(3); } },
    { proof: (kind, value) => { if (kind === 'arena_retirement') value.retirementObservation = { kind: 'darwin_unlinked',
      heldPathUnchanged: true, parentPathUnchanged: true, observedLinkCount: 2 }; } },
    { proof: (kind, value) => { if (kind === 'transient_absence') value.observationRefs = [...value.observationRefs].reverse(); } },
    { proof: (kind, value) => { if (kind === 'projection_closure') value.forwardResultItemRefs = []; } },
    { proof: (kind, value) => { if (kind === 'git_index_unchanged') value.observedAt = at(11); } },
    { result: value => { value.retirement.slotObservationRefs = [...value.retirement.slotObservationRefs].reverse(); } },
    { cut: value => { value.journal = value.journal.filter((row: any) => row.phase !== 'dispatch_claimed'); value.highWaterJournalSeq--; value.nextJournalSeq--; } },
    { cut: value => { const cp = value.checkpoints.find((row: any) => row.runItemSeq === 5); cp.journalSeq = 1; } },
    { cut: value => { const cp = value.checkpoints.find((row: any) => row.runItemSeq === 5); cp.createdAt = at(6); } },
  ];
  for (const mutate of mutations) {
    const data = graph(true, mutate);
    await assert.rejects(assertInstalledDeliveryPublication(data.input), /publication graph refused/u);
  }
});

test('no-op still requires its real owner-bound fresh complete root projection and same-transaction verification Checkpoint', async () => {
  for (const mutate of [
    { proof: (kind: string, value: any) => { if (kind === 'projection_closure') value.inspectorIdentityDigest = canonicalSha256('foreign inspector'); } },
    { cut: (value: any) => { value.checkpoints[0].basedOnRunRevision--; } },
    { cut: (value: any) => { value.checkpoints[1].createdAt = '2026-10-18T00:00:06.000Z'; } },
    { cut: (value: any) => { value.snapshot.run.status = 'failed'; } },
  ]) await assert.rejects(assertInstalledDeliveryPublication(graph(false, mutate).input), /publication graph refused/u);
  const original = graph(false);
  await assert.rejects(assertInstalledDeliveryPublication({ ...original.input, readOwnerHistory: async () => [] }), /publication graph refused/u);
  const owner = structuredClone(original.owners[0])!; owner.acquiredAt = at(11); owner.rowDigest = digestOmitting(owner, 'rowDigest');
  await assert.rejects(assertInstalledDeliveryPublication({ ...original.input, readOwnerHistory: async () => [owner] }), /publication graph refused/u);
  await assert.rejects(assertInstalledDeliveryPublication(graph(false, {}, 'not the desired source\n').input), /publication graph refused/u);
});

test('retained reads require complete canonical bytes, bounded objects and stable caller data', async () => {
  const data = graph(true), before = canonicalJsonBytes(data.cut);
  await assertInstalledDeliveryPublication(data.input); assert.ok(canonicalJsonBytes(data.cut).equals(before));
  const badReaders = [async () => Buffer.from('{}'), async () => Buffer.alloc(1_048_577), async () => Buffer.from([0xff])];
  for (const readRetainedArtifact of badReaders)
    await assert.rejects(assertInstalledDeliveryPublication({ ...data.input, readRetainedArtifact }), /publication graph refused/u);
  let getterRuns = 0;
  const getterCut = { ...data.cut, get journal() { getterRuns++; return data.cut.journal; } };
  await assert.rejects(assertInstalledDeliveryPublication({ ...data.input, cut: getterCut }), /publication graph refused/u);
  assert.equal(getterRuns, 0);
});

test('one retained walk snapshots the actual cut before asynchronous I/O', async () => {
  const data = graph(true), expected = await assertInstalledDeliveryPublication(data.input);
  let first = true;
  const result = await assertInstalledDeliveryPublication({ ...data.input, readRetainedArtifact: async ref => {
    if (first) { first = false; data.cut.snapshot.run.resultRef = canonicalSha256('changed caller result'); }
    return data.input.readRetainedArtifact(ref);
  } });
  assert.deepEqual(result, expected);
});
