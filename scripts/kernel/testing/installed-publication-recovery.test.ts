// Inert regression data only; no actual installed Run or native evidence is created.
import test from 'node:test';
import { readInstalledPublicationCrashBirth, assertInstalledPublicationCleanupRecovery } from './installed-publication-recovery.js';
import * as recovery from './installed-publication-recovery.js';
import { addCanonicalDuration } from '../../../src/kernel/identity.js';
import { publicationEnvelopeLocations } from '../../../src/state/delivery-publication-progress.js';
import assert from 'node:assert/strict';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { encodeControlCheckpointCursor } from '../../../src/kernel/control-wire.js';
import { digestOmitting, identityHash, sha256Bytes } from '../../../src/kernel/identity.js';
import { decodePublicationProof, publicationArenaId, publicationDirectoryIdentityDigest,
  publicationLateObservationCheckpointId, publicationLateObservationItemId } from '../../../src/kernel/publication.js';
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

function normalGraph(withPath = false, mutations: Mutations = {}, capturedText = 'before\n') {
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
  const diff = seal({ schemaVersion: 1, format: 'cliq-workspace-diff-v1', baseSourceRef: capturedRef, resultSourceRef: desiredRef,
    operations: withPath ? [{ path: 'example.txt', kind: 'modify', before: entries(beforeBlob).entries[0], after: entries(afterBlob).entries[0] }] : [] }, 'diffDigest');
  const topology = seal({ schemaVersion: 1, format: 'cliq-delivery-capture-topology-v1', inspectionId: identityHash('original-apply-inspection'),
    capturedWorkspaceRef: capturedRef, workspaceIdentityRef: workspaceRef, workspaceIdentityDigest: workspace.identityDigest,
    rootIdentity: capturedParent, directories: [], fileModes: [{ path: 'example.txt', mode: 0o644 }], capturedAt: at() }, 'topologyDigest');
  const operation = { index: 0, operationId: identityHash('inert-regular-replace'), path: 'example.txt',
    parent: { kind: 'existing_directory', expectedIdentityDigest: capturedParent.identityDigest }, kind: 'replace',
    expected: { kind: 'file', mode: 0o644, digest: beforeBlob }, desired: { kind: 'file', mode: 0o644, digest: afterBlob },
    stagingName: 'desired', stagingExpected: { kind: 'absent' }, quarantineName: 'preimage', quarantineExpected: { kind: 'absent' } };
  const plan = { schemaVersion: 1, deliveryRunId: runId, sourceRunResultRef: sourceResultRef,
    sourceBaseRef: ref('B'), sourceDesiredRef: desiredRef, capturedWorkspaceRef: capturedRef,
    captureTopologyRef: put(topology), captureTopologyDigest: topology.topologyDigest, desiredSourceRef: desiredRef, diffRef: put(diff),
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
    sourceDigest: desired.manifestDigest, diffDigest: diff.diffDigest, createdAt: at() };
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

function claimCut(data: ReturnType<typeof normalGraph>) {
  const cut = structuredClone(data.cut), run = cut.snapshot.run;
  const read = (ref: string) => JSON.parse(data.objects.get(ref)!.toString());
  cut.journal = cut.journal.slice(0, 2);
  cut.items = cut.items.filter((row: any) => { const item = read(row.payloadRef); return item.kind !== 'publication_path_result' &&
    !(item.kind === 'publication_path_progress' && item.state === 'received_handoff'); });
  const progress = cut.items.find((row: any) => read(row.payloadRef).state === 'desired_committed_cleanup_pending');
  cut.checkpoints = cut.checkpoints.filter((row: any) => row.runItemSeq <= progress.itemSeq);
  const cp = cut.checkpoints.at(-1)!;
  run.status = 'running'; delete run.terminalReason; delete run.resultRef; run.nextStep = 'delivery';
  run.activeWorkerLaunchId = 'original-M-worker'; run.frontierRef = read(cut.journal[0].requestRef).frontierRef;
  run.latestCheckpointId = cp.id; run.revision = 4; run.budgetReserved = one; run.budgetConsumed = zero; run.updatedAt = cp.createdAt;
  cut.snapshot.latestRunItemSeq = cut.items.length; cut.highWaterItemSeq = cut.nextItemSeq = cut.items.length;
  cut.highWaterJournalSeq = cut.nextJournalSeq = 2;
  cut.highWaterCheckpointCursor = cut.nextCheckpointCursor = encodeControlCheckpointCursor(run.id, { createdAt: cp.createdAt, checkpointId: cp.id });
  return cut;
}

test('the actual public claim reader arms data only before any original result or handoff', async () => {
  const data = normalGraph(true), cut = claimCut(data), birth = await readInstalledPublicationCrashBirth({ ...data.input, cut });
  assert.equal(birth.arenaId, JSON.parse(data.objects.get(cut.journal[1].evidenceRef)!.toString()).arenaId);
  await assert.rejects(readInstalledPublicationCrashBirth(data.input));
  await assert.rejects(readInstalledPublicationCrashBirth({ ...data.input, cut: { ...cut, journal: [...cut.journal, data.cut.journal[2]],
    highWaterJournalSeq: 3, nextJournalSeq: 3 } }));
});

function recoveryGraph(change: (parts: Record<string, any>) => void = () => undefined) {
  const data = normalGraph(true), { objects } = data, cut = structuredClone(data.cut), run = cut.snapshot.run;
  const object = (ref: string) => JSON.parse(objects.get(ref)!.toString()), put = (value: unknown) => {
    const bytes = canonicalJsonBytes(value), ref = sha256Bytes(bytes); objects.set(ref, bytes); return ref;
  };
  const raw = cut.items.map((row: any) => object(row.payloadRef)), claim = cut.journal[1], prepared = cut.journal[0];
  const birth = object(claim.evidenceRef), plan = object(data.planRef), operation = plan.forwardOperations[0];
  const progress = raw.find((item: any) => item.state === 'desired_committed_cleanup_pending');
  const handoff = raw.find((item: any) => item.state === 'received_handoff'), result = raw.find((item: any) => item.kind === 'publication_path_result');
  const originalReceipt = object(result.receiptRef), previous = data.owners[0]!;
  const newProcess = seal({ ...object(previous.processIdentityRef), pid: 1001, processStartToken: 'linux-proc-start-ticks:9999', observedAt: at(6) }, 'identityDigest');
  const core = { ownerEpoch: 2, supervisorInstanceId: 'successor-supervisor', runtimeBundleRef: previous.runtimeBundleRef,
    runtimeBundleManifestDigest: previous.runtimeBundleManifestDigest, processIdentityRef: put(newProcess), processIdentityDigest: newProcess.identityDigest,
    stateLockIdentityRef: previous.stateLockIdentityRef, stateLockIdentityDigest: previous.stateLockIdentityDigest,
    instanceNonceDigest: canonicalSha256('successor nonce'), acquiredAt: at(6) };
  const transition = seal({ schemaVersion: 1, format: 'cliq-state-owner-transition-evidence-v1', kind: 'superseded_after_owner_death',
    priorOwnerEpoch: 1, priorSupervisorInstanceId: previous.supervisorInstanceId, priorProcessIdentityRef: previous.processIdentityRef,
    priorProcessIdentityDigest: previous.processIdentityDigest, stateLockIdentityRef: previous.stateLockIdentityRef,
    stateLockIdentityDigest: previous.stateLockIdentityDigest, priorProcessObservation: 'absent_or_start_token_mismatch',
    successorOwnerEpoch: 2, successorSupervisorInstanceId: core.supervisorInstanceId, successorRuntimeBundleRef: core.runtimeBundleRef,
    successorRuntimeBundleManifestDigest: core.runtimeBundleManifestDigest, successorProcessIdentityRef: core.processIdentityRef,
    successorProcessIdentityDigest: core.processIdentityDigest, successorInstanceNonceDigest: core.instanceNonceDigest, observedAt: core.acquiredAt }, 'evidenceDigest');
  const owner = seal({ ...previous, state: 'terminal', rowVersion: 2, releasedAt: at(6), terminalReason: 'superseded_after_owner_death',
    transitionEvidenceRef: put(transition), transitionEvidenceDigest: transition.evidenceDigest }, 'rowDigest');
  const acquisition = seal({ schemaVersion: 1, format: 'cliq-state-owner-acquisition-evidence-v1', ...core, kind: 'takeover_after_owner_death',
    priorOwnerEpoch: 1, priorTerminalRowDigest: owner.rowDigest, priorTransitionEvidenceRef: owner.transitionEvidenceRef,
    priorTransitionEvidenceDigest: owner.transitionEvidenceDigest, priorTerminalReason: owner.terminalReason }, 'evidenceDigest');
  const successor = seal({ ...previous, ...core, acquisitionEvidenceRef: put(acquisition), acquisitionEvidenceDigest: acquisition.evidenceDigest }, 'rowDigest');
  const inspector = supervisorInspectorIdentity(successor), inspectorRef = put(inspector);
  const origin = seal({ schemaVersion: 1, format: 'cliq-publication-recovery-origin-v1', deliveryRunId: run.id,
    deliveryPlanRef: data.planRef, opId: claim.opId, attempt: 0, dispatchId: claim.dispatchId, claimJournalSeq: claim.seq,
    arenaBirthRef: claim.evidenceRef, arenaBirthDigest: birth.birthDigest, inspectorIdentityRef: inspectorRef, inspectorIdentityDigest: inspector.identityDigest,
    ownerDeathAcquisitionEvidenceRef: successor.acquisitionEvidenceRef, ownerDeathAcquisitionEvidenceDigest: acquisition.evidenceDigest, observedAt: at(9) }, 'originDigest');
  const association = { recoveryOriginRef: put(origin), recoveryOriginDigest: origin.originDigest };
  const proof = (kind: string, fields: Record<string, unknown>, ms: number) => seal({ schemaVersion: 1, format: 'cliq-publication-proof-v1',
    deliveryRunId: run.id, deliveryPlanRef: data.planRef, workspaceIdentityRef: birth.workspaceIdentityRef, workspaceIdentityDigest: birth.workspaceIdentityDigest,
    inspectorIdentityRef: inspectorRef, inspectorIdentityDigest: inspector.identityDigest, ...association, kind, ...fields, observedAt: at(ms) }, 'proofDigest');
  const desired = proof('path_observation', { observation: originalReceipt.after }, 10), namespace = proof('arena_namespace_absence', {
    arenaId: birth.arenaId, stateRootIdentityRef: birth.stateRootIdentityRef, stateRootIdentityDigest: birth.stateRootIdentityDigest,
    registeredArenaIdentity: birth.arenaIdentity, namespaceParentIdentity: birth.parentIdentity,
    coveredLocations: publicationEnvelopeLocations({ birth, operation }), destinationObservationRef: put(desired),
    arenaAbsent: true, arenaParentFsyncCompleted: true, workspaceParentFsyncCompleted: true, namespaceHandlesJoined: true }, 11);
  const { transientFinalObservations: _oldSlots, ...receiptCore } = originalReceipt;
  const receipt = seal({ ...receiptCore, ...association, inspectorIdentityRef: inspectorRef, inspectorIdentityDigest: inspector.identityDigest,
    namespaceRetirementEvidenceRef: put(namespace), observedAt: at(12) }, 'proofDigest');
  const ambiguity = proof('path_ambiguity', { sequence: 'forward', operationIndex: 0, operationId: operation.operationId, opId: claim.opId,
    attempt: 0, launchDispatchId: claim.dispatchId, failure: 'transient_state_ambiguous', lastKnownObservationRefs: [progress.destinationEvidenceRef] }, 7);
  // Original UNKNOWN precedes the subsequent readonly probe; it has its own
  // genuine producer provenance, not the new probe's later origin association.
  delete ambiguity.recoveryOriginRef; delete ambiguity.recoveryOriginDigest; ambiguity.proofDigest = digestOmitting(ambiguity, 'proofDigest');
  const budget = seal({ schemaVersion: 1, format: 'cliq-budget-settlement-v1', runId: run.id, opId: claim.opId, attempt: 0,
    preparedJournalSeq: 1, terminalJournalSeq: 3, terminalPhase: 'unknown', reserved: one, consumed: one, released: one,
    budgetConsumedBefore: zero, budgetConsumedAfter: one, budgetReservedBefore: one, budgetReservedAfter: zero, settledAt: at(7) }, 'settlementDigest');
  const unknown = { ...claim, seq: 3, phase: 'unknown', timestamp: at(7), budgetDelta: one, evidenceRef: put(ambiguity),
    evidenceDigest: ambiguity.proofDigest, budgetSettlementRef: put(budget) };
  const subject = { kind: 'publication_path', deliveryPlanRef: data.planRef, pathOperationId: operation.operationId, attempt: 0 };
  const pending = { schemaVersion: 1, kind: 'reconciliation', runId: run.id, createdFromRevision: 7, createdAt: at(8),
    frontierRef: object(prepared.requestRef).frontierRef, subject, probeState: { phase: 'automatic_pending', automaticProbeCount: 0, userProbeCount: 0, nextProbeAt: at(8) } };
  const target = { schemaVersion: 1, format: 'cliq-publication-inspection-target-v1', runId: run.id, subject,
    preparedJournalSeq: 1, claimJournalSeq: 2, unknownJournalSeq: 3, unknownEvidenceRef: unknown.evidenceRef,
    unknownBudgetSettlementRef: unknown.budgetSettlementRef, progress: { itemRef: put(progress), checkpointId: publicationProgressCheckpointId(run.id, claim.opId, 0) } };
  const nonce = canonicalSha256('fixed inert nonce'), dispatch = seal({ schemaVersion: 1, format: 'cliq-reconciliation-probe-dispatch-v1',
    runId: run.id, reconciliationSubjectDigest: canonicalSha256(subject), probeKind: 'automatic', probeOrdinal: 1, probeNonceDigest: nonce,
    probeStartedAt: at(9), probeDeadlineAt: addCanonicalDuration(at(9), 30000), owningSupervisorInstanceId: successor.supervisorInstanceId,
    subjectKind: 'publication', inspectorTaskId: identityHash(run.id, canonicalSha256(subject), 'automatic', 1, nonce),
    inspectionTargetDigest: put(target), previousWaitingSubjectRef: put(pending) }, 'dispatchDigest'); put(dispatch);
  const wait = { ...pending, probeState: { phase: 'automatic_in_flight', automaticProbeCount: 1, userProbeCount: 0, dispatch } };
  const wrapper = seal({ schemaVersion: 1, format: 'cliq-reconciliation-probe-evidence-v1', runId: run.id,
    waitingSubjectRef: put(wait), waitingSubjectDigest: put(wait), probeKind: 'automatic', probeOrdinal: 1, probeNonceDigest: nonce,
    probeDispatchDigest: dispatch.dispatchDigest, probeStartedAt: dispatch.probeStartedAt, probeDeadlineAt: dispatch.probeDeadlineAt,
    inspectorIdentityRef: inspectorRef, inspectorIdentityDigest: inspector.identityDigest, observedAt: receipt.observedAt,
    outcome: 'subject_observation', subjectEvidenceKind: 'publication', subjectEvidenceRef: put(receipt), subjectEvidenceDigest: receipt.proofDigest }, 'evidenceDigest');
  const retirement = { kind: 'current_namespace', namespaceEvidenceRef: put(namespace) };
  Object.assign(handoff, { receiptRef: put(receipt), receiptDigest: receipt.proofDigest, retirement,
    reconciliationEvidenceRef: put(wrapper), reconciliationEvidenceDigest: wrapper.evidenceDigest, createdAt: at(13),
    generationResources: { kind: 'genuinely_retired_from_verified_checkpoint', workerLaunchId: 'original-M-worker', generationRef: canonicalSha256('M'),
      sourceCheckpointId: 'original-verified-checkpoint', quarantineEvidenceRef: canonicalSha256('quarantine'), retirementEvidenceRef: canonicalSha256('retired') } });
  const unknownResult = { ...result, outcome: 'unknown', evidenceRef: unknown.evidenceRef, createdAt: unknown.timestamp,
    itemId: publicationResultItemId(run.id, claim.opId, 0, unknown.evidenceRef) };
  delete unknownResult.receiptRef; delete unknownResult.retirement;
  Object.assign(result, { itemId: publicationResultItemId(run.id, claim.opId, 0, put(receipt)), evidenceRef: put(receipt), receiptRef: put(receipt),
    retirement, reconciliationEvidenceRef: put(wrapper), reconciliationEvidenceDigest: wrapper.evidenceDigest, createdAt: at(14) });
  const completed = { ...unknown, phase: 'completed', seq: 4, timestamp: at(15), budgetDelta: zero,
    evidenceRef: put(receipt), evidenceDigest: receipt.proofDigest, receiptRef: put(receipt) };
  change({ namespace, receipt, desired, origin, wrapper, result, completed, handoff, unknown, budget, owner, successor });
  // Rehash the altered leaf and all structural incoming edges. Regressions
  // below therefore exercise semantic rejection, not a stale content hash.
  origin.originDigest = digestOmitting(origin, 'originDigest');
  for (const value of [desired, namespace, receipt]) {
    value.recoveryOriginRef = put(origin); value.recoveryOriginDigest = origin.originDigest;
  }
  desired.proofDigest = digestOmitting(desired, 'proofDigest'); namespace.destinationObservationRef = put(desired);
  namespace.proofDigest = digestOmitting(namespace, 'proofDigest'); receipt.namespaceRetirementEvidenceRef = put(namespace);
  receipt.proofDigest = digestOmitting(receipt, 'proofDigest'); wrapper.subjectEvidenceRef = put(receipt);
  wrapper.subjectEvidenceDigest = receipt.proofDigest; wrapper.evidenceDigest = digestOmitting(wrapper, 'evidenceDigest');
  for (const value of [result, handoff]) {
    value.receiptRef = put(receipt); value.retirement = { kind: 'current_namespace', namespaceEvidenceRef: put(namespace) };
    value.reconciliationEvidenceRef = put(wrapper); value.reconciliationEvidenceDigest = wrapper.evidenceDigest;
  }
  result.evidenceRef = put(receipt); result.itemId = publicationResultItemId(run.id, claim.opId, 0, put(receipt));
  handoff.receiptDigest = receipt.proofDigest; completed.evidenceRef = completed.receiptRef = put(receipt); completed.evidenceDigest = receipt.proofDigest;
  const finalItems = raw.filter((item: any) => item.kind !== 'publication_path_result' && item.state !== 'received_handoff');
  finalItems.push(unknownResult, handoff, result);
  cut.items = finalItems.map((item: any, index: number) => ({ schemaVersion: 1, itemSeq: index + 1, itemId: item.itemId,
    payloadRef: put(item), payloadDigest: put(item), createdAt: item.createdAt }));
  cut.journal = [prepared, claim, unknown, completed]; const terminal = cut.checkpoints.at(-1)!;
  terminal.createdAt = completed.timestamp; terminal.journalSeq = 4; terminal.runItemSeq = finalItems.length;
  const manifest = object(terminal.contextManifestRef); manifest.throughItemSeq = finalItems.length;
  manifest.segments = finalItems.map((item: any, index: number) => ({ kind: 'excluded_control', fromItemSeq: index + 1, throughItemSeq: index + 1,
    sourceItemsDigest: contextSourceDigest([{ itemSeq: index + 1, itemRef: put(item), item }]) }));
  manifest.projectionDigest = digestOmitting(manifest, 'projectionDigest'); terminal.contextManifestRef = put(manifest);
  const finalProof = (kind: string, fields: Record<string, unknown>) => {
    const value = proof(kind, fields, 14); delete value.recoveryOriginRef; delete value.recoveryOriginDigest;
    return seal(value, 'proofDigest');
  };
  const path = finalProof('path_observation', { observation: receipt.after });
  const aggregate = finalProof('transient_absence', { transientLocations: publicationEnvelopeLocations({ birth, operation }),
    envelopeRetirements: [{ arenaId: birth.arenaId, retirement: result.retirement }] });
  const projectionCore = { selectedBranch: 'forward_finalize', observedSourceRef: plan.desiredSourceRef,
    forwardResultItemRefs: [put(result)], unstartedForwardOperationIds: [], abortResultItemRefs: [] };
  const finalProjectionProof = finalProof('projection_closure', { ...projectionCore, observedPathEvidenceRefs: [put(path)] });
  const git = finalProof('git_index_unchanged', { repositoryKind: 'non_git' });
  const projection = seal({ schemaVersion: 1, deliveryRunId: run.id, deliveryPlanRef: data.planRef, ...projectionCore,
    observedPathStates: [{ path: operation.path, state: operation.desired, evidenceRef: put(path) }], transientAbsenceEvidenceRef: put(aggregate),
    projectionClosureEvidenceRef: put(finalProjectionProof), gitIndexUnchangedEvidenceRef: put(git), observedAt: at(14) }, 'evidenceDigest');
  const finalResult = object(run.resultRef); finalResult.deliveryTerminalProjectionEvidenceRef = put(projection); finalResult.createdAt = at(14);
  run.resultRef = put(finalResult);
  const finalCheckpoint = { ...terminal, id: identityHash('cliq-run-result-checkpoint-v1', run.id, 'candidate', run.resultRef),
    basedOnRunRevision: terminal.basedOnRunRevision + 1 };
  cut.checkpoints.push(finalCheckpoint); run.latestCheckpointId = finalCheckpoint.id;
  run.updatedAt = completed.timestamp; run.revision = finalCheckpoint.basedOnRunRevision + 1; cut.snapshot.latestRunItemSeq = finalItems.length;
  cut.highWaterItemSeq = cut.nextItemSeq = finalItems.length; cut.highWaterJournalSeq = cut.nextJournalSeq = 4;
  const last = [...cut.checkpoints].sort((a: any, b: any) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id)).at(-1)!;
  cut.highWaterCheckpointCursor = cut.nextCheckpointCursor = encodeControlCheckpointCursor(run.id, { createdAt: last.createdAt, checkpointId: last.id });
  return { input: { cut, originalBirth: birth, expectedFiles: [{ path: 'example.txt', text: 'after\n' }], sourceResultRef: plan.sourceRunResultRef,
    readRetainedArtifact: data.input.readRetainedArtifact, readOwnerHistory: async () => [owner, successor] },
    objects, put, parts: { namespace, receipt, desired, origin, wrapper, result, completed, handoff, unknown, budget, owner, successor } };
}

test('the recovered-data reader follows the same UNKNOWN claim and current namespace without charging twice', async () => {
  const data = recoveryGraph(), result = await assertInstalledPublicationCleanupRecovery(data.input);
  assert.equal(result.originalDurableReceiptAssociationAbsent, true); assert.equal(result.redispatchCount, 0);
  assert.equal(result.resolutionBudgetDeltaZero, true); assert.equal(result.originalOwnerEpoch, 1); assert.equal(result.successorOwnerEpoch, 2);
  assert.equal(result.probeDeadlineAt, data.parts.wrapper.probeDeadlineAt);
  assert.match(result.retirementDiagnosticKey, /^[0-9a-f]{64}$/u);
  assert.equal(Object.hasOwn(result, 'qualified'), false); assert.equal(Object.hasOwn(result, 'nativeObservation'), false);
});

test('a receipt already submitted by the original owner is not this cleanup-crash cut', async () => {
  const data = normalGraph(true), birth = JSON.parse(data.objects.get(data.cut.journal[1].evidenceRef)!.toString());
  await assert.rejects(assertInstalledPublicationCleanupRecovery({ ...data.input, originalBirth: birth,
    expectedFiles: [{ path: 'example.txt', text: 'after\n' }], sourceResultRef: canonicalSha256('original verified source result') }));
});

test('rehashed foreign-domain, provenance and missing-resource facts cannot qualify current namespace recovery', async () => {
  for (const change of [
    (p: Record<string, any>) => { p.namespace.stateRootIdentityRef = canonicalSha256('another StateRoot'); },
    (p: Record<string, any>) => { p.origin.inspectorIdentityRef = canonicalSha256('another inspector'); },
    (p: Record<string, any>) => { p.receipt.sequence = 'abort'; },
    (p: Record<string, any>) => { p.receipt.deliveryRunId = 'another-run'; },
    (p: Record<string, any>) => { p.namespace.namespaceHandlesJoined = false; },
    (p: Record<string, any>) => { p.namespace.workspaceParentFsyncCompleted = false; },
    (p: Record<string, any>) => { p.desired.observation.entryFileId = 'replacement-inode'; },
    (p: Record<string, any>) => { p.completed.budgetDelta = one; },
    (p: Record<string, any>) => { p.result.createdAt = at(16); },
  ]) {
    const data = recoveryGraph(change);
    await assert.rejects(assertInstalledPublicationCleanupRecovery(data.input));
  }
});

test('recovery also requires the complete terminal projection, exact result bytes and separate atomic final Checkpoint', async () => {
  const read = (data: ReturnType<typeof recoveryGraph>, ref: string) => JSON.parse(data.objects.get(ref)!.toString());
  for (const change of [
    (p: Record<string, any>) => { p.aggregate.envelopeRetirements[0].retirement.namespaceEvidenceRef = canonicalSha256('unrelated namespace'); },
    (p: Record<string, any>) => { p.projection.forwardResultItemRefs = []; },
    (p: Record<string, any>) => { p.projection.observedPathStates[0].path = 'another.txt'; },
    (p: Record<string, any>) => { p.final.resultSourceRef = canonicalSha256('different full tree'); },
    (p: Record<string, any>) => { p.finalCheckpoint.contextManifestRef = canonicalSha256('another context'); },
    (p: Record<string, any>) => { p.finalCheckpoint.basedOnRunRevision++; },
  ]) {
    const data = recoveryGraph(), run = data.input.cut.snapshot.run, final = read(data, run.resultRef),
      projection = read(data, final.deliveryTerminalProjectionEvidenceRef), aggregate = read(data, projection.transientAbsenceEvidenceRef),
      finalCheckpoint = data.input.cut.checkpoints.find((row: any) => row.id === run.latestCheckpointId);
    change({ final, projection, aggregate, finalCheckpoint });
    aggregate.proofDigest = digestOmitting(aggregate, 'proofDigest'); projection.transientAbsenceEvidenceRef = data.put(aggregate);
    projection.evidenceDigest = digestOmitting(projection, 'evidenceDigest'); final.deliveryTerminalProjectionEvidenceRef = data.put(projection);
    run.resultRef = data.put(final); finalCheckpoint.id = identityHash('cliq-run-result-checkpoint-v1', run.id, 'candidate', run.resultRef);
    run.latestCheckpointId = finalCheckpoint.id;
    await assert.rejects(assertInstalledPublicationCleanupRecovery(data.input));
  }
  const wrongBytes = recoveryGraph();
  await assert.rejects(assertInstalledPublicationCleanupRecovery({ ...wrongBytes.input, expectedFiles: [{ path: 'example.txt', text: 'not the complete expected bytes' }] }));
  const noFinalCheckpoint = recoveryGraph(); noFinalCheckpoint.input.cut.checkpoints.pop();
  await assert.rejects(assertInstalledPublicationCleanupRecovery(noFinalCheckpoint.input));
});

function lateAuditGraph(change: (parts: Record<string, any>) => void = () => undefined) {
  const data = recoveryGraph(), { objects, put, parts } = data;
  const object = (ref: string) => JSON.parse(objects.get(ref)!.toString());
  const beforeCut = structuredClone(data.input.cut), beforeRun = beforeCut.snapshot.run;
  const wait = object(parts.wrapper.waitingSubjectRef), dispatch = wait.probeState.dispatch;
  const completedAt = addCanonicalDuration(dispatch.probeDeadlineAt, 2), createdAt = addCanonicalDuration(completedAt, 1);
  const desired = { ...parts.desired, observedAt: addCanonicalDuration(dispatch.probeStartedAt, 29999) };
  desired.proofDigest = digestOmitting(desired, 'proofDigest');
  const namespace = { ...parts.namespace, destinationObservationRef: put(desired), observedAt: dispatch.probeDeadlineAt };
  namespace.proofDigest = digestOmitting(namespace, 'proofDigest');
  const receipt = { ...parts.receipt, namespaceRetirementEvidenceRef: put(namespace), observedAt: completedAt };
  receipt.proofDigest = digestOmitting(receipt, 'proofDigest');
  const late: any = { schemaVersion: 1, itemId: '', runId: beforeRun.id, kind: 'publication_late_observation',
    deliveryPlanRef: parts.result.deliveryPlanRef, sequence: 'forward', operationIndex: 0, operationId: parts.result.operationId,
    opId: parts.result.opId, attempt: 0, dispatchId: parts.handoff.dispatchId, claimJournalSeq: parts.handoff.claimJournalSeq,
    probeWaitingSubjectRef: put(wait), probeDispatchDigest: dispatch.dispatchDigest,
    evidenceRef: put(receipt), evidenceDigest: receipt.proofDigest, disposition: 'received', completedAt,
    retirement: { kind: 'current_namespace', namespaceEvidenceRef: put(namespace) }, createdAt };
  beforeCut.journal.pop();
  beforeCut.items = beforeCut.items.filter((row: any) => { const value = object(row.payloadRef); return value.outcome !== 'completed' && value.state !== 'received_handoff'; });
  const previous = { ...beforeCut.checkpoints.find((row: any) => row.id === publicationProgressCheckpointId(beforeRun.id, late.opId, 0)),
    id: identityHash('inert-original-in-flight-checkpoint'), basedOnRunRevision: 7, runItemSeq: beforeCut.items.length,
    journalSeq: 3, createdAt: dispatch.probeStartedAt };
  const beforeContext = object(previous.contextManifestRef);
  beforeContext.throughItemSeq = beforeCut.items.length;
  beforeContext.segments = beforeCut.items.map((row: any) => ({ kind: 'excluded_control', fromItemSeq: row.itemSeq,
    throughItemSeq: row.itemSeq, sourceItemsDigest: contextSourceDigest([{ itemSeq: row.itemSeq, itemRef: row.payloadRef, item: object(row.payloadRef) }]) }));
  beforeContext.projectionDigest = digestOmitting(beforeContext, 'projectionDigest'); previous.contextManifestRef = put(beforeContext);
  beforeCut.checkpoints = beforeCut.checkpoints.filter((row: any) => row.runItemSeq < previous.runItemSeq);
  beforeCut.checkpoints.push(previous);
  Object.assign(beforeRun, { status: 'waiting', waitingReason: 'reconciliation', waitingOnRef: put(wait), nextStep: 'delivery',
    frontierRef: wait.frontierRef, latestCheckpointId: previous.id, revision: 8, updatedAt: previous.createdAt });
  delete beforeRun.resultRef; delete beforeRun.terminalReason;
  beforeCut.snapshot.latestRunItemSeq = beforeCut.highWaterItemSeq = beforeCut.nextItemSeq = beforeCut.items.length;
  beforeCut.highWaterJournalSeq = beforeCut.nextJournalSeq = 3;
  beforeCut.highWaterCheckpointCursor = beforeCut.nextCheckpointCursor = encodeControlCheckpointCursor(beforeRun.id,
    { createdAt: previous.createdAt, checkpointId: previous.id });
  change({ beforeCut, late, desired, namespace, receipt, wait, dispatch, previous });
  desired.proofDigest = digestOmitting(desired, 'proofDigest'); namespace.destinationObservationRef = put(desired);
  namespace.proofDigest = digestOmitting(namespace, 'proofDigest'); receipt.namespaceRetirementEvidenceRef = put(namespace);
  receipt.proofDigest = digestOmitting(receipt, 'proofDigest'); late.evidenceRef = put(receipt); late.evidenceDigest = receipt.proofDigest;
  late.retirement.namespaceEvidenceRef = put(namespace);
  late.itemId = publicationLateObservationItemId(beforeRun.id, late.opId, 0, late.probeDispatchDigest, late.evidenceRef);
  const auditCut = structuredClone(beforeCut), row = { schemaVersion: 1, itemId: late.itemId, itemSeq: auditCut.items.length + 1,
    payloadRef: put(late), payloadDigest: put(late), createdAt: late.createdAt };
  auditCut.items.push(row);
  const context = structuredClone(beforeContext);
  context.throughItemSeq++; context.segments.push({ kind: 'excluded_control', fromItemSeq: row.itemSeq, throughItemSeq: row.itemSeq,
    sourceItemsDigest: contextSourceDigest([{ itemSeq: row.itemSeq, itemRef: row.payloadRef, item: late }]) });
  context.projectionDigest = digestOmitting(context, 'projectionDigest');
  const checkpoint = { ...previous, id: publicationLateObservationCheckpointId(beforeRun.id, late.opId, 0, late.probeDispatchDigest, late.evidenceRef),
    basedOnRunRevision: beforeRun.revision, runItemSeq: row.itemSeq, contextManifestRef: put(context), createdAt: late.createdAt };
  auditCut.checkpoints.push(checkpoint);
  Object.assign(auditCut.snapshot.run, { latestCheckpointId: checkpoint.id, revision: beforeRun.revision + 1, updatedAt: checkpoint.createdAt });
  auditCut.snapshot.latestRunItemSeq = auditCut.highWaterItemSeq = auditCut.nextItemSeq = row.itemSeq;
  auditCut.highWaterCheckpointCursor = auditCut.nextCheckpointCursor = encodeControlCheckpointCursor(beforeRun.id,
    { createdAt: checkpoint.createdAt, checkpointId: checkpoint.id });
  return { ...data, beforeCut, auditCut, late, receipt, namespace, desired,
    lateInput: { originalBirth: data.input.originalBirth, beforeCut, auditCut,
      readRetainedArtifact: data.input.readRetainedArtifact, readOwnerHistory: data.input.readOwnerHistory } };
}

test('retained late audit requires the actual before/after public cuts and never resolves its original UNKNOWN wait', async () => {
  const data = lateAuditGraph();
  const result = await (recovery as any).assertInstalledPublicationLateAudit(data.lateInput);
  assert.equal(result.diagnosticOnly, true); assert.equal(result.expiredProbeDigest, data.late.probeDispatchDigest);
  assert.equal(result.lateEvidenceRef, data.late.evidenceRef); assert.equal(result.originalUnknownSettlementRef, data.parts.unknown.budgetSettlementRef);
  assert.equal(result.originalWaitUnchanged, true); assert.equal(Object.hasOwn(result, 'qualified'), false);
  await assert.rejects((recovery as any).assertInstalledPublicationLateAudit({ ...data.lateInput, beforeCut: data.auditCut }));
});

test('rehashed late facts cannot change the original producer, expired nonce, real completion or namespace closure', async () => {
  let caseIndex = 0;
  for (const change of [
    (p: Record<string, any>) => { p.late.completedAt = p.dispatch.probeDeadlineAt; },
    (p: Record<string, any>) => { p.receipt.observedAt = addCanonicalDuration(p.late.completedAt, 1); },
    (p: Record<string, any>) => { p.late.claimJournalSeq = 3; },
    (p: Record<string, any>) => { p.late.dispatchId = 'another-permanent-dispatch'; },
    (p: Record<string, any>) => { p.late.probeDispatchDigest = canonicalSha256('another probe'); },
    (p: Record<string, any>) => { p.namespace.stateRootIdentityRef = canonicalSha256('another StateRoot'); },
    (p: Record<string, any>) => { p.namespace.namespaceHandlesJoined = false; },
    (p: Record<string, any>) => { p.namespace.workspaceParentFsyncCompleted = false; },
    (p: Record<string, any>) => { p.desired.observation.entryFileId = 'same-bytes-different-inode'; },
    (p: Record<string, any>) => { p.namespace.observedAt = at(); },
  ]) {
    const data = lateAuditGraph(change);
    if (caseIndex++ === 9) await assert.rejects(recovery.assertInstalledPublicationLateAudit(data.lateInput), {
      name: 'AssertionError', code: 'ERR_ASSERTION',
      message: 'publication observations must not predate their original probe or follow their actual receipt',
    });
    else await assert.rejects(recovery.assertInstalledPublicationLateAudit(data.lateInput));
  }
});

test('the audit delta cannot clear waiting, reuse W_M, alter budgets or append Journal and extra checkpoints', async () => {
  for (const change of [
    (data: ReturnType<typeof lateAuditGraph>) => { data.auditCut.snapshot.run.status = 'running'; },
    (data: ReturnType<typeof lateAuditGraph>) => { data.auditCut.snapshot.run.waitingOnRef = canonicalSha256('new nonce wait'); },
    (data: ReturnType<typeof lateAuditGraph>) => { data.auditCut.snapshot.run.frontierRef = canonicalSha256('new frontier'); },
    (data: ReturnType<typeof lateAuditGraph>) => { data.auditCut.snapshot.run.budgetConsumed = zero; },
    (data: ReturnType<typeof lateAuditGraph>) => { data.auditCut.snapshot.run.revision++; },
    (data: ReturnType<typeof lateAuditGraph>) => { data.auditCut.checkpoints.at(-1).workspaceStateRef = canonicalSha256('new W_M'); },
    (data: ReturnType<typeof lateAuditGraph>) => { data.auditCut.checkpoints.at(-1).journalSeq++; },
    (data: ReturnType<typeof lateAuditGraph>) => { data.auditCut.checkpoints.push(data.auditCut.checkpoints.at(-1)); },
    (data: ReturnType<typeof lateAuditGraph>) => { data.auditCut.journal.pop(); data.auditCut.highWaterJournalSeq--; data.auditCut.nextJournalSeq--; },
  ]) {
    const data = lateAuditGraph(); change(data);
    await assert.rejects(recovery.assertInstalledPublicationLateAudit(data.lateInput));
  }
  const missing = lateAuditGraph(); missing.objects.delete(missing.late.evidenceRef);
  await assert.rejects(recovery.assertInstalledPublicationLateAudit(missing.lateInput));
  const noBirth = lateAuditGraph();
  await assert.rejects(recovery.assertInstalledPublicationLateAudit({ ...noBirth.lateInput,
    originalBirth: { ...noBirth.lateInput.originalBirth, arenaId: canonicalSha256('replacement birth') } }));
});

test('the late namespace inspector must retain its exact owner row and acquisition, not only an equal identity projection', async () => {
  const data = lateAuditGraph(), owners = await data.lateInput.readOwnerHistory();
  for (const update of [
    (owner: any) => ({ ...owner, rowDigest: canonicalSha256('not the actual owner row') }),
    (owner: any) => seal({ ...owner, acquisitionEvidenceDigest: canonicalSha256('another acquisition') }, 'rowDigest'),
  ]) {
    const changed = owners.map(owner => owner.ownerEpoch === 2 ? update(owner) : owner);
    await assert.rejects(recovery.assertInstalledPublicationLateAudit({ ...data.lateInput, readOwnerHistory: async () => changed }));
  }
});

function lateRecoveryGraph(change: (value: any) => void = () => undefined) {
  const data = lateAuditGraph(), { put, objects, parts } = data;
  const sealed = (value: any, field: string) => { change(value); return seal(value, field); };
  const object = (ref: string) => JSON.parse(objects.get(ref)!.toString()), cut = structuredClone(data.input.cut);
  const expiredWait = object(data.late.probeWaitingSubjectRef), oldDispatch = expiredWait.probeState.dispatch;
  const closedAt = addCanonicalDuration(data.late.createdAt, 1), nextProbeAt = addCanonicalDuration(closedAt, 1000);
  const inspector = { inspectorIdentityRef: parts.receipt.inspectorIdentityRef, inspectorIdentityDigest: parts.receipt.inspectorIdentityDigest };
  const closure = sealed({ schemaVersion: 1, format: 'cliq-reconciliation-probe-timeout-closure-v1', runId: data.late.runId,
    waitingSubjectRef: data.late.probeWaitingSubjectRef, probeKind: 'automatic', probeOrdinal: 1,
    probeNonceDigest: oldDispatch.probeNonceDigest, probeDispatchDigest: oldDispatch.dispatchDigest, probeDeadlineAt: oldDispatch.probeDeadlineAt,
    ...inspector, closedAt, subjectKind: 'publication', deliveryPlanRef: data.late.deliveryPlanRef, pathOperationId: data.late.operationId,
    attempt: 0, inspectorTaskId: oldDispatch.inspectorTaskId, taskClosure: { closureKind: 'cancelled_and_joined', inspectorTaskCancelledAndJoined: true } }, 'closureDigest');
  const timeout = sealed({ schemaVersion: 1, format: 'cliq-reconciliation-probe-evidence-v1', runId: data.late.runId,
    waitingSubjectRef: data.late.probeWaitingSubjectRef, waitingSubjectDigest: data.late.probeWaitingSubjectRef,
    probeKind: 'automatic', probeOrdinal: 1, probeNonceDigest: oldDispatch.probeNonceDigest, probeDispatchDigest: oldDispatch.dispatchDigest,
    probeStartedAt: oldDispatch.probeStartedAt, probeDeadlineAt: oldDispatch.probeDeadlineAt, ...inspector, observedAt: closedAt,
    outcome: 'probe_timeout', timeoutReason: 'no_authoritative_observation_before_deadline', timeoutClosureRef: put(closure),
    timeoutClosureDigest: closure.closureDigest }, 'evidenceDigest');
  const pending = { ...expiredWait, probeState: { phase: 'automatic_pending', automaticProbeCount: 1, userProbeCount: 0,
    nextProbeAt, lastProbeEvidenceRef: put(timeout), lastProbeEvidenceDigest: timeout.evidenceDigest } };
  const nonce = canonicalSha256('a new actual probe nonce, never the late one'), dispatch = sealed({ ...oldDispatch, probeOrdinal: 2,
    probeNonceDigest: nonce, probeStartedAt: nextProbeAt, probeDeadlineAt: addCanonicalDuration(nextProbeAt, 30000),
    previousWaitingSubjectRef: put(pending), inspectorTaskId: identityHash(data.late.runId, canonicalSha256(expiredWait.subject), 'automatic', 2, nonce) }, 'dispatchDigest');
  put(dispatch);
  const wait = { ...expiredWait, probeState: { phase: 'automatic_in_flight', automaticProbeCount: 2, userProbeCount: 0, dispatch } };
  const time = (offset: number) => addCanonicalDuration(nextProbeAt, offset);
  const desired = sealed({ ...data.desired, observedAt: time(1) }, 'proofDigest');
  const namespace = sealed({ ...data.namespace, destinationObservationRef: put(desired), observedAt: time(2) }, 'proofDigest');
  const receipt = sealed({ ...data.receipt, namespaceRetirementEvidenceRef: put(namespace), observedAt: time(3) }, 'proofDigest');
  const wrapper = sealed({ ...parts.wrapper, waitingSubjectRef: put(wait), waitingSubjectDigest: put(wait), probeOrdinal: 2,
    probeNonceDigest: nonce, probeDispatchDigest: dispatch.dispatchDigest, probeStartedAt: dispatch.probeStartedAt,
    probeDeadlineAt: dispatch.probeDeadlineAt, observedAt: receipt.observedAt, subjectEvidenceRef: put(receipt), subjectEvidenceDigest: receipt.proofDigest }, 'evidenceDigest');
  const retirement = { kind: 'current_namespace', namespaceEvidenceRef: put(namespace) };
  const handoff = { ...parts.handoff, receiptRef: put(receipt), receiptDigest: receipt.proofDigest, retirement,
    reconciliationEvidenceRef: put(wrapper), reconciliationEvidenceDigest: wrapper.evidenceDigest, createdAt: time(4) };
  const result = { ...parts.result, itemId: publicationResultItemId(data.late.runId, data.late.opId, 0, put(receipt)),
    evidenceRef: put(receipt), receiptRef: put(receipt), retirement, reconciliationEvidenceRef: put(wrapper),
    reconciliationEvidenceDigest: wrapper.evidenceDigest, createdAt: time(5) };
  const completed = { ...parts.completed, evidenceRef: put(receipt), receiptRef: put(receipt), evidenceDigest: receipt.proofDigest, timestamp: time(6) };
  cut.items = structuredClone(data.auditCut.items);
  for (const item of [handoff, result]) cut.items.push({ schemaVersion: 1, itemId: item.itemId, itemSeq: cut.items.length + 1,
    payloadRef: put(item), payloadDigest: put(item), createdAt: item.createdAt });
  cut.journal = [...structuredClone(data.beforeCut.journal), completed];
  const final = object(cut.snapshot.run.resultRef), projection = object(final.deliveryTerminalProjectionEvidenceRef);
  const path = seal({ ...object(projection.observedPathStates[0].evidenceRef), observedAt: time(5) }, 'proofDigest');
  const aggregate = seal({ ...object(projection.transientAbsenceEvidenceRef), envelopeRetirements: [{ arenaId: data.input.originalBirth.arenaId, retirement }], observedAt: time(5) }, 'proofDigest');
  const projectionProof = seal({ ...object(projection.projectionClosureEvidenceRef), observedPathEvidenceRefs: [put(path)], forwardResultItemRefs: [put(result)], observedAt: time(5) }, 'proofDigest');
  const git = seal({ ...object(projection.gitIndexUnchangedEvidenceRef), observedAt: time(5) }, 'proofDigest');
  Object.assign(projection, { observedPathStates: [{ ...projection.observedPathStates[0], evidenceRef: put(path) }],
    forwardResultItemRefs: [put(result)], transientAbsenceEvidenceRef: put(aggregate), projectionClosureEvidenceRef: put(projectionProof),
    gitIndexUnchangedEvidenceRef: put(git), observedAt: time(5) }); projection.evidenceDigest = digestOmitting(projection, 'evidenceDigest');
  final.deliveryTerminalProjectionEvidenceRef = put(projection); final.createdAt = time(5);
  const terminal = { ...cut.checkpoints.find((row: any) => row.id === deliveryPublicationTerminalCheckpointId(data.late.runId, data.late.deliveryPlanRef)),
    basedOnRunRevision: 13, runItemSeq: cut.items.length, createdAt: time(6) };
  const context = object(terminal.contextManifestRef); context.throughItemSeq = cut.items.length;
  context.segments = cut.items.map((row: any) => ({ kind: 'excluded_control', fromItemSeq: row.itemSeq, throughItemSeq: row.itemSeq,
    sourceItemsDigest: contextSourceDigest([{ itemSeq: row.itemSeq, itemRef: row.payloadRef, item: object(row.payloadRef) }]) }));
  context.projectionDigest = digestOmitting(context, 'projectionDigest'); terminal.contextManifestRef = put(context);
  const finalRef = put(final), finalCheckpoint = { ...terminal, id: identityHash('cliq-run-result-checkpoint-v1', data.late.runId, 'candidate', finalRef), basedOnRunRevision: 14 };
  cut.checkpoints = [...structuredClone(data.auditCut.checkpoints), terminal, finalCheckpoint];
  Object.assign(cut.snapshot.run, { resultRef: finalRef, revision: 15, updatedAt: time(6), latestCheckpointId: finalCheckpoint.id });
  cut.snapshot.latestRunItemSeq = cut.highWaterItemSeq = cut.nextItemSeq = cut.items.length;
  const last = [...cut.checkpoints].sort((a: any, b: any) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id)).at(-1)!;
  cut.highWaterCheckpointCursor = cut.nextCheckpointCursor = encodeControlCheckpointCursor(data.late.runId, { createdAt: last.createdAt, checkpointId: last.id });
  return { ...data, dispatch, wrapper, receipt, namespace, closure, timeout, pending, terminalInput: { ...data.input, ...data.lateInput, cut } };
}

test('only a new current probe can resolve the same UNKNOWN after its inert late audit', async () => {
  const data = lateRecoveryGraph();
  const result = await (recovery as any).assertInstalledPublicationLateAuditRecovery(data.terminalInput);
  assert.equal(result.resolutionBudgetDeltaZero, true); assert.equal(result.redispatchCount, 0);
  assert.equal(result.expiredProbeDigest, data.late.probeDispatchDigest); assert.equal(result.currentProbeDigest, data.dispatch.dispatchDigest);
  assert.equal(result.originalWaitUnchanged, true); assert.equal(Object.hasOwn(result, 'qualified'), false);
  await assert.rejects(assertInstalledPublicationCleanupRecovery(data.terminalInput));
});

test('live late sampling distinguishes the actual first before/audit cuts and retains both final nonce bindings without reconstructing either cut', async () => {
  const data = lateRecoveryGraph();
  const read = (cut: Record<string, any>) => recovery.readInstalledPublicationProbeSample({ ...data.terminalInput, cut });
  const before = await read(data.beforeCut), audit = await read(data.auditCut), final = await read(data.terminalInput.cut);
  assert.equal(before.phase, 'first_before'); assert.equal(before.probes.length, 1);
  assert.equal(audit.phase, 'first_audit'); assert.equal(audit.probes.length, 1);
  assert.equal(audit.probes[0]!.completedAt, data.late.completedAt);
  assert.equal(final.phase, 'other'); assert.equal(final.probes.length, 2);
  assert.equal(final.probes[0]!.probeDispatchDigest, data.late.probeDispatchDigest);
  assert.equal(final.probes[1]!.probeDispatchDigest, data.dispatch.dispatchDigest);
  assert.notEqual(final.probes[0]!.key, final.probes[1]!.key);
  assert(Object.isFrozen(final)); assert(Object.isFrozen(final.probes));
  assert.equal(Object.hasOwn(final, 'beforeCut'), false); assert.equal(Object.hasOwn(final, 'auditCut'), false);
});

test('a within-probe miss retains its real single nonce but cannot claim a late audit, completion time or earlier cut', async () => {
  const data = recoveryGraph(), original = structuredClone(data.input.cut);
  const sampled = await recovery.readInstalledPublicationProbeSample(data.input);
  assert.equal(sampled.phase, 'other'); assert.equal(sampled.probes.length, 1);
  assert.equal(sampled.probes[0]!.probeOrdinal, 1); assert.equal(Object.hasOwn(sampled.probes[0], 'completedAt'), false);
  assert.equal(Object.hasOwn(sampled, 'qualified'), false); assert.equal(Object.hasOwn(sampled, 'beforeCut'), false);
  assert.deepEqual(data.input.cut, original);
});

test('sampling refuses partial public pages, substituted original birth, bad retained bytes and an audit without a strictly late completion', async () => {
  const incomplete = lateRecoveryGraph(); incomplete.beforeCut.items.pop();
  await assert.rejects(recovery.readInstalledPublicationProbeSample({ ...incomplete.terminalInput, cut: incomplete.beforeCut }));
  const foreign = lateRecoveryGraph();
  await assert.rejects(recovery.readInstalledPublicationProbeSample({ ...foreign.terminalInput,
    originalBirth: { ...foreign.input.originalBirth, arenaId: canonicalSha256('another arena') } }));
  const bytes = lateRecoveryGraph();
  await assert.rejects(recovery.readInstalledPublicationProbeSample({ ...bytes.terminalInput,
    readRetainedArtifact: async () => Buffer.from('{}') }));
  const early = lateAuditGraph(value => { value.late.completedAt = value.dispatch.probeDeadlineAt; });
  await assert.rejects(recovery.readInstalledPublicationProbeSample({ ...early.lateInput, cut: early.auditCut }));
});

test('a rehashed replacement nonce, unjoined old task or late-borrowed observation cannot complete recovery', async () => {
  for (const change of [
    (value: any) => { if (value.format === 'cliq-reconciliation-probe-timeout-closure-v1') value.taskClosure.inspectorTaskCancelledAndJoined = false; },
    (value: any) => { if (value.format === 'cliq-reconciliation-probe-timeout-closure-v1') value.probeDispatchDigest = canonicalSha256('foreign closed task'); },
    (value: any) => { if (value.format === 'cliq-reconciliation-probe-evidence-v1' && value.outcome === 'probe_timeout') value.probeNonceDigest = canonicalSha256('foreign old nonce'); },
    (value: any) => { if (value.format === 'cliq-reconciliation-probe-evidence-v1' && value.outcome === 'subject_observation') value.probeNonceDigest = canonicalSha256('fixed inert nonce'); },
    (value: any) => { if (value.kind === 'terminal_receipt') value.observedAt = addCanonicalDuration(at(9), 30002); },
    (value: any) => { if (value.kind === 'arena_namespace_absence') value.namespaceHandlesJoined = false; },
  ]) {
    const data = lateRecoveryGraph(change);
    await assert.rejects(recovery.assertInstalledPublicationLateAuditRecovery(data.terminalInput));
  }
  const staleAudit = lateRecoveryGraph(); staleAudit.terminalInput.cut.items.splice(staleAudit.auditCut.items.length - 1, 1);
  await assert.rejects(recovery.assertInstalledPublicationLateAuditRecovery(staleAudit.terminalInput));
});
