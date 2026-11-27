// Pure retained-data seam: no filesystem capture, native effect, StateOwner,
// grant or Journal authority is created by these decoder fixtures.
import assert from 'node:assert/strict';
import test from 'node:test';
import { digestOmitting, identityHash } from './identity.js';
import { decodeDeliveryCaptureTopology, decodeDeliveryPlan, decodePublicationPathProgressItem, decodePublicationPathResultItem,
  decodePublicationProof, publicationDirectoryIdentityDigest, type DeliveryPlan } from './publication.js';
import { decodePublicationDirectoryPreimage, decodeDeliveryTerminalProjectionEvidence } from './publication.js';
import { decodePublicationArenaBirth, publicationArenaId } from './publication.js';
import { decodePublicationActualPreimage, decodePublicationPreparationClosure, decodePublicationLateObservationItem } from './publication.js';

test('canonical Git index proof separates a present file from actual absence without inventing a descriptor', () => {
  const ref = 'a'.repeat(64);
  const base = { schemaVersion: 1, format: 'cliq-publication-proof-v1', kind: 'git_index_unchanged', repositoryKind: 'git',
    deliveryRunId: 'data-only-index', deliveryPlanRef: ref, workspaceIdentityRef: ref, workspaceIdentityDigest: ref,
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, observedAt: '2026-10-19T00:00:01.000Z', proofDigest: '',
    repositoryIdentityRef: ref, repositoryIdentityDigest: ref, capturedSourceRef: ref, capturedIndexRef: ref, capturedIndexDigest: ref,
    observedIndexRef: ref, observedIndexDigest: ref,
    objectFormat: 'sha1', canonicalIndexBytesRef: ref, canonicalIndexByteCount: 32, indexTreeObjectId: 'b'.repeat(40),
    descriptorReadComplete: true, readerJoined: true };
  for (const observedIndex of [{ kind: 'present', deviceId: '1', fileId: '2', ownerUid: 501, rawByteCount: 32, rawBytesDigest: ref },
    { kind: 'absent', rawByteCount: 0 }]) {
    const value = { ...base, observedIndex }; value.proofDigest = digestOmitting(value, 'proofDigest');
    assert.deepEqual(decodePublicationProof(value), value);
  }
  for (const observedIndex of [{ kind: 'absent', rawByteCount: 1 }, { kind: 'absent', rawByteCount: 0, fileId: '2' },
    { kind: 'present', deviceId: '1', fileId: '2', ownerUid: 501, rawByteCount: 1, rawBytesDigest: ref },
    { kind: 'unknown', rawByteCount: 0 }]) {
    const value = { ...base, observedIndex }; value.proofDigest = digestOmitting(value, 'proofDigest');
    assert.throws(() => decodePublicationProof(value), TypeError);
  }
  let observed = 0;
  const accessor = { ...base, observedIndex: { kind: 'absent', rawByteCount: 0 } };
  Object.defineProperty(accessor, 'repositoryKind', { enumerable: true, get() { observed++; throw new Error('caller getter executed'); } });
  assert.throws(() => decodePublicationProof(accessor), TypeError);
  const nested = { ...base, observedIndex: { rawByteCount: 0 } };
  Object.defineProperty(nested.observedIndex, 'kind', { enumerable: true, get() { observed++; throw new Error('caller getter executed'); } });
  assert.throws(() => decodePublicationProof(nested), TypeError);
  const proxy = new Proxy({}, { getOwnPropertyDescriptor() { observed++; throw new Error('caller proxy executed'); } });
  assert.throws(() => decodePublicationProof(proxy), TypeError);
  assert.throws(() => decodePublicationProof({ ...base, observedIndex: proxy }), TypeError);
  assert.equal(observed, 0);
});

test('current namespace absence is closed fresh evidence, never an old arena descriptor unlink', () => {
  const ref = 'a'.repeat(64), arenaId = identityHash('namespace-data-arena');
  const value = { schemaVersion: 1, format: 'cliq-publication-proof-v1', kind: 'arena_namespace_absence',
    deliveryRunId: 'data-only-run', deliveryPlanRef: ref, workspaceIdentityRef: ref, workspaceIdentityDigest: ref,
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, observedAt: '2026-10-19T00:00:01.000Z', proofDigest: '',
    recoveryOriginRef: ref, recoveryOriginDigest: ref, arenaId, stateRootIdentityRef: ref, stateRootIdentityDigest: ref,
    registeredArenaIdentity: { deviceId: '1', fileId: '3', ownerUid: 501, mode: 448 },
    namespaceParentIdentity: { deviceId: '1', fileId: '2', ownerUid: 501, mode: 448 },
    coveredLocations: [{ kind: 'publication_arena', arenaId, component: 'stage' }], destinationObservationRef: ref,
    arenaAbsent: true, arenaParentFsyncCompleted: true, workspaceParentFsyncCompleted: true, namespaceHandlesJoined: true };
  value.proofDigest = digestOmitting(value, 'proofDigest');
  assert.deepEqual(decodePublicationProof(value), value);
  for (const change of [{ recoveryOriginRef: undefined }, { namespaceHandlesJoined: false }, { workspaceParentFsyncCompleted: false },
    { retirementObservation: { kind: 'linux_unlinked', linkCount: 0 } }, { arenaIdentity: value.registeredArenaIdentity },
    { coveredLocations: [{ kind: 'workspace', path: 'file' }] }]) {
    const bad = { ...value, ...change };
    assert.throws(() => { bad.proofDigest = digestOmitting(bad, 'proofDigest'); decodePublicationProof(bad); }, TypeError);
  }
});

test('namespace retirement and receipt data cannot smuggle original-descriptor slot observations', () => {
  const ref = 'a'.repeat(64), at = '2026-10-19T00:00:01.000Z', operationId = identityHash('namespace-receipt-operation');
  const absent = { location: { kind: 'workspace', path: 'file' }, state: { kind: 'absent' }, parentDeviceId: '1', parentFileId: '2', parentLinkCount: 2 };
  const receipt = { schemaVersion: 1, format: 'cliq-publication-proof-v1', kind: 'terminal_receipt', deliveryRunId: 'data-only-run',
    deliveryPlanRef: ref, workspaceIdentityRef: ref, workspaceIdentityDigest: ref, inspectorIdentityRef: ref, inspectorIdentityDigest: ref,
    observedAt: at, proofDigest: '', recoveryOriginRef: ref, recoveryOriginDigest: ref, sequence: 'forward', operationIndex: 0,
    operationId, opId: 'data-only-op', attempt: 0, before: absent, after: absent, namespaceRetirementEvidenceRef: ref,
    parentIdentityBeforeDigest: ref, parentIdentityAfterDigest: ref, directoryFsyncCompleted: true };
  receipt.proofDigest = digestOmitting(receipt, 'proofDigest'); assert.deepEqual(decodePublicationProof(receipt), receipt);
  const result = { schemaVersion: 1, kind: 'publication_path_result', itemId: 'data-only-result', runId: receipt.deliveryRunId,
    deliveryPlanRef: ref, sequence: 'forward', operationIndex: 0, operationId, opId: receipt.opId, attempt: 0,
    outcome: 'completed', evidenceRef: ref, receiptRef: ref, retirement: { kind: 'current_namespace', namespaceEvidenceRef: ref }, createdAt: at };
  assert.deepEqual(decodePublicationPathResultItem(result), result);
  for (const retirement of [{ ...result.retirement, slotObservationRefs: [] }, { ...result.retirement, arenaRetirementRef: ref },
    { slotObservationRefs: [], arenaRetirementRef: ref }, { kind: 'current_namespace', namespaceEvidenceRef: 'invalid' }])
    assert.throws(() => decodePublicationPathResultItem({ ...result, retirement }), TypeError);
  const mixed = { ...receipt, transientFinalObservations: [] }; mixed.proofDigest = digestOmitting(mixed, 'proofDigest');
  assert.throws(() => decodePublicationProof(mixed), TypeError);
  const { recoveryOriginRef: _origin, recoveryOriginDigest: _digest, ...unowned } = receipt;
  unowned.proofDigest = digestOmitting(unowned, 'proofDigest'); assert.throws(() => decodePublicationProof(unowned), TypeError);
});

test('transient aggregation partitions claimed envelopes without inventing old slot descriptors', () => {
  const ref = 'a'.repeat(64), arenaId = identityHash('covered-data-arena');
  const value = { schemaVersion: 1, format: 'cliq-publication-proof-v1', kind: 'transient_absence', deliveryRunId: 'data-only-run',
    deliveryPlanRef: ref, workspaceIdentityRef: ref, workspaceIdentityDigest: ref, inspectorIdentityRef: ref, inspectorIdentityDigest: ref,
    observedAt: '2026-10-19T00:00:01.000Z', proofDigest: '',
    transientLocations: [{ kind: 'publication_arena', arenaId, component: 'stage' }],
    envelopeRetirements: [{ arenaId, retirement: { kind: 'current_namespace', namespaceEvidenceRef: ref } }] };
  value.proofDigest = digestOmitting(value, 'proofDigest'); assert.deepEqual(decodePublicationProof(value), value);
  for (const change of [{ observationRefs: [] }, { arenaRetirementRefs: [] }, { envelopeRetirements: [] },
    { envelopeRetirements: [value.envelopeRetirements[0], value.envelopeRetirements[0]] },
    { envelopeRetirements: [{ arenaId: identityHash('foreign-arena'), retirement: value.envelopeRetirements[0]!.retirement }] }]) {
    const bad = { ...value, ...change }; bad.proofDigest = digestOmitting(bad, 'proofDigest');
    assert.throws(() => decodePublicationProof(bad), TypeError);
  }
});

test('late publication observations are audit data and cannot assert a handoff or discard an actual disposition', () => {
  const ref = 'a'.repeat(64), runId = 'data-only-run', opId = 'data-only-op', probeDispatchDigest = 'b'.repeat(64);
  const base = { schemaVersion: 1, kind: 'publication_late_observation',
    itemId: identityHash('cliq-publication-late-observation-item-v1', runId, opId, '0', probeDispatchDigest, ref),
    runId, deliveryPlanRef: ref, sequence: 'forward', operationIndex: 0, operationId: identityHash('late-data-operation'), opId, attempt: 0,
    dispatchId: 'original-claim-dispatch', claimJournalSeq: 2, probeWaitingSubjectRef: ref, probeDispatchDigest,
    evidenceRef: ref, evidenceDigest: ref, completedAt: '2026-10-19T00:00:30.001Z', createdAt: '2026-10-19T00:00:31.000Z' };
  for (const disposition of ['received', 'stopped_before_effect', 'retained_planned_descendant', 'unknown']) {
    const value = { ...base, disposition, ...(disposition === 'unknown' ? {} :
      { retirement: { kind: 'current_namespace', namespaceEvidenceRef: ref } }) };
    assert.deepEqual(decodePublicationLateObservationItem(value), value);
    for (const extra of [{ outcome: 'completed' }, { receiptRef: ref }, { generationResources: {} }, { state: 'received_handoff' },
      { itemId: 'another-audit' }, { probeDispatchDigest: 'c'.repeat(64) }, { attempt: 1 }, { completedAt: '2026-10-19T00:00:32.000Z' }])
      assert.throws(() => decodePublicationLateObservationItem({ ...value, ...extra }), TypeError);
    if (disposition === 'unknown') assert.throws(() => decodePublicationLateObservationItem({ ...value,
      retirement: { slotObservationRefs: [ref], arenaRetirementRef: ref } }), TypeError);
    else { const { retirement: _retirement, ...missing } = value; assert.throws(() => decodePublicationLateObservationItem(missing), TypeError); }
  }
});

function actualPreimageData() {
  const ref = 'a'.repeat(64), operationId = identityHash('actual-preimage-data-operation');
  const data = { schemaVersion: 1, format: 'cliq-publication-actual-preimage-v1', deliveryRunId: 'data-only-run', deliveryPlanRef: ref,
    sequence: 'forward', operationIndex: 0, operationId, opId: 'data-only-op', attempt: 0, dispatchId: 'data-only-dispatch', arenaBirthRef: ref,
    location: { kind: 'publication_arena', arenaId: publicationArenaId('data-only-run', operationId, 'data-only-op', 0, 'data-only-dispatch'), component: '.stage' },
    physical: { identity: { deviceId: '1', fileId: '3', ownerUid: 501 }, mode: 0o600, linkCount: 1, byteCount: '3' },
    payload: { kind: 'file', bytesRef: ref, bytesDigest: ref, byteCount: 3 }, preimageDigest: '' };
  data.preimageDigest = digestOmitting(data, 'preimageDigest');
  return data;
}

test('publication preparation closure is a closed zero-dispatch data branch, never a path receipt or factory-unknown success', () => {
  const ref = 'a'.repeat(64), base = { schemaVersion: 1, format: 'cliq-publication-preparation-closure-v1', deliveryRunId: 'data-only-run',
    deliveryPlanRef: ref, sequence: 'forward', operationIndex: 0, operationId: identityHash('preparation-only-operation'),
    opId: 'data-only-op', attempt: 0, preparedJournalSeq: 1, requestRef: ref, targetRef: ref, grantRef: ref, dispatchId: 'original-unclaimed-dispatch',
    stateOwnerEpoch: 1, supervisorInstanceId: 'original-supervisor', leaseEpoch: 1,
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, observedAt: '2026-10-18T00:00:00.000Z', closureDigest: '' };
  for (const retirement of [{ kind: 'no_birth' }, { kind: 'retired', arenaBirthRef: 'b'.repeat(64),
    slotObservationRefs: ['c'.repeat(64)], arenaRetirementRef: 'd'.repeat(64) }]) {
    const value = { ...base, retirement }; value.closureDigest = digestOmitting(value, 'closureDigest');
    assert.deepEqual(decodePublicationPreparationClosure(value), value);
    for (const altered of [ { ...value, attempt: 1 }, { ...value, preparedJournalSeq: 0 }, { ...value, stateOwnerEpoch: 0 },
      { ...value, sequence: 'semantic' }, { ...value, claimRef: ref }, { ...value, cleanupAllowed: true },
      { ...value, retirement: { ...retirement, kind: 'unknown' } }, { ...value, retirement: { ...retirement, joined: true } } ]) {
      altered.closureDigest = digestOmitting(altered, 'closureDigest');
      assert.throws(() => decodePublicationPreparationClosure(altered), TypeError);
    }
    assert.throws(() => decodePublicationPreparationClosure({ ...value, closureDigest: 'b'.repeat(64) }), /digest/u);
    for (const raw of retirement.kind === 'no_birth' ? [{ ...retirement, arenaBirthRef: ref }] : [
      { ...retirement, arenaBirthRef: 'invalid' }, { ...retirement, slotObservationRefs: [] },
      { ...retirement, slotObservationRefs: [ref, ref] }, { ...retirement, arenaRetirementRef: 'invalid' },
      { ...retirement, slotObservationRefs: Array(1) } ]) {
      const candidate = { ...value, retirement: raw };
      assert.throws(() => { candidate.closureDigest = digestOmitting(candidate, 'closureDigest');
        decodePublicationPreparationClosure(candidate); }, TypeError);
    }
    const accessor = Object.defineProperty({ ...value }, 'retirement', { enumerable: true,
      get() { assert.fail('preparation closure must reject accessors'); } });
    assert.throws(() => decodePublicationPreparationClosure(accessor), TypeError);
  }
});

test('an actual preimage is closed preserved data bound to one original dispatch, never expected cleanup evidence', () => {
  const data = actualPreimageData();
  assert.deepEqual(decodePublicationActualPreimage(data), data);
});

test('actual preimage decoding rejects incomplete, unbounded, noncanonical and authority-shaped payloads', () => {
  const source = actualPreimageData();
  for (const mutate of [
    (copy: any) => { copy.authority = true; },
    (copy: any) => { copy.sequence = 'abort'; },
    (copy: any) => { copy.attempt = -1; },
    (copy: any) => { copy.location.kind = 'workspace'; },
    (copy: any) => { copy.location.arenaId = identityHash('different-arena'); },
    (copy: any) => { copy.location.component = 'nested/slot'; },
    (copy: any) => { copy.physical.byteCount = '03'; },
    (copy: any) => { copy.physical.byteCount = 3; },
    (copy: any) => { copy.physical.identity.deviceId = '01'; },
    (copy: any) => { copy.physical.identity.ownerUid = 0x100000000; },
    (copy: any) => { copy.physical.identity.ownerUid = true; },
    (copy: any) => { copy.physical.identity.authority = true; },
    (copy: any) => { copy.physical.mode = 0o10000; },
    (copy: any) => { copy.physical.linkCount = 2; },
    (copy: any) => { copy.physical.linkCount = true; },
    (copy: any) => { copy.payload.bytesDigest = 'b'.repeat(64); },
    (copy: any) => { copy.payload.byteCount = 2; },
    (copy: any) => { copy.physical.byteCount = '268435457'; copy.payload.byteCount = 268435457; },
    (copy: any) => { copy.payload.kind = 'symlink'; copy.physical.byteCount = '4097'; copy.payload.byteCount = 4097; },
    (copy: any) => { copy.payload.kind = 'symlink'; copy.physical.byteCount = '0'; copy.payload.byteCount = 0; },
    (copy: any) => { copy.payload = { kind: 'nonempty_directory', entriesRef: 'a'.repeat(64) }; },
    (copy: any) => { copy.payload.target = 'normalized targets are not raw preservation'; },
    (copy: any) => { copy.payload.cleanupAllowed = true; }
  ]) {
    const copy = structuredClone(source); mutate(copy); copy.preimageDigest = digestOmitting(copy, 'preimageDigest');
    assert.throws(() => decodePublicationActualPreimage(copy), TypeError);
  }
  assert.throws(() => decodePublicationActualPreimage({ ...source, preimageDigest: 'b'.repeat(64) }), /digest/u);
  const empty = { ...source, payload: { kind: 'empty_directory', entriesRef: 'b'.repeat(64) } };
  empty.preimageDigest = digestOmitting(empty, 'preimageDigest'); assert.deepEqual(decodePublicationActualPreimage(empty), empty);
  const symlink = { ...source, payload: { ...source.payload, kind: 'symlink' } };
  symlink.preimageDigest = digestOmitting(symlink, 'preimageDigest'); assert.deepEqual(decodePublicationActualPreimage(symlink), symlink);
  for (const select of [(data: any) => data, (data: any) => data.location, (data: any) => data.physical,
    (data: any) => data.physical.identity, (data: any) => data.payload]) {
    const copy = structuredClone(source), selected = select(copy);
    Object.defineProperty(selected, 'hostile', { enumerable: true, get() { assert.fail('actual data decoder must not execute accessors'); } });
    assert.throws(() => decodePublicationActualPreimage(copy), TypeError);
  }
  const getter = structuredClone(source);
  Object.defineProperty(getter.payload, 'kind', { enumerable: true, get() { assert.fail('payload kind must be read as data only'); } });
  assert.throws(() => decodePublicationActualPreimage(getter), TypeError);
});

test('only unknown publication evidence can retain an actual preimage reference', () => {
  const data = actualPreimageData(), ref = 'a'.repeat(64), common = { schemaVersion: 1, format: 'cliq-publication-proof-v1',
    deliveryRunId: data.deliveryRunId, deliveryPlanRef: ref, workspaceIdentityRef: ref, workspaceIdentityDigest: ref,
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, observedAt: '2026-10-18T00:00:00.000Z', proofDigest: '',
    sequence: 'forward', operationIndex: 0, operationId: data.operationId, opId: data.opId, attempt: 0 };
  const unknown = { ...common, kind: 'path_ambiguity', launchDispatchId: data.dispatchId, failure: 'transient_state_ambiguous',
    lastKnownObservationRefs: [], preservedActualPreimageRef: ref };
  unknown.proofDigest = digestOmitting(unknown, 'proofDigest'); assert.deepEqual(decodePublicationProof(unknown), unknown);
  const abort = { ...unknown, sequence: 'abort' }; abort.proofDigest = digestOmitting(abort, 'proofDigest');
  assert.throws(() => decodePublicationProof(abort), TypeError);
  const absent = { location: { kind: 'workspace', path: 'file' }, state: { kind: 'absent' }, parentDeviceId: '1', parentFileId: '2', parentLinkCount: 2 };
  const completed = { ...common, kind: 'terminal_receipt', before: absent, after: absent, transientFinalObservations: [],
    parentIdentityBeforeDigest: ref, parentIdentityAfterDigest: ref, directoryFsyncCompleted: true, preservedActualPreimageRef: ref };
  completed.proofDigest = digestOmitting(completed, 'proofDigest'); assert.throws(() => decodePublicationProof(completed), TypeError);
  assert.throws(() => decodePublicationPathProgressItem({ schemaVersion: 1, itemId: 'data-only-item', runId: data.deliveryRunId,
    kind: 'publication_path_progress', deliveryPlanRef: ref, operationIndex: 0, operationId: data.operationId, opId: data.opId, attempt: 0,
    state: 'desired_committed_cleanup_pending', beforeObservationRef: ref, destinationEvidenceRef: ref, preservedActualPreimageRef: ref,
    createdAt: '2026-10-18T00:00:00.000Z' }), TypeError);
});

test('closed publication plans preserve raw expected modes and exact directory creator edges', () => {
  const id = (value: string) => identityHash('retained-data-plan', value), ref = 'a'.repeat(64);
  const plan: DeliveryPlan = { schemaVersion: 1, deliveryRunId: 'data-only-run', sourceRunResultRef: ref, sourceBaseRef: ref,
    sourceDesiredRef: ref, capturedWorkspaceRef: ref, captureTopologyRef: ref, captureTopologyDigest: ref, desiredSourceRef: ref, diffRef: ref,
    mergeAlgorithm: 'cliq-diff3-v1', publicationStateMachine: 'cliq-publish-v1', forwardOperations: [
      { index: 0, operationId: id('create-directory'), kind: 'replace', path: 'p', parent: { kind: 'existing_directory', expectedIdentityDigest: ref },
        expected: { kind: 'file', mode: 0o600, digest: ref }, desired: { kind: 'directory', mode: 493 },
        stagingName: '.stage-p', stagingExpected: { kind: 'absent' }, quarantineName: '.old-p', quarantineExpected: { kind: 'absent' } },
      { index: 1, operationId: id('create-child'), kind: 'create', path: 'p/c', parent: { kind: 'planned_directory', createdByOperationId: id('create-directory') },
        expected: { kind: 'absent' }, desired: { kind: 'file', mode: 0o644, digest: ref }, stagingName: '.stage-c', stagingExpected: { kind: 'absent' } }
    ], abortOperations: [{ index: 0, operationId: id('abort-p'), kind: 'abort_rmdir', path: 'p', createdByOperationId: id('create-directory'),
      quarantineName: 'preimage', quarantineExpected: { kind: 'absent' } }] };
  assert.deepEqual(decodeDeliveryPlan(plan), plan);
  for (const mutate of [
    (copy: any) => { copy.unknown = true; },
    (copy: any) => { copy.forwardOperations[0].desired.mode = 0o700; },
    (copy: any) => { copy.forwardOperations[1].parent.createdByOperationId = id('other'); },
    (copy: any) => { copy.forwardOperations[1].stagingName = '../c'; },
    (copy: any) => { copy.forwardOperations[0].expected.empty = true; },
    (copy: any) => { copy.abortOperations = []; },
    (copy: any) => { delete copy.abortOperations[0].quarantineName; },
    (copy: any) => { delete copy.abortOperations[0].quarantineExpected; },
    (copy: any) => { copy.abortOperations[0].quarantineName = 'foreign'; },
    (copy: any) => { copy.abortOperations[0].quarantineExpected = { kind: 'directory' }; },
    (copy: any) => { copy.abortOperations[0].stagingName = 'desired'; },
    (copy: any) => { copy.abortOperations[0].desired = { kind: 'absent' }; },
    (copy: any) => { copy.forwardOperations.reverse(); },
    (copy: any) => { copy.forwardOperations[1].path = 'p/../escape'; }
  ]) { const copy = structuredClone(plan); mutate(copy); assert.throws(() => decodeDeliveryPlan(copy), TypeError); }
});

test('capture topology uses raw mode and excludes mutable content metadata from directory identity', () => {
  const workspace = 'b'.repeat(64), physical = { deviceId: '1', fileId: '2', ownerUid: 501, mode: 0o700 };
  const identityDigest = publicationDirectoryIdentityDigest(workspace, physical);
  const topology = { schemaVersion: 1, format: 'cliq-delivery-capture-topology-v1', inspectionId: identityHash('data-only-inspection'),
    capturedWorkspaceRef: 'c'.repeat(64), workspaceIdentityRef: 'd'.repeat(64), workspaceIdentityDigest: workspace,
    rootIdentity: { ...physical, identityDigest }, directories: [{ path: 'p', ...physical, identityDigest }],
    fileModes: [{ path: 'p/c', mode: 0o600 }], capturedAt: '2026-10-18T00:00:00.000Z', topologyDigest: '' };
  topology.topologyDigest = digestOmitting(topology, 'topologyDigest');
  assert.deepEqual(decodeDeliveryCaptureTopology(topology), topology);
  for (const field of ['mtimeNs', 'ctimeNs', 'linkCount', 'treeDigest']) {
    const copy = structuredClone(topology) as any; copy.directories[0][field] = 2; copy.topologyDigest = digestOmitting(copy, 'topologyDigest');
    assert.throws(() => decodeDeliveryCaptureTopology(copy), TypeError);
  }
  const copy = structuredClone(topology); copy.fileModes[0].mode = 0o644;
  assert.throws(() => decodeDeliveryCaptureTopology(copy), /digest/);
});

test('publication progress and result decoding never substitutes retained data for a terminal receipt', () => {
  const ref = 'a'.repeat(64), op = identityHash('data-only-operation'), common = { schemaVersion: 1, itemId: 'data-only-item', runId: 'data-only-run',
    deliveryPlanRef: ref, operationIndex: 0, operationId: op, opId: 'data-only-op', attempt: 1, createdAt: '2026-10-18T00:00:00.000Z' };
  const progress = { ...common, kind: 'publication_path_progress', state: 'desired_committed_cleanup_pending', beforeObservationRef: ref, destinationEvidenceRef: ref,
    preservedPreimageRef: ref, transientObservationRef: ref };
  assert.deepEqual(decodePublicationPathProgressItem(progress), progress);
  assert.throws(() => decodePublicationPathProgressItem({ ...progress, state: 'completed' }), TypeError);
  assert.throws(() => decodePublicationPathProgressItem({ ...progress, receiptRef: ref }), TypeError);
  const { beforeObservationRef: _before, ...withoutBefore } = progress;
  assert.throws(() => decodePublicationPathProgressItem(withoutBefore), TypeError);
  for (const beforeObservationRef of [undefined, 'invalid', true, ''])
    assert.throws(() => decodePublicationPathProgressItem({ ...progress, beforeObservationRef }), TypeError);
  const beforeAccessor = Object.defineProperty({ ...progress }, 'beforeObservationRef', { enumerable: true,
    get() { assert.fail('progress must reject before-observation accessors'); } });
  assert.throws(() => decodePublicationPathProgressItem(beforeAccessor), TypeError);
  const result = { ...common, kind: 'publication_path_result', sequence: 'forward', outcome: 'completed', receiptRef: ref, evidenceRef: ref,
    retirement: { slotObservationRefs: ['b'.repeat(64)], arenaRetirementRef: 'c'.repeat(64) } };
  assert.deepEqual(decodePublicationPathResultItem(result), result);
  assert.throws(() => decodePublicationPathResultItem({ ...result, receiptRef: 'b'.repeat(64) }), TypeError);
  assert.throws(() => decodePublicationPathResultItem({ ...result, outcome: 'unknown' }), TypeError);
  const { receiptRef: _, retirement: _retirement, ...unknown } = { ...result, outcome: 'unknown' };
  assert.deepEqual(decodePublicationPathResultItem(unknown), unknown);
  const handoff = { ...result, abortStopIntentRef: 'b'.repeat(64) };
  assert.deepEqual(decodePublicationPathResultItem(handoff), handoff);
  for (const changed of [{ sequence: 'abort' }, { outcome: 'unknown', receiptRef: undefined },
    { abortStopIntentRef: 'not-a-ref' }, { stopIntentRef: 'b'.repeat(64) }]) {
    const data = { ...handoff, ...changed };
    if (changed.outcome === 'unknown') Reflect.deleteProperty(data, 'receiptRef');
    assert.throws(() => decodePublicationPathResultItem(data), TypeError);
  }
});

function receivedHandoffData() {
  return { schemaVersion: 1, kind: 'publication_path_progress', itemId: 'data-only-received-handoff', runId: 'data-only-run',
    deliveryPlanRef: 'a'.repeat(64), operationIndex: 0, operationId: identityHash('data-only-last-forward'), opId: 'data-only-op',
    attempt: 0, createdAt: '2026-10-19T00:00:00.000Z', state: 'received_handoff', sequence: 'forward',
    dispatchId: 'data-only-original-dispatch', claimJournalSeq: 2, receiptRef: 'b'.repeat(64), receiptDigest: 'c'.repeat(64),
    retirement: { slotObservationRefs: ['d'.repeat(64)], arenaRetirementRef: 'e'.repeat(64) },
    generationResources: { kind: 'sealed', workerLaunchId: 'data-only-original-worker', generationRef: 'f'.repeat(64), snapshotEvidenceRef: '1'.repeat(64) } };
}

test('received publication handoff is a separate closed data state, not cleanup or terminal authority', () => {
  const data = receivedHandoffData();
  const decoded = decodePublicationPathProgressItem(data);
  assert.deepEqual(decoded, data);
  assert(Object.isFrozen(decoded));
});

test('received recovered resources are a closed retired-from-verified branch requiring a separate reconciliation edge', () => {
  const original = receivedHandoffData(), generationResources = { kind: 'genuinely_retired_from_verified_checkpoint',
    workerLaunchId: 'data-only-original-worker', generationRef: 'f'.repeat(64), sourceCheckpointId: 'data-only-verified-checkpoint',
    quarantineEvidenceRef: '1'.repeat(64), retirementEvidenceRef: '2'.repeat(64) };
  const data = { ...original, generationResources, reconciliationEvidenceRef: '3'.repeat(64), reconciliationEvidenceDigest: '4'.repeat(64) };
  assert.deepEqual(decodePublicationPathProgressItem(data), data);
  for (const change of [
    { reconciliationEvidenceRef: undefined }, { reconciliationEvidenceDigest: undefined },
    { generationResources: { ...generationResources, sourceCheckpointId: '' } },
    { generationResources: { ...generationResources, snapshotEvidenceRef: '5'.repeat(64) } },
    { generationResources: { ...generationResources, kind: 'retired' } },
    { generationResources: { ...generationResources, retired: true } },
    { generationResources: { ...generationResources, quarantineEvidenceRef: 'invalid' } },
    { generationSeal: original.generationResources }
  ]) assert.throws(() => decodePublicationPathProgressItem({ ...data, ...change }), TypeError);
  assert.throws(() => decodePublicationPathProgressItem({ ...original, generationResources }), TypeError);
  for (const key of ['kind', 'retirementEvidenceRef']) {
    const accessor = Object.defineProperty({ ...generationResources }, key, { enumerable: true,
      get() { assert.fail('resource decoder must not invoke accessors'); } });
    assert.throws(() => decodePublicationPathProgressItem({ ...data, generationResources: accessor }), TypeError);
  }
});

test('received handoff rejects mixed cleanup fields, unsupported branches and incomplete retirement', () => {
  for (const change of [
    (data: any) => { data.state = 'completed'; },
    (data: any) => { data.sequence = 'abort'; },
    (data: any) => { data.attempt = 1; },
    (data: any) => { data.claimJournalSeq = 0; },
    (data: any) => { data.claimJournalSeq = true; },
    (data: any) => { data.dispatchId = ''; },
    (data: any) => { data.receiptRef = 'not-an-artifact'; },
    (data: any) => { data.receiptDigest = 'not-a-digest'; },
    (data: any) => { data.destinationEvidenceRef = 'a'.repeat(64); },
    (data: any) => { data.beforeObservationRef = 'a'.repeat(64); },
    (data: any) => { data.preservedPreimageRef = 'a'.repeat(64); },
    (data: any) => { data.transientObservationRef = 'a'.repeat(64); },
    (data: any) => { data.retirement.slotObservationRefs = []; },
    (data: any) => { data.retirement.slotObservationRefs = ['d'.repeat(64), 'd'.repeat(64)]; },
    (data: any) => { data.retirement.slotObservationRefs = Array(1); },
    (data: any) => { data.retirement.arenaRetirementRef = data.retirement.slotObservationRefs[0]; },
    (data: any) => { data.retirement.joined = true; },
    (data: any) => { data.generationResources.snapshotEvidenceRef = 'invalid'; },
    (data: any) => { data.generationResources.workerLaunchId = ''; },
    (data: any) => { data.generationResources.active = false; },
    (data: any) => { delete data.generationResources; },
    (data: any) => { data.budgetSettlementRef = 'a'.repeat(64); },
    (data: any) => { data.cleanupAllowed = true; }
  ]) {
    const data = receivedHandoffData(); change(data);
    assert.throws(() => decodePublicationPathProgressItem(data), TypeError);
  }
  for (const field of ['state', 'retirement', 'generationResources']) {
    const data = Object.defineProperty(receivedHandoffData(), field, { enumerable: true,
      get() { assert.fail('handoff decoder must reject accessors'); } });
    assert.throws(() => decodePublicationPathProgressItem(data), TypeError);
  }
});

test('known claimed publication results require closed durable original retirement refs while unknown and unclaimed absence forbid them', () => {
  // Closed data only: none of these refs is presented as a native proof,
  // original Journal claim, cleanup permit or real retirement qualification.
  const ref = 'a'.repeat(64), common = { schemaVersion: 1, kind: 'publication_path_result', itemId: 'data-only-item', runId: 'data-only-run',
    deliveryPlanRef: ref, sequence: 'forward', operationIndex: 0, operationId: identityHash('retirement-data'),
    opId: 'data-only-op', attempt: 0, evidenceRef: ref, createdAt: '2026-10-18T00:00:00.000Z' };
  const retirement = { slotObservationRefs: ['b'.repeat(64)], arenaRetirementRef: 'c'.repeat(64) };
  for (const outcome of ['completed', 'failed', 'retained_planned_descendant']) {
    const result = { ...common, outcome, ...(outcome === 'completed' ? { receiptRef: ref } : {}), retirement };
    assert.deepEqual(decodePublicationPathResultItem(result), result);
    const { retirement: _omitted, ...missing } = result;
    assert.throws(() => decodePublicationPathResultItem(missing), TypeError);
    for (const altered of [ { ...retirement, joined: true }, { slotObservationRefs: retirement.slotObservationRefs },
      { arenaRetirementRef: retirement.arenaRetirementRef }, { ...retirement, slotObservationRefs: [] },
      { ...retirement, slotObservationRefs: [ref, ref] }, { ...retirement, slotObservationRefs: [ref, 'd'.repeat(64), 'e'.repeat(64)] },
      { ...retirement, arenaRetirementRef: 'invalid' }, { ...retirement, slotObservationRefs: ['invalid'] },
      { ...retirement, arenaRetirementRef: retirement.slotObservationRefs[0] } ])
      assert.throws(() => decodePublicationPathResultItem({ ...result, retirement: altered }), TypeError);
    const accessor = Object.defineProperty({ ...retirement }, 'arenaRetirementRef', { enumerable: true,
      get() { assert.fail('retirement decoder must reject accessors without running them'); } });
    assert.throws(() => decodePublicationPathResultItem({ ...result, retirement: accessor }), TypeError);
    const sparse = Array(1);
    assert.throws(() => decodePublicationPathResultItem({ ...result, retirement: { ...retirement, slotObservationRefs: sparse } }), TypeError);
  }
  for (const outcome of ['unknown', 'not_created']) {
    assert.deepEqual(decodePublicationPathResultItem({ ...common, outcome }), { ...common, outcome });
    assert.throws(() => decodePublicationPathResultItem({ ...common, outcome, retirement }), TypeError);
  }
});

test('known result reconciliation is a complete closed reference pair, never unknown or unclaimed authority', () => {
  const ref = 'a'.repeat(64), pair = { reconciliationEvidenceRef: 'b'.repeat(64), reconciliationEvidenceDigest: 'c'.repeat(64) };
  const common = { schemaVersion: 1, kind: 'publication_path_result', itemId: 'data-only-reconciled-item', runId: 'data-only-run',
    deliveryPlanRef: ref, sequence: 'forward', operationIndex: 0, operationId: identityHash('reconciled-data'), opId: 'data-only-op',
    attempt: 0, evidenceRef: ref, createdAt: '2026-10-19T00:00:00.000Z' };
  for (const outcome of ['completed', 'failed', 'retained_planned_descendant']) {
    const value = { ...common, outcome, ...(outcome === 'completed' ? { receiptRef: ref } : {}),
      retirement: { slotObservationRefs: ['d'.repeat(64)], arenaRetirementRef: 'e'.repeat(64) }, ...pair };
    assert.deepEqual(decodePublicationPathResultItem(value), value);
    for (const changed of [{ reconciliationEvidenceRef: undefined }, { reconciliationEvidenceDigest: undefined },
      { reconciliationEvidenceRef: 'invalid' }, { reconciliationEvidenceDigest: true }, { reconciled: true }])
      assert.throws(() => decodePublicationPathResultItem({ ...value, ...changed }), TypeError);
    for (const field of Object.keys(pair)) {
      const accessor = Object.defineProperty({ ...value }, field, { enumerable: true,
        get() { assert.fail('reconciliation decoder must reject accessors'); } });
      assert.throws(() => decodePublicationPathResultItem(accessor), TypeError);
      const missing = { ...value }; Reflect.deleteProperty(missing, field);
      assert.throws(() => decodePublicationPathResultItem(missing), TypeError);
    }
  }
  for (const outcome of ['unknown', 'not_created'])
    assert.throws(() => decodePublicationPathResultItem({ ...common, outcome, ...pair }), TypeError);
});

test('recovery provenance is allowed only on original-claim path proofs and is covered by their complete digest', () => {
  const ref = 'a'.repeat(64), absent = { location: { kind: 'workspace', path: 'file' }, state: { kind: 'absent' },
    parentDeviceId: '1', parentFileId: '2', parentLinkCount: 2 };
  const base = { schemaVersion: 1, format: 'cliq-publication-proof-v1', deliveryRunId: 'data-only-run', deliveryPlanRef: ref,
    workspaceIdentityRef: ref, workspaceIdentityDigest: ref, inspectorIdentityRef: ref, inspectorIdentityDigest: ref,
    observedAt: '2026-10-19T00:00:00.000Z', proofDigest: '' };
  const operation = { sequence: 'forward', operationIndex: 0, operationId: identityHash('data-only-recovered-operation'), opId: 'data-only-op', attempt: 0 };
  const pair = { recoveryOriginRef: 'b'.repeat(64), recoveryOriginDigest: 'c'.repeat(64) };
  const allowed = [
    { kind: 'path_observation', observation: absent },
    { kind: 'terminal_receipt', ...operation, before: absent, after: absent, transientFinalObservations: [],
      parentIdentityBeforeDigest: ref, parentIdentityAfterDigest: ref, directoryFsyncCompleted: true },
    { kind: 'path_ambiguity', ...operation, launchDispatchId: 'data-only-dispatch', failure: 'transient_state_ambiguous', lastKnownObservationRefs: [] },
    { kind: 'arena_retirement', arenaId: identityHash('data-only-arena'), stateRootIdentityRef: ref, stateRootIdentityDigest: ref,
      arenaIdentity: { deviceId: '1', fileId: '3', ownerUid: 501, mode: 448 },
      parentIdentity: { deviceId: '1', fileId: '4', ownerUid: 501, mode: 448 }, arenaAbsent: true, arenaParentFsyncCompleted: true,
      retirementObservation: { kind: 'linux_unlinked', linkCount: 0 } }
  ];
  for (const fields of allowed) {
    const value = { ...base, ...fields, ...pair }; value.proofDigest = digestOmitting(value, 'proofDigest');
    assert.deepEqual(decodePublicationProof(value), value);
    assert.throws(() => decodePublicationProof({ ...value, recoveryOriginDigest: 'd'.repeat(64) }), /digest/u);
    for (const field of Object.keys(pair)) {
      const missing = { ...value }; Reflect.deleteProperty(missing, field); missing.proofDigest = digestOmitting(missing, 'proofDigest');
      assert.throws(() => decodePublicationProof(missing), TypeError);
      const accessor = Object.defineProperty({ ...value }, field, { enumerable: true,
        get() { assert.fail('origin decoder must reject accessors'); } });
      assert.throws(() => decodePublicationProof(accessor), TypeError);
    }
  }
  for (const fields of [
    { kind: 'ancestor_projection_absence', path: 'd/file', ancestorPath: 'd', ancestorObservationRef: ref },
    { kind: 'planned_descendant', abortOperationId: operation.operationId, retainedDescendantOperationIds: [operation.operationId], observationRefs: [ref] },
    { kind: 'transient_absence', transientLocations: [], observationRefs: [], arenaRetirementRefs: [] },
    { kind: 'projection_closure', selectedBranch: 'forward_finalize', observedSourceRef: ref, observedPathEvidenceRefs: [],
      forwardResultItemRefs: [], unstartedForwardOperationIds: [], abortResultItemRefs: [] },
    { kind: 'git_index_unchanged', repositoryKind: 'non_git' }
  ]) {
    const value = { ...base, ...fields, ...pair }; value.proofDigest = digestOmitting(value, 'proofDigest');
    assert.throws(() => decodePublicationProof(value), TypeError);
  }
});

test('path observations bind complete identities, exact raw bytes and their own closed digest', () => {
  const ref = 'a'.repeat(64), proof = { schemaVersion: 1, format: 'cliq-publication-proof-v1', kind: 'path_observation',
    deliveryRunId: 'data-only-run', deliveryPlanRef: ref, workspaceIdentityRef: ref, workspaceIdentityDigest: ref,
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, observedAt: '2026-10-18T00:00:00.000Z', proofDigest: '',
    observation: { location: { kind: 'workspace', path: 'file' }, state: { kind: 'file', mode: 0o600, digest: ref }, parentDeviceId: '1', parentFileId: '2', parentLinkCount: 2,
      entryDeviceId: '1', entryFileId: '3', entryLinkCount: 1 } };
  proof.proofDigest = digestOmitting(proof, 'proofDigest'); assert.deepEqual(decodePublicationProof(proof), proof);
  for (const mutate of [
    (copy: any) => { delete copy.observation.entryFileId; },
    (copy: any) => { copy.observation.state = { kind: 'absent' }; },
    (copy: any) => { copy.observation.state.authority = true; },
    (copy: any) => { copy.observation.parentDeviceId = '01'; },
    (copy: any) => { copy.observation.location.path = '../escape'; }
  ]) { const copy = structuredClone(proof); mutate(copy); copy.proofDigest = digestOmitting(copy, 'proofDigest'); assert.throws(() => decodePublicationProof(copy), TypeError); }
});

test('terminal ancestor projection absence is closed and names only a strict canonical workspace ancestor', () => {
  const ref = 'a'.repeat(64), proof = { schemaVersion: 1, format: 'cliq-publication-proof-v1', kind: 'ancestor_projection_absence',
    deliveryRunId: 'data-only-run', deliveryPlanRef: ref, workspaceIdentityRef: ref, workspaceIdentityDigest: ref,
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, observedAt: '2026-10-18T00:00:00.000Z', proofDigest: '',
    path: 'd/f', ancestorPath: 'd', ancestorObservationRef: ref };
  proof.proofDigest = digestOmitting(proof, 'proofDigest'); assert.deepEqual(decodePublicationProof(proof), proof);
  for (const change of [
    { path: 'd' }, { path: 'different/f' }, { path: 'distant/f' }, { path: '../d/f' }, { path: 'd//f' },
    { path: 'd/.git/f' }, { ancestorPath: '' }, { ancestorPath: 'd/f' }, { ancestorPath: 'd/f/child' },
    { ancestorObservationRef: 'not-an-artifact' }, { location: { kind: 'publication_arena', arenaId: identityHash('data'), component: 'slot' } },
    { parentDeviceId: '1' }, { parentLinkCount: 0 }, { cleanupAllowed: true }, { kind: 'ancestor_absence' }
  ]) {
    const altered = { ...proof, ...change }; altered.proofDigest = digestOmitting(altered, 'proofDigest');
    assert.throws(() => decodePublicationProof(altered), TypeError);
  }
  assert.throws(() => decodePublicationProof({ ...proof, proofDigest: 'b'.repeat(64) }), /digest/u);
  const accessor = { ...proof };
  Object.defineProperty(accessor, 'ancestorObservationRef', { enumerable: true, get() { assert.fail('absence decoder must not execute accessors'); } });
  assert.throws(() => decodePublicationProof(accessor), TypeError);
});

test('empty-directory preimages and terminal projections are closed self-digested data, never cleanup authority', () => {
  const ref = 'a'.repeat(64), preimage = { schemaVersion: 1, format: 'cliq-publication-directory-preimage-v1',
    deliveryRunId: 'data-only-run', deliveryPlanRef: ref, operationId: identityHash('data-only-operation'), opId: 'data-only-op', attempt: 1,
    beforeObservationRef: ref, quarantineObservationRef: 'b'.repeat(64), entriesRef: ref, preimageDigest: '' };
  preimage.preimageDigest = digestOmitting(preimage, 'preimageDigest');
  assert.deepEqual(decodePublicationDirectoryPreimage(preimage), preimage);
  const bad = { ...preimage, preserved: true }; bad.preimageDigest = digestOmitting(bad, 'preimageDigest');
  assert.throws(() => decodePublicationDirectoryPreimage(bad), TypeError);
  const projection = { schemaVersion: 1, deliveryRunId: 'data-only-run', deliveryPlanRef: ref, selectedBranch: 'forward_finalize', observedSourceRef: ref,
    observedPathStates: [{ path: 'p', state: { kind: 'absent' }, evidenceRef: ref }], forwardResultItemRefs: [ref], unstartedForwardOperationIds: [], abortResultItemRefs: [],
    transientAbsenceEvidenceRef: ref, projectionClosureEvidenceRef: ref, gitIndexUnchangedEvidenceRef: ref, observedAt: '2026-10-18T00:00:00.000Z', evidenceDigest: '' };
  projection.evidenceDigest = digestOmitting(projection, 'evidenceDigest');
  assert.deepEqual(decodeDeliveryTerminalProjectionEvidence(projection), projection);
  const notClosed = { ...projection, abortResultItemRefs: [ref] }; notClosed.evidenceDigest = digestOmitting(notClosed, 'evidenceDigest');
  assert.throws(() => decodeDeliveryTerminalProjectionEvidence(notClosed), TypeError);
});

test('publication data preserves Journal attempt zero and rejects invalid attempts in every carrying variant', async t => {
  const ref = 'a'.repeat(64), operationId = identityHash('attempt-zero-operation');
  const common = { schemaVersion: 1, itemId: 'data-only-item', runId: 'data-only-run', deliveryPlanRef: ref,
    operationIndex: 0, operationId, opId: 'data-only-op', attempt: 0, createdAt: '2026-10-18T00:00:00.000Z' };
  const proof = { schemaVersion: 1, format: 'cliq-publication-proof-v1', deliveryRunId: 'data-only-run', deliveryPlanRef: ref,
    workspaceIdentityRef: ref, workspaceIdentityDigest: ref, inspectorIdentityRef: ref, inspectorIdentityDigest: ref,
    observedAt: common.createdAt, proofDigest: '', sequence: 'forward', operationIndex: 0, operationId, opId: common.opId, attempt: 0 };
  const absent = { location: { kind: 'workspace', path: 'p' }, state: { kind: 'absent' }, parentDeviceId: '1', parentFileId: '2', parentLinkCount: 2 };
  const fixtures = [
    { name: 'progress', decode: decodePublicationPathProgressItem, value: { ...common, kind: 'publication_path_progress',
      state: 'desired_committed_cleanup_pending', beforeObservationRef: ref, destinationEvidenceRef: ref } },
    { name: 'result', decode: decodePublicationPathResultItem, value: { ...common, kind: 'publication_path_result',
      sequence: 'forward', outcome: 'completed', receiptRef: ref, evidenceRef: ref,
      retirement: { slotObservationRefs: ['b'.repeat(64)], arenaRetirementRef: 'c'.repeat(64) } } },
    { name: 'terminal receipt', decode: decodePublicationProof, digestField: 'proofDigest', value: { ...proof, kind: 'terminal_receipt',
      before: absent, after: absent, transientFinalObservations: [], parentIdentityBeforeDigest: ref, parentIdentityAfterDigest: ref,
      directoryFsyncCompleted: true } },
    { name: 'ambiguity', decode: decodePublicationProof, digestField: 'proofDigest', value: { ...proof, kind: 'path_ambiguity',
      launchDispatchId: 'data-only-dispatch', failure: 'descriptor_unreadable', lastKnownObservationRefs: [] } },
    { name: 'directory preimage', decode: decodePublicationDirectoryPreimage, digestField: 'preimageDigest', value: {
      schemaVersion: 1, format: 'cliq-publication-directory-preimage-v1', deliveryRunId: 'data-only-run', deliveryPlanRef: ref,
      operationId, opId: common.opId, attempt: 0, beforeObservationRef: ref, quarantineObservationRef: ref, entriesRef: ref, preimageDigest: '' } }
  ];
  for (const fixture of fixtures) await t.test(fixture.name, () => {
    const value: Record<string, unknown> = { ...fixture.value };
    if (fixture.digestField) value[fixture.digestField] = digestOmitting(value, fixture.digestField);
    assert.deepEqual(fixture.decode(value), value);
    for (const attempt of [-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, '0', null]) {
      const invalid = { ...value, attempt };
      assert.throws(() => fixture.decode(invalid), TypeError);
    }
  });
});

test('publication observations distinguish workspace paths from exact private arena components', () => {
  const ref = 'a'.repeat(64), base = { schemaVersion: 1, format: 'cliq-publication-proof-v1', deliveryRunId: 'data-only-run',
    deliveryPlanRef: ref, workspaceIdentityRef: ref, workspaceIdentityDigest: ref, inspectorIdentityRef: ref, inspectorIdentityDigest: ref,
    observedAt: '2026-10-18T00:00:00.000Z', proofDigest: '' };
  const locations = [{ kind: 'workspace', path: 'dir/file' },
    { kind: 'publication_arena', arenaId: identityHash('original-claim-arena'), component: '.desired' }];
  for (const location of locations) {
    const proof = { ...base, kind: 'path_observation', observation: { location, state: { kind: 'absent' },
      parentDeviceId: '1', parentFileId: '2', parentLinkCount: 2 } };
    proof.proofDigest = digestOmitting(proof, 'proofDigest'); assert.deepEqual(decodePublicationProof(proof), proof);
  }
  for (const location of [
    { kind: 'workspace', path: 'dir/file', arenaId: identityHash('extra') },
    { kind: 'publication_arena', arenaId: identityHash('original-claim-arena'), component: '../escape' },
    { kind: 'publication_arena', arenaId: 'guessed', component: '.desired' },
    { kind: 'publication_arena', arenaId: identityHash('original-claim-arena'), component: '.desired', path: 'dir/file' }
  ]) {
    const proof = { ...base, kind: 'path_observation', observation: { location, state: { kind: 'absent' },
      parentDeviceId: '1', parentFileId: '2', parentLinkCount: 2 } };
    proof.proofDigest = digestOmitting(proof, 'proofDigest'); assert.throws(() => decodePublicationProof(proof), TypeError);
  }
  const proof = { ...base, kind: 'transient_absence', transientLocations: [locations[1]], observationRefs: [ref], arenaRetirementRefs: [ref] };
  proof.proofDigest = digestOmitting(proof, 'proofDigest'); assert.deepEqual(decodePublicationProof(proof), proof);
});

test('arena birth data binds the original dispatch and actual private identity, not a successor epoch', () => {
  const ref = 'a'.repeat(64), operationId = identityHash('birth-operation');
  const birth = { schemaVersion: 1, format: 'cliq-publication-arena-birth-v1', deliveryRunId: 'data-only-run', deliveryPlanRef: ref,
    workspaceIdentityRef: ref, workspaceIdentityDigest: ref, stateRootIdentityRef: ref, stateRootIdentityDigest: ref,
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, sequence: 'forward', operationIndex: 0, operationId,
    opId: 'data-only-op', attempt: 0, dispatchId: 'original-dispatch', arenaId: publicationArenaId('data-only-run', operationId, 'data-only-op', 0, 'original-dispatch'),
    arenaIdentity: { deviceId: '1', fileId: '2', ownerUid: 501, mode: 0o700 }, parentIdentity: { deviceId: '1', fileId: '3', ownerUid: 501, mode: 0o700 },
    observedAt: '2026-10-18T00:00:00.000Z', birthDigest: '' };
  birth.birthDigest = digestOmitting(birth, 'birthDigest'); assert.deepEqual(decodePublicationArenaBirth(birth), birth);
  for (const mutate of [
    (value: any) => { value.arenaIdentity.mode = 0o755; },
    (value: any) => { value.dispatchId = 'different-dispatch'; },
    (value: any) => { value.attempt = -1; },
    (value: any) => { value.parentIdentity.mode = 0o755; },
    (value: any) => { value.stateOwnerEpoch = 2; },
    (value: any) => { value.arenaIdentity.path = '/guessed'; }
  ]) { const value = structuredClone(birth); mutate(value); value.birthDigest = digestOmitting(value, 'birthDigest'); assert.throws(() => decodePublicationArenaBirth(value), TypeError); }
  const accessor = { ...birth };
  Object.defineProperty(accessor, 'arenaIdentity', { enumerable: true, get() { assert.fail('birth decoder must not execute input accessors'); } });
  assert.throws(() => decodePublicationArenaBirth(accessor), TypeError);
});

test('private arena retirement proof is closed and cannot substitute an absence guess for a completed sync', () => {
  const ref = 'a'.repeat(64), proof = { schemaVersion: 1, format: 'cliq-publication-proof-v1', kind: 'arena_retirement',
    deliveryRunId: 'data-only-run', deliveryPlanRef: ref, workspaceIdentityRef: ref, workspaceIdentityDigest: ref,
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, observedAt: '2026-10-18T00:00:00.000Z', proofDigest: '',
    arenaId: identityHash('original-claim-arena'), stateRootIdentityRef: ref, stateRootIdentityDigest: ref,
    arenaIdentity: { deviceId: '1', fileId: '2', ownerUid: 501, mode: 448 }, parentIdentity: { deviceId: '1', fileId: '3', ownerUid: 501, mode: 448 },
    arenaAbsent: true, arenaParentFsyncCompleted: true, retirementObservation: { kind: 'linux_unlinked', linkCount: 0 } };
  proof.proofDigest = digestOmitting(proof, 'proofDigest'); assert.deepEqual(decodePublicationProof(proof), proof);
  for (const mutate of [
    (value: any) => { value.arenaAbsent = false; },
    (value: any) => { value.arenaParentFsyncCompleted = false; },
    (value: any) => { value.arenaIdentity.mode = 493; },
    (value: any) => { value.parentIdentity.deviceId = '2'; },
    (value: any) => { value.retirementObservation.linkCount = 2; },
    (value: any) => { value.retired = true; }
  ]) { const value = structuredClone(proof); mutate(value); value.proofDigest = digestOmitting(value, 'proofDigest'); assert.throws(() => decodePublicationProof(value), TypeError); }
  const darwin = { ...proof, retirementObservation: { kind: 'darwin_unlinked', heldPathUnchanged: true, parentPathUnchanged: true, observedLinkCount: 2 } };
  darwin.proofDigest = digestOmitting(darwin, 'proofDigest'); assert.deepEqual(decodePublicationProof(darwin), darwin);
  const mixed = { ...darwin, retirementObservation: { ...darwin.retirementObservation, linkCount: 0 } };
  mixed.proofDigest = digestOmitting(mixed, 'proofDigest'); assert.throws(() => decodePublicationProof(mixed), TypeError);
});
