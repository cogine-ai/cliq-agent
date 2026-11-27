// Association checks only. These inert records mint no original owner,
// native retirement, retained full-R graph, cleanup permission or Run result.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, open, realpath, rm, writeFile } from 'node:fs/promises';
import { Module } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { decodePublicationArenaBirth, decodePublicationProof, publicationArenaId } from '../kernel/publication.js';
import { assertPublicationReconciledRetirement, readOwnedPublicationReconciledRetirement } from './publication-invocation.js';
import type { RetainedPublicationOperation } from './delivery-publication-progress.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { decodePublicationProbeEvidence } from './publication-reconciliation-artifacts.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { loadHeldStateOwnerImage, openHeldPublicationOperation, readHeldPublicationBirth, readRetiredPublicationArena } from './native-owner.js';

function data() {
  const ref = 'a'.repeat(64), at = '2026-10-19T00:00:01.000Z', operationId = identityHash('retired-data-operation');
  const operation = { kind: 'create' as const, index: 0, operationId, path: 'file', parent: { kind: 'captured_directory' as const, path: '' },
    expected: { kind: 'absent' as const }, desired: { kind: 'file' as const, mode: 0o644, digest: ref }, stagingName: 'desired' };
  const source = { schemaVersion: 1, format: 'cliq-publication-arena-birth-v1', deliveryRunId: 'data-only-run', deliveryPlanRef: ref,
    workspaceIdentityRef: ref, workspaceIdentityDigest: ref, stateRootIdentityRef: ref, stateRootIdentityDigest: ref,
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, sequence: 'forward', operationIndex: 0, operationId,
    opId: 'data-only-op', attempt: 0, dispatchId: 'data-only-dispatch',
    arenaId: publicationArenaId('data-only-run', operationId, 'data-only-op', 0, 'data-only-dispatch'),
    arenaIdentity: { deviceId: '1', fileId: '2', ownerUid: 501, mode: 448 }, parentIdentity: { deviceId: '1', fileId: '3', ownerUid: 501, mode: 448 },
    observedAt: at, birthDigest: '' };
  source.birthDigest = digestOmitting(source, 'birthDigest');
  const birth = decodePublicationArenaBirth(source), observation = { location: { kind: 'workspace', path: 'file' },
    state: { kind: 'absent' }, parentDeviceId: '1', parentFileId: '4', parentLinkCount: 2 };
  const proof = { schemaVersion: 1, format: 'cliq-publication-proof-v1', kind: 'terminal_receipt', deliveryRunId: source.deliveryRunId,
    deliveryPlanRef: ref, workspaceIdentityRef: ref, workspaceIdentityDigest: ref, inspectorIdentityRef: ref, inspectorIdentityDigest: ref,
    observedAt: at, proofDigest: '', sequence: 'forward', operationIndex: 0, operationId, opId: source.opId, attempt: 0,
    before: observation, after: observation, transientFinalObservations: [{ ...observation,
      location: { kind: 'publication_arena', arenaId: birth.arenaId, component: 'desired' } }],
    parentIdentityBeforeDigest: ref, parentIdentityAfterDigest: ref, directoryFsyncCompleted: true };
  proof.proofDigest = digestOmitting(proof, 'proofDigest');
  const evidence = decodePublicationProof(proof), evidenceRef = canonicalSha256(evidence);
  const prepared = { runId: source.deliveryRunId, opId: source.opId, seq: 1, phase: 'prepared', opKind: 'publish', attempt: 0,
    leaseEpoch: 1, target: ref, requestRef: ref, grantRef: ref, replayClass: 'reconcile', timestamp: at,
    budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 } };
  const claim = { ...prepared, seq: 2, phase: 'dispatch_claimed', dispatchId: source.dispatchId, evidenceRef: canonicalSha256(birth) };
  const unknown = { ...claim, seq: 3, phase: 'unknown', evidenceRef: 'b'.repeat(64) };
  const terminal = { ...claim, seq: 4, phase: 'completed', evidenceRef, receiptRef: evidenceRef, evidenceDigest: evidence.proofDigest };
  const wrapperData = { schemaVersion: 1, format: 'cliq-reconciliation-probe-evidence-v1', runId: source.deliveryRunId,
    waitingSubjectRef: ref, waitingSubjectDigest: ref, probeKind: 'automatic', probeOrdinal: 1, probeNonceDigest: ref,
    probeDispatchDigest: ref, probeStartedAt: at, probeDeadlineAt: '2026-10-19T00:00:31.000Z',
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, outcome: 'subject_observation', subjectEvidenceKind: 'publication',
    subjectEvidenceRef: evidenceRef, subjectEvidenceDigest: evidence.proofDigest, observedAt: at, evidenceDigest: '' };
  wrapperData.evidenceDigest = digestOmitting(wrapperData, 'evidenceDigest');
  const wrapper = decodePublicationProbeEvidence(wrapperData);
  if (wrapper.outcome !== 'subject_observation') assert.fail('data fixture changed its fixed observation kind');
  const retirement = { slotObservationRefs: ['d'.repeat(64)], arenaRetirementRef: 'e'.repeat(64) };
  const retired = { disposition: 'received', planRef: ref, operation, prepared, claim, birth, unknownEvidenceRef: unknown.evidenceRef, evidence, evidenceRef,
    wrapper, wrapperRef: canonicalSha256(wrapper), retirement, metadata: [] };
  const result = { item: { outcome: 'completed', evidenceRef, receiptRef: evidenceRef, retirement,
    reconciliationEvidenceRef: retired.wrapperRef, reconciliationEvidenceDigest: wrapper.evidenceDigest } };
  return { entry: structuredClone({ planRef: ref, operation, prepared, claim, birth, history: [prepared, claim, unknown, terminal], result }),
    retired: structuredClone(retired) };
}

test('a retired original owner matches only its actual resolved probe result without rewriting the UNKNOWN', () => {
  const { entry, retired } = data(), before = structuredClone(entry);
  assert.doesNotThrow(() => assertPublicationReconciledRetirement(entry as unknown as RetainedPublicationOperation, retired as never));
  assert.deepEqual(entry, before);
  assert.equal(entry.history[2]!.phase, 'unknown');
});

test('a genuinely joined stopped-before-effect association remains failed, never a successful receipt', () => {
  const { entry, retired } = data();
  if (retired.evidence.kind !== 'terminal_receipt') assert.fail('data fixture changed its fixed receipt');
  const { sequence: _sequence, operationIndex: _index, operationId: _operationId, opId: _opId, attempt: _attempt,
    before, after: _after, transientFinalObservations: _slots, parentIdentityBeforeDigest: _parentBefore,
    parentIdentityAfterDigest: _parentAfter, directoryFsyncCompleted: _sync, ...base } = retired.evidence;
  const proof = { ...base, kind: 'path_observation', observation: before, proofDigest: '' };
  proof.proofDigest = digestOmitting(proof, 'proofDigest');
  const evidence = decodePublicationProof(proof), evidenceRef = canonicalSha256(evidence);
  const wrapper = { ...retired.wrapper, subjectEvidenceRef: evidenceRef, subjectEvidenceDigest: evidence.proofDigest, evidenceDigest: '' };
  wrapper.evidenceDigest = digestOmitting(wrapper, 'evidenceDigest');
  const actual = { ...retired, disposition: 'stopped_before_effect', evidence, evidenceRef, wrapper, wrapperRef: canonicalSha256(wrapper) };
  const { receiptRef: _receipt, ...result } = entry.result.item;
  const { receiptRef: _terminalReceipt, ...terminal } = entry.history.at(-1)! as typeof entry.history[number] & { receiptRef?: string };
  const selected = { ...entry, history: [...entry.history.slice(0, -1), { ...terminal, phase: 'failed', evidenceRef, evidenceDigest: evidence.proofDigest }],
    result: { item: { ...result, outcome: 'failed', evidenceRef,
      reconciliationEvidenceRef: actual.wrapperRef, reconciliationEvidenceDigest: wrapper.evidenceDigest } } };
  assert.doesNotThrow(() => assertPublicationReconciledRetirement(selected as unknown as RetainedPublicationOperation, actual as never));
  assert.throws(() => assertPublicationReconciledRetirement(selected as unknown as RetainedPublicationOperation,
    { ...actual, disposition: 'received' } as never));
});

test('unresolved, late-only and substituted retirement data cannot close an original UNKNOWN owner', () => {
  const original = data();
  for (const mutate of [
    (value: ReturnType<typeof data>) => { value.entry.result.item.outcome = 'unknown'; },
    (value: ReturnType<typeof data>) => { delete (value.entry as Partial<typeof value.entry>).result; },
    (value: ReturnType<typeof data>) => { value.entry.history.pop(); },
    (value: ReturnType<typeof data>) => { value.retired.unknownEvidenceRef = 'f'.repeat(64); },
    (value: ReturnType<typeof data>) => { value.entry.claim.dispatchId = 'foreign-claim'; },
    (value: ReturnType<typeof data>) => { value.entry.birth.arenaIdentity.fileId = '99'; },
    (value: ReturnType<typeof data>) => { value.entry.result.item.evidenceRef = 'f'.repeat(64); },
    (value: ReturnType<typeof data>) => { value.entry.result.item.receiptRef = 'f'.repeat(64); },
    (value: ReturnType<typeof data>) => { value.entry.result.item.reconciliationEvidenceRef = 'f'.repeat(64); },
    (value: ReturnType<typeof data>) => { value.entry.result.item.reconciliationEvidenceDigest = 'f'.repeat(64); },
    (value: ReturnType<typeof data>) => { value.entry.result.item.retirement.arenaRetirementRef = 'f'.repeat(64); },
    (value: ReturnType<typeof data>) => { value.entry.result.item.retirement.slotObservationRefs = ['f'.repeat(64)]; },
    (value: ReturnType<typeof data>) => { value.retired.wrapper.subjectEvidenceRef = 'f'.repeat(64); },
    (value: ReturnType<typeof data>) => { value.retired.wrapper.probeDeadlineAt = '2026-10-19T00:00:00.000Z'; },
  ]) {
    const value = structuredClone(original); mutate(value);
    assert.throws(() => assertPublicationReconciledRetirement(value.entry as unknown as RetainedPublicationOperation, value.retired as never));
  }
});

test('a structural archived retirement is rejected before storage, catalog or retained-entry getters', () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('no structural owner may read SQL'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'readCanonical', { get() { assert.fail('no structural owner may read CAS'); } }) as ArtifactCatalog;
  const entry = Object.defineProperty({}, 'prepared', { get() { assert.fail('the original owner brand must precede retained data'); } });
  for (const token of [{}, Object.defineProperty({}, 'retirement', { get() { assert.fail('must not read caller retirement data'); } })])
    assert.throws(() => readOwnedPublicationReconciledRetirement(driver, artifacts, {} as StateOwnerContext, {}, token, entry as never),
      /exact original invocation owner/);
});

test('the actual original lost-ACK operation has no retirement fact until cleanup, arena retirement and descriptor join all complete', async t => {
  // The approved real native filesystem seam, not a StateOwner context, Run,
  // Journal, installation, probe result or authority fixture.
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-reconciled-retirement-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const binary = path.join(directory, 'fault.node'), state = path.join(directory, 'state'), workspace = path.join(directory, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  const includes = JSON.parse(execFileSync(process.execPath,
    [fileURLToPath(new URL('../../scripts/kernel/build-state-owner-native.mjs', import.meta.url)), '--print-includes'], { encoding: 'utf8' })) as string[];
  const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
    ...(process.platform === 'linux' ? ['-shared', '-fPIC'] : ['-bundle', '-undefined', 'dynamic_lookup']),
    ...includes.flatMap(include => ['-I', include]), fileURLToPath(new URL('./testing/publication-fault-native.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
  assert.equal(compiled.status, 0, compiled.stderr); await chmod(binary, 0o500);
  const image = await open(binary);
  const native = await loadHeldStateOwnerImage(image).finally(() => image.close());
  const module = new Module(binary); process.dlopen(module, binary);
  const fault = module.exports as { setFault(point: string, ordinal: number, callback: () => number): void };
  const lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  let operation: ReturnType<typeof openHeldPublicationOperation> | undefined;
  try {
    await writeFile(path.join(workspace, 'file'), 'old', { mode: 0o600 });
    const old = await lstat(path.join(workspace, 'file')), digest = (text: string) => createHash('sha256').update(text).digest('hex');
    operation = openHeldPublicationOperation(lock, root, { arenaId: identityHash('retirement-lost-ack'), kind: 'replace', path: 'file',
      parents: [{ ...root.identity, mode: root.mode }], expected: { kind: 'file', mode: 0o600, byteCount: 3, digest: digest('old') },
      desired: { kind: 'file', mode: 0o644, byteCount: 3, digest: digest('new') }, stagingName: 'desired', quarantineName: 'preimage' });
    const birth = readHeldPublicationBirth(lock, operation);
    while (operation.readOriginalChunk() !== null) {} operation.arm(); operation.stage(); operation.writeChunk(Buffer.from('new'));
    while (!operation.finishStage()) {}
    fault.setFault('after_rename', 1, () => 5); assert.throws(() => operation!.commit()); operation.revoke();
    assert.equal(operation.inspectState(), 'effect_present');
    assert.equal(operation.reconcile(), 'committed');
    assert.equal((await lstat(path.join(state, 'runtime', 'publications', birth.arenaId, 'preimage'))).ino, old.ino);
    while (operation.readDestinationChunk() !== null) {} while (operation.readPreimageChunk() !== null) {}
    operation.finishCleanup();
    assert.throws(() => readRetiredPublicationArena(lock, operation!), { code: 'RECOVERY_REQUIRED' });
    operation.finishArenaRetirement();
    assert.throws(() => readRetiredPublicationArena(lock, operation!), { code: 'RECOVERY_REQUIRED' });
    operation.close();
    const retired = readRetiredPublicationArena(lock, operation);
    assert.deepEqual(retired.arenaIdentity, birth.arenaIdentity);
    assert.deepEqual(retired.parentIdentity, birth.parentIdentity);
    assert.deepEqual(readRetiredPublicationArena(lock, operation), retired);
    // Actual joined CAS failure after the real native close cannot turn that
    // physical fact back into an open descriptor or another semantic attempt.
    // This is still not a Run/probe/archived-owner positive qualification.
    const objects = path.join(directory, 'objects'), catalog = new ArtifactCatalog(new ContentAddressedStore(objects));
    await assert.rejects(catalog.publishCanonical(retired, 'retired-native-data'), error => error instanceof Error &&
      error.cause instanceof Error && 'code' in error.cause && error.cause.code === 'ENOENT');
    assert.deepEqual(readRetiredPublicationArena(lock, operation), retired);
    await mkdir(objects, { mode: 0o700 });
    const artifact = await catalog.publishCanonical(retired, 'retired-native-data');
    assert.deepEqual(await catalog.readCanonical(artifact.ref), retired);
    assert.throws(() => operation!.arm()); assert.throws(() => operation!.commit());
  } finally { operation?.close(); root.close(); lock.close(); }
});
