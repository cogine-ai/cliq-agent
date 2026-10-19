// Real CAS retained-data checks only. These fixtures create no StateOwner,
// native observation, Run, Journal authority, permission or cleanup proof.
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { publicationArenaId, type PublicationActualPreimageV1, type PublicationArenaBirthV1, type PublicationOperation,
  type PublicationProofV1 } from '../kernel/publication.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { readPublicationActualPreimage } from './publication-actual-preimage.js';

async function fixture(t: TestContext, bytes = Buffer.alloc(65536 + 17, 0xff)) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-actual-preimage-data-')), root = path.join(directory, 'cas');
  await mkdir(root, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true, force: true }));
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root)), ref = 'a'.repeat(64), runId = 'data-only-run', opId = 'data-only-op';
  const operation: PublicationOperation = { kind: 'replace', index: 0, operationId: identityHash('actual-preimage-data-operation'),
    path: 'file', parent: { kind: 'existing_directory', expectedIdentityDigest: ref }, expected: { kind: 'file', mode: 0o600, digest: ref },
    desired: { kind: 'file', mode: 0o644, digest: ref }, stagingName: '.stage', stagingExpected: { kind: 'absent' },
    quarantineName: '.old', quarantineExpected: { kind: 'absent' } };
  const birth: PublicationArenaBirthV1 = { schemaVersion: 1, format: 'cliq-publication-arena-birth-v1', deliveryRunId: runId,
    deliveryPlanRef: ref, workspaceIdentityRef: ref, workspaceIdentityDigest: ref, stateRootIdentityRef: ref, stateRootIdentityDigest: ref,
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, sequence: 'forward', operationIndex: 0, operationId: operation.operationId,
    opId, attempt: 0, dispatchId: 'data-only-dispatch', arenaId: publicationArenaId(runId, operation.operationId, opId, 0, 'data-only-dispatch'),
    arenaIdentity: { deviceId: '1', fileId: '2', ownerUid: 501, mode: 448 }, parentIdentity: { deviceId: '1', fileId: '1', ownerUid: 501, mode: 448 },
    observedAt: '2026-10-18T00:00:00.000Z', birthDigest: '' };
  birth.birthDigest = digestOmitting(birth, 'birthDigest'); const born = await artifacts.publishCanonical(birth, birth.format);
  const raw = await artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-workspace-file-v1');
  const data: PublicationActualPreimageV1 = { schemaVersion: 1, format: 'cliq-publication-actual-preimage-v1', deliveryRunId: runId,
    deliveryPlanRef: ref, sequence: 'forward', operationIndex: 0, operationId: operation.operationId, opId, attempt: 0,
    dispatchId: birth.dispatchId, arenaBirthRef: born.ref, location: { kind: 'publication_arena', arenaId: birth.arenaId, component: '.stage' },
    physical: { identity: { deviceId: '1', fileId: '3', ownerUid: 501 }, mode: 0o600, linkCount: 1, byteCount: String(bytes.length) },
    payload: { kind: 'file', bytesRef: raw.ref, bytesDigest: raw.ref, byteCount: bytes.length }, preimageDigest: '' };
  data.preimageDigest = digestOmitting(data, 'preimageDigest'); const wrapper = await artifacts.publishCanonical(data, data.format);
  const proof: Extract<PublicationProofV1, { kind: 'path_ambiguity' }> = { schemaVersion: 1, format: 'cliq-publication-proof-v1',
    kind: 'path_ambiguity', deliveryRunId: runId, deliveryPlanRef: ref, workspaceIdentityRef: ref, workspaceIdentityDigest: ref,
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, observedAt: '2026-10-18T00:00:01.000Z', proofDigest: '',
    sequence: 'forward', operationIndex: 0, operationId: operation.operationId, opId, attempt: 0, launchDispatchId: birth.dispatchId,
    failure: 'transient_state_ambiguous', lastKnownObservationRefs: [], preservedActualPreimageRef: wrapper.ref };
  proof.proofDigest = digestOmitting(proof, 'proofDigest');
  const binding = { birth, operation, claim: { phase: 'dispatch_claimed' as const, runId, opId, attempt: 0, dispatchId: birth.dispatchId,
    evidenceRef: born.ref, evidenceDigest: birth.birthDigest } };
  const publish = async (value: PublicationActualPreimageV1) => {
    value.preimageDigest = digestOmitting(value, 'preimageDigest'); const artifact = await artifacts.publishCanonical(value, value.format);
    const selected = { ...proof, preservedActualPreimageRef: artifact.ref }; selected.proofDigest = digestOmitting(selected, 'proofDigest');
    return selected;
  };
  return { artifacts, root, data, proof, binding, raw, publish };
}

test('unknown actual-preimage data rehashes the full real CAS payload without becoming completion evidence', async t => {
  const f = await fixture(t);
  assert.deepEqual(await readPublicationActualPreimage(f.artifacts, f.proof, f.binding), f.data);
  assert.equal(f.proof.kind, 'path_ambiguity'); assert.equal(f.binding.claim.phase, 'dispatch_claimed');
});

test('actual-preimage data cannot substitute its original claim, birth, operation, owner or private slot', async t => {
  const f = await fixture(t, Buffer.from('bad'));
  for (const change of [
    { deliveryRunId: 'different-run' }, { deliveryPlanRef: 'b'.repeat(64) }, { operationIndex: 1 },
    { operationId: identityHash('different-operation') }, { opId: 'different-op' }, { attempt: 1 },
    { dispatchId: 'different-dispatch' }, { arenaBirthRef: 'b'.repeat(64) },
    { location: { ...f.data.location, component: '.foreign' } },
    { physical: { ...f.data.physical, identity: { ...f.data.physical.identity, deviceId: '2' } } },
    { physical: { ...f.data.physical, identity: { ...f.data.physical.identity, ownerUid: 502 } } }
  ]) {
    const copy = { ...f.data, ...change };
    copy.location = { ...copy.location, arenaId: publicationArenaId(copy.deliveryRunId, copy.operationId, copy.opId, copy.attempt, copy.dispatchId) };
    await assert.rejects(readPublicationActualPreimage(f.artifacts, await f.publish(copy), f.binding), /actual preimage/u);
  }
  for (const change of [ { phase: 'completed' }, { runId: 'other' }, { opId: 'other' }, { attempt: 1 },
    { dispatchId: 'other' }, { evidenceRef: 'b'.repeat(64) }, { evidenceDigest: 'b'.repeat(64) } ]) {
    await assert.rejects(readPublicationActualPreimage(f.artifacts, f.proof,
      { ...f.binding, claim: { ...f.binding.claim, ...change } } as typeof f.binding));
  }
  const altered = { ...f.binding.birth, inspectorIdentityRef: 'b'.repeat(64) };
  altered.birthDigest = digestOmitting(altered, 'birthDigest');
  await assert.rejects(readPublicationActualPreimage(f.artifacts, f.proof, { ...f.binding, birth: altered }), /original retained birth/u);
  const otherOperation = { ...f.binding.operation, operationId: identityHash('other') };
  await assert.rejects(readPublicationActualPreimage(f.artifacts, f.proof, { ...f.binding, operation: otherOperation }), /original displaced-operation/u);
  await assert.rejects(readPublicationActualPreimage(f.artifacts, f.proof, { ...f.binding, birth: undefined }), /original displaced-operation/u);
  const invalidOwner = { ...f.proof, inspectorIdentityRef: 'b'.repeat(64) };
  invalidOwner.proofDigest = digestOmitting(invalidOwner, 'proofDigest');
  await assert.rejects(readPublicationActualPreimage(f.artifacts, invalidOwner, f.binding), /original claim, private birth or native owner/u);
});

test('actual-preimage reads do not accept a matching prefix when later CAS bytes are corrupt', async t => {
  const f = await fixture(t), file = path.join(f.root, f.raw.ref);
  const bad = Buffer.alloc(65536 + 17, 0xff); bad[bad.length - 1] = 0;
  await chmod(file, 0o600); await writeFile(file, bad); await chmod(file, 0o400);
  await assert.rejects(readPublicationActualPreimage(f.artifacts, f.proof, f.binding), { message: `artifact ${f.raw.ref} is corrupt` });
});

test('raw symlink bytes and empty files are preserved as data without UTF-8 or NFC interpretation', async t => {
  const raw = await fixture(t, Buffer.from([47, 255, 47, 101, 204, 129]));
  const symlink: PublicationActualPreimageV1 = { ...raw.data, physical: { ...raw.data.physical, mode: 0o777 },
    payload: { kind: 'symlink', bytesRef: raw.raw.ref, bytesDigest: raw.raw.ref, byteCount: 6 } };
  const decoded = await readPublicationActualPreimage(raw.artifacts, await raw.publish(symlink), raw.binding);
  assert.deepEqual(decoded, symlink);
  const empty = await fixture(t, Buffer.alloc(0));
  assert.deepEqual(await readPublicationActualPreimage(empty.artifacts, empty.proof, empty.binding), empty.data);
});

test('an actual empty-directory payload requires the complete canonical empty entries artifact', async t => {
  const f = await fixture(t, Buffer.from('bad'));
  const entries = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: [] as unknown[], entryCount: 0, byteCount: 0,
    treeDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: [] }) };
  const artifact = await f.artifacts.publishCanonical(entries, entries.format);
  const data: PublicationActualPreimageV1 = { ...f.data, physical: { ...f.data.physical, mode: 0o700, linkCount: 2, byteCount: '64' },
    payload: { kind: 'empty_directory', entriesRef: artifact.ref } };
  assert.deepEqual(await readPublicationActualPreimage(f.artifacts, await f.publish(data), f.binding), data);
  const present = [{ path: 'retained-child', kind: 'file', mode: 0o644, size: 3, blobRef: f.raw.ref }];
  const nonempty = { ...entries, entries: present, entryCount: 1, byteCount: 3,
    treeDigest: canonicalSha256({ schemaVersion: 1, format: entries.format, entries: present }) };
  const wrong = await f.artifacts.publishCanonical(nonempty, entries.format);
  await assert.rejects(readPublicationActualPreimage(f.artifacts, await f.publish({ ...data,
    payload: { kind: 'empty_directory', entriesRef: wrong.ref } }), f.binding), /not empty/u);
  const missing = await f.publish({ ...data, payload: { kind: 'empty_directory', entriesRef: 'b'.repeat(64) } });
  await assert.rejects(readPublicationActualPreimage(f.artifacts, missing, f.binding));
});

test('unknown without complete preservation stays unknown, while cancellation and malformed CAS propagate unchanged', async t => {
  const f = await fixture(t, Buffer.from('bad'));
  const { preservedActualPreimageRef: _ref, ...without } = f.proof;
  without.proofDigest = digestOmitting(without, 'proofDigest');
  assert.equal(await readPublicationActualPreimage(f.artifacts, without, f.binding), undefined);
  const controller = new AbortController(), reason = new Error('original reader closed'); controller.abort(reason);
  await assert.rejects(readPublicationActualPreimage(f.artifacts.withReadSignal(controller.signal), f.proof, f.binding), error => error === reason);
  const malformed = await f.artifacts.publishBytes(Buffer.from(JSON.stringify(f.data, null, 2)), 'application/json', f.data.format);
  const proof = { ...f.proof, preservedActualPreimageRef: malformed.ref }; proof.proofDigest = digestOmitting(proof, 'proofDigest');
  await assert.rejects(readPublicationActualPreimage(f.artifacts, proof, f.binding), /canonical JSON/u);
});
