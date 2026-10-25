import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, realpath, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { GitIndexSnapshotV1, SourceManifest } from '../kernel/types.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { loadNativeStateOwner } from './native-owner.js';
import { observePublicationGitIndex, readPublicationGitIndexObservation, readPublicationGitIndexClosure } from './publication-git-index.js';
import { captureLiveWorkspaceIdentity } from './workspace-identity.js';
import { normalizeGitIndex } from '../workspace/git-index.js';
import { decodePublicationProof } from '../kernel/publication.js';

test('publication index rejects structural physical handles and observation stand-ins without observing caller properties', async () => {
  let observed = 0; const fake = new Proxy({}, { get() { observed++; throw new Error('caller property executed'); } });
  assert.throws(() => readPublicationGitIndexObservation(fake as never), TypeError);
  await assert.rejects(observePublicationGitIndex(fake as never, fake as never, fake as never, fake as never), TypeError);
  assert.equal(observed, 0);
});

test('real fixed index read joins before canonical comparison and retains a physical fact without granting publication', async () => {
  // Owned ordinary descriptors/data only: no SQL StateOwner, Session, Run,
  // source receipt, publication task, approval, claim or execution is created.
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'publication-index-data-'));
  const state = path.join(directory, 'state'), workspace = path.join(directory, 'workspace'), cas = path.join(directory, 'cas');
  for (const name of [state, workspace, cas, path.join(workspace, '.git')]) await mkdir(name, { mode: 0o700 });
  const header = Buffer.from('444952430000000200000000', 'hex');
  const canonical = Buffer.concat([header, createHash('sha1').update(header).digest()]);
  const extension = Buffer.alloc(8), cache = Buffer.from('own optional cache'); extension.write('TREE'); extension.writeUInt32BE(cache.length, 4);
  const rawBody = Buffer.concat([header, extension, cache]), raw = Buffer.concat([rawBody, createHash('sha1').update(rawBody).digest()]);
  await writeFile(path.join(workspace, '.git/index'), raw, { mode: 0o600 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  try {
    const artifacts = new ArtifactCatalog(new ContentAddressedStore(cas));
    const captured = await captureLiveWorkspaceIdentity({ workspacePath: workspace, ownerPrincipalId: 'own-publication-index-data' });
    assert(captured.repository);
    const repo = (await artifacts.publishCanonical(captured.repository, captured.repository.format)).ref;
    const identity = { ...captured.identity, repositoryIdentityRef: repo, identityDigest: '' };
    identity.identityDigest = digestOmitting(identity, 'identityDigest');
    const indexBytes = await artifacts.publishBytes(canonical, 'application/octet-stream', 'cliq-git-index-bytes-v1');
    const normalized = normalizeGitIndex(canonical, 'sha1', { maxBytes: DEFAULT_SANDBOX_RESOURCES.maxSingleFileBytes, maxEntries: 100_000 });
    const index: GitIndexSnapshotV1 = { schemaVersion: 1, format: 'cliq-git-index-snapshot-v1',
      repositoryIdentityDigest: captured.repository.repositoryIdentityDigest, objectFormat: 'sha1', canonicalIndexVersion: 2, entries: [],
      canonicalIndexBytesRef: indexBytes.ref, canonicalIndexBytesDigest: indexBytes.ref, canonicalIndexByteCount: canonical.length,
      indexTreeObjectId: normalized.indexTreeObjectId, snapshotDigest: '' };
    index.snapshotDigest = digestOmitting(index, 'snapshotDigest'); const indexRef = (await artifacts.publishCanonical(index, index.format)).ref;
    const source: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role: 'base', workspaceIdentityDigest: identity.identityDigest,
      entriesRef: 'a'.repeat(64), sourceProjectionRef: 'b'.repeat(64), sourceProjectionDigest: 'c'.repeat(64), frozenIgnoreRulesRef: 'd'.repeat(64),
      frozenIgnoreRulesDigest: 'e'.repeat(64), treeDigest: 'f'.repeat(64), git: { repositoryIdentityDigest: index.repositoryIdentityDigest,
        head: { kind: 'unborn', branch: 'main' }, indexRef, indexTreeObjectId: index.indexTreeObjectId }, manifestDigest: '' };
    source.manifestDigest = digestOmitting(source, 'manifestDigest'); const sourceRef = (await artifacts.publishCanonical(source, source.format)).ref;
    const input = { workspace: identity, capturedSourceRef: sourceRef, resources: DEFAULT_SANDBOX_RESOURCES };
    const fact = await observePublicationGitIndex(lock, root, artifacts, input), observed = readPublicationGitIndexObservation(fact);
    assert.equal(observed.repositoryKind, 'git');
    if (observed.repositoryKind !== 'git') assert.fail('actual Git index must use its closed branch');
    assert.equal(observed.observedIndex.kind, 'present');
    if (observed.observedIndex.kind !== 'present') assert.fail('actual existing index must retain its genuine file identity');
    assert.equal(observed.observedIndex.rawBytesDigest, sha256Bytes(raw));
    assert.notEqual(observed.observedIndex.rawBytesDigest, observed.canonicalIndexBytesRef);
    assert.equal(observed.canonicalIndexBytesRef, indexBytes.ref); assert.equal(observed.observedIndex.rawByteCount, raw.length);
    const proof = { ...observed, schemaVersion: 1 as const, format: 'cliq-publication-proof-v1' as const,
      deliveryRunId: 'own-data', deliveryPlanRef: '0'.repeat(64), workspaceIdentityRef: canonicalSha256(identity), workspaceIdentityDigest: identity.identityDigest,
      inspectorIdentityRef: '1'.repeat(64), inspectorIdentityDigest: '2'.repeat(64), observedAt: '2026-10-08T00:00:00.000Z', proofDigest: '' };
    proof.proofDigest = digestOmitting(proof, 'proofDigest');
    await readPublicationGitIndexClosure(artifacts, proof, input);
    const bad = { ...proof, capturedIndexDigest: '3'.repeat(64), observedIndexDigest: '3'.repeat(64), proofDigest: '' }; bad.proofDigest = digestOmitting(bad, 'proofDigest');
    await assert.rejects(readPublicationGitIndexClosure(artifacts, bad, input), { code: 'ARTIFACT_MISMATCH' });
    await unlink(path.join(workspace, '.git/index'));
    const missing = readPublicationGitIndexObservation(await observePublicationGitIndex(lock, root, artifacts, input));
    assert.equal(missing.repositoryKind, 'git');
    if (missing.repositoryKind !== 'git') assert.fail('missing canonical-empty Git index remains a Git observation');
    assert.deepEqual(missing.observedIndex, { kind: 'absent', rawByteCount: 0 });
    const absenceProof = { ...proof, ...missing, proofDigest: '' }; absenceProof.proofDigest = digestOmitting(absenceProof, 'proofDigest');
    decodePublicationProof(absenceProof); await readPublicationGitIndexClosure(artifacts, absenceProof, input);
    const inventedFd = { ...absenceProof, observedIndex: { ...missing.observedIndex, fileId: '12' }, proofDigest: '' };
    inventedFd.proofDigest = digestOmitting(inventedFd, 'proofDigest'); assert.throws(() => decodePublicationProof(inventedFd), TypeError);
    const entry = Buffer.alloc(64); entry.writeUInt32BE(0o100644, 24); createHash('sha1').update('blob 1\0x').digest().copy(entry, 40); entry.writeUInt16BE(1, 60); entry.write('a', 62);
    const nonemptyHeader = Buffer.from(header); nonemptyHeader.writeUInt32BE(1, 8); const body = Buffer.concat([nonemptyHeader, entry]);
    const changedBytes = Buffer.concat([body, createHash('sha1').update(body).digest()]);
    await writeFile(path.join(workspace, '.git/index'), changedBytes, { mode: 0o600 });
    await assert.rejects(observePublicationGitIndex(lock, root, artifacts, input), { code: 'ARTIFACT_MISMATCH' });
    const changed = normalizeGitIndex(changedBytes, 'sha1', { maxBytes: DEFAULT_SANDBOX_RESOURCES.maxSingleFileBytes, maxEntries: 100_000 });
    const changedRaw = await artifacts.publishBytes(changed.canonicalBytes, 'application/octet-stream', 'cliq-git-index-bytes-v1');
    const changedIndex = { ...index, entries: changed.entries, canonicalIndexBytesRef: changedRaw.ref, canonicalIndexBytesDigest: changedRaw.ref,
      canonicalIndexByteCount: changed.canonicalBytes.length, indexTreeObjectId: changed.indexTreeObjectId, snapshotDigest: '' };
    changedIndex.snapshotDigest = digestOmitting(changedIndex, 'snapshotDigest');
    const changedRef = (await artifacts.publishCanonical(changedIndex, changedIndex.format)).ref;
    const changedSource = { ...source, git: { ...source.git!, indexRef: changedRef, indexTreeObjectId: changed.indexTreeObjectId }, manifestDigest: '' };
    changedSource.manifestDigest = digestOmitting(changedSource, 'manifestDigest');
    const changedSourceRef = (await artifacts.publishCanonical(changedSource, changedSource.format)).ref;
    await unlink(path.join(workspace, '.git/index'));
    await assert.rejects(observePublicationGitIndex(lock, root, artifacts, { ...input, capturedSourceRef: changedSourceRef }), { code: 'ARTIFACT_MISMATCH' });
    const wrongAbsence = { ...absenceProof, capturedSourceRef: changedSourceRef, capturedIndexRef: changedRef, capturedIndexDigest: changedIndex.snapshotDigest,
      observedIndexRef: changedRef, observedIndexDigest: changedIndex.snapshotDigest,
      canonicalIndexBytesRef: changedRaw.ref, canonicalIndexByteCount: changedIndex.canonicalIndexByteCount,
      indexTreeObjectId: changedIndex.indexTreeObjectId, proofDigest: '' };
    wrongAbsence.proofDigest = digestOmitting(wrongAbsence, 'proofDigest');
    await assert.rejects(readPublicationGitIndexClosure(artifacts, wrongAbsence, { ...input, capturedSourceRef: changedSourceRef }), { code: 'ARTIFACT_MISMATCH' });
    // A rejected canonical comparison has still joined its original reader.
    root.assertHeld(); lock.assertHeld();
  } finally { root.close(); lock.close(); await rm(directory, { recursive: true, force: true }); }
});
