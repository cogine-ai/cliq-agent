// Existing real StateStore/CAS seam. All model and quiescence facts below reuse
// the offline fixture; no filesystem capture, native death or installation is qualified.
import assert from 'node:assert/strict';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, sha256Bytes } from '../kernel/identity.js';
import type { FinalCandidateItem, RunResult, SourceManifest, SourceProjectionSpec, WorkspaceDiffV1, WorkspaceEntry,
  WorkspaceEntryManifest, WorkspaceStateManifest } from '../kernel/types.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { CandidateSourceLimitError } from './result-source.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { activateFixtureWorker, admissionKey, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;

async function sourceFixture(label: string, changes?: Partial<Pick<SourceProjectionSpec,
  'maxChangedPaths' | 'maxChangedBytes' | 'explicitExcludes'>>): Promise<Fixture> {
  const fixture = await createAgentFixture(label, undefined, { mode: 'plan' });
  if (!changes) return fixture;
  try {
    const { runSpec } = await fixture.store.readRecoveryClosure(fixture.runId);
    const frozen = await fixture.store.artifacts.readCanonical<SourceProjectionSpec>(runSpec.sourceProjectionRef);
    const projection = { ...frozen, ...changes, projectionDigest: '' };
    projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
    const projectionRef = (await fixture.store.artifacts.publishCanonical(projection, 'cliq-source-projection-v1')).ref;
    const oldBase = await fixture.store.artifacts.readCanonical<SourceManifest>(runSpec.baseWorkspaceManifestRef);
    const base: SourceManifest = { ...oldBase, sourceProjectionRef: projectionRef,
      sourceProjectionDigest: projection.projectionDigest, manifestDigest: '' };
    base.manifestDigest = digestOmitting(base, 'manifestDigest');
    const baseRef = (await fixture.store.artifacts.publishCanonical(base, base.format)).ref;
    const session = fixture.store.getSession(fixture.store.getRun(fixture.runId).sessionId);
    // Normal admission creates the RunSpec/consent; no SQL authority or
    // historical RunSpec is rewritten to install a different result limit.
    const admitted = await fixture.store.admitRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(),
      admissionKey: admissionKey(`${label}-projection`), sessionId: session.id, expectedContextRevision: session.contextRevision,
      workspacePath: fixture.workspace, objective: 'Retain the exact frozen source projection.', allowUnverified: true,
      assemblyRef: runSpec.assemblyRef, policyRef: runSpec.policyRef, sandboxProfileRef: runSpec.sandboxProfileRef,
      verifierSpecRef: runSpec.verifierSpecRef, credentialGrantRefs: runSpec.credentialGrantRefs, budgets: runSpec.budgets,
      sourceProjectionRef: projectionRef, frozenIgnoreRulesRef: projection.frozenIgnoreRulesRef, baseWorkspaceManifestRef: baseRef });
    const target = { ...fixture, ...await activateFixtureWorker({ ...fixture, runId: admitted.run.id }, `${label}-worker`) };
    target.agent = await fixture.store.loadAgentRun({ runId: target.runId, material: fixture.authority.material,
      releaseKeys: fixture.signed.releaseKeys });
    return target;
  } catch (error) { await disposeFixture(fixture); throw error; }
}

async function completeFinalTurn(fixture: Fixture) {
  const prepared = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
    leaseEpoch: fixture.leaseEpoch });
  await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
    leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'candidate-source-dispatch' });
  const reader = fixture.agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
  reader.push(Buffer.from(JSON.stringify({ id: 'candidate-source-response', object: 'response', status: 'completed', model: 'model-1',
    output: [{ type: 'message', id: 'candidate-source-message', role: 'assistant', status: 'completed',
      content: [{ type: 'output_text', text: 'The retained source is ready for checks.', annotations: [] }] }] })));
  const completed = await fixture.agent.completeModel({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
    expectedRunRevision: prepared.run.revision, result: reader.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput) });
  assert.equal(completed.disposition, 'candidate_required');
  const producerId = identityHash('cliq-model-turn-item-v1', fixture.runId, prepared.entry.opId, String(prepared.entry.attempt));
  return { completed, checkpointId: identityHash('cliq-final-candidate-checkpoint-v1', fixture.runId, producerId) };
}

async function file(fixture: Fixture, path: string, bytes: string | Buffer): Promise<WorkspaceEntry> {
  const content = Buffer.from(bytes);
  const blob = await fixture.store.artifacts.publishBytes(content, 'application/octet-stream', 'cliq-workspace-file-v1');
  return { kind: 'file', path, mode: 0o644, size: content.byteLength, blobRef: blob.ref };
}

async function sourceProof(fixture: Fixture, checkpointId: string, values: WorkspaceEntry[]) {
  const proof = await quiescedToolCheckpoint(fixture, checkpointId);
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1',
    entries: [...values].sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path))),
    entryCount: values.length, byteCount: values.reduce((sum, entry) => sum + (entry.kind === 'file' ? entry.size :
      entry.kind === 'symlink' ? Buffer.byteLength(entry.target) : 0), 0), treeDigest: '' };
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  const entriesRef = (await fixture.store.artifacts.publishCanonical(entries, entries.format)).ref;
  const original = await fixture.store.artifacts.readCanonical<WorkspaceStateManifest>(proof.workspaceStateRef);
  const workspace = { ...original, entriesRef, stateDigest: '' };
  workspace.stateDigest = digestOmitting(workspace, 'stateDigest');
  const workspaceStateRef = (await fixture.store.artifacts.publishCanonical(workspace, workspace.format)).ref;
  // Only retained-data fields change. Original fixture identities, timestamps,
  // inspector, quiescence/retirement refs and fsync/death flags are unchanged.
  const snapshot = { ...proof.snapshot, workspaceStateRef, workspaceStateDigest: workspace.stateDigest,
    entriesRef, treeDigest: entries.treeDigest, evidenceDigest: '' };
  snapshot.evidenceDigest = digestOmitting(snapshot, 'evidenceDigest');
  const snapshotEvidenceRef = (await fixture.store.artifacts.publishCanonical(snapshot, snapshot.format)).ref;
  return { ...proof.checkpoint, workspaceStateRef, snapshotEvidenceRef };
}

async function candidateGraph(fixture: Fixture) {
  const cut = await fixture.store.readRecoveryClosure(fixture.runId);
  const candidate = await fixture.store.artifacts.readCanonical<FinalCandidateItem>(cut.items.at(-1)!.payloadRef);
  assert.equal(candidate.kind, 'final_candidate');
  const source = await fixture.store.artifacts.readCanonical<SourceManifest>(candidate.resultSourceRef);
  const entries = await fixture.store.artifacts.readCanonical<WorkspaceEntryManifest>(source.entriesRef);
  const diff = await fixture.store.artifacts.readCanonical<WorkspaceDiffV1>(candidate.diffRef);
  return { cut, candidate, source, entries, diff };
}

test('an unchanged retained workspace publishes an exact empty candidate diff and reuses its entry object', async () => {
  const fixture = await sourceFixture('candidate-source-empty');
  try {
    const { completed, checkpointId } = await completeFinalTurn(fixture);
    const checkpoint = await sourceProof(fixture, checkpointId, []);
    await fixture.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision, checkpoint });
    const graph = await candidateGraph(fixture);
    const base = await fixture.store.artifacts.readCanonical<SourceManifest>(graph.candidate.baseSourceRef);
    assert.deepEqual(graph.diff.operations, []);
    assert.equal(graph.source.entriesRef, base.entriesRef);
    assert.equal(graph.source.treeDigest, base.treeDigest);
    assert.equal(graph.source.role, 'result');
    assert.notEqual(graph.candidate.resultSourceRef, graph.candidate.baseSourceRef);
    assert.equal(graph.candidate.sourceDigest, graph.source.manifestDigest);
  } finally { await disposeFixture(fixture); }
});

test('an ordinary source file can share bytes with a retained structured artifact without changing either use', async () => {
  const fixture = await sourceFixture('candidate-source-shared-bytes');
  try {
    const { runSpec } = await fixture.store.readRecoveryClosure(fixture.runId);
    const projection = await fixture.store.artifacts.readCanonical<SourceProjectionSpec>(runSpec.sourceProjectionRef);
    const rules = await fixture.store.artifacts.readCanonical(projection.frozenIgnoreRulesRef);
    const bytes = canonicalJsonBytes(rules), entry = await file(fixture, 'rules-copy.json', bytes);
    assert.equal(entry.kind, 'file');
    if (entry.kind !== 'file') throw new Error('source test requires a regular file');
    assert.equal(entry.blobRef, projection.frozenIgnoreRulesRef);
    const blobRef = entry.blobRef;
    // Approved read-only catalog diagnostic: no StateOwner, authority rewrite,
    // migration, dispatch or alternate persistence implementation is created.
    function descriptor() {
      const reader = new DatabaseSync(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME), { readOnly: true, allowExtension: false });
      try {
        const query = reader.prepare('SELECT ref, media_type, schema_kind, byte_length, created_at FROM artifacts WHERE ref = ?');
        query.setReadBigInts(true);
        const row = query.get(blobRef);
        assert.ok(row, 'the original structured artifact must already be registered');
        return { ...row };
      } finally { reader.close(); }
    }
    const originalDescriptor = descriptor();
    assert.equal(originalDescriptor.media_type, 'application/json');
    assert.equal(originalDescriptor.schema_kind, 'cliq-frozen-ignore-rules-v1');
    assert.equal(originalDescriptor.byte_length, BigInt(bytes.byteLength));
    async function assertSharedBytes() {
      assert.deepEqual(descriptor(), originalDescriptor);
      assert.deepEqual(await fixture.store.artifacts.readBytes(blobRef), bytes);
      assert.deepEqual(await fixture.store.artifacts.readCanonical(projection.frozenIgnoreRulesRef), rules);
      assert.equal(sha256Bytes(await fixture.store.artifacts.readBytes(blobRef)), blobRef);
    }
    await assertSharedBytes();
    const { completed, checkpointId } = await completeFinalTurn(fixture);
    const checkpoint = await sourceProof(fixture, checkpointId, [entry]);
    await assertSharedBytes();
    await fixture.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision, checkpoint });
    const graph = await candidateGraph(fixture);
    assert.deepEqual(graph.entries.entries, [entry]);
    assert.deepEqual(graph.diff.operations.map(operation => [operation.kind, operation.path]), [['add', 'rules-copy.json']]);
    assert.deepEqual(await fixture.store.artifacts.readBytes(entry.blobRef), bytes);
    assert.deepEqual(await fixture.store.artifacts.readCanonical(projection.frozenIgnoreRulesRef), rules);
    await assertSharedBytes();
    const finalized = await fixture.agent.completeVerification({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    assert.equal(finalized.run.nextStep, 'finalize'); assert.equal(finalized.run.resultRef, undefined);
    await assertSharedBytes();
    const committed = await fixture.agent.commitRunResult({ expectedRunRevision: finalized.run.revision });
    assert.equal(committed.run.status, 'completed_unverified'); assert.equal(committed.run.terminalReason, 'no_required_verifier');
    const result = await fixture.store.artifacts.readCanonical<RunResult>(committed.resultRef);
    assert.equal(result.resultSourceRef, graph.candidate.resultSourceRef); assert.equal(result.diffRef, graph.candidate.diffRef);
    await assertSharedBytes();
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material,
      releaseKeys: fixture.signed.releaseKeys });
    await assertSharedBytes();
    const reopened = await candidateGraph(fixture);
    assert.deepEqual(reopened.source, graph.source); assert.deepEqual(reopened.entries, graph.entries); assert.deepEqual(reopened.diff, graph.diff);
    assert.deepEqual(await fixture.store.artifacts.readCanonical(committed.resultRef), result);
  } finally { await disposeFixture(fixture); }
});

test('a file cannot reuse a real retained artifact ref with a different declared byte length', async () => {
  const fixture = await sourceFixture('candidate-source-shared-wrong-size');
  try {
    const { runSpec } = await fixture.store.readRecoveryClosure(fixture.runId);
    const projection = await fixture.store.artifacts.readCanonical<SourceProjectionSpec>(runSpec.sourceProjectionRef);
    const original = await fixture.store.artifacts.readBytes(projection.frozenIgnoreRulesRef);
    const entry: WorkspaceEntry = { kind: 'file', path: 'wrong-size.json', mode: 0o644,
      blobRef: projection.frozenIgnoreRulesRef, size: original.byteLength + 1 };
    const { completed, checkpointId } = await completeFinalTurn(fixture);
    const checkpoint = await sourceProof(fixture, checkpointId, [entry]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision, checkpoint }), /unexpected byte count/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    assert.deepEqual(await fixture.store.artifacts.readBytes(projection.frozenIgnoreRulesRef), original);
  } finally { await disposeFixture(fixture); }
});

test('new directories, binary files and a safe Unicode symlink retain one byte-ordered diff across reopen', async () => {
  const fixture = await sourceFixture('candidate-source-order');
  try {
    const target = 'a/é.txt';
    const values: WorkspaceEntry[] = [await file(fixture, 'ä', Buffer.from([0, 255, 10])),
      { kind: 'symlink', path: 'link', mode: 0o777, target, targetDigest: sha256Bytes(Buffer.from(target)) },
      { kind: 'directory', path: 'empty', mode: 0o755 }, await file(fixture, 'a/é.txt', '你好'),
      { kind: 'directory', path: 'a', mode: 0o755 }, await file(fixture, 'Z', 'Z')];
    const { completed, checkpointId } = await completeFinalTurn(fixture);
    const checkpoint = await sourceProof(fixture, checkpointId, values);
    await fixture.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision, checkpoint });
    const graph = await candidateGraph(fixture);
    assert.deepEqual(graph.diff.operations.map(operation => [operation.kind, operation.path]),
      [['add', 'Z'], ['add', 'a'], ['add', 'a/é.txt'], ['add', 'empty'], ['add', 'link'], ['add', 'ä']]);
    assert.equal(graph.entries.entryCount, 6); assert.equal(graph.entries.byteCount, 18);
    assert.deepEqual(graph.diff.operations.map(operation => operation.kind === 'add' ? operation.after : undefined), graph.entries.entries);
    const binary = graph.entries.entries.find(entry => entry.path === 'ä');
    assert.equal(binary?.kind, 'file');
    if (binary?.kind !== 'file') throw new Error('source test requires its binary file');
    assert.deepEqual(await fixture.store.artifacts.readBytes(binary.blobRef), Buffer.from([0, 255, 10]));
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    assert.deepEqual(await candidateGraph(fixture), graph);
  } finally { await disposeFixture(fixture); }
});

test('zero frozen changed paths rejects a new file without installing a candidate or altering its cut', async () => {
  const fixture = await sourceFixture('candidate-source-zero-paths', { maxChangedPaths: 0 });
  try {
    const { completed, checkpointId } = await completeFinalTurn(fixture);
    const checkpoint = await sourceProof(fixture, checkpointId, [await file(fixture, 'new', 'x')]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision, checkpoint }),
      error => error instanceof CandidateSourceLimitError && error.reason === 'changed_paths' && error.observed === 1 && error.limit === 0);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    assert.equal(before.items.length, 1); assert.equal(before.run.resultRef, undefined);
  } finally { await disposeFixture(fixture); }
});

test('the frozen changed-byte ceiling accepts its exact UTF-8 size and rejects one byte less', async t => {
  for (const limit of [2, 1]) await t.test(`a two-byte character with a ${limit}-byte ceiling`, async () => {
    const fixture = await sourceFixture(`candidate-source-bytes-${limit}`, { maxChangedBytes: limit });
    try {
      const { completed, checkpointId } = await completeFinalTurn(fixture);
      const entry = await file(fixture, 'text', 'é');
      assert.equal(entry.kind, 'file');
      if (entry.kind !== 'file') throw new Error('source byte test requires a regular file');
      assert.equal(entry.size, 2);
      const checkpoint = await sourceProof(fixture, checkpointId, [entry]);
      const before = await fixture.store.readRecoveryClosure(fixture.runId);
      if (limit === 2) {
        await fixture.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision, checkpoint });
        const graph = await candidateGraph(fixture);
        assert.deepEqual(graph.diff.operations, [{ kind: 'add', path: 'text', after: entry }]);
        assert.equal(graph.entries.byteCount, 2);
      } else {
        await assert.rejects(fixture.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision, checkpoint }),
          error => error instanceof CandidateSourceLimitError && error.reason === 'changed_bytes' && error.observed === 2 && error.limit === 1);
        assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
      }
    } finally { await disposeFixture(fixture); }
  });
});

test('unsafe symlink lookup and a missing directory cannot become a candidate source', async t => {
  for (const kind of ['escape', 'cycle', 'missing-directory'] as const) await t.test(kind, async () => {
    const fixture = await sourceFixture(`candidate-source-unsafe-${kind}`);
    try {
      const values: WorkspaceEntry[] = kind === 'missing-directory'
        ? [await file(fixture, 'absent/file', 'x')]
        : (kind === 'escape' ? [['link', '../outside']] : [['a', 'b'], ['b', 'a']]).map(([path, target]) =>
          ({ kind: 'symlink', path, mode: 0o777, target, targetDigest: sha256Bytes(Buffer.from(target)) }));
      const { completed, checkpointId } = await completeFinalTurn(fixture);
      const checkpoint = await sourceProof(fixture, checkpointId, values);
      const before = await fixture.store.readRecoveryClosure(fixture.runId);
      await assert.rejects(fixture.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision, checkpoint }),
        { code: 'ARTIFACT_MISMATCH' });
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
      assert.equal(before.items.length, 1); assert.equal(before.run.resultRef, undefined);
    } finally { await disposeFixture(fixture); }
  });
});

test('a frozen subtree exclude stays outside result and diff without hiding a same-prefix sibling or recovery state', async () => {
  const fixture = await sourceFixture('candidate-source-exclude', { explicitExcludes: [{ path: 'cache', scope: 'subtree' }] });
  try {
    const values: WorkspaceEntry[] = [{ kind: 'directory', path: 'cache', mode: 0o755 },
      await file(fixture, 'cache/hidden', 'excluded payload'), { kind: 'directory', path: 'cache2', mode: 0o755 },
      await file(fixture, 'cache2/keep', 'visible'), await file(fixture, 'keep', 'kept')];
    const { completed, checkpointId } = await completeFinalTurn(fixture);
    const checkpoint = await sourceProof(fixture, checkpointId, values);
    await fixture.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision, checkpoint });
    const graph = await candidateGraph(fixture);
    assert.deepEqual(graph.entries.entries.map(entry => entry.path), ['cache2', 'cache2/keep', 'keep']);
    assert.deepEqual(graph.diff.operations.map(operation => [operation.kind, operation.path]),
      [['add', 'cache2'], ['add', 'cache2/keep'], ['add', 'keep']]);
    assert.equal(graph.source.sourceProjectionRef, graph.cut.runSpec.sourceProjectionRef);
    const recovery = await fixture.store.artifacts.readCanonical<WorkspaceStateManifest>(graph.cut.latestCheckpoint.workspaceStateRef);
    const recovered = await fixture.store.artifacts.readCanonical<WorkspaceEntryManifest>(recovery.entriesRef);
    assert.deepEqual(recovered.entries.map(entry => entry.path), ['cache', 'cache/hidden', 'cache2', 'cache2/keep', 'keep']);
    assert.notEqual(graph.source.entriesRef, recovery.entriesRef);
  } finally { await disposeFixture(fixture); }
});
