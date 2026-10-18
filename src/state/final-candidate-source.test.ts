// Existing real StateStore/CAS seam. All model and quiescence facts below reuse
// the offline fixture; no filesystem capture, native death or installation is qualified.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, sha256Bytes } from '../kernel/identity.js';
import type { FinalCandidateItem, RunResult, SourceManifest, SourceProjectionSpec, WorkspaceDiffV1, WorkspaceEntry,
  WorkspaceEntryManifest, WorkspaceStateManifest, StopIntent, TerminalDetail } from '../kernel/types.js';
import type { ToolObservationV1 } from '../kernel/tool-authorization.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { isJoinedCasPublicationFailure } from './cas.js';
import { CandidateSourceLimitError } from './result-source.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { activateFixtureWorker, admissionKey, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';
import { openSqliteDriver } from './sqlite-driver.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;

async function sourceFixture(label: string, changes?: Partial<Pick<SourceProjectionSpec,
  'maxChangedPaths' | 'maxChangedBytes' | 'explicitExcludes'>>, edits = false, wallTimeMs?: number): Promise<Fixture> {
  const fixture = await createAgentFixture(label, wallTimeMs === undefined ? undefined : { wallTimeMs },
    edits ? { mode: 'accept-edits', tools: ['edit'] } : { mode: 'plan' });
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
  const owner = await fixture.agent.beginFinalCandidate({ expectedRunRevision: completed.run.revision });
  return { completed, owner, checkpointId: owner.checkpointId };
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

async function accountedSourceFixture(label: string, changes: Partial<Pick<SourceProjectionSpec, 'maxChangedPaths' | 'maxChangedBytes'>>, wallTimeMs?: number) {
  const fixture = await sourceFixture(label, changes, true, wallTimeMs);
  try {
    await batch(fixture, [{ name: 'edit', input: { path: 'a', old_text: 'before', new_text: 'after' } }]);
    const claimed = await claimTool(fixture, await prepareTool(fixture));
    const checkpointId = identityHash('cliq-tool-checkpoint-v1', fixture.runId, claimed.entry.opId, String(claimed.entry.attempt));
    const original = await fixture.store.artifacts.readCanonical<ToolObservationV1>(await observation(fixture, claimed, 'Offline edit completed.'));
    const checkpoint = await sourceProof(fixture, checkpointId, [await file(fixture, 'a', 'after\n')]);
    const value = { ...original, postEffect: checkpoint, observationDigest: '' };
    value.observationDigest = digestOmitting(value, 'observationDigest');
    await fixture.agent.completeTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
      opId: claimed.entry.opId, attempt: claimed.entry.attempt,
      observationRef: (await fixture.store.artifacts.publishCanonical(value, value.format)).ref });
    Object.assign(fixture, await activateFixtureWorker(fixture, `${label}-final-worker`));
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material,
      releaseKeys: fixture.signed.releaseKeys });
    return fixture;
  } catch (error) { await disposeFixture(fixture); throw error; }
}

test('an accounted result exceeding its frozen path limit seals the original final cut and publishes one recoverable resource terminal', async () => {
  const fixture = await accountedSourceFixture('candidate-source-resource-path', { maxChangedPaths: 0, maxChangedBytes: 0 });
  try {
    const { completed, owner, checkpointId } = await completeFinalTurn(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId), sessionBefore = fixture.store.getSession(before.run.sessionId);
    const proof = await quiescedToolCheckpoint(fixture, checkpointId);
    const sealed = await owner.complete({ expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint });
    assert.equal(sealed.disposition, 'stopped');
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(cut.run.status, 'queued'); assert.equal(cut.run.nextStep, 'agent'); assert.equal(cut.run.activeWorkerLaunchId, undefined);
    assert.deepEqual(cut.items, before.items); assert.deepEqual(cut.journal, before.journal);
    assert.equal(cut.latestCheckpoint.id, checkpointId); assert.equal(cut.latestCheckpoint.workspaceStateRef, before.latestCheckpoint.workspaceStateRef);
    const intent = await fixture.store.artifacts.readCanonical<StopIntent>(cut.run.stopIntentRef!);
    assert.deepEqual(intent, { schemaVersion: 1, runId: fixture.runId, createdAt: intent.createdAt, origin: 'runtime',
      targetStatus: 'failed', reason: 'runtime_failed', runtimeSubtype: 'result_source_limit_exceeded',
      sourceCheckpointId: before.latestCheckpoint.id, workspaceStateRef: before.latestCheckpoint.workspaceStateRef,
      producingItemId: before.items.at(-1)!.itemId, modelOpId: before.journal.at(-1)!.opId,
      attempt: before.journal.at(-1)!.attempt, limitKind: 'changed_paths', observed: 1, limit: 0 });
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: cut.run.revision });
    assert.equal(terminal.run.status, 'failed'); assert.equal(terminal.run.terminalReason, 'runtime_failed'); assert.equal(terminal.run.resultRef, undefined);
    const detail = await fixture.store.artifacts.readCanonical<TerminalDetail>(terminal.run.terminalDetailRef!);
    assert.equal(detail.primaryEvidenceRef, cut.run.stopIntentRef);
    assert.equal(detail.reasonDetail.kind, 'result_source_limit_exceeded');
    const session = fixture.store.getSession(before.run.sessionId);
    assert.equal(session.latestItemSeq, sessionBefore.latestItemSeq + 1); assert.equal(session.contextRevision, sessionBefore.contextRevision + 1);
    await fixture.store.close(); fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    assert.deepEqual(fixture.store.getRun(fixture.runId), terminal.run);
    assert.deepEqual(fixture.store.getSession(session.id), session);
    const reopened = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(reopened.journal, before.journal); assert.deepEqual(reopened.items, before.items);
    assert.deepEqual(reopened.run.budgetConsumed, before.run.budgetConsumed); assert.deepEqual(reopened.run.budgetReserved, before.run.budgetReserved);
  } finally { await disposeFixture(fixture); }
});

test('accounted result limits accept exact path/byte boundaries and fail only the strictly exceeded byte ceiling', async t => {
  for (const maxChangedBytes of [6, 5]) await t.test(`${maxChangedBytes} bytes`, async () => {
    const fixture = await accountedSourceFixture(`candidate-source-resource-bytes-${maxChangedBytes}`, { maxChangedPaths: 1, maxChangedBytes });
    try {
      const { completed, owner, checkpointId } = await completeFinalTurn(fixture);
      const before = await fixture.store.readRecoveryClosure(fixture.runId);
      if (maxChangedBytes === 6) {
        await assert.rejects(fixture.agent.stopForResourceFailure({ expectedRunRevision: before.run.revision }), { code: 'STATE_TRANSITION_INVALID' });
        assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
      }
      const proof = await quiescedToolCheckpoint(fixture, checkpointId);
      const sealed = await owner.complete({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, checkpoint: proof.checkpoint });
      assert.equal(sealed.disposition, maxChangedBytes === 6 ? 'candidate' : 'stopped');
      const cut = await fixture.store.readRecoveryClosure(fixture.runId);
      assert.deepEqual(cut.journal, before.journal); assert.deepEqual(cut.run.budgetConsumed, before.run.budgetConsumed);
      if (maxChangedBytes === 6) {
        assert.equal(cut.run.stopIntentRef, undefined);
        const graph = await candidateGraph(fixture);
        assert.deepEqual(graph.diff.operations, [{ kind: 'add', path: 'a', after: await file(fixture, 'a', 'after\n') }]);
      } else {
        const intent = await fixture.store.artifacts.readCanonical<StopIntent>(cut.run.stopIntentRef!);
        assert.ok(intent.origin === 'runtime' && intent.runtimeSubtype === 'result_source_limit_exceeded');
        assert.equal(intent.limitKind, 'changed_bytes'); assert.equal(intent.observed, 6); assert.equal(intent.limit, 5);
        assert.deepEqual(cut.items, before.items); assert.equal(cut.run.resultRef, undefined);
        assert.equal((await fixture.agent.commitTerminalStop({ expectedRunRevision: cut.run.revision })).run.status, 'failed');
      }
    } finally { await disposeFixture(fixture); }
  });
});

test('joined result-stop publication failure retains one final owner and preserves resource, cancellation and deadline precedence', async t => {
  for (const winner of ['resource', 'cancel', 'deadline'] as const) await t.test(winner, async t => {
    let clock = Date.now(); t.mock.method(Date, 'now', () => clock);
    const fixture = await accountedSourceFixture(`candidate-source-stop-cas-${winner}`, { maxChangedPaths: 0 }, 60_000);
    try {
      const { completed, owner, checkpointId } = await completeFinalTurn(fixture);
      if (winner === 'deadline') clock = Date.parse(completed.run.deadlineAt) - 1000;
      const proof = await quiescedToolCheckpoint(fixture, checkpointId), before = await fixture.store.readRecoveryClosure(fixture.runId);
      const sample = await fs.open(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, proof.workspaceStateRef), 'r');
      const prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] }, original = prototype.writeFile;
      await sample.close();
      const failure = Object.assign(new Error('result stop publication ENOSPC after its actual write'), { code: 'ENOSPC' });
      let injected = 0, candidates = 0;
      const writer = t.mock.method(prototype, 'writeFile', async function(this: FileHandle, ...args: unknown[]) {
        await Reflect.apply(original, this, args);
        if (!Buffer.isBuffer(args[0])) return;
        const text = args[0].toString('utf8');
        if (text.includes('"kind":"final_candidate"')) candidates++;
        if (!injected && text.includes('"runtimeSubtype":"result_source_limit_exceeded"')) { injected++; throw failure; }
      });
      const request = { expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint };
      await assert.rejects(owner.complete(request), error => error === failure);
      assert.equal(injected, 1); assert(isJoinedCasPublicationFailure(failure));
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
      if (winner === 'cancel') await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(),
        expectedRunRevision: before.run.revision });
      if (winner === 'deadline') clock = Date.parse(before.run.deadlineAt);
      const sealed = await owner.complete({ ...request, expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
      writer.mock.restore(); assert.equal(candidates, 0); assert.equal(sealed.disposition, 'stopped');
      const cut = await fixture.store.readRecoveryClosure(fixture.runId);
      const intent = await fixture.store.artifacts.readCanonical<StopIntent>(cut.run.stopIntentRef!);
      assert.equal(intent.origin, winner === 'resource' ? 'runtime' : winner === 'cancel' ? 'user_cancel' : 'deadline');
      assert.equal(cut.latestCheckpoint.id, checkpointId); assert.deepEqual(cut.items, before.items); assert.deepEqual(cut.journal, before.journal);
      const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: cut.run.revision });
      assert.equal(terminal.run.status, winner === 'cancel' ? 'cancelled' : 'failed');
      assert.equal(terminal.run.terminalReason, winner === 'resource' ? 'runtime_failed' : winner === 'cancel' ? 'cancelled_by_user' : 'budget_exhausted');
      assert.equal(terminal.run.resultRef, undefined);
      await fixture.store.close(); fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
      assert.deepEqual(fixture.store.getRun(fixture.runId), terminal.run);
      assert.deepEqual((await fixture.store.readRecoveryClosure(fixture.runId)).journal, before.journal);
    } finally { await disposeFixture(fixture); }
  });
});

test('a rolled-back resource seal retains its original source Checkpoint and commits no candidate on retry', async () => {
  const fixture = await accountedSourceFixture('candidate-source-stop-sql', { maxChangedBytes: 5 });
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const { completed, owner, checkpointId } = await completeFinalTurn(fixture);
    const proof = await quiescedToolCheckpoint(fixture, checkpointId), before = await fixture.store.readRecoveryClosure(fixture.runId);
    fault.exec("CREATE TRIGGER fail_result_resource_checkpoint BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT, 'injected resource seal rollback'); END");
    const request = { expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint };
    await assert.rejects(owner.complete(request), /injected resource seal rollback/);
    const stopped = await fixture.store.readRecoveryClosure(fixture.runId);
    assert(stopped.run.stopIntentRef); assert.equal(stopped.run.revision, before.run.revision + 1);
    assert.deepEqual(stopped.latestCheckpoint, before.latestCheckpoint); assert.deepEqual(stopped.journal, before.journal); assert.deepEqual(stopped.items, before.items);
    fault.exec('DROP TRIGGER fail_result_resource_checkpoint');
    const sealed = await owner.complete({ ...request, expectedRunRevision: stopped.run.revision });
    assert.equal(sealed.disposition, 'stopped'); assert.equal(sealed.run.stopIntentRef, stopped.run.stopIntentRef);
    const intent = await fixture.store.artifacts.readCanonical<StopIntent>(sealed.run.stopIntentRef!);
    assert.ok(intent.origin === 'runtime' && intent.runtimeSubtype === 'result_source_limit_exceeded');
    assert.equal(intent.sourceCheckpointId, before.latestCheckpoint.id);
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(cut.journal, before.journal); assert.deepEqual(cut.items, before.items); assert.equal(cut.latestCheckpoint.id, checkpointId);
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: cut.run.revision });
    assert.equal(terminal.run.status, 'failed'); assert.equal(terminal.run.resultRef, undefined);
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('result-source stop recovery rejects altered causes, producer identities and the original accounted Checkpoint', async () => {
  const fixture = await accountedSourceFixture('candidate-source-stop-forged', { maxChangedPaths: 0, maxChangedBytes: 0 });
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const { completed, owner, checkpointId } = await completeFinalTurn(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId), proof = await quiescedToolCheckpoint(fixture, checkpointId);
    const sealed = await owner.complete({ expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint });
    const originalRef = sealed.run.stopIntentRef!, intent = await fixture.store.artifacts.readCanonical<StopIntent>(originalRef);
    assert.ok(intent.origin === 'runtime' && intent.runtimeSubtype === 'result_source_limit_exceeded');
    for (const replacement of [
      { ...intent, sourceCheckpointId: checkpointId },
      { ...intent, workspaceStateRef: before.runSpec.baseWorkspaceManifestRef },
      { ...intent, producingItemId: before.items[0]!.itemId },
      { ...intent, modelOpId: before.journal[0]!.opId },
      { ...intent, attempt: intent.attempt + 1 },
      { ...intent, limitKind: 'changed_bytes', observed: 6 },
      { ...intent, observed: 2 },
      { ...intent, observed: 0 },
      { ...intent, limit: 1 },
      { ...intent, limitKind: 'other' },
      { ...intent, diagnostic: 'a caught error cannot be a closed resource cause' }
    ]) {
      const forged = await fixture.store.artifacts.publishCanonical(replacement, 'cliq-stop-intent-v1');
      fault.prepare('UPDATE runs SET stop_intent_ref = ? WHERE id = ?').run(forged.ref, fixture.runId);
      try { await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' }); }
      finally { fault.prepare('UPDATE runs SET stop_intent_ref = ? WHERE id = ?').run(originalRef, fixture.runId); }
    }
    const source = before.latestCheckpoint;
    // Existing isolated corruption seam: restore the exact schema guard inside
    // each write transaction before any production recovery reader is invoked.
    const guard = fault.prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'checkpoints_immutable_update'")
      .get<{ sql: string }>()!.sql;
    const corruptCheckpoint = (column: string, value: string | number) => fault.transaction(connection => {
      connection.exec('DROP TRIGGER checkpoints_immutable_update');
      connection.prepare(`UPDATE checkpoints SET ${column} = ? WHERE id = ?`).run(value, source.id);
      connection.exec(guard);
    });
    const initial = fault.prepare('SELECT workspace_state_ref, context_manifest_ref FROM checkpoints WHERE id = ?')
      .get<{ workspace_state_ref: string; context_manifest_ref: string }>(identityHash('cliq-checkpoint-id-v1', fixture.runId, 'initial', 0))!;
    for (const [column, changed, original] of [
      ['workspace_state_ref', initial.workspace_state_ref, source.workspaceStateRef],
      ['context_manifest_ref', initial.context_manifest_ref, source.contextManifestRef],
      ['run_item_seq', source.runItemSeq - 1, source.runItemSeq],
      ['journal_seq', source.journalSeq - 1, source.journalSeq],
      ['created_at', new Date(Date.parse(source.createdAt) + 1).toISOString(), source.createdAt],
      ['based_on_run_revision', sealed.run.revision, source.basedOnRunRevision]
    ] as const) {
      corruptCheckpoint(column, changed);
      try { await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' }); }
      finally { corruptCheckpoint(column, original); }
    }
    const valid = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(valid.items, before.items); assert.deepEqual(valid.journal, before.journal);
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: valid.run.revision });
    assert.equal(terminal.run.status, 'failed'); assert.equal(terminal.run.resultRef, undefined);
    await fixture.store.close(); fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    assert.deepEqual(fixture.store.getRun(fixture.runId), terminal.run);
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('an unchanged retained workspace publishes an exact empty candidate diff and reuses its entry object', async () => {
  const fixture = await sourceFixture('candidate-source-empty');
  try {
    const { completed, owner, checkpointId } = await completeFinalTurn(fixture);
    const checkpoint = await sourceProof(fixture, checkpointId, []);
    await owner.complete({ expectedRunRevision: completed.run.revision, checkpoint });
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
    const { completed, owner, checkpointId } = await completeFinalTurn(fixture);
    const checkpoint = await sourceProof(fixture, checkpointId, [entry]);
    await assertSharedBytes();
    await owner.complete({ expectedRunRevision: completed.run.revision, checkpoint });
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
    const { completed, owner, checkpointId } = await completeFinalTurn(fixture);
    const checkpoint = await sourceProof(fixture, checkpointId, [entry]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(owner.complete({ expectedRunRevision: completed.run.revision, checkpoint }), /unexpected byte count/);
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
    const { completed, owner, checkpointId } = await completeFinalTurn(fixture);
    const checkpoint = await sourceProof(fixture, checkpointId, values);
    await owner.complete({ expectedRunRevision: completed.run.revision, checkpoint });
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
    const { completed, owner, checkpointId } = await completeFinalTurn(fixture);
    const checkpoint = await sourceProof(fixture, checkpointId, [await file(fixture, 'new', 'x')]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(owner.complete({ expectedRunRevision: completed.run.revision, checkpoint }),
      error => error instanceof CandidateSourceLimitError && error.reason === 'changed_paths' && error.observed === 1 && error.limit === 0);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    assert.equal(before.items.length, 1); assert.equal(before.run.resultRef, undefined);
  } finally { await disposeFixture(fixture); }
});

test('the frozen changed-byte ceiling accepts its exact UTF-8 size and rejects one byte less', async t => {
  for (const limit of [2, 1]) await t.test(`a two-byte character with a ${limit}-byte ceiling`, async () => {
    const fixture = await sourceFixture(`candidate-source-bytes-${limit}`, { maxChangedBytes: limit });
    try {
      const { completed, owner, checkpointId } = await completeFinalTurn(fixture);
      const entry = await file(fixture, 'text', 'é');
      assert.equal(entry.kind, 'file');
      if (entry.kind !== 'file') throw new Error('source byte test requires a regular file');
      assert.equal(entry.size, 2);
      const checkpoint = await sourceProof(fixture, checkpointId, [entry]);
      const before = await fixture.store.readRecoveryClosure(fixture.runId);
      if (limit === 2) {
        await owner.complete({ expectedRunRevision: completed.run.revision, checkpoint });
        const graph = await candidateGraph(fixture);
        assert.deepEqual(graph.diff.operations, [{ kind: 'add', path: 'text', after: entry }]);
        assert.equal(graph.entries.byteCount, 2);
      } else {
        await assert.rejects(owner.complete({ expectedRunRevision: completed.run.revision, checkpoint }),
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
      const { completed, owner, checkpointId } = await completeFinalTurn(fixture);
      const checkpoint = await sourceProof(fixture, checkpointId, values);
      const before = await fixture.store.readRecoveryClosure(fixture.runId);
      await assert.rejects(owner.complete({ expectedRunRevision: completed.run.revision, checkpoint }),
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
    const { completed, owner, checkpointId } = await completeFinalTurn(fixture);
    const checkpoint = await sourceProof(fixture, checkpointId, values);
    await owner.complete({ expectedRunRevision: completed.run.revision, checkpoint });
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
