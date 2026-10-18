// Real SQLite/CAS and the existing offline signed model/retirement fixture.
// These checks establish storage invariants, not installed/native qualification.
import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { ContextManifest, FinalCandidateItem, VerifierSpec, WorkspaceStateManifest } from '../kernel/types.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { activateFixtureWorker, admissionKey, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';
import { openStateStore, publishInProcessChannel } from './store.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;

async function completeFinalTurn(fixture: Fixture) {
  const prepared = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
    leaseEpoch: fixture.leaseEpoch });
  await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
    leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'candidate-integrity-dispatch' });
  const reader = fixture.agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
  reader.push(Buffer.from(JSON.stringify({ id: 'candidate-integrity-response', object: 'response', status: 'completed', model: 'model-1',
    output: [{ type: 'message', id: 'candidate-integrity-message', role: 'assistant', status: 'completed',
      content: [{ type: 'output_text', text: 'This exact workspace is ready for verification.', annotations: [] }] }] })));
  const completed = await fixture.agent.completeModel({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
    expectedRunRevision: prepared.run.revision, result: reader.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput) });
  assert.equal(completed.disposition, 'candidate_required');
  const producerId = identityHash('cliq-model-turn-item-v1', fixture.runId, prepared.entry.opId, String(prepared.entry.attempt));
  return { completed, checkpointId: identityHash('cliq-final-candidate-checkpoint-v1', fixture.runId, producerId) };
}

test('a complete model turn cannot publish a candidate while its owning worker remains writable', async () => {
  const fixture = await createAgentFixture('candidate-still-writable');
  try {
    const { completed } = await completeFinalTurn(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(before.workerLaunches[0]!.generationWriteState, 'active');
    // All refs name retained data, but none is a worker snapshot/death proof.
    const workspaceStateRef = before.latestCheckpoint.workspaceStateRef;
    await assert.rejects(fixture.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision,
      checkpoint: { workspaceStateRef, snapshotEvidenceRef: workspaceStateRef, retirementEvidenceRef: workspaceStateRef } }));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('a candidate refuses a substituted checkpoint identity or a foreign Run workspace without changing its cut', async () => {
  const fixture = await createAgentFixture('candidate-foreign-proof');
  try {
    const { completed, checkpointId } = await completeFinalTurn(fixture);
    const proof = await quiescedToolCheckpoint(fixture, checkpointId, true);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const wrongCheckpoint = { ...proof.snapshot, checkpointId: 'another-candidate-checkpoint', evidenceDigest: '' };
    wrongCheckpoint.evidenceDigest = digestOmitting(wrongCheckpoint, 'evidenceDigest');
    const wrongSnapshotRef = (await fixture.store.artifacts.publishCanonical(wrongCheckpoint, wrongCheckpoint.format)).ref;
    await assert.rejects(fixture.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision,
      checkpoint: { ...proof.checkpoint, snapshotEvidenceRef: wrongSnapshotRef } }));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);

    const workspace = await fixture.store.artifacts.readCanonical<WorkspaceStateManifest>(proof.workspaceStateRef);
    const foreignWorkspace = { ...workspace, runId: 'foreign-candidate-run', stateDigest: '' };
    foreignWorkspace.stateDigest = digestOmitting(foreignWorkspace, 'stateDigest');
    const workspaceStateRef = (await fixture.store.artifacts.publishCanonical(foreignWorkspace, foreignWorkspace.format)).ref;
    const foreignSnapshot = { ...proof.snapshot, workspaceStateRef, workspaceStateDigest: foreignWorkspace.stateDigest, evidenceDigest: '' };
    foreignSnapshot.evidenceDigest = digestOmitting(foreignSnapshot, 'evidenceDigest');
    const snapshotEvidenceRef = (await fixture.store.artifacts.publishCanonical(foreignSnapshot, foreignSnapshot.format)).ref;
    await assert.rejects(fixture.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision,
      checkpoint: { ...proof.checkpoint, workspaceStateRef, snapshotEvidenceRef } }));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('a candidate cannot consume a valid worker seal at a stale Run revision', async () => {
  const fixture = await createAgentFixture('candidate-stale-revision');
  try {
    const { completed, checkpointId } = await completeFinalTurn(fixture);
    const proof = await quiescedToolCheckpoint(fixture, checkpointId, true);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision - 1,
      checkpoint: proof.checkpoint }), { code: 'REVISION_CONFLICT' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('a committed cancellation wins over a previously completed final model turn and valid candidate seal', async () => {
  const fixture = await createAgentFixture('candidate-cancel-wins');
  try {
    const { completed, checkpointId } = await completeFinalTurn(fixture);
    const proof = await quiescedToolCheckpoint(fixture, checkpointId, true);
    const stopped = await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store),
      requestId: uuidv7(), expectedRunRevision: completed.run.revision });
    assert.ok(stopped.run.stopIntentRef);
    assert.equal(stopped.run.cancelRequested, true);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.agent.prepareFinalCandidate({ expectedRunRevision: stopped.run.revision,
      checkpoint: proof.checkpoint }));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    assert.equal(fixture.store.getRun(fixture.runId).stopIntentRef, stopped.run.stopIntentRef);
  } finally { await disposeFixture(fixture); }
});

test('reopened recovery independently rejects an alternate candidate summary even after its context links are repaired', async t => {
  const fixture = await createAgentFixture('candidate-recovery-summary');
  let writer: ReturnType<typeof openSqliteDriver> | undefined;
  let restore: (() => void) | undefined;
  try {
    const { completed, checkpointId } = await completeFinalTurn(fixture);
    const proof = await quiescedToolCheckpoint(fixture, checkpointId, true);
    const accepted = await fixture.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision,
      checkpoint: proof.checkpoint });
    const original = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(original.run.status, 'queued');
    assert.equal(original.run.nextStep, 'verify');
    assert.equal(original.run.resultRef, undefined);
    assert.equal(original.run.latestCheckpointId, accepted.checkpointId);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    const reopened = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(reopened.run, original.run);
    assert.deepEqual(reopened.items, original.items);
    assert.deepEqual(reopened.journal, original.journal);
    assert.deepEqual(reopened.latestCheckpoint, original.latestCheckpoint);
    writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    for (const status of ['waiting', 'running'] as const) {
      await t.test(status === 'waiting' ? 'waiting without a subject is not an initial verifier cut' :
        'running without a worker is not an initial verifier cut', async () => {
        writer!.prepare('UPDATE runs SET status = ? WHERE id = ?').run(status, fixture.runId);
        try {
          await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
        } finally { writer!.prepare("UPDATE runs SET status = 'queued' WHERE id = ?").run(fixture.runId); }
        assert.deepEqual((await fixture.store.readRecoveryClosure(fixture.runId)).run, original.run);
      });
    }
    const workerRows = writer.prepare('SELECT rowid, launch_id, run_id, phase, row_json, retired_at FROM worker_launches WHERE run_id = ? ORDER BY rowid LIMIT 2')
      .all<{ rowid: bigint; launch_id: string; run_id: string; phase: string; row_json: string; retired_at: string }>(fixture.runId);
    const generationRows = writer.prepare('SELECT rowid, generation_id, run_id, phase, row_version, row_json FROM workspace_generations WHERE run_id = ? ORDER BY rowid LIMIT 2')
      .all<{ rowid: bigint; generation_id: string; run_id: string; phase: string; row_version: bigint; row_json: string }>(fixture.runId);
    assert.equal(workerRows.length, 1); assert.equal(workerRows[0]!.phase, 'retired');
    assert.equal(generationRows.length, 1); assert.equal(generationRows[0]!.phase, 'sealed');
    const historyGuards = new Map(['worker_launches_immutable_delete', 'workspace_generations_immutable_delete',
      'worker_launches_validate_insert', 'workspace_generations_validate_insert'].map(name => {
      const guard = writer!.prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?").get<{ sql: string }>(name);
      assert.ok(guard);
      return [name, guard.sql] as const;
    }));
    for (const removeGeneration of [false, true]) {
      await t.test(removeGeneration ? 'candidate data cannot replace missing worker and generation history' :
        'a sealed generation cannot replace its missing original retired worker', async () => {
        const deletedTables = removeGeneration ? ['worker_launches', 'workspace_generations'] : ['worker_launches'];
        let removed = false;
        try {
          writer!.transaction(connection => {
            for (const table of deletedTables) connection.exec(`DROP TRIGGER ${table}_immutable_delete`);
            const worker = workerRows[0]!;
            assert.equal(connection.prepare("DELETE FROM worker_launches WHERE launch_id = ? AND run_id = ? AND phase = 'retired'")
              .run(worker.launch_id, fixture.runId).changes, 1n);
            if (removeGeneration) {
              const generation = generationRows[0]!;
              assert.equal(connection.prepare("DELETE FROM workspace_generations WHERE generation_id = ? AND run_id = ? AND phase = 'sealed'")
                .run(generation.generation_id, fixture.runId).changes, 1n);
            }
            for (const table of deletedTables) connection.exec(historyGuards.get(`${table}_immutable_delete`)!);
          });
          removed = true;
          await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
        } finally {
          if (removed) writer!.transaction(connection => {
            for (const table of deletedTables) connection.exec(`DROP TRIGGER ${table}_validate_insert`);
            const worker = workerRows[0]!;
            connection.prepare('INSERT INTO worker_launches (rowid, launch_id, run_id, phase, row_json, retired_at) VALUES (?, ?, ?, ?, ?, ?)')
              .run(worker.rowid, worker.launch_id, worker.run_id, worker.phase, worker.row_json, worker.retired_at);
            if (removeGeneration) {
              const generation = generationRows[0]!;
              connection.prepare('INSERT INTO workspace_generations (rowid, generation_id, run_id, phase, row_version, row_json) VALUES (?, ?, ?, ?, ?, ?)')
                .run(generation.rowid, generation.generation_id, generation.run_id, generation.phase, generation.row_version, generation.row_json);
            }
            for (const table of deletedTables) connection.exec(historyGuards.get(`${table}_validate_insert`)!);
          });
        }
        assert.equal(canonicalSha256(await fixture.store.readRecoveryClosure(fixture.runId)), canonicalSha256(reopened));
      });
    }

    const row = reopened.items.at(-1)!;
    const candidate = await fixture.store.artifacts.readCanonical<FinalCandidateItem>(row.payloadRef);
    assert.equal(candidate.kind, 'final_candidate');
    const alternate: ModelTextV1 = { schemaVersion: 1, format: 'cliq-model-text-v1',
      utf8: 'An unrelated summary must not replace the final model text.', byteCount: 0, textDigest: '' };
    alternate.byteCount = Buffer.byteLength(alternate.utf8);
    alternate.textDigest = digestOmitting(alternate, 'textDigest');
    const summaryRef = (await fixture.store.artifacts.publishCanonical(alternate, alternate.format)).ref;
    const substituted = { ...candidate, summaryRef };
    const candidateRef = (await fixture.store.artifacts.publishCanonical(substituted, 'cliq-final-candidate-item-v1')).ref;
    const context = await fixture.store.artifacts.readCanonical<ContextManifest>(reopened.latestCheckpoint.contextManifestRef);
    const segment = context.segments.find(segment => segment.fromItemSeq === row.itemSeq && segment.throughItemSeq === row.itemSeq);
    if (segment?.kind !== 'excluded_control') assert.fail('the candidate must be retained only as excluded control');
    segment.sourceItemsDigest = canonicalSha256([{ itemSeq: row.itemSeq, kind: 'final_candidate', payloadRef: candidateRef }]);
    context.projectionDigest = digestOmitting(context, 'projectionDigest');
    const contextRef = (await fixture.store.artifacts.publishCanonical(context, context.format)).ref;
    const guards = ['items_immutable_update', 'checkpoints_immutable_update'].map(name => {
      const guard = writer!.prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?").get<{ sql: string }>(name);
      assert.ok(guard);
      return { name, sql: guard.sql };
    });
    const rewrite = (itemRef: string, manifestRef: string) => writer!.transaction(connection => {
      for (const guard of guards) connection.exec(`DROP TRIGGER ${guard.name}`);
      connection.prepare('UPDATE items SET payload_ref = ? WHERE item_id = ?').run(itemRef, row.itemId);
      connection.prepare('UPDATE checkpoints SET context_manifest_ref = ? WHERE id = ?')
        .run(manifestRef, reopened.latestCheckpoint.id);
      for (const guard of guards) connection.exec(guard.sql);
    });
    // Existing disposable-database corruption seam: preserve canonical hashes
    // and the complete context partition, changing only producer provenance.
    rewrite(candidateRef, contextRef);
    restore = () => rewrite(row.payloadRef, reopened.latestCheckpoint.contextManifestRef);
    const rejection = { code: 'RECOVERY_REQUIRED', message: /candidate recovery/ };
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), rejection);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), rejection);
    restore();
    restore = undefined;
    assert.deepEqual((await fixture.store.readRecoveryClosure(fixture.runId)).items, original.items);
  } finally {
    try { restore?.(); } finally { writer?.close(); await disposeFixture(fixture); }
  }
});

test('a candidate rejects unsupported nonempty verifiers rather than accepting a digest-only command and environment', async () => {
  const fixture = await createAgentFixture('candidate-nonempty-verifier', undefined, { mode: 'plan' });
  try {
    const { runSpec } = await fixture.store.readRecoveryClosure(fixture.runId);
    // Deliberately schema-invalid canonical data, not an executable identity,
    // verifier grant, permission, launch or physical execution evidence.
    const command = { schemaVersion: 1, format: 'not-a-verifier-command', commandDigest: '' };
    command.commandDigest = digestOmitting(command, 'commandDigest');
    const commandRef = (await fixture.store.artifacts.publishCanonical(command, 'cliq-verifier-command-v1')).ref;
    const environment = { schemaVersion: 1, format: 'not-a-verifier-environment', environmentDigest: '' };
    environment.environmentDigest = digestOmitting(environment, 'environmentDigest');
    const environmentRef = (await fixture.store.artifacts.publishCanonical(environment, 'cliq-verifier-environment-v1')).ref;
    const entry: VerifierSpec['verifiers'][number] = { index: 0, id: 'digest-only', version: '1', gate: 'advisory',
      commandRef, commandDigest: command.commandDigest, environmentRef, environmentDigest: environment.environmentDigest,
      timeoutMs: 1000, retries: 0, outputLimitBytes: 1024, entryDigest: '' };
    entry.entryDigest = digestOmitting(entry, 'entryDigest');
    const spec: VerifierSpec = { schemaVersion: 1, format: 'cliq-verifier-spec-v1', verifiers: [entry], specDigest: '' };
    spec.specDigest = digestOmitting(spec, 'specDigest');
    const verifierSpecRef = (await fixture.store.artifacts.publishCanonical(spec, spec.format)).ref;
    // Normal admission creates the exact RunSpec and consent under the same
    // StateOwner. No authority or historical RunSpec is manufactured by SQL.
    const admitted = await fixture.store.admitRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(),
      admissionKey: admissionKey('candidate-verifier-data-only'), sessionId: fixture.store.getRun(fixture.runId).sessionId,
      expectedContextRevision: 1, workspacePath: fixture.workspace, objective: 'Reject an unsupported verifier chain.', allowUnverified: true,
      assemblyRef: runSpec.assemblyRef, policyRef: runSpec.policyRef, sandboxProfileRef: runSpec.sandboxProfileRef,
      verifierSpecRef, credentialGrantRefs: runSpec.credentialGrantRefs, budgets: runSpec.budgets,
      sourceProjectionRef: runSpec.sourceProjectionRef, baseWorkspaceManifestRef: runSpec.baseWorkspaceManifestRef,
      frozenIgnoreRulesRef: (await fixture.store.artifacts.readCanonical<{ frozenIgnoreRulesRef: string }>(runSpec.sourceProjectionRef)).frozenIgnoreRulesRef });
    const target = { ...fixture,
      ...await activateFixtureWorker({ ...fixture, runId: admitted.run.id }, 'candidate-nonempty-verifier-worker') };
    target.agent = await fixture.store.loadAgentRun({ runId: target.runId, material: fixture.authority.material,
      releaseKeys: fixture.signed.releaseKeys });
    const { completed, checkpointId } = await completeFinalTurn(target);
    const proof = await quiescedToolCheckpoint(target, checkpointId, true);
    const before = await fixture.store.readRecoveryClosure(target.runId);
    await assert.rejects(target.agent.prepareFinalCandidate({ expectedRunRevision: completed.run.revision,
      checkpoint: proof.checkpoint }), { code: 'STATE_TRANSITION_INVALID' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(target.runId), before);
  } finally { await disposeFixture(fixture); }
});
