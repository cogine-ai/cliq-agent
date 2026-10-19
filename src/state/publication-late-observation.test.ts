// Inert data equations and real CAS/SQLite mapping, not a native observation,
// admitted Delivery, StateOwner, cleanup permission or Linux qualification.
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { decodePublicationLateObservationItem, publicationLateObservationItemId, publicationLateObservationCheckpointId } from '../kernel/publication.js';
import type { Checkpoint, ContextManifest, InvocationJournalEntry, RecoveryClosureV1, Run, RunFrontier } from '../kernel/types.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { planContinuationCommit } from './continuation-commit.js';
import { projectPublicationLateObservation, readPublicationLateObservation } from './publication-late-observation.js';
import { readCheckpoint, ZERO_BUDGET } from './rows.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { createQueuedFixture, disposeFixture } from './testing/fixtures.js';
import type { SqliteDriver } from './sqlite-driver.js';

function data() {
  const ref = 'a'.repeat(64), at = '2026-10-19T00:00:31.000Z';
  const frontier: RunFrontier = { schemaVersion: 1, kind: 'delivery', phase: 'merge', sourceRunResultRef: ref, capturedWorkspaceRef: ref };
  const run: Run = { id: 'data-only-run', sessionId: 'data-session', specRef: ref, status: 'waiting', nextStep: 'delivery',
    frontierRef: canonicalSha256(frontier), waitingReason: 'reconciliation', waitingOnRef: ref, revision: 7, leaseEpoch: 1,
    latestCheckpointId: 'data-before', budgetReserved: ZERO_BUDGET, budgetConsumed: { ...ZERO_BUDGET, toolCalls: 4 }, repairCount: 0,
    cancelRequested: true, stopIntentRef: ref, createdAt: '2026-10-19T00:00:00.000Z', updatedAt: at, deadlineAt: '2026-10-19T00:01:00.000Z' };
  const previous: Checkpoint = { id: run.latestCheckpointId, schemaVersion: 1, runId: run.id, basedOnRunRevision: 5,
    runItemSeq: 0, contextManifestRef: ref, journalSeq: 3, workspaceStateRef: ref, createdAt: run.createdAt, reason: 'auto' };
  const prepared: InvocationJournalEntry = { runId: run.id, opId: 'data-op', opKind: 'publish', seq: 1, phase: 'prepared', attempt: 0,
    leaseEpoch: 1, target: ref, requestRef: ref, grantRef: ref, replayClass: 'reconcile', budgetDelta: ZERO_BUDGET, timestamp: run.createdAt };
  const claim: InvocationJournalEntry = { ...prepared, seq: 2, phase: 'dispatch_claimed', dispatchId: 'original-dispatch' };
  const unknown: InvocationJournalEntry = { ...claim, seq: 3, phase: 'unknown', budgetSettlementRef: ref, evidenceRef: ref, evidenceDigest: ref };
  const item = decodePublicationLateObservationItem({ schemaVersion: 1, kind: 'publication_late_observation',
    itemId: publicationLateObservationItemId(run.id, claim.opId, 0, ref, ref), runId: run.id, deliveryPlanRef: ref,
    sequence: 'forward', operationIndex: 0, operationId: identityHash('data-operation'), opId: claim.opId, attempt: 0,
    dispatchId: claim.dispatchId, claimJournalSeq: 2, probeWaitingSubjectRef: run.waitingOnRef, probeDispatchDigest: ref,
    evidenceRef: ref, evidenceDigest: ref, disposition: 'unknown', completedAt: at, createdAt: at });
  const checkpoint: Checkpoint = { ...previous, id: publicationLateObservationCheckpointId(run.id, claim.opId, 0, ref, ref),
    basedOnRunRevision: 7, runItemSeq: 1, contextManifestRef: 'b'.repeat(64), createdAt: at };
  const after = { ...run, latestCheckpointId: checkpoint.id, revision: 8 };
  const cut: Pick<RecoveryClosureV1, 'run' | 'latestCheckpoint' | 'items' | 'journal'> = {
    run, latestCheckpoint: previous, items: [], journal: [prepared, claim, unknown] };
  return { cut, item, checkpoint, after, frontier };
}

test('late audit data appends one excluded item without closing the nonce or changing UNKNOWN accounting', () => {
  const { cut, item, checkpoint, after } = data(), before = structuredClone(cut);
  const projected = projectPublicationLateObservation(cut, item, checkpoint, after);
  assert.equal(projected.items.length, 1); assert.equal(projected.items[0]!.payloadRef, canonicalSha256(item));
  for (const key of ['status', 'waitingReason', 'waitingOnRef', 'nextStep', 'frontierRef', 'budgetConsumed', 'budgetReserved', 'stopIntentRef'] as const)
    assert.deepEqual(projected.run[key], cut.run[key]);
  assert.deepEqual(cut, before);
});

test('late audit exact-delta rejects checkpoint, Journal, nonce, Stop and budget drift', () => {
  const { cut, item, checkpoint, after } = data();
  for (const changed of [{ ...after, waitingOnRef: 'c'.repeat(64) }, { ...after, status: 'queued' as const },
    { ...after, revision: 9 }, { ...after, cancelRequested: false }, { ...after, budgetReserved: { ...ZERO_BUDGET, toolCalls: 1 } },
    { ...after, budgetConsumed: { ...ZERO_BUDGET, toolCalls: 5 } }])
    assert.throws(() => projectPublicationLateObservation(cut, item, checkpoint, changed));
  for (const changed of [{ ...checkpoint, journalSeq: 4 }, { ...checkpoint, workspaceStateRef: 'c'.repeat(64) },
    { ...checkpoint, runItemSeq: 2 }, { ...checkpoint, basedOnRunRevision: 6 }, { ...checkpoint, reason: 'handoff' as const }])
    assert.throws(() => projectPublicationLateObservation(cut, item, changed, after));
  assert.throws(() => projectPublicationLateObservation({ ...cut, journal: cut.journal.slice(0, 2) }, item, checkpoint, after));
});

test('a fixed fact remains auditable after a later validated Stop without retiming the fact', () => {
  const { cut, item, checkpoint } = data();
  const later = '2026-10-19T00:00:32.000Z', current = { ...cut.run, revision: 8, updatedAt: later };
  const cp = { ...checkpoint, basedOnRunRevision: 8, createdAt: later };
  const projected = projectPublicationLateObservation({ ...cut, run: current }, item, cp,
    { ...current, latestCheckpointId: cp.id, revision: 9 });
  assert.equal(projected.items[0]!.createdAt, item.createdAt);
  assert.equal(projected.run.updatedAt, later); assert.equal(projected.run.stopIntentRef, current.stopIntentRef);
});

test('real CAS late-shaped data cannot give an Agent an original publication claim or audit checkpoint', async () => {
  const fixture = await createQueuedFixture('late-audit-no-authority');
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId), { item } = data();
    const artifact = await fixture.store.artifacts.publishCanonical(item, 'cliq-publication-late-observation-item-v1');
    const driver = (fixture.store as unknown as { driver: SqliteDriver }).driver;
    await assert.rejects(readPublicationLateObservation(driver, fixture.store.artifacts, {} as never, before,
      { history: [] } as never, new Map(), { schemaVersion: 1, itemId: item.itemId, itemSeq: 1,
        payloadRef: artifact.ref, payloadDigest: artifact.ref, createdAt: item.createdAt }, before.latestCheckpoint), /original unresolved claim/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('real CAS and SQLite keep late raw audit excluded, with original W_M and untouched Journal and waiting columns', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-late-audit-data-'));
  await mkdir(path.join(home, 'objects'), { mode: 0o700 });
  const driver = openSqliteDriver(path.join(home, 'data.sqlite'));
  try {
    driver.exec(`CREATE TABLE items (item_id TEXT,session_id TEXT,run_id TEXT,item_seq INTEGER,kind TEXT,payload_ref TEXT,created_at TEXT);
      CREATE TABLE checkpoints (id TEXT PRIMARY KEY,schema_version INTEGER,run_id TEXT,based_on_run_revision INTEGER,
        run_item_seq INTEGER,context_manifest_ref TEXT,journal_seq INTEGER,workspace_state_ref TEXT,created_at TEXT,reason TEXT);
      CREATE TABLE runs (id TEXT PRIMARY KEY,latest_checkpoint_id TEXT,frontier_ref TEXT,next_step TEXT,waiting_on_ref TEXT,status TEXT,budget TEXT);
      CREATE TABLE run_journal (entry_json TEXT);`);
    const { cut, item, frontier } = data();
    driver.prepare('INSERT INTO runs VALUES (?,?,?,?,?,?,?)').run(cut.run.id, cut.run.latestCheckpointId, cut.run.frontierRef!,
      cut.run.nextStep, cut.run.waitingOnRef!, cut.run.status, JSON.stringify(cut.run.budgetConsumed));
    for (const row of cut.journal) driver.prepare('INSERT INTO run_journal VALUES (?)').run(JSON.stringify(row));
    const beforeJournal = driver.prepare('SELECT * FROM run_journal').all();
    const context: ContextManifest = { schemaVersion: 1, format: 'cliq-context-manifest-v1', runId: cut.run.id, throughItemSeq: 0,
      admittedContextRef: item.evidenceRef, assemblyRef: item.evidenceRef, segments: [], projectionDigest: '' };
    context.projectionDigest = digestOmitting(context, 'projectionDigest');
    const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(home, 'objects')));
    const graph = planContinuationCommit(artifacts, { context, existingItems: [], items: [item], frontier,
      checkpointId: publicationLateObservationCheckpointId(item.runId, item.opId, 0, item.probeDispatchDigest, item.evidenceRef),
      workspaceStateRef: cut.latestCheckpoint.workspaceStateRef });
    const actual = await graph.publish();
    driver.transaction(connection => actual.commit(connection, cut.run, cut.journal.length, item.createdAt));
    const cp = readCheckpoint(driver, graph.runUpdate.latestCheckpointId);
    const projected = projectPublicationLateObservation(cut, item, cp,
      { ...cut.run, latestCheckpointId: cp.id, revision: cut.run.revision + 1, updatedAt: cp.createdAt });
    assert.equal(projected.items.length, 1);
    const retained = await artifacts.readCanonical<ContextManifest>(cp.contextManifestRef);
    assert.equal(retained.segments.length, 1); assert.equal(retained.segments[0]!.kind, 'excluded_control');
    assert.deepEqual(await artifacts.readCanonical(canonicalSha256(item)), item);
    const row = driver.prepare('SELECT waiting_on_ref,status,budget FROM runs').get();
    assert.deepEqual({ ...row }, { waiting_on_ref: cut.run.waitingOnRef, status: cut.run.status, budget: JSON.stringify(cut.run.budgetConsumed) });
    assert.deepEqual(driver.prepare('SELECT * FROM run_journal').all(), beforeJournal);
  } finally { driver.close(); await rm(home, { recursive: true, force: true }); }
});
