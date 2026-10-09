import assert from 'node:assert/strict';
import path from 'node:path';
import { rm } from 'node:fs/promises';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { addCanonicalDuration, digestOmitting, identityHash } from '../kernel/identity.js';
import type { ReconciliationProbeEvidenceV1, ReconciliationProbeTimeoutClosureV1, SupervisorInspectorIdentityV1, WorkerDeathWait } from '../kernel/types.js';
import { KERNEL_SCHEMA_V2_SQL, KERNEL_SCHEMA_V3_SQL, readSchemaUserVersion } from './schema.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, type StateStore } from './store.js';
import { createActiveFixture, disposeFixture, makePrivateDir } from './testing/fixtures.js';
import { childFor } from './testing/state-owner-process.js';

test('public Store.close refuses an unjoined same-owner worker probe and retains its actual lock', async t => {
  const container = await makePrivateDir('.cliq-worker-unjoined-close-');
  const child = await childFor(t, container, 'fixture_probe');
  let store: StateStore | undefined;
  t.after(async () => { await store?.close(); await rm(container, { recursive: true, force: true }); });
  const started = await child.request('acquire');
  assert.equal(started.state, 'held', started.message);
  const refused = await child.probe('close-and-begin-probe', started.runId!, started.runRevision!, Date.now());
  assert.equal(refused.state, 'close-and-probe');
  assert.equal(refused.closeCode, 'RECOVERY_REQUIRED');
  assert.equal(refused.probeCode, 'LEASE_FENCED');
  assert.equal(refused.runRevision, started.runRevision);
  assert.deepEqual(refused.wait, started.wait, 'shutdown must not mint a new nonce or replace the persisted dispatch');
  const contender = await childFor(t, started.stateRoot!);
  assert.equal((await contender.request('acquire', started.authority)).state, 'error', 'failed graceful close must retain the actual owner lock');
  child.child.kill('SIGKILL');
  assert.equal((await child.exited)[1], 'SIGKILL');
  store = await openStateStore(started.stateRoot!, started.authority);
  const retained = await store.readRecoveryClosure(started.runId!);
  assert.equal(retained.run.revision, started.runRevision);
  assert.equal(retained.run.waitingOnRef, started.waitingOnRef);
});

test('a real v2 database reopens and persists one exact worker inspection before I/O', async t => {
  const fixture = await createActiveFixture('worker-probe-v2');
  let child: Awaited<ReturnType<typeof childFor>> | undefined;
  t.after(async () => {
    if (child && child.child.exitCode === null && child.child.signalCode === null) child.child.kill('SIGKILL');
    if (child) await child.exited;
    await disposeFixture(fixture);
  });
  const waiting = await fixture.store.beginWorkerRecovery({ runId: fixture.runId,
    expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
  const before = await fixture.store.readRecoveryClosure(fixture.runId);
  await fixture.store.close();
  const legacy = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    // Recreate V2 around real retained work, rather than relabel a V4 layout.
    // Upgrade must install its missing schema; no existing V4 authority is
    // accepted or backfilled as if it had belonged to the older database.
    legacy.transaction(connection => {
      connection.exec('DROP TRIGGER sessions_admission_identity_immutable');
      connection.exec('DROP TRIGGER runs_admission_identity_immutable');
      connection.exec('ALTER TABLE sessions DROP COLUMN admission_request_id');
      connection.exec('ALTER TABLE runs DROP COLUMN admission_request_id');
      connection.exec('DROP TABLE source_inspection_attempts');
      const start = KERNEL_SCHEMA_V2_SQL.indexOf('CREATE TRIGGER workspace_generations_validate_update');
      const end = KERNEL_SCHEMA_V2_SQL.indexOf('CREATE TRIGGER workspace_generations_immutable_delete', start);
      connection.exec(`DROP TRIGGER workspace_generations_validate_update; ${KERNEL_SCHEMA_V2_SQL.slice(start, end)}`);
      connection.exec('PRAGMA user_version=2');
    });
  } finally { legacy.close(); }
  child = await childFor(t, fixture.stateRoot);
  const acquired = await child.request('acquire', fixture.runtimeAuthority);
  assert.equal(acquired.state, 'held', acquired.message);
  const probing = await child.probe('begin-probe', fixture.runId, waiting.revision, Date.now());
  assert.equal(probing.state, 'probed', probing.message);
  child.child.kill('SIGKILL');
  assert.equal((await child.exited)[1], 'SIGKILL');
  fixture.store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
  const after = await fixture.store.readRecoveryClosure(fixture.runId);
  const probe = after.run;
  const wait = await fixture.store.artifacts.readCanonical<WorkerDeathWait>(probe.waitingOnRef!);
  assert.equal(wait.probeState.phase, 'automatic_in_flight');
  if (wait.probeState.phase !== 'automatic_in_flight') throw new Error('inspection was not durably enqueued');
  const dispatch = wait.probeState.dispatch;
  assert.equal(dispatch.subjectKind, 'worker_recovery');
  if (dispatch.subjectKind !== 'worker_recovery') throw new Error('incorrect inspection subject');
  assert.equal(dispatch.inspectionTargetDigest, canonicalSha256(before.workspaceGenerations[0]));
  assert.deepEqual(await fixture.store.artifacts.readCanonical(dispatch.inspectionTargetDigest), before.workspaceGenerations[0]);
  const previous = await fixture.store.artifacts.readCanonical<WorkerDeathWait>(waiting.waitingOnRef!);
  assert.deepEqual({ ...wait, probeState: previous.probeState }, previous);
  assert.equal(dispatch.reconciliationSubjectDigest, canonicalSha256(previous.subject));
  assert.equal(dispatch.probeOrdinal, 1);
  assert.equal(dispatch.probeDeadlineAt, addCanonicalDuration(dispatch.probeStartedAt, 30_000));
  assert.equal(dispatch.dispatchDigest, digestOmitting(dispatch, 'dispatchDigest'));
  assert.equal(dispatch.inspectorTaskId, identityHash(fixture.runId, canonicalSha256(previous.subject), 'automatic', 1, dispatch.probeNonceDigest));
  assert.equal(probe.revision, waiting.revision + 1);
  assert.deepEqual(after.journal, before.journal);
  assert.deepEqual(after.workerLaunches, before.workerLaunches);
  const generation = after.workspaceGenerations[0]!;
  assert.deepEqual(generation, { ...before.workspaceGenerations[0], rowVersion: before.workspaceGenerations[0]!.rowVersion + 1,
    updatedAt: probe.updatedAt, waitingSubjectRef: probe.waitingOnRef, waitingSubjectDigest: probe.waitingOnRef });
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    assert.equal(readSchemaUserVersion(driver), KERNEL_STATE_SCHEMA_VERSION);
    assert.throws(() => driver.prepare('UPDATE workspace_generations SET row_version=row_version+1, row_json=? WHERE generation_id=?')
      .run(JSON.stringify({ ...generation, rowVersion: generation.rowVersion + 1, fencedJournalSeq: generation.fencedJournalSeq + 1 }), generation.generationId),
    /frozen|transition/);
  } finally { driver.close(); }
  await fixture.store.close();
  fixture.store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
  assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), after);
  await assert.rejects(fixture.store.beginWorkerRecoveryProbe({ runId: fixture.runId, expectedRunRevision: probe.revision }),
    { code: 'STATE_TRANSITION_INVALID' });
  const tampered = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    // Model retained-state corruption, not an authorized transition; the owning guard remains tested above.
    tampered.exec('DROP TRIGGER workspace_generations_validate_update');
    for (const change of [{ generationIdentityDigest: identityHash('foreign-anchor') },
      { fencedJournalSeq: before.workspaceGenerations[0]!.fencedJournalSeq! + 1 },
      { rowVersion: before.workspaceGenerations[0]!.rowVersion + 1 }]) {
      const forgedAnchor = await fixture.store.artifacts.publishCanonical({ ...before.workspaceGenerations[0], ...change }, 'cliq-workspace-generation-state-v1');
      const forgedDispatch = { ...dispatch, inspectionTargetDigest: forgedAnchor.ref, dispatchDigest: '' };
      forgedDispatch.dispatchDigest = digestOmitting(forgedDispatch, 'dispatchDigest');
      await fixture.store.artifacts.publishCanonical(forgedDispatch, forgedDispatch.format);
      const forgedWait = await fixture.store.artifacts.publishCanonical({ ...wait, probeState: { ...wait.probeState, dispatch: forgedDispatch } }, 'cliq-waiting-subject-v1');
      tampered.prepare('UPDATE runs SET waiting_on_ref=? WHERE id=?').run(forgedWait.ref, fixture.runId);
      tampered.prepare('UPDATE workspace_generations SET row_json=? WHERE generation_id=?')
        .run(JSON.stringify({ ...generation, waitingSubjectRef: forgedWait.ref, waitingSubjectDigest: forgedWait.ref }), generation.generationId);
      const forgedRun = fixture.store.getRun(fixture.runId);
      await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
      assert.deepEqual(fixture.store.getRun(fixture.runId), forgedRun);
    }
    tampered.prepare('UPDATE runs SET waiting_on_ref=? WHERE id=?').run(probe.waitingOnRef!, fixture.runId);
    tampered.prepare('UPDATE workspace_generations SET row_json=? WHERE generation_id=?').run(JSON.stringify(generation), generation.generationId);
  } finally { tampered.close(); }
  assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), after);
});

test('a SIGKILL successor fence-closes the old nonce and reuses its fixed quarantine intent in a fresh probe', async t => {
  const container = await makePrivateDir('.cliq-worker-probe-successor-');
  const child = await childFor(t, container, 'fixture_probe');
  const started = await child.request('acquire');
  assert.equal(started.state, 'held', started.message);
  child.child.kill('SIGKILL');
  assert.equal((await child.exited)[1], 'SIGKILL');
  let store = await openStateStore(started.stateRoot!, started.authority);
  let successor: Awaited<ReturnType<typeof childFor>> | undefined;
  t.after(async () => {
    if (successor && successor.child.exitCode === null && successor.child.signalCode === null) successor.child.kill('SIGKILL');
    if (successor) await successor.exited;
    await store.close(); await rm(container, { recursive: true, force: true });
  });
  const before = await store.readRecoveryClosure(started.runId!);
  const oldWait = await store.artifacts.readCanonical<WorkerDeathWait>(before.run.waitingOnRef!);
  assert.equal(oldWait.probeState.phase, 'automatic_in_flight');
  if (oldWait.probeState.phase !== 'automatic_in_flight') throw new Error('child did not persist its inspection');
  const oldDispatch = oldWait.probeState.dispatch;
  if (oldDispatch.subjectKind !== 'worker_recovery') throw new Error('child did not persist worker inspection');
  let now = Date.parse(oldDispatch.probeDeadlineAt);
  t.mock.method(Date, 'now', () => now);
  const closed = await store.closeWorkerRecoveryProbe({ runId: started.runId!, expectedRunRevision: before.run.revision });
  const pending = await store.artifacts.readCanonical<WorkerDeathWait>(closed.waitingOnRef!);
  assert.equal(pending.probeState.phase, 'automatic_pending');
  if (pending.probeState.phase !== 'automatic_pending' || pending.probeState.automaticProbeCount !== 1) throw new Error('successor did not preserve its completed probe count');
  assert.equal(pending.probeState.nextProbeAt, addCanonicalDuration(oldDispatch.probeDeadlineAt, 1000));
  const wrapper = await store.artifacts.readCanonical<Record<string, unknown>>(pending.probeState.lastProbeEvidenceRef!);
  assert.equal(wrapper.outcome, 'probe_timeout');
  assert.equal(wrapper.probeNonceDigest, oldDispatch.probeNonceDigest);
  assert.equal(wrapper.waitingSubjectRef, before.run.waitingOnRef);
  const timeout = await store.artifacts.readCanonical<Record<string, unknown>>(wrapper.timeoutClosureRef as string);
  assert.equal((timeout.taskClosure as { closureKind: string }).closureKind, 'owner_process_dead');
  const acquisition = await store.artifacts.readCanonical<Record<string, unknown>>(
    (timeout.taskClosure as { ownerDeathAcquisitionEvidenceRef: string }).ownerDeathAcquisitionEvidenceRef);
  assert.equal(acquisition.kind, 'takeover_after_owner_death');
  const originalCut = await store.readRecoveryClosure(started.runId!);
  const inspector = await store.artifacts.readCanonical<SupervisorInspectorIdentityV1>(wrapper.inspectorIdentityRef as string);
  assert.ok(oldDispatch.probeStartedAt < inspector.activatedAt, 'the actual successor acquired after the original task started');
  // Disposable retained-byte corruption: rebind the predecessor task to the
  // actual signed successor while falsely claiming that successor joined it.
  const forgedDispatch = { ...oldDispatch, owningSupervisorInstanceId: inspector.supervisorInstanceId, dispatchDigest: '' };
  forgedDispatch.dispatchDigest = digestOmitting(forgedDispatch, 'dispatchDigest');
  await store.artifacts.publishCanonical(forgedDispatch, forgedDispatch.format);
  const forgedPrior = await store.artifacts.publishCanonical({ ...oldWait,
    probeState: { ...oldWait.probeState, dispatch: forgedDispatch } }, 'cliq-waiting-subject-v1');
  const forgedTimeout = { ...timeout, waitingSubjectRef: forgedPrior.ref, probeDispatchDigest: forgedDispatch.dispatchDigest,
    taskClosure: { closureKind: 'cancelled_and_joined', inspectorTaskCancelledAndJoined: true }, closureDigest: '' } as ReconciliationProbeTimeoutClosureV1;
  forgedTimeout.closureDigest = digestOmitting(forgedTimeout, 'closureDigest');
  const timeoutArtifact = await store.artifacts.publishCanonical(forgedTimeout, forgedTimeout.format);
  const forgedWrapper = { ...wrapper, waitingSubjectRef: forgedPrior.ref, waitingSubjectDigest: forgedPrior.ref,
    probeDispatchDigest: forgedDispatch.dispatchDigest, timeoutClosureRef: timeoutArtifact.ref,
    timeoutClosureDigest: forgedTimeout.closureDigest, evidenceDigest: '' } as ReconciliationProbeEvidenceV1;
  forgedWrapper.evidenceDigest = digestOmitting(forgedWrapper, 'evidenceDigest');
  const wrapperArtifact = await store.artifacts.publishCanonical(forgedWrapper, forgedWrapper.format);
  const forgedPending = await store.artifacts.publishCanonical({ ...pending, probeState: { ...pending.probeState,
    lastProbeEvidenceRef: wrapperArtifact.ref, lastProbeEvidenceDigest: forgedWrapper.evidenceDigest } }, 'cliq-waiting-subject-v1');
  const corrupted = openSqliteDriver(path.join(started.stateRoot!, KERNEL_DATABASE_FILENAME));
  try {
    corrupted.exec('DROP TRIGGER workspace_generations_validate_update');
    corrupted.prepare('UPDATE runs SET waiting_on_ref=? WHERE id=?').run(forgedPending.ref, started.runId!);
    const generation = originalCut.workspaceGenerations[0]!;
    corrupted.prepare('UPDATE workspace_generations SET row_json=? WHERE generation_id=?')
      .run(JSON.stringify({ ...generation, waitingSubjectRef: forgedPending.ref, waitingSubjectDigest: forgedPending.ref }), generation.generationId);
    await assert.rejects(store.readRecoveryClosure(started.runId!), { code: 'RECOVERY_REQUIRED' });
  } finally {
    corrupted.prepare('UPDATE runs SET waiting_on_ref=? WHERE id=?').run(closed.waitingOnRef!, started.runId!);
    const generation = originalCut.workspaceGenerations[0]!;
    corrupted.prepare('UPDATE workspace_generations SET row_json=? WHERE generation_id=?').run(JSON.stringify(generation), generation.generationId);
    corrupted.exec(KERNEL_SCHEMA_V3_SQL.slice(KERNEL_SCHEMA_V3_SQL.indexOf('CREATE TRIGGER')));
    corrupted.close();
  }
  assert.deepEqual(await store.readRecoveryClosure(started.runId!), originalCut);
  await assert.rejects(store.beginWorkerRecoveryProbe({ runId: started.runId!, expectedRunRevision: closed.revision }),
    { code: 'STATE_TRANSITION_INVALID' });
  now += 1000;
  await store.close();
  successor = await childFor(t, started.stateRoot!);
  assert.equal((await successor.request('acquire', started.authority, now)).state, 'held');
  const nextReply = await successor.probe('begin-probe', started.runId!, closed.revision, now);
  assert.equal(nextReply.state, 'probed', nextReply.message);
  const fresh = nextReply.wait!;
  if (fresh.probeState.phase !== 'automatic_in_flight' || fresh.probeState.dispatch.subjectKind !== 'worker_recovery') throw new Error('successor did not persist a fresh worker inspection');
  assert.equal(fresh.probeState.automaticProbeCount, 2);
  assert.notEqual(fresh.probeState.dispatch.probeNonceDigest, oldDispatch.probeNonceDigest);
  assert.notEqual(fresh.probeState.dispatch.owningSupervisorInstanceId, oldDispatch.owningSupervisorInstanceId);
  assert.equal(fresh.probeState.dispatch.inspectionTargetDigest, oldDispatch.inspectionTargetDigest);
  now = Date.parse(fresh.probeState.dispatch.probeDeadlineAt);
  const unjoined = await successor.probe('close-probe', started.runId!, nextReply.runRevision!, now);
  assert.equal(unjoined.state, 'error');
  assert.equal(unjoined.code, 'RECOVERY_REQUIRED');
  successor.child.kill('SIGKILL');
  assert.equal((await successor.exited)[1], 'SIGKILL');
  store = await openStateStore(started.stateRoot!, started.authority);
  const after = await store.readRecoveryClosure(started.runId!);
  assert.deepEqual(after.journal, before.journal);
  assert.equal(after.workspaceGenerations[0]!.rowVersion, before.workspaceGenerations[0]!.rowVersion + 2);
  await assert.rejects(store.closeWorkerRecoveryProbe({ runId: started.runId!, expectedRunRevision: before.run.revision }),
    { code: 'REVISION_CONFLICT' });
  assert.deepEqual(await store.readRecoveryClosure(started.runId!), after);
});

test('eight actual owner deaths exhaust the persisted worker schedule without retargeting or a ninth probe', async t => {
  const container = await makePrivateDir('.cliq-worker-probe-exhaustion-');
  const first = await childFor(t, container, 'fixture_probe');
  const started = await first.request('acquire');
  assert.equal(started.state, 'held', started.message);
  let wait = started.wait!;
  let revision = started.runRevision!;
  if (wait.probeState.phase !== 'automatic_in_flight' || wait.probeState.dispatch.subjectKind !== 'worker_recovery') throw new Error('missing initial dispatch');
  const anchor = wait.probeState.dispatch.inspectionTargetDigest;
  const nonces = new Set([wait.probeState.dispatch.probeNonceDigest]);
  first.child.kill('SIGKILL');
  assert.equal((await first.exited)[1], 'SIGKILL');
  let now = Date.parse(wait.probeState.dispatch.probeDeadlineAt);
  t.mock.method(Date, 'now', () => now);
  const delays = [1000, 5000, 30_000, 120_000, 600_000, 1_800_000, 3_600_000];
  for (let count = 1; count <= 8; count++) {
    const successor = await childFor(t, started.stateRoot!);
    assert.equal((await successor.request('acquire', started.authority, now)).state, 'held');
    const closed = await successor.probe('close-probe', started.runId!, revision, now);
    assert.equal(closed.state, 'probed', closed.message);
    const pending = closed.wait!;
    assert.equal(pending.probeState.automaticProbeCount, count);
    assert.equal(pending.probeState.userProbeCount, 0);
    assert.equal(pending.probeState.phase, count === 8 ? 'automatic_exhausted' : 'automatic_pending');
    if (count === 8) {
      const ninth = await successor.probe('begin-probe', started.runId!, closed.runRevision!, now + 3_600_000);
      assert.equal(ninth.state, 'error');
      assert.equal(ninth.code, 'STATE_TRANSITION_INVALID');
      // Failed due checks are read-only, including the canonical-time fence.
      assert.equal((await successor.request('close')).state, 'released');
      now += 3_600_000;
      break;
    }
    if (pending.probeState.phase !== 'automatic_pending') throw new Error('missing pending schedule');
    assert.equal(pending.probeState.nextProbeAt, addCanonicalDuration(new Date(now).toISOString(), delays[count - 1]!));
    now = Date.parse(pending.probeState.nextProbeAt);
    const fresh = await successor.probe('begin-probe', started.runId!, closed.runRevision!, now);
    assert.equal(fresh.state, 'probed', fresh.message);
    wait = fresh.wait!;
    revision = fresh.runRevision!;
    if (wait.probeState.phase !== 'automatic_in_flight' || wait.probeState.dispatch.subjectKind !== 'worker_recovery') throw new Error('missing successor dispatch');
    assert.equal(wait.probeState.dispatch.inspectionTargetDigest, anchor);
    assert.equal(wait.probeState.automaticProbeCount, count + 1);
    assert.equal(nonces.has(wait.probeState.dispatch.probeNonceDigest), false);
    nonces.add(wait.probeState.dispatch.probeNonceDigest);
    successor.child.kill('SIGKILL');
    assert.equal((await successor.exited)[1], 'SIGKILL');
    now = Date.parse(wait.probeState.dispatch.probeDeadlineAt);
  }
  const store = await openStateStore(started.stateRoot!, started.authority);
  t.after(async () => { await store.close(); await rm(container, { recursive: true, force: true }); });
  const closure = await store.readRecoveryClosure(started.runId!);
  const exhausted = await store.artifacts.readCanonical<WorkerDeathWait>(closure.run.waitingOnRef!);
  assert.equal(exhausted.probeState.phase, 'automatic_exhausted');
  assert.equal(exhausted.probeState.automaticProbeCount, 8);
  assert.equal(nonces.size, 8);
  assert.equal(closure.journal.length, 0);
  assert.equal(closure.workspaceGenerations[0]!.phase, 'fenced_reconciling');
});
