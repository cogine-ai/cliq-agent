import assert from 'node:assert/strict';
import { rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { InvocationJournalEntry, WorkerDeathWait, WorkerIdentity } from '../kernel/types.js';
import { readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { openSqliteDriver, type SqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { activateFixtureWorker, createActiveFixture, digest, disposeFixture, makePrivateDir, uuidv7, type ActiveFixture } from './testing/fixtures.js';
import { childFor } from './testing/state-owner-process.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';

const ZERO = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
const revision = (fixture: ActiveFixture) => fixture.store.getRun(fixture.runId).revision;
const begin = (fixture: ActiveFixture) => fixture.store.beginWorkerRecovery({ runId: fixture.runId, expectedRunRevision: revision(fixture) });
function withDb<T>(root: string, operation: (driver: SqliteDriver) => T): T {
  const driver = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
  try { return operation(driver); } finally { driver.close(); }
}
function snapshot(root: string) {
  return withDb(root, driver => Object.fromEntries(['runs', 'worker_launches', 'workspace_generations', 'run_journal',
    'artifacts', 'canonical_time_fence', 'items', 'checkpoints', 'sessions', 'control_requests', 'run_events']
    .map(table => [table, driver.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()])));
}
async function fixtureFor(t: TestContext, label: string) {
  const fixture = await createActiveFixture(`worker-fence-${label}`);
  t.after(() => disposeFixture(fixture));
  return fixture;
}
async function prepare(fixture: ActiveFixture, opId: string, claimed = false) {
  const request = await fixture.store.artifacts.publishCanonical({ input: opId }, 'cliq-test-request-v1');
  const prepared = await fixture.store.prepareInvocation({ runId: fixture.runId, expectedRunRevision: revision(fixture),
    leaseEpoch: fixture.leaseEpoch, opId, opKind: 'tool', target: 'test.read', requestRef: request.ref,
    replayClass: 'manual', reservation: { ...ZERO, toolCalls: 1 } });
  if (claimed) await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: revision(fixture),
    leaseEpoch: fixture.leaseEpoch, opId, attempt: prepared.entry.attempt, dispatchId: `${opId}-dispatch`,
    brokerFenceTokenDigest: digest(`${opId}-fence`) });
  return prepared.entry;
}

for (const phase of ['active', 'revoking', 'checkpointing'] as const) {
  test(`worker loss atomically fences ${phase}, preserves its exact history and denies replacement`, async t => {
    const fixture = await fixtureFor(t, phase);
    const unclaimed = await prepare(fixture, 'unclaimed');
    const claimed = await prepare(fixture, 'claimed', true);
    const unknown = await prepare(fixture, 'unknown', true);
    const evidence = await fixture.store.artifacts.publishCanonical({ uncertain: true }, 'cliq-test-ambiguity-v1');
    await fixture.store.markInvocationUnknown({ runId: fixture.runId, expectedRunRevision: revision(fixture),
      opId: unknown.opId, attempt: unknown.attempt, evidenceRef: evidence.ref, evidenceDigest: evidence.ref });
    const completed = await prepare(fixture, 'completed', true);
    const result = await fixture.store.artifacts.publishCanonical({ done: true }, 'cliq-test-result-v1');
    await fixture.store.completeInvocation({ runId: fixture.runId, expectedRunRevision: revision(fixture),
      opId: completed.opId, attempt: completed.attempt, resultRef: result.ref, consumed: { ...ZERO, toolCalls: 1 } });
    if (phase !== 'active') {
      const revoking = fixture.store.beginGenerationRevocation({ launchId: fixture.launchId, expectedLeaseVersion: fixture.leaseVersion,
        expectedGenerationRowVersion: fixture.generationRowVersion, quiesceId: 'retained-barrier' });
      if (phase === 'checkpointing') fixture.store.beginGenerationCheckpoint({ launchId: fixture.launchId,
        expectedLeaseVersion: fixture.leaseVersion, expectedGenerationRowVersion: revoking.generation.rowVersion, quiesceId: 'retained-barrier' });
    }
    const before = await fixture.store.readRecoveryClosure(fixture.runId), rows = snapshot(fixture.stateRoot);
    const waiting = await begin(fixture);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(waiting.status, 'waiting');
    assert.equal(waiting.waitingReason, 'reconciliation');
    assert.equal(waiting.revision, before.run.revision + 1);
    assert.equal(waiting.activeWorkerLaunchId, undefined);
    assert.equal(waiting.leaseEpoch, before.run.leaseEpoch);
    assert.equal(waiting.frontierRef, before.run.frontierRef);
    assert.equal(waiting.latestCheckpointId, before.run.latestCheckpointId);
    assert.deepEqual(waiting.budgetReserved, before.run.budgetReserved);
    assert.deepEqual(waiting.budgetConsumed, before.run.budgetConsumed);
    const wait = await fixture.store.artifacts.readCanonical<WorkerDeathWait>(waiting.waitingOnRef!);
    assert.deepEqual(wait, {
      schemaVersion: 1, kind: 'reconciliation', runId: fixture.runId, createdFromRevision: before.run.revision,
      createdAt: wait.createdAt, frontierRef: before.run.frontierRef,
      subject: { kind: 'worker_death', oldWorkerLaunchId: fixture.launchId, oldLeaseEpoch: fixture.leaseEpoch,
        oldWorkerIdentity: fixture.workerIdentityDigest, processContainmentRef: before.workerLaunches[0]!.processContainmentRef,
        workspaceGenerationRef: fixture.generationRef, openInvocationRefs: [unclaimed, claimed, unknown].map(canonicalSha256) },
      probeState: { phase: 'automatic_pending', automaticProbeCount: 0, userProbeCount: 0, nextProbeAt: wait.createdAt }
    });
    assert.deepEqual(after.workerLaunches[0], { ...before.workerLaunches[0], phase: 'reconciling', generationWriteState: 'fenced_reconciling' });
    assert.deepEqual(after.workspaceGenerations[0], { ...before.workspaceGenerations[0], phase: 'fenced_reconciling',
      rowVersion: before.workspaceGenerations[0]!.rowVersion + 1, updatedAt: waiting.updatedAt,
      waitingSubjectRef: waiting.waitingOnRef, waitingSubjectDigest: waiting.waitingOnRef, fencedFromPhase: phase,
      fencedJournalSeq: before.journal.length });
    for (const entry of [unclaimed, claimed, unknown]) {
      assert.deepEqual(await fixture.store.artifacts.readCanonical(canonicalSha256(entry)), entry);
      assert.equal(withDb(fixture.stateRoot, driver => driver.prepare('SELECT schema_kind FROM artifacts WHERE ref = ?')
        .get<{ schema_kind: string }>(canonicalSha256(entry)))?.schema_kind, 'cliq-invocation-journal-entry-v1');
    }
    const afterRows = snapshot(fixture.stateRoot);
    for (const table of ['run_journal', 'items', 'checkpoints', 'sessions', 'control_requests']) assert.deepEqual(afterRows[table], rows[table], table);
    assert.equal((afterRows.run_events as unknown[]).length, (rows.run_events as unknown[]).length + 1);
    await assert.rejects(fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: waiting.revision,
      leaseEpoch: fixture.leaseEpoch, opId: unclaimed.opId, attempt: unclaimed.attempt, dispatchId: 'forbidden',
      brokerFenceTokenDigest: digest('forbidden') }), { code: 'LEASE_FENCED' });
    assert.throws(() => fixture.store.renewWorkerLease({ launchId: fixture.launchId, expectedLeaseVersion: fixture.leaseVersion,
      runId: fixture.runId, leaseEpoch: fixture.leaseEpoch, workerIdentityDigest: fixture.workerIdentityDigest,
      newLeaseExpiresAt: new Date(Date.now() + 30_000).toISOString() }), { code: 'LEASE_FENCED' });
    assert.throws(() => fixture.store.beginGenerationCheckpoint({ launchId: fixture.launchId, expectedLeaseVersion: fixture.leaseVersion,
      expectedGenerationRowVersion: after.workspaceGenerations[0]!.rowVersion, quiesceId: 'retained-barrier' }), { code: 'LEASE_FENCED' });
    await assert.rejects(activateFixtureWorker(fixture, 'forbidden-replacement'));
    await assert.rejects(begin(fixture), { code: 'STATE_TRANSITION_INVALID' });
    assert.deepEqual(fixture.store.getRun(fixture.runId), waiting);
  });
}

test('real owner death, takeover, fencing and another owner restart retain one unchanged worker wait', async t => {
  const container = await makePrivateDir('.cliq-worker-fence-crash-');
  const child = await childFor(t, container, 'fixture');
  const started = await child.request('acquire');
  assert.equal(started.state, 'held', started.message);
  child.child.kill('SIGKILL');
  assert.equal((await child.exited)[1], 'SIGKILL');
  let store = await openStateStore(started.stateRoot!);
  t.after(async () => { await store.close(); await rm(container, { recursive: true, force: true }); });
  assert.equal(store.ownerEpoch, 2);
  const before = await store.readRecoveryClosure(started.runId!);
  assert.equal(before.run.status, 'running'); // Owner acquisition itself still changes no Run row.
  const waiting = await store.beginWorkerRecovery({ runId: started.runId!, expectedRunRevision: before.run.revision });
  const frozen = await store.readRecoveryClosure(started.runId!);
  await store.close();
  store = await openStateStore(started.stateRoot!);
  assert.equal(store.ownerEpoch, 3);
  assert.deepEqual(await store.readRecoveryClosure(started.runId!), frozen);
  await assert.rejects(store.beginWorkerRecovery({ runId: started.runId!, expectedRunRevision: waiting.revision }), { code: 'STATE_TRANSITION_INVALID' });
});

test('parallel worker fences commit one Run revision and never reset the installed probe state', async t => {
  const fixture = await fixtureFor(t, 'race');
  const input = { runId: fixture.runId, expectedRunRevision: revision(fixture) };
  const results = await Promise.allSettled([fixture.store.beginWorkerRecovery(input), fixture.store.beginWorkerRecovery(input)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.filter(result => result.status === 'rejected' && result.reason.code === 'REVISION_CONFLICT').length, 1);
  const frozen = await fixture.store.readRecoveryClosure(fixture.runId);
  assert.equal(frozen.workspaceGenerations[0]!.fencedJournalSeq, 0);
  await assert.rejects(fixture.store.beginWorkerRecovery(input), { code: 'REVISION_CONFLICT' });
  assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), frozen);
});

for (const race of ['heartbeat', 'claim'] as const) {
  test(`${race} between observation and fence publication rejects the stale cut without partial revocation`, async t => {
    const fixture = await fixtureFor(t, race);
    const prepared = await prepare(fixture, 'racing');
    let reached!: () => void, release!: () => void;
    const observed = new Promise<void>(resolve => { reached = resolve; });
    const barrier = new Promise<void>(resolve => { release = resolve; });
    const publish = fixture.store.artifacts.publishCanonical.bind(fixture.store.artifacts);
    t.mock.method(fixture.store.artifacts, 'publishCanonical', async (value: unknown, kind: string) => {
      const artifact = await publish(value, kind);
      if (kind === 'cliq-waiting-subject-v1') { reached(); await barrier; }
      return artifact;
    });
    const pending = begin(fixture);
    await observed;
    if (race === 'heartbeat') fixture.store.renewWorkerLease({ launchId: fixture.launchId, expectedLeaseVersion: fixture.leaseVersion,
      runId: fixture.runId, leaseEpoch: fixture.leaseEpoch, workerIdentityDigest: fixture.workerIdentityDigest,
      newLeaseExpiresAt: new Date(Date.now() + 30_000).toISOString() });
    else await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: revision(fixture),
      leaseEpoch: fixture.leaseEpoch, opId: prepared.opId, attempt: prepared.attempt, dispatchId: 'won-before-fence',
      brokerFenceTokenDigest: digest('claim-race') });
    const afterRace = snapshot(fixture.stateRoot);
    release();
    await assert.rejects(pending, { code: 'REVISION_CONFLICT' });
    assert.deepEqual(snapshot(fixture.stateRoot), afterRace);
    await begin(fixture);
    await fixture.store.readRecoveryClosure(fixture.runId);
  });
}

for (const edge of ['BEFORE UPDATE ON worker_launches', 'BEFORE UPDATE ON runs', 'BEFORE INSERT ON run_events']) {
  test(`failure ${edge} rolls back the complete worker fence, artifact roots and canonical time`, async t => {
    const fixture = await fixtureFor(t, 'rollback');
    await prepare(fixture, 'retained', true);
    withDb(fixture.stateRoot, driver => driver.exec(`CREATE TRIGGER fail_worker_fence ${edge}
      BEGIN SELECT RAISE(ABORT, 'injected worker fence failure'); END;`));
    const before = snapshot(fixture.stateRoot);
    await assert.rejects(begin(fixture), /injected worker fence failure/);
    assert.deepEqual(snapshot(fixture.stateRoot), before);
    withDb(fixture.stateRoot, driver => driver.exec('DROP TRIGGER fail_worker_fence'));
    await begin(fixture);
    await fixture.store.readRecoveryClosure(fixture.runId);
  });
}

test('failed CAS publication leaves all authority untouched and a retry can use orphan witness bytes', async t => {
  const fixture = await fixtureFor(t, 'cas-failure');
  await prepare(fixture, 'open');
  const before = snapshot(fixture.stateRoot);
  const publish = fixture.store.artifacts.publishCanonical.bind(fixture.store.artifacts);
  const mocked = t.mock.method(fixture.store.artifacts, 'publishCanonical', async (value: unknown, kind: string) => {
    if (kind === 'cliq-waiting-subject-v1') throw new Error('injected wait publication failure');
    return publish(value, kind);
  });
  await assert.rejects(begin(fixture), /injected wait publication failure/);
  assert.deepEqual(snapshot(fixture.stateRoot), before);
  mocked.mock.restore();
  await begin(fixture);
  await fixture.store.readRecoveryClosure(fixture.runId);
});

test('late no-dispatch and pessimistic unknown settlements preserve the frozen wait and its invocation identities', async t => {
  const fixture = await fixtureFor(t, 'late-evidence');
  const prepared = await prepare(fixture, 'prepared');
  const claimed = await prepare(fixture, 'claimed', true);
  const waiting = await begin(fixture);
  const error = await fixture.store.artifacts.publishCanonical({ fenced: true }, 'cliq-test-error-v1');
  await fixture.store.failInvocationBeforeDispatch({ runId: fixture.runId, expectedRunRevision: revision(fixture),
    opId: prepared.opId, attempt: prepared.attempt, errorRef: error.ref });
  const ambiguity = await fixture.store.artifacts.publishCanonical({ unknown: true }, 'cliq-test-ambiguity-v1');
  await fixture.store.markInvocationUnknown({ runId: fixture.runId, expectedRunRevision: revision(fixture),
    opId: claimed.opId, attempt: claimed.attempt, evidenceRef: ambiguity.ref, evidenceDigest: ambiguity.ref });
  const cut = await fixture.store.readRecoveryClosure(fixture.runId);
  assert.equal(cut.run.status, 'waiting');
  assert.equal(cut.run.waitingOnRef, waiting.waitingOnRef);
  assert.deepEqual(cut.run.budgetReserved, ZERO);
  assert.deepEqual(cut.run.budgetConsumed, { ...ZERO, toolCalls: 1 });
  assert.deepEqual(cut.journal.slice(-2).map(entry => entry.phase), ['failed', 'unknown']);
});

for (const phase of ['completed', 'failed', 'abandoned'] as const) {
  test(`recovery rejects an extra ${phase} pre-fence witness but retains a same-millisecond late settlement`, async t => {
    const fixture = await fixtureFor(t, `historical-${phase}`);
    const now = withDb(fixture.stateRoot, driver => Date.parse(readTimeFence(driver)!.lastAcceptedAt)) + 1;
    t.mock.method(Date, 'now', () => now);
    const historical = await prepare(fixture, 'closed-before-fence', phase !== 'failed');
    const open = await prepare(fixture, 'settled-after-fence', true);
    const result = await fixture.store.artifacts.publishCanonical({ received: true }, 'cliq-test-result-v1');
    const settle = { runId: fixture.runId, opId: historical.opId, attempt: historical.attempt };
    if (phase === 'completed') await fixture.store.completeInvocation({ ...settle, expectedRunRevision: revision(fixture),
      resultRef: result.ref, consumed: { ...ZERO, toolCalls: 1 } });
    else if (phase === 'failed') {
      const error = await fixture.store.artifacts.publishCanonical({ noDispatch: true }, 'cliq-test-error-v1');
      await fixture.store.failInvocationBeforeDispatch({ ...settle, expectedRunRevision: revision(fixture), errorRef: error.ref });
    } else {
      const evidence = await fixture.store.artifacts.publishCanonical({ unknown: true }, 'cliq-test-ambiguity-v1');
      await fixture.store.markInvocationUnknown({ ...settle, expectedRunRevision: revision(fixture), evidenceRef: evidence.ref, evidenceDigest: evidence.ref });
      const attestation = await fixture.store.artifacts.publishCanonical({ abandon: true }, 'cliq-test-attestation-v1');
      await fixture.store.abandonUnknownInvocation({ ...settle, attestationRef: attestation.ref });
    }
    const waiting = await begin(fixture);
    const wait = await fixture.store.artifacts.readCanonical<WorkerDeathWait>(waiting.waitingOnRef!);
    assert.deepEqual(wait.subject.openInvocationRefs, [canonicalSha256(open)]);
    await fixture.store.completeInvocation({ runId: fixture.runId, expectedRunRevision: revision(fixture),
      opId: open.opId, attempt: open.attempt, resultRef: result.ref, consumed: { ...ZERO, toolCalls: 1 } });
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.ok(cut.journal.every(entry => entry.timestamp === wait.createdAt));
    assert.equal(cut.run.waitingOnRef, waiting.waitingOnRef);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), cut);
    await fixture.store.artifacts.publishCanonical(historical, 'cliq-invocation-journal-entry-v1');
    withDb(fixture.stateRoot, driver => driver.exec('DROP TRIGGER workspace_generations_validate_update'));
    for (const refs of [[historical, open].map(canonicalSha256), []]) {
      const forged = await fixture.store.artifacts.publishCanonical({ ...wait, subject: { ...wait.subject, openInvocationRefs: refs } }, 'cliq-waiting-subject-v1');
      withDb(fixture.stateRoot, driver => {
        const generation = { ...cut.workspaceGenerations[0], waitingSubjectRef: forged.ref, waitingSubjectDigest: forged.ref };
        driver.prepare('UPDATE workspace_generations SET row_json = ? WHERE generation_id = ?').run(JSON.stringify(generation), fixture.generationId);
        driver.prepare('UPDATE runs SET waiting_on_ref = ? WHERE id = ?').run(forged.ref, fixture.runId);
      });
      await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
    }
  });
}

test('late native model completion cannot advance the frontier or checkpoint underneath worker recovery', async t => {
  const fixture = await createAgentFixture('worker-fence-late-model', undefined, { mode: 'plan' });
  t.after(() => disposeFixture(fixture));
  const prepared = await fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
  await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: revision(fixture),
    leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'late-model' });
  const response = fixture.agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
  response.push(Buffer.from(JSON.stringify({ id: 'response', object: 'response', status: 'completed', model: 'model-1',
    output: [{ type: 'function_call', id: 'wire-read', call_id: 'read', name: 'read', arguments: '{"path":"a"}' }] })));
  const result = response.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput);
  assert.equal(result.kind, 'usable');
  const waiting = await begin(fixture), before = snapshot(fixture.stateRoot);
  await assert.rejects(fixture.agent.completeModel({ expectedRunRevision: waiting.revision,
    opId: prepared.entry.opId, attempt: prepared.entry.attempt, result }), { code: 'STATE_TRANSITION_INVALID' });
  assert.deepEqual(snapshot(fixture.stateRoot), before);
  assert.deepEqual((await fixture.store.readRecoveryClosure(fixture.runId)).run, waiting);
});

test('a typed tool frontier survives worker fencing and restart but cannot consume a late result into its next call', async t => {
  const fixture = await createAgentFixture('worker-fence-late-tool', undefined, { mode: 'plan' });
  t.after(() => disposeFixture(fixture));
  await batch(fixture, [{ name: 'read', input: { path: 'a' } }, { name: 'read', input: { path: 'b' } }]);
  const prepared = await prepareTool(fixture), claim = await claimTool(fixture, prepared);
  const observationRef = await observation(fixture, claim, 'retained actual bytes');
  const waiting = await begin(fixture);
  assert.deepEqual((await fixture.store.readRecoveryClosure(fixture.runId)).run, waiting);
  const before = snapshot(fixture.stateRoot);
  await assert.rejects(fixture.agent.completeTool({ expectedRunRevision: waiting.revision, opId: claim.entry.opId,
    attempt: claim.entry.attempt, observationRef }), { code: 'STATE_TRANSITION_INVALID' });
  assert.deepEqual(snapshot(fixture.stateRoot), before);
  await fixture.store.close();
  fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
  fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
  await assert.rejects(prepareTool(fixture), { code: 'LEASE_FENCED' });
  const cancelled = await fixture.agent.cancelRun({ requestId: uuidv7(),
    expectedRunRevision: revision(fixture), ...await publishInProcessChannel(fixture.store) });
  assert.equal(cancelled.run.waitingOnRef, waiting.waitingOnRef);
  assert.equal((await fixture.store.readRecoveryClosure(fixture.runId)).run.status, 'waiting');
});

for (const order of ['before', 'after'] as const) {
  test(`authenticated cancellation ${order} fencing cannot clear worker recovery or publish a premature terminal result`, async t => {
    const fixture = await createAgentFixture(`worker-fence-cancel-${order}`, undefined, { mode: 'plan' });
    t.after(() => disposeFixture(fixture));
    await fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
    const cancel = async () => fixture.agent.cancelRun({ requestId: uuidv7(),
      expectedRunRevision: revision(fixture), ...await publishInProcessChannel(fixture.store) });
    if (order === 'before') await cancel();
    const waiting = await begin(fixture);
    if (order === 'after') await cancel();
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(cut.run.waitingOnRef, waiting.waitingOnRef);
    assert.ok(cut.run.cancelRequested && cut.run.stopIntentRef);
    const before = snapshot(fixture.stateRoot);
    await assert.rejects(fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture) }), { code: 'STATE_TRANSITION_INVALID' });
    assert.deepEqual(snapshot(fixture.stateRoot), before);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
    assert.deepEqual((await fixture.store.readRecoveryClosure(fixture.runId)).run, cut.run);
    await assert.rejects(fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch }), { code: 'STATE_TRANSITION_INVALID' });
  });
}

test('expired leases and Run deadlines still permit authority-reducing worker fencing', async t => {
  const fixture = await fixtureFor(t, 'expiry');
  const now = Date.parse(fixture.store.getRun(fixture.runId).deadlineAt) + 1;
  t.mock.method(Date, 'now', () => now);
  await begin(fixture);
  assert.equal((await fixture.store.readRecoveryClosure(fixture.runId)).run.status, 'waiting');
});

test('deadline stops persist during worker recovery without clearing the wait or settling its reservation', async t => {
  const fixture = await createAgentFixture('worker-fence-deadline', undefined, { mode: 'plan' });
  t.after(() => disposeFixture(fixture));
  await fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
  const waiting = await begin(fixture);
  t.mock.method(Date, 'now', () => Date.parse(waiting.deadlineAt));
  const stopped = await fixture.agent.expireRun({ expectedRunRevision: revision(fixture) });
  assert.equal(stopped.run.waitingOnRef, waiting.waitingOnRef);
  assert.deepEqual(stopped.run.budgetReserved, waiting.budgetReserved);
  assert.ok(stopped.run.stopIntentRef);
  assert.equal((await fixture.store.readRecoveryClosure(fixture.runId)).run.status, 'waiting');
  await assert.rejects(fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture) }), { code: 'STATE_TRANSITION_INVALID' });
});

test('canonical clock regression retains its high-water and makes no partial worker transition', async t => {
  const fixture = await fixtureFor(t, 'clock');
  const fence = withDb(fixture.stateRoot, driver => readTimeFence(driver)!);
  const before = snapshot(fixture.stateRoot);
  const clock = t.mock.method(Date, 'now', () => Date.parse(fence.lastAcceptedAt) - 1);
  await assert.rejects(begin(fixture), { code: 'RECOVERY_REQUIRED' });
  const after = snapshot(fixture.stateRoot);
  for (const table of Object.keys(before).filter(table => table !== 'canonical_time_fence')) assert.deepEqual(after[table], before[table], table);
  const regressed = withDb(fixture.stateRoot, driver => readTimeFence(driver)!);
  assert.equal(regressed.state, 'clock_regressed');
  assert.equal(regressed.lastAcceptedAt, fence.lastAcceptedAt);
  clock.mock.restore();
  assert.equal(fixture.store.recoverCanonicalTime(), 'healthy');
  await begin(fixture);
});

test('recovery rejects rehashed foreign waits, omitted/open invocation identities, probe resets and orphan fences', async t => {
  const fixture = await fixtureFor(t, 'substitution');
  await prepare(fixture, 'one');
  await prepare(fixture, 'two', true);
  const waiting = await begin(fixture);
  const original = await fixture.store.artifacts.readCanonical<WorkerDeathWait>(waiting.waitingOnRef!);
  const originalGeneration = withDb(fixture.stateRoot, driver => driver.prepare('SELECT row_json FROM workspace_generations WHERE generation_id = ?')
    .get<{ row_json: string }>(fixture.generationId)!.row_json);
  withDb(fixture.stateRoot, driver => driver.exec('DROP TRIGGER workspace_generations_validate_update'));
  const changeWait = async (change: (wait: WorkerDeathWait) => void) => {
    const wait = structuredClone(original);
    change(wait);
    const artifact = await fixture.store.artifacts.publishCanonical(wait, 'cliq-waiting-subject-v1');
    withDb(fixture.stateRoot, driver => {
      const generation = JSON.parse(originalGeneration);
      generation.waitingSubjectRef = generation.waitingSubjectDigest = artifact.ref;
      driver.prepare('UPDATE workspace_generations SET row_json = ? WHERE generation_id = ?').run(JSON.stringify(generation), fixture.generationId);
      driver.prepare('UPDATE runs SET waiting_on_ref = ? WHERE id = ?').run(artifact.ref, fixture.runId);
    });
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
  };
  for (const field of ['oldWorkerLaunchId', 'oldWorkerIdentity', 'processContainmentRef', 'workspaceGenerationRef'] as const) {
    await changeWait(wait => { wait.subject[field] = digest(`foreign-${field}`); });
  }
  await changeWait(wait => { wait.subject.oldLeaseEpoch++; });
  await changeWait(wait => { wait.frontierRef = digest('foreign-frontier'); });
  await changeWait(wait => { wait.createdFromRevision = waiting.revision; });
  await changeWait(wait => { wait.subject.openInvocationRefs.pop(); });
  await changeWait(wait => { wait.subject.openInvocationRefs.reverse(); });
  await changeWait(wait => { wait.subject.openInvocationRefs.push(wait.subject.openInvocationRefs[0]!); });
  await changeWait(wait => { Object.assign(wait.probeState, { phase: 'automatic_exhausted', automaticProbeCount: 8 }); });
  await changeWait(wait => { wait.probeState.nextProbeAt = new Date(Date.parse(wait.createdAt) + 1).toISOString(); });
  await changeWait(wait => { Object.assign(wait, { deathProven: true }); });
  const witness = await fixture.store.artifacts.readCanonical<InvocationJournalEntry>(original.subject.openInvocationRefs[0]!);
  const forged = await fixture.store.artifacts.publishCanonical({ ...witness, requestRef: digest('foreign-request') }, 'cliq-invocation-journal-entry-v1');
  await changeWait(wait => { wait.subject.openInvocationRefs[0] = forged.ref; });
  withDb(fixture.stateRoot, driver => {
    driver.prepare('UPDATE workspace_generations SET row_json = ? WHERE generation_id = ?').run(originalGeneration, fixture.generationId);
    driver.prepare("UPDATE runs SET waiting_on_ref = ?, waiting_reason = 'approval' WHERE id = ?").run(waiting.waitingOnRef!, fixture.runId);
  });
  await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
  withDb(fixture.stateRoot, driver => driver.prepare("UPDATE runs SET waiting_reason = 'reconciliation' WHERE id = ?").run(fixture.runId));
  await fixture.store.readRecoveryClosure(fixture.runId);
});

test('missing wait or invocation witnesses block recovery without changing retained authority', async t => {
  const fixture = await fixtureFor(t, 'missing');
  const prepared = await prepare(fixture, 'open');
  const waiting = await begin(fixture);
  const before = snapshot(fixture.stateRoot);
  for (const ref of [waiting.waitingOnRef!, canonicalSha256(prepared)]) {
    const artifact = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, ref);
    await rename(artifact, `${artifact}.saved`);
    try { await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' }); }
    finally { await rename(`${artifact}.saved`, artifact); }
    assert.deepEqual(snapshot(fixture.stateRoot), before);
  }
  await fixture.store.readRecoveryClosure(fixture.runId);
});

test('the fence Journal cutoff is immutable, required and rejects invalid or productive suffix cuts', async t => {
  const fixture = await fixtureFor(t, 'journal-cut');
  await prepare(fixture, 'open', true);
  await begin(fixture);
  const cut = await fixture.store.readRecoveryClosure(fixture.runId);
  const generation = cut.workspaceGenerations[0]!;
  assert.equal(generation.fencedJournalSeq, cut.journal.length);
  assert.throws(() => withDb(fixture.stateRoot, driver => driver.prepare(
    'UPDATE workspace_generations SET row_version = row_version + 1, row_json = ? WHERE generation_id = ?'
  ).run(JSON.stringify({ ...generation, rowVersion: generation.rowVersion + 1, fencedJournalSeq: 0 }), fixture.generationId)),
  /workspace generation phase transition is invalid/);
  withDb(fixture.stateRoot, driver => driver.exec('DROP TRIGGER workspace_generations_validate_update'));
  for (const fencedJournalSeq of [undefined, null, -1, 0.5, '2', Number.MAX_SAFE_INTEGER + 1, cut.journal.length + 1, 0, cut.journal.length - 1]) {
    withDb(fixture.stateRoot, driver => driver.prepare('UPDATE workspace_generations SET row_json = ? WHERE generation_id = ?')
      .run(JSON.stringify({ ...generation, fencedJournalSeq }), fixture.generationId));
    const before = snapshot(fixture.stateRoot);
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
    assert.deepEqual(snapshot(fixture.stateRoot), before);
  }
});

test('worker identity epoch and quiesce drift reject fencing before any authority mutation', async t => {
  const fixture = await fixtureFor(t, 'source-closure');
  const original = withDb(fixture.stateRoot, driver => driver.prepare('SELECT row_json FROM worker_launches WHERE launch_id = ?')
    .get<{ row_json: string }>(fixture.launchId)!.row_json);
  const identity = await fixture.store.artifacts.readCanonical<WorkerIdentity>(fixture.workerIdentityDigest);
  const foreign = await fixture.store.artifacts.publishCanonical({ ...identity, intendedLeaseEpoch: identity.intendedLeaseEpoch + 1 }, 'cliq-worker-identity-v1');
  withDb(fixture.stateRoot, driver => driver.prepare('UPDATE worker_launches SET row_json = ? WHERE launch_id = ?')
    .run(JSON.stringify({ ...JSON.parse(original), workerIdentityDigest: foreign.ref }), fixture.launchId));
  const before = snapshot(fixture.stateRoot);
  await assert.rejects(begin(fixture), { code: 'RECOVERY_REQUIRED' });
  assert.deepEqual(snapshot(fixture.stateRoot), before);
  withDb(fixture.stateRoot, driver => driver.prepare('UPDATE worker_launches SET row_json = ? WHERE launch_id = ?').run(original, fixture.launchId));
  fixture.store.beginGenerationRevocation({ launchId: fixture.launchId, expectedLeaseVersion: fixture.leaseVersion,
    expectedGenerationRowVersion: fixture.generationRowVersion, quiesceId: 'real-quiesce' });
  withDb(fixture.stateRoot, driver => {
    const launch = JSON.parse(driver.prepare('SELECT row_json FROM worker_launches WHERE launch_id = ?').get<{ row_json: string }>(fixture.launchId)!.row_json);
    launch.quiesceId = 'foreign-quiesce';
    driver.prepare('UPDATE worker_launches SET row_json = ? WHERE launch_id = ?').run(JSON.stringify(launch), fixture.launchId);
  });
  await assert.rejects(begin(fixture), { code: 'RECOVERY_REQUIRED' });
});

test('worker fencing accepts no caller-selected wait, generation, evidence or extra fields', async t => {
  const fixture = await fixtureFor(t, 'input');
  const input = { runId: fixture.runId, expectedRunRevision: revision(fixture) };
  for (const extra of ['waitingOnRef', 'generationRef', 'deathEvidenceRef', 'fencedJournalSeq']) {
    await assert.rejects(fixture.store.beginWorkerRecovery({ ...input, [extra]: digest(extra) }), { code: 'INVALID_REQUEST' });
  }
  await assert.rejects(fixture.store.beginWorkerRecovery({ ...input, expectedRunRevision: 0 }), { code: 'INVALID_REQUEST' });
  assert.equal(fixture.store.getRun(fixture.runId).status, 'running');
});
