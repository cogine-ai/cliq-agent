// Serialized test-owned SQLite data only; no StateOwner, native owner or worker
// authority is created. Real installed renewal is a separate Linux qualification.
import assert from 'node:assert/strict';
import { chmod, copyFile, link, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test, type TestContext } from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../../src/kernel/identity.js';
import type { WorkerIdentity, WorkerLaunch, WorkspaceGenerationStateV1 } from '../../../src/kernel/types.js';
import { assertInstalledWorkerLeaseRenewed, inspectInstalledWorkerIdentity, inspectInstalledWorkerLease,
  inspectInstalledWorkerRetirement, inspectInstalledWorkerRetirementHistory, inspectInstalledWorkerLaunchIds } from './installed-worker-lease.js';
import { inspectInstalledPublicationClaim, inspectInstalledRecoveredWorkerRetirement } from './installed-worker-lease.js';
import { publicationArenaId } from '../../../src/kernel/publication.js';
import { addCanonicalDuration, identityHash } from '../../../src/kernel/identity.js';

test('publication crash diagnostics never accept an absent claim or manufacture a birth from a pathname', async t => {
  const value = await workerFixture(t);
  update(value.filename, database => database.exec(`CREATE TABLE run_journal(run_id TEXT,seq INTEGER,op_id TEXT,op_kind TEXT,attempt INTEGER,phase TEXT,entry_json TEXT);
    CREATE TABLE items(run_id TEXT,item_id TEXT,item_seq INTEGER,payload_ref TEXT,kind TEXT,created_at TEXT);`));
  const before = await readFile(value.filename), names = await readdir(value.cas);
  assert.equal(inspectInstalledPublicationClaim(value.stateRoot, value.expected.uid, value.expected.runId), undefined);
  assert.deepEqual(await readFile(value.filename), before); assert.deepEqual(await readdir(value.cas), names);
});

test('publication crash diagnostics bind actual canonical birth and retain an already-committed receipt as a missed cut', async t => {
  const value = await workerFixture(t), hash = 'a'.repeat(64), time = new Date().toISOString();
  const budget = { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 };
  const birth = { schemaVersion: 1, format: 'cliq-publication-arena-birth-v1', deliveryRunId: value.expected.runId,
    deliveryPlanRef: hash, workspaceIdentityRef: hash, workspaceIdentityDigest: hash, stateRootIdentityRef: hash, stateRootIdentityDigest: hash,
    inspectorIdentityRef: hash, inspectorIdentityDigest: hash, sequence: 'forward', operationIndex: 0, operationId: 'O'.repeat(43),
    opId: 'actual-original-op', attempt: 0, dispatchId: 'actual-dispatch',
    arenaId: publicationArenaId(value.expected.runId, 'O'.repeat(43), 'actual-original-op', 0, 'actual-dispatch'),
    arenaIdentity: { deviceId: '1', fileId: '20', ownerUid: value.expected.uid, mode: 0o700 },
    parentIdentity: { deviceId: '1', fileId: '21', ownerUid: value.expected.uid, mode: 0o700 }, observedAt: time, birthDigest: '' };
  birth.birthDigest = digestOmitting(birth, 'birthDigest'); const bytes = canonicalJsonBytes(birth), birthRef = sha256Bytes(bytes);
  await writeFile(path.join(value.cas, birthRef), bytes, { mode: 0o400, flag: 'wx' });
  const prepared = { runId: value.expected.runId, seq: 1, opId: birth.opId, opKind: 'publish', attempt: 0, phase: 'prepared',
    leaseEpoch: 1, requestRef: hash, target: hash, grantRef: hash, replayClass: 'reconcile', budgetDelta: budget, timestamp: time };
  const claim = { ...prepared, seq: 2, phase: 'dispatch_claimed', budgetDelta: { ...budget, toolCalls: 0 },
    evidenceRef: birthRef, evidenceDigest: birth.birthDigest, dispatchId: birth.dispatchId, stateOwnerEpoch: 1, supervisorInstanceId: value.expected.supervisorInstanceId };
  const insert = (database: DatabaseSync, row: typeof prepared) => database.prepare('INSERT INTO run_journal VALUES(?,?,?,?,?,?,?)')
    .run(row.runId, row.seq, row.opId, row.opKind, row.attempt, row.phase, JSON.stringify(row));
  update(value.filename, database => {
    database.exec(`CREATE TABLE run_journal(run_id TEXT,seq INTEGER,op_id TEXT,op_kind TEXT,attempt INTEGER,phase TEXT,entry_json TEXT);
      CREATE TABLE items(run_id TEXT,item_id TEXT,item_seq INTEGER,payload_ref TEXT,kind TEXT,created_at TEXT);`);
    insert(database, prepared); insert(database, claim);
  });
  const before = await readFile(value.filename), observed = inspectInstalledPublicationClaim(value.stateRoot, value.expected.uid, value.expected.runId)!;
  assert.equal(observed.originalReceiptCommitted, false); assert.deepEqual(observed.birth, birth); assert.equal(observed.claim.dispatchId, birth.dispatchId);
  assert.deepEqual(await readFile(value.filename), before); assert.equal(Object.hasOwn(observed, 'qualified'), false);
  update(value.filename, database => insert(database, { ...claim, seq: 3, phase: 'completed', budgetDelta: budget,
    budgetSettlementRef: hash, receiptRef: birthRef } as typeof prepared));
  assert.equal(inspectInstalledPublicationClaim(value.stateRoot, value.expected.uid, value.expected.runId)!.originalReceiptCommitted, true);
});

test('a normal sealed worker is not the genuinely retired recovery branch', async t => {
  const value = await workerFixture(t); await retireFixture(value);
  assert.throws(() => inspectInstalledRecoveredWorkerRetirement(value.stateRoot, value.expected.uid, {
    runId: value.expected.runId, supervisorInstanceId: value.expected.supervisorInstanceId, leaseEpoch: 1,
    inspectorIdentityRef: 'a'.repeat(64), inspectorIdentityDigest: 'a'.repeat(64),
    resources: { kind: 'genuinely_retired_from_verified_checkpoint', workerLaunchId: value.expected.launchId,
      generationRef: value.generation.generationRef, sourceCheckpointId: value.generation.sourceCheckpointId,
      quarantineEvidenceRef: 'a'.repeat(64), retirementEvidenceRef: 'a'.repeat(64) },
  }), { message: 'installed recovered worker retirement inspection refused' });
});

async function recoveredFixture(t: TestContext) {
  const value = await workerFixture(t), hash = 'a'.repeat(64);
  const time = (n: number) => new Date(Date.parse(value.launch.activatedAt!) + n).toISOString();
  const published = new Set<string>();
  const put = async (object: unknown) => {
    const ref = canonicalSha256(object); if (published.has(ref)) return ref;
    await publishFixture(value, object); published.add(ref); return ref;
  };
  const seal = <T extends Record<string, unknown>>(object: T) => ({ ...object, evidenceDigest: digestOmitting(object, 'evidenceDigest') });
  const subject = { kind: 'worker_death', oldWorkerLaunchId: value.launch.launchId, oldLeaseEpoch: 1,
    oldWorkerIdentity: value.launch.workerIdentityDigest, processContainmentRef: value.launch.processContainmentRef,
    workspaceGenerationRef: value.generation.generationRef, openInvocationRefs: [] };
  const pending = { schemaVersion: 1, kind: 'reconciliation', runId: value.expected.runId, createdFromRevision: 4,
    createdAt: time(100), frontierRef: hash, subject,
    probeState: { phase: 'automatic_pending', automaticProbeCount: 0, userProbeCount: 0, nextProbeAt: time(100) } };
  const pendingRef = await put(pending);
  const anchor = { ...value.generation, rowVersion: 4, phase: 'fenced_reconciling', updatedAt: time(100),
    waitingSubjectRef: pendingRef, waitingSubjectDigest: pendingRef, fencedJournalSeq: 2, fencedFromPhase: 'active' };
  const anchorRef = await put(anchor), nonce = canonicalSha256('inert worker probe');
  const dispatch: Record<string, any> = { schemaVersion: 1, format: 'cliq-reconciliation-probe-dispatch-v1', runId: value.expected.runId,
    reconciliationSubjectDigest: canonicalSha256(subject), probeKind: 'automatic', probeOrdinal: 1, probeNonceDigest: nonce,
    probeStartedAt: time(200), probeDeadlineAt: addCanonicalDuration(time(200), 30000), owningSupervisorInstanceId: 'inert-successor',
    subjectKind: 'worker_recovery', inspectorTaskId: identityHash(value.expected.runId, canonicalSha256(subject), 'automatic', 1, nonce),
    inspectionTargetDigest: anchorRef };
  dispatch.dispatchDigest = digestOmitting(dispatch, 'dispatchDigest');
  const wait = { ...pending, probeState: { phase: 'automatic_in_flight', automaticProbeCount: 1, userProbeCount: 0, dispatch } }, waitRef = await put(wait);
  const death = seal({ schemaVersion: 1, kind: 'containment_all_descendants_dead', containmentRef: value.launch.processContainmentRef,
    planRef: value.launch.containmentPlanRef, sandboxLaunchSpecRef: value.launch.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: hash,
    owner: value.containment.owner, launchNonceDigest: value.launch.spawnNonceDigest, inspectorSupervisorInstanceId: 'inert-successor',
    inspectorIdentityRef: hash, inspectorIdentityDigest: hash, backend: { ...value.containment.backend,
      cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 }, observedAt: time(300) });
  const recovery = seal({ schemaVersion: 1, format: 'cliq-worker-recovery-evidence-v1', runId: value.expected.runId,
    waitingSubjectRef: waitRef, oldWorkerLaunchId: value.launch.launchId, oldLeaseEpoch: 1, oldWorkerIdentityDigest: value.launch.workerIdentityDigest,
    processContainmentRef: value.launch.processContainmentRef, containmentDeathEvidenceRef: await put(death), containmentDeathEvidenceDigest: death.evidenceDigest,
    workspaceGenerationRef: value.generation.generationRef, generationTreeDigest: value.generation.lastVerifiedTreeDigest,
    inspectorIdentityRef: hash, inspectorIdentityDigest: hash, observedAt: time(400), generationDisposition: 'quarantined' });
  const quarantine = seal({ schemaVersion: 1, format: 'cliq-workspace-generation-quarantine-evidence-v1', runId: value.expected.runId,
    generationRef: value.generation.generationRef, generationIdentityDigest: value.generation.generationIdentityDigest, sourceRowVersion: 5,
    observedState: { kind: 'complete_tree', treeDigest: value.generation.lastVerifiedTreeDigest }, inspectorIdentityRef: hash, inspectorIdentityDigest: hash,
    quarantineCanonicalRootRelativePath: `quarantine/workspace-generations/${identityHash(value.generation.generationId, '5')}`,
    quarantineDeviceId: '1', quarantineFileId: '2', originalLocatorAbsent: true, renameNoReplace: true, directoryFsyncComplete: true,
    observedAt: time(500), reason: 'worker_recovery', fromPhase: 'fenced_reconciling', workerRecoveryEvidenceRef: await put(recovery),
    workerRecoveryEvidenceDigest: recovery.evidenceDigest });
  const quarantineRef = await put(quarantine), wrapper = seal({ schemaVersion: 1, format: 'cliq-reconciliation-probe-evidence-v1',
    runId: value.expected.runId, waitingSubjectRef: waitRef, waitingSubjectDigest: waitRef, probeKind: 'automatic', probeOrdinal: 1,
    probeNonceDigest: nonce, probeDispatchDigest: dispatch.dispatchDigest, probeStartedAt: dispatch.probeStartedAt, probeDeadlineAt: dispatch.probeDeadlineAt,
    inspectorIdentityRef: hash, inspectorIdentityDigest: hash, observedAt: recovery.observedAt, outcome: 'subject_observation',
    subjectEvidenceKind: 'worker_recovery', subjectEvidenceRef: await put(recovery), subjectEvidenceDigest: recovery.evidenceDigest });
  const retired = seal({ schemaVersion: 1, format: 'cliq-workspace-generation-retirement-evidence-v1', runId: value.expected.runId,
    generationRef: value.generation.generationRef, generationIdentityDigest: value.generation.generationIdentityDigest,
    inspectorIdentityRef: hash, inspectorIdentityDigest: hash, observedAt: time(700), fromPhase: 'quarantined',
    quarantineEvidenceRef: quarantineRef, quarantineEvidenceDigest: quarantine.evidenceDigest, sourceQuarantinedRowVersion: 6,
    activeRunPointerCount: 0, nonretiredWorkerLaunchCount: 0, liveContainmentCount: 0, activeMountCount: 0, releasableBrokerClaimCount: 0 });
  const retiredRef = await put(retired);
  const { snapshotEvidenceRef: _snapshot, snapshotEvidenceDigest: _digest, activeWorkerLaunchId: _active, leaseEpoch: _lease, ...base } = value.generation;
  const generation = { ...base, phase: 'retired', rowVersion: 7, updatedAt: time(800), retirementEvidenceRef: retiredRef, retirementEvidenceDigest: retired.evidenceDigest };
  const launch = { ...value.launch, phase: 'retired', generationWriteState: 'fenced_reconciling', retiredAt: time(600), retirementEvidenceRef: await put(wrapper) };
  update(value.filename, database => {
    database.prepare('UPDATE runs SET active_worker_launch_id=NULL,status=?').run('succeeded');
    database.prepare('UPDATE worker_launches SET phase=?,row_json=?,retired_at=?').run('retired', JSON.stringify(launch), launch.retiredAt);
    database.prepare('UPDATE workspace_generations SET phase=?,row_version=?,row_json=?').run('retired', generation.rowVersion, JSON.stringify(generation));
  });
  const expected = { runId: value.expected.runId, supervisorInstanceId: value.expected.supervisorInstanceId, leaseEpoch: 1,
    inspectorIdentityRef: hash, inspectorIdentityDigest: hash,
    resources: { kind: 'genuinely_retired_from_verified_checkpoint' as const, workerLaunchId: value.expected.launchId,
      generationRef: generation.generationRef, sourceCheckpointId: generation.sourceCheckpointId,
      quarantineEvidenceRef: quarantineRef, retirementEvidenceRef: retiredRef } };
  return { ...value, expected, retired, retiredRef, put };
}

test('actual readonly SQL recovery diagnostics require the complete original quarantine, death and retirement graph', async t => {
  const value = await recoveredFixture(t), before = await readFile(value.filename), names = await readdir(value.cas);
  const observed = inspectInstalledRecoveredWorkerRetirement(value.stateRoot, process.getuid!(), value.expected);
  assert.equal(observed.generationPhase, 'retired'); assert.equal(observed.generationWriteState, 'fenced_reconciling');
  assert.equal(observed.retirementEvidenceRef, value.expected.resources.retirementEvidenceRef);
  assert.equal(observed.pid, 12345); assert.equal(Object.hasOwn(observed, 'qualified'), false);
  assert.deepEqual(await readFile(value.filename), before); assert.deepEqual(await readdir(value.cas), names);
  assert.throws(() => inspectInstalledRecoveredWorkerRetirement(value.stateRoot, process.getuid!(), {
    ...value.expected, inspectorIdentityDigest: 'b'.repeat(64) }));
  assert.throws(() => inspectInstalledRecoveredWorkerRetirement(value.stateRoot, process.getuid!(), {
    ...value.expected, resources: { ...value.expected.resources, sourceCheckpointId: 'another-checkpoint' } }));
});

async function fixture(t: TestContext) {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-worker-lease-'));
  t.after(() => rm(stateRoot, { recursive: true, force: true }));
  await chmod(stateRoot, 0o700);
  const filename = path.join(stateRoot, KERNEL_DATABASE_FILENAME), now = Date.now(), hash = 'a'.repeat(64);
  const time = (offset: number) => new Date(now + offset).toISOString();
  const expected = { uid: process.getuid!(), runId: 'fixture-run', launchId: 'fixture-launch', leaseEpoch: 1,
    runRevision: 3, supervisorInstanceId: 'fixture-supervisor', deadlineAt: time(180000) };
  const launch: WorkerLaunch = { schemaVersion: 1, launchId: expected.launchId, runId: expected.runId,
    plannedRunRevision: 2, supervisorInstanceId: expected.supervisorInstanceId, spawnNonceDigest: hash,
    activationNonceDigest: hash, workspaceGenerationRef: hash, containmentPlanRef: hash, sandboxLaunchSpecRef: hash,
    workerIdentityDigest: hash, processContainmentRef: hash, phase: 'activated', generationWriteState: 'active',
    leaseEpoch: 1, leaseVersion: 1, leaseExpiresAt: time(60000), createdAt: time(-2000),
    activationDeadlineAt: time(1000), activatedAt: time(-1000) };
  const database = new DatabaseSync(filename);
  try {
    database.exec(`PRAGMA user_version=${KERNEL_STATE_SCHEMA_VERSION};
      CREATE TABLE runs(id TEXT, active_worker_launch_id TEXT, status TEXT, lease_epoch INTEGER,
        revision INTEGER, cancel_requested INTEGER, stop_intent_ref TEXT, deadline_at TEXT);
      CREATE TABLE worker_launches(launch_id TEXT, run_id TEXT, phase TEXT, row_json TEXT, retired_at TEXT)`);
    database.prepare('INSERT INTO runs VALUES(?, ?, ?, ?, ?, ?, ?, ?)')
      .run(expected.runId, expected.launchId, 'running', 1, 3, 0, null, expected.deadlineAt);
    database.prepare('INSERT INTO worker_launches VALUES(?, ?, ?, ?, ?)')
      .run(launch.launchId, launch.runId, launch.phase, JSON.stringify(launch), null);
  } finally { database.close(); }
  await chmod(filename, 0o600);
  return { stateRoot, filename, expected, launch };
}

async function retainedBytes(stateRoot: string) {
  return Promise.all((await readdir(stateRoot)).sort().map(async name => [name, await readFile(path.join(stateRoot, name))]));
}

test('reads only the exact active lease and leaves database bytes and sidecars unchanged', async t => {
  const value = await fixture(t), before = await retainedBytes(value.stateRoot);
  const observed = inspectInstalledWorkerLease(value.stateRoot, value.expected);
  assert.equal(observed.diagnosticOnly, true);
  assert.match(observed.databaseIdentity, /^[a-f0-9]{64}$/u);
  assert.match(observed.launchInvariantDigest, /^[a-f0-9]{64}$/u);
  assert.equal(observed.leaseVersion, 1); assert.equal(observed.leaseExpiresAt, value.launch.leaseExpiresAt);
  assert(Date.parse(observed.observedAt) <= Date.now());
  assert(Date.parse(observed.observedAt) < Date.parse(observed.leaseExpiresAt));
  assert.deepEqual(await retainedBytes(value.stateRoot), before);
});

function update(filename: string, operation: (database: DatabaseSync) => void) {
  const database = new DatabaseSync(filename);
  try { operation(database); } finally { database.close(); }
}

test('bounded readonly launch enumeration distinguishes an existing empty Run from missing and preserves original bytes', async t => {
  const value = await fixture(t); await mkdir(path.join(value.stateRoot, KERNEL_CAS_DIRECTORY), { mode: 0o700 });
  const databaseBefore = await readFile(value.filename), namesBefore = await readdir(value.stateRoot);
  const observed = inspectInstalledWorkerLaunchIds(value.stateRoot, value.expected.uid, value.expected.runId);
  assert.deepEqual(observed.launchIds, [value.expected.launchId]); assert.equal(observed.diagnosticOnly, true);
  assert.equal(Object.hasOwn(observed, 'qualified'), false); assert(Object.isFrozen(observed) && Object.isFrozen(observed.launchIds));
  assert.deepEqual(await readFile(value.filename), databaseBefore); assert.deepEqual(await readdir(value.stateRoot), namesBefore);
  assert.throws(() => inspectInstalledWorkerLaunchIds(value.stateRoot, value.expected.uid, 'missing'),
    { message: 'installed worker launch enumeration refused' });
  update(value.filename, db => db.prepare('DELETE FROM worker_launches WHERE run_id=?').run(value.expected.runId));
  assert.deepEqual(inspectInstalledWorkerLaunchIds(value.stateRoot, value.expected.uid, value.expected.runId).launchIds, []);
});

test('readonly launch enumeration has an exact bound, scopes the original Run and refuses malformed IDs', async t => {
  const value = await fixture(t); await mkdir(path.join(value.stateRoot, KERNEL_CAS_DIRECTORY), { mode: 0o700 });
  const add = (runId: string, id: string) => update(value.filename, db => db.prepare('INSERT INTO worker_launches VALUES(?,?,?,?,?)')
    .run(id, runId, 'data-only', '{}', null));
  add('unrelated-run', 'must-not-escape');
  for (let index = 1; index < 16; index++) add(value.expected.runId, `data-launch-${String(index).padStart(2, '0')}`);
  const observed = inspectInstalledWorkerLaunchIds(value.stateRoot, value.expected.uid, value.expected.runId);
  assert.equal(observed.launchIds.length, 16); assert(!observed.launchIds.includes('must-not-escape'));
  add(value.expected.runId, 'seventeenth');
  assert.throws(() => inspectInstalledWorkerLaunchIds(value.stateRoot, value.expected.uid, value.expected.runId));
  update(value.filename, db => { db.prepare('DELETE FROM worker_launches WHERE run_id=?').run(value.expected.runId); });
  add(value.expected.runId, '');
  assert.throws(() => inspectInstalledWorkerLaunchIds(value.stateRoot, value.expected.uid, value.expected.runId));
  update(value.filename, db => { db.prepare('DELETE FROM worker_launches WHERE run_id=?').run(value.expected.runId); });
  add(value.expected.runId, 'x'.repeat(129));
  assert.throws(() => inspectInstalledWorkerLaunchIds(value.stateRoot, value.expected.uid, value.expected.runId));
});

// Pure serialized data for the diagnostic seam, never a native birth/death proof.
async function workerFixture(t: TestContext) {
  const value = await fixture(t), hash = 'a'.repeat(64);
  const cas = path.join(value.stateRoot, KERNEL_CAS_DIRECTORY);
  await mkdir(cas, { mode: 0o700 });
  const containment = { schemaVersion: 1, planRef: value.launch.containmentPlanRef, sandboxLaunchSpecRef: value.launch.sandboxLaunchSpecRef,
    sandboxLaunchSpecDigest: hash, owner: { kind: 'worker_activation', runId: value.expected.runId, intendedLeaseEpoch: 1, workerLaunchId: value.expected.launchId },
    filesystemBinding: { kind: 'run-generation', generationRef: value.launch.workspaceGenerationRef }, launchNonceDigest: value.launch.spawnNonceDigest,
    backend: { kind: 'linux', pidNamespaceReservationId: 'fixture-reservation', pidNamespaceId: 'fixture-namespace',
      cgroupPath: '/fixture/cgroup', cgroupId: 'fixture-cgroup', namespaceInitStartToken: 'fixture-init', subreaperStartToken: 'fixture-subreaper' },
    createdAt: value.launch.createdAt };
  value.launch.processContainmentRef = canonicalSha256(containment);
  await writeFile(path.join(cas, value.launch.processContainmentRef), canonicalJsonBytes(containment), { mode: 0o400 });
  const worker: WorkerIdentity = { schemaVersion: 1, executableRealpath: '/fixture/worker', executableDigest: hash,
    pid: 12345, processStartToken: 'linux-proc-start-ticks:67890', spawnNonceDigest: value.launch.spawnNonceDigest,
    activationNonceDigest: value.launch.activationNonceDigest, intendedLeaseEpoch: 1, launchId: value.launch.launchId,
    supervisorInstanceId: value.launch.supervisorInstanceId, processContainmentRef: value.launch.processContainmentRef! };
  const workerRef = canonicalSha256(worker), workerFilename = path.join(cas, workerRef);
  await writeFile(workerFilename, canonicalJsonBytes(worker), { mode: 0o400 });
  value.launch.workerIdentityDigest = workerRef;
  const generation: WorkspaceGenerationStateV1 = { schemaVersion: 1, generationId: 'fixture-generation', runId: value.expected.runId,
    generationRef: value.launch.workspaceGenerationRef!, generationIdentityDigest: 'b'.repeat(64), rowVersion: 3,
    sourceCheckpointId: 'fixture-checkpoint', sourceWorkspaceStateRef: hash, sourceWorkspaceStateDigest: hash,
    lastVerifiedTreeDigest: hash, updatedAt: value.launch.activatedAt!, phase: 'active',
    snapshotEvidenceRef: hash, snapshotEvidenceDigest: hash, activeWorkerLaunchId: value.launch.launchId, leaseEpoch: 1 };
  update(value.filename, database => {
    database.exec(`CREATE TABLE workspace_generations(generation_id TEXT, run_id TEXT, phase TEXT, row_version INTEGER, row_json TEXT)`);
    database.prepare('UPDATE worker_launches SET row_json=?').run(JSON.stringify(value.launch));
    database.prepare('INSERT INTO workspace_generations VALUES(?, ?, ?, ?, ?)')
      .run(generation.generationId, generation.runId, generation.phase, generation.rowVersion, JSON.stringify(generation));
  });
  return { ...value, cas, containment, worker, workerFilename, generation };
}

test('active identity diagnostic fixes the original worker PID/start and generation without creating authority', async t => {
  const value = await workerFixture(t);
  const observed = inspectInstalledWorkerIdentity(value.stateRoot, value.expected);
  assert.equal(observed.diagnosticOnly, true);
  assert.equal(observed.runId, value.expected.runId); assert.equal(observed.launchId, value.expected.launchId);
  assert.equal(observed.pid, 12345); assert.equal(observed.processStartToken, 'linux-proc-start-ticks:67890');
  assert.equal(observed.workerIdentityDigest, value.launch.workerIdentityDigest);
  assert.equal(observed.workspaceGenerationRef, value.launch.workspaceGenerationRef);
  assert.equal(observed.generationId, 'fixture-generation'); assert.equal(observed.generationIdentityDigest, 'b'.repeat(64));
  assert(Object.isFrozen(observed));
  assert.equal(Object.hasOwn(observed, 'qualified'), false); assert.equal(Object.hasOwn(observed, 'executableRealpath'), false);
});

async function publishFixture(value: Awaited<ReturnType<typeof workerFixture>>, data: unknown) {
  const ref = canonicalSha256(data);
  await writeFile(path.join(value.cas, ref), canonicalJsonBytes(data), { mode: 0o400 });
  return ref;
}

async function retireFixture(value: Awaited<ReturnType<typeof workerFixture>>) {
  const hash = 'a'.repeat(64), retiredTime = new Date().toISOString(), time = (_offset: number) => retiredTime;
  const death = { schemaVersion: 1, kind: 'containment_all_descendants_dead', containmentRef: value.launch.processContainmentRef!,
    planRef: value.launch.containmentPlanRef, sandboxLaunchSpecRef: value.launch.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: hash,
    owner: { kind: 'worker_activation', runId: value.expected.runId, intendedLeaseEpoch: 1, workerLaunchId: value.expected.launchId },
    launchNonceDigest: value.launch.spawnNonceDigest, inspectorSupervisorInstanceId: value.expected.supervisorInstanceId,
    inspectorIdentityRef: hash, inspectorIdentityDigest: hash,
    backend: { ...value.containment.backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 },
    observedAt: time(500), evidenceDigest: '' };
  death.evidenceDigest = digestOmitting(death, 'evidenceDigest');
  const retirementEvidenceRef = await publishFixture(value, death);
  const snapshot = { schemaVersion: 1, format: 'cliq-workspace-generation-snapshot-evidence-v1', purpose: 'sealed_to_checkpoint',
    runId: value.expected.runId, generationRef: value.generation.generationRef, generationIdentityDigest: value.generation.generationIdentityDigest,
    checkpointId: 'fixture-stop-checkpoint', workspaceStateRef: hash, workspaceStateDigest: hash, entriesRef: hash,
    treeDigest: 'c'.repeat(64), descriptorRewalkComplete: true, fileFsyncComplete: true, directoryFsyncComplete: true,
    observedAt: time(250), quiescenceEvidenceRef: hash, evidenceDigest: '' };
  snapshot.evidenceDigest = digestOmitting(snapshot, 'evidenceDigest');
  const snapshotEvidenceRef = await publishFixture(value, snapshot), retiredAt = time(750);
  const retiredLaunch = { ...value.launch, phase: 'retired', generationWriteState: 'sealed', quiesceId: 'fixture-quiesce',
    leaseVersion: 4, retiredAt, retirementEvidenceRef };
  const { activeWorkerLaunchId: _active, leaseEpoch: _epoch, ...base } = value.generation;
  const sealedGeneration = { ...base, phase: 'sealed', rowVersion: 6, updatedAt: retiredAt,
    lastVerifiedTreeDigest: snapshot.treeDigest, snapshotEvidenceRef, snapshotEvidenceDigest: snapshot.evidenceDigest };
  update(value.filename, database => {
    database.prepare('UPDATE worker_launches SET phase=?, row_json=?, retired_at=?')
      .run(retiredLaunch.phase, JSON.stringify(retiredLaunch), retiredAt);
    database.prepare('UPDATE workspace_generations SET phase=?, row_version=?, row_json=?')
      .run(sealedGeneration.phase, sealedGeneration.rowVersion, JSON.stringify(sealedGeneration));
    database.exec("UPDATE runs SET active_worker_launch_id='successor-launch', lease_epoch=2, revision=9");
  });
  return { retiredLaunch, sealedGeneration, death, snapshot };
}

test('retirement diagnostic follows the captured original worker after the Run points to a successor', async t => {
  const value = await workerFixture(t), original = inspectInstalledWorkerIdentity(value.stateRoot, value.expected);
  const retired = await retireFixture(value), before = await readFile(value.filename), names = await readdir(value.cas);
  const bytes = await Promise.all(names.map(name => readFile(path.join(value.cas, name))));
  const observed = inspectInstalledWorkerRetirement(value.stateRoot, value.expected.uid, original);
  assert.equal(observed.diagnosticOnly, true); assert.equal(observed.databaseIdentity, original.databaseIdentity);
  assert.equal(observed.launchId, 'fixture-launch'); assert.equal(observed.leaseEpoch, 1);
  assert.equal(observed.pid, 12345); assert.equal(observed.processStartToken, 'linux-proc-start-ticks:67890');
  assert.equal(observed.phase, 'retired'); assert.equal(observed.generationWriteState, 'sealed'); assert.equal(observed.generationPhase, 'sealed');
  assert.equal(observed.retiredAt, retired.retiredLaunch.retiredAt);
  assert.equal(observed.retirementEvidenceRef, retired.retiredLaunch.retirementEvidenceRef);
  assert.equal(observed.snapshotEvidenceRef, retired.sealedGeneration.snapshotEvidenceRef);
  assert.equal(observed.deathObservedAt, retired.death.observedAt); assert(Object.isFrozen(observed));
  assert.equal(Object.hasOwn(observed, 'qualified'), false); assert.equal(Object.hasOwn(observed, 'nativeObservation'), false);
  assert.deepEqual(await readFile(value.filename), before); assert.deepEqual(await readdir(value.cas), names);
  assert.deepEqual(await Promise.all(names.map(name => readFile(path.join(value.cas, name)))), bytes);
  update(value.filename, database => {
    database.exec("BEGIN EXCLUSIVE; UPDATE runs SET active_worker_launch_id=NULL, status='failed', revision=10; COMMIT");
  });
  const { observedAt: _firstTime, ...first } = observed;
  const { observedAt: _secondTime, ...second } = inspectInstalledWorkerRetirement(value.stateRoot, value.expected.uid, original);
  assert.deepEqual(second, first, 'the original seal is independent of the later Run pointer and status');
});

test('retirement history reads a real retained seal without inventing an earlier live observation', async t => {
  const value = await workerFixture(t), expected = { runId: value.expected.runId, launchId: value.expected.launchId };
  assert.throws(() => inspectInstalledWorkerRetirementHistory(value.stateRoot, value.expected.uid, expected),
    { message: 'installed worker retirement history inspection refused' });
  const retired = await retireFixture(value), before = await readFile(value.filename), names = await readdir(value.cas);
  const bytes = await Promise.all(names.map(name => readFile(path.join(value.cas, name))));
  const observed = inspectInstalledWorkerRetirementHistory(value.stateRoot, value.expected.uid, expected);
  assert.equal(observed.diagnosticOnly, true); assert.equal(observed.launchId, value.expected.launchId);
  assert.equal(observed.phase, 'retired'); assert.equal(observed.generationWriteState, 'sealed'); assert.equal(observed.generationPhase, 'sealed');
  assert.equal(observed.retirementEvidenceRef, retired.retiredLaunch.retirementEvidenceRef);
  assert.equal(observed.snapshotEvidenceRef, retired.sealedGeneration.snapshotEvidenceRef);
  assert.equal(observed.snapshotEvidenceDigest, retired.sealedGeneration.snapshotEvidenceDigest);
  assert.equal(observed.deathObservedAt, retired.death.observedAt); assert(observed.observedAt >= observed.retiredAt);
  assert(Object.isFrozen(observed)); assert.equal(Object.hasOwn(observed, 'qualified'), false);
  assert.equal(Object.hasOwn(observed, 'nativeObservation'), false);
  const retirement = { launchId: value.expected.launchId, supervisorInstanceId: value.expected.supervisorInstanceId,
    leaseEpoch: 1, workspaceGenerationRef: value.generation.generationRef,
    snapshotEvidenceRef: retired.sealedGeneration.snapshotEvidenceRef,
    snapshotEvidenceDigest: retired.sealedGeneration.snapshotEvidenceDigest, retiredAt: retired.retiredLaunch.retiredAt! };
  assert.equal(inspectInstalledWorkerRetirementHistory(value.stateRoot, value.expected.uid,
    { ...expected, retirement }).snapshotEvidenceRef, retirement.snapshotEvidenceRef);
  for (const changed of [{ ...retirement, launchId: 'other-launch' }, { ...retirement, supervisorInstanceId: 'other-supervisor' },
    { ...retirement, leaseEpoch: 2 }, { ...retirement, workspaceGenerationRef: 'c'.repeat(64) },
    { ...retirement, snapshotEvidenceRef: 'd'.repeat(64) }, { ...retirement, snapshotEvidenceDigest: 'e'.repeat(64) },
    { ...retirement, retiredAt: '2026-01-01T00:00:00.000Z' }, { ...retirement, nativeObservation: true }])
    assert.throws(() => inspectInstalledWorkerRetirementHistory(value.stateRoot, value.expected.uid,
      { ...expected, retirement: changed }), { message: 'installed worker retirement history inspection refused' });
  assert.deepEqual(await readFile(value.filename), before); assert.deepEqual(await readdir(value.cas), names);
  assert.deepEqual(await Promise.all(names.map(name => readFile(path.join(value.cas, name)))), bytes);
  for (const changed of [{ ...expected, runId: 'other' }, { ...expected, launchId: 'successor-launch' },
    { ...expected, nativeObservation: true }]) {
    assert.throws(() => inspectInstalledWorkerRetirementHistory(value.stateRoot, value.expected.uid, changed),
      { message: 'installed worker retirement history inspection refused' });
  }
});

const workerCasChanges: Array<[string, (value: Awaited<ReturnType<typeof workerFixture>>) => Promise<void>]> = [
  ['writable CAS object', async value => { await chmod(value.workerFilename, 0o600); }],
  ['CAS object hardlink', async value => { await link(value.workerFilename, path.join(value.stateRoot, 'worker-alias')); }],
  ['CAS object symlink', async value => {
    const retained = path.join(value.stateRoot, 'worker-retained'); await rename(value.workerFilename, retained);
    await symlink(retained, value.workerFilename);
  }],
  ['CAS directory symlink', async value => {
    const retained = path.join(value.stateRoot, 'cas-retained'); await rename(value.cas, retained); await symlink(retained, value.cas);
  }],
  ['writable CAS directory', async value => { await chmod(value.cas, 0o755); }],
  ['wrong object hash', async value => {
    await chmod(value.workerFilename, 0o600); await writeFile(value.workerFilename, canonicalJsonBytes({ ...value.worker, pid: 99999 }));
    await chmod(value.workerFilename, 0o400);
  }],
  ['oversized object', async value => {
    await chmod(value.workerFilename, 0o600); await writeFile(value.workerFilename, 'x'.repeat(65537)); await chmod(value.workerFilename, 0o400);
  }],
  ['noncanonical content-addressed JSON', async value => {
    const bytes = Buffer.from(JSON.stringify(value.worker) + '\n'), ref = sha256Bytes(bytes);
    await writeFile(path.join(value.cas, ref), bytes, { mode: 0o400 });
    value.launch.workerIdentityDigest = ref;
    update(value.filename, db => db.prepare('UPDATE worker_launches SET row_json=?').run(JSON.stringify(value.launch)));
  }],
  ['malformed UTF-8 content-addressed object', async value => {
    const bytes = Buffer.from([0xff]), ref = sha256Bytes(bytes);
    await writeFile(path.join(value.cas, ref), bytes, { mode: 0o400 });
    value.launch.workerIdentityDigest = ref;
    update(value.filename, db => db.prepare('UPDATE worker_launches SET row_json=?').run(JSON.stringify(value.launch)));
  }],
  ['foreign worker identity', async value => {
    const foreign = { ...value.worker, launchId: 'successor-launch' }, ref = await publishFixture(value, foreign);
    value.launch.workerIdentityDigest = ref;
    update(value.filename, db => db.prepare('UPDATE worker_launches SET row_json=?').run(JSON.stringify(value.launch)));
  }],
];
for (const [label, change] of workerCasChanges) {
  test(`active identity inspection refuses ${label} without leaking object content`, async t => {
    const value = await workerFixture(t); await change(value);
    assert.throws(() => inspectInstalledWorkerIdentity(value.stateRoot, value.expected), error => {
      assert(error instanceof Error); assert.equal(error.message, 'installed worker identity inspection refused');
      assert.equal(error.cause, undefined); return true;
    });
  });
}

for (const table of ['worker_launches', 'workspace_generations']) {
  for (const [label, content] of [['oversized', JSON.stringify({ workspaceGenerationRef: 'a'.repeat(64),
    generationRef: 'a'.repeat(64), private: 'private-data'.repeat(6000) })], ['malformed', '{"private":"private-data"']] as const) {
    test(`identity inspection refuses ${label} ${table} JOIN input with a fixed error`, async t => {
      const value = await workerFixture(t);
      update(value.filename, database => database.prepare(`UPDATE ${table} SET row_json=?`).run(content));
      assert.throws(() => inspectInstalledWorkerIdentity(value.stateRoot, value.expected), error => {
        assert(error instanceof Error); assert.equal(error.message, 'installed worker identity inspection refused');
        assert.equal(error.cause, undefined); return true;
      });
    });
  }
}

const retirementChanges: Array<[string, (value: Awaited<ReturnType<typeof workerFixture>>,
  retired: Awaited<ReturnType<typeof retireFixture>>) => Promise<void> | void]> = [
  ['replacement launch instead of the original', (value, retired) => {
    const changed = { ...retired.retiredLaunch, launchId: 'successor-launch' };
    update(value.filename, db => db.prepare('UPDATE worker_launches SET launch_id=?, row_json=?').run(changed.launchId, JSON.stringify(changed)));
  }],
  ['changed original activation nonce', (value, retired) => {
    const changed = { ...retired.retiredLaunch, activationNonceDigest: 'd'.repeat(64) };
    update(value.filename, db => db.prepare('UPDATE worker_launches SET row_json=?').run(JSON.stringify(changed)));
  }],
  ['changed original generation source', (value, retired) => {
    const changed = { ...retired.sealedGeneration, sourceCheckpointId: 'successor-source' };
    update(value.filename, db => db.prepare('UPDATE workspace_generations SET row_json=?').run(JSON.stringify(changed)));
  }],
  ['mismatched retired SQL column', value => {
    update(value.filename, db => db.exec("UPDATE worker_launches SET retired_at='2026-01-01T00:00:00.000Z'"));
  }],
  ['duplicate original generation', value => {
    update(value.filename, db => db.exec('INSERT INTO workspace_generations SELECT * FROM workspace_generations'));
  }],
  ['unsealed original generation', (value, retired) => {
    const changed = { ...retired.sealedGeneration, phase: 'preactivated_readonly' };
    update(value.filename, db => db.prepare('UPDATE workspace_generations SET phase=?, row_json=?').run(changed.phase, JSON.stringify(changed)));
  }],
  ['recovery wrapper instead of normal seal death', async (value, retired) => {
    const ref = await publishFixture(value, { schemaVersion: 1, kind: 'recovery', private: 'private-data' });
    update(value.filename, db => db.prepare('UPDATE worker_launches SET row_json=?').run(JSON.stringify({ ...retired.retiredLaunch, retirementEvidenceRef: ref })));
  }],
  ['death of a different launch', async (value, retired) => {
    const death = { ...retired.death, owner: { ...retired.death.owner, workerLaunchId: 'successor-launch' } };
    death.evidenceDigest = digestOmitting(death, 'evidenceDigest'); const ref = await publishFixture(value, death);
    update(value.filename, db => db.prepare('UPDATE worker_launches SET row_json=?').run(JSON.stringify({ ...retired.retiredLaunch, retirementEvidenceRef: ref })));
  }],
  ['nonzero descendant declaration', async (value, retired) => {
    const death = { ...retired.death, backend: { ...retired.death.backend, remainingTrackedDescendants: 1 } };
    death.evidenceDigest = digestOmitting(death, 'evidenceDigest'); const ref = await publishFixture(value, death);
    update(value.filename, db => db.prepare('UPDATE worker_launches SET row_json=?').run(JSON.stringify({ ...retired.retiredLaunch, retirementEvidenceRef: ref })));
  }],
  ['foreign containment backend with the original ref', async (value, retired) => {
    const death = { ...retired.death, backend: { ...retired.death.backend, cgroupId: 'successor-cgroup' } };
    death.evidenceDigest = digestOmitting(death, 'evidenceDigest'); const ref = await publishFixture(value, death);
    update(value.filename, db => db.prepare('UPDATE worker_launches SET row_json=?').run(JSON.stringify({ ...retired.retiredLaunch, retirementEvidenceRef: ref })));
  }],
  ['snapshot of a different generation', async (value, retired) => {
    const snapshot = { ...retired.snapshot, generationRef: 'd'.repeat(64) };
    snapshot.evidenceDigest = digestOmitting(snapshot, 'evidenceDigest'); const ref = await publishFixture(value, snapshot);
    const changed = { ...retired.sealedGeneration, snapshotEvidenceRef: ref, snapshotEvidenceDigest: snapshot.evidenceDigest };
    update(value.filename, db => db.prepare('UPDATE workspace_generations SET row_json=?').run(JSON.stringify(changed)));
  }],
  ['snapshot with an invalid semantic digest', async (value, retired) => {
    const snapshot = { ...retired.snapshot, evidenceDigest: 'd'.repeat(64) }, ref = await publishFixture(value, snapshot);
    const changed = { ...retired.sealedGeneration, snapshotEvidenceRef: ref, snapshotEvidenceDigest: snapshot.evidenceDigest };
    update(value.filename, db => db.prepare('UPDATE workspace_generations SET row_json=?').run(JSON.stringify(changed)));
  }],
  ['replaced database inode', async value => {
    const replacement = path.join(value.stateRoot, 'replacement.sqlite3'); await copyFile(value.filename, replacement); await rename(replacement, value.filename);
  }],
];
for (const [label, change] of retirementChanges) {
  test(`original retirement inspection refuses ${label}`, async t => {
    const value = await workerFixture(t), original = inspectInstalledWorkerIdentity(value.stateRoot, value.expected);
    const retired = await retireFixture(value); await change(value, retired);
    assert.throws(() => inspectInstalledWorkerRetirement(value.stateRoot, value.expected.uid, original), error => {
      assert(error instanceof Error); assert.equal(error.message, 'installed worker retirement inspection refused');
      assert.equal(error.cause, undefined); return true;
    });
  });
  // These two checks need the genuinely captured earlier identity, so remain
  // mandatory on the original API above, not falsely promised by a history read.
  if (label === 'changed original generation source' || label === 'replaced database inode') continue;
  test(`retirement history inspection refuses ${label}`, async t => {
    const value = await workerFixture(t), retired = await retireFixture(value); await change(value, retired);
    assert.throws(() => inspectInstalledWorkerRetirementHistory(value.stateRoot, value.expected.uid,
      { runId: value.expected.runId, launchId: value.expected.launchId }), error => {
      assert(error instanceof Error); assert.equal(error.message, 'installed worker retirement history inspection refused');
      assert.equal(error.cause, undefined); return true;
    });
  });
}

test('retirement inspection refuses another UID and any caller-invented or changed identity field', async t => {
  const value = await workerFixture(t), original = inspectInstalledWorkerIdentity(value.stateRoot, value.expected); await retireFixture(value);
  assert.throws(() => inspectInstalledWorkerRetirement(value.stateRoot, value.expected.uid + 1, original),
    { message: 'installed worker retirement inspection refused' });
  for (const changed of [{ ...original, pid: original.pid + 1 }, { ...original, processStartToken: 'linux-proc-start-ticks:67891' },
    { ...original, nativeObservation: 'private-data' }]) {
    assert.throws(() => inspectInstalledWorkerRetirement(value.stateRoot, value.expected.uid, changed),
      { message: 'installed worker retirement inspection refused' });
  }
});

test('two short connections see a later committed renewal without retaining a writer lock', async t => {
  const value = await fixture(t), before = inspectInstalledWorkerLease(value.stateRoot, value.expected);
  value.launch.leaseVersion = 4;
  value.launch.leaseExpiresAt = new Date(Date.parse(value.launch.leaseExpiresAt!) + 1000).toISOString();
  update(value.filename, database => {
    database.exec('BEGIN EXCLUSIVE');
    database.prepare('UPDATE worker_launches SET row_json=?').run(JSON.stringify(value.launch));
    database.exec('COMMIT');
  });
  const retained = await retainedBytes(value.stateRoot), after = inspectInstalledWorkerLease(value.stateRoot, value.expected);
  assert.equal(after.databaseIdentity, before.databaseIdentity);
  assert.equal(after.launchInvariantDigest, before.launchInvariantDigest);
  assert.equal(after.leaseVersion, 4); assert.equal(after.leaseExpiresAt, value.launch.leaseExpiresAt);
  assert.deepEqual(await retainedBytes(value.stateRoot), retained);
});

test('reader fingerprints every retained worker identity even when the public Run and lease remain unchanged', async t => {
  const value = await fixture(t), before = inspectInstalledWorkerLease(value.stateRoot, value.expected);
  for (const key of ['workerIdentityDigest', 'workspaceGenerationRef', 'processContainmentRef', 'activatedAt'] as const) {
    const changed = { ...value.launch, [key]: key === 'activatedAt'
      ? new Date(Date.parse(value.launch.activatedAt!) + 1).toISOString() : 'b'.repeat(64) };
    update(value.filename, db => db.prepare('UPDATE worker_launches SET row_json=?').run(JSON.stringify(changed)));
    const after = inspectInstalledWorkerLease(value.stateRoot, value.expected);
    assert.equal(after.databaseIdentity, before.databaseIdentity, key);
    assert.notEqual(after.launchInvariantDigest, before.launchInvariantDigest, key);
    assert.equal(after.leaseVersion, before.leaseVersion, key);
    assert.equal(after.leaseExpiresAt, before.leaseExpiresAt, key);
  }
});

function pair() {
  const before = { diagnosticOnly: true as const, databaseIdentity: 'a'.repeat(64), launchInvariantDigest: 'b'.repeat(64),
    leaseVersion: 1, observedAt: '2026-10-15T00:00:00.000Z', leaseExpiresAt: '2026-10-15T00:00:01.000Z' };
  const after = { ...before, leaseVersion: 4, observedAt: '2026-10-15T00:00:01.001Z', leaseExpiresAt: '2026-10-15T00:00:02.000Z' };
  return { before, after, deadlineAt: '2026-10-15T00:00:03.000Z' };
}

test('the same lease may advance multiple versions across its original expiry', () => {
  const value = pair();
  assert.doesNotThrow(() => assertInstalledWorkerLeaseRenewed(value.before, value.after, value.deadlineAt));
});

const invalidCuts: Array<[string, (value: Awaited<ReturnType<typeof fixture>>) => void]> = [
  ['wrong schema', value => update(value.filename, db => db.exec('PRAGMA user_version=0'))],
  ['wrong active pointer', value => update(value.filename, db => db.exec("UPDATE runs SET active_worker_launch_id='other'"))],
  ['inactive Run', value => update(value.filename, db => db.exec("UPDATE runs SET status='waiting'"))],
  ['different Run revision', value => update(value.filename, db => db.exec('UPDATE runs SET revision=4'))],
  ['different Run epoch', value => update(value.filename, db => db.exec('UPDATE runs SET lease_epoch=2'))],
  ['cancellation', value => update(value.filename, db => db.exec('UPDATE runs SET cancel_requested=1'))],
  ['stop intent', value => update(value.filename, db => db.exec("UPDATE runs SET stop_intent_ref='private-data'"))],
  ['different deadline', value => update(value.filename, db => db.exec("UPDATE runs SET deadline_at='2026-01-01T00:00:00.000Z'"))],
  ['retired SQL row', value => update(value.filename, db => db.exec("UPDATE worker_launches SET retired_at='2026-01-01T00:00:00.000Z'"))],
  ['duplicate join', value => update(value.filename, db => db.exec('INSERT INTO worker_launches SELECT * FROM worker_launches'))],
  ['malformed JSON', value => update(value.filename, db => db.prepare('UPDATE worker_launches SET row_json=?').run('{"secret":"private-data"'))],
  ['oversized JSON', value => update(value.filename, db => db.prepare('UPDATE worker_launches SET row_json=?').run(' '.repeat(65537)))],
  ['missing table', value => update(value.filename, db => db.exec('DROP TABLE worker_launches'))],
];
for (const [label, change] of invalidCuts) {
  test(`readonly lease inspection refuses ${label} without exposing row content`, async t => {
    const value = await fixture(t); change(value);
    assert.throws(() => inspectInstalledWorkerLease(value.stateRoot, value.expected), error => {
      assert(error instanceof Error); assert.equal(error.message, 'installed worker lease inspection refused');
      assert.equal(error.cause, undefined); return true;
    });
  });
}

const invalidLaunches: Array<[string, (launch: WorkerLaunch, deadlineAt: string) => void]> = [
  ['row id mismatch', launch => { launch.launchId = 'other'; }],
  ['Run id mismatch', launch => { launch.runId = 'other'; }],
  ['owner mismatch', launch => { launch.supervisorInstanceId = 'other'; }],
  ['epoch mismatch', launch => { launch.leaseEpoch = 2; }],
  ['nonactive generation', launch => { launch.generationWriteState = 'revoking'; launch.quiesceId = 'fixture'; }],
  ['expired lease', launch => { launch.leaseExpiresAt = new Date(Date.now() - 1).toISOString(); }],
  ['expiry beyond deadline', (launch, deadlineAt) => { launch.leaseExpiresAt = new Date(Date.parse(deadlineAt) + 1).toISOString(); }],
  ['missing worker identity', launch => { delete launch.workerIdentityDigest; }],
];
for (const [label, change] of invalidLaunches) {
  test(`readonly lease inspection refuses ${label} in the serialized launch`, async t => {
    const value = await fixture(t); change(value.launch, value.expected.deadlineAt);
    update(value.filename, db => db.prepare('UPDATE worker_launches SET row_json=?').run(JSON.stringify(value.launch)));
    assert.throws(() => inspectInstalledWorkerLease(value.stateRoot, value.expected), { message: 'installed worker lease inspection refused' });
  });
}

test('filesystem guards reject permissive modes, symlinks, aliases and a different expected UID', async t => {
  const value = await fixture(t), refuses = () => assert.throws(() => inspectInstalledWorkerLease(value.stateRoot, value.expected),
    { message: 'installed worker lease inspection refused' });
  await chmod(value.stateRoot, 0o755); refuses(); await chmod(value.stateRoot, 0o700);
  await chmod(value.filename, 0o644); refuses(); await chmod(value.filename, 0o600);
  assert.throws(() => inspectInstalledWorkerLease(value.stateRoot, { ...value.expected, uid: value.expected.uid + 1 }),
    { message: 'installed worker lease inspection refused' });
  const alias = path.join(value.stateRoot, 'root-alias'); await symlink(value.stateRoot, alias);
  assert.throws(() => inspectInstalledWorkerLease(alias, value.expected), { message: 'installed worker lease inspection refused' });
  const second = path.join(value.stateRoot, 'second.sqlite3'); await link(value.filename, second); refuses(); await rm(second);
  const original = path.join(value.stateRoot, 'original.sqlite3'); await rename(value.filename, original);
  await symlink(original, value.filename); refuses();
});

test('a replacement database cannot retain the original observation identity', async t => {
  const value = await fixture(t), before = inspectInstalledWorkerLease(value.stateRoot, value.expected);
  const replacement = path.join(value.stateRoot, 'replacement.sqlite3');
  await copyFile(value.filename, replacement); await rename(replacement, value.filename);
  const after = inspectInstalledWorkerLease(value.stateRoot, value.expected);
  assert.notEqual(after.databaseIdentity, before.databaseIdentity);
  assert.equal(after.launchInvariantDigest, before.launchInvariantDigest);
});

test('damaged database bytes are a fixed refusal, never pending', async t => {
  const value = await fixture(t); await writeFile(value.filename, 'private-damaged-database-data');
  assert.throws(() => inspectInstalledWorkerLease(value.stateRoot, value.expected), { message: 'installed worker lease inspection refused' });
});

test('a real test-owned exclusive writer exhausts the fixed wait and is genuinely closed', async t => {
  const value = await fixture(t);
  update(value.filename, db => {
    db.exec('BEGIN EXCLUSIVE');
    assert.throws(() => inspectInstalledWorkerLease(value.stateRoot, value.expected), { message: 'installed worker lease inspection refused' });
    db.exec('ROLLBACK');
  });
  assert.equal(inspectInstalledWorkerLease(value.stateRoot, value.expected).leaseVersion, 1);
});

const invalidPairs: Array<[string, (value: ReturnType<typeof pair>) => void]> = [
  ['unchanged version', value => { value.after.leaseVersion = 1; }],
  ['unchanged expiry', value => { value.after.leaseExpiresAt = value.before.leaseExpiresAt; }],
  ['another database', value => { value.after.databaseIdentity = 'c'.repeat(64); }],
  ['another launch invariant', value => { value.after.launchInvariantDigest = 'c'.repeat(64); }],
  ['old expiry not crossed', value => { value.after.observedAt = value.before.leaseExpiresAt; }],
  ['already expired renewed lease', value => { value.after.observedAt = value.after.leaseExpiresAt; }],
  ['already expired initial lease', value => { value.before.observedAt = value.before.leaseExpiresAt; }],
  ['renewal beyond deadline', value => { value.after.leaseExpiresAt = '2026-10-15T00:00:03.001Z'; }],
  ['noncanonical timestamp', value => { value.after.observedAt = '2026-10-15T00:00:01Z'; }],
  ['malformed hash', value => { value.after.databaseIdentity = 'private-data'; }],
  ['unsafe version', value => { value.after.leaseVersion = Number.MAX_SAFE_INTEGER + 1; }],
];
for (const [label, change] of invalidPairs) {
  test(`pure renewal comparison refuses ${label}`, () => {
    const value = pair(); change(value);
    assert.throws(() => assertInstalledWorkerLeaseRenewed(value.before, value.after, value.deadlineAt),
      { message: 'installed worker lease renewal diagnostic refused' });
  });
}
