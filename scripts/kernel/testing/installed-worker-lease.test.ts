// Serialized test-owned SQLite data only; no StateOwner, native owner or worker
// authority is created. Real installed renewal is a separate Linux qualification.
import assert from 'node:assert/strict';
import { chmod, copyFile, link, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test, type TestContext } from 'node:test';
import { KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../../../src/config.js';
import type { WorkerLaunch } from '../../../src/kernel/types.js';
import { assertInstalledWorkerLeaseRenewed, inspectInstalledWorkerLease } from './installed-worker-lease.js';

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
