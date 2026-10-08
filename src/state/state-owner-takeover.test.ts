import assert from 'node:assert/strict';
import { readdir, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { digestOmitting } from '../kernel/identity.js';
import type { StateOwnerAcquisitionEvidenceV1, StateOwnerTransitionEvidenceV1 } from '../kernel/types.js';
import { testFixture } from '../model/testing/fixtures.js';
import { ArtifactCatalog, insertArtifactMetadata } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { readTimeFence } from './canonical-time.js';
import { loadNativeStateOwner } from './native-owner.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { readStateOwner } from './state-owner.js';
import { openStateStore, type StateStoreRuntimeAuthority } from './store.js';
import { makePrivateDir } from './testing/fixtures.js';
import { childFor, ownerAt } from './testing/state-owner-process.js';
import { signedToolBundle } from './testing/tool-authority.js';

const native = await loadNativeStateOwner();

async function startOwner(t: TestContext, authority?: StateStoreRuntimeAuthority, mode: 'store' | 'fixture' | 'fixture_prepared' = 'store') {
  const container = await makePrivateDir('.cliq-owner-takeover-');
  const child = await childFor(t, container, mode);
  t.after(() => rm(container, { recursive: true, force: true }));
  const acquired = await child.request('acquire', authority);
  assert.equal(acquired.state, 'held', acquired.message);
  const root = acquired.stateRoot ?? container;
  return { root, child, acquired, async crash() {
    child.child.kill('SIGKILL');
    assert.equal((await child.exited)[1], 'SIGKILL');
  } };
}

function snapshot(root: string) {
  const driver = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
  try {
    return Object.fromEntries(['state_owners', 'canonical_time_fence', 'artifacts', 'sessions', 'runs', 'items',
      'run_journal', 'worker_launches', 'workspace_generations', 'checkpoints', 'control_requests']
      .map(table => [table, driver.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()]));
  } finally { driver.close(); }
}

test('SIGKILL takeover atomically retains the exact predecessor and acquires a fresh owner on the same lock', async (t) => {
  const fixture = await startOwner(t);
  const prior = ownerAt(fixture.root);
  await fixture.crash();
  const store = await openStateStore(fixture.root);
  try {
    const owner = ownerAt(fixture.root);
    assert.equal(owner.ownerEpoch, prior.ownerEpoch + 1);
    assert.equal(owner.state, 'active');
    assert.equal(owner.stateLockIdentityRef, prior.stateLockIdentityRef);
    assert.notEqual(owner.supervisorInstanceId, prior.supervisorInstanceId);
    assert.notEqual(owner.instanceNonceDigest, prior.instanceNonceDigest);
    const driver = openSqliteDriver(path.join(fixture.root, KERNEL_DATABASE_FILENAME));
    const terminal = readStateOwner(driver, prior.ownerEpoch)!;
    assert.equal(readTimeFence(driver)!.stateOwnerEpoch, owner.ownerEpoch);
    assert.equal(driver.prepare("SELECT count(*) AS count FROM state_owners WHERE state = 'active'").get<{ count: bigint }>()!.count, 1n);
    driver.close();
    assert.equal(terminal.state, 'terminal');
    if (terminal.state !== 'terminal') assert.fail('predecessor must be terminal');
    assert.equal(terminal.terminalReason, 'superseded_after_owner_death');
    assert.equal(terminal.rowVersion, 2);
    assert.equal(terminal.rowDigest, digestOmitting(terminal, 'rowDigest'));
    const transition = await store.artifacts.readCanonical<StateOwnerTransitionEvidenceV1>(terminal.transitionEvidenceRef);
    assert.equal(transition.kind, 'superseded_after_owner_death');
    if (transition.kind !== 'superseded_after_owner_death') assert.fail('missing death transition');
    assert.deepEqual(transition, {
      schemaVersion: 1, format: 'cliq-state-owner-transition-evidence-v1',
      priorOwnerEpoch: prior.ownerEpoch, priorSupervisorInstanceId: prior.supervisorInstanceId,
      priorProcessIdentityRef: prior.processIdentityRef, priorProcessIdentityDigest: prior.processIdentityDigest,
      stateLockIdentityRef: prior.stateLockIdentityRef, stateLockIdentityDigest: prior.stateLockIdentityDigest,
      observedAt: owner.acquiredAt, evidenceDigest: digestOmitting(transition, 'evidenceDigest'),
      kind: 'superseded_after_owner_death', priorProcessObservation: 'absent_or_start_token_mismatch',
      successorOwnerEpoch: owner.ownerEpoch, successorSupervisorInstanceId: owner.supervisorInstanceId,
      successorRuntimeBundleRef: owner.runtimeBundleRef, successorRuntimeBundleManifestDigest: owner.runtimeBundleManifestDigest,
      successorProcessIdentityRef: owner.processIdentityRef, successorProcessIdentityDigest: owner.processIdentityDigest,
      successorInstanceNonceDigest: owner.instanceNonceDigest
    });
    const acquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(owner.acquisitionEvidenceRef);
    assert.equal(acquisition.kind, 'takeover_after_owner_death');
    if (acquisition.kind !== 'takeover_after_owner_death') assert.fail('missing death acquisition');
    assert.equal(acquisition.evidenceDigest, digestOmitting(acquisition, 'evidenceDigest'));
    assert.equal(acquisition.priorTerminalRowDigest, terminal.rowDigest);
    assert.equal(acquisition.priorTransitionEvidenceRef, terminal.transitionEvidenceRef);
    assert.equal(acquisition.priorTransitionEvidenceDigest, transition.evidenceDigest);
    await assert.rejects(openStateStore(fixture.root), /OS lock is already held/);
  } finally { await store.close(); }
  const reopened = await openStateStore(fixture.root);
  try {
    assert.equal(reopened.ownerEpoch, 3);
    const acquisition = await reopened.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(ownerAt(fixture.root).acquisitionEvidenceRef);
    assert.equal(acquisition.kind, 'acquire_after_graceful_release');
  } finally { await reopened.close(); }
});

test('a free OS lock never authorizes takeover while the exact prior process remains alive', async (t) => {
  const fixture = await startOwner(t);
  assert.equal((await fixture.child.request('drop-lock')).state, 'released');
  const before = snapshot(fixture.root);
  const objects = await readdir(path.join(fixture.root, KERNEL_CAS_DIRECTORY));
  await assert.rejects(openStateStore(fixture.root), { code: 'RECOVERY_REQUIRED', message: 'prior StateOwner process is still present' });
  assert.deepEqual(snapshot(fixture.root), before);
  assert.deepEqual(await readdir(path.join(fixture.root, KERNEL_CAS_DIRECTORY)), objects);
  await fixture.crash();
  const store = await openStateStore(fixture.root);
  try { assert.equal(store.ownerEpoch, 2); } finally { await store.close(); }
});

test('two successors racing a dead owner commit exactly one takeover and no skipped epoch', async (t) => {
  const fixture = await startOwner(t);
  await fixture.crash();
  const successors = await Promise.all([childFor(t, fixture.root), childFor(t, fixture.root)]);
  const results = await Promise.all(successors.map(child => child.request('acquire')));
  assert.equal(results.filter(result => result.state === 'held' && result.epoch === 2).length, 1, JSON.stringify(results));
  assert.equal(results.filter(result => result.state === 'error' && /OS lock is already held/.test(result.message!)).length, 1, JSON.stringify(results));
  const driver = openSqliteDriver(path.join(fixture.root, KERNEL_DATABASE_FILENAME));
  try {
    assert.deepEqual(driver.prepare('SELECT owner_epoch, state FROM state_owners ORDER BY owner_epoch')
      .all<{ owner_epoch: bigint; state: string }>().map(row => [row.owner_epoch, row.state]),
    [[1n, 'terminal'], [2n, 'active']]);
  } finally { driver.close(); }
  await successors[results.findIndex(result => result.state === 'held')]!.request('close');
});

for (const phase of ['prepared', 'claimed'] as const) test(`takeover preserves the exact ${phase} typed call and cannot adopt its old worker`, async (t) => {
  const fixture = await startOwner(t, undefined, phase === 'prepared' ? 'fixture_prepared' : 'fixture');
  const before = snapshot(fixture.root);
  await fixture.crash();
  const store = await openStateStore(fixture.root, fixture.acquired.authority);
  try {
    const after = snapshot(fixture.root);
    for (const table of ['sessions', 'runs', 'items', 'run_journal', 'worker_launches', 'workspace_generations', 'checkpoints', 'control_requests']) {
      assert.deepEqual(after[table], before[table], table);
    }
    const cut = await store.readRecoveryClosure(fixture.acquired.runId!);
    assert.equal(cut.run.activeWorkerLaunchId, fixture.acquired.launchId);
    assert.equal(cut.run.budgetReserved.toolCalls, 1);
    assert.deepEqual(cut.journal.map(entry => [entry.opKind, entry.phase]),
      [['model', 'prepared'], ['model', 'dispatch_claimed'], ['model', 'completed'], ['tool', 'prepared'],
        ...(phase === 'claimed' ? [['tool', 'dispatch_claimed']] : [])]);
    assert.throws(() => store.renewWorkerLease({ launchId: fixture.acquired.launchId!, expectedLeaseVersion: fixture.acquired.leaseVersion!,
      runId: cut.run.id, leaseEpoch: cut.run.leaseEpoch, workerIdentityDigest: cut.workerLaunches[0]!.workerIdentityDigest!,
      newLeaseExpiresAt: new Date(Date.now() + 60_000).toISOString() }), { code: 'LEASE_FENCED' });
  } finally { await store.close(); }
});

test('failure after predecessor terminalization rolls back both owners, artifact metadata and time fence', async (t) => {
  const fixture = await startOwner(t);
  await fixture.crash();
  const driver = openSqliteDriver(path.join(fixture.root, KERNEL_DATABASE_FILENAME));
  try {
    driver.exec(`CREATE TRIGGER fail_takeover BEFORE INSERT ON state_owners WHEN NEW.owner_epoch = 2
      BEGIN SELECT RAISE(ABORT, 'injected successor insert failure'); END;`);
    const before = snapshot(fixture.root);
    await assert.rejects(openStateStore(fixture.root), /injected successor insert failure/);
    assert.deepEqual(snapshot(fixture.root), before);
    native.acquireLock(fixture.root, false).close();
  } finally { driver.exec('DROP TRIGGER fail_takeover'); driver.close(); }
  const store = await openStateStore(fixture.root);
  try { assert.equal(store.ownerEpoch, 2); } finally { await store.close(); }
});

test('takeover publication failure leaves an active predecessor and can retry through unrooted CAS objects', async (t) => {
  const fixture = await startOwner(t);
  await fixture.crash();
  const before = snapshot(fixture.root);
  const original = ArtifactCatalog.prototype.publishCanonical;
  const failure = t.mock.method(ArtifactCatalog.prototype, 'publishCanonical', async function (this: ArtifactCatalog, value: unknown, kind: string) {
    if ((value as { kind?: string }).kind === 'takeover_after_owner_death') throw new Error('injected acquisition publication failure');
    return original.call(this, value, kind);
  });
  try {
    await assert.rejects(openStateStore(fixture.root), /injected acquisition publication failure/);
    assert.deepEqual(snapshot(fixture.root), before);
    native.acquireLock(fixture.root, false).close();
  } finally { failure.mock.restore(); }
  const store = await openStateStore(fixture.root);
  try { assert.equal(store.ownerEpoch, 2); } finally { await store.close(); }
});

for (const delay of [5000, 5001]) test(`takeover enforces the five-second observation-to-commit limit (${delay}ms)`, async (t) => {
  const fixture = await startOwner(t);
  await fixture.crash();
  const before = snapshot(fixture.root);
  let now = Date.now();
  const clock = t.mock.method(Date, 'now', () => now);
  const original = ArtifactCatalog.prototype.publishCanonical;
  const publication = t.mock.method(ArtifactCatalog.prototype, 'publishCanonical', async function (this: ArtifactCatalog, value: unknown, kind: string) {
    const result = await original.call(this, value, kind);
    if ((value as { kind?: string }).kind === 'takeover_after_owner_death') now += delay;
    return result;
  });
  try {
    if (delay === 5000) {
      const store = await openStateStore(fixture.root);
      try { assert.equal(store.ownerEpoch, 2); } finally { await store.close(); }
    } else {
      await assert.rejects(openStateStore(fixture.root), /outside the five-second commit window/);
      assert.deepEqual(snapshot(fixture.root), before);
    }
  } finally { publication.mock.restore(); clock.mock.restore(); }
});

test('death takeover preserves a regressed canonical clock instead of resetting its high-water', async (t) => {
  const fixture = await startOwner(t);
  await fixture.crash();
  const driver = openSqliteDriver(path.join(fixture.root, KERNEL_DATABASE_FILENAME));
  const prior = readTimeFence(driver)!;
  driver.close();
  const clock = t.mock.method(Date, 'now', () => Date.parse(prior.lastAcceptedAt) - 60_000);
  const store = await openStateStore(fixture.root);
  try {
    const reader = openSqliteDriver(path.join(fixture.root, KERNEL_DATABASE_FILENAME));
    try {
      const fence = readTimeFence(reader)!;
      assert.equal(fence.stateOwnerEpoch, 2);
      assert.equal(fence.state, 'clock_regressed');
      assert.equal(fence.lastAcceptedAt, prior.lastAcceptedAt);
    } finally { reader.close(); }
  } finally { clock.mock.restore(); await store.close(); }
});

test('dead-owner takeover requires retained process, acquisition and runtime bytes and the original lock inode', async (t) => {
  const fixture = await startOwner(t);
  const prior = ownerAt(fixture.root);
  await fixture.crash();
  const before = snapshot(fixture.root);
  for (const ref of [prior.processIdentityRef, prior.acquisitionEvidenceRef, prior.runtimeBundleRef, prior.stateLockIdentityRef]) {
    const object = path.join(fixture.root, KERNEL_CAS_DIRECTORY, ref);
    const saved = path.join(fixture.root, 'saved-object');
    await rename(object, saved);
    try {
      await assert.rejects(openStateStore(fixture.root), { code: 'ENOENT' });
      assert.deepEqual(snapshot(fixture.root), before);
    } finally { await rename(saved, object); }
  }
  const lock = path.join(fixture.root, 'runtime/state-owner.lock');
  const saved = path.join(fixture.root, 'saved-lock');
  await rename(lock, saved);
  native.acquireLock(fixture.root, true).close();
  try {
    await assert.rejects(openStateStore(fixture.root), /filesystem identity changed/);
    assert.deepEqual(snapshot(fixture.root), before);
  } finally { await rm(lock); await rename(saved, lock); }
  const store = await openStateStore(fixture.root);
  try { assert.equal(store.ownerEpoch, 2); } finally { await store.close(); }
});

test('signed-owner death never permits unsigned bootstrap or implicit runtime replacement', async (t) => {
  const authority = await signedToolBundle(testFixture().assembly, []);
  const fixture = await startOwner(t, authority);
  const prior = ownerAt(fixture.root);
  await fixture.crash();
  const before = snapshot(fixture.root);
  await assert.rejects(openStateStore(fixture.root), /same signed Supervisor authority/);
  await assert.rejects(openStateStore(fixture.root, { ...authority, releaseKeys: [] }), /trusted release signature/);
  const other = await signedToolBundle(testFixture().assembly, []);
  await assert.rejects(openStateStore(fixture.root, other), /runtime upgrades need their own transition/);
  assert.deepEqual(snapshot(fixture.root), before);
  const store = await openStateStore(fixture.root, authority);
  try {
    assert.equal(store.ownerEpoch, 2);
    assert.equal(ownerAt(fixture.root).runtimeBundleRef, prior.runtimeBundleRef);
  } finally { await store.close(); }
});

test('consecutive crashes revalidate the prior takeover graph and reject a rehashed foreign successor', async (t) => {
  const fixture = await startOwner(t);
  await fixture.crash();
  const second = await childFor(t, fixture.root);
  assert.equal((await second.request('acquire')).epoch, 2);
  second.child.kill('SIGKILL');
  await second.exited;
  const driver = openSqliteDriver(path.join(fixture.root, KERNEL_DATABASE_FILENAME));
  const catalog = new ArtifactCatalog(new ContentAddressedStore(path.join(fixture.root, KERNEL_CAS_DIRECTORY)));
  const predecessor = readStateOwner(driver, 1)!;
  const owner = readStateOwner(driver, 2)!;
  assert.equal(predecessor.state, 'terminal');
  if (predecessor.state !== 'terminal') assert.fail('first owner was not superseded');
  const transition = await catalog.readCanonical<StateOwnerTransitionEvidenceV1>(predecessor.transitionEvidenceRef);
  assert.equal(transition.kind, 'superseded_after_owner_death');
  if (transition.kind !== 'superseded_after_owner_death') assert.fail('first owner has no death evidence');
  const acquisition = await catalog.readCanonical<StateOwnerAcquisitionEvidenceV1>(owner.acquisitionEvidenceRef);
  assert.equal(acquisition.kind, 'takeover_after_owner_death');
  if (acquisition.kind !== 'takeover_after_owner_death') assert.fail('second owner has no acquisition');
  const forgedTransition = { ...transition, successorInstanceNonceDigest: 'f'.repeat(64), evidenceDigest: '' };
  forgedTransition.evidenceDigest = digestOmitting(forgedTransition, 'evidenceDigest');
  const transitionObject = await catalog.publishCanonical(forgedTransition, forgedTransition.format);
  const forgedPredecessor = { ...predecessor, transitionEvidenceRef: transitionObject.ref,
    transitionEvidenceDigest: forgedTransition.evidenceDigest, rowDigest: '' };
  forgedPredecessor.rowDigest = digestOmitting(forgedPredecessor, 'rowDigest');
  const forgedAcquisition = { ...acquisition, priorTerminalRowDigest: forgedPredecessor.rowDigest,
    priorTransitionEvidenceRef: transitionObject.ref, priorTransitionEvidenceDigest: forgedTransition.evidenceDigest, evidenceDigest: '' };
  forgedAcquisition.evidenceDigest = digestOmitting(forgedAcquisition, 'evidenceDigest');
  const acquisitionObject = await catalog.publishCanonical(forgedAcquisition, forgedAcquisition.format);
  const forgedOwner = { ...owner, acquisitionEvidenceRef: acquisitionObject.ref,
    acquisitionEvidenceDigest: forgedAcquisition.evidenceDigest, rowDigest: '' };
  forgedOwner.rowDigest = digestOmitting(forgedOwner, 'rowDigest');
  const trigger = driver.prepare("SELECT sql FROM sqlite_master WHERE name = 'state_owners_validate_update'").get<{ sql: string }>()!.sql;
  // Corrupt only this disposable database, including every enclosing digest:
  // shape/hash checks must not substitute for exact successor ownership.
  const rewrite = (first: typeof predecessor, second: typeof owner) => driver.transaction(connection => {
    connection.exec('DROP TRIGGER state_owners_validate_update');
    for (const record of [first, second]) connection.prepare('UPDATE state_owners SET record_json = ?, row_digest = ? WHERE owner_epoch = ?')
      .run(JSON.stringify(record), record.rowDigest, BigInt(record.ownerEpoch));
    connection.exec(trigger);
  });
  try {
    driver.transaction(connection => {
      insertArtifactMetadata(connection, transitionObject, owner.acquiredAt);
      insertArtifactMetadata(connection, acquisitionObject, owner.acquiredAt);
    });
    rewrite(forgedPredecessor, forgedOwner);
    const before = snapshot(fixture.root);
    await assert.rejects(openStateStore(fixture.root), /transition evidence does not match its prior\/successor/);
    assert.deepEqual(snapshot(fixture.root), before);
  } finally { rewrite(predecessor, owner); driver.close(); }
  const store = await openStateStore(fixture.root);
  try { assert.equal(store.ownerEpoch, 3); } finally { await store.close(); }
});
