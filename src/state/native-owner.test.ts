import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmod, link, lstat, mkdir, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import type { PlatformProcessIdentityV1 } from '../kernel/types.js';
import { loadNativeStateOwner, stateRootIdentityFromDescriptor } from './native-owner.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { StateRootIdentityV1 } from '../kernel/types.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { openStateStore } from './store.js';
import { makePrivateDir } from './testing/fixtures.js';
import { childFor, ownerAt } from './testing/state-owner-process.js';

const native = await loadNativeStateOwner();
const busy = /StateOwner OS lock is already held/;

async function rootFor(t: TestContext) {
  const root = await makePrivateDir('.cliq-native-owner-');
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('stateRootIdentityFromDescriptor matches the held native lock and store bootstrap artifact', async (t) => {
  const root = await rootFor(t);
  const held = native.acquireLock(root, true);
  try {
    const projected = stateRootIdentityFromDescriptor(root, held.root);
    assert.ok(Object.isFrozen(projected));
    assert.equal(projected.platform, process.platform === 'linux' ? 'linux' : 'macos');
    assert.equal(projected.canonicalAbsolutePath, root);
    assert.equal(projected.ownerUid, held.root.ownerUid);
    assert.equal(projected.deviceId, held.root.deviceId);
    assert.equal(projected.directoryFileId, held.root.fileId);
    assert.equal(projected.mode, 448);
    assert.equal(projected.openedNoFollow, true);
    assert.equal(projected.layoutVersion, 1);
    assert.equal(projected.identityDigest, digestOmitting(projected, 'identityDigest'));
    assert.equal(canonicalSha256(projected), canonicalSha256(structuredClone(projected) as StateRootIdentityV1));
  } finally { held.close(); }

  const store = await openStateStore(root);
  const published = await store.artifacts.readCanonical<StateRootIdentityV1>(store.stateRootIdentity.ref);
  assert.equal(published.identityDigest, store.stateRootIdentity.digest);
  await store.close();
  const successor = native.acquireLock(root, false);
  try {
    assert.deepEqual(stateRootIdentityFromDescriptor(root, successor.root), published);
  } finally { successor.close(); }
});

test('stateRootIdentityFromDescriptor changes digest when descriptor identity drifts', () => {
  const root = '/tmp/example-state-root';
  const base = { deviceId: '1', fileId: '2', ownerUid: process.geteuid!() };
  const first = stateRootIdentityFromDescriptor(root, base);
  for (const drift of [{ fileId: '3' }, { deviceId: '9' }, { ownerUid: base.ownerUid + 1 }]) {
    assert.notEqual(stateRootIdentityFromDescriptor(root, { ...base, ...drift }).identityDigest, first.identityDigest);
  }
});

test('native StateOwner lock holds exact descriptor identities until explicit close', async (t) => {
  const root = await rootFor(t);
  const held = native.acquireLock(root, true);
  try {
    for (const [identity, locator] of [[held.root, root], [held.runtime, path.join(root, 'runtime')],
      [held.lock, path.join(root, 'runtime/state-owner.lock')]] as const) {
      const stat = await lstat(locator, { bigint: true });
      assert.deepEqual(identity, { deviceId: String(stat.dev), fileId: String(stat.ino), ownerUid: Number(stat.uid) });
      assert.ok(Object.isFrozen(identity));
    }
    held.assertHeld();
    assert.throws(() => native.acquireLock(root, false), busy);
    assert.throws(() => held.close.call({}), /invalid StateOwner lock handle/);
    held.assertHeld();
  } finally { held.close(); }
  held.close();
  assert.throws(() => held.assertHeld(), /changed or closed/);
  const successor = native.acquireLock(root, false);
  try {
    assert.throws(() => held.assertHeld(), /changed or closed/);
    successor.assertHeld();
  } finally { successor.close(); }
});

test('native process start identity is stable and independent of wall clock and uptime estimates', async (t) => {
  const token = native.processStartToken();
  t.mock.method(Date, 'now', () => 0);
  t.mock.method(process, 'uptime', () => Number.MAX_SAFE_INTEGER);
  assert.equal(native.processStartToken(), token);
  if (process.platform === 'linux') {
    const stat = await readFile('/proc/self/stat', 'utf8');
    assert.equal(token, `linux-proc-start-ticks:${stat.slice(stat.lastIndexOf(')') + 2).trim().split(/\s+/u)[19]}`);
  } else {
    assert.match(token, /^darwin-proc-start-time:[1-9]\d*:\d{6}$/u);
  }
});

test('StateOwner rejects symlink ancestors and noncanonical roots before creating layout', async (t) => {
  const container = await rootFor(t);
  const real = path.join(container, 'real');
  const alias = path.join(container, 'alias');
  await mkdir(real, { mode: 0o700 });
  await mkdir(path.join(real, 'state'), { mode: 0o700 });
  await symlink(real, alias);
  for (const candidate of [alias, path.join(alias, 'state'), `${real}/`, `${real}/./state`, `${real}//state`, `${real}\0ignored`]) {
    assert.throws(() => native.acquireLock(candidate, true));
  }
  await assert.rejects(openStateStore(path.join(alias, 'state')), /without following symlinks/);
  assert.deepEqual(await readdir(path.join(real, 'state')), []);
  assert.deepEqual(await readdir(real), ['state']);
});

test('held owner rejects root, runtime and lock replacement or permission drift without reacquiring', async (t) => {
  const root = await rootFor(t);
  const held = native.acquireLock(root, true);
  try {
    for (const [locator, isDirectory, mode] of [[root, true, 0o700], [path.join(root, 'runtime'), true, 0o700],
      [path.join(root, 'runtime/state-owner.lock'), false, 0o600]] as const) {
      await chmod(locator, 0o755);
      try { assert.throws(() => held.assertHeld(), /changed or closed/); }
      finally { await chmod(locator, mode); }
      held.assertHeld();
      const saved = `${locator}.saved`;
      await rename(locator, saved);
      try {
        if (isDirectory) await mkdir(locator, { mode }); else await writeFile(locator, '', { mode });
        assert.throws(() => held.assertHeld(), /changed or closed/);
      } finally {
        await rm(locator, { recursive: true, force: true });
        await rename(saved, locator);
      }
      held.assertHeld();
      assert.throws(() => native.acquireLock(root, false), busy);
    }
  } finally { held.close(); }
});

test('native acquisition rejects unsafe lock files without repairing them', async (t) => {
  const root = await rootFor(t);
  native.acquireLock(root, true).close();
  const lock = path.join(root, 'runtime/state-owner.lock');
  const saved = path.join(root, 'saved-lock');
  await link(lock, saved);
  try { assert.throws(() => native.acquireLock(root, false), /link count 1/); }
  finally { await rm(saved); }
  await chmod(lock, 0o644);
  assert.throws(() => native.acquireLock(root, false), /0600/);
  assert.equal((await lstat(lock)).mode & 0o777, 0o644);
  await chmod(lock, 0o600);
  await rename(lock, saved);
  try {
    await symlink(saved, lock);
    assert.throws(() => native.acquireLock(root, false), /regular file/);
    await rm(lock);
    await mkdir(lock, { mode: 0o700 });
    assert.throws(() => native.acquireLock(root, false), /regular file/);
    await rm(lock, { recursive: true });
    execFileSync('mkfifo', ['-m', '600', lock]);
    assert.throws(() => native.acquireLock(root, false), /regular file/);
  } finally { await rm(lock, { recursive: true, force: true }); await rename(saved, lock); }
  native.acquireLock(root, false).close();
});

test('a competing process cannot open SQLite or CAS until the actual owner lock is released', async (t) => {
  const root = await rootFor(t);
  const held = native.acquireLock(root, true);
  const child = await childFor(t, root);
  try {
    const denied = await child.request('acquire');
    assert.equal(denied.state, 'error');
    assert.match(denied.message!, busy);
    assert.deepEqual(await readdir(root), ['runtime']);
  } finally { held.close(); }
  const acquired = await child.request('acquire');
  assert.equal(acquired.state, 'held');
  assert.equal(acquired.epoch, 1);
  await assert.rejects(openStateStore(root), busy);
  assert.equal((await child.request('close')).state, 'released');
  const successor = await openStateStore(root);
  try {
    assert.equal(successor.ownerEpoch, 2);
    const identity = await successor.artifacts.readCanonical<PlatformProcessIdentityV1>(ownerAt(root).processIdentityRef);
    assert.equal(identity.pid, process.pid);
    assert.notEqual(identity.pid, acquired.pid);
    assert.equal(identity.processStartToken, native.processStartToken());
  } finally { await successor.close(); }
});

test('simultaneous fresh processes create one owner and leave a cleanly reacquirable generation', async (t) => {
  const root = await rootFor(t);
  const children = await Promise.all([childFor(t, root), childFor(t, root)]);
  const results = await Promise.all(children.map(child => child.request('acquire')));
  assert.equal(results.filter(result => result.state === 'held').length, 1, JSON.stringify(results));
  assert.equal(results.filter(result => result.state === 'error' && busy.test(result.message!)).length, 1, JSON.stringify(results));
  assert.equal(ownerAt(root).ownerEpoch, 1);
  await children[results.findIndex(result => result.state === 'held')]!.request('close');
  const successor = await openStateStore(root);
  try { assert.equal(successor.ownerEpoch, 2); } finally { await successor.close(); }
});

test('simultaneous native acquisitions exclude each other before any SQLite access', async (t) => {
  const root = await rootFor(t);
  const children = await Promise.all([childFor(t, root, 'native'), childFor(t, root, 'native')]);
  const results = await Promise.all(children.map(child => child.request('acquire')));
  assert.equal(results.filter(result => result.state === 'held').length, 1, JSON.stringify(results));
  assert.equal(results.filter(result => result.state === 'error' && busy.test(result.message!)).length, 1, JSON.stringify(results));
  assert.deepEqual(await readdir(root), ['runtime']);
  await children[results.findIndex(result => result.state === 'held')]!.request('close');
});

test('native death inspection requires a held lock and positive PID/start-token absence or mismatch', async (t) => {
  const root = await rootFor(t);
  const child = await childFor(t, root);
  const acquired = await child.request('acquire');
  assert.equal(acquired.state, 'held');
  assert.equal((await child.request('drop-lock')).state, 'released');
  const held = native.acquireLock(root, false);
  try {
    assert.throws(() => held.assertPriorProcessDead(acquired.pid!, acquired.token!), /still present/);
    assert.throws(() => held.assertPriorProcessDead(process.pid, native.processStartToken()), /still present/);
    assert.notEqual(acquired.token, native.processStartToken());
    // Retaining another process's start token exercises the PID-reuse branch.
    held.assertPriorProcessDead(process.pid, acquired.token!);
    for (const pid of [0, -1, 1.5, NaN, Infinity, 2 ** 32 + process.pid]) {
      assert.throws(() => held.assertPriorProcessDead(pid, acquired.token!), /invalid prior/);
    }
    for (const token of ['', 'unknown-token', 'x'.repeat(128), `${acquired.token}\0ignored`]) {
      assert.throws(() => held.assertPriorProcessDead(acquired.pid!, token), /invalid prior/);
    }
    assert.throws(() => held.assertPriorProcessDead.call({} as never, acquired.pid!, acquired.token!), /invalid StateOwner lock handle/);
  } finally { held.close(); }
  child.child.kill('SIGKILL');
  const [, signal] = await child.exited;
  assert.equal(signal, 'SIGKILL');
  assert.throws(() => held.assertPriorProcessDead(acquired.pid!, acquired.token!), /changed or closed/);
  const successor = native.acquireLock(root, false);
  try { successor.assertPriorProcessDead(acquired.pid!, acquired.token!); } finally { successor.close(); }
});

test('failed graceful release keeps the OS lock until durable terminalization succeeds', async (t) => {
  const root = await rootFor(t);
  const store = await openStateStore(root);
  const publication = t.mock.method(store.artifacts, 'publishCanonical', async () => { throw new Error('injected CAS publication failure'); });
  try {
    await assert.rejects(store.close(), /injected CAS publication failure/);
    assert.equal(ownerAt(root).state, 'active');
    assert.throws(() => native.acquireLock(root, false), busy);
  } finally { publication.mock.restore(); await store.close(); }
  assert.equal(ownerAt(root).state, 'terminal');
  const successor = await openStateStore(root);
  try { assert.equal(successor.ownerEpoch, 2); } finally { await successor.close(); }
});

test('failed SQLite close retains the lock and retries without a second graceful transition', async (t) => {
  const root = await rootFor(t);
  const store = await openStateStore(root);
  const driver = (store as unknown as { driver: SqliteDriver }).driver;
  const closing = t.mock.method(driver, 'close', () => { throw new Error('injected SQLite close failure'); });
  try {
    await assert.rejects(store.close(), /injected SQLite close failure/);
    assert.equal(ownerAt(root).state, 'terminal');
    assert.throws(() => native.acquireLock(root, false), busy);
  } finally { closing.mock.restore(); await store.close(); }
  const successor = await openStateStore(root);
  try { assert.equal(successor.ownerEpoch, 2); } finally { await successor.close(); }
});
