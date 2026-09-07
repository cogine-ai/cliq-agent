import assert from 'node:assert/strict';
import { execFileSync, fork } from 'node:child_process';
import { once } from 'node:events';
import { chmod, link, lstat, mkdir, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import type { PlatformProcessIdentityV1 } from '../kernel/types.js';
import { loadNativeStateOwner } from './native-owner.js';
import { openSqliteDriver, type SqliteDriver } from './sqlite-driver.js';
import { readLatestStateOwner } from './state-owner.js';
import { openStateStore } from './store.js';
import { makePrivateDir } from './testing/fixtures.js';

const native = await loadNativeStateOwner();
const busy = /StateOwner OS lock is already held/;

async function rootFor(t: TestContext) {
  const root = await makePrivateDir('.cliq-native-owner-');
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

type ChildReply = { state: string; message?: string; epoch?: number; pid?: number; token?: string };
async function childFor(t: TestContext, root: string, mode: 'store' | 'native' = 'store') {
  const child = fork(new URL('./testing/state-owner-child.ts', import.meta.url), [root, mode], {
    execArgv: ['--import', 'tsx'], stdio: ['ignore', 'ignore', 'pipe', 'ipc']
  });
  let diagnostic = '';
  child.stderr!.on('data', (chunk: Buffer) => { diagnostic = (diagnostic + chunk.toString()).slice(-4096); });
  const exited = once(child, 'exit');
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await exited; });
  const reply = async () => {
    try {
      const [message] = await once(child, 'message', { signal: AbortSignal.timeout(30_000) });
      return message as ChildReply;
    } catch (error) { throw new Error(`StateOwner child did not reply: ${diagnostic}`, { cause: error }); }
  };
  assert.equal((await reply()).state, 'ready');
  return { child, exited, request(command: 'acquire' | 'close') {
    const pending = reply();
    child.send(command);
    return pending;
  } };
}

function ownerAt(root: string) {
  const driver = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
  try { return readLatestStateOwner(driver)!; } finally { driver.close(); }
}

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

test('SIGKILL releases the OS lock but does not authorize takeover of an active durable owner', async (t) => {
  const root = await rootFor(t);
  const child = await childFor(t, root);
  assert.equal((await child.request('acquire')).state, 'held');
  const prior = ownerAt(root);
  child.child.kill('SIGKILL');
  const [, signal] = await child.exited;
  assert.equal(signal, 'SIGKILL');
  native.acquireLock(root, false).close();
  await assert.rejects(openStateStore(root), /epoch 1 is still active/);
  assert.deepEqual(ownerAt(root), prior);
  native.acquireLock(root, false).close();
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
