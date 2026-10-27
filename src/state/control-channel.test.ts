import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fstatSync, openSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { openLocalControlListener, type LocalControlConnection } from './control-channel.js';
import { loadNativeStateOwner, type HeldControlPeer } from './native-owner.js';
import type { StateOwnerContext } from './state-owner.js';
import { makePrivateDir } from './testing/fixtures.js';

async function bounded<T>(promise: Promise<T>): Promise<T> {
  let timer!: ReturnType<typeof setTimeout>;
  try { return await Promise.race([promise, new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('control callback test timed out')), 10_000);
  })]); } finally { clearTimeout(timer); }
}

// Exercise the registered native callback directly so its old escaping error
// can be asserted without deliberately terminating the test process. Socket
// descriptors still come from the real native listener; this pre-authentication
// fault fixture never dispatches or claims to establish durable authority.
async function callbacks(t: TestContext, onConnection: (connection: LocalControlConnection) => void) {
  const root = await makePrivateDir('.cliq-control-callback-');
  const held = (await loadNativeStateOwner()).acquireLock(root, true);
  const incoming: HeldControlPeer[] = [], waiting: Array<(peer: HeldControlPeer) => void> = [];
  const nextPeer = () => incoming.length ? Promise.resolve(incoming.shift()!)
    : new Promise<HeldControlPeer>(resolve => { waiting.push(resolve); });
  const native = held.openControlListener(peer => {
    const receiver = waiting.shift(); if (receiver) receiver(peer); else incoming.push(peer);
  }, () => {});
  let accept!: (peer: HeldControlPeer) => void;
  let nativeError!: (error: Error) => void;
  let listenerCloses = 0;
  const errors: Error[] = [];
  let errorReported!: (error: Error) => void;
  const reported = new Promise<Error>(resolve => { errorReported = resolve; });
  const ref = '0'.repeat(64);
  const owner: StateOwnerContext = {
    ownerEpoch: 1, supervisorInstanceId: 'callback-fault-fixture', rowDigest: ref,
    processIdentityRef: ref, processIdentityDigest: ref, stateLockIdentityRef: ref, stateLockIdentityDigest: ref,
    stateRootIdentityRef: ref, stateRootIdentityDigest: ref,
    filesystem: { ...held, openControlListener(onAccept, onError) {
      accept = onAccept; nativeError = onError;
      return { assertHeld: () => native.assertHeld(), close() { listenerCloses++; native.close(); } };
    } }
  };
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root));
  const listener = openLocalControlListener(artifacts, owner,
    onConnection, error => { errors.push(error); errorReported(error); throw new Error('error reporter failed'); });
  t.after(async () => { await listener.close(); held.close(); await rm(root, { recursive: true, force: true }); });
  const peers = async (count: number) => {
    assert(Number.isSafeInteger(count) && count > 0 && count <= 64);
    const accepted = Array.from({ length: count }, nextPeer);
    const child = spawn(process.execPath, ['--input-type=module', '-e',
      `import net from 'node:net';
       const sockets=Array.from({length:Number(process.argv[2])},()=>net.createConnection(process.argv[1]));
       for(const socket of sockets)socket.on('error',()=>{});
       process.on('disconnect',()=>process.exit(0));`,
      path.join(root, 'runtime/control-v1.sock'), String(count)], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
    const exited = once(child, 'exit');
    t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await bounded(exited); });
    return bounded(Promise.all(accepted));
  };
  return { owner, artifacts, reported, accept: (peer: HeldControlPeer) => accept(peer), nativeError: (error: Error) => nativeError(error), errors,
    get listenerCloses() { return listenerCloses; },
    peers, async peer() { return (await peers(1))[0]!; }
  };
}

test('invalid connection callbacks are rejected before creating a native listener', async t => {
  // Argument validation must not consult authority or touch the native boundary.
  const f = await callbacks(t, () => {});
  const owner = { ...f.owner, filesystem: { ...f.owner.filesystem,
    openControlListener() { assert.fail('unexpected native listener creation'); } } };
  for (const [onConnection, onError] of [[undefined, () => {}], [() => {}, undefined]]) {
    assert.throws(() => openLocalControlListener(f.artifacts, owner, onConnection as never, onError as never), TypeError);
  }
});

test('failed socket transfer closes only its peer and contains even an error-reporter exception', async t => {
  const f = await callbacks(t, () => assert.fail('failed peer must not be delivered'));
  const error = new Error('socket transfer failed');
  let closed = false;
  const peer: HeldControlPeer = { takeSocketFd() { throw error; }, close() { closed = true; },
    capture() { throw new Error('unexpected capture'); }, assertObservation() { assert.fail('unexpected observation'); } };
  assert.doesNotThrow(() => f.accept(peer));
  assert.equal(closed, true);
  assert.deepEqual(f.errors, [error]);
  assert.equal(f.listenerCloses, 0);
  const listenerFailure = new Error('listener failure');
  assert.doesNotThrow(() => f.nativeError(listenerFailure));
  assert.deepEqual(f.errors, [error, listenerFailure]);
});

test('failed Socket construction closes the transferred descriptor and contains the callback error', async t => {
  const f = await callbacks(t, () => assert.fail('invalid socket must not be delivered'));
  const fd = openSync('/dev/null', 'r');
  let closed = false;
  const peer: HeldControlPeer = { takeSocketFd: () => fd, close() { closed = true; },
    capture() { throw new Error('unexpected capture'); }, assertObservation() { assert.fail('unexpected observation'); } };
  assert.doesNotThrow(() => f.accept(peer));
  assert.equal(closed, true);
  assert.throws(() => fstatSync(fd), { code: 'EBADF' });
  assert.equal(f.errors.length, 1);
  assert.equal(f.listenerCloses, 0);
});

test('a failed connection consumer cannot escape the native callback or prevent a later real connection', async t => {
  const error = new Error('connection consumer failed');
  let failed!: LocalControlConnection;
  let delivered!: LocalControlConnection;
  const f = await callbacks(t, connection => {
    if (!failed) { failed = connection; throw error; }
    delivered = connection;
  });
  const first = await f.peer();
  assert.doesNotThrow(() => f.accept(first));
  assert.equal(failed.socket.destroyed, true);
  assert.throws(() => first.takeSocketFd());
  assert.deepEqual(f.errors, [error]);
  assert.equal(f.listenerCloses, 0);
  const second = await f.peer();
  assert.doesNotThrow(() => f.accept(second));
  assert.equal(delivered.socket.destroyed, false);
  delivered.close();
});

test('an accepted-peer preparation failure closes only that connection and contains a throwing reporter', async t => {
  const failure = new Error('original peer capture refused');
  const delivered: LocalControlConnection[] = [];
  const f = await callbacks(t, connection => {
    delivered.push(connection);
    if (delivered.length > 1) connection.close();
  });
  const original = await f.peer();
  const peer: HeldControlPeer = { takeSocketFd: () => original.takeSocketFd(), close: () => original.close(),
    capture() { throw failure; }, assertObservation: observation => original.assertObservation(observation) };
  assert.doesNotThrow(() => f.accept(peer));
  assert.equal(await bounded(f.reported), failure);
  assert.equal(delivered[0]!.socket.destroyed, true);
  assert.deepEqual(f.errors, [failure]); assert.equal(f.listenerCloses, 0);
  const next = await f.peer(); assert.doesNotThrow(() => f.accept(next));
  assert.equal(delivered.length, 2);
});

test('one accepted preparation preserves the separate 64-dispatch refusal bound without entering a frame', async t => {
  let connection!: LocalControlConnection;
  const f = await callbacks(t, value => { connection = value; });
  const publish = f.artifacts.publishCanonicalFour;
  let entered!: () => void, release!: () => void;
  const started = new Promise<void>(resolve => { entered = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  t.mock.method(f.artifacts, 'publishCanonicalFour', async function (values: Parameters<typeof publish>[0]) {
    entered(); await gate; return Reflect.apply(publish, f.artifacts, [values]);
  });
  const pending: Array<Promise<unknown>> = [];
  try {
    f.accept(await f.peer()); await bounded(started);
    // Negative capacity only. Every accepted dispatch waits on the original
    // preparation; closing below prevents all frame/operation activation.
    for (let index = 0; index < 64; index++) pending.push(connection.dispatch(async () => assert.fail('closed preparation must not activate a frame')));
    const joined = Promise.allSettled(pending);
    await assert.rejects(connection.dispatch(async () => assert.fail('overflow must not dispatch')), { code: 'INVALID_REQUEST' });
    connection.close(); release();
    const outcomes = await bounded(joined);
    assert.equal(outcomes.length, 64); assert(outcomes.every(value => value.status === 'rejected'));
  } finally { connection?.close(); release(); await Promise.allSettled(pending); }
});

test('closed accepted peers retain their 64 preparation slots until the original producers join', async t => {
  const delivered: LocalControlConnection[] = [];
  const f = await callbacks(t, connection => { delivered.push(connection); });
  const peers = await f.peers(64);
  // One synchronous turn: each real native descriptor is transferred and
  // closed, while its registered producer has not run or left the join set.
  for (const peer of peers) { f.accept(peer); delivered.at(-1)!.close(); }
  assert.equal(delivered.length, 64);
  let transfers = 0, closed = false;
  const overflow: HeldControlPeer = { takeSocketFd() { transfers++; throw new Error('overflow reached socket transfer'); },
    close() { closed = true; }, capture() { assert.fail('overflow must not capture a peer'); },
    assertObservation() { assert.fail('overflow must not observe a peer'); } };
  assert.doesNotThrow(() => f.accept(overflow));
  assert.equal(closed, true); assert.equal(transfers, 0); assert.deepEqual(f.errors, []);
  await new Promise<void>(resolve => setImmediate(resolve));
  f.accept(await f.peer()); assert.equal(delivered.length, 65);
  delivered.at(-1)!.close(); assert.deepEqual(f.errors, []);
});
