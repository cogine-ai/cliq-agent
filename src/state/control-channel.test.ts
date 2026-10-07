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
  let resolve!: (peer: HeldControlPeer) => void;
  let incoming = new Promise<HeldControlPeer>(yes => { resolve = yes; });
  const native = held.openControlListener(peer => resolve(peer), () => {});
  let accept!: (peer: HeldControlPeer) => void;
  let nativeError!: (error: Error) => void;
  let listenerCloses = 0;
  const errors: Error[] = [];
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
    onConnection, error => { errors.push(error); throw new Error('error reporter failed'); });
  t.after(async () => { await listener.close(); held.close(); await rm(root, { recursive: true, force: true }); });
  return { owner, artifacts, accept: (peer: HeldControlPeer) => accept(peer), nativeError: (error: Error) => nativeError(error), errors,
    get listenerCloses() { return listenerCloses; },
    async peer() {
      const peer = incoming;
      const child = spawn(process.execPath, ['--input-type=module', '-e',
        `import net from 'node:net'; const socket = net.createConnection(process.argv[1]);
         socket.on('error', () => {}); process.on('disconnect', () => process.exit(0));`,
        path.join(root, 'runtime/control-v1.sock')], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
      const exited = once(child, 'exit');
      t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await bounded(exited); });
      const accepted = await bounded(peer);
      incoming = new Promise<HeldControlPeer>(yes => { resolve = yes; });
      return accepted;
    }
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
