import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { fstatSync, readSync } from 'node:fs';
import { chmod, lstat, mkdir, readFile, readlink, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { Socket } from 'node:net';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { Worker } from 'node:worker_threads';

import { loadNativeStateOwner, STATE_OWNER_NATIVE_PATH, type HeldControlPeer, type NativePeerObservation } from './native-owner.js';
import { makePrivateDir } from './testing/fixtures.js';

// Real host transport/process observations, not installed-platform qualification.
const native = await loadNativeStateOwner();
const timeoutMs = 30_000;

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

async function bounded<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer!: ReturnType<typeof setTimeout>;
  try {
    return await Promise.race([promise, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Timed out waiting for ${label}`)), timeoutMs);
    })]);
  } finally { clearTimeout(timer); }
}

type ChildReply = { kind: string; pid: number; uid: number; gid: number; imageDigest: string; message?: string };

async function clientFor(t: TestContext, socketPath: string, mode: 'client' | 'server' | 'owner' = 'client') {
  const script = `
    import net from 'node:net';
    import fs from 'node:fs';
    import crypto from 'node:crypto';
    import path from 'node:path';
    import { createRequire } from 'node:module';
    const socketPath = process.argv[1];
    const identity = { pid: process.pid, uid: process.geteuid(), gid: process.getegid(),
      imageDigest: crypto.createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex') };
    const report = (kind, extra = {}) => { if (process.connected) process.send({ kind, ...identity, ...extra }); };
    let socket;
    if (process.argv[2] === 'owner') {
      const native = createRequire(import.meta.url)(process.argv[3]);
      const held = native.acquireLock(path.dirname(path.dirname(socketPath)), true);
      const peers = [];
      socket = held.openControlListener(peer => { peers.push(peer); report('accepted'); },
        error => report('error', { message: error.message }));
      globalThis.handles = { held, socket, peers };
      report('ready');
    } else if (process.argv[2] === 'server') {
      socket = net.createServer(connection => { connection.on('error', () => {}); });
      socket.listen(socketPath, () => { fs.chmodSync(socketPath, 0o600); report('ready'); });
    } else {
      socket = net.createConnection(socketPath, () => report('ready'));
      socket.on('close', () => report('closed'));
      socket.on('data', bytes => report('received', { message: bytes.toString('utf8') }));
    }
    if (typeof socket.on === 'function') socket.on('error', error => report('error', { message: error.message }));
    process.on('message', command => {
      if (command === 'send') { socket.write('native-control-frame\\n'); report('sent'); }
      else if (command === 'close') socket.destroy();
      else if (command === 'transfer') process.send({ kind: 'transferred', ...identity }, socket, { keepOpen: true },
        error => { if (error) report('error', { message: error.message }); });
      else if (command === 'exit') process.exit(0);
    });
    process.on('disconnect', () => process.exit(0));
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', script, socketPath, mode, STATE_OWNER_NATIVE_PATH],
    { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  const exited = once(child, 'exit');
  let diagnostic = '';
  child.stderr!.on('data', (bytes: Buffer) => { diagnostic = (diagnostic + bytes.toString()).slice(-4096); });
  const messages = new Map<string, ChildReply[]>();
  const waiting = new Map<string, ReturnType<typeof deferred<ChildReply>>>();
  child.on('message', value => {
    const reply = value as ChildReply;
    const pending = waiting.get(reply.kind);
    if (pending) { waiting.delete(reply.kind); pending.resolve(reply); }
    else messages.set(reply.kind, [...messages.get(reply.kind) ?? [], reply]);
    if (reply.kind === 'error') {
      for (const pending of waiting.values()) pending.reject(new Error(`Control child failed: ${reply.message}`));
      waiting.clear();
    }
  });
  child.on('exit', (code, signal) => {
    for (const pending of waiting.values()) pending.reject(new Error(`Control child exited (${code ?? signal}): ${diagnostic}`));
    waiting.clear();
  });
  const wait = (kind: string) => {
    const queued = messages.get(kind)?.shift();
    if (queued) return Promise.resolve(queued);
    const pending = deferred<ChildReply>();
    waiting.set(kind, pending);
    return bounded(pending.promise, `child ${kind}`);
  };
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await bounded(exited, 'control child exit');
  });
  const ready = await wait('ready');
  return { child, exited, ready, wait };
}

async function fixture(t: TestContext) {
  const root = await makePrivateDir('.cliq-control-');
  const held = native.acquireLock(root, true);
  const peers: HeldControlPeer[] = [];
  const pending = deferred<HeldControlPeer>();
  // Native failure can arrive before the caller begins awaiting accept.
  void pending.promise.catch(() => {});
  const errors: unknown[] = [];
  const listener = held.openControlListener(peer => { peers.push(peer); pending.resolve(peer); }, error => {
    errors.push(error); pending.reject(error);
  });
  t.after(async () => {
    for (const peer of peers) peer.close();
    listener.close();
    held.close();
    await rm(root, { recursive: true, force: true });
  });
  return { root, held, listener, errors, socketPath: path.join(root, 'runtime/control-v1.sock'),
    peer: () => bounded(pending.promise, 'native accept') };
}

function hashCapturedImage(observation: NativePeerObservation) {
  const hash = createHash('sha256');
  const bytes = Buffer.alloc(64 * 1024);
  let position = 0;
  for (;;) {
    const count = readSync(observation.imageFd, bytes, 0, bytes.length, position);
    if (count === 0) break;
    position += count;
    hash.update(bytes.subarray(0, count));
  }
  assert.equal(position, observation.imageByteCount);
  return hash.digest('hex');
}

function socketFor(t: TestContext, peer: HeldControlPeer) {
  const fd = peer.takeSocketFd();
  const descriptor = fstatSync(fd, { bigint: true });
  const socket = new Socket({ fd, readable: true, writable: true });
  socket.on('error', () => {});
  t.after(() => socket.destroy());
  return { socket, descriptor };
}

test('native UDS accepts event-driven real child credentials and holds the exact peer image through hashing', async t => {
  const f = await fixture(t);
  const child = await clientFor(t, f.socketPath);
  const peer = await f.peer();
  const { socket, descriptor } = socketFor(t, peer);
  const observation = peer.capture();
  try {
    const entry = await lstat(f.socketPath, { bigint: true });
    assert.equal(entry.isSocket(), true);
    assert.equal(entry.mode & 0o7777n, 0o600n);
    assert.deepEqual(observation.listener, { deviceId: String(entry.dev), fileId: String(entry.ino), ownerUid: Number(entry.uid) });
    assert.deepEqual(observation.acceptedSocket,
      { deviceId: String(process.platform === 'darwin' ? BigInt.asUintN(32, descriptor.dev) : descriptor.dev),
        fileId: String(descriptor.ino), ownerUid: Number(descriptor.uid) });
    assert.equal(observation.pid, child.child.pid);
    assert.notEqual(observation.pid, process.pid);
    assert.equal(observation.uid, child.ready.uid);
    assert.equal(observation.uid, process.geteuid!());
    assert.equal(observation.gid, child.ready.gid);
    assert.notEqual(observation.processStartToken, native.processStartToken());
    assert.match(observation.processStartToken, process.platform === 'linux'
      ? /^linux-proc-start-ticks:[1-9]\d*$/u : /^darwin-proc-start-time:[1-9]\d*:\d{6}$/u);
    assert.equal(hashCapturedImage(observation), child.ready.imageDigest);
    peer.assertObservation(observation);
    f.listener.assertHeld();
    const received = once(socket, 'data');
    child.child.send('send');
    const [bytes] = await bounded(received, 'native fd stream bytes');
    assert.equal((bytes as Buffer).toString('utf8'), 'native-control-frame\n');
    peer.assertObservation(observation);
    assert.deepEqual(f.errors, []);
  } finally { observation.close(); }
});

test('native peer and observation handles reject receiver spoofing, copied observations and duplicate fd transfer', async t => {
  const f = await fixture(t);
  await clientFor(t, f.socketPath);
  const peer = await f.peer();
  const observation = peer.capture();
  try {
    assert.throws(() => peer.takeSocketFd.call({} as never));
    assert.throws(() => peer.capture.call({} as never));
    assert.throws(() => peer.close.call({} as never));
    assert.throws(() => f.listener.assertHeld.call({} as never));
    assert.throws(() => f.listener.close.call({} as never));
    assert.throws(() => f.held.openControlListener.call({} as never, () => {}, () => {}));
    assert.throws(() => peer.assertObservation({ ...observation }));
    assert.throws(() => peer.assertObservation.call({} as never, observation));
    assert.throws(() => observation.close.call({} as never));
    socketFor(t, peer);
    assert.throws(() => peer.takeSocketFd());
    peer.assertObservation(observation);
  } finally { observation.close(); }
  assert.throws(() => peer.assertObservation(observation));
});

for (const locator of ['socket', 'runtime', 'root'] as const) {
  test(`native control observation rejects ${locator} permission drift without repairing it`, async t => {
    const f = await fixture(t);
    await clientFor(t, f.socketPath);
    const peer = await f.peer();
    const observation = peer.capture();
    const target = locator === 'socket' ? f.socketPath : locator === 'runtime' ? path.dirname(f.socketPath) : f.root;
    const originalMode = locator === 'socket' ? 0o600 : 0o700;
    try {
      await chmod(target, locator === 'socket' ? 0o644 : 0o755);
      assert.throws(() => f.listener.assertHeld());
      assert.throws(() => peer.capture());
      assert.throws(() => peer.assertObservation(observation));
      assert.equal((await lstat(target)).mode & 0o7777, locator === 'socket' ? 0o644 : 0o755);
    } finally { await chmod(target, originalMode); observation.close(); }
  });
}

for (const replacement of ['file', 'symlink'] as const) {
  test(`native listener close rejects a replaced socket and preserves the replacement ${replacement}`, async t => {
    const f = await fixture(t);
    await clientFor(t, f.socketPath);
    const peer = await f.peer();
    const observation = peer.capture();
    const displaced = path.join(f.root, 'runtime/displaced.sock');
    const marker = path.join(f.root, 'replacement-marker');
    await writeFile(marker, 'replacement bytes', { mode: 0o600 });
    await rename(f.socketPath, displaced);
    if (replacement === 'file') await writeFile(f.socketPath, 'replacement bytes', { mode: 0o600 });
    else await symlink(marker, f.socketPath);
    try {
      assert.throws(() => f.listener.assertHeld());
      assert.throws(() => peer.capture());
      assert.throws(() => peer.assertObservation(observation));
      f.listener.close();
      f.held.close();
      if (replacement === 'file') assert.equal(await readFile(f.socketPath, 'utf8'), 'replacement bytes');
      else assert.equal(await readlink(f.socketPath), marker);
      assert.equal((await lstat(displaced)).isSocket(), true);
      assert.equal(await readFile(marker, 'utf8'), 'replacement bytes');
    } finally { observation.close(); }
  });
}

for (const locator of ['root', 'runtime'] as const) {
  test(`native listener refuses ${locator} directory replacement and does not delete a replacement socket locator`, async t => {
    const f = await fixture(t);
    await clientFor(t, f.socketPath);
    const peer = await f.peer();
    const observation = peer.capture();
    const target = locator === 'root' ? f.root : path.dirname(f.socketPath);
    const displaced = `${target}.displaced`;
    await rename(target, displaced);
    try {
      await mkdir(target, { mode: 0o700 });
      if (locator === 'root') await mkdir(path.dirname(f.socketPath), { mode: 0o700 });
      await writeFile(f.socketPath, 'replacement locator', { mode: 0o600 });
      assert.throws(() => f.listener.assertHeld());
      assert.throws(() => peer.capture());
      assert.throws(() => peer.assertObservation(observation));
      f.listener.close();
      f.held.close();
      assert.equal(await readFile(f.socketPath, 'utf8'), 'replacement locator');
    } finally {
      observation.close();
      await rm(target, { recursive: true, force: true });
      await rename(displaced, target);
    }
  });
}

test('peer process death invalidates a retained observation instead of reusing its PID or image', async t => {
  const f = await fixture(t);
  const child = await clientFor(t, f.socketPath);
  const peer = await f.peer();
  const observation = peer.capture();
  try {
    child.child.kill('SIGKILL');
    const [, signal] = await bounded(child.exited, 'peer process death');
    assert.equal(signal, 'SIGKILL');
    assert.throws(() => peer.capture());
    assert.throws(() => peer.assertObservation(observation));
    f.listener.assertHeld();
  } finally { observation.close(); }
});

test('delayed first capture rejects a dead original client even while its IPC-transferred socket still sends frames', async t => {
  const f = await fixture(t);
  const child = await clientFor(t, f.socketPath);
  const peer = await f.peer();
  const { socket: accepted } = socketFor(t, peer);
  // Do not capture the peer before death: the baseline must come from accept.
  const transferred = once(child.child, 'message');
  child.child.send('transfer');
  const [message, handle] = await bounded(transferred, 'actual client socket IPC transfer');
  assert.equal((message as ChildReply).kind, 'transferred');
  assert.ok(handle instanceof Socket);
  handle.on('error', () => {});
  t.after(() => handle.destroy());
  child.child.send('exit');
  const [code, signal] = await bounded(child.exited, 'original client exit after socket handoff');
  assert.equal(code, 0);
  assert.equal(signal, null);
  const received = once(accepted, 'data');
  handle.write('retained-client-fd-frame\n');
  const [bytes] = await bounded(received, 'live stream after original client exit');
  assert.equal((bytes as Buffer).toString('utf8'), 'retained-client-fd-frame\n');
  assert.equal(handle.destroyed, false);
  assert.equal(accepted.destroyed, false);
  assert.throws(() => peer.capture());
  f.listener.assertHeld();
  assert.deepEqual(f.errors, []);
});

for (const close of ['peer', 'listener', 'owner'] as const) {
  test(`closing the ${close} invalidates accepted capabilities and ends the duplicated stream`, async t => {
    const f = await fixture(t);
    await clientFor(t, f.socketPath);
    const peer = await f.peer();
    const observation = peer.capture();
    const { socket } = socketFor(t, peer);
    socket.resume();
    const closed = new Promise<void>(resolve => socket.once('close', resolve));
    try {
      if (close === 'peer') peer.close();
      else if (close === 'listener') f.listener.close();
      else f.held.close();
      await bounded(closed, 'duplicate stream close');
      assert.throws(() => peer.capture());
      assert.throws(() => peer.takeSocketFd());
      assert.throws(() => peer.assertObservation(observation));
      if (close !== 'peer') {
        assert.throws(() => f.listener.assertHeld());
        await assert.rejects(lstat(f.socketPath), { code: 'ENOENT' });
      }
      if (close === 'listener') f.held.assertHeld();
    } finally { observation.close(); }
  });
}

test('native listener refuses an existing live stream socket and preserves its filesystem identity', async t => {
  const root = await makePrivateDir('.cliq-control-live-');
  const held = native.acquireLock(root, true);
  t.after(async () => { held.close(); await rm(root, { recursive: true, force: true }); });
  const socketPath = path.join(root, 'runtime/control-v1.sock');
  await clientFor(t, socketPath, 'server');
  const before = await lstat(socketPath, { bigint: true });
  assert.throws(() => held.openControlListener(() => {}, () => {}));
  const after = await lstat(socketPath, { bigint: true });
  assert.equal(after.dev, before.dev);
  assert.equal(after.ino, before.ino);
  assert.equal(after.mode & 0o7777n, 0o600n);
});

test('a new StateOwner recovers a real SIGKILL predecessor socket and accepts at the same fixed locator', async t => {
  const root = await makePrivateDir('.cliq-control-stale-');
  t.after(() => rm(root, { recursive: true, force: true }));
  const socketPath = path.join(root, 'runtime/control-v1.sock');
  const predecessor = await clientFor(t, socketPath, 'owner');
  const before = await lstat(socketPath, { bigint: true });
  assert.equal(before.isSocket(), true);
  assert.equal(before.mode & 0o7777n, 0o600n);
  assert.throws(() => native.acquireLock(root, false));
  predecessor.child.kill('SIGKILL');
  const [, signal] = await bounded(predecessor.exited, 'predecessor StateOwner death');
  assert.equal(signal, 'SIGKILL');
  const stale = await lstat(socketPath, { bigint: true });
  assert.equal(stale.dev, before.dev);
  assert.equal(stale.ino, before.ino);
  const held = native.acquireLock(root, false);
  const accepted = deferred<HeldControlPeer>();
  void accepted.promise.catch(() => {});
  const errors: Error[] = [];
  const listener = held.openControlListener(peer => accepted.resolve(peer), error => {
    errors.push(error); accepted.reject(error);
  });
  let peer: HeldControlPeer | undefined;
  try {
    listener.assertHeld();
    const child = await clientFor(t, socketPath);
    peer = await bounded(accepted.promise, 'replacement StateOwner accept');
    const observation = peer.capture();
    try {
      const replacement = await lstat(socketPath, { bigint: true });
      assert.equal(replacement.isSocket(), true);
      assert.equal(replacement.mode & 0o7777n, 0o600n);
      assert.deepEqual(observation.listener,
        { deviceId: String(replacement.dev), fileId: String(replacement.ino), ownerUid: Number(replacement.uid) });
      assert.equal(observation.pid, child.child.pid);
      assert.equal(hashCapturedImage(observation), child.ready.imageDigest);
      peer.assertObservation(observation);
      const { socket } = socketFor(t, peer);
      const received = once(socket, 'data');
      child.child.send('send');
      const [bytes] = await bounded(received, 'recovered locator frame');
      assert.equal((bytes as Buffer).toString('utf8'), 'native-control-frame\n');
      assert.deepEqual(errors, []);
    } finally { observation.close(); }
  } finally { peer?.close(); listener.close(); held.close(); }
});

test('terminating a real worker environment closes its native listener, observations and duplicated sockets', async t => {
  const root = await makePrivateDir('.cliq-control-env-');
  const socketPath = path.join(root, 'runtime/control-v1.sock');
  const worker = new Worker(`
    const { parentPort, workerData } = require('node:worker_threads');
    const { Socket } = require('node:net');
    const native = require(workerData.helperPath);
    const held = native.acquireLock(workerData.root, true);
    const accepted = [];
    const listener = held.openControlListener(peer => {
      const observation = peer.capture();
      const socket = new Socket({ fd: peer.takeSocketFd(), readable: true, writable: true });
      socket.on('error', () => {});
      socket.resume();
      accepted.push({ peer, observation, socket });
      parentPort.postMessage({ kind: 'accepted', pid: observation.pid });
    }, error => parentPort.postMessage({ kind: 'error', message: error.message }));
    // Deliberately retain all native handles until environment teardown.
    globalThis.handles = { held, listener, accepted };
    parentPort.postMessage({ kind: 'ready' });
  `, { eval: true, workerData: { root, helperPath: STATE_OWNER_NATIVE_PATH } });
  let terminated = false;
  t.after(async () => {
    if (!terminated) await bounded(worker.terminate(), 'worker cleanup termination');
    await rm(root, { recursive: true, force: true });
  });
  const [ready] = await bounded(once(worker, 'message'), 'worker listener ready');
  assert.deepEqual(ready, { kind: 'ready' });
  const accepted = once(worker, 'message');
  const child = await clientFor(t, socketPath);
  const [peer] = await bounded(accepted, 'worker native accept');
  assert.deepEqual(peer, { kind: 'accepted', pid: child.child.pid });
  await bounded(worker.terminate(), 'worker environment termination');
  terminated = true;
  await child.wait('closed');
  await assert.rejects(lstat(socketPath), { code: 'ENOENT' });
  const reclaimed = native.acquireLock(root, false);
  const errors: Error[] = [];
  try {
    reclaimed.assertHeld();
    const listener = reclaimed.openControlListener(() => {}, error => { errors.push(error); });
    listener.assertHeld();
    listener.close();
    assert.deepEqual(errors, []);
  } finally { reclaimed.close(); }
});

test('explicit listener close remains safe when worker execution blocks before the uv close callback and terminates', async t => {
  const root = await makePrivateDir('.cliq-control-close-');
  const socketPath = path.join(root, 'runtime/control-v1.sock');
  const gate = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
  const worker = new Worker(`
    const { parentPort, workerData } = require('node:worker_threads');
    const native = require(workerData.helperPath);
    const held = native.acquireLock(workerData.root, true);
    const listener = held.openControlListener(() => {},
      error => parentPort.postMessage({ kind: 'error', message: error.message }));
    globalThis.handles = { held, listener };
    listener.assertHeld();
    listener.close();
    parentPort.postMessage({ kind: 'closed' });
    // No event-loop turn can run uv_close before forced environment teardown.
    Atomics.wait(new Int32Array(workerData.gate), 0, 0);
  `, { eval: true, workerData: { root, helperPath: STATE_OWNER_NATIVE_PATH, gate } });
  let terminated = false;
  t.after(async () => {
    if (!terminated) await bounded(worker.terminate(), 'blocked worker cleanup termination');
    await rm(root, { recursive: true, force: true });
  });
  const [closed] = await bounded(once(worker, 'message'), 'worker explicit listener close');
  assert.deepEqual(closed, { kind: 'closed' });
  await assert.rejects(lstat(socketPath), { code: 'ENOENT' });
  await bounded(worker.terminate(), 'blocked worker termination');
  terminated = true;
  const held = native.acquireLock(root, false);
  const errors: Error[] = [];
  try {
    const listener = held.openControlListener(() => {}, error => { errors.push(error); });
    listener.assertHeld();
    listener.close();
    held.assertHeld();
    assert.deepEqual(errors, []);
  } finally { held.close(); }
});

test('concurrent native worker binds preserve the process umask in an isolated child', async t => {
  const root = await makePrivateDir('.c-mask-');
  const runnerMask = process.umask();
  const workerCode = `
    const { parentPort, workerData } = require('node:worker_threads');
    const { tsImport } = require('tsx/esm/api');
    (async () => {
      const { loadNativeStateOwner } = await tsImport(workerData.nativeOwnerUrl, workerData.nativeOwnerUrl);
      const native = await loadNativeStateOwner();
      const held = native.acquireLock(workerData.root, true);
      try {
        parentPort.postMessage({ kind: 'ready' });
        Atomics.wait(new Int32Array(workerData.gate), 0, 0);
        const errors = [];
        const listener = held.openControlListener(() => {}, error => errors.push(error));
        listener.assertHeld();
        listener.close();
        held.assertHeld();
        if (errors.length) throw errors[0];
        parentPort.postMessage({ kind: 'bound' });
      } finally { held.close(); }
    })().catch(error => { throw error; });
  `;
  const script = `
    import assert from 'node:assert/strict';
    import { once } from 'node:events';
    import { mkdir } from 'node:fs/promises';
    import path from 'node:path';
    import { Worker } from 'node:worker_threads';
    const originalMask = process.umask(0o022);
    const workerCode = ${JSON.stringify(workerCode)};
    const workers = [], exits = [], ready = [];
    const gate = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
    try {
      for (let index = 0; index < 32; index++) {
        const root = path.join(process.argv[1], String(index));
        await mkdir(root, { mode: 0o700 });
        const worker = new Worker(workerCode, { eval: true, execArgv: [],
          workerData: { root, gate, nativeOwnerUrl: process.argv[2] } });
        // Capture exit before any readiness/outcome wait: an exit can race its message.
        const exit = once(worker, 'exit');
        const started = once(worker, 'message');
        void exit.catch(() => {});
        void started.catch(() => {});
        workers.push(worker); exits.push(exit); ready.push(started);
      }
      for (const [message] of await Promise.all(ready)) assert.deepEqual(message, { kind: 'ready' });
      const bound = workers.map(worker => once(worker, 'message'));
      Atomics.store(new Int32Array(gate), 0, 1);
      Atomics.notify(new Int32Array(gate), 0, workers.length);
      for (const [message] of await Promise.all(bound)) assert.deepEqual(message, { kind: 'bound' });
      for (const [code] of await Promise.all(exits)) assert.equal(code, 0);
      const afterMask = process.umask();
      assert.equal(afterMask, 0o022, 'concurrent native binds changed the process-wide umask');
      await new Promise((resolve, reject) => process.send(
        { workers: workers.length, beforeMask: 0o022, afterMask }, error => error ? reject(error) : resolve()));
    } finally {
      await Promise.all(workers.map(worker => worker.terminate()));
      process.umask(originalMask);
      if (process.connected) process.disconnect();
    }
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', script, root,
    new URL('./native-owner.ts', import.meta.url).href], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  const exited = once(child, 'exit');
  const reported = once(child, 'message');
  void exited.catch(() => {});
  void reported.catch(() => {});
  let diagnostic = '';
  child.stderr!.on('data', (bytes: Buffer) => { diagnostic = (diagnostic + bytes.toString()).slice(-4096); });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await bounded(exited, 'concurrent-bind child cleanup');
    await rm(root, { recursive: true, force: true });
  });
  const [code, signal] = await bounded(exited, 'concurrent-bind child completion');
  assert.equal(signal, null, diagnostic);
  assert.equal(code, 0, diagnostic);
  const [report] = await bounded(reported, 'concurrent-bind umask result');
  assert.deepEqual(report, { workers: 32, beforeMask: 0o022, afterMask: 0o022 });
  assert.equal(process.umask(), runnerMask);
});

test('a strict host umask refuses a native listener without relaxing permissions or poisoning a later bind', async t => {
  const root = await makePrivateDir('.c-tight-');
  const runnerMask = process.umask();
  const script = `
    import assert from 'node:assert/strict';
    import { lstat } from 'node:fs/promises';
    import path from 'node:path';
    import { tsImport } from 'tsx/esm/api';
    const originalMask = process.umask(0o022);
    let held, listener;
    try {
      const { loadNativeStateOwner } = await tsImport(process.argv[2], process.argv[2]);
      const native = await loadNativeStateOwner();
      const prepared = native.acquireLock(process.argv[1], true);
      prepared.assertHeld();
      prepared.close();
      const socketPath = path.join(process.argv[1], 'runtime/control-v1.sock');
      assert.equal(process.umask(0o777), 0o022);
      held = native.acquireLock(process.argv[1], false);
      held.assertHeld();
      assert.throws(() => held.openControlListener(() => {}, () => {}),
        /host umask that permits owner read and write/);
      const rejectedMask = process.umask();
      assert.equal(rejectedMask, 0o777);
      await assert.rejects(lstat(socketPath), { code: 'ENOENT' });
      held.assertHeld();
      assert.equal(process.umask(0o022), 0o777);
      const errors = [];
      listener = held.openControlListener(() => {}, error => errors.push(error));
      listener.assertHeld();
      const entry = await lstat(socketPath);
      assert.equal(entry.isSocket(), true);
      assert.equal(entry.mode & 0o7777, 0o600);
      listener.close();
      held.assertHeld();
      assert.deepEqual(errors, []);
      await assert.rejects(lstat(socketPath), { code: 'ENOENT' });
      await new Promise((resolve, reject) => process.send(
        { rejectedMask, restoredMask: process.umask() }, error => error ? reject(error) : resolve()));
    } finally {
      process.umask(0o022);
      listener?.close(); held?.close();
      process.umask(originalMask);
      if (process.connected) process.disconnect();
    }
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', script, root,
    new URL('./native-owner.ts', import.meta.url).href], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  const exited = once(child, 'exit');
  const reported = once(child, 'message');
  void exited.catch(() => {});
  void reported.catch(() => {});
  let diagnostic = '';
  child.stderr!.on('data', (bytes: Buffer) => { diagnostic = (diagnostic + bytes.toString()).slice(-4096); });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await bounded(exited, 'strict-mask child cleanup');
    await rm(root, { recursive: true, force: true });
  });
  const [code, signal] = await bounded(exited, 'strict-mask child completion');
  assert.equal(signal, null, diagnostic);
  assert.equal(code, 0, diagnostic);
  const [report] = await bounded(reported, 'strict-mask child result');
  assert.deepEqual(report, { rejectedMask: 0o777, restoredMask: 0o022 });
  assert.equal(process.umask(), runnerMask);
});
