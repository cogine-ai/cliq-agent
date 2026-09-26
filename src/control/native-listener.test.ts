import assert from 'node:assert/strict';
import { createConnection } from 'node:net';
import { chmod, lstat, mkdir, mkdtemp, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { once } from 'node:events';
import path from 'node:path';
import { test } from 'node:test';
import { setTimeout } from 'node:timers/promises';

import { NativeControlListener, type NativeControlConnection, type NativeControlRoot } from './native-listener.js';

async function privateRoot(): Promise<string> {
  const root = await mkdtemp(path.join(await realpath('/tmp'), '.cliq-control-native-'));
  await chmod(root, 0o700);
  await mkdir(path.join(root, 'runtime'), { mode: 0o700 });
  return root;
}

function endpoint(root: string): string {
  return path.join(root, 'runtime', 'control-v1.sock');
}

async function expected(root: string): Promise<NativeControlRoot> {
  const [state, runtime] = await Promise.all([
    lstat(root, { bigint: true }), lstat(path.join(root, 'runtime'), { bigint: true })
  ]);
  return {
    root: { deviceId: state.dev.toString(10), fileId: state.ino.toString(10) },
    runtime: { deviceId: runtime.dev.toString(10), fileId: runtime.ino.toString(10) }
  };
}

async function connectAndWrite(root: string, request: string): Promise<string> {
  const socket = createConnection(endpoint(root));
  await once(socket, 'connect');
  socket.write(`${request}\n`);
  const [bytes] = await once(socket, 'data') as [Buffer];
  socket.destroy();
  return bytes.toString('utf8');
}

test('native UDS listener derives same-user peer and keeps endpoint distinct from socket descriptors', async () => {
  const root = await privateRoot();
  const connections: NativeControlConnection[] = [];
  const received: string[] = [];
  let listener: NativeControlListener | undefined;
  try {
    listener = await NativeControlListener.start(root, await expected(root), {
      onOpen(connection) { connections.push(connection); },
      onFrame(_connection, frame) {
        received.push(frame.toString('utf8'));
        return Buffer.from('{"ok":true}');
      },
      onClosed() {}
    });
    const info = await lstat(endpoint(root), { bigint: true });
    assert.equal(info.isSocket(), true);
    assert.equal(info.mode & 0o7777n, 0o600n);
    assert.equal(info.uid, BigInt(process.geteuid!()));
    assert.equal(await connectAndWrite(root, '{"method":"control.hello"}'), '{"ok":true}\n');
    assert.deepEqual(received, ['{"method":"control.hello"}']);
    assert.equal(connections.length, 1);
    const peer = connections[0]!.peer;
    assert.equal(peer.peerUid, process.geteuid!());
    assert.equal(peer.endpoint.mode, 384);
    assert.equal(peer.endpoint.fileId, info.ino.toString(10));
    assert.equal(peer.endpoint.deviceId, info.dev.toString(10));
    if (process.platform === 'darwin') {
      assert.notEqual(peer.endpoint.deviceId, peer.listenerSocket.deviceId);
      assert.notEqual(peer.endpoint.fileId, peer.listenerSocket.fileId);
    }
    assert.equal(peer.credentialApi, process.platform === 'darwin' ? 'macos_getpeereid' : 'linux_so_peercred');
  } finally {
    await listener?.close();
    await assert.rejects(lstat(endpoint(root)), { code: 'ENOENT' });
    await rm(root, { recursive: true, force: true });
  }
});

test('native listener refuses an existing endpoint and never removes it', async () => {
  const root = await privateRoot();
  try {
    await writeFile(endpoint(root), 'sentinel', { mode: 0o600 });
    await assert.rejects(NativeControlListener.start(root, await expected(root), {
      onOpen() {}, onFrame() { return Buffer.from('{}'); }, onClosed() {}
    }));
    assert.equal((await lstat(endpoint(root))).isFile(), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('native listener refuses a root identity that differs from the held owner descriptor', async () => {
  const root = await privateRoot();
  try {
    const identity = await expected(root);
    await assert.rejects(NativeControlListener.start(root, {
      ...identity, root: { ...identity.root, fileId: (BigInt(identity.root.fileId) + 1n).toString(10) }
    }, { onOpen() {}, onFrame() { return Buffer.from('{}'); }, onClosed() {} }));
    await assert.rejects(lstat(endpoint(root)), { code: 'ENOENT' });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('endpoint replacement revokes future frames and shutdown does not unlink the replacement', async () => {
  const root = await privateRoot();
  const received: string[] = [];
  let listener: NativeControlListener | undefined;
  try {
    listener = await NativeControlListener.start(root, await expected(root), {
      onOpen() {},
      onFrame(_connection, frame) { received.push(frame.toString('utf8')); return Buffer.from('{}'); },
      onClosed() {}
    });
    const socket = createConnection(endpoint(root));
    await once(socket, 'connect');
    const closed = once(socket, 'close');
    await rename(endpoint(root), path.join(root, 'runtime', 'original.sock'));
    await writeFile(endpoint(root), 'replacement', { mode: 0o600 });
    socket.write('{"method":"session.create"}\n');
    await closed;
    assert.deepEqual(received, []);
    await listener.close();
    listener = undefined;
    assert.equal((await lstat(endpoint(root))).isFile(), true);
  } finally {
    await listener?.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('runtime parent replacement revokes an already accepted connection', async () => {
  const root = await privateRoot();
  const received: string[] = [];
  let opened!: () => void;
  const accepted = new Promise<void>((resolve) => { opened = resolve; });
  let listener: NativeControlListener | undefined;
  let socket: ReturnType<typeof createConnection> | undefined;
  try {
    listener = await NativeControlListener.start(root, await expected(root), {
      onOpen() { opened(); },
      onFrame(_connection, frame) { received.push(frame.toString('utf8')); return Buffer.from('{}'); },
      onClosed() {}
    });
    socket = createConnection(endpoint(root));
    await once(socket, 'connect');
    await Promise.race([
      accepted,
      setTimeout(3000).then(() => { throw new Error('native listener did not accept the connection'); })
    ]);
    const closed = once(socket, 'close');
    await rename(path.join(root, 'runtime'), path.join(root, 'runtime-old'));
    await mkdir(path.join(root, 'runtime'), { mode: 0o700 });
    socket.write('{"method":"session.create"}\n');
    await closed;
    assert.deepEqual(received, []);
    await listener.close(); listener = undefined;
    await assert.rejects(lstat(endpoint(root)), { code: 'ENOENT' });
  } finally {
    socket?.destroy();
    await listener?.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('a native recheck rejects endpoint drift after a complete frame but before dispatch', async () => {
  const root = await privateRoot();
  let frameSeen!: (connection: NativeControlConnection) => void;
  const frame = new Promise<NativeControlConnection>((resolve) => { frameSeen = resolve; });
  let finishFrame!: (response: Buffer) => void;
  let listener: NativeControlListener | undefined;
  let socket: ReturnType<typeof createConnection> | undefined;
  try {
    listener = await NativeControlListener.start(root, await expected(root), {
      onOpen() {},
      onFrame(connection) {
        frameSeen(connection);
        return new Promise<Buffer>((resolve) => { finishFrame = resolve; });
      },
      onClosed() {}
    });
    socket = createConnection(endpoint(root));
    await once(socket, 'connect');
    socket.write('{"method":"session.create"}\n');
    const connection = await frame;
    await rename(endpoint(root), path.join(root, 'runtime', 'original.sock'));
    await writeFile(endpoint(root), 'replacement', { mode: 0o600 });
    await assert.rejects(Promise.race([
      listener.recheck(connection),
      setTimeout(3000).then(() => { throw new Error('native recheck timed out'); })
    ]), /closed before recheck|not live/);
    finishFrame(Buffer.from('{}'));
    await listener.close(); listener = undefined;
    assert.equal((await lstat(endpoint(root))).isFile(), true);
  } finally {
    socket?.destroy();
    await listener?.close();
    await rm(root, { recursive: true, force: true });
  }
});
