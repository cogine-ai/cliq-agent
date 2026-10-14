import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { constants, closeSync } from 'node:fs';
import { chmod, copyFile, mkdir, mkdtemp, open, rename, realpath, rm } from 'node:fs/promises';
import { Socket } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { KernelStorageError } from './errors.js';
import { loadNativeStateOwner, openHeldInstalledControlClient, type HeldInstalledControlClient, type NativeStateOwner } from './native-owner.js';

// Genuine native transport/image/lifetime conformance. An actual signed
// installation and systemd binding remain the installed journey's proof.
const native = await loadNativeStateOwner();

test('installed client rejects a structural native before inspecting producer properties', () => {
  const input = new Proxy({} as Parameters<typeof openHeldInstalledControlClient>[1], {
    get() { throw new Error('untrusted producer properties inspected'); }
  });
  assert.throws(() => openHeldInstalledControlClient({} as NativeStateOwner, input), error =>
    error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
});

if (process.platform === 'linux') {
  async function fixture(t: TestContext) {
    const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-control-client-')));
    const rootPath = path.join(directory, 'root');
    await mkdir(rootPath, { mode: 0o700 }); await mkdir(path.join(rootPath, 'runtime'), { mode: 0o700 });
    const executable = path.join(directory, 'selected');
    await copyFile(process.execPath, executable); await chmod(executable, 0o500);
    const root = await open(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const image = await open(executable, constants.O_RDONLY | constants.O_NOFOLLOW);
    const socketPath = path.join(rootPath, 'runtime/control-v1.sock');
    const server = spawn(executable, ['--input-type=module', '-e', `
      import net from 'node:net'; import fs from 'node:fs';
      const socket=process.argv[1], peers=new Set();
      const server=net.createServer(peer=>{peers.add(peer);peer.on('error',()=>{});peer.on('close',()=>peers.delete(peer));
        peer.on('data',bytes=>peer.write(bytes));});
      server.listen(socket,()=>{fs.chmodSync(socket,0o600);process.send({pid:process.pid});});
      process.on('message',command=>{if(command==='close-peers'){for(const peer of peers)peer.destroy();process.send('closed-peers');}});
      process.on('disconnect',()=>{for(const peer of peers)peer.destroy();server.close(()=>process.exit(0));});
    `, socketPath], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
    let diagnostic = ''; server.stderr!.on('data', chunk => { diagnostic = (diagnostic + chunk).slice(-4096); });
    const joined = once(server, 'exit'); void joined.catch(() => undefined);
    const watchdog = setTimeout(() => server.kill('SIGKILL'), 15000);
    const clients: HeldInstalledControlClient[] = [], sockets: Socket[] = [];
    t.after(async () => {
      clearTimeout(watchdog);
      for (const socket of sockets) {
        if (!socket.closed) { const closed = once(socket, 'close'); socket.destroy(); await closed; }
      }
      for (const client of clients) client.close();
      if (server.exitCode === null && server.signalCode === null) server.kill('SIGKILL');
      await joined; await image.close(); await root.close(); await rm(directory, { recursive: true, force: true });
    });
    const [ready] = await Promise.race([once(server, 'message'), joined.then(() => { throw new Error(`server exited before ready: ${diagnostic}`); })]);
    assert.equal((ready as { pid: number }).pid, server.pid);
    const connect = async (selectedImage = image) => {
      const client = openHeldInstalledControlClient(native, { root, rootIdentity: await root.stat({ bigint: true }),
        stateRoot: rootPath, image: selectedImage, imageIdentity: await selectedImage.stat({ bigint: true }) });
      clients.push(client); return client;
    };
    const socketFor = (client: HeldInstalledControlClient) => {
      const fd = client.takeSocketFd();
      let socket: Socket;
      try { socket = new Socket({ fd, readable: true, writable: true }); }
      catch (error) { closeSync(fd); throw error; }
      socket.on('error', () => {}); sockets.push(socket); return socket;
    };
    return { directory, rootPath, image, executable, server, joined, connect, socketFor };
  }

  test('fixed client authenticates actual selected process and transfers only one live socket', { timeout: 30000 }, async t => {
    const f = await fixture(t), client = await f.connect();
    assert.equal(client.server.pid, f.server.pid);
    assert.equal(client.server.uid, process.geteuid!());
    assert.match(client.server.processStartToken, /^linux-proc-start-ticks:[1-9]\d*$/u);
    assert(Object.isFrozen(client)); assert(Object.isFrozen(client.server)); client.assertHeld();
    assert.throws(() => client.assertHeld.call({}), /invalid installed control client/u);
    const socket = f.socketFor(client);
    assert.throws(() => client.takeSocketFd(), /closed|consumed|unavailable/u);
    const response = once(socket, 'data'); socket.write('actual-frame\n');
    assert.equal((await response)[0].toString(), 'actual-frame\n'); client.assertHeld();
    const closed = once(socket, 'close'); socket.destroy(); await closed;
    client.close(); assert.throws(() => client.assertHeld(), /closed|unavailable/u);
  });

  test('fixed client refuses a byte-identical but different physical selected image', { timeout: 30000 }, async t => {
    const f = await fixture(t), duplicatePath = path.join(f.directory, 'other-image');
    await copyFile(f.executable, duplicatePath); await chmod(duplicatePath, 0o500);
    const duplicate = await open(duplicatePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { await assert.rejects(f.connect(duplicate), /identity|unavailable/u); }
    finally { await duplicate.close(); }
    (await f.connect()).assertHeld();
  });

  test('held client rejects exact socket entry and executable locator replacement', { timeout: 30000 }, async t => {
    const f = await fixture(t), client = await f.connect();
    const socketPath = path.join(f.rootPath, 'runtime/control-v1.sock'), oldSocket = `${socketPath}.retained`;
    await rename(socketPath, oldSocket);
    try { assert.throws(() => client.assertHeld(), /changed|unavailable/u); }
    finally { await rename(oldSocket, socketPath); }
    client.assertHeld();
    await rename(f.executable, `${f.executable}.retained`);
    await copyFile(`${f.executable}.retained`, f.executable); await chmod(f.executable, 0o500);
    assert.throws(() => client.assertHeld(), /changed|unavailable/u);
  });

  test('held client rejects a closed connection and the original server death', { timeout: 30000 }, async t => {
    const f = await fixture(t), client = await f.connect(), socket = f.socketFor(client);
    const echoed = once(socket, 'data'); socket.write('accepted\n'); await echoed;
    const closed = once(socket, 'close'), notice = once(f.server, 'message');
    f.server.send('close-peers'); assert.equal((await notice)[0], 'closed-peers'); await closed;
    assert.throws(() => client.assertHeld(), /changed|closed|unavailable/u); client.close();
    const second = await f.connect();
    f.server.kill('SIGKILL'); await f.joined;
    assert.throws(() => second.assertHeld(), /changed|closed|unavailable/u);
  });
}
