import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { lstat, mkdtemp, readFile, rm, unlink } from 'node:fs/promises';
import { createConnection } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { isReplacementControlSocketHint } from './installed-control-readiness.js';

type OwnedSocketChild = { child: ReturnType<typeof spawn>;
  closed: Promise<{ code: number | null; signal: NodeJS.Signals | null }>; errors: Buffer[] };

test('an actual orphaned Unix socket remains a false readiness hint until a real listener replaces it', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-owned-socket-hint-'));
  const socketPath = path.join(directory, 'control.sock');
  const children: OwnedSocketChild[] = [];
  const source = "import {createServer} from 'node:net'; const server=createServer(s=>s.end());" +
    "server.listen(process.argv[1],()=>process.stdout.write('READY\\n'));" +
    "process.once('SIGTERM',()=>server.close(()=>process.exit(0)));";
  function start(): OwnedSocketChild {
    const child = spawn(process.execPath, ['--input-type=module', '-e', source, socketPath],
      { cwd: directory, stdio: ['ignore', 'pipe', 'pipe'] });
    const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
      child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
    });
    void closed.catch(() => undefined);
    const errors: Buffer[] = []; child.stderr.on('data', (bytes: Buffer) => errors.push(bytes));
    const value = { child, closed, errors }; children.push(value); return value;
  }
  async function ready(value: OwnedSocketChild) {
    assert(value.child.stdout);
    const [bytes] = await once(value.child.stdout, 'data', { signal: AbortSignal.timeout(5000) });
    assert.equal(bytes.toString(), 'READY\n');
  }
  try {
    const original = start(); await ready(original);
    const before = await lstat(socketPath, { bigint: true });
    assert(before.isSocket());
    original.child.kill('SIGKILL'); assert.deepEqual(await original.closed, { code: null, signal: 'SIGKILL' });
    const stale = await lstat(socketPath, { bigint: true });
    assert.equal(stale.ino, before.ino); assert.equal(stale.ctimeNs, before.ctimeNs);
    assert(stale.isSocket() && stale.uid === BigInt(process.getuid!()),
      'the old existence/uid readiness predicate really accepts this orphan');
    assert.equal(isReplacementControlSocketHint(before, stale), false);
    const connection = createConnection(socketPath), closed = new Promise<void>(resolve => connection.once('close', () => resolve()));
    const [failure] = await once(connection, 'error', { signal: AbortSignal.timeout(5000) });
    await closed;
    assert.equal((failure as NodeJS.ErrnoException).code, 'ECONNREFUSED');
    await unlink(socketPath);
    const successor = start(); await ready(successor);
    const replacement = await lstat(socketPath, { bigint: true });
    assert.equal(isReplacementControlSocketHint(before, replacement), true);
    t.diagnostic(JSON.stringify({ diagnosticOnly: true, source: 'actual_owned_unix_socket_component',
      original: { dev: before.dev.toString(), ino: before.ino.toString(), ctimeNs: before.ctimeNs.toString() },
      orphan: { dev: stale.dev.toString(), ino: stale.ino.toString(), ctimeNs: stale.ctimeNs.toString() },
      replacement: { dev: replacement.dev.toString(), ino: replacement.ino.toString(), ctimeNs: replacement.ctimeNs.toString() },
      originalConnectRefusal: 'ECONNREFUSED', installedAuthenticationQualified: false }));
    successor.child.kill('SIGTERM'); assert.deepEqual(await successor.closed, { code: 0, signal: null });
    for (const owned of children) assert.equal(Buffer.concat(owned.errors).length, 0);
  } finally {
    for (const owned of children) {
      if (owned.child.exitCode === null && owned.child.signalCode === null) owned.child.kill('SIGKILL');
      await owned.closed;
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test('the cleanup-crash successor waits for replacement inside the original restart budget before its single authenticated client', async () => {
  const source = await readFile(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  const helper = source.slice(source.indexOf('const selectedSupervisor ='), source.indexOf('const waitForSuccessorOwnerHistory ='));
  assert.match(helper, /isReplacementControlSocketHint\(previousSocket, socket\)/u);
  assert.match(helper, /Date\.now\(\) < by/u);
  const crash = source.slice(source.indexOf('cleanupCrash: async source =>'), source.indexOf("diagnostic.stage = 'current_namespace'"));
  assert(crash.indexOf('const originalControlSocket = await lstat(') < crash.indexOf('observer.arm(claimed.birth)'));
  assert.match(crash, /selectedSupervisor\(services!\.supervisorUnit, successorUnit, installedImage, restartBy, originalControlSocket\)/u);
  assert.equal(crash.match(/client = await persistentClient\(\)/gu)?.length, 1);
});
