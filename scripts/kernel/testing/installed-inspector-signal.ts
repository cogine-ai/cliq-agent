// Real Linux signal/HTTP/proc observations only. Never a production entrypoint.
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { lstat, readFile, readdir, readlink, stat } from 'node:fs/promises';
import { get } from 'node:http';
import os from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { SUPERVISOR_SEA_NODE_VERSION } from './supervisor-sea-builder.js';

export type InstalledInspectorSignalReport = {
  diagnosticOnly: true;
  positiveControl?: Record<string, unknown>;
  installed?: Record<string, unknown>;
};
const signalBit = 1n << BigInt(os.constants.signals.SIGUSR1 - 1);
const timeout = 30_000;

async function bounded<T>(pending: Promise<T>, milliseconds = timeout): Promise<T> {
  let timer!: ReturnType<typeof setTimeout>;
  try {
    return await Promise.race([pending, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('inspector signal qualification timed out')), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

function assertAlive(child: ChildProcess, failure?: Error): asserts child is ChildProcess & { pid: number } {
  if (failure) throw failure;
  assert(child.pid && child.exitCode === null && child.signalCode === null, 'signal target must remain our live child');
}

async function processIdentity(pid: number) {
  const raw = await readFile(`/proc/${pid}/stat`, 'utf8');
  assert(raw.startsWith(`${pid} (`));
  const fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/u);
  assert(fields.length >= 20 && fields[0] !== 'Z' && fields[0] !== 'X');
  assert.match(fields[19]!, /^[0-9]+$/u);
  const image = await stat(`/proc/${pid}/exe`, { bigint: true });
  assert(image.isFile());
  return { pid, processStartToken: `linux-proc-start-ticks:${fields[19]}`,
    executable: await readlink(`/proc/${pid}/exe`), deviceId: image.dev.toString(), fileId: image.ino.toString(),
    byteCount: image.size.toString(), mtimeNs: image.mtimeNs.toString(), ctimeNs: image.ctimeNs.toString() };
}

function statusMask(status: string, name: 'SigBlk' | 'ShdPnd' | 'SigCgt') {
  const matches = [...status.matchAll(new RegExp(`^${name}:\\s*([0-9a-fA-F]+)$`, 'gmu'))];
  assert.equal(matches.length, 1, `missing or ambiguous ${name} in actual proc status`);
  return matches[0]![1]!;
}
const hasSignal = (mask: string) => (BigInt(`0x${mask}`) & signalBit) !== 0n;

async function signalObservation(pid: number) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const tasks = (await readdir(`/proc/${pid}/task`)).sort();
    assert(tasks.length > 0 && tasks.includes(String(pid)));
    assert(tasks.every(task => /^[1-9][0-9]*$/u.test(task)));
    try {
      const masks = await Promise.all(tasks.map(async task => {
        const status = await readFile(`/proc/${pid}/task/${task}/status`, 'utf8');
        assert.match(status, new RegExp(`^Tgid:\\s*${pid}$`, 'mu'));
        assert.match(status, new RegExp(`^Pid:\\s*${task}$`, 'mu'));
        return { taskId: task, blocked: statusMask(status, 'SigBlk'), caught: statusMask(status, 'SigCgt') };
      }));
      const status = await readFile(`/proc/${pid}/status`, 'utf8');
      const after = (await readdir(`/proc/${pid}/task`)).sort();
      if (tasks.length === after.length && tasks.every((task, index) => task === after[index]))
        return { tasks: masks, sharedPending: statusMask(status, 'ShdPnd') };
    } catch (error) {
      // Only a disappearing task is retried. Unreadable/malformed evidence fails.
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    assert(Date.now() < deadline, 'could not completely observe a stable task set');
    await delay(10);
  }
}

async function ownedTcpListeners(pid: number) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const descriptors = (await readdir(`/proc/${pid}/fd`)).sort();
    assert(descriptors.length > 0 && descriptors.every(fd => /^(0|[1-9][0-9]*)$/u.test(fd)));
    try {
      const links = await Promise.all(descriptors.map(fd => readlink(`/proc/${pid}/fd/${fd}`)));
      const inodes = new Set(links.flatMap(link => /^socket:\[([1-9][0-9]*)\]$/u.exec(link)?.slice(1) ?? []));
      const listeners: Array<{ family: string; address: string; port: number; inode: string }> = [];
      for (const family of ['tcp', 'tcp6']) {
        // These are namespace-wide tables, not PID-owned tables. Intersect FDs.
        const lines = (await readFile(`/proc/${pid}/net/${family}`, 'utf8')).trim().split('\n');
        assert(lines[0]?.includes('local_address') && lines[0]?.includes('inode'));
        for (const line of lines.slice(1)) {
          const fields = line.trim().split(/\s+/u);
          assert(fields.length >= 10 && /^[0-9]+:$/u.test(fields[0]!));
          assert.match(fields[1]!, /^(?:[0-9A-Fa-f]{8}|[0-9A-Fa-f]{32}):[0-9A-Fa-f]{4}$/u);
          assert.match(fields[3]!, /^[0-9A-Fa-f]{2}$/u); assert.match(fields[9]!, /^[0-9]+$/u);
          if (fields[3]!.toUpperCase() !== '0A' || !inodes.has(fields[9]!)) continue;
          const [address, port] = fields[1]!.split(':');
          listeners.push({ family, address: address!.toUpperCase(), port: Number.parseInt(port!, 16), inode: fields[9]! });
        }
      }
      const after = (await readdir(`/proc/${pid}/fd`)).sort();
      if (descriptors.length === after.length && descriptors.every((fd, index) => fd === after[index])) {
        const afterLinks = await Promise.all(after.map(fd => readlink(`/proc/${pid}/fd/${fd}`)));
        if (links.every((link, index) => link === afterLinks[index])) return listeners;
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    assert(Date.now() < deadline, 'could not completely observe a stable descriptor set');
    await delay(10);
  }
}

function debuggerUrl(stderr: string): URL | undefined {
  const match = /Debugger listening on (ws:\/\/[^\s]+)/u.exec(stderr);
  if (!match) return undefined;
  const url = new URL(match[1]!);
  assert.equal(url.protocol, 'ws:'); assert.equal(url.hostname, '127.0.0.1');
  assert(/^[1-9][0-9]*$/u.test(url.port) && Number(url.port) <= 65535);
  assert.match(url.pathname, /^\/[0-9a-f-]+$/u); assert.equal(url.search, ''); assert.equal(url.hash, '');
  return url;
}

async function inspectorTarget(url: URL) {
  let request: ReturnType<typeof get> | undefined, closed: Promise<void> | undefined;
  let body: string;
  try {
    body = await new Promise<string>((resolve, reject) => {
      request = get({ hostname: '127.0.0.1', port: Number(url.port), path: '/json/list',
        headers: { Connection: 'close' }, signal: AbortSignal.timeout(timeout) }, response => {
        if (response.statusCode !== 200) {
          response.resume(); reject(new Error(`inspector HTTP status ${response.statusCode}`)); return;
        }
        let bytes = 0; const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => {
          bytes += chunk.length;
          if (bytes > 128 * 1024) { response.destroy(new Error('inspector HTTP response exceeded bound')); return; }
          chunks.push(chunk);
        });
        response.on('error', reject);
        response.on('end', () => {
          try { resolve(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
          catch (error) { reject(error); }
        });
      });
      closed = new Promise(resolve => request!.once('close', resolve));
      request.on('error', reject);
    });
  } finally {
    request?.destroy();
    if (closed) await bounded(closed, 5_000);
  }
  const targets = JSON.parse(body) as Array<{ type?: string; webSocketDebuggerUrl?: string }>;
  assert(Array.isArray(targets)); assert.equal(targets.length, 1);
  assert.equal(targets[0]!.type, 'node'); assert.equal(targets[0]!.webSocketDebuggerUrl, url.href);
  return { type: 'node', webSocketDebuggerUrl: url.href };
}

function ownsDebugger(listeners: Awaited<ReturnType<typeof ownedTcpListeners>>, url: URL) {
  return listeners.find(listener => listener.family === 'tcp' && listener.address === '0100007F' && listener.port === Number(url.port));
}

async function carrierControl(carrier: string, cwd: string, report: InstalledInspectorSignalReport) {
  // No --inspect: only the real signal may start this inspector. No StateRoot.
  const script = `const timer = setInterval(() => {}, 1000);
process.on('SIGTERM', () => clearInterval(timer));
console.log(JSON.stringify({pid:process.pid,nodeVersion:process.version}));`;
  const child = spawn(carrier, ['--inspect-port=127.0.0.1:0', '-e', script], {
    cwd, env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', spawnError: Error | undefined;
  child.once('error', error => { spawnError = error; });
  child.stdout!.on('data', (bytes: Buffer) => { stdout = (stdout + bytes.toString('utf8')).slice(-128 * 1024); });
  child.stderr!.on('data', (bytes: Buffer) => { stderr = (stderr + bytes.toString('utf8')).slice(-128 * 1024); });
  const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve =>
    child.once('close', (code, signal) => resolve({ code, signal })));
  const facts: Record<string, unknown> = { signalSent: false };
  report.positiveControl = facts;
  try {
    let deadline = Date.now() + timeout;
    while (!stdout.includes('\n')) {
      assertAlive(child, spawnError); assert(Date.now() < deadline, 'carrier control never reached actual READY'); await delay(10);
    }
    assertAlive(child, spawnError);
    const ready = JSON.parse(stdout.trim()) as { pid: number; nodeVersion: string };
    assert.equal(ready.pid, child.pid); assert.equal(ready.nodeVersion, `v${SUPERVISOR_SEA_NODE_VERSION}`);
    const before = await processIdentity(child.pid); facts.before = before;
    assert.equal(before.executable, carrier);
    assert.deepEqual(await ownedTcpListeners(child.pid), []); assert.equal(debuggerUrl(stderr), undefined);
    assert(child.kill('SIGUSR1'), 'carrier control signal must actually be sent'); facts.signalSent = true;
    deadline = Date.now() + timeout;
    for (;;) {
      assertAlive(child, spawnError); assert.deepEqual(await processIdentity(child.pid), before);
      const url = debuggerUrl(stderr), listeners = await ownedTcpListeners(child.pid);
      if (url && ownsDebugger(listeners, url)) {
        facts.debugger = { target: await inspectorTarget(url), listener: ownsDebugger(listeners, url) };
        facts.stderr = stderr; break;
      }
      assert(Date.now() < deadline, 'actual SIGUSR1 carrier control never opened its own inspector'); await delay(10);
    }
  } finally {
    facts.stderr = stderr;
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      try { await bounded(closed, 5_000); }
      catch (error) {
        child.kill('SIGKILL'); facts.cleanup = { ...await bounded(closed, 5_000), joined: true, forced: true };
        throw error; // Joining a forced kill is not positive qualification.
      }
    }
    facts.cleanup = { ...await bounded(closed, 5_000), joined: true, forced: false };
    assert.deepEqual(facts.cleanup, { code: 0, signal: null, joined: true, forced: false });
  }
}

export async function qualifyInstalledInspectorSignal(input: {
  carrier: string; cwd: string; supervisor: ChildProcess; selectedImage: string; processStartToken: string;
  stderr: () => string; checkControl: () => Promise<void>; report: InstalledInspectorSignalReport;
}): Promise<void> {
  assert.equal(process.platform, 'linux');
  await carrierControl(input.carrier, input.cwd, input.report);
  await input.checkControl();
  const child = input.supervisor; assertAlive(child);
  const before = await processIdentity(child.pid);
  assert.equal(before.processStartToken, input.processStartToken); assert.equal(before.executable, input.selectedImage);
  const selected = await lstat(input.selectedImage, { bigint: true }); assert(selected.isFile());
  for (const [field, expected] of [['deviceId', selected.dev], ['fileId', selected.ino], ['byteCount', selected.size],
    ['mtimeNs', selected.mtimeNs], ['ctimeNs', selected.ctimeNs]] as const) assert.equal(before[field], expected.toString());
  const beforeSignals = await signalObservation(child.pid), beforeListeners = await ownedTcpListeners(child.pid);
  const facts: Record<string, unknown> = { before, beforeSignals, beforeListeners, signalSent: false };
  input.report.installed = facts;
  // Send even on the unfixed image: retain the real listener RED, not a mask-only failure.
  assertAlive(child); assert.deepEqual(await processIdentity(child.pid), before);
  assert(child.kill('SIGUSR1'), 'installed signal must actually be sent'); facts.signalSent = true;
  const deadline = Date.now() + timeout;
  for (;;) {
    assertAlive(child); assert.deepEqual(await processIdentity(child.pid), before);
    const signals = await signalObservation(child.pid), listeners = await ownedTcpListeners(child.pid);
    facts.afterSignals = signals; facts.afterListeners = listeners; facts.stderr = input.stderr();
    const allBlocked = signals.tasks.every(task => hasSignal(task.blocked));
    const pending = hasSignal(signals.sharedPending);
    const url = debuggerUrl(input.stderr());
    if (url && ownsDebugger(listeners, url)) {
      facts.debugger = { target: await inspectorTarget(url), listener: ownsDebugger(listeners, url) };
      assert.fail('actual installed image opened a PID-owned inspector after SIGUSR1');
    }
    if (allBlocked && pending) {
      assert(!hasSignal(beforeSignals.sharedPending), 'fresh signal must transition shared pending from absent to present');
      assert(signals.tasks.every(task => !hasSignal(task.caught)), 'installed image must not register a SIGUSR1 callback');
      assert.deepEqual(beforeListeners, []); assert.deepEqual(listeners, []); assert.equal(url, undefined);
      break;
    }
    assert(Date.now() < deadline, 'installed signal route did not close; actual stderr/listener/masks retained in report');
    await delay(10);
  }
  await input.checkControl();
  assertAlive(child); assert.deepEqual(await processIdentity(child.pid), before);
  const finalSignals = await signalObservation(child.pid), finalListeners = await ownedTcpListeners(child.pid);
  facts.finalSignals = finalSignals; facts.finalListeners = finalListeners; facts.stderr = input.stderr();
  assert(finalSignals.tasks.every(task => hasSignal(task.blocked) && !hasSignal(task.caught)));
  assert(hasSignal(finalSignals.sharedPending)); assert.deepEqual(finalListeners, []);
  assert.equal(debuggerUrl(input.stderr()), undefined); facts.qualified = true;
}
