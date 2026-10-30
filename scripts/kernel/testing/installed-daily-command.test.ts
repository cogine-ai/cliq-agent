import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer, type Socket } from 'node:net';
import { spawnSync } from 'node:child_process';
import { lstat, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createCredentialSecretScanner } from './credential-secret-scan.js';
import { InstalledDailyCommandError, runInstalledDailyCommand } from './installed-daily-command.js';

const scanner = () => createCredentialSecretScanner([Buffer.from('owned-unused-secret-741083e4')], { maxBytes: 65_536, maxStreams: 2 });
test('ordinary command success requires actual child, complete input and all original pipe joins', async () => {
  const scan = scanner();
  try {
    const result = await runInstalledDailyCommand({ executable: process.execPath,
      args: ['--input-type=module', '-e', "const parts=[];for await(const value of process.stdin)parts.push(value);process.stdout.write(Buffer.concat(parts));process.stderr.write('joined\\n');"],
      cwd: tmpdir(), env: {}, input: Buffer.from('owned public metadata\n'), deadlineMs: 3_000, scanner: scan });
    assert.equal(result.stdout.toString(), 'owned public metadata\n'); assert.equal(result.stderr.toString(), 'joined\n');
    assert.equal(scan.stats().streamsOpened, 2); assert.equal(scan.stats().streamsClosed, 2);
  } finally { scan.close(); }
});

for (const ignoreTerm of [false, true]) test(ignoreTerm
  ? 'an actually unjoined TERM-ignoring launcher returns failure to its outer owner without claiming process death'
  : 'failed ordinary parent returns its joined pipes to the outer owner while its real child still holds inherited stdout', {
  skip: process.platform === 'win32' ? 'requires a real Unix-domain socket' : false, timeout: 22_000,
}, async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'cliq-daily-'));
  const filename = path.join(directory, 'child.sock'), scan = scanner();
  let peer: Socket | undefined, peerClosed = false, completion = '';
  let connectionResolve!: () => void, closeResolve!: () => void;
  const connected = new Promise<void>(resolve => { connectionResolve = resolve; });
  const closed = new Promise<void>(resolve => { closeResolve = resolve; });
  const server = createServer(socket => {
    assert.equal(peer, undefined); peer = socket;
    socket.on('data', data => { completion += data.toString(); });
    socket.on('error', () => {});
    socket.once('close', () => { peerClosed = true; closeResolve(); }); connectionResolve();
  });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(filename, resolve); });
  // The ordinary child has a bounded natural lifetime and an independently
  // observed socket. The parent is killed by the actual command owner; closing
  // our inherited pipe ends must never be relabeled as that child's death.
  const childSource = `import{createConnection}from'node:net';${ignoreTerm ? "process.on('SIGTERM',()=>{});" : ''}const socket=createConnection(${JSON.stringify(filename)});socket.on('error',()=>process.exit(2));socket.on('connect',()=>{process.stdout.write('child holds inherited stdout\\n');setTimeout(()=>socket.end('complete',()=>process.exit(0)),${ignoreTerm ? 16000 : 8000});});`;
  const parentSource = ignoreTerm ? childSource : `import{spawn}from'node:child_process';spawn(process.execPath,['--input-type=module','-e',${JSON.stringify(childSource)}],{stdio:['ignore','inherit','inherit']});setInterval(()=>{},1000);`;
  const started = performance.now();
  const failure = runInstalledDailyCommand({ executable: process.execPath, args: ['--input-type=module', '-e', parentSource],
    cwd: directory, env: {}, deadlineMs: 3_000, scanner: scan });
  void failure.catch(() => {});
  try {
    await Promise.race([connected, failure.then(() => { throw new Error('command unexpectedly succeeded before child connection'); }),
      delay(5_000, undefined, { ref: false }).then(() => { throw new Error('ordinary child did not connect'); })]);
    await assert.rejects(failure, error => {
      assert(error instanceof InstalledDailyCommandError);
      assert.equal(error.launcherAndPipesJoined, !ignoreTerm);
      assert.equal(error.descendantRetirement, 'outer_uid_coordinator_required'); return true;
    });
    assert(performance.now() - started < (ignoreTerm ? 15_000 : 7_000));
    assert.equal(peerClosed, false, 'the actual descendant is still independently connected');
    assert.equal(completion, ''); assert.equal(scan.stats().streamsClosed, 2);
  } finally {
    // Join the independent ordinary child fixture before releasing its server.
    // This socket completion is not native or production death evidence.
    if (peer) await closed;
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    scan.close(); await rm(directory, { recursive: true, force: true });
  }
  assert.equal(completion, 'complete'); assert.equal(peerClosed, true);
});

test('actual root-owned Linux runuser TERM retires its original nobody command and joins the original launcher and stdios', {
  skip: process.platform !== 'linux' || process.geteuid?.() !== 0 ? 'requires actual Linux root and util-linux runuser' : false,
  timeout: 45_000,
}, async () => {
  const scan = scanner(), runuser = '/usr/sbin/runuser', sleep = '/usr/bin/sleep';
  const account = spawnSync('/usr/bin/id', ['-u', 'nobody'], { env: {}, timeout: 2_000, maxBuffer: 4_096, encoding: 'utf8' });
  assert.equal(account.error, undefined); assert.equal(account.status, 0); assert.match(account.stdout, /^[1-9][0-9]*\n$/u);
  const uid = Number(account.stdout.trim()); assert(Number.isSafeInteger(uid) && uid > 0);
  const originalSleep = await lstat(sleep, { bigint: true }), originalLauncher = await lstat(runuser, { bigint: true });
  let output = '', observedPid: number | undefined, resolvePid!: (pid: number) => void;
  const pidReady = new Promise<number>(resolve => { resolvePid = resolve; });
  let streamIndex = 0;
  const observedScanner = { ...scan, openStream() {
    const stream = scan.openStream(), index = streamIndex++;
    return { close: () => stream.close(), scan(bytes: Uint8Array) {
      stream.scan(bytes);
      if (index === 0) {
        output += Buffer.from(bytes).toString('ascii'); assert(output.length <= 32);
        if (/^[1-9][0-9]*\n$/u.test(output)) { observedPid = Number(output.trim()); resolvePid(observedPid); }
      }
    } };
  } };
  const fact = async (pid: number) => {
    try {
      const raw = await readFile(`/proc/${pid}/stat`, 'utf8'); assert(raw.length <= 8_192 && raw.startsWith(`${pid} (`));
      const fields = raw.slice(raw.lastIndexOf(') ') + 2).trim().split(/\s+/u);
      assert(fields.length >= 20 && /^[1-9][0-9]*$/u.test(fields[19]!));
      return { start: fields[19]!, parent: Number(fields[1]) };
    } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT' || (error as NodeJS.ErrnoException).code === 'ESRCH') return undefined; throw error; }
  };
  const gone = async (pid: number, start: string, milliseconds: number) => {
    const by = performance.now() + milliseconds;
    for (;;) {
      const current = await fact(pid); if (!current || current.start !== start) return;
      assert(performance.now() < by, 'original ordinary command lifetime remains present'); await delay(20);
    }
  };
  // This fixed child is not a service, Run, native proof or pause/tracer target.
  const command = runInstalledDailyCommand({ executable: runuser,
    args: ['--user', 'nobody', '--', '/bin/sh', '-c', 'printf "%s\\n" "$$"; exec /usr/bin/sleep 30'],
    cwd: '/', env: {}, deadlineMs: 3_000, scanner: observedScanner });
  void command.catch(() => {});
  let child: Awaited<ReturnType<typeof fact>>, launcher: Awaited<ReturnType<typeof fact>>;
  try {
    const pid = await Promise.race([pidReady, command.then(() => { throw new Error('fixed sleep command unexpectedly completed'); })]);
    child = await fact(pid); assert(child); launcher = await fact(child.parent); assert(launcher); assert.equal(launcher.parent, process.pid);
    const status = await readFile(`/proc/${pid}/status`, 'utf8'), uids = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu.exec(status); assert(uids);
    assert.deepEqual(uids.slice(1).map(Number), [uid, uid, uid, uid]);
    const by = performance.now() + 1_000;
    for (;;) {
      const image = await stat(`/proc/${pid}/exe`, { bigint: true });
      if (image.dev === originalSleep.dev && image.ino === originalSleep.ino) break;
      assert(performance.now() < by); assert.equal((await fact(pid))?.start, child.start); await delay(10);
    }
    const parentImage = await stat(`/proc/${child.parent}/exe`, { bigint: true });
    assert.equal(parentImage.dev, originalLauncher.dev); assert.equal(parentImage.ino, originalLauncher.ino);
    await assert.rejects(command, error => {
      assert(error instanceof InstalledDailyCommandError); assert.equal(error.launcherAndPipesJoined, true);
      assert.equal(error.descendantRetirement, 'outer_uid_coordinator_required'); return true;
    });
    await gone(pid, child.start, 5_000); await gone(child.parent, launcher.start, 5_000);
    assert.equal(scan.stats().streamsOpened, 2); assert.equal(scan.stats().streamsClosed, 2);
  } finally {
    await command.catch(() => {});
    // On a genuine failure, retain failure and wait for this fixed child's
    // bounded natural exit. Never signal a possibly reused numeric PID.
    if (child && observedPid !== undefined) await gone(observedPid, child.start, 35_000);
    scan.close();
  }
});
