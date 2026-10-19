import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { chmod, copyFile, mkdtemp, readFile, realpath, rm, stat } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { createEnrollWorkObservation, decodeEnrollWorkFrame, decodeEnrollCredentialPhase, decodeEnrollProcessCounters,
  runOwnedEnrollDiagnostic, type InstalledEnrollDiagnostic } from './installed-enroll-diagnostic.js';
import { createCredentialSecretScanner } from './credential-secret-scan.js';

async function ownedFixture(fixture: string): Promise<string> {
  const executable = path.join(fixture, 'owned-process');
  const result = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
    fileURLToPath(new URL('./credential-producer-lifetime-probe.c', import.meta.url)), '-o', executable],
  { encoding: 'utf8', timeout: 60000 });
  assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 0, result.stderr);
  return executable;
}

async function joinedWithin<T>(pending: Promise<T>, milliseconds: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try { return await Promise.race([pending, new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('owned lifetime fixture did not join')), milliseconds);
  })]); } finally { clearTimeout(timer); }
}

test('enroll phase observations accept only the complete fixed source-owned byte markers', () => {
  for (const phase of ['open_selected', 'history', 'first_supervisor', 'secret_input', 'second_supervisor', 'platform_store', 'finalize', 'retire'])
    assert.equal(decodeEnrollCredentialPhase(Buffer.from(`CLIQ_CREDENTIAL_PHASE_V1:${phase}\n`)), phase);
  let accessed = false;
  const hostile = Object.defineProperty({}, 'length', { get() { accessed = true; throw new Error('must not inspect caller fields'); } });
  for (const input of [hostile, 'CLIQ_CREDENTIAL_PHASE_V1:history\n', null, Buffer.from('CLIQ_CREDENTIAL_PHASE_V1:secret'),
    Buffer.from('CLIQ_CREDENTIAL_PHASE_V1:history\nextra'), Buffer.from('CLIQ_CREDENTIAL_PHASE_V1:history\r\n'),
    Buffer.from('CLIQ_CREDENTIAL_PHASE_V1:history'), Buffer.from('CLIQ_CREDENTIAL_PHASE_V1:unknown\n'),
    Buffer.from([0xff, 0x0a]), Buffer.from('arbitrary-private-content\n')])
    assert.equal(decodeEnrollCredentialPhase(input), undefined);
  assert.equal(accessed, false);
});

test('work frames are closed numeric data and a split stream keeps bounded sparse history plus the latest inflight work', () => {
  const frame = (role: string, started: number, completed: number, bytes: number, nativeStarted = 0, nativeCompleted = 0) =>
    Buffer.from(`CLIQ_INSTALLED_WORK_V1:${role}:${started}:${completed}:${bytes}:10:0:0:0:0:${nativeStarted}:${nativeCompleted}:0:0\n`);
  const first = frame('bootstrap', 1, 0, 7), parsed = decodeEnrollWorkFrame(first)!;
  assert.deepEqual(parsed, { role: 'bootstrap', package: { started: 1, completed: 0, bytesRead: 7, spanElapsedMs: 10 },
    revalidate: { started: 0, completed: 0, bytesRead: 0, spanElapsedMs: 0 },
    createCompare: { started: 0, completed: 0, bytesRead: 0, spanElapsedMs: 0 } });
  let accessed = false;
  const hostile = Object.defineProperty({}, 'length', { get() { accessed = true; throw 0; } });
  for (const value of [hostile, first.toString(), Buffer.concat([first, Buffer.from('\n')]),
    Buffer.from(first.toString().replace(':7:', ':07:')), Buffer.from(first.toString().replace(':7:', ':9007199254740992:')),
    frame('unknown-private-role', 1, 0, 7), frame('credential', 0, 1, 7), Buffer.from([0xff, ...first]),
    Buffer.from(first.toString().replace(':0:0\n', ':1:0\n')), Buffer.from('private-unretained-content\n')])
    assert.equal(decodeEnrollWorkFrame(value), undefined);
  assert.equal(accessed, false);
  const observer = createEnrollWorkObservation();
  observer.write(first.subarray(0, 11), 1); observer.write(first.subarray(11), 2);
  observer.write(frame('credential', 1, 0, 8), 5);
  // Counters may reset only on the single real bootstrap -> credential cut.
  observer.write(frame('bootstrap', 9, 0, 99), 6);
  observer.write(frame('credential', 0, 0, 0), 7);
  for (let i = 2; i <= 45; i++) observer.write(frame('credential', i, i - 1, i * 10), i * 3000);
  observer.write(frame('credential', 46, 45, 461, 1, 0), 135001);
  observer.write(Buffer.from('x'.repeat(300) + '\n'), 135002);
  observer.finish();
  const report = observer.result!;
  assert.equal(report.snapshots.length, 32); assert.equal(report.truncated, true);
  assert.equal(report.snapshots[0]!.role, 'bootstrap');
  assert.equal(report.snapshots.at(-1)!.role, 'credential');
  assert.equal(report.snapshots.at(-1)!.package.bytesRead, 461);
  assert.equal(report.snapshots.at(-1)!.package.started - report.snapshots.at(-1)!.package.completed, 1);
  assert.equal(report.snapshots.at(-1)!.createCompare.started, 1);
  assert.equal(report.snapshots.at(-1)!.createCompare.completed, 0);
  assert(!JSON.stringify(report).includes('private-unretained-content'));
});

test('enroll diagnostics retain only exact numeric process counters, including values beyond safe integers', () => {
  const fields = ['S', '12', '34', '34', ...Array(7).fill('0'), '120', '45', ...Array(5).fill('0'), '0', '678', '0'];
  const stat = `42 (a process ) with spaces) ${fields.join(' ')}\n`;
  assert.deepEqual(decodeEnrollProcessCounters(42, stat,
    'rchar: 9007199254740993\nwchar: 999\nsyscr: 1234\nsyscw: 8\nread_bytes: 5678\nwrite_bytes: 99\ncancelled_write_bytes: 0\n'), {
    pid: 42, parent: 12, group: 34, session: 34, startTicks: '678', userTicks: '120', systemTicks: '45',
    rchar: '9007199254740993', syscr: '1234', readBytes: '5678',
  });
  for (const io of ['rchar: 01\nsyscr: 1\nread_bytes: 1\n', 'rchar: 1\nrchar: 2\nsyscr: 1\nread_bytes: 1\n',
    'rchar: canary-private-input\nsyscr: 1\nread_bytes: 1\n'])
    assert.throws(() => decodeEnrollProcessCounters(42, stat, io), { message: 'enroll process counters are invalid' });
  assert.throws(() => decodeEnrollProcessCounters(43, stat, ''), { message: 'enroll process counters are invalid' });
});

test('the verifier enroll alone uses the owned asynchronous command without changing the original deadline or raw-state policy', async () => {
  const source = await readFile(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  assert.equal((source.match(/await runOwnedEnrollDiagnostic\(/gu) ?? []).length, 1);
  assert(source.includes("const setup = credential({ schemaVersion: 1, kind: 'install_services' })"));
  assert(source.includes('originalDeadlineMs: 60000'));
  assert(source.includes("assert.equal(enrollmentResult.error, undefined, 'actual fixture command must join')"));
  assert(source.includes("assert.equal(enrollmentResult.signal, null)"));
  assert(source.includes("{ kind: 'unavailable', reason: 'no_safe_readonly_wal_reader' }"));
  assert(source.includes('inspectInstalledOwnerHistory(recipe.stateRoot).owners'));
  assert(source.includes('liveObserved: false'));
});

test('an owned enroll diagnostic really joins an over-deadline process and both scanned output streams',
  { skip: process.platform !== 'linux' ? 'requires actual Linux process identities; not installed qualification' : false }, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-enroll-owned-')));
    const scanner = createCredentialSecretScanner([Buffer.from('fixture-private-input')], { maxBytes: 1024 * 1024, maxStreams: 16 });
    try {
      const image = path.join(fixture, 'node'); await copyFile(process.execPath, image); await chmod(image, 0o500);
      const diagnostic = {} as InstalledEnrollDiagnostic;
      const work = 'CLIQ_INSTALLED_WORK_V1:credential:1:0:7:10:0:0:0:0:1:0:0:5\n';
      const result = await runOwnedEnrollDiagnostic({ command: { executable: image,
        args: ['-e', `process.stdin.resume(); process.stderr.write(${JSON.stringify(work)}); process.stdout.write("joined-output"); setInterval(()=>{},1000)`], cwd: fixture, env: {} },
        input: Buffer.from('fixture-private-input'), uid: process.geteuid!(), bootstrapImage: image, installedImage: image,
        originalDeadlineMs: 1000, scanner, diagnostic });
      assert.equal(result.error?.code, 'ETIMEDOUT'); assert.equal(result.signal, 'SIGKILL'); assert.equal(diagnostic.outcome, 'timeout');
      assert.equal(diagnostic.launcherObserved, true); assert.equal(diagnostic.authObserved, true);
      assert.equal(diagnostic.launcherJoined, true); assert.equal(diagnostic.authJoined, true); assert.equal(diagnostic.processAndPipesJoined, true);
      assert.equal(diagnostic.completeInputWriteJoined, true);
      assert(diagnostic.samples.length > 0 && diagnostic.samples.length <= 20);
      const sample = diagnostic.samples.find(value => value.process.kind === 'observed')!;
      assert(sample && sample.process.kind === 'observed');
      await assert.rejects(readFile(`/proc/${sample.process.pid}/stat`), { code: 'ENOENT' });
      assert.equal(scanner.stats().streamsOpened, 2); assert.equal(scanner.stats().streamsClosed, 2);
      assert.equal(scanner.stats().matched, false); assert(!JSON.stringify(diagnostic).includes('fixture-private-input'));
      assert.equal(diagnostic.work?.snapshots.at(-1)!.createCompare.started, 1);
      assert.equal(diagnostic.work?.snapshots.at(-1)!.createCompare.completed, 0);
      assert.equal(diagnostic.work?.snapshots.at(-1)!.package.bytesRead, 7);
    } finally { scanner.close(); await rm(fixture, { recursive: true, force: true }); }
  });

test('an actual enroll launcher spawn refusal cannot appear completed or leave scanner streams open',
  { skip: process.platform !== 'linux' ? 'requires actual Linux owned-command diagnostics' : false }, async () => {
    const scanner = createCredentialSecretScanner([Buffer.from('fixture-private-input')], { maxBytes: 1024 * 1024, maxStreams: 16 });
    const diagnostic = {} as InstalledEnrollDiagnostic;
    try {
      const result = await runOwnedEnrollDiagnostic({ command: { executable: '/not-an-enroll-fixture-command', args: [], cwd: os.tmpdir(), env: {} },
        input: Buffer.from('fixture-private-input'), uid: process.geteuid!(), bootstrapImage: process.execPath, installedImage: process.execPath,
        originalDeadlineMs: 1000, scanner, diagnostic });
      assert.equal(result.error?.code, 'ESPAWN'); assert.equal(diagnostic.outcome, 'spawn_failed');
      assert.equal(diagnostic.authObserved, false); assert.equal(diagnostic.authJoined, false);
      assert.equal(diagnostic.processAndPipesJoined, true); assert.equal(diagnostic.completeInputWriteJoined, false);
      assert.equal(scanner.stats().streamsOpened, 2); assert.equal(scanner.stats().streamsClosed, 2);
    } finally { scanner.close(); }
  });

test('real owned enroll stderr preserves raw output while retaining bounded fixed split phase observations only',
  { skip: process.platform !== 'linux' ? 'requires actual Linux owned process and scanned pipes; not credential qualification' : false }, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-enroll-phases-')));
    const scanner = createCredentialSecretScanner([Buffer.from('fixture-private-input')], { maxBytes: 1024 * 1024, maxStreams: 16 });
    try {
      const image = path.join(fixture, 'node'); await copyFile(process.execPath, image); await chmod(image, 0o500);
      const diagnostic = {} as InstalledEnrollDiagnostic;
      const first = 'unretained-status\n' + 'x'.repeat(200) + '\nCLIQ_INSTALLED_WORK_V1:credential:1:0:7:10:0:0:0:0:0:0:0:0\nCLIQ_CREDENTIAL_PHASE_V1:his';
      const last = 'tory\nCLIQ_INSTALLED_WORK_V1:credential:1:1:9:11:0:0:0:0:1:1:0:2\nCLIQ_CREDENTIAL_PHASE_V1:unknown\n' + 'CLIQ_CREDENTIAL_PHASE_V1:retire\n'.repeat(40);
      const result = await runOwnedEnrollDiagnostic({ command: { executable: image, args: ['-e',
        `const fs=require('node:fs');process.stdin.resume();process.stdin.once('end',()=>{fs.writeSync(2,${JSON.stringify(first)});setTimeout(()=>{fs.writeSync(2,${JSON.stringify(last)});fs.writeSync(1,'joined-output')},20)})`],
        cwd: fixture, env: {} }, input: Buffer.from('fixture-private-input'), uid: process.geteuid!(),
        bootstrapImage: image, installedImage: image, originalDeadlineMs: 2000, scanner, diagnostic });
      assert.equal(result.error, undefined); assert.equal(result.status, 0); assert.equal(result.signal, null);
      assert.equal(result.stdout, 'joined-output'); assert.equal(result.stderr, first + last);
      assert.equal(diagnostic.phases.length, 32);
      assert.equal(diagnostic.phases[0]!.phase, 'history'); assert(diagnostic.phases.slice(1).every(row => row.phase === 'retire'));
      assert(diagnostic.phases.every((row, index) => row.elapsedMs >= (diagnostic.phases[index - 1]?.elapsedMs ?? 0) && row.elapsedMs <= diagnostic.elapsedMs));
      assert.equal(diagnostic.authJoined, true); assert.equal(diagnostic.launcherJoined, true); assert.equal(diagnostic.processAndPipesJoined, true);
      assert(!JSON.stringify(diagnostic).includes('unretained-status')); assert(!JSON.stringify(diagnostic).includes('fixture-private-input'));
      assert.equal(scanner.stats().matched, false); assert.equal(scanner.stats().streamsOpened, scanner.stats().streamsClosed);
      assert.equal(diagnostic.work?.snapshots.at(-1)!.package.bytesRead, 9);
      assert.equal(diagnostic.work?.snapshots.at(-1)!.createCompare.completed, 1);
    } finally { scanner.close(); await rm(fixture, { recursive: true, force: true }); }
  });

test('secret output refusal still joins the actual original process and scan owners',
  { skip: process.platform !== 'linux' ? 'requires actual Linux process identities; not credential qualification' : false }, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-enroll-secret-')));
    const scanner = createCredentialSecretScanner([Buffer.from('fixture-private-input')], { maxBytes: 1024 * 1024, maxStreams: 16 });
    const diagnostic = {} as InstalledEnrollDiagnostic;
    try {
      const image = path.join(fixture, 'node'); await copyFile(process.execPath, image); await chmod(image, 0o500);
      await assert.rejects(runOwnedEnrollDiagnostic({ command: { executable: image,
        args: ['-e', 'process.stdin.on("data",chunk=>process.stdout.write(chunk)); setInterval(()=>{},1000)'], cwd: fixture, env: {} },
        input: Buffer.from('fixture-private-input'), uid: process.geteuid!(), bootstrapImage: image, installedImage: image,
        originalDeadlineMs: 2000, scanner, diagnostic }));
      assert.equal(scanner.stats().matched, true); assert.equal(diagnostic.outcome, 'observation_failed');
      assert.equal(diagnostic.authJoined, true); assert.equal(diagnostic.launcherJoined, true); assert.equal(diagnostic.processAndPipesJoined, true);
      assert.equal(scanner.stats().streamsOpened, 2); assert.equal(scanner.stats().streamsClosed, 2);
      assert(!JSON.stringify(diagnostic).includes('fixture-private-input'));
    } finally { scanner.close(); await rm(fixture, { recursive: true, force: true }); }
  });

test('a naturally exited original auth zombie is not a live foreign image and joins only after its real parent reaps it',
  { timeout: 15000, skip: process.platform !== 'linux' ? 'requires actual Linux natural exit and owned WNOWAIT/reap; not installed qualification' : false }, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-enroll-zombie-')));
    const scanner = createCredentialSecretScanner([Buffer.from('fixture-private-input')], { maxBytes: 1024 * 1024, maxStreams: 16 });
    const diagnostic = {} as InstalledEnrollDiagnostic, server = net.createServer();
    let control: net.Socket | undefined, controlJoined: Promise<unknown> | undefined;
    let completed: Promise<{ value: Awaited<ReturnType<typeof runOwnedEnrollDiagnostic>> } | { error: unknown }> | undefined;
    try {
      const launcher = await ownedFixture(fixture), image = path.join(fixture, 'node');
      await copyFile(process.execPath, image); await chmod(image, 0o500);
      const accepted = once(server, 'connection') as Promise<[net.Socket]>;
      const socketPath = path.join(fixture, 'control'); server.listen(socketPath); await once(server, 'listening');
      completed = runOwnedEnrollDiagnostic({ command: { executable: launcher,
        args: ['--enroll-natural-exit', image, socketPath], cwd: fixture, env: {} }, input: Buffer.from('fixture-private-input'),
        uid: process.geteuid!(), bootstrapImage: image, installedImage: image, originalDeadlineMs: 5000, scanner, diagnostic })
        .then(value => ({ value }), error => ({ error }));
      [control] = await joinedWithin(accepted, 5000); controlJoined = once(control, 'close');
      let message = '', oversized = false;
      control.on('data', bytes => { if (message.length + bytes.length > 128) oversized = true; else message += bytes.toString('ascii'); });
      const by = performance.now() + 5000;
      while (!message.endsWith('\n')) { assert(!oversized && performance.now() < by); await delay(5); }
      const live = /^LIVE ([1-9][0-9]*)\n$/u.exec(message); assert(live);
      const pid = Number(live[1]);
      while (!diagnostic.samples.some(sample => sample.process.kind === 'observed' && sample.process.pid === pid)) {
        assert(performance.now() < by); await delay(5);
      }
      control.write('e');
      while (message.split('\n').length < 3) { assert(!oversized && performance.now() < by); await delay(5); }
      assert.equal(message, `LIVE ${pid}\nZOMBIE ${pid}\n`);
      const original = await readFile(`/proc/${pid}/stat`, 'utf8');
      const fields = original.slice(original.lastIndexOf(')') + 2).trim().split(/\s+/u);
      assert.equal(fields[0], 'Z'); await assert.rejects(stat(`/proc/${pid}/exe`), { code: 'ENOENT' });
      assert(diagnostic.samples.some(sample => sample.process.kind === 'observed' && sample.process.pid === pid && sample.process.startTicks === fields[19]));
      // Wait for an actual later monitor sample of this still-unreaped child,
      // not a sleep that assumes the image check has executed. The old helper
      // instead records observation_failed at its live-image assertion.
      while (diagnostic.outcome === 'completed' && !diagnostic.samples.some(sample => sample.process.kind === 'unavailable')) {
        assert(performance.now() < by); await delay(5);
      }
      const beforeReap = await readFile(`/proc/${pid}/stat`, 'utf8');
      assert.equal(beforeReap.slice(beforeReap.lastIndexOf(')') + 2).trim().split(/\s+/u)[19], fields[19]);
      assert.equal(diagnostic.authJoined, false); assert.equal(diagnostic.processAndPipesJoined, false);
      control.end('r');
      const result = await joinedWithin(completed, 6000);
      if ('error' in result) throw result.error;
      assert.equal(result.value.status, 0); assert.equal(result.value.signal, null); assert.equal(result.value.error, undefined);
      assert.equal(result.value.stdout, 'joined-output'); assert.equal(result.value.stderr, '');
      assert.equal(diagnostic.outcome, 'completed'); assert.equal(diagnostic.authJoined, true);
      assert.equal(diagnostic.launcherJoined, true); assert.equal(diagnostic.processAndPipesJoined, true);
      assert.equal(diagnostic.completeInputWriteJoined, true);
      await assert.rejects(readFile(`/proc/${pid}/stat`), { code: 'ENOENT' });
      assert.equal(scanner.stats().matched, false); assert.equal(scanner.stats().streamsOpened, scanner.stats().streamsClosed);
    } finally {
      if (control && !control.destroyed) control.end('r');
      if (completed) await joinedWithin(completed, 11000);
      control?.destroy(); if (controlJoined) await controlJoined;
      if (server.listening) await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      scanner.close(); await rm(fixture, { recursive: true, force: true });
    }
  });

test('a still-live original auth that really execs a foreign image is rejected and fully joined',
  { timeout: 15000, skip: process.platform !== 'linux' ? 'requires actual Linux exec and original owned child identity; not installed qualification' : false }, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-enroll-foreign-')));
    const scanner = createCredentialSecretScanner([Buffer.from('fixture-private-input')], { maxBytes: 1024 * 1024, maxStreams: 16 });
    const diagnostic = {} as InstalledEnrollDiagnostic;
    try {
      const launcher = await ownedFixture(fixture), image = path.join(fixture, 'auth-image');
      await copyFile(launcher, image); await chmod(image, 0o500);
      await assert.rejects(runOwnedEnrollDiagnostic({ command: { executable: launcher,
        args: ['--enroll-live-foreign', image], cwd: fixture, env: {} }, input: Buffer.from('fixture-private-input'),
        uid: process.geteuid!(), bootstrapImage: image, installedImage: image, originalDeadlineMs: 5000, scanner, diagnostic }),
      error => error instanceof AggregateError && error.errors.some(value => value instanceof assert.AssertionError &&
        value.message === 'original owned auth executable image changed'));
      assert.equal(diagnostic.outcome, 'observation_failed'); assert.equal(diagnostic.authObserved, true);
      assert.equal(diagnostic.completeInputWriteJoined, true); assert.equal(diagnostic.authJoined, true);
      assert.equal(diagnostic.launcherJoined, true); assert.equal(diagnostic.processAndPipesJoined, true);
      assert.equal(scanner.stats().matched, false); assert.equal(scanner.stats().streamsOpened, scanner.stats().streamsClosed);
    } finally { scanner.close(); await rm(fixture, { recursive: true, force: true }); }
  });
