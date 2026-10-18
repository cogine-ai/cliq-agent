import assert from 'node:assert/strict';
import test from 'node:test';
import { chmod, copyFile, mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { decodeEnrollCredentialPhase, decodeEnrollProcessCounters, runOwnedEnrollDiagnostic, type InstalledEnrollDiagnostic } from './installed-enroll-diagnostic.js';
import { createCredentialSecretScanner } from './credential-secret-scan.js';

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
  const source = await readFile(new URL('../qualify-installed-verifier-journey.ts', import.meta.url), 'utf8');
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
      const result = await runOwnedEnrollDiagnostic({ command: { executable: image,
        args: ['-e', 'process.stdin.resume(); process.stdout.write("joined-output"); setInterval(()=>{},1000)'], cwd: fixture, env: {} },
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
      const first = 'unretained-status\n' + 'x'.repeat(200) + '\nCLIQ_CREDENTIAL_PHASE_V1:his';
      const last = 'tory\nCLIQ_CREDENTIAL_PHASE_V1:unknown\n' + 'CLIQ_CREDENTIAL_PHASE_V1:retire\n'.repeat(40);
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
