// A real signed install on the owned NSS account, the normal authenticated
// v1 control path and independent readonly observation of physical results.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { chown, lstat, mkdir, open, readdir, readFile, readlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { types } from 'node:util';
import { build } from 'esbuild';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { parseJsonStrict } from '../../src/kernel/json.js';
import { decodeMigrationAuthorityMarker } from '../../src/kernel/migration-control.js';
import { decodeOwnedLegacyImportResponse } from '../../src/kernel/migration-control-wire.js';
import { decodeKernelRollbackRestoringControl, decodeLegacyRollbackAuthAbsence, decodeLegacyRollbackReceipt,
  decodeOwnedKernelArchiveWitness, decodeRestoredAbsentLegacyGeneration } from '../../src/kernel/kernel-rollback-records.js';
import { decodeKernelRollbackArchiveReadyControl } from '../../src/kernel/kernel-rollback-handoff.js';
import type { StateOwnerRecordV1 } from '../../src/kernel/types.js';
import { decodeLegacyContextPayload } from '../../src/kernel/legacy-context.js';
import { CompleteKernelArchiveManifestStream } from '../../src/state/kernel-archive-manifest-stream.js';
import { KERNEL_AUTHORITY_TABLES } from '../../src/state/schema.js';
import { buildInstalledClientDriver } from './testing/installed-client-build.js';
import { InstalledClientConsumerDeadlineError, InstalledClientDriverError, openInstalledClientConsumer } from './testing/installed-client-consumer.js';
import { buildInstalledSupervisorPackage } from './testing/installed-supervisor-package.js';
import { createCredentialSecretScanner } from './testing/credential-secret-scan.js';
import { fixtureCommandJoinDiagnostic } from './testing/fixture-command-diagnostic.js';
import { readLedger, transferPackage } from './testing/installed-node-journey.js';
import { inspectInstalledOwnerHistory, type InstalledOwnerHistoryReadStage } from './testing/installed-read-control.js';
import { qualifyInstalledOwnerProcess } from './testing/installed-owner-history.js';

assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64'); assert.equal(process.geteuid!(), 0);
const [mode, filename, ...extra] = process.argv.slice(2);
assert(mode === '--migration-campaign' || mode === '--migration-live-legacy-campaign' ||
  mode === '--migration-archive-ready-crash-campaign' || mode === '--migration-restoring-crash-campaign');
assert(filename); assert.deepEqual(extra, []);
const busy = mode === '--migration-live-legacy-campaign';
const crashPhase = mode === '--migration-archive-ready-crash-campaign' ? 'rollback_archive_ready' :
  mode === '--migration-restoring-crash-campaign' ? 'rollback_restoring' : undefined;
const ledger = await readLedger(filename), recipe = ledger.runJourney;
const legacy = path.join(ledger.home, '.cliq'), sourceName = 'sessions/2026/01/02/source.json';
const source = path.join(legacy, sourceName), root = recipe.stateRoot;
assert.equal(root, path.join(legacy, 'kernel-v1'));
const markerFile = path.join(root, 'migration/authority-v1.json');
const rendezvous = path.join(legacy, '.cliq-generation-v1.json');
const auth = path.join(legacy, 'auth.json');
const content = 'owned old Session context';
const originalSource = canonicalJsonBytes({ version: 5, app: 'cliq', id: 'source', cwd: recipe.workspace,
  createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-02T00:00:00.000Z', model: {},
  lifecycle: { status: 'idle', turn: 0 }, records: [{ id: 'record', ts: '2026-01-01T00:00:00.000Z',
    kind: 'user', role: 'user', content }], checkpoints: [], compactions: [] });
const environment = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' };
const prefix = ['--user', ledger.username, '--', '/usr/bin/env', '-i', 'HOME=' + ledger.home, 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C',
  'XDG_RUNTIME_DIR=/run/user/' + ledger.uid, 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + ledger.uid + '/bus'];
const scanner = createCredentialSecretScanner([randomBytes(32)], { maxBytes: 16 * 1024 * 1024, maxStreams: 256 });
const scan = (bytes: Buffer) => { const scope = scanner.openStream(); try { scope.scan(bytes); } finally { scope.close(); } };
const driver = path.join(recipe.buildFixture, 'installed-control-client-driver.mjs');
let client: Awaited<ReturnType<typeof openInstalledClientConsumer>> | undefined;
let units: [string, string] | undefined;
let joinedClients = 0;
type CommandFailure = Readonly<{ exitStatus: number | null; spawnCode?: string; join?: ReturnType<typeof fixtureCommandJoinDiagnostic> }>;
const diagnostics: {
  failure?: ReturnType<typeof migrationFailure>;
  ownerReadStage?: InstalledOwnerHistoryReadStage;
  servicesBeforeStop?: ReturnType<typeof unitStatus>[];
  cleanupFailed?: true;
} = {};
let commandFailure: CommandFailure | undefined;
const knownCodes = ['ARTIFACT_MISMATCH', 'AUTHORIZATION_REQUIRED', 'INTERNAL', 'INVALID_REQUEST', 'LEASE_FENCED', 'RECOVERY_REQUIRED',
  'UNSUPPORTED_PLATFORM', 'ERR_ASSERTION', 'ERR_SQLITE_ERROR', 'ERR_CLIQ_RESOURCE_RETIREMENT',
  'EACCES', 'EPERM', 'ENOENT', 'EIO', 'ENOSPC', 'ECONNREFUSED', 'ECONNRESET', 'EPIPE', 'ETIMEDOUT'] as const;
function knownCode(value: unknown) {
  return knownCodes.find(code => code === value);
}
function ownData(value: unknown, key: string): unknown {
  if (!value || typeof value !== 'object' || types.isProxy(value)) return undefined;
  return Object.getOwnPropertyDescriptor(value, key)?.value;
}
function migrationFailure(phase: string, error: unknown, command?: CommandFailure, ownerReadStage?: InstalledOwnerHistoryReadStage) {
  const client = !types.isProxy(error) && (error instanceof InstalledClientConsumerDeadlineError || error instanceof InstalledClientDriverError)
    ? error.diagnostic : undefined;
  const code = knownCode(ownData(error, 'code'));
  const sqlite = ownData(error, 'errcode');
  const sqliteCode = code === 'ERR_SQLITE_ERROR' && typeof sqlite === 'number' && Number.isInteger(sqlite) && sqlite >= 0 && sqlite <= 65535
    ? sqlite : undefined;
  const source = client ? 'installed_client' : command ? 'same_user_command' : ownerReadStage ? 'owner_history' : 'qualification';
  return { phase, source, ...(client ? { client } : {}), ...(code ? { code } : {}),
    ...(sqliteCode === undefined ? {} : { sqliteCode }), ...(command ? { command } : {}) };
}
const report = { schemaVersion: 1, format: 'cliq-installed-migration-qualification-v1', diagnosticOnly: true,
  case: crashPhase ?? (busy ? 'actual_same_uid_open_legacy_source' : 'default_overlapping_root_import_restart_and_rollback'),
  phase: 'installation', qualified: false, authenticated: false, sameUidOpenLegacyRefused: false, importCompleted: false,
  importedSessionCount: 0, successorOwnerVerified: false, archiveVerified: false, finalOwnerVerified: false, kernelRestartRefused: false,
  allCrashCutsQualified: false, maximumFixtureQualified: false, runtimeWitnessQualified: false, typedGcQualified: false,
  archiveReadyCrashQualified: false, restoringCrashQualified: false, exactCrashSubphase: 'unobserved',
  macosQualified: false, completeI4Qualified: false, diagnostics };
const mark = (phase: string) => {
  report.phase = phase; commandFailure = undefined; delete diagnostics.ownerReadStage;
  console.log('Installed migration phase ' + phase);
};
const sameUser = (executable: string, args: readonly string[], milliseconds = 30000) => {
  const started = performance.now();
  const result = spawnSync('/usr/sbin/runuser', [...prefix, executable, ...args],
    { cwd: ledger.home, env: environment, timeout: milliseconds, killSignal: 'SIGKILL', maxBuffer: 2 * 1024 * 1024 });
  const join = fixtureCommandJoinDiagnostic(result, milliseconds, started);
  if (join) {
    const spawnCode = knownCode(ownData(result.error, 'code'));
    commandFailure = { exitStatus: result.status, ...(spawnCode ? { spawnCode } : {}), join };
  }
  assert(Buffer.isBuffer(result.stdout) && Buffer.isBuffer(result.stderr)); scan(result.stdout); scan(result.stderr);
  assert.equal(result.error, undefined); assert.equal(result.signal, null);
  return { status: result.status, stdout: result.stdout };
};
const command = (executable: string, args: readonly string[], milliseconds?: number) => {
  const result = sameUser(executable, args, milliseconds);
  if (result.status !== 0) commandFailure = { exitStatus: result.status };
  assert.equal(result.status, 0, 'owned signed installation or manager command refused');
  return result.stdout;
};
const systemctl = (args: readonly string[]) => command('/usr/bin/systemctl', ['--user', ...args]);
const show = (unit: string) => Object.fromEntries(systemctl(['show', unit,
  '--property=ActiveState,MainPID,ExecMainPID,InvocationID,Result,ExecMainCode,ExecMainStatus,TimeoutStopUSec', '--no-pager'])
  .toString('utf8').trim().split('\n').map(line => { const at = line.indexOf('='); assert(at > 0); return [line.slice(0, at), line.slice(at + 1)]; }));
function startupJournal(shown: Record<string, string>) {
  const pid = shown.ExecMainPID, invocation = shown.InvocationID;
  if (!pid || !/^[1-9][0-9]{0,9}$/u.test(pid) || !invocation || !/^[a-f0-9]{32}$/u.test(invocation)) return undefined;
  try {
    const result = spawnSync('/usr/bin/journalctl', ['--boot=0', '--no-pager', '--output=json', '--lines=16',
      '_UID=' + ledger.uid, '_PID=' + pid, '_SYSTEMD_INVOCATION_ID=' + invocation, '_TRANSPORT=stdout'],
    { env: environment, timeout: 5000, killSignal: 'SIGKILL', maxBuffer: 256 * 1024 });
    assert(Buffer.isBuffer(result.stdout) && Buffer.isBuffer(result.stderr)); scan(result.stdout); scan(result.stderr);
    if (result.error || result.signal !== null || result.status !== 0) return undefined;
    for (const line of result.stdout.toString('utf8').trim().split('\n').reverse()) {
      try {
        const row = parseJsonStrict(line) as Record<string, unknown>;
        if (row?._UID !== String(ledger.uid) || row._PID !== pid || row._SYSTEMD_INVOCATION_ID !== invocation ||
            row._TRANSPORT !== 'stdout' || typeof row.MESSAGE !== 'string') continue;
        const data = parseJsonStrict(row.MESSAGE) as Record<string, unknown>;
        if (data?.diagnosticOnly !== true || data.scope !== 'installed-read-startup') continue;
        return { reportSeen: true, code: knownCode(data.code) ?? 'unclassified' };
      } catch { /* Unrecognized lines are never retained. */ }
    }
  } catch { /* Optional observation cannot replace the original failure. */ }
}
function unitStatus(role: 'supervisor' | 'keeper', shown: Record<string, string>) {
  const active = ['active', 'inactive', 'activating', 'deactivating', 'failed'].find(value => value === shown.ActiveState) ?? 'unknown';
  const result = ['success', 'resources', 'protocol', 'timeout', 'exit-code', 'signal', 'core-dump', 'watchdog', 'start-limit-hit', 'oom-kill']
    .find(value => value === shown.Result) ?? 'unknown';
  const mainCode = /^[0-6]$/u.test(shown.ExecMainCode ?? '') ? Number(shown.ExecMainCode) : null;
  const mainStatus = /^[0-9]{1,3}$/u.test(shown.ExecMainStatus ?? '') ? Number(shown.ExecMainStatus) : null;
  const startup = startupJournal(shown);
  return { role, active, result, mainCode, mainStatus, hasMainProcess: /^[1-9][0-9]*$/u.test(shown.MainPID ?? ''),
    ...(startup ? { startup } : {}) };
}
function readOwnerHistory() {
  return inspectInstalledOwnerHistory(root, stage => { diagnostics.ownerReadStage = stage; });
}
const metadata = ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const;
const sameFile = (before: BigIntStats, after: BigIntStats) => {
  for (const field of metadata) assert.equal(after[field], before[field]);
};
async function readExact(filename: string, mode: bigint, sizeLimit: number, consume: (bytes: Buffer) => void) {
  const before = await lstat(filename, { bigint: true });
  assert(before.isFile() && before.uid === BigInt(ledger.uid) && before.gid === BigInt(ledger.gid) &&
    before.nlink === 1n && (before.mode & 0o7777n) === mode && before.size <= BigInt(sizeLimit));
  const held = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const hash = createHash('sha256');
  try {
    sameFile(before, await held.stat({ bigint: true }));
    const chunk = Buffer.allocUnsafe(65536); let offset = 0;
    while (offset < Number(before.size)) {
      const { bytesRead } = await held.read(chunk, 0, Math.min(chunk.length, Number(before.size) - offset), offset);
      assert(bytesRead > 0); const bytes = chunk.subarray(0, bytesRead);
      hash.update(bytes); consume(bytes); offset += bytesRead;
    }
    assert.equal((await held.read(chunk, 0, 1, offset)).bytesRead, 0);
    sameFile(before, await held.stat({ bigint: true })); sameFile(before, await lstat(filename, { bigint: true }));
  } finally { await held.close(); }
  return { info: before, sha256: hash.digest('hex') };
}
async function smallFile(filename: string, mode: bigint, expected?: string) {
  const chunks: Buffer[] = [];
  const current = await readExact(filename, mode, 1_048_576, bytes => chunks.push(Buffer.from(bytes)));
  if (expected !== undefined) assert.equal(current.sha256, expected);
  return Buffer.concat(chunks);
}
async function sourceUnchanged(original: BigIntStats) {
  const bytes = await smallFile(source, 0o600n); assert(bytes.equals(originalSource));
  sameFile(original, await lstat(source, { bigint: true }));
}
async function absent(filename: string) { await assert.rejects(lstat(filename), { code: 'ENOENT' }); }
function document(bytes: Buffer): unknown {
  const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  assert(canonicalJsonBytes(value).equals(bytes)); return value;
}
function tail(ref: string) {
  assert.match(ref, /^[0-9a-f]{64}$/u);
  return smallFile(path.join(root, 'migration/artifacts/sha256', ref.slice(0, 2), ref), 0o400n, ref);
}
async function connect(kind: 'initial' | 'after_refusal' | 'successor') {
  mark(kind + '_client_hello');
  const active = await openInstalledClientConsumer({ executable: '/usr/sbin/runuser',
    args: [...prefix, process.execPath, '--disable-warning=ExperimentalWarning', driver, filename!, '--schema3'],
    cwd: ledger.home, env: environment, headlessSchemaVersion: 3, coldHello: 'migration',
    openScan: () => scanner.openStream(), onJoined: () => { joinedClients++; } });
  client = active;
  mark(kind + '_migration_features');
  assert(Array.isArray(active.hello.enabledFeatureIds));
  for (const method of ['state.migrate', 'state.rollback'])
    assert(active.hello.enabledFeatureIds.includes(method), 'actual signed Supervisor must advertise complete ' + method + ' composition');
  report.authenticated = true; return active;
}
async function joined(pending: Promise<void>, milliseconds: number) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { await Promise.race([pending, new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('owned Legacy descriptor process did not join')), milliseconds);
  })]); } finally { clearTimeout(timer); }
}

async function observeRollbackCut(input: { phase: NonNullable<typeof crashPhase>; pid: number; selected: string;
  owner: StateOwnerRecordV1; kernelMarker: Buffer; migrationId: string }) {
  const source = { stateRoot: root, uid: ledger.uid, pid: input.pid, selectedImage: input.selected, imageDigest: input.owner.supervisorExecutableDigest };
  const processIdentity = await qualifyInstalledOwnerProcess(source, input.owner, {});
  const start = /^linux-proc-start-ticks:([1-9][0-9]{0,19})$/u.exec(processIdentity.processStartToken); assert(start);
  const image = await lstat(input.selected, { bigint: true });
  const child = spawn(recipe.publicationObserver, [root, String(input.pid), start[1]!, String(ledger.uid), source.imageDigest,
    String(image.dev), String(image.ino), String(image.size), '--rollback-cut', input.phase,
    createHash('sha256').update(input.kernelMarker).digest('hex')], { cwd: ledger.home, env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
  const readyLine = 'migration_rollback_cut_ready\n';
  let output = '', errors = 0, failure: unknown, isArmed = false, resolveReady!: () => void, rejectReady!: (error: unknown) => void;
  const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  const refuse = (error: unknown) => {
    failure ??= error; rejectReady(error);
    if (!child.stdin.destroyed && !child.stdin.writableEnded) child.stdin.end();
  };
  for (const pipe of [child.stdin, child.stdout, child.stderr]) pipe.on('error', refuse);
  child.on('error', refuse);
  child.stdout.on('data', (bytes: Buffer) => {
    try {
      scan(bytes);
      assert(bytes.every(byte => byte < 128) && output.length + bytes.length <= 256);
      output += bytes.toString('ascii');
      assert(output.startsWith(readyLine) || readyLine.startsWith(output));
      assert(isArmed || output.length <= readyLine.length);
      if (output.length >= readyLine.length) resolveReady();
    } catch (error) { refuse(error); }
  });
  child.stderr.on('data', (bytes: Buffer) => {
    try { scan(bytes); errors += bytes.length; assert(errors <= 256); } catch (error) { refuse(error); }
  });
  let result: Readonly<{ phase: NonNullable<typeof crashPhase>; controlRef: string; authPresent: boolean;
    authDevice: string; authFile: string; legacyStillKernel: boolean; observedDeathAt: number }> | undefined;
  const actorJoined = new Promise<void>((resolve, reject) => {
    child.once('close', (status, signal) => {
      try {
        if (failure !== undefined) throw failure;
        assert.equal(status, 0, 'the original phase was not positively retained across actual Supervisor death');
        assert.equal(signal, null); assert.equal(errors, 0); assert(output.startsWith(readyLine));
        const values = /^migration_rollback_cut_v1 (rollback_archive_ready|rollback_restoring) ([0-9a-f]{64}) ([01]) (0|[1-9][0-9]{0,19}) (0|[1-9][0-9]{0,19}) ([01]) ([1-9][0-9]{0,15})\n$/u
          .exec(output.slice(readyLine.length));
        assert(values); assert.equal(values[1], input.phase);
        assert(values[3] === '1' ? values[5] !== '0' : values[4] === '0' && values[5] === '0');
        const observedDeathAt = Number(values[7]); assert(Number.isSafeInteger(observedDeathAt));
        result = Object.freeze({ phase: input.phase, controlRef: values[2]!, authPresent: values[3] === '1',
          authDevice: values[4]!, authFile: values[5]!, legacyStillKernel: values[6] === '1', observedDeathAt });
        resolve();
      } catch (error) { rejectReady(error); reject(error); }
    });
  });
  void ready.catch(() => {}); void actorJoined.catch(() => {});
  try {
    await joined(ready, 30000);
    isArmed = true;
    await new Promise<void>((resolve, reject) => child.stdin.write('rollback\n', error => error ? reject(error) : resolve()));
    const wallBefore = Date.now();
    const interrupted = sameUser(input.selected, ['state', 'rollback', '--to-legacy', input.migrationId]);
    assert.equal(interrupted.status, 1, 'an interrupted original signed command cannot return rollback success');
    await joined(actorJoined, 30000); assert(result);
    assert(result.observedDeathAt >= wallBefore && result.observedDeathAt <= Date.now());
    return result;
  } catch (error) {
    if (!child.stdin.destroyed && !child.stdin.writableEnded) child.stdin.end();
    try { await joined(actorJoined, 30000); } catch (retirement) { throw new AggregateError([error, retirement]); }
    throw error;
  }
}

async function requireBusyRefusal(selected: string) {
  // Ordinary Node execution holds a real original no-follow Legacy file.
  // Neither process suspension nor a migration fixture hook is involved.
  const child = spawn('/usr/sbin/runuser', [...prefix, process.execPath, '-e', [
    "const fs = require('node:fs');",
    'const fd = fs.openSync(process.argv[1], fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);',
    'process.stdout.write(JSON.stringify({pid: process.pid, fd}) + "\\n");',
    "process.stdin.once('end', () => fs.closeSync(fd)); process.stdin.resume();"
  ].join('\n'), source], { cwd: ledger.home, env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
  const exit = new Promise<void>((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (status, signal) => { if (status === 0 && signal === null) resolve(); else reject(new Error('owned Legacy reader failed')); });
  });
  void exit.catch(() => {});
  child.stdin.on('error', () => {});
  let output = '', errors = 0, pid = 0, fd = -1, failure: unknown;
  const ready = new Promise<void>((resolve, reject) => {
    child.once('error', reject); child.once('close', () => reject(new Error('owned Legacy reader closed before observation')));
    child.stdout.on('data', (bytes: Buffer) => {
      try {
        output += bytes.toString('ascii'); assert(output.length <= 128);
        if (!output.endsWith('\n')) return;
        const value = parseJsonStrict(output.trim()) as { pid: number; fd: number };
        assert.deepEqual(Object.keys(value).sort(), ['fd', 'pid']);
        assert(Number.isSafeInteger(value.pid) && value.pid > 0 && Number.isSafeInteger(value.fd) && value.fd > 2);
        ({ pid, fd } = value); resolve();
      } catch (error) { reject(error); }
    });
  });
  child.stderr.on('data', (bytes: Buffer) => { errors += bytes.length; });
  try {
    await joined(ready, 5000);
    const proc = '/proc/' + pid, original = await lstat(source, { bigint: true });
    const verifyHolder = async () => {
      const status = await readFile(path.join(proc, 'status'), 'utf8'); assert(status.length <= 65536);
      const ids = status.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu);
      assert(ids && ids.slice(1).every(value => Number(value) === ledger.uid));
      const descriptor = await open(path.join(proc, 'fd', String(fd)), constants.O_RDONLY | constants.O_NONBLOCK);
      try { sameFile(original, await descriptor.stat({ bigint: true })); } finally { await descriptor.close(); }
    };
    await verifyHolder();
    const refusal = sameUser(selected, ['state', 'migrate']);
    assert.equal(refusal.status, 1);
    assert.deepEqual(parseJsonStrict(refusal.stdout.toString('utf8').trim()), {
      schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'migration.legacy_quiescence_required'
    });
    await verifyHolder();
    await absent(markerFile); await absent(auth); await sourceUnchanged(original);
    assert.equal(errors, 0);
  } catch (error) { failure = error; }
  finally {
    child.stdin.end();
    try { await joined(exit, 10000); }
    catch (error) { failure = failure === undefined ? error : new AggregateError([failure, error]); }
  }
  if (failure !== undefined) throw failure;
  await absent('/proc/' + pid);
  report.sameUidOpenLegacyRefused = true;
}

async function directoryIdentity(filename: string) {
  const current = await lstat(filename, { bigint: true });
  assert(current.isDirectory() && current.uid === BigInt(ledger.uid) && current.gid === BigInt(ledger.gid) &&
    (current.mode & 0o7777n) === 0o700n);
  return { deviceId: String(current.dev), fileId: String(current.ino), ownerUid: ledger.uid };
}
async function verifyArchive(ref: string, digest: string, migrationId: string, originalOwnerEpoch: number) {
  const witness = decodeOwnedKernelArchiveWitness(document(await tail(ref)));
  assert.equal(witness.witnessDigest, digest); assert.equal(witness.migrationId, migrationId);
  assert.equal(witness.ownerEpoch, originalOwnerEpoch);
  const collection = path.join(root, 'migration/kernel-archives'), archive = path.join(collection, witness.archiveId);
  assert.deepEqual(await directoryIdentity(collection), witness.archiveCollection);
  assert.deepEqual(await directoryIdentity(archive), witness.archiveDirectory);
  const reader = new CompleteKernelArchiveManifestStream({ byteCount: witness.manifestByteCount, sha256: witness.manifestSha256 });
  const names: ReturnType<typeof reader.feed>[number][] = [];
  const manifest = await readExact(path.join(archive, 'manifest-v1.json'), 0o400n, witness.manifestByteCount, chunk => {
    names.push(...reader.feed(chunk));
    assert(names.length <= 8192, 'small qualification fixture unexpectedly exceeded its complete CAS member bound');
  });
  const header = reader.finish();
  assert.equal(String(manifest.info.dev), witness.manifestFile.deviceId);
  assert.equal(String(manifest.info.ino), witness.manifestFile.fileId);
  assert.equal(header.manifestDigest, witness.manifestDigest);
  assert.deepEqual(header.archiveDirectory, witness.archiveDirectory);
  assert.equal(header.control.archiveId, witness.archiveId);
  assert.equal(header.control.migrationId, witness.migrationId);
  assert.equal(header.control.controlDigest, witness.drainingControlDigest);
  assert.equal(header.localModelStore.kind, 'absent'); assert.equal(header.localInferenceRuntime.kind, 'absent');
  assert.deepEqual((await readdir(archive)).sort(), ['cas', 'kernel.sqlite3', 'manifest-v1.json']);
  const sourceCas = path.join(root, 'cas'), archivedCas = path.join(archive, 'cas');
  assert.deepEqual(await directoryIdentity(sourceCas), header.cas.sourceDirectory);
  assert.deepEqual(await directoryIdentity(archivedCas), header.cas.archiveDirectory);
  assert(names.length > 0); assert.equal(names.length, header.cas.entryCount);
  const only = names.map(entry => entry.name);
  assert.deepEqual((await readdir(sourceCas)).sort(), only); assert.deepEqual((await readdir(archivedCas)).sort(), only);
  for (const item of names) {
    const original = await readExact(path.join(sourceCas, item.name), BigInt(item.sourceMode), item.byteCount, () => {});
    const copied = await readExact(path.join(archivedCas, item.name), 0o400n, item.byteCount, () => {});
    assert.equal(original.info.size, BigInt(item.byteCount)); assert.equal(copied.info.size, original.info.size);
    assert.equal(original.sha256, item.sha256); assert.equal(copied.sha256, item.sha256);
    assert.equal(String(original.info.ino), item.sourceFileId); assert.equal(String(copied.info.ino), item.archiveFileId);
    assert.notEqual(original.info.ino, copied.info.ino);
  }
  const archiveDb = path.join(archive, 'kernel.sqlite3');
  const copied = await readExact(archiveDb, 0o400n, header.database.byteCount, () => {});
  assert.equal(copied.info.size, BigInt(header.database.byteCount)); assert.equal(copied.sha256, header.database.sha256);
  assert.equal(String(copied.info.ino), header.database.file.fileId);
  assert.notEqual(copied.info.ino, (await lstat(path.join(root, 'kernel.sqlite3'), { bigint: true })).ino);
  const database = new DatabaseSync(archiveDb, { readOnly: true, allowExtension: false });
  try {
    assert.equal(database.prepare('PRAGMA user_version').get()?.user_version, 8);
    assert.deepEqual(database.prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name").all().map(row => row.name),
      [...KERNEL_AUTHORITY_TABLES].sort());
    assert.equal(database.prepare("SELECT count(*) AS count FROM sessions WHERE id = 'source'").get()?.count, 1);
    assert.equal(database.prepare('SELECT count(*) AS count FROM runs').get()?.count, 0);
  } finally { database.close(); }
  sameFile(copied.info, await lstat(archiveDb, { bigint: true }));
  const archived = inspectInstalledOwnerHistory(archive).owners;
  assert.equal(archived.at(-1)?.ownerEpoch, originalOwnerEpoch); assert.equal(archived.at(-1)?.state, 'active');
  report.archiveVerified = true;
}

let failure: unknown;
try {
  mark('signed_package');
  await mkdir(recipe.buildFixture, { mode: 0o755 });
  const signed = await buildInstalledSupervisorPackage(recipe.buildFixture, 'complete', undefined, { headlessSchemaVersion: 3 });
  const installer = await build({ entryPoints: [fileURLToPath(new URL('./testing/installed-runtime-installer.ts', import.meta.url))],
    outfile: recipe.installerEntry, bundle: true, platform: 'node', format: 'esm', target: 'node22.13', metafile: true, write: false });
  assert(Object.values(installer.metafile!.outputs).flatMap(value => value.imports).every(value => value.external && value.path.startsWith('node:')));
  assert.equal(installer.outputFiles!.length, 1);
  await writeFile(recipe.installerEntry, installer.outputFiles![0]!.contents, { flag: 'wx', mode: 0o444 });
  await writeFile(driver, await buildInstalledClientDriver(driver), { flag: 'wx', mode: 0o444 });
  await writeFile(recipe.releaseKeysFile, canonicalJsonBytes(signed.releaseKeys), { flag: 'wx', mode: 0o444 });
  await transferPackage(recipe.packageRoot, ledger.uid, ledger.gid);
  for (const name of ['', 'sessions', 'sessions/2026', 'sessions/2026/01', 'sessions/2026/01/02']) {
    const directory = path.join(legacy, name); await mkdir(directory, { mode: 0o700 }); await chown(directory, ledger.uid, ledger.gid);
  }
  await writeFile(source, originalSource, { flag: 'wx', mode: 0o600 }); await chown(source, ledger.uid, ledger.gid);
  const original = await lstat(source, { bigint: true });
  mark('physical_installation');
  const installed = parseJsonStrict(command(process.execPath, [recipe.installerEntry, recipe.packageRoot, root, recipe.releaseKeysFile])
    .toString('utf8').trim()) as { bundleDigest: string };
  assert.equal(installed.bundleDigest, canonicalSha256(signed.bundle));
  mark('install_signed_services');
  const setup = parseJsonStrict(command(path.join(root, 'runtime/bootstrap'), ['--bootstrap-credential',
    canonicalJsonBytes({ schemaVersion: 1, kind: 'install_services' }).toString('base64url')], 60000).toString('utf8').trim()) as
    { schemaVersion: number; supervisorUnit: string; keeperUnit: string };
  assert.deepEqual(Object.keys(setup).sort(), ['keeperUnit', 'schemaVersion', 'supervisorUnit']); assert.equal(setup.schemaVersion, 1);
  assert([setup.supervisorUnit, setup.keeperUnit].every(unit => /^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,240}\.service$/u.test(unit)));
  units = [setup.supervisorUnit, setup.keeperUnit];
  const [supervisor, keeper] = units;
  mark('start_signed_keeper');
  systemctl(['start', keeper]);
  mark('start_signed_supervisor');
  systemctl(['start', supervisor]);
  const selected = path.join(root, 'runtime/bundles', installed.bundleDigest, 'supervisor');
  const verifyRunning = async () => {
    const service = show(supervisor);
    assert.equal(service.ActiveState, 'active'); assert.equal(service.MainPID, service.ExecMainPID);
    assert.match(service.MainPID!, /^[1-9][0-9]*$/u); assert.match(service.InvocationID!, /^[0-9a-f]{32}$/u);
    assert.equal(service.TimeoutStopUSec, '2s'); assert.equal(await readlink('/proc/' + service.MainPID + '/exe'), selected);
    return service;
  };
  const active = await connect('initial');
  mark('initial_supervisor_process');
  const first = await verifyRunning();
  mark('initial_owner_history');
  const before = readOwnerHistory().owners;
  assert.equal(before.length, 1); assert.equal(before[0]!.state, 'active');
  assert.equal(before[0]!.runtimeBundleRef, installed.bundleDigest); assert.equal(before[0]!.supervisorInstanceId, active.supervisorInstanceId);
  await active.close(); client = undefined;
  await absent(markerFile); await absent(auth); await absent(rendezvous);
  if (busy) {
    mark('real_same_uid_open_legacy_descriptor');
    await requireBusyRefusal(selected);
    await absent(path.join(root, 'migration/control-v1.json')); await absent(rendezvous);
    // The rejected cut retires its actual EX and reopens the same original
    // Store. A new Owner or an unavailable service could mask a fence leak.
    const afterRefusal = await connect('after_refusal');
    assert.equal(afterRefusal.supervisorInstanceId, active.supervisorInstanceId);
    await afterRefusal.close(); client = undefined;
    mark('original_same_store_import_after_legacy_reader_retired');
    const admitted = decodeOwnedLegacyImportResponse(parseJsonStrict(command(selected, ['state', 'migrate']).toString('utf8').trim()));
    const marker = decodeMigrationAuthorityMarker(document(await smallFile(markerFile, 0o600n)));
    assert.equal(marker.authority, 'kernel'); assert.equal(marker.migrationId, admitted.migrationId);
    assert.equal(marker.receiptRef, admitted.receiptRef); assert.equal(marker.receiptDigest, admitted.receiptDigest);
    assert.equal(inspectInstalledOwnerHistory(root).owners.at(-1)?.supervisorInstanceId, active.supervisorInstanceId);
    report.importCompleted = true;
  } else {
    mark('authenticated_import');
    const imported = decodeOwnedLegacyImportResponse(parseJsonStrict(command(selected, ['state', 'migrate']).toString('utf8').trim()));
    const { migrationId } = imported;
    const kernelMarker = await smallFile(markerFile, 0o600n);
    assert(kernelMarker.equals(await smallFile(rendezvous, 0o600n)));
    const kernel = decodeMigrationAuthorityMarker(document(kernelMarker));
    assert.equal(kernel.authority, 'kernel'); assert.equal(kernel.migrationId, migrationId);
    assert.equal(kernel.receiptRef, imported.receiptRef); assert.equal(kernel.receiptDigest, imported.receiptDigest);
    const migratedAuth = document(await smallFile(auth, 0o600n)) as { format: string; migrationId: string };
    assert.equal(migratedAuth.format, 'cliq-auth-migrated-v1'); assert.equal(migratedAuth.migrationId, migrationId);
    const backup = path.join(root, 'migration/owned-import', migrationId, 'backup');
    assert((await smallFile(path.join(backup, sourceName), 0o400n)).equals(originalSource));
    assert.deepEqual(await readdir(backup), ['sessions']);
    await sourceUnchanged(original);
    report.importCompleted = true;

    mark('restart_and_read_imported_context');
    systemctl(['restart', supervisor]);
    const successor = await connect('successor');
    mark('successor_supervisor_process');
    const second = await verifyRunning();
    assert.notEqual(second.MainPID, first.MainPID); assert.notEqual(second.InvocationID, first.InvocationID);
    await absent('/proc/' + first.MainPID);
    mark('successor_owner_history');
    const after = readOwnerHistory().owners;
    assert.equal(after.length, 2);
    assert.equal(after[0]!.state, 'terminal'); assert.equal(after[0]!.terminalReason, 'graceful_release');
    assert.equal(after[0]!.supervisorInstanceId, active.supervisorInstanceId);
    assert.equal(after[1]!.state, 'active'); assert.equal(after[1]!.supervisorInstanceId, successor.supervisorInstanceId);
    const session = await successor.send({ protocolVersion: 1, method: 'session.get', sessionId: 'source' });
    assert.equal(session.ok, true); assert(session.result);
    assert.equal(session.result.snapshot.session.id, 'source');
    assert.equal(session.result.highWaterItemSeq, 1); assert.equal(session.result.nextItemSeq, 1);
    const items = session.result.items; assert(Array.isArray(items)); assert.equal(items.length, 1);
    assert.match(items[0].payloadRef, /^[0-9a-f]{64}$/u);
    const payload = decodeLegacyContextPayload(document(await smallFile(path.join(root, 'cas', items[0].payloadRef), 0o400n, items[0].payloadRef)));
    assert.equal(payload.legacySessionId, 'source'); assert.equal(payload.sourceCanonicalRootRelativePath, sourceName);
    assert(payload.kind === 'legacy_record');
    assert.equal(payload.content.recordKind, 'user'); assert.equal(payload.content.contentUtf8, content);
    report.importedSessionCount = 1; report.successorOwnerVerified = true;
    await successor.close(); client = undefined;

    mark(crashPhase ?? 'authenticated_rollback');
    const cut = crashPhase ? await observeRollbackCut({ phase: crashPhase, pid: Number(second.MainPID), selected,
      owner: after[1]!, kernelMarker, migrationId }) : undefined;
    type RollbackResponse = { method: string; requestId: string; receiptRef: string; receipt: unknown };
    let response: RollbackResponse | undefined;
    let restoredMarker: Buffer;
    if (cut) {
      mark('actual_fenced_successor_rollback');
      const by = cut.observedDeathAt + 30000;
      for (;;) {
        assert(Date.now() < by, 'the original 30-second restart budget expired before actual Legacy authority');
        const observed = await smallFile(markerFile, 0o600n);
        const marker = decodeMigrationAuthorityMarker(document(observed));
        if (marker.authority === 'legacy') {
          assert(Date.now() < by); restoredMarker = observed; break;
        }
        assert(observed.equals(kernelMarker)); await delay(20);
      }
    } else {
      response = parseJsonStrict(command(selected, ['state', 'rollback', '--to-legacy', migrationId]).toString('utf8').trim()) as RollbackResponse;
      assert(response); assert.deepEqual(Object.keys(response).sort(), ['method', 'receipt', 'receiptRef', 'requestId']);
      assert.equal(response.method, 'state.rollback'); assert.match(response.requestId, /^[0-9a-f-]{36}$/u);
      restoredMarker = await smallFile(markerFile, 0o600n);
    }
    assert(restoredMarker.equals(await smallFile(rendezvous, 0o600n)));
    const restored = decodeMigrationAuthorityMarker(document(restoredMarker));
    assert.equal(restored.authority, 'legacy'); assert.equal(restored.migrationId, migrationId);
    const receipt = decodeLegacyRollbackReceipt(document(await tail(restored.receiptRef)));
    assert.equal(restored.receiptDigest, receipt.receiptDigest);
    if (response) { assert.equal(restored.receiptRef, response.receiptRef); assert.deepEqual(decodeLegacyRollbackReceipt(response.receipt), receipt); }
    const finalControl = decodeKernelRollbackRestoringControl(document(await smallFile(path.join(root, 'migration/control-v1.json'), 0o600n)));
    assert.equal(finalControl.preparedReceiptRef, restored.receiptRef); assert.equal(finalControl.preparedReceiptDigest, receipt.receiptDigest);
    assert.equal(finalControl.archivedKernelGenerationRef, receipt.archivedKernelGenerationRef);
    const generation = decodeRestoredAbsentLegacyGeneration(document(await tail(receipt.legacyGenerationRef)));
    const authEvidence = decodeLegacyRollbackAuthAbsence(document(await tail(generation.restoredAuthObservationRef)));
    assert.equal(generation.manifestDigest, receipt.legacyGenerationDigest);
    assert.equal(authEvidence.observationDigest, generation.restoredAuthObservationDigest);
    assert.equal(authEvidence.inspectorOwnerEpoch, finalControl.preparerOwnerEpoch);
    if (cut?.phase === 'rollback_archive_ready') {
      assert.equal(cut.legacyStillKernel, true); assert.equal(finalControl.archiveReadyControlRef, cut.controlRef);
      const durable = decodeKernelRollbackArchiveReadyControl(document(await tail(cut.controlRef)));
      assert.equal(durable.controlDigest, finalControl.archiveReadyControlDigest);
      assert.equal(durable.archivedKernelGenerationRef, receipt.archivedKernelGenerationRef);
      if (cut.authPresent) {
        assert.equal(durable.originalAuthMarkerFile.deviceId, cut.authDevice);
        assert.equal(durable.originalAuthMarkerFile.fileId, cut.authFile);
      }
      assert.equal(authEvidence.observation, cut.authPresent ? 'exact_marker_removed_and_directory_synced' :
        'original_intent_current_absence_and_directory_synced');
    } else if (cut) {
      assert.equal(cut.authPresent, false);
      assert.equal(canonicalSha256(finalControl), cut.controlRef);
      assert.deepEqual(decodeKernelRollbackRestoringControl(document(await tail(cut.controlRef))), finalControl);
    }
    await absent(auth); await sourceUnchanged(original);
    await verifyArchive(receipt.archivedKernelGenerationRef, receipt.archivedKernelGenerationDigest, migrationId, after[1]!.ownerEpoch);
    const terminal = inspectInstalledOwnerHistory(root);
    assert.equal(terminal.owners.length, cut ? 3 : 2); assert.deepEqual(terminal.owners[0], after[0]);
    const last = terminal.owners.at(-1)!;
    assert.equal(last.state, 'terminal'); assert.equal(last.terminalReason, 'graceful_release');
    // The marker's bytes are prepared before the real final SQL release.
    // The still-Kernel Root observation at the killed cut is the physical
    // ordering check, distinct from the marker's literal time field.
    assert(restored.publishedAt <= last.releasedAt);
    if (cut) {
      const predecessor = terminal.owners[1]!;
      assert.equal(predecessor.state, 'terminal'); assert.equal(predecessor.supervisorInstanceId, after[1]!.supervisorInstanceId);
      assert.notEqual(last.supervisorInstanceId, predecessor.supervisorInstanceId);
      if (cut.phase === 'rollback_archive_ready') {
        assert.equal(predecessor.terminalReason, 'superseded_after_owner_death');
        assert.equal(finalControl.preparerOwnerEpoch, last.ownerEpoch);
        report.exactCrashSubphase = cut.authPresent ? 'archive_ready_original_auth_marker_still_present' : 'archive_ready_after_auth_marker_absence';
        report.archiveReadyCrashQualified = true;
      } else {
        assert.equal(finalControl.preparerOwnerEpoch, predecessor.ownerEpoch);
        if (!cut.legacyStillKernel) assert.equal(predecessor.terminalReason, 'graceful_release');
        report.exactCrashSubphase = predecessor.terminalReason === 'graceful_release' ?
          (cut.legacyStillKernel ? 'restoring_after_last_sql_before_legacy_marker' : 'restoring_after_legacy_before_root_marker') :
          'restoring_before_last_sql';
        report.restoringCrashQualified = true;
      }
    } else assert.equal(last.supervisorInstanceId, after[1]!.supervisorInstanceId);
    assert.equal(joinedClients, 2); report.finalOwnerVerified = true;

    mark('legacy_authority_blocks_new_kernel_owner');
    systemctl(['stop', supervisor]); await absent('/proc/' + second.MainPID);
    const stopped = show(supervisor);
    systemctl(['start', '--no-block', supervisor]);
    const socket = path.join(root, 'runtime/control-v1.sock'), by = Date.now() + 30000;
    let refusal: Record<string, string>;
    for (;;) {
      assert(Date.now() < by, 'signed start did not observe Legacy authority refusal');
      const attempted = show(supervisor);
      await absent(socket);
      if (attempted.InvocationID !== stopped.InvocationID && attempted.Result === 'exit-code' &&
          attempted.ExecMainCode === '1' && attempted.ExecMainStatus === '1' && attempted.MainPID === '0' &&
          /^[a-f0-9]{32}$/u.test(attempted.InvocationID!) && /^[1-9][0-9]*$/u.test(attempted.ExecMainPID!)) { refusal = attempted; break; }
      await delay(20);
    }
    systemctl(['stop', supervisor]);
    let exact = false;
    for (let attempt = 0; attempt < 20 && !exact; attempt++) {
      const result = spawnSync('/usr/bin/journalctl', ['--boot=0', '--no-pager', '--output=json', '--all', '--no-tail',
        '_UID=' + ledger.uid, '_PID=' + refusal.ExecMainPID, '_SYSTEMD_INVOCATION_ID=' + refusal.InvocationID, '_TRANSPORT=stdout'],
      { env: environment, timeout: 5000, killSignal: 'SIGKILL', maxBuffer: 256 * 1024 });
      assert.equal(result.error, undefined); assert.equal(result.status, 0); assert.equal(result.signal, null);
      assert(Buffer.isBuffer(result.stdout) && Buffer.isBuffer(result.stderr)); scan(result.stdout); scan(result.stderr);
      for (const line of result.stdout.toString('utf8').split('\n').filter(Boolean)) {
        const row = parseJsonStrict(line) as Record<string, unknown>;
        if (row._UID !== String(ledger.uid) || row._PID !== refusal.ExecMainPID ||
            row._SYSTEMD_INVOCATION_ID !== refusal.InvocationID || row._TRANSPORT !== 'stdout' || typeof row.MESSAGE !== 'string') continue;
        let data: Record<string, unknown>;
        try { data = parseJsonStrict(row.MESSAGE) as Record<string, unknown>; } catch { continue; }
        if (data?.diagnosticOnly === true && data.scope === 'installed-read-startup' && data.code === 'RECOVERY_REQUIRED' &&
            data.message === 'installed migration authority requires its retained original recovery path before StateOwner acquisition') exact = true;
      }
      if (!exact) await delay(50);
    }
    assert(exact, 'same original signed invocation must report the exact Legacy authority pre-Owner refusal');
    assert.deepEqual(inspectInstalledOwnerHistory(root), terminal);
    assert((await smallFile(markerFile, 0o600n)).equals(restoredMarker));
    assert((await smallFile(rendezvous, 0o600n)).equals(restoredMarker));
    await absent(auth); report.kernelRestartRefused = true;
  }
} catch (error) {
  failure = error;
  diagnostics.failure = migrationFailure(report.phase, error, commandFailure, diagnostics.ownerReadStage);
}
finally {
  const cleanup: unknown[] = [];
  let beforeStop: Record<string, string>[] | undefined;
  try { await client?.close(); } catch (error) { cleanup.push(error); }
  try {
    if (units) {
      const before = units.map(show);
      if (failure !== undefined) beforeStop = before;
      systemctl(['stop', ...units]);
      for (const [index, unit] of units.entries()) {
        const after = show(unit);
        assert.equal(after.ActiveState, 'inactive'); assert.equal(after.MainPID, '0'); assert.equal(after.TimeoutStopUSec, '2s');
        if (/^[1-9][0-9]*$/u.test(before[index]!.MainPID!)) await absent('/proc/' + before[index]!.MainPID);
      }
    }
  } catch (error) { cleanup.push(error); }
  if (beforeStop) diagnostics.servicesBeforeStop = [unitStatus('supervisor', beforeStop[0]!), unitStatus('keeper', beforeStop[1]!)];
  if (cleanup.length) {
    diagnostics.cleanupFailed = true;
    diagnostics.failure ??= migrationFailure('cleanup', cleanup[0], commandFailure);
    failure = new AggregateError(failure === undefined ? cleanup : [failure, ...cleanup], 'owned migration resources did not join');
  }
  report.qualified = failure === undefined;
  await writeFile(recipe.reportFile, Buffer.concat([canonicalJsonBytes(report), Buffer.from('\n')]), { flag: 'wx', mode: 0o644 });
}
if (failure !== undefined) process.exitCode = 1;
