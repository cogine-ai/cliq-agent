// Test-private process-crash cut at the genuine signed auth entry. A copied
// read-only SQLite/WAL snapshot identifies the cut, never credential authority.
// SIGKILL is not power loss, native producer-death proof or installed I1.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, type BigIntStats } from 'node:fs';
import { chown, chmod, lstat, mkdir, mkdtemp, readFile, readdir, readlink, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { decodeCredentialAuthorityOperation, type CredentialAuthorityOperationV1 } from '../../../src/kernel/credential-authority.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { CredentialWriteRequest } from '../../../src/state/store.js';
import { decodeControlChannel, decodePlatformProcessIdentity } from '../../../src/state/decoders.js';
import { checkedThreadCalls } from './credential-vfs-storage.js';
import { inspectWal } from './endpoint-wal-proof.js';

const dataLimit = 4 * 1024 * 1024, traceLimit = 8 * 1024 * 1024, delayMs = 2000;
type Physical = { dev: string; ino: string; size: string; uid: string; gid: string; mode: string;
  nlink: string; mtimeNs: string; ctimeNs: string };
const physical = (info: BigIntStats): Physical => Object.fromEntries(
  ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'].map(key =>
    [key, info[key as keyof BigIntStats]!.toString()])) as Physical;
const sameObject = (left: Physical, right: Physical) => left.dev === right.dev && left.ino === right.ino;
const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

async function processFact(pid: number) {
  try {
    const raw = await readFile(`/proc/${pid}/stat`, 'utf8'); assert(raw.startsWith(`${pid} (`) && raw.length <= 8192);
    const fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/u);
    assert(fields.length > 19); assert.match(fields[19]!, /^[1-9][0-9]*$/u);
    const status = await readFile(`/proc/${pid}/status`, 'utf8');
    const uid = status.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu);
    assert(uid);
    const confirmed = await readFile(`/proc/${pid}/stat`, 'utf8'); assert(confirmed.startsWith(`${pid} (`));
    assert.equal(confirmed.slice(confirmed.lastIndexOf(')') + 2).trim().split(/\s+/u)[19], fields[19]);
    return { pid, parent: Number(fields[1]), group: Number(fields[2]), session: Number(fields[3]),
      start: fields[19]!, state: fields[0]!, uids: uid.slice(1).map(Number) };
  } catch (error) { if (['ENOENT', 'ESRCH'].includes((error as NodeJS.ErrnoException).code ?? '')) return undefined; throw error; }
}
type ProcessFact = NonNullable<Awaited<ReturnType<typeof processFact>>>;
async function onlyChild(parent: ProcessFact): Promise<ProcessFact | undefined> {
  const current = await processFact(parent.pid);
  if (!current || current.start !== parent.start) return undefined;
  const raw = await readFile(`/proc/${parent.pid}/task/${parent.pid}/children`, 'utf8').catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT' || error.code === 'ESRCH') return ''; throw error;
  });
  assert(raw.length <= 1024);
  const pids = raw.trim() ? raw.trim().split(/\s+/u).map(Number) : [];
  assert(pids.length <= 1, 'owned runuser and tracer may each own only their fixed child');
  const child = pids[0] === undefined ? undefined : await processFact(pids[0]);
  if (child) assert.equal(child.parent, parent.pid);
  return child;
}
async function waitGone(original: ProcessFact): Promise<void> {
  const deadline = performance.now() + 5000;
  for (;;) {
    const current = await processFact(original.pid);
    if (!current || current.start !== original.start) return;
    assert(performance.now() < deadline, 'original owned fixture lifetime did not retire'); await delay(20);
  }
}
async function actualBytes(filename: string, original: Physical): Promise<Buffer> {
  const before = await lstat(filename, { bigint: true });
  assert(before.isFile() && before.nlink === 1n && before.size <= BigInt(dataLimit));
  assert(sameObject(physical(before), original));
  const bytes = await readFile(filename); assert(bytes.length <= dataLimit);
  assert.deepEqual(physical(await lstat(filename, { bigint: true })), physical(before), 'actual snapshot bytes must be stable');
  return bytes;
}

/** Only copied real bytes reach the default engine. It opens read-only and
 * cannot acquire or change the original production credential store. */
async function snapshotFacts(directory: string, main: Buffer, wal: Buffer, requestId: string) {
  const snapshot = await mkdtemp(path.join(directory, 'snapshot-'));
  try {
    const filename = path.join(snapshot, 'authority.sqlite');
    await writeFile(filename, main, { flag: 'wx', mode: 0o600 });
    await writeFile(`${filename}-wal`, wal, { flag: 'wx', mode: 0o600 });
    const database = new DatabaseSync(filename, { readOnly: true, allowExtension: false });
    try {
      assert.equal(database.prepare('PRAGMA user_version').get()?.user_version, 2, 'warm-up must genuinely commit credential v2 first');
      const retained = (ref: string) => {
        const bytes = database.prepare('SELECT bytes FROM retained_objects WHERE artifact_ref=?').get(ref)?.bytes;
        assert(bytes instanceof Uint8Array && bytes.length <= 1048576 && hash(bytes) === ref);
        const value = parseJsonStrict(Buffer.from(bytes).toString('utf8'));
        assert(canonicalJsonBytes(value).equals(Buffer.from(bytes))); return value;
      };
      const rows = database.prepare(`SELECT attempt,phase_rank,operation_json FROM credential_operation_facts
        WHERE request_id=? ORDER BY attempt,phase_rank LIMIT 10`).all(requestId);
      assert(rows.length <= 9);
      return rows.map(row => {
        assert.equal(typeof row.operation_json, 'string'); assert(Buffer.byteLength(row.operation_json as string) <= 1048576);
        const decoded = parseJsonStrict(row.operation_json as string);
        assert.equal(canonicalJsonBytes(decoded).toString('utf8'), row.operation_json);
        const operation = decodeCredentialAuthorityOperation(decoded);
        assert.equal(operation.requestId, requestId); assert.equal(operation.attempt, row.attempt);
        assert.equal(row.phase_rank, operation.phase === 'prepared' ? 0 : operation.phase === 'secret_stored' ? 1 : 2);
        const channel = decodeControlChannel(retained(operation.channelIdentityRef));
        assert.equal(channel.channelIdentityDigest, operation.channelIdentityDigest);
        assert.equal(channel.principalId, operation.ownerPrincipalId); assert.equal(channel.transport.kind, 'in_process');
        if (channel.transport.kind !== 'in_process') throw new Error('copied preparation does not name an in-process channel');
        const producer = decodePlatformProcessIdentity(retained(channel.transport.processIdentityRef));
        assert.equal(producer.identityDigest, channel.transport.processIdentityDigest);
        assert.equal(producer.observedAt, channel.openedAt);
        assert.equal(canonicalSha256(channel), operation.channelIdentityRef);
        return { operation, producer };
      });
    } finally { database.close(); }
  } finally { await rm(snapshot, { recursive: true, force: true }); }
}

export type PreparedCredentialCrashInput = Readonly<{ fixture: string; username: string; uid: number; gid: number; home: string;
  stateRoot: string; ownerPrincipalId: string; selectedImage: string; selectedImageDigest: string;
  request: CredentialWriteRequest; secret: Buffer; expectedAttempt?: 1 | 2 | 3;
  previous?: Readonly<{ prepared: CredentialAuthorityOperationV1; facts: readonly CredentialAuthorityOperationV1[] }> }>;

/** Caller is the existing root-owned disposable-user ledger campaign. Inputs
 * are its fixed paths/UID/signed selection, not accepted production evidence.
 * Warm v2 with genuine business commands first. Later cuts use the previous
 * actual copied history only for cut identification, never production proof. */
export async function crashPreparedCredentialWrite(input: PreparedCredentialCrashInput) {
  assert.equal(process.platform, 'linux'); assert.equal(process.geteuid!(), 0);
  assert(input.uid > 0 && Number.isSafeInteger(input.uid) && input.gid === input.uid);
  assert.match(input.fixture, /^\/var\/tmp\/cliq-systemd-probe\.[A-Za-z0-9]+$/u);
  assert.equal(input.username, `cliq-probe-${input.fixture.split('.').at(-1)!.toLowerCase()}`);
  assert.equal(input.home, path.join(input.fixture, 'home'));
  assert.equal(input.stateRoot, path.join(input.home, 'probe/credential-state'));
  assert.match(input.selectedImageDigest, /^[0-9a-f]{64}$/u);
  assert(input.selectedImage.startsWith(`${input.stateRoot}/runtime/bundles/`) && path.basename(input.selectedImage) === 'supervisor');
  const root = await lstat(input.stateRoot, { bigint: true });
  assert(root.isDirectory() && root.uid === BigInt(input.uid) && (root.mode & 0o7777n) === 0o700n);
  const fixture = await lstat(input.fixture); assert(fixture.isDirectory() && !fixture.isSymbolicLink() && fixture.uid === 0);
  const requestBytes = canonicalJsonBytes(input.request); assert(requestBytes.length <= 65536);
  assert(input.secret.length > 0 && input.secret.length <= 65536);
  const expectedAttempt = input.expectedAttempt ?? 1;
  assert([1, 2, 3].includes(expectedAttempt));
  assert.equal(Boolean(input.previous), expectedAttempt !== 1);
  if (input.previous) {
    assert.equal(input.previous.prepared.phase, 'prepared'); assert.equal(input.previous.prepared.attempt, expectedAttempt - 1);
    assert.equal(input.previous.prepared.requestId, input.request.requestId);
    assert.equal(input.previous.prepared.credentialGrantId, input.request.credentialGrantId);
    assert.deepEqual(input.previous.facts.at(-1), input.previous.prepared);
  }
  const main = path.join(input.stateRoot, 'credentials/authority.sqlite'), wal = `${main}-wal`;
  const mainIdentity = physical(await lstat(main, { bigint: true })), walIdentity = physical(await lstat(wal, { bigint: true }));
  for (const identity of [mainIdentity, walIdentity]) {
    assert.equal(identity.uid, String(input.uid)); assert.equal(identity.nlink, '1');
    assert.equal(BigInt(identity.mode) & 0o7777n, 0o600n);
  }
  const imageInfo = await lstat(input.selectedImage, { bigint: true });
  assert(imageInfo.isFile() && !imageInfo.isSymbolicLink() && imageInfo.size <= 512n * 1024n * 1024n);
  const image = physical(imageInfo);
  assert.equal(image.uid, String(input.uid)); assert.equal(image.nlink, '1');
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(input.selectedImage, { signal: AbortSignal.timeout(30000) })) digest.update(chunk);
  assert.equal(digest.digest('hex'), input.selectedImageDigest);
  assert.deepEqual(physical(await lstat(input.selectedImage, { bigint: true })), image);
  const evidence = await mkdtemp(path.join(input.fixture, 'credential-prepared-crash-'));
  await chmod(evidence, 0o755);
  const traces = path.join(evidence, 'trace'); await mkdir(traces, { mode: 0o700 }); await chown(traces, input.uid, input.gid);
  const baselineMain = await actualBytes(main, mainIdentity), baselineWal = await actualBytes(wal, walIdentity);
  const baselineFacts = (await snapshotFacts(evidence, baselineMain, baselineWal, input.request.requestId)).map(fact => fact.operation);
  assert.deepEqual(baselineFacts, input.previous?.facts ?? [], 'copied cut prefix must remain exactly unchanged');
  const baseline = inspectWal(baselineWal);
  const prefix = path.join(traces, 'auth.trace');
  // No read/write/send/recv payload tracing, input digest, fake errno/retval or
  // memory/register writes. Only actual credential WAL writes can carry data.
  const launcher = spawn('/usr/sbin/runuser', ['--user', input.username, '--', '/usr/bin/env', '-i',
    `HOME=${input.home}`, 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C', `XDG_RUNTIME_DIR=/run/user/${input.uid}`,
    `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${input.uid}/bus`, '/usr/bin/strace', '-ff', '-ttt', '-yy', '-xx',
    '-s', '65536', '-o', prefix, '-e', 'trace=pwrite64,fsync,fdatasync,clone,clone3,execve,execveat',
    '-e', 'inject=fsync:delay_exit=2s', path.join(input.stateRoot, 'runtime/bootstrap'),
    '--bootstrap-credential', requestBytes.toString('base64url')],
  { cwd: input.home, env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' },
    detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const streams = [launcher.stdin, launcher.stdout, launcher.stderr] as const;
  const streamsClosed = Promise.all(streams.map(stream => new Promise<void>(resolve => stream.once('close', resolve))));
  let closed = false, spawnFailed = false, outputBytes = 0, stdoutBytes = 0, outputExceeded = false;
  let containOutput: () => void = () => {};
  const joined = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => {
    launcher.once('close', (code, signal) => { closed = true; resolve({ code, signal }); });
  });
  launcher.once('error', () => { spawnFailed = true; }); launcher.stdin.on('error', () => {});
  for (const stream of [launcher.stdout, launcher.stderr]) stream.on('data', (bytes: Buffer) => {
    outputBytes += bytes.length;
    if (stream === launcher.stdout) stdoutBytes += bytes.length;
    if (outputBytes > 65536 && !outputExceeded) { outputExceeded = true; containOutput(); }
  });
  launcher.stdin.end(input.secret); // The only path receiving raw fixture secret bytes.
  const bounded = async <T>(pending: Promise<T>, milliseconds: number): Promise<T> => {
    let timer: NodeJS.Timeout | undefined;
    try { return await Promise.race([pending, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('owned credential crash fixture did not join')), milliseconds);
    })]); } finally { clearTimeout(timer); }
  };
  let ownedLauncher: ProcessFact | undefined, tracer: ProcessFact | undefined, auth: ProcessFact | undefined;
  const discover = async () => {
    if (!ownedLauncher && launcher.pid) {
      const current = await processFact(launcher.pid);
      if (current) {
        assert.equal(current.parent, process.pid); assert.equal(current.group, launcher.pid); assert.equal(current.session, launcher.pid);
        ownedLauncher = current;
      }
    }
    if (!tracer && ownedLauncher) {
      const current = await onlyChild(ownedLauncher);
      if (current?.uids.every(uid => uid === input.uid) && await readlink(`/proc/${current.pid}/exe`).catch((error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT' || error.code === 'ESRCH') return ''; throw error;
      }) === '/usr/bin/strace') tracer = current;
    }
    if (!auth && tracer) {
      const current = await onlyChild(tracer);
      if (current) { assert(current.uids.every(uid => uid === input.uid)); auth = current; }
    }
  };
  const live = async () => {
    assert(auth && tracer);
    const current = await processFact(auth.pid); assert(current && current.start === auth.start && current.parent === tracer.pid);
    assert(current.uids.every(uid => uid === input.uid));
    assert.deepEqual(physical(await stat(`/proc/${auth.pid}/exe`, { bigint: true })), image);
    return current;
  };
  const killOwnedAuth = async () => {
    await discover();
    if (auth && tracer) {
      const current = await processFact(auth.pid);
      if (current?.start === auth.start && current.parent === tracer.pid && current.uids.every(uid => uid === input.uid)) {
        try { process.kill(auth.pid, 'SIGKILL'); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error; }
      }
    }
  };
  containOutput = () => { void killOwnedAuth().catch(() => {}); };
  let primary: unknown, watchdogFired = false;
  const watchdog = setTimeout(() => { watchdogFired = true; void killOwnedAuth().catch(() => {}); }, 125000);
  try {
    const deadline = performance.now() + 120000;
    const tracedWal = [...Buffer.from(wal)].map(byte => `\\x${byte.toString(16).padStart(2, '0')}`).join('');
    let cut: { prepared: CredentialAuthorityOperationV1; facts: CredentialAuthorityOperationV1[]; sampledAt: number; enteredAt: number;
      delayedEvent: string; observed: NonNullable<ReturnType<typeof inspectWal>>; actualMainSha256: string; actualWalSha256: string } | undefined;
    while (performance.now() < deadline) {
      assert(!spawnFailed && !closed, 'owned credential writer exited before its prepared cut');
      assert(!outputExceeded, 'owned credential writer output exceeded its bound');
      await discover();
      if (!auth || !sameObject(physical(await stat(`/proc/${auth.pid}/exe`, { bigint: true })), image)) { await delay(20); continue; }
      const filename = `${prefix}.${auth.pid}`;
      const info = await lstat(filename).catch((error: NodeJS.ErrnoException) => { if (error.code === 'ENOENT') return undefined; throw error; });
      if (!info) { await delay(20); continue; }
      assert(info.isFile() && !info.isSymbolicLink() && info.uid === input.uid && info.nlink === 1 && info.size <= traceLimit);
      const raw = await readFile(filename, 'utf8'); assert(Buffer.byteLength(raw) <= traceLimit);
      const line = raw.split('\n').filter(Boolean).at(-1)!;
      const event = /^(\d+\.\d{6,9}) fsync\((\d+)<([^>]+)>\)\s+= 0 \(DELAYED\)$/u.exec(line);
      if (!event || event[3] !== tracedWal) { await delay(20); continue; }
      const sampledAt = Date.now(), enteredAt = Number(event[1]) * 1000;
      if (sampledAt < enteredAt || sampledAt - enteredAt > delayMs - 500) { await delay(20); continue; }
      const actualWal = await actualBytes(wal, walIdentity), observed = inspectWal(actualWal);
      if (!observed || observed.commits.length <= (observed.generation === baseline?.generation ? baseline.commits.length : 0)) { await delay(20); continue; }
      const actualMain = await actualBytes(main, mainIdentity);
      const facts = await snapshotFacts(evidence, actualMain, actualWal, input.request.requestId);
      if (!facts.length) { await delay(20); continue; }
      const operations = facts.map(fact => fact.operation);
      assert.deepEqual(operations.slice(0, baselineFacts.length), baselineFacts, 'retry must not rewrite earlier facts');
      const { operation: prepared, producer } = facts.at(-1)!;
      // Automatic recovery genuinely commits the previous abort before the
      // next preparation. Its fsync is not the requested prepared-N cut.
      if (prepared.attempt < expectedAttempt && prepared.phase !== 'committed') { await delay(20); continue; }
      assert.equal(prepared.phase, 'prepared'); assert.equal(prepared.attempt, expectedAttempt);
      assert.equal(facts.length, (expectedAttempt - 1) * 2 + 1, 'prepared-only cuts must have one original preparation/abort per earlier attempt');
      for (let index = 0; index < expectedAttempt - 1; index++) {
        const preparation = operations[index * 2]!, abort = operations[index * 2 + 1]!;
        assert.equal(preparation.phase, 'prepared'); assert.equal(preparation.attempt, index + 1);
        assert.equal(abort.phase, 'aborted'); assert.equal(abort.attempt, index + 1);
        assert.equal(abort.abortReason, 'recovered_orphan');
        const { phase: _preparedPhase, operationDigest: _preparedDigest, ...original } = preparation;
        const { phase: _abortPhase, operationDigest: _abortDigest, abortReason: _reason, finishedAt: _finished, ...retained } = abort;
        assert.deepEqual(retained, original, 'orphan abort may not rewrite its original operation identity');
      }
      if (input.previous) {
        assert.deepEqual(prepared.commandCore, input.previous.prepared.commandCore, 'retry must retain the original complete frozen core');
        for (const key of ['intendedAuthorityRevision', 'intendedSecretGeneration', 'intendedExternalSubjectDigest'] as const)
          assert.equal(prepared[key], input.previous.prepared[key]);
        assert.notEqual(prepared.operationId, input.previous.prepared.operationId);
        assert.notEqual(prepared.channelIdentityRef, input.previous.prepared.channelIdentityRef);
        assert.notEqual(prepared.channelIdentityDigest, input.previous.prepared.channelIdentityDigest);
        assert.notDeepEqual(prepared.platformItem, input.previous.prepared.platformItem);
      }
      assert.equal(prepared.kind, input.request.kind); assert.equal(prepared.ownerPrincipalId, input.ownerPrincipalId);
      assert.equal(prepared.credentialGrantId, input.request.credentialGrantId);
      assert.equal(prepared.commandCore.secretSubmissionId, input.request.secretSubmissionId);
      const current = await live(); assert.equal(current.state, 't', 'prepared writer must remain in the actual traced stop');
      assert.equal(producer.platform, 'linux'); assert.equal(producer.ownerUid, input.uid); assert.equal(producer.pid, auth.pid);
      assert.equal(producer.processStartToken, `linux-proc-start-ticks:${auth.start}`);
      assert.equal(producer.executableImageDigest, input.selectedImageDigest);
      assert(sameObject(physical(await stat(`/proc/${auth.pid}/fd/${event[2]}`, { bigint: true })), walIdentity));
      assert((await actualBytes(wal, walIdentity)).equals(actualWal));
      assert((await actualBytes(main, mainIdentity)).equals(actualMain));
      assert(Date.now() - enteredAt < delayMs - 250, 'identified prepared cut escaped its OS pause');
      cut = { prepared, facts: operations, sampledAt, enteredAt, delayedEvent: line, observed,
        actualMainSha256: hash(actualMain), actualWalSha256: hash(actualWal) };
      process.kill(auth.pid, 'SIGKILL'); break;
    }
    assert(cut && auth && tracer && ownedLauncher, 'no verified real prepared credential commit cut');
    const exit = await bounded(joined, 10000);
    assert(!watchdogFired, 'forced watchdog cleanup is not a qualified prepared cut');
    assert(!outputExceeded, 'an output-bound failure is not a qualified prepared cut');
    assert.equal(stdoutBytes, 0, 'prepared writer must not publish a response before the crash');
    assert.equal(exit.signal, null); assert.equal(exit.code, 128 + 9, 'runuser must join the tracer and killed auth');
    await waitGone(auth); await waitGone(tracer); await waitGone(ownedLauncher);
    const names = await readdir(traces); assert(names.length > 0 && names.length <= 64);
    const corpus = []; let total = 0;
    for (const name of names) {
      assert.match(name, /^auth\.trace\.[1-9][0-9]*$/u);
      const filename = path.join(traces, name), info = await lstat(filename);
      assert(info.isFile() && !info.isSymbolicLink() && info.uid === input.uid && info.nlink === 1);
      const bytes = await readFile(filename); total += bytes.length; assert(total <= traceLimit);
      corpus.push({ tid: Number(name.split('.').at(-1)), raw: bytes.toString('utf8'), sha256: hash(bytes) });
    }
    checkedThreadCalls(corpus, auth.pid, 'joined_sigkill');
    assert(corpus.every(item => !item.raw.includes(' detached ')), 'a detached thread is not a positive join');
    return { diagnosticOnly: true as const, phase: 'prepared' as const, ...cut, stateRoot: input.stateRoot,
      originalMain: mainIdentity, originalWal: walIdentity,
      image, imageDigest: input.selectedImageDigest, auth: { pid: auth.pid, start: auth.start, uid: input.uid },
      baseline, baselineWalSha256: hash(baselineWal), metadataSha256: hash(requestBytes), launcherJoined: true as const,
      authLifetimeGone: true as const, tids: corpus.map(({ tid, sha256 }) => ({ tid, sha256 })), evidence };
  } catch (error) { primary = error; throw error; }
  finally {
    clearTimeout(watchdog); const failures: unknown[] = [];
    if (!closed) {
      try { await killOwnedAuth(); } catch (error) { failures.push(error); }
      try { await bounded(joined, 10000); }
      catch (error) {
        failures.push(error);
        try {
          const current = launcher.pid ? await processFact(launcher.pid) : undefined;
          if (current && ownedLauncher?.start === current.start && current.group === current.pid && current.session === current.pid)
            process.kill(-current.pid, 'SIGKILL');
        } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') failures.push(error); }
        try { await bounded(joined, 5000); } catch (error) { failures.push(error); }
      }
    }
    for (const owned of [auth, tracer, ownedLauncher]) if (owned) {
      try { await waitGone(owned); } catch (error) { failures.push(error); }
    }
    for (const stream of streams) stream.destroy();
    try { await bounded(streamsClosed, 5000); } catch (error) { failures.push(error); }
    if (failures.length) throw new AggregateError([primary, ...failures].filter(Boolean), 'owned credential crash fixture retirement failed');
  }
}

/** Diagnostic copy only, reused after a real refusal to detect a fourth fact.
 * It does not observe producer death or grant an authentication decision. */
export async function inspectPreparedCredentialCrashFacts(cut: Awaited<ReturnType<typeof crashPreparedCredentialWrite>>) {
  assert.equal(process.platform, 'linux'); assert.equal(process.geteuid!(), 0);
  assert.match(cut.stateRoot, /^\/var\/tmp\/cliq-systemd-probe\.[A-Za-z0-9]+\/home\/probe\/credential-state$/u);
  const root = await lstat(cut.stateRoot, { bigint: true });
  assert(root.isDirectory() && root.uid === BigInt(cut.auth.uid) && (root.mode & 0o7777n) === 0o700n);
  const evidence = await lstat(cut.evidence); assert(evidence.isDirectory() && !evidence.isSymbolicLink() && evidence.uid === 0);
  const main = path.join(cut.stateRoot, 'credentials/authority.sqlite'), wal = `${main}-wal`;
  const actualMain = await actualBytes(main, cut.originalMain), actualWal = await actualBytes(wal, cut.originalWal);
  const facts = (await snapshotFacts(cut.evidence, actualMain, actualWal, cut.prepared.requestId)).map(fact => fact.operation);
  assert((await actualBytes(main, cut.originalMain)).equals(actualMain));
  assert((await actualBytes(wal, cut.originalWal)).equals(actualWal));
  return facts;
}
