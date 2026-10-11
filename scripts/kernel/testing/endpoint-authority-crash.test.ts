// Actual signed installed entry, process-crash recovery only. SIGKILL is not
// power loss, credential enrollment, a revoke crash campaign or installed I1.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, type BigIntStats } from 'node:fs';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { decodeEndpointAuthorityOperation, decodeEndpointAuthorityRecord,
  type EndpointAuthorityCommandCoreV1, type EndpointRegistrationV1 } from '../../../src/kernel/credential-authority.js';
import { digestOmitting, identityHash } from '../../../src/kernel/identity.js';
import { createInstalledRuntime } from '../../../src/state/installed-runtime.js';
import { checkedThreadCalls } from './credential-vfs-storage.js';
import { inspectWal, type WalProof } from './endpoint-wal-proof.js';
import { buildInstalledSupervisorPackage } from './installed-supervisor-package.js';

const delayMs = 2000, traceLimit = 8 * 1024 * 1024, walLimit = 4 * 1024 * 1024;
const pause = () => new Promise<void>(resolve => setTimeout(resolve, 25));
const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
type Request = { schemaVersion: 1; kind: 'commit'; requestId: string; commandCore: EndpointAuthorityCommandCoreV1 }
  | { schemaVersion: 1; kind: 'read'; endpointRegistrationId: string };
type Physical = { dev: string; ino: string; size: string; mtimeNs: string; ctimeNs: string };
const physical = (info: BigIntStats) => ({ dev: info.dev.toString(), ino: info.ino.toString(),
  size: info.size.toString(), mtimeNs: info.mtimeNs.toString(), ctimeNs: info.ctimeNs.toString() });
const sameObject = (a: Physical, b: Physical) => a.dev === b.dev && a.ino === b.ino;
function processFields(text: string) {
  const end = text.lastIndexOf(')'); assert(end > 0);
  const fields = text.slice(end + 2).trim().split(/\s+/u);
  assert(fields.length > 19); return { state: fields[0]!, parent: Number(fields[1]), start: fields[19]! };
}
async function imageDigest(filename: string) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(filename)) digest.update(chunk);
  return digest.digest('hex');
}
function newCommit(proof: WalProof | null, baseline: WalProof | null) {
  return proof && proof.commits.length > (proof.generation === baseline?.generation ? baseline.commits.length : 0);
}
async function walBytes(filename: string, original: Physical) {
  const before = await lstat(filename, { bigint: true });
  assert(before.isFile() && before.nlink === 1n && before.size <= BigInt(walLimit));
  assert(sameObject(physical(before), original));
  const bytes = await readFile(filename); assert(bytes.length <= walLimit);
  assert.deepEqual(physical(await lstat(filename, { bigint: true })), physical(before), 'WAL observation must be stable');
  return bytes;
}
function response(bootstrap: string, fixture: string, request: Request, field: 'record' | 'operation') {
  const child = spawnSync(bootstrap, ['--bootstrap-endpoint'], { cwd: fixture, env: { PATH: process.env.PATH },
    input: canonicalJsonBytes(request), encoding: 'utf8', timeout: 60000, killSignal: 'SIGKILL', maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  const value = JSON.parse(child.stdout) as Record<string, unknown>;
  assert.deepEqual(Object.keys(value).sort(), [field, 'schemaVersion']); assert.equal(value.schemaVersion, 1);
  assert.equal(child.stdout, `${canonicalJsonBytes(value).toString('utf8')}\n`);
  return { value: value[field], bytes: child.stdout };
}

/** The OS tracer delays only execution. It never changes results or memory.
 * Pending-write overlay identifies a cut; it is never actual written evidence.
 * https://github.com/strace/strace/blob/v5.16/src/delay.c */
async function cutWriter(input: { phase: 'before' | 'after'; bootstrap: string; fixture: string; request: Request;
  image: Physical; imageDigest: string; wal: string; evidence: string }) {
  const original = physical(await lstat(input.wal, { bigint: true }));
  const main = input.wal.slice(0, -'-wal'.length);
  const originalMain = physical(await lstat(main, { bigint: true }));
  const baselineBytes = await walBytes(input.wal, original), baseline = inspectWal(baselineBytes);
  const prefix = path.join(input.evidence, `${input.phase}.trace`);
  const tracedWal = [...Buffer.from(input.wal)].map(byte => `\\x${byte.toString(16).padStart(2, '0')}`).join('');
  const trace = spawn('strace', ['-ff', '-ttt', '-yy', '-xx', '-s', '65536', '-o', prefix,
    '-e', 'trace=pwrite64,fsync,fdatasync,clone,clone3,execve,execveat',
    '-e', input.phase === 'before' ? 'inject=pwrite64:delay_enter=2s' : 'inject=fsync:delay_exit=2s',
    input.bootstrap, '--bootstrap-endpoint'], { cwd: input.fixture, env: { PATH: process.env.PATH, LANG: 'C' },
    stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', spawnError: Error | undefined;
  let writer: { pid: number; start: string } | undefined, cut: Record<string, unknown> | undefined;
  let actualWal: Buffer | undefined, actualMain: Buffer | undefined;
  const joined = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    trace.once('error', error => { spawnError = error; reject(error); });
    trace.once('close', (code, signal) => resolve({ code, signal }));
  });
  void joined.catch(() => {});
  const boundedJoin = async (milliseconds: number) => {
    let timer: NodeJS.Timeout | undefined;
    try { return await Promise.race([joined, new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error('owned tracer did not join within its bound')), milliseconds);
    })]); } finally { clearTimeout(timer); }
  };
  trace.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString('utf8'); });
  trace.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8'); });
  trace.stdin.on('error', () => {}); // spawn/exit is checked by the owning join.
  trace.stdin.end(canonicalJsonBytes(input.request));
  const deadline = Date.now() + 120000;
  const killOwnedWriter = async () => {
    if (!writer) {
      const children = await readFile(`/proc/${trace.pid}/task/${trace.pid}/children`, 'utf8').catch(() => '');
      const pids = children.trim() ? children.trim().split(/\s+/u).map(Number) : [];
      assert(pids.length <= 1);
      if (pids[0]) {
        const fields = processFields(await readFile(`/proc/${pids[0]}/stat`, 'utf8'));
        assert.equal(fields.parent, trace.pid); writer = { pid: pids[0], start: fields.start };
      }
    }
    if (writer) {
      const fields = await readFile(`/proc/${writer.pid}/stat`, 'utf8').then(processFields).catch((error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT') return undefined; throw error;
      });
      if (fields?.start === writer.start && fields.parent === trace.pid) {
        try { process.kill(writer.pid, 'SIGKILL'); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error; }
      }
    }
  };
  let watchdogFired = false, watchdogError: unknown, primaryFailure: unknown;
  const watchdog = setTimeout(() => {
    watchdogFired = true;
    void killOwnedWriter().catch(error => { watchdogError = error; });
  }, 125000);
  const live = async () => {
    assert(writer);
    const fields = processFields(await readFile(`/proc/${writer.pid}/stat`, 'utf8'));
    assert.equal(fields.start, writer.start); assert.equal(fields.parent, trace.pid);
    const executable = physical(await stat(`/proc/${writer.pid}/exe`, { bigint: true }));
    assert.deepEqual(executable, input.image);
    return fields;
  };
  try {
    while (!writer && Date.now() < deadline) {
      if (spawnError) throw spawnError;
      assert.equal(trace.exitCode, null); assert.equal(trace.signalCode, null);
      const children = await readFile(`/proc/${trace.pid}/task/${trace.pid}/children`, 'utf8').catch(() => '');
      const pids = children.trim() ? children.trim().split(/\s+/u).map(Number) : [];
      assert(pids.length <= 1, 'the tracer must own only its one actual bootstrap');
      if (pids[0]) {
        const fields = processFields(await readFile(`/proc/${pids[0]}/stat`, 'utf8'));
        assert.equal(fields.parent, trace.pid);
        writer = { pid: pids[0], start: fields.start };
      } else await pause();
    }
    assert(writer, 'tracer did not acquire its exact child');
    // Bootstrap execs the selected signed image in the same PID. Observe that
    // transition, not merely a pathname or the tracer's own process identity.
    while (Date.now() < deadline) {
      const image = await stat(`/proc/${writer.pid}/exe`, { bigint: true });
      if (sameObject(physical(image), input.image)) break;
      await pause();
    }
    await live(); assert.equal(await imageDigest(`/proc/${writer.pid}/exe`), input.imageDigest); await live();
    while (Date.now() < deadline) {
      assert(stdout.length <= 65536 && stderr.length <= 65536, 'writer output exceeded bound');
      assert.equal(trace.exitCode, null); assert.equal(trace.signalCode, null);
      const raw = await readFile(`${prefix}.${writer.pid}`, 'utf8'); assert(Buffer.byteLength(raw) <= traceLimit);
      const line = raw.split('\n').filter(Boolean).at(-1)!;
      const write = /^(\d+\.\d{6,9}) pwrite64\((\d+)<([^>]+)>, "((?:\\x[0-9a-f]{2})+)", (\d+), (\d+)\)?$/u.exec(line);
      const sync = /^(\d+\.\d{6,9}) fsync\((\d+)<([^>]+)>\)\s+= 0 \(DELAYED\)$/u.exec(line);
      const event = input.phase === 'before' ? write : sync;
      if (!event || event[3] !== tracedWal) { await pause(); continue; }
      const sampledAt = Date.now(), enteredAt = Number(event[1]) * 1000;
      // The exact delayed event must still be within its bounded OS pause;
      // an old partial trace line or a generic ptrace stop is insufficient.
      if (sampledAt < enteredAt || sampledAt - enteredAt > delayMs - 500) { await pause(); continue; }
      const before = await walBytes(input.wal, original), observed = inspectWal(before);
      let prospective: WalProof | null = null;
      if (write) {
        const bytes = Buffer.from(write[4]!.replaceAll('\\x', ''), 'hex');
        const count = Number(write[5]), offset = Number(write[6]);
        assert.equal(bytes.length, count); assert(count > 0 && count <= 65536);
        assert(Number.isSafeInteger(offset) && offset >= 0 && offset + count <= walLimit);
        const overlay = Buffer.alloc(Math.max(before.length, offset + count)); before.copy(overlay); bytes.copy(overlay, offset);
        prospective = inspectWal(overlay);
        if (newCommit(observed, baseline) || !newCommit(prospective, baseline)) { await pause(); continue; }
      } else if (!newCommit(observed, baseline)) { await pause(); continue; }
      const fields = await live(); assert.equal(fields.state, 't', 'writer must still be in its traced OS stop');
      const fd = physical(await stat(`/proc/${writer.pid}/fd/${event[2]}`, { bigint: true }));
      assert(sameObject(fd, original), 'cut must name the original held WAL inode');
      assert((await walBytes(input.wal, original)).equals(before), 'WAL must remain unchanged during cut verification');
      actualMain = await walBytes(main, originalMain);
      assert(Date.now() - enteredAt < delayMs - 250, 'verified cut escaped its OS pause');
      cut = { phase: input.phase, writer, originalWal: original, image: input.image, actualImageSha256: input.imageDigest,
        sampledAt, enteredAt, delayedEvent: line, observed, prospectiveIdentificationOnly: prospective,
        actualWalSha256: hash(before), actualMainSha256: hash(actualMain), stdinSha256: hash(canonicalJsonBytes(input.request)), requestId:
          input.request.kind === 'commit' ? input.request.requestId : undefined };
      actualWal = before;
      process.kill(writer.pid, 'SIGKILL');
      break;
    }
    assert(cut, `no verified ${input.phase} commit cut: ${stderr}`);
    const exit = await boundedJoin(10000);
    assert(!watchdogFired && watchdogError === undefined, 'forced cleanup is not qualification');
    assert(exit.signal === 'SIGKILL' || exit.code === 128 + 9, 'tracer must positively join its killed writer');
    assert.equal(stdout, '', 'the writer must not have published a response before the crash');
    await writeFile(path.join(input.evidence, `${input.phase}-wal.bin`), actualWal!, { flag: 'wx', mode: 0o600 });
    await writeFile(path.join(input.evidence, `${input.phase}-main.bin`), actualMain!, { flag: 'wx', mode: 0o600 });
    const names = (await readdir(input.evidence)).filter(name => name.startsWith(`${input.phase}.trace.`));
    assert(names.length > 0 && names.length <= 64);
    let total = 0;
    const corpus = [];
    for (const name of names) {
      const bytes = await readFile(path.join(input.evidence, name)); total += bytes.length; assert(total <= traceLimit);
      corpus.push({ tid: Number(name.split('.').at(-1)), raw: bytes.toString('utf8'), sha256: hash(bytes) });
    }
    checkedThreadCalls(corpus, writer.pid, 'joined_sigkill');
    return { ...cut, joined: true, tids: corpus.map(item => ({ tid: item.tid, sha256: item.sha256 })), tracerExit: exit };
  } catch (error) { primaryFailure = error; throw error; }
  finally {
    clearTimeout(watchdog);
    if (trace.exitCode === null && trace.signalCode === null) {
      const failures: unknown[] = [];
      try { await killOwnedWriter(); } catch (error) { failures.push(error); }
      try { await boundedJoin(10000); }
      catch (error) {
        failures.push(error); trace.kill('SIGKILL');
        try { await boundedJoin(5000); } catch (forced) { failures.push(forced); }
      }
      if (failures.length) throw new AggregateError(primaryFailure === undefined ? failures : [primaryFailure, ...failures],
        'owned test processes could not positively retire; preserve the failed fixture');
    }
  }
}

if (process.platform === 'linux') test('the actual installed endpoint transaction recovers whole old/new state at joined SIGKILL cuts',
  { timeout: 300000 }, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-endpoint-crash-')));
    const evidence = process.env.RUNNER_TEMP ? await mkdtemp(path.join(process.env.RUNNER_TEMP, 'cliq-endpoint-crash-'))
      : path.join(fixture, 'evidence');
    await mkdir(evidence, { recursive: true, mode: 0o700 });
    const report: { qualifications: Record<string, boolean>; cuts: unknown[]; error?: string; construction?: unknown; failedFixture?: string } = {
      qualifications: { actualInstalledRegisterSigkill: false, powerLoss: false, revokeCrash: false, credentialAuthority: false, installedI1: false }, cuts: [] };
    try {
      const signed = await buildInstalledSupervisorPackage(fixture);
      report.construction = { bundle: signed.bundle, publicReleaseTrustKeys: signed.releaseKeys };
      for (const phase of ['before', 'after'] as const) {
        const stateRoot = path.join(fixture, phase);
        const installed = await createInstalledRuntime({ releaseKeys: signed.releaseKeys }).installInitial({ packageRoot: signed.packageRoot, stateRoot });
        const root = await lstat(stateRoot, { bigint: true });
        const rootDigest = canonicalSha256({ schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux', canonicalAbsolutePath: stateRoot,
          ownerUid: Number(root.uid), deviceId: root.dev.toString(), directoryFileId: root.ino.toString(), mode: 448, openedNoFollow: true, layoutVersion: 1 });
        const ownerPrincipalId = identityHash('cliq-local-principal-v1', rootDigest, 'linux', process.geteuid!());
        const trust = signed.bundle.entries.find(entry => entry.entryId === 'default_https_trust_store')!;
        const registration = (id: string): EndpointRegistrationV1 => {
          const value: EndpointRegistrationV1 = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1', endpointRegistrationId: id,
            registrationKind: 'user', ownerPrincipalId, purposes: ['model_endpoint'],
            target: { scheme: 'https', hostAscii: 'endpoint.invalid', port: 443, basePath: '/v1', redirectPolicy: 'reject_all' },
            tls: { serverNameAscii: 'endpoint.invalid', minimumVersion: 'TLSv1.3', trustStoreRuntimeBundleRef: installed.bundleDigest,
              trustStoreRuntimeBundleManifestDigest: signed.bundle.manifestDigest, trustStoreEntryId: 'default_https_trust_store',
              trustStoreRef: trust.digest, trustStoreDigest: trust.digest, spkiSha256Pins: ['4'.repeat(64)] },
            createdAt: '2026-10-11T00:00:00.000Z', endpointIdentityDigest: '', tlsPolicyDigest: '', registrationDigest: '' };
          value.tlsPolicyDigest = canonicalSha256(value.tls);
          value.endpointIdentityDigest = canonicalSha256({ target: value.target, tlsPolicyDigest: value.tlsPolicyDigest });
          value.registrationDigest = digestOmitting(value, 'registrationDigest'); return value;
        };
        const request = (id: string, requestId: string): Request => {
          const value = registration(id);
          const core = { schemaVersion: 1, kind: 'register', ownerPrincipalId, registration: value,
            expectedRegistrationArtifactRef: canonicalSha256(value), commandDigest: '' } as const;
          return { schemaVersion: 1, kind: 'commit', requestId, commandCore: { ...core, commandDigest: digestOmitting(core, 'commandDigest') } };
        };
        const bootstrap = path.join(stateRoot, 'runtime/bootstrap');
        // Real business warm-up, not raw SQL: finish schema/trust publication
        // before the single target writer. Startup/no-op scopes do not commit it.
        response(bootstrap, fixture, request('crash-seed', '019a0011-0000-7000-8000-000000000021'), 'operation');
        const target = request('crash-target', '019a0011-0000-7000-8000-000000000022');
        await writeFile(path.join(evidence, `${phase}-request.json`), canonicalJsonBytes(target), { flag: 'wx', mode: 0o600 });
        const read = { schemaVersion: 1, kind: 'read', endpointRegistrationId: 'crash-target' } as const;
        assert.equal(response(bootstrap, fixture, read, 'record').value, null);
        const entry = signed.bundle.entries.find(value => value.role === 'supervisor')!;
        const image = path.join(stateRoot, 'runtime/bundles', installed.bundleDigest, entry.relativePath);
        const cut = await cutWriter({ phase, bootstrap, fixture, request: target, image: physical(await lstat(image, { bigint: true })),
          imageDigest: entry.digest, wal: path.join(stateRoot, 'credentials/authority.sqlite-wal'), evidence });
        report.cuts.push(cut);
        const restored = response(bootstrap, fixture, read, 'record').value;
        await writeFile(path.join(evidence, `${phase}-restored-record.json`), canonicalJsonBytes(restored), { flag: 'wx', mode: 0o600 });
        if (phase === 'before') assert.equal(restored, null, 'before-cut must retain the complete old state');
        else {
          const record = decodeEndpointAuthorityRecord(restored);
          assert.equal(record.state, 'active'); assert.equal(record.authorityRevision, 1);
          assert.equal(record.sourceRequestId, '019a0011-0000-7000-8000-000000000022');
        }
        const replay = response(bootstrap, fixture, target, 'operation');
        await writeFile(path.join(evidence, `${phase}-replay-response.json`), replay.bytes, { flag: 'wx', mode: 0o600 });
        const operation = decodeEndpointAuthorityOperation(replay.value);
        assert.equal(operation.disposition, 'registered'); assert.equal(operation.committedAuthorityRevision, 1);
        assert.deepEqual(operation.commandCore, target.kind === 'commit' ? target.commandCore : undefined);
        const record = decodeEndpointAuthorityRecord(response(bootstrap, fixture, read, 'record').value);
        assert.equal(record.recordDigest, operation.resultRecordDigest);
        if (phase === 'after') assert.deepEqual(record, restored, 'replay must return the already-committed operation without a new record');
        assert.equal(response(bootstrap, fixture, target, 'operation').bytes, replay.bytes, 'fresh-process replay must retain exact original provenance');
      }
      report.qualifications.actualInstalledRegisterSigkill = true;
    } catch (error) { report.error = error instanceof Error ? error.message : String(error); report.failedFixture = fixture; throw error; }
    finally {
      await writeFile(path.join(evidence, 'report.json'), JSON.stringify(report, null, 2), { flag: 'wx', mode: 0o600 });
      if (!report.error) await rm(fixture, { recursive: true, force: true });
    }
  });
