// Real Linux bootstrap-to-selected SEA/read-only startup, not systemd/keeper/worker/I1.
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, readlink, realpath, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../src/kernel/identity.js';
import { parseJsonStrict } from '../../src/kernel/json.js';
import type { PlatformProcessIdentityV1, StateOwnerAcquisitionEvidenceV1, StateOwnerRecordV1 } from '../../src/kernel/types.js';
import { createInstalledRuntime } from '../../src/state/installed-runtime.js';
import { STATE_OWNER_NATIVE_RELATIVE_PATH } from '../../src/state/native-owner.js';
import { buildInstalledSupervisorPackage } from './testing/installed-supervisor-package.js';
import { qualifyInstalledInspectorSignal, type InstalledInspectorSignalReport } from './testing/installed-inspector-signal.js';
import { inspectInstalledOwner, installedReadClientScript as clientScript } from './testing/installed-read-control.js';
import { SUPERVISOR_SEA_CARRIER_CHECKSUMS, SUPERVISOR_SEA_NODE_VERSION } from './testing/supervisor-sea-builder.js';

assert.equal(process.platform, 'linux', 'installed startup qualification requires a real Linux runner');
assert.equal(process.arch, 'x64', 'no installed startup carrier qualified for this architecture');
assert(process.argv.length <= 3, 'expected at most one new absolute output directory');
if (process.argv[2]) {
  assert(path.isAbsolute(process.argv[2]), 'output directory must be absolute');
  await mkdir(process.argv[2], { mode: 0o700 }); // Never adopt an existing fixture.
}
const fixture = await realpath(process.argv[2] ?? await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-startup-')));
await chmod(fixture, 0o700);
const stateRoot = path.join(fixture, 'state');
const report: { diagnosticOnly: true; scope: string; nodeVersion: string; carrierArchiveDigest: string;
  bundleDigest?: string; manifestDigest?: string; supervisorImageDigest?: string; nativeHelperDigest?: string;
  result?: unknown; startupRefusal?: unknown; keeperOutsideServiceRefusal?: unknown;
  inspectorSignal?: InstalledInspectorSignalReport; cleanup?: unknown; error?: string } = {
  diagnosticOnly: true, scope: 'actual SEA bootstrap-to-selected execution, image/helper/genesis and read-only control startup only; not systemd/keeper/worker/admission/model/I1',
  nodeVersion: SUPERVISOR_SEA_NODE_VERSION,
  carrierArchiveDigest: SUPERVISOR_SEA_CARRIER_CHECKSUMS['linux-x64']!,
};

function run(executable: string, args: string[], cwd = fixture) {
  const result = spawnSync(executable, args, { encoding: 'utf8', timeout: 60_000, cwd,
    maxBuffer: 2 * 1024 * 1024 });
  assert.equal(result.error, undefined, `${executable}: ${result.error}`);
  assert.equal(result.status, 0, `${executable}: ${result.stderr}`);
  return result;
}

async function bounded<T>(pending: Promise<T>, milliseconds = 30_000): Promise<T> {
  let timer!: ReturnType<typeof setTimeout>;
  try {
    return await Promise.race([pending, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('installed startup qualification timed out')), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

function inspectOwner(): StateOwnerRecordV1 | undefined {
  return inspectInstalledOwner(stateRoot);
}

async function casJson<T>(ref: string): Promise<T> {
  assert.match(ref, /^[0-9a-f]{64}$/u);
  const filename = path.join(stateRoot, KERNEL_CAS_DIRECTORY, ref);
  const before = await lstat(filename, { bigint: true });
  assert(before.isFile()); assert.equal(before.nlink, 1n);
  assert.equal(before.uid, BigInt(process.geteuid!())); assert.equal(before.mode & 0o7777n, 0o400n);
  const bytes = await readFile(filename);
  const after = await lstat(filename, { bigint: true });
  for (const key of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(after[key], before[key]);
  assert.equal(BigInt(bytes.byteLength), after.size); assert.equal(sha256Bytes(bytes), ref);
  const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as T;
  assert.deepEqual(canonicalJsonBytes(value), bytes);
  return value;
}

let supervisor: ChildProcess | undefined;
let closed: Promise<{ code: number | null; signal: NodeJS.Signals | null }> | undefined;
let stderr = '';
let spawnError: Error | undefined;
async function stopSupervisor(): Promise<void> {
  if (!supervisor || !closed) return;
  if (supervisor.exitCode === null && supervisor.signalCode === null) {
    supervisor.kill('SIGTERM');
    try { await bounded(closed); }
    catch (error) {
      supervisor.kill('SIGKILL'); await bounded(closed);
      throw error; // A kill fallback joins resources, never qualifies cleanup.
    }
  }
  const exit = await closed;
  report.cleanup = { ...exit, joined: true };
}

try {
  const { packageRoot, releaseKeys, bundle, contents, carrier } = await buildInstalledSupervisorPackage(fixture);
  const manifestBytes = canonicalJsonBytes(bundle);
  const installed = await createInstalledRuntime({ releaseKeys }).installInitial({ packageRoot, stateRoot });
  assert.equal(installed.bundleDigest, canonicalSha256(bundle));
  const bootstrap = path.join(stateRoot, 'runtime/bootstrap');
  assert.deepEqual(await readFile(bootstrap), contents[0]!.bytes);
  const wrongHelper = path.join(stateRoot, 'runtime', STATE_OWNER_NATIVE_RELATIVE_PATH);
  await assert.rejects(lstat(wrongHelper), { code: 'ENOENT' });
  assert.deepEqual(await readFile(path.join(stateRoot, 'runtime/bundles', installed.bundleDigest, STATE_OWNER_NATIVE_RELATIVE_PATH)), contents[1]!.bytes);
  const cwd = path.join(fixture, 'unrelated-cwd'); await mkdir(cwd, { mode: 0o700 });
  report.bundleDigest = installed.bundleDigest; report.manifestDigest = bundle.manifestDigest;
  report.supervisorImageDigest = sha256Bytes(contents[0]!.bytes); report.nativeHelperDigest = sha256Bytes(contents[1]!.bytes);
  const rootInfo = await lstat(stateRoot, { bigint: true });
  const rootLocator = `${rootInfo.dev}:${rootInfo.ino}:${rootInfo.uid}`;
  for (const [args, message] of [
    [[], 'expected a fixed installed Supervisor role'],
    [['--installed-supervisor', stateRoot, installed.bundleDigest, rootLocator], 'installed Supervisor differs from the fixed selected image'],
  ] as const) {
    // Actual SEA refusals: neither the removed no-argument bootstrap path nor
    // forged selected-role locators may acquire even the first StateOwner.
    const refused = spawnSync(bootstrap, [...args], { cwd, env: { PATH: process.env.PATH },
      encoding: 'utf8', timeout: 30_000, maxBuffer: 128 * 1024 });
    assert.equal(refused.error, undefined); assert.equal(refused.status, 1); assert.equal(refused.signal, null);
    const diagnostics = refused.stderr.trim().split('\n').map(line => parseJsonStrict(line)) as { message?: string }[];
    assert(diagnostics.some(value => value.message === message), 'refusal must come from the actual closed role boundary');
    await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
    await assert.rejects(lstat(path.join(stateRoot, 'runtime/state-owner.lock')), { code: 'ENOENT' });
  }
  // A bootstrap-to-selected refusal must retain its real stderr, not merely
  // exit 1 after Node replaced closed standard descriptors with /dev/null.
  // This process has no disposable authorized keeper service/delegation. It
  // must refuse before StateOwner, regardless of the keeper's implementation.
  const keeperRefused = spawnSync(bootstrap, ['--bootstrap-keeper'], { cwd, env: { PATH: process.env.PATH },
    stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', timeout: 30_000, maxBuffer: 128 * 1024 });
  report.keeperOutsideServiceRefusal = { status: keeperRefused.status, signal: keeperRefused.signal, stderr: keeperRefused.stderr };
  assert.equal(keeperRefused.error, undefined); assert.equal(keeperRefused.status, 1); assert.equal(keeperRefused.signal, null);
  const keeperDiagnostics = keeperRefused.stderr.trim().split('\n').filter(Boolean).map(line => parseJsonStrict(line)) as
    { diagnosticOnly?: boolean; scope?: string; message?: string }[];
  assert(keeperDiagnostics.some(value => value.diagnosticOnly === true && value.scope === 'installed-read-startup' &&
    value.message === 'installed keeper requires its own empty delegated service root'),
  'keeper refusal diagnostic must survive terminal selected-image exec');
  for (const relative of [KERNEL_DATABASE_FILENAME, `${KERNEL_DATABASE_FILENAME}-wal`, `${KERNEL_DATABASE_FILENAME}-shm`,
    'runtime/state-owner.lock', 'runtime/control-v1.sock'])
    await assert.rejects(lstat(path.join(stateRoot, relative)), { code: 'ENOENT' });
  supervisor = spawn(bootstrap, ['--bootstrap-supervisor'], { cwd, env: { PATH: process.env.PATH }, stdio: ['ignore', 'ignore', 'pipe'] });
  supervisor.once('error', error => { spawnError = error; });
  supervisor.stderr!.on('data', (bytes: Buffer) => { stderr = (stderr + bytes.toString('utf8')).slice(-128 * 1024); });
  closed = new Promise(resolve => supervisor!.once('close', (code, signal) => resolve({ code, signal })));
  const socketPath = path.join(stateRoot, 'runtime/control-v1.sock');
  const deadline = Date.now() + 30_000;
  for (;;) {
    if (spawnError) throw spawnError;
    if (supervisor.exitCode !== null || supervisor.signalCode !== null) {
      const exit = await closed;
      const diagnostics = stderr.split('\n').flatMap(line => { try { return [parseJsonStrict(line)]; } catch { return []; } });
      const refusal = diagnostics.find(value => value !== null && typeof value === 'object'
        && (value as { message?: string }).message === 'expected only the installed Linux SEA bootstrap, without arguments');
      report.startupRefusal = { ...exit, stderr };
      if (refusal) {
        assert.deepEqual(exit, { code: 1, signal: null }, 'RED must be the real unsupported bootstrap mode, not a fixture failure');
        await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
        report.startupRefusal = { ...exit, cause: 'unsupported bootstrap-supervisor mode', authorityDatabaseAbsent: true, stderr };
      }
      throw new Error(`installed SEA startup exited before actual UDS readiness: ${JSON.stringify(report.startupRefusal)}`);
    }
    const socket = await lstat(socketPath).catch((error: NodeJS.ErrnoException) => { if (error.code === 'ENOENT') return undefined; throw error; });
    if (socket) { assert(socket.isSocket()); assert.equal(socket.uid, process.geteuid!()); break; }
    assert(Date.now() < deadline, 'installed SEA did not open its actual native UDS');
    await delay(10);
  }
  const owner = inspectOwner();
  assert(owner); assert.equal(owner.state, 'active'); assert.equal(owner.ownerEpoch, 1);
  assert.equal(owner.runtimeBundleRef, installed.bundleDigest); assert.equal(owner.runtimeBundleManifestDigest, bundle.manifestDigest);
  assert.equal(owner.supervisorExecutableDigest, report.supervisorImageDigest);
  const identity = await casJson<PlatformProcessIdentityV1>(owner.processIdentityRef);
  assert.equal(identity.pid, supervisor.pid); assert.equal(identity.ownerUid, process.geteuid!());
  assert.equal(identity.identityDigest, digestOmitting(identity, 'identityDigest'));
  assert.equal(owner.processIdentityDigest, identity.identityDigest);
  const procStat = await readFile(`/proc/${supervisor.pid}/stat`, 'utf8');
  const procFields = procStat.slice(procStat.lastIndexOf(')') + 2).trim().split(/\s+/u);
  assert.notEqual(procFields[0], 'Z'); assert.match(procFields[19]!, /^[0-9]+$/u);
  assert.equal(identity.processStartToken, `linux-proc-start-ticks:${procFields[19]}`);
  const selectedImage = path.join(stateRoot, 'runtime/bundles', installed.bundleDigest, 'supervisor');
  const selectedInfo = await lstat(selectedImage, { bigint: true });
  const bootstrapInfo = await lstat(bootstrap, { bigint: true });
  const actualImage = `/proc/${supervisor.pid}/exe`;
  assert.equal(await readlink(actualImage), selectedImage, 'actual process must execute the immutable selected image, not bootstrap');
  const actualInfo = await stat(actualImage, { bigint: true });
  for (const key of ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const)
    assert.equal(actualInfo[key], selectedInfo[key]);
  assert(actualInfo.dev !== bootstrapInfo.dev || actualInfo.ino !== bootstrapInfo.ino,
    'identical signed bytes do not prove that bootstrap actually executed the selected inode');
  assert.equal(identity.executableImageDigest, createHash('sha256').update(await readFile(`/proc/${supervisor.pid}/exe`)).digest('hex'));
  assert.equal(identity.executableImageDigest, report.supervisorImageDigest);
  const acquisition = await casJson<StateOwnerAcquisitionEvidenceV1>(owner.acquisitionEvidenceRef);
  assert.equal(acquisition.kind, 'genesis'); assert(acquisition.kind === 'genesis');
  assert.equal(acquisition.ownerEpoch, 1); assert.equal(acquisition.ownerTableObservation, 'empty');
  assert.equal(acquisition.runtimeBundleRef, installed.bundleDigest);
  assert.equal(acquisition.runtimeBundleManifestDigest, bundle.manifestDigest);
  assert.equal(acquisition.processIdentityRef, owner.processIdentityRef);
  assert.equal(acquisition.evidenceDigest, digestOmitting(acquisition, 'evidenceDigest'));
  assert.equal(owner.acquisitionEvidenceDigest, acquisition.evidenceDigest);
  const generation = await casJson<Record<string, any>>(acquisition.kernelGenerationIdentityRef);
  assert.equal(generation.origin, 'fresh_installed'); assert.equal(generation.stateSchemaVersion, KERNEL_STATE_SCHEMA_VERSION);
  assert.equal(generation.runtimeBundleRef, installed.bundleDigest); assert.equal(generation.runtimeBundleManifestDigest, bundle.manifestDigest);
  assert.equal(generation.generationDigest, digestOmitting(generation, 'generationDigest'));
  assert.equal(acquisition.kernelGenerationIdentityDigest, generation.generationDigest);
  const namespace = await casJson<Record<string, any>>(generation.casNamespaceManifestRef);
  const seed = [manifestBytes, ...contents.filter(entry => !entry.executable).map(entry => entry.bytes)]
    .map(bytes => ({ artifactRef: sha256Bytes(bytes), byteCount: bytes.byteLength }))
    .sort((left, right) => left.artifactRef < right.artifactRef ? -1 : left.artifactRef > right.artifactRef ? 1 : 0);
  assert.equal(seed.length, 4); assert.equal(namespace.snapshotBoundary, 'generation_birth');
  assert.deepEqual(canonicalJsonBytes(namespace.entries), canonicalJsonBytes(seed)); assert.equal(namespace.objectCount, seed.length);
  assert.equal(namespace.totalBytes, seed.reduce((total, entry) => total + entry.byteCount, 0));
  assert.equal(namespace.rootDigest, canonicalSha256(seed));
  assert.equal(namespace.manifestDigest, digestOmitting(namespace, 'manifestDigest'));
  assert.equal(generation.casNamespaceManifestDigest, namespace.manifestDigest);
  assert.equal(generation.casRootDigest, namespace.rootDigest);
  const checkControl = async (): Promise<void> => {
    const client = run(process.execPath, ['--input-type=module', '-e', clientScript, socketPath], cwd);
    const exchanges = parseJsonStrict(client.stdout.trim()) as Array<{ hello: string; status: string }>;
    assert.equal(exchanges.length, 2);
    const summary = { schemaVersion: 1, runtimeBundleRef: installed.bundleDigest, bundleDigest: installed.bundleDigest, bundleVersion: bundle.bundleVersion };
    for (const exchange of exchanges) {
      const hello = parseJsonStrict(exchange.hello) as Record<string, any>;
      const status = parseJsonStrict(exchange.status) as Record<string, any>;
      assert.equal(canonicalJsonBytes(hello).toString('utf8'), exchange.hello);
      assert.equal(canonicalJsonBytes(status).toString('utf8'), exchange.status);
      assert.equal(hello.protocolVersion, 1); assert.equal(status.protocolVersion, 1);
      assert.equal(hello.ok, true); assert.equal(hello.result.method, 'control.hello');
      assert.equal(hello.result.protocolVersion, 1);
      assert.equal(hello.result.serverBuild, 'cliq-installed-v1');
      assert.deepEqual(canonicalJsonBytes(hello.result.controlSchemaRange), canonicalJsonBytes({ min: 1, max: 1 }));
      assert.equal(hello.result.supervisorInstanceId, owner.supervisorInstanceId);
      assert.deepEqual(canonicalJsonBytes(hello.result.activeRuntimeBundle), canonicalJsonBytes(summary));
      assert.deepEqual(canonicalJsonBytes(hello.result.headlessSchemaRange), canonicalJsonBytes({ min: 1, max: 1 }));
      assert.deepEqual(hello.result.enabledFeatureIds, ['supervisor.status']);
      assert.equal(status.ok, true);
      assert.deepEqual(canonicalJsonBytes(status.result), canonicalJsonBytes({ method: 'supervisor.status', health: 'degraded', supervisorInstanceId: owner.supervisorInstanceId,
        queue: { queuedRuns: 0, runningRuns: 0, capacity: 0 }, stateSchemaVersion: KERNEL_STATE_SCHEMA_VERSION,
        activeRuntimeBundle: summary, installedRuntimeBundles: [summary], incompatiblePinnedRunCount: 0 }));
    }
    assert.deepEqual(inspectOwner(), owner, 'read-only disconnect/reconnect cannot replace the actual owner');
  };
  report.inspectorSignal = { diagnosticOnly: true };
  await qualifyInstalledInspectorSignal({ carrier, cwd, supervisor, selectedImage,
    processStartToken: identity.processStartToken, stderr: () => stderr, checkControl, report: report.inspectorSignal });
  await stopSupervisor();
  assert.deepEqual(report.cleanup, { code: 0, signal: null, joined: true });
  const terminal = inspectOwner();
  assert(terminal?.state === 'terminal'); assert.equal(terminal.ownerEpoch, 1);
  assert.equal(terminal.terminalReason, 'graceful_release');
  await assert.rejects(lstat(socketPath), { code: 'ENOENT' });
  report.result = { qualified: true, supervisorPid: identity.pid, processStartToken: identity.processStartToken,
    ownerEpoch: owner.ownerEpoch, supervisorInstanceId: owner.supervisorInstanceId, reconnects: 3,
    closedRoleRefusals: 2, actualSelectedPath: selectedImage, actualSelectedDevice: actualInfo.dev.toString(), actualSelectedInode: actualInfo.ino.toString() };
  console.log('Installed SEA bootstrap-to-selected execution/image/helper/genesis/read-only startup qualification passed; not a completed I1');
} catch (error) {
  report.error = String((error as Error).stack ?? error).slice(0, 16_384);
  throw error;
} finally {
  try { await stopSupervisor(); }
  finally {
    await writeFile(path.join(fixture, 'report.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    console.log(`Installed startup qualification fixture/report retained: ${fixture}`);
  }
}
