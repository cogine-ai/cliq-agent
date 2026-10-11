// Real Linux SEA installation/read-only startup, not systemd/keeper/worker/I1.
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as delay } from 'node:timers/promises';
import { rootCertificates } from 'node:tls';
import { fileURLToPath } from 'node:url';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../src/kernel/identity.js';
import { parseJsonStrict } from '../../src/kernel/json.js';
import type { PlatformProcessIdentityV1, StateOwnerAcquisitionEvidenceV1, StateOwnerRecordV1 } from '../../src/kernel/types.js';
import { policyProfile, verifyRuntimeBundle, type RuntimeBundleManifest } from '../../src/policy/runtime-authority.js';
import { createInstalledRuntime } from '../../src/state/installed-runtime.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_RELATIVE_PATH } from '../../src/state/native-owner.js';
import { buildSupervisorSeaImage, prepareSupervisorSeaCarrier,
  SUPERVISOR_SEA_CARRIER_CHECKSUMS, SUPERVISOR_SEA_NODE_VERSION } from './testing/supervisor-sea-builder.js';

assert.equal(process.platform, 'linux', 'installed startup qualification requires a real Linux runner');
assert.equal(process.arch, 'x64', 'no installed startup carrier qualified for this architecture');
assert(process.argv.length <= 3, 'expected at most one new absolute output directory');
if (process.argv[2]) {
  assert(path.isAbsolute(process.argv[2]), 'output directory must be absolute');
  await mkdir(process.argv[2], { mode: 0o700 }); // Never adopt an existing fixture.
}
const fixture = await realpath(process.argv[2] ?? await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-startup-')));
await chmod(fixture, 0o700);
const repository = fileURLToPath(new URL('../..', import.meta.url));
const stateRoot = path.join(fixture, 'state');
const report: { diagnosticOnly: true; scope: string; nodeVersion: string; carrierArchiveDigest: string;
  bundleDigest?: string; manifestDigest?: string; supervisorImageDigest?: string; nativeHelperDigest?: string;
  result?: unknown; startupRefusal?: unknown; cleanup?: unknown; error?: string } = {
  diagnosticOnly: true, scope: 'actual SEA installation, image/helper/genesis and read-only control startup only; not systemd/keeper/worker/admission/model/I1',
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
  // Read-only inspection cannot create a missing database or grant StateOwner.
  const database = new DatabaseSync(path.join(stateRoot, KERNEL_DATABASE_FILENAME), { readOnly: true, allowExtension: false });
  try {
    const version = database.prepare('PRAGMA user_version').get();
    assert.equal(version?.user_version, KERNEL_STATE_SCHEMA_VERSION);
    const rows = database.prepare('SELECT owner_epoch, supervisor_instance_id, record_json, state, row_digest FROM state_owners').all();
    assert(rows.length <= 1, 'this qualification starts exactly one real Supervisor');
    if (!rows.length) return undefined;
    const row = rows[0]!;
    assert.equal(typeof row.record_json, 'string');
    const owner = parseJsonStrict(row.record_json as string) as StateOwnerRecordV1;
    assert.equal(owner.ownerEpoch, row.owner_epoch);
    assert.equal(owner.supervisorInstanceId, row.supervisor_instance_id);
    assert.equal(owner.state, row.state);
    assert.equal(owner.rowDigest, row.row_digest);
    assert.equal(owner.rowDigest, digestOmitting(owner, 'rowDigest'));
    return owner;
  } finally { database.close(); }
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

// Independent ordinary Node client. It controls only its real socket, never
// installation paths, Store internals, keys or authority evidence.
const helloBytes = canonicalJsonBytes({ protocolVersion: 1, method: 'control.hello',
  clientBuild: 'installed-startup-qualification', controlSchemaRange: { min: 1, max: 1 },
  headlessSchemaRange: { min: 1, max: 1 }, requestedFeatureIds: ['supervisor.status'] }).toString('base64');
const statusBytes = canonicalJsonBytes({ protocolVersion: 1, method: 'supervisor.status' }).toString('base64');
const clientScript = `import assert from 'node:assert/strict';
import net from 'node:net';
const exchanges = [];
for (let attempt = 0; attempt < 2; attempt++) {
  const socket = net.createConnection(process.argv[1]);
  let input = Buffer.alloc(0), waiter, error;
  socket.on('data', chunk => {
    try {
      input = Buffer.concat([input, chunk]);
      assert(input.length <= 1048580);
      while (input.length >= 4) {
        const length = input.readUInt32BE(0);
        assert(length >= 1 && length <= 1048576);
        if (input.length < 4 + length) break;
        const json = new TextDecoder('utf-8', {fatal:true}).decode(input.subarray(4, 4 + length));
        input = input.subarray(4 + length);
        assert(waiter, 'unsolicited response frame');
        const complete = waiter; waiter = undefined; complete.resolve(json);
      }
    } catch (failure) { error = failure; waiter?.reject(failure); socket.destroy(); }
  });
  socket.on('error', failure => { error = failure; waiter?.reject(failure); });
  socket.on('close', () => { error ??= new Error('peer closed before response'); waiter?.reject(error); });
  const closed = new Promise(resolve => socket.once('close', resolve));
  try {
    await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
    const request = async bytes => {
      if (error) throw error;
      assert(!waiter, 'one fixed request is outstanding at a time');
      return await new Promise((resolve, reject) => {
        waiter = {resolve,reject};
        const header = Buffer.alloc(4); header.writeUInt32BE(bytes.length);
        try { socket.write(Buffer.concat([header, bytes])); }
        catch (failure) { waiter = undefined; reject(failure); }
      });
    };
    const hello = await request(Buffer.from(${JSON.stringify(helloBytes)}, 'base64'));
    const status = await request(Buffer.from(${JSON.stringify(statusBytes)}, 'base64'));
    exchanges.push({hello,status});
  } finally { socket.destroy(); await closed; }
}
console.log(JSON.stringify(exchanges));`;

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
  const { nodeRoot, carrier } = await prepareSupervisorSeaCarrier(fixture);
  const keys = generateKeyPairSync('ed25519');
  const releaseKeys = [{ keyId: 'explicit-installed-startup-test-root',
    publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  const rootAsset = path.join(fixture, 'explicit-test-root.json');
  await writeFile(rootAsset, canonicalJsonBytes(releaseKeys), { flag: 'wx', mode: 0o400 });
  const packageRoot = path.join(fixture, 'package');
  await mkdir(packageRoot, { mode: 0o700 });
  const supervisorFile = await buildSupervisorSeaImage({ fixture, carrier,
    entryPoint: path.join(repository, 'src/state/testing/installed-supervisor-sea-child.ts'),
    executable: path.join(packageRoot, 'supervisor'), variant: 'installed-supervisor',
    assets: { 'explicit-test-root.json': rootAsset } });
  const helper = path.join(packageRoot, STATE_OWNER_NATIVE_RELATIVE_PATH);
  await mkdir(path.dirname(helper), { recursive: true, mode: 0o700 });
  run('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', '-shared', '-fPIC',
    '-I', path.join(nodeRoot, 'include/node'), path.join(repository, 'native/state-owner/state-owner.c'), '-o', helper]);
  await chmod(helper, 0o500);
  const profile = policyProfile();
  const rootCore = { schemaVersion: 1, format: 'cliq-sandbox-root-profile-v1', protocol: 'cliq-fresh-empty-root-v1',
    filesystemKind: 'fresh_ephemeral_tmpfs', fixedDirectories: ['/home/cliq', '/tmp', '/work'], persistent: false, networkConfiguration: 'none' };
  const contents = [
    { entryId: 'installed-supervisor', role: 'supervisor', relativePath: 'supervisor', executable: true, bytes: await readFile(supervisorFile) },
    { entryId: STATE_OWNER_NATIVE_ENTRY_ID, role: 'platform_helper', relativePath: STATE_OWNER_NATIVE_RELATIVE_PATH,
      executable: true, bytes: await readFile(helper) },
    { entryId: 'unused-installed-worker', role: 'worker', relativePath: 'workers/worker', executable: true,
      bytes: Buffer.from('opaque qualification-only worker; never exec or dlopen\n') },
    { entryId: 'installed-policy', role: 'policy_engine', relativePath: 'profiles/policy.json', executable: false, bytes: canonicalJsonBytes(profile) },
    { entryId: 'default_https_trust_store', role: 'trust_store', relativePath: 'profiles/https-trust.pem', executable: false,
      bytes: Buffer.from(rootCertificates.join('\n')) },
    { entryId: 'installed-empty-root', role: 'sandbox_root_profile', relativePath: 'profiles/empty-root.json', executable: false,
      bytes: canonicalJsonBytes({ ...rootCore, profileDigest: canonicalSha256(rootCore) }) },
  ];
  for (const entry of contents.slice(2)) {
    const filename = path.join(packageRoot, entry.relativePath);
    await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
    await writeFile(filename, entry.bytes, { flag: 'wx', mode: entry.executable ? 0o500 : 0o400 });
  }
  const bundle: RuntimeBundleManifest = {
    schemaVersion: 1, bundleVersion: 'installed-sea-read-qualification-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: KERNEL_STATE_SCHEMA_VERSION }, workerProtocolRange: { min: 1, max: 1 },
    entries: contents.map(({ bytes, ...entry }) => ({ ...entry, version: '1', digest: sha256Bytes(bytes), byteCount: bytes.byteLength })),
    structuredArtifacts: [{ kind: 'policy_engine_profile', artifactId: 'installed-policy', rootEntryId: 'installed-policy',
      artifactRef: canonicalSha256(profile), semanticDigest: profile.profileDigest, memberRefs: [] }],
    guestToolchainManifestRefs: [], publisherKeyId: releaseKeys[0]!.keyId, manifestDigest: '', signature: '',
  };
  const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  verifyRuntimeBundle(bundle, releaseKeys);
  const manifestBytes = canonicalJsonBytes(bundle);
  await writeFile(path.join(packageRoot, 'manifest.json'), manifestBytes, { flag: 'wx', mode: 0o400 });
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
  supervisor = spawn(bootstrap, [], { cwd, env: { PATH: process.env.PATH }, stdio: ['ignore', 'ignore', 'pipe'] });
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
        && (value as { code?: string }).code === 'ENOENT') as { path?: string } | undefined;
      report.startupRefusal = { ...exit, stderr, intendedHelperPath: wrongHelper };
      if (refusal) {
        assert.equal(refusal.path, wrongHelper, 'RED must be the actual fixed SEA helper lookup, not a fixture failure');
        await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
        report.startupRefusal = { ...exit, intendedHelperPath: wrongHelper, authorityDatabaseAbsent: true, stderr };
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
  assert.deepEqual(namespace.entries, seed); assert.equal(namespace.objectCount, seed.length);
  assert.equal(namespace.totalBytes, seed.reduce((total, entry) => total + entry.byteCount, 0));
  assert.equal(namespace.rootDigest, canonicalSha256(seed));
  assert.equal(namespace.manifestDigest, digestOmitting(namespace, 'manifestDigest'));
  assert.equal(generation.casNamespaceManifestDigest, namespace.manifestDigest);
  assert.equal(generation.casRootDigest, namespace.rootDigest);
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
    assert.equal(hello.result.serverBuild, 'installed-sea-read-qualification');
    assert.deepEqual(hello.result.controlSchemaRange, { min: 1, max: 1 });
    assert.equal(hello.result.supervisorInstanceId, owner.supervisorInstanceId);
    assert.deepEqual(hello.result.activeRuntimeBundle, summary);
    assert.deepEqual(hello.result.headlessSchemaRange, { min: 1, max: 1 });
    assert.deepEqual(hello.result.enabledFeatureIds, ['supervisor.status']);
    assert.equal(status.ok, true);
    assert.deepEqual(status.result, { method: 'supervisor.status', health: 'degraded', supervisorInstanceId: owner.supervisorInstanceId,
      queue: { queuedRuns: 0, runningRuns: 0, capacity: 0 }, stateSchemaVersion: KERNEL_STATE_SCHEMA_VERSION,
      activeRuntimeBundle: summary, installedRuntimeBundles: [summary], incompatiblePinnedRunCount: 0 });
  }
  assert.deepEqual(inspectOwner(), owner, 'read-only disconnect/reconnect cannot replace the actual owner');
  await stopSupervisor();
  assert.deepEqual(report.cleanup, { code: 0, signal: null, joined: true });
  const terminal = inspectOwner();
  assert(terminal?.state === 'terminal'); assert.equal(terminal.ownerEpoch, 1);
  assert.equal(terminal.terminalReason, 'graceful_release');
  await assert.rejects(lstat(socketPath), { code: 'ENOENT' });
  report.result = { qualified: true, supervisorPid: identity.pid, processStartToken: identity.processStartToken,
    ownerEpoch: owner.ownerEpoch, supervisorInstanceId: owner.supervisorInstanceId, reconnects: 1 };
  console.log('Installed SEA image/helper/genesis/read-only startup qualification passed; not a completed I1');
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
