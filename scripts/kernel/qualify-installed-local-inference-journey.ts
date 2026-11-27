// One genuine installed model turn. The disposable systemd coordinator owns
// the exact account, manager and volume. This driver adds no endpoint or key.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { chown, lstat, mkdir, open, readdir, readFile, readlink, realpath, rename, stat, writeFile, type FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as delay } from 'node:timers/promises';
import { KERNEL_DATABASE_FILENAME } from '../../src/config.js';
import { decodeHeadlessControlRecord, decodeInstalledControlRequest, decodeInstalledControlResponse,
  type InstalledControlFeature, type InstalledControlRequestV1, type InstalledControlResponseFor } from '../../src/control/v1.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import type { ModelTurnItem, ToolResultItem, ToolResultModelContentV1, ToolResultPayloadV1 } from '../../src/kernel/continuation.js';
import type { ProcessContainment, ProcessContainmentDeathEvidenceV1 } from '../../src/kernel/execution.js';
import { assertArtifactRef, digestOmitting, sha256Bytes } from '../../src/kernel/identity.js';
import { parseJsonStrict } from '../../src/kernel/json.js';
import { decodeLocalInferenceBoundary, decodeLocalInferenceCycle, decodeLocalInferenceLaunch, decodeLocalModelRegistration } from '../../src/kernel/local-inference.js';
import { decodeBoundLocalInferenceNativeInput } from '../../src/kernel/local-inference-native-input.js';
import { decodeModelOperationGrant } from '../../src/kernel/model-grant.js';
import { modelResponseDigest } from '../../src/model/attempt.js';
import { decodeLocalZeroCostProvenanceData } from '../../src/model/pricing.js';
import type { ModelRequestV1 } from '../../src/model/request.js';
import { decodeRetainedRunAssembly } from '../../src/model/run-assembly.js';
import { verifyLocalModelManifestAuthority } from '../../src/policy/local-model-authority.js';
import type { AgentModelTurn, ObservedToolCallInputV1, ToolCallInputV1 } from '../../src/protocol/agent-ir.js';
import { decodeAgentStop } from '../../src/runtime/stop.js';
import { decodeBudgetSettlement, decodeRunSpec } from '../../src/state/decoders.js';
import { installedServiceProfiles } from '../../src/state/installed-services.js';
import { bindLocalInferenceRuntime, localInferenceRuntimeInputs, localInferenceRuntimeRoots } from '../../src/state/local-inference-runtime.js';
import { MODEL_BROKER_ENTRY_ID } from '../../src/state/model-broker-native.js';
import { createCredentialSecretScanner } from './testing/credential-secret-scan.js';
import { buildInstalledClientDriver } from './testing/installed-client-build.js';
import { openInstalledClientConsumer } from './testing/installed-client-consumer.js';
import { InstalledDailyCommandError, runInstalledDailyCommand } from './testing/installed-daily-command.js';
import type { buildInstalledLocalInferencePackage } from './testing/installed-local-inference-package.js';
import { readLedger, transferPackage } from './testing/installed-node-journey.js';
import { inspectInstalledOwnerHistory } from './testing/installed-read-control.js';
import { buildInstalledSupervisorPackage } from './testing/installed-supervisor-package.js';

const model = 'functiongemma-cliq:270m-q4-k-m', alias = 'owned-functiongemma';
const proofPath = 'proof.txt', proof = 'owned local inference readback\n';
const objective = 'Call the read tool with path "proof.txt".';
// The installed context contract also reserves a 4096-token compaction
// envelope for this context. The single actual turn should stop much sooner.
const contextLimitTokens = 32768, maxOutputTokens = 4096;
const oneModelReservation = contextLimitTokens + maxOutputTokens;
const zero = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
const closureDigest = 'f0cd7ab296b69167884d02128a6956922686a0479f1b0ec79d08358e9faa65aa';
const planDigest = '792d70b2a6ef895ac06470b2bc7b935f99d885a3a3605d1e0691400240a80a4b';
const metadata = ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const;
const text = (bytes: Buffer) => new TextDecoder('utf-8', { fatal: true }).decode(bytes);
const same = (a: unknown, b: unknown) => assert(canonicalJsonBytes(a).equals(canonicalJsonBytes(b)));

assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64'); assert.equal(process.geteuid!(), 0);
const [mode, filename, inputDirectory, ...extra] = process.argv.slice(2);
assert.equal(mode, '--local-inference-campaign'); assert(filename && inputDirectory); assert.deepEqual(extra, []);
const ledger = await readLedger(filename), recipe = ledger.runJourney;
const installed = path.join(recipe.stateRoot, 'runtime/bundles');
const executable = path.join(recipe.packageRoot, 'supervisor');
const driver = path.join(recipe.buildFixture, 'installed-control-client-driver.mjs');
const environment = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' };
const prefix = ['--user', ledger.username, '--', '/usr/bin/env', '-i', 'HOME=' + ledger.home, 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C',
  'XDG_RUNTIME_DIR=/run/user/' + ledger.uid, 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + ledger.uid + '/bus'];
const scanner = createCredentialSecretScanner([randomBytes(32)], { maxBytes: 16 * 1024 * 1024, maxStreams: 256 });
const localSetupCommandTimeout = 180_000, localModelCommandTimeout = 360_000;
type DailySetupCommand = 'setup' | 'models_add' | 'models_list' | 'supervisor_start';
const isModelCommand = (command: DailySetupCommand) => command === 'models_add' || command === 'models_list';
const completedDailySetupCommands: { commandId: DailySetupCommand; elapsedMs: number }[] = [];
const report: Record<string, unknown> = { schemaVersion: 1, format: 'cliq-installed-local-inference-qualification-v1',
  diagnosticOnly: true, qualified: false, phase: 'pinned_inputs', completedDailySetupCommands };
const mark = (phase: string) => { report.phase = phase; console.log('Installed local inference phase ' + phase); };
let client: Awaited<ReturnType<typeof openInstalledClientConsumer>> | undefined;
let units: readonly [string, string] | undefined;

async function exactFile(filename: string, uid: bigint, maxBytes: number, digest?: string, retain = true, mounted = false) {
  const before = await lstat(filename, { bigint: true });
  assert(before.isFile() && before.uid === uid && (before.nlink === 1n || mounted && before.nlink === 0n) && !(before.mode & 0o022n) &&
    before.size > 0n && before.size <= BigInt(maxBytes));
  const held = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const compare = (after: typeof before) => metadata.forEach(field => assert.equal(after[field], before[field]));
  const pieces: Buffer[] = [], hash = createHash('sha256'), scratch = Buffer.allocUnsafe(65536);
  try {
    compare(await held.stat({ bigint: true }));
    let offset = 0;
    while (offset < Number(before.size)) {
      const { bytesRead } = await held.read(scratch, 0, Math.min(scratch.length, Number(before.size) - offset), offset);
      assert(bytesRead > 0);
      const bytes = scratch.subarray(0, bytesRead); offset += bytesRead;
      hash.update(bytes);
      if (retain) pieces.push(Buffer.from(bytes));
    }
    assert.equal((await held.read(scratch, 0, 1, offset)).bytesRead, 0);
    const actual = hash.digest('hex');
    if (digest !== undefined) assert.equal(actual, digest);
    compare(await held.stat({ bigint: true })); compare(await lstat(filename, { bigint: true }));
    return { info: before, bytes: Buffer.concat(pieces), digest: actual };
  } finally { await held.close(); }
}

type BuildInput = Omit<Parameters<typeof buildInstalledLocalInferencePackage>[0], 'fixture' | 'publisher'>;
async function offlineInputs(directory: string): Promise<BuildInput> {
  assert(path.isAbsolute(directory)); assert.equal(await realpath(directory), directory);
  for (const name of [directory, path.join(directory, 'objects')]) {
    const info = await lstat(name);
    assert(info.isDirectory() && info.uid === 0 && info.gid === 0 && (info.mode & 0o7777) === 0o700);
  }
  const load = async (name: string, digest: string) =>
    parseJsonStrict(text((await exactFile(path.join(directory, name), 0n, 65536, digest)).bytes));
  // The exact pinned upstream documents are parsed only after their full
  // byte identities match. Runtime file names come from the digest, not a
  // platform path or an executable supplied by the caller.
  const closure = await load('closure.json', closureDigest) as {
    codeBindingsWithoutCliqBootstrap: number; entries: { guestPath: string; sha256: string; size: number }[];
  };
  const plan = await load('input-plan-ollama-v2.json', planDigest) as {
    model: string; architecture: string; provider: string; nativeContextTokens: number; tokenizerRef: string; tokenizerBytes: number;
    files: { canonicalRelativePath: string; contentRef: string; contentDigest: string; sizeBytes: number }[];
  };
  assert.equal(plan.model, model); assert.equal(plan.provider, 'ollama'); assert.equal(plan.architecture, 'gemma3');
  assert.equal(plan.nativeContextTokens, contextLimitTokens); assert.equal(plan.files.length, 5);
  assert.equal(closure.codeBindingsWithoutCliqBootstrap, 17); assert.equal(closure.entries.length, 17);
  const source = (digest: string, byteCount: number) => {
    assertArtifactRef(digest); assert(Number.isSafeInteger(byteCount) && byteCount > 0 && byteCount <= 268_435_456);
    return { filename: path.join(directory, 'objects', digest), digest, byteCount };
  };
  const tokenizer = source(plan.tokenizerRef, plan.tokenizerBytes);
  const files = plan.files.map(file => {
    assert.equal(file.contentRef, file.contentDigest);
    return { ...source(file.contentDigest, file.sizeBytes), canonicalRelativePath: file.canonicalRelativePath };
  });
  const code = closure.entries.map(entry => ({ ...source(entry.sha256, entry.size), guestPath: entry.guestPath }));
  const selected = [...new Set([tokenizer, ...files, ...code].map(item => item.digest))].sort();
  assert.deepEqual((await readdir(path.join(directory, 'objects'))).sort(), selected);
  return { code, loaderVersion: 'glibc-2.35', model: { model, architecture: plan.architecture, tokenizer, files,
    claims: { nativeToolCalling: true, streaming: false, trustedUsageEvidence: false, contextLimitTokens, maxOutputTokens } } };
}

async function command(program: string, argv: readonly string[], deadlineMs = 30_000, commandId?: DailySetupCommand) {
  const fixtureScope = commandId && (isModelCommand(commandId) ? 'installed_local_model' : 'installed_local_setup');
  try {
    const result = await runInstalledDailyCommand({ executable: '/usr/sbin/runuser', args: [...prefix, program, ...argv],
      env: environment, cwd: ledger.home, deadlineMs, scanner,
      ...(fixtureScope ? { fixtureScope } : {}) });
    if (commandId) completedDailySetupCommands.push({ commandId, elapsedMs: Math.floor(result.elapsedMs) });
    return result.stdout;
  } catch (error) {
    if (error instanceof InstalledDailyCommandError)
      report.commandFailure ??= commandId ? { commandId, ...error.diagnostic } : error.diagnostic;
    throw error;
  }
}
const daily = (argv: readonly string[], ms?: number) => command(executable, argv, ms);
const dailySetup = (commandId: DailySetupCommand, argv: readonly string[]) =>
  command(executable, argv, isModelCommand(commandId) ? localModelCommandTimeout : localSetupCommandTimeout, commandId);
type FixtureIdentity = { dev: bigint; ino: bigint };
// Observe only fixed markers through the original disposable home. The active
// pointer marks publication. Durability and setup success need separate proof.
async function observeFailedSetup(homeIdentity: FixtureIdentity, bundleRef: string, bootstrapBytes: number,
  enrollment?: { stateIdentity: FixtureIdentity; objects: readonly { digest: string; byteCount: number }[] }) {
  const progress = enrollment && { storeObserved: false, objectDirectoryObserved: false, expectedObjects: enrollment.objects.length,
    matchingObjectEntries: 0, registryFileObserved: false };
  const observed = { stateRootObserved: false, bootstrapObserved: false, activeSelectionObserved: false,
    ...(progress ? { modelEnrollment: progress } : {}) };
  const handles: FileHandle[] = [], uid = BigInt(ledger.uid), gid = BigInt(ledger.gid);
  const child = (parent: FileHandle, name: string) => `/proc/self/fd/${parent.fd}/${name}`;
  async function directory(filename: string, ownerUid: bigint, ownerGid: bigint, mode: bigint) {
    const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
    handles.push(handle);
    const info = await handle.stat({ bigint: true });
    assert(info.isDirectory() && info.uid === ownerUid && info.gid === ownerGid && (info.mode & 0o7777n) === mode);
    return { handle, info };
  }
  try {
    const fixture = await directory(ledger.fixture, 0n, 0n, 0o755n);
    assert.equal(`${fixture.info.dev}:${fixture.info.ino}:${fixture.info.uid}`, ledger.fixtureIdentity);
    const home = await directory(child(fixture.handle, 'home'), uid, gid, 0o700n);
    assert(home.info.dev === homeIdentity.dev && home.info.ino === homeIdentity.ino);
    const controlled = await directory(child(home.handle, '.cliq'), uid, gid, 0o700n);
    const state = await directory(child(controlled.handle, path.basename(recipe.stateRoot)), uid, gid, 0o700n);
    assert(controlled.info.dev === home.info.dev && state.info.dev === home.info.dev);
    if (enrollment) assert(state.info.dev === enrollment.stateIdentity.dev && state.info.ino === enrollment.stateIdentity.ino);
    observed.stateRootObserved = true;
    const runtime = await directory(child(state.handle, 'runtime'), uid, gid, 0o700n);
    assert.equal(runtime.info.dev, state.info.dev);
    const bootstrap = await lstat(child(runtime.handle, 'bootstrap'), { bigint: true }).catch(() => undefined);
    observed.bootstrapObserved = bootstrap?.isFile() === true && bootstrap.uid === uid && bootstrap.gid === gid &&
      bootstrap.dev === state.info.dev && bootstrap.nlink === 1n && (bootstrap.mode & 0o7777n) === 0o500n &&
      bootstrap.size === BigInt(bootstrapBytes);
    const expected = canonicalJsonBytes({ schemaVersion: 1, bundleDigest: bundleRef });
    const selection = await exactFile(child(runtime.handle, 'active.json'), uid, expected.length, sha256Bytes(expected), false)
      .catch(() => undefined);
    observed.activeSelectionObserved = selection !== undefined && selection.info.gid === gid &&
      selection.info.dev === state.info.dev && (selection.info.mode & 0o7777n) === 0o600n;
    if (enrollment && progress) {
      const store = await directory(child(state.handle, 'local-models'), uid, gid, 0o700n);
      assert.equal(store.info.dev, state.info.dev);
      progress.storeObserved = true;
      const objects = await directory(child(store.handle, 'objects'), uid, gid, 0o700n);
      assert.equal(objects.info.dev, state.info.dev);
      progress.objectDirectoryObserved = true;
      const ownedFile = (info: BigIntStats, mode: bigint) =>
        info.isFile() && info.uid === uid && info.gid === gid && info.dev === state.info.dev && info.nlink === 1n &&
        (info.mode & 0o7777n) === mode;
      for (const { digest, byteCount } of enrollment.objects) {
        assertArtifactRef(digest);
        const info = await lstat(child(objects.handle, digest), { bigint: true }).catch(() => undefined);
        if (info && ownedFile(info, 0o400n) && info.size === BigInt(byteCount)) progress.matchingObjectEntries++;
      }
      const registry = await lstat(child(store.handle, 'registry.sqlite3'), { bigint: true }).catch(() => undefined);
      progress.registryFileObserved = registry !== undefined && ownedFile(registry, 0o600n) && registry.size >= 100n;
    }
  } catch { /* The original command failure remains authoritative. */ }
  finally { await Promise.allSettled(handles.map(handle => handle.close())); }
  return observed;
}

const systemctl = (argv: readonly string[]) => command('/usr/bin/systemctl', ['--user', ...argv]);
async function show(unit: string) {
  const values = text(await systemctl(['show', unit, '--no-pager',
    '--property=ActiveState,MainPID,ExecMainPID,InvocationID,ControlGroup,TimeoutStopUSec,ExecMainStatus,Result']));
  return Object.fromEntries(values.trim().split('\n').map(line => {
    const at = line.indexOf('='); assert(at > 0); return [line.slice(0, at), line.slice(at + 1)];
  }));
}

type Result<M extends InstalledControlFeature> = Extract<InstalledControlResponseFor<M>, { ok: true }>['result'];
async function send<M extends InstalledControlFeature>(request: Extract<InstalledControlRequestV1, { method: M }>, method: M) {
  assert(client);
  const decoded = decodeInstalledControlRequest(request);
  const response = decodeInstalledControlResponse(await client.send(decoded, 10_000), decoded);
  if (!response.ok) {
    report.refusal = { method, code: response.error.code };
    throw new Error('installed authenticated control refused ' + method);
  }
  assert.equal(response.result.method, method);
  return response.result as Result<M>;
}
async function cas(ref: string, limit = 1_048_576) {
  assertArtifactRef(ref); return (await exactFile(path.join(recipe.stateRoot, 'cas', ref), BigInt(ledger.uid), limit, ref)).bytes;
}
async function artifact<T = unknown>(ref: string): Promise<T> {
  const bytes = await cas(ref), value = parseJsonStrict(text(bytes));
  assert(canonicalJsonBytes(value).equals(bytes)); return value as T;
}
function dailyAdmission(bytes: Buffer) {
  const lines = text(bytes);
  assert(lines.endsWith('\n'));
  const records = lines.slice(0, -1).split('\n').map(line => {
    const value = parseJsonStrict(line);
    assert(canonicalJsonBytes(value).equals(Buffer.from(line))); return decodeHeadlessControlRecord(value);
  });
  const [only, ...others] = records.filter(row => row.type === 'response' && row.response.ok && row.response.result.method === 'run.submit');
  assert(only?.type === 'response' && only.response.ok && only.response.result.method === 'run.submit' && !others.length);
  return only.response.result;
}

async function startToken(pid: string) {
  assert.match(pid, /^[1-9][0-9]{0,9}$/u);
  const value = await readFile('/proc/' + pid + '/stat', 'utf8');
  assert(value.length <= 8192 && value.startsWith(pid + ' ('));
  const fields = value.slice(value.lastIndexOf(')') + 2).trim().split(/\s+/u);
  assert(!['Z', 'X', 'x'].includes(fields[0]!) && /^[1-9][0-9]*$/u.test(fields[19]!));
  return 'linux-proc-start-ticks:' + fields[19];
}

type LinuxContainment = ProcessContainment & { backend: Extract<ProcessContainment['backend'], { kind: 'linux' }> };
async function observePhysical(backend: LinuxContainment['backend'], groups: readonly string[], port: number) {
  for (const group of groups) assert(group.startsWith('/user.slice/user-' + ledger.uid + '.slice/user@' + ledger.uid + '.service/'));
  const absolute = backend.cgroupPath;
  assert(groups.some(group => absolute.startsWith('/sys/fs/cgroup' + group + '/')) && path.normalize(absolute) === absolute);
  assert.match(path.basename(absolute), /^cliq-local-[a-f0-9]{64}$/u);
  const info = await lstat(absolute, { bigint: true });
  assert(info.isDirectory()); assert.equal(info.ino.toString(), backend.cgroupId);
  const members = (await readFile(path.join(absolute, 'cgroup.procs'), 'utf8')).trim().split('\n');
  assert(members.length > 0 && members.length <= 256 && members.every(pid => /^[1-9][0-9]{0,9}$/u.test(pid)));
  for (const pid of members) {
    const proc = '/proc/' + pid;
    const invocation = await readFile(proc + '/cmdline').catch(error => {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      return Buffer.alloc(0);
    });
    if (!invocation.equals(Buffer.from('/runtime/bin/ollama\0serve\0'))) continue;
    const start = await startToken(pid);
    const processStatus = await readFile(proc + '/status', 'utf8');
    assert(processStatus.length <= 65536);
    const uids = processStatus.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu);
    assert(uids && uids.slice(1).every(uid => Number(uid) === ledger.uid));
    assert.equal(await readlink(proc + '/ns/pid'), 'pid:[' + backend.pidNamespaceId + ']');
    assert.notEqual(await readlink(proc + '/ns/net'), await readlink('/proc/self/ns/net'));
    const interfaces = (await readFile(proc + '/net/dev', 'utf8')).split('\n').slice(2).filter(Boolean).map(line => line.split(':')[0]!.trim());
    assert.deepEqual(interfaces, ['lo']);
    assert.equal((await readFile(proc + '/net/route', 'utf8')).trim().split('\n').length, 1);
    const tables = (await readFile(proc + '/net/tcp', 'utf8')).trim().split('\n').slice(1);
    assert(tables.length <= 256);
    const address = '0100007F:' + port.toString(16).toUpperCase().padStart(4, '0');
    const rows = tables.map(line => line.trim().split(/\s+/u));
    assert.equal(rows.filter(row => row[1]?.endsWith(address.slice(8)) && row[3] === '0A').length, 1);
    assert(rows.some(row => row[1] === address && row[3] === '0A'));
    const connected = rows.some(row => row[1] === address && row[2]?.startsWith('0100007F:') && row[3] === '01');
    assert.equal(await startToken(pid), start);
    return { pid, start, connected };
  }
  throw new Error('original local service cgroup has no actual Ollama serve process');
}

async function verifyMountedInputs(pid: string, files: readonly { guestPath: string; artifactRef: string; byteCount: number }[]) {
  const proc = '/proc/' + pid;
  const mountinfo = await readFile(proc + '/mountinfo', 'utf8');
  assert(mountinfo.length <= 262144);
  const mounts = mountinfo.trim().split('\n').map(line => line.split(' '));
  const actual = await stat(proc + '/exe', { bigint: true });
  const selected = await lstat(proc + '/root/runtime/bin/ollama', { bigint: true });
  assert.equal(actual.ino, selected.ino); assert.equal(actual.dev, selected.dev);
  for (const file of files) {
    const [mount, ...duplicates] = mounts.filter(row => row[4] === file.guestPath);
    assert(mount && !duplicates.length && mount[5]?.split(',').includes('ro'));
    const checked = await exactFile(proc + '/root' + file.guestPath, BigInt(ledger.uid), file.byteCount, file.artifactRef, false, true);
    assert.equal(checked.info.size, BigInt(file.byteCount));
  }
}

async function requireRetired(boundary: ReturnType<typeof decodeLocalInferenceBoundary>, containment: LinuxContainment,
  registration: ReturnType<typeof decodeLocalModelRegistration>, bundle: Awaited<ReturnType<typeof buildInstalledSupervisorPackage>>['bundle']) {
  // Read only after the original systemd unit and StateOwner have joined.
  const database = new DatabaseSync(path.join(recipe.stateRoot, KERNEL_DATABASE_FILENAME), { readOnly: true, allowExtension: false });
  let launch: ReturnType<typeof decodeLocalInferenceLaunch>, cycle: ReturnType<typeof decodeLocalInferenceCycle>;
  try {
    const row = database.prepare('SELECT row_json FROM local_inference_launches WHERE launch_id=?').get(boundary.serviceLaunchId);
    assert(typeof row?.row_json === 'string');
    launch = decodeLocalInferenceLaunch(parseJsonStrict(row.row_json));
    const activation = database.prepare('SELECT row_json FROM local_inference_activation_cycles WHERE activation_cycle_id=?').get(launch.activationCycleId);
    assert(typeof activation?.row_json === 'string');
    cycle = decodeLocalInferenceCycle(parseJsonStrict(activation.row_json));
    assert.equal(database.prepare('SELECT count(*) AS n FROM local_inference_launches').get()?.n, 1);
  } finally { database.close(); }
  assert(launch.phase === 'retired' && launch.retirementKind === 'death' && launch.leaseVersion >= 1);
  assert(cycle.phase === 'active' && cycle.activationAttempt === 1 && cycle.currentLaunchId === boundary.serviceLaunchId);
  assert.equal(launch.processContainmentRef, boundary.processContainmentRef);
  const nativeSource = decodeBoundLocalInferenceNativeInput(await cas(launch.nativeInputRef), launch, cycle, registration);
  const profileRoot = localInferenceRuntimeRoots(bundle)[0]; assert(profileRoot);
  const expected = localInferenceRuntimeInputs(bundle, bindLocalInferenceRuntime(bundle, profileRoot.artifactRef,
    await artifact(profileRoot.artifactRef)), registration.objectClosure);
  same(nativeSource.data.files, expected.files);
  same(nativeSource.data.bootstrap, expected.bootstrap);
  same(nativeSource.data.controller, expected.controller);
  same(nativeSource.data.bubblewrap, expected.bubblewrap);
  const death = await artifact<ProcessContainmentDeathEvidenceV1>(launch.retirementEvidenceRef);
  assert.equal(death.kind, 'containment_all_descendants_dead');
  assert.equal(death.containmentRef, boundary.processContainmentRef);
  assert.equal(death.sandboxLaunchSpecRef, boundary.sandboxLaunchSpecRef);
  assert.equal(death.inspectorSupervisorInstanceId, boundary.inspectorSupervisorInstanceId);
  assert.equal(death.evidenceDigest, digestOmitting(death, 'evidenceDigest'));
  same(death.owner, containment.owner);
  same(death.backend, { ...containment.backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 });
  await assert.rejects(lstat(containment.backend.cgroupPath), { code: 'ENOENT' });
  return { activationCycleId: cycle.activationCycleId, launchId: launch.launchId, finalLeaseVersion: launch.leaseVersion,
    nativeInputRef: launch.nativeInputRef, retirementEvidenceRef: launch.retirementEvidenceRef };
}

let failure: unknown;
try {
  const inputs = await offlineInputs(inputDirectory);
  await mkdir(recipe.buildFixture, { mode: 0o755 });
  mark('signed_package');
  const signed = await buildInstalledSupervisorPackage(recipe.buildFixture, 'complete', undefined,
    { headlessSchemaVersion: 3, guestToolchain: 'node-test-v1', localInference: inputs });
  assert(signed.localInference && signed.guestToolchain && signed.modelAuthority === undefined);
  const bundleRef = canonicalSha256(signed.bundle), bundleRoot = path.join(installed, bundleRef);
  const broker = signed.bundle.entries.find(entry => entry.entryId === MODEL_BROKER_ENTRY_ID);
  assert(broker?.executable && broker.role === 'provider_adapter');
  assert.equal(signed.bundle.entries.filter(entry => entry.role === 'provider_adapter').length, 1);
  assert.equal(signed.bundle.structuredArtifacts.filter(root => root.kind === 'local_inference_runtime').length, 1);
  assert(signed.bundle.structuredArtifacts.every(root => !('provider' in root) || root.provider === 'ollama'));
  const staged = signed.localInference;
  const manifest = canonicalJsonBytes(staged.modelManifest);
  assert.equal(sha256Bytes(manifest), staged.modelManifestRef);
  const signature = await exactFile(path.join(staged.modelPackageRoot, 'objects', staged.modelManifest.signatureRef), 0n, 64,
    staged.modelManifest.signatureRef);
  same(verifyLocalModelManifestAuthority({ bundle: signed.bundle, releaseKeys: signed.releaseKeys, manifestBytes: manifest,
    signatureBytes: signature.bytes }), staged.modelManifest);
  const modelPackage = path.join(recipe.buildFixture, 'local-model-package');
  await rename(staged.modelPackageRoot, modelPackage);
  await transferPackage(modelPackage, ledger.uid, ledger.gid);
  await transferPackage(recipe.packageRoot, ledger.uid, ledger.gid);
  await writeFile(driver, await buildInstalledClientDriver(driver), { flag: 'wx', mode: 0o444 });
  await writeFile(recipe.releaseKeysFile, canonicalJsonBytes(signed.releaseKeys), { flag: 'wx', mode: 0o444 });
  report.package = { bundleRef, modelManifestRef: staged.modelManifestRef, modelManifestDigest: staged.modelManifest.modelManifestDigest,
    engineVersion: '0.40.14', detachedSignatureVerified: true };

  mark('daily_setup_and_enrollment');
  const homeIdentity = await lstat(ledger.home, { bigint: true });
  const bootstrap = signed.bundle.entries.find(entry => entry.role === 'supervisor');
  assert(bootstrap);
  try { await dailySetup('setup', ['setup']); }
  catch (error) {
    if (error instanceof InstalledDailyCommandError && error.launcherAndPipesJoined)
      report.setupFailureObservation = await observeFailedSetup(homeIdentity, bundleRef, bootstrap.byteCount);
    throw error;
  }
  const state = await lstat(recipe.stateRoot, { bigint: true });
  assert(state.isDirectory() && state.uid === BigInt(ledger.uid) && state.gid === BigInt(ledger.gid) && (state.mode & 0o7777n) === 0o700n);
  const rootDigest = canonicalSha256({ schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux',
    canonicalAbsolutePath: recipe.stateRoot, ownerUid: ledger.uid, deviceId: state.dev.toString(), directoryFileId: state.ino.toString(),
    mode: 448, openedNoFollow: true, layoutVersion: 1 });
  const profiles = installedServiceProfiles(recipe.stateRoot, rootDigest);
  units = [profiles.supervisor.unit, profiles.keeper.unit];
  await assert.rejects(lstat(path.join(recipe.packageRoot, 'model-authority.json')), { code: 'ENOENT' });
  await assert.rejects(lstat(path.join(bundleRoot, 'model-authority.json')), { code: 'ENOENT' });
  try { await dailySetup('models_add', ['models', 'add', alias, '--manifest', path.join(modelPackage, 'model-manifest.json')]); }
  catch (error) {
    if (error instanceof InstalledDailyCommandError && error.launcherAndPipesJoined)
      report.modelEnrollmentFailureObservation = await observeFailedSetup(homeIdentity, bundleRef, bootstrap.byteCount, {
        stateIdentity: state, objects: [
          { digest: staged.modelManifestRef, byteCount: manifest.length },
          { digest: staged.modelManifest.signatureRef, byteCount: 64 },
          inputs.model.tokenizer, ...inputs.model.files,
        ],
      });
    throw error;
  }
  const listing = parseJsonStrict(text(await dailySetup('models_list', ['models', 'list'])).trim());
  same(listing, { models: [{ alias, provider: 'ollama', model }], localModels: [{ provider: 'ollama', model, state: 'active' }], profiles: [] });
  await dailySetup('supervisor_start', ['supervisor', 'start']);
  const [supervisor, keeper] = await Promise.all(units.map(show));
  for (const unit of [supervisor!, keeper!]) {
    assert.equal(unit.ActiveState, 'active'); assert.equal(unit.TimeoutStopUSec, '2s');
    assert.equal(unit.MainPID, unit.ExecMainPID); assert.match(unit.InvocationID!, /^[a-f0-9]{32}$/u);
    await startToken(unit.MainPID!);
  }
  const supervisorPid = supervisor!.MainPID!;
  assert.equal(await readlink('/proc/' + supervisorPid + '/exe'), path.join(bundleRoot, 'supervisor'));
  report.signedDailySetupAndEnrollment = true;

  mark('authenticated_daily_admission');
  client = await openInstalledClientConsumer({ executable: '/usr/sbin/runuser',
    args: [...prefix, process.execPath, '--disable-warning=ExperimentalWarning', driver, filename, '--schema3'],
    cwd: ledger.home, env: environment, headlessSchemaVersion: 3, coldHello: 'local_inference', openScan: () => scanner.openStream(),
    onJoined: () => { report.clientAndPipesJoined = true; } });
  for (const method of ['run.submit', 'run.get', 'artifact.get', 'supervisor.status']) assert(client.hello.enabledFeatureIds.includes(method));
  const status = await send({ protocolVersion: 1, method: 'supervisor.status' }, 'supervisor.status');
  assert.equal(status.health, 'ready'); assert.equal(status.activeRuntimeBundle.runtimeBundleRef, bundleRef);
  const workspaceFile = path.join(recipe.workspace, proofPath);
  await mkdir(recipe.workspace, { mode: 0o700 }); await chown(recipe.workspace, ledger.uid, ledger.gid);
  await writeFile(workspaceFile, proof, { flag: 'wx', mode: 0o600 }); await chown(workspaceFile, ledger.uid, ledger.gid);
  const originalWorkspace = await lstat(workspaceFile, { bigint: true });
  // Allow one normal model reservation and one readonly tool. The next
  // model reservation must exhaust the original token budget without dispatch.
  const admitted = dailyAdmission(await daily(['run', objective, '--workspace', recipe.workspace, '--model', alias, '--policy', 'yolo',
    '--trust-workspace', '--allow-unverified', '--detach', '--json', '--budget-usd', '0',
    '--budget-tokens', String(oneModelReservation), '--options',
    canonicalJsonBytes({ budgets: { wallTimeMs: 300_000, toolCalls: 1, repairAttempts: 0, childDepth: 0, childConcurrency: 1 } }).toString('utf8')], 90_000));
  assert.equal(admitted.snapshot.operation, 'agent');
  const run = admitted.snapshot.run, spec = decodeRunSpec(await artifact(run.specRef));
  assert.equal(spec.operation, 'agent'); assert.equal(spec.budgets.modelTokens, oneModelReservation); assert.equal(spec.budgets.costMicros, 0);
  const assembly = decodeRetainedRunAssembly(await artifact(spec.assemblyRef));
  assert.equal(assembly.runtime.runtimeBundleRef, bundleRef);
  const provider = assembly.provider;
  assert(provider.name === 'ollama' && provider.model === model && provider.endpoint.kind === 'local_zero_cost' && provider.pricing.kind === 'zero_cost');
  assert.deepEqual(provider.credentialGrantRefs, []);
  const provenanceRef = provider.endpoint.localProvenanceRef;
  assert.equal(provider.pricing.provenanceRef, provenanceRef);
  assert.equal(provider.pricing.maxRunCostMicros, 0);
  assert.equal(provider.adapter.codeDigest, broker.digest);
  assert.equal(provider.negotiation.mode, 'native-tools');
  assert.equal(provider.negotiation.streaming, false);
  const provenance = decodeLocalZeroCostProvenanceData(await artifact(provenanceRef));
  const registration = decodeLocalModelRegistration(await artifact(provenance.localModelRegistrationRef));
  assert(registration.state === 'active' && registration.provider === 'ollama' && registration.model === model);
  assert.equal(registration.expectedModelManifestRef, staged.modelManifestRef);
  same(registration.modelManifest, staged.modelManifest);
  assert.equal(provenance.serviceSpecRef, registration.expectedServiceSpecRef);
  same(provenance.endpoint, registration.serviceSpec.endpoint);
  assert.equal(provenance.endpoint.host, '127.0.0.1');
  const boundary = decodeLocalInferenceBoundary(await artifact(provenance.boundaryEvidenceRef));
  assert.equal(boundary.modelManifestRef, staged.modelManifestRef);
  assert.equal(boundary.runtimeBundleRef, bundleRef);
  assert.equal(boundary.inspectorSupervisorInstanceId, status.supervisorInstanceId);
  assert(boundary.backend === 'linux_namespace' && boundary.externalNetworkEgress === 'denied' && boundary.loopbackOnly);
  assert(boundary.observedAt <= run.createdAt && run.createdAt < boundary.validThrough);
  const containment = await artifact<LinuxContainment>(boundary.processContainmentRef);
  assert.equal(containment.backend.kind, 'linux'); assert.equal(containment.planRef, boundary.containmentPlanRef);
  assert(containment.owner.kind === 'local_inference_service' && containment.owner.serviceLaunchId === boundary.serviceLaunchId);
  assert.equal(containment.sandboxLaunchSpecRef, boundary.sandboxLaunchSpecRef);
  const groups = [supervisor!.ControlGroup!, keeper!.ControlGroup!], port = provenance.endpoint.port;
  const firstPhysical = await observePhysical(containment.backend, groups, port);

  mark('native_model_claim_and_response');
  const cutRequest = { protocolVersion: 1, method: 'run.get', runId: run.id, itemLimit: 100, journalLimit: 100, checkpointLimit: 100 } as const;
  const by = Math.min(Date.parse(run.deadlineAt), Date.now() + 90_000);
  let connected = false, workerLaunchId: string | undefined, cut: Result<'run.get'>;
  for (;;) {
    assert(Date.now() < by, 'the original installed Run did not complete its narrow turn in time');
    cut = await send(cutRequest, 'run.get');
    const models = cut.journal.filter(row => row.opKind === 'model');
    const claim = models.find(row => row.phase === 'dispatch_claimed');
    if (claim && cut.snapshot.run.activeWorkerLaunchId) {
      assert(cut.snapshot.run.leaseEpoch === claim.leaseEpoch && claim.leaseEpoch > 0);
      workerLaunchId ??= cut.snapshot.run.activeWorkerLaunchId;
      assert.equal(cut.snapshot.run.activeWorkerLaunchId, workerLaunchId);
      if (!connected && !models.some(row => row.phase === 'completed')) {
        const observed = await observePhysical(containment.backend, groups, port);
        assert.equal(observed.pid, firstPhysical.pid); assert.equal(observed.start, firstPhysical.start);
        connected = observed.connected;
      }
    }
    if (['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(cut.snapshot.run.status)) break;
    assert.notEqual(cut.snapshot.run.status, 'waiting', 'the fixed read-only turn reached an unsupported wait');
    await delay(100);
  }
  assert(connected && workerLaunchId, 'require the original model claim, live Run worker lease and private established Ollama connection');
  assert.equal(cut.nextJournalSeq, cut.highWaterJournalSeq); assert.equal(cut.nextItemSeq, cut.highWaterItemSeq);
  assert.equal(cut.snapshot.run.status, 'failed'); assert.equal(cut.snapshot.run.terminalReason, 'budget_exhausted');
  assert.equal(cut.snapshot.run.activeWorkerLaunchId, undefined);
  assert(cut.snapshot.run.stopIntentRef);
  const stop = decodeAgentStop(await artifact(cut.snapshot.run.stopIntentRef), cut.snapshot.run);
  assert(stop.origin === 'budget' && stop.counter === 'modelTokens' && stop.required === oneModelReservation);
  assert.equal(stop.consumed, oneModelReservation);
  const modelRows = cut.journal.filter(row => row.opKind === 'model');
  assert.deepEqual(modelRows.map(row => row.phase), ['prepared', 'dispatch_claimed', 'completed']);
  const [prepared, claim, complete] = modelRows;
  assert(prepared && claim && complete && prepared.grantRef && complete.resultRef && complete.budgetSettlementRef);
  assert.equal(prepared.attempt, 0); assert.equal(claim.attempt, 0); assert.equal(complete.attempt, 0);
  assert(claim.dispatchId && claim.brokerFenceTokenDigest && claim.stateOwnerEpoch && claim.supervisorInstanceId === status.supervisorInstanceId);
  for (const row of [prepared, claim, complete]) {
    assert.equal(row.runId, run.id); assert.equal(row.opId, prepared.opId); assert.equal(row.requestRef, prepared.requestRef);
    assert.equal(row.target, provenanceRef); assert.equal(row.leaseEpoch, claim.leaseEpoch);
  }
  const request = await artifact<ModelRequestV1>(prepared.requestRef);
  assert(request.format === 'cliq-model-request-v1' && request.kind === 'normal' && request.provider === 'ollama' &&
    request.model === model && request.requestPath === '/api/chat' && request.streaming === false);
  assert.equal(request.requestDigest, digestOmitting(request, 'requestDigest'));
  assert.equal(request.assemblyRef, spec.assemblyRef);
  const body = await cas(request.bodyBytesRef);
  assert.equal(body.length, request.bodyByteCount);
  const wire = parseJsonStrict(text(body)) as { model: string; stream: boolean; messages: { role: string; content: string }[];
    tools: { function: { name: string } }[] };
  assert(wire.model === model && wire.stream === false && wire.messages.some(message => message.role === 'user' && message.content.includes(objective)));
  assert(wire.tools.some(tool => tool.function.name === 'read'));
  const grant = decodeModelOperationGrant(await artifact(prepared.grantRef));
  assert.equal(grant.requestRef, prepared.requestRef); assert.equal(grant.targetRef, provenanceRef); assert.equal(grant.targetDigest, provenance.provenanceDigest);
  const settlement = decodeBudgetSettlement(await artifact(complete.budgetSettlementRef));
  assert.equal(settlement.preparedJournalSeq, prepared.seq); assert.equal(settlement.terminalJournalSeq, complete.seq);
  same(settlement.consumed, { ...zero, modelTokens: oneModelReservation });
  same(cut.snapshot.run.budgetConsumed, { ...zero, modelTokens: oneModelReservation, toolCalls: 1 });
  same(cut.snapshot.run.budgetReserved, zero);

  const selected = await send({ protocolVersion: 1, method: 'artifact.get', digest: complete.resultRef, offset: 0, length: 65_536 }, 'artifact.get');
  const retained = await cas(complete.resultRef);
  assert(selected.eof && selected.offset === 0 && selected.nextOffset === retained.length);
  assert.equal(selected.artifact.ref, complete.resultRef);
  assert.equal(selected.bytesBase64, retained.toString('base64'));
  const turn = await artifact<AgentModelTurn>(complete.resultRef);
  assert(turn.format === 'cliq-agent-model-turn-v1' && turn.provider === 'ollama' && turn.model === model &&
    turn.negotiatedMode === 'native-tools' && turn.stopReason === 'tool_calls' && turn.toolCalls.length === 1 && turn.usageTrusted === false);
  assert.equal(turn.requestDigest, request.requestDigest);
  assert.equal(turn.responseDigest, modelResponseDigest(turn));
  const call = turn.toolCalls[0]!;
  assert.equal(call.toolName, 'read'); assert.equal(call.index, 0);
  const resolved = await artifact<ToolCallInputV1>(call.inputRef);
  assert(resolved.disposition === 'resolved' && resolved.callId === call.callId && resolved.toolName === 'read');
  assert.equal(resolved.inputDigest, call.inputDigest); assert.equal(resolved.inputDigest, digestOmitting(resolved, 'inputDigest'));
  same(resolved.value, { path: proofPath });
  const observed = await artifact<ObservedToolCallInputV1>(resolved.observedInputRef);
  assert(observed.encoding === 'jcs_json'); same(observed.value, { path: proofPath });
  assert.equal(observed.observedInputDigest, resolved.observedInputDigest);
  const items = await Promise.all(cut.items.map(row => artifact<ModelTurnItem | ToolResultItem>(row.payloadRef)));
  assert.equal(items.filter(item => item.kind === 'model_turn' && item.modelTurnRef === complete.resultRef).length, 1);
  const results = items.filter(item => item.kind === 'tool_result');
  assert(results.length === 1 && results[0]!.callId === call.callId && results[0]!.outcome === 'executed');
  const payload = await artifact<ToolResultPayloadV1>(results[0]!.resultRef);
  assert(payload.outcome === 'executed' && payload.source === 'invocation' && payload.callId === call.callId);
  const toolRows = cut.journal.filter(row => row.opKind === 'tool');
  assert.deepEqual(toolRows.map(row => row.phase), ['prepared', 'dispatch_claimed', 'completed']);
  assert(toolRows.every(row => row.opId === payload.opId) && toolRows[2]!.resultRef === payload.journalResultRef);
  const content = await artifact<ToolResultModelContentV1>(payload.modelContentRef);
  assert(content.outcome === 'executed' && content.toolName === 'read' && content.callId === call.callId);
  assert(canonicalJsonBytes(content.content).includes(Buffer.from(proof.trim())));

  mark('independent_live_closure');
  const originalMounts = localInferenceRuntimeInputs(signed.bundle, bindLocalInferenceRuntime(signed.bundle,
    localInferenceRuntimeRoots(signed.bundle)[0]!.artifactRef, await artifact(localInferenceRuntimeRoots(signed.bundle)[0]!.artifactRef)),
  registration.objectClosure);
  await verifyMountedInputs(firstPhysical.pid, [...originalMounts.files,
    { guestPath: '/runtime/bin/cliq-local-inference', artifactRef: originalMounts.bootstrap.digest, byteCount: originalMounts.bootstrap.byteCount }]);
  assert.equal(await startToken(firstPhysical.pid), firstPhysical.start);
  const brokerPath = path.join(bundleRoot, broker.relativePath);
  const brokerFile = await exactFile(brokerPath, BigInt(ledger.uid), broker.byteCount, broker.digest, false);
  const maps = await readFile('/proc/' + supervisorPid + '/maps', 'utf8');
  assert(maps.length <= 262144 && maps.split('\n').some(line => {
    const fields = line.trim().split(/\s+/u); return fields[4] === brokerFile.info.ino.toString() && fields[5] === brokerPath;
  }));
  const host = await exactFile(workspaceFile, BigInt(ledger.uid), 4096, sha256Bytes(Buffer.from(proof)));
  assert.deepEqual(await readdir(recipe.workspace), [proofPath]);
  for (const key of metadata) assert.equal(host.info[key], originalWorkspace[key]);
  report.turn = { runId: run.id, dispatchId: claim.dispatchId, modelTurnRef: complete.resultRef, workerLaunchId,
    leaseEpoch: claim.leaseEpoch, modelCalls: 1, toolCalls: 1, tool: 'read', providerCalls: 0, costMicros: 0,
    publicTurnMatchesPhysicalCas: true, privateLoopbackConnectionObserved: true, signedNativeBrokerMapped: true,
    verifiedMountedInputs: originalMounts.files.length + 1,
    terminalReason: cut.snapshot.run.terminalReason };

  mark('original_service_retirement');
  await client.close(); client = undefined;
  await systemctl(['stop', ...units]);
  for (const [index, unit] of units.entries()) {
    const original = index === 0 ? supervisor! : keeper!, final = await show(unit);
    assert.equal(final.ActiveState, 'inactive'); assert.equal(final.MainPID, '0'); assert.equal(final.Result, 'success');
    assert.equal(final.TimeoutStopUSec, '2s'); await assert.rejects(lstat('/proc/' + original.MainPID), { code: 'ENOENT' });
  }
  units = undefined;
  await assert.rejects(lstat('/proc/' + firstPhysical.pid), { code: 'ENOENT' });
  const owners = inspectInstalledOwnerHistory(recipe.stateRoot).owners;
  assert(owners.length === 1 && owners[0]!.state === 'terminal' && owners[0]!.terminalReason === 'graceful_release' &&
    owners[0]!.supervisorInstanceId === status.supervisorInstanceId && owners[0]!.ownerEpoch === claim.stateOwnerEpoch);
  report.retirement = await requireRetired(boundary, containment, registration, signed.bundle);
  report.phase = 'complete'; report.qualified = true;
} catch (error) { failure = error; }
finally {
  const cleanup: unknown[] = [];
  try { await client?.close(); } catch (error) { cleanup.push(error); }
  try { if (units) await systemctl(['stop', ...units]); } catch (error) { cleanup.push(error); }
  if (cleanup.length) failure = new AggregateError(failure === undefined ? cleanup : [failure, ...cleanup], 'owned installed local inference did not join');
  await writeFile(recipe.reportFile, Buffer.concat([canonicalJsonBytes(report), Buffer.from('\n')]), { flag: 'wx', mode: 0o644 });
}
if (failure !== undefined) throw failure;
