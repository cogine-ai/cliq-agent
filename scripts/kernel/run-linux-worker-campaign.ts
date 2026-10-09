import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fork, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs';
import { access, lstat, open, readFile, stat, type FileHandle } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import net from 'node:net';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { inspect } from 'node:util';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { identityHash } from '../../src/kernel/identity.js';
import type { ProcessContainment, ProcessContainmentDeathEvidenceV1, ProcessContainmentNoSpawnEvidenceV1, ProcessContainmentPlanV1, SandboxLaunchSpecV1 } from '../../src/kernel/execution.js';
import type { ReconciliationProbeEvidenceV1, ReconciliationProbeTimeoutClosureV1 } from '../../src/kernel/reconciliation.js';
import type { WorkerDeathWait, WorkerIdentity, WorkspaceEntryManifest, WorkspaceGenerationIdentityV1,
  WorkspaceGenerationQuarantineEvidenceV1, WorkspaceGenerationStateV1, WorkspaceStateManifest, PlatformProcessIdentityV1, Run, WorkerLaunch } from '../../src/kernel/types.js';
import { openLinuxWorkerLauncher } from '../../src/sandbox/linux-worker.js';
import { createLinuxWorkerCampaignFixture } from '../../src/sandbox/testing/worker-campaign-fixture.js';
import type { LocalControlConnection, LocalControlListener } from '../../src/state/control-channel.js';
import { decodeWorkerIdentity } from '../../src/state/decoders.js';
import { decodeWorkerProcessContainment } from '../../src/state/execution-closure.js';
import { journalEntryFromRow, type JournalSqlRow } from '../../src/state/repositories/journal.js';
import { readRequiredWorkerLaunch } from '../../src/state/repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef } from '../../src/state/repositories/workspace-generations.js';
import { readRun } from '../../src/state/rows.js';
import { openSqliteDriver } from '../../src/state/sqlite-driver.js';
import { readLatestStateOwner } from '../../src/state/state-owner.js';
import { openStateStore, type StateStore } from '../../src/state/store.js';
import type { CrashChildInput, CrashChildPaused, CrashChildRetirementRefused, CrashChildControllerLossRefused } from './linux-worker-crash-child.js';

// This command is intentionally separate from ordinary portable unit tests.
// Missing actual images, persistent bounded storage, namespaces or delegated
// cgroups is a failed qualification, never a skip or a caller success flag.
if (process.platform !== 'linux') throw new Error('real Linux worker campaign requires Linux (not skipped)');
const required = (name: string) => {
  const value = process.env[name];
  if (!value || !path.isAbsolute(value)) throw new Error(`required absolute campaign resource is absent: ${name}`);
  return value;
};
const options = { installationRoot: required('CLIQ_I1_INSTALLATION'), cgroupParent: required('CLIQ_I1_CGROUP_PARENT'),
  stateVolume: required('CLIQ_I1_STATE_VOLUME') };
for (const filename of ['linux-worker.node', 'cliq-linux-worker-controller', 'cliq-linux-worker', 'cliq-linux-edit', 'cliq-linux-bubblewrap']) {
  await access(path.join(options.installationRoot, filename));
}
await access(path.join(options.cgroupParent, 'cgroup.controllers'));
assert.equal((await stat(options.stateVolume)).isDirectory(), true);
const revision = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' });
if (revision.status !== 0) throw new Error('campaign source revision is unavailable');
console.log(JSON.stringify({ campaign: 'cliq-real-linux-worker-v1', sourceRevision: revision.stdout.trim(),
  node: process.version, platform: process.platform, architecture: process.arch,
  prefix: 'offline retained model/worker facts only; no provider request or native qualification' }));

async function bounded<T>(operation: Promise<T>, milliseconds = 30_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([operation, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('actual Linux campaign operation timed out')), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

async function control(store: StateStore) {
  let accepted!: (connection: LocalControlConnection) => void;
  let rejected!: (error: Error) => void;
  let waiting = new Promise<LocalControlConnection>((resolve, reject) => { accepted = resolve; rejected = reject; });
  const errors: Error[] = [];
  const listener: LocalControlListener = store.openLocalControl(connection => accepted(connection), error => {
    errors.push(error); rejected(error);
  });
  const sockets = new Set<net.Socket>(), connections = new Set<LocalControlConnection>();
  return {
    async connect() {
      const socket = net.createConnection(path.join(store.stateRoot, 'runtime/control-v1.sock'));
      sockets.add(socket);
      await bounded(once(socket, 'connect'));
      const connection = await bounded(waiting); connections.add(connection);
      waiting = new Promise<LocalControlConnection>((resolve, reject) => { accepted = resolve; rejected = reject; });
      // Prime actual native peer authentication before any effect is started.
      return { connection, close() { connection.close(); socket.destroy(); connections.delete(connection); sockets.delete(socket); } };
    },
    async close() {
      for (const connection of connections) connection.close();
      for (const socket of sockets) socket.destroy();
      await listener.close(); assert.deepEqual(errors, []);
    }
  };
}

async function checkpointBytes(store: StateStore, runId: string) {
  const closure = await store.readRecoveryClosure(runId);
  const workspace = await store.artifacts.readCanonical<WorkspaceStateManifest>(closure.latestCheckpoint.workspaceStateRef);
  const entries = await store.artifacts.readCanonical<WorkspaceEntryManifest>(workspace.entriesRef);
  assert.equal(entries.entries.length, 1);
  const file = entries.entries[0]!;
  assert.equal(file.path, 'a'); assert.equal(file.kind, 'file');
  if (file.kind !== 'file') throw new Error('checkpoint did not retain the real edited file');
  const chunks: Buffer[] = [];
  for await (const chunk of store.artifacts.readChunks(file.blobRef, file.size)) chunks.push(chunk);
  return { closure, bytes: Buffer.concat(chunks) };
}

function nativeBackend(backend: ProcessContainment['backend']) {
  assert.equal(backend.kind, 'linux');
  if (backend.kind !== 'linux') throw new Error('campaign did not produce Linux containment');
  return backend;
}

async function editedCheckpoint() {
  const fixture = await createLinuxWorkerCampaignFixture({ ...options, label: 'edit' });
  let store = fixture.store, transport = await control(store);
  try {
    const originalStat = await stat(path.join(fixture.workspace, 'a'));
    const before = await store.readRecoveryClosure(fixture.runId);
    const execution = await store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
    assert.deepEqual(await store.readRecoveryClosure(fixture.runId), before, 'factory is validation only');
    await assert.rejects(store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material }), { code: 'REVISION_CONFLICT' });
    assert.deepEqual(await store.readRecoveryClosure(fixture.runId), before, 'duplicate scope cannot change or acquire Run authority');
    const first = await transport.connect();
    const read = () => first.connection.dispatch(identity => store.readControl({ protocolVersion: 1, method: 'run.get', runId: fixture.runId }, identity));
    await read();
    let finished = false, timerTicks = 0, reads = 0, maxTurnGap = 0, lastTurn = performance.now();
    const ticker = setInterval(() => {
      const now = performance.now(); maxTurnGap = Math.max(maxTurnGap, now - lastTurn); lastTurn = now; timerTicks++;
    }, 1);
    const operation = bounded(execution.executeCurrentTool({ expectedRunRevision: before.run.revision }));
    void operation.then(() => { finished = true; }, () => { finished = true; });
    try {
      while (!finished) { await read(); reads++; await delay(1); }
      const result = await bounded(operation);
      assert.equal(result.status, 'queued'); assert.equal(result.activeWorkerLaunchId, undefined);
    } finally { clearInterval(ticker); }
    assert.ok(timerTicks > 0 && reads > 0, 'actual execution leaves timers and authenticated control responsive');
    assert.ok(maxTurnGap < 1000, `native operation blocked the Supervisor event loop for ${maxTurnGap}ms`);
    const after = await checkpointBytes(store, fixture.runId);
    assert.deepEqual(after.bytes, Buffer.from('after\n'), 'ready checkpoint contains actual native edit bytes');
    assert.notEqual(after.closure.latestCheckpoint.id, before.latestCheckpoint.id);
    const toolClaims = after.closure.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'dispatch_claimed');
    assert.equal(toolClaims.length, 1, 'exactly one permanent native tool dispatch');
    assert.equal(after.closure.run.budgetConsumed.toolCalls, 1);
    const completed = after.closure.journal.find(entry => entry.opKind === 'tool' && entry.phase === 'completed');
    assert.ok(completed?.resultRef);
    const result = await store.artifacts.readCanonical<{ postEffect: { retirementEvidenceRef: string } }>(completed.resultRef);
    const death = await store.artifacts.readCanonical<{ planRef: string; backend: ProcessContainment['backend'] & {
      cgroupPopulated: number; namespaceInitDeadAndReaped: boolean; remainingTrackedDescendants: number } }>(result.postEffect.retirementEvidenceRef);
    const workerPlan = await store.artifacts.readCanonical<ProcessContainmentPlanV1>(death.planRef);
    const claim = toolClaims[0]!;
    assert.ok(claim.sandboxLaunchSpecRef);
    const invocationSpec = await store.artifacts.readCanonical<SandboxLaunchSpecV1>(claim.sandboxLaunchSpecRef);
    const invocationPlan = await store.artifacts.readCanonical<ProcessContainmentPlanV1>(invocationSpec.containmentPlanRef);
    if (workerPlan.owner.kind !== 'worker_activation' || workerPlan.backend.kind !== 'linux' ||
        invocationSpec.owner.kind !== 'run_invocation' || invocationSpec.purpose !== 'tool' ||
        invocationPlan.owner.kind !== 'run_invocation' || invocationPlan.backend.kind !== 'linux') {
      throw new Error('actual edit did not retain its exact Linux worker and invocation plans');
    }
    assert.equal(workerPlan.owner.runId, fixture.runId);
    assert.equal(workerPlan.owner.workerLaunchId, invocationSpec.owner.workerLaunchId);
    assert.equal(invocationPlan.owner.dispatchId, claim.dispatchId);
    // Digest fields are lowercase SHA-256; opaque namespace reservations keep H's base64url encoding.
    assert.match(workerPlan.backend.cgroupNameReservationDigest, /^[0-9a-f]{64}$/u);
    assert.equal(workerPlan.backend.cgroupNameReservationDigest,
      canonicalSha256(['cliq-worker-cgroup-v1', fixture.runId, workerPlan.owner.workerLaunchId]));
    assert.equal(path.posix.basename(workerPlan.backend.cgroupPath), `cliq-${workerPlan.backend.cgroupNameReservationDigest}`);
    assert.equal(workerPlan.backend.pidNamespaceReservationId,
      identityHash('cliq-worker-namespace-v1', fixture.runId, workerPlan.owner.workerLaunchId));
    assert.match(invocationPlan.backend.cgroupNameReservationDigest, /^[0-9a-f]{64}$/u);
    assert.equal(invocationPlan.backend.cgroupNameReservationDigest, canonicalSha256(['cliq-edit-cgroup-v1', claim.dispatchId]));
    assert.equal(path.posix.basename(invocationPlan.backend.cgroupPath), `cliq-${invocationPlan.backend.cgroupNameReservationDigest}`);
    assert.equal(invocationPlan.backend.pidNamespaceReservationId, identityHash('cliq-edit-namespace-v1', claim.dispatchId));
    assert.equal(death.backend.cgroupPopulated, 0); assert.equal(death.backend.namespaceInitDeadAndReaped, true);
    assert.equal(death.backend.remainingTrackedDescendants, 0);
    const backend = nativeBackend(death.backend);
    assert.match(await readFile(path.join(backend.cgroupPath, 'cgroup.events'), 'utf8'), /(?:^|\n)populated 0\n/u);
    assert.deepEqual(await readFile(path.join(fixture.workspace, 'a')), fixture.original);
    assert.equal((await stat(path.join(fixture.workspace, 'a'))).ino, originalStat.ino);
    first.close();
    const second = await transport.connect();
    const attached = await second.connection.dispatch(identity => store.readControl({ protocolVersion: 1, method: 'run.attach',
      runId: fixture.runId, afterEventSeq: 0 }, identity));
    if (attached.method !== 'run.attach') throw new Error('authenticated attach returned another method');
    assert.equal(attached.snapshot.run.revision, after.closure.run.revision);
    await assert.rejects(execution.executeCurrentTool({ expectedRunRevision: after.closure.run.revision }),
      'equal current cut cannot replay an already-completed edit');
    assert.equal((await store.readRecoveryClosure(fixture.runId)).journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'dispatch_claimed').length, 1);
    console.log(JSON.stringify({ scenario: 'actual-edit-ready-checkpoint', bundleDigest: fixture.signed.bundle.manifestDigest,
      imageDigests: fixture.signed.bundle.entries.filter(entry => ['worker', 'tool_adapter', 'platform_helper'].includes(entry.role))
        .map(entry => ({ id: entry.entryId, digest: entry.digest })), startingRunRevision: before.run.revision,
      checkpointId: after.closure.latestCheckpoint.id, leaseEpoch: after.closure.run.leaseEpoch,
      permanentToolClaims: 1, nativeEffectCount: 1, controlReadsDuringExecution: reads, timerTicks, maxTurnGap }));
    second.close(); await transport.close(); await store.close();
    store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    transport = await control(store);
    const reopened = await checkpointBytes(store, fixture.runId);
    assert.deepEqual(reopened.bytes, Buffer.from('after\n'));
    assert.equal(reopened.closure.latestCheckpoint.id, after.closure.latestCheckpoint.id);
    const reconnected = await transport.connect();
    const durable = await reconnected.connection.dispatch(identity => store.readControl({ protocolVersion: 1, method: 'run.get', runId: fixture.runId }, identity));
    if (durable.method !== 'run.get') throw new Error('authenticated read returned another method');
    assert.equal(durable.snapshot.run.revision, reopened.closure.run.revision);
    const next = await store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
    await assert.rejects(next.executeCurrentTool({ expectedRunRevision: reopened.closure.run.revision }));
    assert.equal((await checkpointBytes(store, fixture.runId)).closure.run.budgetConsumed.toolCalls, 1);
    reconnected.close();
  } finally { await transport.close(); await store.close(); await fixture.dispose(); }
}

async function preactivationRetirementRetry(boundary: 'before_spawn' | 'ready_before_identity' | 'ready_invalid_tree') {
  const created = boundary !== 'before_spawn', invalidTree = boundary === 'ready_invalid_tree';
  const fixture = await createLinuxWorkerCampaignFixture({ ...options, label: `${boundary.replaceAll('_', '-')}-retry` });
  let store = fixture.store;
  let metadata: ReturnType<typeof openSqliteDriver> | undefined;
  const originalRead = fs.readSync;
  const primary = Object.assign(new Error(`campaign actual worker image read failed ${created ? 'after READY before identity' : 'before spawn'}`), { code: 'EIO' });
  type ReadyScope = { path: string; cgroupId: string; pidNamespaceId: string; workerPid: number; workerToken: string;
    initPid: number; initToken: string; members: { pid: number; token: string }[] };
  let injected: { launch: WorkerLaunch; controllerPid: number; controllerToken: string; physicalScope?: ReadyScope } | undefined;
  let probing = false, faults = 0;
  let operationFailure: { error: unknown } | undefined;
  let successorOpeningFailed = false;
  try {
    const before = await checkpointBytes(store, fixture.runId);
    const execution = await store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
    const inspection = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    metadata = inspection;
    const workerImage = fixture.signed.bundle.entries.find(entry => entry.entryId === 'linux_worker')!;
    assert.equal(workerImage.role, 'worker'); assert.ok(workerImage.executable);
    // Consume real OS bytes first. Selection is a read-only retained cut plus
    // the exact signed held image, not a native/reducer replacement or receipt.
    fs.readSync = ((...args: unknown[]) => {
      const count = Reflect.apply(originalRead, fs, args) as number;
      if (!injected && !probing) {
        probing = true;
        try {
          const fd = args[0] as number, held = fs.fstatSync(fd, { bigint: true });
          if (held.isFile() && held.size === BigInt(workerImage.byteCount) &&
              (created || fs.readlinkSync(`/proc/self/fd/${fd}`) === '/memfd:cliq-runtime-image (deleted)')) {
            const launch = inspection.readSnapshot(connection => {
              const rows = connection.prepare('SELECT launch_id FROM worker_launches WHERE run_id=? AND retired_at IS NULL')
                .all<{ launch_id: string }>(fixture.runId);
              assert.ok(rows.length <= 1, 'the fault must not select competing launch reservations');
              return rows.length === 1 ? readRequiredWorkerLaunch(connection, rows[0]!.launch_id) : undefined;
            });
            if (launch?.phase === 'reserved') {
              assert.equal(launch.workerIdentityDigest, undefined); assert.equal(launch.processContainmentRef, undefined);
              const plan = frozenArtifact<ProcessContainmentPlanV1>(fixture.stateRoot, launch.containmentPlanRef);
              assert.equal(plan.owner.kind, 'worker_activation');
              if (plan.owner.kind !== 'worker_activation' || plan.backend.kind !== 'linux') throw new Error('preactivation fault lacks its Linux worker reservation');
              assert.equal(plan.owner.runId, fixture.runId);
              assert.equal(plan.owner.workerLaunchId, launch.launchId); assert.equal(plan.launchNonceDigest, launch.spawnNonceDigest);
              const scopePath = plan.backend.cgroupPath;
              // Installed/sealed image reads precede creation. READY observation
              // reads the real worker's executable, a different held inode.
              const running = created ? imageProcess(path.join(scopePath, 'worker'), 'cliq-linux-worker') : undefined;
              if (created && (!running || running.image.dev !== held.dev || running.image.ino !== held.ino)) return count;
              const hash = createHash('sha256'), chunk = Buffer.alloc(Math.min(64 * 1024, workerImage.byteCount));
              for (let offset = 0; offset < workerImage.byteCount;) {
                const length = originalRead(fd, chunk, 0, Math.min(chunk.length, workerImage.byteCount - offset), offset);
                assert.ok(length > 0, 'the fault selector must read the complete actual image');
                hash.update(chunk.subarray(0, length)); offset += length;
              }
              if (hash.digest('hex') === workerImage.digest) {
                let physicalScope: ReadyScope | undefined;
                if (running) {
                  const group = fs.lstatSync(scopePath, { bigint: true }); assert.ok(group.isDirectory() && !group.isSymbolicLink());
                  assert.match(fs.readFileSync(path.join(scopePath, 'cgroup.events'), 'utf8'), /(?:^|\n)populated 1\n/u);
                  const namespace = fs.statSync(`/proc/${running.pid}/ns/pid`, { bigint: true });
                  const members = pids(path.join(scopePath, 'worker')).map(pid => ({ pid, token: processToken(pid) }));
                  const init = members.filter(member => {
                    const identity = fs.statSync(`/proc/${member.pid}/ns/pid`, { bigint: true });
                    return identity.dev === namespace.dev && identity.ino === namespace.ino && namespacePid(member.pid) === 1;
                  });
                  assert.equal(init.length, 1); assert.equal(processToken(running.pid), running.token);
                  assert.ok(members.some(member => member.pid === running.pid && member.token === running.token));
                  physicalScope = { path: scopePath, cgroupId: String(group.ino), pidNamespaceId: String(namespace.ino),
                    workerPid: running.pid, workerToken: running.token, initPid: init[0]!.pid, initToken: init[0]!.token, members };
                } else {
                  assert.throws(() => fs.lstatSync(scopePath), error =>
                    (error as NodeJS.ErrnoException).code === 'ENOENT' && (error as NodeJS.ErrnoException).path === scopePath);
                }
                const controller = /^linux-subreaper:([1-9][0-9]*):(linux-proc-start-ticks:[0-9]+)$/u.exec(plan.backend.subreaperStartToken);
                assert.ok(controller); const controllerPid = Number(controller[1]), controllerToken = controller[2]!;
                assert.equal(processToken(controllerPid), controllerToken); assert.ok(directChildren().has(controllerPid));
                const after = fs.fstatSync(fd, { bigint: true });
                assert.equal(after.dev, held.dev); assert.equal(after.ino, held.ino); assert.equal(after.size, held.size);
                assert.equal(after.mtimeNs, held.mtimeNs); assert.equal(after.ctimeNs, held.ctimeNs);
                if (invalidTree) {
                  const generation = frozenArtifact<WorkspaceGenerationIdentityV1>(fixture.stateRoot, launch.workspaceGenerationRef);
                  if (generation.locator.kind !== 'linux_directory') throw new Error('invalid-tree fault has no exact Linux generation');
                  const root = fs.openSync(path.join(fixture.stateRoot, generation.locator.canonicalRootRelativePath),
                    fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
                  try {
                    const heldRoot = fs.fstatSync(root, { bigint: true });
                    assert.equal(String(heldRoot.dev), generation.locator.deviceId);
                    assert.equal(String(heldRoot.ino), generation.locator.directoryFileId);
                    assert.equal(Number(heldRoot.uid), generation.locator.ownerUid); assert.equal(heldRoot.mode & 0o7777n, 0o700n);
                    // A real invalid entry in this disposable private tree. It
                    // is never followed and no source/host bytes are changed.
                    fs.symlinkSync('../../outside', `/proc/self/fd/${root}/escape`);
                    const afterRoot = fs.fstatSync(root, { bigint: true });
                    assert.equal(afterRoot.dev, heldRoot.dev); assert.equal(afterRoot.ino, heldRoot.ino);
                    assert.equal(afterRoot.uid, heldRoot.uid); assert.equal(afterRoot.mode, heldRoot.mode);
                    console.log(JSON.stringify({ scenario: 'actual-invalid-private-entry-observed', launchId: launch.launchId,
                      generationRef: launch.workspaceGenerationRef, directoryFileId: generation.locator.directoryFileId,
                      workerPid: physicalScope!.workerPid, fault: 'escaping_symlink_then_image_EIO' }));
                  } finally { fs.closeSync(root); }
                }
                assert.ok(count > 0); injected = { launch, controllerPid, controllerToken, ...(physicalScope ? { physicalScope } : {}) }; faults++;
                throw primary;
              }
            }
          }
        } finally { probing = false; }
      }
      return count;
    }) as typeof fs.readSync;
    syncBuiltinESMExports();
    await assert.rejects(bounded(execution.executeCurrentTool({ expectedRunRevision: before.closure.run.revision })), error => error === primary);
    fs.readSync = originalRead; syncBuiltinESMExports();
    assert.ok(injected, `missing actual ${boundary} fault is not a passed campaign`); assert.equal(faults, 1);
    const fault = injected;
    assert.equal(fault.physicalScope !== undefined, created);
    const failed = await checkpointBytes(store, fixture.runId);
    assert.equal(failed.closure.run.status, 'queued'); assert.equal(failed.closure.run.activeWorkerLaunchId, undefined);
    assert.equal(failed.closure.run.leaseEpoch, before.closure.run.leaseEpoch);
    assert.deepEqual(failed.closure.latestCheckpoint, before.closure.latestCheckpoint); assert.deepEqual(failed.bytes, fixture.original);
    assert.deepEqual(failed.closure.journal, before.closure.journal);
    assert.deepEqual(failed.closure.run.budgetConsumed, before.closure.run.budgetConsumed);
    assert.deepEqual(failed.closure.run.budgetReserved, before.closure.run.budgetReserved);
    const identity = frozenArtifact<WorkspaceGenerationIdentityV1>(fixture.stateRoot, fault.launch.workspaceGenerationRef);
    if (identity.locator.kind !== 'linux_directory') throw new Error('preactivation fixture did not materialize a real Linux generation');
    const generation = failed.closure.workspaceGenerations.find(row => row.generationRef === fault.launch.workspaceGenerationRef);
    assert.ok(generation);
    let relativePath = identity.locator.canonicalRootRelativePath;
    if (generation.phase === 'quarantined') {
      const receipt = await store.artifacts.readCanonical<WorkspaceGenerationQuarantineEvidenceV1>(generation.quarantineEvidenceRef);
      assert.equal(receipt.reason, created ? 'launch_died_before_activation' : 'launch_aborted'); assert.equal(receipt.generationRef, fault.launch.workspaceGenerationRef);
      if (invalidTree) {
        assert.deepEqual(receipt.observedState, { kind: 'unreadable_partial', failureCode: 'path_or_entry_invalid' });
        assert.deepEqual(generation.observedState, receipt.observedState);
        assert.equal(Object.hasOwn(receipt.observedState, 'treeDigest'), false);
      }
      assert.equal(receipt.quarantineDeviceId, identity.locator.deviceId); assert.equal(receipt.quarantineFileId, identity.locator.directoryFileId);
      relativePath = receipt.quarantineCanonicalRootRelativePath;
    } else { assert.equal(created, false, 'a created worker must be physically retired and quarantined'); assert.equal(generation.phase, 'preactivated_readonly'); }
    const root = await open(path.join(fixture.stateRoot, relativePath), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try {
      const held = await root.stat({ bigint: true });
      assert.equal(String(held.dev), identity.locator.deviceId); assert.equal(String(held.ino), identity.locator.directoryFileId);
      const file = await open(`/proc/self/fd/${root.fd}/a`, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      try {
        const heldFile = await file.stat(); assert.ok(heldFile.isFile()); assert.equal(heldFile.size, fixture.original.length);
        assert.deepEqual(await file.readFile(), fixture.original, 'the actual failed private generation has zero edit effects');
      } finally { await file.close(); }
    } finally { await root.close(); }
    if (fault.physicalScope) {
      assert.match(await readFile(path.join(fault.physicalScope.path, 'cgroup.events'), 'utf8'), /(?:^|\n)populated 0\n/u);
      for (const member of fault.physicalScope.members) await assert.rejects(access(`/proc/${member.pid}`), { code: 'ENOENT' });
    }
    await assert.rejects(access(`/proc/${fault.controllerPid}`), { code: 'ENOENT' });
    await store.close();
    try { store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority); }
    catch (error) { successorOpeningFailed = true; throw error; }
    const reopened = await checkpointBytes(store, fixture.runId);
    assert.deepEqual(reopened.closure.latestCheckpoint, before.closure.latestCheckpoint); assert.deepEqual(reopened.bytes, fixture.original);
    assert.deepEqual(reopened.closure.journal, before.closure.journal);
    assert.equal(reopened.closure.run.leaseEpoch, before.closure.run.leaseEpoch);
    assert.deepEqual(reopened.closure.run.budgetConsumed, before.closure.run.budgetConsumed);
    assert.deepEqual(reopened.closure.run.budgetReserved, before.closure.run.budgetReserved);
    const retry = await store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
    await bounded(retry.executeCurrentTool({ expectedRunRevision: reopened.closure.run.revision }));
    const after = await checkpointBytes(store, fixture.runId);
    assert.equal(after.closure.run.id, before.closure.run.id); assert.equal(after.closure.run.status, 'queued');
    assert.equal(after.closure.run.leaseEpoch, before.closure.run.leaseEpoch + 1);
    assert.deepEqual(after.bytes, Buffer.from('after\n')); assert.deepEqual(await readFile(path.join(fixture.workspace, 'a')), fixture.original);
    assert.equal(after.closure.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'dispatch_claimed').length, 1);
    assert.equal(after.closure.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'completed').length, 1);
    assert.equal(after.closure.run.budgetConsumed.toolCalls, before.closure.run.budgetConsumed.toolCalls + 1);
    assert.deepEqual(after.closure.run.budgetReserved, before.closure.run.budgetReserved);
    const launches = inspection.readSnapshot(connection => connection.prepare('SELECT launch_id FROM worker_launches WHERE run_id=?')
      .all<{ launch_id: string }>(fixture.runId).map(row => readRequiredWorkerLaunch(connection, row.launch_id)));
    const old = launches.find(launch => launch.launchId === fault.launch.launchId)!;
    const replacements = launches.filter(launch => launch.leaseEpoch === after.closure.run.leaseEpoch);
    assert.equal(old.phase, 'retired'); assert.ok(old.retirementEvidenceRef); assert.equal(replacements.length, 1);
    const originalFacts = { ...old, phase: fault.launch.phase };
    delete originalFacts.retiredAt; delete originalFacts.retirementEvidenceRef;
    if (created) delete originalFacts.processContainmentRef;
    assert.deepEqual(originalFacts, fault.launch, 'retirement must retain every original reservation binding');
    const replacement = replacements[0]!;
    assert.equal(replacement.phase, 'retired');
    assert.notEqual(replacement.launchId, old.launchId); assert.notEqual(replacement.spawnNonceDigest, old.spawnNonceDigest);
    assert.notEqual(replacement.activationNonceDigest, old.activationNonceDigest); assert.notEqual(replacement.workspaceGenerationRef, old.workspaceGenerationRef);
    const proof = await store.artifacts.readCanonical<ProcessContainmentNoSpawnEvidenceV1 | ProcessContainmentDeathEvidenceV1>(old.retirementEvidenceRef);
    const oldPlan = frozenArtifact<ProcessContainmentPlanV1>(fixture.stateRoot, old.containmentPlanRef);
    assert.equal(proof.planRef, old.containmentPlanRef); assert.deepEqual(proof.owner, oldPlan.owner);
    assert.equal(proof.sandboxLaunchSpecRef, old.sandboxLaunchSpecRef); assert.equal(proof.launchNonceDigest, old.spawnNonceDigest);
    assert.equal(proof.backend.kind, 'linux'); assert.equal(old.workerIdentityDigest, undefined);
    if (fault.physicalScope) {
      assert.equal(proof.kind, 'containment_all_descendants_dead');
      if (proof.kind !== 'containment_all_descendants_dead' || proof.backend.kind !== 'linux') throw new Error('created worker retirement lacks exact Linux death evidence');
      assert.equal(proof.containmentRef, old.processContainmentRef);
      assert.equal(proof.backend.cgroupPath, fault.physicalScope.path); assert.equal(proof.backend.cgroupId, fault.physicalScope.cgroupId);
      assert.equal(proof.backend.pidNamespaceId, fault.physicalScope.pidNamespaceId);
      assert.equal(proof.backend.cgroupPopulated, 0); assert.equal(proof.backend.namespaceInitDeadAndReaped, true);
      assert.equal(proof.backend.remainingTrackedDescendants, 0);
      const tokens = /^linux-namespace-init:([1-9][0-9]*):([0-9]+):monitor:([1-9][0-9]*):([0-9]+)$/u.exec(proof.backend.namespaceInitStartToken);
      assert.ok(tokens); assert.equal(Number(tokens[1]), fault.physicalScope.initPid);
      assert.equal(`linux-proc-start-ticks:${tokens[2]}`, fault.physicalScope.initToken);
      assert.ok(fault.physicalScope.members.some(member => member.pid === Number(tokens[3]) && member.token === `linux-proc-start-ticks:${tokens[4]}`));
      const containment = decodeWorkerProcessContainment(await store.artifacts.readCanonical(proof.containmentRef));
      assert.equal(containment.planRef, old.containmentPlanRef); assert.equal(containment.sandboxLaunchSpecRef, old.sandboxLaunchSpecRef);
      assert.equal(containment.launchNonceDigest, old.spawnNonceDigest); assert.deepEqual(containment.owner, oldPlan.owner);
      assert.deepEqual(containment.filesystemBinding, { kind: 'run-generation', generationRef: old.workspaceGenerationRef });
    } else {
      assert.equal(proof.kind, 'containment_plan_quiescent');
      if (proof.kind !== 'containment_plan_quiescent' || proof.backend.kind !== 'linux') throw new Error('unattempted worker retirement lacks exact Linux no-spawn evidence');
      assert.equal(proof.backend.matchingLaunchNonceProcessCount, 0);
    }
    console.log(JSON.stringify({ scenario: `actual-${boundary.replaceAll('_', '-')}-retirement-and-retry`, runId: fixture.runId,
      oldLaunchId: old.launchId, newLaunchId: replacement.launchId, oldGenerationRef: old.workspaceGenerationRef,
      newGenerationRef: replacement.workspaceGenerationRef,
      ...(fault.physicalScope ? { actualWorkerPid: fault.physicalScope.workerPid, actualWorkerStartToken: fault.physicalScope.workerToken } : {}),
      actualReadFaults: faults, nativeEffectCount: 1, permanentToolClaims: 1 }));
  } catch (error) { operationFailure = { error }; throw error; }
  finally {
    fs.readSync = originalRead; syncBuiltinESMExports();
    const failures: unknown[] = [];
    // A successful close of the old Store says nothing about resources retained
    // by a failed successor opening. Preserve that evidence even without a Store.
    let resourcesRetired = !successorOpeningFailed;
    try { metadata?.close(); } catch (error) { failures.push(error); resourcesRetired = false; }
    try { await store.close(); } catch (error) { failures.push(error); resourcesRetired = false; }
    if (resourcesRetired) {
      try { await fixture.dispose(); } catch (error) { failures.push(error); }
    } else console.error(`preserving uncertain ${boundary} fixture: ${fixture.stateRoot}`);
    if (failures.length !== 0) throw new AggregateError([...(operationFailure ? [operationFailure.error] : []), ...failures], 'preactivation campaign and cleanup failures');
  }
}

function heldDescriptorTargets() {
  const descriptors = new Map<number, string>();
  for (const filename of fs.readdirSync('/proc/self/fd')) {
    try { descriptors.set(Number(filename), fs.readlinkSync(`/proc/self/fd/${filename}`)); }
    catch (error) {
      // Enumeration's own descriptor can be gone before its readlink.
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
  return descriptors;
}

async function interruptedControllerClose() {
  const fixture = await createLinuxWorkerCampaignFixture({ ...options, label: 'async-close' });
  const launcher = await openLinuxWorkerLauncher({ ...options, runtimeAuthority: fixture.runtimeAuthority });
  const transport = await control(fixture.store);
  try {
    const client = await transport.connect();
    const read = () => client.connection.dispatch(identity => fixture.store.readControl({ protocolVersion: 1,
      method: 'run.get', runId: fixture.runId }, identity));
    await read();
    const installedDescriptors = heldDescriptorTargets();
    const beforeSpawn = new AbortController(), beforeReason = new Error('campaign cancelled before controller spawn');
    beforeSpawn.abort(beforeReason);
    await assert.rejects(launcher.startController({ signal: beforeSpawn.signal }), error => error === beforeReason);
    assert.deepEqual(heldDescriptorTargets(), installedDescriptors, 'pre-abort must not allocate native controller descriptors');
    const startingAbort = new AbortController(), startingReason = new Error('campaign cancelled controller readiness');
    const starting = launcher.startController({ signal: startingAbort.signal });
    startingAbort.abort(startingReason);
    // timers/promises wraps an in-flight abort; throwIfAborted returns the reason itself.
    await assert.rejects(bounded(starting), error => error === startingReason ||
      (error instanceof Error && error.name === 'AbortError' &&
        (error as NodeJS.ErrnoException).code === 'ABORT_ERR' && error.cause === startingReason));
    assert.deepEqual(heldDescriptorTargets(), installedDescriptors, 'cancelled actual readiness must await descriptor join');
    const controller = await launcher.startController();
    assert.ok(heldDescriptorTargets().size > installedDescriptors.size, 'the actual controller holds channel and captured output descriptors');
    const token = controller.processStartToken;
    assert.match(token, /^linux-proc-start-ticks:[0-9]+$/u);
    process.kill(controller.pid, 'SIGSTOP');
    let ticks = 0, reads = 0, joined = false, largestGap = 0, previous = performance.now();
    const timer = setInterval(() => { const now = performance.now(); largestGap = Math.max(largestGap, now - previous); previous = now; ticks++; }, 5);
    const started = performance.now(), closing = bounded(controller.close(), 15_000);
    void closing.then(() => { joined = true; }, () => { joined = true; });
    try {
      while (!joined) { await read(); reads++; await delay(5); }
      await bounded(closing, 15_000);
    } finally { clearInterval(timer); }
    assert.ok(ticks >= 2, 'actual stopped-controller join must not block Node timers');
    assert.ok(reads >= 2, 'authenticated control remains available while an actual native join reaches its deadline');
    assert.ok(largestGap < 1000, `actual controller join blocked the main loop for ${largestGap}ms`);
    assert.ok(performance.now() - started >= 5000, 'stopped controller must actually exercise the native join deadline');
    await assert.rejects(access(`/proc/${controller.pid}`), { code: 'ENOENT' });
    assert.deepEqual(heldDescriptorTargets(), installedDescriptors, 'close must join captured output/image/channel resources, not only observe a gone PID');
    console.log(JSON.stringify({ scenario: 'actual-stopped-controller-async-join', pid: controller.pid, processStartToken: token,
      timerTicks: ticks, controlReads: reads, largestGap, note: 'controller resource join/deadline, not whole-worker containment death evidence' }));
    client.close();
  } finally { await transport.close(); await launcher.close(); await fixture.dispose(); }
}

function processToken(pid: number): string {
  const line = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
  const fields = line.slice(line.lastIndexOf(')') + 2).trim().split(/\s+/u);
  assert.notEqual(fields[0], 'Z'); assert.match(fields[19]!, /^[0-9]+$/u);
  return `linux-proc-start-ticks:${fields[19]}`;
}

function pids(directory: string) {
  const value = fs.readFileSync(path.join(directory, 'cgroup.procs'), 'utf8').trim();
  return value === '' ? [] : value.split('\n').map(value => {
    const pid = Number(value); assert.ok(Number.isSafeInteger(pid) && pid > 0); return pid;
  });
}

function namespacePid(pid: number): number {
  const value = fs.readFileSync(`/proc/${pid}/status`, 'utf8').match(/^NSpid:\s+([0-9\s]+)$/mu)?.[1];
  if (value === undefined) throw new Error('native namespace process identity is unavailable');
  return Number(value.trim().split(/\s+/u).at(-1));
}

function imageProcess(directory: string, filename: string) {
  let candidates: number[];
  try { candidates = pids(directory); }
  catch (error) {
    const failure = error as NodeJS.ErrnoException;
    // The permanent claim precedes invocation creation. The first sealed-image
    // hash therefore has no process yet; wait for the actual process-image read.
    // Absence can never pass the campaign: it still requires a real injected kill.
    if (failure.code === 'ENOENT' && failure.path === path.join(directory, 'cgroup.procs')) return undefined;
    throw error;
  }
  for (const pid of candidates) {
    try {
      if (namespacePid(pid) !== 2) continue;
      const image = fs.statSync(`/proc/${pid}/exe`, { bigint: true });
      const runtime = fs.statSync(`/proc/${pid}/root/runtime/${filename}`, { bigint: true });
      if (image.dev === runtime.dev && image.ino === runtime.ino) return { pid, token: processToken(pid), image };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
  return undefined;
}

function frozenArtifact<T>(stateRoot: string, ref: string): T {
  assert.match(ref, /^[0-9a-f]{64}$/u);
  const fd = fs.openSync(path.join(stateRoot, KERNEL_CAS_DIRECTORY, ref), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    assert.ok(before.isFile() && before.size <= 1024n * 1024n && before.nlink === 1n);
    assert.equal(before.mode & 0o7777n, 0o400n);
    const bytes = fs.readFileSync(fd);
    const value: T = JSON.parse(bytes.toString('utf8'));
    assert.equal(canonicalSha256(value), ref); assert.deepEqual(canonicalJsonBytes(value), bytes);
    const after = fs.fstatSync(fd, { bigint: true });
    assert.equal(after.ino, before.ino); assert.equal(after.dev, before.dev); assert.equal(after.size, before.size);
    assert.equal(after.mtimeNs, before.mtimeNs); assert.equal(after.ctimeNs, before.ctimeNs);
    return value;
  } finally { fs.closeSync(fd); }
}

async function parentLossBeforeRelease() {
  const fixture = await createLinuxWorkerCampaignFixture({ ...options, label: 'parent-loss' });
  const before = await fixture.store.readRecoveryClosure(fixture.runId);
  const execution = await fixture.store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
  // Read-only metadata inspection is an OS test boundary, not an execution
  // authority seam. The signal target comes from this Run's exact frozen
  // launch/containment/WorkerIdentity, never a directory or process scan.
  const metadata = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  const originalRead = fs.readSync;
  let probing = false;
  let fault: { workerPid: number; processStartToken: string; generationRef: string; scope: string; survivingBeforeStop: number[] } | undefined;
  // Agreed native lifecycle seam, instrumented only at the OS read boundary.
  // Hashing still consumes real bytes from the actual native-opened executable.
  // No native handle, closure, PID credential or death receipt is mocked.
  fs.readSync = ((...args: unknown[]) => {
    if (!fault && !probing) {
      probing = true;
      try {
        const heldImage = fs.fstatSync(args[0] as number, { bigint: true });
        const retained = metadata.readSnapshot(connection => {
          const run = connection.prepare('SELECT active_worker_launch_id FROM runs WHERE id = ?')
            .get<{ active_worker_launch_id: string | null }>(fixture.runId);
          if (!run?.active_worker_launch_id) return undefined;
          const launch = readRequiredWorkerLaunch(connection, run.active_worker_launch_id);
          const claimRow = connection.prepare(`SELECT run_id, seq, op_id, op_kind, attempt, phase, entry_json FROM run_journal
            WHERE run_id = ? AND op_kind = 'tool' AND phase = 'dispatch_claimed' ORDER BY seq DESC LIMIT 1`)
            .get<JournalSqlRow>(fixture.runId);
          return claimRow ? { launch, claim: journalEntryFromRow(claimRow) } : undefined;
        });
        if (retained) {
          assert.equal(retained.launch.runId, fixture.runId); assert.equal(retained.launch.phase, 'activated');
          const worker = decodeWorkerIdentity(frozenArtifact<WorkerIdentity>(fixture.stateRoot, retained.launch.workerIdentityDigest!));
          const containment = decodeWorkerProcessContainment(frozenArtifact(fixture.stateRoot, retained.launch.processContainmentRef!));
          assert.equal(worker.processContainmentRef, retained.launch.processContainmentRef);
          assert.equal(worker.launchId, retained.launch.launchId);
          const parent = nativeBackend(containment.backend);
          assert.ok(retained.claim.sandboxLaunchSpecRef);
          const spec = frozenArtifact<SandboxLaunchSpecV1>(fixture.stateRoot, retained.claim.sandboxLaunchSpecRef);
          if (spec.owner.kind !== 'run_invocation' || spec.purpose !== 'tool') throw new Error('fault selected another invocation purpose');
          assert.equal(spec.owner.runId, fixture.runId); assert.equal(spec.owner.workerLaunchId, retained.launch.launchId);
          assert.equal(spec.owner.opId, retained.claim.opId); assert.equal(spec.owner.attempt, retained.claim.attempt);
          assert.equal(spec.owner.dispatchId, retained.claim.dispatchId); assert.equal(spec.owner.intendedLeaseEpoch, retained.claim.leaseEpoch);
          assert.equal(spec.parentWorkerContainmentRef, retained.launch.processContainmentRef);
          const plan = frozenArtifact<ProcessContainmentPlanV1>(fixture.stateRoot, spec.containmentPlanRef);
          if (plan.backend.kind !== 'linux') throw new Error('invocation did not retain its real Linux plan');
          const invocation = plan.backend;
          assert.equal(path.dirname(invocation.cgroupPath), parent.cgroupPath);
          const invoked = imageProcess(invocation.cgroupPath, 'cliq-linux-edit');
          if (invoked && invoked.image.dev === heldImage.dev && invoked.image.ino === heldImage.ino) {
            assert.equal(processToken(worker.pid), worker.processStartToken);
            const nativeIds = parent.namespaceInitStartToken.match(/^linux-namespace-init:([1-9][0-9]*):([0-9]+):monitor:([1-9][0-9]*):([0-9]+)$/u);
            assert.ok(nativeIds, 'fault requires the exact native init/monitor observation');
            const init = Number(nativeIds[1]), monitor = Number(nativeIds[3]);
            assert.equal(namespacePid(init), 1); assert.equal(processToken(init), `linux-proc-start-ticks:${nativeIds[2]}`);
            assert.equal(processToken(monitor), `linux-proc-start-ticks:${nativeIds[4]}`);
            process.kill(worker.pid, 'SIGKILL');
            // Killing the worker does not retire its frozen init/monitor.
            fs.statSync(`/proc/${init}`); fs.statSync(`/proc/${monitor}`);
            fault = { workerPid: worker.pid, processStartToken: worker.processStartToken,
              generationRef: retained.launch.workspaceGenerationRef, scope: parent.cgroupPath, survivingBeforeStop: [init, monitor] };
          }
        }
      } finally { probing = false; }
    }
    return Reflect.apply(originalRead, fs, args);
  }) as typeof fs.readSync;
  syncBuiltinESMExports();
  try {
    await assert.rejects(bounded(execution.executeCurrentTool({ expectedRunRevision: before.run.revision })),
      /actual invocation or parent process identity was revoked/u);
    assert.ok(fault, 'actual parent loss must be injected before the release; absent coverage is a failed campaign');
    const failed = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(failed.run.status, 'waiting'); assert.equal(failed.run.waitingReason, 'reconciliation');
    assert.equal(failed.run.activeWorkerLaunchId, undefined); assert.equal(failed.run.cancelRequested, false);
    const wait = await fixture.store.artifacts.readCanonical<WorkerDeathWait>(failed.run.waitingOnRef!);
    assert.equal(wait.subject.kind, 'worker_death');
    const claims = failed.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'dispatch_claimed');
    assert.equal(claims.length, 1);
    const claim = claims[0]!;
    const prepared = failed.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'prepared' &&
      entry.opId === claim.opId && entry.attempt === claim.attempt);
    assert.equal(prepared.length, 1); assert.ok(claim.grantRef);
    assert.equal(prepared[0]!.grantRef, claim.grantRef);
    // Preparation publishes the authorization decision using the previous ready
    // workspace. Parent loss must retain that exact pre-effect cut, never seal
    // the active generation or publish a completed-effect checkpoint.
    assert.equal(failed.latestCheckpoint.id, identityHash('cliq-tool-admission-checkpoint-v1', claim.grantRef));
    assert.equal(failed.latestCheckpoint.journalSeq, prepared[0]!.seq);
    assert.ok(failed.latestCheckpoint.journalSeq < claim.seq);
    assert.equal(failed.latestCheckpoint.workspaceStateRef, before.latestCheckpoint.workspaceStateRef);
    assert.deepEqual((await checkpointBytes(fixture.store, fixture.runId)).bytes, fixture.original);
    assert.match(await readFile(path.join(fault.scope, 'cgroup.events'), 'utf8'), /(?:^|\n)populated 0\n/u);
    const generationRef = fault.generationRef;
    assert.equal(wait.subject.workspaceGenerationRef, generationRef);
    assert.equal(failed.workspaceGenerations.find(row => row.generationRef === generationRef)?.phase, 'fenced_reconciling');
    const generation = frozenArtifact<WorkspaceGenerationIdentityV1>(fixture.stateRoot, generationRef);
    if (generation.locator.kind !== 'linux_directory') throw new Error('parent loss did not retain its actual Linux generation');
    const root = fs.openSync(path.join(fixture.stateRoot, generation.locator.canonicalRootRelativePath),
      fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try {
      const identity = fs.fstatSync(root, { bigint: true });
      assert.equal(String(identity.dev), generation.locator.deviceId); assert.equal(String(identity.ino), generation.locator.directoryFileId);
      const file = fs.openSync(`/proc/self/fd/${root}/a`, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      try {
        const actual = fs.fstatSync(file, { bigint: true });
        assert.ok(actual.isFile()); assert.equal(actual.size, BigInt(fixture.original.length));
        assert.deepEqual(fs.readFileSync(file), fixture.original, 'blocked native edit must not change even its private generation');
      } finally { fs.closeSync(file); }
    } finally { fs.closeSync(root); }
    assert.equal(failed.run.budgetReserved.toolCalls, 1);
    assert.equal(failed.run.budgetConsumed.toolCalls, 0);
    assert.equal(failed.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'completed').length, 0);
    await assert.rejects(execution.executeCurrentTool({ expectedRunRevision: failed.run.revision }));
    const replay = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(replay.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'dispatch_claimed').length, 1);
    assert.equal(replay.run.budgetReserved.toolCalls, 1, 'unknown claim keeps its conservative reservation');
    assert.deepEqual(await readFile(path.join(fixture.workspace, 'a')), fixture.original);
    console.log(JSON.stringify({ scenario: 'actual-parent-loss-before-release', ...fault,
      waitingSubjectRef: failed.run.waitingOnRef, permanentToolClaims: 1, nativeEffectCount: 0,
      remainingBudgetReservation: 1, note: 'worker_death wait preserved; manual/unknown settlement is not qualified' }));
  } finally {
    fs.readSync = originalRead; syncBuiltinESMExports();
    metadata.close();
    try { await fixture.dispose(); }
    catch (error) { console.error('parent-loss StateStore.close failed:', error); throw error; }
  }
}

function directChildren() {
  const value = fs.readFileSync(`/proc/self/task/${process.pid}/children`, 'utf8').trim();
  const children = value === '' ? [] : value.split(/\s+/u).map(value => {
    assert.match(value, /^[1-9][0-9]*$/u);
    const pid = Number(value); assert.ok(Number.isSafeInteger(pid)); return pid;
  });
  assert.equal(new Set(children).size, children.length);
  return new Set(children);
}

async function closeActualInspection(fixture: Awaited<ReturnType<typeof createLinuxWorkerCampaignFixture>>,
  execution: Awaited<ReturnType<StateStore['loadRunExecution']>>, failed: Run) {
  const baseline = directChildren();
  const controllerImage = fixture.signed.bundle.entries.find(entry => entry.entryId === 'linux_worker_controller')!;
  assert.ok(controllerImage.executable && controllerImage.role === 'platform_helper');
  const recovery = execution.recoverWorker({ expectedRunRevision: failed.revision });
  const rejected = assert.rejects(recovery);
  void rejected.catch(() => {}); // Also awaited after the real close below.
  let stopped: { pid: number; token: string; wait: WorkerDeathWait } | undefined;
  const discoveryDeadline = performance.now() + 5000;
  // This fault target is a new direct child of this otherwise sequential
  // fixture, pinned to the installed signed controller bytes and token. It is
  // only an OS test selection, never production authority or a receipt seam.
  while (!stopped && performance.now() < discoveryDeadline) {
    const run = fixture.store.getRun(fixture.runId);
    const wait = frozenArtifact<WorkerDeathWait>(fixture.stateRoot, run.waitingOnRef!);
    const children = [...directChildren()].filter(pid => !baseline.has(pid));
    assert.ok(children.length <= 1, 'ambiguous new controller children refuse the fault rather than selecting a process');
    if (wait.probeState.phase === 'automatic_in_flight' && children.length === 1) {
      const pid = children[0]!;
      const token = processToken(pid);
      const fd = fs.openSync(`/proc/${pid}/exe`, fs.constants.O_RDONLY);
      try {
        const before = fs.fstatSync(fd, { bigint: true });
        // The brief pre-exec fork image is not the controller: wait, never
        // signal it or allocate its potentially large image as controller data.
        if (before.size === BigInt(controllerImage.byteCount)) {
          const bytes = fs.readFileSync(fd), after = fs.fstatSync(fd, { bigint: true });
          assert.equal(createHash('sha256').update(bytes).digest('hex'), controllerImage.digest);
          assert.equal(after.dev, before.dev); assert.equal(after.ino, before.ino); assert.equal(after.size, before.size);
          assert.equal(after.mtimeNs, before.mtimeNs); assert.equal(after.ctimeNs, before.ctimeNs);
          assert.equal(processToken(pid), token);
          assert.ok(directChildren().has(pid), 'controller remains an actual direct child');
          process.kill(pid, 'SIGSTOP');
          stopped = { pid, token, wait };
        }
      } finally { fs.closeSync(fd); }
    }
    if (!stopped) await delay(1);
  }
  assert.ok(stopped, 'actual in-flight controller must be pinned and stopped; missing coverage fails the campaign');
  const stopDeadline = performance.now() + 1000;
  for (;;) {
    const line = fs.readFileSync(`/proc/${stopped.pid}/stat`, 'utf8');
    const state = line.slice(line.lastIndexOf(')') + 2).split(' ')[0];
    assert.equal(processToken(stopped.pid), stopped.token);
    if (state === 'T') break;
    assert.ok(performance.now() < stopDeadline, 'SIGSTOP must be an actual kernel-observed state');
    await delay(1);
  }
  assert.equal(stopped.wait.probeState.phase, 'automatic_in_flight');
  if (stopped.wait.probeState.phase !== 'automatic_in_flight') throw new Error('fault did not freeze its inspection dispatch');
  const dispatch = stopped.wait.probeState.dispatch;
  if (dispatch.subjectKind !== 'worker_recovery') throw new Error('fault did not select the worker inspector');
  const oldWorker = decodeWorkerIdentity(frozenArtifact<WorkerIdentity>(fixture.stateRoot, stopped.wait.subject.oldWorkerIdentity));
  assert.equal(dispatch.owningSupervisorInstanceId, oldWorker.supervisorInstanceId, 'this is the original live-owner inspection');
  const closingAt = performance.now();
  await bounded(fixture.store.close(), 45_000);
  await rejected;
  await assert.rejects(access(`/proc/${stopped.pid}`), { code: 'ENOENT' });
  const store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
  try {
    const cut = await store.readRecoveryClosure(fixture.runId);
    const wait = await store.artifacts.readCanonical<WorkerDeathWait>(cut.run.waitingOnRef!);
    assert.equal(wait.probeState.phase, 'automatic_pending'); assert.equal(wait.probeState.automaticProbeCount, 1);
    if (wait.probeState.phase !== 'automatic_pending' || wait.probeState.automaticProbeCount !== 1) {
      throw new Error('same-owner cancellation did not close one exact deadline/nonce');
    }
    const wrapper = await store.artifacts.readCanonical<ReconciliationProbeEvidenceV1>(wait.probeState.lastProbeEvidenceRef);
    assert.equal(wrapper.outcome, 'probe_timeout');
    if (wrapper.outcome !== 'probe_timeout') throw new Error('cancelled inspection installed a late subject proof');
    const closure = await store.artifacts.readCanonical<ReconciliationProbeTimeoutClosureV1>(wrapper.timeoutClosureRef);
    if (closure.subjectKind !== 'worker_recovery') throw new Error('timeout belongs to another subject');
    assert.equal(closure.taskClosure.closureKind, 'cancelled_and_joined');
    assert.equal(closure.waitingSubjectRef, canonicalSha256(stopped.wait));
    assert.equal(closure.probeNonceDigest, dispatch.probeNonceDigest); assert.equal(closure.probeDispatchDigest, dispatch.dispatchDigest);
    assert.equal(closure.inspectorTaskId, dispatch.inspectorTaskId); assert.ok(closure.closedAt >= dispatch.probeDeadlineAt);
    assert.equal(cut.run.latestCheckpointId, failed.latestCheckpointId); assert.equal(cut.run.budgetReserved.toolCalls, 0);
    assert.equal(cut.journal.filter(entry => entry.opKind === 'tool').length, 0);
    const generation = cut.workspaceGenerations.find(row => row.generationRef === wait.subject.workspaceGenerationRef)!;
    assert.equal(generation.phase, 'fenced_reconciling', 'cancelled proof cannot promote or archive the old generation');
    const revision = cut.run.revision, waitingOnRef = cut.run.waitingOnRef;
    await delay(10);
    assert.equal(store.getRun(fixture.runId).revision, revision); assert.equal(store.getRun(fixture.runId).waitingOnRef, waitingOnRef);
    await delay(Math.max(0, Date.parse(wait.probeState.nextProbeAt) - Date.now()));
    const replacement = await store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
    console.log(JSON.stringify({ scenario: 'actual-inspection-cancelled-and-joined', pid: stopped.pid, processStartToken: stopped.token,
      probeNonceDigest: dispatch.probeNonceDigest, timeoutClosureRef: wrapper.timeoutClosureRef,
      closeElapsedMs: performance.now() - closingAt, nextProbeAt: wait.probeState.nextProbeAt,
      note: 'real SIGSTOP, public Store.close abort plus native join, actual wall-clock persisted deadline; no late proof' }));
    return { store, execution: replacement };
  } catch (error) { await store.close(); throw error; }
}

async function noOpenInvocationRecovery(cancelInspection = false) {
  const fixture = await createLinuxWorkerCampaignFixture({ ...options, label: cancelInspection ? 'joined-inspection' : 'no-open-recovery' });
  let store = fixture.store;
  const before = await fixture.store.readRecoveryClosure(fixture.runId);
  let execution = await fixture.store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
  const metadata = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  const policyPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, before.runSpec.policyRef);
  const sample = await open(policyPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  const policyIdentity = await sample.stat({ bigint: true });
  const filePrototype = Object.getPrototypeOf(sample) as { readFile: FileHandle['readFile'] };
  const originalReadFile = filePrototype.readFile;
  await sample.close();
  let fault: { workerPid: number; processStartToken: string; generationRef: string; scope: string;
    originalPath: string; originalDevice: bigint; originalInode: bigint } | undefined;
  // FileHandle.readFile is the actual CAS OS boundary (CAS is asynchronous;
  // mocking fs.readSync would not exercise this path). Return real OS bytes
  // everywhere except the single explicitly injected I/O failure after an
  // exact frozen worker is SIGKILLed, before any tool attempt exists.
  filePrototype.readFile = (async function(this: FileHandle, ...args: unknown[]) {
    const bytes: unknown = await Reflect.apply(originalReadFile, this, args);
    if (!fault && Buffer.isBuffer(bytes)) {
      const held = fs.fstatSync(this.fd, { bigint: true });
      if (held.dev === policyIdentity.dev && held.ino === policyIdentity.ino) {
        const launch = metadata.readSnapshot(connection => {
          const row = connection.prepare('SELECT active_worker_launch_id FROM runs WHERE id = ?')
            .get<{ active_worker_launch_id: string | null }>(fixture.runId);
          const attempts = connection.prepare("SELECT COUNT(*) AS count FROM run_journal WHERE run_id = ? AND op_kind = 'tool'")
            .get<{ count: bigint }>(fixture.runId)!.count;
          if (!row?.active_worker_launch_id || attempts !== 0n) return undefined;
          return readRequiredWorkerLaunch(connection, row.active_worker_launch_id);
        });
        if (launch?.phase === 'activated') {
          assert.equal(canonicalSha256(JSON.parse(bytes.toString('utf8'))), before.runSpec.policyRef);
          const worker = decodeWorkerIdentity(frozenArtifact<WorkerIdentity>(fixture.stateRoot, launch.workerIdentityDigest!));
          const containment = decodeWorkerProcessContainment(frozenArtifact(fixture.stateRoot, launch.processContainmentRef!));
          assert.equal(worker.launchId, launch.launchId); assert.equal(worker.processContainmentRef, launch.processContainmentRef);
          assert.equal(processToken(worker.pid), worker.processStartToken);
          const generation = frozenArtifact<WorkspaceGenerationIdentityV1>(fixture.stateRoot, launch.workspaceGenerationRef);
          if (generation.locator.kind !== 'linux_directory') throw new Error('recovery fixture did not produce a real Linux generation');
          const originalPath = path.join(fixture.stateRoot, generation.locator.canonicalRootRelativePath);
          const physical = fs.statSync(originalPath, { bigint: true });
          assert.equal(String(physical.dev), generation.locator.deviceId); assert.equal(String(physical.ino), generation.locator.directoryFileId);
          process.kill(worker.pid, 'SIGKILL');
          fault = { workerPid: worker.pid, processStartToken: worker.processStartToken, generationRef: launch.workspaceGenerationRef,
            scope: nativeBackend(containment.backend).cgroupPath, originalPath, originalDevice: physical.dev, originalInode: physical.ino };
          // This EIO is an OS-boundary fault injection, not a claim that the
          // kernel spontaneously failed. Process death/evidence remain real.
          throw Object.assign(new Error('campaign injected CAS read I/O failure after actual worker loss'), { code: 'EIO' });
        }
      }
    }
    return bytes;
  }) as FileHandle['readFile'];
  try {
    await assert.rejects(bounded(execution.executeCurrentTool({ expectedRunRevision: before.run.revision })));
    assert.ok(fault, 'activated-before-prepare loss must occur; missing fault coverage fails the campaign');
    // Remove the OS instrumentation before native inspection/recovery.
    filePrototype.readFile = originalReadFile;
    const failed = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(failed.run.status, 'waiting'); assert.equal(failed.run.waitingReason, 'reconciliation');
    const wait = await fixture.store.artifacts.readCanonical<WorkerDeathWait>(failed.run.waitingOnRef!);
    assert.equal(wait.subject.kind, 'worker_death'); assert.deepEqual(wait.subject.openInvocationRefs, []);
    assert.equal(failed.journal.filter(entry => entry.opKind === 'tool').length, 0);
    assert.equal(failed.run.budgetReserved.toolCalls, 0); assert.equal(failed.run.budgetConsumed.toolCalls, 0);
    assert.equal(failed.latestCheckpoint.id, before.latestCheckpoint.id);
    assert.deepEqual((await checkpointBytes(fixture.store, fixture.runId)).bytes, fixture.original);
    if (cancelInspection) ({ store, execution } = await closeActualInspection(fixture, execution, failed.run));
    const recovered = await bounded(execution.recoverWorker({ expectedRunRevision: store.getRun(fixture.runId).revision }));
    assert.equal(recovered.status, 'queued'); assert.equal(recovered.activeWorkerLaunchId, undefined);
    const restored = await store.readRecoveryClosure(fixture.runId);
    assert.equal(restored.latestCheckpoint.id, before.latestCheckpoint.id, 'restore selects the exact previous ready Checkpoint');
    const originalGenerationRef = fault.generationRef;
    const archived = restored.workspaceGenerations.find(row => row.generationRef === originalGenerationRef);
    assert.equal(archived?.phase, 'quarantined');
    if (archived?.phase !== 'quarantined') throw new Error('real recovery did not archive the exact fenced generation');
    const receipt = await store.artifacts.readCanonical<WorkspaceGenerationQuarantineEvidenceV1>(archived.quarantineEvidenceRef);
    const physicalArchive = await stat(path.join(fixture.stateRoot, receipt.quarantineCanonicalRootRelativePath), { bigint: true });
    assert.equal(physicalArchive.dev, fault.originalDevice); assert.equal(physicalArchive.ino, fault.originalInode);
    assert.equal(receipt.quarantineDeviceId, String(fault.originalDevice)); assert.equal(receipt.quarantineFileId, String(fault.originalInode));
    await assert.rejects(access(fault.originalPath), { code: 'ENOENT' });
    assert.equal(restored.workspaceGenerations.filter(row => row.phase === 'preactivated_readonly').length, 1);
    assert.deepEqual((await checkpointBytes(store, fixture.runId)).bytes, fixture.original);
    assert.match(await readFile(path.join(fault.scope, 'cgroup.events'), 'utf8'), /(?:^|\n)populated 0\n/u);
    assert.deepEqual(await readFile(path.join(fixture.workspace, 'a')), fixture.original);
    const productive = await bounded(execution.executeCurrentTool({ expectedRunRevision: recovered.revision }));
    assert.equal(productive.status, 'queued');
    const final = await checkpointBytes(store, fixture.runId);
    assert.deepEqual(final.bytes, Buffer.from('after\n'));
    assert.equal(final.closure.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'dispatch_claimed').length, 1);
    assert.equal(final.closure.run.budgetConsumed.toolCalls, 1);
    assert.deepEqual(await readFile(path.join(fixture.workspace, 'a')), fixture.original);
    console.log(JSON.stringify({ scenario: cancelInspection ? 'actual-joined-inspection-successor-recovery' : 'actual-no-open-worker-loss-recovery', workerPid: fault.workerPid,
      processStartToken: fault.processStartToken, oldGenerationRef: fault.generationRef,
      quarantinePath: receipt.quarantineCanonicalRootRelativePath, quarantineInode: receipt.quarantineFileId,
      restoredCheckpointId: before.latestCheckpoint.id, nativeEffectsAfterRecovery: 1,
      note: 'actual native whole-hierarchy death plus descriptor archive; CAS EIO explicitly injected at OS boundary' }));
  } finally {
    filePrototype.readFile = originalReadFile; metadata.close();
    if (store !== fixture.store) await store.close();
    try { await fixture.dispose(); }
    catch (error) { console.error('no-open recovery StateStore.close failed:', error); throw error; }
  }
}

async function closeDuringFactoryOpen() {
  const fixture = await createLinuxWorkerCampaignFixture({ ...options, label: 'factory-close' });
  let reopened: StateStore | undefined;
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const opening = fixture.store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
    const refused = assert.rejects(opening, { code: 'LEASE_FENCED' });
    await bounded(fixture.store.close()); await refused;
    reopened = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    assert.deepEqual(await reopened.readRecoveryClosure(fixture.runId), before,
      'closing during validation must not spawn or acquire durable Run authority');
    const retry = await reopened.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
    assert.ok(retry, 'reopen can safely validate a fresh resource scope');
    console.log(JSON.stringify({ scenario: 'actual-factory-open-close-race',
      note: 'public Store close joins in-flight validation and releases the actual StateOwner lock before reopen' }));
  } finally { await reopened?.close(); await fixture.dispose(); }
}

async function supervisorCrashAfterMove() {
  const fixture = await createLinuxWorkerCampaignFixture({ ...options, label: 'move-crash' });
  const before = await fixture.store.readRecoveryClosure(fixture.runId);
  await fixture.store.close();
  const child = fork(new URL('./linux-worker-crash-child.ts', import.meta.url), [], {
    execArgv: ['--import', 'tsx'], serialization: 'advanced', stdio: ['ignore', 'pipe', 'pipe', 'ipc']
  });
  let diagnostic = '', successor: StateStore | undefined;
  for (const output of [child.stdout!, child.stderr!]) output.on('data', (chunk: Buffer) => {
    diagnostic = (diagnostic + chunk.toString()).slice(-8192);
  });
  const exited = once(child, 'exit'); void exited.catch(() => {});
  const reply = async () => {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(new Error('crash Supervisor IPC timed out')), 40_000);
    try {
      return await Promise.race([
        once(child, 'message', { signal: abort.signal }).then(([message]) => message as { state?: string; message?: string }),
        exited.then(([code, signal]) => { throw new Error(`crash Supervisor exited before reply: ${code}/${signal}: ${diagnostic}`); })
      ]);
    } catch (cause) { throw new Error(`real crash Supervisor did not reach its OS boundary: ${diagnostic}`, { cause }); }
    finally { clearTimeout(timer); abort.abort(); }
  };
  try {
    assert.equal((await reply()).state, 'ready');
    const paused = reply(); void paused.catch(() => {});
    const input: CrashChildInput = { stateRoot: fixture.stateRoot, runId: fixture.runId, runtimeAuthority: fixture.runtimeAuthority,
      materialData: Object.fromEntries(Object.entries(fixture.authority.material).filter(([, value]) => typeof value !== 'function')) as CrashChildInput['materialData'] };
    await new Promise<void>((resolve, reject) => child.send(input, error => error ? reject(error) : resolve()));
    const message = await paused;
    assert.equal(message.state, 'post_move_pre_cas', message.message ?? diagnostic);
    const boundary = message as CrashChildPaused;
    assert.equal(boundary.runId, fixture.runId);
    const metadata = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    const held = (() => { try { return metadata.readSnapshot(connection => {
      const run = readRun(connection, fixture.runId);
      assert.equal(run.status, 'waiting'); assert.equal(run.waitingReason, 'reconciliation');
      assert.equal(run.waitingOnRef, boundary.waitingOnRef);
      const wait = frozenArtifact<WorkerDeathWait>(fixture.stateRoot, run.waitingOnRef!);
      if (wait.probeState.phase !== 'automatic_in_flight' || wait.probeState.dispatch.subjectKind !== 'worker_recovery') {
        throw new Error('independent parent observation lacks the exact retained worker dispatch');
      }
      const anchor = frozenArtifact<WorkspaceGenerationStateV1>(fixture.stateRoot, wait.probeState.dispatch.inspectionTargetDigest);
      const generation = readRequiredWorkspaceGenerationByRef(connection, wait.subject.workspaceGenerationRef);
      const owner = readLatestStateOwner(connection)!;
      assert.equal(owner.state, 'active'); assert.equal(owner.supervisorInstanceId, wait.probeState.dispatch.owningSupervisorInstanceId);
      assert.equal(generation.phase, 'fenced_reconciling'); assert.equal(generation.waitingSubjectRef, run.waitingOnRef);
      assert.equal(generation.rowVersion, anchor.rowVersion + 1, 'physical move must not have committed the row CAS');
      assert.equal(anchor.generationRef, boundary.generationRef); assert.equal(anchor.rowVersion + 1, boundary.sourceRowVersion);
      assert.equal(connection.prepare("SELECT COUNT(*) AS count FROM run_journal WHERE run_id=? AND op_kind='tool'")
        .get<{ count: bigint }>(fixture.runId)!.count, 0n);
      return { run, wait, anchor, owner };
    }); } finally { metadata.close(); } })();
    const oldDispatch = held.wait.probeState;
    if (oldDispatch.phase !== 'automatic_in_flight' || oldDispatch.dispatch.subjectKind !== 'worker_recovery') throw new Error('missing actual crash dispatch');
    const identity = frozenArtifact<WorkspaceGenerationIdentityV1>(fixture.stateRoot, held.anchor.generationRef);
    if (identity.locator.kind !== 'linux_directory') throw new Error('crash does not retain a real Linux directory');
    const sourceRowVersion = held.anchor.rowVersion + 1;
    // IPC locators are not authority: derive both exact names from persisted
    // bytes, and independently compare the actual archived descriptor identity.
    const archiveRelativePath = `quarantine/workspace-generations/${identityHash(identity.generationId, String(sourceRowVersion))}`;
    assert.equal(boundary.archiveRelativePath, archiveRelativePath);
    const archivePath = path.join(fixture.stateRoot, archiveRelativePath);
    const physical = await lstat(archivePath, { bigint: true });
    assert.ok(physical.isDirectory() && !physical.isSymbolicLink()); assert.equal(String(physical.dev), identity.locator.deviceId);
    assert.equal(String(physical.ino), identity.locator.directoryFileId);
    assert.equal(boundary.archiveDevice, String(physical.dev)); assert.equal(boundary.archiveInode, String(physical.ino));
    await assert.rejects(access(path.join(fixture.stateRoot, identity.locator.canonicalRootRelativePath)), { code: 'ENOENT' });
    assert.match(boundary.quarantineArtifactRef, /^[0-9a-f]{64}$/u);
    await assert.rejects(access(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, boundary.quarantineArtifactRef)), { code: 'ENOENT' });
    const containment = decodeWorkerProcessContainment(frozenArtifact(fixture.stateRoot, held.wait.subject.processContainmentRef));
    assert.match(await readFile(path.join(nativeBackend(containment.backend).cgroupPath, 'cgroup.events'), 'utf8'), /(?:^|\n)populated 0\n/u);
    await assert.rejects(openStateStore(fixture.stateRoot, fixture.runtimeAuthority), 'a live paused Supervisor must still hold the real StateOwner lock');
    const supervisorToken = processToken(child.pid!);
    const supervisorIdentity = frozenArtifact<PlatformProcessIdentityV1>(fixture.stateRoot, held.owner.processIdentityRef);
    assert.equal(supervisorIdentity.platform, 'linux'); assert.equal(supervisorIdentity.pid, child.pid);
    assert.equal(supervisorIdentity.processStartToken, supervisorToken);
    assert.ok(child.kill('SIGKILL')); assert.equal((await bounded(exited))[1], 'SIGKILL');
    successor = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    const retained = await successor.readRecoveryClosure(fixture.runId);
    assert.deepEqual(retained.run, held.run, 'process takeover cannot finish the interrupted recovery');
    const metadataAfter = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    const newOwner = (() => { try { return metadataAfter.readSnapshot(connection => readLatestStateOwner(connection)!); }
      finally { metadataAfter.close(); } })();
    assert.ok(newOwner.ownerEpoch > held.owner.ownerEpoch); assert.notEqual(newOwner.supervisorInstanceId, held.owner.supervisorInstanceId);
    const execution = await successor.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
    await delay(Math.max(0, Date.parse(oldDispatch.dispatch.probeDeadlineAt) - Date.now()));
    const closed = await bounded(execution.recoverWorker({ expectedRunRevision: retained.run.revision }));
    const pending = await successor.artifacts.readCanonical<WorkerDeathWait>(closed.waitingOnRef!);
    if (pending.probeState.phase !== 'automatic_pending' || pending.probeState.automaticProbeCount !== 1) {
      throw new Error('successor must close the predecessor task before starting a fresh inspection');
    }
    const timeoutWrapper = await successor.artifacts.readCanonical<ReconciliationProbeEvidenceV1>(pending.probeState.lastProbeEvidenceRef!);
    if (timeoutWrapper.outcome !== 'probe_timeout') throw new Error('a dead-owner inspection cannot be adopted as positive evidence');
    const timeout = await successor.artifacts.readCanonical<ReconciliationProbeTimeoutClosureV1>(timeoutWrapper.timeoutClosureRef);
    if (timeout.subjectKind !== 'worker_recovery' || timeout.taskClosure.closureKind !== 'owner_process_dead') {
      throw new Error('successor lacks genuine StateOwner-acquisition death closure');
    }
    const acquisition = await successor.artifacts.readCanonical<{ kind: string }>(timeout.taskClosure.ownerDeathAcquisitionEvidenceRef);
    assert.equal(acquisition.kind, 'takeover_after_owner_death');
    assert.equal(timeout.probeNonceDigest, oldDispatch.dispatch.probeNonceDigest);
    assert.equal(timeout.waitingSubjectRef, held.run.waitingOnRef); assert.equal(closed.latestCheckpointId, before.latestCheckpoint.id);
    await delay(Math.max(0, Date.parse(pending.probeState.nextProbeAt) - Date.now()));
    const recovered = await bounded(execution.recoverWorker({ expectedRunRevision: closed.revision }));
    const recoveredCut = await successor.readRecoveryClosure(fixture.runId);
    const archived = recoveredCut.workspaceGenerations.find(row => row.generationRef === held.anchor.generationRef)!;
    assert.equal(archived?.phase, 'quarantined');
    if (archived?.phase !== 'quarantined') throw new Error('successor did not finish the exact retained archive');
    const receipt = await successor.artifacts.readCanonical<WorkspaceGenerationQuarantineEvidenceV1>(archived.quarantineEvidenceRef);
    assert.equal(receipt.reason, 'worker_recovery');
    if (receipt.reason !== 'worker_recovery' || typeof receipt.workerRecoveryEvidenceRef !== 'string') throw new Error('archive is not bound to worker recovery');
    const recovery = await successor.artifacts.readCanonical<{ waitingSubjectRef: string; inspectorIdentityRef: string }>(receipt.workerRecoveryEvidenceRef);
    const fresh = await successor.artifacts.readCanonical<WorkerDeathWait>(recovery.waitingSubjectRef);
    if (fresh.probeState.phase !== 'automatic_in_flight' || fresh.probeState.dispatch.subjectKind !== 'worker_recovery') {
      throw new Error('successor receipt must bind its own exact fresh worker inspection');
    }
    assert.equal(fresh.probeState.automaticProbeCount, 2); assert.notEqual(fresh.probeState.dispatch.probeNonceDigest, oldDispatch.dispatch.probeNonceDigest);
    assert.equal(fresh.probeState.dispatch.owningSupervisorInstanceId, newOwner.supervisorInstanceId);
    assert.equal(fresh.probeState.dispatch.inspectionTargetDigest, oldDispatch.dispatch.inspectionTargetDigest);
    assert.equal(receipt.sourceRowVersion, sourceRowVersion); assert.equal(receipt.quarantineCanonicalRootRelativePath, archiveRelativePath);
    const reobserved = await lstat(archivePath, { bigint: true }); assert.ok(reobserved.isDirectory() && !reobserved.isSymbolicLink());
    assert.equal(reobserved.dev, physical.dev); assert.equal(reobserved.ino, physical.ino);
    assert.equal(recoveredCut.latestCheckpoint.id, before.latestCheckpoint.id);
    assert.equal(recoveredCut.workspaceGenerations.filter(row => row.phase === 'preactivated_readonly').length, 1);
    assert.deepEqual(recoveredCut.journal, retained.journal);
    assert.deepEqual((await checkpointBytes(successor, fixture.runId)).bytes, fixture.original);
    await bounded(execution.executeCurrentTool({ expectedRunRevision: recovered.revision }));
    const final = await checkpointBytes(successor, fixture.runId);
    assert.deepEqual(final.bytes, Buffer.from('after\n')); assert.deepEqual(await readFile(path.join(fixture.workspace, 'a')), fixture.original);
    assert.equal(final.closure.journal.filter(row => row.opKind === 'tool' && row.phase === 'dispatch_claimed').length, 1);
    assert.equal(final.closure.run.budgetConsumed.toolCalls, 1);
    assert.ok(final.closure.run.leaseEpoch > held.wait.subject.oldLeaseEpoch);
    console.log(JSON.stringify({ scenario: 'actual-supervisor-crash-post-move-pre-cas', supervisorPid: child.pid,
      supervisorStartToken: supervisorToken, signal: 'SIGKILL', priorOwnerEpoch: held.owner.ownerEpoch, successorOwnerEpoch: newOwner.ownerEpoch,
      runtimeBundleRef: newOwner.runtimeBundleRef, bundleDigest: fixture.signed.bundle.manifestDigest,
      startingRunRevision: before.run.revision, interruptedRunRevision: held.run.revision, restoredCheckpointId: before.latestCheckpoint.id,
      oldProbeNonceDigest: oldDispatch.dispatch.probeNonceDigest, freshProbeNonceDigest: fresh.probeState.dispatch.probeNonceDigest,
      inspectionTargetDigest: oldDispatch.dispatch.inspectionTargetDigest, sourceRowVersion,
      archiveRelativePath, archiveInode: String(reobserved.ino), nativeEffectsAfterRecovery: 1,
      note: 'actual native death/move and Supervisor SIGKILL; initial CAS-read EIO is injected, and the pre-receipt OS write is suspended' }));
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await bounded(exited); await successor?.close(); await fixture.dispose();
  }
}

async function retirementFailureKeepsOwner(fault: NonNullable<CrashChildInput['retirementFault']>) {
  const fixture = await createLinuxWorkerCampaignFixture({ ...options, label: `retirement-${fault}` });
  const before = await fixture.store.readRecoveryClosure(fixture.runId);
  await fixture.store.close();
  const child = fork(new URL('./linux-worker-crash-child.ts', import.meta.url), [], {
    execArgv: ['--import', 'tsx'], serialization: 'advanced', stdio: ['ignore', 'pipe', 'pipe', 'ipc']
  });
  const exited = once(child, 'exit'); void exited.catch(() => {});
  let diagnostic = '', successor: StateStore | undefined;
  for (const output of [child.stdout!, child.stderr!]) output.on('data', (chunk: Buffer) => {
    diagnostic = (diagnostic + chunk.toString()).slice(-8192);
  });
  const reply = async () => {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(new Error('retirement Supervisor IPC timed out')), 80_000);
    try {
      return await Promise.race([
        once(child, 'message', { signal: abort.signal }).then(([message]) => message as { state?: string; message?: string }),
        exited.then(([code, signal]) => { throw new Error(`retirement Supervisor exited before reply: ${code}/${signal}: ${diagnostic}`); })
      ]);
    } finally { clearTimeout(timer); abort.abort(); }
  };
  try {
    assert.equal((await reply()).state, 'ready');
    const refused = reply(); void refused.catch(() => {});
    const input: CrashChildInput = { stateRoot: fixture.stateRoot, runId: fixture.runId, runtimeAuthority: fixture.runtimeAuthority,
      retirementFault: fault,
      materialData: Object.fromEntries(Object.entries(fixture.authority.material).filter(([, value]) => typeof value !== 'function')) as CrashChildInput['materialData'] };
    await new Promise<void>((resolve, reject) => child.send(input, error => error ? reject(error) : resolve()));
    const message = await refused;
    assert.equal(message.state, fault === 'controller_loss' ? 'controller_loss_close_refused' : 'retirement_close_refused',
      `${message.message ?? ''}\ncrash child stderr/stdout:\n${diagnostic}`);
    const refusal = message as CrashChildRetirementRefused | CrashChildControllerLossRefused;
    assert.equal(refusal.runId, fixture.runId); assert.equal(refusal.fault, fault);
    assert.equal(refusal.closeCode, 'RECOVERY_REQUIRED');
    if (refusal.fault === 'controller_loss') {
      assert.equal(refusal.actualReadFaults, 1); assert.equal(refusal.primaryCode, 'EIO');
    } else assert.equal(refusal.actualCloseFaults, 1);
    assert.equal(refusal.probePhase, fault === 'timeout_closure' ? 'automatic_in_flight' : 'automatic_pending');
    const metadata = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    const held = (() => { try { return metadata.readSnapshot(connection => {
      const owner = readLatestStateOwner(connection)!;
      assert.equal(owner.state, 'active', 'uncertain retirement must not gracefully terminalize the owner');
      const run = readRun(connection, fixture.runId);
      assert.equal(run.waitingOnRef, refusal.waitingOnRef); assert.equal(run.latestCheckpointId, before.latestCheckpoint.id);
      assert.equal(run.status, 'waiting'); assert.equal(run.activeWorkerLaunchId, undefined);
      assert.equal(connection.prepare("SELECT COUNT(*) AS count FROM run_journal WHERE run_id=? AND op_kind='tool'")
        .get<{ count: bigint }>(fixture.runId)!.count, 0n, 'neither retirement fault can create or repeat a tool attempt');
      const wait = frozenArtifact<WorkerDeathWait>(fixture.stateRoot, run.waitingOnRef!);
      assert.equal(wait.probeState.phase, refusal.probePhase); assert.deepEqual(wait.subject.openInvocationRefs, []);
      const processIdentity = frozenArtifact<PlatformProcessIdentityV1>(fixture.stateRoot, owner.processIdentityRef);
      assert.equal(processIdentity.pid, child.pid); assert.equal(processToken(child.pid!), processIdentity.processStartToken);
      return { owner, run, wait };
    }); } finally { metadata.close(); } })();
    if (refusal.fault === 'controller_loss') {
      assert.equal(held.run.revision, refusal.runRevision);
      assert.equal(held.run.revision, before.run.revision + 2, 'shutdown retries must not advance the fenced Run');
      assert.deepEqual(held.run.budgetConsumed, before.run.budgetConsumed);
      assert.equal(held.wait.probeState.automaticProbeCount, 0); assert.equal(held.wait.probeState.userProbeCount, 0);
      const containment = decodeWorkerProcessContainment(frozenArtifact(fixture.stateRoot, held.wait.subject.processContainmentRef));
      const backend = nativeBackend(containment.backend);
      assert.equal(backend.subreaperStartToken, `linux-subreaper:${refusal.controllerPid}:${refusal.controllerStartToken}`);
      await assert.rejects(access(`/proc/${refusal.controllerPid}`), { code: 'ENOENT' }, 'the actual killed controller has been joined');
    }
    await assert.rejects(openStateStore(fixture.stateRoot, fixture.runtimeAuthority), /OS lock is already held/u,
      'a real contender must not acquire after the failed operation and repeated shutdown attempts');
    assert.deepEqual(await readFile(path.join(fixture.workspace, 'a')), fixture.original);
    console.log(JSON.stringify({ scenario: `actual-${fault}-retirement-keeps-owner`, supervisorPid: child.pid,
      ownerEpoch: held.owner.ownerEpoch, waitingOnRef: held.run.waitingOnRef,
      ...(refusal.fault === 'controller_loss' ? { actualReadFaults: 1, controllerPid: refusal.controllerPid,
        note: 'actual controller SIGKILL; real CAS read then exact EIO; primary and independent native cleanup remain aggregated through close retry and actual flock retention' }
        : { actualCloseFaults: 1,
          note: 'actual Linux worker SIGKILL; real CAS close then injected EIO; public close retry refuses and actual flock stays held' }),
      nativeEffects: 0 }));
    // Only real process death permits takeover and disposal of this retained
    // owner. The fault was removed before both Store.close assertions.
    child.kill('SIGKILL');
    const [code, signal] = await bounded(exited);
    assert.equal(code, null); assert.equal(signal, 'SIGKILL');
    successor = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    assert.equal(successor.getRun(fixture.runId).waitingOnRef, held.run.waitingOnRef);
    await successor.close(); successor = undefined;
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await bounded(exited); await successor?.close(); await fixture.dispose();
  }
}

for (const [scenario, run] of [
  ['before-spawn-retirement-retry', () => preactivationRetirementRetry('before_spawn')],
  ['ready-before-identity-retirement-retry', () => preactivationRetirementRetry('ready_before_identity')],
  ['invalid-preactivation-tree-retirement-retry', () => preactivationRetirementRetry('ready_invalid_tree')],
  ['controller-loss-retirement-failure', () => retirementFailureKeepsOwner('controller_loss')],
  ['edit-ready-checkpoint', editedCheckpoint],
  ['parent-loss-before-release', parentLossBeforeRelease],
  ['no-open-invocation-recovery', () => noOpenInvocationRecovery()],
  ['cancelled-recovery', () => noOpenInvocationRecovery(true)],
  ['supervisor-crash-after-move', supervisorCrashAfterMove],
  ['close-during-factory-open', closeDuringFactoryOpen],
  ['interrupted-controller-close', interruptedControllerClose],
  ['pre-probe-retirement-failure', () => retirementFailureKeepsOwner('pre_probe')],
  ['timeout-retirement-failure', () => retirementFailureKeepsOwner('timeout_closure')]
] as const) {
  console.log(JSON.stringify({ scenario, phase: 'start' }));
  try { await run(); }
  catch (error) {
    console.error(`[cliq-linux-worker-campaign] ${scenario}: ${inspect(error, { depth: 8 }).slice(0, 8192)}`);
    throw error;
  }
  // PASS includes the complete scenario, reopen assertions and cleanup.
  console.log(JSON.stringify({ scenario, phase: 'passed' }));
}
console.log('real Linux worker campaign passed');
