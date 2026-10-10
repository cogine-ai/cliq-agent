import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { fork, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs';
import { access, lstat, mkdtemp, open, readFile, rename, rm, stat, type FileHandle } from 'node:fs/promises';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { digestOmitting, identityHash } from '../../src/kernel/identity.js';
import type { ProcessContainment, ProcessContainmentDeathEvidenceV1, ProcessContainmentNoSpawnEvidenceV1, ProcessContainmentPlanV1, SandboxLaunchSpecV1 } from '../../src/kernel/execution.js';
import type { ReconciliationProbeEvidenceV1, ReconciliationProbeTimeoutClosureV1 } from '../../src/kernel/reconciliation.js';
import type { WorkerDeathWait, WorkerIdentity, WorkspaceEntryManifest, WorkspaceGenerationIdentityV1,
  WorkspaceGenerationQuarantineEvidenceV1, WorkspaceGenerationStateV1, WorkspaceStateManifest, PlatformProcessIdentityV1,
  SupervisorInspectorIdentityV1, Run, WorkerLaunch, BudgetSettlementV1 } from '../../src/kernel/types.js';
import { openLinuxWorkerLauncher } from '../../src/sandbox/linux-worker.js';
import { createLinuxWorkerCampaignFixture } from '../../src/sandbox/testing/worker-campaign-fixture.js';
import type { LocalControlConnection, LocalControlListener } from '../../src/state/control-channel.js';
import { decodeWorkerIdentity } from '../../src/state/decoders.js';
import { decodeWorkerProcessContainment } from '../../src/state/execution-closure.js';
import { loadNativeStateOwner, type HeldStateOwnerLock } from '../../src/state/native-owner.js';
import { journalEntryFromRow, readInvocationJournal, type JournalSqlRow } from '../../src/state/repositories/journal.js';
import { readRequiredWorkerLaunch, readWorkerLaunchesForRun } from '../../src/state/repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef } from '../../src/state/repositories/workspace-generations.js';
import { readRun } from '../../src/state/rows.js';
import { openSqliteDriver, type SqliteConnection } from '../../src/state/sqlite-driver.js';
import { readLatestStateOwner } from '../../src/state/state-owner.js';
import { openStateStore, type StateStore } from '../../src/state/store.js';
import type { CrashChildInput, CrashChildPaused, CrashChildQueuedPostMove, CrashChildRetirementRefused, CrashChildControllerLossRefused } from './linux-worker-crash-child.js';

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

function assertQueuedReadyCut(actual: Awaited<ReturnType<typeof checkpointBytes>>, before: Awaited<ReturnType<typeof checkpointBytes>>) {
  assert.equal(actual.closure.run.status, 'queued'); assert.equal(actual.closure.run.activeWorkerLaunchId, undefined);
  for (const field of ['leaseEpoch', 'frontierRef', 'nextStep'] as const) assert.equal(actual.closure.run[field], before.closure.run[field]);
  assert.deepEqual(actual.closure.latestCheckpoint, before.closure.latestCheckpoint); assert.deepEqual(actual.bytes, before.bytes);
  assert.deepEqual(actual.closure.journal, before.closure.journal);
  assert.deepEqual(actual.closure.run.budgetConsumed, before.closure.run.budgetConsumed);
  assert.deepEqual(actual.closure.run.budgetReserved, before.closure.run.budgetReserved);
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

async function expiredFinalDeathPublication() {
  const fixture = await createLinuxWorkerCampaignFixture({ ...options, label: 'late-final-death' });
  let reopened: StateStore | undefined, sample: FileHandle | undefined, root: FileHandle | undefined, file: FileHandle | undefined;
  let reopeningFailed = false;
  let operationFailure: { error: unknown } | undefined;
  let prototype: { writeFile: FileHandle['writeFile'] } | undefined, originalWrite: FileHandle['writeFile'] | undefined;
  let death: { ref: string; value: ProcessContainmentDeathEvidenceV1 } | undefined;
  let held: { cut: Awaited<ReturnType<typeof checkpointBytes>>; settlement: BudgetSettlementV1; elapsedMs: number } | undefined;
  let delays = 0, settlementWrites = 0;
  const finalObservationTimes: string[] = [];
  try {
    sample = await open(path.join(fixture.workspace, 'a'), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] }; originalWrite = prototype.writeFile;
    await sample.close(); sample = undefined;
    const writeFile = originalWrite;
    const before = await checkpointBytes(fixture.store, fixture.runId);
    const originalHost = await stat(path.join(fixture.workspace, 'a'), { bigint: true });
    const startingChildren = directChildren();
    const execution = await fixture.store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
    // Keep the real native producers and every actual CAS write. Only the
    // final small death publications are delayed; the prepared graph is stable.
    prototype.writeFile = (async function(this: FileHandle, ...args: unknown[]) {
      await Reflect.apply(writeFile, this, args);
      if (!Buffer.isBuffer(args[0])) return;
      const text = args[0].toString('utf8');
      if (text.includes('"kind":"containment_all_descendants_dead"')) {
        const value = JSON.parse(text) as ProcessContainmentDeathEvidenceV1;
        if (value.kind === 'containment_all_descendants_dead' && value.owner.kind === 'worker_activation' && value.owner.runId === fixture.runId) {
          if (!death) { death = { ref: canonicalSha256(value), value }; return; }
          assert.ok(held, 'final death follows the one prepared tool settlement');
          assert.equal(value.containmentRef, death.value.containmentRef);
          assert.ok(value.observedAt > (finalObservationTimes.at(-1) ?? death.value.observedAt));
          assert.ok(Date.now() - Date.parse(value.observedAt) <= 5_000, 'each final death is genuinely fresh before the real delayed write');
          finalObservationTimes.push(value.observedAt); delays++;
          assert.ok(delays <= 3, 'the authority-only retry bound cannot reset or rebuild the prepared completion');
          const started = performance.now();
          await delay(6_000);
          while (performance.now() < started + 6_000) await delay(Math.ceil(started + 6_000 - performance.now()));
          const elapsedMs = performance.now() - started;
          assert.ok(elapsedMs >= 6_000);
          assert.ok(Date.now() - Date.parse(value.observedAt) > 5_000);
          held.elapsedMs += elapsedMs;
          return;
        }
      }
      if (!text.includes('"format":"cliq-budget-settlement-v1"')) return;
      const settlement = JSON.parse(text) as BudgetSettlementV1;
      if (settlement.runId !== fixture.runId) return;
      settlementWrites++;
      assert.equal(settlementWrites, 1, 'the fixture has one actual tool settlement, never a rebuilt retry');
      const cut = await checkpointBytes(fixture.store, fixture.runId);
      const claims = cut.closure.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'dispatch_claimed');
      assert.equal(claims.length, 1);
      const claim = claims[0]!;
      assert.equal(settlement.opId, claim.opId); assert.equal(settlement.attempt, claim.attempt);
      assert.equal(settlement.terminalPhase, 'completed'); assert.equal(settlement.consumed.toolCalls, 1);
      assert.equal(cut.closure.run.status, 'running');
      assert.ok(cut.closure.run.activeWorkerLaunchId);
      const launch = cut.closure.workerLaunches.find(row => row.launchId === cut.closure.run.activeWorkerLaunchId)!;
      assert.equal(launch.phase, 'activated'); assert.equal(launch.generationWriteState, 'checkpointing');
      assert.ok(death, 'the completed native edit must first publish actual worker retirement');
      assert.deepEqual(await fixture.store.artifacts.readCanonical(death.ref), death.value);
      assert.equal(death.value.owner.kind, 'worker_activation');
      if (death.value.owner.kind !== 'worker_activation') throw new Error('retirement selected another owner');
      assert.equal(death.value.owner.workerLaunchId, launch.launchId);
      assert.equal(death.value.containmentRef, launch.processContainmentRef);
      const stagedAge = Date.parse(settlement.settledAt) - Date.parse(death.value.observedAt);
      assert.ok(stagedAge >= 0 && stagedAge <= 5_000, 'the staged settlement really precedes death-evidence expiration');
      const identity = await fixture.store.artifacts.readCanonical<WorkspaceGenerationIdentityV1>(launch.workspaceGenerationRef);
      if (identity.locator.kind !== 'linux_directory') throw new Error('late settlement has no actual Linux generation');
      root = await open(path.join(fixture.stateRoot, identity.locator.canonicalRootRelativePath),
        fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const rootStat = await root.stat({ bigint: true });
      assert.equal(String(rootStat.dev), identity.locator.deviceId); assert.equal(String(rootStat.ino), identity.locator.directoryFileId);
      file = await open(`/proc/self/fd/${root.fd}/a`, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      const actualFile = await file.stat();
      assert.ok(actualFile.isFile()); assert.equal(actualFile.size, Buffer.byteLength('after\n'));
      assert.deepEqual(await witnessBytes(file, actualFile.size), Buffer.from('after\n'), 'the real edit already happened before slow publication');
      assert.deepEqual(cut.bytes, fixture.original);
      held = { cut, settlement, elapsedMs: 0 };
    }) as FileHandle['writeFile'];
    await assert.rejects(bounded(execution.executeCurrentTool({ expectedRunRevision: before.closure.run.revision }), 40_000), error => {
      const pending: unknown[] = [error], seen = new Set<Error>();
      while (pending.length) {
        const next = pending.pop();
        if (!(next instanceof Error) || seen.has(next)) continue;
        seen.add(next);
        if ((next as NodeJS.ErrnoException).code === 'RECOVERY_REQUIRED' && /worker retirement proof is stale/u.test(next.message)) return true;
        pending.push(next.cause);
        if (next instanceof AggregateError) pending.push(...next.errors);
      }
      return false;
    });
    prototype.writeFile = originalWrite;
    assert.equal(delays, 3); assert.equal(settlementWrites, 1); assert.ok(held); assert.ok(death); assert.ok(file);
    const failed = await checkpointBytes(fixture.store, fixture.runId), cut = held.cut.closure;
    assert.equal(failed.closure.run.status, 'waiting'); assert.equal(failed.closure.run.waitingReason, 'reconciliation');
    assert.equal(failed.closure.run.activeWorkerLaunchId, undefined); assert.equal(failed.closure.run.cancelRequested, false);
    assert.equal(failed.closure.run.revision, cut.run.revision + 1, 'only the conservative recovery fence advances the Run');
    assert.deepEqual(failed.closure.journal, cut.journal, 'no tool completion or budget settlement can commit');
    assert.deepEqual(failed.closure.items, cut.items, 'no completed-effect continuation can commit');
    assert.equal(failed.closure.run.frontierRef, cut.run.frontierRef);
    assert.deepEqual(failed.closure.latestCheckpoint, cut.latestCheckpoint, 'no completed-effect ready Checkpoint can commit');
    assert.deepEqual(failed.bytes, fixture.original);
    assert.equal(failed.closure.latestCheckpoint.workspaceStateRef, before.closure.latestCheckpoint.workspaceStateRef);
    assert.deepEqual(failed.closure.run.budgetConsumed, cut.run.budgetConsumed);
    assert.deepEqual(failed.closure.run.budgetReserved, cut.run.budgetReserved);
    assert.equal(failed.closure.run.budgetConsumed.toolCalls, 0); assert.equal(failed.closure.run.budgetReserved.toolCalls, 1);
    const claim = cut.journal.find(entry => entry.opKind === 'tool' && entry.phase === 'dispatch_claimed')!;
    const prepared = cut.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'prepared' &&
      entry.opId === claim.opId && entry.attempt === claim.attempt);
    assert.equal(prepared.length, 1);
    const wait = await fixture.store.artifacts.readCanonical<WorkerDeathWait>(failed.closure.run.waitingOnRef!);
    assert.deepEqual(wait.subject.openInvocationRefs, [canonicalSha256(prepared[0]!)]);
    assert.equal(wait.subject.oldWorkerLaunchId, cut.run.activeWorkerLaunchId);
    const generation = failed.closure.workspaceGenerations.find(row => row.generationRef === wait.subject.workspaceGenerationRef)!;
    assert.equal(generation.phase, 'fenced_reconciling');
    if (generation.phase !== 'fenced_reconciling') throw new Error('late settlement did not fence its exact private generation');
    assert.equal(generation.fencedFromPhase, 'checkpointing');
    assert.equal(failed.closure.workerLaunches[0]!.phase, 'reconciling');
    assert.equal(failed.closure.workerLaunches[0]!.retiredAt, undefined);
    assert.equal((await file.stat()).size, Buffer.byteLength('after\n'));
    assert.deepEqual(await witnessBytes(file, Buffer.byteLength('after\n')), Buffer.from('after\n'));
    assert.deepEqual(await readFile(path.join(fixture.workspace, 'a')), fixture.original);
    const host = await stat(path.join(fixture.workspace, 'a'), { bigint: true });
    assert.equal(host.dev, originalHost.dev); assert.equal(host.ino, originalHost.ino);
    assert.equal(death.value.backend.kind, 'linux');
    if (death.value.backend.kind !== 'linux') throw new Error('late settlement did not retire real Linux containment');
    const backend = nativeBackend(death.value.backend);
    assert.match(await readFile(path.join(backend.cgroupPath, 'cgroup.events'), 'utf8'), /(?:^|\n)populated 0\n/u);
    const controller = /^linux-subreaper:([1-9][0-9]*):linux-proc-start-ticks:[0-9]+$/u.exec(backend.subreaperStartToken);
    const members = /^linux-namespace-init:([1-9][0-9]*):[0-9]+:monitor:([1-9][0-9]*):[0-9]+$/u.exec(backend.namespaceInitStartToken);
    assert.ok(controller); assert.ok(members);
    const worker = decodeWorkerIdentity(await fixture.store.artifacts.readCanonical(wait.subject.oldWorkerIdentity));
    for (const pid of [worker.pid, Number(controller[1]), Number(members[1]), Number(members[2])]) {
      await assert.rejects(access(`/proc/${pid}`), { code: 'ENOENT' }, 'the actual worker hierarchy and controller are joined');
    }
    assert.deepEqual(directChildren(), startingChildren);
    await file.close(); file = undefined; await root!.close(); root = undefined;
    await fixture.store.close();
    try { reopened = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority); }
    catch (error) { reopeningFailed = true; throw error; }
    assert.deepEqual(await reopened.readRecoveryClosure(fixture.runId), failed.closure,
      'public reopen acquires the released OS owner lock and preserves the conservative unresolved attempt');
    await reopened.close(); reopened = undefined;
    console.log(JSON.stringify({ scenario: 'actual-expired-final-death-publication', runId: fixture.runId,
      settledAt: held.settlement.settledAt, deathObservedAt: death.value.observedAt, publicationDelayMs: held.elapsedMs,
      finalObservationTimes, authorityAttempts: delays, preparedSettlements: settlementWrites,
      permanentToolClaims: 1, actualPrivateEditObserved: true, completedToolEntries: 0, remainingBudgetReservation: 1,
      note: 'three actual six-second final-evidence publications exhaust the authority-only bound; no effect or immutable graph replay; joined cleanup' }));
  } catch (error) { operationFailure = { error }; throw error; }
  finally {
    if (prototype && originalWrite) prototype.writeFile = originalWrite;
    const failures: unknown[] = [];
    // Store.close joins an in-flight operation even if the outer bound failed;
    // only then can the separately owned observation descriptors be released.
    for (const resource of [reopened, fixture.store]) {
      try { await resource?.close(); } catch (error) { failures.push(error); }
    }
    for (const resource of [sample, file, root]) {
      try { await resource?.close(); } catch (error) { failures.push(error); }
    }
    if (failures.length === 0 && !reopeningFailed) {
      try { await fixture.dispose(); } catch (error) { failures.push(error); }
    } else console.error(`preserving uncertain late-settlement fixture: ${fixture.stateRoot}`);
    if (failures.length) throw new AggregateError([...(operationFailure ? [operationFailure.error] : []), ...failures], 'late settlement campaign and cleanup failures');
  }
}

async function slowToolSealReobservesPausedController() {
  const fixture = await createLinuxWorkerCampaignFixture({ ...options, label: 'slow-seal-reobserve' });
  let reopened: StateStore | undefined, sample: FileHandle | undefined, cgroup: FileHandle | undefined;
  let prototype: { writeFile: FileHandle['writeFile'] } | undefined, originalWrite: FileHandle['writeFile'] | undefined;
  let resumeTimer: ReturnType<typeof setTimeout> | undefined, resumeFailure: unknown;
  let operationFailure: { error: unknown } | undefined, reopeningFailed = false;
  let controller: { pid: number; token: string; stopped: boolean; pausedAt: number; resumedAt?: number } | undefined;
  let scope: { device: bigint; inode: bigint; pids: number[] } | undefined;
  const deaths: ProcessContainmentDeathEvidenceV1[] = [];
  let slowWrites = 0, publicationDelayMs = 0;
  function resumeController() {
    if (!controller?.stopped) return;
    assert.equal(processToken(controller.pid), controller.token, 'SIGCONT targets only the original controller identity');
    controller.resumedAt = Date.now();
    process.kill(controller.pid, 'SIGCONT'); controller.stopped = false;
  }
  try {
    const before = await checkpointBytes(fixture.store, fixture.runId);
    const hostBefore = await stat(path.join(fixture.workspace, 'a'), { bigint: true });
    const startingChildren = directChildren();
    const execution = await fixture.store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
    sample = await open(path.join(fixture.workspace, 'a'), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] }; originalWrite = prototype.writeFile;
    await sample.close(); sample = undefined;
    const writeFile = originalWrite;
    // Preserve actual native execution and publication. Only the OS process
    // pause and one real FileHandle publication delay are fault injections.
    prototype.writeFile = (async function(this: FileHandle, ...args: Parameters<FileHandle['writeFile']>) {
      await Reflect.apply(writeFile, this, args);
      if (typeof args[0] !== 'string' && !Buffer.isBuffer(args[0])) return;
      let candidate: Record<string, unknown>;
      try { candidate = JSON.parse(args[0].toString()) as Record<string, unknown>; }
      catch { return; }
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return;
      if (candidate.kind === 'containment_all_descendants_dead') {
        const death = candidate as unknown as ProcessContainmentDeathEvidenceV1;
        if (death.owner.kind !== 'worker_activation' || death.owner.runId !== fixture.runId) return;
        assert.equal(death.evidenceDigest, digestOmitting(death, 'evidenceDigest'));
        assert.equal(death.backend.kind, 'linux');
        if (death.backend.kind !== 'linux') throw new Error('slow seal did not observe its actual Linux containment');
        const backend = death.backend;
        if (deaths.length !== 0) {
          assert.ok(controller && !controller.stopped && controller.resumedAt !== undefined,
            'a stopped real controller cannot produce a fresh second death observation');
          assert.ok(Date.parse(death.observedAt) >= controller.resumedAt,
            'fresh death must be inspected after the exact controller is resumed, not reuse the first native observation');
          assert.equal(death.containmentRef, deaths[0]!.containmentRef);
          deaths.push(death); return;
        }
        deaths.push(death);
        const cut = await fixture.store.readRecoveryClosure(fixture.runId);
        const workerOwner = death.owner;
        const launch = cut.workerLaunches.find(row => row.launchId === workerOwner.workerLaunchId)!;
        assert.equal(launch.phase, 'activated'); assert.equal(cut.run.activeWorkerLaunchId, launch.launchId);
        assert.equal(death.containmentRef, launch.processContainmentRef);
        const worker = decodeWorkerIdentity(await fixture.store.artifacts.readCanonical(launch.workerIdentityDigest!));
        const subreaper = /^linux-subreaper:([1-9][0-9]*):(linux-proc-start-ticks:[0-9]+)$/u.exec(backend.subreaperStartToken);
        const members = /^linux-namespace-init:([1-9][0-9]*):[0-9]+:monitor:([1-9][0-9]*):[0-9]+$/u.exec(backend.namespaceInitStartToken);
        assert.ok(subreaper); assert.ok(members);
        const pid = Number(subreaper[1]), token = subreaper[2]!;
        assert.equal(processToken(pid), token); assert.ok(directChildren().has(pid));
        const controllerImage = fixture.signed.bundle.entries.find(entry => entry.entryId === 'linux_worker_controller')!;
        const image = await open(`/proc/${pid}/exe`, fs.constants.O_RDONLY);
        try {
          const physical = await image.stat({ bigint: true });
          assert.equal(physical.size, BigInt(controllerImage.byteCount));
          assert.equal(createHash('sha256').update(await image.readFile()).digest('hex'), controllerImage.digest);
          const after = await image.stat({ bigint: true });
          for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(after[field], physical[field]);
        } finally { await image.close(); }
        cgroup = await open(backend.cgroupPath, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
        const physical = await cgroup.stat({ bigint: true }), named = await lstat(backend.cgroupPath, { bigint: true });
        assert.ok(physical.isDirectory() && named.isDirectory() && !named.isSymbolicLink());
        assert.equal(physical.dev, named.dev); assert.equal(physical.ino, named.ino); assert.equal(String(physical.ino), backend.cgroupId);
        scope = { device: physical.dev, inode: physical.ino, pids: [worker.pid, Number(members[1]), Number(members[2])] };
        assert.match(await readFile(`/proc/self/fd/${cgroup.fd}/cgroup.events`, 'utf8'), /(?:^|\n)populated 0\n/u);
        for (const member of scope.pids) await assert.rejects(access(`/proc/${member}`), { code: 'ENOENT' });
        assert.equal(processToken(pid), token);
        process.kill(pid, 'SIGSTOP');
        controller = { pid, token, stopped: true, pausedAt: Date.now() };
        const deadline = performance.now() + 1000;
        while (!/^State:\s+T\b/mu.test(await readFile(`/proc/${pid}/status`, 'utf8'))) {
          assert.equal(processToken(pid), token);
          assert.ok(performance.now() < deadline, 'the first native death must actually pause its original controller');
          await delay(1);
        }
        return;
      }
      if (candidate.format !== 'cliq-budget-settlement-v1' || candidate.runId !== fixture.runId ||
          candidate.terminalPhase !== 'completed' || slowWrites !== 0) return;
      assert.ok(controller?.stopped && deaths.length === 1, 'slow completion retains the original stopped controller');
      const settlement = candidate as unknown as BudgetSettlementV1;
      const cut = await checkpointBytes(fixture.store, fixture.runId);
      const claims = cut.closure.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'dispatch_claimed');
      assert.equal(claims.length, 1); assert.equal(settlement.opId, claims[0]!.opId); assert.equal(settlement.attempt, claims[0]!.attempt);
      assert.deepEqual(cut.bytes, fixture.original); assert.equal(cut.closure.run.budgetReserved.toolCalls, 1);
      slowWrites++;
      const started = performance.now();
      resumeTimer = setTimeout(() => { try { resumeController(); } catch (error) { resumeFailure = error; } }, 6500);
      await delay(6000);
      while (performance.now() < started + 6000) await delay(Math.ceil(started + 6000 - performance.now()));
      publicationDelayMs = performance.now() - started;
      assert.ok(publicationDelayMs >= 6000); assert.ok(Date.now() - Date.parse(deaths[0]!.observedAt) > 5000);
      assert.equal(deaths.length, 1, 'no fresh death can be published while its actual inspector is stopped');
    }) as FileHandle['writeFile'];
    const result = await bounded(execution.executeCurrentTool({ expectedRunRevision: before.closure.run.revision }), 40_000);
    prototype.writeFile = originalWrite;
    if (resumeFailure !== undefined) throw resumeFailure;
    assert.equal(slowWrites, 1); assert.ok(controller?.resumedAt !== undefined); assert.ok(scope && cgroup);
    assert.ok(deaths.length >= 2, 'slow I/O success requires a genuinely refreshed native death, not a longer freshness window');
    assert.equal(result.status, 'queued'); assert.equal(result.activeWorkerLaunchId, undefined);
    const after = await checkpointBytes(fixture.store, fixture.runId);
    assert.deepEqual(after.bytes, Buffer.from('after\n'));
    assert.equal(after.closure.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'dispatch_claimed').length, 1);
    assert.equal(after.closure.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'completed').length, 1);
    assert.equal(after.closure.run.budgetConsumed.toolCalls, 1); assert.equal(after.closure.run.budgetReserved.toolCalls, 0);
    const refreshed = deaths.at(-1)!;
    if (refreshed.owner.kind !== 'worker_activation') throw new Error('refreshed death lost its original worker owner');
    const refreshedOwner = refreshed.owner;
    const metadata = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    let retired: WorkerLaunch;
    try { retired = metadata.readSnapshot(connection => readRequiredWorkerLaunch(connection, refreshedOwner.workerLaunchId)); }
    finally { metadata.close(); }
    assert.equal(retired.phase, 'retired'); assert.equal(retired.retirementEvidenceRef, canonicalSha256(refreshed));
    const group = await cgroup.stat({ bigint: true }); assert.equal(group.dev, scope.device); assert.equal(group.ino, scope.inode);
    assert.match(await readFile(`/proc/self/fd/${cgroup.fd}/cgroup.events`, 'utf8'), /(?:^|\n)populated 0\n/u);
    for (const pid of [...scope.pids, controller.pid]) await assert.rejects(access(`/proc/${pid}`), { code: 'ENOENT' });
    assert.deepEqual(directChildren(), startingChildren);
    assert.deepEqual(await readFile(path.join(fixture.workspace, 'a')), fixture.original);
    const hostAfter = await stat(path.join(fixture.workspace, 'a'), { bigint: true });
    assert.equal(hostAfter.dev, hostBefore.dev); assert.equal(hostAfter.ino, hostBefore.ino);
    await cgroup.close(); cgroup = undefined;
    await fixture.store.close();
    try { reopened = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority); }
    catch (error) { reopeningFailed = true; throw error; }
    assert.deepEqual((await checkpointBytes(reopened, fixture.runId)).bytes, Buffer.from('after\n'));
    assert.deepEqual(await reopened.readRecoveryClosure(fixture.runId), after.closure);
    await reopened.close(); reopened = undefined;
    console.log(JSON.stringify({ scenario: 'actual-slow-tool-seal-reobserves-paused-controller', runId: fixture.runId,
      pausedAt: controller.pausedAt, resumedAt: controller.resumedAt, initialDeathObservedAt: deaths[0]!.observedAt,
      finalDeathObservedAt: refreshed.observedAt, publicationDelayMs, permanentToolClaims: 1, completedToolEntries: 1,
      consumedToolCalls: 1, remainingBudgetReservation: 0, nativeEffects: 1 }));
  } catch (error) { operationFailure = { error }; throw error; }
  finally {
    if (prototype && originalWrite) prototype.writeFile = originalWrite;
    clearTimeout(resumeTimer);
    const failures: unknown[] = [];
    try { resumeController(); } catch (error) { failures.push(error); }
    if (resumeFailure !== undefined) failures.push(resumeFailure);
    for (const resource of [reopened, fixture.store]) {
      try { await resource?.close(); } catch (error) { failures.push(error); }
    }
    for (const resource of [sample, cgroup]) {
      try { await resource?.close(); } catch (error) { failures.push(error); }
    }
    if (failures.length === 0 && !reopeningFailed) {
      try { await fixture.dispose(); } catch (error) { failures.push(error); }
    } else console.error(`preserving uncertain slow-seal fixture: ${fixture.stateRoot}`);
    if (failures.length) throw new AggregateError([...(operationFailure ? [operationFailure.error] : []), ...failures], 'slow seal campaign and cleanup failures');
  }
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
    assertQueuedReadyCut(failed, before);
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
    assertQueuedReadyCut(reopened, before);
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

// Independent test-side encoding of the explicit LE witness body, not the C
// packet ABI or a producer/inspector call. Exact equality includes zero padding.
function expectedNativeBirthBody(numbers: readonly bigint[], texts: readonly (readonly [string, number])[]) {
  assert.equal(numbers.length, 12);
  const body = Buffer.alloc(2048); body.write('CLIQWRB1'); let cursor = 16;
  for (const value of numbers) { body.writeBigUInt64LE(value, cursor); cursor += 8; }
  for (const [value, width] of texts) {
    const bytes = Buffer.from(value); assert.ok(bytes.length < width); assert.equal(bytes.includes(0), false);
    bytes.copy(body, cursor); cursor += width;
  }
  assert.ok(cursor <= body.length); return body;
}

async function witnessBytes(handle: FileHandle, length: number) {
  const bytes = Buffer.alloc(length);
  for (let offset = 0; offset < bytes.length;) {
    const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
    assert.ok(bytesRead > 0); offset += bytesRead;
  }
  return bytes;
}

function verifyNativeBirthFrames(bytes: Buffer, lengths: readonly number[]) {
  let offset = 0;
  for (const [index, length] of lengths.entries()) {
    const end = offset + length + 64, footer = bytes.subarray(offset + length, end);
    assert.equal(footer.length, 64);
    assert.deepEqual(footer.subarray(0, 8), Buffer.from('CLIQWRF1')); assert.equal(footer.readBigUInt64LE(8), BigInt(index + 1));
    assert.equal(footer.readBigUInt64LE(16), BigInt(end)); assert.equal(footer.readBigUInt64LE(24), BigInt.asUintN(64, ~BigInt(end)));
    assert.deepEqual(footer.subarray(32), createHash('sha256').update(bytes.subarray(offset, offset + length)).digest());
    offset = end;
  }
  assert.equal(offset, bytes.length);
}

type LinuxForkTracer = { arm(controllerPid: number): void; pollFork(): number | null; release(): boolean;
  finishControllerLoss(): { controllerSignal: 9; monitorExitCode: 70 } | null };

type CampaignEventRow = { run_id: string; event_seq: bigint; payload_json: string; occurred_at: string };
type CampaignLaunchRow = { launch_id: string; run_id: string; phase: string; row_json: string; retired_at: string | null };
type CampaignGenerationRow = { generation_id: string; run_id: string; phase: string; row_version: bigint; row_json: string };
type CampaignArtifactRow = { ref: string; media_type: string; schema_kind: string; byte_length: bigint; created_at: string };
type CampaignJournalRow = Omit<JournalSqlRow, 'seq' | 'attempt'> & { seq: bigint; attempt: bigint };

function preactivationRefusalRows(connection: SqliteConnection, runId: string) {
  return {
    events: connection.prepare('SELECT run_id, event_seq, payload_json, occurred_at FROM run_events WHERE run_id=? ORDER BY event_seq').all<CampaignEventRow>(runId),
    launches: connection.prepare('SELECT launch_id, run_id, phase, row_json, retired_at FROM worker_launches WHERE run_id=? ORDER BY launch_id').all<CampaignLaunchRow>(runId),
    generations: connection.prepare('SELECT generation_id, run_id, phase, row_version, row_json FROM workspace_generations WHERE run_id=? ORDER BY generation_id').all<CampaignGenerationRow>(runId),
    journal: connection.prepare('SELECT run_id, seq, op_id, op_kind, attempt, phase, entry_json FROM run_journal WHERE run_id=? ORDER BY seq').all<CampaignJournalRow>(runId),
    // The fixture's offline prefix may already contain these kinds. Compare
    // exact registered rows, never mislabel its metadata as native evidence.
    proofs: connection.prepare(`SELECT ref, media_type, schema_kind, byte_length, created_at FROM artifacts WHERE schema_kind IN (
      'cliq-worker-identity-v1', 'cliq-process-containment-v1', 'cliq-process-containment-death-evidence-v1',
      'cliq-process-containment-no-spawn-evidence-v1', 'cliq-workspace-generation-quarantine-evidence-v1') ORDER BY ref`).all<CampaignArtifactRow>()
  };
}

async function releaseForkTracer(tracer: LinuxForkTracer) {
  const deadline = performance.now() + 30_000;
  for (;;) {
    const released = tracer.release(); assert.equal(typeof released, 'boolean');
    if (released) return;
    assert.ok(performance.now() < deadline, 'actual fork tracer attachment release timed out');
    await delay(1);
  }
}

async function supervisorCrashPreactivation(boundary: NonNullable<CrashChildInput['preactivationCrash']>, witnessFault?: 'corrupt_ready_footer' | 'missing' | 'replaced_inode') {
  if (witnessFault !== undefined) assert.equal(boundary, 'ready_before_identity');
  const committed = boundary === 'preactivated_before_activation';
  const postMove = boundary === 'queued_post_move_before_retirement';
  const controllerLoss = boundary === 'monitor_fork_controller_loss';
  const corruptReadyFooter = witnessFault === 'corrupt_ready_footer';
  const negative = controllerLoss || witnessFault !== undefined;
  const monitorFork = boundary === 'monitor_fork_before_ready' || controllerLoss;
  const hasReadyAtPause = boundary === 'ready_before_identity' || committed;
  const expectsCreatedRetirement = !negative && (hasReadyAtPause || boundary === 'monitor_fork_before_ready');
  const scenarioBoundary = witnessFault ?? boundary;
  const fixture = await createLinuxWorkerCampaignFixture({ ...options, label: `${scenarioBoundary.replaceAll('_', '-')}-crash` });
  let child: ReturnType<typeof fork> | undefined, exited: ReturnType<typeof once> | undefined, successor: StateStore | undefined;
  let history: ReturnType<typeof openSqliteDriver> | undefined;
  let refusedOwner: ReturnType<typeof fork> | undefined, refusedOwnerExit: ReturnType<typeof once> | undefined;
  let retainedWitness: FileHandle | undefined, tracer: LinuxForkTracer | undefined, tracerDirectory: string | undefined;
  let removeHintListener: (() => void) | undefined;
  let diagnostic = '', resourcesRetired = false, supervisorJoined = false, negativeQualified = false, operationFailure: { error: unknown } | undefined;
  try {
    const before = await checkpointBytes(fixture.store, fixture.runId);
    await fixture.store.close();
    child = fork(new URL('./linux-worker-crash-child.ts', import.meta.url), [], {
      execArgv: ['--import', 'tsx'], serialization: 'advanced', stdio: ['ignore', 'pipe', 'pipe', 'ipc']
    });
    const supervisor = child;
    const exit = once(supervisor, 'exit'); exited = exit; void exit.catch(() => {});
    for (const output of [supervisor.stdout!, supervisor.stderr!]) output.on('data', (chunk: Buffer) => {
      diagnostic = (diagnostic + chunk.toString()).slice(-8192);
    });
    const reply = async () => {
      const abort = new AbortController(), timer = setTimeout(() => abort.abort(), 40_000);
      try { return await Promise.race([
        once(supervisor, 'message', { signal: abort.signal }).then(([message]) => message as { state?: string; runId?: string; message?: string }),
        exit.then(([code, signal]) => { throw new Error(`${boundary} crash Supervisor exited before reply: ${code}/${signal}: ${diagnostic}`); })
      ]); } finally { clearTimeout(timer); abort.abort(); }
    };
    assert.equal((await reply()).state, 'ready');
    // This listener is installed before dispatch, not after awaiting the arming
    // reply. A quick producer must not lose its flushed diagnostic locator hint.
    let hintCount = 0;
    const hintPromise = postMove ? new Promise<unknown>(resolve => {
      const listener = (value: unknown) => {
        if (value && typeof value === 'object' && (value as { state?: unknown }).state === 'queued_post_move_pre_retirement') {
          hintCount++; resolve(value);
        }
      };
      supervisor.on('message', listener); removeHintListener = () => supervisor.off('message', listener);
    }) : undefined;
    const armed = reply(); void armed.catch(() => {});
    const input: CrashChildInput = { stateRoot: fixture.stateRoot, runId: fixture.runId, runtimeAuthority: fixture.runtimeAuthority,
      preactivationCrash: boundary,
      materialData: Object.fromEntries(Object.entries(fixture.authority.material).filter(([, value]) => typeof value !== 'function')) as CrashChildInput['materialData'] };
    await new Promise<void>((resolve, reject) => supervisor.send(input, error => error ? reject(error) : resolve()));
    const message = await armed;
    assert.equal(message.state, 'preactivation_crash_armed', message.message ?? diagnostic); assert.equal(message.runId, fixture.runId);
    const hint = hintPromise ? await bounded(Promise.race([hintPromise,
      exit.then(([code, signal]) => { throw new Error(`queued post-move Supervisor exited before its hint: ${code}/${signal}: ${diagnostic}`); })
    ]), 40_000) as CrashChildQueuedPostMove : undefined;
    // Arming is flushed before execution. Stopping is an actual OS barrier,
    // not a child's IPC assertion about which persisted cut was reached.
    await bounded((async () => {
      for (;;) {
        const line = await readFile(`/proc/${supervisor.pid}/stat`, 'utf8');
        const state = line.slice(line.lastIndexOf(')') + 2).trim().split(/\s+/u)[0];
        if (state === 'T') return;
        assert.notEqual(state, 'Z', `${boundary} crash Supervisor became a zombie: ${diagnostic}`);
        await delay(10);
      }
    })(), 40_000);
    if (postMove) assert.equal(hintCount, 1);
    const metadata = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    const held = (() => { try { return metadata.readSnapshot(connection => {
      const run = readRun(connection, fixture.runId), owner = readLatestStateOwner(connection)!;
      const launches = readWorkerLaunchesForRun(connection, fixture.runId).filter(launch => launch.retiredAt === undefined);
      assert.equal(launches.length, 1); const launch = launches[0]!;
      const generation = readRequiredWorkspaceGenerationByRef(connection, launch.workspaceGenerationRef);
      assert.deepEqual(run, before.closure.run); assert.deepEqual(readInvocationJournal(connection, fixture.runId), before.closure.journal);
      assert.equal(owner.state, 'active'); assert.equal(launch.supervisorInstanceId, owner.supervisorInstanceId);
      assert.equal(launch.phase, committed ? 'preactivated' : 'reserved');
      if (committed) assert.ok(launch.workerIdentityDigest && launch.processContainmentRef);
      else { assert.equal(launch.workerIdentityDigest, undefined); assert.equal(launch.processContainmentRef, undefined); }
      assert.equal(launch.leaseVersion, 0); assert.equal(launch.leaseEpoch, undefined); assert.equal(launch.leaseExpiresAt, undefined);
      assert.equal(launch.activatedAt, undefined); assert.equal(launch.quiesceId, undefined);
      assert.equal(launch.generationWriteState, 'preactivated_readonly'); assert.equal(generation.phase, 'preactivated_readonly');
      assert.equal(generation.sourceCheckpointId, before.closure.latestCheckpoint.id);
      assert.equal(generation.sourceWorkspaceStateRef, before.closure.latestCheckpoint.workspaceStateRef);
      const eventSeq = connection.prepare('SELECT max(event_seq) AS seq FROM run_events WHERE run_id=?').get<{ seq: bigint }>(fixture.runId)!.seq;
      return { run, owner, launch, generation, eventSeq, refusalRows: negative ? preactivationRefusalRows(connection, fixture.runId) : undefined };
    }); } finally { metadata.close(); } })();
    const supervisorIdentity = frozenArtifact<PlatformProcessIdentityV1>(fixture.stateRoot, held.owner.processIdentityRef);
    assert.equal(supervisorIdentity.platform, 'linux'); assert.equal(supervisorIdentity.pid, supervisor.pid);
    assert.equal(supervisorIdentity.processStartToken, processToken(supervisor.pid!));
    const plan = frozenArtifact<ProcessContainmentPlanV1>(fixture.stateRoot, held.launch.containmentPlanRef);
    if (plan.owner.kind !== 'worker_activation' || plan.backend.kind !== 'linux' || !plan.backend.nativeReservation) {
      throw new Error('independent preactivation crash observation lacks its bound native witness');
    }
    assert.equal(plan.owner.runId, fixture.runId); assert.equal(plan.owner.workerLaunchId, held.launch.launchId);
    assert.equal(plan.launchNonceDigest, held.launch.spawnNonceDigest);
    const spec = frozenArtifact<SandboxLaunchSpecV1>(fixture.stateRoot, held.launch.sandboxLaunchSpecRef);
    const recordedWorker = committed
      ? decodeWorkerIdentity(frozenArtifact(fixture.stateRoot, held.launch.workerIdentityDigest!)) : undefined;
    const recordedContainment = committed
      ? decodeWorkerProcessContainment(frozenArtifact(fixture.stateRoot, held.launch.processContainmentRef!)) : undefined;
    const controller = /^linux-subreaper:([1-9][0-9]*):(linux-proc-start-ticks:[0-9]+)$/u.exec(plan.backend.subreaperStartToken);
    assert.ok(controller); const controllerPid = Number(controller[1]), controllerToken = controller[2]!;
    if (postMove) await assert.rejects(access(`/proc/${controllerPid}`), { code: 'ENOENT' });
    else {
      assert.equal(processToken(controllerPid), controllerToken);
      assert.match(await readFile(`/proc/${controllerPid}/status`, 'utf8'), new RegExp(`^PPid:\\s+${supervisor.pid}$`, 'mu'));
    }
    const identity = frozenArtifact<WorkspaceGenerationIdentityV1>(fixture.stateRoot, held.generation.generationRef);
    if (identity.locator.kind !== 'linux_directory') throw new Error('preactivation crash lacks an actual private Linux generation');
    const archiveRelativePath = `quarantine/workspace-generations/${identityHash(identity.generationId, String(held.generation.rowVersion))}`;
    const noSpawnBackend = {
      kind: 'linux', cgroupPath: plan.backend.cgroupPath, cgroupObservation: { kind: 'absent' },
      pidNamespaceObservation: { kind: 'never_created', pidNamespaceReservationId: plan.backend.pidNamespaceReservationId },
      matchingLaunchNonceProcessCount: 0, subreaperStartToken: plan.backend.subreaperStartToken
    } satisfies Extract<ProcessContainmentNoSpawnEvidenceV1['backend'], { kind: 'linux' }>;
    let pendingReceipt: Extract<WorkspaceGenerationQuarantineEvidenceV1, { reason: 'launch_aborted' }> | undefined;
    let pendingProof: ProcessContainmentNoSpawnEvidenceV1 | undefined;
    let pendingReceiptRef: string | undefined;
    let physicalScope: { cgroupId: string; pidNamespaceId: string; workerPid: number; workerToken: string;
      initPid: number; initToken: string; monitorPid: number; monitorToken: string;
      namespaceInitStartToken: string; birthObservation: 'independent-live-READY' | 'durable-native-birth-after-controller-release';
      members: { pid: number; token: string }[] } | undefined;
    let bindingPrefix: Buffer | undefined;
    let readyObservation: { bytes: Buffer; witness: fs.BigIntStats; group: fs.BigIntStats } | undefined;
    let forkObservation: { prefix: Buffer; witness: fs.BigIntStats; group: fs.BigIntStats; monitorPid: number; monitorToken: string } | undefined;
    const bindingTexts: (readonly [string, number])[] = [[held.launch.containmentPlanRef, 65],
      [held.launch.sandboxLaunchSpecRef, 65], [spec.launchSpecDigest, 65], [held.launch.workspaceGenerationRef, 65],
      [held.launch.spawnNonceDigest, 65], [held.launch.activationNonceDigest, 65], [path.posix.basename(plan.backend.cgroupPath), 96],
      [plan.backend.pidNamespaceReservationId, 192], ['', 192], ['', 192], ['', 192], ['', 192], [controllerToken, 192]];
    const witnessPath = path.join(fixture.stateRoot, 'runtime/worker-reservations',
      identityHash('cliq-worker-reservation-v1', held.launch.launchId, held.launch.spawnNonceDigest));
    const witness = await open(witnessPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    retainedWitness = witness;
    try {
      const physical = await witness.stat({ bigint: true });
      assert.ok(physical.isFile()); assert.equal(physical.nlink, 1n); assert.equal(physical.mode & 0o7777n, 0o600n);
      assert.equal(String(physical.dev), plan.backend.nativeReservation.deviceId); assert.equal(String(physical.ino), plan.backend.nativeReservation.fileId);
      assert.equal(Number(physical.uid), plan.backend.nativeReservation.ownerUid); assert.equal(physical.size, hasReadyAtPause ? 4768n : 2112n);
      // Every footer hashes its own actual body, not an accumulated prefix.
      // Verify all five durable birth facts before using any recorded PID.
      const bytes = await witnessBytes(witness, hasReadyAtPause ? 4768 : 2112);
      verifyNativeBirthFrames(bytes, hasReadyAtPause ? [2048, 32, 64, 256, 2048] : [2048]);
      if (monitorFork) bindingPrefix = bytes;
      const bindingNumbers = [physical.dev, physical.ino, physical.uid, BigInt(identity.locator.deviceId),
        BigInt(identity.locator.directoryFileId), 0n, 0n, 0n, 0n, 0n, 0n, BigInt(controllerPid)];
      assert.deepEqual(bytes.subarray(0, 2048), expectedNativeBirthBody(bindingNumbers, bindingTexts));
      if (hasReadyAtPause) {
        const intent = Buffer.alloc(32); intent.write('CREATE1'); assert.deepEqual(bytes.subarray(2112, 2144), intent);
        const group = await lstat(plan.backend.cgroupPath, { bigint: true }); assert.ok(group.isDirectory() && !group.isSymbolicLink());
        const cgroup = Buffer.alloc(64);
        for (const [index, value] of [group.dev, group.ino, group.uid, group.mode].entries()) cgroup.writeBigUInt64LE(value, index * 8);
        assert.deepEqual(bytes.subarray(2208, 2272), cgroup);
        assert.match(await readFile(path.join(plan.backend.cgroupPath, 'cgroup.events'), 'utf8'), /(?:^|\n)populated 1\n/u);
        const running = imageProcess(path.join(plan.backend.cgroupPath, 'worker'), 'cliq-linux-worker'); assert.ok(running);
        const workerImage = fixture.signed.bundle.entries.find(entry => entry.entryId === 'linux_worker')!;
        assert.ok(workerImage.executable && workerImage.role === 'worker');
        const executable = await open(`/proc/${running.pid}/exe`, fs.constants.O_RDONLY);
        try {
          const beforeImage = await executable.stat({ bigint: true });
          assert.ok(beforeImage.isFile()); assert.equal(beforeImage.dev, running.image.dev); assert.equal(beforeImage.ino, running.image.ino);
          assert.equal(beforeImage.size, BigInt(workerImage.byteCount));
          assert.equal(createHash('sha256').update(await executable.readFile()).digest('hex'), workerImage.digest);
          const afterImage = await executable.stat({ bigint: true });
          for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(afterImage[field], beforeImage[field]);
        } finally { await executable.close(); }
        const namespace = await stat(`/proc/${running.pid}/ns/pid`, { bigint: true });
        const members = pids(path.join(plan.backend.cgroupPath, 'worker')).map(pid => ({ pid, token: processToken(pid) }));
        const init = members.filter(member => {
          const ns = fs.statSync(`/proc/${member.pid}/ns/pid`, { bigint: true });
          return ns.dev === namespace.dev && ns.ino === namespace.ino && namespacePid(member.pid) === 1;
        });
        assert.equal(init.length, 1); assert.equal(processToken(running.pid), running.token);
        assert.ok(members.some(member => member.pid === running.pid && member.token === running.token));
        const monitorPid = Number(bytes.readBigUInt64LE(2336)); assert.ok(Number.isSafeInteger(monitorPid) && monitorPid > 0);
        const monitorToken = processToken(monitorPid); assert.ok(members.some(member => member.pid === monitorPid && member.token === monitorToken));
        assert.match(await readFile(`/proc/${monitorPid}/status`, 'utf8'), new RegExp(`^PPid:\\s+${controllerPid}$`, 'mu'));
        const monitor = Buffer.alloc(256); monitor.writeBigUInt64LE(BigInt(monitorPid)); monitor.write(monitorToken, 8);
        assert.deepEqual(bytes.subarray(2336, 2592), monitor);
        const namespaceInitStartToken = `linux-namespace-init:${init[0]!.pid}:${init[0]!.token.slice('linux-proc-start-ticks:'.length)}:monitor:${monitorPid}:${monitorToken.slice('linux-proc-start-ticks:'.length)}`;
        const readyNumbers = [...bindingNumbers]; readyNumbers.splice(5, 6, group.dev, group.ino, namespace.ino,
          BigInt(running.pid), BigInt(init[0]!.pid), BigInt(monitorPid));
        const readyTexts = [...bindingTexts]; readyTexts.splice(8, 4, [running.token, 192], [namespaceInitStartToken, 192],
          [init[0]!.token, 192], [monitorToken, 192]);
        assert.deepEqual(bytes.subarray(2656, 4704), expectedNativeBirthBody(readyNumbers, readyTexts));
        physicalScope = { cgroupId: String(group.ino), pidNamespaceId: String(namespace.ino), workerPid: running.pid,
          workerToken: running.token, initPid: init[0]!.pid, initToken: init[0]!.token, monitorPid, monitorToken,
          namespaceInitStartToken, birthObservation: 'independent-live-READY', members };
        if (witnessFault !== undefined) readyObservation = { bytes, witness: physical, group };
      } else await assert.rejects(lstat(plan.backend.cgroupPath), { code: 'ENOENT' });
      const after = await witness.stat({ bigint: true });
      for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(after[field], physical[field]);
    } finally {
      if (!monitorFork && witnessFault === undefined) { await witness.close(); retainedWitness = undefined; }
    }
    if (postMove) {
      assert.ok(hint); assert.equal(hint.runId, fixture.runId); assert.equal(hint.generationRef, held.generation.generationRef);
      assert.equal(hint.sourceRowVersion, held.generation.rowVersion); assert.equal(hint.actualReadFaults, 1);
      assert.equal(typeof hint.temporaryBasename, 'string'); assert.match(hint.temporaryBasename, /^\.tmp-stream-[0-9a-f]{32}$/u);
      assert.ok(Number.isSafeInteger(hint.temporaryFd) && hint.temporaryFd >= 3);
      assert.match(hint.quarantineArtifactRef, /^[0-9a-f]{64}$/u);
      const temporaryPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, hint.temporaryBasename);
      assert.equal(fs.readlinkSync(`/proc/${supervisor.pid}/fd/${hint.temporaryFd}`), temporaryPath);
      const temporary = await open(temporaryPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      try {
        const physical = await temporary.stat({ bigint: true });
        assert.ok(physical.isFile()); assert.equal(physical.mode & 0o7777n, 0o600n); assert.equal(physical.nlink, 1n);
        assert.equal(Number(physical.uid), supervisorIdentity.ownerUid); assert.ok(physical.size > 0n && physical.size <= 64n * 1024n);
        const remote = await stat(`/proc/${supervisor.pid}/fd/${hint.temporaryFd}`, { bigint: true });
        assert.equal(remote.dev, physical.dev); assert.equal(remote.ino, physical.ino);
        const bytes = Buffer.alloc(Number(physical.size));
        for (let offset = 0; offset < bytes.length;) {
          const { bytesRead } = await temporary.read(bytes, offset, bytes.length - offset, offset);
          assert.ok(bytesRead > 0); offset += bytesRead;
        }
        const receipt = JSON.parse(bytes.toString('utf8')) as Extract<WorkspaceGenerationQuarantineEvidenceV1, { reason: 'launch_aborted' }>;
        assert.deepEqual(bytes, canonicalJsonBytes(receipt)); assert.equal(receipt.evidenceDigest, digestOmitting(receipt, 'evidenceDigest'));
        pendingReceiptRef = canonicalSha256(receipt); assert.equal(pendingReceiptRef, hint.quarantineArtifactRef);
        await assert.rejects(lstat(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, pendingReceiptRef)), { code: 'ENOENT' });
        const proof = frozenArtifact<ProcessContainmentNoSpawnEvidenceV1>(fixture.stateRoot, receipt.containmentNoSpawnEvidenceRef);
        const inspector = frozenArtifact<SupervisorInspectorIdentityV1>(fixture.stateRoot, proof.inspectorIdentityRef);
        assert.equal(inspector.identityDigest, digestOmitting(inspector, 'identityDigest'));
        assert.deepEqual(inspector, {
          schemaVersion: 1, format: 'cliq-supervisor-inspector-identity-v1', supervisorInstanceId: held.owner.supervisorInstanceId,
          stateOwnerEpoch: held.owner.ownerEpoch, runtimeBundleRef: held.owner.runtimeBundleRef,
          runtimeBundleManifestDigest: held.owner.runtimeBundleManifestDigest, supervisorEntryId: held.owner.supervisorEntryId,
          supervisorEntryVersion: held.owner.supervisorEntryVersion, supervisorExecutableDigest: held.owner.supervisorExecutableDigest,
          processIdentityRef: held.owner.processIdentityRef, processIdentityDigest: held.owner.processIdentityDigest,
          stateLockIdentityRef: held.owner.stateLockIdentityRef, stateLockIdentityDigest: held.owner.stateLockIdentityDigest,
          instanceNonceDigest: held.owner.instanceNonceDigest, activatedAt: held.owner.acquiredAt, identityDigest: inspector.identityDigest
        } satisfies SupervisorInspectorIdentityV1);
        assert.equal(proof.evidenceDigest, digestOmitting(proof, 'evidenceDigest'));
        assert.deepEqual(proof, {
          schemaVersion: 1, kind: 'containment_plan_quiescent', planRef: held.launch.containmentPlanRef,
          sandboxLaunchSpecRef: held.launch.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: spec.launchSpecDigest,
          owner: plan.owner, launchNonceDigest: held.launch.spawnNonceDigest,
          inspectorSupervisorInstanceId: held.owner.supervisorInstanceId, inspectorIdentityRef: proof.inspectorIdentityRef,
          inspectorIdentityDigest: inspector.identityDigest, backend: noSpawnBackend, observedAt: proof.observedAt,
          evidenceDigest: proof.evidenceDigest
        } satisfies ProcessContainmentNoSpawnEvidenceV1);
        assert.deepEqual(receipt, {
          schemaVersion: 1, format: 'cliq-workspace-generation-quarantine-evidence-v1', runId: fixture.runId,
          generationRef: held.generation.generationRef, generationIdentityDigest: held.generation.generationIdentityDigest,
          sourceRowVersion: held.generation.rowVersion, observedState: { kind: 'complete_tree', treeDigest: held.generation.lastVerifiedTreeDigest },
          inspectorIdentityRef: proof.inspectorIdentityRef, inspectorIdentityDigest: inspector.identityDigest,
          quarantineCanonicalRootRelativePath: archiveRelativePath, quarantineDeviceId: identity.locator.deviceId,
          quarantineFileId: identity.locator.directoryFileId, originalLocatorAbsent: true, renameNoReplace: true,
          directoryFsyncComplete: true, observedAt: receipt.observedAt, evidenceDigest: receipt.evidenceDigest,
          workerLaunchId: held.launch.launchId, fromPhase: 'preactivated_readonly', reason: 'launch_aborted',
          containmentNoSpawnEvidenceRef: receipt.containmentNoSpawnEvidenceRef, containmentNoSpawnEvidenceDigest: proof.evidenceDigest
        } satisfies Extract<WorkspaceGenerationQuarantineEvidenceV1, { reason: 'launch_aborted' }>);
        assert.ok(proof.observedAt >= held.owner.acquiredAt && proof.observedAt >= held.launch.createdAt && proof.observedAt <= receipt.observedAt);
        const pending = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
        try { pending.readSnapshot(connection => {
          for (const ref of [pendingReceiptRef!, receipt.containmentNoSpawnEvidenceRef]) {
            assert.equal(connection.prepare('SELECT ref FROM artifacts WHERE ref=?').get(ref), undefined,
              'after-real-write pause must precede retirement artifact metadata registration');
          }
          assert.deepEqual(readRequiredWorkerLaunch(connection, held.launch.launchId), held.launch);
          assert.deepEqual(readRequiredWorkspaceGenerationByRef(connection, held.generation.generationRef), held.generation);
        }); } finally { pending.close(); }
        const after = await temporary.stat({ bigint: true }), named = await lstat(temporaryPath, { bigint: true });
        for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(after[field], physical[field]);
        assert.equal(named.dev, physical.dev); assert.equal(named.ino, physical.ino);
        pendingReceipt = receipt; pendingProof = proof;
      } finally { await temporary.close(); }
    }
    if (committed) {
      assert.ok(recordedWorker && recordedContainment && physicalScope);
      assert.equal(spec.executable.kind, 'runtime_bundle');
      if (spec.executable.kind !== 'runtime_bundle') throw new Error('committed preactivation lacks its signed worker recipe');
      assert.deepEqual(recordedWorker, {
        schemaVersion: 1, executableRealpath: spec.executable.executionPath, executableDigest: spec.executable.executableDigest,
        pid: physicalScope.workerPid, processStartToken: physicalScope.workerToken,
        spawnNonceDigest: held.launch.spawnNonceDigest, activationNonceDigest: held.launch.activationNonceDigest,
        intendedLeaseEpoch: held.run.leaseEpoch + 1, launchId: held.launch.launchId,
        supervisorInstanceId: held.owner.supervisorInstanceId, processContainmentRef: held.launch.processContainmentRef!
      } satisfies WorkerIdentity);
      assert.deepEqual(recordedContainment, {
        schemaVersion: 1, planRef: held.launch.containmentPlanRef, sandboxLaunchSpecRef: held.launch.sandboxLaunchSpecRef,
        sandboxLaunchSpecDigest: spec.launchSpecDigest, owner: plan.owner,
        filesystemBinding: { kind: 'run-generation', generationRef: held.launch.workspaceGenerationRef },
        launchNonceDigest: held.launch.spawnNonceDigest,
        backend: { kind: 'linux', cgroupPath: plan.backend.cgroupPath, cgroupId: physicalScope.cgroupId,
          pidNamespaceReservationId: plan.backend.pidNamespaceReservationId, pidNamespaceId: physicalScope.pidNamespaceId,
          namespaceInitStartToken: physicalScope.namespaceInitStartToken, subreaperStartToken: plan.backend.subreaperStartToken },
        createdAt: recordedContainment.createdAt
      } satisfies ProcessContainment);
    }
    if (postMove) await assert.rejects(lstat(path.join(fixture.stateRoot, identity.locator.canonicalRootRelativePath)), { code: 'ENOENT' });
    const root = await open(path.join(fixture.stateRoot, postMove ? archiveRelativePath : identity.locator.canonicalRootRelativePath),
      fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try {
      const physical = await root.stat({ bigint: true });
      assert.equal(String(physical.dev), identity.locator.deviceId); assert.equal(String(physical.ino), identity.locator.directoryFileId);
      assert.equal(Number(physical.uid), identity.locator.ownerUid); assert.equal(physical.mode & 0o7777n, 0o700n);
      const file = await open(`/proc/self/fd/${root.fd}/a`, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      try { assert.deepEqual(await file.readFile(), fixture.original); } finally { await file.close(); }
    } finally { await root.close(); }
    await assert.rejects(openStateStore(fixture.stateRoot, fixture.runtimeAuthority), /OS lock is already held/u);
    if (monitorFork) {
      assert.ok(bindingPrefix && retainedWitness === witness);
      // Compile a test-only module in its own directory, using the installed
      // Node header selector without staging or replacing a production image.
      tracerDirectory = await mkdtemp(path.join(tmpdir(), 'cliq-linux-fork-tracer-'));
      const queried = spawnSync(process.execPath, [fileURLToPath(new URL('./build-state-owner-native.mjs', import.meta.url)), '--print-includes'],
        { encoding: 'utf8', timeout: 30_000 });
      if (queried.error) throw queried.error;
      assert.equal(queried.status, 0, queried.stderr);
      const includes: unknown = JSON.parse(queried.stdout);
      assert.ok(Array.isArray(includes) && includes.length > 0 && includes.every(value => typeof value === 'string' && path.isAbsolute(value)));
      const binary = path.join(tracerDirectory, 'linux-fork-tracer.node');
      const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
        ...includes.flatMap(value => ['-I', value as string]), fileURLToPath(new URL('./linux-fork-tracer.c', import.meta.url)), '-o', binary],
        { encoding: 'utf8', timeout: 30_000 });
      if (compiled.error) throw compiled.error;
      assert.equal(compiled.status, 0, compiled.stderr);
      const loaded: unknown = createRequire(import.meta.url)(binary);
      assert.ok(loaded && typeof loaded === 'object');
      const candidate = loaded as LinuxForkTracer;
      for (const method of ['arm', 'pollFork', 'release'] as const) assert.equal(typeof candidate[method], 'function');
      if (controllerLoss) assert.equal(typeof candidate.finishControllerLoss, 'function');
      tracer = candidate;
      assert.equal(processToken(controllerPid), controllerToken);
      const beforeAttach = await readFile(`/proc/${controllerPid}/status`, 'utf8');
      assert.match(beforeAttach, new RegExp(`^PPid:\\s+${supervisor.pid}$`, 'mu')); assert.match(beforeAttach, /^TracerPid:\s+0$/mu);
      tracer.arm(controllerPid);
      assert.equal(processToken(controllerPid), controllerToken);
      const afterAttach = await readFile(`/proc/${controllerPid}/status`, 'utf8');
      assert.match(afterAttach, new RegExp(`^TracerPid:\\s+${process.pid}$`, 'mu'));
      assert.match(afterAttach, new RegExp(`^PPid:\\s+${supervisor.pid}$`, 'mu'));
      assert.equal(processToken(supervisor.pid!), supervisorIdentity.processStartToken);
      assert.ok(supervisor.kill('SIGCONT'));
      const deadline = performance.now() + 30_000;
      let monitorPid: number;
      for (;;) {
        const observed = tracer.pollFork();
        if (observed !== null) {
          assert.ok(Number.isSafeInteger(observed) && observed > 0 && observed !== controllerPid && observed !== supervisor.pid);
          monitorPid = observed; break;
        }
        assert.ok(supervisor.exitCode === null && supervisor.signalCode === null, `Supervisor exited before the actual monitor fork: ${diagnostic}`);
        assert.ok(performance.now() < deadline, 'actual monitor fork was not captured (not retried or skipped)');
        await delay(1);
      }
      const monitorToken = processToken(monitorPid);
      const assertTraceStop = async (pid: number, startToken: string, parentPid: number) => {
        assert.equal(processToken(pid), startToken);
        const line = await readFile(`/proc/${pid}/stat`, 'utf8');
        assert.equal(line.slice(line.lastIndexOf(')') + 2).trim().split(/\s+/u)[0], 't');
        const status = await readFile(`/proc/${pid}/status`, 'utf8');
        assert.match(status, new RegExp(`^TracerPid:\\s+${process.pid}$`, 'mu'));
        assert.match(status, new RegExp(`^PPid:\\s+${parentPid}$`, 'mu'));
        assert.equal(Number(status.match(/^Uid:\s+([0-9]+)/mu)?.[1]), supervisorIdentity.ownerUid);
      };
      await assertTraceStop(controllerPid, controllerToken, supervisor.pid!);
      await assertTraceStop(monitorPid, monitorToken, controllerPid);
      const physical = await witness.stat({ bigint: true });
      assert.ok(physical.isFile()); assert.equal(physical.nlink, 1n); assert.equal(physical.mode & 0o7777n, 0o600n);
      assert.equal(String(physical.dev), plan.backend.nativeReservation.deviceId); assert.equal(String(physical.ino), plan.backend.nativeReservation.fileId);
      assert.equal(Number(physical.uid), plan.backend.nativeReservation.ownerUid); assert.equal(physical.size, 2336n);
      const prefix = await witnessBytes(witness, 2336); verifyNativeBirthFrames(prefix, [2048, 32, 64]);
      assert.deepEqual(prefix.subarray(0, 2112), bindingPrefix);
      const intent = Buffer.alloc(32); intent.write('CREATE1'); assert.deepEqual(prefix.subarray(2112, 2144), intent);
      const group = await lstat(plan.backend.cgroupPath, { bigint: true }); assert.ok(group.isDirectory() && !group.isSymbolicLink());
      const cgroup = Buffer.alloc(64);
      for (const [index, value] of [group.dev, group.ino, group.uid, group.mode].entries()) cgroup.writeBigUInt64LE(value, index * 8);
      assert.deepEqual(prefix.subarray(2208, 2272), cgroup);
      for (const scope of [plan.backend.cgroupPath, path.join(plan.backend.cgroupPath, 'worker')]) {
        assert.equal((await readFile(path.join(scope, 'cgroup.procs'), 'utf8')).trim(), '');
        assert.match(await readFile(path.join(scope, 'cgroup.events'), 'utf8'), /(?:^|\n)populated 0\n/u);
      }
      const after = await witness.stat({ bigint: true });
      for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(after[field], physical[field]);
      await assertTraceStop(controllerPid, controllerToken, supervisor.pid!);
      await assertTraceStop(monitorPid, monitorToken, controllerPid);
      const cut = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
      try { cut.readSnapshot(connection => {
        assert.deepEqual(readRun(connection, fixture.runId), held.run);
        assert.deepEqual(readLatestStateOwner(connection), held.owner);
        assert.deepEqual(readInvocationJournal(connection, fixture.runId), before.closure.journal);
        assert.deepEqual(readRequiredWorkerLaunch(connection, held.launch.launchId), held.launch);
        assert.deepEqual(readRequiredWorkspaceGenerationByRef(connection, held.generation.generationRef), held.generation);
      }); } finally { cut.close(); }
      forkObservation = { prefix, witness: physical, group, monitorPid, monitorToken };
    }
    assert.equal(processToken(supervisor.pid!), supervisorIdentity.processStartToken);
    assert.ok(supervisor.kill('SIGKILL'));
    const supervisorExit = await bounded(exit); supervisorJoined = true; assert.deepEqual(supervisorExit, [null, 'SIGKILL']);
    const linuxLocator = identity.locator, linuxBackend = plan.backend;
    const assertPublicOpeningRefusal = async (assertWitnessFault: () => Promise<void>, expectedGroup: fs.BigIntStats) => {
      assert.ok(negative && held.refusalRows && retainedWitness === witness && supervisorJoined);
      await assertWitnessFault();
      // Public failed startup owns the refusal and its GC boundary. This
      // campaign never opens, repairs, retries or closes the negative fixture.
      refusedOwner = fork(new URL('../../src/state/testing/preactivation-owner-child.ts', import.meta.url), [], {
        execArgv: ['--expose-gc', '--import', 'tsx'], serialization: 'advanced', stdio: ['ignore', 'pipe', 'pipe', 'ipc']
      });
      const helper = refusedOwner, helperExit = once(helper, 'exit'); refusedOwnerExit = helperExit; void helperExit.catch(() => {});
      for (const output of [helper.stdout!, helper.stderr!]) output.on('data', (chunk: Buffer) => {
        diagnostic = (diagnostic + chunk.toString()).slice(-8192);
      });
      const helperReply = async () => {
        const abort = new AbortController(), timer = setTimeout(() => abort.abort(), 40_000);
        try { return await Promise.race([
          once(helper, 'message', { signal: abort.signal }).then(([value]) => value as unknown),
          helperExit.then(([code, signal]) => { throw new Error(`${scenarioBoundary} refused owner exited before reply: ${code}/${signal}: ${diagnostic}`); })
        ]); } finally { clearTimeout(timer); abort.abort(); }
      };
      assert.deepEqual(await helperReply(), { state: 'ready' });
      const response = helperReply(); void response.catch(() => {});
      await new Promise<void>((resolve, reject) => helper.send({ stateRoot: fixture.stateRoot, authority: fixture.runtimeAuthority },
        error => error ? reject(error) : resolve()));
      const refused = await response;
      assert.ok(refused && typeof refused === 'object' && !Array.isArray(refused));
      const { message: refusalMessage, ...refusalFacts } = refused as Record<string, unknown>;
      assert.equal(typeof refusalMessage, 'string');
      assert.deepEqual(refusalFacts, { state: 'refused', failurePhase: 'open', retirement: true, code: 'RECOVERY_REQUIRED', closeFaults: 0 },
        typeof refusalMessage === 'string' ? refusalMessage : diagnostic);
      const native = await loadNativeStateOwner(fixture.runtimeAuthority.bundle);
      let incorrectlyAcquired: HeldStateOwnerLock | undefined;
      try { incorrectlyAcquired = native.acquireLock(fixture.stateRoot, false); }
      catch (error) { assert.match(String(error), /OS lock is already held/u); }
      if (incorrectlyAcquired) {
        incorrectlyAcquired.close(); assert.fail('actual failed opening released its OS owner after caller GC');
      }
      const inspection = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME)); history = inspection;
      const refusingOwner = inspection.readSnapshot(connection => {
        assert.deepEqual(readRun(connection, fixture.runId), held.run);
        assert.deepEqual(readInvocationJournal(connection, fixture.runId), before.closure.journal);
        assert.deepEqual(readRequiredWorkerLaunch(connection, held.launch.launchId), held.launch);
        assert.deepEqual(readRequiredWorkspaceGenerationByRef(connection, held.generation.generationRef), held.generation);
        assert.deepEqual(preactivationRefusalRows(connection, fixture.runId), held.refusalRows,
          'invalid birth refusal cannot change any Run events, Journal, launch/generation rows or register positive native/quarantine proof');
        const owner = readLatestStateOwner(connection)!;
        assert.equal(owner.state, 'active'); assert.ok(owner.ownerEpoch > held.owner.ownerEpoch);
        assert.notEqual(owner.supervisorInstanceId, held.owner.supervisorInstanceId); return owner;
      });
      const helperIdentity = frozenArtifact<PlatformProcessIdentityV1>(fixture.stateRoot, refusingOwner.processIdentityRef);
      assert.equal(helperIdentity.platform, 'linux'); assert.equal(helperIdentity.pid, helper.pid);
      assert.equal(processToken(helper.pid!), helperIdentity.processStartToken);
      await assertWitnessFault();
      const generation = await open(path.join(fixture.stateRoot, linuxLocator.canonicalRootRelativePath),
        fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      try {
        const physical = await generation.stat({ bigint: true }); assert.ok(physical.isDirectory());
        assert.equal(String(physical.dev), linuxLocator.deviceId); assert.equal(String(physical.ino), linuxLocator.directoryFileId);
        assert.equal(Number(physical.uid), linuxLocator.ownerUid); assert.equal(physical.mode & 0o7777n, 0o700n);
        const file = await open(`/proc/self/fd/${generation.fd}/a`, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
        try { assert.deepEqual(await file.readFile(), fixture.original); } finally { await file.close(); }
      } finally { await generation.close(); }
      assert.deepEqual(await readFile(path.join(fixture.workspace, 'a')), fixture.original);
      await assert.rejects(lstat(path.join(fixture.stateRoot, archiveRelativePath)), { code: 'ENOENT' });
      const group = await lstat(linuxBackend.cgroupPath, { bigint: true });
      for (const field of ['dev', 'ino', 'uid', 'mode'] as const) assert.equal(group[field], expectedGroup[field]);
      for (const scope of [linuxBackend.cgroupPath, path.join(linuxBackend.cgroupPath, 'worker')]) {
        assert.equal((await readFile(path.join(scope, 'cgroup.procs'), 'utf8')).trim(), '');
        assert.match(await readFile(path.join(scope, 'cgroup.events'), 'utf8'), /(?:^|\n)populated 0\n/u);
      }
      assert.equal(processToken(helper.pid!), helperIdentity.processStartToken);
      assert.ok(helper.kill('SIGKILL')); assert.deepEqual(await bounded(helperExit), [null, 'SIGKILL']);
      return { refusingOwnerEpoch: refusingOwner.ownerEpoch, publicOpening: refusalFacts };
    };
    if (controllerLoss) {
      assert.ok(tracer && forkObservation && retainedWitness === witness && held.refusalRows && supervisorJoined);
      const observedFork = forkObservation;
      assert.equal(processToken(controllerPid), controllerToken);
      const controllerLine = await readFile(`/proc/${controllerPid}/stat`, 'utf8');
      assert.equal(controllerLine.slice(controllerLine.lastIndexOf(')') + 2).trim().split(/\s+/u)[0], 't');
      assert.match(await readFile(`/proc/${controllerPid}/status`, 'utf8'), new RegExp(`^TracerPid:\\s+${process.pid}$`, 'mu'));
      assert.equal(processToken(observedFork.monitorPid), observedFork.monitorToken);
      // Only the exact retained controller is killed. The module joins its
      // SIGKILL before CONT(0) lets M hit the real barrier EOF and exit 70.
      process.kill(controllerPid, 'SIGKILL');
      const terminalDeadline = performance.now() + 30_000;
      let terminal: { controllerSignal: 9; monitorExitCode: 70 };
      for (;;) {
        const observed = tracer.finishControllerLoss();
        if (observed !== null) {
          assert.deepEqual(observed, { controllerSignal: 9, monitorExitCode: 70 }); terminal = observed; break;
        }
        assert.ok(performance.now() < terminalDeadline, 'actual controller-loss terminal joins timed out');
        await delay(1);
      }
      tracer = undefined;
      // Trace wait statuses and /proc absence are independent observations.
      for (const pid of [controllerPid, observedFork.monitorPid]) {
        const deadline = performance.now() + 5000;
        for (;;) {
          try { await access(`/proc/${pid}`); }
          catch (error) { assert.equal((error as NodeJS.ErrnoException).code, 'ENOENT'); break; }
          assert.ok(performance.now() < deadline, `joined controller-loss process ${pid} remains in /proc`);
          await delay(1);
        }
      }
      const assertIncompleteBirth = async () => {
        const physical = await witness.stat({ bigint: true });
        for (const field of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const) {
          assert.equal(physical[field], observedFork.witness[field]);
        }
        assert.equal(physical.size, 2336n);
        const bytes = await witnessBytes(witness, 2336); verifyNativeBirthFrames(bytes, [2048, 32, 64]);
        assert.deepEqual(bytes, observedFork.prefix, 'controller loss cannot append, repair or invent a later birth fact');
        const after = await witness.stat({ bigint: true });
        for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(after[field], physical[field]);
      };
      const refusal = await assertPublicOpeningRefusal(assertIncompleteBirth, observedFork.group);
      negativeQualified = true;
      console.log(JSON.stringify({ scenario: 'actual-supervisor-crash-monitor-fork-controller-loss', supervisorPid: supervisor.pid,
        supervisorStartToken: supervisorIdentity.processStartToken, supervisorSignal: 'SIGKILL', controllerPid,
        controllerStartToken: controllerToken, ...terminal, monitorPid: observedFork.monitorPid, monitorStartToken: observedFork.monitorToken,
        witnessBytes: 2336, oldLaunchId: held.launch.launchId, oldGenerationRef: held.generation.generationRef,
        sourceRowVersion: held.generation.rowVersion, ...refusal,
        actualOwnerLockAfterCallerGc: 'busy', nativeEffectCount: 0, retryCount: 0,
        preservedStateRoot: fixture.stateRoot, preservedWorkspace: fixture.workspace,
        note: 'real monitor fork; Supervisor and original controller SIGKILL; natural monitor barrier EOF exit 70; no birth repair, no native positive proof or generation quarantine; retained unknown fixture for controlled CI teardown' }));
      return;
    }
    if (witnessFault !== undefined) {
      assert.ok(readyObservation && physicalScope && retainedWitness === witness && !tracer);
      const originalReady = readyObservation, oldScope = physicalScope;
      // The file fault follows natural EOF cleanup, never interrupts its
      // producer or lets an old live flock/process mask READY frame checking.
      for (const pid of new Set([controllerPid, ...oldScope.members.map(member => member.pid), oldScope.monitorPid])) {
        const deadline = performance.now() + 5000;
        for (;;) {
          try { await access(`/proc/${pid}`); }
          catch (error) { assert.equal((error as NodeJS.ErrnoException).code, 'ENOENT'); break; }
          assert.ok(performance.now() < deadline, `pre-fault original process ${pid} remains in /proc`);
          await delay(1);
        }
      }
      const group = await lstat(plan.backend.cgroupPath, { bigint: true });
      for (const field of ['dev', 'ino', 'uid', 'mode'] as const) assert.equal(group[field], originalReady.group[field]);
      for (const scope of [plan.backend.cgroupPath, path.join(plan.backend.cgroupPath, 'worker')]) {
        assert.equal((await readFile(path.join(scope, 'cgroup.procs'), 'utf8')).trim(), '');
        assert.match(await readFile(path.join(scope, 'cgroup.events'), 'utf8'), /(?:^|\n)populated 0\n/u);
      }
    }
    if (corruptReadyFooter) {
      assert.ok(readyObservation && retainedWitness === witness);
      const originalReady = readyObservation;
      const footerShaOffset = 4736, oldByte = originalReady.bytes[footerShaOffset]!, newByte = oldByte ^ 1;
      const writable = await open(witnessPath, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW);
      let writeFailure: { error: unknown } | undefined;
      try {
        const physical = await writable.stat({ bigint: true }), retained = await witness.stat({ bigint: true });
        assert.ok(physical.isFile()); assert.equal(physical.size, 4768n); assert.equal(physical.nlink, 1n); assert.equal(physical.mode & 0o7777n, 0o600n);
        for (const field of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size'] as const) {
          assert.equal(physical[field], retained[field]); assert.equal(physical[field], originalReady.witness[field]);
        }
        assert.equal(String(physical.dev), plan.backend.nativeReservation.deviceId); assert.equal(String(physical.ino), plan.backend.nativeReservation.fileId);
        assert.equal(Number(physical.uid), plan.backend.nativeReservation.ownerUid);
        const bytes = await witnessBytes(writable, 4768); assert.deepEqual(bytes, originalReady.bytes);
        verifyNativeBirthFrames(bytes, [2048, 32, 64, 256, 2048]);
        const { bytesWritten } = await writable.write(Buffer.from([newByte]), 0, 1, footerShaOffset); assert.equal(bytesWritten, 1);
        await writable.sync();
      } catch (error) { writeFailure = { error }; throw error; }
      finally {
        try { await writable.close(); }
        catch (error) { throw new AggregateError([...(writeFailure ? [writeFailure.error] : []), error], 'READY footer fault writer did not close'); }
      }
      const postFault = await witness.stat({ bigint: true });
      const assertCorruptReadyFooter = async () => {
        const physical = await witness.stat({ bigint: true }), named = await lstat(witnessPath, { bigint: true });
        assert.ok(physical.isFile() && named.isFile() && !named.isSymbolicLink());
        for (const field of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const) {
          assert.equal(physical[field], postFault[field]); assert.equal(named[field], postFault[field]);
        }
        assert.equal(physical.size, 4768n);
        const bytes = await witnessBytes(witness, 4768), differences: number[] = [];
        for (let offset = 0; offset < bytes.length; offset++) if (bytes[offset] !== originalReady.bytes[offset]) differences.push(offset);
        assert.deepEqual(differences, [footerShaOffset]); assert.equal(bytes[footerShaOffset], newByte);
        verifyNativeBirthFrames(bytes.subarray(0, 2656), [2048, 32, 64, 256]);
        assert.deepEqual(bytes.subarray(4704, 4736), originalReady.bytes.subarray(4704, 4736), 'final footer framing must remain valid');
        const actualReadySha = createHash('sha256').update(bytes.subarray(2656, 4704)).digest();
        assert.deepEqual(actualReadySha, originalReady.bytes.subarray(4736, 4768));
        assert.notDeepEqual(actualReadySha, bytes.subarray(4736, 4768), 'only the final READY checksum is corrupt');
        const after = await witness.stat({ bigint: true });
        for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(after[field], physical[field]);
      };
      const refusal = await assertPublicOpeningRefusal(assertCorruptReadyFooter, originalReady.group);
      await assertCorruptReadyFooter();
      const faultBytes = await witnessBytes(witness, 4768);
      negativeQualified = true;
      console.log(JSON.stringify({ scenario: 'actual-supervisor-crash-corrupt-ready-footer', supervisorPid: supervisor.pid,
        supervisorStartToken: supervisorIdentity.processStartToken, supervisorSignal: 'SIGKILL', controllerPid,
        controllerStartToken: controllerToken, oldLaunchId: held.launch.launchId, oldGenerationRef: held.generation.generationRef,
        sourceRowVersion: held.generation.rowVersion, ...refusal, actualOwnerLockAfterCallerGc: 'busy', nativeEffectCount: 0, retryCount: 0,
        fault: { kind: 'corrupt_ready_footer', byteOffset: footerShaOffset, originalByte: oldByte, corruptedByte: faultBytes[footerShaOffset],
          byteLength: faultBytes.length, originalSha256: createHash('sha256').update(originalReady.bytes).digest('hex'),
          corruptedSha256: createHash('sha256').update(faultBytes).digest('hex'), deviceId: String(postFault.dev), fileId: String(postFault.ino),
          ownerUid: Number(postFault.uid), mode: Number(postFault.mode & 0o7777n), linkCount: Number(postFault.nlink),
          postFaultMtimeNs: String(postFault.mtimeNs), postFaultCtimeNs: String(postFault.ctimeNs), fsyncComplete: true },
        preservedStateRoot: fixture.stateRoot, preservedWorkspace: fixture.workspace,
        note: 'real READY observed before Supervisor loss; original controller and captured members naturally gone before one-byte footer SHA fault; public opening refuses without repair or new native birth/death evidence; retained fixture for controlled CI teardown' }));
      return;
    }
    if (witnessFault === 'missing' || witnessFault === 'replaced_inode') {
      assert.ok(readyObservation && retainedWitness === witness);
      const originalReady = readyObservation, parentPath = path.dirname(witnessPath);
      const parent = await open(parentPath, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      let pathFaultFailure: { error: unknown } | undefined;
      try {
        const directory = await parent.stat({ bigint: true }), namedDirectory = await lstat(parentPath, { bigint: true });
        assert.ok(directory.isDirectory() && namedDirectory.isDirectory() && !namedDirectory.isSymbolicLink());
        assert.equal(directory.mode & 0o7777n, 0o700n); assert.equal(Number(directory.uid), plan.backend.nativeReservation.ownerUid);
        assert.equal(directory.dev, originalReady.witness.dev);
        for (const field of ['dev', 'ino', 'uid', 'mode'] as const) assert.equal(namedDirectory[field], directory[field]);
        const originalName = `/proc/self/fd/${parent.fd}/${path.basename(witnessPath)}`;
        const retainedBasename = `.retained-worker-reservation-${randomUUID()}`;
        const retainedName = `/proc/self/fd/${parent.fd}/${retainedBasename}`;
        const original = await witness.stat({ bigint: true }), named = await lstat(originalName, { bigint: true });
        assert.ok(original.isFile() && named.isFile() && !named.isSymbolicLink());
        for (const field of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size'] as const) {
          assert.equal(original[field], originalReady.witness[field]); assert.equal(named[field], original[field]);
        }
        assert.equal(original.mode & 0o7777n, 0o600n); assert.equal(original.nlink, 1n); assert.equal(original.size, 4768n);
        const nativeBytes = await witnessBytes(witness, 4768); assert.deepEqual(nativeBytes, originalReady.bytes);
        verifyNativeBirthFrames(nativeBytes, [2048, 32, 64, 256, 2048]);
        await assert.rejects(lstat(retainedName), { code: 'ENOENT' });
        await rename(originalName, retainedName);
        await assert.rejects(lstat(witnessPath), { code: 'ENOENT' });
        let copiedBytes = 0;
        if (witnessFault === 'replaced_inode') {
          const replacement = await open(originalName,
            fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
          let copyFailure: { error: unknown } | undefined;
          try {
            const physical = await replacement.stat({ bigint: true });
            assert.ok(physical.isFile()); assert.equal(physical.dev, original.dev); assert.notEqual(physical.ino, original.ino);
            assert.equal(physical.uid, original.uid); assert.equal(physical.mode & 0o7777n, 0o600n);
            assert.equal(physical.nlink, 1n); assert.equal(physical.size, 0n);
            // Exact original native bytes retain the old inode binding. Do not
            // recompute a body/footer or invent a replacement birth witness.
            while (copiedBytes < nativeBytes.length) {
              const { bytesWritten } = await replacement.write(nativeBytes, copiedBytes, nativeBytes.length - copiedBytes, copiedBytes);
              assert.ok(bytesWritten > 0 && bytesWritten <= nativeBytes.length - copiedBytes); copiedBytes += bytesWritten;
            }
            assert.equal(copiedBytes, 4768); await replacement.sync();
          } catch (error) { copyFailure = { error }; throw error; }
          finally {
            try { await replacement.close(); }
            catch (error) { throw new AggregateError([...(copyFailure ? [copyFailure.error] : []), error], 'replacement witness writer did not close'); }
          }
        }
        await parent.sync();
        // Rename legally changes the original ctime; directory mutations also
        // change parent timestamps. Only the completed fault is the baseline.
        const postOriginal = await witness.stat({ bigint: true }), postParent = await parent.stat({ bigint: true });
        const postReplacement = witnessFault === 'replaced_inode' ? await lstat(originalName, { bigint: true }) : undefined;
        let replacementDigest: string | undefined;
        const assertPathFault = async () => {
          const physical = await witness.stat({ bigint: true }), retained = await lstat(retainedName, { bigint: true });
          assert.ok(physical.isFile() && retained.isFile() && !retained.isSymbolicLink());
          for (const field of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const) {
            assert.equal(physical[field], postOriginal[field]); assert.equal(retained[field], postOriginal[field]);
          }
          for (const field of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size'] as const) assert.equal(physical[field], original[field]);
          const bytes = await witnessBytes(witness, 4768); assert.deepEqual(bytes, nativeBytes);
          verifyNativeBirthFrames(bytes, [2048, 32, 64, 256, 2048]);
          const directory = await parent.stat({ bigint: true }), namedDirectory = await lstat(parentPath, { bigint: true });
          assert.ok(directory.isDirectory() && namedDirectory.isDirectory() && !namedDirectory.isSymbolicLink());
          for (const field of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const) {
            assert.equal(directory[field], postParent[field]); assert.equal(namedDirectory[field], postParent[field]);
          }
          if (witnessFault === 'missing') {
            await assert.rejects(lstat(witnessPath), { code: 'ENOENT' });
          } else {
            assert.ok(postReplacement);
            const named = await lstat(witnessPath, { bigint: true }); assert.ok(named.isFile() && !named.isSymbolicLink());
            for (const field of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(named[field], postReplacement[field]);
            assert.equal(named.dev, physical.dev); assert.notEqual(named.ino, physical.ino); assert.equal(named.uid, physical.uid);
            assert.equal(named.mode & 0o7777n, 0o600n); assert.equal(named.nlink, 1n); assert.equal(named.size, 4768n);
            const replacement = await open(originalName, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
            try {
              const before = await replacement.stat({ bigint: true });
              for (const field of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(before[field], postReplacement[field]);
              const bytes = await witnessBytes(replacement, 4768); assert.deepEqual(bytes, nativeBytes);
              verifyNativeBirthFrames(bytes, [2048, 32, 64, 256, 2048]);
              assert.equal(bytes.readBigUInt64LE(24), physical.ino); assert.notEqual(bytes.readBigUInt64LE(24), before.ino);
              replacementDigest = createHash('sha256').update(bytes).digest('hex');
              const after = await replacement.stat({ bigint: true });
              for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(after[field], before[field]);
            } finally { await replacement.close(); }
          }
          const after = await witness.stat({ bigint: true });
          for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(after[field], physical[field]);
        };
        const refusal = await assertPublicOpeningRefusal(assertPathFault, originalReady.group);
        await assertPathFault(); negativeQualified = true;
        console.log(JSON.stringify({ scenario: `actual-supervisor-crash-witness-${witnessFault.replaceAll('_', '-')}`,
          supervisorPid: supervisor.pid, supervisorStartToken: supervisorIdentity.processStartToken, supervisorSignal: 'SIGKILL',
          controllerPid, controllerStartToken: controllerToken, oldLaunchId: held.launch.launchId,
          oldGenerationRef: held.generation.generationRef, sourceRowVersion: held.generation.rowVersion, ...refusal,
          actualOwnerLockAfterCallerGc: 'busy', nativeEffectCount: 0, retryCount: 0,
          fault: { kind: witnessFault, originalFd: witness.fd, parentFd: parent.fd, derivedPath: witnessPath,
            retainedOriginalPath: path.join(parentPath, retainedBasename), byteLength: nativeBytes.length,
            nativeOriginalSha256: createHash('sha256').update(nativeBytes).digest('hex'), originalDeviceId: String(postOriginal.dev),
            originalFileId: String(postOriginal.ino), ownerUid: Number(postOriginal.uid), mode: Number(postOriginal.mode & 0o7777n),
            linkCount: Number(postOriginal.nlink), postFaultOriginalMtimeNs: String(postOriginal.mtimeNs),
            postFaultOriginalCtimeNs: String(postOriginal.ctimeNs), parentFsyncComplete: true,
            ...(postReplacement ? { replacementDeviceId: String(postReplacement.dev), replacementFileId: String(postReplacement.ino),
              replacementSha256: replacementDigest, copiedBytes, replacementFsyncComplete: true, copiedBindingFileId: String(postOriginal.ino) }
              : { derivedPathAbsent: true, derivedPathErrorCode: 'ENOENT' }) },
          preservedStateRoot: fixture.stateRoot, preservedWorkspace: fixture.workspace,
          note: 'real READY and natural old process cleanup precede a single path-identity fault; original inode and native bytes retained; public opening refuses without repair or new native positive proof; fixture retained for controlled CI teardown' }));
      } catch (error) { pathFaultFailure = { error }; throw error; }
      finally {
        try { await parent.close(); }
        catch (error) { throw new AggregateError([...(pathFaultFailure ? [pathFaultFailure.error] : []), error], 'path fault private parent did not close'); }
      }
      return;
    }
    if (tracer) { await releaseForkTracer(tracer); tracer = undefined; }
    // Do not signal the original controller: actual EOF cleanup and natural
    // orphan reaping must satisfy the native inspector's own five-second bound.
    successor = await bounded(openStateStore(fixture.stateRoot, fixture.runtimeAuthority));
    if (monitorFork) {
      assert.ok(forkObservation && retainedWitness === witness);
      const physical = await witness.stat({ bigint: true });
      assert.ok(physical.isFile()); assert.equal(physical.nlink, 1n); assert.equal(physical.mode & 0o7777n, 0o600n);
      assert.equal(String(physical.dev), plan.backend.nativeReservation.deviceId); assert.equal(String(physical.ino), plan.backend.nativeReservation.fileId);
      assert.equal(Number(physical.uid), plan.backend.nativeReservation.ownerUid); assert.equal(physical.size, 4768n);
      const bytes = await witnessBytes(witness, 4768); verifyNativeBirthFrames(bytes, [2048, 32, 64, 256, 2048]);
      assert.deepEqual(bytes.subarray(0, 2336), forkObservation.prefix, 'natural birth completion must preserve every durable pre-fork byte');
      const group = await lstat(plan.backend.cgroupPath, { bigint: true }); assert.ok(group.isDirectory() && !group.isSymbolicLink());
      for (const field of ['dev', 'ino', 'uid', 'mode'] as const) assert.equal(group[field], forkObservation.group[field]);
      const monitor = Buffer.alloc(256); monitor.writeBigUInt64LE(BigInt(forkObservation.monitorPid)); monitor.write(forkObservation.monitorToken, 8);
      assert.deepEqual(bytes.subarray(2336, 2592), monitor, 'the durable monitor fact must name the independently captured fork child');
      const body = bytes.subarray(2656, 4704);
      const nativePid = (index: number) => {
        const value = Number(body.readBigUInt64LE(16 + index * 8)); assert.ok(Number.isSafeInteger(value) && value > 0); return value;
      };
      const workerPid = nativePid(8), initPid = nativePid(9), monitorPid = nativePid(10);
      assert.equal(monitorPid, forkObservation.monitorPid);
      assert.equal(new Set([workerPid, initPid, monitorPid, controllerPid, supervisor.pid]).size, 5);
      const namespaceInode = body.readBigUInt64LE(16 + 7 * 8); assert.ok(namespaceInode > 0n);
      let cursor = 112;
      const actualTexts = bindingTexts.map(([, width]) => {
        const end = body.indexOf(0, cursor); assert.ok(end >= cursor && end < cursor + width);
        const text = body.subarray(cursor, end).toString('utf8'); cursor += width; return text;
      });
      const workerToken = actualTexts[8]!, initToken = actualTexts[10]!;
      assert.match(workerToken, /^linux-proc-start-ticks:[0-9]+$/u); assert.match(initToken, /^linux-proc-start-ticks:[0-9]+$/u);
      const monitorToken = forkObservation.monitorToken;
      const namespaceInitStartToken = `linux-namespace-init:${initPid}:${initToken.slice('linux-proc-start-ticks:'.length)}:monitor:${monitorPid}:${monitorToken.slice('linux-proc-start-ticks:'.length)}`;
      const readyNumbers = [physical.dev, physical.ino, physical.uid, BigInt(identity.locator.deviceId),
        BigInt(identity.locator.directoryFileId), group.dev, group.ino, namespaceInode,
        BigInt(workerPid), BigInt(initPid), BigInt(monitorPid), BigInt(controllerPid)];
      const readyTexts = [...bindingTexts]; readyTexts.splice(8, 4, [workerToken, 192], [namespaceInitStartToken, 192], [initToken, 192], [monitorToken, 192]);
      assert.deepEqual(body, expectedNativeBirthBody(readyNumbers, readyTexts), 'full native birth keeps exact bindings, captured monitor token and zero padding');
      const after = await witness.stat({ bigint: true });
      for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(after[field], physical[field]);
      // Worker/init were born after detach; their PIDs and tokens come from
      // this actual held durable witness, not a claimed live PID-2 observation
      // or the successor's death evidence that will be compared below.
      physicalScope = { cgroupId: String(group.ino), pidNamespaceId: String(namespaceInode), workerPid, workerToken,
        initPid, initToken, monitorPid, monitorToken, namespaceInitStartToken,
        birthObservation: 'durable-native-birth-after-controller-release',
        members: [{ pid: workerPid, token: workerToken }, { pid: initPid, token: initToken }, { pid: monitorPid, token: monitorToken }] };
    }
    const reopened = await checkpointBytes(successor, fixture.runId); assertQueuedReadyCut(reopened, before);
    assert.equal(reopened.closure.run.revision, held.run.revision + 1);
    await assert.rejects(access(`/proc/${controllerPid}`), { code: 'ENOENT' });
    if (physicalScope) {
      assert.match(await readFile(path.join(plan.backend.cgroupPath, 'cgroup.events'), 'utf8'), /(?:^|\n)populated 0\n/u);
      for (const member of physicalScope.members) await assert.rejects(access(`/proc/${member.pid}`), { code: 'ENOENT' });
    }
    // The public recovery cut contains live launches, not retired history.
    // Independently read this exact historical row without widening that API.
    const inspection = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME)); history = inspection;
    const retired = inspection.readSnapshot(connection => readRequiredWorkerLaunch(connection, held.launch.launchId));
    assert.equal(retired.phase, 'retired'); assert.ok(retired.retirementEvidenceRef);
    assert.equal(retired.workerIdentityDigest, held.launch.workerIdentityDigest, 'successor must retain only the genuinely committed WorkerIdentity');
    const originalFacts = { ...retired, phase: held.launch.phase }; delete originalFacts.retiredAt; delete originalFacts.retirementEvidenceRef;
    if (expectsCreatedRetirement && !committed) delete originalFacts.processContainmentRef;
    assert.deepEqual(originalFacts, held.launch, 'successor retirement cannot adopt or replace the old reservation');
    if (committed) {
      assert.deepEqual(frozenArtifact(fixture.stateRoot, retired.workerIdentityDigest!), recordedWorker,
        'the historical WorkerIdentity bytes keep the original owner and nonces');
      assert.equal(retired.processContainmentRef, held.launch.processContainmentRef);
      assert.deepEqual(frozenArtifact(fixture.stateRoot, retired.processContainmentRef!), recordedContainment);
    }
    const archived = reopened.closure.workspaceGenerations.find(generation => generation.generationRef === held.generation.generationRef)!;
    assert.equal(archived.phase, 'quarantined');
    if (archived.phase !== 'quarantined') throw new Error('successor did not quarantine the old preactivation generation');
    assert.equal(archived.rowVersion, held.generation.rowVersion + 1);
    const receipt = await successor.artifacts.readCanonical<WorkspaceGenerationQuarantineEvidenceV1>(archived.quarantineEvidenceRef);
    assert.equal(receipt.reason, expectsCreatedRetirement ? 'launch_died_before_activation' : 'launch_aborted'); assert.equal(receipt.sourceRowVersion, held.generation.rowVersion);
    assert.equal(receipt.quarantineCanonicalRootRelativePath, archiveRelativePath);
    if (postMove) {
      assert.ok(pendingReceipt && pendingReceiptRef);
      assert.notEqual(archived.quarantineEvidenceRef, pendingReceiptRef, 'successor must rebuild with its own inspector, not adopt the temporary receipt');
      assert.equal(receipt.quarantineCanonicalRootRelativePath, pendingReceipt.quarantineCanonicalRootRelativePath);
      assert.equal(receipt.sourceRowVersion, pendingReceipt.sourceRowVersion);
      assert.deepEqual(receipt.observedState, pendingReceipt.observedState);
    }
    const physical = await lstat(path.join(fixture.stateRoot, receipt.quarantineCanonicalRootRelativePath), { bigint: true });
    assert.ok(physical.isDirectory() && !physical.isSymbolicLink()); assert.equal(String(physical.dev), identity.locator.deviceId);
    assert.equal(String(physical.ino), identity.locator.directoryFileId);
    await assert.rejects(lstat(path.join(fixture.stateRoot, identity.locator.canonicalRootRelativePath)), { code: 'ENOENT' });
    const proof = await successor.artifacts.readCanonical<ProcessContainmentNoSpawnEvidenceV1 | ProcessContainmentDeathEvidenceV1>(retired.retirementEvidenceRef);
    assert.equal(proof.planRef, held.launch.containmentPlanRef);
    assert.equal(proof.sandboxLaunchSpecRef, held.launch.sandboxLaunchSpecRef); assert.equal(proof.launchNonceDigest, held.launch.spawnNonceDigest);
    assert.equal(proof.sandboxLaunchSpecDigest, spec.launchSpecDigest);
    assert.deepEqual(proof.owner, plan.owner);
    if (physicalScope) {
      assert.equal(proof.kind, 'containment_all_descendants_dead');
      if (proof.kind !== 'containment_all_descendants_dead' || proof.backend.kind !== 'linux') throw new Error('created preactivation crash lacks actual Linux created-death closure');
      assert.equal(proof.containmentRef, retired.processContainmentRef);
      const backend = {
        kind: 'linux', cgroupPath: plan.backend.cgroupPath, cgroupId: physicalScope.cgroupId,
        pidNamespaceReservationId: plan.backend.pidNamespaceReservationId, pidNamespaceId: physicalScope.pidNamespaceId,
        namespaceInitStartToken: physicalScope.namespaceInitStartToken, subreaperStartToken: plan.backend.subreaperStartToken,
        cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0
      } satisfies Extract<ProcessContainmentDeathEvidenceV1['backend'], { kind: 'linux' }>;
      assert.deepEqual(proof.backend, backend);
      const containment = decodeWorkerProcessContainment(await successor.artifacts.readCanonical(proof.containmentRef));
      assert.equal(canonicalSha256(containment), proof.containmentRef);
      if (committed) assert.deepEqual(containment, recordedContainment, 'fresh death inspection cannot replace committed birth facts');
      const { cgroupPopulated: _populated, namespaceInitDeadAndReaped: _reaped, remainingTrackedDescendants: _remaining, ...birth } = backend;
      assert.deepEqual(containment.backend, birth); assert.deepEqual(containment.owner, plan.owner);
      assert.equal(containment.planRef, held.launch.containmentPlanRef); assert.equal(containment.sandboxLaunchSpecRef, held.launch.sandboxLaunchSpecRef);
      assert.equal(containment.sandboxLaunchSpecDigest, spec.launchSpecDigest); assert.equal(containment.launchNonceDigest, held.launch.spawnNonceDigest);
      assert.deepEqual(containment.filesystemBinding, { kind: 'run-generation', generationRef: held.launch.workspaceGenerationRef });
    } else {
      assert.equal(expectsCreatedRetirement, false); assert.equal(proof.kind, 'containment_plan_quiescent');
      if (proof.kind !== 'containment_plan_quiescent' || proof.backend.kind !== 'linux') throw new Error('reserved crash lacks actual Linux no-spawn closure');
      assert.deepEqual(proof.backend, noSpawnBackend);
    }
    const metadataAfter = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    const newOwner = (() => { try { return metadataAfter.readSnapshot(connection => {
      const eventSeq = connection.prepare('SELECT max(event_seq) AS seq FROM run_events WHERE run_id=?').get<{ seq: bigint }>(fixture.runId)!.seq;
      assert.equal(eventSeq, held.eventSeq + 1n); return readLatestStateOwner(connection)!;
    }); } finally { metadataAfter.close(); } })();
    assert.ok(newOwner.ownerEpoch > held.owner.ownerEpoch); assert.notEqual(newOwner.supervisorInstanceId, held.owner.supervisorInstanceId);
    assert.equal(proof.inspectorSupervisorInstanceId, newOwner.supervisorInstanceId);
    const inspector = await successor.artifacts.readCanonical<{ supervisorInstanceId: string; stateOwnerEpoch: number }>(proof.inspectorIdentityRef);
    assert.equal(inspector.supervisorInstanceId, newOwner.supervisorInstanceId); assert.equal(inspector.stateOwnerEpoch, newOwner.ownerEpoch);
    if (monitorFork) {
      assert.ok(proof.observedAt >= newOwner.acquiredAt && proof.observedAt <= retired.retiredAt!);
      assert.ok(Date.parse(retired.retiredAt!) - Date.parse(proof.observedAt) <= 5000);
      assert.equal(receipt.inspectorIdentityRef, proof.inspectorIdentityRef); assert.equal(receipt.inspectorIdentityDigest, proof.inspectorIdentityDigest);
    }
    if (postMove) {
      assert.ok(pendingReceipt && pendingProof);
      assert.notEqual(retired.retirementEvidenceRef, pendingReceipt.containmentNoSpawnEvidenceRef);
      assert.notEqual(proof.inspectorIdentityRef, pendingProof.inspectorIdentityRef);
      assert.equal(proof.kind, 'containment_plan_quiescent');
      const { inspectorSupervisorInstanceId: _oldSupervisor, inspectorIdentityRef: _oldInspector,
        inspectorIdentityDigest: _oldInspectorDigest, observedAt: _oldTime, evidenceDigest: _oldDigest, ...oldBirth } = pendingProof;
      const { inspectorSupervisorInstanceId: _newSupervisor, inspectorIdentityRef: _newInspector,
        inspectorIdentityDigest: _newInspectorDigest, observedAt: _newTime, evidenceDigest: _newDigest, ...newBirth } = proof;
      assert.deepEqual(newBirth, oldBirth, 'fresh native inspection must preserve the exact original reservation bindings');
      assert.ok(proof.observedAt >= newOwner.acquiredAt && proof.observedAt <= retired.retiredAt!);
      assert.ok(Date.parse(retired.retiredAt!) - Date.parse(proof.observedAt) <= 5000);
      assert.equal(receipt.inspectorIdentityRef, proof.inspectorIdentityRef);
      assert.equal(receipt.inspectorIdentityDigest, proof.inspectorIdentityDigest);
    }
    const retry = await successor.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
    await bounded(retry.executeCurrentTool({ expectedRunRevision: reopened.closure.run.revision }));
    const after = await checkpointBytes(successor, fixture.runId);
    assert.deepEqual(after.bytes, Buffer.from('after\n')); assert.deepEqual(await readFile(path.join(fixture.workspace, 'a')), fixture.original);
    assert.equal(after.closure.run.id, held.run.id); assert.equal(after.closure.run.status, 'queued');
    assert.equal(after.closure.run.leaseEpoch, held.run.leaseEpoch + 1);
    assert.equal(after.closure.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'dispatch_claimed').length, 1);
    assert.equal(after.closure.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'completed').length, 1);
    assert.deepEqual(after.closure.run.budgetConsumed, { ...held.run.budgetConsumed, toolCalls: held.run.budgetConsumed.toolCalls + 1 });
    assert.deepEqual(after.closure.run.budgetReserved, held.run.budgetReserved);
    const replacements = inspection.readSnapshot(connection => readWorkerLaunchesForRun(connection, fixture.runId))
      .filter(launch => launch.leaseEpoch === after.closure.run.leaseEpoch);
    assert.deepEqual(inspection.readSnapshot(connection => readRequiredWorkerLaunch(connection, held.launch.launchId)), retired,
      'the distinct retry cannot replace or mutate the retired preactivation history');
    if (committed) {
      assert.deepEqual(frozenArtifact(fixture.stateRoot, retired.workerIdentityDigest!), recordedWorker);
      assert.deepEqual(frozenArtifact(fixture.stateRoot, retired.processContainmentRef!), recordedContainment);
    }
    assert.equal(replacements.length, 1); const replacement = replacements[0]!; assert.equal(replacement.phase, 'retired');
    for (const field of ['launchId', 'workspaceGenerationRef', 'spawnNonceDigest', 'activationNonceDigest'] as const) {
      assert.notEqual(replacement[field], held.launch[field]);
    }
    const nextGeneration = frozenArtifact<WorkspaceGenerationIdentityV1>(fixture.stateRoot, replacement.workspaceGenerationRef);
    if (nextGeneration.locator.kind !== 'linux_directory') throw new Error('retry did not create its distinct actual generation');
    assert.notEqual(nextGeneration.locator.directoryFileId, identity.locator.directoryFileId);
    const archive = await open(path.join(fixture.stateRoot, receipt.quarantineCanonicalRootRelativePath),
      fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try {
      const retained = await archive.stat({ bigint: true }); assert.equal(retained.dev, physical.dev); assert.equal(retained.ino, physical.ino);
      const file = await open(`/proc/self/fd/${archive.fd}/a`, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      try { assert.deepEqual(await file.readFile(), fixture.original, 'retry cannot edit the old quarantined generation'); }
      finally { await file.close(); }
    } finally { await archive.close(); }
    console.log(JSON.stringify({ scenario: `actual-supervisor-crash-${boundary.replaceAll('_', '-')}`, supervisorPid: supervisor.pid,
      supervisorStartToken: supervisorIdentity.processStartToken, signal: 'SIGKILL', controllerPid, controllerStartToken: controllerToken,
      ...(physicalScope ? { actualWorkerPid: physicalScope.workerPid, actualWorkerStartToken: physicalScope.workerToken,
        actualInitPid: physicalScope.initPid, actualInitStartToken: physicalScope.initToken,
        actualMonitorPid: physicalScope.monitorPid, actualMonitorStartToken: physicalScope.monitorToken,
        birthObservation: physicalScope.birthObservation } : {}),
      priorOwnerEpoch: held.owner.ownerEpoch, successorOwnerEpoch: newOwner.ownerEpoch, oldLaunchId: retired.launchId,
      newLaunchId: replacement.launchId, oldGenerationRef: held.generation.generationRef, newGenerationRef: replacement.workspaceGenerationRef,
      sourceRowVersion: held.generation.rowVersion, nativeEffectCount: 1, permanentToolClaims: 1,
      ...(committed ? { interruptedTransaction: 'activation-begun-before-any-write' } : {}),
      ...(postMove ? { interruptedPublication: 'canonical-quarantine-written-before-cas-publication', priorQuarantineRef: pendingReceiptRef,
        successorQuarantineRef: archived.quarantineEvidenceRef, priorProofRef: pendingReceipt!.containmentNoSpawnEvidenceRef,
        successorProofRef: retired.retirementEvidenceRef, actualReadFaults: 1 } : {}),
      ...(monitorFork ? { interruptedBirth: 'actual-controller-monitor-fork-before-monitor-record-or-READY',
        forkWitnessBytes: 2336, completedWitnessBytes: 4768, independentLiveWorkerPid2AtCrash: false } : {}),
      note: `actual ${monitorFork ? 'monitor fork with original C/M trace-stopped, then Supervisor SIGKILL and M-to-C detach with signal 0' : postMove ? 'sealed-image EIO then quarantine temp write before publication' : committed ? 'committed preactivation and real clock sample inside unwritten activation transaction' : 'signed held-image read'}; fresh successor ${expectsCreatedRetirement ? 'whole-created-death' : 'no-spawn'} closure` }));
    await successor.close(); successor = undefined; resourcesRetired = true;
  } catch (error) { operationFailure = { error }; throw error; }
  finally {
    const failures: unknown[] = [];
    removeHintListener?.();
    try {
      if (child?.exitCode === null && child.signalCode === null) assert.ok(child.kill('SIGKILL'));
    } catch (error) { failures.push(error); resourcesRetired = false; }
    try { if (exited) { await bounded(exited); supervisorJoined = true; } }
    catch (error) { failures.push(error); resourcesRetired = false; }
    try {
      if (refusedOwner?.exitCode === null && refusedOwner.signalCode === null) assert.ok(refusedOwner.kill('SIGKILL'));
    } catch (error) { failures.push(error); resourcesRetired = false; }
    try { if (refusedOwnerExit) await bounded(refusedOwnerExit); }
    catch (error) { failures.push(error); resourcesRetired = false; }
    // Never resume an attached controller while its Supervisor is still alive.
    // Even after a primary failure, independently join it before attempting
    // bounded M-to-C signal-zero detach; uncertainty retains the fixture.
    try { if (tracer) {
      assert.ok(supervisorJoined, 'cannot release native fork attachments before the Supervisor is actually joined');
      await releaseForkTracer(tracer); tracer = undefined;
    } }
    catch (error) { failures.push(error); resourcesRetired = false; }
    try { if (retainedWitness) { await retainedWitness.close(); retainedWitness = undefined; } }
    catch (error) { failures.push(error); resourcesRetired = false; }
    try { if (tracerDirectory) { await rm(tracerDirectory, { recursive: true, force: true }); tracerDirectory = undefined; } }
    catch (error) { failures.push(error); resourcesRetired = false; }
    try { history?.close(); } catch (error) { failures.push(error); resourcesRetired = false; }
    if (successor) {
      try { await successor.close(); resourcesRetired = operationFailure === undefined && failures.length === 0; }
      catch (error) { failures.push(error); resourcesRetired = false; }
    }
    if (!negative && resourcesRetired) {
      try { await fixture.dispose(); } catch (error) { failures.push(error); }
    } else console.error(`preserving ${negativeQualified ? 'qualified invalid-birth refusal' : 'uncertain'} ${scenarioBoundary}-crash fixture: ${fixture.stateRoot}`);
    if (failures.length !== 0) throw new AggregateError([...(operationFailure ? [operationFailure.error] : []), ...failures], 'preactivation crash campaign and cleanup failures');
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
  ['supervisor-crash-reserved-before-create', () => supervisorCrashPreactivation('reserved_before_create')],
  ['supervisor-crash-ready-before-identity', () => supervisorCrashPreactivation('ready_before_identity')],
  ['supervisor-crash-preactivated-before-activation', () => supervisorCrashPreactivation('preactivated_before_activation')],
  ['supervisor-crash-queued-post-move-before-retirement', () => supervisorCrashPreactivation('queued_post_move_before_retirement')],
  ['supervisor-crash-monitor-fork-before-ready', () => supervisorCrashPreactivation('monitor_fork_before_ready')],
  ['supervisor-crash-monitor-fork-controller-loss', () => supervisorCrashPreactivation('monitor_fork_controller_loss')],
  ['supervisor-crash-corrupt-ready-footer', () => supervisorCrashPreactivation('ready_before_identity', 'corrupt_ready_footer')],
  ['supervisor-crash-witness-missing', () => supervisorCrashPreactivation('ready_before_identity', 'missing')],
  ['supervisor-crash-witness-replaced-inode', () => supervisorCrashPreactivation('ready_before_identity', 'replaced_inode')],
  ['controller-loss-retirement-failure', () => retirementFailureKeepsOwner('controller_loss')],
  ['edit-ready-checkpoint', editedCheckpoint],
  ['expired-final-death-publication', expiredFinalDeathPublication],
  ['slow-tool-seal-reobserves-paused-controller', slowToolSealReobservesPausedController],
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
