import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsPromises, { open, type FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { inspect } from 'node:util';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { digestOmitting, identityHash } from '../../src/kernel/identity.js';
import type { ToolContractManifestV1, WorkerDeathWait, WorkerIdentity, WorkspaceGenerationIdentityV1,
  WorkspaceGenerationQuarantineEvidenceV1, WorkspaceGenerationStateV1 } from '../../src/kernel/types.js';
import type { RunAssemblyValidationMaterial, RunAssemblyToolAuthority } from '../../src/model/run-assembly.js';
import { testFixture } from '../../src/model/testing/fixtures.js';
import { decodeWorkerIdentity } from '../../src/state/decoders.js';
import { ResourceRetirementError } from '../../src/state/errors.js';
import { decodeWorkerProcessContainment } from '../../src/state/execution-closure.js';
import { readRequiredWorkerLaunch } from '../../src/state/repositories/worker-launches.js';
import { openSqliteDriver } from '../../src/state/sqlite-driver.js';
import { openStateStore, type StateStoreRuntimeAuthority } from '../../src/state/store.js';

export type CrashChildInput = {
  stateRoot: string; runId: string; runtimeAuthority: StateStoreRuntimeAuthority;
  retirementFault?: 'pre_probe' | 'timeout_closure' | 'controller_loss';
  materialData: Omit<RunAssemblyValidationMaterial, 'resolveVerifiedCapabilityClaims' | 'verifyLocalZeroCostAuthority' |
    'resolvePriceTableAuthority' | 'resolveVerifiedTools' | 'verifyReference' | 'verifyProviderAdapter' | 'verifyProviderEndpoint'>;
};
export type CrashChildPaused = { state: 'post_move_pre_cas'; runId: string; waitingOnRef: string;
  generationRef: string; sourceRowVersion: number; archiveRelativePath: string; archiveDevice: string; archiveInode: string;
  quarantineArtifactRef: string };
export type CrashChildRetirementRefused = { state: 'retirement_close_refused'; runId: string;
  fault: Exclude<NonNullable<CrashChildInput['retirementFault']>, 'controller_loss'>; waitingOnRef: string; probePhase: string;
  closeCode: 'RECOVERY_REQUIRED'; actualCloseFaults: 1 };
export type CrashChildControllerLossRefused = { state: 'controller_loss_close_refused'; runId: string;
  fault: 'controller_loss'; waitingOnRef: string; probePhase: 'automatic_pending'; runRevision: number;
  closeCode: 'RECOVERY_REQUIRED'; actualReadFaults: 1; primaryCode: 'EIO';
  controllerPid: number; controllerStartToken: string };

if (process.platform !== 'linux' || !process.send) throw new Error('real Linux crash child requires Linux and parent IPC');

function artifact<T>(root: string, ref: string): T {
  assert.match(ref, /^[0-9a-f]{64}$/u);
  const fd = fs.openSync(path.join(root, KERNEL_CAS_DIRECTORY, ref), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    assert.ok(before.isFile() && before.nlink === 1n && before.size <= 1024n * 1024n && (before.mode & 0o7777n) === 0o400n);
    const bytes = fs.readFileSync(fd), value: unknown = JSON.parse(bytes.toString('utf8'));
    assert.deepEqual(bytes, canonicalJsonBytes(value)); assert.equal(canonicalSha256(value), ref);
    const after = fs.fstatSync(fd, { bigint: true });
    assert.equal(after.dev, before.dev); assert.equal(after.ino, before.ino); assert.equal(after.size, before.size);
    assert.equal(after.mtimeNs, before.mtimeNs); assert.equal(after.ctimeNs, before.ctimeNs);
    return value as T;
  } finally { fs.closeSync(fd); }
}

function token(pid: number): string {
  const line = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
  const fields = line.slice(line.lastIndexOf(')') + 2).trim().split(/\s+/u);
  assert.notEqual(fields[0], 'Z'); assert.match(fields[19]!, /^[0-9]+$/u);
  return `linux-proc-start-ticks:${fields[19]}`;
}

async function run(input: CrashChildInput) {
  const store = await openStateStore(input.stateRoot, input.runtimeAuthority);
  const before = await store.readRecoveryClosure(input.runId);
  const assembly = await store.artifacts.readCanonical<{ tools: { manifestRef: string; manifestDigest: string } }>(before.runSpec.assemblyRef);
  const manifest = await store.artifacts.readCanonical<ToolContractManifestV1>(assembly.tools.manifestRef);
  assert.equal(canonicalSha256(manifest), assembly.tools.manifestRef);
  assert.equal(manifest.manifestDigest, assembly.tools.manifestDigest);
  assert.equal(digestOmitting(manifest, 'manifestDigest'), manifest.manifestDigest);
  assert.equal(manifest.entries.length, 1); assert.equal(manifest.entries[0]!.name, 'edit');
  const tools: RunAssemblyToolAuthority[] = [];
  for (const entry of manifest.entries) {
    const inputSchema = await store.artifacts.readCanonical<RunAssemblyToolAuthority['inputSchema']>(entry.inputSchemaRef);
    assert.equal(canonicalSha256(inputSchema), entry.inputSchemaRef); assert.equal(entry.inputSchemaDigest, entry.inputSchemaRef);
    tools.push({ name: entry.name, description: entry.description, replayClass: entry.replayClass,
      inputSchemaRef: entry.inputSchemaRef, inputSchemaDigest: entry.inputSchemaDigest, inputSchema });
  }
  // Only the already-declared offline admission resolvers are reconstructed.
  // Runtime signatures are the parent's original bytes; tool resolution is
  // restricted to the exact retained manifest and independently rehashed schemas.
  const material: RunAssemblyValidationMaterial = { ...testFixture().material, ...input.materialData,
    resolveVerifiedTools: reference => canonicalSha256(reference) === canonicalSha256(assembly.tools) ? tools : null };
  const execution = await store.loadRunExecution({ runId: input.runId, material });
  const metadata = openSqliteDriver(path.join(input.stateRoot, KERNEL_DATABASE_FILENAME));
  const sample = await open(path.join(input.stateRoot, KERNEL_CAS_DIRECTORY, before.runSpec.policyRef), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  const policy = await sample.stat({ bigint: true });
  const prototype = Object.getPrototypeOf(sample) as Pick<FileHandle, 'readFile' | 'writeFile'>;
  const originalRead = prototype.readFile, originalWrite = prototype.writeFile, originalOpen = fsPromises.open;
  await sample.close();
  let processLossInjected = false, paused = false;
  let controllerLoss: { pid: number; processStartToken: string } | undefined;
  const primary = Object.assign(new Error('campaign real CAS read failure after actual controller SIGKILL'), { code: 'EIO' });
  let controllerReadFaults = 0, retainedFailure: ResourceRetirementError | undefined;
  let operationFailure: { error: unknown } | undefined;
  try {
    prototype.readFile = (async function(this: FileHandle, ...args: unknown[]) {
      const bytes: unknown = await Reflect.apply(originalRead, this, args);
      if (!processLossInjected && Buffer.isBuffer(bytes)) {
        const held = fs.fstatSync(this.fd, { bigint: true });
        if (held.dev === policy.dev && held.ino === policy.ino) {
          const launch = metadata.readSnapshot(connection => {
            const active = connection.prepare('SELECT active_worker_launch_id FROM runs WHERE id=?')
              .get<{ active_worker_launch_id: string | null }>(input.runId);
            const count = connection.prepare("SELECT COUNT(*) AS count FROM run_journal WHERE run_id=? AND op_kind='tool'")
              .get<{ count: bigint }>(input.runId)!.count;
            return active?.active_worker_launch_id && count === 0n ? readRequiredWorkerLaunch(connection, active.active_worker_launch_id) : undefined;
          });
          if (launch?.phase === 'activated') {
            assert.equal(canonicalSha256(JSON.parse(bytes.toString('utf8'))), before.runSpec.policyRef);
            const worker = decodeWorkerIdentity(artifact<WorkerIdentity>(input.stateRoot, launch.workerIdentityDigest!));
            assert.equal(worker.launchId, launch.launchId); assert.equal(token(worker.pid), worker.processStartToken);
            if (input.retirementFault === 'controller_loss') {
              assert.equal(worker.processContainmentRef, launch.processContainmentRef);
              const containment = decodeWorkerProcessContainment(artifact(input.stateRoot, launch.processContainmentRef!));
              assert.equal(containment.owner.kind, 'worker_activation');
              if (containment.backend.kind !== 'linux') throw new Error('controller fault lacks actual Linux containment');
              const match = /^linux-subreaper:([1-9][0-9]*):(linux-proc-start-ticks:[0-9]+)$/u.exec(containment.backend.subreaperStartToken);
              assert.ok(match, 'controller PID/token must come from the exact retained native containment');
              const pid = Number(match[1]), processStartToken = match[2]!;
              assert.ok(Number.isSafeInteger(pid) && pid > 0 && pid !== process.pid && pid !== worker.pid);
              assert.equal(token(pid), processStartToken);
              process.kill(pid, 'SIGKILL');
              controllerLoss = { pid, processStartToken }; processLossInjected = true; controllerReadFaults++;
              throw primary;
            }
            process.kill(worker.pid, 'SIGKILL'); processLossInjected = true;
            throw Object.assign(new Error('campaign OS-boundary CAS read failure after actual worker SIGKILL'), { code: 'EIO' });
          }
        }
      }
      return bytes;
    }) as FileHandle['readFile'];
    await assert.rejects(execution.executeCurrentTool({ expectedRunRevision: before.run.revision }), error => {
      if (input.retirementFault !== 'controller_loss') return true;
      // The old implementation rejects with only the secondary native stop
      // error, losing this exact primary and the retirement trait.
      assert.ok(error instanceof ResourceRetirementError);
      assert.ok(error.cause instanceof AggregateError);
      assert.equal(error.cause.errors.length, 2);
      assert.equal(error.cause.errors[0], primary);
      const cleanup: unknown = error.cause.errors[1];
      assert.ok(cleanup instanceof Error && cleanup !== primary);
      assert.match(cleanup.message, /native|controller|scope|containment/iu);
      retainedFailure = error;
      return true;
    });
    assert.ok(processLossInjected, 'missing real activated/no-invocation process-loss fault is not a pass');
    prototype.readFile = originalRead;
    const waiting = await store.readRecoveryClosure(input.runId);
    const initialWait = await store.artifacts.readCanonical<WorkerDeathWait>(waiting.run.waitingOnRef!);
    assert.deepEqual(initialWait.subject.openInvocationRefs, []); assert.equal(waiting.journal.filter(row => row.opKind === 'tool').length, 0);
    if (input.retirementFault === 'controller_loss') {
      assert.ok(controllerLoss && retainedFailure);
      assert.equal(controllerReadFaults, 1); assert.equal(initialWait.probeState.phase, 'automatic_pending');
      assert.equal(initialWait.probeState.automaticProbeCount, 0); assert.equal(initialWait.probeState.userProbeCount, 0);
      assert.equal(waiting.run.revision, before.run.revision + 2, 'activation and worker-loss fencing each advance the Run once');
      assert.deepEqual(waiting.run.budgetConsumed, before.run.budgetConsumed);
      // The OS read hook is gone. Both public shutdown attempts must retain
      // the same aggregate object, not just rethrow a new similar message.
      await assert.rejects(store.close(), error => error === retainedFailure);
      await assert.rejects(store.close(), error => error === retainedFailure);
      assert.deepEqual(store.getRun(input.runId), waiting.run);
      const message: CrashChildControllerLossRefused = { state: 'controller_loss_close_refused', runId: input.runId,
        fault: 'controller_loss', waitingOnRef: waiting.run.waitingOnRef!, probePhase: 'automatic_pending', runRevision: waiting.run.revision,
        closeCode: 'RECOVERY_REQUIRED', actualReadFaults: 1, primaryCode: 'EIO',
        controllerPid: controllerLoss.pid, controllerStartToken: controllerLoss.processStartToken };
      process.channel?.ref(); process.send!(message);
      await new Promise<never>(() => {});
    }
    if (input.retirementFault && input.retirementFault !== 'controller_loss') {
      assert.equal(initialWait.probeState.phase, 'automatic_pending');
      const failure = Object.assign(new Error('campaign uncertainty after the actual CAS FileHandle.close'), { code: 'EIO' });
      let closeFaults = 0, closeSelected = false;
      const injectClose = () => {
        // close is an own FileHandle field, not a prototype method. Wrap the
        // exact actual policy handle, and inject only after its real close.
        fsPromises.open = (async (...args: Parameters<typeof open>) => {
          const handle = await originalOpen(...args);
          const held = fs.fstatSync(handle.fd, { bigint: true });
          if (held.dev === policy.dev && held.ino === policy.ino) {
            const actualClose = handle.close.bind(handle);
            handle.close = async () => {
              const selected = !closeSelected;
              if (selected) closeSelected = true;
              await actualClose();
              if (selected) { closeFaults++; throw failure; }
            };
          }
          return handle;
        }) as typeof open;
      };
      const isRetirement = (error: unknown) => error instanceof ResourceRetirementError && error.cause === failure;
      if (input.retirementFault === 'pre_probe') {
        injectClose();
        await assert.rejects(execution.recoverWorker({ expectedRunRevision: waiting.run.revision }), isRetirement);
        fsPromises.open = originalOpen;
        assert.equal(store.getRun(input.runId).waitingOnRef, waiting.run.waitingOnRef,
          'the real CAS retirement failure happened before a probe dispatch was registered');
      } else {
        // A normal OS read failure ends one genuinely registered task. It is
        // not cleanup uncertainty, and its original work/resources can join.
        let readFaulted = false;
        prototype.readFile = (async function(this: FileHandle, ...args: unknown[]) {
          const bytes: unknown = await Reflect.apply(originalRead, this, args);
          const held = fs.fstatSync(this.fd, { bigint: true });
          if (!readFaulted && held.dev === policy.dev && held.ino === policy.ino) {
            const current = store.getRun(input.runId);
            const wait = artifact<WorkerDeathWait>(input.stateRoot, current.waitingOnRef!);
            if (wait.probeState.phase === 'automatic_in_flight') {
              readFaulted = true;
              throw Object.assign(new Error('campaign real CAS read fault after task registration'), { code: 'EIO' });
            }
          }
          return bytes;
        }) as FileHandle['readFile'];
        await assert.rejects(execution.recoverWorker({ expectedRunRevision: waiting.run.revision }),
          error => !(error instanceof ResourceRetirementError));
        prototype.readFile = originalRead;
        assert.ok(readFaulted, 'missing actual registered-task read fault is not coverage');
        const current = store.getRun(input.runId);
        const wait = artifact<WorkerDeathWait>(input.stateRoot, current.waitingOnRef!);
        if (wait.probeState.phase !== 'automatic_in_flight') throw new Error('timeout fault needs its actual registered task');
        // Use the real stored wall-clock deadline, never a mocked future time.
        while (Date.now() < Date.parse(wait.probeState.dispatch.probeDeadlineAt)) {
          await delay(Math.max(1, Date.parse(wait.probeState.dispatch.probeDeadlineAt) - Date.now()));
        }
        injectClose();
        await assert.rejects(store.closeWorkerRecoveryProbe({ runId: input.runId, expectedRunRevision: current.revision }), isRetirement);
        fsPromises.open = originalOpen;
        assert.equal(store.getRun(input.runId).waitingOnRef, current.waitingOnRef,
          'the failed timeout read must not commit a successful cancellation closure');
      }
      assert.equal(closeFaults, 1);
      const retained = store.getRun(input.runId);
      const retainedWait = artifact<WorkerDeathWait>(input.stateRoot, retained.waitingOnRef!);
      assert.equal(retainedWait.probeState.phase, input.retirementFault === 'pre_probe' ? 'automatic_pending' : 'automatic_in_flight');
      // Regression expectation on the unfixed implementation: this first
      // shutdown unexpectedly succeeds, releasing the actual StateOwner lock.
      // Removing the OS fault must not erase a previously uncertain retirement.
      await assert.rejects(store.close(), isRetirement);
      await assert.rejects(store.close(), isRetirement);
      assert.equal(store.getRun(input.runId).waitingOnRef, retained.waitingOnRef);
      const message: CrashChildRetirementRefused = { state: 'retirement_close_refused', runId: input.runId,
        fault: input.retirementFault, waitingOnRef: retained.waitingOnRef!, probePhase: retainedWait.probeState.phase,
        closeCode: 'RECOVERY_REQUIRED', actualCloseFaults: 1 };
      process.channel?.ref();
      process.send!(message);
      // The parent tests the actual live flock before SIGKILL. No retry,
      // synthetic receipt or GC finalizer is permitted to release this owner.
      await new Promise<never>(() => {});
    }
    prototype.writeFile = (async function(this: FileHandle, data: unknown, ...args: unknown[]) {
      let value: unknown;
      if (Buffer.isBuffer(data)) { try { value = JSON.parse(data.toString('utf8')); } catch { /* Other actual CAS chunks. */ } }
      const candidate = value as Partial<WorkspaceGenerationQuarantineEvidenceV1> | undefined;
      if (!paused && candidate?.format === 'cliq-workspace-generation-quarantine-evidence-v1' && candidate.runId === input.runId) {
        const receipt = candidate as WorkspaceGenerationQuarantineEvidenceV1;
        assert.deepEqual(data, canonicalJsonBytes(receipt));
        assert.equal(receipt.evidenceDigest, digestOmitting(receipt, 'evidenceDigest'));
        const cut = await store.readRecoveryClosure(input.runId);
        const wait = await store.artifacts.readCanonical<WorkerDeathWait>(cut.run.waitingOnRef!);
        if (wait.probeState.phase !== 'automatic_in_flight' || wait.probeState.dispatch.subjectKind !== 'worker_recovery') {
          throw new Error('crash target lacks the exact persisted worker inspection');
        }
        assert.equal(wait.probeState.dispatch.owningSupervisorInstanceId,
          artifact<{ supervisorInstanceId: string }>(input.stateRoot, receipt.inspectorIdentityRef).supervisorInstanceId);
        const anchor = artifact<WorkspaceGenerationStateV1>(input.stateRoot, wait.probeState.dispatch.inspectionTargetDigest);
        const sourceRowVersion = anchor.rowVersion + 1;
        assert.equal(receipt.sourceRowVersion, sourceRowVersion); assert.equal(receipt.generationRef, anchor.generationRef);
        const generation = artifact<WorkspaceGenerationIdentityV1>(input.stateRoot, anchor.generationRef);
        if (generation.locator.kind !== 'linux_directory') throw new Error('crash target is not a real Linux generation');
        assert.equal(receipt.quarantineCanonicalRootRelativePath,
          `quarantine/workspace-generations/${identityHash(generation.generationId, String(sourceRowVersion))}`);
        const originalRelativePath = generation.locator.canonicalRootRelativePath;
        assert.throws(() => fs.lstatSync(path.join(input.stateRoot, originalRelativePath)), { code: 'ENOENT' });
        const archive = fs.lstatSync(path.join(input.stateRoot, receipt.quarantineCanonicalRootRelativePath), { bigint: true });
        assert.ok(archive.isDirectory() && !archive.isSymbolicLink());
        assert.equal(String(archive.dev), generation.locator.deviceId); assert.equal(String(archive.ino), generation.locator.directoryFileId);
        assert.equal(receipt.quarantineDeviceId, String(archive.dev)); assert.equal(receipt.quarantineFileId, String(archive.ino));
        assert.equal(cut.workspaceGenerations.find(row => row.generationRef === anchor.generationRef)!.phase, 'fenced_reconciling');
        const fdPath = fs.readlinkSync(`/proc/self/fd/${this.fd}`);
        assert.equal(path.dirname(fdPath), path.join(input.stateRoot, KERNEL_CAS_DIRECTORY));
        assert.match(path.basename(fdPath), /^\.tmp-stream-[0-9a-f]{32}$/u);
        assert.equal(fs.fstatSync(this.fd).size, 0, 'pause before the quarantine receipt first byte');
        const quarantineArtifactRef = canonicalSha256(receipt);
        assert.throws(() => fs.lstatSync(path.join(input.stateRoot, KERNEL_CAS_DIRECTORY, quarantineArtifactRef)), { code: 'ENOENT' });
        paused = true;
        const message: CrashChildPaused = { state: 'post_move_pre_cas', runId: input.runId, waitingOnRef: cut.run.waitingOnRef!,
          generationRef: anchor.generationRef, sourceRowVersion, archiveRelativePath: receipt.quarantineCanonicalRootRelativePath,
          archiveDevice: String(archive.dev), archiveInode: String(archive.ino), quarantineArtifactRef };
        process.send!(message);
        // Suspend this one real OS write. Do not return invented bytes/evidence;
        // the parent independently observes the cut and SIGKILLs this process.
        await new Promise<never>(() => {});
      }
      return Reflect.apply(originalWrite, this, [data, ...args]);
    }) as FileHandle['writeFile'];
    await execution.recoverWorker({ expectedRunRevision: waiting.run.revision });
    throw new Error('recovery completed without the required post-move/pre-CAS crash boundary');
  } catch (error) {
    operationFailure = { error };
    throw error;
  } finally {
    prototype.readFile = originalRead; prototype.writeFile = originalWrite; fsPromises.open = originalOpen;
    const cleanupFailures: unknown[] = [];
    try { metadata.close(); } catch (error) { cleanupFailures.push(error); }
    try { await store.close(); } catch (error) { cleanupFailures.push(error); }
    if (cleanupFailures.length > 0) {
      const cleanup = cleanupFailures.length === 1 ? cleanupFailures[0]
        : new AggregateError(cleanupFailures, 'crash child metadata and Store cleanup failed');
      if (operationFailure) throw new AggregateError([operationFailure.error, cleanup], 'crash child operation and cleanup both failed');
      throw cleanup;
    }
  }
}

process.once('message', (message: CrashChildInput) => {
  void run(message).catch(error => {
    const diagnostic = inspect(error, { depth: 8 }).slice(0, 8192);
    console.error(diagnostic);
    process.send!({ state: 'error', message: diagnostic }, () => process.exit(1));
  });
});
process.send({ state: 'ready' });
