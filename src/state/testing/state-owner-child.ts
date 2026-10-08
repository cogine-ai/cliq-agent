import { loadNativeStateOwner, type HeldStateOwnerLock } from '../native-owner.js';
import { openStateStore, type StateStore, type StateStoreRuntimeAuthority } from '../store.js';
import { createAgentFixture } from './agent-fixtures.js';
import { mock } from 'node:test';
import { batch, prepareTool, claimTool } from './tool-calls.js';
import type { WorkerDeathWait, WorkspaceGenerationIdentityV1 } from '../../kernel/types.js';

// Test-only IPC barrier: no sleeps, inherited descriptors, or simulated locks.
const stateRoot = process.argv[2]!;
const native = await loadNativeStateOwner();
let held: StateStore | HeldStateOwnerLock | undefined;
let clockNow: number | undefined;
process.on('message', async (message: string | { command: string; authority?: StateStoreRuntimeAuthority;
  generation?: WorkspaceGenerationIdentityV1; sourceRowVersion?: number; clockNow?: number; runId?: string; expectedRunRevision?: number }) => {
  const command = typeof message === 'string' ? message : message.command;
  try {
    if (typeof message !== 'string' && message.clockNow !== undefined) {
      if (!Number.isSafeInteger(message.clockNow)) throw new Error('invalid test clock');
      if (clockNow === undefined) mock.method(Date, 'now', () => clockNow!);
      clockNow = message.clockNow;
    }
    if (command === 'acquire') {
      if (held) throw new Error('test child already holds an owner');
      if (process.argv[3] === 'fixture' || process.argv[3] === 'fixture_prepared' || process.argv[3] === 'fixture_probe') {
        process.chdir(stateRoot);
        const fixture = await createAgentFixture('takeover', undefined, { mode: 'default' });
        held = fixture.store;
        if (process.argv[3] === 'fixture_probe') {
          const waiting = await held.beginWorkerRecovery({ runId: fixture.runId, expectedRunRevision: held.getRun(fixture.runId).revision });
          const probing = await held.beginWorkerRecoveryProbe({ runId: fixture.runId, expectedRunRevision: waiting.revision });
          process.send!({ state: 'held', epoch: held.ownerEpoch, pid: process.pid, token: native.processStartToken(),
            authority: fixture.runtimeAuthority, stateRoot: fixture.stateRoot, runId: fixture.runId, launchId: fixture.launchId,
            runRevision: probing.revision, waitingOnRef: probing.waitingOnRef,
            wait: await held.artifacts.readCanonical<WorkerDeathWait>(probing.waitingOnRef!),
            leaseEpoch: fixture.leaseEpoch, leaseVersion: fixture.leaseVersion });
          return;
        }
        await batch(fixture, [{ name: 'read', input: { path: 'a' } }]);
        const prepared = await prepareTool(fixture);
        if (process.argv[3] === 'fixture') await claimTool(fixture, prepared);
        process.send!({ state: 'held', epoch: held.ownerEpoch, pid: process.pid, token: native.processStartToken(),
          authority: fixture.runtimeAuthority,
          stateRoot: fixture.stateRoot, runId: fixture.runId, launchId: fixture.launchId,
          runRevision: prepared.run.revision, leaseEpoch: fixture.leaseEpoch, leaseVersion: fixture.leaseVersion });
        return;
      }
      held = process.argv[3] === 'native' ? native.acquireLock(stateRoot, true)
        : await openStateStore(stateRoot, typeof message === 'string' ? undefined : message.authority);
      process.send!({ state: 'held', pid: process.pid, token: native.processStartToken(),
        epoch: 'ownerEpoch' in held ? held.ownerEpoch : undefined });
    } else if (command === 'close-and-begin-probe' && held && 'ownerEpoch' in held && typeof message !== 'string') {
      const store = held;
      // Both public calls start in this turn, before either asynchronous operation can finish.
      const closing = store.close();
      const probing = store.beginWorkerRecoveryProbe({ runId: message.runId!, expectedRunRevision: message.expectedRunRevision! });
      const [close, probe] = await Promise.allSettled([closing, probing]);
      const code = (result: PromiseSettledResult<unknown>) => result.status === 'rejected' &&
        result.reason !== null && typeof result.reason === 'object' && 'code' in result.reason ? result.reason.code : undefined;
      const run = store.getRun(message.runId!);
      process.send!({ state: 'close-and-probe', closeCode: code(close), probeCode: code(probe),
        runRevision: run.revision, waitingOnRef: run.waitingOnRef,
        wait: await store.artifacts.readCanonical<WorkerDeathWait>(run.waitingOnRef!) });
    } else if ((command === 'close-probe' || command === 'begin-probe') && held && 'ownerEpoch' in held && typeof message !== 'string') {
      const input = { runId: message.runId!, expectedRunRevision: message.expectedRunRevision! };
      const run = command === 'close-probe' ? await held.closeWorkerRecoveryProbe(input) : await held.beginWorkerRecoveryProbe(input);
      process.send!({ state: 'probed', runRevision: run.revision, waitingOnRef: run.waitingOnRef,
        wait: await held.artifacts.readCanonical<WorkerDeathWait>(run.waitingOnRef!) });
    } else if (command === 'quarantine' && held && 'quarantineGeneration' in held && typeof message !== 'string') {
      held.quarantineGeneration(message.generation!, message.sourceRowVersion!);
      process.send!({ state: 'quarantined' });
    } else if (command === 'close') {
      await held?.close();
      held = undefined;
      process.send!({ state: 'released' });
    } else if (command === 'drop-lock' && held && 'ownerEpoch' in held) {
      // Deliberately violate lifecycle only in this disposable test process:
      // a free lock must not authorize takeover while its exact owner is alive.
      (held as unknown as { owner: { filesystem: HeldStateOwnerLock } }).owner.filesystem.close();
      process.send!({ state: 'released' });
    } else {
      throw new Error('unknown test command');
    }
  } catch (error) {
    process.send!({ state: 'error', message: error instanceof Error ? error.message : String(error),
      code: error !== null && typeof error === 'object' && 'code' in error ? error.code : undefined });
  }
});
process.on('disconnect', () => process.exit(0));
process.send!({ state: 'ready' });
