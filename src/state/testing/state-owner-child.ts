import { loadNativeStateOwner, type HeldStateOwnerLock } from '../native-owner.js';
import { openStateStore, type StateStore, type StateStoreRuntimeAuthority } from '../store.js';
import { createActiveFixture, digest } from './fixtures.js';

// Test-only IPC barrier: no sleeps, inherited descriptors, or simulated locks.
const stateRoot = process.argv[2]!;
const native = await loadNativeStateOwner();
let held: StateStore | HeldStateOwnerLock | undefined;
process.on('message', async (message: string | { command: string; authority: StateStoreRuntimeAuthority }) => {
  const command = typeof message === 'string' ? message : message.command;
  try {
    if (command === 'acquire') {
      if (held) throw new Error('test child already holds an owner');
      if (process.argv[3] === 'fixture') {
        process.chdir(stateRoot);
        const fixture = await createActiveFixture('takeover');
        held = fixture.store;
        const request = await held.artifacts.publishCanonical({ schemaVersion: 1, input: 'offline' }, 'cliq-test-request-v1');
        const prepared = await held.prepareInvocation({ runId: fixture.runId, expectedRunRevision: fixture.runRevision,
          leaseEpoch: fixture.leaseEpoch, opId: 'unclaimed', opKind: 'tool', target: 'test.read', requestRef: request.ref,
          replayClass: 'retry', reservation: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 } });
        const second = await held.prepareInvocation({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
          leaseEpoch: fixture.leaseEpoch, opId: 'claimed', opKind: 'tool', target: 'test.read', requestRef: request.ref,
          replayClass: 'manual', reservation: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 } });
        await held.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: second.run.revision,
          leaseEpoch: fixture.leaseEpoch, opId: 'claimed', attempt: 0, dispatchId: 'old-owner-dispatch',
          brokerFenceTokenDigest: digest('old-owner-fence') });
        process.send!({ state: 'held', epoch: held.ownerEpoch, pid: process.pid, token: native.processStartToken(),
          stateRoot: fixture.stateRoot, runId: fixture.runId, launchId: fixture.launchId,
          runRevision: second.run.revision, leaseEpoch: fixture.leaseEpoch, leaseVersion: fixture.leaseVersion });
        return;
      }
      held = process.argv[3] === 'native' ? native.acquireLock(stateRoot, true)
        : await openStateStore(stateRoot, typeof message === 'string' ? undefined : message.authority);
      process.send!({ state: 'held', pid: process.pid, token: native.processStartToken(),
        epoch: 'ownerEpoch' in held ? held.ownerEpoch : undefined });
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
    process.send!({ state: 'error', message: error instanceof Error ? error.message : String(error) });
  }
});
process.on('disconnect', () => process.exit(0));
process.send!({ state: 'ready' });
