import { loadNativeStateOwner, type HeldStateOwnerLock } from '../native-owner.js';
import { openStateStore, type StateStore } from '../store.js';

// Test-only IPC barrier: no sleeps, inherited descriptors, or simulated locks.
const stateRoot = process.argv[2]!;
const native = await loadNativeStateOwner();
let held: StateStore | HeldStateOwnerLock | undefined;
process.on('message', async (command) => {
  try {
    if (command === 'acquire') {
      if (held) throw new Error('test child already holds an owner');
      held = process.argv[3] === 'native' ? native.acquireLock(stateRoot, true) : await openStateStore(stateRoot);
      process.send!({ state: 'held', pid: process.pid, token: native.processStartToken(),
        epoch: 'ownerEpoch' in held ? held.ownerEpoch : undefined });
    } else if (command === 'close') {
      await held?.close();
      held = undefined;
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
