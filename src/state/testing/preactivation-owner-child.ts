import fs from 'node:fs/promises';
import path from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { KERNEL_CAS_DIRECTORY } from '../../config.js';
import { ResourceRetirementError } from '../errors.js';
import { openStateStore, type StateStoreRuntimeAuthority } from '../store.js';

type Input = { stateRoot: string; authority?: StateStoreRuntimeAuthority; closeFault?: true };
async function attempt(input: Input) {
  const originalOpen = fs.open;
  let closeFaults = 0;
  try {
    const store = await openStateStore(input.stateRoot, input.authority);
    if (input.closeFault) {
      fs.open = (async (...args: Parameters<typeof fs.open>) => {
        const handle = await originalOpen(...args);
        if (args[0] === path.join(input.stateRoot, KERNEL_CAS_DIRECTORY)) {
          const close = handle.close.bind(handle);
          handle.close = async () => {
            await close(); closeFaults++;
            throw Object.assign(new Error('actual CAS root close uncertainty'), { code: 'EIO' });
          };
        }
        return handle;
      }) as typeof fs.open;
    }
    await store.close();
    return { state: 'unexpected_success' };
  } catch (error) {
    return { state: 'refused', closeFaults, retirement: error instanceof ResourceRetirementError,
      code: error instanceof ResourceRetirementError ? error.code : undefined,
      message: error instanceof Error ? error.message : String(error) };
  } finally { fs.open = originalOpen; }
}

let started = false;
process.on('message', async (input: Input) => {
  if (started) return;
  started = true;
  const result = await attempt(input);
  if (!globalThis.gc) throw new Error('preactivation owner fixture requires --expose-gc');
  // Only primitive failure facts survive this boundary. Neither the caller's
  // Store nor a rejected close promise can accidentally keep its native lock.
  for (let round = 0; round < 8; round++) { globalThis.gc(); await setImmediate(); }
  process.send!(result);
});
process.send!({ state: 'ready' });
