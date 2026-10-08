import { promises as fs } from 'node:fs';
import path from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { KERNEL_CAS_DIRECTORY } from '../../config.js';
import { ResourceRetirementError } from '../errors.js';
import { loadNativeStateOwner } from '../native-owner.js';
import { openStateStore, publishInProcessChannel, type StateStore, type StateStoreRuntimeAuthority } from '../store.js';

type Command = {
  mode: 'source-write' | 'retirement-write' | 'recover' | 'recovery-close-fault';
  stateRoot: string;
  authority: StateStoreRuntimeAuthority;
  request: unknown;
  sourceBytes: string;
  targetRef?: string;
};

function send(message: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!process.send) { reject(new Error('source crash fixture requires IPC')); return; }
    process.send(message, error => error ? reject(error) : resolve());
  });
}

// This fixture pauses an actual OS write after the original bytes were written.
// It does not replace capture, a native observation, lifecycle join or a row.
function pauseActualWrite(command: Command, store: StateStore): () => void {
  const originalOpen = fs.open;
  let paused = false;
  const sourceBytes = Buffer.from(command.sourceBytes);
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await originalOpen(...args);
    if (typeof args[0] === 'string' && args[0].startsWith(path.join(command.stateRoot, KERNEL_CAS_DIRECTORY, '.tmp-stream-'))) {
      const write = handle.writeFile.bind(handle);
      handle.writeFile = async (...writeArgs: Parameters<typeof handle.writeFile>) => {
        await write(...writeArgs);
        const bytes = writeArgs[0] instanceof Uint8Array ? Buffer.from(writeArgs[0]) : undefined;
        let matches = command.mode === 'source-write' && bytes?.equals(sourceBytes);
        if (command.mode === 'retirement-write' && bytes) {
          try {
            const value = JSON.parse(bytes.toString());
            matches = value.format === 'cliq-supervisor-inspector-identity-v1' && value.stateOwnerEpoch === store.ownerEpoch;
          } catch { /* Ordinary source bytes are not metadata. */ }
        }
        if (matches && !paused) {
          paused = true;
          const native = await loadNativeStateOwner(command.authority.bundle);
          await send({ state: 'paused', mode: command.mode, pid: process.pid, token: native.processStartToken() });
          // The parent must observe the real durable/physical cut and SIGKILL.
          // IPC keeps this process alive; there is no fabricated completion.
          await new Promise<void>(() => {});
        }
      };
    }
    return handle;
  }) as typeof fs.open;
  return () => { fs.open = originalOpen; };
}

let started = false;
async function run(command: Command): Promise<void> {
  if (started) return;
  started = true;
  let store: StateStore | undefined, restore: (() => void) | undefined;
  let failedCloses = 0;
  try {
    if (command.mode === 'recovery-close-fault') {
      if (!command.targetRef || !/^[0-9a-f]{64}$/.test(command.targetRef)) throw new Error('close fault requires the exact retained target ref');
      const originalOpen = fs.open;
      fs.open = (async (...args: Parameters<typeof fs.open>) => {
        const handle = await originalOpen(...args);
        if (args[0] === path.join(command.stateRoot, KERNEL_CAS_DIRECTORY, command.targetRef!)) {
          const close = handle.close.bind(handle);
          handle.close = async () => {
            await close(); failedCloses++;
            throw Object.assign(new Error('source retained-target descriptor close failed after actual OS close'), { code: 'EIO' });
          };
        }
        return handle;
      }) as typeof fs.open;
      restore = () => { fs.open = originalOpen; };
    }
    store = await openStateStore(command.stateRoot, command.authority);
    if (command.mode === 'recovery-close-fault') throw new Error('startup returned without the required actual retained-target close failure');
    const identity = await publishInProcessChannel(store);
    if (command.mode !== 'recover') restore = pauseActualWrite(command, store);
    const row = await store.captureSubmittedSource({ request: command.request, identity });
    if (command.mode !== 'recover') throw new Error('capture completed without observing the required actual OS write');
    await store.close();
    await send({ state: 'replayed', row, ownerEpoch: store.ownerEpoch });
    process.disconnect?.();
  } catch (error) {
    restore?.();
    if (command.mode === 'recovery-close-fault' && failedCloses > 0 && error instanceof ResourceRetirementError) {
      if (!globalThis.gc) throw new Error('close-fault fixture requires --expose-gc');
      for (let round = 0; round < 8; round++) { globalThis.gc(); await setImmediate(); }
      await send({ state: 'faulted', failedCloses, message: error.message, code: error.code });
      return;
    }
    await send({ state: 'error', message: (error instanceof Error ? error.message : String(error)).slice(0, 1024),
      code: error && typeof error === 'object' && 'code' in error ? error.code : undefined });
    // An uncertain owner is deliberately not relabeled as gracefully released.
    // The parent owns this fixture process and must SIGKILL and await its exit.
  }
}
process.on('message', (command: Command) => {
  void run(command).catch(error => {
    // IPC failure must end in an observed child failure, never an unhandled
    // async EventEmitter callback rejection or a fictional graceful release.
    process.stderr.write(`${(error instanceof Error ? error.message : String(error)).slice(0, 1024)}\n`);
    process.exitCode = 1;
    if (process.connected) process.disconnect();
  });
});
await send({ state: 'ready' });
