import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import path from 'node:path';
import type { TestContext } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../../config.js';
import { openSqliteDriver } from '../sqlite-driver.js';
import { readLatestStateOwner } from '../state-owner.js';
import type { StateStoreRuntimeAuthority } from '../store.js';

type ChildReply = { state: string; message?: string; epoch?: number; pid?: number; token?: string;
  stateRoot?: string; runId?: string; launchId?: string; runRevision?: number; leaseEpoch?: number; leaseVersion?: number };

export async function childFor(t: TestContext, root: string, mode: 'store' | 'native' | 'fixture' = 'store') {
  const child = fork(new URL('./state-owner-child.ts', import.meta.url), [root, mode], {
    execArgv: ['--import', 'tsx'], stdio: ['ignore', 'ignore', 'pipe', 'ipc']
  });
  let diagnostic = '';
  child.stderr!.on('data', (chunk: Buffer) => { diagnostic = (diagnostic + chunk.toString()).slice(-4096); });
  const exited = once(child, 'exit');
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await exited; });
  const reply = async () => {
    try {
      const [message] = await once(child, 'message', { signal: AbortSignal.timeout(30_000) });
      return message as ChildReply;
    } catch (error) { throw new Error(`StateOwner child did not reply: ${diagnostic}`, { cause: error }); }
  };
  assert.equal((await reply()).state, 'ready');
  return { child, exited, request(command: 'acquire' | 'close' | 'drop-lock', authority?: StateStoreRuntimeAuthority) {
    const pending = reply();
    child.send(authority ? { command, authority } : command);
    return pending;
  } };
}

export function ownerAt(root: string) {
  const driver = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
  try { return readLatestStateOwner(driver)!; } finally { driver.close(); }
}
