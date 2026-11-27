import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { realpath, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { loadNativeStateOwner } from './native-owner.js';

test('only a real successor may inspect a dead owner preparation, and its opaque context cannot adopt that owner', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-preparing-owner-context-')));
  const children: Array<{ child: ReturnType<typeof fork>; exited: Promise<unknown[]> }> = [];
  const start = async () => {
    const child = fork(new URL('./testing/preparing-owner-child.ts', import.meta.url), [root],
      { execArgv: ['--import', 'tsx'], stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
    const exited = once(child, 'exit'), held = { child, exited }; children.push(held);
    let diagnostic = ''; child.stderr!.on('data', (data: Buffer) => { diagnostic = (diagnostic + data.toString()).slice(-4096); });
    const receive = async () => {
      const [value] = await once(child, 'message', { signal: AbortSignal.timeout(20_000) });
      const message = value as Record<string, unknown>; assert.notEqual(message.state, 'error', `${message.stack ?? message.message ?? diagnostic}`); return message;
    };
    assert.equal((await receive()).state, 'ready'); return { ...held, receive };
  };
  try {
    const original = await start(), prepared = original.receive(); original.child.send({ mode: 'create' });
    const data = await prepared; assert.equal(data.state, 'created');
    original.child.kill('SIGKILL'); assert.equal((await original.exited)[1], 'SIGKILL');
    const successor = await start(), checked = successor.receive(); successor.child.send({ mode: 'inspect', ...data });
    assert.deepEqual(await checked, { state: 'inspected', readonlyContext: true, ordinaryRecoveryStillRefuses: true,
      originalOwnerNotAdopted: true, derivedOriginalDigestMatchesActual: true, zeroNativeBirths: true, structuralGetterUntouched: true, missingBirthStillWaiting: true });
    assert.equal((await successor.exited)[0], 0);
    // Both actual owner processes have exited. This is an OS-lock observation,
    // not a StateOwner transaction or a native preparation retirement proof.
    const native = await loadNativeStateOwner(), raw = native.acquireLock(data.stateRoot as string, false); raw.close();
  } finally {
    for (const { child } of children) if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await Promise.all(children.map(({ exited }) => exited)); await rm(root, { recursive: true, force: true });
  }
});
