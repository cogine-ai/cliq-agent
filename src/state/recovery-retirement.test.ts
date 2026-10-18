import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { KERNEL_CAS_DIRECTORY } from '../config.js';
import type { AgentModelTurn, ToolCallInputV1 } from '../protocol/agent-ir.js';
import { ResourceRetirementError } from './errors.js';
import { loadNativeStateOwner, type HeldStateOwnerLock } from './native-owner.js';
import { openStateStore, type StateStoreRuntimeAuthority } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { createQueuedFixture, disposeFixture, makePrivateDir } from './testing/fixtures.js';
import { ownerAt } from './testing/state-owner-process.js';
import { batch } from './testing/tool-calls.js';
import { canonicalSha256 } from '../kernel/canonical.js';

for (const operation of ['recovery read'] as const) {
  test(`a failed ${operation} joins every real CAS handle and retains any retirement failure`, async () => {
    const fixture = await createQueuedFixture('recovery-read-join');
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const missingRef = before.run.specRef, delayedRef = before.run.frontierRef!;
    const missingPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, missingRef);
    const savedPath = `${missingPath}.fault-fixture`;
    const delayedPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, delayedRef);
    const failure = Object.assign(new Error('uncertainty after the actual CAS handle close'), { code: 'EIO' });
    const originalOpen = fs.open;
    let entered!: () => void, release!: () => void;
    const closing = new Promise<void>(resolve => { entered = resolve; });
    const held = new Promise<void>(resolve => { release = resolve; });
    let reading: Promise<unknown> | undefined, settled = false;
    await fs.rename(missingPath, savedPath); // A real missing artifact fails independently of the held read.
    fs.open = (async (...args: Parameters<typeof fs.open>) => {
      const handle = await originalOpen(...args);
      if (args[0] === delayedPath) {
        const actualClose = handle.close.bind(handle);
        handle.close = async () => {
          await actualClose();
          entered();
          await held;
          throw failure;
        };
      }
      return handle;
    }) as typeof fs.open;
    try {
      reading = fixture.store.readRecoveryClosure(fixture.runId);
      void reading.then(() => { settled = true; }, () => { settled = true; });
      await closing;
      await nextTurn();
      assert.equal(settled, false, 'the missing artifact must not end inspection while another actual read is unjoined');
      release();
      await assert.rejects(reading, error => error instanceof ResourceRetirementError && error.cause === failure);
      fs.open = originalOpen;
      await fs.rename(savedPath, missingPath);
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    } finally {
      release();
      await reading?.catch(() => {});
      fs.open = originalOpen;
      await fs.rename(savedPath, missingPath).catch(error => { if (error.code !== 'ENOENT') throw error; });
      await disposeFixture(fixture);
    }
  });
}

test('a failed agent opening joins real CAS reads and retains the original owner until its process dies', async () => {
  const directory = await makePrivateDir('.cliq-agent-opening-retirement-');
  const child = fork(new URL('./testing/agent-opening-retirement-child.ts', import.meta.url), [directory], {
    execArgv: ['--expose-gc', '--import', 'tsx'], stdio: ['ignore', 'ignore', 'inherit', 'ipc']
  });
  const exited = once(child, 'exit'), closed = once(child, 'close');
  let successorResourcesRetired = false;
  try {
    const reply = async () => (await once(child, 'message', { signal: AbortSignal.timeout(30_000) }))[0] as {
      state: string; stateRoot?: string; workspace?: string; runId?: string; beforeDigest?: string; epoch?: number;
      authority?: StateStoreRuntimeAuthority; message?: string;
    };
    assert.equal((await reply()).state, 'ready');
    const response = reply(); child.send('exercise');
    const retained = await response;
    assert.equal(retained.state, 'retained', retained.message);
    assert(retained.stateRoot && retained.workspace && retained.runId && retained.beforeDigest && retained.authority && retained.epoch);
    assert.equal(path.dirname(retained.stateRoot), directory);
    assert.equal(path.dirname(retained.workspace), directory);
    const original = ownerAt(retained.stateRoot);
    assert.equal(original.state, 'active'); assert.equal(original.ownerEpoch, retained.epoch);
    const native = await loadNativeStateOwner();
    let incorrectlyAcquired: HeldStateOwnerLock | undefined;
    try { incorrectlyAcquired = native.acquireLock(retained.stateRoot, false); }
    catch (error) { assert.match(String(error), /OS lock is already held/); }
    if (incorrectlyAcquired) {
      incorrectlyAcquired.close();
      assert.fail('a failed agent opening or Store.close released the real OS owner lock before its process died');
    }
    child.kill('SIGKILL');
    assert.equal((await exited)[1], 'SIGKILL'); assert.equal((await closed)[1], 'SIGKILL');
    // The old process really exited. A genuine successor acquires the same
    // StateRoot, preserving the original ready cut rather than faking a join.
    const successor = await openStateStore(retained.stateRoot, retained.authority);
    try {
      assert.equal(successor.ownerEpoch, original.ownerEpoch + 1);
      assert.equal(canonicalSha256(await successor.readRecoveryClosure(retained.runId)), retained.beforeDigest);
    } finally { await successor.close(); successorResourcesRetired = true; }
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited; await closed;
    if (successorResourcesRetired) await fs.rm(directory, { recursive: true, force: true });
    else console.error(`preserving uncertain agent-opening fixture: ${directory}`);
  }
});

test('typed recovery preserves actual CAS retirement failure without tagging a missing model input', async () => {
  const fixture = await createAgentFixture('typed-recovery-retirement');
  const originalOpen = fs.open;
  let savedPath: string | undefined, observedPath: string | undefined;
  try {
    // The retained model prefix is offline; this test qualifies real CAS
    // retirement through the Store interface, not native worker execution.
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const completed = before.journal.find(entry => entry.opKind === 'model' && entry.phase === 'completed')!;
    const turn = await fixture.store.artifacts.readCanonical<AgentModelTurn>(completed.resultRef!);
    const call = await fixture.store.artifacts.readCanonical<ToolCallInputV1>(turn.toolCalls[0]!.inputRef);
    observedPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, call.observedInputRef);
    const failure = Object.assign(new Error('uncertainty retiring the actual observed input handle'), { code: 'EIO' });
    fs.open = (async (...args: Parameters<typeof fs.open>) => {
      const handle = await originalOpen(...args);
      if (args[0] === observedPath) {
        const actualClose = handle.close.bind(handle);
        handle.close = async () => { await actualClose(); throw failure; };
      }
      return handle;
    }) as typeof fs.open;
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId),
      error => error instanceof ResourceRetirementError && error.cause === failure);
    fs.open = originalOpen;
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    savedPath = `${observedPath}.fault-fixture`;
    await fs.rename(observedPath, savedPath);
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), error =>
      error instanceof Error && !(error instanceof ResourceRetirementError) &&
      'code' in error && error.code === 'RECOVERY_REQUIRED');
  } finally {
    fs.open = originalOpen;
    if (savedPath && observedPath) await fs.rename(savedPath, observedPath);
    await disposeFixture(fixture);
  }
});
