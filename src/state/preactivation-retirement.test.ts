import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_CAS_DIRECTORY } from '../config.js';
import { loadNativeStateOwner, type HeldStateOwnerLock } from './native-owner.js';
import { openStateStore } from './store.js';
import { createQueuedFixture, disposeFixture, makePrivateDir, prepareFixtureGeneration } from './testing/fixtures.js';
import { ownerAt } from './testing/state-owner-process.js';
import { publishFixtureWorkerLaunch } from './testing/worker-launch.js';

test('startup with an unreadable reserved plan retains the actual owner lock even after caller GC', async () => {
  const fixture = await createQueuedFixture('preactivation-plan-corrupt');
  let child: ReturnType<typeof fork> | undefined;
  let exited: Promise<unknown[]> | undefined;
  let retainedPath: string | undefined, planPath: string | undefined;
  try {
    // This is negative retained-metadata validation at the public Store seam,
    // not a fabricated Linux birth, no-spawn observation or death proof.
    const generation = await prepareFixtureGeneration(fixture, 'corrupt-plan');
    const publication = await publishFixtureWorkerLaunch(fixture, generation.generationArtifact.ref, 'corrupt-plan');
    await fixture.store.reserveWorkerLaunch(publication.input);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await fixture.store.close();
    const prior = ownerAt(fixture.stateRoot);
    planPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, publication.input.containmentPlanRef);
    retainedPath = `${planPath}-retained`;
    await rename(planPath, retainedPath);
    child = fork(new URL('./testing/preactivation-owner-child.ts', import.meta.url), [], {
      execArgv: ['--expose-gc', '--import', 'tsx'], stdio: ['ignore', 'ignore', 'inherit', 'ipc']
    });
    exited = once(child, 'exit');
    const reply = async () => (await once(child!, 'message', { signal: AbortSignal.timeout(20_000) }))[0] as
      { state: string; retirement?: boolean; code?: string; message?: string };
    assert.equal((await reply()).state, 'ready');
    const response = reply(); child.send({ stateRoot: fixture.stateRoot, authority: fixture.runtimeAuthority });
    const refused = await response;
    assert.equal(refused.state, 'refused', refused.message);
    const successor = ownerAt(fixture.stateRoot);
    assert.equal(successor.state, 'active'); assert.equal(successor.ownerEpoch, prior.ownerEpoch + 1);
    const native = await loadNativeStateOwner();
    let incorrectlyAcquired: HeldStateOwnerLock | undefined;
    try { incorrectlyAcquired = native.acquireLock(fixture.stateRoot, false); }
    catch (error) { assert.match(String(error), /OS lock is already held/); }
    if (incorrectlyAcquired) {
      incorrectlyAcquired.close();
      assert.fail('unresolved startup released the real OS owner lock while its successor process remains alive');
    }
    assert.equal(refused.retirement, true); assert.equal(refused.code, 'RECOVERY_REQUIRED');
    child.kill('SIGKILL'); assert.equal((await exited)[1], 'SIGKILL');
    await rename(retainedPath, planPath); retainedPath = undefined;
    fixture.store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before,
      'failed discovery cannot retire, activate or mutate the old ready cut');
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    if (exited) await exited;
    if (retainedPath && planPath) await rename(retainedPath, planPath);
    await disposeFixture(fixture);
  }
});

test('failed public Store.close retains the actual owner after its caller drops the Store and forces GC', async () => {
  const root = await makePrivateDir('.cliq-preactivation-close-gc-');
  const child = fork(new URL('./testing/preactivation-owner-child.ts', import.meta.url), [], {
    execArgv: ['--expose-gc', '--import', 'tsx'], stdio: ['ignore', 'ignore', 'inherit', 'ipc']
  });
  const exited = once(child, 'exit');
  try {
    const reply = async () => (await once(child, 'message', { signal: AbortSignal.timeout(20_000) }))[0] as
      { state: string; retirement?: boolean; code?: string; closeFaults?: number; message?: string };
    assert.equal((await reply()).state, 'ready');
    const response = reply(); child.send({ stateRoot: root, closeFault: true });
    const refused = await response;
    assert.equal(refused.state, 'refused', refused.message);
    assert.ok(refused.closeFaults! > 0, 'the real CAS close fault must have happened');
    assert.equal(refused.retirement, true); assert.equal(refused.code, 'RECOVERY_REQUIRED');
    assert.equal(ownerAt(root).state, 'active');
    const native = await loadNativeStateOwner();
    let incorrectlyAcquired: HeldStateOwnerLock | undefined;
    try { incorrectlyAcquired = native.acquireLock(root, false); }
    catch (error) { assert.match(String(error), /OS lock is already held/); }
    if (incorrectlyAcquired) {
      incorrectlyAcquired.close();
      assert.fail('GC released the real owner lock after an unresolved Store.close');
    }
    child.kill('SIGKILL'); assert.equal((await exited)[1], 'SIGKILL');
    const successor = await openStateStore(root);
    try { assert.equal(successor.ownerEpoch, 2); } finally { await successor.close(); }
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited;
    await rm(root, { recursive: true, force: true });
  }
});
