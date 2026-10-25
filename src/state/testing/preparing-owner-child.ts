// Real metadata/StateOwner-death regression only. No native generation,
// controller, reservation, Run execution or positive cleanup proof is created.
import assert from 'node:assert/strict';
import { identityHash } from '../../kernel/identity.js';
import { createQueuedFixture } from './fixtures.js';
import { openStateStore, type StateStoreRuntimeAuthority } from '../store.js';
import type { StateOwnerContext } from '../state-owner.js';
import type { SqliteDriver } from '../sqlite-driver.js';
import { assertWorkerPreparationCleanupContext, assertWorkerPreparationRelease, beginWorkerPreparation,
  openWorkerPreparationCleanupContext, readWorkerPreparationCleanupTarget, retireRetainedWorkerPreparation, type WorkerPreparationCleanupContext } from '../worker-preparation.js';
import { readPreparingCleanupClosure } from '../recovery-closure.js';
import { observeRetainedPreparingGeneration } from '../../workspace/run-workspace/preparation-retirement.js';
import { assertRetainedPreparingGitInputOwner } from '../native-owner.js';
import type { LinuxWorkerController, NativeRetainedPreparingGitRetirement } from '../../sandbox/linux-worker.js';
import type { HeldRetainedPreparingGitInput, HeldStateOwnerLock } from '../native-owner.js';
import type { WorkspaceGenerationIdentityV1 } from '../../kernel/types.js';
import type { InstalledBrokerQuiescence } from '../store.js';
import { retireAbandonedWorkerPreparations } from '../preparing-successor.js';
import type { LinuxWorkerInstallation } from '../../sandbox/linux-worker.js';

process.chdir(process.argv[2]!);
process.on('message', async (message: { mode: 'create' | 'inspect'; stateRoot?: string; runId?: string; launchId?: string;
  authority?: StateStoreRuntimeAuthority; originalStateOwnerRowDigest?: string }) => {
  try {
    if (message.mode === 'create') {
      const f = await createQueuedFixture('cleanup-owner-context');
      const { driver, owner } = f.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
      const run = f.store.getRun(f.runId), launchId = identityHash('readonly-cleanup-test', run.id);
      await beginWorkerPreparation(driver, f.store.artifacts, owner, { runId: run.id, expectedRunRevision: run.revision,
        launchId, spawnNonceDigest: 'a'.repeat(64), activationNonceDigest: 'b'.repeat(64), generationCreationNonceDigest: 'c'.repeat(64) });
      process.send!({ state: 'created', stateRoot: f.stateRoot, workspace: f.workspace, runId: run.id, launchId,
        originalStateOwnerRowDigest: owner.rowDigest, authority: f.runtimeAuthority }); return;
    }
    const store = await openStateStore(message.stateRoot!, message.authority);
    const { driver, owner } = store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
    await assert.rejects(store.readRecoveryClosure(message.runId!), { code: 'RECOVERY_REQUIRED' });
    const context = await openWorkerPreparationCleanupContext(driver, store.artifacts, owner, message.launchId!);
    const target = readWorkerPreparationCleanupTarget(driver, owner, context);
    assert.equal(target.originalStateOwnerRowDigest, message.originalStateOwnerRowDigest);
    assert.equal(target.launch.supervisorInstanceId, target.death.priorOwner.supervisorInstanceId);
    assert.equal(target.death.priorOwner.state, 'terminal'); assert(target.death.priorOwner.ownerEpoch < owner.ownerEpoch);
    assertWorkerPreparationCleanupContext(driver, context, message.runId!);
    const cut = await readPreparingCleanupClosure(driver, store.artifacts, message.runId!, context);
    assert.equal(cut.run.id, message.runId); await assert.rejects(store.readRecoveryClosure(message.runId!), { code: 'RECOVERY_REQUIRED' });
    assert.throws(() => assertWorkerPreparationRelease(driver, owner, message.launchId!), { code: 'RECOVERY_REQUIRED' });
    let inspected = false;
    const fake = Object.defineProperty({}, 'owner', { get() { inspected = true; throw new Error('untrusted getter'); } });
    assert.throws(() => assertWorkerPreparationCleanupContext(driver, fake as WorkerPreparationCleanupContext, message.runId!), TypeError);
    assert.throws(() => assertWorkerPreparationCleanupContext(driver, context, identityHash('foreign-run')), TypeError);
    assert.equal(inspected, false);
    const fakeController = Object.defineProperty({}, 'preparationBirth', { get() { inspected = true; throw new Error('fake controller getter'); } });
    await assert.rejects(retireRetainedWorkerPreparation(driver, store.artifacts, owner, context,
      fakeController as LinuxWorkerController, {} as InstalledBrokerQuiescence), TypeError);
    const fakeIdentity = Object.defineProperty({}, 'locator', { get() { inspected = true; throw new Error('fake directory getter'); } });
    assert.throws(() => observeRetainedPreparingGeneration({} as HeldStateOwnerLock, fakeIdentity as WorkspaceGenerationIdentityV1,
      1, {} as NativeRetainedPreparingGitRetirement), TypeError);
    assert.throws(() => assertRetainedPreparingGitInputOwner({} as HeldStateOwnerLock,
      Object.defineProperty({}, 'identity', { get() { inspected = true; throw new Error('fake input getter'); } }) as HeldRetainedPreparingGitInput), TypeError);
    assert.equal(inspected, false);
    // Discovery uses the actual retained SQL row. Even when a caller requests
    // a native inspection, no installation property may be consumed to turn
    // this zero-birth preparation into absence or a successful retirement.
    const unavailableInstallation = Object.defineProperty({}, 'installationRoot', { get() {
      inspected = true; throw new Error('missing birth must be refused before an installation is opened');
    } }) as LinuxWorkerInstallation;
    await assert.rejects(retireAbandonedWorkerPreparations(driver, store.artifacts, owner,
      { store, installation: unavailableInstallation, signal: new AbortController().signal }), { name: 'ResourceRetirementError', code: 'RECOVERY_REQUIRED' });
    assert.equal(inspected, false);
    assert.equal(driver.prepare('SELECT count(*) AS n FROM workspace_generations').get<{ n: bigint }>()!.n, 0n);
    const before = owner.rowDigest; owner.rowDigest = 'f'.repeat(64);
    assert.throws(() => assertWorkerPreparationCleanupContext(driver, context, message.runId!)); owner.rowDigest = before;
    assertWorkerPreparationCleanupContext(driver, context, message.runId!);
    process.send!({ state: 'inspected', readonlyContext: true, ordinaryRecoveryStillRefuses: true,
      originalOwnerNotAdopted: true, derivedOriginalDigestMatchesActual: true, zeroNativeBirths: true, structuralGetterUntouched: true, missingBirthStillWaiting: true });
    // The parent observes actual process exit before removing its own fixture.
    // A context test never fabricates a graceful preparation cleanup receipt.
    process.exit(0);
  } catch (error) { process.send!({ state: 'error', message: String(error), stack: (error as Error).stack }); }
});
process.send!({ state: 'ready' });
