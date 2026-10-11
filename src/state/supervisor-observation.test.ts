import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { publishInProcessChannel } from './store.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { readLatestStateOwner } from './state-owner.js';
import { KernelStorageError } from './errors.js';
import { createQueuedFixture, disposeFixture } from './testing/fixtures.js';

// Real signed current-Node/StateOwner observation, not an installed SEA or
// systemd qualification. The queued fixture never starts a worker.
test('Supervisor hello observes the actual signed owner without granting execution or exposing release keys', async () => {
  const fixture = await createQueuedFixture('supervisor-hello-observation');
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const observed = await fixture.store.readSupervisorHello(identity);
    const bundle = fixture.runtimeAuthority.bundle;
    const inspector = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    let instanceId: string;
    try { instanceId = readLatestStateOwner(inspector)!.supervisorInstanceId; }
    finally { inspector.close(); }
    assert.deepEqual(observed, {
      supervisorInstanceId: instanceId,
      activeRuntimeBundle: { schemaVersion: 1, runtimeBundleRef: canonicalSha256(bundle),
        bundleDigest: canonicalSha256(bundle), bundleVersion: bundle.bundleVersion },
      headlessSchemaRange: bundle.headlessSchemaRange,
    });
  } finally { await disposeFixture(fixture); }
});

test('an ordinary signed Store cannot advertise installed runtime inventory or execution readiness', async () => {
  const fixture = await createQueuedFixture('supervisor-status-no-installation');
  try {
    const identity = await publishInProcessChannel(fixture.store);
    await assert.rejects(fixture.store.readSupervisorStatus(identity),
      error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
    await assert.rejects(fixture.store.readSupervisorHello({ ...identity, principalId: '0'.repeat(64) }),
      error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
    await fixture.store.close();
    await assert.rejects(fixture.store.readSupervisorHello(identity),
      error => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED');
  } finally { await disposeFixture(fixture); }
});
