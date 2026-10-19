// Retained corruption/refusal seam only. Registered CAS is not native proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import { digestOmitting } from '../kernel/identity.js';
import type { PublicationRecoveryOriginV1 } from '../kernel/reconciliation.js';
import { readPublicationRecoveryOrigin } from './publication-reconciliation-history.js';
import { decodePublicationRecoveryOrigin } from './publication-reconciliation-artifacts.js';
import { loadNativeStateOwner } from './native-owner.js';
import { makePrivateDir } from './testing/fixtures.js';
import { rm } from 'node:fs/promises';
import { createQueuedFixture, disposeFixture } from './testing/fixtures.js';
import type { SqliteDriver } from './sqlite-driver.js';

test('a real Agent Store and self-hashed origin cannot fabricate a delivery claim or owner death', async () => {
  const fixture = await createQueuedFixture('publication-origin-refusal');
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const origin: PublicationRecoveryOriginV1 = { schemaVersion: 1, format: 'cliq-publication-recovery-origin-v1',
      deliveryRunId: fixture.runId, deliveryPlanRef: 'a'.repeat(64), opId: 'b'.repeat(43), attempt: 0,
      dispatchId: 'c'.repeat(64), claimJournalSeq: 2, arenaBirthRef: 'd'.repeat(64), arenaBirthDigest: 'e'.repeat(64),
      inspectorIdentityRef: 'f'.repeat(64), inspectorIdentityDigest: 'a'.repeat(64),
      ownerDeathAcquisitionEvidenceRef: 'b'.repeat(64), ownerDeathAcquisitionEvidenceDigest: 'c'.repeat(64),
      observedAt: before.run.updatedAt, originDigest: '' };
    origin.originDigest = digestOmitting(origin, 'originDigest');
    const { ownerDeathAcquisitionEvidenceRef: _ref, ownerDeathAcquisitionEvidenceDigest: _digest, ...core } = origin;
    const graceful = { ...core, gracefulOwnerDeath: { kind: 'observed_after_graceful_release',
      priorOwnerRowDigest: 'a'.repeat(64), priorProcessIdentityRef: 'b'.repeat(64), priorProcessIdentityDigest: 'c'.repeat(64),
      gracefulTransitionEvidenceRef: 'd'.repeat(64), gracefulTransitionEvidenceDigest: 'e'.repeat(64),
      processObservation: 'absent_or_start_token_mismatch' } };
    graceful.originDigest = digestOmitting(graceful, 'originDigest');
    const driver = (fixture.store as unknown as { driver: SqliteDriver }).driver;
    for (const value of [origin, decodePublicationRecoveryOrigin(graceful)]) {
      const artifact = await fixture.store.artifacts.publishCanonical(value, value.format);
      await assert.rejects(readPublicationRecoveryOrigin(driver, fixture.store.artifacts,
      { run: before.run, spec: { ...before.runSpec, operation: 'delivery' }, source: {} } as never,
      { runId: fixture.runId, opId: origin.opId, opKind: 'publish', attempt: 0, phase: 'dispatch_claimed' } as never,
      {} as never, { recoveryOriginRef: artifact.ref, recoveryOriginDigest: value.originDigest } as never),
      /original Delivery RunSpec/);
    }
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('an actual released lock and graceful-shaped data cannot declare the still-live original process dead', async () => {
  const root = await makePrivateDir('.cliq-publication-graceful-alive-');
  const native = await loadNativeStateOwner(), first = native.acquireLock(root, true), token = native.processStartToken();
  first.close();
  const inspecting = native.acquireLock(root, false);
  try {
    assert.throws(() => inspecting.observePriorProcessDeath(process.pid, token), /still present/);
  } finally { inspecting.close(); await rm(root, { recursive: true, force: true }); }
});
