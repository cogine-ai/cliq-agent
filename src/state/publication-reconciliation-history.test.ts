// Retained corruption/refusal seam only. Registered CAS is not native proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import { digestOmitting } from '../kernel/identity.js';
import type { PublicationRecoveryOriginV1 } from '../kernel/reconciliation.js';
import { readPublicationRecoveryOrigin } from './publication-reconciliation-history.js';
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
    const artifact = await fixture.store.artifacts.publishCanonical(origin, origin.format);
    const driver = (fixture.store as unknown as { driver: SqliteDriver }).driver;
    await assert.rejects(readPublicationRecoveryOrigin(driver, fixture.store.artifacts,
      { run: before.run, spec: { ...before.runSpec, operation: 'delivery' }, source: {} } as never,
      { runId: fixture.runId, opId: origin.opId, opKind: 'publish', attempt: 0, phase: 'dispatch_claimed' } as never,
      {} as never, { recoveryOriginRef: artifact.ref, recoveryOriginDigest: origin.originDigest } as never),
    /original Delivery RunSpec/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
