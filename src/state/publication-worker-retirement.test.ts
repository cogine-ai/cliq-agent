// Refusal-only tests at the real Store/opaque-retirement seam. No stopped
// native owner, publication claim or successful Delivery cut is fabricated.
import assert from 'node:assert/strict';
import test from 'node:test';
import type { ArtifactCatalog } from './artifacts.js';
import { commitStoppedPublicationWorkerRetirement, commitUnresolvedPublicationWorkerRetirement,
  readUnresolvedPublicationWorkerCut } from './publication-worker-retirement.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { createQueuedFixture, disposeFixture } from './testing/fixtures.js';

test('publication recovery cannot build a retirement owner from a callback or retained cut', async () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('structural retirement reached SQLite'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'readCanonical', { get() { assert.fail('structural retirement reached CAS'); } }) as ArtifactCatalog;
  const hostile = Object.defineProperty({}, 'commit', { get() { assert.fail('retirement input getters must not run'); } });
  Object.defineProperty(hostile, 'commitQuarantined', { get() { assert.fail('caller quarantine must not run'); } });
  for (const value of [{}, hostile, { cut: {}, commit() { assert.fail('caller commit'); } }])
    await assert.rejects(commitStoppedPublicationWorkerRetirement(driver, artifacts, {} as StateOwnerContext, value as never, 'not-an-owned-run'),
      /exact original live producer/);
  await assert.rejects(commitUnresolvedPublicationWorkerRetirement(driver, artifacts, {} as StateOwnerContext, hostile as never, 'not-an-owned-run'),
    /exact original live producer/);
});

test('a real queued Agent Store cannot manufacture stopped publication retirement or change its frontier', async () => {
  const fixture = await createQueuedFixture('publication-recovery-bridge');
  try {
    const { driver, owner } = fixture.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(readUnresolvedPublicationWorkerCut(driver, fixture.store.artifacts, before), /original Delivery worker/);
    await assert.rejects(commitStoppedPublicationWorkerRetirement(driver, fixture.store.artifacts, owner,
      { runId: fixture.runId, stopped: true, retired: true, commit() { assert.fail('caller commit'); } } as never, fixture.runId),
    /exact original live producer/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
