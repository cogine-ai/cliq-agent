// Actual Store/refusal and original opaque-task boundaries. These are not
// successful native publication or owner-death fixtures.
import assert from 'node:assert/strict';
import test from 'node:test';
import { beginPublicationReconciliationProbe, preparePublicationReconciliation,
  readPublicationReconciliation, replayPublicationReconciliationProbe, updatePublicationReconciliationProgress } from './publication-reconciliation.js';
import { preparePublicationLateObservation } from './publication-reconciliation.js';
import type { ArtifactCatalog } from './artifacts.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { createQueuedFixture, disposeFixture } from './testing/fixtures.js';

test('late audit requires its genuine original producer before getters, CAS or SQL', async () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('late data must not reach SQL'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'publishCanonical', { get() { assert.fail('late data must not reach CAS'); } }) as ArtifactCatalog;
  const token = Object.defineProperty({}, 'cut', { get() { assert.fail('late source getters must not run'); } });
  await assert.rejects(preparePublicationLateObservation(driver, artifacts, {} as StateOwnerContext,
    { execution: {}, lateObservation: token as never }), /genuine same-execution late publication observation/);
  const input = Object.defineProperty({ lateObservation: token }, 'execution', { enumerable: true,
    get() { assert.fail('late input accessor must not run'); } });
  await assert.rejects(preparePublicationLateObservation(driver, artifacts, {} as StateOwnerContext, input as never), /closed input/);
});

test('publication wait creation and dispatch require the actual owning task before caller data or CAS', async () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('structural probe must not read SQLite'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'readCanonical', { get() { assert.fail('structural probe must not read CAS'); } }) as ArtifactCatalog;
  const input = { runId: 'inert', expectedRunRevision: 1, execution: {}, task: {} as never };
  await assert.rejects(preparePublicationReconciliation(driver, artifacts, {} as StateOwnerContext, input), /genuine same-owner original task and ArtifactCatalog/);
  await assert.rejects(beginPublicationReconciliationProbe(driver, artifacts, {} as StateOwnerContext, input), /genuine same-owner original task and ArtifactCatalog/);
  await assert.rejects(replayPublicationReconciliationProbe(driver, artifacts, {} as StateOwnerContext,
    { request: {} as never, identity: {} as never }), /current native authenticated frame/);
  const progress = Object.defineProperty({}, 'run', { get() { assert.fail('structural progress must not be inspected'); } });
  assert.throws(() => updatePublicationReconciliationProgress(driver, artifacts, {} as StateOwnerContext, {}, input.task, progress as never),
    /genuine same-task publication progress transfer/);
});

test('a real ordinary queued Agent has no publication wait or replayable publication state', async () => {
  const fixture = await createQueuedFixture('publication-reconciliation-read');
  try {
    const held = fixture.store as unknown as { driver: SqliteDriver };
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(await readPublicationReconciliation(held.driver, fixture.store.artifacts, fixture.runId), undefined);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
