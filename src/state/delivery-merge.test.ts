// Existing real StateStore seam. A live agent is not a verified delivery
// source; these refusals mint no delivery, verifier or physical authority.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadDeliveryMerge } from './delivery-merge.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { readDeliveryMergeLimitCause } from './delivery-recovery.js';
import { readAgentStop } from './stop-recovery.js';

test('delivery merge cannot reinterpret an actual agent Run or create a candidate from its source bytes', async () => {
  const fixture = await createAgentFixture('delivery-merge-kind', undefined, { mode: 'plan' });
  try {
    const held = fixture.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const merge = loadDeliveryMerge(held.driver, fixture.store.artifacts, held.owner, { run: before.run, spec: before.runSpec });
    await assert.rejects(merge.mergeDelivery({ expectedRunRevision: before.run.revision }), { code: 'STATE_TRANSITION_INVALID' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('delivery merge rejects caller-selected fields and revisions before accessing storage', async () => {
  const merge = loadDeliveryMerge(undefined as unknown as SqliteDriver, undefined as never,
    undefined as unknown as StateOwnerContext, { run: { id: 'closed-input' }, spec: {} } as never);
  for (const input of [{ expectedRunRevision: 1, resultSourceRef: 'a'.repeat(64) }, { expectedRunRevision: 0 }])
    await assert.rejects(merge.mergeDelivery(input), { code: 'INVALID_REQUEST' });
});

test('a schema-valid delivery limit cannot reinterpret an actual Agent or its current workspace as resource-stop authority', async () => {
  const fixture = await createAgentFixture('delivery-limit-refuses-agent', undefined, { mode: 'plan' });
  try {
    const held = fixture.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
    const before = await fixture.store.readRecoveryClosure(fixture.runId), initial = before.latestCheckpoint;
    assert.equal(await readDeliveryMergeLimitCause(held.driver, fixture.store.artifacts, before), undefined);
    const ref = before.runSpec.baseWorkspaceManifestRef;
    const intent = { schemaVersion: 1, runId: fixture.runId, createdAt: before.run.updatedAt, origin: 'runtime',
      targetStatus: 'failed', reason: 'runtime_failed', runtimeSubtype: 'delivery_merge_limit_exceeded',
      sourceCheckpointId: initial.id, workspaceStateRef: initial.workspaceStateRef, sourceRunResultRef: ref,
      sourceBaseRef: ref, sourceDesiredRef: ref, capturedWorkspaceRef: ref, sourceProjectionRef: before.runSpec.sourceProjectionRef,
      sandboxProfileRef: before.runSpec.sandboxProfileRef, mergeAlgorithm: 'cliq-diff3-v1', limitKind: 'changed_paths', observed: 1, limit: 0 };
    const artifact = await fixture.store.artifacts.publishCanonical(intent, 'cliq-stop-intent-v1');
    // Deliberately corrupted retained data, never a positive Delivery admission
    // or a fabricated StateOwner/native proof. The actual reader must refuse.
    await assert.rejects(readAgentStop(held.driver, fixture.store.artifacts,
      { ...before, run: { ...before.run, stopIntentRef: artifact.ref } }), /resource stop has no reproducible failure|resource .*mismatch/u);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
