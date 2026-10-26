import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import { readChildMergePlan, readRetainedChildMergePlan } from './child-merge-plan.js';
import { createChildMergeFixture } from './testing/child-runs.js';
import { disposeFixture } from './testing/fixtures.js';

// Real ordinary Store lifecycle with existing inert physical-proof fixtures.
// This plans CAS only; no merge grant, mutation or new generation is created.
test('child merge reuses complete B/S/current-parent data and plans a logical workspace retaining the parent original base', async () => {
  const fixture = await createChildMergeFixture('child-merge-original-plan', true);
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const plan = await readChildMergePlan(fixture.driver, fixture.store.artifacts, fixture.runId);
    assert(plan.workers.length >= 2, 'both actual parent worker births remain in the complete retired source graph');
    assert(plan.workers.every(worker => worker.phase === 'retired'));
    assert(plan.workers.some(worker => worker.leaseEpoch === plan.run.leaseEpoch));
    assert.equal(plan.computation.kind, 'ready');
    if (plan.computation.kind !== 'ready') throw new Error('disjoint child change should plan a complete merge');
    assert.equal(plan.computation.noOp, false);
    assert.deepEqual(plan.changedPaths, ['a']);
    assert.equal(plan.computation.diff.operations.length, 1);
    assert.equal(plan.computation.diff.baseSourceRef, plan.capturedWorkspaceRef);
    assert.equal(plan.sourceBaseRef, plan.child.spec.baseWorkspaceManifestRef);
    const workspace = parseJsonStrict(Buffer.from(plan.workspacePlan!.bytes).toString('utf8')) as { runId: string; baseWorkspaceManifestRef: string };
    assert.equal(workspace.runId, fixture.runId);
    assert.equal(workspace.baseWorkspaceManifestRef, before.runSpec.baseWorkspaceManifestRef);
    assert.notEqual(plan.workspacePlan!.ref, before.latestCheckpoint.workspaceStateRef);
    const original = await readRetainedChildMergePlan(fixture.driver, fixture.store.artifacts, fixture.runId,
      { mergeBatchItemId: plan.batch.itemId, callIndex: plan.call.index, sourceCheckpointId: plan.checkpoint.id });
    if (original.computation.kind !== 'ready') throw new Error('original retained computation changed kind');
    const { publications: currentPublications, ...currentData } = plan.computation;
    const { publications: originalPublications, ...originalData } = original.computation;
    assert.deepEqual(canonicalJsonBytes(originalData), canonicalJsonBytes(currentData));
    assert.deepEqual(originalPublications.map(item => item.ref), currentPublications.map(item => item.ref));
    original.assertUnchanged(fixture.driver); plan.assertUnchanged(fixture.driver);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('an awaited child can merge while its independent sibling remains reserved and runnable', async () => {
  const fixture = await createChildMergeFixture('child-merge-owned-subset', false, 2);
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const sibling = fixture.store.getRun(fixture.children[1]!.childRunId);
    assert.equal(sibling.status, 'queued');
    assert(before.run.budgetReserved.modelTokens > 0);
    const plan = await readChildMergePlan(fixture.driver, fixture.store.artifacts, fixture.runId);
    assert.equal(plan.child.run.id, fixture.children[0]!.childRunId);
    assert.equal(plan.computation.kind, 'ready');
    assert.equal(sibling.budgetConsumed.modelTokens, 0);
    assert.deepEqual(canonicalJsonBytes(plan.run.budgetReserved),
      canonicalJsonBytes(before.childAllocations.find(row => row.childRunId === sibling.id)!.grantedAdditiveCeilings));
    assert.deepEqual(fixture.store.getRun(sibling.id), sibling);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
