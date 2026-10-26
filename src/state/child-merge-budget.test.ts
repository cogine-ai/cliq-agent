import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { lstat, rename } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { prepareChildMergeAuthorization, approveChildMerge, readChildMergeApproval, readChildMergePendingBudgetData } from './child-merge-authorization.js';
import { readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { mergeChildResult } from './child-merge.js';
import { createChildMergeFixture } from './testing/child-runs.js';
import { createMergeApprovalFixture } from './testing/child-merge-approval.js';
import { disposeFixture, uuidv7 } from './testing/fixtures.js';
import { publishInProcessChannel } from './store.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateStore } from './store.js';

type Fixture = { runId: string; store: StateStore; driver: SqliteDriver };
async function source(fixture: Fixture) {
  const cut = await fixture.store.readRecoveryClosure(fixture.runId);
  return { runId: fixture.runId, sourceCheckpointId: cut.latestCheckpoint.id, sourceRunRevision: cut.run.revision,
    sourceJournalSeq: cut.journal.length, observedAt: sampleCanonicalNow() };
}

// Real ordinary Store/SQLite/CAS/owner and original admitted child/patch
// consumers; existing inert worker fixtures confer no Linux qualification.
test('pending merge cost reads the exact source with conservative sibling reservations, makes no grant, and becomes stale after the sole actual merge', async () => {
  const fixture = await createChildMergeFixture('pending-merge-cost-source', true, 2);
  try {
    const original = await source(fixture), before = canonicalJsonBytes(await fixture.store.readRecoveryClosure(fixture.runId)), fence = readTimeFence(fixture.driver);
    const facts = await readChildMergePendingBudgetData(fixture.driver, fixture.store.artifacts, original);
    assert.equal(facts?.required, 1); facts!.assertUnchanged(fixture.driver);
    assert.deepEqual(readTimeFence(fixture.driver), fence);
    assert.deepEqual(canonicalJsonBytes(await fixture.store.readRecoveryClosure(fixture.runId)), before);
    assert.equal(fixture.driver.prepare("SELECT count(*) AS n FROM run_journal WHERE run_id=? AND op_kind='child_merge'").get<{n:bigint}>(fixture.runId)!.n, 0n);
    await assert.rejects(readChildMergePendingBudgetData(fixture.driver, fixture.store.artifacts, { ...original, sourceRunRevision: original.sourceRunRevision + 1 }), { code: 'RECOVERY_REQUIRED' });
    await assert.rejects(readChildMergePendingBudgetData(fixture.driver, fixture.store.artifacts, { ...original, sourceJournalSeq: original.sourceJournalSeq + 1 }), { code: 'RECOVERY_REQUIRED' });
    await assert.rejects(readChildMergePendingBudgetData(fixture.driver, fixture.store.artifacts, { ...original, sourceCheckpointId: 'missing-original-checkpoint' }), { code: 'RECOVERY_REQUIRED' });
    const policyRef = (await fixture.store.readRecoveryClosure(fixture.runId)).runSpec.policyRef;
    const policy = path.join(fixture.stateRoot, 'cas', policyRef), retained = path.join(fixture.stateRoot, 'original-policy-for-budget-test');
    const birth = await lstat(policy, { bigint: true });
    await rename(policy, retained);
    try { await assert.rejects(readChildMergePendingBudgetData(fixture.driver, fixture.store.artifacts, original), { code: 'RECOVERY_REQUIRED' }); }
    finally { await rename(retained, policy); }
    const restored = await lstat(policy, { bigint: true });
    for (const key of ['dev', 'ino', 'uid', 'gid', 'mode', 'size', 'mtimeNs'] as const) assert.equal(restored[key], birth[key]);
    await fixture.store.readRecoveryClosure(fixture.runId);
    const merged = await mergeChildResult(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: fixture.store.getRun(fixture.runId).revision, releaseKeys: fixture.signed.releaseKeys });
    assert.equal(merged.run.budgetReserved.modelTokens > 0, true, 'the independent sibling remains conservatively reserved');
    assert.throws(() => facts!.assertUnchanged(fixture.driver));
    assert.equal(await readChildMergePendingBudgetData(fixture.driver, fixture.store.artifacts, original), undefined);
    assert.equal(await readChildMergePendingBudgetData(fixture.driver, fixture.store.artifacts, await source(fixture)), undefined);
  } finally { await disposeFixture(fixture); }
});

test('only the actual unused allow proves pending cost; original source remains readable after real Stop and natural expiry cannot rewrite its observation', async () => {
  const fixture = await createMergeApprovalFixture('pending-merge-approved-original');
  try {
    assert.equal(await readChildMergePendingBudgetData(fixture.driver, fixture.store.artifacts, await source(fixture)), undefined);
    const waiting = await prepareChildMergeAuthorization(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: fixture.store.getRun(fixture.runId).revision, releaseKeys: fixture.signed.releaseKeys });
    if (waiting.disposition !== 'waiting') throw new Error('default merge must obtain its own approval');
    assert.equal(await readChildMergePendingBudgetData(fixture.driver, fixture.store.artifacts, await source(fixture)), undefined);
    const core = { protocolVersion: 1 as const, method: 'run.approve' as const, runId: fixture.runId, requestId: uuidv7(),
      expectedRevision: waiting.run.revision, waitingOnRef: waiting.run.waitingOnRef!, decision: 'allow' as const, ttlMs: 3000 };
    const approved = await approveChildMerge(fixture.driver, fixture.store.artifacts, fixture.owner,
      { request: { ...core, requestDigest: canonicalSha256(core) }, identity: await publishInProcessChannel(fixture.store), releaseKeys: fixture.signed.releaseKeys });
    const grant = await readChildMergeApproval(fixture.driver, fixture.store.artifacts, fixture.runId, approved.response.result.decisionRef);
    const original = await source(fixture);
    assert.notEqual(original.sourceCheckpointId, grant.request.sourceCheckpointId, 'approval CP does not replace the original authorized source');
    const proof = await readChildMergePendingBudgetData(fixture.driver, fixture.store.artifacts, original);
    assert.equal(proof?.required, 1);
    const cancelled = await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(),
      expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    assert.throws(() => proof!.assertUnchanged(fixture.driver));
    await fixture.agent.commitTerminalStop({ expectedRunRevision: cancelled.run.revision });
    assert.equal((await readChildMergePendingBudgetData(fixture.driver, fixture.store.artifacts, original))?.required, 1);
    await delay(Math.max(0, Date.parse(grant.grant!.expiresAt) - Date.now()) + 2);
    assert.equal(await readChildMergePendingBudgetData(fixture.driver, fixture.store.artifacts, { ...original, observedAt: sampleCanonicalNow() }), undefined);
    assert.equal((await readChildMergePendingBudgetData(fixture.driver, fixture.store.artifacts, original))?.required, 1);
    assert.equal(fixture.driver.prepare("SELECT count(*) AS n FROM run_journal WHERE run_id=? AND op_kind='child_merge'").get<{n:bigint}>(fixture.runId)!.n, 0n);
  } finally { await disposeFixture(fixture); }
});

test('an actual merge denial cannot become a budget-cost proof', async () => {
  const fixture = await createMergeApprovalFixture('pending-merge-denied-source');
  try {
    const waiting = await prepareChildMergeAuthorization(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: fixture.store.getRun(fixture.runId).revision, releaseKeys: fixture.signed.releaseKeys });
    if (waiting.disposition !== 'waiting') throw new Error('default merge must ask');
    const core = { protocolVersion: 1 as const, method: 'run.approve' as const, runId: fixture.runId, requestId: uuidv7(),
      expectedRevision: waiting.run.revision, waitingOnRef: waiting.run.waitingOnRef!, decision: 'deny' as const };
    await approveChildMerge(fixture.driver, fixture.store.artifacts, fixture.owner,
      { request: { ...core, requestDigest: canonicalSha256(core) }, identity: await publishInProcessChannel(fixture.store), releaseKeys: fixture.signed.releaseKeys });
    assert.equal(await readChildMergePendingBudgetData(fixture.driver, fixture.store.artifacts, await source(fixture)), undefined);
  } finally { await disposeFixture(fixture); }
});
