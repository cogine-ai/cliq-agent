import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { RunApproveRequestV1 } from '../kernel/control-wire.js';
import type { ContinuationItem } from '../kernel/types.js';
import { approveChildMerge, readChildMergeAuthorization } from './child-merge-authorization.js';
import { mergeChildResult } from './child-merge.js';
import { publishInProcessChannel } from './store.js';
import { createMergeApprovalFixture } from './testing/child-merge-approval.js';
import { disposeFixture, uuidv7 } from './testing/fixtures.js';

// Actual original Store/StateOwner/public reducer/local effect path. The
// existing inert worker/model observations give no installed/native proof.
for (const decision of ['allow', 'deny'] as const) test(`an actual ${decision} merge approval survives the sole effect and exact lost-response replay without another use`, async () => {
  const f = await createMergeApprovalFixture(`child-merge-actual-use-${decision}`);
  try {
    const input = () => ({ runId: f.runId, expectedRunRevision: f.store.getRun(f.runId).revision, releaseKeys: f.signed.releaseKeys });
    const waiting = await mergeChildResult(f.driver, f.store.artifacts, f.owner, input());
    assert.equal(waiting.run.waitingReason, 'approval'); assert.equal(waiting.run.activeWorkerLaunchId, undefined);
    const before = await f.store.readRecoveryClosure(f.runId), core = { protocolVersion: 1 as const, method: 'run.approve' as const,
      requestId: uuidv7(), runId: f.runId, expectedRevision: waiting.run.revision, waitingOnRef: waiting.run.waitingOnRef!, decision };
    const request: RunApproveRequestV1 = { ...core, requestDigest: canonicalSha256(core) };
    const response = await approveChildMerge(f.driver, f.store.artifacts, f.owner,
      { request, identity: await publishInProcessChannel(f.store), releaseKeys: f.signed.releaseKeys });
    const authorized = await f.store.readRecoveryClosure(f.runId), committed = await mergeChildResult(f.driver, f.store.artifacts, f.owner, input());
    assert.equal(committed.run.nextStep, 'agent'); assert.equal(committed.run.waitingReason, undefined);
    const after = await f.store.readRecoveryClosure(f.runId), local = after.journal.filter(row => row.opKind === 'child_merge');
    assert.deepEqual(after.childAllocations, before.childAllocations);
    assert.equal(after.run.budgetConsumed.toolCalls, authorized.run.budgetConsumed.toolCalls + (decision === 'allow' ? 1 : 0));
    assert.equal(local.length, decision === 'allow' ? 3 : 0);
    if (decision === 'allow') assert.deepEqual(local.map(row => row.phase), ['prepared', 'dispatch_claimed', 'completed']);
    const items = await f.store.artifacts.mapReads(after.items, row => f.store.artifacts.readCanonical<ContinuationItem>(row.payloadRef));
    const merge = items.filter(item => item.kind === 'child_merge_result'); assert.equal(merge.length, 1);
    assert.equal(merge[0]!.outcome, decision === 'allow' ? 'merged' : 'denied');
    const policy = items.filter(item => item.kind === 'policy_decision' && item.subjectKind === 'child_merge'); assert.equal(policy.length, 1);
    const original = await readChildMergeAuthorization(f.driver, f.store.artifacts, f.runId, policy[0]!.itemId);
    assert.equal(original.localUse.operationUsed, decision === 'allow');
    if (decision === 'allow') {
      assert.equal(local[0]!.grantRef, canonicalSha256(original.grant));
      assert.equal(local[0]!.requestRef, canonicalSha256(original.request));
      assert(local[0]!.timestamp >= original.grant!.issuedAt); assert(local[0]!.localCommittedAt! < original.grant!.expiresAt);
      assert.notEqual(after.latestCheckpoint.workspaceStateRef, before.latestCheckpoint.workspaceStateRef);
    } else assert.equal(after.latestCheckpoint.workspaceStateRef, before.latestCheckpoint.workspaceStateRef);
    const replay = await approveChildMerge(f.driver, f.store.artifacts, f.owner,
      { request, identity: await publishInProcessChannel(f.store), releaseKeys: f.signed.releaseKeys });
    assert.equal(replay.replayed, true); assert.deepEqual(canonicalJsonBytes(replay.response), canonicalJsonBytes(response.response));
    await assert.rejects(mergeChildResult(f.driver, f.store.artifacts, f.owner, input()));
    assert.deepEqual(await f.store.readRecoveryClosure(f.runId), after);
  } finally { await disposeFixture(f); }
});
