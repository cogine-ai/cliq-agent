import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { approveChildMerge, prepareChildMergeAuthorization, readChildMergeApproval, readPreparedChildMergeAuthorization } from './child-merge-authorization.js';
import { advanceTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { publishInProcessChannel } from './store.js';
import { uuidv7 } from './testing/fixtures.js';
import type { RunApproveRequestV1 } from '../kernel/control-wire.js';
import { createChildMergeFixture } from './testing/child-runs.js';
import { disposeFixture } from './testing/fixtures.js';

// Genuine Store/StateOwner/SQLite/CAS, with the original explicitly inert
// worker/model fixture observations. No local merge effect or native/backend
// qualification is simulated by this prepared-permission component.
test('a genuine owner prepares the complete exact CAS merge and only its one-use capability authorizes the same local commit cut', async () => {
  const fixture = await createChildMergeFixture('merge-authority-direct', true);
  try {
    const before = canonicalJsonBytes(await fixture.store.readRecoveryClosure(fixture.runId));
    const selected = await prepareChildMergeAuthorization(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: fixture.store.getRun(fixture.runId).revision, releaseKeys: fixture.signed.releaseKeys });
    assert.equal(selected.disposition, 'prepared');
    if (selected.disposition !== 'prepared') throw new Error('yolo exact write path should be an explicit local allow');
    const facts = readPreparedChildMergeAuthorization(fixture.driver, fixture.owner, selected.token);
    assert.equal(facts.disposition, 'allow'); assert.equal(facts.grant?.subject.kind, 'child_merge');
    assert.equal(facts.target.execution.handlerId, 'child_merge'); assert.equal(facts.source.computation.kind, 'ready');
    assert.deepEqual(facts.evidence.canonicalRootRelativePaths, ['a']);
    assert.equal(facts.target.changedPathsDigest, canonicalSha256(['a']));
    assert.equal(facts.request.sourceCheckpointId, facts.source.checkpoint.id);
    assert.equal(facts.request.workspaceStateRef, facts.source.checkpoint.workspaceStateRef);
    assert.equal(typeof facts.source.workspaceStateRef, 'string');
    assert.notEqual(facts.source.workspaceStateRef, facts.request.workspaceStateRef);
    const workspace = await fixture.store.artifacts.readCanonical<{ runId: string; baseWorkspaceManifestRef: string }>(facts.source.workspaceStateRef!);
    assert.equal(workspace.runId, fixture.runId);
    assert.equal(workspace.baseWorkspaceManifestRef, facts.source.spec.baseWorkspaceManifestRef);
    assert.equal(facts.grantRef, canonicalSha256(facts.grant));
    for (const artifact of facts.metadata) await fixture.store.artifacts.verifyBytes(artifact.ref);
    assert.throws(() => readPreparedChildMergeAuthorization(fixture.driver, fixture.owner, facts.grant as never), { code: 'RECOVERY_REQUIRED' });
    assert.throws(() => readPreparedChildMergeAuthorization(fixture.driver, fixture.owner, {} as never), { code: 'RECOVERY_REQUIRED' });
    fixture.driver.transaction(connection => {
      const now = sampleCanonicalNow(); assert.equal(advanceTimeFence(connection, fixture.owner.ownerEpoch, now), 'healthy');
      facts.assertCommit(connection, now);
      assert.throws(() => facts.assertCommit(connection, now), { code: 'RECOVERY_REQUIRED' });
    });
    assert.throws(() => readPreparedChildMergeAuthorization(fixture.driver, fixture.owner, selected.token), { code: 'RECOVERY_REQUIRED' });
    assert.deepEqual(canonicalJsonBytes(await fixture.store.readRecoveryClosure(fixture.runId)), before);
    assert.equal(fixture.driver.prepare("SELECT count(*) AS n FROM run_journal WHERE run_id=? AND op_kind='child_merge'")
      .get<{ n: bigint }>(fixture.runId)!.n, 0n, 'permission preparation does not claim or execute a merge');
  } finally { await disposeFixture(fixture); }
});

test('the original delegate approval does not authorize the parent merge and a real default-policy merge installs its own exact wait', async () => {
  const { createMergeApprovalFixture } = await import('./testing/child-merge-approval.js');
  const { validateChildMergeAuthorizationHistory } = await import('./child-merge-authorization.js');
  const { decodeChildMergeApprovalWait } = await import('../kernel/child-merge.js');
  const fixture = await createMergeApprovalFixture('merge-must-have-own-approval');
  try {
    const before = fixture.store.getRun(fixture.runId), journal = fixture.driver.prepare('SELECT * FROM run_journal WHERE run_id=? ORDER BY seq').all(fixture.runId);
    const prepared = await prepareChildMergeAuthorization(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: before.revision, releaseKeys: fixture.signed.releaseKeys });
    assert.equal(prepared.disposition, 'waiting');
    if (prepared.disposition !== 'waiting') throw new Error('ordinary delegate approval cannot substitute for current fs-write permission');
    assert.equal(prepared.run.status, 'waiting'); assert.equal(prepared.run.waitingReason, 'approval');
    assert.equal(prepared.run.activeWorkerLaunchId, undefined); assert.equal(prepared.run.revision, before.revision + 1);
    const wait = decodeChildMergeApprovalWait(await fixture.store.artifacts.readCanonical(prepared.run.waitingOnRef!));
    assert.equal(wait.subject.kind, 'child_merge'); assert.equal(wait.subject.childRunId, fixture.children[0]!.childRunId);
    assert.notEqual(wait.subject.policyChannelEvidenceRef, fixture.originalDelegateApproval.result.decisionRef);
    assert.deepEqual(fixture.driver.prepare('SELECT * FROM run_journal WHERE run_id=? ORDER BY seq').all(fixture.runId), journal);
    const rows = fixture.driver.prepare('SELECT item_id,payload_ref FROM items WHERE run_id=? ORDER BY item_seq')
      .all<{ item_id: string; payload_ref: string }>(fixture.runId);
    const entries = await fixture.store.artifacts.mapReads(rows, async row => [row.item_id,
      await fixture.store.artifacts.readCanonical<import('../kernel/types.js').ContinuationItem>(row.payload_ref)] as const);
    await validateChildMergeAuthorizationHistory(fixture.driver, fixture.store.artifacts, { run: prepared.run, items: new Map(entries) });
    await assert.rejects(validateChildMergeAuthorizationHistory(fixture.driver, fixture.store.artifacts,
      { run: prepared.run, items: new Map() }), { code: 'RECOVERY_REQUIRED' });
  } finally { await disposeFixture(fixture); }
});

test('a real authenticated merge approval preserves its original first response and source while a separate explicit refusal cannot be reevaluated into permission', async () => {
  const { createMergeApprovalFixture } = await import('./testing/child-merge-approval.js');
  for (const decision of ['allow', 'deny'] as const) {
    const fixture = await createMergeApprovalFixture(`merge-public-${decision}`);
    try {
      const selected = await prepareChildMergeAuthorization(fixture.driver, fixture.store.artifacts, fixture.owner,
        { runId: fixture.runId, expectedRunRevision: fixture.store.getRun(fixture.runId).revision, releaseKeys: fixture.signed.releaseKeys });
      if (selected.disposition !== 'waiting') throw new Error('default merge must require its own public approval');
      const before = selected.run, identity = await publishInProcessChannel(fixture.store);
      const core = { protocolVersion: 1 as const, method: 'run.approve' as const, runId: fixture.runId, requestId: uuidv7(),
        expectedRevision: before.revision, waitingOnRef: before.waitingOnRef!, decision };
      const request: RunApproveRequestV1 = { ...core, requestDigest: canonicalSha256(core) };
      const approved = await approveChildMerge(fixture.driver, fixture.store.artifacts, fixture.owner,
        { request, identity, releaseKeys: fixture.signed.releaseKeys });
      assert.equal(approved.replayed, false); assert.equal(approved.run.status, 'queued');
      assert.equal(approved.run.revision, before.revision + 1); assert.equal(approved.run.activeWorkerLaunchId, undefined);
      assert.equal(approved.run.waitingOnRef, undefined); assert.equal(approved.run.waitingReason, undefined);
      assert.deepEqual(approved.run.budgetConsumed, before.budgetConsumed); assert.deepEqual(approved.run.budgetReserved, before.budgetReserved);
      const historical = await readChildMergeApproval(fixture.driver, fixture.store.artifacts, fixture.runId, approved.response.result.decisionRef);
      assert.equal(historical.decision.decision, decision); assert.equal(historical.grant?.subject.kind, decision === 'allow' ? 'child_merge' : undefined);
      const replay = await approveChildMerge(fixture.driver, fixture.store.artifacts, fixture.owner,
        { request, identity: await publishInProcessChannel(fixture.store), releaseKeys: fixture.signed.releaseKeys });
      assert.equal(replay.replayed, true); assert.deepEqual(canonicalJsonBytes(replay.response), canonicalJsonBytes(approved.response));
      const permission = await prepareChildMergeAuthorization(fixture.driver, fixture.store.artifacts, fixture.owner,
        { runId: fixture.runId, expectedRunRevision: approved.run.revision, releaseKeys: fixture.signed.releaseKeys });
      if (permission.disposition !== 'prepared') throw new Error('a decided merge must preserve its original allow or refusal');
      const facts = readPreparedChildMergeAuthorization(fixture.driver, fixture.owner, permission.token);
      assert.equal(facts.disposition, decision); assert.equal(facts.appendDecisionItem, false);
      assert.equal(facts.request.sourceCheckpointId, historical.request.sourceCheckpointId);
      assert.notEqual(facts.request.sourceCheckpointId, approved.run.latestCheckpointId);
      assert.deepEqual(canonicalJsonBytes(facts.request), canonicalJsonBytes(historical.request));
      await fixture.store.readRecoveryClosure(fixture.runId);
      assert.equal(fixture.driver.prepare("SELECT count(*) AS n FROM run_journal WHERE run_id=? AND op_kind='child_merge'")
        .get<{ n: bigint }>(fixture.runId)!.n, 0n, 'approval never executes or claims the merge');
    } finally { await disposeFixture(fixture); }
  }
});

test('an unused merge approval expires on its original TTL and only a new explicit approval can continue the same immutable source', async () => {
  const { createMergeApprovalFixture } = await import('./testing/child-merge-approval.js');
  const fixture = await createMergeApprovalFixture('merge-expiry-original-response');
  try {
    const first = await prepareChildMergeAuthorization(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: fixture.store.getRun(fixture.runId).revision, releaseKeys: fixture.signed.releaseKeys });
    if (first.disposition !== 'waiting') throw new Error('default merge must ask');
    const makeRequest = (run: typeof first.run, ttlMs?: number): RunApproveRequestV1 => {
      const core = { protocolVersion: 1 as const, method: 'run.approve' as const, runId: fixture.runId, requestId: uuidv7(),
        expectedRevision: run.revision, waitingOnRef: run.waitingOnRef!, decision: 'allow' as const, ...(ttlMs === undefined ? {} : { ttlMs }) };
      return { ...core, requestDigest: canonicalSha256(core) };
    };
    const firstRequest = makeRequest(first.run, 3000);
    const approved = await approveChildMerge(fixture.driver, fixture.store.artifacts, fixture.owner,
      { request: firstRequest, identity: await publishInProcessChannel(fixture.store), releaseKeys: fixture.signed.releaseKeys });
    const original = await readChildMergeApproval(fixture.driver, fixture.store.artifacts, fixture.runId, approved.response.result.decisionRef);
    assert.equal(Date.parse(original.grant!.expiresAt) - Date.parse(original.grant!.issuedAt), 3000);
    await delay(Math.max(0, Date.parse(original.grant!.expiresAt) - Date.now()) + 2);
    const renewed = await prepareChildMergeAuthorization(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: approved.run.revision, releaseKeys: fixture.signed.releaseKeys });
    if (renewed.disposition !== 'waiting') throw new Error('expiry must request a new explicit approval rather than extend the old grant');
    assert.notEqual(renewed.run.waitingOnRef, first.run.waitingOnRef);
    const secondRequest = makeRequest(renewed.run);
    const second = await approveChildMerge(fixture.driver, fixture.store.artifacts, fixture.owner,
      { request: secondRequest, identity: await publishInProcessChannel(fixture.store), releaseKeys: fixture.signed.releaseKeys });
    const current = await readChildMergeApproval(fixture.driver, fixture.store.artifacts, fixture.runId, second.response.result.decisionRef);
    assert.deepEqual(canonicalJsonBytes(current.request), canonicalJsonBytes(original.request));
    assert.equal(current.grant!.issuedAt >= original.grant!.expiresAt, true);
    const replay = await approveChildMerge(fixture.driver, fixture.store.artifacts, fixture.owner,
      { request: firstRequest, identity: await publishInProcessChannel(fixture.store), releaseKeys: fixture.signed.releaseKeys });
    assert.deepEqual(canonicalJsonBytes(replay.response), canonicalJsonBytes(approved.response));
    const row = fixture.driver.prepare("SELECT response_ref FROM control_requests WHERE principal_id=? AND method='run.approve' AND request_id=?")
      .get<{ response_ref: string }>(original.principalId, firstRequest.requestId)!;
    const other = fixture.driver.prepare("SELECT response_ref FROM control_requests WHERE principal_id=? AND method='run.approve' AND request_id=?")
      .get<{ response_ref: string }>(original.principalId, secondRequest.requestId)!;
    try {
      // Deliberate retained-data corruption is a refusal input only. Both
      // approvals were genuinely committed for this same Run/principal.
      fixture.driver.prepare("UPDATE control_requests SET response_ref=? WHERE principal_id=? AND method='run.approve' AND request_id=?")
        .run(other.response_ref, original.principalId, firstRequest.requestId);
      await assert.rejects(approveChildMerge(fixture.driver, fixture.store.artifacts, fixture.owner,
        { request: firstRequest, identity: await publishInProcessChannel(fixture.store), releaseKeys: fixture.signed.releaseKeys }),
      { code: 'RECOVERY_REQUIRED' });
    } finally {
      fixture.driver.prepare("UPDATE control_requests SET response_ref=? WHERE principal_id=? AND method='run.approve' AND request_id=?")
        .run(row.response_ref, original.principalId, firstRequest.requestId);
    }
    await fixture.store.readRecoveryClosure(fixture.runId);
    const restored = await approveChildMerge(fixture.driver, fixture.store.artifacts, fixture.owner,
      { request: firstRequest, identity: await publishInProcessChannel(fixture.store), releaseKeys: fixture.signed.releaseKeys });
    assert.deepEqual(canonicalJsonBytes(restored.response), canonicalJsonBytes(approved.response));
  } finally { await disposeFixture(fixture); }
});

test('a genuine Stop can retain the exact merge approval wait for recovery while every new permission and approval stays fenced', async () => {
  const { createMergeApprovalFixture } = await import('./testing/child-merge-approval.js');
  const fixture = await createMergeApprovalFixture('merge-wait-real-stop');
  try {
    const selected = await prepareChildMergeAuthorization(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: fixture.store.getRun(fixture.runId).revision, releaseKeys: fixture.signed.releaseKeys });
    if (selected.disposition !== 'waiting') throw new Error('default merge must ask');
    const stopped = await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(),
      expectedRunRevision: selected.run.revision });
    assert.equal(stopped.run.cancelRequested, true); assert.equal(typeof stopped.run.stopIntentRef, 'string');
    assert.equal(stopped.run.waitingOnRef, selected.run.waitingOnRef); assert.equal(stopped.run.latestCheckpointId, selected.run.latestCheckpointId);
    assert.equal(stopped.run.revision, selected.run.revision + 1);
    await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(prepareChildMergeAuthorization(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: stopped.run.revision, releaseKeys: fixture.signed.releaseKeys }),
    { code: 'STATE_TRANSITION_INVALID' });
    const core = { protocolVersion: 1 as const, method: 'run.approve' as const, requestId: uuidv7(), runId: fixture.runId,
      expectedRevision: stopped.run.revision, waitingOnRef: stopped.run.waitingOnRef!, decision: 'allow' as const };
    await assert.rejects(approveChildMerge(fixture.driver, fixture.store.artifacts, fixture.owner,
      { request: { ...core, requestDigest: canonicalSha256(core) }, identity: await publishInProcessChannel(fixture.store), releaseKeys: fixture.signed.releaseKeys }),
    { code: 'STATE_TRANSITION_INVALID' });
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: stopped.run.revision });
    assert.equal(terminal.run.status, 'cancelled');
    await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(fixture.driver.prepare("SELECT count(*) AS n FROM run_journal WHERE run_id=? AND op_kind='child_merge'")
      .get<{ n: bigint }>(fixture.runId)!.n, 0n);
  } finally { await disposeFixture(fixture); }
});
