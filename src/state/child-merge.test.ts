import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import type { ContinuationItem, RunFrontier, WorkspaceStateManifest } from '../kernel/types.js';
import { mergeChildResult } from './child-merge.js';
import { readChildMergePlan } from './child-merge-plan.js';
import { readCandidateSource } from './result-source.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { activateOfflineChild, completeOfflineChild, createChildMergeFixture, createChildRunFixture } from './testing/child-runs.js';
import { activateFixtureWorker, disposeFixture } from './testing/fixtures.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';
import { retireFixtureToolSelection } from './testing/tool-effects.js';
import { readResourceStopCause } from './resource-stop.js';
import { sampleCanonicalNow } from './canonical-time.js';

// Actual ordinary Store/SQLite/CAS/StateOwner and the existing explicitly inert
// model/worker fixtures. No Linux, physical retirement or provider claim.
test('a genuinely exhausted pending merge registers the original resource Stop and terminates without a local claim or second child settlement', async () => {
  const f = await createChildRunFixture('child-pending-merge-budget-stop', 1, { mode: 'mutating', parentBudgets: { toolCalls: 8 } });
  try {
    Object.assign(f, await activateFixtureWorker(f, 'parent-consumes-merge-floor', 30_000));
    await batch(f, [{ name: 'read', input: { path: 'a' } }]);
    let prepared = await prepareTool(f), claimed = await claimTool(f, prepared);
    await f.agent.completeTool({ opId: prepared.entry.opId, attempt: prepared.entry.attempt, expectedRunRevision: prepared.run.revision,
      observationRef: await observation(f, claimed, { text: 'ordinary parent read' }) });
    await batch(f, [{ name: 'await_children', input: { childRunIds: [f.children[0]!.childRunId] } }]);
    const selection = await f.agent.prepareTool({ expectedRunRevision: f.store.getRun(f.runId).revision, leaseEpoch: f.leaseEpoch });
    if (selection.disposition !== 'retirement_required') throw new Error('parent await must retire its own original worker');
    await retireFixtureToolSelection(f, selection);
    const waiting = await f.agent.waitForChildren({ expectedRunRevision: f.store.getRun(f.runId).revision });
    const child = await activateOfflineChild(f);
    await batch(child, Array.from({ length: 5 }, () => ({ name: 'read', input: { path: 'a' } })));
    for (let i = 0; i < 5; i++) {
      prepared = await prepareTool(child); claimed = await claimTool(child, prepared);
      await child.agent.completeTool({ opId: prepared.entry.opId, attempt: prepared.entry.attempt, expectedRunRevision: prepared.run.revision,
        observationRef: await observation(child, claimed, { text: `ordinary child read ${i}` }) });
    }
    await completeOfflineChild(child, { changedWorkspace: true });
    await f.agent.settleChildren({ expectedRunRevision: waiting.run.revision });
    const before = await f.store.readRecoveryClosure(f.runId);
    assert.equal(before.run.budgetConsumed.toolCalls, 8); assert.equal(before.run.budgetReserved.toolCalls, 0);
    await assert.rejects(mergeChildResult(f.driver, f.store.artifacts, f.owner, { runId: f.runId,
      expectedRunRevision: before.run.revision, releaseKeys: f.signed.releaseKeys }), { code: 'BUDGET_EXHAUSTED' });
    assert.deepEqual(await f.store.readRecoveryClosure(f.runId), before);
    const cause = await readResourceStopCause(f.driver, f.store.artifacts, before, sampleCanonicalNow());
    assert.deepEqual(cause, { origin: 'budget', targetStatus: 'failed', reason: 'budget_exhausted', counter: 'toolCalls',
      ceiling: 8, consumed: 8, reserved: 0, required: 1 });
    const stopped = await f.agent.stopForResourceFailure({ expectedRunRevision: before.run.revision });
    const intent = await f.store.artifacts.readCanonical<import('../runtime/stop.js').AgentStopIntent>(stopped.run.stopIntentRef!);
    assert.equal(intent.origin, 'budget'); assert.equal(intent.registeredCheckpointId, before.latestCheckpoint.id);
    assert.equal(intent.registeredRunRevision, before.run.revision); assert.equal(intent.registeredJournalSeq, before.journal.length);
    const terminal = await f.agent.commitTerminalStop({ expectedRunRevision: stopped.run.revision });
    assert.equal(terminal.run.status, 'failed'); assert.equal(terminal.run.terminalReason, 'budget_exhausted');
    assert.equal(terminal.run.budgetConsumed.toolCalls, 8);
    const after = await f.store.readRecoveryClosure(f.runId);
    assert.deepEqual(after.journal, before.journal); assert.deepEqual(after.childAllocations, before.childAllocations);
    assert.equal(after.journal.some(row => row.opKind === 'child_merge'), false);
    assert.deepEqual(await f.agent.commitTerminalStop({ expectedRunRevision: terminal.run.revision }), terminal);
  } finally { await disposeFixture(f); }
});

test('a successful ordinary child patch commits one local merge and a logical ready workspace without changing the old sealed generation', async () => {
  const fixture = await createChildMergeFixture('child-merge-complete-effect', true);
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const workers = readWorkerLaunchesForRun(fixture.driver, fixture.runId);
    const generations = readWorkspaceGenerationsForRun(fixture.driver, fixture.runId);
    const planned = await readChildMergePlan(fixture.driver, fixture.store.artifacts, fixture.runId);
    assert.equal(planned.computation.kind, 'ready');
    const merged = await mergeChildResult(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: before.run.revision, releaseKeys: fixture.signed.releaseKeys });
    assert.equal(merged.run.status, 'queued'); assert.equal(merged.run.nextStep, 'agent');
    assert.equal(merged.run.activeWorkerLaunchId, undefined); assert.equal(merged.run.leaseEpoch, before.run.leaseEpoch);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(after.journal.length, before.journal.length + 3);
    assert.deepEqual(after.journal.slice(-3).map(row => row.phase), ['prepared', 'dispatch_claimed', 'completed']);
    assert(after.journal.slice(-3).every(row => row.opKind === 'child_merge' && row.leaseEpoch === 0 && row.attempt === 0 && row.replayClass === 'retry'));
    assert(after.journal.slice(-3).every(row => !row.sandboxLaunchSpecRef && !row.brokerFenceTokenDigest));
    assert.equal(after.run.budgetConsumed.toolCalls, before.run.budgetConsumed.toolCalls + 1);
    assert.deepEqual(after.run.budgetReserved, before.run.budgetReserved);
    assert.deepEqual(readWorkerLaunchesForRun(fixture.driver, fixture.runId), workers);
    assert.deepEqual(readWorkspaceGenerationsForRun(fixture.driver, fixture.runId), generations);
    assert.notEqual(after.latestCheckpoint.workspaceStateRef, before.latestCheckpoint.workspaceStateRef);
    const workspace = await fixture.store.artifacts.readCanonical<WorkspaceStateManifest>(after.latestCheckpoint.workspaceStateRef);
    assert.equal(workspace.runId, fixture.runId); assert.equal(workspace.baseWorkspaceManifestRef, after.runSpec.baseWorkspaceManifestRef);
    const source = await readCandidateSource(fixture.store.artifacts, after.runSpec, after.latestCheckpoint.workspaceStateRef);
    assert.equal(planned.computation.kind === 'ready' && source.sourceRef, planned.computation.kind === 'ready' && planned.computation.sourceRef);
    const items = await fixture.store.artifacts.mapReads(after.items, row => fixture.store.artifacts.readCanonical<ContinuationItem>(row.payloadRef));
    assert.equal(items.filter(item => item.kind === 'child_merge_result').length, 1);
    const results = items.filter(item => item.kind === 'tool_result' && item.outcome === 'executed');
    assert.equal(results.length, 2, 'only the real delegate and real await provider calls have results');
    const last = results.at(-1)!;
    if (last.kind !== 'tool_result') throw new Error('expected real await result');
    const payload = await fixture.store.artifacts.readCanonical<{ modelContentRef: string }>(last.resultRef);
    const model = await fixture.store.artifacts.readCanonical<{ content: { merge: unknown } }>(payload.modelContentRef);
    assert.deepEqual(canonicalJsonBytes(model.content.merge), Buffer.from('{"appliedCalls":1,"chargedCalls":1,"outcome":"merged","processedCalls":1,"unattemptedCalls":0}'));
    await assert.rejects(mergeChildResult(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: after.run.revision, releaseKeys: fixture.signed.releaseKeys }));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), after);
  } finally { await disposeFixture(fixture); }
});

test('merge publications and the sole SQL effect fully join or roll back before the same stable call may commit', async () => {
  const fixture = await createChildMergeFixture('child-merge-publication-and-sql-fault', true);
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const original = fixture.store.artifacts.publishBytes.bind(fixture.store.artifacts);
    let pending = 0, held!: () => void, entered!: () => void;
    const gate = new Promise<void>(resolve => { held = resolve; });
    const reached = new Promise<void>(resolve => { entered = resolve; });
    fixture.store.artifacts.publishBytes = async (bytes, media, kind) => {
      pending++;
      try {
        const value = await original(bytes, media, kind);
        if (kind === 'cliq-budget-settlement-v1') { entered(); await gate; }
        return value;
      } finally { pending--; }
    };
    let merging: ReturnType<typeof mergeChildResult> | undefined;
    const input = { runId: fixture.runId, expectedRunRevision: before.run.revision, releaseKeys: fixture.signed.releaseKeys };
    // The ordinary publication is held only after its actual private CAS write;
    // this is a data lifecycle regression, not a process pause/death proof.
    try {
      merging = mergeChildResult(fixture.driver, fixture.store.artifacts, fixture.owner, input);
      let released = false;
      const joined = merging.then(result => {
        assert(released, 'merge committed before its original publication joined');
        return result;
      });
      await Promise.race([reached, joined]);
      assert.deepEqual(fixture.store.getRun(fixture.runId), before.run);
      assert.equal(Number(fixture.driver.prepare("SELECT count(*) AS n FROM run_journal WHERE run_id=? AND op_kind='child_merge'").get<{n:unknown}>(fixture.runId)!.n), 0);
      assert(pending > 0); released = true; held();
      await joined;
      assert.equal(pending, 0);
    } finally {
      held(); await merging?.catch(() => undefined); fixture.store.artifacts.publishBytes = original;
    }
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(after.journal.length, before.journal.length + 3);
  } finally { await disposeFixture(fixture); }
});

test('a failed merge transaction leaves no policy use, charge, item, cursor or logical workspace effect', async () => {
  const fixture = await createChildMergeFixture('child-merge-sql-atomicity', true);
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    fixture.driver.exec("CREATE TRIGGER fail_merge_checkpoint BEFORE INSERT ON checkpoints WHEN NEW.id NOT IN (SELECT id FROM checkpoints) AND EXISTS(SELECT 1 FROM run_journal WHERE run_id=NEW.run_id AND op_kind='child_merge' AND phase='completed') BEGIN SELECT RAISE(ABORT,'injected merge Checkpoint failure'); END");
    try {
      await assert.rejects(mergeChildResult(fixture.driver, fixture.store.artifacts, fixture.owner,
        { runId: fixture.runId, expectedRunRevision: before.run.revision, releaseKeys: fixture.signed.releaseKeys }), /injected merge Checkpoint failure/);
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    } finally { fixture.driver.exec('DROP TRIGGER fail_merge_checkpoint'); }
    const merged = await mergeChildResult(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: before.run.revision, releaseKeys: fixture.signed.releaseKeys });
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(merged.run.revision, before.run.revision + 1);
    assert.equal(after.journal.length, before.journal.length + 3);
    assert.equal(after.run.budgetConsumed.toolCalls, before.run.budgetConsumed.toolCalls + 1);
  } finally { await disposeFixture(fixture); }
});

test('a real CAS write failure joins its sibling publications and leaves the original merge call reusable once', async () => {
  const fixture = await createChildMergeFixture('child-merge-cas-write-failure', true);
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId), original = fixture.store.artifacts.publishBytes.bind(fixture.store.artifacts);
    let held!: () => void, entered!: () => void, failed!: () => void, pending = 0, released = false, finished = false;
    const gate = new Promise<void>(resolve => { held = resolve; }), reached = new Promise<void>(resolve => { entered = resolve; }),
      fault = new Promise<void>(resolve => { failed = resolve; });
    fixture.store.artifacts.publishBytes = async (bytes, media, kind) => {
      pending++;
      try {
        const value = await original(bytes, media, kind);
        if (kind === 'cliq-child-merge-receipt-v1') { entered(); await gate; }
        if (kind === 'cliq-budget-settlement-v1') { failed(); throw new Error('injected joined merge CAS failure'); }
        return value;
      } finally { pending--; }
    };
    let operation: ReturnType<typeof mergeChildResult> | undefined;
    try {
      operation = mergeChildResult(fixture.driver, fixture.store.artifacts, fixture.owner,
        { runId: fixture.runId, expectedRunRevision: before.run.revision, releaseKeys: fixture.signed.releaseKeys });
      const joined = operation.then(() => { finished = true; throw new Error('failed merge unexpectedly committed'); }, error => {
        finished = true; assert(released, 'failed merge returned before its actual sibling publication joined'); throw error;
      });
      void joined.catch(() => undefined);
      await Promise.all([reached, fault]); await new Promise<void>(resolve => setImmediate(resolve));
      assert.equal(finished, false); assert(pending > 0); assert.deepEqual(fixture.store.getRun(fixture.runId), before.run);
      released = true; held(); await assert.rejects(joined, /injected joined merge CAS failure/); assert.equal(pending, 0);
    } finally { released = true; held(); await operation?.catch(() => undefined); fixture.store.artifacts.publishBytes = original; }
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    await mergeChildResult(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: before.run.revision, releaseKeys: fixture.signed.releaseKeys });
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(after.journal.length, before.journal.length + 3);
    assert.equal(after.run.budgetConsumed.toolCalls, before.run.budgetConsumed.toolCalls + 1);
  } finally { await disposeFixture(fixture); }
});

test('two ordinary child patches merge serially and a real second-patch conflict preserves the first result without repeating either child', async () => {
  const fixture = await createChildRunFixture('child-merge-two-conflicting-patches', 2, { mode: 'mutating' });
  try {
    Object.assign(fixture, await activateFixtureWorker(fixture, 'parent-two-merge-await', 30_000));
    await batch(fixture, [{ name: 'await_children', input: { childRunIds: fixture.children.map(child => child.childRunId) } }]);
    const selected = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    if (selected.disposition !== 'retirement_required') throw new Error('original parent must retire before child wait');
    await retireFixtureToolSelection(fixture, selected);
    const waiting = await fixture.agent.waitForChildren({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    await completeOfflineChild(await activateOfflineChild(fixture, 0), { changedWorkspace: 'first child\n' });
    await completeOfflineChild(await activateOfflineChild(fixture, 1), { changedWorkspace: 'second child\n' });
    await fixture.agent.settleChildren({ expectedRunRevision: waiting.run.revision });
    const before = await fixture.store.readRecoveryClosure(fixture.runId), first = await mergeChildResult(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: before.run.revision, releaseKeys: fixture.signed.releaseKeys });
    const applied = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.notEqual(applied.latestCheckpoint.workspaceStateRef, before.latestCheckpoint.workspaceStateRef);
    assert.equal((await fixture.store.artifacts.readCanonical<RunFrontier>(applied.run.frontierRef!)).kind, 'tool');
    const conflict = await readChildMergePlan(fixture.driver, fixture.store.artifacts, fixture.runId);
    assert.equal(conflict.computation.kind, 'conflict');
    await mergeChildResult(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: first.run.revision, releaseKeys: fixture.signed.releaseKeys });
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(after.latestCheckpoint.workspaceStateRef, applied.latestCheckpoint.workspaceStateRef);
    assert.equal(after.journal.length, before.journal.length + 6);
    assert.equal(after.run.budgetConsumed.toolCalls, before.run.budgetConsumed.toolCalls + 2);
    assert.equal((await fixture.store.artifacts.readCanonical<RunFrontier>(after.run.frontierRef!)).kind, 'agent');
    const items = await fixture.store.artifacts.mapReads(after.items, row => fixture.store.artifacts.readCanonical<ContinuationItem>(row.payloadRef));
    assert.deepEqual(items.filter(item => item.kind === 'child_merge_result').map(item => item.outcome), ['merged', 'conflict']);
    const realAwait = items.filter(item => item.kind === 'tool_result').at(-1)!;
    if (realAwait.kind !== 'tool_result') throw new Error('missing true await result');
    const payload = await fixture.store.artifacts.readCanonical<{ modelContentRef: string }>(realAwait.resultRef),
      model = await fixture.store.artifacts.readCanonical<{ content: { merge: { appliedCalls: number; chargedCalls: number; conflicts: {total: number} } } }>(payload.modelContentRef);
    assert.equal(model.content.merge.appliedCalls, 1); assert.equal(model.content.merge.chargedCalls, 2);
    assert.equal(model.content.merge.conflicts.total, 1);
    await assert.rejects(mergeChildResult(fixture.driver, fixture.store.artifacts, fixture.owner,
      { runId: fixture.runId, expectedRunRevision: after.run.revision, releaseKeys: fixture.signed.releaseKeys }));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), after);
  } finally { await disposeFixture(fixture); }
});
