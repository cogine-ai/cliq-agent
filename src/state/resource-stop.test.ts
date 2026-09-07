import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { ContinuationItem, StopIntent, TerminalDetail } from '../kernel/types.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { AgentContextExhaustedError } from './reducers/agent.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture, uuidv7 } from './testing/fixtures.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';
import { fixtureInspector, quiescedToolCheckpoint } from './testing/tool-effects.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;
const revision = (fixture: Fixture) => fixture.store.getRun(fixture.runId).revision;
const stop = (fixture: Fixture) => fixture.agent.stopForResourceFailure({ expectedRunRevision: revision(fixture) });
async function cancel(fixture: Fixture) {
  return fixture.agent.cancelRun({ principalId: 'cliq-m2-principal', requestId: uuidv7(), expectedRunRevision: revision(fixture),
    ...await publishInProcessChannel(fixture.store, 'cliq-m2-principal') });
}
async function reopen(fixture: Fixture) {
  await fixture.store.close();
  fixture.store = await openStateStore(fixture.stateRoot);
  fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
}
async function finish(fixture: Fixture, checkpointId: string) {
  const run = fixture.store.getRun(fixture.runId);
  const proof = run.activeWorkerLaunchId ? await quiescedToolCheckpoint(fixture, checkpointId) : undefined;
  return fixture.agent.commitTerminalStop({ expectedRunRevision: run.revision, ...(proof ? { checkpoint: proof.checkpoint } : {}) });
}
async function modelTurn(fixture: Fixture, text: string, toolName?: string) {
  const prepared = await fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
  await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch,
    opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: `dispatch:${prepared.entry.opId}:${prepared.entry.attempt}` });
  const reader = fixture.agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
  reader.push(Buffer.from(JSON.stringify({ id: 'response', object: 'response', status: 'completed', model: 'model-1', output: [
    { type: 'message', id: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text, annotations: [] }] },
    ...(toolName ? [{ type: 'function_call', id: 'wire', call_id: 'call', name: toolName, arguments: '{}' }] : [])
  ] })));
  const completed = await fixture.agent.completeModel({ expectedRunRevision: revision(fixture), opId: prepared.entry.opId,
    attempt: prepared.entry.attempt, result: reader.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput) });
  return { prepared, completed };
}
async function longContext(fixture: Fixture, texts = ['a', 'b', 'c'].map((text) => text.repeat(28_000))) {
  for (const text of texts) assert.equal((await modelTurn(fixture, text, 'unknown')).completed.disposition, 'batch_rejected');
}

for (const [counter, required] of [['modelTokens', 40_960], ['costMicros', 114_688]] as const) {
  test(`${counter} exhaustion derives the exact next reservation and publishes one recoverable terminal Session item`, async () => {
    const fixture = await createAgentFixture(`resource-${counter}`, { [counter]: required - 1 }, { mode: 'plan' });
    try {
      const before = await fixture.store.readRecoveryClosure(fixture.runId);
      await assert.rejects(fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch }), { code: 'BUDGET_EXHAUSTED' });
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
      const raced = await Promise.allSettled([stop(fixture), stop(fixture)]);
      const winner = raced.find((result) => result.status === 'fulfilled');
      assert.ok(winner?.status === 'fulfilled');
      const loser = raced.find((result) => result.status === 'rejected');
      assert.ok(loser?.status === 'rejected');
      assert.equal(loser.reason.code, 'REVISION_CONFLICT');
      const stopped = winner.value;
      assert.deepEqual(await fixture.store.artifacts.readCanonical<StopIntent>(stopped.run.stopIntentRef!), {
        schemaVersion: 1, runId: fixture.runId, createdAt: stopped.run.updatedAt, origin: 'budget', targetStatus: 'failed',
        reason: 'budget_exhausted', counter, ceiling: required - 1, consumed: 0, reserved: 0, required
      });
      assert.equal((await stop(fixture)).run.stopIntentRef, stopped.run.stopIntentRef);
      await reopen(fixture);
      const sessionBefore = fixture.store.getSession(stopped.run.sessionId);
      const terminal = await finish(fixture, stopped.checkpointId);
      assert.equal(terminal.run.status, 'failed');
      assert.equal(terminal.run.terminalReason, 'budget_exhausted');
      assert.equal(terminal.run.cancelRequested, false);
      assert.deepEqual(terminal.run.budgetConsumed, before.run.budgetConsumed);
      const after = await fixture.store.readRecoveryClosure(fixture.runId);
      assert.deepEqual(after.journal, before.journal);
      const detail = await fixture.store.artifacts.readCanonical<TerminalDetail>(terminal.run.terminalDetailRef!);
      assert.deepEqual(detail.reasonDetail, { kind: 'budget_exhausted', stopIntentRef: stopped.run.stopIntentRef });
      assert.equal(detail.primaryEvidenceRef, stopped.run.stopIntentRef);
      await reopen(fixture);
      assert.deepEqual(fixture.store.getRun(fixture.runId), terminal.run);
      const session = fixture.store.getSession(stopped.run.sessionId);
      assert.equal(session.contextRevision, sessionBefore.contextRevision + 1);
      assert.equal(session.latestItemSeq, sessionBefore.latestItemSeq + 1);
      await fixture.agent.commitTerminalStop({ expectedRunRevision: terminal.run.revision });
      assert.deepEqual(fixture.store.getSession(session.id), session);
    } finally { await disposeFixture(fixture); }
  });
}

test('tool-call exhaustion cancels only the undispatched ordered suffix without charging or inventing Journal calls', async () => {
  const fixture = await createAgentFixture('resource-tool', { toolCalls: 1 }, { mode: 'plan', tools: ['read', 'request_input'] });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'first' } }, { name: 'read', input: { path: 'a' } }, { name: 'request_input', input: {
      prompt: 'Continue?', responseKind: 'text', maximumResponseBytes: 20 } }]);
    const claimed = await claimTool(fixture, await prepareTool(fixture));
    await fixture.agent.completeTool({ expectedRunRevision: revision(fixture), opId: claimed.entry.opId, attempt: claimed.entry.attempt,
      observationRef: await observation(fixture, claimed, 'first result') });
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(prepareTool(fixture), { code: 'BUDGET_EXHAUSTED' });
    const stopped = await stop(fixture);
    const intent = await fixture.store.artifacts.readCanonical<StopIntent>(stopped.run.stopIntentRef!);
    assert.ok(intent.origin === 'budget');
    assert.equal(intent.counter, 'toolCalls');
    assert.equal(intent.required, 1);
    await reopen(fixture);
    await finish(fixture, stopped.checkpointId);
    await reopen(fixture);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(after.journal, before.journal);
    assert.deepEqual(after.run.budgetConsumed, before.run.budgetConsumed);
    const items = await Promise.all(after.items.map((row) => fixture.store.artifacts.readCanonical<ContinuationItem>(row.payloadRef)));
    assert.deepEqual(items.filter((item) => item.kind === 'tool_result').map((item) => [item.index, item.outcome]), [[0, 'executed'], [1, 'cancelled'], [2, 'cancelled']]);
    assert.equal(items.filter((item) => item.kind === 'input_request').length, 0);
  } finally { await disposeFixture(fixture); }
});

test('protected context exhaustion retains exact estimates, survives restart and needs no model dispatch', async () => {
  const fixture = await createAgentFixture('resource-context', undefined, { mode: 'plan' });
  try {
    await longContext(fixture, ['x'.repeat(70_000)]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    let estimates: AgentContextExhaustedError['evidence'] | undefined;
    await assert.rejects(fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch }), (error) => {
      if (!(error instanceof AgentContextExhaustedError)) return false;
      estimates = error.evidence; return true;
    });
    const stopped = await stop(fixture);
    const intent = await fixture.store.artifacts.readCanonical<StopIntent>(stopped.run.stopIntentRef!);
    assert.ok(intent.origin === 'runtime' && intent.runtimeSubtype === 'context_window_exhausted');
    for (const key of ['contextManifestRef', 'nextPromptTokens', 'triggerThresholdTokens', 'hardPromptTokens', 'protectedTokens', 'sourceInputTokenCap'] as const) {
      assert.equal(intent[key], estimates![key]);
    }
    await reopen(fixture);
    const terminal = await finish(fixture, stopped.checkpointId);
    assert.equal(terminal.run.terminalReason, 'runtime_failed');
    const detail = await fixture.store.artifacts.readCanonical<TerminalDetail>(terminal.run.terminalDetailRef!);
    assert.ok(detail.reasonDetail.kind === 'context_window_exhausted');
    assert.equal(detail.reasonDetail.evidenceRef, stopped.run.stopIntentRef);
    await reopen(fixture);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(after.journal, before.journal);
    assert.deepEqual(after.items, before.items);
    assert.equal(after.latestCheckpoint.contextManifestRef, before.latestCheckpoint.contextManifestRef);
    assert.deepEqual(after.run.budgetConsumed, before.run.budgetConsumed);
  } finally { await disposeFixture(fixture); }
});

for (const expired of [false, true]) test(`tool budget stopping respects ${expired ? 'expired' : 'live'} approval and never grants permission`, async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture(`resource-approval-${expired}`, { toolCalls: 1 }, { mode: 'default', tools: ['bash', 'read'] });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'first' } }, { name: 'bash', input: { command: 'printf ok' } }]);
    const claimed = await claimTool(fixture, await prepareTool(fixture));
    await fixture.agent.completeTool({ expectedRunRevision: revision(fixture), opId: claimed.entry.opId, attempt: claimed.entry.attempt,
      observationRef: await observation(fixture, claimed, 'first result') });
    const pending = await fixture.agent.prepareTool({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
    assert.ok(pending.disposition === 'approval_required');
    const proof = await quiescedToolCheckpoint(fixture, pending.checkpointId);
    await fixture.agent.waitForToolApproval({ expectedRunRevision: revision(fixture), waitingOnRef: pending.waitingOnRef, checkpoint: proof.checkpoint });
    await assert.rejects(stop(fixture), { code: 'STATE_TRANSITION_INVALID' });
    const command = { principalId: 'cliq-m2-principal', requestId: uuidv7(), expectedRunRevision: revision(fixture),
      waitingOnRef: pending.waitingOnRef, decision: 'allow' as const, ttlMs: 1000, ...await publishInProcessChannel(fixture.store, 'cliq-m2-principal') };
    await fixture.agent.approveTool(command);
    await reopen(fixture);
    if (expired) {
      now += 1000;
      const before = await fixture.store.readRecoveryClosure(fixture.runId);
      await assert.rejects(stop(fixture), { code: 'STATE_TRANSITION_INVALID' });
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    } else {
      const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
      try {
        const before = fixture.store.getRun(fixture.runId);
        writer.prepare("UPDATE control_requests SET channel_identity_digest = ? WHERE method = 'run.approve' AND request_id = ?")
          .run(canonicalSha256('substituted-channel'), command.requestId);
        await assert.rejects(stop(fixture), /control-row owner/);
        assert.deepEqual(fixture.store.getRun(fixture.runId), before);
        writer.prepare("UPDATE control_requests SET channel_identity_digest = ? WHERE method = 'run.approve' AND request_id = ?")
          .run(command.channelIdentityDigest, command.requestId);
      } finally { writer.close(); }
      const stopped = await stop(fixture);
      assert.equal(stopped.run.activeWorkerLaunchId, undefined);
      const recoveryWriter = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
      try {
        recoveryWriter.prepare("UPDATE control_requests SET request_id = ? WHERE method = 'run.approve' AND request_id = ?").run('missing-owner', command.requestId);
        await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), /control-row owner/);
        await assert.rejects(fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture) }), /control-row owner/);
        recoveryWriter.prepare("UPDATE control_requests SET request_id = ? WHERE method = 'run.approve' AND request_id = ?").run(command.requestId, 'missing-owner');
      } finally { recoveryWriter.close(); }
      // Expiry after the stop does not invalidate the original, authority-bound reservation failure.
      now += 1000;
      await reopen(fixture);
      const terminal = await finish(fixture, stopped.checkpointId);
      assert.equal(terminal.run.terminalReason, 'budget_exhausted');
      assert.equal(terminal.run.budgetConsumed.toolCalls, 1);
      await reopen(fixture);
    }
  } finally { await disposeFixture(fixture); }
});

for (const outcome of ['unusable', 'ineffective', 'reducing'] as const) test(`${outcome} compaction is classified from retained result and context, not a caller reason`, async () => {
  const fixture = await createAgentFixture(`resource-compaction-${outcome}`, { modelTokens: 1_000_000, costMicros: 10_000_000 }, { mode: 'plan' });
  try {
    await longContext(fixture, outcome === 'ineffective' ? ['\n'.repeat(12_000), 'recent'.repeat(12_000)] : undefined);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const { prepared, completed } = await modelTurn(fixture, outcome === 'ineffective' ? 's'.repeat(12_288) : '# Summary\nEarlier tools were rejected.',
      outcome === 'unusable' ? 'read' : undefined);
    assert.equal(prepared.prepared.request.kind, 'context_compaction');
    assert.deepEqual(completed.settlement.consumed, prepared.entry.budgetDelta);
    await assert.rejects(fixture.agent.stopForModelFailure({ expectedRunRevision: revision(fixture),
      ...(await fixtureInspector(fixture)).identity }), { code: 'STATE_TRANSITION_INVALID' });
    if (outcome === 'reducing') {
      assert.equal(completed.disposition, 'context_compacted');
      await assert.rejects(stop(fixture), { code: 'STATE_TRANSITION_INVALID' });
      await reopen(fixture);
      await assert.rejects(stop(fixture), { code: 'STATE_TRANSITION_INVALID' });
      return;
    }
    assert.equal(completed.disposition, 'stop_required');
    const stopped = await stop(fixture);
    const intent = await fixture.store.artifacts.readCanonical<StopIntent>(stopped.run.stopIntentRef!);
    assert.ok(intent.origin === 'runtime' && intent.runtimeSubtype === 'context_compaction_failed');
    assert.equal(intent.compactionPlanRef, prepared.prepared.request.compactionPlanRef);
    assert.equal(intent.modelOpId, prepared.entry.opId);
    assert.equal(intent.attempt, prepared.entry.attempt);
    await reopen(fixture);
    const terminal = await finish(fixture, stopped.checkpointId);
    const detail = await fixture.store.artifacts.readCanonical<TerminalDetail>(terminal.run.terminalDetailRef!);
    assert.deepEqual(detail.reasonDetail, { kind: 'context_compaction_failed', compactionPlanRef: intent.compactionPlanRef,
      modelOpId: intent.modelOpId, attempt: intent.attempt, evidenceRef: stopped.run.stopIntentRef });
    await reopen(fixture);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(after.items, before.items);
    assert.equal(after.latestCheckpoint.contextManifestRef, before.latestCheckpoint.contextManifestRef);
    assert.deepEqual(after.run.budgetConsumed, completed.run.budgetConsumed);
    assert.equal(after.journal.at(-1)?.resultRef, completed.entry.resultRef);
  } finally { await disposeFixture(fixture); }
});

test('resource proposals cannot overtake productive capacity, reserved attempts, candidate handoff or permission/input waits', async () => {
  const fixture = await createAgentFixture('resource-not-failed', undefined, { mode: 'plan' });
  try {
    const initial = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(stop(fixture), { code: 'STATE_TRANSITION_INVALID' });
    await assert.rejects(fixture.agent.stopForResourceFailure({ expectedRunRevision: revision(fixture) - 1 }), { code: 'REVISION_CONFLICT' });
    await assert.rejects(fixture.agent.stopForResourceFailure({ expectedRunRevision: revision(fixture), reason: 'runtime_failed' } as never), { code: 'INVALID_REQUEST' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), initial);
    await fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
    const pending = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(stop(fixture), { code: 'STATE_TRANSITION_INVALID' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), pending);
  } finally { await disposeFixture(fixture); }
  const candidate = await createAgentFixture('resource-candidate', { modelTokens: 40_960 }, { mode: 'plan' });
  try {
    assert.equal((await modelTurn(candidate, 'done')).completed.disposition, 'candidate_required');
    await assert.rejects(stop(candidate), { code: 'STATE_TRANSITION_INVALID' });
  } finally { await disposeFixture(candidate); }
  for (const kind of ['input', 'approval', 'denied'] as const) {
    const waiting = await createAgentFixture(`resource-${kind}`, { toolCalls: 1 }, { mode: kind === 'denied' ? 'plan' : 'default', tools: ['bash', 'read', 'request_input'] });
    try {
      await batch(waiting, [{ name: 'read', input: { path: 'first' } }, kind === 'input' ? { name: 'request_input', input: { prompt: 'Name?', responseKind: 'text', maximumResponseBytes: 20 } }
        : { name: 'bash', input: { command: 'pwd' } }]);
      const claimed = await claimTool(waiting, await prepareTool(waiting));
      await waiting.agent.completeTool({ expectedRunRevision: revision(waiting), opId: claimed.entry.opId, attempt: claimed.entry.attempt,
        observationRef: await observation(waiting, claimed, 'first result') });
      const before = await waiting.store.readRecoveryClosure(waiting.runId);
      await assert.rejects(stop(waiting), { code: 'STATE_TRANSITION_INVALID' });
      assert.deepEqual(await waiting.store.readRecoveryClosure(waiting.runId), before);
    } finally { await disposeFixture(waiting); }
  }
});

test('unknown model attempts retain their full charge and cannot terminalize merely because the retry lacks budget', async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture('resource-unknown', { modelTokens: 40_960 }, { mode: 'plan' });
  try {
    const prepared = await fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
    await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch,
      opId: prepared.entry.opId, attempt: 0, dispatchId: 'dispatch' });
    const evidence = await fixture.store.artifacts.publishCanonical({ reason: 'offline transport ambiguity' }, 'cliq-invocation-ambiguity-evidence-v1');
    await fixture.store.markInvocationUnknown({ runId: fixture.runId, expectedRunRevision: revision(fixture), opId: prepared.entry.opId,
      attempt: 0, evidenceRef: evidence.ref, evidenceDigest: evidence.ref });
    await assert.rejects(stop(fixture), { code: 'STATE_TRANSITION_INVALID' });
    now += 500;
    await assert.rejects(fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch }), { code: 'BUDGET_EXHAUSTED' });
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(stop(fixture), { code: 'STATE_TRANSITION_INVALID' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    await reopen(fixture);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(after.run.status, 'running');
    assert.deepEqual(after.run.budgetConsumed, prepared.entry.budgetDelta);
    assert.equal(after.journal.at(-1)?.phase, 'unknown');
  } finally { await disposeFixture(fixture); }
});

test('deadline replaces runtime failure, equal-precedence budgets remain stable and user cancellation always wins', async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture('resource-priority', { wallTimeMs: 60_000 }, { mode: 'plan' });
  try {
    await longContext(fixture, ['x'.repeat(70_000)]);
    const resource = await stop(fixture);
    now += 60_000;
    const deadline = await fixture.agent.expireRun({ expectedRunRevision: revision(fixture) });
    assert.notEqual(deadline.run.stopIntentRef, resource.run.stopIntentRef);
    assert.equal((await fixture.store.artifacts.readCanonical<StopIntent>(deadline.run.stopIntentRef!)).origin, 'deadline');
    const cancelled = await cancel(fixture);
    assert.equal((await stop(fixture)).run.stopIntentRef, cancelled.run.stopIntentRef);
    await finish(fixture, cancelled.checkpointId);
    await reopen(fixture);
    assert.equal(fixture.store.getRun(fixture.runId).status, 'cancelled');
  } finally { await disposeFixture(fixture); }
  const budget = await createAgentFixture('resource-equal-priority', { modelTokens: 1, wallTimeMs: 60_000 }, { mode: 'plan' });
  try {
    const first = await stop(budget);
    now += 60_000;
    assert.deepEqual((await budget.agent.expireRun({ expectedRunRevision: revision(budget) })).run, first.run);
    assert.deepEqual((await stop(budget)).run, first.run);
  } finally { await disposeFixture(budget); }
});

test('resource stop and Session publication roll back atomically, and a rehashed false budget cannot survive recovery', async () => {
  const fixture = await createAgentFixture('resource-atomic', { modelTokens: 1 }, { mode: 'plan' });
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    fault.exec("CREATE TRIGGER fail_resource BEFORE UPDATE ON runs WHEN NEW.stop_intent_ref IS NOT OLD.stop_intent_ref BEGIN SELECT RAISE(ABORT, 'injected resource failure'); END");
    await assert.rejects(stop(fixture), /injected resource failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    fault.exec('DROP TRIGGER fail_resource');
    const stopped = await stop(fixture);
    const intent = await fixture.store.artifacts.readCanonical<StopIntent>(stopped.run.stopIntentRef!);
    assert.ok(intent.origin === 'budget');
    const forged = await fixture.store.artifacts.publishCanonical({ ...intent, required: intent.required + 1 }, 'cliq-stop-intent-v1');
    fault.prepare('UPDATE runs SET stop_intent_ref = ? WHERE id = ?').run(forged.ref, fixture.runId);
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
    fault.prepare('UPDATE runs SET stop_intent_ref = ? WHERE id = ?').run(stopped.run.stopIntentRef!, fixture.runId);
    const proof = await quiescedToolCheckpoint(fixture, stopped.checkpointId);
    const pending = await fixture.store.readRecoveryClosure(fixture.runId), session = fixture.store.getSession(stopped.run.sessionId);
    fault.exec("CREATE TRIGGER fail_resource_terminal BEFORE INSERT ON items WHEN NEW.session_id IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected resource terminal failure'); END");
    const commit = { expectedRunRevision: revision(fixture), checkpoint: proof.checkpoint };
    await assert.rejects(fixture.agent.commitTerminalStop(commit), /injected resource terminal failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), pending);
    assert.deepEqual(fixture.store.getSession(session.id), session);
    fault.exec('DROP TRIGGER fail_resource_terminal');
    await fixture.agent.commitTerminalStop(commit);
    await reopen(fixture);
  } finally { fault.close(); await disposeFixture(fixture); }
});
