import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { ContinuationItem, RunCancel, SessionContextProjection, StopIntent, TerminalDetail, WorkerLaunch } from '../kernel/types.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { activateFixtureWorker, admissionKey, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;
const revision = (fixture: Fixture) => fixture.store.getRun(fixture.runId).revision;
async function cancelCommand(fixture: Fixture): Promise<RunCancel> {
  return { principalId: 'cliq-m2-principal', requestId: uuidv7(), expectedRunRevision: revision(fixture),
    ...await publishInProcessChannel(fixture.store, 'cliq-m2-principal') };
}
async function finish(fixture: Fixture, checkpointId: string) {
  const run = fixture.store.getRun(fixture.runId);
  const proof = run.activeWorkerLaunchId ? await quiescedToolCheckpoint(fixture, checkpointId) : undefined;
  return fixture.agent.commitTerminalStop({ expectedRunRevision: run.revision, ...(proof ? { checkpoint: proof.checkpoint } : {}) });
}
async function reopen(fixture: Fixture) {
  await fixture.store.close();
  fixture.store = await openStateStore(fixture.stateRoot);
  fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
}
const runItems = async (fixture: Fixture) => Promise.all((await fixture.store.readRecoveryClosure(fixture.runId)).items.map((row) =>
  fixture.store.artifacts.readCanonical<ContinuationItem>(row.payloadRef)));

test('cancel fences a prepared model, replays authenticated requests, and atomically refunds and publishes one terminal Session item', async () => {
  const fixture = await createAgentFixture('stop-model-prepared', undefined, { mode: 'plan' });
  try {
    const prepared = await fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
    const command = await cancelCommand(fixture);
    const answers = await Promise.all([fixture.agent.cancelRun(command), fixture.agent.cancelRun(command)]);
    assert.deepEqual(answers.map((answer) => answer.replayed).sort(), [false, true]);
    assert.deepEqual(answers[0]!.response, answers[1]!.response);
    const stopped = answers[0]!;
    assert.equal(stopped.run.status, 'running');
    assert.ok(stopped.run.stopIntentRef);
    assert.equal(stopped.run.cancelRequested, true);
    assert.deepEqual(stopped.run.budgetReserved, prepared.run.budgetReserved);
    await assert.rejects(fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: revision(fixture),
      leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'too-late' }), { code: 'LEASE_FENCED' });
    await assert.rejects(fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture) }), /positive retirement/);
    const sessionBefore = fixture.store.getSession(stopped.run.sessionId);
    const terminal = await finish(fixture, stopped.checkpointId);
    assert.equal(terminal.run.status, 'cancelled');
    assert.equal(terminal.run.terminalReason, 'cancelled_by_user');
    assert.equal(terminal.run.nextStep, null);
    for (const key of ['frontierRef', 'waitingOnRef', 'activeWorkerLaunchId', 'resultRef'] as const) assert.equal(terminal.run[key], undefined);
    assert.deepEqual(terminal.run.budgetReserved, { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 });
    assert.deepEqual(terminal.run.budgetConsumed, terminal.run.budgetReserved);
    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(closure.journal.map((entry) => entry.phase), ['prepared', 'failed']);
    assert.equal(closure.journal[1]!.errorRef, stopped.run.stopIntentRef);
    const session = fixture.store.getSession(stopped.run.sessionId);
    assert.equal(session.contextRevision, sessionBefore.contextRevision + 1);
    assert.equal(session.latestItemSeq, sessionBefore.latestItemSeq + 1);
    const projection = await fixture.store.artifacts.readCanonical<SessionContextProjection>(session.contextProjectionRef);
    assert.equal(projection.segments.at(-1)?.kind, 'raw');
    const detail = await fixture.store.artifacts.readCanonical<TerminalDetail>(terminal.run.terminalDetailRef!);
    assert.deepEqual(detail.reasonDetail, { kind: 'cancelled', stopIntentRef: stopped.run.stopIntentRef });
    await reopen(fixture);
    assert.deepEqual(fixture.store.getRun(fixture.runId), terminal.run);
    const replay = await fixture.agent.cancelRun({ ...command, ...await publishInProcessChannel(fixture.store, command.principalId) });
    assert.deepEqual(replay.response, stopped.response);
    assert.deepEqual(fixture.store.getSession(session.id), session);
    await assert.rejects(fixture.agent.readModelAttempt(), { code: 'STATE_TRANSITION_INVALID' });
    await assert.rejects(activateFixtureWorker(fixture, 'forbidden-stop-worker'));
    await assert.rejects(fixture.agent.cancelRun({ ...command, expectedRunRevision: command.expectedRunRevision + 1 }), { code: 'REQUEST_ID_CONFLICT' });
  } finally { await disposeFixture(fixture); }
});

test('a prepared ordinary tool is refunded and the complete undispatched suffix receives ordered cancellation results', async () => {
  const fixture = await createAgentFixture('stop-tool-prepared', undefined, { mode: 'plan', tools: ['read', 'request_input'] });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }, { name: 'request_input', input: {
      prompt: 'Continue?', responseKind: 'text', maximumResponseBytes: 20 } }, { name: 'read', input: { path: 'b' } }]);
    await prepareTool(fixture);
    const stopped = await fixture.agent.cancelRun(await cancelCommand(fixture));
    const terminal = await finish(fixture, stopped.checkpointId);
    assert.equal(terminal.run.budgetConsumed.toolCalls, 0);
    const items = await runItems(fixture);
    assert.deepEqual(items.filter((item) => item.kind === 'tool_result').map((item) => [item.index, item.outcome]), [[0, 'cancelled'], [1, 'cancelled'], [2, 'cancelled']]);
    assert.equal(items.filter((item) => item.kind === 'input_request').length, 0);
    await reopen(fixture);
    assert.equal((await fixture.store.readRecoveryClosure(fixture.runId)).run.status, 'cancelled');
  } finally { await disposeFixture(fixture); }
});

test('an already claimed read needs its real result after cancel, retains its full charge, and does not dispatch the next call', async () => {
  const fixture = await createAgentFixture('stop-claimed-read', undefined, { mode: 'plan' });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }, { name: 'read', input: { path: 'b' } }]);
    const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared);
    const stopped = await fixture.agent.cancelRun(await cancelCommand(fixture));
    await assert.rejects(fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture) }), /dispatch\/reconciliation closure/);
    const result = await fixture.agent.completeTool({ expectedRunRevision: revision(fixture), opId: claimed.entry.opId, attempt: claimed.entry.attempt,
      observationRef: await observation(fixture, claimed, 'actual bytes') });
    assert.equal(result.run.budgetConsumed.toolCalls, 1);
    await assert.rejects(prepareTool(fixture), { code: 'LEASE_FENCED' });
    const terminal = await finish(fixture, stopped.checkpointId);
    assert.equal(terminal.run.budgetConsumed.toolCalls, 1);
    assert.deepEqual((await runItems(fixture)).filter((item) => item.kind === 'tool_result').map((item) => item.outcome), ['executed', 'cancelled']);
    await reopen(fixture);
  } finally { await disposeFixture(fixture); }
});

for (const waiting of ['input', 'approval'] as const) test(`cancel closes a worker-free ${waiting} wait without granting permission or fabricating an answer`, async () => {
  const fixture = await createAgentFixture(`stop-wait-${waiting}`, undefined, { mode: 'default', tools: waiting === 'input' ? ['read', 'request_input'] : ['bash'] });
  try {
    await batch(fixture, waiting === 'input' ? [{ name: 'request_input', input: { prompt: 'Which name?', responseKind: 'text', maximumResponseBytes: 20 } },
      { name: 'read', input: { path: 'a' } }] : [{ name: 'bash', input: { command: 'pwd' } }]);
    const plan = await fixture.agent.prepareTool({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
    assert.ok(plan.disposition === 'input_required' || plan.disposition === 'approval_required');
    const proof = await quiescedToolCheckpoint(fixture, plan.checkpointId);
    const wait = { expectedRunRevision: revision(fixture), waitingOnRef: plan.waitingOnRef, checkpoint: proof.checkpoint };
    if (waiting === 'input') await fixture.agent.waitForInput(wait); else await fixture.agent.waitForToolApproval(wait);
    await reopen(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const stopped = await fixture.agent.cancelRun(await cancelCommand(fixture));
    await reopen(fixture);
    const blocked = { ...await cancelCommand(fixture), waitingOnRef: before.run.waitingOnRef! };
    if (waiting === 'input') await assert.rejects(fixture.agent.submitInput({ ...blocked, input: { kind: 'text', value: 'late answer' } }));
    else await assert.rejects(fixture.agent.approveTool({ ...blocked, decision: 'allow' }));
    await finish(fixture, stopped.checkpointId);
    await reopen(fixture);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(after.journal, before.journal);
    assert.deepEqual(after.run.budgetConsumed, before.run.budgetConsumed);
    assert.equal(after.latestCheckpoint.workspaceStateRef, before.latestCheckpoint.workspaceStateRef);
    assert.equal(after.run.waitingOnRef, undefined);
    assert.equal((await runItems(fixture)).filter((item) => item.kind === 'user_input').length, 0);
  } finally { await disposeFixture(fixture); }
});

for (const outcome of ['received', 'abort'] as const) test(`${outcome} model observation during stop drain retains its real Journal result and full charge`, async () => {
  const fixture = await createAgentFixture(`stop-model-${outcome}`, undefined, { mode: 'plan' });
  try {
    const prepared = await fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
    await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch,
      opId: prepared.entry.opId, attempt: 0, dispatchId: 'model-dispatch' });
    const reader = fixture.agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
    const stopped = await fixture.agent.cancelRun(await cancelCommand(fixture));
    const observedAt = new Date(Date.now()).toISOString();
    if (outcome === 'received') reader.push(Buffer.from(JSON.stringify({ id: 'response', object: 'response', status: 'completed', model: 'model-1', output: [
      { type: 'message', id: 'msg', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'done', annotations: [] }] }
    ] })));
    const result = outcome === 'received' ? reader.finish(observedAt, fixture.agent.resolveToolInput)
      : reader.abort(observedAt, stopped.run.stopIntentRef!, fixture.agent.resolveToolInput);
    const completed = await fixture.agent.completeModel({ expectedRunRevision: revision(fixture), opId: prepared.entry.opId, attempt: 0, result });
    assert.deepEqual(completed.run.budgetConsumed, prepared.entry.budgetDelta);
    await finish(fixture, stopped.checkpointId);
    await reopen(fixture);
    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(closure.journal.at(-1)?.phase, 'completed');
    assert.equal(closure.journal.at(-1)?.resultRef, completed.entry.resultRef);
    assert.deepEqual(closure.run.budgetConsumed, prepared.entry.budgetDelta);
    assert.equal(closure.run.status, 'cancelled');
  } finally { await disposeFixture(fixture); }
});

test('deadline uses canonical time and user cancellation wins without resetting the first equal-precedence intent', async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture('stop-precedence', { wallTimeMs: 60_000 }, { mode: 'plan' });
  try {
    await assert.rejects(fixture.agent.expireRun({ expectedRunRevision: revision(fixture) }), /not elapsed/);
    now += 60_000;
    const deadline = await fixture.agent.expireRun({ expectedRunRevision: revision(fixture) });
    assert.equal((await fixture.store.artifacts.readCanonical<StopIntent>(deadline.run.stopIntentRef!)).origin, 'deadline');
    const first = await fixture.agent.cancelRun(await cancelCommand(fixture));
    assert.notEqual(first.run.stopIntentRef, deadline.run.stopIntentRef);
    now++;
    const second = await fixture.agent.cancelRun(await cancelCommand(fixture));
    assert.equal(second.run.stopIntentRef, first.run.stopIntentRef);
    assert.equal((await fixture.agent.expireRun({ expectedRunRevision: revision(fixture) })).run.stopIntentRef, first.run.stopIntentRef);
    const terminal = await finish(fixture, first.checkpointId);
    assert.equal(terminal.run.status, 'cancelled');
    await reopen(fixture);
  } finally { await disposeFixture(fixture); }
});

test('expired Runs terminate as failed budget_exhausted, not user cancellation', async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture('stop-deadline', { wallTimeMs: 60_000 }, { mode: 'plan' });
  try {
    now += 60_000;
    const stopped = await fixture.agent.expireRun({ expectedRunRevision: revision(fixture) });
    const terminal = await finish(fixture, stopped.checkpointId);
    assert.equal(terminal.run.status, 'failed');
    assert.equal(terminal.run.terminalReason, 'budget_exhausted');
    assert.equal(terminal.run.cancelRequested, false);
    await reopen(fixture);
  } finally { await disposeFixture(fixture); }
});

test('claimed or unknown model attempts cannot be refunded or terminalized using only worker retirement', async () => {
  const fixture = await createAgentFixture('stop-unknown', undefined, { mode: 'plan' });
  try {
    const prepared = await fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
    await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch,
      opId: prepared.entry.opId, attempt: 0, dispatchId: 'model-dispatch' });
    const stopped = await fixture.agent.cancelRun(await cancelCommand(fixture));
    const proof = await quiescedToolCheckpoint(fixture, stopped.checkpointId);
    await assert.rejects(fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture), checkpoint: proof.checkpoint }), /dispatch\/reconciliation closure/);
    // Existing offline M2 ambiguity fixture, not authenticated broker revocation/dispatch-closure proof.
    const evidence = await fixture.store.artifacts.publishCanonical({ reason: 'offline ambiguous transport' }, 'cliq-invocation-ambiguity-evidence-v1');
    await fixture.store.markInvocationUnknown({ runId: fixture.runId, expectedRunRevision: revision(fixture), opId: prepared.entry.opId,
      attempt: 0, evidenceRef: evidence.ref, evidenceDigest: evidence.ref });
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(before.run.budgetConsumed, prepared.entry.budgetDelta);
    await assert.rejects(fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture), checkpoint: proof.checkpoint }), /dispatch\/reconciliation closure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    await reopen(fixture);
    assert.equal(fixture.store.getRun(fixture.runId).status, 'running');
  } finally { await disposeFixture(fixture); }
});

test('cancellation and terminal faults roll back their entire control, Journal, worker and Session commits', async () => {
  const fixture = await createAgentFixture('stop-atomic', undefined, { mode: 'plan' });
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
    const command = await cancelCommand(fixture), before = await fixture.store.readRecoveryClosure(fixture.runId);
    fault.exec("CREATE TRIGGER fail_cancel BEFORE INSERT ON control_requests BEGIN SELECT RAISE(ABORT, 'injected cancel failure'); END");
    await assert.rejects(fixture.agent.cancelRun(command), /injected cancel failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    fault.exec('DROP TRIGGER fail_cancel');
    const stopped = await fixture.agent.cancelRun(command);
    const proof = await quiescedToolCheckpoint(fixture, stopped.checkpointId);
    const pending = await fixture.store.readRecoveryClosure(fixture.runId), session = fixture.store.getSession(stopped.run.sessionId);
    fault.exec("CREATE TRIGGER fail_stop BEFORE INSERT ON items WHEN NEW.session_id IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected terminal failure'); END");
    await assert.rejects(fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture), checkpoint: proof.checkpoint }), /injected terminal failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), pending);
    assert.deepEqual(fixture.store.getSession(session.id), session);
    fault.exec('DROP TRIGGER fail_stop');
    const commit = { expectedRunRevision: revision(fixture), checkpoint: proof.checkpoint };
    const terminal = await fixture.agent.commitTerminalStop(commit);
    const terminalSession = fixture.store.getSession(session.id);
    assert.deepEqual(await fixture.agent.commitTerminalStop(commit), terminal);
    assert.deepEqual(fixture.store.getSession(session.id), terminalSession);
    await fixture.store.readRecoveryClosure(fixture.runId);
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('foreign, malformed and stale cancellation requests cannot mutate state; distinct request IDs race one revision', async () => {
  const fixture = await createAgentFixture('stop-control-fences', undefined, { mode: 'plan' });
  try {
    const command = await cancelCommand(fixture), before = await fixture.store.readRecoveryClosure(fixture.runId);
    for (const change of [{ principalId: 'foreign' }, { requestId: 'bad' }, { expectedRunRevision: command.expectedRunRevision - 1 },
      { expectedRunRevision: 0 }, { channelIdentityDigest: canonicalSha256('foreign channel') }, { extra: true }]) {
      await assert.rejects(fixture.agent.cancelRun({ ...command, ...change }));
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    }
    const race = await Promise.allSettled([fixture.agent.cancelRun(command), fixture.agent.cancelRun({ ...command, requestId: uuidv7() })]);
    assert.equal(race.filter((answer) => answer.status === 'fulfilled').length, 1);
    const failure = race.find((answer) => answer.status === 'rejected');
    assert.ok(failure?.status === 'rejected');
    assert.equal(failure.reason.code, 'REVISION_CONFLICT');
  } finally { await disposeFixture(fixture); }
});

test('stop and recovery reject substituted retirement, terminal reason and control-row ownership', async () => {
  const fixture = await createAgentFixture('stop-recovery-proof', undefined, { mode: 'plan' });
  const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const command = await cancelCommand(fixture), stopped = await fixture.agent.cancelRun(command);
    const proof = await quiescedToolCheckpoint(fixture, stopped.checkpointId);
    const death = await fixture.store.artifacts.readCanonical<{ backend: { remainingTrackedDescendants: number }; evidenceDigest: string }>(proof.checkpoint.retirementEvidenceRef);
    death.backend.remainingTrackedDescendants = 1;
    death.evidenceDigest = digestOmitting(death, 'evidenceDigest');
    const bad = await fixture.store.artifacts.publishCanonical(death, 'cliq-process-containment-death-evidence-v1');
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture), checkpoint: { ...proof.checkpoint, retirementEvidenceRef: bad.ref } }), /positive all-descendant death/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture), checkpoint: proof.checkpoint });
    await fixture.store.readRecoveryClosure(fixture.runId);
    const launch = readWorkerLaunchesForRun(writer, fixture.runId)[0]!;
    const forged: WorkerLaunch = { ...launch, retirementEvidenceRef: bad.ref };
    // Simulate a damaged database image beyond the SQL write guard; recovery must still reject it.
    const guard = writer.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'worker_launches' AND sql LIKE '%BEFORE UPDATE%'")
      .get<{ name: string; sql: string }>()!;
    writer.exec(`DROP TRIGGER ${guard.name}`);
    writer.prepare('UPDATE worker_launches SET row_json = ? WHERE launch_id = ?').run(JSON.stringify(forged), launch.launchId);
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
    writer.prepare('UPDATE worker_launches SET row_json = ? WHERE launch_id = ?').run(JSON.stringify(launch), launch.launchId);
    writer.exec(guard.sql);
    const detail = await fixture.store.artifacts.readCanonical<TerminalDetail>(terminal.run.terminalDetailRef!);
    const wrongDetail = await fixture.store.artifacts.publishCanonical({ ...detail, reasonDetail: { kind: 'budget_exhausted', stopIntentRef: terminal.run.stopIntentRef } }, 'cliq-terminal-detail-v1');
    writer.prepare('UPDATE runs SET terminal_detail_ref = ? WHERE id = ?').run(wrongDetail.ref, fixture.runId);
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
    writer.prepare('UPDATE runs SET terminal_detail_ref = ? WHERE id = ?').run(terminal.run.terminalDetailRef!, fixture.runId);
    const row = writer.prepare("SELECT request_digest FROM control_requests WHERE method = 'run.cancel' AND request_id = ?").get<{ request_digest: string }>(command.requestId)!;
    writer.prepare("UPDATE control_requests SET request_digest = ? WHERE method = 'run.cancel' AND request_id = ?").run(canonicalSha256('different request'), command.requestId);
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
    writer.prepare("UPDATE control_requests SET request_digest = ? WHERE method = 'run.cancel' AND request_id = ?").run(row.request_digest, command.requestId);
    await reopen(fixture);
  } finally { writer.close(); await disposeFixture(fixture); }
});

test('concurrent root stops append separate Session segments in commit order without losing either outcome', async () => {
  const fixture = await createAgentFixture('stop-session-race', undefined, { mode: 'plan' });
  try {
    const { run, runSpec: spec } = await fixture.store.readRecoveryClosure(fixture.runId);
    const source = await fixture.store.artifacts.readCanonical<{ frozenIgnoreRulesRef: string }>(spec.sourceProjectionRef);
    const second = await fixture.store.admitRun({ principalId: 'cliq-m2-principal', requestId: uuidv7(), admissionKey: admissionKey('stop-second-root'),
      sessionId: run.sessionId, expectedContextRevision: 1, workspacePath: fixture.workspace, objective: 'second stopped root', allowUnverified: true,
      assemblyRef: spec.assemblyRef, policyRef: spec.policyRef, sandboxProfileRef: spec.sandboxProfileRef, verifierSpecRef: spec.verifierSpecRef,
      sourceProjectionRef: spec.sourceProjectionRef, baseWorkspaceManifestRef: spec.baseWorkspaceManifestRef,
      frozenIgnoreRulesRef: source.frozenIgnoreRulesRef,
      credentialGrantRefs: spec.credentialGrantRefs, budgets: spec.budgets, ...await publishInProcessChannel(fixture.store, 'cliq-m2-principal') });
    const agent = await fixture.store.loadAgentRun({ runId: second.run.id, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
    const firstStop = await fixture.agent.cancelRun(await cancelCommand(fixture));
    const secondStop = await agent.cancelRun({ ...await cancelCommand(fixture), expectedRunRevision: second.run.revision });
    const proof = await quiescedToolCheckpoint(fixture, firstStop.checkpointId);
    const completed = await Promise.all([fixture.agent.commitTerminalStop({ expectedRunRevision: firstStop.run.revision, checkpoint: proof.checkpoint }),
      agent.commitTerminalStop({ expectedRunRevision: secondStop.run.revision })]);
    assert.ok(completed.every(({ run }) => run.status === 'cancelled'));
    const session = fixture.store.getSession(run.sessionId);
    assert.equal(session.latestItemSeq, 2);
    assert.equal(session.contextRevision, 3);
    const projection = await fixture.store.artifacts.readCanonical<SessionContextProjection>(session.contextProjectionRef);
    assert.deepEqual(projection.segments.map((segment) => [segment.kind, segment.fromItemSeq, segment.throughItemSeq]), [['raw', 1, 1], ['raw', 2, 2]]);
    await fixture.store.readRecoveryClosure(second.run.id);
    await reopen(fixture);
    await fixture.store.readRecoveryClosure(second.run.id);
  } finally { await disposeFixture(fixture); }
});

for (const age of [5_000, 5_001]) test(`terminal stop checks the five-second retirement observation bound at commit (${age}ms)`, async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture(`stop-freshness-${age}`, undefined, { mode: 'plan' });
  try {
    const stopped = await fixture.agent.cancelRun(await cancelCommand(fixture));
    const proof = await quiescedToolCheckpoint(fixture, stopped.checkpointId);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    now += age;
    const commit = fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture), checkpoint: proof.checkpoint });
    if (age === 5_000) {
      assert.equal((await commit).run.status, 'cancelled');
      await reopen(fixture);
    } else {
      await assert.rejects(commit, /retirement proof is stale/);
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    }
  } finally { await disposeFixture(fixture); }
});
