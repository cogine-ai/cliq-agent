// Existing real StateStore seam. Offline signed model and retirement fixtures
// establish reducer invariants, not installed verifier or physical-death qualification.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { identityHash } from '../kernel/identity.js';
import type { StopIntent } from '../kernel/types.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture, uuidv7 } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;
const revision = (fixture: Fixture) => fixture.store.getRun(fixture.runId).revision;
async function prepareCandidate(fixture: Fixture) {
  const prepared = await fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
  await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
    leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'candidate-stop-dispatch' });
  const reader = fixture.agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
  reader.push(Buffer.from(JSON.stringify({ id: 'candidate-stop-response', object: 'response', status: 'completed', model: 'model-1',
    output: [{ type: 'message', id: 'candidate-stop-message', role: 'assistant', status: 'completed',
      content: [{ type: 'output_text', text: 'Ready for the declared checks.', annotations: [] }] }] })));
  const completed = await fixture.agent.completeModel({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
    expectedRunRevision: prepared.run.revision, result: reader.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput) });
  assert.equal(completed.disposition, 'candidate_required');
  const modelItemId = identityHash('cliq-model-turn-item-v1', fixture.runId, prepared.entry.opId, String(prepared.entry.attempt));
  const checkpointId = identityHash('cliq-final-candidate-checkpoint-v1', fixture.runId, modelItemId);
  const owner = await fixture.agent.beginFinalCandidate({ expectedRunRevision: completed.run.revision });
  const proof = await quiescedToolCheckpoint(fixture, checkpointId, true);
  return owner.complete({ expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint });
}
async function cancelCommand(fixture: Fixture) {
  return { requestId: uuidv7(), expectedRunRevision: revision(fixture), ...await publishInProcessChannel(fixture.store) };
}
async function reopen(fixture: Fixture) {
  await fixture.store.close();
  fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
  fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material,
    releaseKeys: fixture.signed.releaseKeys });
}

test('cancel retires an unstarted candidate without executing a verifier or publishing its result, including replay after reopen', async () => {
  const fixture = await createAgentFixture('candidate-stop-cancel', undefined, { mode: 'plan' });
  try {
    const candidate = await prepareCandidate(fixture);
    assert.equal(candidate.run.status, 'queued'); assert.equal(candidate.run.nextStep, 'verify');
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const candidateBytes = await fixture.store.artifacts.readBytes(before.items.at(-1)!.payloadRef);
    const session = fixture.store.getSession(candidate.run.sessionId);
    await assert.rejects(fixture.agent.stopForResourceFailure({ expectedRunRevision: revision(fixture) }),
      { code: 'STATE_TRANSITION_INVALID' });
    await assert.rejects(fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture) }), /persisted StopIntent/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    await reopen(fixture);
    const command = await cancelCommand(fixture), stopped = await fixture.agent.cancelRun(command);
    assert.equal(stopped.run.cancelRequested, true); assert.equal(stopped.run.nextStep, 'verify');
    const terminalRequest = { expectedRunRevision: revision(fixture) };
    const terminal = await fixture.agent.commitTerminalStop(terminalRequest);
    assert.equal(terminal.run.status, 'cancelled'); assert.equal(terminal.run.terminalReason, 'cancelled_by_user');
    assert.equal(terminal.run.resultRef, undefined); assert.equal(terminal.run.nextStep, null);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(after.journal, before.journal); assert.deepEqual(after.items, before.items);
    assert.deepEqual(after.run.budgetConsumed, before.run.budgetConsumed);
    assert.deepEqual(after.run.budgetReserved, before.run.budgetReserved);
    assert.deepEqual(await fixture.store.artifacts.readBytes(before.items.at(-1)!.payloadRef), candidateBytes);
    assert.equal(fixture.store.getSession(session.id).latestItemSeq, session.latestItemSeq + 1);
    const terminalSession = fixture.store.getSession(session.id);
    await reopen(fixture);
    assert.deepEqual((await fixture.agent.cancelRun({ ...command, ...await publishInProcessChannel(fixture.store) })).response, stopped.response);
    assert.deepEqual(await fixture.agent.commitTerminalStop(terminalRequest), terminal);
    assert.deepEqual(fixture.store.getSession(session.id), terminalSession);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), after);
  } finally { await disposeFixture(fixture); }
});

for (const cancel of [false, true]) test(`an unstarted candidate ${cancel ? 'retains user cancellation over its deadline' : 'expires without claiming verification'}`, async t => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture(`candidate-stop-deadline-${cancel}`, { wallTimeMs: 60_000 }, { mode: 'plan' });
  try {
    await prepareCandidate(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.agent.expireRun({ expectedRunRevision: revision(fixture) }), /not elapsed/);
    now += 60_000;
    let stopped = await fixture.agent.expireRun({ expectedRunRevision: revision(fixture) });
    assert.equal((await fixture.store.artifacts.readCanonical<StopIntent>(stopped.run.stopIntentRef!)).origin, 'deadline');
    if (cancel) {
      const cancelled = await fixture.agent.cancelRun(await cancelCommand(fixture));
      assert.notEqual(cancelled.run.stopIntentRef, stopped.run.stopIntentRef);
      stopped = cancelled;
      now++;
      const repeated = await fixture.agent.cancelRun(await cancelCommand(fixture));
      assert.equal(repeated.run.stopIntentRef, stopped.run.stopIntentRef);
      assert.equal((await fixture.agent.expireRun({ expectedRunRevision: revision(fixture) })).run.stopIntentRef, stopped.run.stopIntentRef);
    }
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture) });
    assert.equal(terminal.run.status, cancel ? 'cancelled' : 'failed');
    assert.equal(terminal.run.terminalReason, cancel ? 'cancelled_by_user' : 'budget_exhausted');
    assert.equal(terminal.run.cancelRequested, cancel); assert.equal(terminal.run.resultRef, undefined);
    await reopen(fixture);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(after.run, terminal.run); assert.deepEqual(after.items, before.items); assert.deepEqual(after.journal, before.journal);
  } finally { await disposeFixture(fixture); }
});
