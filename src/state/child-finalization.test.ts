import assert from 'node:assert/strict';
import test from 'node:test';
import type { ContinuationItem } from '../kernel/types.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { activateFixtureWorker, disposeFixture } from './testing/fixtures.js';
import { activateOfflineChild, completeOfflineChild, createChildRunFixture } from './testing/child-runs.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

// Same existing inert worker/model proof fixtures as ordinary RunResult tests.
// Actual owner, ordinary reducers, SQLite and CAS; not provider/Linux evidence.
test('a premature final turn cannot create a candidate around outstanding children or enter the next prompt', async () => {
  const fixture = await createChildRunFixture('children-premature-final');
  try {
    Object.assign(fixture, await activateFixtureWorker(fixture, 'premature-final-parent', 30_000));
    const prepared = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
      leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'premature-final-model' });
    const response = fixture.agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
    response.push(Buffer.from(JSON.stringify({ id: 'premature-final-response', object: 'response', status: 'completed', model: 'model-1',
      output: [{ type: 'message', id: 'premature-final-message', role: 'assistant', status: 'completed',
        content: [{ type: 'output_text', text: 'PREMATURE_FINAL_MUST_NOT_BE_REUSED', annotations: [] }] }] })));
    const completed = await fixture.agent.completeModel({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
      expectedRunRevision: prepared.run.revision, result: response.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput) });
    assert.equal(completed.disposition, 'candidate_required');
    await assert.rejects(fixture.agent.beginFinalCandidate({ expectedRunRevision: completed.run.revision }), { code: 'STATE_TRANSITION_INVALID' });
    const selection = await fixture.agent.planFinalChildren({ expectedRunRevision: completed.run.revision });
    assert.equal(selection.disposition, 'child_final_required');
    if (selection.disposition !== 'child_final_required') throw new Error('outstanding child must own finalization');
    for (const key of ['grant', 'entry', 'waitingOnRef', 'subject']) assert(!Object.hasOwn(selection, key));
    const proof = await quiescedToolCheckpoint(fixture, selection.checkpointId);
    const waiting = await fixture.agent.waitForFinalChildren({ expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint });
    assert.equal(waiting.run.status, 'waiting'); assert.equal(waiting.run.waitingReason, 'child');
    const waitCut = await fixture.store.readRecoveryClosure(fixture.runId);
    const items = await fixture.store.artifacts.mapReads(waitCut.items, row => fixture.store.artifacts.readCanonical<ContinuationItem>(row.payloadRef));
    assert.equal(items.filter(item => item.kind === 'final_candidate').length, 0);
    assert.equal(items.at(-1)!.kind, 'model_turn');
    assert.equal(waitCut.workerLaunches.length, 0);
    await completeOfflineChild(await activateOfflineChild(fixture));
    const awakened = await fixture.agent.settleChildren({ expectedRunRevision: waiting.run.revision });
    assert.equal(awakened.run.status, 'queued'); assert.equal(awakened.run.nextStep, 'agent');
    Object.assign(fixture, await activateFixtureWorker(fixture, 'after-child-final-results', 30_000));
    const next = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    assert.equal(next.projection.messages.some(message => message.role === 'assistant' && message.contentUtf8.includes('PREMATURE_FINAL_MUST_NOT_BE_REUSED')), false);
    const results = next.projection.messages.filter(message => message.role === 'user' && message.sourceKind === 'child_result');
    assert.equal(results.length, 1);
    assert.equal(results[0]!.contentUtf8, JSON.stringify({ childRunId: fixture.children[0]!.childRunId, status: 'completed_unverified', summary: 'The child inspection is complete.' }));
  } finally { await disposeFixture(fixture); }
});

test('a received final turn retains its original seal when Stop arrives before child waiting commits', async () => {
  const fixture = await createChildRunFixture('children-final-stop-after-result');
  try {
    Object.assign(fixture, await activateFixtureWorker(fixture, 'final-stop-parent', 30_000));
    const prepared = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
      leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'before-child-stop-final' });
    const response = fixture.agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
    response.push(Buffer.from(JSON.stringify({ id: 'final-before-stop', object: 'response', status: 'completed', model: 'model-1',
      output: [{ type: 'message', id: 'before-stop', role: 'assistant', status: 'completed',
        content: [{ type: 'output_text', text: 'RECEIVED_FINAL_BEFORE_STOP', annotations: [] }] }] })));
    const completed = await fixture.agent.completeModel({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
      expectedRunRevision: prepared.run.revision, result: response.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput) });
    const selected = await fixture.agent.planFinalChildren({ expectedRunRevision: completed.run.revision });
    if (selected.disposition !== 'child_final_required') throw new Error('original outstanding child must own final waiting');
    const { publishInProcessChannel } = await import('./store.js');
    const { uuidv7 } = await import('./testing/fixtures.js');
    const cancelled = await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(), expectedRunRevision: completed.run.revision });
    const proof = await quiescedToolCheckpoint(fixture, selected.checkpointId);
    const retained = await fixture.agent.waitForFinalChildren({ expectedRunRevision: cancelled.run.revision, checkpoint: proof.checkpoint });
    const subject = await fixture.store.artifacts.readCanonical<import('../kernel/children.js').ChildWaitingSubject>(retained.run.waitingOnRef!);
    assert.equal(subject.subject.kind, 'finalize_settlement');
    if (subject.subject.kind !== 'finalize_settlement') throw new Error('actual received final result retains its original wait subject');
    assert.equal(subject.subject.observedStopIntentRef, cancelled.run.stopIntentRef);
    await assert.rejects(fixture.agent.settleChildren({ expectedRunRevision: retained.run.revision }), /Stop child settlement transition/);
    const waiting = await fixture.agent.waitForStoppedChildren({ expectedRunRevision: retained.run.revision });
    const { loadOfflineChild } = await import('./testing/child-runs.js');
    const child = await loadOfflineChild(fixture);
    const stopped = await child.agent.stopFromParent({ expectedRunRevision: fixture.store.getRun(child.runId).revision });
    await child.agent.commitTerminalStop({ expectedRunRevision: stopped.run.revision });
    const settled = await fixture.agent.settleChildren({ expectedRunRevision: waiting.run.revision });
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: settled.run.revision });
    assert.equal(terminal.run.status, 'cancelled'); assert.equal(terminal.run.resultRef, undefined);
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    const items = await fixture.store.artifacts.mapReads(cut.items, row => fixture.store.artifacts.readCanonical<ContinuationItem>(row.payloadRef));
    assert.equal(items.some(item => item.kind === 'final_candidate'), false);
    assert.equal(items.filter(item => item.kind === 'child_result' && item.delivery.kind === 'stop_settlement').length, 1);
  } finally { await disposeFixture(fixture); }
});
