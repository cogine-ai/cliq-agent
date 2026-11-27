// Existing real StateStore seam with offline signed model/retirement data.
// These tests establish reducer invariants, never installed/native qualification.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash } from '../kernel/identity.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

test('a complete final turn becomes one exact-source candidate only after its owning worker seal', async () => {
  const fixture = await createAgentFixture('final-candidate');
  try {
    const prepared = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
      leaseEpoch: fixture.leaseEpoch });
    await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
      leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'final-candidate-dispatch' });
    const reader = fixture.agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
    reader.push(Buffer.from(JSON.stringify({ id: 'final-response', object: 'response', status: 'completed', model: 'model-1',
      output: [{ type: 'message', id: 'final-message', role: 'assistant', status: 'completed',
        content: [{ type: 'output_text', text: 'The change is ready for verification.', annotations: [] }] }] })));
    const completed = await fixture.agent.completeModel({ opId: prepared.entry.opId, attempt: 0,
      expectedRunRevision: prepared.run.revision, result: reader.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput) });
    assert.equal(completed.disposition, 'candidate_required');
    const producerId = identityHash('cliq-model-turn-item-v1', fixture.runId, prepared.entry.opId, String(prepared.entry.attempt));
    const owner = await fixture.agent.beginFinalCandidate({ expectedRunRevision: completed.run.revision });
    const proof = await quiescedToolCheckpoint(fixture,
      identityHash('cliq-final-candidate-checkpoint-v1', fixture.runId, producerId), true);
    const result = await owner.complete({ expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint });
    assert.equal(result.run.status, 'queued'); assert.equal(result.run.nextStep, 'verify');
    assert.equal(result.run.activeWorkerLaunchId, undefined); assert.equal(result.run.resultRef, undefined);
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    const items = await Promise.all(cut.items.map(item => fixture.store.artifacts.readCanonical<Record<string, any>>(item.payloadRef)));
    assert.deepEqual(items.map(item => item.kind), ['model_turn', 'final_candidate']);
    const candidate = await fixture.store.artifacts.readCanonical<Record<string, any>>(cut.items[1]!.payloadRef);
    assert.equal(candidate.runId, fixture.runId); assert.equal(candidate.operation, 'agent');
    assert.equal(candidate.producingItemId, cut.items[0]!.itemId); assert.equal(candidate.producingOpId, prepared.entry.opId);
    assert.equal(candidate.summaryRef, (await fixture.store.artifacts.readCanonical<Record<string, any>>(cut.items[0]!.payloadRef)).textRef);
    const source = await fixture.store.artifacts.readCanonical<Record<string, any>>(candidate.resultSourceRef);
    const diff = await fixture.store.artifacts.readCanonical<Record<string, any>>(candidate.diffRef);
    assert.equal(source.role, 'result'); assert.equal(source.manifestDigest, candidate.sourceDigest);
    assert.equal(diff.resultSourceRef, candidate.resultSourceRef); assert.equal(diff.baseSourceRef, candidate.baseSourceRef);
    assert.deepEqual(diff.operations.map((entry: any) => [entry.kind, entry.path]), [['add', 'a']]);
    assert.equal(cut.latestCheckpoint.workspaceStateRef, proof.workspaceStateRef);
    assert.equal(cut.latestCheckpoint.runItemSeq, 2); assert.equal(cut.latestCheckpoint.journalSeq, completed.entry.seq);
    assert.equal(cut.workerLaunches.length, 0); assert.equal(cut.workspaceGenerations[0]!.phase, 'sealed');
    assert.equal(canonicalSha256(cut.run.budgetConsumed), canonicalSha256(completed.run.budgetConsumed));
    assert.equal(cut.journal.length, completed.entry.seq);
  } finally { await disposeFixture(fixture); }
});

test('a completed final-turn owner releases its Agent slot without bypassing the next frontier or its original replay', async () => {
  const fixture = await createAgentFixture('final-candidate-owner-lifetime');
  try {
    const agent = fixture.agent;
    const prepared = await agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
      leaseEpoch: fixture.leaseEpoch });
    await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
      leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'candidate-owner-lifetime' });
    const reader = agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
    reader.push(Buffer.from(JSON.stringify({ id: 'owner-lifetime-response', object: 'response', status: 'completed', model: 'model-1',
      output: [{ type: 'message', id: 'owner-lifetime-message', role: 'assistant', status: 'completed',
        content: [{ type: 'output_text', text: 'Ready for the declared verifier.', annotations: [] }] }] })));
    const completed = await agent.completeModel({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
      expectedRunRevision: prepared.run.revision, result: reader.finish(sampleCanonicalNow(), agent.resolveToolInput) });
    assert.equal(completed.disposition, 'candidate_required');
    const owner = await agent.beginFinalCandidate({ expectedRunRevision: completed.run.revision });
    await assert.rejects(agent.beginFinalCandidate({ expectedRunRevision: completed.run.revision }), { code: 'REVISION_CONFLICT' });
    const proof = await quiescedToolCheckpoint(fixture, owner.checkpointId);
    const request = { expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint };
    const result = await owner.complete(request);
    assert.equal(result.disposition, 'candidate'); assert.equal(result.run.nextStep, 'verify');
    assert.deepEqual(await owner.complete(request), result);
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    // The same Agent must reach the real current-frontier check. A completed
    // owner is not a Run-wide lock, but neither completion nor a new begin is
    // permission to invent repair, another model turn or a second candidate.
    await assert.rejects(agent.beginFinalCandidate({ expectedRunRevision: result.run.revision }), { code: 'STATE_TRANSITION_INVALID' });
    await assert.rejects(owner.complete({ ...request, checkpoint: { ...request.checkpoint, snapshotEvidenceRef: 'a'.repeat(64) } }),
      { code: 'REVISION_CONFLICT' });
    assert.deepEqual(await owner.complete(request), result);
    assert.equal(fixture.agent, agent);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), cut);
    assert.deepEqual(cut.journal.map(entry => entry.phase), ['prepared', 'dispatch_claimed', 'completed']);
    assert.equal(cut.items.length, 2);
  } finally { await disposeFixture(fixture); }
});
