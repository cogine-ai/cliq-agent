import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import { rm } from 'node:fs/promises';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { openSqliteDriver } from './sqlite-driver.js';
import type { ContinuationItem, RunFrontier, RunContextCompactionPlan } from '../kernel/types.js';
import { AgentContextExhaustedError, AgentHandoffPendingError } from './reducers/agent.js';
import { KernelStorageError } from './errors.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { openStateStore } from './store.js';

async function prepare(fixture: Awaited<ReturnType<typeof createAgentFixture>>) {
  const prepared = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
    leaseEpoch: fixture.leaseEpoch });
  await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
    leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt,
    dispatchId: `dispatch:${prepared.entry.opId}:${prepared.entry.attempt}` });
  return prepared;
}

function response(fixture: Awaited<ReturnType<typeof createAgentFixture>>, prepared: Awaited<ReturnType<typeof prepare>>,
  calls: Array<{ id: string; name?: string; arguments: string }>, text = '') {
  const reader = fixture.agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
  reader.push(Buffer.from(JSON.stringify({ id: 'response-1', object: 'response', status: 'completed', model: 'model-1',
    output: [{ type: 'reasoning', id: 'reasoning-1', encrypted_content: 'opaque-history', summary: [] },
      ...(text ? [{ type: 'message', id: 'msg', role: 'assistant', status: 'completed',
        content: [{ type: 'output_text', text, annotations: [] }] }] : []),
      ...calls.map((call) => ({ type: 'function_call', id: `wire:${call.id}`, call_id: call.id,
        name: call.name ?? 'read', arguments: call.arguments }))] })));
  return reader.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput);
}

test('real model admission binds zero-based identity, native bytes and the full signed reservation', async () => {
  const fixture = await createAgentFixture('typed-model');
  try {
    const admitted = await prepare(fixture);
    assert.equal(admitted.entry.attempt, 0);
    assert.equal(admitted.entry.requestRef, admitted.prepared.requestRef);
    assert.deepEqual(admitted.entry.budgetDelta, { modelTokens: 40_960, costMicros: 114_688, toolCalls: 0, repairAttempts: 0 });
    assert.deepEqual(await fixture.store.artifacts.readBytes(admitted.prepared.request.bodyBytesRef),
      Buffer.from(admitted.prepared.outbound.bodyBytes));
    const result = response(fixture, admitted, [{ id: 'a', arguments: '{"path":"./src//a.ts"}' }, { id: 'b', arguments: '{"path":"b.ts"}' }]);
    assert.equal(result.kind, 'usable');
    const completed = await fixture.agent.completeModel({ opId: admitted.entry.opId, attempt: 0, expectedRunRevision: admitted.run.revision, result });
    assert.equal(completed.disposition, 'tool_batch');
    assert.deepEqual(completed.settlement.consumed, admitted.entry.budgetDelta);
    assert.equal(completed.run.budgetReserved.modelTokens, 0);
    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    const items = await Promise.all(closure.items.map((item) => fixture.store.artifacts.readCanonical<ContinuationItem>(item.payloadRef)));
    assert.deepEqual(items.map((item) => item.kind), ['model_turn', 'assistant_tool_batch']);
    const frontier = await fixture.store.artifacts.readCanonical<RunFrontier>(completed.run.frontierRef!);
    assert.deepEqual(frontier, { schemaVersion: 1, kind: 'tool', batchItemId: items[1]!.itemId, orderedCallIds: ['a', 'b'], nextCallIndex: 0 });
    assert.equal(closure.latestCheckpoint.runItemSeq, 2);
    assert.equal(closure.latestCheckpoint.journalSeq, completed.entry.seq);
    const current = await fixture.agent.readToolInvocation();
    assert.deepEqual(current.invocation, { callId: 'a', index: 0, toolName: 'read', input: { path: 'src/a.ts' }, replayClass: 'retry' });
    assert.deepEqual(current.subject.channel, { kind: 'fs-read', path: 'src/a.ts' });
    assert.equal(current.subject.display.path, 'src/a.ts');
    assert.equal(Object.isFrozen(current.invocation.input), true);
    assert.equal('grant' in current, false);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot);
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material });
    const restored = await fixture.agent.readToolInvocation();
    assert.deepEqual(restored.invocation, current.invocation);
    assert.equal(restored.loopSignature, current.loopSignature);
    assert.deepEqual(restored.execution, current.execution);
  } finally { await disposeFixture(fixture); }
});

async function longContext(fixture: Awaited<ReturnType<typeof createAgentFixture>>, texts = ['a', 'b', 'c'].map((v) => v.repeat(28_000))) {
  for (const [index, text] of texts.entries()) {
    const admitted = await prepare(fixture);
    assert.equal(admitted.prepared.request.kind, 'normal');
    const result = response(fixture, admitted, [{ id: `call-${index}`, name: 'unknown', arguments: '{}' }], text);
    const completed = await fixture.agent.completeModel({ opId: admitted.entry.opId, attempt: 0,
      expectedRunRevision: admitted.run.revision, result });
    assert.equal(completed.disposition, 'batch_rejected');
  }
}

test('compaction journals the greatest closed prefix, atomically replaces context and reproduces requests across restart', async () => {
  const fixture = await createAgentFixture('typed-compaction', { modelTokens: 1_000_000, costMicros: 10_000_000 });
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await longContext(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const admitted = await prepare(fixture);
    assert.equal(admitted.prepared.request.kind, 'context_compaction');
    assert.equal(admitted.prepared.request.negotiatedMode, 'text-only');
    const plan = await fixture.store.artifacts.readCanonical<RunContextCompactionPlan>(admitted.prepared.request.compactionPlanRef!);
    assert.equal(plan.compactFromItemSeq, 1);
    assert.equal(plan.compactThroughItemSeq, 3);
    assert.equal(plan.sourceContextManifestRef, before.latestCheckpoint.contextManifestRef);
    assert.equal(plan.summaryTokenCap, admitted.prepared.request.maximumOutputTokens);
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material });
    const resumed = await fixture.agent.readModelAttempt();
    assert.ok(resumed);
    assert.equal(resumed.state.phase, 'dispatch_claimed');
    assert.equal(resumed.prepared.requestRef, admitted.prepared.requestRef);
    assert.deepEqual(resumed.prepared.outbound.bodyBytes, admitted.prepared.outbound.bodyBytes);
    admitted.prepared = resumed.prepared;
    const result = response(fixture, admitted, [], '# Summary\n\nThe first read was rejected.');
    const commit = { opId: admitted.entry.opId, attempt: 0, expectedRunRevision: admitted.run.revision, result };
    const pending = await fixture.store.readRecoveryClosure(fixture.runId);
    fault.exec(`CREATE TRIGGER fail_compaction_checkpoint BEFORE INSERT ON checkpoints
      BEGIN SELECT RAISE(ABORT, 'injected compaction checkpoint failure'); END`);
    await assert.rejects(fixture.agent.completeModel(commit), /injected compaction checkpoint failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), pending);
    fault.exec('DROP TRIGGER fail_compaction_checkpoint');
    const completed = await fixture.agent.completeModel(commit);
    assert.equal(completed.disposition, 'context_compacted');
    assert.deepEqual(completed.settlement.consumed, admitted.entry.budgetDelta);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(after.items.length, before.items.length + 1);
    assert.deepEqual(after.items.slice(0, before.items.length), before.items);
    assert.equal(after.latestCheckpoint.workspaceStateRef, before.latestCheckpoint.workspaceStateRef);
    const context = await fixture.store.artifacts.readCanonical<{ segments: Array<{ kind: string }> }>(after.latestCheckpoint.contextManifestRef);
    assert.equal(context.segments[0]?.kind, 'summary');
    const next = await fixture.agent.prepareModel({ expectedRunRevision: completed.run.revision, leaseEpoch: fixture.leaseEpoch });
    assert.equal(next.prepared.request.kind, 'normal');
    assert.equal(next.projection.messages[2]?.contentUtf8, '# Summary\n\nThe first read was rejected.');
    assert.equal(next.projection.messages.filter((message) => message.role === 'assistant').length, 2);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot);
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material });
    const recoveredNext = await fixture.agent.readModelAttempt();
    assert.ok(recoveredNext);
    assert.equal(recoveredNext.prepared.requestRef, next.prepared.requestRef);
    assert.deepEqual(recoveredNext.prepared.outbound.bodyBytes, next.prepared.outbound.bodyBytes);
    await assert.rejects(fixture.agent.prepareModel({ expectedRunRevision: next.run.revision, leaseEpoch: fixture.leaseEpoch }),
      { code: 'LEASE_FENCED' });
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('executed invalid compaction is fully charged, preserves raw context and cannot retry semantically', async () => {
  const fixture = await createAgentFixture('typed-bad-compaction', { modelTokens: 1_000_000, costMicros: 10_000_000 });
  try {
    await longContext(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const admitted = await prepare(fixture);
    const result = response(fixture, admitted, [{ id: 'forbidden', arguments: '{}' }]);
    assert.equal(result.kind, 'unusable');
    const completed = await fixture.agent.completeModel({ opId: admitted.entry.opId, attempt: 0,
      expectedRunRevision: admitted.run.revision, result });
    assert.equal(completed.disposition, 'stop_required');
    assert.equal(completed.failure?.kind, 'context_compaction_failed');
    assert.deepEqual(completed.settlement.consumed, admitted.entry.budgetDelta);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(after.items, before.items);
    assert.equal(after.latestCheckpoint.contextManifestRef, before.latestCheckpoint.contextManifestRef);
    await assert.rejects(fixture.agent.prepareModel({ expectedRunRevision: completed.run.revision, leaseEpoch: fixture.leaseEpoch }),
      error => error instanceof AgentHandoffPendingError && error.disposition === 'stop_required' && error.evidenceRef === completed.entry.resultRef);
  } finally { await disposeFixture(fixture); }
});

test('a shape-valid summary that does not shrink the complete prompt is charged but never installed', async () => {
  const fixture = await createAgentFixture('typed-ineffective-compaction', { modelTokens: 1_000_000, costMicros: 10_000_000 });
  try {
    // JSON-escaped newlines make the compaction source larger than the original normal message.
    await longContext(fixture, ['\n'.repeat(12_000), 'recent'.repeat(12_000)]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const admitted = await prepare(fixture);
    assert.equal(admitted.prepared.request.kind, 'context_compaction');
    const result = response(fixture, admitted, [], 's'.repeat(12_288));
    assert.equal(result.kind, 'usable');
    const completed = await fixture.agent.completeModel({ opId: admitted.entry.opId, attempt: 0,
      expectedRunRevision: admitted.run.revision, result });
    assert.equal(completed.disposition, 'stop_required');
    assert.equal(completed.failure?.kind, 'context_compaction_failed');
    assert.deepEqual(completed.settlement.consumed, admitted.entry.budgetDelta);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(after.items, before.items);
    assert.equal(after.latestCheckpoint.contextManifestRef, before.latestCheckpoint.contextManifestRef);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot);
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material });
    assert.equal((await fixture.agent.readModelAttempt())?.disposition, 'stop_required');
  } finally { await disposeFixture(fixture); }
});

test('context exhaustion retains exact evidence and dispatches nothing when the only large segment is protected', async () => {
  const fixture = await createAgentFixture('typed-context-exhausted');
  try {
    await longContext(fixture, ['x'.repeat(70_000)]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.agent.prepareModel({ expectedRunRevision: before.run.revision, leaseEpoch: fixture.leaseEpoch }),
      asyncError => asyncError instanceof AgentContextExhaustedError && asyncError.evidence.nextPromptTokens > asyncError.evidence.triggerThresholdTokens);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('loading an agent snapshots authority before asynchronous recovery reads', async () => {
  const fixture = await createAgentFixture('typed-authority-snapshot');
  try {
    const material = { ...fixture.authority.material, additionalCredentialGrantRefs: [...fixture.authority.material.additionalCredentialGrantRefs] };
    const loading = fixture.store.loadAgentRun({ runId: fixture.runId, material });
    material.resolveVerifiedTools = () => null;
    material.additionalCredentialGrantRefs.push('invalid');
    const loaded = await loading;
    const prepared = await loaded.prepareModel({ expectedRunRevision: fixture.runRevision, leaseEpoch: fixture.leaseEpoch });
    assert.equal(prepared.entry.attempt, 0);
  } finally { await disposeFixture(fixture); }
});

test('an invalid batch atomically retains every call and ordered result, then rebuilds the complete next native request', async () => {
  const fixture = await createAgentFixture('typed-invalid');
  try {
    const admitted = await prepare(fixture);
    const result = response(fixture, admitted, [{ id: 'z', arguments: '{"path":"ok.ts"}' },
      { id: 'a', arguments: '{"path":12}' }, { id: 'b', name: 'unknown', arguments: '{}' }]);
    const completed = await fixture.agent.completeModel({ opId: admitted.entry.opId, attempt: 0, expectedRunRevision: admitted.run.revision, result });
    assert.equal(completed.disposition, 'batch_rejected');
    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    const items = await Promise.all(closure.items.map((item) => fixture.store.artifacts.readCanonical<ContinuationItem>(item.payloadRef)));
    assert.deepEqual(items.map((item) => item.kind), ['model_turn', 'assistant_tool_batch', 'tool_result', 'tool_result', 'tool_result']);
    assert.deepEqual(items.filter((item) => item.kind === 'tool_result').map((item) => item.outcome), ['batch_not_executed', 'error', 'error']);
    assert.equal(closure.journal.filter((entry) => entry.opKind !== 'model').length, 0);
    await assert.rejects(fixture.agent.readToolInvocation(), { code: 'STATE_TRANSITION_INVALID' });
    const next = await fixture.agent.prepareModel({ expectedRunRevision: completed.run.revision, leaseEpoch: fixture.leaseEpoch });
    assert.deepEqual(next.projection.messages.map((message) => message.role), ['system', 'user', 'assistant', 'tool', 'tool', 'tool']);
    const assistant = next.projection.messages[2]!;
    assert.equal(assistant.role, 'assistant');
    assert.deepEqual(assistant.toolCalls.map((call) => call.callId), ['z', 'a', 'b']);
    assert.equal(assistant.continuation?.items.length, 1);
    assert.deepEqual(next.projection.messages.slice(3).map((message) => JSON.parse(message.contentUtf8)), [
      { code: 'BATCH_REJECTED_BEFORE_DISPATCH', invalidCallIds: ['a', 'b'] }, { code: 'TOOL_INPUT_INVALID' }, { code: 'TOOL_NOT_FOUND' }
    ]);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot);
    const recovered = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(recovered.items.length, 5);
    assert.equal(recovered.run.frontierRef, next.run.frontierRef);
    const reloaded = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material });
    const replayed = reloaded.model.prepare({ kind: 'normal', invocation: { runId: fixture.runId, opId: next.entry.opId, attempt: 0 },
      projectionRef: next.prepared.request.promptProjectionRef, projection: next.projection });
    assert.equal(replayed.requestRef, next.prepared.requestRef);
    assert.deepEqual(replayed.outbound.bodyBytes, next.prepared.outbound.bodyBytes);
  } finally { await disposeFixture(fixture); }
});

test('a model request cannot bypass typed admission with a caller-selected reservation', async () => {
  const fixture = await createAgentFixture('typed-budget', { modelTokens: 40_959 });
  try {
    await assert.rejects(fixture.agent.prepareModel({ expectedRunRevision: fixture.runRevision, leaseEpoch: fixture.leaseEpoch }),
      { code: 'BUDGET_EXHAUSTED' });
    const run = fixture.store.getRun(fixture.runId);
    assert.equal(run.revision, fixture.runRevision);
    await assert.rejects(fixture.store.prepareInvocation({ runId: fixture.runId, expectedRunRevision: run.revision,
      leaseEpoch: fixture.leaseEpoch, opId: 'forged', opKind: 'model', target: 'model-1', requestRef: fixture.authority.assemblyRef,
      replayClass: 'retry', reservation: { modelTokens: 1, costMicros: 0, toolCalls: 0, repairAttempts: 0 } }), { code: 'INVALID_REQUEST' });
    await assert.rejects(fixture.store.prepareInvocation({ runId: fixture.runId, expectedRunRevision: run.revision,
      leaseEpoch: fixture.leaseEpoch, opId: 'disguised-model', opKind: 'tool', target: 'model-1', requestRef: fixture.authority.assemblyRef,
      replayClass: 'retry', reservation: { modelTokens: 1, costMicros: 0, toolCalls: 0, repairAttempts: 0 } }), { code: 'INVALID_REQUEST' });
    assert.equal((await fixture.store.readRecoveryClosure(fixture.runId)).journal.length, 0);
  } finally { await disposeFixture(fixture); }
});

test('checkpoint failure rolls back the entire model settlement, batch and context; retry commits once', async () => {
  const fixture = await createAgentFixture('typed-atomic');
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const admitted = await prepare(fixture);
    const result = response(fixture, admitted, [{ id: 'a', arguments: '{"path":"ok"}' }, { id: 'b', arguments: '{"path":false}' }]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const commit = { opId: admitted.entry.opId, attempt: 0, expectedRunRevision: admitted.run.revision, result };
    await assert.rejects(fixture.agent.completeModel({ ...commit, expectedRunRevision: admitted.run.revision - 1 }), { code: 'REVISION_CONFLICT' });
    fault.exec(`CREATE TRIGGER fail_continuation_checkpoint BEFORE INSERT ON checkpoints
      BEGIN SELECT RAISE(ABORT, 'injected checkpoint failure'); END`);
    await assert.rejects(fixture.agent.completeModel(commit), /injected checkpoint failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    fault.exec('DROP TRIGGER fail_continuation_checkpoint');
    const raced = await Promise.allSettled([fixture.agent.completeModel(commit), fixture.agent.completeModel(commit)]);
    const successes = raced.filter((result) => result.status === 'fulfilled');
    assert.equal(successes.length, 1);
    assert.equal(raced.filter((result) => result.status === 'rejected').length, 1);
    const completed = successes[0]!.value;
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(after.items.length, 4);
    assert.equal(after.journal.length, 3);
    await assert.rejects(fixture.agent.completeModel({ ...commit, expectedRunRevision: completed.run.revision }));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), after);
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('an unusable native response is durably charged once without a fabricated batch or semantic retry', async () => {
  const fixture = await createAgentFixture('typed-unusable');
  try {
    const admitted = await prepare(fixture);
    const result = response(fixture, admitted, [{ id: 'duplicate', arguments: '{}' }, { id: 'duplicate', arguments: '{}' }]);
    assert.equal(result.kind, 'unusable');
    const completed = await fixture.agent.completeModel({ opId: admitted.entry.opId, attempt: 0, expectedRunRevision: admitted.run.revision, result });
    assert.equal(completed.disposition, 'stop_required');
    assert.deepEqual(completed.settlement.consumed, admitted.entry.budgetDelta);
    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(closure.items.length, 0);
    assert.equal(closure.journal.at(-1)?.resultRef, result.responseRef);
    assert.equal(closure.latestCheckpoint.journalSeq, completed.entry.seq);
    await assert.rejects(fixture.agent.prepareModel({ expectedRunRevision: completed.run.revision, leaseEpoch: fixture.leaseEpoch }),
      { code: 'AGENT_HANDOFF_PENDING' });
  } finally { await disposeFixture(fixture); }
});

test('recovery rejects a missing transitive tool input even when the Journal, batch and checkpoint still exist', async () => {
  const fixture = await createAgentFixture('typed-closure');
  try {
    const admitted = await prepare(fixture);
    const result = response(fixture, admitted, [{ id: 'a', arguments: '{"path":"retained.ts"}' }]);
    assert.equal(result.kind, 'usable');
    await fixture.agent.completeModel({ opId: admitted.entry.opId, attempt: 0, expectedRunRevision: admitted.run.revision, result });
    await rm(path.join(fixture.stateRoot, 'cas', result.turn.toolCalls[0]!.inputRef));
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
    await assert.rejects(fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material,
      }), { code: 'RECOVERY_REQUIRED' });
  } finally { await disposeFixture(fixture); }
});

test('generic settlement cannot replace a typed model result or invent a post-claim refund', async () => {
  const fixture = await createAgentFixture('typed-settlement');
  try {
    const admitted = await prepare(fixture);
    const fake = await fixture.store.artifacts.publishCanonical({ claimed: 'no I/O' }, 'cliq-test-fake-evidence-v1');
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const identity = { runId: fixture.runId, opId: admitted.entry.opId, attempt: 0, expectedRunRevision: admitted.run.revision };
    await assert.rejects(fixture.store.completeInvocation({ ...identity, resultRef: fake.ref,
      consumed: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 } }), { code: 'INVALID_REQUEST' });
    await assert.rejects(fixture.store.failClaimedInvocationWithoutRelease({ ...identity, errorRef: fake.ref,
      evidenceRef: fake.ref, evidenceDigest: fake.ref }), { code: 'INVALID_REQUEST' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('JSON-looking final text stays inert and cannot mark an unverified Run successful', async () => {
  const fixture = await createAgentFixture('typed-final');
  try {
    const admitted = await prepare(fixture);
    const reader = fixture.agent.model.start(admitted.prepared, { status: 200, mediaType: 'application/json' });
    reader.push(Buffer.from(JSON.stringify({ id: 'end-1', object: 'response', status: 'completed', model: 'model-1',
      output: [{ type: 'message', id: 'message-1', role: 'assistant', status: 'completed',
        content: [{ type: 'output_text', text: '{"bash":"this is text, not an executable call"}', annotations: [] }] }] })));
    const result = reader.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput);
    assert.equal(result.kind, 'usable');
    const completed = await fixture.agent.completeModel({ opId: admitted.entry.opId, attempt: 0, expectedRunRevision: admitted.run.revision, result });
    assert.equal(completed.disposition, 'candidate_required');
    assert.equal(completed.run.status, 'running');
    assert.equal(completed.run.resultRef, undefined);
    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(closure.items.length, 1);
    assert.equal(closure.journal.filter((entry) => entry.opKind !== 'model').length, 0);
    await assert.rejects(fixture.agent.prepareModel({ expectedRunRevision: completed.run.revision, leaseEpoch: fixture.leaseEpoch }),
      error => error instanceof AgentHandoffPendingError && error.disposition === 'candidate_required' && error.evidenceRef === completed.entry.resultRef);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot);
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material });
    assert.equal((await fixture.agent.readModelAttempt())?.disposition, 'candidate_required');
    await assert.rejects(fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch }),
      { code: 'AGENT_HANDOFF_PENDING', disposition: 'candidate_required' });
  } finally { await disposeFixture(fixture); }
});

test('the current tool projection rejects skipped, reordered and foreign batch frontiers', async () => {
  const fixture = await createAgentFixture('typed-tool-cursor');
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const admitted = await prepare(fixture);
    const result = response(fixture, admitted, [{ id: 'a', arguments: '{"path":"a"}' }, { id: 'b', arguments: '{"path":"b"}' }]);
    const completed = await fixture.agent.completeModel({ opId: admitted.entry.opId, attempt: 0, expectedRunRevision: admitted.run.revision, result });
    const current = await fixture.agent.readToolInvocation();
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    for (const frontier of [
      { ...current.frontier, nextCallIndex: 1 }, { ...current.frontier, nextCallIndex: 2 },
      { ...current.frontier, orderedCallIds: ['b', 'a'] }, { ...current.frontier, batchItemId: 'foreign-batch' },
      { ...current.frontier, schemaVersion: 2 }, { ...current.frontier, ignoredAuthority: true }
    ]) {
      const artifact = await fixture.store.artifacts.publishCanonical(frontier, 'cliq-run-frontier-v1');
      fault.prepare('UPDATE runs SET frontier_ref = ? WHERE id = ?').run(artifact.ref, fixture.runId);
      await assert.rejects(fixture.agent.readToolInvocation(), { code: 'RECOVERY_REQUIRED' });
      fault.prepare('UPDATE runs SET frontier_ref = ? WHERE id = ?').run(completed.run.frontierRef!, fixture.runId);
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    }
    assert.equal((await fixture.agent.readToolInvocation()).invocation.callId, 'a');
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('model dispatch claims bind the current frontier before and inside the permanent claim transaction', async () => {
  const fixture = await createAgentFixture('typed-claim-frontier');
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const admitted = await fixture.agent.prepareModel({ expectedRunRevision: fixture.runRevision, leaseEpoch: fixture.leaseEpoch });
    const input = { runId: fixture.runId, expectedRunRevision: admitted.run.revision, leaseEpoch: fixture.leaseEpoch,
      opId: admitted.entry.opId, attempt: 0, dispatchId: 'exact-dispatch' };
    const frontier = await fixture.store.artifacts.readCanonical<RunFrontier>(admitted.run.frontierRef!);
    assert.equal(frontier.kind, 'agent');
    const other = await fixture.store.artifacts.publishCanonical({ ...frontier, turnId: 'different-turn' }, 'cliq-run-frontier-v1');
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const staleContext = await fixture.store.artifacts.publishCanonical({ ...frontier, contextItemSeq: 1 }, 'cliq-run-frontier-v1');
    for (const ref of [other.ref, staleContext.ref]) {
      fault.prepare('UPDATE runs SET frontier_ref = ? WHERE id = ?').run(ref, fixture.runId);
      await assert.rejects(fixture.store.claimInvocationDispatch(input), { code: 'RECOVERY_REQUIRED' });
    }
    fault.prepare('UPDATE runs SET frontier_ref = ? WHERE id = ?').run(admitted.run.frontierRef!, fixture.runId);
    const raced = fixture.store.claimInvocationDispatch(input);
    fault.prepare('UPDATE runs SET frontier_ref = ? WHERE id = ?').run(other.ref, fixture.runId);
    await assert.rejects(raced, { code: 'REVISION_CONFLICT' });
    fault.prepare('UPDATE runs SET frontier_ref = ? WHERE id = ?').run(admitted.run.frontierRef!, fixture.runId);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    const body = admitted.prepared.artifacts.find((artifact) => artifact.ref === admitted.prepared.request.bodyBytesRef)!;
    await rm(path.join(fixture.stateRoot, 'cas', body.ref));
    await assert.rejects(fixture.store.claimInvocationDispatch(input), /ENOENT/);
    await fixture.store.artifacts.publishBytes(body.bytes, body.mediaType, body.schemaKind);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    const claim = fixture.store.claimInvocationDispatch(input);
    input.opId = 'mutated-after-call';
    input.dispatchId = 'mutated-after-call';
    const claimed = await claim;
    assert.equal(claimed.opId, admitted.entry.opId);
    assert.equal(claimed.dispatchId, 'exact-dispatch');
    await assert.rejects(fixture.store.claimInvocationDispatch({ ...input, opId: admitted.entry.opId }), { code: 'STATE_TRANSITION_INVALID' });
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('the loaded state seam classifies authority and caller validation failures without hiding their cause', async () => {
  const fixture = await createAgentFixture('typed-error-codes');
  try {
    await assert.rejects(fixture.store.loadAgentRun({ runId: fixture.runId,
      material: { ...fixture.authority.material, resolveVerifiedTools: () => null } }),
    error => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED' && error.cause instanceof TypeError);
    const admitted = await prepare(fixture);
    const result = response(fixture, admitted, [{ id: 'a', arguments: '{"path":"a"}' }]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.agent.completeModel({ opId: admitted.entry.opId, attempt: 0, expectedRunRevision: admitted.run.revision,
      result: { ...result, artifacts: null } as unknown as typeof result }),
    error => error instanceof KernelStorageError && error.code === 'INVALID_REQUEST' && error.cause instanceof TypeError);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
