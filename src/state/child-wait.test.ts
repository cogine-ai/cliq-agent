import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { publishInProcessChannel } from './store.js';
import { activateFixtureWorker, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { createChildRunFixture, activateOfflineChild, completeOfflineChild } from './testing/child-runs.js';
import { batch } from './testing/tool-calls.js';
import { retireFixtureToolSelection } from './testing/tool-effects.js';

// Storage/owner regression with the existing explicitly inert worker fixture;
// no child model provider or physical Linux concurrency is claimed.
test('await releases its original parent and settles children once; repeated await rereads their same owned results', async () => {
  const fixture = await createChildRunFixture('children-await-and-reread', 2);
  try {
    const ids = fixture.children.map(child => child.childRunId);
    Object.assign(fixture, await activateFixtureWorker(fixture, 'parent-before-await', 30_000));
    await batch(fixture, [{ name: 'await_children', input: { childRunIds: [ids[1], ids[0]] } },
      { name: 'await_children', input: { childRunIds: [ids[0], ids[1]] } }]);
    const selection = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
      leaseEpoch: fixture.leaseEpoch });
    assert.equal(selection.disposition, 'retirement_required');
    if (selection.disposition !== 'retirement_required') throw new Error('await must retire the original parent worker');
    assert.equal(selection.reason, 'children');
    await retireFixtureToolSelection(fixture, selection);
    const beforeRegistration = fixture.store.getRun(fixture.runId);
    const waiting = await fixture.agent.waitForChildren({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    assert.equal(waiting.run.status, 'waiting'); assert.equal(waiting.run.waitingReason, 'child');
    const waitingBytes = canonicalJsonBytes(waiting.run);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(before.run.budgetConsumed.toolCalls, beforeRegistration.budgetConsumed.toolCalls + 1);
    assert.deepEqual(before.journal.slice(-3).map(row => row.phase), ['prepared', 'dispatch_claimed', 'completed']);
    assert(before.journal.slice(-3).every(row => row.opKind === 'child_await' && row.grantRef === undefined && row.leaseEpoch === 0 &&
      !row.sandboxLaunchSpecRef && !row.brokerFenceTokenDigest));
    assert.equal(before.workerLaunches.length, 0);
    await completeOfflineChild(await activateOfflineChild(fixture, 0));
    assert.deepEqual(canonicalJsonBytes(fixture.store.getRun(fixture.runId)), waitingBytes);
    assert.deepEqual(await fixture.agent.settleChildren({ expectedRunRevision: waiting.run.revision }), waiting);
    await completeOfflineChild(await activateOfflineChild(fixture, 1));
    assert.deepEqual(canonicalJsonBytes(fixture.store.getRun(fixture.runId)), waitingBytes);
    const terminalCut = await fixture.store.readRecoveryClosure(fixture.runId);
    fixture.driver.exec("CREATE TRIGGER fail_child_settlement BEFORE UPDATE ON child_allocations WHEN NEW.state='settled' BEGIN SELECT RAISE(ABORT,'injected child settlement failure'); END");
    try {
      await assert.rejects(fixture.agent.settleChildren({ expectedRunRevision: waiting.run.revision }), /injected child settlement failure/);
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), terminalCut,
        'the original child results, both allocations, parent budgets, items and wake all roll back together');
    } finally { fixture.driver.exec('DROP TRIGGER fail_child_settlement'); }
    const awakened = await fixture.agent.settleChildren({ expectedRunRevision: waiting.run.revision });
    assert.equal(awakened.run.status, 'queued'); assert.equal(awakened.run.activeWorkerLaunchId, undefined);
    assert.equal(awakened.run.waitingOnRef, undefined); assert.equal(awakened.run.budgetReserved.toolCalls, 0);
    const first = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(first.journal, before.journal, 'wake settles child usage without registering or charging the same await again');
    const results = await fixture.store.artifacts.mapReads(first.items, item => fixture.store.artifacts.readCanonical<{ kind: string; childRunId?: string }>(item.payloadRef));
    assert.deepEqual(results.filter(item => item.kind === 'child_result').map(item => item.childRunId), [ids[1], ids[0]]);
    const repeated = await fixture.agent.waitForChildren({ expectedRunRevision: awakened.run.revision });
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(repeated.run.status, 'queued'); assert.equal(repeated.run.nextStep, 'agent');
    assert.deepEqual(after.run.budgetConsumed, { ...first.run.budgetConsumed, toolCalls: first.run.budgetConsumed.toolCalls + 1 });
    assert.deepEqual(after.run.budgetReserved, first.run.budgetReserved);
    assert.deepEqual(after.childAllocations, first.childAllocations);
    assert.equal(after.items.length, first.items.length + 1, 'reread appends only the current await ToolResult');
    assert.deepEqual(after.journal.slice(0, first.journal.length), first.journal);
    assert.equal(after.journal.length, first.journal.length + 3, 'a new explicit re-await records exactly its own one local registration');
    assert(after.journal.slice(-3).every(row => row.opKind === 'child_await' && row.grantRef === undefined && row.leaseEpoch === 0));
    const prepared = await fixture.agent.prepareTool({ expectedRunRevision: after.run.revision, leaseEpoch: after.run.leaseEpoch }).catch(error => error);
    assert.equal(prepared.code, 'STATE_TRANSITION_INVALID');
    Object.assign(fixture, await activateFixtureWorker(fixture, 'parent-await-true-model-content', 30_000));
    const next = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    const result = next.projection.messages.filter(message => message.role === 'tool').at(-1)!;
    assert.equal(result.contentUtf8, canonicalJsonBytes({ schemaVersion: 1, results: ids.map(childRunId => ({ childRunId, mode: 'read_only',
      status: 'completed_unverified', summary: 'The child inspection is complete.' })) }).toString('utf8'));
    assert.equal(next.projection.messages.some(message => message.role === 'user' && message.sourceKind === 'child_result'), false,
      'the actual await returns the summaries without duplicate user messages');
    assert(!result.contentUtf8.includes('waitSetRef')); assert(!result.contentUtf8.includes('childResultItemIds'));
  } finally { await disposeFixture(fixture); }
});

test('await registration publications and its sole transaction can fail without leaving a charge, wait or partial local claim', async () => {
  const fixture = await createChildRunFixture('child-await-registration-faults');
  try {
    Object.assign(fixture, await activateFixtureWorker(fixture, 'parent-before-faulted-await', 30_000));
    await batch(fixture, [{ name: 'await_children', input: { childRunIds: [fixture.children[0]!.childRunId] } }]);
    const selected = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    if (selected.disposition !== 'retirement_required') throw new Error('await registration needs true original fixture retirement');
    await retireFixtureToolSelection(fixture, selected);
    const before = await fixture.store.readRecoveryClosure(fixture.runId), original = fixture.store.artifacts.publishBytes.bind(fixture.store.artifacts);
    fixture.store.artifacts.publishBytes = async (bytes, media, kind) => {
      const value = await original(bytes, media, kind);
      if (kind === 'cliq-child-await-receipt-v1') throw new Error('injected actual await CAS publication failure');
      return value;
    };
    try { await assert.rejects(fixture.agent.waitForChildren({ expectedRunRevision: before.run.revision }), /injected actual await CAS publication failure/); }
    finally { fixture.store.artifacts.publishBytes = original; }
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    fixture.driver.exec("CREATE TRIGGER fail_await_registration BEFORE INSERT ON checkpoints WHEN EXISTS(SELECT 1 FROM run_journal WHERE run_id=NEW.run_id AND op_kind='child_await' AND phase='completed') BEGIN SELECT RAISE(ABORT,'injected await registration Checkpoint failure'); END");
    try { await assert.rejects(fixture.agent.waitForChildren({ expectedRunRevision: before.run.revision }), /injected await registration Checkpoint failure/); }
    finally { fixture.driver.exec('DROP TRIGGER fail_await_registration'); }
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    const waiting = await fixture.agent.waitForChildren({ expectedRunRevision: before.run.revision }), after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(waiting.run.status, 'waiting'); assert.equal(after.journal.length, before.journal.length + 3);
    assert.equal(after.run.budgetConsumed.toolCalls, before.run.budgetConsumed.toolCalls + 1);
    assert.deepEqual(after.childAllocations, before.childAllocations);
    await assert.rejects(fixture.agent.waitForChildren({ expectedRunRevision: waiting.run.revision }));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), after);
  } finally { await disposeFixture(fixture); }
});

test('a real parent Stop registered during await publication fences the exact old accounting cut before any claim or charge', async () => {
  const fixture = await createChildRunFixture('child-await-registration-stop-race');
  try {
    Object.assign(fixture, await activateFixtureWorker(fixture, 'parent-before-stopped-await', 30_000));
    await batch(fixture, [{ name: 'await_children', input: { childRunIds: [fixture.children[0]!.childRunId] } }]);
    const selected = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    if (selected.disposition !== 'retirement_required') throw new Error('await must retire before publication');
    await retireFixtureToolSelection(fixture, selected);
    const before = await fixture.store.readRecoveryClosure(fixture.runId), original = fixture.store.artifacts.publishBytes.bind(fixture.store.artifacts);
    let fired = false;
    const cancel = { ...await publishInProcessChannel(fixture.store), requestId: uuidv7(), expectedRunRevision: before.run.revision };
    fixture.store.artifacts.publishBytes = async (bytes, media, kind) => {
      const value = await original(bytes, media, kind);
      if (!fired && kind === 'cliq-child-await-receipt-v1') {
        fired = true;
        await fixture.agent.cancelRun(cancel);
      }
      return value;
    };
    try { await assert.rejects(fixture.agent.waitForChildren({ expectedRunRevision: before.run.revision })); }
    finally { fixture.store.artifacts.publishBytes = original; }
    assert.equal(fired, true);
    const stopped = await fixture.store.readRecoveryClosure(fixture.runId);
    assert(stopped.run.stopIntentRef); assert.deepEqual(stopped.run.budgetConsumed, before.run.budgetConsumed);
    assert.deepEqual(stopped.journal, before.journal); assert.deepEqual(stopped.childAllocations, before.childAllocations);
    assert.equal(stopped.run.waitingOnRef, undefined);
  } finally { await disposeFixture(fixture); }
});
