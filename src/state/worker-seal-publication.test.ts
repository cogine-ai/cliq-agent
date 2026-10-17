import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_CAS_DIRECTORY } from '../config.js';
import type { BudgetSettlementV1, RecoveryClosureV1, Session, ToolResultItem } from '../kernel/types.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { admissionKey, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';
import { postEffectObservation } from './testing/tool-effects.js';

test('an unrelated Session advances canonical time without rebuilding a published tool settlement', async t => {
  const initial = Date.now();
  let clock = initial;
  t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('seal-publication-session', undefined, { mode: 'accept-edits', tools: ['edit'] });
  try {
    // Real SQLite/CAS with an offline canonical containment graph; this test does not qualify native death.
    await batch(fixture, [{ name: 'edit', input: { path: 'a', old_text: 'old', new_text: 'new' } }]);
    const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared);
    const proof = await postEffectObservation(fixture, await observation(fixture, claimed, { changed: true }), prepared.checkpointId);
    const identity = await publishInProcessChannel(fixture.store);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const sample = await fs.open(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, proof.observationRef), 'r');
    const prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] };
    const writeFile = prototype.writeFile;
    await sample.close();
    const settlements: BudgetSettlementV1[] = [];
    const unrelatedSessions: Session[] = [];
    const writer = t.mock.method(prototype, 'writeFile', async function(this: FileHandle, ...args: unknown[]) {
      await Reflect.apply(writeFile, this, args);
      if (!Buffer.isBuffer(args[0]) || !args[0].toString('utf8').includes('"format":"cliq-budget-settlement-v1"')) return;
      const settlement = JSON.parse(args[0].toString('utf8')) as BudgetSettlementV1;
      if (settlement.runId !== fixture.runId || settlement.opId !== prepared.entry.opId || settlement.terminalPhase !== 'completed') return;
      settlements.push(settlement);
      clock += 1_000;
      const unrelated = await fixture.store.createSession({ ...identity, requestId: uuidv7(), admissionKey: admissionKey('seal-publication-unrelated'),
        workspacePath: fixture.workspace });
      unrelatedSessions.push(unrelated.session);
      assert.notEqual(unrelated.session.id, before.run.sessionId);
      assert.equal(unrelated.session.createdAt, new Date(clock).toISOString());
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before,
        'the unrelated public transaction must leave the selected Run, Journal, launch and generation cut unchanged');
    });
    const completed = await fixture.agent.completeTool({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
      expectedRunRevision: prepared.run.revision, observationRef: proof.observationRef });
    writer.mock.restore();
    assert.equal(settlements.length, 1, 'the actual completed-settlement file write is never repeated');
    const stagedAt = new Date(initial).toISOString(), committedAt = new Date(initial + 1_000).toISOString();
    assert.equal(settlements[0]!.settledAt, stagedAt);
    assert.deepEqual(completed.settlement, settlements[0]);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(after.run.status, 'queued');
    assert.equal(after.run.updatedAt, committedAt);
    assert.equal(after.run.budgetConsumed.toolCalls, 1);
    assert.equal(after.run.budgetReserved.toolCalls, 0);
    assert.equal(after.latestCheckpoint.id, prepared.checkpointId);
    assert.equal(after.latestCheckpoint.createdAt, committedAt);
    assert.deepEqual(after.workerLaunches, []);
    assert.equal(after.workspaceGenerations[0]!.phase, 'sealed');
    assert.equal(after.workspaceGenerations[0]!.updatedAt, committedAt);
    // Public recovery additionally requires the retired launch's time to equal this Checkpoint's commit time.
    const terminal = after.journal.at(-1)!;
    assert.equal(terminal.phase, 'completed');
    assert.equal(terminal.timestamp, stagedAt);
    assert.deepEqual(await fixture.store.artifacts.readCanonical<BudgetSettlementV1>(terminal.budgetSettlementRef!), settlements[0]);
    const result = await fixture.store.artifacts.readCanonical<ToolResultItem>(after.items.at(-1)!.payloadRef);
    assert.equal(result.createdAt, stagedAt);
    const events = await fixture.store.readControl({ protocolVersion: 1, method: 'run.attach', runId: fixture.runId, afterEventSeq: 0 }, identity);
    assert.ok(events.method === 'run.attach');
    const event = events.events.at(-1)!;
    assert.ok(event.kind === 'state_changed');
    assert.equal(event.runRevision, after.run.revision);
    assert.equal(event.occurredAt, committedAt);
    assert.equal(unrelatedSessions.length, 1);
    const unrelatedSession = unrelatedSessions[0]!;
    clock += 6_000;
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), after);
    assert.deepEqual(fixture.store.getSession(unrelatedSession.id), unrelatedSession);
  } finally { await disposeFixture(fixture); t.mock.restoreAll(); }
});

test('a cancellation during settlement publication preserves the winning cut without rebuilding completion', async t => {
  const initial = Date.now();
  let clock = initial;
  t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('seal-publication-cancel', undefined, { mode: 'accept-edits', tools: ['edit'] });
  try {
    // Offline retained proofs exercise public persistence, not actual process creation or native retirement.
    await batch(fixture, [{ name: 'edit', input: { path: 'a', old_text: 'old', new_text: 'new' } }]);
    const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared);
    const proof = await postEffectObservation(fixture, await observation(fixture, claimed, { changed: true }), prepared.checkpointId);
    const identity = await publishInProcessChannel(fixture.store);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const sample = await fs.open(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, proof.observationRef), 'r');
    const prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] };
    const writeFile = prototype.writeFile;
    await sample.close();
    const settlements: BudgetSettlementV1[] = [];
    const cancelledCuts: RecoveryClosureV1[] = [];
    const writer = t.mock.method(prototype, 'writeFile', async function(this: FileHandle, ...args: unknown[]) {
      await Reflect.apply(writeFile, this, args);
      if (!Buffer.isBuffer(args[0]) || !args[0].toString('utf8').includes('"format":"cliq-budget-settlement-v1"')) return;
      const settlement = JSON.parse(args[0].toString('utf8')) as BudgetSettlementV1;
      if (settlement.runId !== fixture.runId || settlement.opId !== prepared.entry.opId || settlement.terminalPhase !== 'completed') return;
      settlements.push(settlement);
      clock += 1_000;
      const cancelled = await fixture.agent.cancelRun({ ...identity, requestId: uuidv7(), expectedRunRevision: before.run.revision });
      const winning = await fixture.store.readRecoveryClosure(fixture.runId);
      assert.deepEqual(winning.run, cancelled.run);
      cancelledCuts.push(winning);
    });
    await assert.rejects(fixture.agent.completeTool({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
      expectedRunRevision: prepared.run.revision, observationRef: proof.observationRef }), { code: 'REVISION_CONFLICT' });
    writer.mock.restore();
    assert.equal(settlements.length, 1, 'the rejected prepared continuation does not regenerate its already-written settlement');
    assert.equal(settlements[0]!.settledAt, new Date(initial).toISOString());
    assert.equal(cancelledCuts.length, 1);
    const winning = cancelledCuts[0]!;
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(after, winning);
    assert.equal(after.run.cancelRequested, true);
    assert.ok(after.run.stopIntentRef);
    assert.equal(after.run.revision, before.run.revision + 1);
    assert.equal(after.run.updatedAt, new Date(initial + 1_000).toISOString());
    assert.equal(after.run.activeWorkerLaunchId, before.run.activeWorkerLaunchId);
    assert.equal(after.run.budgetConsumed.toolCalls, 0);
    assert.equal(after.run.budgetReserved.toolCalls, 1);
    assert.deepEqual(after.journal, before.journal);
    assert.equal(after.journal.filter(entry => entry.opId === prepared.entry.opId && entry.phase === 'dispatch_claimed').length, 1);
    assert.deepEqual(after.latestCheckpoint, before.latestCheckpoint);
    assert.notEqual(after.latestCheckpoint.id, prepared.checkpointId);
    assert.deepEqual(after.items, before.items);
    assert.deepEqual(after.workerLaunches, before.workerLaunches);
    assert.deepEqual(after.workspaceGenerations, before.workspaceGenerations);
    const resumed = await fixture.agent.completeTool({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
      expectedRunRevision: after.run.revision, observationRef: proof.observationRef });
    assert.deepEqual(resumed.settlement, settlements[0], 'explicit StopIntent-only rebinding retains the original settlement bytes and timestamp');
    const settled = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(settled.run.stopIntentRef, winning.run.stopIntentRef); assert.equal(settled.run.cancelRequested, true);
    assert.equal(settled.run.revision, winning.run.revision + 1);
    assert.equal(settled.run.budgetConsumed.toolCalls, 1); assert.equal(settled.run.budgetReserved.toolCalls, 0);
    assert.deepEqual(settled.journal.filter(entry => entry.opId === prepared.entry.opId).map(entry => entry.phase),
      ['prepared', 'dispatch_claimed', 'completed']);
    assert.deepEqual(settled.workerLaunches, []); assert.equal(settled.latestCheckpoint.id, prepared.checkpointId);
  } finally { await disposeFixture(fixture); t.mock.restoreAll(); }
});

test('a joined result-graph publication refusal resumes the same completion without restaging its settlement', async t => {
  let clock = Date.now();
  t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('seal-publication-resume', undefined, { mode: 'accept-edits', tools: ['edit'] });
  try {
    // The existing real SQLite/CAS and FileHandle seam is used here. Its
    // offline containment graph is neither native death nor full-disk proof.
    await batch(fixture, [{ name: 'edit', input: { path: 'a', old_text: 'old', new_text: 'new' } }]);
    const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared);
    const raw = await observation(fixture, claimed, { changed: true });
    const proof = await postEffectObservation(fixture, raw, prepared.checkpointId);
    const input = { opId: prepared.entry.opId, attempt: prepared.entry.attempt,
      expectedRunRevision: prepared.run.revision, observationRef: proof.observationRef };
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const sample = await fs.open(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, proof.observationRef), 'r');
    const prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] };
    const writeFile = prototype.writeFile; await sample.close();
    const failure = Object.assign(new Error('joined completion graph publication refused'), { code: 'ENOSPC' });
    const settlements: BudgetSettlementV1[] = [], payloads: Buffer[] = [];
    let injected = false;
    const writer = t.mock.method(prototype, 'writeFile', async function(this: FileHandle, ...args: unknown[]) {
      await Reflect.apply(writeFile, this, args);
      if (!Buffer.isBuffer(args[0])) return;
      const bytes = args[0], text = bytes.toString('utf8');
      if (!text.includes('"format":"cliq-budget-settlement-v1"') && !text.includes('"format":"cliq-tool-result-payload-v1"')) return;
      const value = JSON.parse(text) as { format?: string; runId?: string; opId?: string };
      if (value.runId !== fixture.runId || value.opId !== prepared.entry.opId) return;
      if (value.format === 'cliq-budget-settlement-v1') settlements.push(value as BudgetSettlementV1);
      if (value.format !== 'cliq-tool-result-payload-v1') return;
      payloads.push(Buffer.from(bytes));
      if (!injected) { injected = true; throw failure; }
    });
    await assert.rejects(fixture.agent.completeTool(input), error => error === failure);
    assert(injected); assert.equal(settlements.length, 1); assert.equal(payloads.length, 1);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    await assert.rejects(fixture.agent.completeTool({ ...input, observationRef: raw }), { code: 'REVISION_CONFLICT' });
    clock += 1_000;
    const completed = await fixture.agent.completeTool(input);
    writer.mock.restore();
    assert.equal(settlements.length, 1, 'the successful settlement publication is not repeated');
    assert.deepEqual(completed.settlement, settlements[0]);
    assert.equal(payloads.length, 2); assert.deepEqual(payloads[1], payloads[0], 'only the same failed artifact is republished');
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(after.run.budgetConsumed.toolCalls, 1); assert.equal(after.run.budgetReserved.toolCalls, 0);
    assert.equal(after.latestCheckpoint.id, prepared.checkpointId); assert.deepEqual(after.workerLaunches, []);
    assert.deepEqual(after.journal.filter(entry => entry.opId === prepared.entry.opId).map(entry => entry.phase),
      ['prepared', 'dispatch_claimed', 'completed']);
    assert.deepEqual(after.journal.slice(0, -1), before.journal);
  } finally { t.mock.restoreAll(); await disposeFixture(fixture); }
});
