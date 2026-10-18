// Real StateStore/SQLite/CAS and the existing offline model/seal fixture.
// Faults cross real FileHandle/SQLite seams; they are not native qualification.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { digestOmitting } from '../kernel/identity.js';
import type { WorkspaceGenerationSnapshotEvidenceV1 } from '../kernel/types.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { isJoinedCasPublicationFailure } from './cas.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture, uuidv7 } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';
import { publishInProcessChannel } from './store.js';
import { openSqliteDriver } from './sqlite-driver.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;
async function finalTurn(fixture: Fixture) {
  const prepared = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
    leaseEpoch: fixture.leaseEpoch });
  await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
    leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'candidate-publication-dispatch' });
  const reader = fixture.agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
  reader.push(Buffer.from(JSON.stringify({ id: 'final-response', object: 'response', status: 'completed', model: 'model-1',
    output: [{ type: 'message', id: 'final-message', role: 'assistant', status: 'completed',
      content: [{ type: 'output_text', text: 'The accounted workspace is ready.', annotations: [] }] }] })));
  return fixture.agent.completeModel({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
    expectedRunRevision: prepared.run.revision, result: reader.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput) });
}

for (const priorDeadline of [false, true]) test(`a final-turn owner survives joined publication failure ${priorDeadline ? 'and a deadline upgraded to cancellation' : 'and cancellation'} without publishing a candidate`, async t => {
  let clock = Date.now(); t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('candidate-publication-stop', { wallTimeMs: 60_000 }, { mode: 'plan' });
  try {
    const completed = await finalTurn(fixture);
    const owner = await fixture.agent.beginFinalCandidate({ expectedRunRevision: completed.run.revision });
    assert(Object.isFrozen(owner));
    if (priorDeadline) clock = Date.parse(completed.run.deadlineAt) - 1000;
    const proof = await quiescedToolCheckpoint(fixture, owner.checkpointId);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const sample = await fs.open(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, proof.workspaceStateRef), 'r');
    const prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] };
    const original = prototype.writeFile; await sample.close();
    const failure = Object.assign(new Error('candidate publication refused after a real temporary write'), { code: 'ENOSPC' });
    let injected = false;
    const writer = t.mock.method(prototype, 'writeFile', async function(this: FileHandle, ...args: unknown[]) {
      await Reflect.apply(original, this, args);
      if (!injected && Buffer.isBuffer(args[0]) && args[0].toString('utf8').includes('"kind":"final_candidate"')) {
        injected = true; throw failure;
      }
    });
    const request = { expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint };
    await assert.rejects(owner.complete(request), error => error === failure);
    assert(injected); assert(isJoinedCasPublicationFailure(failure));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    writer.mock.restore();
    if (priorDeadline) {
      clock = Date.parse(before.run.deadlineAt);
      const expired = await fixture.agent.expireRun({ expectedRunRevision: before.run.revision });
      assert.equal((await fixture.store.artifacts.readCanonical<{ origin: string }>(expired.run.stopIntentRef!)).origin, 'deadline');
    }
    let cancelled = await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(),
      expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    if (priorDeadline) {
      const originalStop = cancelled.run.stopIntentRef;
      assert.equal((await fixture.store.artifacts.readCanonical<{ origin: string }>(originalStop!)).origin, 'user_cancel');
      cancelled = await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(),
        expectedRunRevision: cancelled.run.revision });
      assert.equal(cancelled.run.stopIntentRef, originalStop);
      assert.deepEqual((await fixture.agent.expireRun({ expectedRunRevision: cancelled.run.revision })).run, cancelled.run);
    }
    await assert.rejects(owner.complete(request), { code: 'REVISION_CONFLICT' });
    const sealed = await owner.complete({ ...request, expectedRunRevision: cancelled.run.revision });
    assert.equal(sealed.disposition, 'stopped'); assert.equal(sealed.run.stopIntentRef, cancelled.run.stopIntentRef);
    assert.equal(sealed.run.cancelRequested, true); assert.equal(sealed.run.frontierRef, before.run.frontierRef);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(after.latestCheckpoint.id, owner.checkpointId);
    assert.equal(after.latestCheckpoint.workspaceStateRef, before.latestCheckpoint.workspaceStateRef);
    assert.deepEqual(after.items, before.items); assert.deepEqual(after.journal, before.journal);
    assert.deepEqual(after.workerLaunches, []); assert.equal(after.run.resultRef, undefined);
    assert.deepEqual(await owner.complete({ ...request, expectedRunRevision: cancelled.run.revision }), sealed);
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: sealed.run.revision });
    assert.equal(terminal.run.status, 'cancelled'); assert.equal(terminal.run.resultRef, undefined);
  } finally { await disposeFixture(fixture); }
});

test('expiry during candidate publication persists the real deadline StopIntent before the original owner seals nonproductively', async t => {
  let clock = Date.now(); t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('candidate-publication-deadline', { wallTimeMs: 60_000 }, { mode: 'plan' });
  try {
    const completed = await finalTurn(fixture);
    const owner = await fixture.agent.beginFinalCandidate({ expectedRunRevision: completed.run.revision });
    clock = Date.parse(completed.run.deadlineAt) - 1000;
    const proof = await quiescedToolCheckpoint(fixture, owner.checkpointId);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const sample = await fs.open(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, proof.workspaceStateRef), 'r');
    const prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] };
    const original = prototype.writeFile; await sample.close();
    let crossed = false;
    const writer = t.mock.method(prototype, 'writeFile', async function(this: FileHandle, ...args: unknown[]) {
      await Reflect.apply(original, this, args);
      if (!crossed && Buffer.isBuffer(args[0]) && args[0].toString('utf8').includes('"kind":"final_candidate"')) {
        crossed = true; clock = Date.parse(before.run.deadlineAt);
      }
    });
    const result = await owner.complete({ expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint });
    writer.mock.restore(); assert(crossed);
    assert.equal(result.disposition, 'stopped'); assert(result.run.stopIntentRef);
    const intent = await fixture.store.artifacts.readCanonical<{ origin: string }>(result.run.stopIntentRef!);
    assert.equal(intent.origin, 'deadline'); assert.equal(result.run.cancelRequested, false);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(after.items, before.items); assert.deepEqual(after.journal, before.journal);
    assert.equal(after.latestCheckpoint.id, owner.checkpointId);
    assert.equal(after.latestCheckpoint.workspaceStateRef, before.latestCheckpoint.workspaceStateRef);
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: result.run.revision });
    assert.equal(terminal.run.status, 'failed'); assert.equal(terminal.run.terminalReason, 'budget_exhausted');
    assert.equal(terminal.run.resultRef, undefined);
  } finally { await disposeFixture(fixture); }
});

test('a rolled-back final checkpoint preserves its original candidate bytes, rejects proof substitution and commits once', async t => {
  const fixture = await createAgentFixture('candidate-publication-sql', undefined, { mode: 'plan' });
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const completed = await finalTurn(fixture);
    await assert.rejects(fixture.agent.beginFinalCandidate({ expectedRunRevision: completed.run.revision - 1 }), { code: 'REVISION_CONFLICT' });
    const owner = await fixture.agent.beginFinalCandidate({ expectedRunRevision: completed.run.revision });
    const proof = await quiescedToolCheckpoint(fixture, owner.checkpointId);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const sample = await fs.open(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, proof.workspaceStateRef), 'r');
    const prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] };
    const original = prototype.writeFile; await sample.close();
    const writes: Buffer[] = [];
    const writer = t.mock.method(prototype, 'writeFile', async function(this: FileHandle, ...args: unknown[]) {
      await Reflect.apply(original, this, args);
      if (Buffer.isBuffer(args[0]) && args[0].toString('utf8').includes('"kind":"final_candidate"')) writes.push(Buffer.from(args[0]));
    });
    fault.exec("CREATE TRIGGER fail_candidate_checkpoint BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT, 'injected final checkpoint rollback'); END");
    const request = { expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint };
    await assert.rejects(owner.complete(request), /injected final checkpoint rollback/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    assert.equal(writes.length, 1);
    fault.exec('DROP TRIGGER fail_candidate_checkpoint');
    const changed: WorkspaceGenerationSnapshotEvidenceV1 = { ...proof.snapshot, checkpointId: 'different-final-checkpoint', evidenceDigest: '' };
    changed.evidenceDigest = digestOmitting(changed, 'evidenceDigest');
    const replacement = await fixture.store.artifacts.publishCanonical(changed, changed.format);
    await assert.rejects(owner.complete({ ...request, checkpoint: { ...proof.checkpoint, snapshotEvidenceRef: replacement.ref } }),
      { code: 'REVISION_CONFLICT' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    const [result, duplicate] = await Promise.all([owner.complete(request), owner.complete(request)]);
    assert.deepEqual(duplicate, result); assert.equal(result.disposition, 'candidate');
    writer.mock.restore(); assert.equal(writes.length, 1, 'a native SQL rollback cannot rebuild already published candidate bytes');
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(after.items.length, before.items.length + 1); assert.deepEqual(after.journal, before.journal);
    assert.equal(after.latestCheckpoint.id, owner.checkpointId);
    assert.deepEqual(await owner.complete(request), result);
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('a stopped final-turn owner cannot seal unaccounted workspace changes and a cold stopped caller cannot begin one', async () => {
  const fixture = await createAgentFixture('candidate-publication-unaccounted', undefined, { mode: 'plan' });
  try {
    const completed = await finalTurn(fixture);
    const owner = await fixture.agent.beginFinalCandidate({ expectedRunRevision: completed.run.revision });
    const proof = await quiescedToolCheckpoint(fixture, owner.checkpointId, true);
    const stopped = await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(),
      expectedRunRevision: completed.run.revision });
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(owner.complete({ expectedRunRevision: stopped.run.revision, checkpoint: proof.checkpoint }),
      { code: 'STATE_TRANSITION_INVALID' });
    const cold = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed.releaseKeys });
    await assert.rejects(cold.beginFinalCandidate({ expectedRunRevision: stopped.run.revision }), { code: 'STATE_TRANSITION_INVALID' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('an unclassified publication failure cannot gain persistence retry permission from a later cancellation', async t => {
  const fixture = await createAgentFixture('candidate-publication-unclassified', undefined, { mode: 'plan' });
  try {
    const completed = await finalTurn(fixture);
    const owner = await fixture.agent.beginFinalCandidate({ expectedRunRevision: completed.run.revision });
    const proof = await quiescedToolCheckpoint(fixture, owner.checkpointId);
    const sample = await fs.open(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, proof.workspaceStateRef), 'r');
    const prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] };
    const original = prototype.writeFile; await sample.close();
    const failure = Object.assign(new Error('candidate write EIO has no joined ENOSPC retry classification'), { code: 'EIO' });
    let injected = false;
    const writer = t.mock.method(prototype, 'writeFile', async function(this: FileHandle, ...args: unknown[]) {
      await Reflect.apply(original, this, args);
      if (!injected && Buffer.isBuffer(args[0]) && args[0].toString('utf8').includes('"kind":"final_candidate"')) {
        injected = true; throw failure;
      }
    });
    await assert.rejects(owner.complete({ expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint }), error => error === failure);
    writer.mock.restore(); assert(injected); assert.equal(isJoinedCasPublicationFailure(failure), false);
    const cancelled = await fixture.agent.cancelRun({ ...await publishInProcessChannel(fixture.store), requestId: uuidv7(),
      expectedRunRevision: completed.run.revision });
    const stopped = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(owner.complete({ expectedRunRevision: cancelled.run.revision, checkpoint: proof.checkpoint }), error => error === failure);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), stopped);
  } finally { await disposeFixture(fixture); }
});
