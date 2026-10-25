// Inert public-wire data only; no Run, owner, permission or native proof is made.
import assert from 'node:assert/strict';
import test from 'node:test';
import { encodeControlCheckpointCursor } from '../../../src/kernel/control-wire.js';
import { projectInstalledRunProgress } from './installed-run-progress.js';

const ref = 'a'.repeat(64), at = '2026-10-18T00:00:00.000Z';
const zero = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
function input(): any {
  const checkpoint = { id: 'checkpoint-1', schemaVersion: 1, runId: 'run-1', basedOnRunRevision: 2,
    runItemSeq: 2, contextManifestRef: ref, journalSeq: 1, workspaceStateRef: ref, createdAt: at, reason: 'auto' };
  const cursor = encodeControlCheckpointCursor('run-1', { createdAt: at, checkpointId: checkpoint.id });
  return { caseKind: 'required_repair', postCount: 6, cut: { method: 'run.get', snapshot: {
    schemaVersion: 1, operation: 'agent', latestRunItemSeq: 2,
    run: { id: 'run-1', sessionId: 'session-1', specRef: ref, status: 'running', nextStep: 'verify', frontierRef: ref,
      revision: 2, leaseEpoch: 1, activeWorkerLaunchId: 'launch-1', latestCheckpointId: checkpoint.id,
      budgetReserved: zero, budgetConsumed: zero, repairCount: 0, cancelRequested: false, createdAt: at, deadlineAt: at, updatedAt: at } },
    items: [1, 2].map(itemSeq => ({ schemaVersion: 1, itemId: `item-${itemSeq}`, itemSeq, payloadRef: ref, payloadDigest: ref, createdAt: at })),
    journal: [{ seq: 1, runId: 'run-1', opId: 'op-1', opKind: 'verifier', attempt: 0, leaseEpoch: 1,
      phase: 'prepared', target: 'node-tests', requestRef: ref, replayClass: 'retry', budgetDelta: zero, timestamp: at }],
    checkpoints: [checkpoint], highWaterItemSeq: 2, highWaterJournalSeq: 1,
    highWaterCheckpointCursor: cursor, nextItemSeq: 2, nextJournalSeq: 1, nextCheckpointCursor: cursor } };
}

test('an actual public run.get cut projects only closed progress counts, not authority or retained content', () => {
  assert.deepEqual(projectInstalledRunProgress(input()), {
    diagnosticOnly: true, source: 'actual_public_run_get', operation: 'agent', caseKind: 'required_repair', postCount: 6,
    status: 'running', nextStep: 'verify', revision: 2, activeWorkerRecorded: true, waitingRecorded: false, waitingReason: null,
    cancelRequested: false, completeCut: true,
    counts: { items: 2, journal: 1, checkpoints: 1, highWaterItemSeq: 2, highWaterJournalSeq: 1, nextItemSeq: 2, nextJournalSeq: 1 },
    phaseCounts: { prepared: 1, dispatch_claimed: 0, completed: 0, failed: 0, unknown: 0, abandoned: 0 },
    lastJournal: { opKind: 'verifier', phase: 'prepared', attempt: 0 },
    recordedElapsed: { latestRunUpdateMs: 0, lastJournalMs: 0 },
  });
});

test('the same named source case cannot be confused with its actual Delivery public cut', () => {
  const source = input(), delivery = input();
  source.caseKind = delivery.caseKind = 'delivery_publish';
  delivery.cut.snapshot.operation = 'delivery';
  assert.equal(projectInstalledRunProgress(source).operation, 'agent');
  assert.equal(projectInstalledRunProgress(delivery).operation, 'delivery');
  for (const operation of ['unknown', ['delivery'], null]) {
    const value = input(); value.cut.snapshot.operation = operation;
    assert.throws(() => projectInstalledRunProgress(value));
  }
});

test('valid item, journal and checkpoint prefixes never claim a complete cut', () => {
  const items = input(); items.cut.items.pop(); items.cut.nextItemSeq = 1;
  const journal = input(); journal.cut.highWaterJournalSeq = 2;
  const checkpoints = input(); checkpoints.cut.checkpoints = []; delete checkpoints.cut.nextCheckpointCursor;
  for (const value of [items, journal, checkpoints]) assert.equal(projectInstalledRunProgress(value).completeCut, false);
  assert.equal(projectInstalledRunProgress(items).counts.items, 1);
  assert.equal(projectInstalledRunProgress(journal).counts.highWaterJournalSeq, 2);
});

test('recorded progress offsets preserve relative completion timing without reading a clock', () => {
  const value = input();
  value.cut.snapshot.run.updatedAt = '2026-10-18T00:01:20.300Z';
  value.cut.snapshot.run.deadlineAt = '2026-10-18T00:05:00.000Z';
  value.cut.journal[0].timestamp = '2026-10-18T00:01:18.000Z';
  const originalNow = Date.now;
  let clockReads = 0;
  try {
    Date.now = () => { clockReads++; throw new Error('a data projection must not read a clock'); };
    assert.deepEqual(projectInstalledRunProgress(value).recordedElapsed,
      { latestRunUpdateMs: 80300, lastJournalMs: 78000 });
  } finally { Date.now = originalNow; }
  assert.equal(clockReads, 0);
});

test('recorded elapsed fields keep an absent journal null and refuse timestamps preceding admission', () => {
  const noJournal = input(); noJournal.cut.journal = [];
  noJournal.cut.highWaterJournalSeq = noJournal.cut.nextJournalSeq = 0;
  assert.deepEqual(projectInstalledRunProgress(noJournal).recordedElapsed, { latestRunUpdateMs: 0, lastJournalMs: null });
  for (const field of ['run', 'journal']) {
    const value = input();
    if (field === 'run') value.cut.snapshot.run.updatedAt = '2026-10-17T23:59:59.999Z';
    else value.cut.journal[0].timestamp = '2026-10-17T23:59:59.999Z';
    assert.throws(() => projectInstalledRunProgress(value));
  }
});

test('counts describe the returned journal, including every closed phase, and never deduplicate operation IDs', () => {
  const value = input(), base = value.cut.journal[0];
  const claim = { ...base, dispatchId: 'dispatch', supervisorInstanceId: 'supervisor', stateOwnerEpoch: 1 };
  value.cut.journal = [base, { ...claim, seq: 2, phase: 'dispatch_claimed' },
    { ...claim, seq: 3, phase: 'completed', resultRef: ref, budgetSettlementRef: ref },
    { ...claim, seq: 4, phase: 'failed', errorRef: ref, budgetSettlementRef: ref },
    { ...claim, seq: 5, phase: 'unknown', evidenceRef: ref, evidenceDigest: ref, budgetSettlementRef: ref },
    { ...claim, seq: 6, phase: 'abandoned', attestationRef: ref, budgetSettlementRef: ref, attempt: 2 }];
  value.cut.highWaterJournalSeq = value.cut.nextJournalSeq = 6;
  const result = projectInstalledRunProgress(value);
  assert.deepEqual(result.phaseCounts, { prepared: 1, dispatch_claimed: 1, completed: 1, failed: 1, unknown: 1, abandoned: 1 });
  assert.deepEqual(result.lastJournal, { opKind: 'verifier', phase: 'abandoned', attempt: 2 });
  assert.equal(result.counts.journal, 6);
  assert.equal(Object.values(result.phaseCounts).reduce((sum, count) => sum + count), 6);
  value.cut.journal = []; value.cut.highWaterJournalSeq = value.cut.nextJournalSeq = 0;
  assert.equal(projectInstalledRunProgress(value).lastJournal, null);
});

test('waiting progress preserves only the actual closed public reason, while nonwaiting progress records null', () => {
  assert.equal(projectInstalledRunProgress(input()).waitingReason, null);
  const queued = input(); queued.cut.snapshot.run.status = 'queued'; delete queued.cut.snapshot.run.activeWorkerLaunchId;
  assert.equal(projectInstalledRunProgress(queued).waitingReason, null);
  for (const waitingReason of ['approval', 'input', 'child', 'reconciliation']) {
    const value = input(); value.cut.snapshot.run.status = 'waiting'; delete value.cut.snapshot.run.activeWorkerLaunchId;
    Object.assign(value.cut.snapshot.run, { waitingReason, waitingOnRef: ref });
    const result = projectInstalledRunProgress(value);
    assert.equal(result.waitingRecorded, true); assert.equal(result.activeWorkerRecorded, false);
    assert.equal(result.waitingReason, waitingReason); assert.equal(Object.hasOwn(result, 'waitingKind'), false);
    value.cut.snapshot.run.waitingReason = 'input';
    assert.equal(result.waitingReason, waitingReason);
  }
  for (const waitingReason of [null, 'unknown', ['input'], {}, 0]) {
    const value = input(); value.cut.snapshot.run.status = 'waiting'; delete value.cut.snapshot.run.activeWorkerLaunchId;
    Object.assign(value.cut.snapshot.run, { waitingReason, waitingOnRef: ref });
    assert.throws(() => projectInstalledRunProgress(value));
  }
  const nonwaiting = input(); Object.assign(nonwaiting.cut.snapshot.run, { waitingReason: 'input', waitingOnRef: ref });
  assert.throws(() => projectInstalledRunProgress(nonwaiting));
  const noJournal = input(); noJournal.cut.journal = []; noJournal.cut.highWaterJournalSeq = noJournal.cut.nextJournalSeq = 0;
  assert.deepEqual(projectInstalledRunProgress(noJournal).phaseCounts,
    { prepared: 0, dispatch_claimed: 0, completed: 0, failed: 0, unknown: 0, abandoned: 0 });
});

test('output is deeply frozen and independent of caller-owned data', () => {
  const value = input(), result = projectInstalledRunProgress(value), original = JSON.stringify(result);
  value.caseKind = 'required_pass'; value.cut.snapshot.run.revision = 99; value.cut.journal[0].phase = 'invalid';
  for (const node of [result, result.counts, result.phaseCounts, result.lastJournal, result.recordedElapsed]) assert(Object.isFrozen(node));
  assert.throws(() => { (result.counts as any).items = 90; }, TypeError);
  assert.throws(() => { (result.recordedElapsed as any).lastJournalMs = 99; }, TypeError);
  assert.equal(JSON.stringify(result), original);
  for (const forbidden of ['run-1', 'session-1', 'launch-1', 'node-tests', ref, at]) assert(!original.includes(forbidden));
});

test('getters, hidden fields, symbols and Proxy traps are refused without invocation', () => {
  let calls = 0;
  const accessor = input(); Object.defineProperty(accessor.cut.snapshot.run, 'revision', { enumerable: true, get() { calls++; return 2; } });
  const hidden = input(); Object.defineProperty(hidden.cut, 'hidden', { value: true });
  const symbol = input(); symbol.cut.items[Symbol('hidden')] = true;
  const proxy = input(); proxy.cut = new Proxy(proxy.cut, { ownKeys() { calls++; throw 0; }, get() { calls++; throw 0; } });
  const toJSON = input(); Object.defineProperty(toJSON.cut, 'toJSON', { enumerable: true, get() { calls++; throw 0; } });
  const arrayProxy = input(); arrayProxy.cut.items = new Proxy([], { get() { calls++; throw 0; } });
  const waitingAccessor = input(); Object.defineProperty(waitingAccessor.cut.snapshot.run, 'waitingReason',
    { enumerable: true, get() { calls++; return 'input'; } });
  const waitingProxy = input(); waitingProxy.cut.snapshot.run.waitingReason = new Proxy({}, { get() { calls++; throw 0; }, ownKeys() { calls++; throw 0; } });
  for (const value of [accessor, hidden, symbol, proxy, toJSON, arrayProxy, waitingAccessor, waitingProxy]) assert.throws(() => projectInstalledRunProgress(value));
  assert.equal(calls, 0);
});

test('a closed case, counters and the production public discriminators are mandatory', () => {
  const changes = [(v: any) => { v.extra = true; }, (v: any) => { v.caseKind = 'arbitrary'; },
    (v: any) => { v.cut.snapshot.run.status = 'success'; }, (v: any) => { v.cut.snapshot.run.nextStep = 'shell'; },
    (v: any) => { v.cut.journal[0].opKind = 'shell'; }, (v: any) => { v.cut.journal[0].phase = 'sent'; },
    (v: any) => { v.cut.snapshot.run.revision = 0; }, (v: any) => { v.cut.journal[0].attempt = -1; },
    (v: any) => { v.cut.snapshot.run.permit = true; }, (v: any) => { v.cut.method = 'run.attach'; }];
  for (const mutate of changes) { const value = input(); mutate(value); assert.throws(() => projectInstalledRunProgress(value)); }
  for (const postCount of [-1, 11, 0.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, '6']) {
    assert.throws(() => projectInstalledRunProgress({ ...input(), postCount }));
  }
  for (const caseKind of ['required_pass', 'required_repair', 'advisory_failure', 'required_timeout', 'ordinary_git', 'delivery_publish', 'delivery_merge', 'delivery_cancel', 'delivery_git', 'delivery_git_merge']) {
    assert.equal(projectInstalledRunProgress({ ...input(), caseKind, postCount: 10 }).caseKind, caseKind);
  }
});

test('array lookalikes cannot cross the shared Journal decoder as primitive enum values', () => {
  const opKind = input(); opKind.cut.journal[0].opKind = ['verifier'];
  const replayClass = input(); replayClass.cut.journal[0].replayClass = ['retry'];
  // The full valid pre-dispatch failure shape reached the old coercive else
  // branch: an incomplete failure alone would not catch this exact defect.
  const phase = input(); Object.assign(phase.cut.journal[0], {
    phase: ['failed'], errorRef: ref, budgetSettlementRef: ref,
  });
  for (const value of [opKind, replayClass, phase]) assert.throws(() => projectInstalledRunProgress(value));
});

test('suffixes, gaps, foreign Run rows, false counts and invalid checkpoint positions refuse', () => {
  const changes = [(v: any) => { v.cut.items.shift(); }, (v: any) => { v.cut.items[1].itemSeq = 3; },
    (v: any) => { v.cut.nextItemSeq = 1; }, (v: any) => { v.cut.journal[0].seq = 2; v.cut.nextJournalSeq = v.cut.highWaterJournalSeq = 2; },
    (v: any) => { v.cut.journal[0].runId = 'foreign'; }, (v: any) => { v.cut.checkpoints[0].runId = 'foreign'; },
    (v: any) => { v.cut.highWaterJournalSeq = -1; }, (v: any) => { v.cut.nextJournalSeq = 0; },
    (v: any) => { v.cut.highWaterCheckpointCursor = 'invalid'; }, (v: any) => { delete v.cut.nextCheckpointCursor; },
    (v: any) => { v.cut.checkpoints.push({ ...v.cut.checkpoints[0] }); }];
  for (const mutate of changes) { const value = input(); mutate(value); assert.throws(() => projectInstalledRunProgress(value)); }
});

test('non-JSON, sparse, cyclic and over-budget values refuse before producing a partial diagnostic', () => {
  const sparse = input(); delete sparse.cut.items[0];
  const namedArray = input(); namedArray.cut.items.extra = true;
  const cycle = input(); cycle.cut.cycle = cycle;
  const huge = input(); huge.cut.huge = 'x'.repeat(1_048_577);
  const deep = input(); let child = deep.cut; for (let i = 0; i < 33; i++) child = child.deep = {};
  const members = input(); members.cut.extra = Array(10001).fill(null);
  const unusual = input(); Object.setPrototypeOf(unusual.cut, { inherited: true });
  for (const value of [undefined, null, () => 0, sparse, namedArray, cycle, huge, deep, members, unusual]) {
    assert.throws(() => projectInstalledRunProgress(value));
  }
});
