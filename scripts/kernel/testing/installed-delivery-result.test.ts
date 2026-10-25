// Pure retained-data assertions, not StateOwner, signed installation, native
// observation or permission. The Linux campaign supplies actual public cuts.
import assert from 'node:assert/strict';
import test from 'node:test';
import { assertInstalledDeliveryClaims, assertInstalledDeliveryOutcome, assertInstalledDeliverySettlement, assertInstalledDeliveryUnknownSettlement, assertInstalledDeliveryVerifier, InstalledDeliveryOutcomeError } from './installed-delivery-result.js';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting } from '../../../src/kernel/identity.js';

const zero = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
function cut() {
  const common = { runId: 'delivery-data', opId: 'path-data', opKind: 'publish', attempt: 0, leaseEpoch: 1,
    target: 'b'.repeat(64), requestRef: 'c'.repeat(64), grantRef: 'd'.repeat(64), replayClass: 'reconcile' };
  const claim = { ...common, seq: 2, phase: 'dispatch_claimed', budgetDelta: zero,
    dispatchId: 'data-dispatch', supervisorInstanceId: 'data-supervisor', stateOwnerEpoch: 1 };
  return { snapshot: { run: { id: common.runId, budgetConsumed: { ...zero, toolCalls: 1 }, budgetReserved: zero } },
    journal: [{ ...common, seq: 1, phase: 'prepared', budgetDelta: { ...zero, toolCalls: 1 } },
      claim,
      { ...claim, seq: 3, phase: 'completed', budgetDelta: { ...zero, toolCalls: 1 }, budgetSettlementRef: 'a'.repeat(64) }] };
}

function settlement(phase: 'completed' | 'failed' = 'completed') {
  const selected = cut(), prepared = selected.journal[0]!, terminal = { ...selected.journal[2]!, phase,
    timestamp: '2026-10-18T00:00:00.002Z', budgetSettlementRef: '' };
  const value = { schemaVersion: 1, format: 'cliq-budget-settlement-v1', runId: prepared.runId, opId: prepared.opId,
    attempt: prepared.attempt, preparedJournalSeq: prepared.seq, terminalJournalSeq: terminal.seq, terminalPhase: terminal.phase,
    reserved: { ...zero, toolCalls: 1 }, consumed: { ...zero, toolCalls: 1 }, released: { ...zero, toolCalls: 1 },
    budgetConsumedBefore: { ...zero }, budgetConsumedAfter: { ...zero, toolCalls: 1 },
    budgetReservedBefore: { ...zero, toolCalls: 1 }, budgetReservedAfter: { ...zero }, settledAt: terminal.timestamp, settlementDigest: '' };
  value.settlementDigest = digestOmitting(value, 'settlementDigest'); terminal.budgetSettlementRef = canonicalSha256(value);
  return { prepared, claim: selected.journal[1]!, terminal, value };
}

test('real completed and claimed-cancel settlement data release the entire original reservation while charging once', () => {
  for (const phase of ['completed', 'failed'] as const) {
    const data = settlement(phase);
    assert.deepEqual(assertInstalledDeliverySettlement(data.prepared, data.claim, data.terminal, data.value, 0), data.value);
  }
  const mutations: Array<(data: ReturnType<typeof settlement>) => void> = [
    data => { data.prepared.budgetDelta.toolCalls = 0; },
    data => { data.value.reserved.toolCalls = 2; data.value.released.toolCalls = 2; data.value.budgetReservedBefore.toolCalls = 2; },
    data => { data.value.released.toolCalls = 0; data.value.budgetReservedAfter.toolCalls = 1; },
    data => { data.value.consumed.toolCalls = 0; data.value.budgetConsumedAfter.toolCalls = 0; },
    data => { data.value.preparedJournalSeq = 2; },
    data => { data.value.terminalJournalSeq = 4; },
    data => { data.value.opId = 'another-original-operation'; },
    data => { data.value.attempt = 1; },
    data => { data.claim.opId = 'another-claim'; },
    data => { data.value.budgetConsumedBefore.toolCalls = 1; data.value.budgetConsumedAfter.toolCalls = 2; },
    data => { data.terminal.budgetDelta.toolCalls = 0; },
  ];
  for (const phase of ['completed', 'failed'] as const) for (const mutate of mutations) {
    const data = settlement(phase); mutate(data);
    data.value.settlementDigest = digestOmitting(data.value, 'settlementDigest');
    data.terminal.budgetSettlementRef = canonicalSha256(data.value);
    assert.throws(() => assertInstalledDeliverySettlement(data.prepared, data.claim, data.terminal, data.value, 0));
  }
});

test('parent-domain UNKNOWN retains its original full charge without becoming a known child result', () => {
  const make = () => {
    const data = settlement('failed');
    data.prepared.opKind = data.claim.opKind = data.terminal.opKind = 'verifier';
    data.prepared.replayClass = data.claim.replayClass = data.terminal.replayClass = 'retry';
    const terminal = { ...data.terminal, phase: 'unknown' };
    const value = { ...data.value, terminalPhase: 'unknown' };
    value.settlementDigest = digestOmitting(value, 'settlementDigest'); terminal.budgetSettlementRef = canonicalSha256(value);
    return { ...data, terminal, value };
  };
  const data = make();
  assert.deepEqual(assertInstalledDeliveryUnknownSettlement(data.prepared, data.claim, data.terminal, data.value), data.value);
  assert.throws(() => assertInstalledDeliverySettlement(data.prepared, data.claim, data.terminal, data.value, 0));
  const mutations: Array<(data: ReturnType<typeof make>) => void> = [
    data => { data.terminal.phase = 'failed'; },
    data => { data.terminal.opKind = 'publish'; },
    data => { data.value.consumed.toolCalls = 0; data.value.budgetConsumedAfter.toolCalls = 0; },
    data => { data.value.released.toolCalls = 0; },
    data => { data.value.terminalJournalSeq++; },
    data => { data.claim.opId = 'other-original-claim'; },
  ];
  for (const mutate of mutations) {
    const value = make(); mutate(value);
    value.value.settlementDigest = digestOmitting(value.value, 'settlementDigest'); value.terminal.budgetSettlementRef = canonicalSha256(value.value);
    assert.throws(() => assertInstalledDeliveryUnknownSettlement(value.prepared, value.claim, value.terminal, value.value));
  }
});
test('Delivery assertions require one original complete claim and settlement, never model/tool execution', () => {
  assert.deepEqual(assertInstalledDeliveryClaims(cut(), { publish: 1, verifier: 0 }), { publishClaims: 1, verifierClaims: 0, settlementCount: 1 });
  const mutations: Array<(value: ReturnType<typeof cut>) => void> = [
    value => { value.journal[0]!.budgetDelta = { ...zero }; },
    value => { value.journal[1]!.opKind = 'model'; },
    value => { value.journal.push({ ...value.journal[1]!, seq: 4 }); },
    value => { value.journal.splice(1, 1); },
    value => { value.journal[2]!.phase = 'unknown'; },
    value => { value.snapshot.run.budgetConsumed.toolCalls = 2; },
  ];
  for (const mutate of mutations) {
    const value = cut(); mutate(value);
    assert.throws(() => assertInstalledDeliveryClaims(value, { publish: 1, verifier: 0 }));
  }
  assert.throws(() => assertInstalledDeliveryClaims(cut(), { publish: 0, verifier: 0 }));
  const noOp = cut(); noOp.journal = []; noOp.snapshot.run.budgetConsumed.toolCalls = 0;
  assert.deepEqual(assertInstalledDeliveryClaims(noOp, { publish: 0, verifier: 0 }), { publishClaims: 0, verifierClaims: 0, settlementCount: 0 });
  const duplicate = cut(); duplicate.snapshot.run.budgetConsumed.toolCalls = 2;
  duplicate.journal.push(...duplicate.journal.map(row => ({ ...row, opId: 'other-data', seq: row.seq + 3 })));
  assert.throws(() => assertInstalledDeliveryClaims(duplicate, { publish: 2, verifier: 0 }), 'two attempts cannot share one settlement');
});

test('invalid source/cut stops before artifact I/O and exposes only a fixed diagnostic stage', async () => {
  let reads = 0;
  for (const value of [{}, { method: 'run.get', snapshot: { schemaVersion: 1, operation: 'agent', run: {} } }]) {
    await assert.rejects(assertInstalledDeliveryOutcome({ cut: value, sessionCut: {}, sourceCut: {}, sourceResultRef: 'a'.repeat(64),
      expectedFiles: [], kind: 'publish', readRetainedArtifact: async () => { reads++; throw new Error('private-untrusted-detail'); },
      readOwnerHistory: async () => { reads++; throw new Error('private-owner-detail'); } }),
    error => error instanceof InstalledDeliveryOutcomeError && error.diagnosticStage === 'public_cut' &&
      !String(error).includes('private-untrusted-detail'));
  }
  assert.equal(reads, 0);
});

test('new Delivery verifier refuses foreign/unexecuted cuts without creating retained or process evidence', async () => {
  let reads = 0;
  for (const outcome of ['passed', 'stopped'] as const) for (const cut of [{},
    { method: 'run.get', snapshot: { operation: 'agent', run: {} } }]) {
    await assert.rejects(assertInstalledDeliveryVerifier({ cut, sourceCut: {}, outcome,
      readRetainedArtifact: async () => { reads++; throw new Error('untrusted-output'); },
      readOwnerHistory: async () => { reads++; throw new Error('untrusted-owner'); } }),
    error => error instanceof InstalledDeliveryOutcomeError && error.diagnosticStage === 'verification' &&
      !String(error).includes('untrusted-output'));
  }
  assert.equal(reads, 0);
});

test('a retained-input refusal reports its fixed verification phase without inspecting private errors', async () => {
  let reads = 0, detailReads = 0;
  const privateFailure = Object.defineProperties(new Error(), Object.fromEntries(['message', 'stack', 'cause'].map(key =>
    [key, { get() { detailReads++; throw new Error('private diagnostic data must not be read'); } }])));
  // Protocol data reaches only the first retained read. It creates no Run,
  // StateOwner, native identity, grant or positive retirement evidence.
  await assert.rejects(assertInstalledDeliveryVerifier({ outcome: 'stopped',
    cut: { method: 'run.get', snapshot: { operation: 'delivery', run: { specRef: 'a'.repeat(64) } },
      nextItemSeq: 0, highWaterItemSeq: 0, items: [], nextJournalSeq: 0, highWaterJournalSeq: 0, journal: [],
      nextCheckpointCursor: 0, highWaterCheckpointCursor: 0 },
    sourceCut: { snapshot: { operation: 'agent', run: { status: 'succeeded', specRef: 'b'.repeat(64) } } },
    readRetainedArtifact: async () => { reads++; throw privateFailure; },
    readOwnerHistory: async () => { throw new Error('owner history must not be reached'); } }),
  error => error instanceof InstalledDeliveryOutcomeError && error.diagnosticStage === 'verification_inputs');
  assert.equal(reads, 1); assert.equal(detailReads, 0);
});
