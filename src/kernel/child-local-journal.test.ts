// Inert local-operation data only. These fixtures create no SQL claim,
// signed Supervisor, child allocation, Run, worker lease or death evidence.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeWireJournal } from './control-wire-data.js';

const ref = 'a'.repeat(64), zero = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
function row(phase: 'prepared' | 'dispatch_claimed' | 'completed' = 'prepared') {
  return { seq: phase === 'prepared' ? 1 : phase === 'dispatch_claimed' ? 2 : 3, runId: 'parent', opId: 'stable-local-op',
    opKind: 'child_admission', attempt: 0, leaseEpoch: 0, phase, target: ref, requestRef: ref,
    replayClass: 'retry', idempotencyKey: 'one-stable-admission', grantRef: ref,
    budgetDelta: { ...zero, toolCalls: phase === 'dispatch_claimed' ? 0 : 1 }, timestamp: '2026-10-27T00:00:00.000Z',
    localCommittedAt: '2026-10-27T00:00:00.001Z',
    ...(phase === 'prepared' ? {} : { dispatchId: 'local-transaction-claim', supervisorInstanceId: 'original-supervisor', stateOwnerEpoch: 1 }),
    ...(phase === 'completed' ? { resultRef: ref, budgetSettlementRef: ref } : {}) };
}

test('closed grant-bearing local Journal uses zero to denote no worker lease, and never accepts a physical release or unknown branch', () => {
  for (const opKind of ['child_admission', 'child_merge', 'skill_resource']) for (const phase of ['prepared', 'dispatch_claimed', 'completed'] as const) {
    const value = { ...row(phase), opKind }; assert.equal(decodeWireJournal(value), value);
    for (const key of ['sandboxLaunchSpecRef', 'brokerFenceTokenDigest', 'receiptRef', 'errorRef', 'evidenceRef', 'evidenceDigest', 'attestationRef'])
      assert.throws(() => decodeWireJournal({ ...value, [key]: ref }));
    assert.throws(() => decodeWireJournal({ ...value, attempt: 1 }));
    assert.throws(() => decodeWireJournal({ ...value, leaseEpoch: 1 }));
    assert.throws(() => decodeWireJournal({ ...value, budgetDelta: { ...value.budgetDelta, modelTokens: 1 } }));
    assert.throws(() => decodeWireJournal({ ...value, localCommittedAt: '2026-10-26T23:59:59.999Z' }));
  }
  for (const phase of ['failed', 'unknown', 'abandoned']) assert.throws(() => decodeWireJournal({ ...row('completed'), phase }));
  assert.throws(() => decodeWireJournal({ ...row(), localCommittedAt: undefined }));
  assert.throws(() => decodeWireJournal({ ...row(), idempotencyKey: undefined }));
  assert.throws(() => decodeWireJournal({ ...row(), target: 'not-a-CAS-reference' }));
});

test('existing physical Journal cannot borrow local zero lease or the local commit field', () => {
  for (const opKind of ['model', 'tool', 'mcp-server', 'mcp', 'verifier', 'publish']) {
    assert.throws(() => decodeWireJournal({ ...row(), opKind }));
    assert.throws(() => decodeWireJournal({ ...row(), opKind, leaseEpoch: 1 }));
    const { localCommittedAt: _local, ...original } = row();
    assert.doesNotThrow(() => decodeWireJournal({ ...original, opKind, leaseEpoch: 1 }));
  }
});

test('local Journal data rejects hostile observations without executing getters or proxy traps', () => {
  let traps = 0;
  const value = row(); Object.defineProperty(value, 'opKind', { enumerable: true, get() { traps++; return 'child_admission'; } });
  assert.throws(() => decodeWireJournal(value)); assert.equal(traps, 0);
  const proxy = new Proxy(row(), { get() { traps++; return undefined; }, getPrototypeOf() { traps++; return Object.prototype; } });
  assert.throws(() => decodeWireJournal(proxy)); assert.equal(traps, 0);
});
