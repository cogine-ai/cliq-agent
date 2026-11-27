// Retained JSON data only. These fixtures create no Run, StateOwner,
// allocation row, grant, result authority or native process/death evidence.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { ChildAllocationV1 } from '../kernel/types.js';
import { childAllocationBudgetFacts, decodeChildAllocation } from './invariants.js';

const granted = { modelTokens: 100, costMicros: 20, toolCalls: 10, repairAttempts: 2 };
const used = { modelTokens: 60, costMicros: 8, toolCalls: 4, repairAttempts: 1 };
function allocation(): Extract<ChildAllocationV1, { state: 'child_terminal' }> {
  return { schemaVersion: 1, parentRunId: 'parent', childRunId: 'child', admissionKey: 'admission', delegateBatchItemId: 'batch',
    delegateCallId: 'call', delegateCallIndex: 0, delegateOpId: 'delegate', delegateOperationGrantRef: 'a'.repeat(64),
    capabilityGrantRef: 'b'.repeat(64), mode: 'mutating', grantedAdditiveCeilings: { ...granted },
    grantedChildDepth: 1, grantedChildConcurrency: 2, childDeadlineAt: '2026-10-27T00:01:00.000Z', createdAt: '2026-10-27T00:00:00.000Z',
    state: 'child_terminal', terminal: { mode: 'mutating', status: 'completed_unverified', resultRef: 'c'.repeat(64),
      patchManifestRef: 'd'.repeat(64), modelContentRef: 'e'.repeat(64), modelContentDigest: 'f'.repeat(64) },
    inclusiveBudgetUsage: { ...used }, terminalAt: '2026-10-27T00:00:40.000Z' };
}

test('retained child data preserves conservative inclusive usage and the exact one-time unused difference', () => {
  const terminal = allocation(); assert.equal(decodeChildAllocation(terminal), terminal);
  const settled = { ...terminal, state: 'settled' as const, childResultItemId: 'child-result', parentSettlementRevision: 4,
    releasedUnusedBudget: { modelTokens: 40, costMicros: 12, toolCalls: 6, repairAttempts: 1 }, settledAt: '2026-10-27T00:00:41.000Z' };
  assert.equal(decodeChildAllocation(settled), settled);
  for (const field of ['modelTokens', 'costMicros', 'toolCalls', 'repairAttempts'] as const) {
    assert.throws(() => decodeChildAllocation({ ...terminal, inclusiveBudgetUsage: { ...used, [field]: granted[field] + 1 } }));
    assert.throws(() => decodeChildAllocation({ ...settled, releasedUnusedBudget: { ...settled.releasedUnusedBudget,
      [field]: settled.releasedUnusedBudget[field] + 1 } }));
  }
  // The data decoder must not turn a pessimistically charged unknown into a
  // refund: exactly full usage has precisely zero unused capacity.
  assert.doesNotThrow(() => decodeChildAllocation({ ...settled, inclusiveBudgetUsage: { ...granted },
    releasedUnusedBudget: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 } }));
});

test('retained child terminal/settlement timestamps cannot precede the original allocation', () => {
  const terminal = allocation();
  assert.throws(() => decodeChildAllocation({ ...terminal, childDeadlineAt: terminal.createdAt }));
  assert.throws(() => decodeChildAllocation({ ...terminal, terminalAt: '2026-10-26T23:59:59.999Z' }));
  assert.throws(() => decodeChildAllocation({ ...terminal, state: 'settled', childResultItemId: 'child-result', parentSettlementRevision: 4,
    releasedUnusedBudget: { modelTokens: 40, costMicros: 12, toolCalls: 6, repairAttempts: 1 }, settledAt: terminal.createdAt }));
  // Cleanup after the absolute deadline is real terminal work, not an expiry
  // extension or permission to run. Its genuine history is checked separately.
  assert.doesNotThrow(() => decodeChildAllocation({ ...terminal, terminalAt: '2026-10-27T00:01:01.000Z' }));
});

test('retained child data cannot execute accessors or proxy traps while being refused', () => {
  let traps = 0;
  const accessor = { ...allocation() };
  Object.defineProperty(accessor, 'inclusiveBudgetUsage', { enumerable: true, get() { traps++; return used; } });
  assert.throws(() => decodeChildAllocation(accessor)); assert.equal(traps, 0);
  const proxy = new Proxy(allocation(), { get() { traps++; return undefined; }, getPrototypeOf() { traps++; return Object.prototype; },
    ownKeys() { traps++; return []; }, getOwnPropertyDescriptor() { traps++; return undefined; } });
  assert.throws(() => decodeChildAllocation(proxy)); assert.equal(traps, 0);
});

test('inclusive budget equations include only direct outgoing allocations and keep terminal usage reserved until settlement', () => {
  const outgoing = allocation();
  const incoming = { ...allocation(), parentRunId: 'root', childRunId: 'parent' };
  assert.deepEqual(childAllocationBudgetFacts('parent', [incoming, outgoing]), {
    reserved: granted, consumed: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, nonterminalDirectChildren: 0 });
  const settled = { ...outgoing, state: 'settled' as const, childResultItemId: 'child-result', parentSettlementRevision: 4,
    releasedUnusedBudget: { modelTokens: 40, costMicros: 12, toolCalls: 6, repairAttempts: 1 }, settledAt: '2026-10-27T00:00:41.000Z' };
  const { terminal: _terminal, terminalAt: _at, inclusiveBudgetUsage: _usage, ...origin } = outgoing;
  const reserved = { ...origin, state: 'reserved' as const, childRunId: 'other-child' };
  assert.deepEqual(childAllocationBudgetFacts('parent', [incoming, settled, reserved]), {
    reserved: granted, consumed: used, nonterminalDirectChildren: 1 });
  assert.throws(() => childAllocationBudgetFacts('parent', [outgoing, outgoing]));
  assert.throws(() => childAllocationBudgetFacts('parent', [incoming, incoming]));
  assert.throws(() => childAllocationBudgetFacts('foreign', [outgoing]));
});
