// Pure budget projections. No SQL allocation, Run, clock, grant or native
// authority is created and these values cannot authorize child admission.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { planChildBudgetAllocation } from './child-budget.js';

function frame() {
  return { parent: { budgets: { wallTimeMs: 60000, modelTokens: 300, costMicros: 40, toolCalls: 10,
    repairAttempts: 2, childDepth: 2, childConcurrency: 4 }, consumed: { modelTokens: 20, costMicros: 2, toolCalls: 1, repairAttempts: 0 },
    reserved: { modelTokens: 180, costMicros: 28, toolCalls: 3, repairAttempts: 1 }, deadlineAt: '2026-10-27T00:00:30.000Z' },
    requestedBudgets: { wallTimeMs: 60000, modelTokens: 90, costMicros: 8, toolCalls: 3, repairAttempts: 1,
      childDepth: 8, childConcurrency: 64 }, createdAt: '2026-10-27T00:00:00.000Z', nonterminalDirectChildren: 2,
    continuationFloor: { modelTokens: 10, costMicros: 2, toolCalls: 2, repairAttempts: 0 } };
}

test('child proposal retains exact requested additive ceilings and a shared parent continuation floor without double-reserving ancestors', () => {
  const input = frame(), before = JSON.stringify(input), result = planChildBudgetAllocation(input);
  assert.equal(result.kind, 'available'); if (result.kind !== 'available') throw new Error('expected bounded data proposal');
  assert.deepEqual(result.grantedAdditiveCeilings, { modelTokens: 90, costMicros: 8, toolCalls: 3, repairAttempts: 1 });
  assert.deepEqual(result.grantedBudgets, { ...result.grantedAdditiveCeilings, wallTimeMs: 30000, childDepth: 1, childConcurrency: 4 });
  assert.equal(result.childDeadlineAt, input.parent.deadlineAt);
  assert.deepEqual(result.localAdmissionCost, { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 });
  assert.equal(JSON.stringify(input), before); assert(Object.isFrozen(result) && Object.isFrozen(result.grantedBudgets));
  const leaf = frame(); leaf.requestedBudgets.childDepth = 0; leaf.requestedBudgets.wallTimeMs = 1000;
  const smaller = planChildBudgetAllocation(leaf); assert.equal(smaller.kind, 'available');
  if (smaller.kind === 'available') { assert.equal(smaller.grantedBudgets.childDepth, 0); assert.equal(smaller.childDeadlineAt, '2026-10-27T00:00:01.000Z'); }
});

test('the exact continuation boundary admits once and one missing unit refuses without silently shrinking an explicit child ceiling', () => {
  for (const field of ['modelTokens', 'costMicros', 'toolCalls', 'repairAttempts'] as const) {
    const input = frame();
    assert.equal(planChildBudgetAllocation(input).kind, 'available');
    input.requestedBudgets[field]++;
    assert.deepEqual(planChildBudgetAllocation(input), { kind: 'refused', reason: field });
  }
});

test('exhausted depth, concurrency, deadline and conservatively held capacity cannot allocate or refund', () => {
  for (const [reason, mutate] of [
    ['depth', (input: ReturnType<typeof frame>) => { input.parent.budgets.childDepth = 0; }],
    ['concurrency', (input: ReturnType<typeof frame>) => { input.nonterminalDirectChildren = 4; }],
    ['deadline', (input: ReturnType<typeof frame>) => { input.createdAt = '2026-10-27T00:00:29.001Z'; }],
    ['modelTokens', (input: ReturnType<typeof frame>) => { input.parent.reserved.modelTokens = 280; }],
    ['costMicros', (input: ReturnType<typeof frame>) => { input.parent.reserved.costMicros = 38; }],
    ['toolCalls', (input: ReturnType<typeof frame>) => { input.parent.reserved.toolCalls = 8; }],
  ] as const) {
    const input = frame(); mutate(input); assert.deepEqual(planChildBudgetAllocation(input), { kind: 'refused', reason });
  }
  const invalid = frame(); invalid.parent.reserved.modelTokens = Number.MAX_SAFE_INTEGER;
  assert.throws(() => planChildBudgetAllocation(invalid), /parent retained budget/u);
});

test('child projection retains all original ordinary-Run bounds and rejects hostile data without invoking it', () => {
  for (const mutate of [
    (input: ReturnType<typeof frame>) => { input.requestedBudgets.childConcurrency = 65; },
    (input: ReturnType<typeof frame>) => { input.requestedBudgets.wallTimeMs = 999; },
    (input: ReturnType<typeof frame>) => { input.requestedBudgets.costMicros = 0; },
    (input: ReturnType<typeof frame>) => { input.requestedBudgets.modelTokens = Number.POSITIVE_INFINITY; },
  ]) { const input = frame(); mutate(input); assert.throws(() => planChildBudgetAllocation(input)); }
  let calls = 0;
  const getter = frame(); Object.defineProperty(getter.parent, 'reserved', { enumerable: true, get() { calls++; return {}; } });
  assert.throws(() => planChildBudgetAllocation(getter)); assert.equal(calls, 0);
  const proxy = new Proxy(frame(), { getPrototypeOf() { calls++; return Object.prototype; }, ownKeys() { calls++; return []; } });
  assert.throws(() => planChildBudgetAllocation(proxy)); assert.equal(calls, 0);
  assert.throws(() => planChildBudgetAllocation({ ...frame(), refundUnknown: true }));
});
