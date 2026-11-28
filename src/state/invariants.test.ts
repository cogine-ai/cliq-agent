import assert from 'node:assert/strict';
import test from 'node:test';
import { KernelStorageError } from './errors.js';
import { addBudget, assertBudgetWithin, decodeBudgetUsage, isZeroBudget, subtractBudget } from './invariants.js';

const zero = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };

test('isZeroBudget requires every budget field to be zero', () => {
  assert.equal(isZeroBudget(zero), true);
  assert.equal(isZeroBudget({ ...zero, toolCalls: 1 }), false);
  assert.equal(isZeroBudget({ ...zero, modelTokens: -0 }), true);
});

test('decodeBudgetUsage rejects unknown fields and non-safe integers', () => {
  assert.deepEqual(decodeBudgetUsage({ ...zero, toolCalls: 2 }), { ...zero, toolCalls: 2 });
  for (const bad of [{ extra: 1 }, { toolCalls: 1.5 }, { toolCalls: -1 }, { costMicros: null }]) {
    assert.throws(() => decodeBudgetUsage({ ...zero, ...bad }), KernelStorageError);
  }
});

test('addBudget and subtractBudget enforce safe non-negative totals', () => {
  const left = { modelTokens: 10, costMicros: 5, toolCalls: 2, repairAttempts: 1 };
  const right = { modelTokens: 2, costMicros: 1, toolCalls: 1, repairAttempts: 0 };
  assert.deepEqual(addBudget(left, right), { modelTokens: 12, costMicros: 6, toolCalls: 3, repairAttempts: 1 });
  assert.deepEqual(subtractBudget(left, right), { modelTokens: 8, costMicros: 4, toolCalls: 1, repairAttempts: 1 });
  assert.throws(() => subtractBudget(right, left), KernelStorageError);
  assert.throws(() => addBudget(left, { ...right, modelTokens: Number.MAX_SAFE_INTEGER }), KernelStorageError);
});

test('assertBudgetWithin throws BUDGET_EXHAUSTED when reservation would exceed ceiling', () => {
  const consumed = { modelTokens: 5, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  const reserved = { modelTokens: 3, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  const required = { modelTokens: 2, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  const ceilings = { modelTokens: 10, costMicros: 0, toolCalls: 1, repairAttempts: 0 };
  assertBudgetWithin(consumed, reserved, required, ceilings);
  assert.throws(() => assertBudgetWithin(consumed, reserved, { ...required, modelTokens: 3 }, ceilings),
    (error: unknown) => error instanceof KernelStorageError && error.code === 'BUDGET_EXHAUSTED');
});