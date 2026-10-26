import { assertControlWireJson, BUDGET_FIELDS, controlWireInteger, controlWireRecord, decodeWireBudget } from './control-wire-data.js';
import { mergeBudgets } from './control-submit.js';
import { addCanonicalDuration, parseCanonicalTime } from './identity.js';
import type { BudgetUsage, RunSpec } from './types.js';

type Budgets = RunSpec['budgets'];
const BUDGET_KEYS = ['wallTimeMs', ...BUDGET_FIELDS, 'childDepth', 'childConcurrency'] as const;
const ADMISSION_COST = Object.freeze({ modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 });
export type ChildBudgetProposal =
  | Readonly<{ kind: 'refused'; reason: 'deadline' | 'depth' | 'concurrency' | 'modelTokens' | 'costMicros' | 'toolCalls' | 'repairAttempts' }>
  | Readonly<{ kind: 'available'; grantedBudgets: Readonly<Budgets>; grantedAdditiveCeilings: Readonly<BudgetUsage>;
      childDeadlineAt: string; localAdmissionCost: Readonly<BudgetUsage> }>;

function budgets(value: unknown): Budgets {
  const fields = controlWireRecord(value, BUDGET_KEYS);
  return mergeBudgets(fields as Budgets);
}

/** Pure composition data only, never an allocation or budget authority. The
 * owning admission transaction must independently reproduce this proposal
 * from its exact parent/Journal/child cut and actual current time. The parent
 * snapshots precede the one local delegate admission; existing reservations
 * already include its other child subtrees and are not reserved again. */
export function planChildBudgetAllocation(value: unknown): ChildBudgetProposal {
  assertControlWireJson(value);
  const input = controlWireRecord(value, ['parent', 'requestedBudgets', 'createdAt', 'nonterminalDirectChildren', 'continuationFloor']);
  const parent = controlWireRecord(input.parent, ['budgets', 'consumed', 'reserved', 'deadlineAt']);
  const ceiling = budgets(parent.budgets), requested = budgets(input.requestedBudgets);
  const consumed = decodeWireBudget(parent.consumed), reserved = decodeWireBudget(parent.reserved);
  const continuationFloor = decodeWireBudget(input.continuationFloor);
  if (typeof input.createdAt !== 'string' || typeof parent.deadlineAt !== 'string') throw new TypeError('child budget times must be canonical text');
  const start = parseCanonicalTime(input.createdAt), deadline = parseCanonicalTime(parent.deadlineAt);
  const count = controlWireInteger(input.nonterminalDirectChildren);
  const available = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  for (const field of BUDGET_FIELDS) {
    if (consumed[field] > ceiling[field] || reserved[field] > ceiling[field] - consumed[field])
      throw new TypeError('parent retained budget exceeds its original ceiling');
    available[field] = ceiling[field] - consumed[field] - reserved[field];
  }
  if (deadline - start < 1000) return Object.freeze({ kind: 'refused', reason: 'deadline' });
  if (ceiling.childDepth === 0) return Object.freeze({ kind: 'refused', reason: 'depth' });
  if (count >= ceiling.childConcurrency) return Object.freeze({ kind: 'refused', reason: 'concurrency' });
  // Preserve the exact requested additive ceilings or refuse. One shared
  // parent continuation floor is a constraint on this original cut, not a
  // second reservation/ledger or a promise that unknown output will fit.
  for (const field of BUDGET_FIELDS) {
    const local = field === 'toolCalls' ? ADMISSION_COST.toolCalls : 0;
    if (continuationFloor[field] > available[field] || local > available[field] - continuationFloor[field] ||
        requested[field] > available[field] - continuationFloor[field] - local)
      return Object.freeze({ kind: 'refused', reason: field });
  }
  const grantedAdditiveCeilings = Object.freeze(Object.fromEntries(BUDGET_FIELDS.map(field => [field, requested[field]])) as BudgetUsage);
  const grantedBudgets = Object.freeze({ ...grantedAdditiveCeilings,
    wallTimeMs: Math.min(requested.wallTimeMs, deadline - start),
    childDepth: Math.min(requested.childDepth, ceiling.childDepth - 1),
    childConcurrency: Math.min(requested.childConcurrency, ceiling.childConcurrency) });
  // Reuse every original bound. No smaller child proposal is permitted to
  // escape the ordinary Run schema as a compatibility or budget exception.
  budgets(grantedBudgets);
  return Object.freeze({ kind: 'available', grantedBudgets, grantedAdditiveCeilings,
    childDeadlineAt: addCanonicalDuration(input.createdAt, grantedBudgets.wallTimeMs), localAdmissionCost: ADMISSION_COST });
}
