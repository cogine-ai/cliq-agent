import type { RecoveryClosureV1 } from '../kernel/types.js';

/** An authority-reducing data invariant, never admission, permission, native
 * quiescence or publication proof. Real closure readers validate those graphs. */
export function assertDeliveryModelFreeCut(cut: Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'journal' | 'childAllocations'>): void {
  const { run, runSpec: spec } = cut;
  if (spec.operation !== 'delivery' || spec.credentialGrantRefs.length || run.parentRunId !== undefined || run.repairCount !== 0 ||
      cut.childAllocations.length || spec.budgets.modelTokens !== 0 || spec.budgets.costMicros !== 0 || spec.budgets.repairAttempts !== 0 ||
      spec.budgets.childDepth !== 0 || spec.budgets.childConcurrency !== 0 ||
      [run.budgetReserved, run.budgetConsumed].some(budget => budget.modelTokens !== 0 || budget.costMicros !== 0 || budget.repairAttempts !== 0) ||
      cut.journal.some(entry => !['verifier', 'publish'].includes(entry.opKind) || entry.brokerFenceTokenDigest !== undefined ||
        entry.budgetDelta.modelTokens !== 0 || entry.budgetDelta.costMicros !== 0 || entry.budgetDelta.repairAttempts !== 0))
    throw new TypeError('delivery continuation cannot carry model, tool, credential, repair or child authority');
}
