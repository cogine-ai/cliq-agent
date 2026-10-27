// Pure historical counters from the complete original source prefix. This
// validates data only; the owning source reader independently binds every row.
import type { Checkpoint, ContinuationItem, InvocationJournalEntry, Run } from '../kernel/types.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeBudgetSettlement } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { addBudget, childAllocationBudgetFacts } from './invariants.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import type { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { ZERO_BUDGET } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
const same = (a: unknown, b: unknown) => canonicalSha256(a) === canonicalSha256(b);
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
export async function validateHistoricalSourceRunCounters(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: {
  original: Run; checkpoint: Checkpoint; items: readonly { itemSeq: number; item: ContinuationItem }[];
  journal: readonly InvocationJournalEntry[]; workers: ReturnType<typeof readWorkerLaunchesForRun>;
}): Promise<void> {
  const { original, checkpoint } = cut;
  const prefix = cut.items.slice(0, checkpoint.runItemSeq);
  const repairs = prefix.filter(row => row.item.kind === 'repair_diagnostic').map(row => row.item);
  if (repairs.length !== original.repairCount || repairs.some((item, i) => item.kind !== 'repair_diagnostic' || item.repairOrdinal !== i + 1))
    invalid('original repair count does not close its exact immutable prefix');
  const journals = cut.journal.slice(0, checkpoint.journalSeq), groups = new Map<string, typeof journals>();
  if (journals.length !== checkpoint.journalSeq) invalid('source Checkpoint Journal cursor exceeds its complete prefix');
  for (const [i, row] of journals.entries()) {
    if (row.seq !== i + 1) invalid('original Journal prefix has a sequence gap');
    const key = `${row.opId}\\0${row.attempt}`, rows = groups.get(key) ?? []; rows.push(row); groups.set(key, rows);
  }
  let consumed = { ...ZERO_BUDGET, repairAttempts: original.repairCount }, reserved = { ...ZERO_BUDGET };
  for (const rows of groups.values()) {
    const prepared = rows[0]!, terminal = rows.find(row => ['completed', 'failed', 'unknown'].includes(row.phase));
    if (prepared.phase !== 'prepared' || !['completed', 'failed'].includes(rows.at(-1)!.phase)) invalid('original parent retains an unresolved own invocation');
    if (!terminal?.budgetSettlementRef) invalid('original invocation lost its exact settlement');
    const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, terminal.budgetSettlementRef));
    if (settlement.runId !== original.id || settlement.opId !== prepared.opId || settlement.attempt !== prepared.attempt ||
        settlement.preparedJournalSeq !== prepared.seq || settlement.terminalJournalSeq !== terminal.seq ||
        settlement.terminalPhase !== terminal.phase || settlement.settledAt !== terminal.timestamp ||
        !same(settlement.reserved, prepared.budgetDelta) || !same(settlement.consumed, terminal.budgetDelta) ||
        rows.slice(rows.indexOf(terminal)).some(row => row.budgetSettlementRef !== terminal.budgetSettlementRef))
      invalid('original budget settlement changed its exact Journal identity');
    consumed = addBudget(consumed, settlement.consumed);
  }
  const admitted = new Set(journals.filter(row => row.opKind === 'child_admission' && row.phase === 'completed').map(row => row.opId));
  const prior = readChildAllocationsForRun(driver, original.id).filter(row => row.parentRunId === original.id && admitted.has(row.delegateOpId));
  const allocations = prior.map(row => {
    if (row.state === 'settled' && row.parentSettlementRevision <= original.revision) {
      const item = prefix.find(value => value.item.itemId === row.childResultItemId);
      if (item?.item.kind !== 'child_result' || item.item.childRunId !== row.childRunId || row.settledAt > checkpoint.createdAt)
        invalid('original settled budget has no owned source-prefix child result');
      return row;
    }
    const { state: _state, terminal: _terminal, inclusiveBudgetUsage: _usage, terminalAt: _at, childResultItemId: _item,
      parentSettlementRevision: _revision, releasedUnusedBudget: _unused, settledAt: _settled, ...origin } = row;
    return { ...origin, state: 'reserved' as const };
  });
  const children = childAllocationBudgetFacts(original.id, allocations);
  consumed = addBudget(consumed, children.consumed); reserved = addBudget(reserved, children.reserved);
  requireEqual(consumed, original.budgetConsumed, 'merge exact original inclusive consumed budget');
  requireEqual(reserved, original.budgetReserved, 'merge exact original conservative reserved budget');
  const leases = cut.workers.flatMap(worker => worker.activatedAt && worker.leaseEpoch !== undefined &&
    worker.plannedRunRevision < original.revision ? [worker.leaseEpoch] : []);
  if (original.leaseEpoch !== Math.max(0, ...leases)) invalid('source snapshot invented a parent worker lease');
}
