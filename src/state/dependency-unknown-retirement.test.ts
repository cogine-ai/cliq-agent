import assert from 'node:assert/strict';
import test from 'node:test';
import type { InvocationJournalEntry } from '../kernel/types.js';
import { hasOnlySettledDependencyUnknowns } from './dependency-unknown-retirement.js';

// Inert protocol-selection data only, never a Run, dispatch, fence or death.
const rows = () => ['prepared', 'dispatch_claimed', 'unknown'].map((phase, index) => ({
  runId: 'run', seq: index + 1, opId: 'original', opKind: 'tool', attempt: 0,
  target: 'builtin:dependency-acquire', replayClass: 'workspace-rollback-retry', phase,
  ...(phase === 'unknown' ? { budgetSettlementRef: 'a'.repeat(64), evidenceRef: 'b'.repeat(64), evidenceDigest: 'b'.repeat(64) } : {}),
})) as InvocationJournalEntry[];
test('dependency terminal selection keeps one original charged UNKNOWN and cannot select another attempt or open operation', () => {
  assert.equal(hasOnlySettledDependencyUnknowns(rows()), true);
  assert.equal(hasOnlySettledDependencyUnknowns([]), false);
  for (const change of [
    (value: InvocationJournalEntry[]) => { value.pop(); },
    (value: InvocationJournalEntry[]) => { value[2]!.phase = 'completed'; },
    (value: InvocationJournalEntry[]) => { value[2]!.attempt = 1; },
    (value: InvocationJournalEntry[]) => { value[1]!.target = 'builtin:bash'; },
    (value: InvocationJournalEntry[]) => { value[2]!.replayClass = 'manual'; },
    (value: InvocationJournalEntry[]) => { delete value[2]!.budgetSettlementRef; },
    (value: InvocationJournalEntry[]) => { value.push({ ...value[0]!, opId: 'unsettled-other' }); },
    (value: InvocationJournalEntry[]) => { value.splice(1, 0, { ...value[0]! }); },
  ]) { const value = rows(); change(value); assert.equal(hasOnlySettledDependencyUnknowns(value), false); }
});
