import test from 'node:test';
import assert from 'node:assert/strict';
import type { InvocationJournalEntry } from '../kernel/types.js';
import { hasOnlySettledMcpUnknowns } from './worker-recovery.js';

// Eligibility data only. These tests create no Store, native owner, process,
// network, resource/death proof or authority callback.
function history(replayClass: 'manual' | 'retry' | 'reconcile' = 'manual'): InvocationJournalEntry[] {
  const prepared: InvocationJournalEntry = { seq: 1, runId: 'run', opId: 'mcp-call', opKind: 'mcp', attempt: 0,
    phase: 'prepared', leaseEpoch: 1, target: 'a'.repeat(64), requestRef: 'b'.repeat(64), grantRef: 'c'.repeat(64), replayClass,
    budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, timestamp: '2026-11-03T00:00:00.000Z' };
  const claim: InvocationJournalEntry = { ...prepared, seq: 2, phase: 'dispatch_claimed', dispatchId: 'dispatch',
    supervisorInstanceId: 'original', stateOwnerEpoch: 1, brokerFenceTokenDigest: 'd'.repeat(64),
    budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 } };
  return [prepared, claim, { ...claim, seq: 3, phase: 'unknown', budgetDelta: prepared.budgetDelta,
    budgetSettlementRef: 'e'.repeat(64), evidenceRef: 'f'.repeat(64), evidenceDigest: '0'.repeat(64) }];
}
for (const replayClass of ['manual', 'retry', 'reconcile'] as const) test(`one fully charged ${replayClass} MCP UNKNOWN can retire M without claiming an effect outcome`, () => {
  const journal = history(replayClass), original = structuredClone(journal);
  assert.equal(hasOnlySettledMcpUnknowns(journal), true);
  assert.deepEqual(journal, original);
  assert.equal(journal.at(-1)!.phase, 'unknown');
});
test('unsettled, refunded, foreign-purpose and competing effects cannot enter MCP worker retirement', () => {
  const complete = history();
  for (const journal of [[], complete.slice(0, 1), complete.slice(0, 2),
    complete.map(row => ({ ...row, opKind: 'tool' as const })),
    complete.map(row => row.phase === 'unknown' ? { ...row, budgetSettlementRef: undefined } : row),
    complete.map(row => row.phase === 'unknown' ? { ...row, budgetDelta: complete[1]!.budgetDelta } : row),
    [...complete, { ...complete[0]!, seq: 4, opId: 'another-effect' }]])
    assert.equal(hasOnlySettledMcpUnknowns(journal), false);
});

test('MCP worker retirement binds the original prepared, claim and UNKNOWN replay class and op kind', () => {
  for (const replayClass of ['manual', 'retry', 'reconcile'] as const) {
    const complete = history(replayClass);
    for (let selected = 0; selected < complete.length; selected++) {
      for (const foreign of ['manual', 'retry', 'reconcile', 'workspace-rollback-retry'] as const) {
        if (foreign === replayClass) continue;
        const changed = complete.map((entry, index) => index === selected ? { ...entry, replayClass: foreign } : entry);
        assert.equal(hasOnlySettledMcpUnknowns(changed), false, `row ${selected} cannot substitute ${foreign} for ${replayClass}`);
      }
      for (const opKind of ['tool', 'mcp-server', 'model'] as const) {
        const changed = complete.map((entry, index) => index === selected ? { ...entry, opKind } : entry);
        assert.equal(hasOnlySettledMcpUnknowns(changed), false, `row ${selected} cannot borrow ${opKind} purpose`);
      }
    }
  }
});
