import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { InvocationJournalEntry } from './types.js';

/** Terminal-only truth: the result remains ambiguous and is never supplied to
 * another model turn. This is neither failed execution nor a cancelled effect. */
export type RetryUnknownCancelledResult = Readonly<{
  schemaVersion: 1; kind: 'retry_unknown_cancelled'; opId: string; attempt: number; unknownJournalSeq: number;
  budgetSettlementRef: string; dispatchFenceOrDeathEvidenceRef: string;
  message: 'Run stopped without using the ambiguous result';
}>;

/** An earlier ambiguity remains audited, but cannot replace the real result
 * of a later productive attempt. An unclaimed preparation does not supersede it. */
export function retryUnknownHasLaterClaim(journal: readonly InvocationJournalEntry[], unknown: Pick<RetryUnknownCancelledResult, 'opId' | 'attempt'>): boolean {
  return journal.some(entry => entry.opId === unknown.opId && entry.opKind === 'mcp' && entry.attempt > unknown.attempt && entry.phase === 'dispatch_claimed');
}

export function decodeRetryUnknownCancelledResult(value: unknown): RetryUnknownCancelledResult {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['schemaVersion', 'kind', 'opId', 'attempt', 'unknownJournalSeq',
    'budgetSettlementRef', 'dispatchFenceOrDeathEvidenceRef', 'message']);
  if (data.schemaVersion !== 1 || data.kind !== 'retry_unknown_cancelled' || data.message !== 'Run stopped without using the ambiguous result')
    throw new TypeError('retry UNKNOWN result must remain an unused terminal ambiguity');
  controlWireText(data.opId, 256); controlWireInteger(data.attempt); controlWireInteger(data.unknownJournalSeq, 1);
  controlWireRef(data.budgetSettlementRef); controlWireRef(data.dispatchFenceOrDeathEvidenceRef);
  return immutableSnapshot(data) as RetryUnknownCancelledResult;
}
