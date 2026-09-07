import { canonicalSha256 } from '../kernel/canonical.js';
import { parseCanonicalTime } from '../kernel/identity.js';
import type { InvocationJournalEntry, RunAssemblyV1 } from '../kernel/types.js';
import type { ModelRequestV1 } from '../model/request.js';

type Policy = RunAssemblyV1['retry']['model'];
type Counts = { dispatchedAttempts: number };
export type ModelRetryState = Counts & (
  | { kind: 'ready'; nextAttempt: number }
  | { kind: 'backoff'; nextAttempt: number; notBefore: string }
  | { kind: 'pending'; attempt: number; phase: 'prepared' | 'dispatch_claimed' }
  | { kind: 'completed'; attempt: number; resultRef: string }
  | { kind: 'exhausted'; attempt: number; evidenceRef: string }
);

/** Retry eligibility from durable facts, never a transport fence, dispatch capability or failure classifier. */
export function modelRetryState(policy: Policy, entries: readonly InvocationJournalEntry[], now: string): ModelRetryState {
  if (policy.maxDispatchedAttempts !== 3 || policy.maxZeroByteTransportRetriesPerAttempt !== 0 ||
      policy.postAttemptDelaysMs.length !== 2 || policy.postAttemptDelaysMs[0] !== 500 ||
      policy.postAttemptDelaysMs[1] !== 2000) throw new TypeError('invalid frozen model retry policy');
  const sampled = parseCanonicalTime(now);
  let dispatchedAttempts = 0, lastDispatchSettledAt: number | undefined;
  let previous: InvocationJournalEntry | undefined;
  const attempts: InvocationJournalEntry[][] = [];
  const readyAt = () => lastDispatchSettledAt === undefined ? undefined
    : lastDispatchSettledAt + (policy.postAttemptDelaysMs[dispatchedAttempts - 1] ?? 0);
  const assertEligible = (timestamp: string) => {
    if (dispatchedAttempts >= policy.maxDispatchedAttempts) throw new TypeError('model Journal exceeds its dispatched-attempt ceiling');
    if (parseCanonicalTime(timestamp) < (readyAt() ?? -Infinity)) throw new TypeError('model Journal bypasses its frozen retry backoff');
  };
  for (const entry of entries) {
    const first = entries[0]!;
    if (entry.opKind !== 'model' || entry.runId !== first.runId || entry.opId !== first.opId || entry.target !== first.target || entry.replayClass !== 'retry') {
      throw new TypeError('model retry history mixes operation identities');
    }
    if (previous && (entry.seq <= previous.seq || parseCanonicalTime(entry.timestamp) < parseCanonicalTime(previous.timestamp))) {
      throw new TypeError('model retry history is not in canonical Journal order');
    }
    previous = entry;
    if (entry.phase === 'prepared') {
      if (entry.attempt !== attempts.length) throw new TypeError('model retry attempts must be contiguous from zero');
      const prior = attempts.at(-1)?.at(-1);
      if (prior && (!['failed', 'unknown'].includes(prior.phase) || !prior.budgetSettlementRef || prior.seq >= entry.seq ||
          parseCanonicalTime(prior.timestamp) > parseCanonicalTime(entry.timestamp))) throw new TypeError('model retry overtakes an unsettled or completed attempt');
      assertEligible(entry.timestamp);
      attempts.push([entry]);
    } else {
      const attempt = attempts[entry.attempt];
      if (!attempt || entry.requestRef !== attempt[0]!.requestRef) throw new TypeError('model retry phase has no exact prepared owner');
      if (entry.phase === 'dispatch_claimed') {
        if (entry.attempt !== attempts.length - 1 || attempt.length !== 1) throw new TypeError('model dispatch is not a single claim on the current attempt');
        assertEligible(entry.timestamp);
        dispatchedAttempts++;
      } else {
        const previous = attempt.at(-1)!;
        const claimed = attempt.some((row) => row.phase === 'dispatch_claimed');
        if (!['completed', 'failed', 'unknown'].includes(entry.phase) || !entry.budgetSettlementRef ||
            (previous.phase !== 'dispatch_claimed' && !(previous.phase === 'prepared' && entry.phase === 'failed') &&
              !(previous.phase === 'unknown' && ['completed', 'failed'].includes(entry.phase)))) throw new TypeError('invalid model retry settlement');
        // A late audit resolution must not reset the delay or close a newer attempt.
        if (claimed && previous.phase === 'dispatch_claimed') lastDispatchSettledAt = parseCanonicalTime(entry.timestamp);
      }
      attempt.push(entry);
    }
  }
  const last = attempts.at(-1)?.at(-1);
  if (!last) return { kind: 'ready', nextAttempt: 0, dispatchedAttempts };
  if (last.phase === 'prepared' || last.phase === 'dispatch_claimed') return { kind: 'pending', attempt: last.attempt, phase: last.phase, dispatchedAttempts };
  if (last.phase === 'completed') {
    if (!last.resultRef) throw new TypeError('completed model attempt has no typed result');
    return { kind: 'completed', attempt: last.attempt, resultRef: last.resultRef, dispatchedAttempts };
  }
  if (dispatchedAttempts === policy.maxDispatchedAttempts) {
    const evidenceRef = last.phase === 'unknown' ? last.evidenceRef : last.errorRef;
    if (!evidenceRef) throw new TypeError('exhausted model attempt has no retained failure evidence');
    return { kind: 'exhausted', attempt: last.attempt, dispatchedAttempts, evidenceRef };
  }
  const notBefore = readyAt();
  return notBefore !== undefined && sampled < notBefore
    ? { kind: 'backoff', nextAttempt: last.attempt + 1, dispatchedAttempts, notBefore: new Date(notBefore).toISOString() }
    : { kind: 'ready', nextAttempt: last.attempt + 1, dispatchedAttempts };
}

/** A new attempt may change audit projection/revision, never the bytes or authority of the operation being retried. */
export function assertSameModelOperation(first: ModelRequestV1, next: ModelRequestV1): void {
  const content = ({ attempt: _attempt, promptProjectionRef: _projection, promptProjectionDigest: _digest,
    requestDigest: _request, ...stable }: ModelRequestV1) => stable;
  if (canonicalSha256(content(first)) !== canonicalSha256(content(next))) throw new TypeError('model retry changes its original request bytes or authority');
}
