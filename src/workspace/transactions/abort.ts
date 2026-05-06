import { withTxLock, readTxState, readApplyProgress, readAbortProgress } from './store.js';
import type { Transaction, AbortReason } from './types.js';
import { abortRecordId } from './types.js';
import type { Session } from '../../session/types.js';

export type AbortContext = {
  root: string;
  txId: string;
  cwd: string;
  session: Session;
  restoreConfirmed?: boolean;
  keepPartial?: boolean;
  reason?: AbortReason;
};

export type AbortDecision = {
  reason: AbortReason;
  partialFiles?: string[];
  ghostSnapshotId?: string;
  restoreConfirmed: boolean;
} | null;

export class AbortRejected extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AbortRejected';
  }
}

const IN_FLIGHT_PHASES = new Set(['apply-pending', 'apply-writing', 'apply-committed']);

// AB0: read apply-progress without lock; if in-flight, reject fast.
async function checkAB0(ctx: AbortContext): Promise<void> {
  const progress = await readApplyProgress(ctx.root, ctx.txId);
  if (progress && IN_FLIGHT_PHASES.has(progress.phase)) {
    throw new AbortRejected(`apply is in flight (phase=${progress.phase}); cannot abort`);
  }
}

// AB0a: pre-lock applied-partial flag rules.
// Returns the resolved reason (and partial flag set) for use by later phases, or null when no
// applied-partial-specific reason resolution is needed.
type AB0aResult = {
  reason: AbortReason;
  restoreConfirmed: boolean;
} | null;

async function checkAB0a(ctx: AbortContext): Promise<AB0aResult> {
  const tx: Transaction | null = await readTxState(ctx.root, ctx.txId);
  if (!tx) return null;
  if (ctx.restoreConfirmed && ctx.keepPartial) {
    throw new AbortRejected('--restore-confirmed and --keep-partial are mutually exclusive');
  }
  if (tx.state === 'applied-partial') {
    if (ctx.restoreConfirmed) {
      return { reason: 'apply-failed-partial-restored', restoreConfirmed: true };
    }
    if (ctx.keepPartial) {
      return { reason: 'apply-failed-partial-kept', restoreConfirmed: false };
    }
    throw new AbortRejected('tx is applied-partial; pass --restore-confirmed or --keep-partial');
  }
  // state is not applied-partial -- flags must not be set
  if (ctx.restoreConfirmed || ctx.keepPartial) {
    throw new AbortRejected(
      `flags --restore-confirmed/--keep-partial only apply when state is applied-partial (state=${tx.state})`
    );
  }
  return null;
}

// Public entry point. Runs AB0 + AB0a pre-lock, then acquires the per-tx lock
// for AB2 re-read and AB3a authoritative recheck of apply-progress phase.
// Future tasks (32-33) will append AB3a.5 + AB3b under-lock checks before returning.
export async function decideAbort(ctx: AbortContext): Promise<AbortDecision> {
  await checkAB0(ctx);
  const ab0a = await checkAB0a(ctx);
  return await withTxLock(ctx.root, ctx.txId, async () => {
    // AB2: re-read authoritative state under lock.
    const txUnderLock = await readTxState(ctx.root, ctx.txId);
    const progressUnderLock = await readApplyProgress(ctx.root, ctx.txId);
    // AB3a: re-check apply-progress phase. If it's now in-flight, reject (race after AB0).
    if (progressUnderLock && IN_FLIGHT_PHASES.has(progressUnderLock.phase)) {
      throw new AbortRejected(
        `apply is in flight (phase=${progressUnderLock.phase}); cannot abort (race)`
      );
    }
    // AB3a.5: re-check applied-partial flag rules using under-lock state. The under-lock
    // state is authoritative; AB0a's pre-lock check was a fast-fail and may have raced.
    let reason: AbortReason;
    let restoreConfirmed = false;
    let partialFiles: string[] | undefined;
    let ghostSnapshotId: string | undefined;
    if (txUnderLock?.state === 'applied-partial') {
      if (ctx.restoreConfirmed && ctx.keepPartial) {
        throw new AbortRejected('--restore-confirmed and --keep-partial are mutually exclusive');
      }
      if (ctx.restoreConfirmed) {
        reason = 'apply-failed-partial-restored';
        restoreConfirmed = true;
      } else if (ctx.keepPartial) {
        reason = 'apply-failed-partial-kept';
      } else {
        throw new AbortRejected(
          'tx is applied-partial; pass --restore-confirmed or --keep-partial (under-lock recheck)'
        );
      }
      partialFiles = progressUnderLock?.filesWritten ?? [];
      ghostSnapshotId = progressUnderLock?.ghostSnapshotId ?? txUnderLock.ghostSnapshotId;
    } else {
      if (ctx.restoreConfirmed || ctx.keepPartial) {
        throw new AbortRejected(
          `flags --restore-confirmed/--keep-partial only apply when state is applied-partial (state=${txUnderLock?.state}, under-lock)`
        );
      }
      reason = ctx.reason ?? 'user-abort';
    }
    // AB3b: all-four-terminal-markers idempotency check. If the tx has already been
    // fully aborted (state, abort-progress, session.activeTxId, and tx-aborted record
    // all consistent), short-circuit with a no-op (null).
    const abortProgressUnderLock = await readAbortProgress(ctx.root, ctx.txId);
    const recordId = abortRecordId(ctx.txId);
    const recordPresent = ctx.session.records.some((r) => r.id === recordId);
    if (
      txUnderLock?.state === 'aborted' &&
      abortProgressUnderLock?.phase === 'aborted' &&
      ctx.session.activeTxId !== ctx.txId &&
      recordPresent
    ) {
      return null;
    }
    return {
      reason,
      restoreConfirmed,
      partialFiles,
      ghostSnapshotId
    };
  });
}
