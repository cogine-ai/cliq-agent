import {
  withTxLock,
  readTxState,
  readApplyProgress,
  readAbortProgress,
  writeAbortProgress,
  writeTxState
} from './store.js';
import type { Transaction, AbortReason } from './types.js';
import { abortRecordId } from './types.js';
import { mutateSession } from '../../session/store.js';
import type { Session, SessionRecord } from '../../session/types.js';

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

/**
 * AB4..AB7 — Abort write phase. Mirrors apply.ts Stage C in shape: two distinct
 * lock-acquisition phases so that session fsync MUST happen before tx state.json
 * transitions. A crash between phases leaves session ahead of tx-store; recovery
 * converges by re-running this phase.
 *
 * Phase abort-session: take the session lock via mutateSession; inside, take the
 * tx-store lock briefly to write abort-progress.phase=aborting, then mutate the
 * in-memory session to append the deterministic tx-aborted record and clear
 * activeTxId when it points to this tx. mutateSession fsyncs the session.
 *
 * Phase abort-tx: re-acquire the tx-store lock; finalize abort-progress
 * (phase=aborted) then tx state (state=aborted). Both writes are idempotent.
 */
export async function runAbortWritePhase(
  ctx: AbortContext,
  decision: NonNullable<AbortDecision>
): Promise<void> {
  // Snapshot the data we need to build the tx-aborted record from the
  // authoritative on-disk tx state. This read happens before we take the
  // session lock; AB3b idempotency already guarded against duplicate work.
  const txInitial = await readTxState(ctx.root, ctx.txId);
  const files = {
    wouldHaveCreated: txInitial?.diffSummary?.creates ?? [],
    wouldHaveModified: txInitial?.diffSummary?.modifies ?? [],
    wouldHaveDeleted: txInitial?.diffSummary?.deletes ?? []
  };
  const failedValidators =
    txInitial?.blockingFailures && txInitial.blockingFailures.length > 0
      ? txInitial.blockingFailures
      : undefined;
  const appliedPartial =
    decision.reason === 'apply-failed-partial-restored' ||
    decision.reason === 'apply-failed-partial-kept'
      ? {
          partialFiles: decision.partialFiles ?? [],
          ghostSnapshotId: decision.ghostSnapshotId ?? '',
          restoreConfirmed: decision.restoreConfirmed
        }
      : undefined;

  // Phase abort-session: take session lock, briefly take tx-store lock to write
  // abort-progress=aborting, then append the deterministic record and clear
  // activeTxId. mutateSession fsyncs on return.
  await mutateSession(ctx.cwd, ctx.session, async (session) => {
    const recordId = abortRecordId(ctx.txId);
    const present = session.records.some((r) => r.id === recordId);
    if (!present) {
      // AB4: write abort-progress.phase=aborting under tx-store lock.
      await withTxLock(ctx.root, ctx.txId, async () => {
        const existing = await readAbortProgress(ctx.root, ctx.txId);
        if (!existing || existing.phase !== 'aborting') {
          const ts = new Date().toISOString();
          await writeAbortProgress(ctx.root, ctx.txId, {
            phase: 'aborting',
            reason: decision.reason,
            startedAt: existing?.startedAt ?? ts,
            ts
          });
        }
      });
      // AB5: append the deterministic tx-aborted record.
      const record: SessionRecord = {
        id: recordId,
        ts: new Date().toISOString(),
        kind: 'tx-aborted',
        role: 'user',
        content: `Transaction ${ctx.txId} aborted: ${decision.reason}`,
        meta: {
          txId: ctx.txId,
          txKind: 'edit',
          reason: decision.reason,
          ...(failedValidators ? { failedValidators } : {}),
          files,
          artifactRef: `tx/${ctx.txId}/`,
          ...(appliedPartial ? { appliedPartial } : {})
        }
      };
      session.records.push(record);
    }
    // AB5c: clear activeTxId only if it points to this tx.
    if (session.activeTxId === ctx.txId) {
      session.activeTxId = undefined;
    }
  });

  // Phase abort-tx: re-acquire tx-store lock; finalize abort-progress and
  // tx state. Preserves original abort-progress.reason/startedAt fields.
  await withTxLock(ctx.root, ctx.txId, async () => {
    const progress = await readAbortProgress(ctx.root, ctx.txId);
    const tx = await readTxState(ctx.root, ctx.txId);
    if (progress && progress.phase !== 'aborted') {
      await writeAbortProgress(ctx.root, ctx.txId, {
        ...progress,
        phase: 'aborted',
        ts: new Date().toISOString()
      });
    }
    if (tx && tx.state !== 'aborted') {
      await writeTxState(ctx.root, { ...tx, state: 'aborted' });
    }
  });
}
