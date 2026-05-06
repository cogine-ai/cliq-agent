import { withTxLock, readTxState, readApplyProgress, readAbortProgress } from './store.js';
import type { Transaction, AbortReason } from './types.js';
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

// Public entry point that runs only AB0 + AB0a so far.
// Future tasks (31-33) will append AB1..AB3b under-lock checks before returning.
export async function decideAbort(ctx: AbortContext): Promise<AbortDecision> {
  await checkAB0(ctx);
  const ab0a = await checkAB0a(ctx);
  // Until tasks 31-33 land, we return a partial decision shaped for the eventual contract.
  // Reason resolution: AB0a result wins; otherwise ctx.reason; otherwise default 'user-abort'.
  const reason: AbortReason = ab0a?.reason ?? ctx.reason ?? 'user-abort';
  return {
    reason,
    restoreConfirmed: ab0a?.restoreConfirmed ?? false
  };
}
