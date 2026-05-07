import type { TxBashPolicy, TxValidatorsConfig, TxStagedViewConfig } from '../workspace/config.js';
import { openTx, getActiveTx } from '../workspace/transactions/coordinator.js';
import type { Transaction } from '../workspace/transactions/types.js';
import type { Session } from '../session/types.js';
import type { RuntimeEvent } from './events.js';

export type TxRunnerOptions = {
  mode: 'edit';
  auto: 'per-turn' | 'manual';
  applyPolicy: 'interactive' | 'auto-on-pass' | 'manual-only';
  bashPolicy: TxBashPolicy;
  headless: boolean;
  validatorsConfig: TxValidatorsConfig;
  stagedViewConfig: TxStagedViewConfig;
  workspaceId: string;
  workspaceRealPath: string;
  cliqHome?: string;
  confirmApply?: () => Promise<boolean>;
};

export type CoordinatorCtx = {
  cwd: string;
  session: Session;
  cliqHome?: string;
  workspaceId: string;
  sessionId: string;
  workspaceRealPath: string;
};

export type EventEmitter = (event: RuntimeEvent) => Promise<void> | void;

export function assertHeadlessCompatible(opts: TxRunnerOptions): void {
  if (opts.headless && opts.applyPolicy === 'interactive') {
    throw new Error('--tx-apply interactive requires a TTY; use --tx-apply manual-only or auto-on-pass for headless runs');
  }
}

/**
 * Open a transaction at turn start when needed.
 *
 * - If a tx is already active (user ran `cliq tx open` previously), reuse it
 *   and return `{ tx, opened: false }`. Do NOT re-emit `tx-staging-start`.
 *   The runner uses `opened === false` to skip end-of-turn finalize so the
 *   explicit tx accumulates edits across turns and the user drives apply.
 * - Else if `opts.auto !== 'per-turn'`, return `{ tx: null, opened: false }`.
 *   Manual mode without an active tx → skip turn lifecycle.
 * - Else create an implicit per-turn tx via `openTx({ explicit: false })`,
 *   emit `tx-staging-start { trigger: 'auto-turn', txId }`, and return
 *   `{ tx, opened: true }`.
 */
export async function openTurnTx(
  ctx: CoordinatorCtx,
  opts: TxRunnerOptions,
  emit: EventEmitter
): Promise<{ tx: Transaction | null; opened: boolean }> {
  const existing = await getActiveTx(ctx);
  if (existing) {
    // Reuse existing tx (explicit tx open precedes the runner). Do NOT re-emit
    // tx-staging-start. opened=false signals the runner to skip finishTurnTx so
    // the explicit tx accumulates edits across turns and the user drives apply
    // manually.
    return { tx: existing, opened: false };
  }
  if (opts.auto !== 'per-turn') {
    // Manual mode without an active tx → skip turn lifecycle entirely.
    return { tx: null, opened: false };
  }
  const tx = await openTx(ctx, { explicit: false });
  await emit({ type: 'tx-staging-start', txId: tx.id, trigger: 'auto-turn' });
  return { tx, opened: true };
}
