import type { TxBashPolicy, TxValidatorsConfig, TxStagedViewConfig } from '../workspace/config.js';
import {
  openTx,
  getActiveTx,
  finalizeTx,
  validateTx,
  approveTx,
  applyTx,
  abortTx
} from '../workspace/transactions/coordinator.js';
import type { Transaction, ValidatorResultSummary } from '../workspace/transactions/types.js';
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

/**
 * End-of-turn lifecycle for an auto-opened implicit tx.
 *
 * The runner only calls this when `openTurnTx` returned `opened === true`.
 * Drives the tx through finalize → validate → (optional confirm) → approve →
 * apply, emitting structured runtime events at each stage. On any abortable
 * failure (validator block, user decline, empty diff, apply error), aborts the
 * tx and emits `tx-aborted` with the appropriate reason. The applied-partial
 * branch is the one exception: emits an `error` event but leaves the tx in
 * applied-partial state — the user must drive abort manually.
 */
export async function finishTurnTx(
  ctx: CoordinatorCtx,
  opts: TxRunnerOptions,
  tx: Transaction,
  emit: EventEmitter
): Promise<void> {
  // Step 1: finalizeTx
  const finalized = await finalizeTx(ctx, tx.id);
  await emit({ type: 'tx-finalized', txId: tx.id, diffSummary: finalized.diffSummary });

  // No-edits short-circuit: abort the empty implicit tx instead of producing a no-op applied artifact.
  if (finalized.diffSummary.filesChanged === 0) {
    await abortTx(ctx, tx.id, { reason: 'user-abort' });
    await emit({
      type: 'tx-aborted',
      txId: tx.id,
      reason: 'user-abort',
      artifactRef: `tx/${tx.id}/`,
      failedValidators: undefined
    });
    return;
  }

  // Step 2: validateTx
  const validated = await validateTx(ctx, tx.id, opts.validatorsConfig, opts.stagedViewConfig);
  await emit({
    type: 'tx-validated',
    txId: tx.id,
    validators: validatorSummary(validated.validators),
    blockingFailures: validated.blockingFailures
  });

  if (validated.blockingFailures.length > 0) {
    await abortTx(ctx, tx.id, { reason: 'validator-fail' });
    await emit({
      type: 'tx-aborted',
      txId: tx.id,
      reason: 'validator-fail',
      artifactRef: `tx/${tx.id}/`,
      failedValidators: validated.blockingFailures
    });
    return;
  }

  // Step 3: applyPolicy decision
  if (opts.applyPolicy === 'manual-only') {
    // Defensive: A.7 refuses manual-only + per-turn at config-load. Leave validated, do not apply.
    return;
  }
  if (opts.applyPolicy === 'interactive') {
    if (!opts.confirmApply) {
      throw new Error(
        'applyPolicy=interactive requires confirmApply callback (should have been refused at construction for headless)'
      );
    }
    const ok = await opts.confirmApply();
    if (!ok) {
      await abortTx(ctx, tx.id, { reason: 'user-abort' });
      await emit({
        type: 'tx-aborted',
        txId: tx.id,
        reason: 'user-abort',
        artifactRef: `tx/${tx.id}/`,
        failedValidators: undefined
      });
      return;
    }
  }

  // Step 4: approveTx (no overrides — implicit tx defaults)
  const approval = await approveTx(ctx, tx.id, {});
  if (!approval.ok) {
    // Defensive: should be rare here since blockingFailures was already empty.
    await abortTx(ctx, tx.id, { reason: 'validator-fail' });
    await emit({
      type: 'tx-aborted',
      txId: tx.id,
      reason: 'validator-fail',
      artifactRef: `tx/${tx.id}/`,
      failedValidators: approval.uncoveredFailures
    });
    return;
  }

  // Step 5: applyTx
  const applyResult = await applyTx(ctx, tx.id);
  if (applyResult.ok) {
    await emit({
      type: 'tx-applied',
      txId: tx.id,
      diffSummary: finalized.diffSummary,
      validators: validatorSummary(validated.validators),
      overrides: [],
      artifactRef: `tx/${tx.id}/`,
      ghostSnapshotId: applyResult.ghostSnapshotId
    });
  } else if (applyResult.error === 'conflict') {
    await emit({
      type: 'error',
      stage: 'tool',
      message: applyResult.message,
      code: 'tx-apply-conflict',
      recoverable: true
    });
    await emit({
      type: 'tx-aborted',
      txId: tx.id,
      reason: 'apply-conflict',
      artifactRef: `tx/${tx.id}/`,
      failedValidators: undefined
    });
  } else if (applyResult.error === 'partial') {
    await emit({
      type: 'error',
      stage: 'tool',
      message: applyResult.message,
      code: 'tx-apply-partial',
      recoverable: false
    });
    // No tx-aborted event: tx remains in applied-partial; user must abort manually.
  } else {
    await emit({
      type: 'error',
      stage: 'tool',
      message: applyResult.message,
      code: 'tx-overlay-error',
      recoverable: true
    });
    await abortTx(ctx, tx.id, { reason: 'staging-error' });
    await emit({
      type: 'tx-aborted',
      txId: tx.id,
      reason: 'staging-error',
      artifactRef: `tx/${tx.id}/`,
      failedValidators: undefined
    });
  }
}

function validatorSummary(results: ValidatorResultSummary[]): {
  blocking: { pass: number; fail: number };
  advisory: { pass: number; fail: number; names: string[] };
} {
  const summary = {
    blocking: { pass: 0, fail: 0 },
    advisory: { pass: 0, fail: 0, names: [] as string[] }
  };
  for (const r of results) {
    if (r.severity === 'blocking') {
      if (r.status === 'pass') summary.blocking.pass++;
      else summary.blocking.fail++;
    } else {
      if (r.status === 'pass') summary.advisory.pass++;
      else {
        summary.advisory.fail++;
        summary.advisory.names.push(r.name);
      }
    }
  }
  return summary;
}
