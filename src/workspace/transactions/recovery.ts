import { promises as fs } from 'node:fs';

import {
  readTxState,
  writeTxState,
  readApplyProgress,
  writeApplyProgress,
  deleteApplyProgress,
  readAbortProgress,
  withTxLock
} from './store.js';
import { runStageC } from './apply.js';
import type { Transaction, ApplyProgress, AbortProgress } from './types.js';
import type { Session } from '../../session/types.js';

export type ApplyRecoveryKind =
  | 'apply-pending'
  | 'apply-writing'
  | 'apply-committed'
  | 'apply-finalized';

export type AbortRecoveryKind =
  | 'aborting'
  | 'aborted-finalize';

export type RecoveryAction =
  | {
      txId: string;
      tx: Transaction;
      kind: 'apply';
      phase: ApplyRecoveryKind;
      progress: ApplyProgress;
    }
  | {
      txId: string;
      tx: Transaction;
      kind: 'abort';
      phase: AbortRecoveryKind;
      progress: AbortProgress;
    };

/**
 * Enumerate `<root>/tx_*` directories and return the recovery actions needed
 * to converge each transaction whose on-disk state was left non-terminal by a
 * crash. Terminal transactions (state==='applied' or state==='aborted', or
 * apply-progress.phase==='apply-failed-partial') are skipped — recovery is
 * only triggered for tx that need a re-run of a stage.
 *
 * Apply-progress takes precedence over abort-progress because Stage A's A1a
 * guard prevents both files from coexisting in non-terminal phases.
 */
export async function scanForRecovery(root: string): Promise<RecoveryAction[]> {
  const actions: RecoveryAction[] = [];
  let entries: Array<{ name: string; isDirectory: () => boolean }>;
  try {
    entries = (await fs.readdir(root, { withFileTypes: true })) as Array<{
      name: string;
      isDirectory: () => boolean;
    }>;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return actions;
    throw err;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (!entry.name.startsWith('tx_')) continue;
    const txId = entry.name;
    const tx = await readTxState(root, txId);
    if (!tx) continue;

    // Apply-progress wins if present and non-terminal.
    const applyProgress = await readApplyProgress(root, txId);
    if (applyProgress) {
      if (applyProgress.phase === 'apply-failed-partial') {
        // Terminal — user must run `cliq tx abort` with the appropriate
        // --restore-confirmed/--keep-partial flag. Skip.
        continue;
      }
      if (
        applyProgress.phase === 'apply-pending' ||
        applyProgress.phase === 'apply-writing' ||
        applyProgress.phase === 'apply-committed' ||
        applyProgress.phase === 'apply-finalized'
      ) {
        actions.push({
          txId,
          tx,
          kind: 'apply',
          phase: applyProgress.phase,
          progress: applyProgress
        });
        continue;
      }
    }

    // Abort-progress in non-terminal phase, or aborted-but-state-not-yet-aborted.
    const abortProgress = await readAbortProgress(root, txId);
    if (abortProgress) {
      if (abortProgress.phase === 'aborting') {
        actions.push({
          txId,
          tx,
          kind: 'abort',
          phase: 'aborting',
          progress: abortProgress
        });
        continue;
      }
      if (abortProgress.phase === 'aborted' && tx.state !== 'aborted') {
        // Crash between abort-progress=aborted and tx.state=aborted.
        actions.push({
          txId,
          tx,
          kind: 'abort',
          phase: 'aborted-finalize',
          progress: abortProgress
        });
        continue;
      }
    }

    // No recovery needed: tx is terminal (applied/aborted) or staging/etc
    // with no progress files.
  }
  return actions;
}

export type RecoveryOutcomeAction =
  | 'apply-pending-reverted'
  | 'apply-pending-orphan-discarded'
  | 'apply-writing-partial'
  | 'apply-committed-stage-c'
  | 'apply-finalized-state'
  | 'no-op';

export type RecoveryOutcome = {
  txId: string;
  action: RecoveryOutcomeAction;
  warning?: string;
  ts: string;
};

export type RecoveryContext = {
  cwd: string;
  session: Session;
};

/**
 * Apply recovery rules per Section 16.4.1 of the v0.8 design spec.
 *
 * Locking model:
 *   - The 'apply-committed' branch calls runStageC, which manages its own
 *     session-lock-then-tx-lock acquisition. Calling it from within an outer
 *     withTxLock would deadlock the per-tx lock, so this branch runs WITHOUT
 *     an outer lock; runStageC's own four-marker idempotency check guards
 *     concurrent recovery attempts.
 *   - All other branches mutate state.json/apply-progress.json atomically,
 *     so they take the per-tx lock. The branch re-reads tx + progress under
 *     the lock to confirm phase/state hasn't changed since the scanner ran.
 */
export async function recoverApply(
  root: string,
  action: RecoveryAction & { kind: 'apply' },
  ctx: RecoveryContext
): Promise<RecoveryOutcome> {
  const ts = new Date().toISOString();

  // apply-committed: delegate to runStageC, which has its own locking.
  if (action.phase === 'apply-committed') {
    const progress = await readApplyProgress(root, action.txId);
    if (!progress || progress.phase !== 'apply-committed') {
      return { txId: action.txId, action: 'no-op', ts };
    }
    await runStageC(
      { root, txId: action.txId, cwd: ctx.cwd, session: ctx.session },
      progress.ghostSnapshotId
    );
    return { txId: action.txId, action: 'apply-committed-stage-c', ts };
  }

  // All other phases: take the per-tx lock for atomic state mutation.
  return await withTxLock(root, action.txId, async () => {
    const tx = await readTxState(root, action.txId);
    const progress = await readApplyProgress(root, action.txId);
    if (!tx || !progress) {
      // Already converged.
      return { txId: action.txId, action: 'no-op', ts };
    }

    switch (progress.phase) {
      case 'apply-pending': {
        if (tx.state === 'approved') {
          // Stage A1a never finished writing — drop the progress so a retry
          // re-runs Stage A from scratch.
          await deleteApplyProgress(root, action.txId);
          return { txId: action.txId, action: 'apply-pending-reverted', ts };
        }
        // Orphan: state is not approved (a non-tx-runtime component flipped
        // state, or the user manually edited state.json). Discard the
        // progress without mutating state, but emit a warning so the operator
        // can investigate.
        await deleteApplyProgress(root, action.txId);
        return {
          txId: action.txId,
          action: 'apply-pending-orphan-discarded',
          warning: `apply-pending recovered with state=${tx.state}; orphan apply-progress discarded`,
          ts
        };
      }
      case 'apply-writing': {
        // Files in progress.filesWritten were partially applied. Mark the tx
        // applied-partial; the user must run `cliq tx abort` with
        // --restore-confirmed or --keep-partial.
        await writeTxState(root, { ...tx, state: 'applied-partial' });
        await writeApplyProgress(root, action.txId, {
          ...progress,
          phase: 'apply-failed-partial',
          error: {
            stage: 'recovery',
            message:
              'crash during apply-writing; tx must be aborted with --restore-confirmed or --keep-partial'
          }
        });
        return {
          txId: action.txId,
          action: 'apply-writing-partial',
          warning: `apply-writing crash recovered: state→applied-partial. Files written: ${progress.filesWritten.join(', ')}`,
          ts
        };
      }
      case 'apply-finalized': {
        // Idempotent transition. The four-marker invariant
        // (apply-progress=apply-finalized AND tx.state=applied) requires
        // tx.state to converge. Preserve ghostSnapshotId from progress.
        if (tx.state !== 'applied') {
          await writeTxState(root, {
            ...tx,
            state: 'applied',
            ghostSnapshotId: progress.ghostSnapshotId
          });
        }
        return { txId: action.txId, action: 'apply-finalized-state', ts };
      }
      default: {
        // 'apply-committed' handled above; 'apply-failed-partial' filtered
        // out by the scanner. Any unexpected phase is a no-op.
        return { txId: action.txId, action: 'no-op', ts };
      }
    }
  });
}
