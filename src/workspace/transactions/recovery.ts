import { promises as fs } from 'node:fs';

import {
  readTxState,
  readApplyProgress,
  readAbortProgress
} from './store.js';
import type { Transaction, ApplyProgress, AbortProgress } from './types.js';

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
