import { promises as fs } from 'node:fs';
import path from 'node:path';

import { resolveCliqHome, mutateSession } from '../../session/store.js';
import type { Session, SessionRecord } from '../../session/types.js';

import {
  resolveTxRoot,
  createTx as createTxRow,
  readTxState,
  txDir,
  makeTxId
} from './store.js';
import {
  applyTx as runApplyTx,
  ApplyRejected,
  ApplyConflict,
  ApplyPartial,
  StageCMetadataError
} from './apply.js';
import { abortTx as runAbortTx, AbortRejected } from './abort.js';
import { openRecordId } from './types.js';
import type { Transaction } from './types.js';

/**
 * Coordinator scope (v0.8 Phase 12 Task 48):
 *
 * This module exposes manual operations only -- openTx, getTxStatus, listTx,
 * applyTx, abortTx -- intended to be driven from the CLI. Auto-open at turn
 * start, auto-finalize/auto-validate at turn end, and auto-apply per
 * applyPolicy require runner integration (OverlayWriter injection,
 * turn-boundary hooks) and are deferred to a follow-up task.
 *
 * Likewise the validate/approve/finalize stages of the tx lifecycle are
 * deferred. v0.8's `applyTx` requires the underlying tx to already be in
 * 'approved' state (Stage A guard). For now the coordinator surfaces this
 * as a 'rejected' result and the operator/test must construct an approved
 * tx with diff manually. TODO(post-v0.8): wire auto-validate/auto-approve.
 */

export type CoordinatorContext = {
  cwd: string;
  session: Session;
  cliqHome?: string;
  workspaceId: string;
  sessionId: string;
  workspaceRealPath: string;
};

function txRootFor(ctx: CoordinatorContext): string {
  return resolveTxRoot(ctx.cliqHome ?? resolveCliqHome());
}

export type OpenTxOptions = {
  explicit: boolean;
  name?: string;
};

export async function openTx(ctx: CoordinatorContext, opts: OpenTxOptions): Promise<Transaction> {
  const root = txRootFor(ctx);
  const id = makeTxId();
  const tx = await createTxRow(root, {
    id,
    kind: 'edit',
    workspaceId: ctx.workspaceId,
    sessionId: ctx.sessionId,
    workspaceRealPath: ctx.workspaceRealPath
  });
  if (opts.explicit) {
    await mutateSession(ctx.cwd, ctx.session, (session) => {
      const record: SessionRecord = {
        id: openRecordId(id),
        ts: new Date().toISOString(),
        kind: 'tx-opened',
        role: 'user',
        content: opts.name
          ? `Transaction "${opts.name}" opened (${id})`
          : `Transaction opened (${id})`,
        meta: {
          txId: id,
          txKind: 'edit',
          ...(opts.name ? { name: opts.name } : {}),
          explicit: true
        }
      };
      session.records.push(record);
      session.activeTxId = id;
    });
  } else {
    // Implicit per-turn open: still set activeTxId but no tx-opened record.
    await mutateSession(ctx.cwd, ctx.session, (session) => {
      session.activeTxId = id;
    });
  }
  return tx;
}

export type TxStatusInfo = {
  tx: Transaction;
  hasApplyProgress: boolean;
  hasAbortProgress: boolean;
};

export async function getTxStatus(
  ctx: CoordinatorContext,
  txId: string
): Promise<TxStatusInfo | null> {
  const root = txRootFor(ctx);
  const tx = await readTxState(root, txId);
  if (!tx) return null;
  const dir = txDir(root, txId);
  const hasApplyProgress = await fs.stat(path.join(dir, 'apply-progress.json')).then(
    () => true,
    () => false
  );
  const hasAbortProgress = await fs.stat(path.join(dir, 'abort-progress.json')).then(
    () => true,
    () => false
  );
  return { tx, hasApplyProgress, hasAbortProgress };
}

export async function listTx(ctx: CoordinatorContext): Promise<Transaction[]> {
  const root = txRootFor(ctx);
  const txs: Transaction[] = [];
  let entries: Array<{ name: string; isDirectory: () => boolean }>;
  try {
    entries = (await fs.readdir(root, { withFileTypes: true })) as unknown as Array<{
      name: string;
      isDirectory: () => boolean;
    }>;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
  for (const entry of entries) {
    if (!entry.isDirectory() || !entry.name.startsWith('tx_')) continue;
    const tx = await readTxState(root, entry.name);
    if (tx) txs.push(tx);
  }
  return txs.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

export type CoordinatorApplyResult =
  | { ok: true; txId: string; filesApplied: string[]; ghostSnapshotId: string }
  | {
      ok: false;
      error: 'rejected' | 'conflict' | 'partial' | 'metadata-missing' | 'unknown';
      message: string;
    };

export async function applyTx(
  ctx: CoordinatorContext,
  txId: string,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _opts: { overrides?: string[]; reason?: string } = {}
): Promise<CoordinatorApplyResult> {
  // For v0.8: tx must already be 'approved'. The auto-validate/auto-approve
  // pipeline is deferred to runner integration. CLI users can run this
  // against a manually-prepared tx for testing or wait for the full pipeline.
  // TODO(post-v0.8): plumb overrides/reason into the validate/approve stage.
  try {
    const result = await runApplyTx({
      root: txRootFor(ctx),
      txId,
      cwd: ctx.cwd,
      session: ctx.session
    });
    return {
      ok: true,
      txId,
      filesApplied: result.filesApplied,
      ghostSnapshotId: result.ghostSnapshotId
    };
  } catch (err) {
    if (err instanceof ApplyConflict) return { ok: false, error: 'conflict', message: err.message };
    if (err instanceof ApplyPartial) return { ok: false, error: 'partial', message: err.message };
    if (err instanceof ApplyRejected) return { ok: false, error: 'rejected', message: err.message };
    if (err instanceof StageCMetadataError) {
      return { ok: false, error: 'metadata-missing', message: err.message };
    }
    return {
      ok: false,
      error: 'unknown',
      message: err instanceof Error ? err.message : String(err)
    };
  }
}

export type CoordinatorAbortResult =
  | { ok: true; aborted: boolean; reason?: string }
  | { ok: false; error: 'rejected' | 'unknown'; message: string };

export async function abortTx(
  ctx: CoordinatorContext,
  txId: string,
  opts: { restoreConfirmed?: boolean; keepPartial?: boolean; reason?: string } = {}
): Promise<CoordinatorAbortResult> {
  try {
    const result = await runAbortTx({
      root: txRootFor(ctx),
      txId,
      cwd: ctx.cwd,
      session: ctx.session,
      restoreConfirmed: opts.restoreConfirmed,
      keepPartial: opts.keepPartial,
      // The CLI's `--reason` is operator free-form text. It flows into the
      // protocol's `note` field, NOT the typed `reason` field. The protocol
      // computes the typed AbortReason internally from state + flags
      // (defaults to 'user-abort'; promotes to 'apply-failed-partial-*' when
      // an applied-partial flag is set).
      ...(opts.reason !== undefined ? { note: opts.reason } : {})
    });
    return { ok: true, aborted: result.aborted, reason: result.reason };
  } catch (err) {
    if (err instanceof AbortRejected) return { ok: false, error: 'rejected', message: err.message };
    return {
      ok: false,
      error: 'unknown',
      message: err instanceof Error ? err.message : String(err)
    };
  }
}
