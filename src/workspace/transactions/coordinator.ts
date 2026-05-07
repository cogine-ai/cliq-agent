import { promises as fs } from 'node:fs';
import path from 'node:path';

import { resolveCliqHome, mutateSession } from '../../session/store.js';
import type { Session, SessionRecord } from '../../session/types.js';

import {
  resolveTxRoot,
  createTx as createTxRow,
  readTxState,
  writeTxState,
  txDir,
  makeTxId,
  overlayDir,
  writeDiff,
  validatorsDir
} from './store.js';
import {
  applyTx as runApplyTx,
  ApplyRejected,
  ApplyConflict,
  ApplyPartial
} from './apply.js';
import { abortTx as runAbortTx, AbortRejected } from './abort.js';
import { computeDiff, summarizeDiff } from './diff.js';
import { openRecordId } from './types.js';
import type { Transaction, DiffSummary, ValidatorResultSummary } from './types.js';
import { buildValidatorRegistry } from '../../validators/registry.js';
import { runValidators } from '../../validators/runner.js';
import { materializeStagedView, cleanupStagedView } from './staged-view.js';
import type { TxValidatorsConfig, TxStagedViewConfig } from '../config.js';
import type { ValidatorResult } from '../../validators/types.js';

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

export async function getActiveTx(ctx: CoordinatorContext): Promise<Transaction | null> {
  if (!ctx.session.activeTxId) return null;
  return readTxState(txRootFor(ctx), ctx.session.activeTxId);
}

export type CoordinatorApplyResult =
  | { ok: true; txId: string; filesApplied: string[]; ghostSnapshotId: string }
  | { ok: false; error: 'rejected' | 'conflict' | 'partial' | 'unknown'; message: string };

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
      // The CLI surface accepts a free-form reason; the underlying abort
      // protocol uses a constrained AbortReason union. Cast through to allow
      // operator-supplied strings (e.g., 'user-abort'); the abort orchestrator
      // ultimately defaults to 'user-abort' if undefined.
      reason: opts.reason as never
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

export async function finalizeTx(
  ctx: CoordinatorContext,
  txId: string
): Promise<{ diffSummary: DiffSummary }> {
  const root = txRootFor(ctx);
  const tx = await readTxState(root, txId);
  if (!tx) throw new Error(`tx not found: ${txId}`);
  if (tx.state !== 'staging') {
    throw new Error(`finalizeTx requires state=staging; got ${tx.state}`);
  }
  const diff = await computeDiff(ctx.cwd, overlayDir(root, txId));
  const diffSummary = summarizeDiff(diff);
  await writeDiff(root, txId, diff);
  await writeTxState(root, { ...tx, state: 'finalized', diffSummary });
  return { diffSummary };
}

export async function validateTx(
  ctx: CoordinatorContext,
  txId: string,
  validatorsConfig: TxValidatorsConfig,
  stagedViewConfig: TxStagedViewConfig
): Promise<{ validators: ValidatorResultSummary[]; blockingFailures: string[] }> {
  const root = txRootFor(ctx);
  const tx = await readTxState(root, txId);
  if (!tx) throw new Error(`tx not found: ${txId}`);
  if (tx.state !== 'finalized') {
    throw new Error(`validateTx requires state=finalized; got ${tx.state}`);
  }

  const registry = buildValidatorRegistry(validatorsConfig);
  const stagedTarget = path.join(txDir(root, txId), 'staged-view');
  await materializeStagedView({
    cwd: ctx.cwd,
    overlayRoot: overlayDir(root, txId),
    target: stagedTarget,
    bindPaths: stagedViewConfig.bindPaths ?? ['node_modules'],
    copyMode: stagedViewConfig.copyMode ?? 'auto'
  });

  const results: ValidatorResult[] = [];
  try {
    await runValidators({
      txId,
      registry,
      workspaceView: stagedTarget,
      realCwd: ctx.cwd,
      onResult: async (r) => {
        results.push(r);
        await persistValidatorResult(root, txId, r);
      }
    });
  } finally {
    await cleanupStagedView(stagedTarget);
  }

  const summaries: ValidatorResultSummary[] = results.map((r) => ({
    name: r.name,
    severity: r.severity,
    status: r.status,
    durationMs: r.durationMs
  }));
  const blockingFailures = results
    .filter((r) => r.severity === 'blocking' && (r.status === 'fail' || r.status === 'error'))
    .map((r) => r.name);

  await writeTxState(root, { ...tx, state: 'validated', validators: summaries, blockingFailures });
  return { validators: summaries, blockingFailures };
}

async function persistValidatorResult(root: string, txId: string, r: ValidatorResult): Promise<void> {
  await fs.mkdir(validatorsDir(root, txId), { recursive: true });
  const sanitized = r.name.replace(/[^A-Za-z0-9_.-]/g, '_');
  await fs.writeFile(path.join(validatorsDir(root, txId), `${sanitized}.json`), JSON.stringify(r, null, 2), 'utf8');
}
