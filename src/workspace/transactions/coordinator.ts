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
  validatorsDir,
  withTxLock
} from './store.js';
import {
  applyTx as runApplyTx,
  ApplyRejected,
  ApplyConflict,
  ApplyPartial,
  StageCMetadataError
} from './apply.js';
import { abortTx as runAbortTx, AbortRejected } from './abort.js';
import { computeDiff, summarizeDiff } from './diff.js';
import {
  scanForRecovery,
  recoverApply,
  recoverAbort,
  writeRecoveryRecord,
  type RecoveryOutcome
} from './recovery.js';
import { openRecordId } from './types.js';
import type { Transaction, DiffSummary, ValidatorResultSummary, OverrideEntry } from './types.js';
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
    // Filter by workspaceId so users do not see tx from other workspaces
    // sharing the same CLIQ_HOME (e.g., $HOME/.cliq used across repos).
    if (tx && tx.workspaceId === ctx.workspaceId) txs.push(tx);
  }
  return txs.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

export async function getActiveTx(ctx: CoordinatorContext): Promise<Transaction | null> {
  if (!ctx.session.activeTxId) return null;
  return readTxState(txRootFor(ctx), ctx.session.activeTxId);
}

export type CoordinatorApplyResult =
  | { ok: true; txId: string; filesApplied: string[]; ghostSnapshotId: string }
  | {
      ok: false;
      error: 'rejected' | 'conflict' | 'partial' | 'metadata-missing' | 'unknown';
      message: string;
    };

export type ApplyTxOptions = { overrides?: string[]; reason?: string };

function hasApplyApprovalOptions(opts: ApplyTxOptions): boolean {
  return (opts.overrides?.length ?? 0) > 0 || opts.reason !== undefined;
}

function hasRecordedApplyApprovalOptions(tx: Transaction, opts: ApplyTxOptions): boolean {
  const overrides = opts.overrides ?? [];
  if (overrides.length === 0) return false;
  return overrides.every((validatorName) =>
    (tx.overridesApplied ?? []).some(
      (entry) =>
        entry.validatorName === validatorName &&
        (opts.reason === undefined || entry.reason === opts.reason)
    )
  );
}

export async function applyTx(
  ctx: CoordinatorContext,
  txId: string,
  opts: ApplyTxOptions = {}
): Promise<CoordinatorApplyResult> {
  // `applyTx` can safely drive validated -> approved -> applied because the
  // approve stage needs only tx-local state plus these options. It still cannot
  // validate finalized txs by itself because validation requires workspace
  // validator/staged-view config from the caller.
  try {
    const root = txRootFor(ctx);
    const tx = await readTxState(root, txId);
    if (tx?.state === 'validated') {
      const approval = await approveTx(ctx, txId, opts);
      if (!approval.ok) {
        return {
          ok: false,
          error: 'rejected',
          message: `uncovered blocking failures: ${approval.uncoveredFailures.join(', ')}`
        };
      }
    } else if (
      tx?.state === 'approved' &&
      hasApplyApprovalOptions(opts) &&
      !hasRecordedApplyApprovalOptions(tx, opts)
    ) {
      return {
        ok: false,
        error: 'rejected',
        message:
          'applyTx received approval options for an already approved transaction, but they are not recorded on the transaction; pass overrides/reason before approval or re-run from validated state'
      };
    }

    const result = await runApplyTx({
      root,
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
  // v0.8 supports only file modifications; reject any other op at finalize
  // time so the user sees a clear error before approval rather than a crash
  // mid-apply (defense-in-depth: apply.ts also enforces this).
  for (const entry of diff.files) {
    if (entry.op !== 'modify') {
      throw new Error(
        `v0.8 supports only file modifications; encountered op='${entry.op}' at ${entry.path}. Creating new files or deleting files is not yet supported.`
      );
    }
  }
  const diffSummary = summarizeDiff(diff);
  await writeDiff(root, txId, diff);

  // Critical section: re-read state under lock, verify it's still 'staging',
  // then merge with new fields and write. Closes a TOCTOU race where a
  // concurrent abort or recovery could move the tx to a terminal state mid-
  // computeDiff; without this guard, we'd resurrect it from a stale snapshot.
  await withTxLock(root, txId, async () => {
    const cur = await readTxState(root, txId);
    if (!cur) throw new Error(`tx vanished mid-finalize: ${txId}`);
    if (cur.state !== 'staging') {
      throw new Error(
        `finalizeTx race: tx state changed from staging to ${cur.state} during finalize`
      );
    }
    await writeTxState(root, { ...cur, state: 'finalized', diffSummary });
  });
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

  // Critical section: re-read state under lock to close TOCTOU race against
  // concurrent abort/recovery during the long-running validator pipeline.
  await withTxLock(root, txId, async () => {
    const cur = await readTxState(root, txId);
    if (!cur) throw new Error(`tx vanished mid-validate: ${txId}`);
    if (cur.state !== 'finalized') {
      throw new Error(
        `validateTx race: tx state changed from finalized to ${cur.state} during validation`
      );
    }
    await writeTxState(root, {
      ...cur,
      state: 'validated',
      validators: summaries,
      blockingFailures
    });
  });
  return { validators: summaries, blockingFailures };
}

async function persistValidatorResult(root: string, txId: string, r: ValidatorResult): Promise<void> {
  await fs.mkdir(validatorsDir(root, txId), { recursive: true });
  const sanitized = r.name.replace(/[^A-Za-z0-9_.-]/g, '_');
  await fs.writeFile(path.join(validatorsDir(root, txId), `${sanitized}.json`), JSON.stringify(r, null, 2), 'utf8');
}

export type ApproveTxOptions = {
  overrides?: string[];
  overrideAll?: boolean;
  allowValidatorError?: string[];
  reason?: string;
  by?: string;
};

export async function approveTx(
  ctx: CoordinatorContext,
  txId: string,
  opts: ApproveTxOptions
): Promise<{ ok: true } | { ok: false; uncoveredFailures: string[] }> {
  const root = txRootFor(ctx);
  const tx = await readTxState(root, txId);
  if (!tx) throw new Error(`tx not found: ${txId}`);
  if (tx.state !== 'validated') {
    throw new Error(`approveTx requires state=validated; got ${tx.state}`);
  }

  const blockingFailures = tx.blockingFailures ?? [];
  const overrides = new Set(opts.overrides ?? []);
  const allowError = new Set(opts.allowValidatorError ?? []);

  const uncovered = blockingFailures.filter((name) => {
    if (opts.overrideAll) return false;
    if (overrides.has(name)) return false;
    // Status-error failures are covered only when --allow-validator-error names them explicitly.
    const v = tx.validators?.find((x) => x.name === name);
    if (v?.status === 'error' && allowError.has(name)) return false;
    return true;
  });
  if (uncovered.length > 0) {
    return { ok: false, uncoveredFailures: uncovered };
  }

  const ts = new Date().toISOString();
  const overridesApplied: OverrideEntry[] = blockingFailures
    .filter((name) => opts.overrideAll || overrides.has(name) || allowError.has(name))
    .map((name) => ({
      validatorName: name,
      reason: opts.reason,
      by: opts.by ?? 'cli',
      ts
    }));

  // Critical section: re-read state under lock, verify still 'validated',
  // merge using the fresh read (NOT the stale `tx` snapshot from the top of
  // the function). Closes a TOCTOU race against concurrent abort/recovery.
  await withTxLock(root, txId, async () => {
    const cur = await readTxState(root, txId);
    if (!cur) throw new Error(`tx vanished mid-approve: ${txId}`);
    if (cur.state !== 'validated') {
      throw new Error(
        `approveTx race: tx state changed from validated to ${cur.state} during approval`
      );
    }
    await writeTxState(root, {
      ...cur,
      state: 'approved',
      overridesApplied: [...(cur.overridesApplied ?? []), ...overridesApplied]
    });
  });
  return { ok: true };
}

/**
 * Coordinator-level crash recovery entry point.
 *
 * Wraps `recoverAll` with a cross-session filter:
 *   - Own-session orphans (tx.sessionId === ctx.session.id) → run normal
 *     recoverApply/recoverAbort and write recovery.json for non-no-op outcomes.
 *   - Cross-session orphans → write a recovery.json marked as no-op with a
 *     'cross-session-skipped' warning; do NOT mutate state. The user can run
 *     recovery from the original session to converge it.
 *
 * The cross-session filter is required because runStageC (called by
 * recoverApply on apply-committed orphans) writes the tx-applied record into
 * the *current* session — wrong session if the orphan came from another.
 */
export async function recoverAtStart(
  ctx: CoordinatorContext
): Promise<{ recovered: RecoveryOutcome[]; crossSessionSkipped: string[] }> {
  const root = txRootFor(ctx);
  const actions = await scanForRecovery(root);
  const recovered: RecoveryOutcome[] = [];
  const crossSessionSkipped: string[] = [];
  const ts = new Date().toISOString();
  for (const action of actions) {
    if (action.tx.sessionId !== ctx.session.id) {
      crossSessionSkipped.push(action.txId);
      const skipOutcome: RecoveryOutcome = {
        txId: action.txId,
        action: 'no-op',
        warning: `cross-session-skipped: tx originated in session ${action.tx.sessionId}, current session ${ctx.session.id}`,
        ts
      };
      await writeRecoveryRecord(root, skipOutcome);
      continue;
    }
    const outcome =
      action.kind === 'apply'
        ? await recoverApply(root, action, ctx)
        : await recoverAbort(root, action, ctx);
    if (outcome.action !== 'no-op') {
      await writeRecoveryRecord(root, outcome);
    }
    recovered.push(outcome);
  }
  return { recovered, crossSessionSkipped };
}
