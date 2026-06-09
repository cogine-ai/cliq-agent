import { promises as fs } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

import {
  withTxLock,
  readTxState,
  writeTxState,
  readApplyProgress,
  writeApplyProgress,
  deleteApplyProgress,
  readAbortProgress,
  readDiff
} from './store.js';
import { createApplyPreSnapshot } from './snapshot.js';
import { mutateSession } from '../../session/store.js';
import type { Session, SessionRecord } from '../../session/types.js';
import { applyRecordId, validatorSummaryFromTx } from './types.js';
import {
  checkIndexUnchanged,
  IndexChangedSinceValidation
} from '../../validators/builtin/index-clean.js';

export type ApplyContext = {
  root: string;
  txId: string;
  cwd: string;
};

export type PlanEntry = {
  path: string;
  fingerprint: string;
  newContent: string;
};

export type StageAOutcome = {
  plan: PlanEntry[];
  ghostSnapshotId: string;
};

export class ApplyRejected extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ApplyRejected';
  }
}

export class ApplyConflict extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ApplyConflict';
  }
}

export async function runStageA(ctx: ApplyContext): Promise<StageAOutcome> {
  return withTxLock(ctx.root, ctx.txId, async () => {
    // A1a: state, abort-progress, apply-progress guards
    const tx = await readTxState(ctx.root, ctx.txId);
    if (!tx) throw new Error(`tx not found: ${ctx.txId}`);
    if (tx.state !== 'approved') {
      throw new ApplyRejected(`tx state is ${tx.state}; cannot apply`);
    }
    if (await readAbortProgress(ctx.root, ctx.txId)) {
      throw new ApplyRejected('tx is being aborted; cannot apply');
    }
    if (await readApplyProgress(ctx.root, ctx.txId)) {
      throw new ApplyRejected('apply already in flight; use cliq tx status or wait');
    }

    // A2: re-check the validator-time Git index baseline before writing
    // apply-progress. If builtin:index-clean was disabled or not persisted
    // (e.g. unit fixtures that construct approved tx rows directly), this is
    // a no-op.
    try {
      await checkIndexUnchanged({
        root: ctx.root,
        txId: ctx.txId,
        realCwd: tx.workspaceRealPath
      });
    } catch (err) {
      if (err instanceof IndexChangedSinceValidation) {
        throw new ApplyRejected(err.message);
      }
      throw err;
    }

    // A3: bulk preflight -- read every modify target's current bytes, fingerprint,
    // and compare to entry.oldContent. Any mismatch aborts Stage A without writing
    // apply-progress.
    const diff = await readDiff(ctx.root, ctx.txId);
    if (!diff) throw new Error(`tx diff missing: ${ctx.txId}`);
    const plan: PlanEntry[] = [];
    for (const entry of diff.files) {
      if (entry.op !== 'modify') {
        // v0.8 ships 'modify' only. 'create' / 'delete' are tracked for
        // v0.9 in docs/superpowers/specs/2026-05-02-cliq-transactional-workspace-runtime-design.md.
        // Surface the limitation explicitly so operators don't read a generic
        // error and assume the tx system is broken.
        throw new Error(
          `unsupported diff op in v0.8: ${entry.op} ` +
            "(only 'modify' is supported; 'create'/'delete' planned for v0.9 — see " +
            'docs/superpowers/specs/2026-05-02-cliq-transactional-workspace-runtime-design.md)'
        );
      }
      const real = await fs.readFile(path.join(tx.workspaceRealPath, entry.path), 'utf8');
      if (real !== entry.oldContent) {
        throw new ApplyConflict(`external change detected at ${entry.path}`);
      }
      plan.push({
        path: entry.path,
        fingerprint: createHash('sha256').update(real).digest('hex'),
        newContent: entry.newContent
      });
    }

    // A4: ghost snapshot
    const ghostSnapshotId = await createApplyPreSnapshot(tx.workspaceRealPath);

    // A5: write apply-progress with phase=apply-pending
    await writeApplyProgress(ctx.root, ctx.txId, {
      phase: 'apply-pending',
      ghostSnapshotId,
      startedAt: new Date().toISOString(),
      filesPlanned: plan.map((p) => p.path),
      filesWritten: []
    });

    // A6: lock auto-released by withTxLock when the closure returns.
    return { plan, ghostSnapshotId };
  });
}

export type StageBOutcome = {
  ghostSnapshotId: string;
};

export class ApplyPartial extends Error {
  constructor(message: string, public ghostSnapshotId: string) {
    super(message);
    this.name = 'ApplyPartial';
  }
}

/**
 * Stage C precondition failure: an approved tx reached Stage C without the
 * `diffSummary` metadata that the tx-applied session record requires. Emitted
 * to surface the broken finalize/approve invariant rather than silently
 * marking the tx applied without an audit record.
 */
export class StageCMetadataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StageCMetadataError';
  }
}

export async function runStageB(ctx: ApplyContext, plan: PlanEntry[]): Promise<StageBOutcome> {
  return withTxLock(ctx.root, ctx.txId, async () => {
    // B1a defense: tx state must still be 'approved' -- if it changed, scrap
    // apply-progress and bail.
    const tx = await readTxState(ctx.root, ctx.txId);
    if (!tx || tx.state !== 'approved') {
      await deleteApplyProgress(ctx.root, ctx.txId);
      throw new Error('tx state changed during apply; aborting Stage B');
    }
    let progress = await readApplyProgress(ctx.root, ctx.txId);
    if (!progress) throw new Error('apply-progress missing at Stage B');

    // B2: transition to apply-writing
    progress = { ...progress, phase: 'apply-writing' };
    await writeApplyProgress(ctx.root, ctx.txId, progress);

    for (const planned of plan) {
      // B3a: re-verify fingerprint right before write. IO errors here (e.g.,
      // file deleted between Stage A and Stage B) must converge to
      // applied-partial just like a fingerprint mismatch -- otherwise the
      // failure crashes the runner and leaves the tx in apply-writing forever.
      let real: string;
      try {
        real = await fs.readFile(path.join(tx.workspaceRealPath, planned.path), 'utf8');
      } catch (err) {
        await writeTxState(ctx.root, { ...tx, state: 'applied-partial' });
        await writeApplyProgress(ctx.root, ctx.txId, {
          ...progress,
          phase: 'apply-failed-partial',
          error: {
            stage: 'B3a',
            path: planned.path,
            message: err instanceof Error ? err.message : String(err)
          }
        });
        throw new ApplyPartial(
          `mid-stage IO error at ${planned.path}`,
          progress.ghostSnapshotId
        );
      }
      const fp = createHash('sha256').update(real).digest('hex');
      if (fp !== planned.fingerprint) {
        // partial: tx -> applied-partial, progress -> apply-failed-partial
        await writeTxState(ctx.root, { ...tx, state: 'applied-partial' });
        await writeApplyProgress(ctx.root, ctx.txId, {
          ...progress,
          phase: 'apply-failed-partial',
          error: { stage: 'B3a', path: planned.path, message: 'fingerprint mismatch' }
        });
        throw new ApplyPartial(
          `mid-stage external change at ${planned.path}`,
          progress.ghostSnapshotId
        );
      }
      // B3b-d: write tmp + fsync + rename + parent-dir fsync
      const target = path.join(tx.workspaceRealPath, planned.path);
      const tmp = `${target}.cliq-tx-tmp`;
      try {
        await fs.writeFile(tmp, planned.newContent, 'utf8');
        const fh = await fs.open(tmp, 'r+');
        try {
          await fh.sync();
        } finally {
          await fh.close();
        }
        await fs.rename(tmp, target);
        // Durability: rename() updates the directory entry but the new entry
        // is only persisted once the parent directory itself is synced. If
        // the host crashes between rename() and that fsync, recovery would
        // see filesWritten contain `planned.path` (next line) while the on-
        // disk directory still points at the old inode. Fsync the parent
        // here so the apply protocol's "wrote it" assertion stays honest.
        // Best-effort: some platforms (notably Windows) reject opening a
        // directory for read; treat that specifically as a no-op so we don't
        // turn the success into a partial failure on those hosts.
        try {
          const dir = await fs.open(path.dirname(target), 'r');
          try {
            await dir.sync();
          } finally {
            await dir.close();
          }
        } catch (err) {
          const code = (err as NodeJS.ErrnoException).code;
          if (code !== 'EISDIR' && code !== 'EPERM' && code !== 'EACCES') throw err;
        }
      } catch (err) {
        // Disk error mid-write: tx -> applied-partial; progress records the failure.
        await writeTxState(ctx.root, { ...tx, state: 'applied-partial' });
        await writeApplyProgress(ctx.root, ctx.txId, {
          ...progress,
          phase: 'apply-failed-partial',
          error: {
            stage: 'B3b',
            path: planned.path,
            message: err instanceof Error ? err.message : String(err)
          }
        });
        // Best-effort tmp cleanup
        await fs.rm(tmp, { force: true });
        throw new ApplyPartial(`disk error at ${planned.path}`, progress.ghostSnapshotId);
      }
      // B4: append filesWritten and re-persist progress
      progress = { ...progress, filesWritten: [...progress.filesWritten, planned.path] };
      await writeApplyProgress(ctx.root, ctx.txId, progress);
    }

    // B5: phase -> apply-committed
    progress = { ...progress, phase: 'apply-committed' };
    await writeApplyProgress(ctx.root, ctx.txId, progress);
    return { ghostSnapshotId: progress.ghostSnapshotId };
  });
}

export type StageCContext = ApplyContext & {
  session: Session;
};

/**
 * Stage C — finalize apply by writing the session record and tx-store transitions
 * in two distinct lock-acquisition phases. The spec mandates session fsync MUST
 * happen before tx state.json transitions so that crash recovery can reason about
 * the four idempotency markers (session record presence, session.activeTxId,
 * apply-progress.phase, tx.state) consistently.
 *
 * Phase C-session: take the session lock via mutateSession; inside, take the tx
 * lock briefly to read authoritative state, snapshot the data needed to build
 * the tx-applied record, then mutate the in-memory session. mutateSession
 * fsyncs the session on return.
 *
 * Phase C-tx: re-acquire the tx-store lock and finalize the on-disk tx state
 * (apply-progress.phase=apply-finalized, tx.state=applied).
 */
export async function runStageC(ctx: StageCContext, ghostSnapshotId: string): Promise<void> {
  // Phase C-session: take session lock (via mutateSession). Inside, briefly take
  // tx-store lock to read authoritative state, then mutate session in-memory.
  // mutateSession fsyncs on return.
  await mutateSession(ctx.cwd, ctx.session, async (session) => {
    const decision = await withTxLock(ctx.root, ctx.txId, async () => {
      const progress = await readApplyProgress(ctx.root, ctx.txId);
      const tx = await readTxState(ctx.root, ctx.txId);
      if (!progress || !tx) return null;
      // Four-marker terminal idempotency: everything already done. Strengthened
      // beyond the plan with the records-contains check so a fresh re-run is
      // still allowed to append the record if it somehow went missing.
      if (
        progress.phase === 'apply-finalized' &&
        tx.state === 'applied' &&
        session.activeTxId !== ctx.txId &&
        session.records.some((r) => r.id === applyRecordId(ctx.txId))
      ) {
        return null;
      }
      return {
        recordId: applyRecordId(ctx.txId),
        diffSummary: tx.diffSummary,
        validators: validatorSummaryFromTx(tx),
        overrides: tx.overridesApplied ?? []
      };
    });
    if (!decision) return;
    // diffSummary is REQUIRED at apply time. The finalize stage (out of scope
    // of v0.8 Phase 7 but written by future runner integration or tests) must
    // populate tx.diffSummary before Stage C runs. If it is missing here, fail
    // the apply rather than producing an applied tx with no audit record.
    if (!decision.diffSummary) {
      throw new StageCMetadataError(
        `tx ${ctx.txId} cannot be applied: diffSummary is missing on the approved tx (finalize stage did not populate it). Refusing to mark applied without a tx-applied session record.`
      );
    }
    const present = session.records.some((r) => r.id === decision.recordId);
    if (!present) {
      const record: SessionRecord = {
        id: decision.recordId,
        ts: new Date().toISOString(),
        kind: 'tx-applied',
        role: 'user',
        content: `Transaction ${ctx.txId} applied: ${decision.diffSummary.filesChanged} files changed`,
        meta: {
          txId: ctx.txId,
          txKind: 'edit',
          diffSummary: decision.diffSummary,
          files: {
            creates: decision.diffSummary.creates,
            modifies: decision.diffSummary.modifies,
            deletes: decision.diffSummary.deletes
          },
          validators: decision.validators,
          overrides: decision.overrides,
          artifactRef: `tx/${ctx.txId}/`,
          ghostSnapshotId
        }
      };
      session.records.push(record);
    }
    if (session.activeTxId === ctx.txId) {
      session.activeTxId = undefined;
    }
  });

  // Phase C-tx: re-acquire tx-store lock; write apply-progress=apply-finalized
  // first, then state=applied. Both writes are idempotent.
  await withTxLock(ctx.root, ctx.txId, async () => {
    const progress = await readApplyProgress(ctx.root, ctx.txId);
    const tx = await readTxState(ctx.root, ctx.txId);
    if (!progress || !tx) return;
    if (progress.phase !== 'apply-finalized') {
      await writeApplyProgress(ctx.root, ctx.txId, { ...progress, phase: 'apply-finalized' });
    }
    if (tx.state !== 'applied') {
      await writeTxState(ctx.root, { ...tx, state: 'applied', ghostSnapshotId });
    }
  });
}

export type ApplyOutcome = {
  ghostSnapshotId: string;
  filesApplied: string[];
};

/**
 * Top-level apply orchestrator: A → B → C.
 *
 * Error semantics:
 *   - ApplyRejected from Stage A: tx state unchanged. Re-thrown.
 *   - ApplyConflict from Stage A: tx state stays 'approved' (Stage A never
 *     wrote apply-progress, so nothing to roll back). Re-thrown.
 *   - ApplyPartial from Stage B: tx is already 'applied-partial' and progress
 *     is 'apply-failed-partial'. Re-thrown so the caller can initiate abort
 *     via --restore-confirmed or --keep-partial.
 *   - Successful completion: apply-progress.phase='apply-finalized',
 *     tx.state='applied', session has tx-applied record + activeTxId cleared.
 */
export async function applyTx(ctx: ApplyContext & { session: Session }): Promise<ApplyOutcome> {
  const a = await runStageA(ctx);
  const b = await runStageB(ctx, a.plan);
  await runStageC({ ...ctx, session: ctx.session }, b.ghostSnapshotId);
  return {
    ghostSnapshotId: b.ghostSnapshotId,
    filesApplied: a.plan.map((p) => p.path)
  };
}
