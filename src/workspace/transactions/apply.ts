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

    // A2: index-clean cross-check is deferred to a future helper; v0.8 relies on
    // the validator-time baseline captured by builtin:index-clean. TODO(v0.9): add
    // checkIndexUnchanged and re-validate here.

    // A3: bulk preflight -- read every modify target's current bytes, fingerprint,
    // and compare to entry.oldContent. Any mismatch aborts Stage A without writing
    // apply-progress.
    const diff = await readDiff(ctx.root, ctx.txId);
    if (!diff) throw new Error(`tx diff missing: ${ctx.txId}`);
    const plan: PlanEntry[] = [];
    for (const entry of diff.files) {
      if (entry.op !== 'modify') {
        throw new Error(`unsupported diff op in v0.8: ${entry.op}`);
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
      // B3a: re-verify fingerprint right before write
      const real = await fs.readFile(path.join(tx.workspaceRealPath, planned.path), 'utf8');
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
      // B3b-d: write tmp + fsync + rename
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
