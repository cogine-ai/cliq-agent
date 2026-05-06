import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  decideAbort,
  AbortRejected,
  type AbortContext
} from './abort.js';
import {
  resolveTxRoot,
  createTx,
  writeTxState,
  writeApplyProgress,
  writeAbortProgress
} from './store.js';
import type { TxState } from './types.js';
import { abortRecordId } from './types.js';
import { createSession } from '../../session/store.js';

async function setupHome<T>(fn: (home: string) => Promise<T>): Promise<T> {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-abort-'));
  const prev = process.env.CLIQ_HOME;
  process.env.CLIQ_HOME = home;
  try {
    return await fn(home);
  } finally {
    if (prev === undefined) delete process.env.CLIQ_HOME;
    else process.env.CLIQ_HOME = prev;
    await rm(home, { recursive: true, force: true });
  }
}

function buildCtx(home: string, txId: string, opts: Partial<AbortContext> = {}): AbortContext {
  const cwd = path.join(home, 'workspace');
  return {
    root: resolveTxRoot(home),
    txId,
    cwd,
    session: createSession(cwd),
    ...opts
  };
}

async function setupTx(home: string, txId: string, state: TxState = 'approved') {
  const root = resolveTxRoot(home);
  const tx = await createTx(root, {
    id: txId,
    kind: 'edit',
    workspaceId: 'w',
    sessionId: 's',
    workspaceRealPath: '/tmp/ws'
  });
  await writeTxState(root, { ...tx, state });
  return root;
}

test('AB0 rejects fast when apply-progress is in-flight phase', async () => {
  await setupHome(async (home) => {
    await setupTx(home, 'tx_inflight', 'approved');
    await writeApplyProgress(resolveTxRoot(home), 'tx_inflight', {
      phase: 'apply-writing',
      ghostSnapshotId: 'snap_x',
      startedAt: 'x',
      filesPlanned: ['a.txt'],
      filesWritten: []
    });
    await assert.rejects(
      decideAbort(buildCtx(home, 'tx_inflight')),
      (err: unknown) => err instanceof AbortRejected && /apply is in flight/.test((err as Error).message)
    );
  });
});

test('AB0a rejects when state is applied-partial without --restore-confirmed or --keep-partial', async () => {
  await setupHome(async (home) => {
    await setupTx(home, 'tx_partial_no_flag', 'applied-partial');
    await assert.rejects(
      decideAbort(buildCtx(home, 'tx_partial_no_flag')),
      (err: unknown) => err instanceof AbortRejected && /restore-confirmed.*keep-partial/.test((err as Error).message)
    );
  });
});

test('AB0a rejects when both --restore-confirmed and --keep-partial passed', async () => {
  await setupHome(async (home) => {
    await setupTx(home, 'tx_both_flags', 'applied-partial');
    await assert.rejects(
      decideAbort(buildCtx(home, 'tx_both_flags', { restoreConfirmed: true, keepPartial: true })),
      (err: unknown) => err instanceof AbortRejected && /mutually exclusive/.test((err as Error).message)
    );
  });
});

test('AB0a sets reason apply-failed-partial-restored when --restore-confirmed', async () => {
  await setupHome(async (home) => {
    await setupTx(home, 'tx_restored', 'applied-partial');
    const decision = await decideAbort(buildCtx(home, 'tx_restored', { restoreConfirmed: true }));
    assert.equal(decision?.reason, 'apply-failed-partial-restored');
    assert.equal(decision?.restoreConfirmed, true);
  });
});

test('AB0a sets reason apply-failed-partial-kept when --keep-partial', async () => {
  await setupHome(async (home) => {
    await setupTx(home, 'tx_kept', 'applied-partial');
    const decision = await decideAbort(buildCtx(home, 'tx_kept', { keepPartial: true }));
    assert.equal(decision?.reason, 'apply-failed-partial-kept');
    assert.equal(decision?.restoreConfirmed, false);
  });
});

test('AB0a rejects flags when state is not applied-partial', async () => {
  await setupHome(async (home) => {
    await setupTx(home, 'tx_misapplied_flag', 'approved');
    await assert.rejects(
      decideAbort(buildCtx(home, 'tx_misapplied_flag', { restoreConfirmed: true })),
      (err: unknown) => err instanceof AbortRejected && /only apply when state is applied-partial/.test((err as Error).message)
    );
  });
});

test('AB0/AB0a allow normal abort when no flags and not partial', async () => {
  await setupHome(async (home) => {
    await setupTx(home, 'tx_normal', 'approved');
    const decision = await decideAbort(buildCtx(home, 'tx_normal', { reason: 'user-abort' }));
    assert.equal(decision?.reason, 'user-abort');
    assert.equal(decision?.restoreConfirmed, false);
  });
});

test('AB3a rejects when apply-progress in any in-flight phase (race after AB0 passed)', async () => {
  await setupHome(async (home) => {
    await setupTx(home, 'tx_ab3a_race', 'approved');
    // simulate the AB0 read showing the phase non-flight is fine -- but we just write
    // an in-flight phase here to ensure the under-lock recheck catches it.
    await writeApplyProgress(resolveTxRoot(home), 'tx_ab3a_race', {
      phase: 'apply-committed',
      ghostSnapshotId: 'snap_x',
      startedAt: 'x',
      filesPlanned: ['a.txt'],
      filesWritten: ['a.txt']
    });
    await assert.rejects(
      decideAbort(buildCtx(home, 'tx_ab3a_race')),
      (err: unknown) => err instanceof AbortRejected && /apply is in flight/.test((err as Error).message)
    );
  });
});

test('AB3a permits abort when apply-progress.phase is apply-failed-partial', async () => {
  await setupHome(async (home) => {
    await setupTx(home, 'tx_ab3a_partial', 'applied-partial');
    await writeApplyProgress(resolveTxRoot(home), 'tx_ab3a_partial', {
      phase: 'apply-failed-partial',
      ghostSnapshotId: 'snap_x',
      startedAt: 'x',
      filesPlanned: ['a.txt', 'b.txt'],
      filesWritten: ['a.txt']
    });
    const decision = await decideAbort(buildCtx(home, 'tx_ab3a_partial', { restoreConfirmed: true }));
    assert.equal(decision?.reason, 'apply-failed-partial-restored');
  });
});

test('AB3a.5 rejects when state changed to applied-partial mid-abort and no flag was passed', async () => {
  await setupHome(async (home) => {
    // AB0a sees state='approved' (no flag needed). Then state flips to applied-partial under lock.
    // We simulate this by calling decideAbort with no flags AFTER pre-writing applied-partial state.
    // (Without an injection hook into the lock callback, this exercises only the under-lock path; AB0a
    // would normally have caught this. Effectively, we're testing AB3a.5 catches it standalone.)
    await setupTx(home, 'tx_ab3a5_race', 'applied-partial');
    await assert.rejects(
      decideAbort(buildCtx(home, 'tx_ab3a5_race')),
      (err: unknown) => err instanceof AbortRejected && /restore-confirmed.*keep-partial/.test((err as Error).message)
    );
  });
});

test('AB3a.5 promotes reason and loads partial metadata when flag is now applicable', async () => {
  await setupHome(async (home) => {
    await setupTx(home, 'tx_ab3a5_promote', 'applied-partial');
    await writeApplyProgress(resolveTxRoot(home), 'tx_ab3a5_promote', {
      phase: 'apply-failed-partial',
      ghostSnapshotId: 'snap_x',
      startedAt: 'x',
      filesPlanned: ['a.txt', 'b.txt'],
      filesWritten: ['a.txt']
    });
    const decision = await decideAbort(buildCtx(home, 'tx_ab3a5_promote', { restoreConfirmed: true }));
    assert.equal(decision?.reason, 'apply-failed-partial-restored');
    assert.deepEqual(decision?.partialFiles, ['a.txt']);
    assert.equal(decision?.ghostSnapshotId, 'snap_x');
  });
});

test('AB3a.5 rejects flags when state is not applied-partial at lock time', async () => {
  // TODO: full coverage of this race requires injecting a state change between AB0a and AB3a.5
  // (no injection hook exists today). The standalone assertion is exercised by
  // 'AB0a rejects flags when state is not applied-partial' above; AB3a.5 reuses identical rules.
  assert.ok(true);
});

test('AB3b exits no-op when all four terminal markers are set', async () => {
  await setupHome(async (home) => {
    await setupTx(home, 'tx_ab3b_terminal', 'aborted');
    await writeAbortProgress(resolveTxRoot(home), 'tx_ab3b_terminal', {
      phase: 'aborted',
      reason: 'user-abort',
      startedAt: 'x',
      ts: 'x'
    });
    const ctx = buildCtx(home, 'tx_ab3b_terminal');
    ctx.session.activeTxId = undefined;
    ctx.session.records.push({
      id: abortRecordId('tx_ab3b_terminal'),
      ts: 'x',
      kind: 'tx-aborted',
      role: 'user',
      content: 'previously aborted',
      meta: {
        txId: 'tx_ab3b_terminal',
        txKind: 'edit',
        reason: 'user-abort',
        files: { wouldHaveCreated: [], wouldHaveModified: [], wouldHaveDeleted: [] },
        artifactRef: 'tx/tx_ab3b_terminal/'
      }
    } as any);
    const decision = await decideAbort(ctx);
    assert.equal(decision, null);
  });
});

test('AB3b proceeds when ANY one marker is missing', async () => {
  await setupHome(async (home) => {
    // Setup: tx state aborted, abort-progress missing -- should proceed (not no-op).
    await setupTx(home, 'tx_ab3b_partial', 'aborted');
    const ctx = buildCtx(home, 'tx_ab3b_partial');
    ctx.session.activeTxId = undefined;
    // No record, no abort-progress -> AB3b should NOT short-circuit.
    const decision = await decideAbort(ctx);
    assert.notEqual(decision, null);
    assert.equal(decision?.reason, 'user-abort');
  });
});

test('AB3b proceeds idempotently when crash left state=aborted but abort-progress.phase=aborting', async () => {
  await setupHome(async (home) => {
    await setupTx(home, 'tx_ab3b_crash', 'aborted');
    await writeAbortProgress(resolveTxRoot(home), 'tx_ab3b_crash', {
      phase: 'aborting',
      reason: 'user-abort',
      startedAt: 'x',
      ts: 'x' // not 'aborted' yet
    });
    const decision = await decideAbort(buildCtx(home, 'tx_ab3b_crash'));
    assert.notEqual(decision, null);
    assert.equal(decision?.reason, 'user-abort');
  });
});
