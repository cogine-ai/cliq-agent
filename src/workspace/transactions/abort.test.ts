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
  writeApplyProgress
} from './store.js';
import type { TxState } from './types.js';
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
