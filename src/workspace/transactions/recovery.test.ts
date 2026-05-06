import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { scanForRecovery } from './recovery.js';
import {
  resolveTxRoot,
  createTx,
  writeTxState,
  writeApplyProgress,
  writeAbortProgress
} from './store.js';
import type { TxState } from './types.js';

async function withFakeHome<T>(fn: (root: string) => Promise<T>): Promise<T> {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-recovery-'));
  try {
    return await fn(resolveTxRoot(home));
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}

async function makeTx(root: string, txId: string, state: TxState) {
  const tx = await createTx(root, {
    id: txId,
    kind: 'edit',
    workspaceId: 'w',
    sessionId: 's',
    workspaceRealPath: '/tmp'
  });
  await writeTxState(root, { ...tx, state });
  return tx;
}

test('scanForRecovery returns [] when no tx directories exist', async () => {
  await withFakeHome(async (root) => {
    const actions = await scanForRecovery(root);
    assert.deepEqual(actions, []);
  });
});

test('scanForRecovery skips applied tx', async () => {
  await withFakeHome(async (root) => {
    await makeTx(root, 'tx_app', 'applied');
    const actions = await scanForRecovery(root);
    assert.deepEqual(actions, []);
  });
});

test('scanForRecovery skips aborted tx', async () => {
  await withFakeHome(async (root) => {
    await makeTx(root, 'tx_abt', 'aborted');
    const actions = await scanForRecovery(root);
    assert.deepEqual(actions, []);
  });
});

test('scanForRecovery picks up apply-progress in non-terminal phases', async () => {
  await withFakeHome(async (root) => {
    const phases = [
      'apply-pending',
      'apply-writing',
      'apply-committed',
      'apply-finalized'
    ] as const;
    for (const phase of phases) {
      const txId = `tx_${phase.replace(/-/g, '_')}`;
      await makeTx(root, txId, 'approved');
      await writeApplyProgress(root, txId, {
        phase,
        ghostSnapshotId: 'snap_x',
        startedAt: 'x',
        filesPlanned: ['a.txt'],
        filesWritten: phase === 'apply-pending' ? [] : ['a.txt']
      });
    }
    const actions = await scanForRecovery(root);
    assert.equal(actions.length, 4);
    const phasesSeen = actions
      .filter((a) => a.kind === 'apply')
      .map((a) => a.phase)
      .sort();
    assert.deepEqual(phasesSeen, [
      'apply-committed',
      'apply-finalized',
      'apply-pending',
      'apply-writing'
    ]);
  });
});

test('scanForRecovery picks up abort-progress in aborting phase', async () => {
  await withFakeHome(async (root) => {
    await makeTx(root, 'tx_aborting', 'approved');
    await writeAbortProgress(root, 'tx_aborting', {
      phase: 'aborting',
      reason: 'user-abort',
      startedAt: 'x',
      ts: 'x'
    });
    const actions = await scanForRecovery(root);
    assert.equal(actions.length, 1);
    assert.equal(actions[0].kind, 'abort');
    if (actions[0].kind === 'abort') {
      assert.equal(actions[0].phase, 'aborting');
    }
  });
});

test('scanForRecovery picks up aborted-but-state-not-yet-aborted (crash between abort-progress and state write)', async () => {
  await withFakeHome(async (root) => {
    await makeTx(root, 'tx_abf', 'approved');
    await writeAbortProgress(root, 'tx_abf', {
      phase: 'aborted',
      reason: 'user-abort',
      startedAt: 'x',
      ts: 'x'
    });
    const actions = await scanForRecovery(root);
    assert.equal(actions.length, 1);
    assert.equal(actions[0].kind, 'abort');
    if (actions[0].kind === 'abort') {
      assert.equal(actions[0].phase, 'aborted-finalize');
    }
  });
});

test('scanForRecovery skips apply-failed-partial (terminal — user must abort)', async () => {
  await withFakeHome(async (root) => {
    await makeTx(root, 'tx_partial', 'applied-partial');
    await writeApplyProgress(root, 'tx_partial', {
      phase: 'apply-failed-partial',
      ghostSnapshotId: 'snap_x',
      startedAt: 'x',
      filesPlanned: ['a.txt', 'b.txt'],
      filesWritten: ['a.txt']
    });
    const actions = await scanForRecovery(root);
    assert.deepEqual(actions, []);
  });
});

test('scanForRecovery ignores entries that are not tx_-prefixed directories', async () => {
  await withFakeHome(async (root) => {
    await mkdir(path.join(root, 'not_a_tx'), { recursive: true });
    await writeFile(path.join(root, 'stray.txt'), 'hi', 'utf8');
    await makeTx(root, 'tx_real', 'approved');
    await writeApplyProgress(root, 'tx_real', {
      phase: 'apply-pending',
      ghostSnapshotId: 'snap_x',
      startedAt: 'x',
      filesPlanned: [],
      filesWritten: []
    });
    const actions = await scanForRecovery(root);
    assert.equal(actions.length, 1);
    assert.equal(actions[0].txId, 'tx_real');
  });
});
