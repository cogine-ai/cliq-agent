import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import {
  readRecoveryRecord,
  recoverAbort,
  recoverAll,
  recoverApply,
  scanForRecovery
} from './recovery.js';
import {
  resolveTxRoot,
  createTx,
  writeTxState,
  readTxState,
  writeApplyProgress,
  readApplyProgress,
  writeAbortProgress,
  readAbortProgress
} from './store.js';
import { abortRecordId, applyRecordId, type TxState } from './types.js';
import { createSession, mutateSession } from '../../session/store.js';

const execFileAsync = promisify(execFile);

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

// -- Task 37: recoverApply rules ----------------------------------------------

async function setupGitWs(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-rec-ws-'));
  await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.name', 't'], { cwd: dir });
  return dir;
}

async function setupHomeWithEnv<T>(
  fn: (root: string, home: string) => Promise<T>
): Promise<T> {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-rec-home-'));
  const prev = process.env.CLIQ_HOME;
  process.env.CLIQ_HOME = home;
  try {
    return await fn(resolveTxRoot(home), home);
  } finally {
    if (prev === undefined) delete process.env.CLIQ_HOME;
    else process.env.CLIQ_HOME = prev;
    await rm(home, { recursive: true, force: true });
  }
}

test('recover apply-pending with state=approved: revert to approved (delete apply-progress)', async () => {
  await setupHomeWithEnv(async (root) => {
    const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-rec-ws-pending-'));
    try {
      await makeTx(root, 'tx_pending', 'approved');
      await writeApplyProgress(root, 'tx_pending', {
        phase: 'apply-pending',
        ghostSnapshotId: 'snap',
        startedAt: 'x',
        filesPlanned: ['a.txt'],
        filesWritten: []
      });
      const session = createSession(ws);
      const action = {
        txId: 'tx_pending',
        tx: (await readTxState(root, 'tx_pending'))!,
        kind: 'apply' as const,
        phase: 'apply-pending' as const,
        progress: (await readApplyProgress(root, 'tx_pending'))!
      };
      const outcome = await recoverApply(root, action, { cwd: ws, session });
      assert.equal(outcome.action, 'apply-pending-reverted');
      assert.equal(await readApplyProgress(root, 'tx_pending'), null);
      const tx = await readTxState(root, 'tx_pending');
      assert.equal(tx?.state, 'approved');
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('recover apply-pending with state!=approved: discard orphan, leave state, emit warning', async () => {
  await setupHomeWithEnv(async (root) => {
    const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-rec-ws-orphan-'));
    try {
      await makeTx(root, 'tx_orphan', 'aborted');
      await writeApplyProgress(root, 'tx_orphan', {
        phase: 'apply-pending',
        ghostSnapshotId: 'snap',
        startedAt: 'x',
        filesPlanned: ['a.txt'],
        filesWritten: []
      });
      const session = createSession(ws);
      const action = {
        txId: 'tx_orphan',
        tx: (await readTxState(root, 'tx_orphan'))!,
        kind: 'apply' as const,
        phase: 'apply-pending' as const,
        progress: (await readApplyProgress(root, 'tx_orphan'))!
      };
      const outcome = await recoverApply(root, action, { cwd: ws, session });
      assert.equal(outcome.action, 'apply-pending-orphan-discarded');
      assert.match(outcome.warning ?? '', /orphan/);
      assert.equal(await readApplyProgress(root, 'tx_orphan'), null);
      const tx = await readTxState(root, 'tx_orphan');
      assert.equal(tx?.state, 'aborted'); // unchanged
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('recover apply-writing: state→applied-partial, progress→apply-failed-partial, warning emitted', async () => {
  await setupHomeWithEnv(async (root) => {
    const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-rec-ws-writing-'));
    try {
      await makeTx(root, 'tx_writing', 'approved');
      await writeApplyProgress(root, 'tx_writing', {
        phase: 'apply-writing',
        ghostSnapshotId: 'snap',
        startedAt: 'x',
        filesPlanned: ['a.txt', 'b.txt'],
        filesWritten: ['a.txt']
      });
      const session = createSession(ws);
      const action = {
        txId: 'tx_writing',
        tx: (await readTxState(root, 'tx_writing'))!,
        kind: 'apply' as const,
        phase: 'apply-writing' as const,
        progress: (await readApplyProgress(root, 'tx_writing'))!
      };
      const outcome = await recoverApply(root, action, { cwd: ws, session });
      assert.equal(outcome.action, 'apply-writing-partial');
      assert.match(outcome.warning ?? '', /a\.txt/);
      const tx = await readTxState(root, 'tx_writing');
      assert.equal(tx?.state, 'applied-partial');
      const ap = await readApplyProgress(root, 'tx_writing');
      assert.equal(ap?.phase, 'apply-failed-partial');
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('recover apply-finalized: state transitions to applied (idempotent)', async () => {
  await setupHomeWithEnv(async (root) => {
    const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-rec-ws-final-'));
    try {
      await makeTx(root, 'tx_final', 'approved');
      await writeApplyProgress(root, 'tx_final', {
        phase: 'apply-finalized',
        ghostSnapshotId: 'snap_y',
        startedAt: 'x',
        filesPlanned: ['a.txt'],
        filesWritten: ['a.txt']
      });
      const session = createSession(ws);
      const action = {
        txId: 'tx_final',
        tx: (await readTxState(root, 'tx_final'))!,
        kind: 'apply' as const,
        phase: 'apply-finalized' as const,
        progress: (await readApplyProgress(root, 'tx_final'))!
      };
      const outcome = await recoverApply(root, action, { cwd: ws, session });
      assert.equal(outcome.action, 'apply-finalized-state');
      const tx = await readTxState(root, 'tx_final');
      assert.equal(tx?.state, 'applied');
      assert.equal(tx?.ghostSnapshotId, 'snap_y');
      // Re-run: idempotent
      const outcome2 = await recoverApply(root, action, { cwd: ws, session });
      assert.equal(outcome2.action, 'apply-finalized-state');
      const tx2 = await readTxState(root, 'tx_final');
      assert.equal(tx2?.state, 'applied');
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('recover apply-committed: invokes Stage C (idempotent)', async () => {
  await setupHomeWithEnv(async (root) => {
    const ws = await setupGitWs();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await execFileAsync('git', ['add', '.'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      // Build tx with diffSummary so Stage C can write the record.
      const tx = await createTx(root, {
        id: 'tx_committed',
        kind: 'edit',
        workspaceId: 'w',
        sessionId: 's',
        workspaceRealPath: ws
      });
      await writeTxState(root, {
        ...tx,
        state: 'approved',
        diffSummary: {
          filesChanged: 1,
          additions: 0,
          deletions: 0,
          creates: [],
          modifies: ['a.txt'],
          deletes: []
        }
      });
      await writeApplyProgress(root, 'tx_committed', {
        phase: 'apply-committed',
        ghostSnapshotId: 'snap_z',
        startedAt: 'x',
        filesPlanned: ['a.txt'],
        filesWritten: ['a.txt']
      });
      const session = createSession(ws);
      await mutateSession(ws, session, (s) => {
        s.activeTxId = 'tx_committed';
      });
      const action = {
        txId: 'tx_committed',
        tx: (await readTxState(root, 'tx_committed'))!,
        kind: 'apply' as const,
        phase: 'apply-committed' as const,
        progress: (await readApplyProgress(root, 'tx_committed'))!
      };
      const outcome = await recoverApply(root, action, { cwd: ws, session });
      assert.equal(outcome.action, 'apply-committed-stage-c');
      const txAfter = await readTxState(root, 'tx_committed');
      assert.equal(txAfter?.state, 'applied');
      const ap = await readApplyProgress(root, 'tx_committed');
      assert.equal(ap?.phase, 'apply-finalized');
      assert.equal(session.activeTxId, undefined);
      // Verify record present
      const rec = session.records.find(
        (r) => r.id === applyRecordId('tx_committed')
      );
      assert.ok(rec);
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

// -- Task 38: recoverAbort rules ----------------------------------------------

test('recover abort-progress phase=aborting: completes via abort protocol (idempotent)', async () => {
  await setupHomeWithEnv(async (root) => {
    const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-rec-abort1-'));
    try {
      const tx = await createTx(root, {
        id: 'tx_aborting',
        kind: 'edit',
        workspaceId: 'w',
        sessionId: 's',
        workspaceRealPath: ws
      });
      await writeTxState(root, {
        ...tx,
        state: 'approved',
        diffSummary: {
          filesChanged: 1,
          additions: 0,
          deletions: 0,
          creates: [],
          modifies: ['a.txt'],
          deletes: []
        }
      });
      await writeAbortProgress(root, 'tx_aborting', {
        phase: 'aborting',
        reason: 'user-abort',
        startedAt: 'x',
        ts: 'x'
      });
      const session = createSession(ws);
      const action = {
        txId: 'tx_aborting',
        tx: (await readTxState(root, 'tx_aborting'))!,
        kind: 'abort' as const,
        phase: 'aborting' as const,
        progress: (await readAbortProgress(root, 'tx_aborting'))!
      };
      const outcome = await recoverAbort(root, action, { cwd: ws, session });
      assert.equal(outcome.action, 'abort-aborting-resumed');
      const txAfter = await readTxState(root, 'tx_aborting');
      assert.equal(txAfter?.state, 'aborted');
      const ap = await readAbortProgress(root, 'tx_aborting');
      assert.equal(ap?.phase, 'aborted');
      const rec = session.records.find(
        (r) => r.id === abortRecordId('tx_aborting')
      );
      assert.ok(rec, 'abort record should be present');
      // Idempotent rerun: AB3b four-marker check inside decideAbort returns
      // null, so recoverAbort returns no-op.
      const outcome2 = await recoverAbort(root, action, { cwd: ws, session });
      assert.equal(outcome2.action, 'no-op');
      const recsAfter = session.records.filter(
        (r) => r.id === abortRecordId('tx_aborting')
      );
      assert.equal(
        recsAfter.length,
        1,
        'idempotent rerun must not duplicate the record'
      );
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('recover abort-progress phase=aborted but state lagged: finalize tx state', async () => {
  await setupHomeWithEnv(async (root) => {
    const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-rec-abort2-'));
    try {
      await makeTx(root, 'tx_abf', 'approved');
      await writeAbortProgress(root, 'tx_abf', {
        phase: 'aborted',
        reason: 'user-abort',
        startedAt: 'x',
        ts: 'x'
      });
      const session = createSession(ws);
      const action = {
        txId: 'tx_abf',
        tx: (await readTxState(root, 'tx_abf'))!,
        kind: 'abort' as const,
        phase: 'aborted-finalize' as const,
        progress: (await readAbortProgress(root, 'tx_abf'))!
      };
      const outcome = await recoverAbort(root, action, { cwd: ws, session });
      assert.equal(outcome.action, 'abort-finalized-state');
      const tx = await readTxState(root, 'tx_abf');
      assert.equal(tx?.state, 'aborted');
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('recoverAll handles a mix of apply and abort actions in one pass', async () => {
  await setupHomeWithEnv(async (root) => {
    const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-rec-all-'));
    try {
      // tx 1: apply-pending revertable
      await makeTx(root, 'tx_pending2', 'approved');
      await writeApplyProgress(root, 'tx_pending2', {
        phase: 'apply-pending',
        ghostSnapshotId: 'snap',
        startedAt: 'x',
        filesPlanned: ['a.txt'],
        filesWritten: []
      });
      // tx 2: aborted-finalize
      await makeTx(root, 'tx_abf2', 'approved');
      await writeAbortProgress(root, 'tx_abf2', {
        phase: 'aborted',
        reason: 'user-abort',
        startedAt: 'x',
        ts: 'x'
      });
      const session = createSession(ws);
      const outcomes = await recoverAll(root, { cwd: ws, session });
      assert.equal(outcomes.length, 2);
      const actionsSeen = outcomes.map((o) => o.action).sort();
      assert.deepEqual(
        actionsSeen,
        ['abort-finalized-state', 'apply-pending-reverted'].sort()
      );
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('recovery is idempotent: running twice yields same state', async () => {
  await setupHomeWithEnv(async (root) => {
    const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-rec-idem-'));
    try {
      await makeTx(root, 'tx_idem', 'approved');
      await writeApplyProgress(root, 'tx_idem', {
        phase: 'apply-finalized',
        ghostSnapshotId: 'snap_z',
        startedAt: 'x',
        filesPlanned: ['a.txt'],
        filesWritten: ['a.txt']
      });
      const session = createSession(ws);
      const r1 = await recoverAll(root, { cwd: ws, session });
      const r2 = await recoverAll(root, { cwd: ws, session });
      assert.equal(r1.length, 1);
      assert.equal(r1[0].action, 'apply-finalized-state');
      // Second run: tx is now applied, but apply-progress.phase=apply-finalized
      // is still considered non-terminal by the scanner. recoverApply sees
      // state===applied and short-circuits the write — outcome is still
      // 'apply-finalized-state' and tx remains applied.
      assert.equal(r2.length, 1);
      assert.equal(r2[0].action, 'apply-finalized-state');
      const tx = await readTxState(root, 'tx_idem');
      assert.equal(tx?.state, 'applied');
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

// -- Task 39: recovery.json warning artifact ---------------------------------

test('recoverAll writes recovery.json with action + ts (skipped for no-op)', async () => {
  await setupHomeWithEnv(async (root) => {
    const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-rec-warn-'));
    try {
      await makeTx(root, 'tx_warn', 'approved');
      await writeApplyProgress(root, 'tx_warn', {
        phase: 'apply-pending',
        ghostSnapshotId: 'snap',
        startedAt: 'x',
        filesPlanned: ['a.txt'],
        filesWritten: []
      });
      const session = createSession(ws);
      await recoverAll(root, { cwd: ws, session });
      const record = await readRecoveryRecord(root, 'tx_warn');
      assert.ok(record);
      assert.equal(record?.action, 'apply-pending-reverted');
      assert.match(record?.ts ?? '', /^\d{4}-\d{2}-\d{2}T/);
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('recovery.json includes warning when recovery emits one', async () => {
  await setupHomeWithEnv(async (root) => {
    const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-rec-warn-msg-'));
    try {
      await makeTx(root, 'tx_warn_msg', 'approved');
      await writeApplyProgress(root, 'tx_warn_msg', {
        phase: 'apply-writing',
        ghostSnapshotId: 'snap',
        startedAt: 'x',
        filesPlanned: ['a.txt', 'b.txt'],
        filesWritten: ['a.txt']
      });
      const session = createSession(ws);
      await recoverAll(root, { cwd: ws, session });
      const record = await readRecoveryRecord(root, 'tx_warn_msg');
      assert.ok(record);
      assert.equal(record?.action, 'apply-writing-partial');
      assert.match(record?.warning ?? '', /a\.txt/);
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('recovery.json round-trips for inspection', async () => {
  await setupHomeWithEnv(async (root) => {
    const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-rec-rt-'));
    try {
      await makeTx(root, 'tx_rt', 'approved');
      await writeApplyProgress(root, 'tx_rt', {
        phase: 'apply-finalized',
        ghostSnapshotId: 'snap_y',
        startedAt: 'x',
        filesPlanned: ['a.txt'],
        filesWritten: ['a.txt']
      });
      const session = createSession(ws);
      const [outcome] = await recoverAll(root, { cwd: ws, session });
      const record = await readRecoveryRecord(root, 'tx_rt');
      assert.equal(record?.txId, outcome.txId);
      assert.equal(record?.action, outcome.action);
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('readRecoveryRecord returns null when no recovery has run', async () => {
  await setupHomeWithEnv(async (root) => {
    await makeTx(root, 'tx_no_rec', 'approved');
    const record = await readRecoveryRecord(root, 'tx_no_rec');
    assert.equal(record, null);
  });
});
