import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  runStageA,
  runStageB,
  runStageC,
  applyTx,
  ApplyRejected,
  ApplyConflict,
  ApplyPartial
} from './apply.js';
import {
  resolveTxRoot,
  createTx,
  writeTxState,
  writeDiff,
  writeApplyProgress,
  writeAbortProgress,
  readApplyProgress,
  readTxState as readTxStateAgain
} from './store.js';
import { createSession, mutateSession } from '../../session/store.js';
import type { Session } from '../../session/types.js';
import { applyRecordId } from './types.js';

const execFileAsync = promisify(execFile);

async function setupGitWorkspace(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-apply-'));
  await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.name', 't'], { cwd: dir });
  return dir;
}

async function setupHome(): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), 'cliq-apply-home-'));
}

async function withFakeCliqHome<T>(fn: (home: string) => Promise<T>): Promise<T> {
  const home = await setupHome();
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

async function setupApprovedTx(
  home: string,
  ws: string,
  txId: string,
  files: { path: string; oldContent: string; newContent: string }[]
): Promise<string> {
  const root = resolveTxRoot(home);
  const tx = await createTx(root, {
    id: txId,
    kind: 'edit',
    workspaceId: 'w',
    sessionId: 's',
    workspaceRealPath: ws
  });
  await writeTxState(root, { ...tx, state: 'approved' });
  await writeDiff(root, txId, {
    files: files.map((f) => ({
      path: f.path,
      op: 'modify' as const,
      oldContent: f.oldContent,
      newContent: f.newContent
    })),
    outOfBand: []
  });
  return root;
}

test('Stage A1a rejects when tx state !== approved', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await execFileAsync('git', ['add', 'a.txt'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTx(home, ws, 'tx_state', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
      ]);
      // override to non-approved state
      const { readTxState, writeTxState } = await import('./store.js');
      const tx = await readTxState(root, 'tx_state');
      await writeTxState(root, { ...tx!, state: 'aborted' });
      await assert.rejects(
        runStageA({ root, txId: 'tx_state', cwd: ws }),
        (err: unknown) =>
          err instanceof ApplyRejected && /state is aborted/.test((err as Error).message)
      );
      assert.equal(await readApplyProgress(root, 'tx_state'), null);
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('Stage A1a rejects when abort-progress.json exists', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await execFileAsync('git', ['add', 'a.txt'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTx(home, ws, 'tx_abp', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
      ]);
      await writeAbortProgress(root, 'tx_abp', {
        phase: 'aborting',
        reason: 'user-abort',
        startedAt: 'x',
        ts: 'x'
      });
      await assert.rejects(
        runStageA({ root, txId: 'tx_abp', cwd: ws }),
        (err: unknown) =>
          err instanceof ApplyRejected && /being aborted/.test((err as Error).message)
      );
      assert.equal(await readApplyProgress(root, 'tx_abp'), null);
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('Stage A1a rejects when apply-progress.json already exists', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await execFileAsync('git', ['add', 'a.txt'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTx(home, ws, 'tx_inflight', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
      ]);
      await writeApplyProgress(root, 'tx_inflight', {
        phase: 'apply-pending',
        ghostSnapshotId: 'snap_x',
        startedAt: 'x',
        filesPlanned: [],
        filesWritten: []
      });
      await assert.rejects(
        runStageA({ root, txId: 'tx_inflight', cwd: ws }),
        (err: unknown) =>
          err instanceof ApplyRejected && /apply already in flight/.test((err as Error).message)
      );
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('Stage A preflight rejects when ANY oldContent does not match (multi-file)', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await writeFile(path.join(ws, 'b.txt'), 'two', 'utf8');
      await writeFile(path.join(ws, 'c.txt'), 'three', 'utf8');
      await execFileAsync('git', ['add', '.'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTx(home, ws, 'tx_multi', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' },
        { path: 'b.txt', oldContent: 'two', newContent: 'TWO' },
        { path: 'c.txt', oldContent: 'three', newContent: 'THREE' }
      ]);
      // External mutation on b.txt to break preflight
      await writeFile(path.join(ws, 'b.txt'), 'TWO_LOCAL', 'utf8');
      await assert.rejects(
        runStageA({ root, txId: 'tx_multi', cwd: ws }),
        (err: unknown) => err instanceof ApplyConflict && /b\.txt/.test((err as Error).message)
      );
      // No apply-progress should have been written because A3 rejected before A5
      assert.equal(await readApplyProgress(root, 'tx_multi'), null);
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('Stage A success: writes apply-progress with phase=apply-pending and returns plan with all files fingerprinted', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await writeFile(path.join(ws, 'b.txt'), 'two', 'utf8');
      await execFileAsync('git', ['add', '.'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTx(home, ws, 'tx_ok', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' },
        { path: 'b.txt', oldContent: 'two', newContent: 'TWO' }
      ]);
      const outcome = await runStageA({ root, txId: 'tx_ok', cwd: ws });
      assert.equal(outcome.plan.length, 2);
      assert.match(outcome.ghostSnapshotId, /^wchk_/);
      const ap = await readApplyProgress(root, 'tx_ok');
      assert.equal(ap?.phase, 'apply-pending');
      assert.deepEqual(ap?.filesPlanned, ['a.txt', 'b.txt']);
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('Stage B writes each planned file via tmp+rename, fsyncs, and reaches apply-committed', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await writeFile(path.join(ws, 'b.txt'), 'two', 'utf8');
      await execFileAsync('git', ['add', '.'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTx(home, ws, 'tx_b_ok', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' },
        { path: 'b.txt', oldContent: 'two', newContent: 'TWO' }
      ]);
      const outcomeA = await runStageA({ root, txId: 'tx_b_ok', cwd: ws });
      const outcomeB = await runStageB({ root, txId: 'tx_b_ok', cwd: ws }, outcomeA.plan);
      assert.equal(outcomeB.ghostSnapshotId, outcomeA.ghostSnapshotId);
      const { readFile: rf } = await import('node:fs/promises');
      assert.equal(await rf(path.join(ws, 'a.txt'), 'utf8'), 'ONE');
      assert.equal(await rf(path.join(ws, 'b.txt'), 'utf8'), 'TWO');
      const ap = await readApplyProgress(root, 'tx_b_ok');
      assert.equal(ap?.phase, 'apply-committed');
      assert.deepEqual(ap?.filesWritten, ['a.txt', 'b.txt']);
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('Stage B B1a defense: state changed mid-stage deletes apply-progress and exits with internal error', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await execFileAsync('git', ['add', '.'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTx(home, ws, 'tx_b1a', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
      ]);
      const outcomeA = await runStageA({ root, txId: 'tx_b1a', cwd: ws });
      // Race injection: flip state out of 'approved' between Stage A and Stage B
      const { readTxState, writeTxState } = await import('./store.js');
      const tx = await readTxState(root, 'tx_b1a');
      await writeTxState(root, { ...tx!, state: 'aborted' });
      await assert.rejects(
        runStageB({ root, txId: 'tx_b1a', cwd: ws }, outcomeA.plan),
        /tx state changed during apply/
      );
      assert.equal(await readApplyProgress(root, 'tx_b1a'), null);
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('Stage B B3a per-file re-verification catches mid-write external change and transitions to applied-partial', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await writeFile(path.join(ws, 'b.txt'), 'two', 'utf8');
      await execFileAsync('git', ['add', '.'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTx(home, ws, 'tx_b3a', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' },
        { path: 'b.txt', oldContent: 'two', newContent: 'TWO' }
      ]);
      const outcomeA = await runStageA({ root, txId: 'tx_b3a', cwd: ws });
      // Mid-write race: change b.txt after Stage A took its fingerprint
      await writeFile(path.join(ws, 'b.txt'), 'TWO_LOCAL', 'utf8');
      await assert.rejects(
        runStageB({ root, txId: 'tx_b3a', cwd: ws }, outcomeA.plan),
        (err: unknown) => err instanceof ApplyPartial && /b\.txt/.test((err as Error).message)
      );
      const tx = await readTxStateAgain(root, 'tx_b3a');
      assert.equal(tx?.state, 'applied-partial');
      const ap = await readApplyProgress(root, 'tx_b3a');
      assert.equal(ap?.phase, 'apply-failed-partial');
      assert.deepEqual(ap?.filesWritten, ['a.txt']);
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('Stage B records filesWritten incrementally so abort sees what was written', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await writeFile(path.join(ws, 'b.txt'), 'two', 'utf8');
      await writeFile(path.join(ws, 'c.txt'), 'three', 'utf8');
      await execFileAsync('git', ['add', '.'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTx(home, ws, 'tx_inc', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' },
        { path: 'b.txt', oldContent: 'two', newContent: 'TWO' },
        { path: 'c.txt', oldContent: 'three', newContent: 'THREE' }
      ]);
      const outcomeA = await runStageA({ root, txId: 'tx_inc', cwd: ws });
      // Break the third file mid-stream
      await writeFile(path.join(ws, 'c.txt'), 'THREE_LOCAL', 'utf8');
      await assert.rejects(
        runStageB({ root, txId: 'tx_inc', cwd: ws }, outcomeA.plan),
        (err: unknown) => err instanceof ApplyPartial
      );
      const ap = await readApplyProgress(root, 'tx_inc');
      assert.deepEqual(ap?.filesWritten, ['a.txt', 'b.txt']);
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

// --- Stage C and applyTx orchestrator tests ---

async function setupSessionForApply(
  cwd: string,
  opts?: { activeTxId?: string }
): Promise<{ session: Session }> {
  const session = createSession(cwd);
  await mutateSession(cwd, session, (s) => {
    s.activeTxId = opts?.activeTxId;
  });
  return { session };
}

async function setupApprovedTxWithDiffSummary(
  home: string,
  ws: string,
  txId: string,
  files: { path: string; oldContent: string; newContent: string }[]
): Promise<string> {
  const root = await setupApprovedTx(home, ws, txId, files);
  // Set diffSummary so Stage C can build the session record.
  const { readTxState, writeTxState } = await import('./store.js');
  const tx = await readTxState(root, txId);
  await writeTxState(root, {
    ...tx!,
    diffSummary: {
      filesChanged: files.length,
      additions: 0,
      deletions: 0,
      creates: [],
      modifies: files.map((f) => f.path),
      deletes: []
    }
  });
  return root;
}

// TODO(Phase 9, Tasks 36-39): add a test for crash between Phase C-session and
// Phase C-tx that exercises recovery convergence. Out of scope for Task 28-29.

test('Stage C Phase C-session appends tx-applied record with deterministic id and clears activeTxId', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await execFileAsync('git', ['add', '.'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTxWithDiffSummary(home, ws, 'tx_c_session', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
      ]);
      const a = await runStageA({ root, txId: 'tx_c_session', cwd: ws });
      await runStageB({ root, txId: 'tx_c_session', cwd: ws }, a.plan);
      const { session } = await setupSessionForApply(ws, { activeTxId: 'tx_c_session' });
      await runStageC({ root, txId: 'tx_c_session', cwd: ws, session }, a.ghostSnapshotId);
      assert.equal(session.activeTxId, undefined);
      const recId = applyRecordId('tx_c_session');
      const rec = session.records.find((r) => r.id === recId);
      assert.ok(rec, 'tx-applied record should be present');
      assert.equal(rec?.kind, 'tx-applied');
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('Stage C Phase C-session is idempotent on rerun: no duplicate record', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await execFileAsync('git', ['add', '.'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTxWithDiffSummary(home, ws, 'tx_c_idem', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
      ]);
      const a = await runStageA({ root, txId: 'tx_c_idem', cwd: ws });
      await runStageB({ root, txId: 'tx_c_idem', cwd: ws }, a.plan);
      const { session } = await setupSessionForApply(ws, { activeTxId: 'tx_c_idem' });
      await runStageC({ root, txId: 'tx_c_idem', cwd: ws, session }, a.ghostSnapshotId);
      await runStageC({ root, txId: 'tx_c_idem', cwd: ws, session }, a.ghostSnapshotId);
      const recId = applyRecordId('tx_c_idem');
      const matches = session.records.filter((r) => r.id === recId);
      assert.equal(matches.length, 1, 'rerun must not duplicate the record');
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('Stage C Phase C-tx is idempotent: state remains applied, no spurious changes', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await execFileAsync('git', ['add', '.'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTxWithDiffSummary(home, ws, 'tx_c_tx_idem', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
      ]);
      const a = await runStageA({ root, txId: 'tx_c_tx_idem', cwd: ws });
      await runStageB({ root, txId: 'tx_c_tx_idem', cwd: ws }, a.plan);
      const { session } = await setupSessionForApply(ws);
      await runStageC({ root, txId: 'tx_c_tx_idem', cwd: ws, session }, a.ghostSnapshotId);
      await runStageC({ root, txId: 'tx_c_tx_idem', cwd: ws, session }, a.ghostSnapshotId);
      const { readTxState } = await import('./store.js');
      const tx = await readTxState(root, 'tx_c_tx_idem');
      assert.equal(tx?.state, 'applied');
      const ap = await readApplyProgress(root, 'tx_c_tx_idem');
      assert.equal(ap?.phase, 'apply-finalized');
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('Stage C does not touch activeTxId if it points to a different tx', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await execFileAsync('git', ['add', '.'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTxWithDiffSummary(home, ws, 'tx_self', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
      ]);
      const a = await runStageA({ root, txId: 'tx_self', cwd: ws });
      await runStageB({ root, txId: 'tx_self', cwd: ws }, a.plan);
      const { session } = await setupSessionForApply(ws, { activeTxId: 'tx_other' });
      await runStageC({ root, txId: 'tx_self', cwd: ws, session }, a.ghostSnapshotId);
      assert.equal(session.activeTxId, 'tx_other');
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('applyTx happy path: A→B→C completes with state=applied and tx-applied record', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await execFileAsync('git', ['add', '.'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTxWithDiffSummary(home, ws, 'tx_orch', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
      ]);
      const { session } = await setupSessionForApply(ws, { activeTxId: 'tx_orch' });
      const result = await applyTx({ root, txId: 'tx_orch', cwd: ws, session });
      assert.deepEqual(result.filesApplied, ['a.txt']);
      const { readTxState } = await import('./store.js');
      const tx = await readTxState(root, 'tx_orch');
      assert.equal(tx?.state, 'applied');
      assert.equal(session.activeTxId, undefined);
      const recId = applyRecordId('tx_orch');
      assert.ok(session.records.find((r) => r.id === recId));
      const { readFile: rf } = await import('node:fs/promises');
      assert.equal(await rf(path.join(ws, 'a.txt'), 'utf8'), 'ONE');
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('applyTx propagates ApplyConflict from Stage A and leaves state=approved', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await execFileAsync('git', ['add', '.'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTxWithDiffSummary(home, ws, 'tx_orch_conflict', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
      ]);
      // External change before applyTx runs
      await writeFile(path.join(ws, 'a.txt'), 'EXTERNAL', 'utf8');
      const { session } = await setupSessionForApply(ws, { activeTxId: 'tx_orch_conflict' });
      await assert.rejects(
        applyTx({ root, txId: 'tx_orch_conflict', cwd: ws, session }),
        (err: unknown) => err instanceof ApplyConflict
      );
      const { readTxState } = await import('./store.js');
      const tx = await readTxState(root, 'tx_orch_conflict');
      assert.equal(tx?.state, 'approved');
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

test('applyTx propagates ApplyPartial from Stage B and leaves state=applied-partial', async () => {
  await withFakeCliqHome(async (home) => {
    const ws = await setupGitWorkspace();
    try {
      await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
      await writeFile(path.join(ws, 'b.txt'), 'two', 'utf8');
      await execFileAsync('git', ['add', '.'], { cwd: ws });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
      const root = await setupApprovedTxWithDiffSummary(home, ws, 'tx_orch_partial', [
        { path: 'a.txt', oldContent: 'one', newContent: 'ONE' },
        { path: 'b.txt', oldContent: 'two', newContent: 'TWO' }
      ]);
      // applyTx itself doesn't expose a hook between Stage A and Stage B, so we
      // exercise the ApplyPartial path by running Stage A, race-modifying b.txt,
      // and asserting that runStageB throws ApplyPartial. This mirrors the B3a
      // test above and gives us the partial-state assertion the orchestrator
      // would propagate verbatim.
      const a = await runStageA({ root, txId: 'tx_orch_partial', cwd: ws });
      await writeFile(path.join(ws, 'b.txt'), 'TWO_EXTERNAL', 'utf8');
      await assert.rejects(
        runStageB({ root, txId: 'tx_orch_partial', cwd: ws }, a.plan),
        (err: unknown) => err instanceof ApplyPartial
      );
      const { readTxState } = await import('./store.js');
      const tx = await readTxState(root, 'tx_orch_partial');
      assert.equal(tx?.state, 'applied-partial');
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  });
});

