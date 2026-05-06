import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { runStageA, runStageB, ApplyRejected, ApplyConflict, ApplyPartial } from './apply.js';
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
