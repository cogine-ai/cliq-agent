import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  openTx,
  applyTx as coordApply,
  abortTx as coordAbort,
  type CoordinatorContext
} from './coordinator.js';
import {
  resolveTxRoot,
  readTxState,
  writeTxState,
  writeDiff
} from './store.js';
import { applyRecordId, abortRecordId, openRecordId } from './types.js';
import { createSession, mutateSession } from '../../session/store.js';
import type { Session } from '../../session/types.js';

const execFileAsync = promisify(execFile);

async function setupGitWorkspace(): Promise<string> {
  const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-int-'));
  await execFileAsync('git', ['init', '-b', 'main'], { cwd: ws });
  await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: ws });
  await execFileAsync('git', ['config', 'user.name', 't'], { cwd: ws });
  return ws;
}

type IntEnv = { home: string; ws: string; ctx: CoordinatorContext; session: Session };

async function withEnv<T>(fn: (env: IntEnv) => Promise<T>): Promise<T> {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-int-home-'));
  const ws = await setupGitWorkspace();
  const prev = process.env.CLIQ_HOME;
  process.env.CLIQ_HOME = home;
  try {
    const session = createSession(ws);
    // Persist session so mutateSession's read-modify-write roundtrip works.
    await mutateSession(ws, session, () => {});
    const ctx: CoordinatorContext = {
      cwd: ws,
      session,
      cliqHome: home,
      workspaceId: 'ws_int',
      sessionId: session.id,
      workspaceRealPath: ws
    };
    return await fn({ home, ws, ctx, session });
  } finally {
    if (prev === undefined) delete process.env.CLIQ_HOME;
    else process.env.CLIQ_HOME = prev;
    await rm(home, { recursive: true, force: true });
    await rm(ws, { recursive: true, force: true });
  }
}

async function approveAndDiff(
  home: string,
  txId: string,
  files: { path: string; oldContent: string; newContent: string }[]
): Promise<void> {
  const root = resolveTxRoot(home);
  const tx = (await readTxState(root, txId))!;
  await writeTxState(root, {
    ...tx,
    state: 'approved',
    diffSummary: {
      filesChanged: files.length,
      additions: 0,
      deletions: 0,
      creates: [],
      modifies: files.map((f) => f.path),
      deletes: []
    }
  });
  await writeDiff(root, txId, {
    files: files.map((f) => ({
      path: f.path,
      op: 'modify' as const,
      oldContent: f.oldContent,
      newContent: f.newContent
    })),
    outOfBand: []
  });
}

test('e2e: explicit tx open → approve → apply produces expected file content + session records', async () => {
  await withEnv(async ({ home, ws, ctx, session }) => {
    await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
    await execFileAsync('git', ['add', '.'], { cwd: ws });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });

    const tx = await openTx(ctx, { explicit: true, name: 'rename-foo' });
    await approveAndDiff(home, tx.id, [
      { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
    ]);

    const result = await coordApply(ctx, tx.id);
    assert.equal(result.ok, true);

    // File content reflects the diff.
    assert.equal(await readFile(path.join(ws, 'a.txt'), 'utf8'), 'ONE');

    // Session contains paired tx-opened + tx-applied with same txId.
    const opened = session.records.find((r) => r.id === openRecordId(tx.id));
    const applied = session.records.find((r) => r.id === applyRecordId(tx.id));
    assert.ok(opened);
    assert.ok(applied);
    if (opened?.kind === 'tx-opened' && applied?.kind === 'tx-applied') {
      assert.equal(opened.meta.txId, applied.meta.txId);
      assert.equal(opened.meta.name, 'rename-foo');
    }

    // activeTxId is cleared after apply.
    assert.equal(session.activeTxId, undefined);
  });
});

test('e2e: tx abort from approved discards diff; no real workspace change', async () => {
  await withEnv(async ({ home, ws, ctx, session }) => {
    await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
    await execFileAsync('git', ['add', '.'], { cwd: ws });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });

    const tx = await openTx(ctx, { explicit: true });
    await approveAndDiff(home, tx.id, [
      { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
    ]);

    const result = await coordAbort(ctx, tx.id, { reason: 'user-abort' });
    assert.equal(result.ok, true);

    // File unchanged.
    assert.equal(await readFile(path.join(ws, 'a.txt'), 'utf8'), 'one');

    // Session has tx-aborted matching the open.
    const aborted = session.records.find((r) => r.id === abortRecordId(tx.id));
    assert.ok(aborted);

    // activeTxId cleared.
    assert.equal(session.activeTxId, undefined);
  });
});

test('e2e: applying with conflicting on-disk content surfaces ApplyConflict', async () => {
  await withEnv(async ({ home, ws, ctx }) => {
    await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
    await execFileAsync('git', ['add', '.'], { cwd: ws });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });

    const tx = await openTx(ctx, { explicit: false });
    await approveAndDiff(home, tx.id, [
      { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
    ]);
    // External change before apply.
    await writeFile(path.join(ws, 'a.txt'), 'EXTERNAL', 'utf8');

    const result = await coordApply(ctx, tx.id);
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error, 'conflict');
    }
  });
});

test('crash between Stage B5 and Stage C: recovery completes Stage C idempotently', async () => {
  await withEnv(async ({ home, ws, ctx, session }) => {
    await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
    await execFileAsync('git', ['add', '.'], { cwd: ws });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });

    const tx = await openTx(ctx, { explicit: false });
    await approveAndDiff(home, tx.id, [
      { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
    ]);

    // Simulate Stage A + B without Stage C: drive the underlying stages
    // directly so apply-progress.phase = 'apply-committed' is on disk while
    // tx.state remains 'approved' — exactly the state we'd see if a crash
    // hit between B5 and C1.
    const { runStageA, runStageB } = await import('./apply.js');
    const root = resolveTxRoot(home);
    const a = await runStageA({ root, txId: tx.id, cwd: ws });
    await runStageB({ root, txId: tx.id, cwd: ws }, a.plan);

    // Run recoverAll — should detect 'apply-committed' and complete Stage C.
    const { recoverAll } = await import('./recovery.js');
    const outcomes = await recoverAll(root, { cwd: ws, session });
    assert.equal(outcomes.length, 1);
    assert.equal(outcomes[0].action, 'apply-committed-stage-c');

    // Final state.
    const finalTx = await readTxState(root, tx.id);
    assert.equal(finalTx?.state, 'applied');
    assert.equal(await readFile(path.join(ws, 'a.txt'), 'utf8'), 'ONE');
    assert.ok(session.records.find((r) => r.id === applyRecordId(tx.id)));
  });
});

test('concurrency: two concurrent applyTx serialize via withTxLock; only one wins', async () => {
  await withEnv(async ({ home, ws, ctx }) => {
    await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
    await execFileAsync('git', ['add', '.'], { cwd: ws });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });

    const tx = await openTx(ctx, { explicit: false });
    await approveAndDiff(home, tx.id, [
      { path: 'a.txt', oldContent: 'one', newContent: 'ONE' }
    ]);

    // Launch two concurrent applies. The second should reject with
    // apply-already-in-flight or already-applied.
    const a = coordApply(ctx, tx.id);
    const b = coordApply(ctx, tx.id);
    const [ra, rb] = await Promise.all([a, b]);

    const successes = [ra, rb].filter((r) => r.ok);
    const failures = [ra, rb].filter((r) => !r.ok);
    // Exactly one wins.
    assert.equal(successes.length, 1);
    assert.equal(failures.length, 1);
    const failure = failures[0];
    if (!failure.ok) {
      assert.match(failure.message, /already in flight|state is applied/i);
    }
  });
});
