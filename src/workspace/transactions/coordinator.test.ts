import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  openTx,
  applyTx,
  abortTx,
  getTxStatus,
  listTx,
  type CoordinatorContext
} from './coordinator.js';
import { createSession, mutateSession } from '../../session/store.js';
import type { Session } from '../../session/types.js';
import { openRecordId } from './types.js';
import { resolveTxRoot, writeTxState, writeDiff, readTxState } from './store.js';

const execFileAsync = promisify(execFile);

async function setupGitWorkspace(): Promise<string> {
  const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-coord-ws-'));
  await execFileAsync('git', ['init', '-b', 'main'], { cwd: ws });
  await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: ws });
  await execFileAsync('git', ['config', 'user.name', 't'], { cwd: ws });
  return ws;
}

type Env = { home: string; ws: string; ctx: CoordinatorContext; session: Session };

async function withCoordinatorEnv<T>(fn: (env: Env) => Promise<T>): Promise<T> {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-coord-home-'));
  const ws = await setupGitWorkspace();
  const prev = process.env.CLIQ_HOME;
  process.env.CLIQ_HOME = home;
  try {
    const session = createSession(ws);
    // Persist the freshly created session so mutateSession can read+write it.
    await mutateSession(ws, session, () => {});
    const ctx: CoordinatorContext = {
      cwd: ws,
      session,
      cliqHome: home,
      workspaceId: 'ws_test',
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

test('coordinator.openTx({explicit: true}) writes tx-opened session record with deterministic id', async () => {
  await withCoordinatorEnv(async ({ ctx, session }) => {
    const tx = await openTx(ctx, { explicit: true, name: 'feature' });
    assert.match(tx.id, /^tx_/);
    assert.equal(tx.state, 'staging');
    const recId = openRecordId(tx.id);
    const rec = session.records.find((r) => r.id === recId);
    assert.ok(rec);
    assert.equal(rec?.kind, 'tx-opened');
    if (rec?.kind === 'tx-opened') {
      assert.equal(rec.meta.name, 'feature');
      assert.equal(rec.meta.explicit, true);
      assert.equal(rec.meta.txId, tx.id);
    }
    assert.equal(session.activeTxId, tx.id);
  });
});

test('coordinator.openTx({explicit: false}) does not write tx-opened record (implicit)', async () => {
  await withCoordinatorEnv(async ({ ctx, session }) => {
    const tx = await openTx(ctx, { explicit: false });
    assert.equal(session.records.filter((r) => r.kind === 'tx-opened').length, 0);
    assert.equal(session.activeTxId, tx.id);
  });
});

test('coordinator.listTx returns all tx in createdAt order', async () => {
  await withCoordinatorEnv(async ({ ctx }) => {
    const a = await openTx(ctx, { explicit: true, name: 'a' });
    await new Promise((r) => setTimeout(r, 5));
    const b = await openTx(ctx, { explicit: true, name: 'b' });
    const list = await listTx(ctx);
    assert.equal(list.length, 2);
    assert.equal(list[0].id, a.id);
    assert.equal(list[1].id, b.id);
  });
});

test('coordinator.getTxStatus returns null for missing tx', async () => {
  await withCoordinatorEnv(async ({ ctx }) => {
    const status = await getTxStatus(ctx, 'tx_nope');
    assert.equal(status, null);
  });
});

test('coordinator.applyTx returns rejected when tx is not approved', async () => {
  await withCoordinatorEnv(async ({ ctx }) => {
    const tx = await openTx(ctx, { explicit: false });
    // tx is in 'staging' state.
    const result = await applyTx(ctx, tx.id);
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error, 'rejected');
    }
  });
});

test('coordinator.applyTx happy path: approved tx applies and writes tx-applied record', async () => {
  await withCoordinatorEnv(async ({ ctx, ws, home, session }) => {
    await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
    await execFileAsync('git', ['add', '.'], { cwd: ws });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
    const tx = await openTx(ctx, { explicit: true });
    const root = resolveTxRoot(home);
    // Manually approve + diff (simulating the validate/approve pipeline).
    const txState = (await readTxState(root, tx.id))!;
    await writeTxState(root, {
      ...txState,
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
    await writeDiff(root, tx.id, {
      files: [{ path: 'a.txt', op: 'modify', oldContent: 'one', newContent: 'ONE' }],
      outOfBand: []
    });
    const result = await applyTx(ctx, tx.id);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.deepEqual(result.filesApplied, ['a.txt']);
    }
    // Verify session has tx-opened then tx-applied with matching txId.
    const opened = session.records.find((r) => r.kind === 'tx-opened');
    const applied = session.records.find((r) => r.kind === 'tx-applied');
    assert.ok(opened);
    assert.ok(applied);
    if (opened?.kind === 'tx-opened' && applied?.kind === 'tx-applied') {
      assert.equal(opened.meta.txId, applied.meta.txId);
    }
  });
});

test('coordinator.abortTx happy path: tx in approved state aborts cleanly', async () => {
  await withCoordinatorEnv(async ({ ctx, home, session }) => {
    const tx = await openTx(ctx, { explicit: true });
    const root = resolveTxRoot(home);
    const txState = (await readTxState(root, tx.id))!;
    await writeTxState(root, {
      ...txState,
      state: 'approved',
      diffSummary: {
        filesChanged: 0,
        additions: 0,
        deletions: 0,
        creates: [],
        modifies: [],
        deletes: []
      }
    });
    const result = await abortTx(ctx, tx.id, { reason: 'user-abort' });
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.aborted, true);
    }
    const recs = session.records.filter((r) => r.kind === 'tx-aborted');
    assert.equal(recs.length, 1);
  });
});
