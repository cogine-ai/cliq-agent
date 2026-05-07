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
  getActiveTx,
  finalizeTx,
  validateTx,
  approveTx,
  type CoordinatorContext
} from './coordinator.js';
import { createSession, mutateSession } from '../../session/store.js';
import type { Session } from '../../session/types.js';
import { openRecordId } from './types.js';
import { resolveTxRoot, writeTxState, writeDiff, readTxState, overlayDir } from './store.js';
import { createOverlayWriter } from './overlay.js';
import type { TxValidatorsConfig, TxStagedViewConfig } from '../config.js';

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

test('getActiveTx returns null when session.activeTxId is undefined', async () => {
  await withCoordinatorEnv(async ({ ctx }) => {
    ctx.session.activeTxId = undefined;
    const tx = await getActiveTx(ctx);
    assert.equal(tx, null);
  });
});

test('getActiveTx returns the Transaction for session.activeTxId', async () => {
  await withCoordinatorEnv(async ({ ctx }) => {
    const created = await openTx(ctx, { explicit: false });
    const got = await getActiveTx(ctx);
    assert.ok(got);
    assert.equal(got?.id, created.id);
  });
});

test('getActiveTx returns null when activeTxId points to a missing tx (defensive)', async () => {
  await withCoordinatorEnv(async ({ ctx }) => {
    ctx.session.activeTxId = 'tx_does_not_exist';
    const tx = await getActiveTx(ctx);
    assert.equal(tx, null);
  });
});

test('finalizeTx writes diff.json, sets diffSummary, transitions state to finalized', async () => {
  await withCoordinatorEnv(async ({ ctx, ws, home }) => {
    await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
    const tx = await openTx(ctx, { explicit: false });
    const root = resolveTxRoot(home);
    // Stage an overlay edit to simulate runner-driven write.
    const { createOverlayWriter } = await import('./overlay.js');
    const { overlayDir } = await import('./store.js');
    const writer = createOverlayWriter(ws, overlayDir(root, tx.id));
    await writer.replaceText('a.txt', 'one', 'ONE');

    const { finalizeTx } = await import('./coordinator.js');
    const result = await finalizeTx(ctx, tx.id);
    assert.equal(result.diffSummary.filesChanged, 1);
    assert.deepEqual(result.diffSummary.modifies, ['a.txt']);

    const { readDiff } = await import('./store.js');
    const diff = await readDiff(root, tx.id);
    assert.ok(diff);
    assert.equal(diff?.files.length, 1);

    const after = await readTxState(root, tx.id);
    assert.equal(after?.state, 'finalized');
    assert.equal(after?.diffSummary?.filesChanged, 1);
  });
});

test('finalizeTx with empty overlay produces zero-file diff', async () => {
  await withCoordinatorEnv(async ({ ctx, home }) => {
    const tx = await openTx(ctx, { explicit: false });
    const root = resolveTxRoot(home);
    const { finalizeTx } = await import('./coordinator.js');
    const result = await finalizeTx(ctx, tx.id);
    assert.equal(result.diffSummary.filesChanged, 0);
    const after = await readTxState(root, tx.id);
    assert.equal(after?.state, 'finalized');
  });
});

test('validateTx runs validators on staged view, persists results, transitions state to validated', async () => {
  await withCoordinatorEnv(async ({ ctx, ws, home }) => {
    await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
    const tx = await openTx(ctx, { explicit: false });
    const root = resolveTxRoot(home);
    const writer = createOverlayWriter(ws, overlayDir(root, tx.id));
    await writer.replaceText('a.txt', 'one', 'ONE');
    await finalizeTx(ctx, tx.id);

    const validatorsConfig: TxValidatorsConfig = { disabled: ['builtin:index-clean', 'builtin:size-limit'] }; // only diff-sanity
    const stagedViewConfig: TxStagedViewConfig = { copyMode: 'copy', bindPaths: [] };
    const result = await validateTx(ctx, tx.id, validatorsConfig, stagedViewConfig);
    assert.equal(result.validators.length, 1);
    assert.equal(result.validators[0].name, 'builtin:diff-sanity');
    assert.deepEqual(result.blockingFailures, []); // diff-sanity passes on a clean modify

    const after = await readTxState(root, tx.id);
    assert.equal(after?.state, 'validated');
    assert.equal(after?.validators?.length, 1);
  });
});

test('validateTx flags blocking failures when a validator fails', async () => {
  await withCoordinatorEnv(async ({ ctx, ws, home }) => {
    await writeFile(path.join(ws, 'a.txt'), 'a', 'utf8');
    const tx = await openTx(ctx, { explicit: false });
    const root = resolveTxRoot(home);
    const writer = createOverlayWriter(ws, overlayDir(root, tx.id));
    // NUL byte triggers diff-sanity binary heuristic.
    await writer.replaceText('a.txt', 'a', 'a\u0000b');
    await finalizeTx(ctx, tx.id);

    const result = await validateTx(ctx, tx.id, { disabled: ['builtin:index-clean', 'builtin:size-limit'] }, { copyMode: 'copy', bindPaths: [] });
    assert.deepEqual(result.blockingFailures, ['builtin:diff-sanity']);

    const after = await readTxState(root, tx.id);
    assert.equal(after?.state, 'validated');
    assert.deepEqual(after?.blockingFailures, ['builtin:diff-sanity']);
  });
});

test('approveTx transitions state to approved when no blocking failures', async () => {
  await withCoordinatorEnv(async ({ ctx, ws, home }) => {
    await writeFile(path.join(ws, 'a.txt'), 'one', 'utf8');
    const tx = await openTx(ctx, { explicit: false });
    const root = resolveTxRoot(home);
    const writer = createOverlayWriter(ws, overlayDir(root, tx.id));
    await writer.replaceText('a.txt', 'one', 'ONE');
    await finalizeTx(ctx, tx.id);
    await validateTx(ctx, tx.id, { disabled: ['builtin:index-clean', 'builtin:size-limit'] }, { copyMode: 'copy', bindPaths: [] });

    const result = await approveTx(ctx, tx.id, {});
    assert.equal(result.ok, true);
    const after = await readTxState(root, tx.id);
    assert.equal(after?.state, 'approved');
  });
});

test('approveTx blocks on uncovered blocking failures and returns the list', async () => {
  await withCoordinatorEnv(async ({ ctx, ws, home }) => {
    await writeFile(path.join(ws, 'a.txt'), 'a', 'utf8');
    const tx = await openTx(ctx, { explicit: false });
    const root = resolveTxRoot(home);
    const writer = createOverlayWriter(ws, overlayDir(root, tx.id));
    await writer.replaceText('a.txt', 'a', 'a\u0000b');
    await finalizeTx(ctx, tx.id);
    await validateTx(ctx, tx.id, { disabled: ['builtin:index-clean', 'builtin:size-limit'] }, { copyMode: 'copy', bindPaths: [] });

    const result = await approveTx(ctx, tx.id, {});
    assert.equal(result.ok, false);
    if (!result.ok) assert.deepEqual(result.uncoveredFailures, ['builtin:diff-sanity']);
    const after = await readTxState(root, tx.id);
    assert.equal(after?.state, 'validated'); // unchanged
  });
});

test('approveTx allows transition when all failures are covered by overrides', async () => {
  await withCoordinatorEnv(async ({ ctx, ws, home }) => {
    await writeFile(path.join(ws, 'a.txt'), 'a', 'utf8');
    const tx = await openTx(ctx, { explicit: false });
    const root = resolveTxRoot(home);
    const writer = createOverlayWriter(ws, overlayDir(root, tx.id));
    await writer.replaceText('a.txt', 'a', 'a\u0000b');
    await finalizeTx(ctx, tx.id);
    await validateTx(ctx, tx.id, { disabled: ['builtin:index-clean', 'builtin:size-limit'] }, { copyMode: 'copy', bindPaths: [] });

    const result = await approveTx(ctx, tx.id, { overrides: ['builtin:diff-sanity'], reason: 'bin file is intentional' });
    assert.equal(result.ok, true);
    const after = await readTxState(root, tx.id);
    assert.equal(after?.state, 'approved');
    assert.equal(after?.overridesApplied?.length, 1);
    assert.equal(after?.overridesApplied?.[0].validatorName, 'builtin:diff-sanity');
  });
});

test('approveTx with overrideAll covers every blocking failure', async () => {
  await withCoordinatorEnv(async ({ ctx, ws, home }) => {
    await writeFile(path.join(ws, 'a.txt'), 'a', 'utf8');
    const tx = await openTx(ctx, { explicit: false });
    const root = resolveTxRoot(home);
    const writer = createOverlayWriter(ws, overlayDir(root, tx.id));
    await writer.replaceText('a.txt', 'a', 'a\u0000b');
    await finalizeTx(ctx, tx.id);
    await validateTx(ctx, tx.id, { disabled: ['builtin:index-clean', 'builtin:size-limit'] }, { copyMode: 'copy', bindPaths: [] });

    const result = await approveTx(ctx, tx.id, { overrideAll: true, reason: 'mass override' });
    assert.equal(result.ok, true);
    const after = await readTxState(root, tx.id);
    assert.equal(after?.state, 'approved');
  });
});
