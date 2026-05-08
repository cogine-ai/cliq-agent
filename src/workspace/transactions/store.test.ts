import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { resolveTxRoot, txDir, applyProgressPath, abortProgressPath, stateJsonPath, auditJsonPath, readTxState, writeTxState, createTx, readApplyProgress, writeApplyProgress, deleteApplyProgress, readAbortProgress, writeAbortProgress, deleteAbortProgress, withTxLock, appendAudit, readAudit, makeTxId, writeDiff, readDiff } from './store.js';

test('resolveTxRoot honors CLIQ_HOME', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-home-'));
  try {
    const root = resolveTxRoot(home);
    assert.equal(root, path.join(home, 'tx'));
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('per-tx paths are under the resolved root', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-paths-'));
  try {
    const root = resolveTxRoot(home);
    assert.equal(txDir(root, 'tx_x'), path.join(root, 'tx_x'));
    assert.equal(stateJsonPath(root, 'tx_x'), path.join(root, 'tx_x', 'state.json'));
    assert.equal(applyProgressPath(root, 'tx_x'), path.join(root, 'tx_x', 'apply-progress.json'));
    assert.equal(abortProgressPath(root, 'tx_x'), path.join(root, 'tx_x', 'abort-progress.json'));
    assert.equal(auditJsonPath(root, 'tx_x'), path.join(root, 'tx_x', 'audit.json'));
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('writeTxState then readTxState round-trips', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-rw-'));
  try {
    const root = resolveTxRoot(home);
    const tx = await createTx(root, {
      id: 'tx_01HX',
      kind: 'edit',
      workspaceId: 'ws_test',
      sessionId: 'sess_test',
      workspaceRealPath: '/tmp/ws'
    });
    assert.equal(tx.state, 'staging');
    const loaded = await readTxState(root, 'tx_01HX');
    assert.deepEqual(loaded, tx);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('readTxState returns null for missing tx', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-missing-'));
  try {
    const loaded = await readTxState(resolveTxRoot(home), 'tx_nope');
    assert.equal(loaded, null);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('writeApplyProgress then readApplyProgress preserves phase', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-apply-progress-'));
  try {
    const root = resolveTxRoot(home);
    const txId = 'tx_apply_01HX';
    const applyProg = {
      phase: 'apply-pending' as const,
      ghostSnapshotId: 'snap_abc',
      startedAt: '2026-05-06T00:00:00Z',
      filesPlanned: ['a.ts', 'b.ts'],
      filesWritten: []
    };
    await writeApplyProgress(root, txId, applyProg);
    const loaded = await readApplyProgress(root, txId);
    assert.deepEqual(loaded, applyProg);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('writeAbortProgress then readAbortProgress preserves phase', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-abort-progress-'));
  try {
    const root = resolveTxRoot(home);
    const txId = 'tx_abort_01HX';
    const abortProg = {
      phase: 'aborting' as const,
      reason: 'user-abort' as const,
      startedAt: '2026-05-06T00:00:00Z',
      ts: '2026-05-06T00:00:01Z'
    };
    await writeAbortProgress(root, txId, abortProg);
    const loaded = await readAbortProgress(root, txId);
    assert.deepEqual(loaded, abortProg);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('deleteApplyProgress is idempotent on missing file', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-delete-apply-'));
  try {
    const root = resolveTxRoot(home);
    const txId = 'tx_delete_01HX';
    // Should not throw even though file doesn't exist
    await deleteApplyProgress(root, txId);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('deleteAbortProgress is idempotent on missing file', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-delete-abort-'));
  try {
    const root = resolveTxRoot(home);
    const txId = 'tx_delete_abort_01HX';
    // Should not throw even though file doesn't exist
    await deleteAbortProgress(root, txId);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('acquireTxLock serializes concurrent operations on the same txId', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-lock-'));
  try {
    const root = resolveTxRoot(home);
    await createTx(root, { id: 'tx_lock', kind: 'edit', workspaceId: 'w', sessionId: 's', workspaceRealPath: '/tmp/ws' });
    // Assert SERIALIZATION (no interleaving), not acquisition ORDER.
    // The lock primitive does not promise FIFO/fairness, so under load `b`
    // can win the race; what matters is that one critical section completes
    // entirely before the other starts.
    const order: string[] = [];
    const work = (label: string, durationMs: number) =>
      withTxLock(root, 'tx_lock', async () => {
        order.push(`${label}-start`);
        await new Promise((r) => setTimeout(r, durationMs));
        order.push(`${label}-end`);
      });
    await Promise.all([work('a', 25), work('b', 5)]);
    // Whichever side acquired first must have finished before the other started.
    assert.equal(order.length, 4, 'both critical sections must run');
    const [first0, first1, second0, second1] = order;
    assert.ok(first0.endsWith('-start'));
    assert.ok(first1.endsWith('-end'));
    assert.equal(first0.split('-')[0], first1.split('-')[0], 'first holder must finish before second');
    assert.ok(second0.endsWith('-start'));
    assert.ok(second1.endsWith('-end'));
    assert.equal(second0.split('-')[0], second1.split('-')[0], 'second holder must run as one block');
    assert.notEqual(first0.split('-')[0], second0.split('-')[0], 'each holder runs once');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('appendAudit writes JSONL entries in order', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-audit-'));
  try {
    const root = resolveTxRoot(home);
    await createTx(root, { id: 'tx_a', kind: 'edit', workspaceId: 'w', sessionId: 's', workspaceRealPath: '/tmp' });
    await appendAudit(root, 'tx_a', { ts: '2026-05-06T00:00:00Z', from: null, to: 'staging', by: 'cli' });
    await appendAudit(root, 'tx_a', { ts: '2026-05-06T00:00:01Z', from: 'staging', to: 'finalized', by: 'cli' });
    const entries = await readAudit(root, 'tx_a');
    assert.equal(entries.length, 2);
    assert.equal(entries[1].to, 'finalized');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('writeDiff then readDiff round-trips', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-diff-rw-'));
  try {
    const root = resolveTxRoot(home);
    await createTx(root, { id: 'tx_diff', kind: 'edit', workspaceId: 'w', sessionId: 's', workspaceRealPath: '/tmp' });
    const diff = {
      files: [{ path: 'a.txt', op: 'modify' as const, oldContent: 'one', newContent: 'ONE' }],
      outOfBand: []
    };
    await writeDiff(root, 'tx_diff', diff);
    const loaded = await readDiff(root, 'tx_diff');
    assert.deepEqual(loaded, diff);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('makeTxId returns lexicographically sortable IDs with tx_ prefix', () => {
  const a = makeTxId(1700000000000);
  const b = makeTxId(1700000000001);
  assert.match(a, /^tx_[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.match(b, /^tx_[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.ok(a < b);
});

test('txDir rejects path-traversal txIds and accepts well-formed ones', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-traversal-'));
  try {
    const root = resolveTxRoot(home);
    // Each of these would, if passed through `path.join` unchecked, escape
    // the per-tx directory or write to an attacker-chosen path.
    assert.throws(() => txDir(root, 'tx_..'), /invalid tx id/i);
    assert.throws(() => txDir(root, 'tx_../foo'), /invalid tx id/i);
    assert.throws(() => txDir(root, '..'), /invalid tx id/i);
    assert.throws(() => txDir(root, '/etc/passwd'), /invalid tx id/i);
    assert.throws(() => txDir(root, 'tx_a/../b'), /invalid tx id/i);
    assert.throws(() => txDir(root, 'tx_a\\b'), /invalid tx id/i);
    assert.throws(() => txDir(root, 'tx_'), /invalid tx id/i); // empty body
    assert.throws(() => txDir(root, 'no_prefix'), /invalid tx id/i);
    assert.throws(() => txDir(root, ''), /invalid tx id/i);
    // Production-shaped IDs and short test fixtures both pass.
    const real = makeTxId();
    assert.equal(txDir(root, real), path.join(root, real));
    assert.equal(txDir(root, 'tx_a'), path.join(root, 'tx_a'));
    assert.equal(txDir(root, 'tx_test_lock_01HX'), path.join(root, 'tx_test_lock_01HX'));
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
