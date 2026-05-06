import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { resolveTxRoot, txDir, applyProgressPath, abortProgressPath, stateJsonPath, auditJsonPath, readTxState, writeTxState, createTx } from './store.js';

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
