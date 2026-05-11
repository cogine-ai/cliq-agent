import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { appendBashEffect } from './bash-effects.js';
import {
  appendAudit,
  createTx,
  resolveTxRoot,
  validatorsDir,
  writeDiff,
  writeTxState
} from './store.js';
import {
  formatTxApplyReview,
  formatTxDiff,
  formatTxShow,
  formatTxValidators,
  readTxReviewSnapshot
} from './inspect.js';

async function makeReviewFixture() {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tx-inspect-'));
  const root = resolveTxRoot(home);
  const txId = 'tx_inspect';
  const tx = await createTx(root, {
    id: txId,
    kind: 'edit',
    workspaceId: 'ws_test',
    sessionId: 'sess_test',
    workspaceRealPath: '/tmp/ws'
  });
  await writeDiff(root, txId, {
    files: [
      {
        path: 'a.txt',
        op: 'modify',
        oldContent: 'one\n',
        newContent: 'one\ntwo\n'
      }
    ],
    outOfBand: []
  });
  await appendAudit(root, txId, {
    ts: '2026-05-11T00:00:00Z',
    from: null,
    to: 'staging',
    by: 'cli'
  });
  await appendBashEffect(root, txId, {
    command: 'npm test',
    exitCode: 0,
    ts: '2026-05-11T00:00:01Z',
    pathsChanged: ['package-lock.json'],
    outOfBand: true
  });
  await mkdir(validatorsDir(root, txId), { recursive: true });
  await writeFile(
    path.join(validatorsDir(root, txId), 'tsc.json'),
    JSON.stringify(
      {
        name: 'tsc',
        severity: 'blocking',
        status: 'pass',
        durationMs: 123,
        message: 'ok'
      },
      null,
      2
    ),
    'utf8'
  );
  await writeTxState(root, {
    ...tx,
    state: 'validated',
    diffSummary: {
      filesChanged: 1,
      additions: 1,
      deletions: 0,
      creates: [],
      modifies: ['a.txt'],
      deletes: []
    },
    validators: [{ name: 'tsc', severity: 'blocking', status: 'pass', durationMs: 123 }],
    blockingFailures: []
  });
  return { home, root, txId };
}

test('readTxReviewSnapshot returns state, diff, validators, bash effects, audit, and artifactRef', async () => {
  const { home, root, txId } = await makeReviewFixture();
  try {
    const snapshot = await readTxReviewSnapshot({ root, txId });
    assert.equal(snapshot.tx.id, txId);
    assert.equal(snapshot.diff?.files.length, 1);
    assert.equal(snapshot.validatorResults[0]?.name, 'tsc');
    assert.equal(snapshot.validatorArtifactResults[0]?.name, 'tsc');
    assert.equal(snapshot.bashEffects[0]?.command, 'npm test');
    assert.equal(snapshot.audit[0]?.to, 'staging');
    assert.equal(snapshot.artifactRef, `tx/${txId}/`);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('readTxReviewSnapshot returns validator artifact errors for invalid JSON', async () => {
  const { home, root, txId } = await makeReviewFixture();
  try {
    await writeFile(path.join(validatorsDir(root, txId), 'bad.json'), '{', 'utf8');
    const snapshot = await readTxReviewSnapshot({ root, txId });
    assert.deepEqual(snapshot.validatorArtifactErrors, ['bad.json: invalid JSON']);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('formatters render deterministic transaction review output', async () => {
  const { home, root, txId } = await makeReviewFixture();
  try {
    const snapshot = await readTxReviewSnapshot({ root, txId });

    assert.equal(formatTxDiff(snapshot), 'M a.txt (net +1/-0)');
    assert.match(formatTxShow(snapshot), /tx: tx_inspect/);
    assert.match(formatTxShow(snapshot), /artifact: tx\/tx_inspect\//);
    assert.equal(formatTxValidators(snapshot), 'PASS blocking tsc 123ms');
    assert.match(formatTxApplyReview(snapshot), /Transaction tx_inspect is ready to apply/);
    assert.match(formatTxApplyReview(snapshot), /Bash effects: 1/);
    assert.match(formatTxApplyReview(snapshot), /Artifact: tx\/tx_inspect\//);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
