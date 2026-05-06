import test from 'node:test';
import assert from 'node:assert/strict';

import { emptyHeadlessArtifacts } from './contract.js';
import type {
  TxStagingStartPayload,
  TxAppliedPayload,
  TxAbortedPayload
} from './contract.js';

test('TxStagingStartPayload allows trigger auto-turn and explicit-open with optional name', () => {
  const a: TxStagingStartPayload = { txId: 'tx_x', txKind: 'edit', trigger: 'auto-turn' };
  const b: TxStagingStartPayload = { txId: 'tx_x', txKind: 'edit', trigger: 'explicit-open', name: 'feature' };
  // Type-only test: compile-time assertion that these shapes are valid.
  assert.equal(a.trigger, 'auto-turn');
  assert.equal(b.name, 'feature');
});

test('TxAppliedPayload includes diffSummary, validators, overrides, artifactRef', () => {
  const p: TxAppliedPayload = {
    txId: 'tx_y',
    txKind: 'edit',
    diffSummary: { filesChanged: 1, additions: 0, deletions: 0, creates: [], modifies: ['a.txt'], deletes: [] },
    validators: { blocking: { pass: 1, fail: 0 }, advisory: { pass: 0, fail: 0, names: [] } },
    overrides: [],
    artifactRef: 'tx/tx_y/'
  };
  assert.equal(p.artifactRef, 'tx/tx_y/');
});

test('TxAbortedPayload includes appliedPartial when applicable', () => {
  const p: TxAbortedPayload = {
    txId: 'tx_z',
    txKind: 'edit',
    reason: 'apply-failed-partial-restored',
    artifactRef: 'tx/tx_z/',
    appliedPartial: { partialFiles: ['a.txt'], ghostSnapshotId: 'wchk_x', restoreConfirmed: true }
  };
  assert.equal(p.appliedPartial?.restoreConfirmed, true);
});

test('emptyHeadlessArtifacts initializes transactions: []', () => {
  const a = emptyHeadlessArtifacts();
  assert.deepEqual(a.transactions, []);
});
