import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { childFor, ownerAt } from './testing/state-owner-process.js';

test('StateStore cannot release its owner over an unretired source inspection with no registered task', async t => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-shutdown-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const child = await childFor(t, root);
  assert.equal((await child.request('acquire')).state, 'held');
  const original = ownerAt(root);
  const intent = 'a'.repeat(64), principal = 'source-principal', key = 'source-inspection-key-123';
  // Crash-style durable metadata at the actual SQLite seam must itself block
  // release. No handcrafted artifact can prove the missing task joined.
  const row = { schemaVersion: 1, inspectionId: identityHash('cliq-source-inspection-v1', principal, 'run.submit', key, intent),
    attempt: 1, principalId: principal, method: 'run.submit', admissionKey: key, admissionIntentDigest: intent,
    targetRef: 'b'.repeat(64), targetDigest: 'c'.repeat(64), workspaceIdentityDigest: 'd'.repeat(64),
    stateOwnerEpoch: original.ownerEpoch, supervisorInstanceId: original.supervisorInstanceId,
    stagingNonceDigest: 'e'.repeat(64), stagingIdentity: { deviceId: '1', fileId: '1', ownerUid: process.geteuid!(), mode: 448 },
    cancelRequested: false, phase: 'capturing', rowVersion: 1, createdAt: original.acquiredAt,
    deadlineAt: new Date(Date.parse(original.acquiredAt) + 60_000).toISOString(), updatedAt: original.acquiredAt, rowDigest: '' };
  row.rowDigest = digestOmitting(row, 'rowDigest');
  const driver = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
  try {
    driver.prepare(`INSERT INTO source_inspection_attempts
      (inspection_id, principal_id, method, admission_key, admission_intent_digest, original_request_id, original_request_digest,
       workspace_identity_digest, phase, row_version, row_json)
      VALUES (?, ?, 'run.submit', ?, ?, ?, ?, ?, 'capturing', 1, ?)`).run(row.inspectionId, principal, key, intent,
      '0199b011-1111-7111-8111-111111111111', 'f'.repeat(64), row.workspaceIdentityDigest, canonicalJsonBytes(row).toString());
  } finally { driver.close(); }
  const close = await child.request('close');
  assert.equal(close.state, 'error');
  assert.equal(close.code, 'RECOVERY_REQUIRED');
  assert.match(close.message!, /source inspection.*retirement/);
  assert.deepEqual(ownerAt(root), original);
  child.child.kill('SIGKILL'); await child.exited;
});
