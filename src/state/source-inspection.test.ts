import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { applyKernelSchema } from './schema.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { readSourceInspectionAttempt } from './source-inspection.js';

test('retained source inspection rejects an unknown field even if its row is rehashed', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'cliq-source-inspection-'));
  const staging = path.join(directory, 'staging');
  await mkdir(staging, { mode: 0o700 });
  const observed = await stat(staging, { bigint: true });
  const driver = openSqliteDriver(path.join(directory, 'kernel.sqlite3'));
  try {
    applyKernelSchema(driver);
    // Stored metadata is deliberately injected at the actual SQL seam. This
    // does not mint a native handle or prove resource retirement/activation.
    const key = { principalId: 'principal', admissionKey: 'abcdefghijklmnopqrstuv', admissionIntentDigest: 'a'.repeat(64) };
    const row = { schemaVersion: 1, inspectionId: identityHash('cliq-source-inspection-v1', key.principalId,
      'run.submit', key.admissionKey, key.admissionIntentDigest), attempt: 1, ...key, method: 'run.submit',
      targetRef: 'b'.repeat(64), targetDigest: 'c'.repeat(64), workspaceIdentityDigest: 'd'.repeat(64),
      stateOwnerEpoch: 1, supervisorInstanceId: 'supervisor', stagingNonceDigest: 'e'.repeat(64),
      stagingIdentity: { deviceId: observed.dev.toString(), fileId: observed.ino.toString(), ownerUid: Number(observed.uid), mode: 448 },
      cancelRequested: false, phase: 'capturing', rowVersion: 1,
      createdAt: '2026-10-08T00:00:00.000Z', deadlineAt: '2026-10-08T00:01:00.000Z', updatedAt: '2026-10-08T00:00:00.000Z',
      forceRetired: true, rowDigest: '' };
    row.rowDigest = digestOmitting(row, 'rowDigest');
    driver.prepare(`INSERT INTO source_inspection_attempts
      (inspection_id, principal_id, method, admission_key, admission_intent_digest, original_request_id, original_request_digest,
       workspace_identity_digest, phase, row_version, row_json)
      VALUES (?, ?, 'run.submit', ?, ?, ?, ?, ?, 'capturing', 1, ?)`).run(row.inspectionId, row.principalId, row.admissionKey,
      row.admissionIntentDigest, '0199b011-1111-7111-8111-111111111111', 'f'.repeat(64), row.workspaceIdentityDigest, canonicalJsonBytes(row).toString());
    assert.throws(() => readSourceInspectionAttempt(driver, key),
      (error: unknown) => error instanceof Error && 'code' in error && error.code === 'RECOVERY_REQUIRED' && /unknown|closed schema/.test(error.message));
    // Key conflicts are resolved from the replay row before traversing any
    // target/source ref, including a malformed historical metadata payload.
    assert.throws(() => readSourceInspectionAttempt(driver, { ...key, admissionIntentDigest: 'f'.repeat(64) }),
      (error: unknown) => error instanceof Error && 'code' in error && error.code === 'ADMISSION_KEY_CONFLICT');
    assert.equal(readSourceInspectionAttempt(driver, { ...key, admissionKey: 'zyxwvutsrqponmlkjihgfe' }), undefined);
  } finally {
    driver.close();
    await rm(directory, { recursive: true, force: true });
  }
});
