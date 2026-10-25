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

test('source capture retains submit and apply under their distinct original method without borrowing an inspection', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'cliq-source-method-'));
  const staging = path.join(directory, 'staging'); await mkdir(staging, { mode: 0o700 });
  const observed = await stat(staging, { bigint: true });
  const driver = openSqliteDriver(path.join(directory, 'kernel.sqlite3'));
  try {
    applyKernelSchema(driver);
    // Existing actual SQLite metadata seam only; these rows are not native
    // staging handles, retirement observations or permission to capture.
    const key = { principalId: 'principal', admissionKey: 'abcdefghijklmnopqrstuv', admissionIntentDigest: 'a'.repeat(64) };
    for (const method of ['run.submit', 'run.apply'] as const) {
      const row = { schemaVersion: 1, inspectionId: identityHash('cliq-source-inspection-v1', key.principalId,
        method, key.admissionKey, key.admissionIntentDigest), attempt: 1, ...key, method,
        targetRef: 'b'.repeat(64), targetDigest: 'c'.repeat(64), workspaceIdentityDigest: (method === 'run.submit' ? 'd' : 'e').repeat(64),
        stateOwnerEpoch: 1, supervisorInstanceId: 'supervisor', stagingNonceDigest: 'e'.repeat(64),
        stagingIdentity: { deviceId: observed.dev.toString(), fileId: observed.ino.toString(), ownerUid: Number(observed.uid), mode: 448 },
        cancelRequested: false, phase: 'capturing', rowVersion: 1,
        ...(method === 'run.submit' ? { inputRef: '1'.repeat(64), inputDigest: '2'.repeat(64) } : {}),
        createdAt: '2026-10-08T00:00:00.000Z', deadlineAt: '2026-10-08T00:01:00.000Z', updatedAt: '2026-10-08T00:00:00.000Z', rowDigest: '' };
      row.rowDigest = digestOmitting(row, 'rowDigest');
      driver.prepare(`INSERT INTO source_inspection_attempts
        (inspection_id, principal_id, method, admission_key, admission_intent_digest, original_request_id, original_request_digest,
         workspace_identity_digest, phase, row_version, row_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'capturing', 1, ?)`).run(row.inspectionId, row.principalId, method, row.admissionKey,
        row.admissionIntentDigest, '0199b011-1111-7111-8111-111111111111', 'f'.repeat(64), row.workspaceIdentityDigest, canonicalJsonBytes(row).toString());
      assert.equal(readSourceInspectionAttempt(driver, { ...key, method })?.method, method);
      const observedIntent = readSourceInspectionAttempt(driver, { ...key, method });
      assert.equal(observedIntent?.phase, 'capturing');
      assert.equal(observedIntent?.inputRef, method === 'run.submit' ? '1'.repeat(64) : undefined);
      assert.throws(() => readSourceInspectionAttempt(driver, { ...key, method, admissionIntentDigest: 'f'.repeat(64) }),
        error => error instanceof Error && 'code' in error && error.code === 'ADMISSION_KEY_CONFLICT');
    }
    assert.equal(readSourceInspectionAttempt(driver, { ...key, method: 'run.submit' })?.method, 'run.submit');
    assert.equal(readSourceInspectionAttempt(driver, { ...key, method: 'run.apply' })?.method, 'run.apply');
    assert.equal(driver.prepare('SELECT count(*) AS count FROM source_inspection_attempts').get<{ count: bigint }>()?.count, 2n);
    for (const method of ['run.submit', 'run.apply'] as const) {
      const original = readSourceInspectionAttempt(driver, { ...key, method })!;
      const retired = { ...original, phase: 'retired', rowVersion: 2, retirementEvidenceRef: 'a'.repeat(64),
        retiredAt: '2026-10-08T00:00:01.000Z', updatedAt: '2026-10-08T00:00:01.000Z',
        outcome: { kind: 'captured', sourceManifestRef: 'b'.repeat(64), sourceManifestDigest: 'c'.repeat(64),
          ...(method === 'run.submit' ? { captureTopologyRef: 'd'.repeat(64), captureTopologyDigest: 'e'.repeat(64) } : {}) }, rowDigest: '' };
      retired.rowDigest = digestOmitting(retired, 'rowDigest');
      driver.prepare(`UPDATE source_inspection_attempts SET phase='retired',row_version=2,row_json=? WHERE inspection_id=?`)
        .run(canonicalJsonBytes(retired).toString(), original.inspectionId);
      assert.throws(() => readSourceInspectionAttempt(driver, { ...key, method }), { code: 'RECOVERY_REQUIRED' },
        method === 'run.apply' ? 'apply cannot omit its retained topology' : 'submit cannot borrow delivery-only topology');
    }
  } finally { driver.close(); await rm(directory, { recursive: true, force: true }); }
});

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
