import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeKernelRollbackDrainingControl } from '../kernel/kernel-archive-data.js';
import { backupOriginalSqliteToKernelArchive } from './sqlite-driver.js';

// Plain control data only. This is neither a migration authority marker nor a
// source/destination/StateOwner/installation/physical-backup proof.
function draining() {
  const data = { schemaVersion: 1, format: 'cliq-kernel-rollback-control-v1', phase: 'rollback_draining', controlRevision: 1,
    migrationId: 'a'.repeat(43), archiveId: 'b'.repeat(43), kernelGenerationId: 'c'.repeat(43),
    stateRootIdentityRef: 'd'.repeat(64), stateRootIdentityDigest: 'e'.repeat(64), stateRootCanonicalAbsolutePath: '/inert/root',
    requestRef: 'f'.repeat(64), requestDigest: '0'.repeat(64), originalImportControlRef: '1'.repeat(64), originalImportControlDigest: '2'.repeat(64),
    originalKernelAuthorityRef: '3'.repeat(64), originalKernelAuthorityDigest: '4'.repeat(64), preparedAt: '2026-10-02T00:00:00.000Z', controlDigest: '' };
  data.controlDigest = digestOmitting(data, 'controlDigest'); return data;
}
test('rollback draining data binds one exact intent and keeps full-byte content ref distinct from semantic digest', () => {
  const value = draining(); assert.deepEqual(decodeKernelRollbackDrainingControl(value), value);
  assert.notEqual(canonicalSha256(value), value.controlDigest);
  const invalid: readonly Record<string, unknown>[] = [
    { ...value, archiveId: 'a'.repeat(42) }, { ...value, kernelGenerationId: '../escape' }, { ...value, phase: 'ready' },
    { ...value, controlRevision: 2 }, { ...value, unknown: true }, { ...value, requestRef: 'A'.repeat(64) },
    { ...value, stateRootCanonicalAbsolutePath: '/inert/../root' }, { ...value, preparedAt: '2026-10-02' },
    { ...value, controlDigest: 'f'.repeat(64) }
  ];
  for (const row of invalid) assert.throws(() => decodeKernelRollbackDrainingControl(row));
});
test('original archive source friend rejects foreign structural data before any supplied getter or operation', async () => {
  let calls = 0;
  const foreign = new Proxy(Object.create(null), { get() { calls++; throw new Error('caller trap'); } });
  await assert.rejects(backupOriginalSqliteToKernelArchive(foreign, foreign), /genuine writable original driver/u);
  assert.equal(calls, 0);
});
