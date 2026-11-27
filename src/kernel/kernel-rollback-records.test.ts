import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalSha256 } from './canonical.js';
import { digestOmitting } from './identity.js';
import { decodeKernelRollbackDrainingControl } from './kernel-archive-data.js';
import { decodeKernelRollbackArchiveReadyControl, encodeRollbackArchiveReadyAuthIdentity } from './kernel-rollback-handoff.js';
import { assertKernelRollbackControlSuccessor, decodeInstalledRollbackRequest, decodeKernelRollbackRestoringControl,
  encodePreparedRollbackMarkerIdentities } from './kernel-rollback-records.js';

const requestId = '019a1234-1234-7123-8123-123456789abc', migrationId = 'a'.repeat(43);
const preparedAt = '2026-10-02T00:00:00.000Z';
const ref = (character: string) => character.repeat(64);
test('rollback input explicitly binds the selected migration and plaintext choice', () => {
  const input = { protocolVersion: 1, method: 'state.rollback', requestId, migrationId, allowPlaintextLegacyCredentials: false };
  assert.deepEqual(decodeInstalledRollbackRequest(input), input);
  assert.deepEqual(decodeInstalledRollbackRequest({ ...input, allowPlaintextLegacyCredentials: true }),
    { ...input, allowPlaintextLegacyCredentials: true });
  const { allowPlaintextLegacyCredentials: _choice, ...missing } = input;
  for (const invalid of [missing, { ...input, allowPlaintextLegacyCredentials: 'false' },
    { ...input, legacyRoot: '/caller/selected' }, { ...input, finalization: true }, { ...input, requestId: requestId.toUpperCase() }])
    assert.throws(() => decodeInstalledRollbackRequest(invalid), TypeError);
});
test('restoring control binds the exact prior draining record and two distinct prepared marker identities', () => {
  const initial = { schemaVersion: 1, format: 'cliq-kernel-rollback-control-v1', phase: 'rollback_draining', controlRevision: 1,
    migrationId, archiveId: 'b'.repeat(43), kernelGenerationId: 'c'.repeat(43),
    stateRootIdentityRef: ref('d'), stateRootIdentityDigest: ref('e'), stateRootCanonicalAbsolutePath: '/inert/root',
    requestRef: ref('f'), requestDigest: ref('0'), originalImportControlRef: ref('1'), originalImportControlDigest: ref('2'),
    originalKernelAuthorityRef: ref('3'), originalKernelAuthorityDigest: ref('4'), preparedAt };
  const draining = decodeKernelRollbackDrainingControl({ ...initial, controlDigest: canonicalSha256(initial) });
  const root = { deviceId: '1', fileId: '10', ownerUid: 1000 }, legacy = { ...root, fileId: '11' };
  const pending = { ...initial, phase: 'rollback_archive_ready', controlRevision: 2,
    drainingControlRef: canonicalSha256(draining), drainingControlDigest: draining.controlDigest,
    archivedKernelGenerationRef: ref('5'), archivedKernelGenerationDigest: ref('6'),
    originalSourceAuthObservationRef: ref('7'), originalSourceAuthObservationDigest: ref('8'),
    originalMigratedAuthMarkerRef: ref('9'), originalMigratedAuthMarkerDigest: ref('a'),
    originalAuthMarkerFile: { ...legacy, fileId: '14' }, updatedAt: preparedAt, controlDigest: '' };
  const decodeReady = (data: typeof pending) => decodeKernelRollbackArchiveReadyControl({ ...data, controlDigest: digestOmitting(data, 'controlDigest') });
  const ready = decodeReady(pending);
  const identity = encodeRollbackArchiveReadyAuthIdentity(ready);
  assert.equal(identity.subarray(0, 8).toString('ascii'), 'CLQMA001');
  assert.equal(identity.readBigUInt64LE(8), 1n); assert.equal(identity.readBigUInt64LE(16), 14n);
  assert.equal(identity.readUInt32LE(24), 1000); assert.equal(identity.readUInt32LE(28), 0);
  assert.throws(() => decodeReady({ ...pending, originalAuthMarkerFile: { ...legacy, fileId: '0' } }), TypeError);
  assert.throws(() => decodeReady({ ...pending, drainingControlRef: draining.controlDigest }), TypeError);
  const restoring = { ...initial, phase: 'rollback_restoring', controlRevision: 3,
    drainingControlRef: canonicalSha256(draining), drainingControlDigest: draining.controlDigest,
    archiveReadyControlRef: canonicalSha256(ready), archiveReadyControlDigest: ready.controlDigest,
    archivedKernelGenerationRef: ref('5'), archivedKernelGenerationDigest: ref('6'), legacyGenerationRef: ref('7'), legacyGenerationDigest: ref('8'),
    preparerOwnerEpoch: 1, preparerOwnerAcquisitionEvidenceRef: ref('2'), preparerOwnerAcquisitionEvidenceDigest: ref('3'),
    preparedReceiptRef: ref('9'), preparedReceiptDigest: ref('a'), preparedLegacyAuthorityMarkerRef: ref('b'), preparedLegacyAuthorityMarkerDigest: ref('c'),
    preparedRootAuthorityFile: root, preparedLegacyAuthorityFile: legacy,
    originalRootAuthorityFile: { ...root, fileId: '12' }, originalLegacyAuthorityFile: { ...legacy, fileId: '13' },
    updatedAt: preparedAt, controlDigest: '' };
  const decode = (data: typeof restoring) => decodeKernelRollbackRestoringControl({ ...data, controlDigest: digestOmitting(data, 'controlDigest') });
  assertKernelRollbackControlSuccessor(draining, decode(restoring), ready);
  const pendingMarker = encodePreparedRollbackMarkerIdentities(decode(restoring), true);
  assert.equal(pendingMarker.readUInt32LE(76), 1);
  assert.equal(encodePreparedRollbackMarkerIdentities(decode(restoring)).readUInt32LE(76), 0);
  assert.throws(() => decode({ ...restoring, preparedLegacyAuthorityFile: root }), TypeError);
  assert.throws(() => decode({ ...restoring, preparedLegacyAuthorityFile: { ...legacy, ownerUid: 999 } }), TypeError);
  assert.throws(() => assertKernelRollbackControlSuccessor(draining, decode({ ...restoring, archiveId: 'd'.repeat(43) }), ready), TypeError);
  assert.throws(() => assertKernelRollbackControlSuccessor(draining, decode({ ...restoring, drainingControlRef: draining.controlDigest }), ready), TypeError);
  assert.throws(() => assertKernelRollbackControlSuccessor(draining, decode({ ...restoring, archiveReadyControlDigest: ref('0') }), ready), TypeError);
});
