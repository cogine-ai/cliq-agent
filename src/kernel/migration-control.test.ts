// Plain control data only. No AuthorityMarker, Owner, Run, native publication
// or physical backup proof is constructed by these regressions.
import test from 'node:test';
import assert from 'node:assert/strict';
import { digestOmitting } from './identity.js';
import { canonicalSha256 } from './canonical.js';
import { decodeOwnedLegacyImportControl, assertOwnedImportControlSuccessor, decodeLegacyMigrationRendezvous } from './migration-control.js';

const at = '2026-10-02T00:00:00.000Z';
function seal(value: Record<string, unknown>) { const data = { ...value, controlDigest: '' }; data.controlDigest = digestOmitting(data, 'controlDigest'); return data; }
function initial() { return seal({ schemaVersion: 1, format: 'cliq-migration-control-v1', phase: 'cutover_preflight',
  migrationId: 'a'.repeat(43), controlRevision: 1, sourceGenerationDigest: 'b'.repeat(64), targetGenerationId: 'c'.repeat(43),
  stateRootIdentityRef: 'd'.repeat(64), stateRootIdentityDigest: 'e'.repeat(64), stateRootCanonicalAbsolutePath: '/inert/root',
  preparationRef: 'f'.repeat(64), preparationDigest: '0'.repeat(64), createdAt: at, updatedAt: at }); }
function candidate() { return seal({ ...initial(), phase: 'cutover_candidate_ready', controlRevision: 2,
  previousControlRef: canonicalSha256(initial()), previousControlDigest: initial().controlDigest,
  inventoryRef: '1'.repeat(64), inventoryDigest: '2'.repeat(64), credentialReadyRef: '3'.repeat(64), credentialReadyDigest: '4'.repeat(64),
  backupRef: '5'.repeat(64), backupDigest: '6'.repeat(64), candidateRef: '7'.repeat(64), candidateDigest: '8'.repeat(64) }); }
test('owned import controls form one contiguous original-root preparation spine without a second timestamp-selected marker', () => {
  const first = decodeOwnedLegacyImportControl(initial()), second = decodeOwnedLegacyImportControl(candidate());
  const third = decodeOwnedLegacyImportControl(seal({ ...second, phase: 'credential_cutover', controlRevision: 3,
    previousControlRef: canonicalSha256(second), previousControlDigest: second.controlDigest, legacyAuthMarkerDigest: '9'.repeat(64) }));
  const fourth = decodeOwnedLegacyImportControl(seal({ ...third, phase: 'cutover_import_committed', controlRevision: 4,
    previousControlRef: canonicalSha256(third), previousControlDigest: third.controlDigest,
    committedReceiptRef: 'a'.repeat(64), committedReceiptDigest: 'b'.repeat(64), committedResponseRef: 'c'.repeat(64), committedResponseDigest: 'd'.repeat(64) }));
  assertOwnedImportControlSuccessor(first, second); assertOwnedImportControlSuccessor(second, third); assertOwnedImportControlSuccessor(third, fourth);
  assert.throws(() => assertOwnedImportControlSuccessor(first, third), TypeError);
  assert.throws(() => assertOwnedImportControlSuccessor(second, decodeOwnedLegacyImportControl(seal({ ...third, backupDigest: 'f'.repeat(64) }))), TypeError);
  assert.throws(() => assertOwnedImportControlSuccessor(first, decodeOwnedLegacyImportControl(seal({ ...second, preparationRef: 'e'.repeat(64) }))), TypeError);
  for (const change of [{ previousControlRef: '0'.repeat(64) }, { previousControlDigest: '1'.repeat(64) }])
    assert.throws(() => assertOwnedImportControlSuccessor(second, decodeOwnedLegacyImportControl(seal({ ...third, ...change }))), TypeError);
});
test('Legacy rendezvous accepts only the immutable initial control data, never a later phase or partial authority-shaped JSON', () => {
  assert.deepEqual(decodeLegacyMigrationRendezvous(initial()), decodeOwnedLegacyImportControl(initial()));
  assert.throws(() => decodeLegacyMigrationRendezvous(candidate()), TypeError);
  assert.throws(() => decodeLegacyMigrationRendezvous({ schemaVersion: 1, format: 'cliq-state-authority-v1', authority: 'kernel' }), TypeError);
  for (const change of [{ controlRevision: 2 }, { phase: 'cutover_future' }, { stateRootCanonicalAbsolutePath: '/inert/../foreign' },
    { extra: true }, { createdAt: '2026-10-03T00:00:00.000Z' }, { preparationDigest: 'bad' }])
    assert.throws(() => decodeOwnedLegacyImportControl(seal({ ...initial(), ...change })), TypeError);
  assert.throws(() => decodeOwnedLegacyImportControl({ ...initial(), controlDigest: 'a'.repeat(64) }), TypeError);
});
