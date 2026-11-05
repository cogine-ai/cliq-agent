import assert from 'node:assert/strict';
import { test } from 'node:test';
import { digestOmitting } from './identity.js';
import { decodeLegacyAuthMigratedMarker, type LegacyAuthMigratedMarkerV1 } from './migration-auth-data.js';

// Pure retained data only: these values never instantiate a native holder,
// StateOwner, credential, cutover authority marker or physical evidence.
function document(records: LegacyAuthMigratedMarkerV1['records'] = []): LegacyAuthMigratedMarkerV1 {
  const data: LegacyAuthMigratedMarkerV1 = { schemaVersion: 1, format: 'cliq-auth-migrated-v1', migrationId: 'm'.repeat(43),
    sourceObservationRef: '1'.repeat(64), sourceObservationDigest: '2'.repeat(64),
    credentialReadyRef: '3'.repeat(64), credentialReadyDigest: '4'.repeat(64), records, markerDigest: '' };
  return { ...data, markerDigest: digestOmitting(data, 'markerDigest') };
}
const record = (endpointRegistrationId: string, credentialGrantId: string) =>
  ({ endpointRegistrationId, credentialGrantId, authorityRecordDigest: '5'.repeat(64) });

test('retained nonsecret auth data closes both empty and byte-sorted record projections without granting authority', () => {
  assert.deepEqual(decodeLegacyAuthMigratedMarker(document()).records, []);
  const data = document([record('a', 'z'), record('b', 'a'), record('b', 'b')]);
  const decoded = decodeLegacyAuthMigratedMarker(data);
  assert.deepEqual(decoded, data);
  assert.ok(Object.isFrozen(decoded)); assert.ok(Object.isFrozen(decoded.records)); assert.ok(Object.isFrozen(decoded.records[0]));
});

test('retained auth projection rejects duplicate or reordered endpoint/grant pairs even with a recomputed digest', () => {
  for (const records of [[record('b', 'a'), record('a', 'z')], [record('a', 'z'), record('a', 'a')],
    [record('a', 'a'), record('a', 'a')]]) assert.throws(() => decodeLegacyAuthMigratedMarker(document(records)), /unique and byte-sorted/u);
});

test('retained auth projection rejects modified data, raw credential fields and unknown authority-shaped fields', () => {
  const valid = document([record('a', 'a')]);
  assert.throws(() => decodeLegacyAuthMigratedMarker({ ...valid, sourceObservationDigest: '6'.repeat(64) }), /digest differ/u);
  for (const field of ['apiKey', 'platformHandle', 'verified', 'rawAuthBytes'])
    assert.throws(() => decodeLegacyAuthMigratedMarker({ ...valid, [field]: 'untrusted' }), /unknown or missing/u);
  assert.throws(() => decodeLegacyAuthMigratedMarker({ ...valid, records: [{ ...valid.records[0], secret: 'untrusted' }] }), /unknown or missing/u);
  assert.throws(() => decodeLegacyAuthMigratedMarker({ ...valid, credentialReadyRef: 'not-a-ref' }));
});

test('retained auth projection keeps original canonical text and aggregate limits', () => {
  assert.throws(() => decodeLegacyAuthMigratedMarker(document([record('e\u0301', 'a')])));
  assert.throws(() => decodeLegacyAuthMigratedMarker(document([record('a', 'a\0')])));
  const records = Array.from({ length: 2_501 }, (_, index) => record('a', String(index).padStart(4, '0')));
  assert.throws(() => decodeLegacyAuthMigratedMarker(document(records)), /10000/u);
});
