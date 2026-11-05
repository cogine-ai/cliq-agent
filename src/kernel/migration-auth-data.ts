// Existing migration auth marker data only. It contains no raw credential,
// platform handle or authority to enroll, restore, execute or publish anything.
import { canonicalJsonBytes } from './canonical.js';
import { assertControlWireJson, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { digestOmitting } from './identity.js';
import { assertBoundedJsonValue } from './json.js';
import { immutableSnapshot } from '../model/immutable.js';

export type LegacyAuthMigratedMarkerV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-auth-migrated-v1'; migrationId: string;
  sourceObservationRef: string; sourceObservationDigest: string; credentialReadyRef: string; credentialReadyDigest: string;
  records: readonly Readonly<{ endpointRegistrationId: string; credentialGrantId: string; authorityRecordDigest: string }>[];
  markerDigest: string;
}>;

export function decodeLegacyAuthMigratedMarker(value: unknown): Readonly<LegacyAuthMigratedMarkerV1> {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'Legacy auth migrated marker');
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'migrationId', 'sourceObservationRef', 'sourceObservationDigest',
    'credentialReadyRef', 'credentialReadyDigest', 'records', 'markerDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-auth-migrated-v1' ||
      !/^[A-Za-z0-9_-]{43}$/u.test(controlWireText(data.migrationId)) || !Array.isArray(data.records))
    throw new TypeError('Legacy auth marker has the wrong closed schema');
  for (const key of ['sourceObservationRef', 'sourceObservationDigest', 'credentialReadyRef', 'credentialReadyDigest', 'markerDigest']) controlWireRef(data[key]);
  let previous: Readonly<{ endpoint: string; grant: string }> | undefined;
  for (const raw of data.records) {
    const record = controlWireRecord(raw, ['endpointRegistrationId', 'credentialGrantId', 'authorityRecordDigest']);
    const endpoint = controlWireText(record.endpointRegistrationId, 4096), grant = controlWireText(record.credentialGrantId, 256);
    controlWireRef(record.authorityRecordDigest);
    if (previous) {
      const comparison = Buffer.compare(Buffer.from(previous.endpoint), Buffer.from(endpoint)) || Buffer.compare(Buffer.from(previous.grant), Buffer.from(grant));
      if (comparison >= 0) throw new TypeError('Legacy auth marker records must be unique and byte-sorted');
    }
    previous = { endpoint, grant };
  }
  if (canonicalJsonBytes(data).length > 1_048_576 || digestOmitting(data, 'markerDigest') !== data.markerDigest)
    throw new TypeError('Legacy auth marker complete bytes or digest differ');
  return immutableSnapshot(data) as Readonly<LegacyAuthMigratedMarkerV1>;
}
