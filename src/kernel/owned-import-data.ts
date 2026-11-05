// Immutable owned-import audit data. These records never authenticate a
// request, create an Owner or certify physical publication.
import { canonicalJsonBytes } from './canonical.js';
import { assertBoundedJsonValue } from './json.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { assertRequestId, digestOmitting, normalizeAbsolutePath, parseCanonicalTime } from './identity.js';
import type { StateOwnerRecordV1 } from './types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { decodeStateOwnerRecord } from '../state/decoders.js';
import type { HeldMigrationBackupEntry, PreparedImportImageObservation } from '../state/native-owner.js';

export type OwnedLegacyImportRequestV1 = Readonly<{ protocolVersion: 1; method: 'state.migrate'; requestId: string;
  migrationId: string; legacyRootCanonicalAbsolutePath: string }>;
export type OwnedLegacyImportPreparationV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-owned-legacy-import-preparation-v1'; migrationId: string; principalId: string;
  requestId: string; requestRef: string; requestDigest: string; channelIdentityRef: string; channelIdentityDigest: string;
  stateRootIdentityRef: string; stateRootIdentityDigest: string; legacyRootIdentityRef: string; legacyRootIdentityDigest: string;
  kernelGenerationIdentityRef: string; kernelGenerationIdentityDigest: string; preparingOwner: StateOwnerRecordV1 & { state: 'active' };
  preparingOwnerHistoryThroughEpoch: number; preparingTimeFenceDigest: string; signedSchemaManifestRef: string;
  signedSchemaManifestDigest: string; signedSchemaDigest: string; preparedAt: string; preparationDigest: string;
}>;
export type OwnedImportRootDescriptor = Readonly<{ canonicalAbsolutePath: string; ownerUid: number; deviceId: string;
  directoryFileId: string; mode: number; openedNoFollow: true }>;
export type OwnedLegacyRootIdentityV1 = Readonly<{ schemaVersion: 1; format: 'cliq-owned-legacy-root-identity-v1';
  migrationId: string; root: OwnedImportRootDescriptor; identityDigest: string }>;
export type OwnedImportInventoryV1 = Readonly<{ schemaVersion: 1; format: 'cliq-owned-legacy-import-inventory-v1';
  migrationId: string; preparationRef: string; preparationDigest: string; legacyRootIdentityRef: string; legacyRootIdentityDigest: string;
  rootPageRef: string | null; pageHeight: number; entryCount: number; entriesDigest: string; inventoryDigest: string }>;
export type OwnedImportInventoryEdge = Readonly<{ ref: string; firstPath: string; lastPath: string; entryCount: number }>;
export type OwnedImportInventoryPage = Readonly<{ schemaVersion: 1; format: 'cliq-owned-import-inventory-page-v1';
  firstPath: string; lastPath: string; entryCount: number }> & (
    Readonly<{ kind: 'leaf'; height: 0; entries: readonly HeldMigrationBackupEntry[] }> |
    Readonly<{ kind: 'branch'; height: number; children: readonly OwnedImportInventoryEdge[] }>);
export type OwnedImportBackupV1 = Readonly<{ schemaVersion: 1; format: 'cliq-owned-legacy-import-backup-v1';
  migrationId: string; preparationRef: string; preparationDigest: string; inventoryRef: string; inventoryDigest: string;
  backupRoot: OwnedImportRootDescriptor; entriesDigest: string; completedAt: string; backupDigest: string }>;
export type OwnedImportCredentialReadyV1 = Readonly<{ schemaVersion: 1; format: 'cliq-owned-legacy-import-credential-ready-v1';
  migrationId: string; preparationRef: string; preparationDigest: string; principalId: string;
  sourceAuthObservationRef: string; sourceAuthObservationDigest: string;
  entries: readonly Readonly<{ endpointRegistrationId: string; endpointAuthorityRef: string; endpointAuthorityDigest: string;
    credentialGrantId: string; credentialAuthorityRef: string; credentialAuthorityDigest: string;
    platformObservationRef: string; platformObservationDigest: string; observedAt: string; verifiedAt: string }>[];
  completedAt: string; readyDigest: string }>;
export type OwnedImportSourceAuthObservationV1 = Readonly<{ schemaVersion: 1; format: 'cliq-owned-import-source-auth-observation-v1';
  migrationId: string; legacyRootIdentityRef: string; legacyRootIdentityDigest: string; observedAt: string;
  observation: Readonly<{ presence: 'absent'; noFollowLookupResult: 'ENOENT' }> |
    Readonly<{ presence: 'present'; file: Readonly<{ deviceId: string; fileId: string; ownerUid: number }>;
      byteCount: number; contentDigest: string; mode: 384; linkCount: 1 }>;
  observationDigest: string }>;
export type PreparedImportDatabaseImageIdentityV1 = Readonly<{ schemaVersion: 1;
  format: 'cliq-prepared-import-database-image-identity-v1'; snapshotBoundary: 'owned_import_preview';
  excludedDatabaseTail: 'final_import_response_receipt_and_committing_time_fence';
  migrationId: string; preparationRef: string; preparationDigest: string;
  signedSchemaManifestRef: string; signedSchemaManifestDigest: string; signedSchemaDigest: string;
  observation: PreparedImportImageObservation; imageDigest: string }>;
export type OwnedPreparedImportCandidateV1 = Readonly<{ schemaVersion: 1; format: 'cliq-owned-prepared-import-candidate-v1';
  snapshotBoundary: 'owned_import_preview'; excludedDatabaseTail: 'final_import_response_receipt_and_committing_time_fence';
  migrationId: string; preparationRef: string; preparationDigest: string;
  kernelGenerationIdentityRef: string; kernelGenerationIdentityDigest: string;
  stateRootIdentityRef: string; stateRootIdentityDigest: string; legacyRootIdentityRef: string; legacyRootIdentityDigest: string;
  signedSchemaManifestRef: string; signedSchemaManifestDigest: string; signedSchemaDigest: string;
  inventoryRef: string; inventoryDigest: string; backupRef: string; backupDigest: string;
  credentialReadyRef: string; credentialReadyDigest: string; imageIdentityRef: string; imageIdentityDigest: string;
  originalArtifactRefs: readonly string[]; preimportSqlCutDigest: string; projectionDigest: string;
  importedRowSetDigest: string; sessions: number; items: number; newArtifacts: number; stagedAt: string; candidateDigest: string }>;
export type OwnedLegacyImportReceiptV1 = Readonly<{ schemaVersion: 1; format: 'cliq-owned-legacy-import-receipt-v1';
  kind: 'kernel_cutover'; migrationId: string; principalId: string; requestId: string; requestRef: string; requestDigest: string;
  channelIdentityRef: string; channelIdentityDigest: string; stateRootIdentityRef: string; stateRootIdentityDigest: string;
  legacyRootIdentityRef: string; legacyRootIdentityDigest: string; preparationRef: string; preparationDigest: string;
  kernelGenerationIdentityRef: string; kernelGenerationIdentityDigest: string; candidateRef: string; candidateDigest: string;
  importedRowSetDigest: string; credentialReadyRef: string; credentialReadyDigest: string; completedAt: string; receiptDigest: string }>;
export type OwnedLegacyImportResponseV1 = Readonly<{ protocolVersion: 1; method: 'state.migrate'; status: 'completed';
  requestId: string; migrationId: string; preparationRef: string; preparationDigest: string; receiptRef: string; receiptDigest: string;
  completedAt: string }>;
function invalid(): never { throw new TypeError('owned import differs from its exact closed retained-data contract'); }
function id(value: unknown): void { if (!/^[A-Za-z0-9_-]{43}$/u.test(controlWireText(value))) invalid(); }
function path(value: unknown): void { const text = controlWireText(value, 4096); if (normalizeAbsolutePath(text) !== text) invalid(); }
function time(value: unknown): string { const text = controlWireText(value); parseCanonicalTime(text); return text; }
function record(value: unknown, fields: readonly string[], format?: string): Record<string, unknown> {
  assertControlWireJson(value); assertBoundedJsonValue(value);
  if (canonicalJsonBytes(value).length > 1_048_576) invalid();
  const data = controlWireRecord(value, fields);
  if (format && (data.schemaVersion !== 1 || data.format !== format)) invalid();
  for (const field of fields) if ((field.endsWith('Ref') || field.endsWith('Digest')) &&
      !(field === 'rootPageRef' && data[field] === null)) controlWireRef(data[field]);
  return data;
}
function digest(data: Record<string, unknown>, field: string): void { if (digestOmitting(data, field) !== data[field]) invalid(); }
function descriptor(value: unknown, mode = false): void {
  const data = controlWireRecord(value, ['ownerUid', 'deviceId', 'fileId', ...(mode ? ['mode'] : [])]);
  controlWireInteger(data.ownerUid);
  for (const key of ['deviceId', 'fileId']) if (!/^(0|[1-9][0-9]*)$/u.test(controlWireText(data[key]))) invalid();
  if (mode) controlWireInteger(data.mode, 0, 4095);
}
export function decodeOwnedImportRootDescriptor(value: unknown): OwnedImportRootDescriptor {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['canonicalAbsolutePath', 'ownerUid', 'deviceId', 'directoryFileId', 'mode', 'openedNoFollow']);
  path(data.canonicalAbsolutePath); controlWireInteger(data.ownerUid); controlWireInteger(data.mode, 0, 4095);
  for (const key of ['deviceId', 'directoryFileId']) if (!/^(0|[1-9][0-9]*)$/u.test(controlWireText(data[key]))) invalid();
  if (data.openedNoFollow !== true) invalid(); return immutableSnapshot(data) as OwnedImportRootDescriptor;
}
export function decodeOwnedLegacyImportRequest(value: unknown): OwnedLegacyImportRequestV1 {
  const data = record(value, ['protocolVersion', 'method', 'requestId', 'migrationId', 'legacyRootCanonicalAbsolutePath']);
  if (data.protocolVersion !== 1 || data.method !== 'state.migrate') invalid();
  assertRequestId(controlWireText(data.requestId)); id(data.migrationId); path(data.legacyRootCanonicalAbsolutePath);
  return immutableSnapshot(data) as OwnedLegacyImportRequestV1;
}
export function decodeOwnedLegacyImportPreparation(value: unknown): OwnedLegacyImportPreparationV1 {
  const data = record(value, ['schemaVersion', 'format', 'migrationId', 'principalId', 'requestId', 'requestRef', 'requestDigest',
    'channelIdentityRef', 'channelIdentityDigest', 'stateRootIdentityRef', 'stateRootIdentityDigest', 'legacyRootIdentityRef',
    'legacyRootIdentityDigest', 'kernelGenerationIdentityRef', 'kernelGenerationIdentityDigest', 'preparingOwner',
    'preparingOwnerHistoryThroughEpoch', 'preparingTimeFenceDigest', 'signedSchemaManifestRef', 'signedSchemaManifestDigest',
    'signedSchemaDigest', 'preparedAt', 'preparationDigest'], 'cliq-owned-legacy-import-preparation-v1');
  id(data.migrationId); controlWireText(data.principalId); assertRequestId(controlWireText(data.requestId)); time(data.preparedAt);
  const owner = decodeStateOwnerRecord(data.preparingOwner);
  if (owner.state !== 'active' || data.preparingOwnerHistoryThroughEpoch !== owner.ownerEpoch ||
      owner.acquiredAt > (data.preparedAt as string)) invalid();
  controlWireInteger(data.preparingOwnerHistoryThroughEpoch, 1); digest(data, 'preparationDigest');
  return immutableSnapshot(data) as OwnedLegacyImportPreparationV1;
}
export function decodeOwnedLegacyRootIdentity(value: unknown): OwnedLegacyRootIdentityV1 {
  const data = record(value, ['schemaVersion', 'format', 'migrationId', 'root', 'identityDigest'], 'cliq-owned-legacy-root-identity-v1');
  id(data.migrationId); decodeOwnedImportRootDescriptor(data.root); digest(data, 'identityDigest');
  return immutableSnapshot(data) as OwnedLegacyRootIdentityV1;
}
export function decodeOwnedImportInventory(value: unknown): OwnedImportInventoryV1 {
  const data = record(value, ['schemaVersion', 'format', 'migrationId', 'preparationRef', 'preparationDigest', 'legacyRootIdentityRef',
    'legacyRootIdentityDigest', 'rootPageRef', 'pageHeight', 'entryCount', 'entriesDigest', 'inventoryDigest'], 'cliq-owned-legacy-import-inventory-v1');
  id(data.migrationId); const count = controlWireInteger(data.entryCount); controlWireInteger(data.pageHeight, 0, 7);
  if (count === 0 ? data.rootPageRef !== null || data.pageHeight !== 0 : typeof data.rootPageRef !== 'string') invalid();
  if (data.rootPageRef !== null) controlWireRef(data.rootPageRef);
  digest(data, 'inventoryDigest'); return immutableSnapshot(data) as OwnedImportInventoryV1;
}
function inventoryPath(value: unknown): string {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 4096 || value.includes('\0') ||
      Buffer.from(value, 'utf8').toString('utf8') !== value || value.startsWith('/') || value.includes('\\') ||
      value.split('/').some(part => !part || part === '.' || part === '..' || Buffer.byteLength(part) > 255)) invalid();
  if (value.split('/').length > 64) invalid();
  return value;
}
export function decodeOwnedImportInventoryPage(value: unknown): OwnedImportInventoryPage {
  const kind = (value as { kind?: unknown } | null)?.kind;
  const data = record(value, ['schemaVersion', 'format', 'kind', 'height', 'firstPath', 'lastPath', 'entryCount',
    kind === 'leaf' ? 'entries' : 'children'], 'cliq-owned-import-inventory-page-v1');
  const height = controlWireInteger(data.height, 0, 7), count = controlWireInteger(data.entryCount, 1);
  inventoryPath(data.firstPath); inventoryPath(data.lastPath);
  if (canonicalJsonBytes(value).length > 262_144) invalid();
  let previous = '';
  if (kind === 'branch') {
    if (height === 0 || !Array.isArray(data.children) || !data.children.length || data.children.length > 128) invalid();
    let total = 0;
    for (const raw of data.children) {
      const edge = controlWireRecord(raw, ['ref', 'firstPath', 'lastPath', 'entryCount']); controlWireRef(edge.ref);
      const first = inventoryPath(edge.firstPath), last = inventoryPath(edge.lastPath), entries = controlWireInteger(edge.entryCount, 1);
      if (Buffer.compare(Buffer.from(first), Buffer.from(previous)) <= 0 || Buffer.compare(Buffer.from(first), Buffer.from(last)) > 0 ||
          entries > Number.MAX_SAFE_INTEGER - total) invalid();
      previous = last; total += entries;
    }
    if (total !== count || data.firstPath !== data.children[0].firstPath || data.lastPath !== previous) invalid();
    return immutableSnapshot(data) as OwnedImportInventoryPage;
  }
  if (kind !== 'leaf' || height !== 0 || !Array.isArray(data.entries) || !data.entries.length || data.entries.length > 64 || data.entries.length !== count) invalid();
  for (const raw of data.entries) {
    if (!raw || typeof raw !== 'object') invalid();
    const kind = (raw as { kind?: unknown }).kind;
    const entry = controlWireRecord(raw, ['canonicalRootRelativePath', 'sourceIdentity', 'backupIdentity', 'mode', 'purpose', 'kind',
      ...(kind === 'regular_file' ? ['contentDigest', 'byteCount', 'linkCount'] : kind === 'unfollowed_link_metadata' ? ['linkTextDigest'] : [])]);
    const relative = inventoryPath(entry.canonicalRootRelativePath);
    // Descendant names retain their exact native UTF-8 bytes, including NFD.
    // Root/display text normalization may not select a different source file.
    if (Buffer.compare(Buffer.from(relative, 'utf8'), Buffer.from(previous, 'utf8')) <= 0 ||
        relative === 'auth.json') invalid();
    previous = relative;
    descriptor(entry.sourceIdentity); descriptor(entry.backupIdentity); controlWireInteger(entry.mode, 0, 4095);
    if (!['backup_only', 'portable_context', 'validation_only'].includes(entry.purpose as string)) invalid();
    if (kind === 'regular_file') {
      controlWireRef(entry.contentDigest); controlWireInteger(entry.byteCount);
      if (entry.linkCount !== 1) invalid();
    } else if (kind === 'unfollowed_link_metadata') controlWireRef(entry.linkTextDigest);
    else if (kind !== 'directory') invalid();
  }
  if (data.firstPath !== data.entries[0].canonicalRootRelativePath || data.lastPath !== previous) invalid();
  return immutableSnapshot(data) as OwnedImportInventoryPage;
}
export function decodeOwnedImportBackup(value: unknown): OwnedImportBackupV1 {
  const data = record(value, ['schemaVersion', 'format', 'migrationId', 'preparationRef', 'preparationDigest', 'inventoryRef',
    'inventoryDigest', 'backupRoot', 'entriesDigest', 'completedAt', 'backupDigest'], 'cliq-owned-legacy-import-backup-v1');
  id(data.migrationId); decodeOwnedImportRootDescriptor(data.backupRoot); time(data.completedAt); digest(data, 'backupDigest');
  return immutableSnapshot(data) as OwnedImportBackupV1;
}
export function decodeOwnedImportCredentialReady(value: unknown): OwnedImportCredentialReadyV1 {
  const data = record(value, ['schemaVersion', 'format', 'migrationId', 'preparationRef', 'preparationDigest', 'principalId',
    'sourceAuthObservationRef', 'sourceAuthObservationDigest', 'entries', 'completedAt', 'readyDigest'],
    'cliq-owned-legacy-import-credential-ready-v1');
  id(data.migrationId); controlWireText(data.principalId); const completed = time(data.completedAt);
  if (!Array.isArray(data.entries)) invalid();
  let previous = '';
  for (const raw of data.entries) {
    const entry = record(raw, ['endpointRegistrationId', 'endpointAuthorityRef', 'endpointAuthorityDigest', 'credentialGrantId',
      'credentialAuthorityRef', 'credentialAuthorityDigest', 'platformObservationRef', 'platformObservationDigest', 'observedAt', 'verifiedAt']);
    controlWireText(entry.endpointRegistrationId); const grant = controlWireText(entry.credentialGrantId);
    if (grant <= previous || time(entry.observedAt) > time(entry.verifiedAt) || time(entry.verifiedAt) > completed) invalid();
    previous = grant;
  }
  digest(data, 'readyDigest'); return immutableSnapshot(data) as OwnedImportCredentialReadyV1;
}
export function decodeOwnedImportSourceAuthObservation(value: unknown): OwnedImportSourceAuthObservationV1 {
  const data = record(value, ['schemaVersion', 'format', 'migrationId', 'legacyRootIdentityRef', 'legacyRootIdentityDigest',
    'observedAt', 'observation', 'observationDigest'], 'cliq-owned-import-source-auth-observation-v1');
  id(data.migrationId); time(data.observedAt);
  const presence = (data.observation as { presence?: unknown } | null)?.presence;
  const observation = controlWireRecord(data.observation, presence === 'absent' ? ['presence', 'noFollowLookupResult'] :
    ['presence', 'file', 'byteCount', 'contentDigest', 'mode', 'linkCount']);
  if (presence === 'absent') { if (observation.noFollowLookupResult !== 'ENOENT') invalid(); }
  else if (presence === 'present') {
    descriptor(observation.file); controlWireInteger(observation.byteCount); controlWireRef(observation.contentDigest);
    if (observation.mode !== 384 || observation.linkCount !== 1) invalid();
  } else invalid();
  digest(data, 'observationDigest'); return immutableSnapshot(data) as OwnedImportSourceAuthObservationV1;
}
export function decodePreparedImportDatabaseImageIdentity(value: unknown): PreparedImportDatabaseImageIdentityV1 {
  const data = record(value, ['schemaVersion', 'format', 'snapshotBoundary', 'excludedDatabaseTail', 'migrationId', 'preparationRef',
    'preparationDigest', 'signedSchemaManifestRef', 'signedSchemaManifestDigest', 'signedSchemaDigest', 'observation', 'imageDigest'],
    'cliq-prepared-import-database-image-identity-v1');
  if (data.snapshotBoundary !== 'owned_import_preview' || data.excludedDatabaseTail !== 'final_import_response_receipt_and_committing_time_fence') invalid();
  id(data.migrationId);
  const observation = controlWireRecord(data.observation, ['file', 'sha256', 'byteCount', 'mode', 'stateRoot', 'migrationDirectory',
    'collectionDirectory', 'packageDirectory', 'candidateDirectory', 'legacyRoot', 'migrationId']);
  descriptor(observation.file); controlWireRef(observation.sha256); controlWireInteger(observation.byteCount, 1);
  if (observation.mode !== 256 || observation.migrationId !== data.migrationId) invalid();
  for (const key of ['stateRoot', 'migrationDirectory', 'collectionDirectory', 'packageDirectory', 'candidateDirectory', 'legacyRoot'])
    descriptor(observation[key]);
  digest(data, 'imageDigest'); return immutableSnapshot(data) as PreparedImportDatabaseImageIdentityV1;
}
export function decodeOwnedPreparedImportCandidate(value: unknown): OwnedPreparedImportCandidateV1 {
  const data = record(value, ['schemaVersion', 'format', 'snapshotBoundary', 'excludedDatabaseTail', 'migrationId',
    'preparationRef', 'preparationDigest', 'kernelGenerationIdentityRef', 'kernelGenerationIdentityDigest', 'stateRootIdentityRef',
    'stateRootIdentityDigest', 'legacyRootIdentityRef', 'legacyRootIdentityDigest', 'signedSchemaManifestRef', 'signedSchemaManifestDigest',
    'signedSchemaDigest', 'inventoryRef', 'inventoryDigest', 'backupRef', 'backupDigest', 'credentialReadyRef', 'credentialReadyDigest',
    'imageIdentityRef', 'imageIdentityDigest', 'originalArtifactRefs', 'preimportSqlCutDigest', 'projectionDigest', 'importedRowSetDigest',
    'sessions', 'items', 'newArtifacts', 'stagedAt', 'candidateDigest'], 'cliq-owned-prepared-import-candidate-v1');
  if (data.snapshotBoundary !== 'owned_import_preview' || data.excludedDatabaseTail !== 'final_import_response_receipt_and_committing_time_fence') invalid();
  id(data.migrationId); time(data.stagedAt); for (const key of ['sessions', 'items', 'newArtifacts']) controlWireInteger(data[key]);
  if (!Array.isArray(data.originalArtifactRefs)) invalid();
  let previous = ''; for (const ref of data.originalArtifactRefs) { controlWireRef(ref); if (ref <= previous) invalid(); previous = ref; }
  digest(data, 'candidateDigest'); return immutableSnapshot(data) as OwnedPreparedImportCandidateV1;
}
export function decodeOwnedLegacyImportReceipt(value: unknown): OwnedLegacyImportReceiptV1 {
  const data = record(value, ['schemaVersion', 'format', 'kind', 'migrationId', 'principalId', 'requestId', 'requestRef', 'requestDigest',
    'channelIdentityRef', 'channelIdentityDigest', 'stateRootIdentityRef', 'stateRootIdentityDigest', 'legacyRootIdentityRef',
    'legacyRootIdentityDigest', 'preparationRef', 'preparationDigest', 'kernelGenerationIdentityRef', 'kernelGenerationIdentityDigest',
    'candidateRef', 'candidateDigest', 'importedRowSetDigest', 'credentialReadyRef', 'credentialReadyDigest', 'completedAt', 'receiptDigest'],
    'cliq-owned-legacy-import-receipt-v1');
  if (data.kind !== 'kernel_cutover') invalid(); id(data.migrationId); controlWireText(data.principalId); assertRequestId(controlWireText(data.requestId));
  time(data.completedAt); digest(data, 'receiptDigest'); return immutableSnapshot(data) as OwnedLegacyImportReceiptV1;
}
export function decodeOwnedLegacyImportResponse(value: unknown): OwnedLegacyImportResponseV1 {
  const data = record(value, ['protocolVersion', 'method', 'status', 'requestId', 'migrationId', 'preparationRef', 'preparationDigest',
    'receiptRef', 'receiptDigest', 'completedAt']);
  if (data.protocolVersion !== 1 || data.method !== 'state.migrate' || data.status !== 'completed') invalid();
  assertRequestId(controlWireText(data.requestId)); id(data.migrationId); time(data.completedAt);
  return immutableSnapshot(data) as OwnedLegacyImportResponseV1;
}

