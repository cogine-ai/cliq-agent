// The fixed installed rollback records join original request, generation and
// physical archive provenance. These decoders grant no mutation authority.
import { canonicalSha256 } from './canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { decodeKernelRollbackDrainingControl, type KernelRollbackDrainingControlV1 } from './kernel-archive-data.js';
import { decodeKernelArchiveDirectoryIdentity, KERNEL_ARCHIVE_MAX_MANIFEST_BYTES, type KernelArchiveDirectoryIdentity } from './kernel-archive-namespace.js';
import { assertRequestId, digestOmitting, identityHash, normalizeAbsolutePath, parseCanonicalTime } from './identity.js';
import { decodeMigrationAuthorityMarker, type MigrationAuthorityMarker } from './migration-control.js';
import { immutableSnapshot } from '../model/immutable.js';
import { decodeLegacyRollbackReceipt, type LegacyRollbackReceiptV1 } from './migration-control-wire.js';
import type { KernelRollbackArchiveReadyControlV1 } from './kernel-rollback-handoff.js';
export { decodeInstalledRollbackRequest, type KernelRollbackCommandV1 } from './migration-control-wire.js';
export { decodeLegacyRollbackReceipt, type LegacyRollbackReceiptV1 };

const REQUEST_FORMAT = 'cliq-rollback-to-legacy-request-v1';
const ARCHIVE_FORMAT = 'cliq-owned-kernel-archive-witness-v1';
const AUTH_FORMAT = 'cliq-legacy-rollback-auth-absence-v1';
const LEGACY_FORMAT = 'cliq-legacy-generation-v1';
const CONTROL_FORMAT = 'cliq-kernel-rollback-control-v1';
type LegacyMarker = Extract<MigrationAuthorityMarker, { authority: 'legacy' }>;
type KernelMarker = Extract<MigrationAuthorityMarker, { authority: 'kernel' }>;

export type RollbackToLegacyRequestV1 = Readonly<{
  schemaVersion: 1; format: typeof REQUEST_FORMAT; migrationId: string; principalId: string;
  channelIdentityRef: string; channelIdentityDigest: string; requestId: string;
  currentAuthorityMarkerRef: string; currentAuthorityMarkerDigest: string;
  currentKernelGenerationIdentityRef: string; currentKernelGenerationIdentityDigest: string;
  backupRef: string; backupDigest: string; requestedAt: string; requestDigest: string;
  allowPlaintextLegacyCredentials: boolean;
}>;
export type OwnedKernelArchiveWitnessV1 = Readonly<{
  schemaVersion: 1; format: typeof ARCHIVE_FORMAT; migrationId: string; archiveId: string;
  drainingControlRef: string; drainingControlDigest: string; kernelGenerationId: string;
  ownerEpoch: number; ownerAcquisitionEvidenceRef: string; ownerAcquisitionEvidenceDigest: string;
  archiveCollection: KernelArchiveDirectoryIdentity; archiveDirectory: KernelArchiveDirectoryIdentity;
  manifestFile: KernelArchiveDirectoryIdentity; manifestByteCount: number; manifestSha256: string;
  manifestDigest: string; witnessDigest: string;
}>;
export type LegacyRollbackAuthAbsenceV1 = Readonly<{
  schemaVersion: 1; format: typeof AUTH_FORMAT; migrationId: string;
  legacyRootIdentityRef: string; legacyRootIdentityDigest: string;
  originalSourceAuthObservationRef: string; originalSourceAuthObservationDigest: string;
  originalMigratedAuthMarkerRef: string; originalMigratedAuthMarkerDigest: string;
  archiveReadyControlRef: string; archiveReadyControlDigest: string;
  inspectorOwnerEpoch: number; inspectorOwnerAcquisitionEvidenceRef: string; inspectorOwnerAcquisitionEvidenceDigest: string;
  previousMarkerFile: KernelArchiveDirectoryIdentity;
  observation: 'exact_marker_removed_and_directory_synced' | 'original_intent_current_absence_and_directory_synced';
  observedAt: string; observationDigest: string;
}>;
export type RestoredAbsentLegacyGenerationV1 = Readonly<{
  schemaVersion: 1; format: typeof LEGACY_FORMAT; migrationId: string; legacyGenerationId: string;
  backupRef: string; backupDigest: string; restoredEntriesDigest: string; verifiedAt: string; manifestDigest: string;
  authOutcome: 'restored_absent'; restoredAuthObservationRef: string; restoredAuthObservationDigest: string;
}>;
export type KernelRollbackRestoringControlV1 = Readonly<{
  schemaVersion: 1; format: typeof CONTROL_FORMAT; phase: 'rollback_restoring'; controlRevision: 3;
  migrationId: string; archiveId: string; kernelGenerationId: string;
  stateRootIdentityRef: string; stateRootIdentityDigest: string; stateRootCanonicalAbsolutePath: string;
  requestRef: string; requestDigest: string; originalImportControlRef: string; originalImportControlDigest: string;
  originalKernelAuthorityRef: string; originalKernelAuthorityDigest: string; preparedAt: string;
  drainingControlRef: string; drainingControlDigest: string;
  archiveReadyControlRef: string; archiveReadyControlDigest: string;
  archivedKernelGenerationRef: string; archivedKernelGenerationDigest: string;
  preparerOwnerEpoch: number; preparerOwnerAcquisitionEvidenceRef: string; preparerOwnerAcquisitionEvidenceDigest: string;
  legacyGenerationRef: string; legacyGenerationDigest: string;
  preparedReceiptRef: string; preparedReceiptDigest: string;
  preparedLegacyAuthorityMarkerRef: string; preparedLegacyAuthorityMarkerDigest: string;
  preparedRootAuthorityFile: KernelArchiveDirectoryIdentity;
  preparedLegacyAuthorityFile: KernelArchiveDirectoryIdentity;
  originalRootAuthorityFile: KernelArchiveDirectoryIdentity;
  originalLegacyAuthorityFile: KernelArchiveDirectoryIdentity;
  updatedAt: string; controlDigest: string;
}>;

function invalid(): never { throw new TypeError('installed rollback record differs from its fixed original generation contract'); }
function id(value: unknown): string {
  const text = controlWireText(value, 43);
  if (!/^[A-Za-z0-9_-]{43}$/u.test(text)) return invalid();
  return text;
}
function time(value: unknown): string { const text = controlWireText(value); parseCanonicalTime(text); return text; }
function record(value: unknown, format: string, digest: string, fields: readonly string[]): Record<string, unknown> {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'migrationId', digest, ...fields]);
  if (data.schemaVersion !== 1 || data.format !== format) return invalid();
  id(data.migrationId);
  for (const key of Object.keys(data)) if (key.endsWith('Ref') || key.endsWith('Digest')) controlWireRef(data[key]);
  if (digestOmitting(data, digest) !== data[digest]) return invalid();
  return data;
}
export function decodeRollbackToLegacyRequest(value: unknown): RollbackToLegacyRequestV1 {
  const data = record(value, REQUEST_FORMAT, 'requestDigest', ['principalId', 'channelIdentityRef', 'channelIdentityDigest',
    'requestId', 'currentAuthorityMarkerRef', 'currentAuthorityMarkerDigest', 'currentKernelGenerationIdentityRef',
    'currentKernelGenerationIdentityDigest', 'backupRef', 'backupDigest', 'requestedAt', 'allowPlaintextLegacyCredentials']);
  id(data.principalId); assertRequestId(controlWireText(data.requestId)); time(data.requestedAt);
  if (typeof data.allowPlaintextLegacyCredentials !== 'boolean') return invalid();
  return immutableSnapshot(data) as RollbackToLegacyRequestV1;
}
export function decodeOwnedKernelArchiveWitness(value: unknown): OwnedKernelArchiveWitnessV1 {
  const data = record(value, ARCHIVE_FORMAT, 'witnessDigest', ['archiveId', 'drainingControlRef', 'drainingControlDigest',
    'kernelGenerationId', 'ownerEpoch', 'ownerAcquisitionEvidenceRef', 'ownerAcquisitionEvidenceDigest',
    'archiveCollection', 'archiveDirectory', 'manifestFile', 'manifestByteCount', 'manifestSha256', 'manifestDigest']);
  id(data.archiveId); id(data.kernelGenerationId); controlWireInteger(data.ownerEpoch, 1);
  controlWireInteger(data.manifestByteCount, 1, KERNEL_ARCHIVE_MAX_MANIFEST_BYTES); controlWireRef(data.manifestSha256);
  const collection = decodeKernelArchiveDirectoryIdentity(data.archiveCollection), directory = decodeKernelArchiveDirectoryIdentity(data.archiveDirectory);
  const manifest = decodeKernelArchiveDirectoryIdentity(data.manifestFile);
  for (const item of [directory, manifest]) {
    if (item.deviceId !== collection.deviceId || item.ownerUid !== collection.ownerUid) return invalid();
  }
  if (new Set([collection.fileId, directory.fileId, manifest.fileId]).size !== 3) return invalid();
  return immutableSnapshot(data) as OwnedKernelArchiveWitnessV1;
}
export function decodeLegacyRollbackAuthAbsence(value: unknown): LegacyRollbackAuthAbsenceV1 {
  const data = record(value, AUTH_FORMAT, 'observationDigest', ['legacyRootIdentityRef', 'legacyRootIdentityDigest',
    'originalSourceAuthObservationRef', 'originalSourceAuthObservationDigest', 'originalMigratedAuthMarkerRef',
    'originalMigratedAuthMarkerDigest', 'archiveReadyControlRef', 'archiveReadyControlDigest',
    'inspectorOwnerEpoch', 'inspectorOwnerAcquisitionEvidenceRef', 'inspectorOwnerAcquisitionEvidenceDigest',
    'previousMarkerFile', 'observation', 'observedAt']);
  if (data.observation !== 'exact_marker_removed_and_directory_synced' &&
      data.observation !== 'original_intent_current_absence_and_directory_synced') return invalid();
  controlWireInteger(data.inspectorOwnerEpoch, 1);
  decodeKernelArchiveDirectoryIdentity(data.previousMarkerFile); time(data.observedAt);
  return immutableSnapshot(data) as LegacyRollbackAuthAbsenceV1;
}
export function decodeRestoredAbsentLegacyGeneration(value: unknown): RestoredAbsentLegacyGenerationV1 {
  const data = record(value, LEGACY_FORMAT, 'manifestDigest', ['legacyGenerationId', 'backupRef', 'backupDigest',
    'restoredEntriesDigest', 'verifiedAt', 'authOutcome', 'restoredAuthObservationRef', 'restoredAuthObservationDigest']);
  if (data.authOutcome !== 'restored_absent' || id(data.legacyGenerationId) !== identityHash(data.migrationId as string, 'legacy')) return invalid();
  time(data.verifiedAt); return immutableSnapshot(data) as RestoredAbsentLegacyGenerationV1;
}
const DRAINING_REPEATED = ['archiveId', 'kernelGenerationId', 'stateRootIdentityRef', 'stateRootIdentityDigest',
  'stateRootCanonicalAbsolutePath', 'requestRef', 'requestDigest', 'originalImportControlRef', 'originalImportControlDigest',
  'originalKernelAuthorityRef', 'originalKernelAuthorityDigest', 'preparedAt'] as const;
export function decodeKernelRollbackRestoringControl(value: unknown): KernelRollbackRestoringControlV1 {
  const data = record(value, CONTROL_FORMAT, 'controlDigest', ['phase', 'controlRevision', ...DRAINING_REPEATED,
    'drainingControlRef', 'drainingControlDigest', 'archiveReadyControlRef', 'archiveReadyControlDigest',
    'archivedKernelGenerationRef', 'archivedKernelGenerationDigest',
    'preparerOwnerEpoch', 'preparerOwnerAcquisitionEvidenceRef', 'preparerOwnerAcquisitionEvidenceDigest',
    'legacyGenerationRef', 'legacyGenerationDigest', 'preparedReceiptRef', 'preparedReceiptDigest',
    'preparedLegacyAuthorityMarkerRef', 'preparedLegacyAuthorityMarkerDigest',
    'preparedRootAuthorityFile', 'preparedLegacyAuthorityFile', 'originalRootAuthorityFile', 'originalLegacyAuthorityFile', 'updatedAt']);
  if (data.phase !== 'rollback_restoring' || data.controlRevision !== 3 || time(data.preparedAt) > time(data.updatedAt)) return invalid();
  controlWireInteger(data.preparerOwnerEpoch, 1);
  const root = controlWireText(data.stateRootCanonicalAbsolutePath, 4096);
  if (normalizeAbsolutePath(root) !== root) return invalid();
  const stagedRoot = decodeKernelArchiveDirectoryIdentity(data.preparedRootAuthorityFile);
  const stagedLegacy = decodeKernelArchiveDirectoryIdentity(data.preparedLegacyAuthorityFile);
  const originalRoot = decodeKernelArchiveDirectoryIdentity(data.originalRootAuthorityFile);
  const originalLegacy = decodeKernelArchiveDirectoryIdentity(data.originalLegacyAuthorityFile);
  const markers = [stagedRoot, stagedLegacy, originalRoot, originalLegacy];
  if (markers.some(file => file.ownerUid !== stagedRoot.ownerUid) ||
      new Set(markers.map(file => file.deviceId + ':' + file.fileId)).size !== 4 ||
      stagedRoot.deviceId !== originalRoot.deviceId || stagedLegacy.deviceId !== originalLegacy.deviceId) return invalid();
  id(data.archiveId); id(data.kernelGenerationId);
  return immutableSnapshot(data) as KernelRollbackRestoringControlV1;
}
/** Closed original identities for the fixed native successor observer.
 * The packet supplies no caller-selected path or mutation permission. */
export function encodePreparedRollbackMarkerIdentities(value: KernelRollbackRestoringControlV1, requireUnpublishedLegacy = false): Buffer {
  const control = decodeKernelRollbackRestoringControl(value), packet = Buffer.alloc(80);
  packet.write('CLQMR001', 0, 'ascii');
  const files = [control.originalRootAuthorityFile, control.originalLegacyAuthorityFile,
    control.preparedRootAuthorityFile, control.preparedLegacyAuthorityFile];
  files.forEach((file, index) => {
    packet.writeBigUInt64LE(BigInt(file.deviceId), 8 + index * 16);
    packet.writeBigUInt64LE(BigInt(file.fileId), 16 + index * 16);
  });
  packet.writeUInt32LE(control.originalRootAuthorityFile.ownerUid, 72);
  if (requireUnpublishedLegacy) packet.writeUInt32LE(1, 76);
  return packet;
}
export function assertKernelRollbackControlSuccessor(before: KernelRollbackDrainingControlV1, after: KernelRollbackRestoringControlV1,
  ready: KernelRollbackArchiveReadyControlV1): void {
  before = decodeKernelRollbackDrainingControl(before); after = decodeKernelRollbackRestoringControl(after);
  if (after.migrationId !== before.migrationId || after.drainingControlRef !== canonicalSha256(before) ||
      after.drainingControlDigest !== before.controlDigest ||
      after.archiveReadyControlRef !== canonicalSha256(ready) || after.archiveReadyControlDigest !== ready.controlDigest ||
      ready.migrationId !== after.migrationId || ready.drainingControlRef !== after.drainingControlRef ||
      ready.drainingControlDigest !== after.drainingControlDigest || ready.archivedKernelGenerationRef !== after.archivedKernelGenerationRef ||
      ready.archivedKernelGenerationDigest !== after.archivedKernelGenerationDigest || ready.updatedAt > after.updatedAt ||
      DRAINING_REPEATED.some(key => before[key] !== after[key] || before[key] !== ready[key])) invalid();
}

/** Exact acyclic dependency graph, independent of physical custody and the
 * genuine last StateOwner transaction. Historical descriptor-copy formats
 * cannot be used in this original-connection profile. */
export function assertKernelRollbackRecordClosure(input: Readonly<{
  request: RollbackToLegacyRequestV1; originalMarker: KernelMarker; draining: KernelRollbackDrainingControlV1;
  ready: KernelRollbackArchiveReadyControlV1;
  archive: OwnedKernelArchiveWitnessV1; auth: LegacyRollbackAuthAbsenceV1; legacy: RestoredAbsentLegacyGenerationV1;
  receipt: LegacyRollbackReceiptV1; marker: LegacyMarker; restoring: KernelRollbackRestoringControlV1;
}>): void {
  const request = decodeRollbackToLegacyRequest(input.request), original = decodeMigrationAuthorityMarker(input.originalMarker);
  const draining = decodeKernelRollbackDrainingControl(input.draining), archive = decodeOwnedKernelArchiveWitness(input.archive);
  const auth = decodeLegacyRollbackAuthAbsence(input.auth), legacy = decodeRestoredAbsentLegacyGeneration(input.legacy);
  const receipt = decodeLegacyRollbackReceipt(input.receipt), marker = decodeMigrationAuthorityMarker(input.marker);
  const restoring = decodeKernelRollbackRestoringControl(input.restoring);
  const { ready } = input;
  assertKernelRollbackControlSuccessor(draining, restoring, ready);
  if (original.authority !== 'kernel' || marker.authority !== 'legacy' ||
      [original, draining, archive, auth, legacy, receipt, marker, restoring].some(row => row.migrationId !== request.migrationId) ||
      request.currentAuthorityMarkerRef !== canonicalSha256(original) || request.currentAuthorityMarkerDigest !== original.markerDigest ||
      request.currentKernelGenerationIdentityRef !== original.kernelGenerationIdentityRef ||
      request.currentKernelGenerationIdentityDigest !== original.kernelGenerationIdentityDigest ||
      draining.requestRef !== canonicalSha256(request) || draining.requestDigest !== request.requestDigest ||
      draining.originalKernelAuthorityRef !== request.currentAuthorityMarkerRef ||
      draining.originalKernelAuthorityDigest !== request.currentAuthorityMarkerDigest ||
      draining.kernelGenerationId !== original.generationId || archive.kernelGenerationId !== draining.kernelGenerationId ||
      archive.archiveId !== draining.archiveId || archive.drainingControlRef !== canonicalSha256(draining) ||
      archive.drainingControlDigest !== draining.controlDigest) invalid();
  if (auth.archiveReadyControlRef !== restoring.archiveReadyControlRef || auth.archiveReadyControlDigest !== restoring.archiveReadyControlDigest ||
      auth.originalSourceAuthObservationRef !== ready.originalSourceAuthObservationRef ||
      auth.originalSourceAuthObservationDigest !== ready.originalSourceAuthObservationDigest ||
      auth.originalMigratedAuthMarkerRef !== ready.originalMigratedAuthMarkerRef || auth.originalMigratedAuthMarkerDigest !== ready.originalMigratedAuthMarkerDigest ||
      canonicalSha256(auth.previousMarkerFile) !== canonicalSha256(ready.originalAuthMarkerFile) ||
      auth.inspectorOwnerEpoch !== restoring.preparerOwnerEpoch || auth.inspectorOwnerAcquisitionEvidenceRef !== restoring.preparerOwnerAcquisitionEvidenceRef ||
      auth.inspectorOwnerAcquisitionEvidenceDigest !== restoring.preparerOwnerAcquisitionEvidenceDigest || auth.inspectorOwnerEpoch < archive.ownerEpoch ||
      (auth.observation === 'original_intent_current_absence_and_directory_synced' && auth.inspectorOwnerEpoch <= archive.ownerEpoch) ||
      (auth.inspectorOwnerEpoch === archive.ownerEpoch && (auth.inspectorOwnerAcquisitionEvidenceRef !== archive.ownerAcquisitionEvidenceRef ||
        auth.inspectorOwnerAcquisitionEvidenceDigest !== archive.ownerAcquisitionEvidenceDigest))) invalid();
  if (legacy.backupRef !== request.backupRef || legacy.backupDigest !== request.backupDigest ||
      legacy.restoredAuthObservationRef !== canonicalSha256(auth) || legacy.restoredAuthObservationDigest !== auth.observationDigest ||
      receipt.rollbackRequestRef !== draining.requestRef || receipt.rollbackRequestDigest !== draining.requestDigest ||
      receipt.backupRef !== legacy.backupRef || receipt.backupDigest !== legacy.backupDigest ||
      receipt.archivedKernelGenerationRef !== canonicalSha256(archive) || receipt.archivedKernelGenerationDigest !== archive.witnessDigest ||
      receipt.legacyGenerationRef !== canonicalSha256(legacy) || receipt.legacyGenerationDigest !== legacy.manifestDigest) invalid();
  if (marker.generationId !== legacy.legacyGenerationId || marker.receiptRef !== canonicalSha256(receipt) ||
      marker.receiptDigest !== receipt.receiptDigest || marker.legacyGenerationRef !== receipt.legacyGenerationRef ||
      marker.legacyGenerationDigest !== receipt.legacyGenerationDigest ||
      restoring.archivedKernelGenerationRef !== receipt.archivedKernelGenerationRef ||
      restoring.archivedKernelGenerationDigest !== receipt.archivedKernelGenerationDigest ||
      restoring.legacyGenerationRef !== marker.legacyGenerationRef || restoring.legacyGenerationDigest !== marker.legacyGenerationDigest ||
      restoring.preparedReceiptRef !== marker.receiptRef || restoring.preparedReceiptDigest !== marker.receiptDigest ||
      restoring.preparedLegacyAuthorityMarkerRef !== canonicalSha256(marker) ||
      restoring.preparedLegacyAuthorityMarkerDigest !== marker.markerDigest) invalid();
  for (const row of [original, marker, restoring]) {
    if (row.stateRootIdentityRef !== draining.stateRootIdentityRef || row.stateRootIdentityDigest !== draining.stateRootIdentityDigest ||
        row.stateRootCanonicalAbsolutePath !== draining.stateRootCanonicalAbsolutePath) invalid();
  }
  if (original.publishedAt > request.requestedAt || request.requestedAt > draining.preparedAt || ready.updatedAt > auth.observedAt ||
      auth.observedAt > legacy.verifiedAt || legacy.verifiedAt > receipt.completedAt ||
      receipt.completedAt > marker.publishedAt || marker.publishedAt > restoring.updatedAt) invalid();
}
