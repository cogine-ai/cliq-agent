import { canonicalSha256 } from './canonical.js';
import { assertControlWireJson, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { digestOmitting, parseCanonicalTime } from './identity.js';
import { decodeKernelRollbackDrainingControl, type KernelRollbackDrainingControlV1 } from './kernel-archive-data.js';
import { decodeKernelArchiveDirectoryIdentity, type KernelArchiveDirectoryIdentity } from './kernel-archive-namespace.js';
import { decodeOwnedKernelArchiveWitness, decodeRollbackToLegacyRequest, type OwnedKernelArchiveWitnessV1,
  type RollbackToLegacyRequestV1 } from './kernel-rollback-records.js';
import { decodeMigrationAuthorityMarker, type MigrationAuthorityMarker } from './migration-control.js';
import { immutableSnapshot } from '../model/immutable.js';

type DrainingFields = Omit<KernelRollbackDrainingControlV1, 'phase' | 'controlRevision' | 'controlDigest'>;
export type KernelRollbackArchiveReadyControlV1 = DrainingFields & Readonly<{
  phase: 'rollback_archive_ready'; controlRevision: 2;
  drainingControlRef: string; drainingControlDigest: string;
  archivedKernelGenerationRef: string; archivedKernelGenerationDigest: string;
  originalSourceAuthObservationRef: string; originalSourceAuthObservationDigest: string;
  originalMigratedAuthMarkerRef: string; originalMigratedAuthMarkerDigest: string;
  originalAuthMarkerFile: KernelArchiveDirectoryIdentity;
  updatedAt: string; controlDigest: string;
}>;

const originalFields = ['migrationId', 'archiveId', 'kernelGenerationId', 'stateRootIdentityRef', 'stateRootIdentityDigest',
  'stateRootCanonicalAbsolutePath', 'requestRef', 'requestDigest', 'originalImportControlRef', 'originalImportControlDigest',
  'originalKernelAuthorityRef', 'originalKernelAuthorityDigest', 'preparedAt'] as const;
const retainedRefs = ['drainingControlRef', 'drainingControlDigest', 'archivedKernelGenerationRef', 'archivedKernelGenerationDigest',
  'originalSourceAuthObservationRef', 'originalSourceAuthObservationDigest',
  'originalMigratedAuthMarkerRef', 'originalMigratedAuthMarkerDigest', 'controlDigest'] as const;
function invalid(): never { throw new TypeError('rollback handoff differs from its exact completed original archive and auth preimage'); }

/** This control advances only after the whole original archive has closed
 * and an independent current scope has verified its source and target.
 * Its auth inode is the authorized preimage, not evidence of an unlink. */
export function decodeKernelRollbackArchiveReadyControl(value: unknown): KernelRollbackArchiveReadyControlV1 {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'phase', 'controlRevision', ...originalFields,
    ...retainedRefs, 'originalAuthMarkerFile', 'updatedAt']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-kernel-rollback-control-v1' ||
      data.phase !== 'rollback_archive_ready' || data.controlRevision !== 2 ||
      digestOmitting(data, 'controlDigest') !== data.controlDigest) return invalid();
  for (const ref of retainedRefs) controlWireRef(data[ref]);
  const initial = { ...Object.fromEntries(originalFields.map(key => [key, data[key]])),
    schemaVersion: 1, format: data.format, phase: 'rollback_draining', controlRevision: 1,
    controlDigest: data.drainingControlDigest };
  const draining = decodeKernelRollbackDrainingControl(initial);
  if (canonicalSha256(draining) !== data.drainingControlRef ||
      parseCanonicalTime(controlWireText(data.updatedAt)) < parseCanonicalTime(draining.preparedAt)) return invalid();
  const file = decodeKernelArchiveDirectoryIdentity(data.originalAuthMarkerFile);
  if (BigInt(file.deviceId) > (1n << 64n) - 1n || BigInt(file.fileId) < 1n || BigInt(file.fileId) > (1n << 64n) - 1n ||
      file.ownerUid > 0xffff_ffff) return invalid();
  return immutableSnapshot(data) as KernelRollbackArchiveReadyControlV1;
}

export function assertKernelRollbackArchiveReadyClosure(input: Readonly<{
  ready: KernelRollbackArchiveReadyControlV1; draining: KernelRollbackDrainingControlV1; request: RollbackToLegacyRequestV1;
  originalMarker: Extract<MigrationAuthorityMarker, { authority: 'kernel' }>; archive: OwnedKernelArchiveWitnessV1;
}>): void {
  const ready = decodeKernelRollbackArchiveReadyControl(input.ready), draining = decodeKernelRollbackDrainingControl(input.draining);
  const request = decodeRollbackToLegacyRequest(input.request), marker = decodeMigrationAuthorityMarker(input.originalMarker);
  const archive = decodeOwnedKernelArchiveWitness(input.archive);
  if (marker.authority !== 'kernel' || ready.drainingControlRef !== canonicalSha256(draining) ||
      ready.drainingControlDigest !== draining.controlDigest || originalFields.some(field => ready[field] !== draining[field]) ||
      ready.archivedKernelGenerationRef !== canonicalSha256(archive) || ready.archivedKernelGenerationDigest !== archive.witnessDigest ||
      archive.drainingControlRef !== ready.drainingControlRef || archive.drainingControlDigest !== ready.drainingControlDigest ||
      archive.migrationId !== ready.migrationId || archive.archiveId !== ready.archiveId || archive.kernelGenerationId !== ready.kernelGenerationId ||
      ready.requestRef !== canonicalSha256(request) || ready.requestDigest !== request.requestDigest || request.migrationId !== ready.migrationId ||
      request.currentAuthorityMarkerRef !== ready.originalKernelAuthorityRef || request.currentAuthorityMarkerDigest !== ready.originalKernelAuthorityDigest ||
      ready.originalKernelAuthorityRef !== canonicalSha256(marker) || ready.originalKernelAuthorityDigest !== marker.markerDigest ||
      marker.migrationId !== ready.migrationId || marker.generationId !== ready.kernelGenerationId ||
      marker.kernelGenerationIdentityRef !== request.currentKernelGenerationIdentityRef ||
      marker.kernelGenerationIdentityDigest !== request.currentKernelGenerationIdentityDigest ||
      marker.stateRootIdentityRef !== ready.stateRootIdentityRef || marker.stateRootIdentityDigest !== ready.stateRootIdentityDigest ||
      marker.stateRootCanonicalAbsolutePath !== ready.stateRootCanonicalAbsolutePath ||
      marker.publishedAt > request.requestedAt || request.requestedAt > ready.preparedAt) invalid();
}

export function encodeRollbackArchiveReadyAuthIdentity(value: KernelRollbackArchiveReadyControlV1): Buffer {
  const { originalAuthMarkerFile: file } = decodeKernelRollbackArchiveReadyControl(value), packet = Buffer.alloc(32);
  packet.write('CLQMA001', 0, 'ascii');
  packet.writeBigUInt64LE(BigInt(file.deviceId), 8); packet.writeBigUInt64LE(BigInt(file.fileId), 16);
  packet.writeUInt32LE(file.ownerUid, 24);
  return packet;
}
