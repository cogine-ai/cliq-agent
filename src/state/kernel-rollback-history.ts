import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeKernelRollbackDrainingControl } from '../kernel/kernel-archive-data.js';
import { assertKernelRollbackRecordClosure, decodeKernelRollbackRestoringControl, decodeLegacyRollbackAuthAbsence,
  decodeLegacyRollbackReceipt, decodeOwnedKernelArchiveWitness, decodeRestoredAbsentLegacyGeneration,
  decodeRollbackToLegacyRequest } from '../kernel/kernel-rollback-records.js';
import { decodeMigrationAuthorityMarker } from '../kernel/migration-control.js';
import { assertKernelRollbackArchiveReadyClosure, decodeKernelRollbackArchiveReadyControl,
  type KernelRollbackArchiveReadyControlV1 } from '../kernel/kernel-rollback-handoff.js';
import { KernelStorageError } from './errors.js';
import { checkCanonicalBytes } from './installed-artifacts.js';
import type { MigrationTailArtifacts } from './installed-runtime.js';

function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'retained rollback does not close its exact prepared original history'); }
type TailReader = Pick<MigrationTailArtifacts, 'readCanonical'>;
async function readTail<T>(tail: TailReader, ref: string, decode: (value: unknown) => T, signal?: AbortSignal): Promise<T> {
  signal?.throwIfAborted();
  const value = await tail.readCanonical(ref);
  signal?.throwIfAborted();
  if (canonicalSha256(value) !== ref) return invalid();
  return decode(value);
}
async function readArchiveReady(tail: TailReader, ready: KernelRollbackArchiveReadyControlV1,
  currentMarker: ReturnType<typeof decodeMigrationAuthorityMarker>, signal?: AbortSignal) {
  if (currentMarker.authority !== 'kernel' || canonicalSha256(currentMarker) !== ready.originalKernelAuthorityRef ||
      currentMarker.markerDigest !== ready.originalKernelAuthorityDigest) return invalid();
  const read = <T>(ref: string, decode: (value: unknown) => T) => readTail(tail, ref, decode, signal);
  const retained = await read(canonicalSha256(ready), decodeKernelRollbackArchiveReadyControl);
  const draining = await read(retained.drainingControlRef, decodeKernelRollbackDrainingControl);
  const originalMarker = await read(draining.originalKernelAuthorityRef, decodeMigrationAuthorityMarker);
  const request = await read(draining.requestRef, decodeRollbackToLegacyRequest);
  const archive = await read(retained.archivedKernelGenerationRef, decodeOwnedKernelArchiveWitness);
  if (originalMarker.authority !== 'kernel' || canonicalSha256(originalMarker) !== canonicalSha256(currentMarker)) return invalid();
  assertKernelRollbackArchiveReadyClosure({ ready: retained, draining, originalMarker, request, archive });
  return Object.freeze({ ready: retained, request, originalMarker, draining, archive });
}
export async function readRetainedRollbackArchiveReady(controlBytes: Buffer, currentKernelMarkerBytes: Buffer,
  tail: TailReader, signal?: AbortSignal) {
  return readArchiveReady(tail, decodeKernelRollbackArchiveReadyControl(checkCanonicalBytes(controlBytes)),
    decodeMigrationAuthorityMarker(checkCanonicalBytes(currentKernelMarkerBytes)), signal);
}
export type RetainedRollbackArchiveReady = Awaited<ReturnType<typeof readRetainedRollbackArchiveReady>>;

/** Reads a complete retained data spine from the fixed migration tail. Its
 * callers must own real pre-Owner SH or current EX and physical observations.
 * This result supplies neither an Owner nor a marker publication permit. */
export async function readRetainedRollbackRecords(controlBytes: Buffer, currentKernelMarkerBytes: Buffer,
  tail: TailReader, signal?: AbortSignal) {
  const restoring = decodeKernelRollbackRestoringControl(checkCanonicalBytes(controlBytes));
  const currentMarker = decodeMigrationAuthorityMarker(checkCanonicalBytes(currentKernelMarkerBytes));
  if (currentMarker.authority !== 'kernel' || canonicalSha256(currentMarker) !== restoring.originalKernelAuthorityRef ||
      currentMarker.markerDigest !== restoring.originalKernelAuthorityDigest) return invalid();
  const read = <T>(ref: string, decode: (value: unknown) => T) => readTail(tail, ref, decode, signal);
  await read(canonicalSha256(restoring), decodeKernelRollbackRestoringControl);
  const original = await readArchiveReady(tail, await read(restoring.archiveReadyControlRef, decodeKernelRollbackArchiveReadyControl),
    currentMarker, signal);
  const { request, originalMarker, draining, archive, ready } = original;
  const legacy = await read(restoring.legacyGenerationRef, decodeRestoredAbsentLegacyGeneration);
  const auth = await read(legacy.restoredAuthObservationRef, decodeLegacyRollbackAuthAbsence);
  const receipt = await read(restoring.preparedReceiptRef, decodeLegacyRollbackReceipt);
  const marker = await read(restoring.preparedLegacyAuthorityMarkerRef, decodeMigrationAuthorityMarker);
  if (originalMarker.authority !== 'kernel' || marker.authority !== 'legacy' ||
      canonicalSha256(originalMarker) !== canonicalSha256(currentMarker)) return invalid();
  assertKernelRollbackRecordClosure({ request, originalMarker, draining, archive, ready, auth, legacy, receipt, marker, restoring });
  return Object.freeze({ ...original, auth, legacy, receipt, marker, restoring });
}
export type RetainedRollbackRecords = Awaited<ReturnType<typeof readRetainedRollbackRecords>>;
