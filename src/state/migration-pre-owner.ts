// Readonly pre-Owner refusal only. This never qualifies migration recovery or
// confers authority from document bytes; after-Owner complete typed SQL/CAS
// history verification remains independently required for Kernel entry.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { decodeOwnedLegacyImportControl, decodeMigrationAuthorityMarker } from '../kernel/migration-control.js';
import { decodeKernelRollbackRestoringControl } from '../kernel/kernel-rollback-records.js';
import { decodeKernelRollbackArchiveReadyControl } from '../kernel/kernel-rollback-handoff.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { KernelMigrationEntryObservation } from './native-owner.js';
import { KernelStorageError } from './errors.js';

function invalid(): never {
  throw new KernelStorageError('RECOVERY_REQUIRED', 'installed migration authority requires its retained original recovery path before StateOwner acquisition');
}
function document(bytes: Buffer): unknown {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 1_048_576) return invalid();
  const value: unknown = parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  if (!canonicalJsonBytes(value).equals(bytes)) return invalid(); return value;
}
/** Complete archive-ready data is eligible only for the fixed fenced
 * successor path. Its actual archive and auth scope are reopened later. */
export function readKernelRollbackArchiveReadyPreOwner(observed: KernelMigrationEntryObservation,
  root: Readonly<{ canonicalAbsolutePath: string; identityRef: string; identityDigest: string }>) {
  if (observed.kind !== 'controlled') return undefined;
  try {
    const fixed = document(observed.controlBytes);
    if ((fixed as { format?: unknown; phase?: unknown } | null)?.format !== 'cliq-kernel-rollback-control-v1' ||
        (fixed as { phase?: unknown }).phase !== 'rollback_archive_ready') return undefined;
    const ready = decodeKernelRollbackArchiveReadyControl(fixed);
    if (observed.authorityBytes === undefined || Reflect.ownKeys(observed).length !== 3) return invalid();
    const marker = decodeMigrationAuthorityMarker(document(observed.authorityBytes));
    if (ready.stateRootCanonicalAbsolutePath !== root.canonicalAbsolutePath || ready.stateRootIdentityRef !== root.identityRef ||
        ready.stateRootIdentityDigest !== root.identityDigest || marker.authority !== 'kernel' ||
        marker.migrationId !== ready.migrationId || marker.generationId !== ready.kernelGenerationId ||
        marker.stateRootCanonicalAbsolutePath !== root.canonicalAbsolutePath || marker.stateRootIdentityRef !== root.identityRef ||
        marker.stateRootIdentityDigest !== root.identityDigest || ready.originalKernelAuthorityRef !== canonicalSha256(marker) ||
        ready.originalKernelAuthorityDigest !== marker.markerDigest || ready.preparedAt < marker.publishedAt) return invalid();
    return Object.freeze({ ready, marker });
  } catch { return invalid(); }
}
/** Classified restoring data only. The installed pre-Owner SH reader must
 * close the fixed retained history before the ordinary Owner opener runs. */
export function readKernelRollbackPreOwner(observed: KernelMigrationEntryObservation,
  root: Readonly<{ canonicalAbsolutePath: string; identityRef: string; identityDigest: string }>) {
  if (observed.kind !== 'controlled') return undefined;
  try {
    const fixed = document(observed.controlBytes);
    if ((fixed as { format?: unknown; phase?: unknown } | null)?.format !== 'cliq-kernel-rollback-control-v1' ||
        (fixed as { phase?: unknown }).phase !== 'rollback_restoring') return undefined;
    const restoring = decodeKernelRollbackRestoringControl(fixed);
    if (observed.authorityBytes === undefined || Reflect.ownKeys(observed).length !== 3) return invalid();
    const marker = decodeMigrationAuthorityMarker(document(observed.authorityBytes));
    if (restoring.stateRootCanonicalAbsolutePath !== root.canonicalAbsolutePath || restoring.stateRootIdentityRef !== root.identityRef ||
        restoring.stateRootIdentityDigest !== root.identityDigest || marker.authority !== 'kernel' ||
        marker.migrationId !== restoring.migrationId || marker.generationId !== restoring.kernelGenerationId ||
        marker.stateRootCanonicalAbsolutePath !== root.canonicalAbsolutePath || marker.stateRootIdentityRef !== root.identityRef ||
        marker.stateRootIdentityDigest !== root.identityDigest || restoring.originalKernelAuthorityRef !== canonicalSha256(marker) ||
        restoring.originalKernelAuthorityDigest !== marker.markerDigest || restoring.preparedAt < marker.publishedAt) return invalid();
    return Object.freeze({ restoring, marker });
  } catch { return invalid(); }
}
/** The actual readonly observer supplies complete original bytes under SH.
 * Any Legacy authority, unknown rollback phase or malformed record refuses
 * before the first Owner/SQL action. An initial partial Kernel cutover remains
 * subject to the existing fenced successor reader, never ordinary admission. */
export function assertKernelEntryAllowsStateOwner(observed: KernelMigrationEntryObservation,
  root: Readonly<{ canonicalAbsolutePath: string; identityRef: string; identityDigest: string }>): void {
  try {
    if (observed.kind === 'unmigrated') {
      if (Reflect.ownKeys(observed).length !== 1) return invalid(); return;
    }
    if (observed.kind !== 'controlled' || Reflect.ownKeys(observed).length !== (observed.authorityBytes === undefined ? 2 : 3)) return invalid();
    const fixed = document(observed.controlBytes);
    // The dedicated EX startup paths first close their exact retained tail
    // before acquisition. Raw draining has no complete original handoff.
    if ((fixed as { format?: unknown } | null)?.format === 'cliq-kernel-rollback-control-v1') return invalid();
    const control = decodeOwnedLegacyImportControl(fixed);
    if (control.stateRootCanonicalAbsolutePath !== root.canonicalAbsolutePath || control.stateRootIdentityRef !== root.identityRef ||
        control.stateRootIdentityDigest !== root.identityDigest) return invalid();
    if (observed.authorityBytes !== undefined) {
      const marker = decodeMigrationAuthorityMarker(document(observed.authorityBytes));
      if (marker.authority !== 'kernel' || marker.generationId !== control.targetGenerationId || marker.migrationId !== control.migrationId ||
          marker.stateRootCanonicalAbsolutePath !== root.canonicalAbsolutePath || marker.stateRootIdentityRef !== root.identityRef ||
          marker.stateRootIdentityDigest !== root.identityDigest || control.phase !== 'cutover_import_committed' ||
          marker.receiptRef !== control.committedReceiptRef || marker.receiptDigest !== control.committedReceiptDigest ||
          marker.candidateRef !== control.candidateRef || marker.candidateDigest !== control.candidateDigest || marker.publishedAt < control.updatedAt)
        return invalid();
    }
  } catch { return invalid(); }
}
