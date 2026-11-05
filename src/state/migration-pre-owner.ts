// Readonly pre-Owner refusal only. This never qualifies migration recovery or
// confers authority from document bytes; after-Owner complete typed SQL/CAS
// history verification remains independently required for Kernel entry.
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { decodeOwnedLegacyImportControl, decodeMigrationAuthorityMarker } from '../kernel/migration-control.js';
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
    const control = decodeOwnedLegacyImportControl(document(observed.controlBytes));
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
