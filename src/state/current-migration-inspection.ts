// One current checker of a genuinely completed original producer. Its data is
// not the producer's old FD/birth or a permission to restore/publish/delete.
// The native inspector owns fresh fixed readonly descriptors under the same
// original Store EX/Owner, while complete SQL/CAS history remains mandatory.
import { canonicalSha256 } from '../kernel/canonical.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { assertOriginalCompletedKernelArchive, type CompleteOriginalKernelArchive } from './kernel-archive.js';
import { readInstalledCompletedImportUnderExclusive } from './migration-history.js';
import { readOwnedImportInventory } from './owned-import-inventory.js';
import { assertHeldMigrationGateOwner, openHeldCurrentMigrationInspector, verifyHeldCurrentMigrationLegacy,
  verifyHeldCurrentKernelArchive, releaseHeldCurrentMigrationLegacyLocks, type HeldCurrentMigrationInspector,
  type NativeStateOwner, type HeldMigrationCredentialGate } from './native-owner.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';

type CurrentLegacy = Awaited<ReturnType<typeof verifyHeldCurrentMigrationLegacy>>;
type CurrentArchive = Awaited<ReturnType<typeof verifyHeldCurrentKernelArchive>>;
export type HeldInstalledMigrationInspection = Readonly<{ source: CurrentLegacy; archive: CurrentArchive;
  assertCurrent(): void; close(): Promise<void> }>;
const currentInspections = new WeakMap<HeldInstalledMigrationInspection, Readonly<{
  native: NativeStateOwner; gate: HeldMigrationCredentialGate; driver: SqliteDriver; context: StateOwnerContext;
}>>();
const retainedInspectionResources = new Set<HeldCurrentMigrationInspector>();
function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'current inspection lacks its complete original import/archive closure'); }

/** Called after the actual original archive producer joined and closed, before
 * final rollback work. A restart cannot enter this same-process issuer branch;
 * it must use an independently closed persisted original producer record.
 * No operation/verification callback or caller truth value grants authority. */
export async function inspectInstalledOriginalKernelArchive<T>(native: NativeStateOwner, gate: HeldMigrationCredentialGate,
  context: StateOwnerContext, driver: SqliteDriver, artifacts: ArtifactCatalog, original: CompleteOriginalKernelArchive<T>,
  signal?: AbortSignal): Promise<HeldInstalledMigrationInspection> {
  assertHeldMigrationGateOwner(native, gate, context.filesystem);
  assertOriginalCompletedKernelArchive(original, native, gate, driver);
  const history = await readInstalledCompletedImportUnderExclusive(native, context, gate, driver, artifacts, signal);
  const draining = history.currentDraining;
  if (!draining || canonicalSha256(draining) !== canonicalSha256(original.manifest.control) ||
      canonicalSha256(original.birth.archiveDirectory) !== canonicalSha256(original.manifest.archiveDirectory) ||
      canonicalSha256(original.image.file) !== canonicalSha256(original.manifest.database.file) ||
      original.image.byteCount !== original.manifest.database.byteCount || original.image.sha256 !== original.manifest.database.sha256)
    return invalid();
  const scope = openHeldCurrentMigrationInspector(native, gate, context.filesystem, {
    migrationId: history.control.migrationId, archiveId: draining.archiveId, legacyRoot: history.legacy.root,
    backupRoot: history.backup.backupRoot, entryCount: history.inventory.entryCount,
    controlBytes: history.originalDocuments.currentControlBytes, authorityBytes: history.originalDocuments.authorityBytes,
    rendezvousBytes: history.originalDocuments.authorityBytes, authMarkerBytes: history.originalDocuments.authMarkerBytes
  });
  let source: CurrentLegacy, archive: CurrentArchive;
  try {
    async function* originalEntries() {
      for await (const event of readOwnedImportInventory(artifacts, history.inventory, signal)) if (event.kind === 'entry') yield event.entry;
    }
    source = await verifyHeldCurrentMigrationLegacy(scope, originalEntries(), signal);
    // rollback_draining has not authorized removal of the original marker.
    // An observed ENOENT is data, and cannot borrow a later restoring phase.
    if (source.sourceAuth !== 'matched_original_marker' || source.entryCount !== history.inventory.entryCount ||
        canonicalSha256(source.legacyRoot) !== canonicalSha256(history.legacy.root)) return invalid();
    archive = await verifyHeldCurrentKernelArchive(scope, {
      archiveCollection: original.birth.archiveCollection, archiveDirectory: original.birth.archiveDirectory,
      manifest: original.manifestObservation
    }, draining, signal);
    if (canonicalSha256(archive.header) !== canonicalSha256(original.manifest)) return invalid();
    driver.readSnapshot(history.assertUnchanged); scope.assertHeld(); signal?.throwIfAborted();
  } catch (error) {
    if (error instanceof ResourceRetirementError) { retainedInspectionResources.add(scope); throw error; }
    try { await releaseHeldCurrentMigrationLegacyLocks(scope); scope.close(); }
    catch (retirement) { retainedInspectionResources.add(scope);
      throw new ResourceRetirementError('current inspection refusal and original resource retirement did not join', new AggregateError([error, retirement])); }
    throw error;
  }
  let closing: Promise<void> | undefined;
  const result: HeldInstalledMigrationInspection = Object.freeze({
    source, archive,
    assertCurrent(...args: unknown[]) {
      if (this !== result || args.length || closing) throw new TypeError('current inspection requires its genuine unclosed receiver');
      assertHeldMigrationGateOwner(native, gate, context.filesystem); driver.readSnapshot(history.assertUnchanged); scope.assertHeld();
    },
    close(...args: unknown[]) {
      if (this !== result || args.length) throw new TypeError('current inspection close requires its genuine receiver');
      if (closing) return closing;
      closing = (async () => {
        try { await releaseHeldCurrentMigrationLegacyLocks(scope); scope.close(); retainedInspectionResources.delete(scope); }
        catch (error) { retainedInspectionResources.add(scope); throw new ResourceRetirementError('current inspection original resources remain held', error); }
      })(); return closing;
    }
  });
  currentInspections.set(result, { native, gate, driver, context }); return result;
}
/** This check only names the real issued observer. Its captured source/archive
 * metadata still supplies no final SQL or marker publication permission. */
export function assertInstalledCurrentMigrationInspection(value: HeldInstalledMigrationInspection, native: NativeStateOwner,
  gate: HeldMigrationCredentialGate, driver: SqliteDriver, context: StateOwnerContext): void {
  const actual = currentInspections.get(value);
  if (!actual || actual.native !== native || actual.gate !== gate || actual.driver !== driver || actual.context !== context)
    throw new TypeError('current migration inspection requires its genuine original Store issuer');
  value.assertCurrent();
}
