// Installed startup consumer of the one complete retained import history.
// Physical current Legacy rendezvous/auth checks remain genuine SH operations;
// the shared readonly history itself is reused by the original EX conductor.
import { inspectHeldKernelMigrationEntry, type NativeStateOwner } from './native-owner.js';
import { assertInstalledAccountParticipant, type HeldInstalledAccountParticipant } from './installed-account-participant.js';
import type { StateOwnerContext } from './state-owner.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import { readInstalledCompletedImportUnderShared } from './migration-history.js';

function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'retained owned import startup closure is incomplete or inconsistent'); }
export async function installedMigrationNeedsRecovery(native: NativeStateOwner, context: StateOwnerContext,
  account: HeldInstalledAccountParticipant, driver: SqliteDriver, artifacts: ArtifactCatalog, signal?: AbortSignal): Promise<boolean> {
  assertInstalledAccountParticipant(account); account.assertShared(); signal?.throwIfAborted();
  const history = await readInstalledCompletedImportUnderShared(native, context, account, driver, artifacts, signal);
  if (history.kind !== 'completed') return history.kind === 'recovery_required';
  const current = () => { signal?.throwIfAborted(); account.assertShared(); artifacts.assertReadActive(); };
  current();
  const legacy = account.readLegacyRendezvous(history.legacy.root.canonicalAbsolutePath);
  if (legacy.kind !== 'rendezvous_present' || !legacy.bytes.equals(history.originalDocuments.authorityBytes) ||
      legacy.rootIdentity.deviceId !== history.legacy.root.deviceId || legacy.rootIdentity.fileId !== history.legacy.root.directoryFileId ||
      legacy.rootIdentity.ownerUid !== history.legacy.root.ownerUid) return invalid();
  const auth = account.verifyLegacyAuth(history.legacy.root.canonicalAbsolutePath, history.authMarker); current();
  if (auth.deviceId !== history.legacy.root.deviceId || auth.fileId !== history.legacy.root.directoryFileId || auth.ownerUid !== history.legacy.root.ownerUid) return invalid();
  driver.readSnapshot(history.assertUnchanged);
  const final = inspectHeldKernelMigrationEntry(native, context.filesystem); current();
  if (final.kind !== 'controlled' || !final.controlBytes.equals(history.originalDocuments.controlBytes) ||
      !final.authorityBytes?.equals(history.originalDocuments.authorityBytes)) return invalid();
  return false;
}
