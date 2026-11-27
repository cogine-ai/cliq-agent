import { canonicalJsonBytes } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeOwnedLegacyImportControl, decodeMigrationAuthorityMarker, assertOwnedImportControlSuccessor,
  type OwnedLegacyImportControl } from '../kernel/migration-control.js';
import { decodeOwnedLegacyImportPreparation, decodeOwnedLegacyImportRequest, decodeOwnedLegacyImportReceipt,
  decodeOwnedLegacyImportResponse, decodeOwnedLegacyRootIdentity, decodeOwnedPreparedImportCandidate,
  decodeOwnedImportCredentialReady, decodeOwnedImportSourceAuthObservation, decodeOwnedImportInventory,
  decodeOwnedImportBackup, decodePreparedImportDatabaseImageIdentity } from '../kernel/owned-import-data.js';
import { decodeLegacyAuthMigratedMarker } from '../kernel/migration-auth-data.js';
import { digestOmitting } from '../kernel/identity.js';
import type { KernelGenerationIdentityV1 } from '../kernel/types.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { KernelStorageError } from './errors.js';
import { assertHeldMigrationGateOwner, inspectHeldKernelMigrationEntry, stateRootIdentityForLock, type HeldMigrationCredentialGate, type NativeStateOwner } from './native-owner.js';
import type { HeldInstalledAccountParticipant } from './installed-account-participant.js';
import { assertInstalledAccountParticipant } from './installed-account-participant.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { ArtifactCatalog } from './artifacts.js';
import { assertSqliteConnectionOwnedBy, type SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readRetainedStateOwnerHistory, type StateOwnerRollbackHistory } from './state-owner-history.js';
import { readRetainedControlChannelClosure } from './control-channel.js';
import { readControlRequest } from './rows.js';
import { readTimeFence } from './canonical-time.js';
import { readOwnedImportInventory } from './owned-import-inventory.js';
import { readSignedKernelSchema } from './signed-schema.js';
import { decodeKernelRollbackDrainingControl, type KernelRollbackDrainingControlV1 } from '../kernel/kernel-archive-data.js';
import type { RetainedRollbackArchiveReady, RetainedRollbackRecords } from './kernel-rollback-history.js';

/** Parse only complete canonical fixed documents, without exposing untrusted
 * source text, parser excerpts or nested causes in a startup diagnostic. */
function document(bytes: Buffer): unknown {
  try {
    const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    if (!canonicalJsonBytes(value).equals(bytes)) throw new TypeError(); return value;
  } catch { throw new KernelStorageError('RECOVERY_REQUIRED', 'fixed migration startup document is not canonical'); }
}
function decodeDocument<T>(bytes: Buffer, decode: (value: unknown) => T): T {
  try { return decode(document(bytes)); }
  catch { throw new KernelStorageError('RECOVERY_REQUIRED', 'fixed migration startup data cannot be decoded'); }
}
function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'retained owned import startup closure is incomplete or inconsistent'); }
/** Read a completed original import as history, not as adoption of its old
 * native package or permission to replay. Current backup/archive availability
 * is a separate rollback check; this reader makes no current-copy birth claim. */
async function readCompletedImportHistory(native: NativeStateOwner, context: StateOwnerContext,
  driver: SqliteDriver, artifacts: ArtifactCatalog, checkAccount: () => void, signal?: AbortSignal, allowDraining = false,
  recovery?: Readonly<{ records: RetainedRollbackRecords | RetainedRollbackArchiveReady; ownerHistory: StateOwnerRollbackHistory }>) {
  checkAccount();
  signal?.throwIfAborted(); artifacts = signal ? artifacts.withReadSignal(signal) : artifacts;
  const owner = context.filesystem;
  const observed = inspectHeldKernelMigrationEntry(native, owner); checkAccount();
  if (observed.kind === 'unmigrated') return Object.freeze({ kind: 'unmigrated' as const });
  const current = () => { signal?.throwIfAborted(); checkAccount(); artifacts.assertReadActive(); assertActiveStateOwner(driver, context); };
  const read = async <T>(ref: string, decode: (value: unknown) => T): Promise<T> => {
    current(); const bytes = await artifacts.readBoundedBytes(ref, 1_048_576); current(); return decodeDocument(bytes, decode);
  };
  let originalControlBytes = observed.controlBytes, draining: KernelRollbackDrainingControlV1 | undefined;
  const fixed = document(observed.controlBytes);
  if ((fixed as { format?: unknown } | null)?.format === 'cliq-kernel-rollback-control-v1') {
    if (!allowDraining) return Object.freeze({ kind: 'recovery_required' as const });
    if (recovery) {
      const current = 'restoring' in recovery.records ? recovery.records.restoring : recovery.records.ready;
      if (canonicalSha256(fixed) !== canonicalSha256(current)) return invalid();
      draining = recovery.records.draining;
    } else draining = decodeKernelRollbackDrainingControl(fixed);
    current(); originalControlBytes = await artifacts.readBoundedBytes(draining.originalImportControlRef, 1_048_576); current();
  } else if (recovery) return invalid();
  const control = decodeDocument(originalControlBytes, decodeOwnedLegacyImportControl);
  const root = stateRootIdentityForLock(owner);
  if (control.stateRootIdentityRef !== canonicalSha256(root) || control.stateRootIdentityDigest !== root.identityDigest ||
      control.stateRootCanonicalAbsolutePath !== root.canonicalAbsolutePath)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'migration startup control belongs to another StateRoot');
  if (observed.authorityBytes === undefined || control.phase !== 'cutover_import_committed') return Object.freeze({ kind: 'recovery_required' as const });
  const marker = decodeDocument(observed.authorityBytes, decodeMigrationAuthorityMarker);
  if (marker.authority !== 'kernel') return Object.freeze({ kind: 'recovery_required' as const });
  if (draining && (draining.migrationId !== control.migrationId || draining.kernelGenerationId !== control.targetGenerationId ||
      draining.stateRootIdentityRef !== control.stateRootIdentityRef || draining.stateRootIdentityDigest !== control.stateRootIdentityDigest ||
      draining.stateRootCanonicalAbsolutePath !== control.stateRootCanonicalAbsolutePath ||
      draining.originalImportControlRef !== canonicalSha256(control) || draining.originalImportControlDigest !== control.controlDigest ||
      draining.originalKernelAuthorityRef !== canonicalSha256(marker) || draining.originalKernelAuthorityDigest !== marker.markerDigest ||
      draining.preparedAt < marker.publishedAt)) return invalid();
  if (draining) {
    const originalAuthority = recovery?.records.originalMarker ??
      await read(draining.originalKernelAuthorityRef, decodeMigrationAuthorityMarker);
    if (canonicalSha256(originalAuthority) !== canonicalSha256(marker)) return invalid();
  }
  if (marker.migrationId !== control.migrationId ||
      marker.stateRootIdentityRef !== control.stateRootIdentityRef || marker.stateRootIdentityDigest !== control.stateRootIdentityDigest ||
      marker.stateRootCanonicalAbsolutePath !== control.stateRootCanonicalAbsolutePath || marker.receiptRef !== control.committedReceiptRef ||
      marker.receiptDigest !== control.committedReceiptDigest || marker.candidateRef !== control.candidateRef ||
      marker.candidateDigest !== control.candidateDigest || marker.generationId !== control.targetGenerationId || marker.publishedAt < control.updatedAt)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'migration startup marker does not close its original committed control');
  const receipt = await read(marker.receiptRef, decodeOwnedLegacyImportReceipt);
  const preparation = await read(control.preparationRef, decodeOwnedLegacyImportPreparation);
  const request = await read(preparation.requestRef, decodeOwnedLegacyImportRequest);
  const response = await read(control.committedResponseRef, decodeOwnedLegacyImportResponse);
  const candidate = await read(marker.candidateRef, decodeOwnedPreparedImportCandidate);
  const legacy = await read(preparation.legacyRootIdentityRef, decodeOwnedLegacyRootIdentity);
  const ready = await read(candidate.credentialReadyRef, decodeOwnedImportCredentialReady);
  const sourceAuth = await read(ready.sourceAuthObservationRef, decodeOwnedImportSourceAuthObservation);
  const backup = await read(candidate.backupRef, decodeOwnedImportBackup);
  const inventory = await read(candidate.inventoryRef, decodeOwnedImportInventory);
  const image = await read(candidate.imageIdentityRef, decodePreparedImportDatabaseImageIdentity);
  if (receipt.receiptDigest !== marker.receiptDigest || preparation.preparationDigest !== control.preparationDigest ||
      receipt.preparationRef !== control.preparationRef || receipt.preparationDigest !== preparation.preparationDigest ||
      preparation.migrationId !== control.migrationId || receipt.migrationId !== control.migrationId || request.migrationId !== control.migrationId ||
      response.migrationId !== control.migrationId || candidate.migrationId !== control.migrationId || legacy.migrationId !== control.migrationId ||
      ready.migrationId !== control.migrationId || sourceAuth.migrationId !== control.migrationId || backup.migrationId !== control.migrationId ||
      inventory.migrationId !== control.migrationId || request.requestId !== preparation.requestId || receipt.requestId !== preparation.requestId ||
      response.requestId !== preparation.requestId || preparation.requestRef !== preparation.requestDigest || receipt.requestRef !== preparation.requestRef ||
      receipt.requestDigest !== preparation.requestDigest || response.receiptRef !== marker.receiptRef || response.receiptDigest !== receipt.receiptDigest ||
      response.preparationRef !== control.preparationRef || response.preparationDigest !== preparation.preparationDigest ||
      response.completedAt !== receipt.completedAt || candidate.candidateDigest !== marker.candidateDigest ||
      candidate.candidateDigest !== control.candidateDigest || receipt.candidateRef !== marker.candidateRef || receipt.candidateDigest !== candidate.candidateDigest ||
      receipt.importedRowSetDigest !== candidate.importedRowSetDigest || legacy.identityDigest !== preparation.legacyRootIdentityDigest ||
      control.sourceGenerationDigest !== legacy.identityDigest || receipt.principalId !== preparation.principalId || ready.principalId !== preparation.principalId ||
      receipt.channelIdentityRef !== preparation.channelIdentityRef || receipt.channelIdentityDigest !== preparation.channelIdentityDigest ||
      marker.kernelGenerationIdentityRef !== preparation.kernelGenerationIdentityRef || marker.kernelGenerationIdentityDigest !== preparation.kernelGenerationIdentityDigest ||
      receipt.kernelGenerationIdentityRef !== preparation.kernelGenerationIdentityRef || receipt.kernelGenerationIdentityDigest !== preparation.kernelGenerationIdentityDigest ||
      image.imageDigest !== candidate.imageIdentityDigest || image.migrationId !== control.migrationId ||
      image.preparationRef !== control.preparationRef || image.preparationDigest !== preparation.preparationDigest ||
      image.signedSchemaManifestRef !== preparation.signedSchemaManifestRef || image.signedSchemaManifestDigest !== preparation.signedSchemaManifestDigest ||
      image.signedSchemaDigest !== preparation.signedSchemaDigest)
    return invalid();
  for (const artifact of [preparation, receipt, candidate]) if (artifact.stateRootIdentityRef !== control.stateRootIdentityRef ||
      artifact.stateRootIdentityDigest !== control.stateRootIdentityDigest) return invalid();
  for (const artifact of [receipt, candidate, sourceAuth, inventory]) if (artifact.legacyRootIdentityRef !== preparation.legacyRootIdentityRef ||
      artifact.legacyRootIdentityDigest !== legacy.identityDigest) return invalid();
  for (const artifact of [candidate, ready, backup, inventory]) if (artifact.preparationRef !== control.preparationRef ||
      artifact.preparationDigest !== preparation.preparationDigest) return invalid();
  if (candidate.kernelGenerationIdentityRef !== preparation.kernelGenerationIdentityRef ||
      candidate.kernelGenerationIdentityDigest !== preparation.kernelGenerationIdentityDigest ||
      candidate.signedSchemaManifestRef !== preparation.signedSchemaManifestRef ||
      candidate.signedSchemaManifestDigest !== preparation.signedSchemaManifestDigest || candidate.signedSchemaDigest !== preparation.signedSchemaDigest ||
      candidate.backupRef !== control.backupRef || candidate.backupDigest !== backup.backupDigest || backup.backupDigest !== control.backupDigest ||
      candidate.inventoryRef !== control.inventoryRef || candidate.inventoryDigest !== inventory.inventoryDigest || inventory.inventoryDigest !== control.inventoryDigest ||
      backup.inventoryRef !== candidate.inventoryRef || backup.inventoryDigest !== inventory.inventoryDigest || backup.entriesDigest !== inventory.entriesDigest ||
      candidate.credentialReadyRef !== control.credentialReadyRef || candidate.credentialReadyDigest !== ready.readyDigest || ready.readyDigest !== control.credentialReadyDigest ||
      receipt.credentialReadyRef !== candidate.credentialReadyRef || receipt.credentialReadyDigest !== ready.readyDigest ||
      sourceAuth.observationDigest !== ready.sourceAuthObservationDigest || preparation.preparedAt !== control.createdAt ||
      preparation.preparedAt > candidate.stagedAt || candidate.stagedAt > receipt.completedAt || receipt.completedAt > control.updatedAt ||
      sourceAuth.observedAt < preparation.preparedAt || sourceAuth.observedAt > ready.completedAt || ready.completedAt > receipt.completedAt ||
      backup.completedAt < preparation.preparedAt || backup.completedAt > receipt.completedAt ||
      legacy.root.canonicalAbsolutePath !== request.legacyRootCanonicalAbsolutePath || legacy.root.ownerUid !== root.ownerUid ||
      backup.backupRoot.ownerUid !== root.ownerUid || backup.backupRoot.mode !== 0o700 ||
      backup.backupRoot.canonicalAbsolutePath !== `${root.canonicalAbsolutePath}/migration/owned-import/${control.migrationId}/backup`)
    return invalid();
  // Current producer supports exact source absence only. A future genuine
  // present-auth participant needs its own original historical reader here.
  if (sourceAuth.observation.presence !== 'absent' || ready.entries.length !== 0) return Object.freeze({ kind: 'recovery_required' as const });
  let before: OwnedLegacyImportControl = control;
  for (let revision = 3; revision >= 1; revision--) {
    if (before.phase === 'cutover_preflight') return invalid();
    if (before.phase === 'credential_cutover' && before.updatedAt > receipt.completedAt ||
        before.phase === 'cutover_candidate_ready' && before.updatedAt < candidate.stagedAt) return invalid();
    const previous: Readonly<OwnedLegacyImportControl> = await read(before.previousControlRef, decodeOwnedLegacyImportControl);
    if (previous.controlDigest !== before.previousControlDigest || previous.controlRevision !== revision) return invalid();
    assertOwnedImportControlSuccessor(previous, before); before = previous;
  }
  if (before.phase !== 'cutover_preflight' || before.updatedAt !== preparation.preparedAt) return invalid();
  const originalFenceCore = { schemaVersion: 1, format: 'cliq-canonical-time-fence-v1',
    stateOwnerEpoch: preparation.preparingOwner.ownerEpoch, lastAcceptedAt: preparation.preparedAt,
    observedWallClockAt: preparation.preparedAt, state: 'healthy', updatedAt: preparation.preparedAt, fenceDigest: '' };
  if (digestOmitting(originalFenceCore, 'fenceDigest') !== preparation.preparingTimeFenceDigest) return invalid();
  // Traverse every retained inventory page/purpose, but do not claim these
  // current data bytes prove that an old backup directory is still available.
  for await (const event of readOwnedImportInventory(artifacts, inventory, signal)) {
    current(); if (event.kind === 'entry' && (event.entry.sourceIdentity.ownerUid !== root.ownerUid ||
        event.entry.backupIdentity.ownerUid !== root.ownerUid)) return invalid();
  }
  const history = await readRetainedStateOwnerHistory(driver, artifacts, context.ownerEpoch, recovery?.ownerHistory); current();
  const original = history.entries[preparation.preparingOwner.ownerEpoch - 1];
  if (!original || preparation.preparingOwnerHistoryThroughEpoch !== preparation.preparingOwner.ownerEpoch) return invalid();
  // Compare immutable fields against the retained actual row. Never rewrite
  // a terminal row or manufacture a new active Owner from its projection.
  for (const key of ['schemaVersion', 'ownerEpoch', 'supervisorInstanceId', 'runtimeBundleRef', 'runtimeBundleManifestDigest',
    'supervisorEntryId', 'supervisorEntryVersion', 'supervisorExecutableDigest', 'processIdentityRef', 'processIdentityDigest',
    'stateLockIdentityRef', 'stateLockIdentityDigest', 'acquisitionEvidenceRef', 'acquisitionEvidenceDigest', 'instanceNonceDigest', 'acquiredAt'] as const)
    if (original.owner[key] !== preparation.preparingOwner[key]) return invalid();
  if (original.owner.state === 'active' ? original.owner.rowDigest !== preparation.preparingOwner.rowDigest :
      original.owner.releasedAt < marker.publishedAt) return invalid();
  const first = history.entries[0]!;
  if (first.acquisition.kind !== 'genesis' || first.acquisition.kernelGenerationIdentityRef !== marker.kernelGenerationIdentityRef ||
      first.acquisition.kernelGenerationIdentityDigest !== marker.kernelGenerationIdentityDigest) return invalid();
  const generation = await artifacts.readCanonical<KernelGenerationIdentityV1>(marker.kernelGenerationIdentityRef); current();
  if (generation.origin !== 'fresh_installed' || generation.generationId !== marker.generationId ||
      generation.generationDigest !== marker.kernelGenerationIdentityDigest || generation.generationDigest !== digestOmitting(generation, 'generationDigest') ||
      generation.stateRootIdentityRef !== control.stateRootIdentityRef || generation.stateRootIdentityDigest !== control.stateRootIdentityDigest) return invalid();
  const originalBundle = await artifacts.readCanonical<RuntimeBundleManifest>(preparation.preparingOwner.runtimeBundleRef); current();
  const schema = await readSignedKernelSchema(artifacts, originalBundle, artifacts.releaseTrustRoots()); current();
  if (canonicalSha256(schema) !== preparation.signedSchemaManifestRef || schema.profileDigest !== preparation.signedSchemaManifestDigest ||
      schema.schemaManifest.schemaDigest !== preparation.signedSchemaDigest) return invalid();
  const channel = await readRetainedControlChannelClosure(artifacts, context, { principalId: preparation.principalId,
    channelIdentityRef: preparation.channelIdentityRef, channelIdentityDigest: preparation.channelIdentityDigest }); current();
  if (channel.channel.openedAt > preparation.preparedAt) return invalid();
  const authCore = { schemaVersion: 1, format: 'cliq-auth-migrated-v1', migrationId: control.migrationId,
    sourceObservationRef: ready.sourceAuthObservationRef, sourceObservationDigest: ready.sourceAuthObservationDigest,
    credentialReadyRef: candidate.credentialReadyRef, credentialReadyDigest: ready.readyDigest, records: [], markerDigest: '' };
  const authMarker = decodeLegacyAuthMigratedMarker({ ...authCore, markerDigest: digestOmitting(authCore, 'markerDigest') });
  if (authMarker.markerDigest !== control.legacyAuthMarkerDigest) return invalid();
  await read(canonicalSha256(authMarker), decodeLegacyAuthMigratedMarker);
  const assertUnchanged = (connection: import('./sqlite-driver.js').SqliteConnection) => {
    signal?.throwIfAborted(); checkAccount(); artifacts.assertReadActive();
    assertSqliteConnectionOwnedBy(driver, connection);
    history.assertUnchanged(connection); assertActiveStateOwner(connection, context);
    const response = readControlRequest(connection, preparation.principalId, 'state.migrate', preparation.requestId), fence = readTimeFence(connection);
    if (!response || response.responseRef !== control.committedResponseRef || response.requestDigest !== preparation.requestDigest ||
        response.channelIdentityRef !== preparation.channelIdentityRef || response.channelIdentityDigest !== preparation.channelIdentityDigest ||
        response.committedAt !== control.updatedAt || control.committedResponseDigest !== response.responseRef ||
        !fence || fence.lastAcceptedAt < response.committedAt ||
        connection.prepare('SELECT response_revision FROM control_requests WHERE principal_id=? AND method=? AND request_id=?')
          .get<{ response_revision: bigint }>(preparation.principalId, 'state.migrate', preparation.requestId)?.response_revision !== 1n) return invalid();
  };
  driver.readSnapshot(assertUnchanged);
  // Re-read actual fixed root documents under the original real SH/EX. A path or stale
  // observation never substitutes for their complete current identities.
  const final = inspectHeldKernelMigrationEntry(native, owner); current();
  if (final.kind !== 'controlled' || !final.controlBytes.equals(observed.controlBytes) ||
      !final.authorityBytes?.equals(observed.authorityBytes)) return invalid();
  return Object.freeze({ kind: 'completed' as const, control, authority: marker, preparation, request, response, candidate, legacy, ready, sourceAuth,
    backup, inventory, image, generation, schema, authMarker, retainedOwnerHistory: history,
    currentDraining: draining,
    originalDocuments: Object.freeze({ controlBytes: Buffer.from(originalControlBytes), authorityBytes: Buffer.from(observed.authorityBytes),
      currentControlBytes: Buffer.from(observed.controlBytes), authMarkerBytes: canonicalJsonBytes(authMarker) }), assertUnchanged });
}


/** Startup keeps its genuine SH; the completed closure is historical data,
 * never current backup existence or the original creator's native proof. */
export async function readInstalledCompletedImportUnderShared(native: NativeStateOwner, context: StateOwnerContext,
  account: HeldInstalledAccountParticipant, driver: SqliteDriver, artifacts: ArtifactCatalog, signal?: AbortSignal) {
  assertInstalledAccountParticipant(account); account.assertShared();
  return readCompletedImportHistory(native, context, driver, artifacts, () => account.assertShared(), signal);
}
/** The same exact history consumer under the original Store's genuine EX.
 * Its private native gate issuer must name this exact original Owner object;
 * no structural token, Boolean, SH callback or stale pre-EX cut is accepted.
 * Returned decoded data is not permission to adopt/copy/restore old objects;
 * the separate current inspector must still observe every original identity. */
export async function readInstalledCompletedImportUnderExclusive(native: NativeStateOwner, context: StateOwnerContext,
  gate: HeldMigrationCredentialGate, driver: SqliteDriver, artifacts: ArtifactCatalog, signal?: AbortSignal,
  recovery?: Readonly<{ records: RetainedRollbackRecords | RetainedRollbackArchiveReady; ownerHistory: StateOwnerRollbackHistory }>) {
  const check = () => assertHeldMigrationGateOwner(native, gate, context.filesystem);
  check();
  const result = await readCompletedImportHistory(native, context, driver, artifacts, check, signal, true, recovery);
  if (result.kind !== 'completed') return invalid();
  return result;
}
export type CompletedInstalledImportHistory = Awaited<ReturnType<typeof readInstalledCompletedImportUnderExclusive>>;
