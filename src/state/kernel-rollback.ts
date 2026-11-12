import { randomBytes } from 'node:crypto';
import type { BigIntStats } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { decodeKernelRollbackDrainingControl } from '../kernel/kernel-archive-data.js';
import { assertKernelRollbackArchiveReadyClosure, decodeKernelRollbackArchiveReadyControl } from '../kernel/kernel-rollback-handoff.js';
import { decodeMigrationAuthorityMarker, type MigrationAuthorityMarker } from '../kernel/migration-control.js';
import { assertKernelRollbackRecordClosure, decodeInstalledRollbackRequest, decodeKernelRollbackRestoringControl,
  decodeLegacyRollbackAuthAbsence, decodeLegacyRollbackReceipt, decodeOwnedKernelArchiveWitness, decodeRestoredAbsentLegacyGeneration,
  decodeRollbackToLegacyRequest, type KernelRollbackRestoringControlV1, type LegacyRollbackReceiptV1 } from '../kernel/kernel-rollback-records.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { assertCurrentControlFrame, readRetainedControlChannelClosure, validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import type { HeldInstalledAnchor, HeldInstalledRuntime, MigrationTailArtifacts, MigrationTailFormat } from './installed-runtime.js';
import { archiveOriginalKernel, assertOriginalCompletedKernelArchive } from './kernel-archive.js';
import { assertInstalledRollbackProductiveCut } from './kernel-archive-cut.js';
import { readRetainedRollbackArchiveReady, readRetainedRollbackRecords, type RetainedRollbackArchiveReady } from './kernel-rollback-history.js';
import { readInstalledCompletedImportUnderExclusive, type CompletedInstalledImportHistory } from './migration-history.js';
import { checkCanonicalBytes } from './installed-artifacts.js';
import { assertHeldMigrationGateOwner, holdCurrentRollbackPublisher, inspectHeldKernelMigrationEntry, inspectHeldLegacyProcessCut, openHeldCurrentMigrationInspector,
  observeHeldRollbackAuthPreimage, publishHeldPreparedRollbackAuthority, publishHeldRollbackArchiveReady,
  publishHeldRollbackDraining, publishHeldRollbackRestoring, recheckHeldCurrentMigrationLegacy,
  releaseHeldCurrentMigrationLegacyLocks, restoreHeldRollbackAuthAbsence, stageHeldRollbackAuthority,
  verifyHeldCurrentKernelArchive, verifyHeldCurrentMigrationLegacy, withHeldCredentialNativeScope,
  type HeldCurrentMigrationInspector, type HeldCurrentRollbackPublisher, type HeldMigrationCredentialGate, type NativeStateOwner } from './native-owner.js';
import type { NativeLocalModelStore } from './local-model-store-native.js';
import { readOwnedImportInventory } from './owned-import-inventory.js';
import { openInstalledRuntimeWitnessCut } from './runtime-witness-archive-cut.js';
import { readSignedKernelSchema } from './signed-schema.js';
import { assertSqliteConnectionOwnedBy, type SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { bindStateOwnerRollbackHistory } from './state-owner-history.js';
import { assertInstalledExclusiveReadSource, assertInstalledRollbackFinalization,
  type InstalledExclusiveReadSource, type InstalledRollbackFinalization } from './store.js';

type RollbackSource = Readonly<{
  source: InstalledExclusiveReadSource; gate: HeldMigrationCredentialGate; driver: SqliteDriver;
  artifacts: ArtifactCatalog; owner: StateOwnerContext; anchor?: HeldInstalledAnchor;
}>;
export type InstalledRollbackInvocation = RollbackSource & Readonly<{ request: unknown; identity: AuthenticatedControlIdentity }>;
export type InstalledRollbackRecoveryInvocation = RollbackSource & Readonly<{ restoringControlDigest: string }>;
type SelectedRollbackInputs = Readonly<{ image: FileHandle; root: FileHandle; rootIdentity: BigIntStats; stateRoot: string;
  modelScope: NativeLocalModelStore | null; tail: MigrationTailArtifacts }>;
export type PreparedInstalledRollback = Readonly<{
  restoring: KernelRollbackRestoringControlV1; marker: Extract<MigrationAuthorityMarker, { authority: 'legacy' }>;
  receipt: LegacyRollbackReceiptV1; retained: readonly PublishedArtifact[]; tail: MigrationTailArtifacts;
}>;
type HeldPreparation = Readonly<{
  native: NativeStateOwner; input: RollbackSource; inspector: HeldCurrentMigrationInspector;
  publisher: HeldCurrentRollbackPublisher; assertCurrent(): void;
}> & { published: boolean };
const issued = new WeakMap<PreparedInstalledRollback, HeldPreparation>();
const notWritten = new WeakMap<object, Readonly<{ source: InstalledExclusiveReadSource; driver: SqliteDriver; owner: StateOwnerContext }>>();
const unretired = new Set<Readonly<{ inspector: HeldCurrentMigrationInspector; publisher?: HeldCurrentRollbackPublisher }>>();

export function isInstalledRollbackRefusalBeforeControl(error: unknown, source: InstalledExclusiveReadSource,
  driver: SqliteDriver, owner: StateOwnerContext): boolean {
  const observed = typeof error === 'object' && error !== null ? notWritten.get(error) : undefined;
  if (!observed || observed.source !== source || observed.driver !== driver || observed.owner !== owner) return false;
  assertInstalledExclusiveReadSource(source, driver, owner); return true;
}
export function assertPreparedInstalledRollback(prepared: PreparedInstalledRollback, source: InstalledExclusiveReadSource,
  driver: SqliteDriver, owner: StateOwnerContext): void {
  const held = issued.get(prepared);
  if (!held || held.published || held.input.source !== source || held.input.driver !== driver || held.input.owner !== owner)
    throw new TypeError('rollback preparation requires its exact original unconsumed Store issuer');
  held.assertCurrent();
}
export function publishPreparedInstalledRollback(prepared: PreparedInstalledRollback, finalization: InstalledRollbackFinalization): void {
  const held = issued.get(prepared);
  if (!held || held.published) throw new TypeError('rollback marker requires its exact original unconsumed preparation');
  // The receipt is minted only after the real last SQL commit and actual
  // driver.close. Every following assertion is physical. There is no SQL.
  assertInstalledRollbackFinalization(finalization, held.native, held.input.gate, prepared.restoring.controlDigest, prepared.marker.markerDigest);
  publishHeldPreparedRollbackAuthority(held.publisher);
  held.published = true;
}

function fail(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function withDigest<T extends Record<string, unknown>, K extends string>(core: T, key: K): T & Readonly<Record<K, string>> {
  return { ...core, [key]: digestOmitting(core as Record<string, unknown>, key) } as T & Readonly<Record<K, string>>;
}
function rollbackTime(driver: SqliteDriver, owner: StateOwnerContext): string {
  const accepted = driver.transaction(connection => {
    assertSqliteConnectionOwnedBy(driver, connection); assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow(); return advanceTimeFence(connection, owner.ownerEpoch, now) === 'healthy' ? now : undefined;
  });
  return accepted ?? fail('original time fence refused rollback preparation');
}

async function finishArchiveReadyRollback<T>(context: Readonly<{
  native: NativeStateOwner; input: RollbackSource; inputs: SelectedRollbackInputs; inspector: HeldCurrentMigrationInspector;
  livePublisher: HeldCurrentRollbackPublisher; history: CompletedInstalledImportHistory; records: RetainedRollbackArchiveReady;
  observed: Awaited<ReturnType<typeof verifyHeldCurrentMigrationLegacy>>;
  retained: readonly PublishedArtifact[]; retain(record: object, purpose: MigrationTailFormat): Promise<string>;
  assertCurrent(): void; recheckProcessCut(): Promise<void>;
  finish(prepared: PreparedInstalledRollback): Promise<T>; signal?: AbortSignal;
}>): Promise<T> {
  const { native, input, inputs, inspector, livePublisher, history, records, observed, retained, retain,
    assertCurrent, recheckProcessCut, finish, signal } = context;
  const { driver, owner } = input, { request, originalMarker, draining, archive: archiveWitness, ready } = records;
  const { requestRef } = draining, { drainingControlRef, archivedKernelGenerationRef } = ready;
  const archiveReadyControlRef = canonicalSha256(ready);
  assertCurrent();
  const authObservation = restoreHeldRollbackAuthAbsence(livePublisher, ready);
  const active = assertActiveStateOwner(driver, owner);
  const auth = decodeLegacyRollbackAuthAbsence(withDigest({
    schemaVersion: 1, format: 'cliq-legacy-rollback-auth-absence-v1', migrationId: request.migrationId,
    legacyRootIdentityRef: history.preparation.legacyRootIdentityRef, legacyRootIdentityDigest: history.legacy.identityDigest,
    originalSourceAuthObservationRef: history.ready.sourceAuthObservationRef,
    originalSourceAuthObservationDigest: history.sourceAuth.observationDigest,
    originalMigratedAuthMarkerRef: canonicalSha256(history.authMarker), originalMigratedAuthMarkerDigest: history.authMarker.markerDigest,
    archiveReadyControlRef, archiveReadyControlDigest: ready.controlDigest,
    inspectorOwnerEpoch: active.ownerEpoch, inspectorOwnerAcquisitionEvidenceRef: active.acquisitionEvidenceRef,
    inspectorOwnerAcquisitionEvidenceDigest: active.acquisitionEvidenceDigest,
    previousMarkerFile: authObservation.previousMarkerFile, observation: authObservation.kind, observedAt: rollbackTime(driver, owner)
  }, 'observationDigest'));
  const restoredAuthObservationRef = await retain(auth, auth.format);
  const rechecked = await recheckHeldCurrentMigrationLegacy(inspector, signal);
  if (rechecked.sourceAuth !== 'absent' || rechecked.entryCount !== observed.entryCount || rechecked.byteCount !== observed.byteCount ||
      canonicalSha256(rechecked.legacyRoot) !== canonicalSha256(observed.legacyRoot))
    return fail('restored Legacy tree differs from its complete original inventory');
  const legacy = decodeRestoredAbsentLegacyGeneration(withDigest({
    schemaVersion: 1, format: 'cliq-legacy-generation-v1', migrationId: request.migrationId,
    legacyGenerationId: identityHash(request.migrationId, 'legacy'), backupRef: request.backupRef, backupDigest: request.backupDigest,
    restoredEntriesDigest: history.inventory.entriesDigest, verifiedAt: rollbackTime(driver, owner), authOutcome: 'restored_absent',
    restoredAuthObservationRef, restoredAuthObservationDigest: auth.observationDigest
  }, 'manifestDigest'));
  const legacyGenerationRef = await retain(legacy, legacy.format);
  const receipt = decodeLegacyRollbackReceipt(withDigest({
    schemaVersion: 1, format: 'cliq-migration-receipt-v1', migrationId: request.migrationId, kind: 'legacy_rollback',
    rollbackRequestRef: requestRef, rollbackRequestDigest: request.requestDigest, backupRef: request.backupRef, backupDigest: request.backupDigest,
    legacyGenerationRef, legacyGenerationDigest: legacy.manifestDigest, archivedKernelGenerationRef,
    archivedKernelGenerationDigest: archiveWitness.witnessDigest, completedAt: rollbackTime(driver, owner)
  }, 'receiptDigest'));
  const receiptRef = await retain(receipt, receipt.format);
  const marker = decodeMigrationAuthorityMarker(withDigest({
    schemaVersion: 1, format: 'cliq-state-authority-v1', authority: 'legacy', generationId: legacy.legacyGenerationId,
    migrationId: request.migrationId, receiptRef, receiptDigest: receipt.receiptDigest, stateRootIdentityRef: draining.stateRootIdentityRef,
    stateRootIdentityDigest: draining.stateRootIdentityDigest, stateRootCanonicalAbsolutePath: draining.stateRootCanonicalAbsolutePath,
    legacyGenerationRef, legacyGenerationDigest: legacy.manifestDigest, publishedAt: rollbackTime(driver, owner)
  }, 'markerDigest'));
  if (marker.authority !== 'legacy') return fail('prepared rollback marker selected another authority');
  const preparedLegacyAuthorityMarkerRef = await retain(marker, marker.format);
  const staged = stageHeldRollbackAuthority(livePublisher, marker);
  const { controlDigest: _drainingDigest, ...drainingFields } = draining;
  const restoring = decodeKernelRollbackRestoringControl(withDigest({
    ...drainingFields, phase: 'rollback_restoring', controlRevision: 3, drainingControlRef, drainingControlDigest: draining.controlDigest,
    archiveReadyControlRef, archiveReadyControlDigest: ready.controlDigest,
    preparerOwnerEpoch: active.ownerEpoch, preparerOwnerAcquisitionEvidenceRef: active.acquisitionEvidenceRef,
    preparerOwnerAcquisitionEvidenceDigest: active.acquisitionEvidenceDigest,
    archivedKernelGenerationRef, archivedKernelGenerationDigest: archiveWitness.witnessDigest,
    legacyGenerationRef, legacyGenerationDigest: legacy.manifestDigest, preparedReceiptRef: receiptRef,
    preparedReceiptDigest: receipt.receiptDigest, preparedLegacyAuthorityMarkerRef, preparedLegacyAuthorityMarkerDigest: marker.markerDigest,
    preparedRootAuthorityFile: staged.rootFile, preparedLegacyAuthorityFile: staged.legacyFile,
    originalRootAuthorityFile: staged.originalRootFile, originalLegacyAuthorityFile: staged.originalLegacyFile, updatedAt: rollbackTime(driver, owner)
  }, 'controlDigest'));
  assertKernelRollbackRecordClosure({ request, originalMarker, draining, archive: archiveWitness, ready, auth, legacy, receipt, marker, restoring });
  await retain(restoring, restoring.format);
  assertCurrent();
  await recheckProcessCut();
  publishHeldRollbackRestoring(livePublisher, restoring);
  assertCurrent();
  const output: PreparedInstalledRollback = Object.freeze({
    restoring, marker, receipt, retained: Object.freeze([...retained]), tail: inputs.tail
  });
  const originalIssuer: HeldPreparation = { native, input, inspector, publisher: livePublisher, assertCurrent, published: false };
  issued.set(output, originalIssuer);
  try {
    const result = await finish(output);
    if (!originalIssuer.published) return fail('original Store finalization did not publish its exact prepared authority');
    return result;
  } finally { issued.delete(output); }
}

/** Signed installed composition only. The genuine EX source holds every
 * productive writer fenced. The operation consumes only the original driver,
 * actual model visitor and canonical Legacy/credential locks. */
export async function runInstalledRollbackPreparation<T>(native: NativeStateOwner, selected: HeldInstalledRuntime,
  inputs: SelectedRollbackInputs, input: InstalledRollbackInvocation,
  finish: (prepared: PreparedInstalledRollback) => Promise<T>, signal?: AbortSignal): Promise<T> {
  const { source, gate, driver, artifacts, owner, identity } = input;
  const command = decodeInstalledRollbackRequest(input.request);
  const current = () => {
    signal?.throwIfAborted(); assertInstalledExclusiveReadSource(source, driver, owner);
    assertHeldMigrationGateOwner(native, gate, owner.filesystem);
    assertCurrentControlFrame(owner, identity);
  };
  current();
  const history = await readInstalledCompletedImportUnderExclusive(native, owner, gate, driver, artifacts, signal);
  if (history.currentDraining) return fail('current rollback requires its retained restart path');
  if (command.migrationId !== history.control.migrationId) {
    current();
    const actual = inspectHeldKernelMigrationEntry(native, owner.filesystem);
    if (actual.kind !== 'controlled' || !actual.controlBytes.equals(history.originalDocuments.controlBytes) ||
        !actual.authorityBytes?.equals(history.originalDocuments.authorityBytes)) return fail('original control changed before rollback refusal');
    const refusal = new KernelStorageError('INVALID_REQUEST', 'rollback names a different migration generation');
    notWritten.set(refusal, { source, driver, owner }); throw refusal;
  }
  if (history.sourceAuth.observation.presence !== 'absent' || history.ready.entries.length !== 0)
    return fail('original auth provenance requires its complete installed restoration branch');
  const runtimeCut = openInstalledRuntimeWitnessCut({ selected, anchor: input.anchor, source, driver, artifacts, owner,
    history: history.retainedOwnerHistory }, signal);
  await validateControlChannelClosure(artifacts, owner, identity); current();
  const schema = await readSignedKernelSchema(artifacts, selected.bundle, artifacts.releaseTrustRoots()); current();
  const archiveId = randomBytes(32).toString('base64url');
  const inspector = openHeldCurrentMigrationInspector(native, gate, owner.filesystem, {
    migrationId: command.migrationId, archiveId, legacyRoot: history.legacy.root, backupRoot: history.backup.backupRoot,
    entryCount: history.inventory.entryCount, controlBytes: history.originalDocuments.controlBytes,
    authorityBytes: history.originalDocuments.authorityBytes, rendezvousBytes: history.originalDocuments.authorityBytes,
    authMarkerBytes: history.originalDocuments.authMarkerBytes
  }, inputs.modelScope);
  let publisher: HeldCurrentRollbackPublisher | undefined;
  let value: T | undefined, failed = false, failure: unknown;
  try {
    const earlyProcess = await inspectHeldLegacyProcessCut(inspector, signal); current();
    if (earlyProcess.kind !== 'complete') {
      const actual = inspectHeldKernelMigrationEntry(native, owner.filesystem);
      if (actual.kind !== 'controlled' || !actual.controlBytes.equals(history.originalDocuments.controlBytes) ||
          !actual.authorityBytes?.equals(history.originalDocuments.authorityBytes)) return fail('original control changed before rollback refusal');
      const refusal = new KernelStorageError('RECOVERY_REQUIRED', 'rollback requires complete original Legacy process quiescence');
      notWritten.set(refusal, { source, driver, owner }); throw refusal;
    }
    const recheckProcessCut = async () => {
      current(); const inspected = await inspectHeldLegacyProcessCut(inspector, signal); current();
      if (inspected.kind !== 'complete' || inspected.digest !== earlyProcess.digest)
        return fail('original Legacy process cut changed during rollback');
    };
    async function* entries() {
      for await (const event of readOwnedImportInventory(artifacts, history.inventory, signal)) {
        current(); if (event.kind === 'entry') yield event.entry;
      }
    }
    const observed = await verifyHeldCurrentMigrationLegacy(inspector, entries(), signal);
    if (observed.sourceAuth !== 'matched_original_marker' || observed.entryCount !== history.inventory.entryCount ||
        canonicalSha256(observed.legacyRoot) !== canonicalSha256(history.legacy.root))
      return fail('rollback lacks the exact original Legacy source and auth marker');
    await recheckProcessCut();
    publisher = holdCurrentRollbackPublisher(inspector);
    // Canonical account/Owner -> model -> Legacy -> credential ordering. The
    // genuine native credential guard is held without opening a write pager.
    value = await withHeldCredentialNativeScope(native, { image: inputs.image, root: inputs.root,
      rootIdentity: inputs.rootIdentity, stateRoot: inputs.stateRoot, migrationGate: gate }, async credential => {
      const livePublisher = publisher!;
      const retained: PublishedArtifact[] = [];
      const retain = async (record: object, purpose: MigrationTailFormat) => {
        current(); credential.assertHeld();
        const item = await inputs.tail.publishCanonical(record, purpose);
        if (canonicalSha256(await inputs.tail.readCanonical(item.ref)) !== item.ref || item.ref !== canonicalSha256(record))
          return fail('migration tail changed its complete original bytes');
        retained.push(item); current(); credential.assertHeld(); return item.ref;
      };
      driver.readSnapshot(history.assertUnchanged); current(); credential.assertHeld(); inspector.assertHeld();
      const originalMarker = history.authority;
      if (originalMarker.authority !== 'kernel') return fail('rollback requires the actual original Kernel marker');
      const originalMarkerRef = await retain(originalMarker, originalMarker.format);
      const requestedAt = rollbackTime(driver, owner);
      const request = decodeRollbackToLegacyRequest(withDigest({
        schemaVersion: 1, format: 'cliq-rollback-to-legacy-request-v1', migrationId: command.migrationId,
        principalId: identity.principalId, channelIdentityRef: identity.channelIdentityRef, channelIdentityDigest: identity.channelIdentityDigest,
        requestId: command.requestId, currentAuthorityMarkerRef: originalMarkerRef, currentAuthorityMarkerDigest: originalMarker.markerDigest,
        currentKernelGenerationIdentityRef: originalMarker.kernelGenerationIdentityRef,
        currentKernelGenerationIdentityDigest: originalMarker.kernelGenerationIdentityDigest,
        backupRef: history.control.backupRef, backupDigest: history.backup.backupDigest,
        allowPlaintextLegacyCredentials: command.allowPlaintextLegacyCredentials, requestedAt
      }, 'requestDigest'));
      const requestRef = await retain(request, request.format);
      const draining = decodeKernelRollbackDrainingControl(withDigest({
        schemaVersion: 1, format: 'cliq-kernel-rollback-control-v1', phase: 'rollback_draining', controlRevision: 1,
        migrationId: command.migrationId, archiveId, kernelGenerationId: originalMarker.generationId,
        stateRootIdentityRef: originalMarker.stateRootIdentityRef, stateRootIdentityDigest: originalMarker.stateRootIdentityDigest,
        stateRootCanonicalAbsolutePath: originalMarker.stateRootCanonicalAbsolutePath,
        requestRef, requestDigest: request.requestDigest, originalImportControlRef: canonicalSha256(history.control),
        originalImportControlDigest: history.control.controlDigest, originalKernelAuthorityRef: originalMarkerRef,
        originalKernelAuthorityDigest: originalMarker.markerDigest, preparedAt: rollbackTime(driver, owner)
      }, 'controlDigest'));
      const drainingControlRef = await retain(draining, draining.format);
      driver.readSnapshot(history.assertUnchanged); current(); credential.assertHeld();
      publishHeldRollbackDraining(livePublisher, draining);
      const original = await archiveOriginalKernel(native, gate, inputs.image, draining, driver, schema,
        async () => undefined, signal, inspector, runtimeCut);
      assertOriginalCompletedKernelArchive(original, native, gate, driver);
      const archive = await verifyHeldCurrentKernelArchive(inspector, { archiveCollection: original.birth.archiveCollection,
        archiveDirectory: original.birth.archiveDirectory, manifest: original.manifestObservation }, draining, signal, runtimeCut);
      if (canonicalSha256(archive.header) !== canonicalSha256(original.manifest)) return fail('current archive differs from its exact original producer');
      const activeOwner = assertActiveStateOwner(driver, owner);
      const archiveWitness = decodeOwnedKernelArchiveWitness(withDigest({
        schemaVersion: 1, format: 'cliq-owned-kernel-archive-witness-v1', migrationId: draining.migrationId,
        archiveId: draining.archiveId, drainingControlRef, drainingControlDigest: draining.controlDigest,
        kernelGenerationId: draining.kernelGenerationId, ownerEpoch: activeOwner.ownerEpoch,
        ownerAcquisitionEvidenceRef: activeOwner.acquisitionEvidenceRef, ownerAcquisitionEvidenceDigest: activeOwner.acquisitionEvidenceDigest,
        archiveCollection: original.birth.archiveCollection, archiveDirectory: original.birth.archiveDirectory,
        manifestFile: original.manifestObservation.file, manifestByteCount: original.manifestObservation.byteCount,
        manifestSha256: original.manifestObservation.sha256, manifestDigest: original.manifest.manifestDigest
      }, 'witnessDigest'));
      const archivedKernelGenerationRef = await retain(archiveWitness, archiveWitness.format);
      driver.readSnapshot(history.assertUnchanged); current(); credential.assertHeld(); inspector.assertHeld();
      await recheckProcessCut();
      const { controlDigest: _originalDrainingDigest, ...drainingFields } = draining;
      const originalMigratedAuthMarkerRef = canonicalSha256(history.authMarker);
      const ready = decodeKernelRollbackArchiveReadyControl(withDigest({
        ...drainingFields, phase: 'rollback_archive_ready', controlRevision: 2,
        drainingControlRef, drainingControlDigest: draining.controlDigest,
        archivedKernelGenerationRef, archivedKernelGenerationDigest: archiveWitness.witnessDigest,
        originalSourceAuthObservationRef: history.ready.sourceAuthObservationRef,
        originalSourceAuthObservationDigest: history.sourceAuth.observationDigest,
        originalMigratedAuthMarkerRef, originalMigratedAuthMarkerDigest: history.authMarker.markerDigest,
        originalAuthMarkerFile: observeHeldRollbackAuthPreimage(livePublisher, originalMigratedAuthMarkerRef),
        updatedAt: rollbackTime(driver, owner)
      }, 'controlDigest'));
      const records = Object.freeze({ request, originalMarker, draining, archive: archiveWitness, ready });
      assertKernelRollbackArchiveReadyClosure(records);
      await retain(ready, ready.format);
      driver.readSnapshot(history.assertUnchanged); current(); credential.assertHeld(); inspector.assertHeld();
      await recheckProcessCut();
      publishHeldRollbackArchiveReady(livePublisher, ready);
      return finishArchiveReadyRollback({ native, input, inputs, inspector, livePublisher, history, records, observed, retained, retain,
        assertCurrent() { current(); driver.readSnapshot(history.assertUnchanged); credential.assertHeld(); inspector.assertHeld(); },
        recheckProcessCut, finish, signal });
    });
  } catch (error) { failed = true; failure = error; }
  if (failure instanceof ResourceRetirementError) {
    unretired.add({ inspector, ...(publisher ? { publisher } : {}) });
    throw failure;
  }
  try {
    publisher?.close(); await releaseHeldCurrentMigrationLegacyLocks(inspector); inspector.close();
  } catch (retirement) {
    unretired.add({ inspector, ...(publisher ? { publisher } : {}) });
    throw new ResourceRetirementError('original rollback and its held Legacy scope did not retire',
      failed ? new AggregateError([failure, retirement]) : retirement);
  }
  if (failed) throw failure;
  return value as T;
}

/** A successor can use only the original complete archive and exact auth
 * intent. Native distinguishes a fresh unlink from current absence. */
async function resumeRollbackArchiveReady<T>(native: NativeStateOwner, selected: HeldInstalledRuntime, inputs: SelectedRollbackInputs,
  input: InstalledRollbackRecoveryInvocation, controlBytes: Buffer, authorityBytes: Buffer,
  finish: (prepared: PreparedInstalledRollback) => Promise<T>, signal?: AbortSignal): Promise<T> {
  const { source, gate, driver, artifacts, owner } = input;
  const current = () => {
    signal?.throwIfAborted(); assertInstalledExclusiveReadSource(source, driver, owner);
    assertHeldMigrationGateOwner(native, gate, owner.filesystem);
  };
  current();
  const records = await readRetainedRollbackArchiveReady(controlBytes, authorityBytes, inputs.tail, signal);
  if (records.ready.controlDigest !== input.restoringControlDigest) return fail('archive-ready control changed after successor acquisition');
  const ownerHistory = await bindStateOwnerRollbackHistory(inputs.tail, records.ready); current();
  const history = await readInstalledCompletedImportUnderExclusive(native, owner, gate, driver, artifacts, signal, { records, ownerHistory });
  const chain = history.retainedOwnerHistory, { request, archive, ready, draining } = records;
  const original = chain.entries[archive.ownerEpoch - 1], latest = chain.entries[owner.ownerEpoch - 1];
  if (!original || !latest || archive.ownerEpoch >= owner.ownerEpoch || original.owner.state !== 'terminal' ||
      original.owner.acquisitionEvidenceRef !== archive.ownerAcquisitionEvidenceRef ||
      original.owner.acquisitionEvidenceDigest !== archive.ownerAcquisitionEvidenceDigest ||
      canonicalSha256(original.acquisition) !== archive.ownerAcquisitionEvidenceRef ||
      original.owner.acquiredAt > ready.updatedAt || original.owner.releasedAt < ready.updatedAt || latest.owner.state !== 'active')
    return fail('archive-ready recovery does not follow the actual original archived Owner');
  for (let epoch = archive.ownerEpoch; epoch < owner.ownerEpoch; epoch++) {
    const prior = chain.entries[epoch - 1], successor = chain.entries[epoch];
    if (!prior || !successor || prior.owner.state !== 'terminal' ||
        (prior.transition?.kind === 'superseded_after_owner_death' ? successor.acquisition.kind !== 'takeover_after_owner_death' :
          prior.transition?.kind !== 'graceful_release' || successor.acquisition.kind !== 'acquire_after_graceful_release'))
      return fail('archive-ready recovery lacks the exact successor Owner chain');
    owner.filesystem.assertPriorProcessDead(prior.process.pid, prior.process.processStartToken);
  }
  const channel = await readRetainedControlChannelClosure(artifacts, owner, request); current();
  if (channel.channel.openedAt > request.requestedAt || request.principalId !== history.preparation.principalId ||
      request.backupRef !== history.control.backupRef || request.backupDigest !== history.backup.backupDigest ||
      history.sourceAuth.observation.presence !== 'absent' || history.ready.entries.length !== 0 ||
      ready.originalSourceAuthObservationRef !== history.ready.sourceAuthObservationRef ||
      ready.originalSourceAuthObservationDigest !== history.sourceAuth.observationDigest ||
      ready.originalMigratedAuthMarkerRef !== canonicalSha256(history.authMarker) ||
      ready.originalMigratedAuthMarkerDigest !== history.authMarker.markerDigest)
    return fail('archive-ready recovery differs from its retained authenticated request or original auth provenance');
  const runtimeCut = openInstalledRuntimeWitnessCut({ selected, anchor: input.anchor, source, driver, artifacts, owner, history: chain }, signal);
  const inspector = openHeldCurrentMigrationInspector(native, gate, owner.filesystem, {
    migrationId: ready.migrationId, archiveId: ready.archiveId, legacyRoot: history.legacy.root,
    backupRoot: history.backup.backupRoot, entryCount: history.inventory.entryCount, controlBytes,
    authorityBytes, rendezvousBytes: authorityBytes, authMarkerBytes: history.originalDocuments.authMarkerBytes
  }, inputs.modelScope, { archiveReady: ready });
  let publisher: HeldCurrentRollbackPublisher | undefined, value: T | undefined, failure: unknown, failed = false;
  try {
    async function* entries() {
      for await (const event of readOwnedImportInventory(artifacts, history.inventory, signal)) {
        current(); if (event.kind === 'entry') yield event.entry;
      }
    }
    const observed = await verifyHeldCurrentMigrationLegacy(inspector, entries(), signal);
    if ((observed.sourceAuth !== 'absent' && observed.sourceAuth !== 'matched_original_marker') ||
        observed.entryCount !== history.inventory.entryCount || canonicalSha256(observed.legacyRoot) !== canonicalSha256(history.legacy.root))
      return fail('archive-ready recovery lacks its complete original Legacy inventory');
    const processCut = await inspectHeldLegacyProcessCut(inspector, signal); current();
    if (processCut.kind !== 'complete') return fail('archive-ready recovery lacks current Legacy process quiescence');
    const recheckProcessCut = async () => {
      current(); const observedCut = await inspectHeldLegacyProcessCut(inspector, signal); current();
      if (observedCut.kind !== 'complete' || observedCut.digest !== processCut.digest)
        return fail('Legacy process cut changed during archive-ready recovery');
    };
    value = await withHeldCredentialNativeScope(native, { image: inputs.image, root: inputs.root,
      rootIdentity: inputs.rootIdentity, stateRoot: inputs.stateRoot, migrationGate: gate }, async credential => {
      const verified = await verifyHeldCurrentKernelArchive(inspector, { archiveCollection: archive.archiveCollection,
        archiveDirectory: archive.archiveDirectory, manifest: { file: archive.manifestFile,
          byteCount: archive.manifestByteCount, sha256: archive.manifestSha256 } }, draining, signal, runtimeCut);
      if (verified.header.manifestDigest !== archive.manifestDigest) return fail('archive-ready source differs from its original complete archive');
      await assertInstalledRollbackProductiveCut(driver, source, owner, verified.header.database.productiveCut, signal);
      await recheckProcessCut();
      const assertCurrent = () => {
        current(); driver.readSnapshot(history.assertUnchanged); credential.assertHeld(); inspector.assertHeld();
      };
      assertCurrent();
      const livePublisher = holdCurrentRollbackPublisher(inspector); publisher = livePublisher;
      const retained: PublishedArtifact[] = Object.values(records).map(record => Object.freeze({
        ref: canonicalSha256(record), mediaType: 'application/json', schemaKind: record.format, byteLength: canonicalJsonBytes(record).length
      }));
      const retain = async (record: object, purpose: MigrationTailFormat) => {
        assertCurrent(); const item = await inputs.tail.publishCanonical(record, purpose);
        if (canonicalSha256(await inputs.tail.readCanonical(item.ref)) !== item.ref || item.ref !== canonicalSha256(record))
          return fail('archive-ready recovery tail changed its complete bytes');
        retained.push(item); assertCurrent(); return item.ref;
      };
      return finishArchiveReadyRollback({ native, input, inputs, inspector, livePublisher, history, records, observed, retained, retain,
        assertCurrent, recheckProcessCut, finish, signal });
    });
  } catch (error) { failed = true; failure = error; }
  if (failure instanceof ResourceRetirementError) {
    unretired.add({ inspector, ...(publisher ? { publisher } : {}) }); throw failure;
  }
  try { publisher?.close(); await releaseHeldCurrentMigrationLegacyLocks(inspector); inspector.close(); }
  catch (retirement) {
    unretired.add({ inspector, ...(publisher ? { publisher } : {}) });
    throw new ResourceRetirementError('archive-ready rollback source did not retire',
      failed ? new AggregateError([failure, retirement]) : retirement);
  }
  if (failed) throw failure;
  return value!;
}

/** A strictly newer actual Owner may continue the exact durable restoring
 * control after the original graceful last transaction. It only revalidates
 * the existing archive/auth/marker objects and performs its own final release.
 * No old process, original descriptor or authenticated frame is reconstructed. */
export async function runInstalledRollbackRecovery<T>(native: NativeStateOwner, selected: HeldInstalledRuntime, inputs: SelectedRollbackInputs,
  input: InstalledRollbackRecoveryInvocation, finish: (prepared: PreparedInstalledRollback) => Promise<T>, signal?: AbortSignal): Promise<T> {
  const { source, gate, driver, artifacts, owner } = input;
  const current = () => {
    signal?.throwIfAborted(); assertInstalledExclusiveReadSource(source, driver, owner);
    assertHeldMigrationGateOwner(native, gate, owner.filesystem);
  };
  current();
  const fixed = inspectHeldKernelMigrationEntry(native, owner.filesystem);
  if (fixed.kind !== 'controlled' || !fixed.authorityBytes) return fail('rollback successor requires its fixed Kernel restoring control');
  const phase = (checkCanonicalBytes(fixed.controlBytes) as { phase?: unknown } | null)?.phase;
  if (phase === 'rollback_archive_ready')
    return resumeRollbackArchiveReady(native, selected, inputs, input, fixed.controlBytes, fixed.authorityBytes, finish, signal);
  const records = await readRetainedRollbackRecords(fixed.controlBytes, fixed.authorityBytes, inputs.tail, signal); current();
  if (records.restoring.controlDigest !== input.restoringControlDigest)
    return fail('rollback successor control changed after its original acquisition');
  const ownerHistory = await bindStateOwnerRollbackHistory(inputs.tail, records.restoring); current();
  const history = await readInstalledCompletedImportUnderExclusive(native, owner, gate, driver, artifacts, signal, { records, ownerHistory });
  const chain = history.retainedOwnerHistory; current();
  const runtimeCut = openInstalledRuntimeWitnessCut({ selected, anchor: input.anchor, source, driver, artifacts, owner, history: chain }, signal);
  const original = chain.entries[records.archive.ownerEpoch - 1], latest = chain.entries[owner.ownerEpoch - 1];
  const preparer = chain.entries[records.restoring.preparerOwnerEpoch - 1];
  if (!original || !preparer || !latest || records.restoring.preparerOwnerEpoch >= owner.ownerEpoch ||
      original.owner.state !== 'terminal' || preparer.owner.state !== 'terminal' ||
      original.owner.acquisitionEvidenceRef !== records.archive.ownerAcquisitionEvidenceRef ||
      original.owner.acquisitionEvidenceDigest !== records.archive.ownerAcquisitionEvidenceDigest ||
      canonicalSha256(original.acquisition) !== records.archive.ownerAcquisitionEvidenceRef ||
      preparer.owner.acquisitionEvidenceRef !== records.restoring.preparerOwnerAcquisitionEvidenceRef ||
      preparer.owner.acquisitionEvidenceDigest !== records.restoring.preparerOwnerAcquisitionEvidenceDigest ||
      original.owner.releasedAt < records.ready.updatedAt || preparer.owner.acquiredAt > records.auth.observedAt ||
      preparer.owner.releasedAt < records.restoring.updatedAt || latest.owner.state !== 'active')
    return fail('rollback successor does not follow the exact restoring Owner and its original archive');
  for (let epoch = records.archive.ownerEpoch; epoch < owner.ownerEpoch; epoch++) {
    const prior = chain.entries[epoch - 1], successor = chain.entries[epoch];
    if (!prior || !successor || prior.owner.state !== 'terminal' ||
        (prior.transition?.kind === 'superseded_after_owner_death' ?
          successor.acquisition.kind !== 'takeover_after_owner_death' :
          prior.transition?.kind !== 'graceful_release' || successor.acquisition.kind !== 'acquire_after_graceful_release'))
      return fail('rollback successor has an incompatible intervening Owner');
    owner.filesystem.assertPriorProcessDead(prior.process.pid, prior.process.processStartToken);
  }
  const channel = await readRetainedControlChannelClosure(artifacts, owner, records.request); current();
  if (channel.channel.openedAt > records.request.requestedAt ||
      records.request.principalId !== history.preparation.principalId ||
      records.request.backupRef !== history.control.backupRef || records.request.backupDigest !== history.backup.backupDigest ||
      records.legacy.restoredEntriesDigest !== history.inventory.entriesDigest ||
      records.auth.legacyRootIdentityRef !== history.preparation.legacyRootIdentityRef ||
      records.auth.legacyRootIdentityDigest !== history.legacy.identityDigest ||
      records.auth.originalSourceAuthObservationRef !== history.ready.sourceAuthObservationRef ||
      records.auth.originalSourceAuthObservationDigest !== history.sourceAuth.observationDigest ||
      records.auth.originalMigratedAuthMarkerRef !== canonicalSha256(history.authMarker) ||
      records.auth.originalMigratedAuthMarkerDigest !== history.authMarker.markerDigest ||
      records.auth.previousMarkerFile.ownerUid !== history.legacy.root.ownerUid ||
      records.auth.previousMarkerFile.deviceId !== history.legacy.root.deviceId ||
      history.sourceAuth.observation.presence !== 'absent' || history.ready.entries.length)
    return fail('rollback successor changed its original import, auth or authenticated request provenance');
  const retained = Object.values(records).map(record => Object.freeze({
    ref: canonicalSha256(record), mediaType: 'application/json', schemaKind: record.format, byteLength: canonicalJsonBytes(record).length
  }));
  let latestReleaseTime: string | undefined;
  for (let epoch = owner.ownerEpoch - 1; epoch >= preparer.owner.ownerEpoch; epoch--) {
    const entry = chain.entries[epoch - 1];
    if (entry?.owner.state === 'terminal' && entry.transition?.kind === 'graceful_release') {
      latestReleaseTime = entry.owner.releasedAt; break;
    }
  }
  const readRetainedSql = () => driver.readSnapshot(connection => {
    assertSqliteConnectionOwnedBy(driver, connection); history.assertUnchanged(connection);
    const metadata = connection.prepare('SELECT byte_length, created_at FROM artifacts WHERE ref = ?');
    const rows: string[] = [];
    for (const item of retained) {
      const observed = metadata.get<{ byte_length: bigint; created_at: string }>(item.ref);
      if (!observed) continue;
      if (observed.byte_length !== BigInt(item.byteLength) || !latestReleaseTime || observed.created_at > latestReleaseTime)
        return fail('restoring control lacks its original last-transaction retained metadata');
      rows.push(observed.created_at);
    }
    if (rows.length && rows.length !== retained.length) return fail('restoring metadata has no complete original atomic cut');
    return rows;
  });
  const originalSql = readRetainedSql(), originalSqlDigest = canonicalSha256(originalSql);
  const assertRetainedSql = () => {
    if (canonicalSha256(readRetainedSql()) !== originalSqlDigest) return fail('original restoring metadata changed under the continuous EX');
  };
  current();
  const inspector = openHeldCurrentMigrationInspector(native, gate, owner.filesystem, {
    migrationId: records.restoring.migrationId, archiveId: records.restoring.archiveId, legacyRoot: history.legacy.root,
    backupRoot: history.backup.backupRoot, entryCount: history.inventory.entryCount, controlBytes: fixed.controlBytes,
    authorityBytes: fixed.authorityBytes, rendezvousBytes: fixed.authorityBytes, authMarkerBytes: history.originalDocuments.authMarkerBytes
  }, inputs.modelScope, { control: records.restoring, marker: records.marker,
    ...(originalSql.length === 0 ? { requireUnpublishedLegacy: true as const } : {}) });
  let publisher: HeldCurrentRollbackPublisher | undefined, prepared: PreparedInstalledRollback | undefined;
  let failed = false, failure: unknown, value: T | undefined;
  try {
    async function* entries() {
      for await (const event of readOwnedImportInventory(artifacts, history.inventory, signal)) {
        current(); if (event.kind === 'entry') yield event.entry;
      }
    }
    const retainedLegacy = await verifyHeldCurrentMigrationLegacy(inspector, entries(), signal);
    if (retainedLegacy.sourceAuth !== 'absent' || retainedLegacy.entryCount !== history.inventory.entryCount ||
        canonicalSha256(retainedLegacy.legacyRoot) !== canonicalSha256(history.legacy.root))
      return fail('current restored Legacy source differs from the original verified inventory');
    const processCut = await inspectHeldLegacyProcessCut(inspector, signal); current();
    if (processCut.kind !== 'complete') return fail('rollback successor requires its own complete Legacy process quiescence');
    value = await withHeldCredentialNativeScope(native, { image: inputs.image, root: inputs.root,
      rootIdentity: inputs.rootIdentity, stateRoot: inputs.stateRoot, migrationGate: gate }, async credential => {
      const witness = records.archive;
      const observed = await verifyHeldCurrentKernelArchive(inspector, { archiveCollection: witness.archiveCollection,
        archiveDirectory: witness.archiveDirectory, manifest: { file: witness.manifestFile,
          byteCount: witness.manifestByteCount, sha256: witness.manifestSha256 } }, records.draining, signal, runtimeCut);
      if (observed.header.manifestDigest !== witness.manifestDigest)
        return fail('current archive differs from its retained original producer');
      await assertInstalledRollbackProductiveCut(driver, source, owner, observed.header.database.productiveCut, signal);
      const finalProcessCut = await inspectHeldLegacyProcessCut(inspector, signal);
      if (finalProcessCut.kind !== 'complete' || finalProcessCut.digest !== processCut.digest)
        return fail('Legacy process cut changed during current rollback inspection');
      current(); credential.assertHeld(); assertRetainedSql();
      const livePublisher = holdCurrentRollbackPublisher(inspector); publisher = livePublisher;
      const assertCurrent = () => { current(); credential.assertHeld(); inspector.assertHeld(); assertRetainedSql(); };
      assertCurrent();
      const output: PreparedInstalledRollback = Object.freeze({ restoring: records.restoring, marker: records.marker,
        receipt: records.receipt, retained: Object.freeze(retained), tail: inputs.tail });
      prepared = output;
      const originalIssuer: HeldPreparation = { native, input, inspector, publisher: livePublisher, assertCurrent, published: false };
      issued.set(output, originalIssuer);
      const result = await finish(output);
      if (!originalIssuer.published) return fail('successor finalization did not publish its exact prepared authority');
      return result;
    });
  } catch (error) { failed = true; failure = error; }
  if (prepared) issued.delete(prepared);
  if (failure instanceof ResourceRetirementError) {
    unretired.add({ inspector, ...(publisher ? { publisher } : {}) }); throw failure;
  }
  try { publisher?.close(); await releaseHeldCurrentMigrationLegacyLocks(inspector); inspector.close(); }
  catch (retirement) {
    unretired.add({ inspector, ...(publisher ? { publisher } : {}) });
    throw new ResourceRetirementError('rollback successor and original physical observations did not retire',
      failed ? new AggregateError([failure, retirement]) : retirement);
  }
  if (failed) throw failure;
  return value as T;
}
