// One original-process producer/consumer chain. Store must establish and keep
// its full entry/Legacy quiescence cohort before calling this internal module.
// This file does not acquire a new Owner, select a path for SQLite, restore
// permissions, certify old creator provenance or advertise a complete command.
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeOwnedLegacyImportRequest, decodeOwnedLegacyImportPreparation, decodeOwnedLegacyRootIdentity,
  decodeOwnedImportBackup, decodeOwnedImportCredentialReady, decodeOwnedImportSourceAuthObservation,
  decodePreparedImportDatabaseImageIdentity, decodeOwnedPreparedImportCandidate, decodeOwnedLegacyImportReceipt,
  decodeOwnedLegacyImportResponse, type OwnedLegacyImportPreparationV1, type OwnedLegacyImportResponseV1 } from '../kernel/owned-import-data.js';
import { decodeOwnedLegacyImportControl, decodeMigrationAuthorityMarker } from '../kernel/migration-control.js';
import { decodeLegacyAuthMigratedMarker } from '../kernel/migration-auth-data.js';
import type { KernelGenerationIdentityV1 } from '../kernel/types.js';
import type { ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { assertCurrentControlFrame, validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { KernelStorageError } from './errors.js';
import { withMigrationCredentialAuthorityLock, withInstalledPreparedImportProjection,
  type HeldInstalledRuntime } from './installed-runtime.js';
import { buildInstalledLegacyImportCandidate } from './legacy-import-source.js';
import { observeHeldMigrationRoots, publishHeldMigrationInitialSpine, observeHeldMigrationOriginalAuth,
  advanceHeldMigrationControl, publishHeldMigrationAuthCutover, publishHeldMigrationKernelAuthority,
  readHeldMigrationRendezvous, readHeldMigrationControl, assertHeldMigrationCredentialFilesystem, prepareHeldMigrationLegacyLocks,
  assertHeldEarlyMigrationProcessRefusal, inspectHeldLegacyProcessCut,
  type HeldMigrationCredentialGate, type HeldMigrationFilesystem } from './native-owner.js';
import { capturePreparedImportBaseline } from './prepared-import-candidate.js';
import { publishOwnedImportInventory } from './owned-import-inventory.js';
import { digestOwnedImportRows } from './owned-import-preview-audit.js';
import { commitInstalledOwnedLegacyImport } from './owned-import-transaction.js';
import { readSignedKernelSchema } from './signed-schema.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { assertSqliteConnectionOwnedBy, type SqliteDriver } from './sqlite-driver.js';
import { readControlRequest } from './rows.js';

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
const earlyProcessRefusals = new WeakMap<KernelStorageError, Readonly<{ gate: HeldMigrationCredentialGate; owner: StateOwnerContext }>>();
export function isInstalledImportLegacyQuiescenceRefusal(error: unknown): boolean {
  return error instanceof KernelStorageError && earlyProcessRefusals.has(error);
}
export function isInstalledImportRefusalBeforeControl(error: unknown, gate: HeldMigrationCredentialGate, owner: StateOwnerContext): boolean {
  const original = error instanceof KernelStorageError ? earlyProcessRefusals.get(error) : undefined;
  return original?.gate === gate && original.owner === owner;
}
/** Real original clock transaction, never an injectable sample or temporary
 * Owner. Clock refusals commit without a productive import row. */
function prepareTime(driver: SqliteDriver, owner: StateOwnerContext): string {
  const result = driver.transaction(connection => {
    assertSqliteConnectionOwnedBy(driver, connection); assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    return advanceTimeFence(connection, owner.ownerEpoch, now) === 'healthy' ? now : undefined;
  });
  if (result === undefined) invalid('original canonical time fence refuses owned import preparation');
  return result;
}

/** Complete existing-scope original-process path. The genuine gate and scope
 * are tied to the same original Owner before a source/auth write. This method
 * does not substitute for Store's entry fence or the canonical Legacy locks.
 * Present auth and successor adoption remain explicit unsupported branches. */
export async function produceInstalledOwnedLegacyImport(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, selected: HeldInstalledRuntime, gate: HeldMigrationCredentialGate,
  filesystem: HeldMigrationFilesystem, value: unknown, identity: AuthenticatedControlIdentity, signal?: AbortSignal):
  Promise<Readonly<{ response: OwnedLegacyImportResponseV1; committedAt: string }>> {
  assertSqliteConnectionOwnedBy(driver, driver);
  const request = decodeOwnedLegacyImportRequest(value);
  const current = () => {
    signal?.throwIfAborted(); artifacts.assertReadActive();
    assertHeldMigrationCredentialFilesystem(gate, filesystem, owner.filesystem);
    assertActiveStateOwner(driver, owner); assertCurrentControlFrame(owner, identity);
  };
  const publish = async <T extends object>(data: T, purpose: string) => {
    current(); const artifact = await artifacts.publishCanonical(data, purpose); current(); return artifact;
  };
  current();
  const earlyProcess = await inspectHeldLegacyProcessCut(filesystem, signal); current();
  if (earlyProcess.kind !== 'complete') {
    assertHeldEarlyMigrationProcessRefusal(filesystem);
    const refusal = new KernelStorageError('RECOVERY_REQUIRED', earlyProcess.kind === 'legacy_process_or_descriptor_open' ?
      'Legacy process still holds its original executable or state descriptor' : 'complete Legacy process inspection is unavailable');
    earlyProcessRefusals.set(refusal, { gate, owner }); throw refusal;
  }
  const recheckProcessCut = async () => {
    current(); const observed = await inspectHeldLegacyProcessCut(filesystem, signal); current();
    if (observed.kind !== 'complete' || observed.digest !== earlyProcess.digest)
      return invalid('original locked Legacy process cut changed after its initial control');
  };
  // A new physical package never adopts a previous committed/uncommitted
  // package merely because a request id, path or content happens to match.
  if (readControlRequest(driver, identity.principalId, 'state.migrate', request.requestId))
    invalid('owned import replay requires its retained original package recovery reader');
  const schema = await readSignedKernelSchema(artifacts, selected.bundle, artifacts.releaseTrustRoots()); current();
  const history = await readRetainedStateOwnerHistory(driver, artifacts, owner.ownerEpoch); current();
  const first = history.entries[0]!;
  if (first.acquisition.kind !== 'genesis') invalid('owned import requires its actual complete installed genesis');
  // The existing complete history reader has already checked this exact
  // generation with its original strict genesis/seed/schema readers.
  const generation = await artifacts.readCanonical<KernelGenerationIdentityV1>(first.acquisition.kernelGenerationIdentityRef); current();
  if (generation.origin !== 'fresh_installed' || generation.generationDigest !== first.acquisition.kernelGenerationIdentityDigest ||
      generation.generationDigest !== digestOmitting(generation, 'generationDigest') || generation.stateSchemaVersion !== 8)
    invalid('owned import requires its unchanged fresh_installed generation');
  const roots = observeHeldMigrationRoots(filesystem);
  if (roots.migrationId !== request.migrationId || roots.legacyRoot.canonicalAbsolutePath !== request.legacyRootCanonicalAbsolutePath ||
      generation.stateRootIdentityRef !== owner.stateRootIdentityRef || generation.stateRootIdentityDigest !== owner.stateRootIdentityDigest)
    invalid('owned import changed its actual original root/generation binding');
  await validateControlChannelClosure(artifacts, owner, identity); current();
  // Recheck every original source/empty business table now, under the actual
  // EX and current frame. An earlier pre-EX SQL cut is never reused here.
  capturePreparedImportBaseline(driver, schema);
  const legacyCore = { schemaVersion: 1, format: 'cliq-owned-legacy-root-identity-v1', migrationId: request.migrationId,
    root: roots.legacyRoot, identityDigest: '' };
  legacyCore.identityDigest = digestOmitting(legacyCore, 'identityDigest');
  const legacy = decodeOwnedLegacyRootIdentity(legacyCore);
  const requestArtifact = await publish(request, 'cliq-owned-legacy-import-request-v1');
  const legacyArtifact = await publish(legacy, legacy.format);
  const schemaArtifact = await publish(schema, 'cliq-signed-kernel-schema-v1');
  const preparedAt = prepareTime(driver, owner), preparingOwner = assertActiveStateOwner(driver, owner), fence = readTimeFence(driver);
  if (!fence || fence.state !== 'healthy' || fence.lastAcceptedAt !== preparedAt) invalid('owned preparation lost its actual original fence');
  const preparationCore: OwnedLegacyImportPreparationV1 = { schemaVersion: 1, format: 'cliq-owned-legacy-import-preparation-v1',
    migrationId: request.migrationId, principalId: identity.principalId, requestId: request.requestId,
    requestRef: requestArtifact.ref, requestDigest: requestArtifact.ref,
    channelIdentityRef: identity.channelIdentityRef, channelIdentityDigest: identity.channelIdentityDigest,
    stateRootIdentityRef: owner.stateRootIdentityRef, stateRootIdentityDigest: owner.stateRootIdentityDigest,
    legacyRootIdentityRef: legacyArtifact.ref, legacyRootIdentityDigest: legacy.identityDigest,
    kernelGenerationIdentityRef: first.acquisition.kernelGenerationIdentityRef,
    kernelGenerationIdentityDigest: first.acquisition.kernelGenerationIdentityDigest,
    preparingOwner: preparingOwner.state === 'active' ? preparingOwner : invalid('original preparing Owner is not active'),
    preparingOwnerHistoryThroughEpoch: preparingOwner.ownerEpoch, preparingTimeFenceDigest: fence.fenceDigest,
    signedSchemaManifestRef: schemaArtifact.ref, signedSchemaManifestDigest: schema.profileDigest,
    signedSchemaDigest: schema.schemaManifest.schemaDigest, preparedAt, preparationDigest: '' };
  const preparation = decodeOwnedLegacyImportPreparation({ ...preparationCore,
    preparationDigest: digestOmitting(preparationCore, 'preparationDigest') });
  const preparationArtifact = await publish(preparation, preparation.format);
  const initialCore = { schemaVersion: 1, format: 'cliq-migration-control-v1', phase: 'cutover_preflight', controlRevision: 1,
    migrationId: request.migrationId, sourceGenerationDigest: legacy.identityDigest, targetGenerationId: generation.generationId,
    stateRootIdentityRef: owner.stateRootIdentityRef, stateRootIdentityDigest: owner.stateRootIdentityDigest,
    stateRootCanonicalAbsolutePath: roots.stateRoot.canonicalAbsolutePath,
    preparationRef: preparationArtifact.ref, preparationDigest: preparation.preparationDigest,
    createdAt: preparedAt, updatedAt: preparedAt, controlDigest: '' };
  const initial = decodeOwnedLegacyImportControl({ ...initialCore, controlDigest: digestOmitting(initialCore, 'controlDigest') });
  await publish(initial, initial.format); publishHeldMigrationInitialSpine(filesystem, preparation, initial); current();
  await prepareHeldMigrationLegacyLocks(filesystem, signal); current();
  await recheckProcessCut();

  const observedAt = prepareTime(driver, owner), observation = observeHeldMigrationOriginalAuth(filesystem);
  if (observation.presence !== 'absent')
    invalid('present Legacy auth requires its recognized private source-to-platform participant');
  const sourceAuthCore = { schemaVersion: 1, format: 'cliq-owned-import-source-auth-observation-v1', migrationId: request.migrationId,
    legacyRootIdentityRef: legacyArtifact.ref, legacyRootIdentityDigest: legacy.identityDigest,
    observedAt, observation, observationDigest: '' };
  const sourceAuth = decodeOwnedImportSourceAuthObservation({ ...sourceAuthCore,
    observationDigest: digestOmitting(sourceAuthCore, 'observationDigest') });
  const sourceAuthArtifact = await publish(sourceAuth, sourceAuth.format);
  const completedReadyAt = prepareTime(driver, owner);
  const readyCore = { schemaVersion: 1, format: 'cliq-owned-legacy-import-credential-ready-v1', migrationId: request.migrationId,
    preparationRef: preparationArtifact.ref, preparationDigest: preparation.preparationDigest, principalId: identity.principalId,
    sourceAuthObservationRef: sourceAuthArtifact.ref, sourceAuthObservationDigest: sourceAuth.observationDigest,
    entries: [], completedAt: completedReadyAt, readyDigest: '' };
  const ready = decodeOwnedImportCredentialReady({ ...readyCore, readyDigest: digestOmitting(readyCore, 'readyDigest') });
  const readyArtifact = await publish(ready, ready.format);
  const stagedAt = prepareTime(driver, owner), baseline = capturePreparedImportBaseline(driver, schema);
  const stage = await buildInstalledLegacyImportCandidate(selected, filesystem, artifacts, schema, baseline, {
    migrationId: request.migrationId, principalId: identity.principalId, legacyRootPath: request.legacyRootCanonicalAbsolutePath,
    publicationPreparedAt: stagedAt, signal }); current();
  const inventory = await publishOwnedImportInventory(filesystem, artifacts, { migrationId: request.migrationId,
    preparationRef: preparationArtifact.ref, preparationDigest: preparation.preparationDigest,
    legacyRootIdentityRef: legacyArtifact.ref, legacyRootIdentityDigest: legacy.identityDigest, signal }); current();
  const backupCore = { schemaVersion: 1, format: 'cliq-owned-legacy-import-backup-v1', migrationId: request.migrationId,
    preparationRef: preparationArtifact.ref, preparationDigest: preparation.preparationDigest,
    inventoryRef: inventory.artifact.ref, inventoryDigest: inventory.manifest.inventoryDigest, backupRoot: roots.backupRoot,
    entriesDigest: inventory.manifest.entriesDigest, completedAt: prepareTime(driver, owner), backupDigest: '' };
  const backup = decodeOwnedImportBackup({ ...backupCore, backupDigest: digestOmitting(backupCore, 'backupDigest') });
  const backupArtifact = await publish(backup, backup.format);
  const imageCore = { schemaVersion: 1, format: 'cliq-prepared-import-database-image-identity-v1', snapshotBoundary: 'owned_import_preview',
    excludedDatabaseTail: 'final_import_response_receipt_and_committing_time_fence', migrationId: request.migrationId,
    preparationRef: preparationArtifact.ref, preparationDigest: preparation.preparationDigest,
    signedSchemaManifestRef: schemaArtifact.ref, signedSchemaManifestDigest: schema.profileDigest,
    signedSchemaDigest: schema.schemaManifest.schemaDigest, observation: stage.image, imageDigest: '' };
  const image = decodePreparedImportDatabaseImageIdentity({ ...imageCore, imageDigest: digestOmitting(imageCore, 'imageDigest') });
  const imageArtifact = await publish(image, image.format);
  const importedRowSetDigest = await withInstalledPreparedImportProjection(selected, filesystem, schema,
    projection => digestOwnedImportRows(projection, baseline), signal); current();
  const candidateCore = { schemaVersion: 1, format: 'cliq-owned-prepared-import-candidate-v1', snapshotBoundary: 'owned_import_preview',
    excludedDatabaseTail: 'final_import_response_receipt_and_committing_time_fence', migrationId: request.migrationId,
    preparationRef: preparationArtifact.ref, preparationDigest: preparation.preparationDigest,
    kernelGenerationIdentityRef: first.acquisition.kernelGenerationIdentityRef,
    kernelGenerationIdentityDigest: first.acquisition.kernelGenerationIdentityDigest,
    stateRootIdentityRef: owner.stateRootIdentityRef, stateRootIdentityDigest: owner.stateRootIdentityDigest,
    legacyRootIdentityRef: legacyArtifact.ref, legacyRootIdentityDigest: legacy.identityDigest,
    signedSchemaManifestRef: schemaArtifact.ref, signedSchemaManifestDigest: schema.profileDigest,
    signedSchemaDigest: schema.schemaManifest.schemaDigest, inventoryRef: inventory.artifact.ref, inventoryDigest: inventory.manifest.inventoryDigest,
    backupRef: backupArtifact.ref, backupDigest: backup.backupDigest, credentialReadyRef: readyArtifact.ref, credentialReadyDigest: ready.readyDigest,
    imageIdentityRef: imageArtifact.ref, imageIdentityDigest: image.imageDigest, originalArtifactRefs: baseline.artifacts.map(row => String(row.ref)),
    preimportSqlCutDigest: baseline.digest, projectionDigest: stage.projectionDigest, importedRowSetDigest,
    sessions: stage.staged.sessions, items: stage.staged.items, newArtifacts: stage.staged.newArtifacts, stagedAt, candidateDigest: '' };
  const candidate = decodeOwnedPreparedImportCandidate({ ...candidateCore, candidateDigest: digestOmitting(candidateCore, 'candidateDigest') });
  const candidateArtifact = await publish(candidate, candidate.format);
  const preparedCandidateCore = { ...initial, phase: 'cutover_candidate_ready', controlRevision: 2,
    previousControlRef: canonicalSha256(initial), previousControlDigest: initial.controlDigest,
    inventoryRef: inventory.artifact.ref, inventoryDigest: inventory.manifest.inventoryDigest,
    backupRef: backupArtifact.ref, backupDigest: backup.backupDigest, credentialReadyRef: readyArtifact.ref, credentialReadyDigest: ready.readyDigest,
    candidateRef: candidateArtifact.ref, candidateDigest: candidate.candidateDigest, updatedAt: prepareTime(driver, owner), controlDigest: '' };
  const preparedCandidate = decodeOwnedLegacyImportControl({ ...preparedCandidateCore,
    controlDigest: digestOmitting(preparedCandidateCore, 'controlDigest') });
  await publish(preparedCandidate, preparedCandidate.format); advanceHeldMigrationControl(filesystem, preparedCandidate); current();
  const authMarkerCore = { schemaVersion: 1, format: 'cliq-auth-migrated-v1', migrationId: request.migrationId,
    sourceObservationRef: sourceAuthArtifact.ref, sourceObservationDigest: sourceAuth.observationDigest,
    credentialReadyRef: readyArtifact.ref, credentialReadyDigest: ready.readyDigest, records: [], markerDigest: '' };
  const authMarker = decodeLegacyAuthMigratedMarker({ ...authMarkerCore, markerDigest: digestOmitting(authMarkerCore, 'markerDigest') });
  await publish(authMarker, authMarker.format);
  const cutoverCore = { ...preparedCandidate, phase: 'credential_cutover', controlRevision: 3,
    previousControlRef: canonicalSha256(preparedCandidate), previousControlDigest: preparedCandidate.controlDigest,
    legacyAuthMarkerDigest: authMarker.markerDigest, updatedAt: prepareTime(driver, owner), controlDigest: '' };
  const cutover = decodeOwnedLegacyImportControl({ ...cutoverCore, controlDigest: digestOmitting(cutoverCore, 'controlDigest') });
  const cutoverArtifact = await publish(cutover, cutover.format); advanceHeldMigrationControl(filesystem, cutover); current();
  const receiptCore = { schemaVersion: 1, format: 'cliq-owned-legacy-import-receipt-v1', kind: 'kernel_cutover', migrationId: request.migrationId,
    principalId: identity.principalId, requestId: request.requestId, requestRef: requestArtifact.ref, requestDigest: requestArtifact.ref,
    channelIdentityRef: identity.channelIdentityRef, channelIdentityDigest: identity.channelIdentityDigest,
    stateRootIdentityRef: owner.stateRootIdentityRef, stateRootIdentityDigest: owner.stateRootIdentityDigest,
    legacyRootIdentityRef: legacyArtifact.ref, legacyRootIdentityDigest: legacy.identityDigest,
    preparationRef: preparationArtifact.ref, preparationDigest: preparation.preparationDigest,
    kernelGenerationIdentityRef: first.acquisition.kernelGenerationIdentityRef,
    kernelGenerationIdentityDigest: first.acquisition.kernelGenerationIdentityDigest, candidateRef: candidateArtifact.ref,
    candidateDigest: candidate.candidateDigest, importedRowSetDigest, credentialReadyRef: readyArtifact.ref,
    credentialReadyDigest: ready.readyDigest, completedAt: prepareTime(driver, owner), receiptDigest: '' };
  const receipt = decodeOwnedLegacyImportReceipt({ ...receiptCore, receiptDigest: digestOmitting(receiptCore, 'receiptDigest') });
  const receiptArtifact = await publish(receipt, receipt.format);
  const response = decodeOwnedLegacyImportResponse({ protocolVersion: 1, method: 'state.migrate', status: 'completed',
    requestId: request.requestId, migrationId: request.migrationId, preparationRef: preparationArtifact.ref,
    preparationDigest: preparation.preparationDigest, receiptRef: receiptArtifact.ref, receiptDigest: receipt.receiptDigest, completedAt: receipt.completedAt });
  const responseArtifact = await publish(response, 'cliq-owned-legacy-import-response-v1');
  return withMigrationCredentialAuthorityLock(selected, gate, async credentialAuthority => {
    const committed = await commitInstalledOwnedLegacyImport(driver, artifacts, owner, selected, filesystem, { identity, requestRef: requestArtifact.ref,
      requestDigest: requestArtifact.ref, preparationRef: preparationArtifact.ref, preparationDigest: preparation.preparationDigest,
      controlRef: cutoverArtifact.ref, controlDigest: cutover.controlDigest, receiptRef: receiptArtifact.ref,
      receiptDigest: receipt.receiptDigest, responseRef: responseArtifact.ref, credentialAuthority, signal }); current();
    const committedCore = { ...cutover, phase: 'cutover_import_committed', controlRevision: 4,
      previousControlRef: cutoverArtifact.ref, previousControlDigest: cutover.controlDigest,
      committedReceiptRef: receiptArtifact.ref, committedReceiptDigest: receipt.receiptDigest,
      committedResponseRef: responseArtifact.ref, committedResponseDigest: responseArtifact.ref,
      updatedAt: committed.committedAt, controlDigest: '' };
    const committedControl = decodeOwnedLegacyImportControl({ ...committedCore, controlDigest: digestOmitting(committedCore, 'controlDigest') });
    await publish(committedControl, committedControl.format); advanceHeldMigrationControl(filesystem, committedControl); current();
    const authorityCore = { schemaVersion: 1, format: 'cliq-state-authority-v1', authority: 'kernel', generationId: generation.generationId,
      migrationId: request.migrationId, receiptRef: receiptArtifact.ref, receiptDigest: receipt.receiptDigest,
      stateRootIdentityRef: owner.stateRootIdentityRef, stateRootIdentityDigest: owner.stateRootIdentityDigest,
      stateRootCanonicalAbsolutePath: roots.stateRoot.canonicalAbsolutePath,
      candidateRef: candidateArtifact.ref, candidateDigest: candidate.candidateDigest,
      kernelGenerationIdentityRef: first.acquisition.kernelGenerationIdentityRef,
      kernelGenerationIdentityDigest: first.acquisition.kernelGenerationIdentityDigest,
      publishedAt: prepareTime(driver, owner), markerDigest: '' };
    const authority = decodeMigrationAuthorityMarker({ ...authorityCore, markerDigest: digestOmitting(authorityCore, 'markerDigest') });
    await recheckProcessCut();
    publishHeldMigrationAuthCutover(filesystem, authMarker); current();
    publishHeldMigrationKernelAuthority(filesystem, authority); current();
    const actual = readControlRequest(driver, identity.principalId, 'state.migrate', request.requestId);
    if (!actual || actual.responseRef !== responseArtifact.ref || actual.requestDigest !== requestArtifact.ref ||
        actual.committedAt !== committed.committedAt || canonicalSha256(readHeldMigrationControl(filesystem)) !== canonicalSha256(committedControl) ||
        canonicalSha256(readHeldMigrationRendezvous(filesystem)) !== canonicalSha256(authority))
      invalid('owned import did not close its original response and physical marker-last lineage');
    return Object.freeze({ response, committedAt: committed.committedAt });
  }, signal);
}
