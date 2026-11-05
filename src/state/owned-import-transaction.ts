// The single owned-import mutation boundary. The caller supplies the genuine
// original driver/Owner/selection/native scope and immutable data refs, never a
// projection, SQL string, path, clock, callback or structural authority receipt.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from '../kernel/control-wire-data.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeEndpointAuthorityRecord, decodeCredentialAuthorityRecord, decodeEndpointRegistration,
  type EndpointAuthorityRecordV1, type CredentialAuthorityRecordV1 } from '../kernel/credential-authority.js';
import { decodeOwnedLegacyImportRequest, decodeOwnedLegacyImportPreparation, decodeOwnedLegacyRootIdentity,
  decodeOwnedImportInventory, decodeOwnedImportBackup, decodeOwnedImportCredentialReady, decodeOwnedImportSourceAuthObservation,
  decodePreparedImportDatabaseImageIdentity, decodeOwnedPreparedImportCandidate, decodeOwnedLegacyImportReceipt,
  decodeOwnedLegacyImportResponse, type OwnedLegacyImportResponseV1, type OwnedPreparedImportCandidateV1,
  type OwnedLegacyImportPreparationV1 } from '../kernel/owned-import-data.js';
import { decodeOwnedLegacyImportControl, assertOwnedImportControlSuccessor } from '../kernel/migration-control.js';
import { decodeLegacyAuthMigratedMarker } from '../kernel/migration-auth-data.js';
import type { KernelGenerationIdentityV1 } from '../kernel/types.js';
import { type ArtifactCatalog, type PublishedArtifact, insertArtifactMetadata } from './artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { assertCurrentControlFrame, validateControlChannelClosure, readRetainedControlChannelClosure,
  type AuthenticatedControlIdentity } from './control-channel.js';
import { decodeStateRootIdentity } from './decoders.js';
import { decodeRetainedSecretServiceObservation } from './credential-platform.js';
import { KernelStorageError } from './errors.js';
import { withInstalledPreparedImportProjection, readInstalledRuntimeObservation, readEndpointAuthority, readCredentialAuthority,
  type HeldInstalledRuntime, type HeldCredentialAuthorityLock } from './installed-runtime.js';
import { observeHeldMigrationRoots, observeHeldMigrationOriginalAuth, readHeldMigrationControl, readHeldMigrationPreparationBytes, readHeldMigrationRendezvous,
  readHeldMigrationBackupInventory, assertHeldMigrationFilesystemOwner, assertHeldCredentialCutoverControl, assertHeldMigrationLegacyLocks,
  type HeldMigrationFilesystem, type HeldMigrationBackupEntry } from './native-owner.js';
import { capturePreparedImportBaseline, assertPreparedImportSourceSqlCut,
  type PreparedImportBaseline, type PreparedImportProjection, type PreparedImportRow } from './prepared-import-candidate.js';
import { auditSealedOwnedImportPreview, encodeOwnedImportRow, decodePreparedLegacySessionRow,
  decodePreparedLegacyItemRow, decodePreparedImportArtifactRow } from './owned-import-preview-audit.js';
import { readOwnedImportInventory } from './owned-import-inventory.js';
import { OwnedImportRetainedDataBudget } from './owned-import-budget.js';
import { readControlRequest, insertControlRequest } from './rows.js';
import { assertOwnedImportCredentialAuthority } from './store.js';
import { readSignedKernelSchema } from './signed-schema.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { assertSqliteConnectionOwnedBy, type SqliteConnection, type SqliteDriver, type SqliteInputValue, type SqliteRow } from './sqlite-driver.js';
import { KERNEL_AUTHORITY_TABLES } from './schema.js';

export type OwnedImportCommitInput = Readonly<{ identity: AuthenticatedControlIdentity;
  requestRef: string; requestDigest: string; preparationRef: string; preparationDigest: string;
  controlRef: string; controlDigest: string; receiptRef: string; receiptDigest: string; responseRef: string;
  credentialAuthority: HeldCredentialAuthorityLock; signal?: AbortSignal }>;
export type OwnedImportCommitResult = Readonly<{ response: OwnedLegacyImportResponseV1; committedAt: string; replay: boolean }>;
type CredentialCut = Readonly<{ endpoint: EndpointAuthorityRecordV1; credential: CredentialAuthorityRecordV1 }>;
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function equal(left: unknown, right: unknown): boolean {
  if (left === undefined || right === undefined) return left === right;
  return canonicalSha256(left) === canonicalSha256(right);
}
function sameRow(left: PreparedImportRow, right: PreparedImportRow): boolean {
  return equal(encodeOwnedImportRow(left), encodeOwnedImportRow(right));
}
/** Purpose-specific lineage read after the unchanged full historical reader.
 * This accepts only the actual current installed birth shape; it adds no birth
 * origin, schema interpretation or pristine-namespace exception. */
function decodeOwnedInstalledGeneration(value: unknown): KernelGenerationIdentityV1 {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'generationId', 'stateRootIdentityRef', 'stateRootIdentityDigest',
    'databaseImageRef', 'databaseImageDigest', 'databaseIdentityDigest', 'databaseContentDigest', 'casNamespaceManifestRef',
    'casNamespaceManifestDigest', 'casNamespaceId', 'casRootDigest', 'stateSchemaVersion', 'generationDigest', 'origin',
    'pristineSchemaManifestRef', 'pristineSchemaManifestDigest', 'pristineSchemaDigest', 'runtimeBundleRef',
    'runtimeBundleManifestDigest', 'modelAuthoritySource']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-kernel-generation-identity-v1' || data.origin !== 'fresh_installed' ||
      data.stateSchemaVersion !== 8 || !/^[A-Za-z0-9_-]{43}$/u.test(controlWireText(data.generationId)) ||
      !/^[A-Za-z0-9_-]{43}$/u.test(controlWireText(data.casNamespaceId)) || digestOmitting(data, 'generationDigest') !== data.generationDigest)
    invalid('owned import generation lineage is outside its exact installed birth data');
  for (const key of Object.keys(data)) if (key.endsWith('Ref') || key.endsWith('Digest')) controlWireRef(data[key]);
  const source = data.modelAuthoritySource as { kind?: unknown } | null;
  const model = controlWireRecord(source, source?.kind === 'none' ? ['kind'] : ['kind', 'closureRef', 'closureDigest']);
  if (model.kind === 'present') { controlWireRef(model.closureRef); controlWireRef(model.closureDigest); }
  else if (model.kind !== 'none') invalid('installed generation model authority source is unknown');
  return data as KernelGenerationIdentityV1;
}
function decodeOwnedInstalledBirthMembers(value: unknown, generation: KernelGenerationIdentityV1, ownerUid: number): readonly string[] {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'snapshotBoundary', 'namespaceId', 'stateRootIdentityRef',
    'stateRootIdentityDigest', 'canonicalRootRelativePath', 'ownerUid', 'deviceId', 'directoryFileId', 'mode', 'entries',
    'objectCount', 'totalBytes', 'rootDigest', 'manifestDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-cas-namespace-manifest-v1' || data.snapshotBoundary !== 'generation_birth' ||
      data.namespaceId !== generation.casNamespaceId || data.stateRootIdentityRef !== generation.stateRootIdentityRef ||
      data.stateRootIdentityDigest !== generation.stateRootIdentityDigest || data.canonicalRootRelativePath !== 'cas' ||
      data.ownerUid !== ownerUid || data.mode !== 448 || !Array.isArray(data.entries) || data.objectCount !== data.entries.length ||
      data.rootDigest !== canonicalSha256(data.entries) || data.rootDigest !== generation.casRootDigest ||
      data.manifestDigest !== generation.casNamespaceManifestDigest || data.manifestDigest !== digestOmitting(data, 'manifestDigest'))
    invalid('owned import original birth member catalog changed its exact historical purpose');
  for (const key of ['deviceId', 'directoryFileId']) if (!/^(0|[1-9][0-9]*)$/u.test(controlWireText(data[key])))
    invalid('owned import original birth namespace identity is malformed');
  let total = 0, previous = ''; const refs: string[] = [];
  for (const raw of data.entries) {
    const entry = controlWireRecord(raw, ['artifactRef', 'byteCount']), ref = controlWireRef(entry.artifactRef), size = controlWireInteger(entry.byteCount);
    if (ref <= previous || size > Number.MAX_SAFE_INTEGER - total) invalid('owned import original birth member order/size changed');
    refs.push(ref); previous = ref; total += size;
  }
  if (total !== data.totalBytes) invalid('owned import original birth namespace total changed');
  return Object.freeze(refs);
}
function baselineFromPreview(projection: PreparedImportProjection, candidate: OwnedPreparedImportCandidateV1): PreparedImportBaseline {
  const canonicalTimeFence = Object.freeze([...projection.rows('canonical_time_fence')]);
  const stateOwners = Object.freeze([...projection.rows('state_owners')]);
  const artifacts = Object.freeze(candidate.originalArtifactRefs.map(ref => {
    const row = projection.artifact(ref); if (!row) invalid('preview omitted a frozen original artifact row');
    return decodePreparedImportArtifactRow(row);
  }));
  const digest = canonicalSha256({ canonicalTimeFence: canonicalTimeFence.map(encodeOwnedImportRow),
    stateOwners: stateOwners.map(encodeOwnedImportRow), artifacts: artifacts.map(encodeOwnedImportRow) });
  if (digest !== candidate.preimportSqlCutDigest || canonicalTimeFence.length !== 1 || !stateOwners.length)
    invalid('preview source SQL cut does not rehash in full');
  return Object.freeze({ canonicalTimeFence, stateOwners, artifacts, digest });
}
const importedColumns = {
  sessions: ['id', 'workspace_identity_ref', 'name', 'parent_session_id', 'forked_through_item_seq', 'context_revision',
    'latest_item_seq', 'context_projection_ref', 'created_at', 'updated_at', 'principal_id', 'admission_method',
    'admission_key', 'admission_intent_digest', 'admission_request_id'],
  items: ['item_id', 'session_id', 'run_id', 'item_seq', 'kind', 'payload_ref', 'created_at'],
  artifacts: ['ref', 'media_type', 'schema_kind', 'byte_length', 'created_at']
} as const;
const importedOrder = { sessions: 'id COLLATE BINARY', items: 'item_id COLLATE BINARY', artifacts: 'ref COLLATE BINARY' } as const;
function* liveRows(connection: SqliteConnection, table: keyof typeof importedColumns): IterableIterator<PreparedImportRow> {
  const columns = importedColumns[table];
  const query = `SELECT ${columns.join(',')},${columns.map((column, index) =>
    `CAST(${column} AS BLOB) AS __cliq_raw_${index}`).join(',')} FROM ${table} ORDER BY ${importedOrder[table]}`;
  for (const raw of connection.prepare(query).iterate<SqliteRow>()) {
    const row: Record<string, string | bigint | null> = Object.create(null);
    for (const [index, column] of columns.entries()) {
      const value = raw[column], bytes = raw[`__cliq_raw_${index}`];
      if (value === null ? bytes !== null : (typeof value !== 'string' && typeof value !== 'bigint') ||
          !(bytes instanceof Uint8Array) || !Buffer.from(value.toString(), 'utf8').equals(bytes))
        invalid('live import readback cannot decode original SQL bytes losslessly');
      row[column] = value as string | bigint | null;
    }
    yield Object.freeze(row);
  }
}
/** Complete final SQL comparison, without shortening a large scan. The sealed
 * preview is semantic data, never a replacement for the live database file. */
function assertImportedRows(connection: SqliteConnection, projection: PreparedImportProjection,
  tail: ReadonlyMap<string, PublishedArtifact>, committedAt: string): void {
  for (const table of ['sessions', 'items'] as const) {
    const expected = projection.rows(table);
    try {
      for (const actual of liveRows(connection, table)) {
        const row = expected.next(); if (row.done || !sameRow(actual, row.value)) invalid('live imported rows differ from the complete sealed preview');
      }
      if (!expected.next().done) invalid('live import omitted complete preview rows');
    } finally { expected.return?.(); }
  }
  let previewArtifacts = 0;
  for (const actual of liveRows(connection, 'artifacts')) {
    const expected = projection.artifact(String(actual.ref));
    if (expected) { if (!sameRow(actual, expected)) invalid('live import changed first preview artifact metadata'); previewArtifacts++; }
    else {
      const extra = tail.get(String(actual.ref));
      if (!extra || actual.media_type !== extra.mediaType || actual.schema_kind !== extra.schemaKind ||
          actual.byte_length !== BigInt(extra.byteLength) || actual.created_at !== committedAt)
        invalid('live import has an artifact outside the complete preview and exact final audit tail');
    }
  }
  let expectedArtifacts = 0; for (const _row of projection.rows('artifacts')) expectedArtifacts++;
  if (previewArtifacts !== expectedArtifacts) invalid('live import omitted a complete preview artifact row');
  for (const table of KERNEL_AUTHORITY_TABLES) if (!['canonical_time_fence', 'state_owners', 'artifacts', 'sessions', 'items', 'control_requests'].includes(table) &&
      connection.prepare(`SELECT 1 FROM ${table} LIMIT 1`).get() !== undefined)
    invalid('live import restored a forbidden business or execution family');
}
function insertPreviewRows(connection: SqliteConnection, projection: PreparedImportProjection): void {
  for (const raw of projection.rows('artifacts')) {
    const row = decodePreparedImportArtifactRow(raw);
    insertArtifactMetadata(connection, { ref: row.ref, mediaType: row.media_type, schemaKind: row.schema_kind,
      byteLength: Number(row.byte_length) }, row.created_at);
  }
  for (const table of ['sessions', 'items'] as const) {
    const columns = importedColumns[table];
    const statement = connection.prepare(`INSERT INTO ${table}(${columns.join(',')}) VALUES(${columns.map(() => '?').join(',')})`);
    for (const raw of projection.rows(table)) {
      const row = table === 'sessions' ? decodePreparedLegacySessionRow(raw) : decodePreparedLegacyItemRow(raw);
      if (statement.run(...columns.map(column => (row as PreparedImportRow)[column] as SqliteInputValue)).changes !== 1n)
        invalid('owned import failed to insert one exact fixed preview row');
    }
  }
}
function checkCredentialCut(token: HeldCredentialAuthorityLock, selected: HeldInstalledRuntime, owner: StateOwnerContext,
  principalId: string, filesystem: HeldMigrationFilesystem, records: readonly CredentialCut[], at: string): boolean {
  // Required original Store friend: private WeakMap first, including an empty
  // ready set. A structural token method is never invoked in this transaction.
  assertOwnedImportCredentialAuthority(token, selected, owner, principalId, filesystem); let causal = true;
  for (const { endpoint, credential } of records) {
    const actualEndpoint = readEndpointAuthority(token, endpoint.endpointRegistrationId);
    const actualCredential = readCredentialAuthority(token, credential.credentialGrantId);
    if (!actualEndpoint || !actualCredential || !equal(actualEndpoint, endpoint) || !equal(actualCredential, credential))
      invalid('original credential authority changed after complete ready verification');
    if ([endpoint.createdAt, endpoint.registration.createdAt, credential.createdAt, credential.externalSubject.observedAt].some(time => time > at) ||
        credential.expiresAt !== undefined && credential.expiresAt <= at) causal = false;
  }
  assertOwnedImportCredentialAuthority(token, selected, owner, principalId, filesystem); return causal;
}
function assertOriginalPreparingOwner(preparation: OwnedLegacyImportPreparationV1, owner: StateOwnerContext,
  active: ReturnType<typeof assertActiveStateOwner>): void {
  if (preparation.preparingOwner.ownerEpoch !== owner.ownerEpoch || !equal(preparation.preparingOwner, active))
    invalid('before-marker successor import is unsupported until exact old active-row provenance is retained; original Owner is never rewritten');
}

/** Genuine original-process path, plus exact committed replay. No caller may
 * supply the SQL projection or bypass the installed original-FD VFS reader.
 * The caller must keep the original Store operation and credential borrow
 * active until this Promise has actually joined. */
export async function commitInstalledOwnedLegacyImport(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, selected: HeldInstalledRuntime, filesystem: HeldMigrationFilesystem,
  input: OwnedImportCommitInput): Promise<OwnedImportCommitResult> {
  assertSqliteConnectionOwnedBy(driver, driver);
  const currentScope = () => { input.signal?.throwIfAborted();
    assertHeldMigrationFilesystemOwner(filesystem, owner.filesystem); };
  const current = () => { currentScope(); artifacts.assertReadActive(); assertActiveStateOwner(driver, owner); };
  current(); assertCurrentControlFrame(owner, input.identity);
  // Authenticate the private installed-selection registry before invoking any
  // method on the supplied value. Later actual handle assertions are original.
  await readInstalledRuntimeObservation(selected, input.signal); current();
  const retainedBudget = new OwnedImportRetainedDataBudget();
  const metadata = new Map<string, PublishedArtifact>();
  const retain = (artifact: PublishedArtifact) => {
    const prior = metadata.get(artifact.ref);
    if (prior && prior.byteLength !== artifact.byteLength) invalid('one complete ref has conflicting byte lengths');
    if (!prior) {
      retainedBudget.reserve(artifact.ref, artifact.mediaType, artifact.schemaKind);
      metadata.set(artifact.ref, artifact);
    }
  };
  const read = async <T>(ref: string, decode: (value: unknown) => T, purpose: string): Promise<T> => {
    current(); const bytes = await artifacts.readBoundedBytes(ref, 1_048_576); current();
    const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (sha256Bytes(bytes) !== ref || !canonicalJsonBytes(value).equals(bytes)) invalid('owned import reference is not complete canonical bytes');
    const result = decode(value); retain({ ref, byteLength: bytes.length, mediaType: 'application/json', schemaKind: purpose }); return result;
  };
  const request = await read(input.requestRef, decodeOwnedLegacyImportRequest, 'cliq-owned-legacy-import-request-v1');
  if (input.requestRef !== input.requestDigest) invalid('owned import request digest differs from its original exact request bytes');
  const preparation = await read(input.preparationRef, decodeOwnedLegacyImportPreparation, 'cliq-owned-legacy-import-preparation-v1');
  const control = await read(input.controlRef, decodeOwnedLegacyImportControl, 'cliq-migration-control-v1');
  const receipt = await read(input.receiptRef, decodeOwnedLegacyImportReceipt, 'cliq-owned-legacy-import-receipt-v1');
  const response = await read(input.responseRef, decodeOwnedLegacyImportResponse, 'cliq-owned-legacy-import-response-v1');
  if (preparation.preparationDigest !== input.preparationDigest || control.controlDigest !== input.controlDigest ||
      receipt.receiptDigest !== input.receiptDigest || preparation.principalId !== input.identity.principalId ||
      request.requestId !== preparation.requestId || request.migrationId !== preparation.migrationId ||
      preparation.requestRef !== input.requestRef || preparation.requestDigest !== input.requestDigest ||
      receipt.requestRef !== input.requestRef || receipt.requestDigest !== input.requestDigest ||
      receipt.requestId !== request.requestId || receipt.principalId !== preparation.principalId ||
      receipt.migrationId !== request.migrationId || control.migrationId !== request.migrationId ||
      control.preparationRef !== input.preparationRef || control.preparationDigest !== input.preparationDigest ||
      receipt.preparationRef !== input.preparationRef || receipt.preparationDigest !== input.preparationDigest ||
      response.requestId !== request.requestId || response.migrationId !== request.migrationId ||
      response.preparationRef !== input.preparationRef || response.preparationDigest !== input.preparationDigest ||
      response.receiptRef !== input.receiptRef || response.receiptDigest !== input.receiptDigest ||
      response.completedAt !== receipt.completedAt || preparation.preparedAt > receipt.completedAt ||
      control.createdAt !== preparation.preparedAt || control.phase === 'credential_cutover' && control.updatedAt > receipt.completedAt ||
      receipt.channelIdentityRef !== preparation.channelIdentityRef || receipt.channelIdentityDigest !== preparation.channelIdentityDigest)
    invalid('owned import lost original request/preparation/receipt/response lineage');
  if (control.phase !== 'credential_cutover' && control.phase !== 'cutover_import_committed')
    invalid('owned import requires its exact original contiguous prepared control');
  const priorAtEntry = readControlRequest(driver, preparation.principalId, 'state.migrate', request.requestId);
  const initialCore = { schemaVersion: 1, format: 'cliq-migration-control-v1', phase: 'cutover_preflight',
    migrationId: control.migrationId, controlRevision: 1, sourceGenerationDigest: control.sourceGenerationDigest,
    targetGenerationId: control.targetGenerationId, stateRootIdentityRef: control.stateRootIdentityRef,
    stateRootIdentityDigest: control.stateRootIdentityDigest, stateRootCanonicalAbsolutePath: control.stateRootCanonicalAbsolutePath,
    preparationRef: control.preparationRef, preparationDigest: control.preparationDigest,
    createdAt: control.createdAt, updatedAt: control.createdAt, controlDigest: '' };
  initialCore.controlDigest = digestOmitting(initialCore, 'controlDigest');
  const initialControl = await read(canonicalSha256(initialCore), decodeOwnedLegacyImportControl, 'cliq-migration-control-v1');
  const controls: Array<ReturnType<typeof decodeOwnedLegacyImportControl>> = [control];
  let controlHead: ReturnType<typeof decodeOwnedLegacyImportControl> = control;
  for (let revision = control.controlRevision - 1; revision >= 1; revision--) {
    if (controlHead.phase === 'cutover_preflight') invalid('owned import control chain ended before its original preparation');
    const previous: ReturnType<typeof decodeOwnedLegacyImportControl> = await read(controlHead.previousControlRef, decodeOwnedLegacyImportControl, 'cliq-migration-control-v1');
    if (previous.controlDigest !== controlHead.previousControlDigest || previous.controlRevision !== revision)
      invalid('owned import control chain changed its exact previous revision');
    assertOwnedImportControlSuccessor(previous, controlHead); controls.push(previous); controlHead = previous;
  }
  if (!equal(controlHead, initialControl)) invalid('owned import control chain substituted its original retained preparation');
  if (!priorAtEntry) {
    const actualControl = readHeldMigrationControl(filesystem);
    if (!equal(actualControl, control) || !equal(readHeldMigrationRendezvous(filesystem), initialControl) ||
        !canonicalJsonBytes(preparation).equals(readHeldMigrationPreparationBytes(filesystem)))
      invalid('retained data differs from original held preparation/control bytes');
  }
  const roots = observeHeldMigrationRoots(filesystem);
  const root = await read(preparation.stateRootIdentityRef, decodeStateRootIdentity, 'cliq-state-root-identity-v1');
  const legacy = await read(preparation.legacyRootIdentityRef, decodeOwnedLegacyRootIdentity, 'cliq-owned-legacy-root-identity-v1');
  if (!equal(root, roots.stateRoot) || root.identityDigest !== preparation.stateRootIdentityDigest ||
      canonicalSha256(root) !== owner.stateRootIdentityRef || root.identityDigest !== owner.stateRootIdentityDigest ||
      roots.migrationId !== request.migrationId || legacy.migrationId !== request.migrationId ||
      !equal(legacy.root, roots.legacyRoot) || legacy.identityDigest !== preparation.legacyRootIdentityDigest ||
      request.legacyRootCanonicalAbsolutePath !== roots.legacyRoot.canonicalAbsolutePath ||
      control.stateRootIdentityRef !== preparation.stateRootIdentityRef || control.stateRootIdentityDigest !== preparation.stateRootIdentityDigest ||
      control.stateRootCanonicalAbsolutePath !== root.canonicalAbsolutePath ||
      receipt.stateRootIdentityRef !== preparation.stateRootIdentityRef || receipt.stateRootIdentityDigest !== preparation.stateRootIdentityDigest ||
      receipt.legacyRootIdentityRef !== preparation.legacyRootIdentityRef || receipt.legacyRootIdentityDigest !== preparation.legacyRootIdentityDigest)
    invalid('owned import changed its actual original held root pair');
  const active = assertActiveStateOwner(driver, owner);
  const history = await readRetainedStateOwnerHistory(driver, artifacts, active.ownerEpoch); current();
  const first = history.entries[0]!;
  if (first.acquisition.kind !== 'genesis') invalid('owned import original history has no complete real genesis');
  const generation = await read(first.acquisition.kernelGenerationIdentityRef, decodeOwnedInstalledGeneration, 'cliq-kernel-generation-identity-v1');
  // readRetainedStateOwnerHistory above executes the existing complete
  // readGenesis/seed/schema/namespace readers. It is not replaced or relaxed.
  if (generation.origin !== 'fresh_installed' || generation.generationDigest !== first.acquisition.kernelGenerationIdentityDigest ||
      generation.generationDigest !== digestOmitting(generation, 'generationDigest') ||
      first.acquisition.kernelGenerationIdentityRef !== preparation.kernelGenerationIdentityRef ||
      first.acquisition.kernelGenerationIdentityDigest !== preparation.kernelGenerationIdentityDigest ||
      generation.stateRootIdentityRef !== preparation.stateRootIdentityRef || generation.stateRootIdentityDigest !== preparation.stateRootIdentityDigest ||
      generation.generationId !== control.targetGenerationId || control.sourceGenerationDigest !== legacy.identityDigest ||
      receipt.kernelGenerationIdentityRef !== preparation.kernelGenerationIdentityRef ||
      receipt.kernelGenerationIdentityDigest !== preparation.kernelGenerationIdentityDigest ||
      history.rootIdentity.identityDigest !== root.identityDigest ||
      history.entries.some(entry => entry.owner.runtimeBundleRef !== selected.bundleDigest ||
        entry.owner.runtimeBundleManifestDigest !== selected.bundle.manifestDigest))
    invalid('owned import is not the unchanged original fresh_installed generation');
  const birthMembers = await read(generation.casNamespaceManifestRef,
    value => decodeOwnedInstalledBirthMembers(value, generation, root.ownerUid), 'cliq-cas-namespace-manifest-v1');
  const schema = await readSignedKernelSchema(artifacts, selected.bundle, artifacts.releaseTrustRoots()); current();
  if (preparation.signedSchemaManifestRef !== canonicalSha256(schema) || preparation.signedSchemaManifestDigest !== schema.profileDigest ||
      preparation.signedSchemaDigest !== schema.schemaManifest.schemaDigest || active.runtimeBundleRef !== selected.bundleDigest ||
      active.runtimeBundleManifestDigest !== selected.bundle.manifestDigest)
    invalid('owned import differs from its exact current signed schema/runtime');
  // Rehash that same complete ref for this preparation purpose as well.
  await read(preparation.signedSchemaManifestRef, value => {
    if (!equal(value, schema)) invalid('preparation schema ref differs from exact signed installed source'); return value;
  }, 'cliq-signed-kernel-schema-v1');
  const originalChannel = await readRetainedControlChannelClosure(artifacts, owner, { principalId: preparation.principalId,
    channelIdentityRef: preparation.channelIdentityRef, channelIdentityDigest: preparation.channelIdentityDigest });
  originalChannel.metadata.forEach(retain);
  const channel = await validateControlChannelClosure(artifacts, owner, input.identity); channel.metadata.forEach(retain); current();
  if (!priorAtEntry && channel.channel.openedAt > receipt.completedAt || originalChannel.channel.openedAt > receipt.completedAt)
    invalid('owned import receipt predates original authenticated channel observation');
  const candidate = await read(receipt.candidateRef, decodeOwnedPreparedImportCandidate, 'cliq-owned-prepared-import-candidate-v1');
  if (candidate.candidateDigest !== receipt.candidateDigest || control.candidateRef !== receipt.candidateRef ||
      control.candidateDigest !== receipt.candidateDigest || candidate.importedRowSetDigest !== receipt.importedRowSetDigest ||
      candidate.stagedAt < preparation.preparedAt || candidate.stagedAt > receipt.completedAt)
    invalid('owned import candidate or exact T-to-P stage boundary changed');
  if (controls.some(previous => previous.phase === 'credential_cutover' && previous.updatedAt > receipt.completedAt ||
      previous.phase === 'cutover_candidate_ready' && previous.updatedAt < candidate.stagedAt))
    invalid('owned import control history does not retain its original candidate-to-receipt causality');
  for (const key of ['migrationId', 'preparationRef', 'preparationDigest', 'stateRootIdentityRef', 'stateRootIdentityDigest',
    'legacyRootIdentityRef', 'legacyRootIdentityDigest', 'kernelGenerationIdentityRef', 'kernelGenerationIdentityDigest',
    'signedSchemaManifestRef', 'signedSchemaManifestDigest', 'signedSchemaDigest'] as const) {
    const expected = key === 'preparationRef' ? input.preparationRef : key === 'preparationDigest' ? input.preparationDigest :
      preparation[key as keyof OwnedLegacyImportPreparationV1];
    if (candidate[key] !== expected) invalid('candidate substituted its original preparation/root/generation/schema lineage');
  }
  for (const key of ['inventoryRef', 'inventoryDigest', 'backupRef', 'backupDigest', 'credentialReadyRef', 'credentialReadyDigest'] as const)
    if (candidate[key] !== control[key]) invalid('candidate changed its contiguous prepared control roots');
  if (receipt.credentialReadyRef !== candidate.credentialReadyRef || receipt.credentialReadyDigest !== candidate.credentialReadyDigest)
    invalid('receipt changed its original credential-ready root');
  // Exact committed replay is historical receipt readback. It performs no
  // source-auth/secret/platform read and does not demand that imported Sessions
  // remain forever unchanged after productive work. The first response and
  // original request/channel/preparation are immutable and independently read.
  if (priorAtEntry) {
    parseCanonicalTime(priorAtEntry.committedAt);
    if (priorAtEntry.requestDigest !== input.requestDigest || priorAtEntry.responseRef !== input.responseRef ||
        priorAtEntry.channelIdentityRef !== preparation.channelIdentityRef ||
        priorAtEntry.channelIdentityDigest !== preparation.channelIdentityDigest || priorAtEntry.committedAt < receipt.completedAt ||
        control.phase === 'cutover_import_committed' && (control.committedReceiptRef !== input.receiptRef ||
          control.committedReceiptDigest !== input.receiptDigest || control.committedResponseRef !== input.responseRef ||
          control.committedResponseDigest !== input.responseRef || control.updatedAt < priorAtEntry.committedAt))
      throw new KernelStorageError('REQUEST_ID_CONFLICT', 'owned import request id names another immutable first response');
    await selected.assertHeld(); current();
    driver.readSnapshot(connection => {
      assertSqliteConnectionOwnedBy(driver, connection); assertActiveStateOwner(connection, owner);
      assertCurrentControlFrame(owner, input.identity); history.assertUnchanged(connection);
      if (!equal(readControlRequest(connection, preparation.principalId, 'state.migrate', request.requestId), priorAtEntry) ||
          connection.prepare('SELECT response_revision FROM control_requests WHERE principal_id=? AND method=? AND request_id=?')
            .get<{ response_revision: bigint }>(preparation.principalId, 'state.migrate', request.requestId)?.response_revision !== 1n)
        invalid('owned import committed first response changed during exact replay');
    });
    return Object.freeze({ response, committedAt: priorAtEntry.committedAt, replay: true });
  }
  const image = await read(candidate.imageIdentityRef, decodePreparedImportDatabaseImageIdentity, 'cliq-prepared-import-database-image-identity-v1');
  if (image.imageDigest !== candidate.imageIdentityDigest || image.migrationId !== request.migrationId ||
      image.preparationRef !== input.preparationRef || image.preparationDigest !== input.preparationDigest ||
      image.signedSchemaManifestRef !== preparation.signedSchemaManifestRef || image.signedSchemaManifestDigest !== preparation.signedSchemaManifestDigest ||
      image.signedSchemaDigest !== preparation.signedSchemaDigest)
    invalid('candidate closed image changed exact schema/preparation identity');
  const inventory = await read(candidate.inventoryRef, decodeOwnedImportInventory, 'cliq-owned-legacy-import-inventory-v1');
  const backup = await read(candidate.backupRef, decodeOwnedImportBackup, 'cliq-owned-legacy-import-backup-v1');
  if (inventory.inventoryDigest !== candidate.inventoryDigest || backup.backupDigest !== candidate.backupDigest ||
      inventory.migrationId !== request.migrationId || backup.migrationId !== request.migrationId ||
      inventory.preparationRef !== input.preparationRef || inventory.preparationDigest !== input.preparationDigest ||
      backup.preparationRef !== input.preparationRef || backup.preparationDigest !== input.preparationDigest ||
      inventory.legacyRootIdentityRef !== preparation.legacyRootIdentityRef || inventory.legacyRootIdentityDigest !== preparation.legacyRootIdentityDigest ||
      backup.inventoryRef !== candidate.inventoryRef || backup.inventoryDigest !== candidate.inventoryDigest ||
      backup.entriesDigest !== inventory.entriesDigest || !equal(backup.backupRoot, roots.backupRoot) ||
      backup.completedAt < preparation.preparedAt || backup.completedAt > receipt.completedAt)
    invalid('backup/inventory closure differs from original held root and complete source');
  const actualEntries = readHeldMigrationBackupInventory(filesystem, input.signal)[Symbol.asyncIterator]();
  const contextSources: HeldMigrationBackupEntry[] = [];
  try {
    for await (const event of readOwnedImportInventory(artifacts, inventory, input.signal)) {
      current();
      if (event.kind === 'page') { retain(event.artifact); continue; }
      const next = await actualEntries.next(); current();
      if (next.done || !equal(next.value, event.entry)) invalid('retained inventory differs from original native complete backup observation');
      if (event.entry.kind === 'regular_file' && event.entry.purpose === 'portable_context') {
        retainedBudget.reserve(canonicalJsonBytes(event.entry).toString('utf8'));
        contextSources.push(event.entry);
      }
    }
    if (!(await actualEntries.next()).done) invalid('retained inventory omitted native backup entries');
  } finally { await actualEntries.return?.(); }
  const ready = await read(candidate.credentialReadyRef, decodeOwnedImportCredentialReady, 'cliq-owned-legacy-import-credential-ready-v1');
  const sourceAuth = await read(ready.sourceAuthObservationRef, decodeOwnedImportSourceAuthObservation, 'cliq-owned-import-source-auth-observation-v1');
  if (ready.readyDigest !== candidate.credentialReadyDigest || ready.migrationId !== request.migrationId ||
      ready.preparationRef !== input.preparationRef || ready.preparationDigest !== input.preparationDigest ||
      ready.principalId !== preparation.principalId || ready.completedAt > receipt.completedAt ||
      sourceAuth.observationDigest !== ready.sourceAuthObservationDigest || sourceAuth.migrationId !== request.migrationId ||
      sourceAuth.legacyRootIdentityRef !== preparation.legacyRootIdentityRef || sourceAuth.legacyRootIdentityDigest !== preparation.legacyRootIdentityDigest ||
      sourceAuth.observedAt < preparation.preparedAt || sourceAuth.observedAt > ready.completedAt ||
      !equal(sourceAuth.observation, observeHeldMigrationOriginalAuth(filesystem)) ||
      sourceAuth.observation.presence === 'absent' && ready.entries.length !== 0)
    invalid('credential readiness/source auth observation differs from original private source');
  // The available native reader authenticates file identity/full bytes only.
  // It does not parse recognized provider secrets or prove that this ready set
  // is all-and-only their actual original-platform enrollment. Until the
  // genuine private credential participant consumes that same held source,
  // a caller's plain ready artifact must never open the present-auth branch.
  if (sourceAuth.observation.presence === 'present')
    invalid('present Legacy auth requires the original private source-to-platform credential participant; a retained ready artifact cannot substitute');
  const credentials: CredentialCut[] = [];
  for (const entry of ready.entries) {
    const endpoint = await read(entry.endpointAuthorityRef, decodeEndpointAuthorityRecord, 'cliq-endpoint-authority-record-v1');
    const credential = await read(entry.credentialAuthorityRef, decodeCredentialAuthorityRecord, 'cliq-credential-authority-record-v1');
    const platform = await read(entry.platformObservationRef, decodeRetainedSecretServiceObservation, 'cliq-secret-service-observation-v1');
    const registration = await read(credential.endpointRegistrationRef, decodeEndpointRegistration, 'cliq-endpoint-registration-v1');
    if (endpoint.recordDigest !== entry.endpointAuthorityDigest || credential.recordDigest !== entry.credentialAuthorityDigest ||
        endpoint.endpointRegistrationId !== entry.endpointRegistrationId || credential.credentialGrantId !== entry.credentialGrantId ||
        endpoint.state !== 'active' || credential.state !== 'active' || endpoint.ownerPrincipalId !== preparation.principalId ||
        credential.ownerPrincipalId !== preparation.principalId || endpoint.expectedRegistrationArtifactRef !== credential.endpointRegistrationRef ||
        !equal(registration, endpoint.registration) || credential.endpointIdentityDigest !== registration.endpointIdentityDigest ||
        credential.tlsPolicyDigest !== registration.tlsPolicyDigest || !registration.purposes.includes(credential.purpose) ||
        platform.observationDigest !== entry.platformObservationDigest || platform.kind !== 'present' ||
        platform.selector.ownerPrincipalId !== preparation.principalId || platform.selector.stateRootIdentityDigest !== root.identityDigest ||
        platform.selector.credentialGrantId !== credential.credentialGrantId || platform.selector.secretGeneration !== credential.secretGeneration ||
        credential.platformItem.kind !== 'linux_secret_service' || platform.selector.itemId !== credential.platformItem.itemId ||
        platform.bus.uid !== root.ownerUid || platform.service.uid !== root.ownerUid ||
        entry.observedAt < sourceAuth.observedAt || entry.verifiedAt > ready.completedAt)
      invalid('credential readiness lost its original typed endpoint/authority/platform binding');
    credentials.push({ endpoint, credential });
  }
  if (!checkCredentialCut(input.credentialAuthority, selected, owner, preparation.principalId, filesystem, credentials, receipt.completedAt))
    invalid('credential readiness is noncausal or expired at final receipt preparation P');
  const markerCore = { schemaVersion: 1, format: 'cliq-auth-migrated-v1', migrationId: request.migrationId,
    sourceObservationRef: ready.sourceAuthObservationRef, sourceObservationDigest: ready.sourceAuthObservationDigest,
    credentialReadyRef: candidate.credentialReadyRef, credentialReadyDigest: candidate.credentialReadyDigest,
    records: ready.entries.map(entry => ({ endpointRegistrationId: entry.endpointRegistrationId,
      credentialGrantId: entry.credentialGrantId, authorityRecordDigest: entry.credentialAuthorityDigest })).sort((left, right) =>
        Buffer.compare(Buffer.from(left.endpointRegistrationId), Buffer.from(right.endpointRegistrationId)) ||
        Buffer.compare(Buffer.from(left.credentialGrantId), Buffer.from(right.credentialGrantId))), markerDigest: '' };
  markerCore.markerDigest = digestOmitting(markerCore, 'markerDigest');
  const authMarker = decodeLegacyAuthMigratedMarker(markerCore);
  if (authMarker.markerDigest !== control.legacyAuthMarkerDigest) invalid('prepared source-auth marker changed its exact ready authority projection');
  await read(canonicalSha256(authMarker), decodeLegacyAuthMigratedMarker, 'cliq-auth-migrated-v1');
  const permittedOriginalArtifacts = new Set<string>(birthMembers);
  for (const ref of [owner.stateRootIdentityRef, active.stateLockIdentityRef, first.acquisition.kernelGenerationIdentityRef,
    generation.pristineSchemaManifestRef, generation.databaseImageRef, generation.casNamespaceManifestRef])
    if (ref !== undefined) permittedOriginalArtifacts.add(ref);
  for (const frame of history.entries) {
    permittedOriginalArtifacts.add(frame.owner.processIdentityRef); permittedOriginalArtifacts.add(frame.owner.acquisitionEvidenceRef);
    if (frame.owner.state === 'terminal') permittedOriginalArtifacts.add(frame.owner.transitionEvidenceRef);
  }
  for (const ref of metadata.keys()) permittedOriginalArtifacts.add(ref);
  await selected.assertHeld(); current();
  return withInstalledPreparedImportProjection(selected, filesystem, schema, async projection => {
    current(); if (!equal(projection.image, image.observation)) invalid('candidate actual full-byte original-FD identity differs from its complete image manifest');
    const baseline = baselineFromPreview(projection, candidate);
    const audited = await auditSealedOwnedImportPreview(projection, artifacts, baseline, { migrationId: request.migrationId,
      principalId: preparation.principalId, stagedAt: candidate.stagedAt, sourceEntries: contextSources,
      permittedOriginalArtifactRefs: permittedOriginalArtifacts, retainedBudget, signal: input.signal });
    if (audited.importedRowSetDigest !== candidate.importedRowSetDigest || audited.sessions !== candidate.sessions ||
        audited.items !== candidate.items || audited.newArtifacts !== candidate.newArtifacts || projection.digest() !== candidate.projectionDigest)
      invalid('candidate exact complete typed row/projection audit differs from its retained manifest');
    const prior = readControlRequest(driver, preparation.principalId, 'state.migrate', request.requestId);
    let finalSourceCut: PreparedImportBaseline | undefined;
    if (!prior) {
      assertOriginalPreparingOwner(preparation, owner, assertActiveStateOwner(driver, owner));
      if (input.identity.channelIdentityRef !== preparation.channelIdentityRef || input.identity.channelIdentityDigest !== preparation.channelIdentityDigest)
        invalid('first owned import no longer has its original authenticated producer channel');
      const live = capturePreparedImportBaseline(driver, schema);
      if (!equal(live.stateOwners.map(encodeOwnedImportRow), baseline.stateOwners.map(encodeOwnedImportRow)) ||
          !equal(live.artifacts.map(encodeOwnedImportRow), baseline.artifacts.map(encodeOwnedImportRow)))
        invalid('original complete source SQL cut changed outside its named canonical-fence audit tail');
      // The original Owner sampled P after candidate verification. Its one
      // fence may continue normal maintenance afterwards; that monotonic clock
      // tail is permitted, while Owner/artifact/business source rows stay exact.
      finalSourceCut = live;
      const capturedFence = { schemaVersion: 1, format: 'cliq-canonical-time-fence-v1', stateOwnerEpoch: preparation.preparingOwner.ownerEpoch,
        lastAcceptedAt: preparation.preparedAt, observedWallClockAt: preparation.preparedAt, state: 'healthy',
        updatedAt: preparation.preparedAt, fenceDigest: '' };
      capturedFence.fenceDigest = digestOmitting(capturedFence, 'fenceDigest');
      const fence = readTimeFence(driver);
      if (capturedFence.fenceDigest !== preparation.preparingTimeFenceDigest || !fence || fence.lastAcceptedAt < receipt.completedAt ||
          typeof baseline.canonicalTimeFence[0]?.last_accepted_at !== 'string' ||
          baseline.canonicalTimeFence[0].last_accepted_at < preparation.preparedAt ||
          baseline.canonicalTimeFence[0].last_accepted_at > candidate.stagedAt)
        invalid('preparation/candidate/final receipt do not name the original P0-to-T-to-P canonical fence lineage');
    }
    // The original selected candidate callback already owns its serialized
    // image borrow and revalidates before/after us. Re-enqueueing assertHeld
    // here would await this very callback; retain its actual scope instead.
    current();
    if (!readControlRequest(driver, preparation.principalId, 'state.migrate', request.requestId)) {
      const latest = capturePreparedImportBaseline(driver, schema);
      if (!equal(latest.stateOwners.map(encodeOwnedImportRow), baseline.stateOwners.map(encodeOwnedImportRow)) ||
          !equal(latest.artifacts.map(encodeOwnedImportRow), baseline.artifacts.map(encodeOwnedImportRow)) ||
          typeof latest.canonicalTimeFence[0]?.last_accepted_at !== 'string' || latest.canonicalTimeFence[0].last_accepted_at < receipt.completedAt)
        invalid('final original SQL source changed outside its continuing canonical-fence tail');
      finalSourceCut = latest;
    }
    // Everything asynchronous/platform/CAS/native-source hashing has joined.
    // Only original synchronous assertions, fixed SQL and sealed cursors run
    // between this point and the actual original-driver transaction readback.
    const cut = driver.transaction(connection => {
      assertSqliteConnectionOwnedBy(driver, connection); currentScope(); projection.assertHeld();
      assertHeldMigrationLegacyLocks(filesystem);
      const frame = assertCurrentControlFrame(owner, input.identity); const active = assertActiveStateOwner(connection, owner);
      history.assertUnchanged(connection); assertHeldMigrationFilesystemOwner(filesystem, owner.filesystem);
      const replay = readControlRequest(connection, preparation.principalId, 'state.migrate', request.requestId);
      if (replay) {
        if (replay.requestDigest !== input.requestDigest || replay.responseRef !== input.responseRef ||
            replay.channelIdentityRef !== preparation.channelIdentityRef || replay.channelIdentityDigest !== preparation.channelIdentityDigest ||
            replay.committedAt < receipt.completedAt ||
            connection.prepare('SELECT response_revision FROM control_requests WHERE principal_id=? AND method=? AND request_id=?')
              .get<{ response_revision: bigint }>(preparation.principalId, 'state.migrate', request.requestId)?.response_revision !== 1n)
          throw new KernelStorageError('REQUEST_ID_CONFLICT', 'owned import request id already names another committed first response');
        const retainedControl = readHeldMigrationControl(filesystem);
        if (!equal(retainedControl, control) || control.phase === 'cutover_import_committed' &&
            (control.committedReceiptRef !== input.receiptRef || control.committedReceiptDigest !== input.receiptDigest ||
             control.committedResponseRef !== input.responseRef || control.committedResponseDigest !== input.responseRef))
          invalid('committed owned import replay changed its original control/receipt/response');
        assertImportedRows(connection, projection, metadata, replay.committedAt);
        if (connection.prepare('SELECT 1 FROM control_requests WHERE NOT (principal_id=? AND method=? AND request_id=?) LIMIT 1')
          .get(preparation.principalId, 'state.migrate', request.requestId) !== undefined)
          invalid('owned import replay has an unrelated control response');
        return { kind: 'committed' as const, committedAt: replay.committedAt, replay: true };
      }
      if (control.phase !== 'credential_cutover') invalid('uncommitted owned import cannot adopt a committed-marker control');
      assertOriginalPreparingOwner(preparation, owner, active);
      if (input.identity.channelIdentityRef !== preparation.channelIdentityRef || input.identity.channelIdentityDigest !== preparation.channelIdentityDigest)
        invalid('final owned import lost its genuine original authenticated frame/channel');
      assertHeldCredentialCutoverControl(filesystem, control);
      if (!finalSourceCut) invalid('first owned import has no complete genuine final source SQL cut');
      assertPreparedImportSourceSqlCut(driver, connection, finalSourceCut, schema);
      const committedAt = sampleCanonicalNow(), status = advanceTimeFence(connection, owner.ownerEpoch, committedAt);
      // Do not throw here: the original clock refusal must commit by itself.
      if (status !== 'healthy') return { kind: 'clock_refused' as const };
      if (candidate.stagedAt > receipt.completedAt || receipt.completedAt > committedAt || preparation.preparedAt > candidate.stagedAt ||
          frame.channel.openedAt > committedAt || originalChannel.channel.openedAt > committedAt ||
          ready.completedAt > committedAt || backup.completedAt > committedAt ||
          !checkCredentialCut(input.credentialAuthority, selected, owner, preparation.principalId, filesystem, credentials, committedAt))
        return { kind: 'causal_refused' as const };
      insertPreviewRows(connection, projection);
      for (const artifact of metadata.values()) insertArtifactMetadata(connection, artifact, committedAt);
      assertImportedRows(connection, projection, metadata, committedAt);
      // Complete final validation remains exact even for large candidates.
      // This synchronous path has no 10M-row or Stop2 qualification claim.
      if (projection.digest() !== candidate.projectionDigest) invalid('sealed candidate changed before final first response');
      assertHeldCredentialCutoverControl(filesystem, control); assertCurrentControlFrame(owner, input.identity);
      insertControlRequest(connection, { principalId: preparation.principalId, method: 'state.migrate', requestId: request.requestId,
        channelIdentityRef: preparation.channelIdentityRef, channelIdentityDigest: preparation.channelIdentityDigest,
        requestDigest: input.requestDigest, responseRef: input.responseRef, committedAt });
      const committed = readControlRequest(connection, preparation.principalId, 'state.migrate', request.requestId);
      if (!committed || committed.committedAt !== committedAt || committed.responseRef !== input.responseRef ||
          connection.prepare('SELECT response_revision FROM control_requests WHERE principal_id=? AND method=? AND request_id=?')
            .get<{ response_revision: bigint }>(preparation.principalId, 'state.migrate', request.requestId)?.response_revision !== 1n)
        invalid('owned import first control response did not read back its actual atomic commit time');
      assertHeldMigrationLegacyLocks(filesystem);
      return { kind: 'committed' as const, committedAt, replay: false };
    });
    if (cut.kind === 'clock_refused') invalid('canonical time fence refuses owned import; original refusal was durably retained');
    if (cut.kind === 'causal_refused') invalid('owned import violates original T-to-P-to-C or credential/channel causality');
    return Object.freeze({ response, committedAt: cut.committedAt, replay: cut.replay });
  }, input.signal);
}

