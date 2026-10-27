import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { AuthorizationGrantV1, AuthorizationResponse, SourceGitInspectionCreateRequest, SourceGitInspectionTargetV1,
  SourceReadScopeCreateRequest } from '../kernel/authorization.js';
import { addCanonicalDuration, digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { authorizationGrantCore, authorizationGrantId, authorizationSummary, decodeAuthorizationConsumptionReceipt,
  decodeAuthorizationRevokeRequest, decodeAuthorizationCreateRequest, decodeVerifierIdentityCreateRequest, VerifierAuthorizationError } from './authorization-artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { readRetainedControlChannelClosure, validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { assertCurrentControlFrame } from './control-channel.js';
import { joinResourceOperations, KernelStorageError, stateOperation } from './errors.js';
import { readRetainedVerifierToolchain } from './guest-toolchain.js';
import { readAuthorizationGrant, readAuthorizationCreationControl, insertAuthorizationGrant, consumeOrRevokeAuthorization } from './repositories/authorization-grants.js';
import { readControlRequest, insertControlRequest, readRun, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readStateOwner, type StateOwnerContext } from './state-owner.js';
import { requireHealthyFence } from './reducers/invocation.js';
import { decodeRunSpec, decodeVerifierSpec, decodeWorkspaceIdentity } from './decoders.js';
import { decodeRepositoryIdentity } from './repository-identity.js';
import { beginInstalledAuthorizationDiagnostic } from './installed-run-diagnostics.js';
import { normalizeSourceReadScopePath } from '../kernel/source-read-scope.js';

export type AuthorizationRuntime = { bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[] };
const same = (left: unknown, right: unknown) => canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
function initialGrant(grant: AuthorizationGrantV1): Extract<AuthorizationGrantV1, { state: 'active' }> {
  const row = { ...authorizationGrantCore(grant), rowVersion: 1, grantCoreDigest: grant.grantCoreDigest,
    state: 'active' as const, useCount: 0 as const, rowDigest: '' };
  row.rowDigest = digestOmitting(row, 'rowDigest'); return row;
}
function createResponse(grant: AuthorizationGrantV1): AuthorizationResponse {
  return { protocolVersion: 1, ok: true, result: { method: 'authorization.create', grant: authorizationSummary(initialGrant(grant)) } };
}
function* authorizationOwnersDuring(driver: SqliteDriver, preparedAt: string, committedAt: string) {
  const rows = driver.prepare('SELECT owner_epoch FROM state_owners ORDER BY owner_epoch').all<{ owner_epoch: bigint }>();
  for (const { owner_epoch } of rows) {
    const historical = readStateOwner(driver, Number(owner_epoch));
    if (historical && historical.acquiredAt <= preparedAt &&
        (historical.state !== 'terminal' || historical.releasedAt >= committedAt)) yield historical;
  }
}
function sourceInspectorEntry(bundle: RuntimeBundleManifest) {
  const entry = bundle.entries.find(value => value.entryId === 'source_git_inspector');
  if (!entry || entry.role !== 'platform_helper' || entry.version !== '1' || entry.executable !== false ||
      entry.relativePath !== 'helpers/source-git-inspector.mjs' || entry.byteCount < 1 || entry.byteCount > 1024 * 1024)
    throw new VerifierAuthorizationError('UNSUPPORTED_EXECUTION_IDENTITY');
  return entry;
}
/** Descriptor artifacts only. This consent selection never opens config,
 * refs, index or objects, and is not the later fresh capture/release fence. */
async function selectSourceInspectionTarget(driver: SqliteDriver, artifacts: ArtifactCatalog, runtime: AuthorizationRuntime,
  principalId: string, request: SourceGitInspectionCreateRequest, signal?: AbortSignal): Promise<SourceGitInspectionTargetV1> {
  artifacts = signal ? artifacts.withReadSignal(signal) : artifacts;
  const selection = request.decision.target, session = readSession(driver, selection.sessionId);
  if (readSessionPrincipalId(driver, session.id) !== principalId) throw new KernelStorageError('NOT_FOUND', 'Session does not belong to this principal');
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, session.workspaceIdentityRef));
  if (workspace.kind !== 'live' || workspace.ownerPrincipalId !== principalId || workspace.identityDigest !== selection.expectedWorkspaceIdentityDigest ||
      !workspace.repositoryIdentityRef || !workspace.repositoryIdentityDigest) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
  const repository = decodeRepositoryIdentity(await readCanonicalArtifact(artifacts, workspace.repositoryIdentityRef));
  if (repository.repositoryIdentityDigest !== workspace.repositoryIdentityDigest || repository.platform !== workspace.platform)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source inspection repository descriptor differs from its Session');
  verifyRuntimeBundle(runtime.bundle, runtime.releaseKeys);
  const inspector = sourceInspectorEntry(runtime.bundle); signal?.throwIfAborted();
  return { kind: 'source_git_inspection', purpose: 'source_inspection', sessionId: session.id,
    workspaceIdentityRef: session.workspaceIdentityRef, workspaceIdentityDigest: workspace.identityDigest,
    repositoryIdentityRef: workspace.repositoryIdentityRef, repositoryIdentityDigest: repository.repositoryIdentityDigest,
    scope: selection.scope, recipe: selection.recipe, retention: selection.retention, resourceCeiling: selection.resourceCeiling,
    inspector: { runtimeBundleRef: canonicalSha256(runtime.bundle), runtimeBundleManifestDigest: runtime.bundle.manifestDigest,
      entryId: 'source_git_inspector', entryVersion: '1', entryDigest: inspector.digest } };
}
/** Inert path consent only. Neither creation nor its replay opens the selected
 * entry (including the special ignore-rule source); capture owns that later. */
async function selectSourceReadTarget(driver: SqliteDriver, artifacts: ArtifactCatalog, principalId: string,
  request: SourceReadScopeCreateRequest, signal?: AbortSignal) {
  const selection = request.decision.target, session = readSession(driver, selection.sessionId);
  if (readSessionPrincipalId(driver, session.id) !== principalId) throw new KernelStorageError('NOT_FOUND', 'Session does not belong to this principal');
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(reads, session.workspaceIdentityRef));
  if (workspace.kind !== 'live' || workspace.ownerPrincipalId !== principalId || workspace.identityDigest !== selection.expectedWorkspaceIdentityDigest)
    throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
  signal?.throwIfAborted();
  const target: Extract<AuthorizationGrantV1['target'], { kind: 'read_scope' }> = { kind: 'read_scope', purpose: 'source',
    workspaceIdentityDigest: workspace.identityDigest, canonicalRootRelativePath: normalizeSourceReadScopePath(selection.path, selection.scope),
    scope: selection.scope, ...(selection.expectedDigest === undefined ? {} : { expectedDigest: selection.expectedDigest }) };
  return { target, workspaceIdentityRef: session.workspaceIdentityRef };
}

/** Historical read consent, not permission to reopen a live path. A receipt
 * cannot be accepted until its specific owning capture/admission exists. */
export async function readSourceReadAuthorizationHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  grant: AuthorizationGrantV1, releaseKeys: readonly ReleaseTrustKey[], signal?: AbortSignal) {
  artifacts = signal ? artifacts.withReadSignal(signal) : artifacts; signal?.throwIfAborted();
  if (grant.target.kind !== 'read_scope') throw new TypeError('source read history has another authorization purpose');
  const target = grant.target, row = readAuthorizationCreationControl(driver, grant);
  const [{ channel }, core] = await joinResourceOperations([
    readRetainedControlChannelClosure(artifacts, owner, { principalId: grant.ownerPrincipalId,
      channelIdentityRef: grant.channelIdentityRef, channelIdentityDigest: grant.channelIdentityDigest }),
    readCanonicalArtifact<Record<string, unknown>>(artifacts, grant.sourceRequestDigest)
  ] as const);
  const request = decodeAuthorizationCreateRequest({ ...core, requestDigest: grant.sourceRequestDigest });
  if (request.decision.kind !== 'read_scope' || request.requestId !== grant.sourceRequestId || channel.openedAt > grant.createdAt ||
      grant.expiresAt !== addCanonicalDuration(grant.createdAt, request.ttlMs ?? 3_600_000) ||
      !same(await readCanonicalArtifact(artifacts, row.responseRef), createResponse(grant)))
    throw new TypeError('source read consent has no exact original authenticated creation');
  const expected = await selectSourceReadTarget(driver, artifacts, grant.ownerPrincipalId, request as SourceReadScopeCreateRequest, signal);
  if (!same(expected.target, target)) throw new TypeError('source read consent differs from its exact original selector');
  let creatingOwner = false;
  for (const historical of authorizationOwnersDuring(driver, grant.createdAt, row.committedAt)) {
    const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, historical.runtimeBundleRef);
    verifyRuntimeBundle(bundle, releaseKeys);
    if (bundle.manifestDigest !== historical.runtimeBundleManifestDigest) throw new TypeError('source read creating runtime differs from its owner');
    creatingOwner = true;
  }
  if (!creatingOwner) throw new TypeError('source read consent has no original creating owner interval');
  if (grant.state === 'consumed') {
    const receipt = decodeAuthorizationConsumptionReceipt(await readCanonicalArtifact(artifacts, grant.consumptionReceiptRef));
    if (receipt.consumer.kind !== 'source_inspection' || receipt.grantId !== grant.grantId || receipt.ownerPrincipalId !== grant.ownerPrincipalId ||
        receipt.targetDigest !== grant.targetDigest || receipt.consumedAt !== grant.consumedAt || receipt.consumedAt < row.committedAt)
      throw new TypeError('source rule-read consumption differs from its original independent consent');
    const original = driver.prepare('SELECT principal_id, method, admission_key, admission_intent_digest FROM source_inspection_attempts WHERE inspection_id = ?')
      .get<{ principal_id: string; method: 'run.submit' | 'run.apply'; admission_key: string; admission_intent_digest: string }>(receipt.consumer.inspectionId);
    const { readSourceInspectionAttempt, readSourceInspectionOriginalRequest } = await import('./source-inspection.js');
    const attempt = original && readSourceInspectionAttempt(driver, { principalId: original.principal_id, method: original.method,
      admissionKey: original.admission_key, admissionIntentDigest: original.admission_intent_digest });
    if (!attempt || attempt.inspectionId !== receipt.consumer.inspectionId || attempt.principalId !== grant.ownerPrincipalId ||
        attempt.admissionIntentDigest !== receipt.consumer.admissionIntentDigest || attempt.workspaceIdentityDigest !== target.workspaceIdentityDigest ||
        receipt.consumedAt > attempt.createdAt || attempt.createdAt >= grant.expiresAt)
      throw new TypeError('source rule-read receipt has no matching original capture transaction');
    const { readSourceInspectionTargetData } = await import('./source-target.js');
    const { target: retained } = await readSourceInspectionTargetData(artifacts, attempt, readSourceInspectionOriginalRequest(driver, attempt.inspectionId));
    const selected = retained.schemaVersion === 2 && retained.ignoreReadConsents.find(value => value.grantId === grant.grantId);
    const include = retained.sourceReadGrantRefs.includes(canonicalSha256(grant));
    const ignore = selected && selected.receiptRef === grant.consumptionReceiptRef && selected.receiptDigest === receipt.receiptDigest &&
      target.scope === 'entry' && (target.canonicalRootRelativePath === '.git/info/exclude' || target.canonicalRootRelativePath.split('/').at(-1) === '.gitignore');
    if ((!include && !ignore) || include && !!selected ||
        retained.sessionId !== request.decision.target.sessionId || retained.workspaceIdentityRef !== expected.workspaceIdentityRef)
      throw new TypeError('source rule-read target has another grant, receipt or Session');
  }
  if (grant.state === 'revoked') await verifyRevokeResponse(driver, artifacts, owner, grant, grant.revokedByRequestId, row.committedAt);
  signal?.throwIfAborted(); return { request, committedAt: row.committedAt };
}
/** Historical source-inspection consent, not current read or native authority.
 * Its immutable receipt is audited against the original attempt, never a Run. */
export async function readSourceGitAuthorizationHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  grant: AuthorizationGrantV1, releaseKeys: readonly ReleaseTrustKey[], signal?: AbortSignal) {
  artifacts = signal ? artifacts.withReadSignal(signal) : artifacts;
  signal?.throwIfAborted();
  if (grant.target.kind !== 'source_git_inspection') throw new TypeError('source inspection history has another authorization purpose');
  const target = grant.target, row = readAuthorizationCreationControl(driver, grant);
  const [{ channel }, core] = await joinResourceOperations([
    readRetainedControlChannelClosure(artifacts, owner, { principalId: grant.ownerPrincipalId,
      channelIdentityRef: grant.channelIdentityRef, channelIdentityDigest: grant.channelIdentityDigest }),
    readCanonicalArtifact<Record<string, unknown>>(artifacts, grant.sourceRequestDigest)
  ] as const);
  const request = decodeAuthorizationCreateRequest({ ...core, requestDigest: grant.sourceRequestDigest });
  if (request.decision.kind !== 'source_git_inspection' || request.requestId !== grant.sourceRequestId || channel.openedAt > grant.createdAt ||
      grant.expiresAt !== addCanonicalDuration(grant.createdAt, request.ttlMs ?? 3_600_000) ||
      !same(await readCanonicalArtifact(artifacts, row.responseRef), createResponse(grant)))
    throw new TypeError('source inspection consent has no exact original authenticated creation');
  const selection = request.decision.target;
  if (selection.sessionId !== target.sessionId || selection.expectedWorkspaceIdentityDigest !== target.workspaceIdentityDigest ||
      selection.scope !== target.scope || selection.recipe !== target.recipe || selection.retention !== target.retention ||
      !same(selection.resourceCeiling, target.resourceCeiling)) throw new TypeError('source inspection consent differs from its original decision');
  const session = readSession(driver, target.sessionId);
  const [workspace, repository, bundle] = await joinResourceOperations([
    readCanonicalArtifact(artifacts, target.workspaceIdentityRef).then(decodeWorkspaceIdentity),
    readCanonicalArtifact(artifacts, target.repositoryIdentityRef).then(decodeRepositoryIdentity),
    readCanonicalArtifact<RuntimeBundleManifest>(artifacts, target.inspector.runtimeBundleRef)
  ] as const);
  verifyRuntimeBundle(bundle, releaseKeys);
  const inspector = sourceInspectorEntry(bundle);
  if (readSessionPrincipalId(driver, session.id) !== grant.ownerPrincipalId || session.workspaceIdentityRef !== target.workspaceIdentityRef ||
      workspace.kind !== 'live' || workspace.ownerPrincipalId !== grant.ownerPrincipalId || workspace.identityDigest !== target.workspaceIdentityDigest ||
      workspace.repositoryIdentityRef !== target.repositoryIdentityRef || workspace.repositoryIdentityDigest !== target.repositoryIdentityDigest ||
      repository.repositoryIdentityDigest !== target.repositoryIdentityDigest || repository.platform !== workspace.platform ||
      bundle.manifestDigest !== target.inspector.runtimeBundleManifestDigest || inspector.digest !== target.inspector.entryDigest ||
      ![...authorizationOwnersDuring(driver, grant.createdAt, row.committedAt)].some(historical =>
        historical.runtimeBundleRef === target.inspector.runtimeBundleRef && historical.runtimeBundleManifestDigest === bundle.manifestDigest))
    throw new TypeError('source inspection consent has no original Session and signed inspector selection');
  if (grant.state === 'consumed') {
    const receipt = decodeAuthorizationConsumptionReceipt(await readCanonicalArtifact(artifacts, grant.consumptionReceiptRef));
    if (receipt.consumer.kind !== 'source_inspection' || receipt.grantId !== grant.grantId || receipt.ownerPrincipalId !== grant.ownerPrincipalId ||
        receipt.targetDigest !== grant.targetDigest || receipt.consumedAt !== grant.consumedAt || receipt.consumedAt < row.committedAt)
      throw new TypeError('source inspection consumption differs from its immutable receipt');
    const original = driver.prepare('SELECT principal_id, method, admission_key, admission_intent_digest FROM source_inspection_attempts WHERE inspection_id = ?')
      .get<{ principal_id: string; method: 'run.submit' | 'run.apply'; admission_key: string; admission_intent_digest: string }>(receipt.consumer.inspectionId);
    const { readSourceInspectionAttempt } = await import('./source-inspection.js');
    const attempt = original && readSourceInspectionAttempt(driver, { principalId: original.principal_id, method: original.method,
      admissionKey: original.admission_key, admissionIntentDigest: original.admission_intent_digest });
    if (!attempt || attempt.inspectionId !== receipt.consumer.inspectionId || attempt.principalId !== grant.ownerPrincipalId ||
        attempt.admissionIntentDigest !== receipt.consumer.admissionIntentDigest || attempt.workspaceIdentityDigest !== target.workspaceIdentityDigest ||
        receipt.consumedAt > attempt.createdAt || attempt.createdAt >= grant.expiresAt)
      throw new TypeError('source inspection receipt has no matching original capture transaction');
    const { readSourceInspectionTargetData } = await import('./source-target.js');
    const { readSourceInspectionOriginalRequest } = await import('./source-inspection.js');
    const { target: retained } = await readSourceInspectionTargetData(artifacts, attempt, readSourceInspectionOriginalRequest(driver, attempt.inspectionId));
    if (retained.schemaVersion !== 2 || retained.inspectionGrantId !== grant.grantId || retained.inspectionReceiptRef !== grant.consumptionReceiptRef ||
        retained.sessionId !== target.sessionId || retained.workspaceIdentityRef !== target.workspaceIdentityRef)
      throw new TypeError('source inspection target has another grant or receipt');
  }
  if (grant.state === 'revoked') await verifyRevokeResponse(driver, artifacts, owner, grant, grant.revokedByRequestId, row.committedAt);
  signal?.throwIfAborted(); return { request, committedAt: row.committedAt };
}
function readAnyAuthorizationHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  grant: AuthorizationGrantV1, releaseKeys: readonly ReleaseTrustKey[], signal?: AbortSignal) {
  return grant.target.kind === 'source_git_inspection' ? readSourceGitAuthorizationHistory(driver, artifacts, owner, grant, releaseKeys, signal)
    : grant.target.kind === 'read_scope' ? readSourceReadAuthorizationHistory(driver, artifacts, owner, grant, releaseKeys, signal)
    : readAuthorizationHistory(driver, artifacts, owner, grant, releaseKeys, signal);
}
/** Historical audit only; it cannot authenticate input or reopen an executable. */
export async function readAuthorizationHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  grant: AuthorizationGrantV1, releaseKeys: readonly ReleaseTrustKey[], signal?: AbortSignal) {
  signal?.throwIfAborted();
  const row = readAuthorizationCreationControl(driver, grant);
  const [{ channel }, core] = await joinResourceOperations([
    readRetainedControlChannelClosure(artifacts, owner, { principalId: grant.ownerPrincipalId,
      channelIdentityRef: grant.channelIdentityRef, channelIdentityDigest: grant.channelIdentityDigest }),
    readCanonicalArtifact<Record<string, unknown>>(artifacts, grant.sourceRequestDigest)
  ] as const);
  const request = decodeVerifierIdentityCreateRequest({ ...core, requestDigest: grant.sourceRequestDigest });
  if (request.requestId !== grant.sourceRequestId || channel.openedAt > grant.createdAt ||
      grant.expiresAt !== addCanonicalDuration(grant.createdAt, request.ttlMs ?? 3_600_000) ||
      !same(await readCanonicalArtifact(artifacts, row.responseRef), createResponse(grant)))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'authorization has no exact original authenticated creation');
  const target = grant.target;
  if (target.kind !== 'execution_identity_read' || target.purpose !== 'verifier' || target.identity.kind !== 'guest_toolchain' ||
      target.identity.toolId !== request.decision.target.toolId) throw new TypeError('authorization target differs from its original decision');
  const executionIdentity = target.identity;
  // The creating owner and its selected signed bundle remain historical
  // authority after upgrade. Do not resolve an old public id against today.
  let originalBundle: RuntimeBundleManifest | undefined;
  for (const historical of authorizationOwnersDuring(driver, grant.createdAt, row.committedAt)) {
    const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, historical.runtimeBundleRef);
    if (bundle.manifestDigest !== historical.runtimeBundleManifestDigest) throw new TypeError('authorization historical bundle differs from its owner');
    if (bundle.structuredArtifacts.some(root => root.kind === 'guest_toolchain' && root.artifactId === request.decision.target.guestToolchainManifestId &&
        root.artifactRef === executionIdentity.guestToolchainManifestRef)) { originalBundle = bundle; break; }
  }
  if (!originalBundle) throw new TypeError('authorization has no creating signed toolchain selection');
  const selected = await readRetainedVerifierToolchain(artifacts, { bundle: originalBundle, releaseKeys,
    guestToolchainManifestId: request.decision.target.guestToolchainManifestId, guestToolchainManifestRef: target.identity.guestToolchainManifestRef, signal });
  signal?.throwIfAborted();
  const node = selected.manifest.node;
  if (selected.manifest.manifestDigest !== target.identity.manifestDigest || node.logicalName !== target.identity.toolId ||
      node.canonicalGuestPath !== target.identity.executionPath || node.digest !== target.identity.executableDigest)
    throw new TypeError('authorization no longer reproduces the retained signed Node identity');
  if (grant.state === 'consumed') {
    const receipt = decodeAuthorizationConsumptionReceipt(await readCanonicalArtifact(artifacts, grant.consumptionReceiptRef));
    if (receipt.consumer.kind !== 'run_admission' || receipt.grantId !== grant.grantId || receipt.ownerPrincipalId !== grant.ownerPrincipalId ||
        receipt.targetDigest !== grant.targetDigest || receipt.consumedAt !== grant.consumedAt || receipt.consumedAt < row.committedAt)
      throw new TypeError('authorization consumption does not match its immutable receipt');
    const run = readRun(driver, receipt.consumer.runId);
    const admission = driver.prepare('SELECT principal_id, admission_intent_digest FROM runs WHERE id = ?')
      .get<{ principal_id: string; admission_intent_digest: string }>(run.id);
    if (!admission || admission.principal_id !== grant.ownerPrincipalId || admission.admission_intent_digest !== receipt.consumer.admissionIntentDigest ||
        run.createdAt !== receipt.consumedAt) throw new TypeError('authorization receipt has no matching original Run admission');
  }
  if (grant.state === 'revoked') {
    const revoked = readControlRequest(driver, grant.ownerPrincipalId, 'authorization.revoke', grant.revokedByRequestId);
    if (!revoked || grant.revokedAt < row.committedAt || revoked.committedAt < grant.revokedAt)
      throw new TypeError('revoked authorization has no original revoke request');
    await verifyRevokeResponse(driver, artifacts, owner, grant, grant.revokedByRequestId, row.committedAt);
  }
  return { request, selected, committedAt: row.committedAt };
}
async function verifyRevokeResponse(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  grant: AuthorizationGrantV1, requestId: string, creationCommittedAt: string) {
  const row = readControlRequest(driver, grant.ownerPrincipalId, 'authorization.revoke', requestId);
  if (!row) throw new TypeError('authorization revoke response has no owner');
  parseCanonicalTime(row.committedAt);
  const core = await readCanonicalArtifact<Record<string, unknown>>(artifacts, row.requestDigest);
  const request = decodeAuthorizationRevokeRequest({ ...core, requestDigest: row.requestDigest });
  const { channel } = await readRetainedControlChannelClosure(artifacts, owner, { principalId: grant.ownerPrincipalId,
    channelIdentityRef: row.channelIdentityRef, channelIdentityDigest: row.channelIdentityDigest });
  const response = await readCanonicalArtifact<AuthorizationResponse>(artifacts, row.responseRef);
  const expected: AuthorizationResponse = { protocolVersion: 1, ok: true, result: { method: 'authorization.revoke',
    grant: authorizationSummary(grant), disposition: grant.state === 'consumed' ? 'already_consumed' : grant.state === 'revoked' &&
      grant.revokedByRequestId === requestId ? 'revoked' : 'already_revoked' } };
  const originalRevocation = grant.state === 'revoked' && grant.revokedByRequestId === requestId;
  // A no-op response has no new immutable decision timestamp. Audit its real
  // commit point, rather than inventing a retained preparation timestamp.
  const ownerIntervalStart = originalRevocation ? grant.revokedAt : row.committedAt;
  const originalRevoke = grant.state === 'revoked' ? readControlRequest(driver, grant.ownerPrincipalId, 'authorization.revoke', grant.revokedByRequestId) : undefined;
  const fence = readTimeFence(driver);
  if (channel.openedAt > ownerIntervalStart || request.grantId !== grant.grantId || request.requestId !== requestId ||
      !same(response, expected) || row.committedAt < ownerIntervalStart || ownerIntervalStart < creationCommittedAt ||
      !fence || row.committedAt > fence.lastAcceptedAt ||
      authorizationOwnersDuring(driver, ownerIntervalStart, row.committedAt).next().done ||
      (grant.state === 'revoked' && (!originalRevoke || row.committedAt < originalRevoke.committedAt)) ||
      (grant.state === 'consumed' && row.committedAt < grant.consumedAt)) throw new TypeError('authorization revoke response differs from its exact historical outcome');
  return response;
}
export async function validateAuthorizationHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime?: AuthorizationRuntime): Promise<void> {
  const consumedRuns = new Set<string>();
  for (const row of driver.prepare('SELECT grant_id FROM authorization_grants ORDER BY grant_id').all<{ grant_id: string }>()) {
    if (!runtime) throw new KernelStorageError('RECOVERY_REQUIRED', 'authorization history requires its signed runtime trust roots');
    const grant = readAuthorizationGrant(driver, row.grant_id)!;
    try { await readAnyAuthorizationHistory(driver, artifacts, owner, grant, runtime.releaseKeys); }
    catch (cause) { throw new KernelStorageError('RECOVERY_REQUIRED', 'authorization history is not closed', { cause }); }
    if (grant.state === 'consumed') {
      const receipt = decodeAuthorizationConsumptionReceipt(await readCanonicalArtifact(artifacts, grant.consumptionReceiptRef));
      if (receipt.consumer.kind === 'run_admission') consumedRuns.add(receipt.consumer.runId);
    }
  }
  // Capturing consumes this independent inspection consent, before any Run
  // exists. A missing grant must not disappear merely because capture failed.
  const { readSourceInspectionAttempt, readSourceInspectionOriginalRequest } = await import('./source-inspection.js');
  const { readSourceInspectionTargetData } = await import('./source-target.js');
  for (const key of driver.prepare(`SELECT principal_id, method, admission_key, admission_intent_digest FROM source_inspection_attempts ORDER BY inspection_id`)
    .all<{ principal_id: string; method: 'run.submit' | 'run.apply'; admission_key: string; admission_intent_digest: string }>()) {
    const attempt = readSourceInspectionAttempt(driver, { principalId: key.principal_id, method: key.method,
      admissionKey: key.admission_key, admissionIntentDigest: key.admission_intent_digest })!;
    const { target } = await readSourceInspectionTargetData(artifacts, attempt, readSourceInspectionOriginalRequest(driver, attempt.inspectionId));
    if (target.schemaVersion === 2) {
      const grant = readAuthorizationGrant(driver, target.inspectionGrantId);
      if (!grant || grant.state !== 'consumed' || grant.target.kind !== 'source_git_inspection' ||
          grant.consumptionReceiptRef !== target.inspectionReceiptRef)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'source inspection lost its original one-use consent');
    }
  }
  // A lost grant row must not erase its consumer from recovery. Enumerate the
  // original admitted Runs as well as surviving receipts, without recreating
  // any command, authorization or immutable CAS bytes.
  for (const row of driver.prepare('SELECT id, spec_ref FROM runs ORDER BY id').all<{ id: string; spec_ref: string }>()) {
    try {
      const spec = decodeRunSpec(await readCanonicalArtifact(artifacts, row.spec_ref));
      if (decodeVerifierSpec(await readCanonicalArtifact(artifacts, spec.verifierSpecRef)).verifiers.length) consumedRuns.add(row.id);
    } catch (cause) { throw new KernelStorageError('RECOVERY_REQUIRED', 'verifier admission source history is not closed', { cause }); }
  }
  for (const runId of consumedRuns) {
    if (!runtime) throw new KernelStorageError('RECOVERY_REQUIRED', 'verifier admission requires its signed runtime trust roots');
    const { validateVerifierRunAdmission } = await import('./verifier-admission.js');
    try { await validateVerifierRunAdmission(driver, artifacts, owner, runtime!, runId); }
    catch (cause) { throw new KernelStorageError('RECOVERY_REQUIRED', 'verifier admission authorization history is not closed', { cause }); }
  }
}
export const createAuthorization = stateOperation('INVALID_REQUEST', async (driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, runtime: AuthorizationRuntime | undefined, value: unknown, identity: AuthenticatedControlIdentity, signal?: AbortSignal) => {
  const diagnosis = beginInstalledAuthorizationDiagnostic();
  try {
    signal?.throwIfAborted();
    const request = immutableSnapshot(decodeAuthorizationCreateRequest(value));
    diagnosis?.stage('current_channel');
    const channel = await validateControlChannelClosure(artifacts, owner, identity);
    const replay = async () => {
      const existing = readControlRequest(driver, identity.principalId, 'authorization.create', request.requestId);
      if (!existing) return undefined;
      if (existing.requestDigest !== request.requestDigest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'authorization request id names other bytes');
      const grant = readAuthorizationGrant(driver, authorizationGrantId(identity.principalId, request.requestId, request.requestDigest));
      if (!grant || !runtime) throw new KernelStorageError('RECOVERY_REQUIRED', 'authorization replay has no original grant');
      await readAnyAuthorizationHistory(driver, artifacts, owner, grant, runtime.releaseKeys, signal);
      return immutableSnapshot({ replayed: true, response: createResponse(grant) });
    };
    diagnosis?.stage('replay');
    const retained = await replay(); if (retained) return retained;
    const decision = request.decision;
    if (!runtime || decision.kind === 'execution_identity_read' && !runtime.bundle.structuredArtifacts.some(root => root.kind === 'guest_toolchain' && root.artifactId === decision.target.guestToolchainManifestId))
      throw new VerifierAuthorizationError('UNSUPPORTED_EXECUTION_IDENTITY');
    const active = assertActiveStateOwner(driver, owner);
    if (active.runtimeBundleRef !== canonicalSha256(runtime.bundle) || active.runtimeBundleManifestDigest !== runtime.bundle.manifestDigest)
      throw new TypeError('authorization runtime differs from the current signed StateOwner');
    if (decision.kind === 'execution_identity_read') diagnosis?.stage('selected_toolchain');
    const readScope = decision.kind === 'read_scope'
      ? await selectSourceReadTarget(driver, artifacts, identity.principalId, request as SourceReadScopeCreateRequest, signal) : undefined;
    const target = decision.kind === 'read_scope' ? readScope!.target : decision.kind === 'source_git_inspection'
      ? await selectSourceInspectionTarget(driver, artifacts, runtime, identity.principalId, request as SourceGitInspectionCreateRequest, signal)
      : await (async () => {
        const selected = await readRetainedVerifierToolchain(artifacts, { ...runtime, guestToolchainManifestId: decision.target.guestToolchainManifestId, signal });
        signal?.throwIfAborted(); const node = selected.manifest.node;
        if (node.logicalName !== decision.target.toolId) throw new VerifierAuthorizationError('UNSUPPORTED_EXECUTION_IDENTITY');
        return { kind: 'execution_identity_read' as const, purpose: 'verifier' as const, identity: { kind: 'guest_toolchain' as const,
          guestToolchainManifestRef: selected.manifestRef, manifestDigest: selected.manifest.manifestDigest,
          toolId: node.logicalName, executionPath: node.canonicalGuestPath, executableDigest: node.digest } };
      })();
    // Preparation fixes the original response bytes and TTL. Only the later
    // transaction's fresh sample may register that grant and advance its fence.
    const createdAt = sampleCanonicalNow(), base = { schemaVersion: 1 as const,
      grantId: authorizationGrantId(identity.principalId, request.requestId, request.requestDigest), ownerPrincipalId: identity.principalId,
      channelIdentityRef: identity.channelIdentityRef, channelIdentityDigest: identity.channelIdentityDigest,
      sourceRequestId: request.requestId, sourceRequestDigest: request.requestDigest, target, targetDigest: canonicalSha256(target),
      maxUses: 1 as const, createdAt, expiresAt: addCanonicalDuration(createdAt, request.ttlMs ?? 3_600_000) };
    const grant: AuthorizationGrantV1 = { ...base, rowVersion: 1, grantCoreDigest: canonicalSha256(base), state: 'active', useCount: 0, rowDigest: '' };
    grant.rowDigest = digestOmitting(grant, 'rowDigest');
    const { requestDigest: _digest, ...requestCore } = request;
    diagnosis?.stage('publish_request');
    const requestArtifact = await artifacts.publishCanonical(requestCore, 'cliq-authorization-create-request-v1');
    diagnosis?.stage('publish_response');
    const response = createResponse(grant), published = await artifacts.publishCanonical(response, 'cliq-control-response-v1');
    diagnosis?.stage('channel_recheck');
    await validateControlChannelClosure(artifacts, owner, identity);
    let outcome: ReturnType<typeof advanceTimeFence> | undefined, committed = false;
    diagnosis?.stage('transaction');
    driver.transaction(connection => {
      signal?.throwIfAborted();
      const currentOwner = assertActiveStateOwner(connection, owner);
      if (channel.channel.transport.kind === 'uds_peer') assertCurrentControlFrame(owner, identity);
      if (readControlRequest(connection, identity.principalId, 'authorization.create', request.requestId)) return;
      const now = sampleCanonicalNow();
      outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
      if (outcome !== 'healthy') return;
      if (now < createdAt || now >= grant.expiresAt || currentOwner.acquiredAt > createdAt || channel.channel.openedAt > createdAt)
        throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
      if (target.kind === 'source_git_inspection' && (readSessionPrincipalId(connection, target.sessionId) !== identity.principalId ||
          readSession(connection, target.sessionId).workspaceIdentityRef !== target.workspaceIdentityRef))
        throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
      if (decision.kind === 'read_scope' && (readSessionPrincipalId(connection, decision.target.sessionId) !== identity.principalId ||
          readSession(connection, decision.target.sessionId).workspaceIdentityRef !== readScope!.workspaceIdentityRef))
        throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
      for (const metadata of [...channel.metadata, requestArtifact, published]) insertArtifactMetadata(connection, metadata, now);
      insertAuthorizationGrant(connection, grant);
      insertControlRequest(connection, { ...identity, method: 'authorization.create', requestId: request.requestId,
        requestDigest: request.requestDigest, responseRef: published.ref, committedAt: now }); committed = true;
    });
    requireHealthyFence(outcome);
    if (committed) return immutableSnapshot({ replayed: false, response });
    diagnosis?.stage('replay');
    const raced = await replay(); if (raced) return raced;
    throw new KernelStorageError('REVISION_CONFLICT', 'authorization creation lost its transaction cut');
  } catch (error) {
    diagnosis?.failure(error);
    throw error;
  }
});
export const revokeAuthorization = stateOperation('INVALID_REQUEST', async (driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, runtime: AuthorizationRuntime | undefined, value: unknown, identity: AuthenticatedControlIdentity, signal?: AbortSignal) => {
  signal?.throwIfAborted();
  const request = immutableSnapshot(decodeAuthorizationRevokeRequest(value));
  const channel = await validateControlChannelClosure(artifacts, owner, identity);
  const replay = readControlRequest(driver, identity.principalId, 'authorization.revoke', request.requestId);
  if (replay && replay.requestDigest !== request.requestDigest)
    throw new KernelStorageError('REQUEST_ID_CONFLICT', 'authorization revoke id names other bytes');
  const prior = readAuthorizationGrant(driver, request.grantId);
  if (!prior || prior.ownerPrincipalId !== identity.principalId) throw new KernelStorageError('NOT_FOUND', 'authorization does not belong to this principal');
  if (!runtime) throw new KernelStorageError('RECOVERY_REQUIRED', 'authorization revocation has no release roots');
  const history = await readAnyAuthorizationHistory(driver, artifacts, owner, prior, runtime.releaseKeys, signal);
  if (replay) {
    return immutableSnapshot({ replayed: true, response: await verifyRevokeResponse(driver, artifacts, owner, prior, request.requestId, history.committedAt) });
  }
  // Revocation keeps this original decision time; its control row records the
  // actual later commit. An expired active grant may still be restricted.
  const createdAt = sampleCanonicalNow();
  const priorCommittedAt = prior.state === 'revoked'
    ? readControlRequest(driver, prior.ownerPrincipalId, 'authorization.revoke', prior.revokedByRequestId)!.committedAt
    : prior.state === 'consumed' ? prior.consumedAt : history.committedAt;
  let next = prior;
  if (prior.state === 'active') {
    next = { ...authorizationGrantCore(prior), rowVersion: 2, grantCoreDigest: prior.grantCoreDigest, state: 'revoked', useCount: 0,
      revokedByRequestId: request.requestId, revokedAt: createdAt, rowDigest: '' };
    next.rowDigest = digestOmitting(next, 'rowDigest');
  }
  const response: AuthorizationResponse = { protocolVersion: 1, ok: true, result: { method: 'authorization.revoke',
    disposition: prior.state === 'active' ? 'revoked' : prior.state === 'consumed' ? 'already_consumed' : 'already_revoked', grant: authorizationSummary(next) } };
  const { requestDigest: _digest, ...core } = request;
  const requestArtifact = await artifacts.publishCanonical(core, 'cliq-authorization-revoke-request-v1');
  const published = await artifacts.publishCanonical(response, 'cliq-control-response-v1');
  await validateControlChannelClosure(artifacts, owner, identity);
  let outcome: ReturnType<typeof advanceTimeFence> | undefined, committed = false;
  driver.transaction((connection: SqliteConnection) => {
    signal?.throwIfAborted();
    const currentOwner = assertActiveStateOwner(connection, owner);
    if (channel.channel.transport.kind === 'uds_peer') assertCurrentControlFrame(owner, identity);
    if (readControlRequest(connection, identity.principalId, 'authorization.revoke', request.requestId)) return;
    if (!same(readAuthorizationGrant(connection, prior.grantId), prior)) throw new KernelStorageError('REVISION_CONFLICT', 'authorization changed before revocation');
    const now = sampleCanonicalNow();
    outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
    if (now < createdAt || createdAt < history.committedAt || createdAt < priorCommittedAt || currentOwner.acquiredAt > createdAt ||
        channel.channel.openedAt > createdAt) throw new TypeError('authorization revocation is noncausal');
    for (const metadata of [...channel.metadata, requestArtifact, published]) insertArtifactMetadata(connection, metadata, now);
    if (prior.state === 'active') consumeOrRevokeAuthorization(connection, prior, next);
    insertControlRequest(connection, { ...identity, method: 'authorization.revoke', requestId: request.requestId,
      requestDigest: request.requestDigest, responseRef: published.ref, committedAt: now });
    committed = true;
  });
  requireHealthyFence(outcome);
  if (committed) return immutableSnapshot({ replayed: false, response });
  const raced = readControlRequest(driver, identity.principalId, 'authorization.revoke', request.requestId);
  if (!raced || raced.requestDigest !== request.requestDigest)
    throw new KernelStorageError('REQUEST_ID_CONFLICT', 'authorization revoke raced another request');
  const current = readAuthorizationGrant(driver, request.grantId);
  if (!current) throw new KernelStorageError('RECOVERY_REQUIRED', 'authorization revoke replay lost its immutable grant');
  return immutableSnapshot({ replayed: true, response: await verifyRevokeResponse(driver, artifacts, owner, current, request.requestId, history.committedAt) });
});
