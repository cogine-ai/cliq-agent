import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { AuthorizationGrantV1, AuthorizationResponse } from '../kernel/authorization.js';
import { addCanonicalDuration, digestOmitting } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { authorizationGrantCore, authorizationGrantId, authorizationSummary, decodeAuthorizationConsumptionReceipt,
  decodeAuthorizationRevokeRequest, decodeVerifierIdentityCreateRequest, VerifierAuthorizationError } from './authorization-artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { readRetainedControlChannelClosure, validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { assertCurrentControlFrame } from './control-channel.js';
import { KernelStorageError, stateOperation } from './errors.js';
import { readRetainedVerifierToolchain } from './guest-toolchain.js';
import { readAuthorizationGrant, insertAuthorizationGrant, consumeOrRevokeAuthorization } from './repositories/authorization-grants.js';
import { readControlRequest, insertControlRequest, readRun } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readStateOwner, type StateOwnerContext } from './state-owner.js';
import { requireHealthyFence } from './reducers/invocation.js';
import { decodeRunSpec, decodeVerifierSpec } from './decoders.js';
import { beginInstalledAuthorizationDiagnostic } from './installed-run-diagnostics.js';

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
/** Historical audit only; it cannot authenticate input or reopen an executable. */
export async function readAuthorizationHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  grant: AuthorizationGrantV1, releaseKeys: readonly ReleaseTrustKey[], signal?: AbortSignal) {
  signal?.throwIfAborted();
  const row = readControlRequest(driver, grant.ownerPrincipalId, 'authorization.create', grant.sourceRequestId);
  const { channel } = await readRetainedControlChannelClosure(artifacts, owner, { principalId: grant.ownerPrincipalId,
    channelIdentityRef: grant.channelIdentityRef, channelIdentityDigest: grant.channelIdentityDigest });
  const core = await readCanonicalArtifact<Record<string, unknown>>(artifacts, grant.sourceRequestDigest);
  const request = decodeVerifierIdentityCreateRequest({ ...core, requestDigest: grant.sourceRequestDigest });
  if (!row || request.requestId !== grant.sourceRequestId || row.requestDigest !== grant.sourceRequestDigest || row.channelIdentityRef !== grant.channelIdentityRef ||
      row.channelIdentityDigest !== grant.channelIdentityDigest || row.committedAt !== grant.createdAt || channel.openedAt > grant.createdAt ||
      grant.expiresAt !== addCanonicalDuration(grant.createdAt, request.ttlMs ?? 3_600_000) ||
      !same(await readCanonicalArtifact(artifacts, row.responseRef), createResponse(grant)))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'authorization has no exact original authenticated creation');
  const target = grant.target;
  if (target.kind !== 'execution_identity_read' || target.purpose !== 'verifier' || target.identity.kind !== 'guest_toolchain' ||
      target.identity.toolId !== request.decision.target.toolId) throw new TypeError('authorization target differs from its original decision');
  const executionIdentity = target.identity;
  // The creating owner and its selected signed bundle remain historical
  // authority after upgrade. Do not resolve an old public id against today.
  const ownerRows = driver.prepare('SELECT owner_epoch FROM state_owners ORDER BY owner_epoch').all<{ owner_epoch: bigint }>();
  let originalBundle: RuntimeBundleManifest | undefined;
  for (const { owner_epoch } of ownerRows) {
    const historical = readStateOwner(driver, Number(owner_epoch));
    if (!historical || historical.acquiredAt > grant.createdAt || (historical.state === 'terminal' && historical.releasedAt < grant.createdAt)) continue;
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
        receipt.targetDigest !== grant.targetDigest || receipt.consumedAt !== grant.consumedAt)
      throw new TypeError('authorization consumption does not match its immutable receipt');
    const run = readRun(driver, receipt.consumer.runId);
    const admission = driver.prepare('SELECT principal_id, admission_intent_digest FROM runs WHERE id = ?')
      .get<{ principal_id: string; admission_intent_digest: string }>(run.id);
    if (!admission || admission.principal_id !== grant.ownerPrincipalId || admission.admission_intent_digest !== receipt.consumer.admissionIntentDigest ||
        run.createdAt !== receipt.consumedAt) throw new TypeError('authorization receipt has no matching original Run admission');
  }
  if (grant.state === 'revoked') {
    const revoked = readControlRequest(driver, grant.ownerPrincipalId, 'authorization.revoke', grant.revokedByRequestId);
    if (!revoked || revoked.committedAt !== grant.revokedAt) throw new TypeError('revoked authorization has no original revoke request');
    await verifyRevokeResponse(driver, artifacts, owner, grant, grant.revokedByRequestId);
  }
  return { request, selected };
}
async function verifyRevokeResponse(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  grant: AuthorizationGrantV1, requestId: string) {
  const row = readControlRequest(driver, grant.ownerPrincipalId, 'authorization.revoke', requestId);
  if (!row) throw new TypeError('authorization revoke response has no owner');
  const core = await readCanonicalArtifact<Record<string, unknown>>(artifacts, row.requestDigest);
  const request = decodeAuthorizationRevokeRequest({ ...core, requestDigest: row.requestDigest });
  const { channel } = await readRetainedControlChannelClosure(artifacts, owner, { principalId: grant.ownerPrincipalId,
    channelIdentityRef: row.channelIdentityRef, channelIdentityDigest: row.channelIdentityDigest });
  const response = await readCanonicalArtifact<AuthorizationResponse>(artifacts, row.responseRef);
  const expected: AuthorizationResponse = { protocolVersion: 1, ok: true, result: { method: 'authorization.revoke',
    grant: authorizationSummary(grant), disposition: grant.state === 'consumed' ? 'already_consumed' : grant.state === 'revoked' &&
      grant.revokedByRequestId === requestId ? 'revoked' : 'already_revoked' } };
  if (channel.openedAt > row.committedAt || request.grantId !== grant.grantId || request.requestId !== requestId ||
      !same(response, expected) || row.committedAt < grant.createdAt ||
      (grant.state === 'consumed' && row.committedAt < grant.consumedAt)) throw new TypeError('authorization revoke response differs from its exact historical outcome');
  return response;
}
export async function validateAuthorizationHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime?: AuthorizationRuntime): Promise<void> {
  const consumedRuns = new Set<string>();
  for (const row of driver.prepare('SELECT grant_id FROM authorization_grants ORDER BY grant_id').all<{ grant_id: string }>()) {
    if (!runtime) throw new KernelStorageError('RECOVERY_REQUIRED', 'authorization history requires its signed runtime trust roots');
    const grant = readAuthorizationGrant(driver, row.grant_id)!;
    try { await readAuthorizationHistory(driver, artifacts, owner, grant, runtime.releaseKeys); }
    catch (cause) { throw new KernelStorageError('RECOVERY_REQUIRED', 'authorization history is not closed', { cause }); }
    if (grant.state === 'consumed') {
      const receipt = decodeAuthorizationConsumptionReceipt(await readCanonicalArtifact(artifacts, grant.consumptionReceiptRef));
      if (receipt.consumer.kind === 'run_admission') consumedRuns.add(receipt.consumer.runId);
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
    const request = immutableSnapshot(decodeVerifierIdentityCreateRequest(value));
    diagnosis?.stage('current_channel');
    const channel = await validateControlChannelClosure(artifacts, owner, identity);
    const replay = async () => {
      const existing = readControlRequest(driver, identity.principalId, 'authorization.create', request.requestId);
      if (!existing) return undefined;
      if (existing.requestDigest !== request.requestDigest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'authorization request id names other bytes');
      const grant = readAuthorizationGrant(driver, authorizationGrantId(identity.principalId, request.requestId, request.requestDigest));
      if (!grant || !runtime) throw new KernelStorageError('RECOVERY_REQUIRED', 'authorization replay has no original grant');
      await readAuthorizationHistory(driver, artifacts, owner, grant, runtime.releaseKeys, signal);
      return immutableSnapshot({ replayed: true, response: createResponse(grant) });
    };
    diagnosis?.stage('replay');
    const retained = await replay(); if (retained) return retained;
    if (!runtime || !runtime.bundle.structuredArtifacts.some(root => root.kind === 'guest_toolchain' && root.artifactId === request.decision.target.guestToolchainManifestId))
      throw new VerifierAuthorizationError('UNSUPPORTED_EXECUTION_IDENTITY');
    const active = assertActiveStateOwner(driver, owner);
    if (active.runtimeBundleRef !== canonicalSha256(runtime.bundle) || active.runtimeBundleManifestDigest !== runtime.bundle.manifestDigest)
      throw new TypeError('authorization runtime differs from the current signed StateOwner');
    diagnosis?.stage('selected_toolchain');
    const selected = await readRetainedVerifierToolchain(artifacts, { ...runtime, guestToolchainManifestId: request.decision.target.guestToolchainManifestId, signal });
    signal?.throwIfAborted();
    const node = selected.manifest.node;
    if (node.logicalName !== request.decision.target.toolId) throw new VerifierAuthorizationError('UNSUPPORTED_EXECUTION_IDENTITY');
    const target = { kind: 'execution_identity_read' as const, purpose: 'verifier' as const, identity: { kind: 'guest_toolchain' as const,
      guestToolchainManifestRef: selected.manifestRef, manifestDigest: selected.manifest.manifestDigest,
      toolId: node.logicalName, executionPath: node.canonicalGuestPath, executableDigest: node.digest } };
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
      assertActiveStateOwner(connection, owner);
      if (channel.channel.transport.kind === 'uds_peer') assertCurrentControlFrame(owner, identity);
      if (readControlRequest(connection, identity.principalId, 'authorization.create', request.requestId)) return;
      const now = sampleCanonicalNow(), fence = readTimeFence(connection);
      if (!fence) throw new KernelStorageError('RECOVERY_REQUIRED', 'authorization time fence is missing');
      if (now >= createdAt && fence.state === 'healthy' && fence.lastAcceptedAt > createdAt)
        throw new KernelStorageError('REVISION_CONFLICT', 'authorization creation timestamp lost its exact control cut');
      outcome = advanceTimeFence(connection, owner.ownerEpoch, now < createdAt ? now : createdAt);
      if (outcome !== 'healthy') return;
      if (now < createdAt || now >= grant.expiresAt || channel.channel.openedAt > createdAt) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
      for (const metadata of [...channel.metadata, requestArtifact, published]) insertArtifactMetadata(connection, metadata, createdAt);
      insertAuthorizationGrant(connection, grant);
      insertControlRequest(connection, { ...identity, method: 'authorization.create', requestId: request.requestId,
        requestDigest: request.requestDigest, responseRef: published.ref, committedAt: createdAt }); committed = true;
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
  await readAuthorizationHistory(driver, artifacts, owner, prior, runtime.releaseKeys, signal);
  if (replay) {
    return immutableSnapshot({ replayed: true, response: await verifyRevokeResponse(driver, artifacts, owner, prior, request.requestId) });
  }
  const createdAt = sampleCanonicalNow();
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
    assertActiveStateOwner(connection, owner);
    if (channel.channel.transport.kind === 'uds_peer') assertCurrentControlFrame(owner, identity);
    if (readControlRequest(connection, identity.principalId, 'authorization.revoke', request.requestId)) return;
    if (!same(readAuthorizationGrant(connection, prior.grantId), prior)) throw new KernelStorageError('REVISION_CONFLICT', 'authorization changed before revocation');
    const now = sampleCanonicalNow(), fence = readTimeFence(connection);
    if (!fence) throw new KernelStorageError('RECOVERY_REQUIRED', 'authorization time fence is missing');
    if (now >= createdAt && fence.state === 'healthy' && fence.lastAcceptedAt > createdAt)
      throw new KernelStorageError('REVISION_CONFLICT', 'authorization revocation timestamp lost its exact control cut');
    outcome = advanceTimeFence(connection, owner.ownerEpoch, now < createdAt ? now : createdAt); if (outcome !== 'healthy') return;
    if (now < createdAt || createdAt < prior.createdAt || channel.channel.openedAt > createdAt) throw new TypeError('authorization revocation is noncausal');
    for (const metadata of [...channel.metadata, requestArtifact, published]) insertArtifactMetadata(connection, metadata, createdAt);
    if (prior.state === 'active') consumeOrRevokeAuthorization(connection, prior, next);
    insertControlRequest(connection, { ...identity, method: 'authorization.revoke', requestId: request.requestId,
      requestDigest: request.requestDigest, responseRef: published.ref, committedAt: createdAt });
    committed = true;
  });
  requireHealthyFence(outcome);
  if (committed) return immutableSnapshot({ replayed: false, response });
  const raced = readControlRequest(driver, identity.principalId, 'authorization.revoke', request.requestId);
  if (!raced || raced.requestDigest !== request.requestDigest)
    throw new KernelStorageError('REQUEST_ID_CONFLICT', 'authorization revoke raced another request');
  const current = readAuthorizationGrant(driver, request.grantId);
  if (!current) throw new KernelStorageError('RECOVERY_REQUIRED', 'authorization revoke replay lost its immutable grant');
  return immutableSnapshot({ replayed: true, response: await verifyRevokeResponse(driver, artifacts, owner, current, request.requestId) });
});
