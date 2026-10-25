import { canonicalSha256 } from '../kernel/canonical.js';
import { normalizeRunSubmitRequest as decodeRunSubmitRequest, InvalidRunSubmitRequestError } from '../kernel/control-submit.js';
import type { NormalizedRunSubmitRequest } from '../kernel/control-submit.js';
import { normalizeRunApplyRequest, runApplyIntentDigest, type NormalizedRunApplyRequest } from '../kernel/control-apply.js';
import type { SandboxProfileV1, SourceInspectionTarget, SourceInspectionTargetV1 } from '../kernel/execution.js';
import { assertArtifactRef, digestOmitting, identityHash, normalizeBoundedText } from '../kernel/identity.js';
import type { SourceInspectionAttemptV1 } from '../kernel/execution.js';
import type { WorkspaceIdentityV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';
import { assertCurrentControlFrame, validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { decodeFrozenIgnoreRules, decodeSourceProjection, decodeWorkspaceIdentity } from './decoders.js';
import { assertVerifiedDeliverySource, readRetainedVerifiedDeliverySource, type VerifiedDeliverySource } from './delivery-source-authority.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { withHeldInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath, type HeldWorkspaceRoot } from './native-owner.js';
import { readAdmissionReplay, readSession, readSessionPrincipalId } from './rows.js';
import { readSourceInspectionAttempt } from './source-inspection.js';
import { assertWorkspaceSourceTrust, type HeldWorkspaceSourceTrust } from './source-trust.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { hostPlatform, recaptureLiveWorkspaceIdentity } from './workspace-identity.js';
import { assertSupportedVerifierRequests, readVerifierRequestIdentities } from './verifier-admission.js';
import { prepareSourceGitConsent, sourceGitConsentData, type PreparedSourceGitConsent } from './source-git-consent.js';
import { decodeAuthorizationConsumptionReceipt, VerifierAuthorizationError } from './authorization-artifacts.js';
import { readFrozenIgnoreRules } from '../workspace/frozen-ignore.js';

function invalid(message: string): never { throw new KernelStorageError('INVALID_REQUEST', message); }
function object(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid('inline member must be a plain object');
  const result = value as Record<string, unknown>;
  if (required.some(key => !Object.hasOwn(result, key)) ||
      Object.keys(result).some(key => !required.includes(key) && !optional.includes(key))) invalid('inline object has unknown or missing fields');
  if (Object.values(result).some(member => member === undefined)) invalid('inline object cannot contain undefined');
  return result;
}
function text(value: unknown, maximum = 128, minimum = 1): string {
  if (typeof value !== 'string') invalid('inline text must be a string');
  return normalizeBoundedText(value, minimum, maximum);
}
export function normalizeRunSubmitRequest(value: unknown): ReturnType<typeof decodeRunSubmitRequest> {
  try { return decodeRunSubmitRequest(value); }
  catch (cause) {
    if (cause instanceof InvalidRunSubmitRequestError) throw new KernelStorageError('INVALID_REQUEST', cause.message, { cause });
    throw cause;
  }
}
export function runSubmitIntentDigest(principalId: string, request: NormalizedRunSubmitRequest): string {
  const { protocolVersion: _version, requestId: _id, requestDigest: _digest, admissionKey: _key, ...intent } = request;
  return canonicalSha256({ principalId, method: 'run.submit', request: intent });
}
export type NormalizedSourceRequest = NormalizedRunSubmitRequest | NormalizedRunApplyRequest;
/** The original wire request remains distinct from this Supervisor-resolved
 * capture selection. These fields are never accepted from run.apply callers. */
export type SourceCaptureSelection = Pick<NormalizedRunSubmitRequest, 'sessionId' | 'expectedContextRevision' | 'workspacePath' |
  'sourceIncludes' | 'sourceExcludes' | 'maxChangedPaths' | 'maxChangedBytes' | 'sandboxResources' | 'sourceInspectionGrantId' | 'ignoreReadGrantIds'> & {
    method: 'run.submit' | 'run.apply'; requestId: string; requestDigest: string; admissionKey: string;
    budgets: { wallTimeMs: number };
    frozenProjection?: { sourceProjectionRef: string; frozenIgnoreRulesRef: string; admittedSourceRef: string };
  };
export function normalizeSourceInspectionRequest(value: unknown) {
  return value && typeof value === 'object' && Object.getOwnPropertyDescriptor(value, 'method')?.value === 'run.apply'
    ? normalizeRunApplyRequest(value) : normalizeRunSubmitRequest(value);
}
export function sourceInspectionIntentDigest(principalId: string, request: NormalizedSourceRequest): string {
  return request.method === 'run.apply' ? runApplyIntentDigest(principalId, request) : runSubmitIntentDigest(principalId, request);
}
export async function resolveDeliverySourceCapture(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  request: NormalizedRunApplyRequest, principalId: string, selected: VerifiedDeliverySource, signal?: AbortSignal): Promise<SourceCaptureSelection> {
  const source = assertVerifiedDeliverySource(driver, owner, selected);
  if (source.run.id !== request.sourceRunId || source.run.resultRef !== request.expectedRunResultRef ||
      readSessionPrincipalId(driver, source.session.id) !== principalId) invalid('delivery source does not match its original request');
  const session = readSession(driver, source.session.id);
  if (session.workspaceIdentityRef !== source.session.workspaceIdentityRef) invalid('delivery source Session identity changed');
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, session.workspaceIdentityRef));
  const projection = decodeSourceProjection(await readCanonicalArtifact(artifacts, source.spec.sourceProjectionRef));
  const rules = decodeFrozenIgnoreRules(await readCanonicalArtifact(artifacts, projection.frozenIgnoreRulesRef));
  const profile = decodeSandboxProfile(await readCanonicalArtifact(artifacts, source.spec.sandboxProfileRef));
  signal?.throwIfAborted();
  if (workspace.kind !== 'live' || workspace.ownerPrincipalId !== principalId) invalid('delivery requires its original live Session identity');
  // An old consumed admission read grant cannot authorize a new live capture.
  // Only the connected ordinary builtin projection is currently implemented.
  if (projection.explicitIncludes.length || projection.frozenIgnoreRulesDigest !== rules.rulesDigest)
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'delivery capture of granted/ignored source is not implemented');
  if (source.spec.dependencyPolicyRef !== undefined || request.verifierExecutionGrantIds.length)
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'delivery dependency/template admission is not implemented');
  return immutableSnapshot({ method: 'run.apply', requestId: request.requestId, requestDigest: request.requestDigest,
    admissionKey: request.admissionKey, budgets: request.budgets, sessionId: session.id, expectedContextRevision: session.contextRevision,
    workspacePath: workspace.canonicalRootPath, sourceIncludes: [], sourceExcludes: projection.explicitExcludes,
    maxChangedPaths: projection.maxChangedPaths, maxChangedBytes: projection.maxChangedBytes, sandboxResources: profile.resources,
    ...(request.sourceInspectionGrantId === undefined ? {} : { sourceInspectionGrantId: request.sourceInspectionGrantId }),
    ...(request.ignoreReadGrantIds === undefined ? {} : { ignoreReadGrantIds: request.ignoreReadGrantIds }),
    frozenProjection: { sourceProjectionRef: source.spec.sourceProjectionRef, frozenIgnoreRulesRef: projection.frozenIgnoreRulesRef,
      admittedSourceRef: source.spec.baseWorkspaceManifestRef } });
}

/** Only trusted Supervisor composition selects this policy and release root.
 * The profile is generated admission policy, not a signed root image or a
 * platform-qualification claim. Its selected runtime is nevertheless signed. */
export type SourceInspectionBootstrap = Readonly<{
  bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[]; sandboxProfile: SandboxProfileV1;
}>;
export type VerifiedSourceInspectionTarget = Readonly<{ kind: 'verified_source_inspection_target' }>;
type TargetBinding = {
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext;
  workspaceRoot: HeldWorkspaceRoot; trust: HeldWorkspaceSourceTrust; identity: AuthenticatedControlIdentity;
  frameIdentity?: AuthenticatedControlIdentity;
  request: SourceCaptureSelection; originalRequest: object; target: SourceInspectionTarget;
  targetRef: string; inspectionId: string; workspace: Extract<WorkspaceIdentityV1, { kind: 'live' }>;
  metadata: readonly PublishedArtifact[];
  inspectionConsent?: PreparedSourceGitConsent;
};
const verifiedTargets = new WeakMap<VerifiedSourceInspectionTarget, TargetBinding>();

function binding(owner: StateOwnerContext, target: VerifiedSourceInspectionTarget): TargetBinding {
  const held = verifiedTargets.get(target);
  if (!held || held.owner !== owner) throw new KernelStorageError('ARTIFACT_MISMATCH', 'source target has no matching trusted producer');
  return held;
}
function assertPhysicalTarget(held: TargetBinding): void {
  assertHeldWorkspaceRoot(held.workspaceRoot);
  if (heldWorkspaceRootPath(held.workspaceRoot) !== held.request.workspacePath ||
      canonicalSha256(held.workspaceRoot.identity) !== canonicalSha256(held.workspace.rootIdentity) ||
      (held.workspaceRoot.repositoryDirectory === undefined) !== (held.workspace.repositoryIdentityRef === undefined))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'live source workspace no longer matches the exact Session identity');
  assertWorkspaceSourceTrust(held.trust, held.request.workspacePath);
}
/** Called again inside the reservation transaction; this is an exact metadata
 * cut check, not a replacement for the async active-channel recheck. */
export function assertVerifiedSourceInspectionTargetCut(connection: SqliteConnection | SqliteDriver,
  owner: StateOwnerContext, target: VerifiedSourceInspectionTarget): void {
  const held = binding(owner, target);
  assertActiveStateOwner(connection, owner); assertPhysicalTarget(held);
  if (held.frameIdentity) assertCurrentControlFrame(owner, held.frameIdentity);
  const session = readSession(connection, held.request.sessionId);
  if (readSessionPrincipalId(connection, session.id) !== held.identity.principalId) throw new KernelStorageError('NOT_FOUND', 'Session does not belong to this principal');
  if (session.contextRevision !== held.request.expectedContextRevision) throw new KernelStorageError('REVISION_CONFLICT', 'Session context changed before source capture');
  if (session.workspaceIdentityRef !== held.target.workspaceIdentityRef) throw new KernelStorageError('ARTIFACT_MISMATCH', 'Session workspace identity changed before source capture');
}
/** Trusted internal capture/storage consumers retain the actual descriptors;
 * a serialized target ref or a structural lookalike cannot mint read scope. */
export function readVerifiedSourceInspectionTarget(owner: StateOwnerContext, target: VerifiedSourceInspectionTarget) {
  const held = binding(owner, target); assertActiveStateOwner(held.driver, owner); assertPhysicalTarget(held);
  return Object.freeze({ request: held.request, originalRequest: held.originalRequest, target: held.target,
    targetRef: held.targetRef, inspectionId: held.inspectionId, workspace: held.workspace,
    workspaceRoot: held.workspaceRoot, metadata: held.metadata, inspectionConsent: held.inspectionConsent });
}
export async function recheckVerifiedSourceInspectionTarget(owner: StateOwnerContext,
  target: VerifiedSourceInspectionTarget): Promise<void> {
  const held = binding(owner, target);
  await validateControlChannelClosure(held.artifacts, owner, held.identity);
  assertVerifiedSourceInspectionTargetCut(held.driver, owner, target);
}

/** Freezes the complete inline intent only after real authentication, Trust,
 * exact Session ownership and live descriptor identity. Caller-provided paths,
 * refs, authorization booleans and structural native handles grant nothing. */
export async function createVerifiedSourceInspectionTarget(context: {
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; bootstrap: SourceInspectionBootstrap;
  workspaceRoot: HeldWorkspaceRoot; trust: HeldWorkspaceSourceTrust;
  selectedRuntime?: HeldInstalledRuntime;
  signal?: AbortSignal;
}, inlineRequest: unknown, identity: AuthenticatedControlIdentity,
deliverySource?: VerifiedDeliverySource): Promise<VerifiedSourceInspectionTarget> {
  const normalized = normalizeSourceInspectionRequest(inlineRequest), wire = normalized.request;
  const frameIdentity = identity;
  identity = immutableSnapshot(identity);
  const bootstrap = immutableSnapshot(context.bootstrap), { driver, artifacts, owner, workspaceRoot, trust } = context;
  const reads = context.signal ? artifacts.withReadSignal(context.signal) : artifacts;
  const request: SourceCaptureSelection = wire.method === 'run.apply'
    ? await resolveDeliverySourceCapture(driver, reads, owner, wire, identity.principalId,
      assertVerifiedDeliverySource(driver, owner, deliverySource), context.signal) : wire;
  const admissionIntentDigest = sourceInspectionIntentDigest(identity.principalId, wire);
  // Any retained attempt/Run is handled by the caller's replay path. Never
  // reopen/capture a mutable source to reconstruct a historical result.
  const key = { principalId: identity.principalId, method: wire.method, admissionKey: request.admissionKey, admissionIntentDigest };
  const existing = readSourceInspectionAttempt(driver, key);
  const admitted = readAdmissionReplay(driver, 'runs', identity.principalId, wire.method, request.admissionKey);
  if (admitted && admitted.admissionIntentDigest !== admissionIntentDigest) throw new KernelStorageError('ADMISSION_KEY_CONFLICT', 'source key names a different intent');
  if (existing || admitted) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'source intent is retained; join or replay it without recapture');
  const channel = await validateControlChannelClosure(reads, owner, identity);
  const active = assertActiveStateOwner(driver, owner);
  const session = readSession(driver, request.sessionId);
  if (readSessionPrincipalId(driver, session.id) !== identity.principalId) throw new KernelStorageError('NOT_FOUND', 'Session does not belong to this principal');
  if (session.contextRevision !== request.expectedContextRevision) throw new KernelStorageError('REVISION_CONFLICT', 'Session context changed before source capture');
  assertHeldWorkspaceRoot(workspaceRoot);
  if (heldWorkspaceRootPath(workspaceRoot) !== request.workspacePath) throw new KernelStorageError('ARTIFACT_MISMATCH', 'held workspace path differs from inline request');
  assertWorkspaceSourceTrust(trust, request.workspacePath);
  if (request.sourceIncludes.some(include => include.readGrantId !== undefined)) invalid('source read grants are not implemented; ignored bytes cannot be captured');
  if (wire.method === 'run.submit') {
    if (wire.dependency.mode !== 'none') invalid('dependency admission is not yet implemented');
    assertSupportedVerifierRequests(wire.verifiers, wire.policyMode);
    if (wire.verifiers.length) await readVerifierRequestIdentities(driver, reads, owner, bootstrap, identity.principalId, wire.verifiers, undefined, context.signal);
    if (wire.registeredMcpServerIds.length || wire.skillIds.length) invalid('MCP/skill admission authority is not yet implemented');
  }
  if (wire.method === 'run.submit' && wire.model.provider !== 'ollama') {
    if (!context.selectedRuntime || wire.model.provider !== 'openai-compatible')
      invalid('remote model admission requires the genuine installed fixed broker recipe');
    await withHeldInstalledRuntime(context.selectedRuntime, async installed => {
      await installed.revalidate(context.signal);
      if (installed.bundleDigest !== canonicalSha256(bootstrap.bundle) ||
          !installed.modelAuthority?.models.some(model => model.catalog.value.provider === wire.model.provider &&
            model.catalog.value.model === wire.model.model && model.catalog.value.adapter.adapterId === 'openai-compatible-broker-v1' &&
            model.catalog.value.adapter.version === '1')) invalid('remote model source capture lacks the selected signed model authority');
      await installed.revalidate(context.signal);
    }, context.signal);
  }
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(reads, session.workspaceIdentityRef));
  if (workspace.kind !== 'live' || workspace.ownerPrincipalId !== identity.principalId || workspace.platform !== hostPlatform() ||
      workspace.canonicalRootPath !== request.workspacePath || canonicalSha256(workspace.rootIdentity) !== canonicalSha256(workspaceRoot.identity) ||
      (workspace.repositoryIdentityRef === undefined) !== (workspaceRoot.repositoryDirectory === undefined))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'live workspace does not match the exact Session identity');
  if (workspace.repositoryIdentityRef !== undefined) await recaptureLiveWorkspaceIdentity(workspace, request.workspacePath, context.selectedRuntime);
  verifyRuntimeBundle(bootstrap.bundle, bootstrap.releaseKeys);
  const runtimeBundleRef = canonicalSha256(bootstrap.bundle);
  if (active.runtimeBundleRef !== runtimeBundleRef || active.runtimeBundleManifestDigest !== bootstrap.bundle.manifestDigest ||
      canonicalSha256(await readCanonicalArtifact(reads, runtimeBundleRef)) !== runtimeBundleRef)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source inspection runtime differs from the signed StateOwner bootstrap');
  const profile = decodeSandboxProfile(bootstrap.sandboxProfile);
  if (!profile.allowedOwners.includes('source_inspection') || canonicalSha256(profile.resources) !== canonicalSha256(request.sandboxResources))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'trusted source inspection profile differs from the requested frozen resources');
  const inspectionId = identityHash('cliq-source-inspection-v1', identity.principalId, wire.method, request.admissionKey, admissionIntentDigest);
  let inspectionConsent: PreparedSourceGitConsent | undefined;
  if (workspace.repositoryIdentityRef !== undefined) {
    if (!request.sourceInspectionGrantId || !workspace.repositoryIdentityDigest) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    inspectionConsent = await prepareSourceGitConsent(driver, reads, owner, bootstrap, request.sourceInspectionGrantId, {
      principalId: identity.principalId, sessionId: session.id, workspaceIdentityRef: session.workspaceIdentityRef,
      workspaceIdentityDigest: workspace.identityDigest, repositoryIdentityRef: workspace.repositoryIdentityRef,
      repositoryIdentityDigest: workspace.repositoryIdentityDigest, inspectionId, admissionIntentDigest, resources: profile.resources
    }, context.signal, request.ignoreReadGrantIds);
  } else if (request.sourceInspectionGrantId !== undefined || request.ignoreReadGrantIds?.length)
    invalid('non-Git capture cannot consume Git inspection or ignore-rule grants');
  // Composition refs alone are not durable data or target authority. All three
  // actual publications join before the original physical/SQL target recheck.
  const originalRef = canonicalSha256(normalized.originalRequest), selectedProfileRef = canonicalSha256(profile);
  const base: SourceInspectionTargetV1 = { schemaVersion: 1, format: 'cliq-source-inspection-target-v1', principalId: identity.principalId,
    method: wire.method, admissionKey: request.admissionKey, admissionIntentDigest,
    originalRequestRef: originalRef, originalRequestDigest: normalized.originalRequestDigest,
    sessionId: request.sessionId, expectedContextRevision: request.expectedContextRevision,
    workspaceIdentityRef: session.workspaceIdentityRef, workspaceIdentityDigest: workspace.identityDigest, sourceReadGrantRefs: [],
    runtimeBundleRef, runtimeBundleManifestDigest: bootstrap.bundle.manifestDigest,
    sandboxProfileRef: selectedProfileRef, sandboxProfileDigest: profile.profileDigest, targetDigest: '' };
  const consent = inspectionConsent && sourceGitConsentData(owner, inspectionConsent);
  const target: SourceInspectionTarget = consent ? { ...base, schemaVersion: 2, format: 'cliq-source-inspection-target-v2',
    inspectionGrantId: consent.grantId, inspectionReceiptRef: consent.receiptRef, inspectionReceiptDigest: consent.receiptDigest,
    ignoreReadConsents: consent.ignoreReadConsents } : base;
  target.targetDigest = digestOmitting(target, 'targetDigest');
  const [original, selectedProfile, published] = await artifacts.publishCanonicalTriple([
    { value: normalized.originalRequest, schemaKind: 'cliq-control-request-v1' },
    { value: profile, schemaKind: profile.format }, { value: target, schemaKind: target.format }
  ]);
  const result: VerifiedSourceInspectionTarget = Object.freeze({ kind: 'verified_source_inspection_target' });
  verifiedTargets.set(result, { driver, artifacts, owner, workspaceRoot, trust, identity, request,
    ...(channel.channel.transport.kind === 'uds_peer' ? { frameIdentity } : {}),
    originalRequest: normalized.originalRequest, target: immutableSnapshot(target), targetRef: published.ref,
    inspectionId, inspectionConsent,
    workspace: immutableSnapshot(workspace), metadata: immutableSnapshot([...channel.metadata, original, selectedProfile, published,
      ...(consent ? consent.metadata : [])]) });
  await recheckVerifiedSourceInspectionTarget(owner, result);
  return result;
}

/** Shared retained-data binding, not a native/read capability. Runtime trust
 * and the inherited source are independently checked by its owning reader. */
export async function readSourceInspectionTargetData(artifacts: ArtifactCatalog, attempt: SourceInspectionAttemptV1,
  originalIndex: { originalRequestId: string; originalRequestDigest: string }) {
  try {
    const raw = await readCanonicalArtifact<Record<string, unknown>>(artifacts, attempt.targetRef);
    const git = raw.schemaVersion === 2;
    const targetData = object(raw, ['schemaVersion', 'format', 'principalId', 'method',
      'admissionKey', 'admissionIntentDigest', 'originalRequestRef', 'originalRequestDigest', 'sessionId', 'expectedContextRevision',
      'workspaceIdentityRef', 'workspaceIdentityDigest', 'sourceReadGrantRefs', 'runtimeBundleRef', 'runtimeBundleManifestDigest',
      'sandboxProfileRef', 'sandboxProfileDigest', 'targetDigest',
      ...(git ? ['inspectionGrantId', 'inspectionReceiptRef', 'inspectionReceiptDigest', 'ignoreReadConsents'] : [])]);
    for (const key of ['admissionIntentDigest', 'originalRequestRef', 'originalRequestDigest', 'workspaceIdentityRef',
      'workspaceIdentityDigest', 'runtimeBundleRef', 'runtimeBundleManifestDigest', 'sandboxProfileRef', 'sandboxProfileDigest', 'targetDigest'])
      assertArtifactRef(text(targetData[key], 64));
    if ((git ? targetData.format !== 'cliq-source-inspection-target-v2' : targetData.schemaVersion !== 1 || targetData.format !== 'cliq-source-inspection-target-v1') || targetData.method !== attempt.method ||
        targetData.targetDigest !== digestOmitting(targetData, 'targetDigest') || targetData.targetDigest !== attempt.targetDigest ||
        targetData.principalId !== attempt.principalId || targetData.admissionKey !== attempt.admissionKey ||
        targetData.admissionIntentDigest !== attempt.admissionIntentDigest || targetData.workspaceIdentityDigest !== attempt.workspaceIdentityDigest ||
        !Array.isArray(targetData.sourceReadGrantRefs) || targetData.sourceReadGrantRefs.length !== 0 ||
        typeof targetData.sessionId !== 'string' || normalizeBoundedText(targetData.sessionId, 1, 128) !== targetData.sessionId ||
        !Number.isSafeInteger(targetData.expectedContextRevision) || (targetData.expectedContextRevision as number) < 1)
      invalid('retained target does not bind its original source attempt');
    const original = normalizeSourceInspectionRequest(await readCanonicalArtifact(artifacts, text(targetData.originalRequestRef, 64)));
    if (original.request.requestId !== originalIndex.originalRequestId || original.originalRequestDigest !== originalIndex.originalRequestDigest ||
        original.originalRequestDigest !== targetData.originalRequestDigest || original.request.method !== attempt.method ||
        sourceInspectionIntentDigest(attempt.principalId, original.request) !== attempt.admissionIntentDigest)
      invalid('retained target original request or derived index differs');
    if (git) {
      text(targetData.inspectionGrantId); assertArtifactRef(text(targetData.inspectionReceiptRef, 64)); assertArtifactRef(text(targetData.inspectionReceiptDigest, 64));
      const receipt = decodeAuthorizationConsumptionReceipt(await readCanonicalArtifact(artifacts, targetData.inspectionReceiptRef as string));
      if (original.request.sourceInspectionGrantId !== targetData.inspectionGrantId || receipt.grantId !== targetData.inspectionGrantId ||
          receipt.receiptDigest !== targetData.inspectionReceiptDigest || receipt.ownerPrincipalId !== attempt.principalId ||
          receipt.consumer.kind !== 'source_inspection' || receipt.consumer.inspectionId !== attempt.inspectionId ||
          receipt.consumer.admissionIntentDigest !== attempt.admissionIntentDigest || receipt.consumedAt > attempt.createdAt)
        invalid('retained Git capture target differs from its inspection consumption');
      const ignored = targetData.ignoreReadConsents;
      if (!Array.isArray(ignored) || ignored.length > 128) invalid('retained ignore consent count differs');
      let previous = '';
      for (const item of ignored) {
        const value = object(item, ['grantId', 'receiptRef', 'receiptDigest']);
        const grantId = text(value.grantId); assertArtifactRef(text(value.receiptRef, 64)); assertArtifactRef(text(value.receiptDigest, 64));
        if (grantId <= previous) invalid('retained ignore consents must be unique and sorted'); previous = grantId;
        const readReceipt = decodeAuthorizationConsumptionReceipt(await readCanonicalArtifact(artifacts, value.receiptRef as string));
        if (readReceipt.grantId !== grantId || readReceipt.receiptDigest !== value.receiptDigest || readReceipt.ownerPrincipalId !== attempt.principalId ||
            readReceipt.consumer.kind !== 'source_inspection' || readReceipt.consumer.inspectionId !== attempt.inspectionId ||
            readReceipt.consumer.admissionIntentDigest !== attempt.admissionIntentDigest || readReceipt.consumedAt > attempt.createdAt)
          invalid('retained ignore read differs from its own capture consumption');
      }
      if (canonicalSha256(ignored.map(value => (value as { grantId: string }).grantId)) !== canonicalSha256([...(original.request.ignoreReadGrantIds ?? [])].sort()))
        invalid('retained ignore consent selection differs from the original request');
    } else if (original.request.sourceInspectionGrantId !== undefined || original.request.ignoreReadGrantIds?.length)
      invalid('historical target cannot borrow an inspection or ignore-rule grant');
    return { target: immutableSnapshot(targetData as SourceInspectionTarget), original: original.request };
  } catch (cause) {
    if (cause instanceof ResourceRetirementError) throw cause;
    throw new KernelStorageError('RECOVERY_REQUIRED', 'source inspection retained target is invalid', { cause });
  }
}

/** Retained replay checks bytes and indexes without reopening a live source.
 * This returns no native/read capability and cannot authorize fresh capture. */
export async function readRetainedSourceInspectionTarget(artifacts: ArtifactCatalog, attempt: SourceInspectionAttemptV1,
  originalIndex: { originalRequestId: string; originalRequestDigest: string }, bootstrap: SourceInspectionBootstrap,
  retained?: { driver: SqliteDriver; owner?: StateOwnerContext; signal?: AbortSignal }) {
  try {
    const { target: targetData, original } = await readSourceInspectionTargetData(artifacts, attempt, originalIndex);
    const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, targetData.workspaceIdentityRef));
    if (workspace.kind !== 'live' || workspace.identityDigest !== targetData.workspaceIdentityDigest ||
        workspace.ownerPrincipalId !== attempt.principalId || targetData.schemaVersion === 2 && workspace.repositoryIdentityRef === undefined)
      invalid('retained target workspace differs from its original request');
    if (targetData.schemaVersion === 2) {
      if (!retained?.owner) invalid('Git capture history requires its original retained consent recovery context');
      const { readAuthorizationGrant } = await import('./repositories/authorization-grants.js');
      const { readSourceGitAuthorizationHistory } = await import('./authorization.js');
      const grant = readAuthorizationGrant(retained.driver, targetData.inspectionGrantId);
      if (!grant || grant.state !== 'consumed' || grant.consumptionReceiptRef !== targetData.inspectionReceiptRef)
        invalid('Git capture lost its original consumed inspection consent');
      await readSourceGitAuthorizationHistory(retained.driver, artifacts, retained.owner, grant, bootstrap.releaseKeys, retained.signal);
      const { readSourceReadAuthorizationHistory } = await import('./authorization.js');
      for (const consent of targetData.ignoreReadConsents) {
        const readGrant = readAuthorizationGrant(retained.driver, consent.grantId);
        if (!readGrant || readGrant.state !== 'consumed' || readGrant.consumptionReceiptRef !== consent.receiptRef)
          invalid('ignore-rule capture lost its original consumed read consent');
        await readSourceReadAuthorizationHistory(retained.driver, artifacts, retained.owner, readGrant, bootstrap.releaseKeys, retained.signal);
      }
    }
    const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, text(targetData.runtimeBundleRef, 64));
    verifyRuntimeBundle(bundle, bootstrap.releaseKeys);
    if (bundle.manifestDigest !== targetData.runtimeBundleManifestDigest) invalid('retained target signed runtime differs');
    const profile = decodeSandboxProfile(await readCanonicalArtifact(artifacts, text(targetData.sandboxProfileRef, 64)));
    if (profile.profileDigest !== targetData.sandboxProfileDigest || !profile.allowedOwners.includes('source_inspection'))
      invalid('retained target source profile differs');
    if (original.method === 'run.submit') {
      if (original.sessionId !== targetData.sessionId || original.expectedContextRevision !== targetData.expectedContextRevision ||
          workspace.canonicalRootPath !== original.workspacePath ||
          canonicalSha256(profile.resources) !== canonicalSha256(original.sandboxResources)) invalid('retained submit capture selection differs');
    } else {
      if (!retained) invalid('retained delivery target requires its original source recovery context');
      const source = await readRetainedVerifiedDeliverySource(retained.driver, artifacts, { principalId: attempt.principalId,
        sourceRunId: original.sourceRunId, expectedRunResultRef: original.expectedRunResultRef, signal: retained.signal });
      const projection = decodeSourceProjection(await readCanonicalArtifact(artifacts, source.spec.sourceProjectionRef));
      const rules = await readFrozenIgnoreRules(artifacts, projection.frozenIgnoreRulesRef, workspace.repositoryIdentityDigest, retained.signal);
      if (source.run.sessionId !== targetData.sessionId || source.session.workspaceIdentityRef !== targetData.workspaceIdentityRef ||
          !Number.isSafeInteger(targetData.expectedContextRevision) || (targetData.expectedContextRevision as number) < 1 ||
          (targetData.expectedContextRevision as number) > source.session.contextRevision ||
          source.spec.sandboxProfileRef !== targetData.sandboxProfileRef || source.assembly.runtime.runtimeBundleRef !== targetData.runtimeBundleRef ||
          projection.explicitIncludes.length || projection.frozenIgnoreRulesDigest !== rules.rulesDigest || source.spec.dependencyPolicyRef !== undefined ||
          original.verifierExecutionGrantIds.length)
        invalid('retained delivery capture selection differs from its exact original source');
    }
    return { target: targetData, original, bundle };
  } catch (cause) {
    if (cause instanceof ResourceRetirementError) throw cause;
    throw new KernelStorageError('RECOVERY_REQUIRED', 'source inspection retained provenance is invalid', { cause });
  }
}
