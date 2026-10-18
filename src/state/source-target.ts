import { canonicalSha256 } from '../kernel/canonical.js';
import { normalizeRunSubmitRequest as decodeRunSubmitRequest, InvalidRunSubmitRequestError } from '../kernel/control-submit.js';
import type { NormalizedRunSubmitRequest } from '../kernel/control-submit.js';
import type { SandboxProfileV1, SourceInspectionTargetV1 } from '../kernel/execution.js';
import { assertArtifactRef, digestOmitting, identityHash, normalizeBoundedText } from '../kernel/identity.js';
import type { SourceInspectionAttemptV1 } from '../kernel/execution.js';
import type { WorkspaceIdentityV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';
import { validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { decodeWorkspaceIdentity } from './decoders.js';
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
  request: NormalizedRunSubmitRequest; originalRequest: object; target: SourceInspectionTargetV1;
  targetRef: string; inspectionId: string; workspace: Extract<WorkspaceIdentityV1, { kind: 'live' }>;
  metadata: readonly PublishedArtifact[];
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
    workspaceRoot: held.workspaceRoot, metadata: held.metadata });
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
}, inlineRequest: unknown, identity: AuthenticatedControlIdentity): Promise<VerifiedSourceInspectionTarget> {
  const normalized = normalizeRunSubmitRequest(inlineRequest), request = normalized.request;
  identity = immutableSnapshot(identity);
  const bootstrap = immutableSnapshot(context.bootstrap), { driver, artifacts, owner, workspaceRoot, trust } = context;
  const admissionIntentDigest = runSubmitIntentDigest(identity.principalId, request);
  // Any retained attempt/Run is handled by the caller's replay path. Never
  // reopen/capture a mutable source to reconstruct a historical result.
  const key = { principalId: identity.principalId, admissionKey: request.admissionKey, admissionIntentDigest };
  const existing = readSourceInspectionAttempt(driver, key);
  const admitted = readAdmissionReplay(driver, 'runs', identity.principalId, 'run.submit', request.admissionKey);
  if (admitted && admitted.admissionIntentDigest !== admissionIntentDigest) throw new KernelStorageError('ADMISSION_KEY_CONFLICT', 'run.submit key names a different intent');
  if (existing || admitted) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'source intent is retained; join or replay it without recapture');
  const channel = await validateControlChannelClosure(artifacts, owner, identity);
  const active = assertActiveStateOwner(driver, owner);
  const session = readSession(driver, request.sessionId);
  if (readSessionPrincipalId(driver, session.id) !== identity.principalId) throw new KernelStorageError('NOT_FOUND', 'Session does not belong to this principal');
  if (session.contextRevision !== request.expectedContextRevision) throw new KernelStorageError('REVISION_CONFLICT', 'Session context changed before source capture');
  assertHeldWorkspaceRoot(workspaceRoot);
  if (heldWorkspaceRootPath(workspaceRoot) !== request.workspacePath) throw new KernelStorageError('ARTIFACT_MISMATCH', 'held workspace path differs from inline request');
  assertWorkspaceSourceTrust(trust, request.workspacePath);
  if (request.sourceIncludes.some(include => include.readGrantId !== undefined)) invalid('source read grants are not implemented; ignored bytes cannot be captured');
  if (request.dependency.mode !== 'none') invalid('dependency admission is not yet implemented');
  assertSupportedVerifierRequests(request.verifiers, request.policyMode);
  if (request.verifiers.length) await readVerifierRequestIdentities(driver, artifacts, owner, bootstrap, identity.principalId, request.verifiers, undefined, context.signal);
  if (request.registeredMcpServerIds.length || request.skillIds.length) invalid('MCP/skill admission authority is not yet implemented');
  if (request.model.provider !== 'ollama') {
    if (!context.selectedRuntime || request.model.provider !== 'openai-compatible')
      invalid('remote model admission requires the genuine installed fixed broker recipe');
    await withHeldInstalledRuntime(context.selectedRuntime, async installed => {
      await installed.revalidate();
      if (installed.bundleDigest !== canonicalSha256(bootstrap.bundle) ||
          !installed.modelAuthority?.models.some(model => model.catalog.value.provider === request.model.provider &&
            model.catalog.value.model === request.model.model && model.catalog.value.adapter.adapterId === 'openai-compatible-broker-v1' &&
            model.catalog.value.adapter.version === '1')) invalid('remote model source capture lacks the selected signed model authority');
      await installed.revalidate();
    });
  }
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, session.workspaceIdentityRef));
  if (workspace.kind !== 'live' || workspace.ownerPrincipalId !== identity.principalId || workspace.platform !== hostPlatform() ||
      workspace.canonicalRootPath !== request.workspacePath || canonicalSha256(workspace.rootIdentity) !== canonicalSha256(workspaceRoot.identity) ||
      (workspace.repositoryIdentityRef === undefined) !== (workspaceRoot.repositoryDirectory === undefined))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'live workspace does not match the exact Session identity');
  if (workspace.repositoryIdentityRef !== undefined) await recaptureLiveWorkspaceIdentity(workspace, request.workspacePath, context.selectedRuntime);
  verifyRuntimeBundle(bootstrap.bundle, bootstrap.releaseKeys);
  const runtimeBundleRef = canonicalSha256(bootstrap.bundle);
  if (active.runtimeBundleRef !== runtimeBundleRef || active.runtimeBundleManifestDigest !== bootstrap.bundle.manifestDigest ||
      canonicalSha256(await readCanonicalArtifact(artifacts, runtimeBundleRef)) !== runtimeBundleRef)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source inspection runtime differs from the signed StateOwner bootstrap');
  const profile = decodeSandboxProfile(bootstrap.sandboxProfile);
  if (!profile.allowedOwners.includes('source_inspection') || canonicalSha256(profile.resources) !== canonicalSha256(request.sandboxResources))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'trusted source inspection profile differs from the requested frozen resources');
  const original = await artifacts.publishCanonical(normalized.originalRequest, 'cliq-control-request-v1');
  const selectedProfile = await artifacts.publishCanonical(profile, profile.format);
  const target: SourceInspectionTargetV1 = { schemaVersion: 1, format: 'cliq-source-inspection-target-v1', principalId: identity.principalId,
    method: 'run.submit', admissionKey: request.admissionKey, admissionIntentDigest,
    originalRequestRef: original.ref, originalRequestDigest: normalized.originalRequestDigest,
    sessionId: request.sessionId, expectedContextRevision: request.expectedContextRevision,
    workspaceIdentityRef: session.workspaceIdentityRef, workspaceIdentityDigest: workspace.identityDigest, sourceReadGrantRefs: [],
    runtimeBundleRef, runtimeBundleManifestDigest: bootstrap.bundle.manifestDigest,
    sandboxProfileRef: selectedProfile.ref, sandboxProfileDigest: profile.profileDigest, targetDigest: '' };
  target.targetDigest = digestOmitting(target, 'targetDigest');
  const published = await artifacts.publishCanonical(target, target.format);
  const result: VerifiedSourceInspectionTarget = Object.freeze({ kind: 'verified_source_inspection_target' });
  verifiedTargets.set(result, { driver, artifacts, owner, workspaceRoot, trust, identity, request,
    originalRequest: normalized.originalRequest, target: immutableSnapshot(target), targetRef: published.ref,
    inspectionId: identityHash('cliq-source-inspection-v1', identity.principalId, 'run.submit', request.admissionKey, admissionIntentDigest),
    workspace: immutableSnapshot(workspace), metadata: immutableSnapshot([...channel.metadata, original, selectedProfile, published]) });
  await recheckVerifiedSourceInspectionTarget(owner, result);
  return result;
}

/** Retained replay checks bytes and indexes without reopening a live source.
 * This returns no native/read capability and cannot authorize fresh capture. */
export async function readRetainedSourceInspectionTarget(artifacts: ArtifactCatalog, attempt: SourceInspectionAttemptV1,
  originalIndex: { originalRequestId: string; originalRequestDigest: string }, bootstrap: SourceInspectionBootstrap) {
  try {
    const targetData = object(await readCanonicalArtifact(artifacts, attempt.targetRef), ['schemaVersion', 'format', 'principalId', 'method',
      'admissionKey', 'admissionIntentDigest', 'originalRequestRef', 'originalRequestDigest', 'sessionId', 'expectedContextRevision',
      'workspaceIdentityRef', 'workspaceIdentityDigest', 'sourceReadGrantRefs', 'runtimeBundleRef', 'runtimeBundleManifestDigest',
      'sandboxProfileRef', 'sandboxProfileDigest', 'targetDigest']);
    for (const key of ['admissionIntentDigest', 'originalRequestRef', 'originalRequestDigest', 'workspaceIdentityRef',
      'workspaceIdentityDigest', 'runtimeBundleRef', 'runtimeBundleManifestDigest', 'sandboxProfileRef', 'sandboxProfileDigest', 'targetDigest'])
      assertArtifactRef(text(targetData[key], 64));
    if (targetData.schemaVersion !== 1 || targetData.format !== 'cliq-source-inspection-target-v1' || targetData.method !== 'run.submit' ||
        targetData.targetDigest !== digestOmitting(targetData, 'targetDigest') || targetData.targetDigest !== attempt.targetDigest ||
        targetData.principalId !== attempt.principalId || targetData.admissionKey !== attempt.admissionKey ||
        targetData.admissionIntentDigest !== attempt.admissionIntentDigest || targetData.workspaceIdentityDigest !== attempt.workspaceIdentityDigest ||
        !Array.isArray(targetData.sourceReadGrantRefs) || targetData.sourceReadGrantRefs.length !== 0) invalid('retained target does not bind its original source attempt');
    const original = normalizeRunSubmitRequest(await readCanonicalArtifact(artifacts, text(targetData.originalRequestRef, 64)));
    if (original.request.requestId !== originalIndex.originalRequestId || original.originalRequestDigest !== originalIndex.originalRequestDigest ||
        original.originalRequestDigest !== targetData.originalRequestDigest || original.request.sessionId !== targetData.sessionId ||
        original.request.expectedContextRevision !== targetData.expectedContextRevision ||
        runSubmitIntentDigest(attempt.principalId, original.request) !== attempt.admissionIntentDigest)
      invalid('retained target original request or derived index differs');
    const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, text(targetData.workspaceIdentityRef, 64)));
    if (workspace.kind !== 'live' || workspace.identityDigest !== targetData.workspaceIdentityDigest ||
        workspace.ownerPrincipalId !== attempt.principalId || workspace.canonicalRootPath !== original.request.workspacePath)
      invalid('retained target workspace differs from its original request');
    const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, text(targetData.runtimeBundleRef, 64));
    verifyRuntimeBundle(bundle, bootstrap.releaseKeys);
    if (bundle.manifestDigest !== targetData.runtimeBundleManifestDigest) invalid('retained target signed runtime differs');
    const profile = decodeSandboxProfile(await readCanonicalArtifact(artifacts, text(targetData.sandboxProfileRef, 64)));
    if (profile.profileDigest !== targetData.sandboxProfileDigest || !profile.allowedOwners.includes('source_inspection') ||
        canonicalSha256(profile.resources) !== canonicalSha256(original.request.sandboxResources)) invalid('retained target source profile differs');
    return { target: targetData as SourceInspectionTargetV1, original: original.request, bundle };
  } catch (cause) {
    if (cause instanceof ResourceRetirementError) throw cause;
    throw new KernelStorageError('RECOVERY_REQUIRED', 'source inspection retained provenance is invalid', { cause });
  }
}
