import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { DependencyRequest, NormalizedRunSubmitRequest, RunModelRequest, SourceSelectorRequest,
  VerifierRequest } from '../kernel/control-submit.js';
import type { SandboxProfileV1, SandboxResourceSpec, SourceInspectionTargetV1 } from '../kernel/execution.js';
import { assertAdmissionKey, assertArtifactRef, assertRequestId, digestOmitting, identityHash, normalizeAbsolutePath, normalizeBoundedText } from '../kernel/identity.js';
import type { SourceInspectionAttemptV1 } from '../kernel/execution.js';
import type { WorkspaceIdentityV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';
import { validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { decodeWorkspaceIdentity } from './decoders.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath, type HeldWorkspaceRoot } from './native-owner.js';
import { DEFAULT_RUN_BUDGETS, mergeBudgets, readAdmissionReplay, readSession, readSessionPrincipalId } from './rows.js';
import { readSourceInspectionAttempt } from './source-inspection.js';
import { assertWorkspaceSourceTrust, type HeldWorkspaceSourceTrust } from './source-trust.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { hostPlatform, recaptureLiveWorkspaceIdentity } from './workspace-identity.js';

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
function integer(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) invalid('inline integer is outside its accepted bounds');
  return value as number;
}
function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') invalid('inline boolean must be a boolean');
  return value;
}
function choice<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) invalid('inline discriminator is invalid');
  return value as T;
}
function array<T>(value: unknown, maximum: number, decode: (value: unknown) => T): T[] {
  if (!Array.isArray(value) || value.length > maximum) invalid('inline array is outside its accepted bounds');
  return value.map(decode);
}
function ids(value: unknown, maximum: number, minimum = 0): string[] {
  const result = array(value, maximum, item => text(item));
  if (result.length < minimum || new Set(result).size !== result.length) invalid('inline ids must be unique and satisfy their count bound');
  return result;
}
function relative(value: unknown, root = false): string {
  const result = text(value, 4096);
  if (root && result === '.') return result;
  if (result.includes('\\') || result.split('/').some(part => !part || part === '.' || part === '..' || Buffer.byteLength(part) > 255))
    invalid('inline path must be an exact canonical root-relative path');
  return result;
}
function literal(value: unknown) {
  const data = object(value, ['kind', 'value']);
  if (data.kind !== 'non_secret_literal') invalid('only explicit non-secret literals are accepted');
  return { kind: 'non_secret_literal' as const, value: text(data.value, 8192, 0) };
}
function selector(value: unknown, include: boolean): SourceSelectorRequest {
  const data = object(value, ['path', 'scope'], include ? ['readGrantId'] : []);
  return { path: relative(data.path), scope: choice(data.scope, ['entry', 'subtree']),
    ...(Object.hasOwn(data, 'readGrantId') ? { readGrantId: text(data.readGrantId) } : {}) };
}
function verifier(value: unknown): VerifierRequest {
  const data = object(value, ['id', 'version', 'required', 'executable', 'argv', 'cwd', 'env',
    'writableEphemeralPaths', 'identityReadGrantId'], ['executionGrantId', 'timeoutMs', 'retries', 'outputLimitBytes']);
  const command = object(data.executable, ['kind'], ['toolId', 'path', 'expectedDigest']);
  let executable: VerifierRequest['executable'];
  if (command.kind === 'toolchain') {
    object(command, ['kind', 'toolId']); executable = { kind: 'toolchain', toolId: text(command.toolId) };
  } else {
    object(command, ['kind', 'path'], ['expectedDigest']);
    if (command.kind !== 'workspace_script') invalid('unsupported verifier executable kind');
    const expectedDigest = Object.hasOwn(command, 'expectedDigest') ? text(command.expectedDigest, 64) : undefined;
    if (expectedDigest !== undefined) assertArtifactRef(expectedDigest);
    executable = { kind: 'workspace_script', path: relative(command.path), ...(expectedDigest === undefined ? {} : { expectedDigest }) };
  }
  if (!data.env || typeof data.env !== 'object' || Array.isArray(data.env)) invalid('verifier env must be an object');
  const names = Object.keys(data.env);
  object(data.env, [], names);
  if (names.length > 64 || names.some(name => !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/u.test(name))) invalid('verifier env names are invalid');
  const env = Object.fromEntries(names.sort().map(name => [name, literal((data.env as Record<string, unknown>)[name])]));
  const writableEphemeralPaths = array(data.writableEphemeralPaths, 32, item => relative(item));
  if (new Set(writableEphemeralPaths).size !== writableEphemeralPaths.length) invalid('verifier writable paths must be unique');
  return { id: text(data.id), version: text(data.version), required: boolean(data.required), executable,
    argv: array(data.argv, 128, literal), cwd: relative(data.cwd, true), env, writableEphemeralPaths,
    identityReadGrantId: text(data.identityReadGrantId),
    ...(Object.hasOwn(data, 'executionGrantId') ? { executionGrantId: text(data.executionGrantId) } : {}),
    ...(Object.hasOwn(data, 'timeoutMs') ? { timeoutMs: integer(data.timeoutMs, 1) } : {}),
    ...(Object.hasOwn(data, 'retries') ? { retries: integer(data.retries, 0) } : {}),
    ...(Object.hasOwn(data, 'outputLimitBytes') ? { outputLimitBytes: integer(data.outputLimitBytes, 1) } : {}) };
}
function dependency(value: unknown): DependencyRequest {
  const data = object(value, ['mode'], ['registryEndpointIds', 'credentialGrantIds', 'allowInstallScripts',
    'installScriptsGrantId', 'maxPackages', 'maxDownloadBytes']);
  if (data.mode === 'none') { object(data, ['mode']); return { mode: 'none' }; }
  object(data, ['mode', 'registryEndpointIds', 'credentialGrantIds', 'allowInstallScripts'],
    ['installScriptsGrantId', 'maxPackages', 'maxDownloadBytes']);
  if (data.mode !== 'locked') invalid('unsupported dependency mode');
  const allowInstallScripts = boolean(data.allowInstallScripts);
  if (!allowInstallScripts && Object.hasOwn(data, 'installScriptsGrantId')) invalid('install-script grant requires an install-script request');
  return { mode: 'locked', registryEndpointIds: ids(data.registryEndpointIds, 128, 1), credentialGrantIds: ids(data.credentialGrantIds, 32), allowInstallScripts,
    ...(Object.hasOwn(data, 'installScriptsGrantId') ? { installScriptsGrantId: text(data.installScriptsGrantId) } : {}),
    ...(Object.hasOwn(data, 'maxPackages') ? { maxPackages: integer(data.maxPackages, 1) } : {}),
    ...(Object.hasOwn(data, 'maxDownloadBytes') ? { maxDownloadBytes: integer(data.maxDownloadBytes, 1) } : {}) };
}
function model(value: unknown): RunModelRequest {
  const data = object(value, ['provider', 'model'], ['endpoint', 'modelCredentialGrantIds']);
  if (data.provider === 'ollama') { object(data, ['provider', 'model']); return { provider: 'ollama', model: text(data.model) }; }
  object(data, ['provider', 'model', 'endpoint', 'modelCredentialGrantIds']);
  const endpoint = object(data.endpoint, ['kind', 'endpointRegistrationId']);
  if (endpoint.kind !== 'registered') invalid('model endpoint must name a registration');
  return { provider: choice(data.provider, ['openai', 'anthropic', 'openrouter', 'openai-compatible', 'zhipu']), model: text(data.model),
    endpoint: { kind: 'registered', endpointRegistrationId: text(endpoint.endpointRegistrationId) },
    modelCredentialGrantIds: ids(data.modelCredentialGrantIds, 32, 1) };
}
const RESOURCE_DEFAULTS: SandboxResourceSpec = { maxProcesses: 256, memoryBytes: 4 * 1024 ** 3,
  cpuQuotaMicrosPerSecond: 400_000, maxOpenFiles: 1024, maxSingleFileBytes: 2 * 1024 ** 3,
  maxGenerationBytes: 20 * 1024 ** 3, maxInvocationOutputBytes: 16 * 1024 ** 2,
  maxIpcFrameBytes: 16 * 1024 ** 2, maxQueuedIpcBytes: 64 * 1024 ** 2 };
const RESOURCE_RANGES: Record<keyof SandboxResourceSpec, readonly [number, number]> = {
  maxProcesses: [1, 1024], memoryBytes: [256 * 1024 ** 2, 32 * 1024 ** 3], cpuQuotaMicrosPerSecond: [10_000, 1_600_000],
  maxOpenFiles: [64, 8192], maxSingleFileBytes: [1024 ** 2, 16 * 1024 ** 3], maxGenerationBytes: [256 * 1024 ** 2, 100 * 1024 ** 3],
  maxInvocationOutputBytes: [64 * 1024, 64 * 1024 ** 2], maxIpcFrameBytes: [16 * 1024 ** 2, 16 * 1024 ** 2], maxQueuedIpcBytes: [64 * 1024 ** 2, 64 * 1024 ** 2] };
function resourceOptions(value: unknown): SandboxResourceSpec {
  const data = value === undefined ? {} : object(value, [], Object.keys(RESOURCE_DEFAULTS));
  const result = { ...RESOURCE_DEFAULTS };
  for (const key of Object.keys(result) as Array<keyof SandboxResourceSpec>) {
    const [minimum, maximum] = RESOURCE_RANGES[key];
    result[key] = integer(Object.hasOwn(data, key) ? data[key] : result[key], minimum, maximum);
  }
  return result;
}
function boundedJson(value: unknown, depth = 0, total = { members: 0 }): void {
  if (depth > 32) invalid('inline JSON exceeds its depth bound');
  if (value && typeof value === 'object') {
    if (Array.isArray(value)) {
      total.members += value.length;
      for (let index = 0; index < value.length; index++) {
        if (!Object.hasOwn(value, index)) invalid('inline JSON cannot contain sparse arrays');
        boundedJson(value[index], depth + 1, total);
      }
    } else {
      const keys = Object.keys(value); total.members += keys.length;
      if (total.members > 10_000) invalid('inline JSON exceeds its member bound');
      for (const key of keys) boundedJson((value as Record<string, unknown>)[key], depth + 1, total);
    }
  }
  if (total.members > 10_000) invalid('inline JSON exceeds its member bound');
}

/** Request hashing retains the supplied optional fields; the admission intent
 * separately incorporates their normative defaults. No resolved capture ref
 * is accepted or mixed into either domain. */
export function normalizeRunSubmitRequest(value: unknown): {
  request: NormalizedRunSubmitRequest; originalRequest: object; originalRequestDigest: string;
} {
  try {
    boundedJson(value);
    const data = object(value, ['protocolVersion', 'requestId', 'requestDigest', 'method', 'admissionKey', 'sessionId',
      'expectedContextRevision', 'workspacePath', 'objective', 'model', 'policyMode', 'verifiers', 'dependency',
      'sourceIncludes', 'sourceExcludes', 'registeredMcpServerIds', 'skillIds', 'allowUnverified'],
    ['budgets', 'sandboxResources', 'maxChangedPaths', 'maxChangedBytes']);
    if (data.protocolVersion !== 1 || data.method !== 'run.submit') invalid('expected protocol-v1 run.submit');
    const requestId = text(data.requestId), admissionKey = text(data.admissionKey), requestDigest = text(data.requestDigest, 64);
    assertRequestId(requestId); assertAdmissionKey(admissionKey); assertArtifactRef(requestDigest);
    const budgets = data.budgets === undefined ? undefined : object(data.budgets, [], Object.keys(DEFAULT_RUN_BUDGETS));
    const verifiers = array(data.verifiers, 32, verifier), allowUnverified = boolean(data.allowUnverified);
    if (new Set(verifiers.map(gate => gate.id)).size !== verifiers.length) invalid('verifier ids must be unique');
    if (verifiers.some(gate => gate.required) === allowUnverified) invalid('allowUnverified must match the absence of required verifiers');
    const core = { protocolVersion: 1 as const, requestId, method: 'run.submit' as const, admissionKey,
      sessionId: text(data.sessionId), expectedContextRevision: integer(data.expectedContextRevision, 1),
      workspacePath: normalizeAbsolutePath(text(data.workspacePath, 4096)), objective: text(data.objective, 262_144),
      model: model(data.model), policyMode: choice(data.policyMode, ['default', 'accept-edits', 'plan', 'yolo']),
      verifiers, dependency: dependency(data.dependency), sourceIncludes: array(data.sourceIncludes, 128, item => selector(item, true)),
      sourceExcludes: array(data.sourceExcludes, 128, item => selector(item, false)), registeredMcpServerIds: ids(data.registeredMcpServerIds, 128),
      skillIds: ids(data.skillIds, 64), allowUnverified,
      ...(budgets === undefined ? {} : { budgets: Object.fromEntries(Object.keys(budgets).map(key => [key, integer(budgets[key], 0)])) }),
      ...(data.sandboxResources === undefined ? {} : { sandboxResources: object(data.sandboxResources, [], Object.keys(RESOURCE_DEFAULTS)) }),
      ...(data.maxChangedPaths === undefined ? {} : { maxChangedPaths: integer(data.maxChangedPaths, 0, 100_000) }),
      ...(data.maxChangedBytes === undefined ? {} : { maxChangedBytes: integer(data.maxChangedBytes, 0, 4 * 1024 ** 3) }) };
    const originalRequest = { ...core, requestDigest };
    if (canonicalJsonBytes(originalRequest).length > 1_048_576) invalid('inline request exceeds 1 MiB');
    if (canonicalSha256(core) !== requestDigest) invalid('inline requestDigest does not match canonical request bytes');
    const request = { ...core, requestDigest, budgets: mergeBudgets(budgets), sandboxResources: resourceOptions(data.sandboxResources),
      maxChangedPaths: core.maxChangedPaths ?? 10_000, maxChangedBytes: core.maxChangedBytes ?? 512 * 1024 ** 2 };
    return immutableSnapshot({ request, originalRequest, originalRequestDigest: requestDigest });
  } catch (cause) {
    if (cause instanceof KernelStorageError) throw cause;
    throw new KernelStorageError('INVALID_REQUEST', 'invalid inline run.submit request', { cause });
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
  if (request.verifiers.length || request.dependency.mode !== 'none') invalid('verifier/dependency admission is not yet implemented');
  if (request.model.provider !== 'ollama' || request.registeredMcpServerIds.length || request.skillIds.length)
    invalid('remote model/MCP/skill admission authority is not yet implemented');
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, session.workspaceIdentityRef));
  if (workspace.kind !== 'live' || workspace.ownerPrincipalId !== identity.principalId || workspace.platform !== hostPlatform() ||
      workspace.canonicalRootPath !== request.workspacePath || canonicalSha256(workspace.rootIdentity) !== canonicalSha256(workspaceRoot.identity) ||
      (workspace.repositoryIdentityRef === undefined) !== (workspaceRoot.repositoryDirectory === undefined))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'live workspace does not match the exact Session identity');
  if (workspace.repositoryIdentityRef !== undefined) await recaptureLiveWorkspaceIdentity(workspace, request.workspacePath);
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
