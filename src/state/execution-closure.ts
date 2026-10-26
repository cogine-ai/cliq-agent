import path from 'node:path';
import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { ProcessContainment, ProcessContainmentPlanV1, SandboxLaunchSpecV1, SandboxProfileV1, SandboxRootProfileV1,
  SandboxResourceSpec, SandboxMountV1 } from '../kernel/execution.js';
import type { InvocationJournalEntry, Run, RunAssemblyV1, RunFrontier, RunSpec, StateOwnerRecordV1, WorkerIdentity, WorkerLaunch,
  WorkspaceGenerationIdentityV1, WorkspaceGenerationStateV1, ToolContractManifestV1 } from '../kernel/types.js';
import type { ToolOperationGrantV1, ToolRequestV1, ToolTargetV1 } from '../kernel/tool-authorization.js';
import type { PolicyEngineProfileV1, RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import type { VerifierOperationGrantV1, VerifierPolicyChannelEvidenceV1, VerifierRequestV1, VerifierTargetV1 } from '../kernel/verifier-invocation.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readRun } from './rows.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef } from './repositories/workspace-generations.js';
import { type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeRunSpec, decodeSourceManifest, decodeStateLockIdentity, decodeStateRootIdentity,
  decodeWorkerIdentity, decodeWorkspaceGenerationIdentity, decodeWorkspaceState } from './decoders.js';
import { joinResourceOperations, KernelStorageError } from './errors.js';
import { validatePreactivationQuarantine } from './preactivation-retirement.js';
import { readRetainedVerifierToolchain } from './guest-toolchain.js';
import { decodeVerifierPlan } from './result-artifacts.js';
import { decodeVerifierCommand, decodeVerifierEnvironment, decodeVerifierSpec } from './verifier-artifacts.js';
import { loadVerifierPolicy } from './verifier-policy.js';
import { readCandidateSource } from './result-source.js';
import { readToolRuntimeAuthority } from './tool-runtime-authority.js';
import { BUILTIN_SCRIPT_TOOL_NAMES } from '../tools/execution-identity.js';
import { loadToolContracts } from '../tools/input-contract.js';
import { BUILTIN_SCRIPT_ENVIRONMENTS, BUILTIN_SCRIPT_PRIVATE_MOUNTS, builtinToolInputBytes, isBuiltinScriptTool } from '../sandbox/builtin-tool-data.js';

type WorkerSpec = Extract<SandboxLaunchSpecV1, { purpose: 'worker_activation' }>;
type WorkerOwner = WorkerSpec['owner'];
type EditSpec = Extract<SandboxLaunchSpecV1, { owner: { kind: 'run_invocation' } }> & { purpose: 'tool' };
type VerifierSpec = Extract<SandboxLaunchSpecV1, { owner: { kind: 'run_invocation' } }> & { purpose: 'verifier' };
type InvocationOwner = EditSpec['owner'];
const workerClosures = new WeakSet<object>();
const editClosures = new WeakSet<object>();
const scriptClosures = new WeakSet<object>();
const verifierClosures = new WeakSet<object>();

/** A structural clone is retained metadata, not authority to mint a native launch. */
export function assertWorkerLaunchClosure(value: unknown): asserts value is WorkerLaunchClosure {
  if (value === null || typeof value !== 'object' || !workerClosures.has(value)) mismatch('native worker launch requires its trusted retained-artifact closure');
}
export function assertBuiltinEditLaunchClosure(value: unknown): asserts value is BuiltinEditLaunchClosure {
  if (value === null || typeof value !== 'object' || !editClosures.has(value)) mismatch('native edit launch requires its trusted retained-artifact closure');
}
export function assertBuiltinScriptLaunchClosure(value: unknown): asserts value is BuiltinScriptLaunchClosure {
  if (value === null || typeof value !== 'object' || !scriptClosures.has(value)) mismatch('native script launch requires its trusted retained-artifact closure');
}
export function isBuiltinScriptLaunchClosure(value: unknown): value is BuiltinScriptLaunchClosure {
  return value !== null && typeof value === 'object' && scriptClosures.has(value);
}
export function assertBuiltinToolLaunchClosure(value: unknown): asserts value is BuiltinToolLaunchClosure {
  if (value === null || typeof value !== 'object' || !editClosures.has(value) && !scriptClosures.has(value))
    mismatch('native builtin launch requires its original retained-artifact closure');
}
export function assertVerifierLaunchClosure(value: unknown): asserts value is VerifierLaunchClosure {
  if (value === null || typeof value !== 'object' || !verifierClosures.has(value)) mismatch('native verifier launch requires its trusted retained-artifact closure');
}

function mismatch(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }
function mint<T extends object>(value: T, authority: WeakSet<object>): T {
  const closure = immutableSnapshot(value);
  authority.add(closure);
  return closure;
}
function record(value: unknown, keys: readonly string[], label: string, optional: readonly string[] = []): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) mismatch(`${label} must be an object`);
  const object = value as Record<string, unknown>;
  if (keys.some((key) => !Object.hasOwn(object, key)) || Object.keys(object).some((key) => !keys.includes(key) && !optional.includes(key))) {
    mismatch(`${label} has an invalid closed shape`);
  }
  return object;
}
function equal(left: unknown, right: unknown, label: string): void {
  if (canonicalSha256(left) !== canonicalSha256(right)) mismatch(`${label} does not match`);
}
function literal(value: unknown, expected: unknown, label: string): void {
  if (value !== expected) mismatch(`${label} does not match`);
}
function text(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || value.normalize('NFC') !== value) mismatch(`${label} must be canonical nonempty text`);
  return value;
}
function digest(value: unknown, label: string): string {
  const result = text(value, label);
  try { assertArtifactRef(result); } catch { mismatch(`${label} must be a canonical SHA-256 digest`); }
  return result;
}
function time(value: unknown, label: string): void {
  try { parseCanonicalTime(text(value, label)); } catch { mismatch(`${label} must be a canonical UTC millisecond`); }
}
function absolute(value: unknown, label: string): string {
  const result = text(value, label);
  if (!result.startsWith('/') || result.includes('\\') || path.posix.normalize(result) !== result || result.endsWith('/')) mismatch(`${label} must be a canonical sandbox path`);
  return result;
}
function relative(value: unknown, label: string): string {
  const result = text(value, label);
  if (result.startsWith('/') || result.includes('\\') || result === '.' || path.posix.normalize(result) !== result || result.split('/').includes('..') || result.endsWith('/')) mismatch(`${label} must be a canonical generation-relative path`);
  return result;
}
function rehash(value: Record<string, unknown>, member: string, label: string): void {
  literal(digest(value[member], `${label}.${member}`), digestOmitting(value, member), `${label}.${member}`);
}
function workerOwner(value: unknown): WorkerOwner {
  const owner = record(value, ['kind', 'runId', 'intendedLeaseEpoch', 'workerLaunchId'], 'worker owner');
  literal(owner.kind, 'worker_activation', 'worker owner purpose');
  text(owner.runId, 'worker Run'); text(owner.workerLaunchId, 'worker launch');
  if (!Number.isSafeInteger(owner.intendedLeaseEpoch) || (owner.intendedLeaseEpoch as number) < 1) mismatch('worker epoch must be a positive safe integer');
  return owner as WorkerOwner;
}
function invocationOwner(value: unknown): InvocationOwner {
  const owner = record(value, ['kind', 'runId', 'intendedLeaseEpoch', 'workerLaunchId', 'opId', 'attempt', 'dispatchId'], 'invocation owner');
  literal(owner.kind, 'run_invocation', 'invocation owner purpose');
  for (const member of ['runId', 'workerLaunchId', 'opId', 'dispatchId']) text(owner[member], `invocation owner ${member}`);
  if (!Number.isSafeInteger(owner.intendedLeaseEpoch) || (owner.intendedLeaseEpoch as number) < 1 || !Number.isSafeInteger(owner.attempt) || (owner.attempt as number) < 0) mismatch('invocation epoch/attempt is invalid');
  return owner as InvocationOwner;
}
function filesystemBinding(value: unknown): void {
  const binding = record(value, ['kind', 'generationRef'], 'worker filesystem binding');
  literal(binding.kind, 'run-generation', 'worker filesystem binding'); digest(binding.generationRef, 'worker generation ref');
}

/** Worker purpose only. Other canonical purposes fail closed until their reserving transitions exist. */
export function decodeWorkerContainmentPlan(value: unknown): ProcessContainmentPlanV1 & { owner: WorkerOwner } {
  return decodeLinuxContainmentPlan(value, 'worker_activation') as ProcessContainmentPlanV1 & { owner: WorkerOwner };
}
/** Retained data only; this cannot mint a native launch closure. */
export function decodeBuiltinEditContainmentPlan(value: unknown): ProcessContainmentPlanV1 {
  return decodeLinuxContainmentPlan(value, 'run_invocation');
}
function decodeLinuxContainmentPlan(value: unknown, purpose: 'worker_activation' | 'run_invocation'): ProcessContainmentPlanV1 {
  const plan = record(value, ['schemaVersion', 'format', 'owner', 'filesystemBinding', 'launchNonceDigest', 'backend', 'createdAt', 'planDigest',
    ...(purpose === 'run_invocation' ? ['parentContainmentRef'] : [])], 'containment plan');
  literal(plan.schemaVersion, 1, 'worker plan schema'); literal(plan.format, 'cliq-process-containment-plan-v1', 'worker plan format');
  if (purpose === 'worker_activation') workerOwner(plan.owner);
  else { invocationOwner(plan.owner); digest(plan.parentContainmentRef, 'invocation parent containment'); }
  filesystemBinding(plan.filesystemBinding); digest(plan.launchNonceDigest, 'worker launch nonce');
  // macOS stays unqualified; do not accept a host-only approximation of the VM authority.
  const backend = record(plan.backend, ['kind', 'cgroupPath', 'cgroupNameReservationDigest', 'pidNamespaceReservationId', 'subreaperStartToken'], 'Linux worker plan',
    purpose === 'worker_activation' ? ['nativeReservation'] : []);
  literal(backend.kind, 'linux', 'worker backend'); absolute(backend.cgroupPath, 'planned cgroup');
  digest(backend.cgroupNameReservationDigest, 'cgroup reservation'); text(backend.pidNamespaceReservationId, 'PID namespace reservation'); text(backend.subreaperStartToken, 'subreaper start token');
  if (Object.hasOwn(backend, 'nativeReservation')) {
    const reservation = record(backend.nativeReservation, ['deviceId', 'fileId', 'ownerUid'], 'native worker reservation');
    for (const field of ['deviceId', 'fileId']) {
      if (!/^(0|[1-9][0-9]*)$/u.test(text(reservation[field], `reservation ${field}`))) mismatch('native reservation identity must be unsigned decimal');
    }
    if (!Number.isSafeInteger(reservation.ownerUid) || (reservation.ownerUid as number) < 0) mismatch('native reservation owner must be an exact uid');
  }
  time(plan.createdAt, 'worker plan creation'); rehash(plan, 'planDigest', 'worker plan');
  return plan as ProcessContainmentPlanV1;
}

const RESOURCE_RANGES: Readonly<Record<keyof SandboxResourceSpec, readonly [number, number]>> = {
  maxProcesses: [1, 1024], memoryBytes: [256 * 1024 ** 2, 32 * 1024 ** 3], cpuQuotaMicrosPerSecond: [10000, 1600000],
  maxOpenFiles: [64, 8192], maxSingleFileBytes: [1024 ** 2, 16 * 1024 ** 3], maxGenerationBytes: [256 * 1024 ** 2, 100 * 1024 ** 3],
  maxInvocationOutputBytes: [64 * 1024, 64 * 1024 ** 2], maxIpcFrameBytes: [16 * 1024 ** 2, 16 * 1024 ** 2], maxQueuedIpcBytes: [64 * 1024 ** 2, 64 * 1024 ** 2]
};
function resources(value: unknown): SandboxResourceSpec {
  const resource = record(value, Object.keys(RESOURCE_RANGES), 'sandbox resources');
  for (const [key, [minimum, maximum]] of Object.entries(RESOURCE_RANGES)) {
    const amount = resource[key];
    if (!Number.isSafeInteger(amount) || (amount as number) < minimum || (amount as number) > maximum) mismatch(`sandbox resource ${key} is outside its canonical bounds`);
  }
  return resource as SandboxResourceSpec;
}
/** Signed acyclic empty-root recipe, not an admission permission/resource policy. */
export function decodeSandboxRootProfile(value: unknown): SandboxRootProfileV1 {
  const profile = record(value, ['schemaVersion', 'format', 'protocol', 'filesystemKind', 'fixedDirectories',
    'persistent', 'networkConfiguration', 'profileDigest'], 'sandbox root profile');
  for (const [key, expected] of Object.entries({ schemaVersion: 1, format: 'cliq-sandbox-root-profile-v1',
    protocol: 'cliq-fresh-empty-root-v1', filesystemKind: 'fresh_ephemeral_tmpfs', persistent: false,
    networkConfiguration: 'none' })) literal(profile[key], expected, `sandbox root profile ${key}`);
  equal(profile.fixedDirectories, ['/home/cliq', '/tmp', '/work'], 'sandbox root profile directories');
  rehash(profile, 'profileDigest', 'sandbox root profile');
  return profile as SandboxRootProfileV1;
}

export function decodeSandboxProfile(value: unknown): SandboxProfileV1 {
  const profile = record(value, ['schemaVersion', 'format', 'backend', 'allowedOwners', 'filesystemPolicy', 'hostFilesystemReachability',
    'networkAtSpawn', 'networkAfterRelease', 'credentialReachability', 'stateRootReachability', 'inheritedHostEnvironment', 'resources', 'profileDigest'], 'sandbox profile');
  for (const [key, expected] of Object.entries({ schemaVersion: 1, format: 'cliq-sandbox-profile-v1', filesystemPolicy: 'typed_launch_spec_only',
    hostFilesystemReachability: 'none', networkAtSpawn: 'none', networkAfterRelease: 'typed_broker_only', credentialReachability: 'typed_broker_only',
    stateRootReachability: 'none', inheritedHostEnvironment: false })) literal(profile[key], expected, `sandbox profile ${key}`);
  if (profile.backend !== 'linux_namespace' && profile.backend !== 'macos_vm') mismatch('sandbox profile backend is invalid');
  if (!Array.isArray(profile.allowedOwners) || profile.allowedOwners.length === 0) mismatch('sandbox profile must declare owners');
  let previous = '';
  for (const owner of profile.allowedOwners) {
    const current = text(owner, 'sandbox profile owner');
    if (!['worker_activation', 'run_invocation', 'admin_probe', 'local_inference_service', 'source_inspection'].includes(current) || Buffer.compare(Buffer.from(previous), Buffer.from(current)) >= 0) mismatch('sandbox profile owners must be valid, unique and byte-sorted');
    previous = current;
  }
  resources(profile.resources); rehash(profile, 'profileDigest', 'sandbox profile');
  return profile as SandboxProfileV1;
}
function environment(value: unknown): void {
  const env = record(value, ['schemaVersion', 'format', 'controlledPath', 'locale', 'home', 'tmpdir', 'variables', 'inheritedHostEnvironment',
    'secretMaterial', 'brokerAccessAtSpawn', 'networkMode', 'environmentDigest'], 'sandbox environment');
  for (const [key, expected] of Object.entries({ schemaVersion: 1, format: 'cliq-sanitized-sandbox-environment-v1', inheritedHostEnvironment: false,
    secretMaterial: 'none', brokerAccessAtSpawn: 'none' })) literal(env[key], expected, `sandbox environment ${key}`);
  if (env.networkMode !== 'none' && env.networkMode !== 'broker_ipc_only') mismatch('sandbox network mode is invalid');
  absolute(env.home, 'sandbox home'); absolute(env.tmpdir, 'sandbox tmpdir');
  if (!Array.isArray(env.controlledPath) || env.controlledPath.length === 0) mismatch('sandbox PATH must be a nonempty explicit list');
  const paths = env.controlledPath.map((item) => absolute(item, 'sandbox PATH member'));
  if (new Set(paths).size !== paths.length || paths.some((item) => item.includes(':'))) mismatch('sandbox PATH members must be unique paths without separators');
  const locale = record(env.locale, ['lang', 'lcAll'], 'sandbox locale'); text(locale.lang, 'sandbox LANG'); text(locale.lcAll, 'sandbox LC_ALL');
  if (!Array.isArray(env.variables)) mismatch('sandbox variables must be an array');
  let previous = '';
  for (const item of env.variables) {
    const variable = record(item, ['name', 'value'], 'sandbox variable');
    const name = text(variable.name, 'sandbox variable name');
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || /^(PATH|HOME|TMP|TMPDIR|TEMP|LANG|LANGUAGE|LC_.*|CLIQ_.*|LD_.*|DYLD_.*|NODE_.*|.*TOKEN.*|.*SECRET.*|.*CREDENTIAL.*|.*API_KEY.*)$/i.test(name) || Buffer.compare(Buffer.from(previous), Buffer.from(name)) >= 0) mismatch('sandbox variables override a dedicated channel or are not unique and byte-sorted');
    const literalValue = record(variable.value, ['kind', 'value'], 'sandbox literal variable');
    literal(literalValue.kind, 'non_secret_literal', 'sandbox variable kind');
    if (typeof literalValue.value !== 'string' || literalValue.value.includes('\0')) mismatch('sandbox variable literal is invalid');
    previous = name;
  }
  rehash(env, 'environmentDigest', 'sandbox environment');
}
function mounts(value: unknown, allowGenerationWrites: boolean): SandboxMountV1[] {
  if (!Array.isArray(value)) mismatch('sandbox mounts must be an array');
  let previous = '';
  const privateRoots = new Set<string>();
  const targets = new Set<string>();
  for (const item of value) {
    const kind = (item as { kind?: unknown } | null)?.kind;
    const mount = record(item, kind === 'cas_artifact' ? ['kind', 'artifactRef', 'artifactDigest', 'targetPath', 'access', 'purpose']
      : kind === 'run_generation' ? ['kind', 'generationRef', 'canonicalRootRelativePath', 'targetPath', 'access', 'purpose']
      : ['kind', 'privateRootId', 'targetPath', 'access', 'purpose'], 'sandbox mount');
    const target = absolute(mount.targetPath, 'mount target');
    if (Buffer.compare(Buffer.from(previous), Buffer.from(target)) >= 0) mismatch('mount targets must be unique and byte-sorted');
    for (let ancestor = path.posix.dirname(target); ancestor !== '/'; ancestor = path.posix.dirname(ancestor)) {
      if (targets.has(ancestor)) mismatch('mount targets overlap');
    }
    targets.add(target);
    previous = target;
    if (kind === 'cas_artifact') {
      digest(mount.artifactRef, 'CAS mount ref'); literal(mount.artifactDigest, mount.artifactRef, 'CAS mount digest'); literal(mount.access, 'read_only', 'CAS mount access');
      if (!['runtime', 'input', 'executable'].includes(mount.purpose as string)) mismatch('CAS mount purpose is invalid');
    } else if (kind === 'run_generation') {
      digest(mount.generationRef, 'generation mount ref'); relative(mount.canonicalRootRelativePath, 'generation mount source');
      if (mount.access !== 'read_only' && !(allowGenerationWrites && mount.access === 'read_write')) mismatch('generation mount access exceeds its launch envelope');
      if (!['source', 'dependency', 'cache', 'output'].includes(mount.purpose as string)) mismatch('generation mount purpose is invalid');
    } else if (kind === 'private_ephemeral') {
      const id = text(mount.privateRootId, 'private root id');
      if (privateRoots.has(id)) mismatch('private ephemeral roots may not be reused'); privateRoots.add(id);
      literal(mount.access, 'read_write', 'private mount access');
      if (!['home', 'tmp', 'dependency', 'cache', 'output'].includes(mount.purpose as string)) mismatch('private mount purpose is invalid');
    } else mismatch('untyped sandbox mount');
  }
  return value as SandboxMountV1[];
}

export function decodeWorkerSandboxLaunchSpec(value: unknown): WorkerSpec {
  return decodeLinuxLaunchSpec(value, 'worker_activation') as WorkerSpec;
}
/** Retained data only; productive creation still requires the branded closure. */
export function decodeBuiltinEditSandboxLaunchSpec(value: unknown): EditSpec {
  const spec = decodeLinuxLaunchSpec(value, 'tool') as EditSpec;
  literal(spec.processInvocation.recipe, 'cliq-tool-launch-v1', 'original edit recipe');
  return spec;
}
export function decodeBuiltinScriptSandboxLaunchSpec(value: unknown): EditSpec {
  const spec = decodeLinuxLaunchSpec(value, 'tool') as EditSpec;
  literal(spec.processInvocation.recipe, 'cliq-builtin-tools-v1', 'builtin script recipe');
  return spec;
}
/** Retained data only; a decoder cannot mint the native verifier brand. */
export function decodeVerifierSandboxLaunchSpec(value: unknown): VerifierSpec {
  return decodeLinuxLaunchSpec(value, 'verifier') as VerifierSpec;
}
function decodeLinuxLaunchSpec(value: unknown, purpose: 'worker_activation' | 'tool' | 'verifier'): WorkerSpec | EditSpec | VerifierSpec {
  const spec = record(value, ['schemaVersion', 'format', 'runtime', 'executable', 'environment', 'filesystem', 'mounts', 'mountsDigest',
    'sandboxProfileRef', 'sandboxProfileDigest', 'resources', 'resourcesDigest', 'containmentPlanRef', 'containmentPlanDigest', 'createdAt',
    'launchSpecDigest', 'owner', 'purpose', 'processInvocation', ...(purpose !== 'worker_activation'
      ? ['operationGrantRef', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'parentWorkerContainmentRef'] : [])], 'launch spec');
  literal(spec.schemaVersion, 1, 'launch schema'); literal(spec.format, 'cliq-sandbox-launch-v1', 'launch format');
  literal(spec.purpose, purpose, 'launch purpose');
  if (purpose === 'worker_activation') workerOwner(spec.owner);
  else {
    invocationOwner(spec.owner);
    for (const member of ['operationGrantRef', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'parentWorkerContainmentRef']) digest(spec[member], member);
  }
  const runtime = record(spec.runtime, ['runtimeBundleRef', 'runtimeBundleManifestDigest', 'sandboxBackend', 'toolchain', 'launcher', 'runtimeDigest'], 'launch runtime');
  const script = purpose === 'tool' && (spec.processInvocation as { recipe?: unknown } | null)?.recipe === 'cliq-builtin-tools-v1';
  const guest = purpose === 'verifier' || script;
  digest(runtime.runtimeBundleRef, 'runtime bundle ref'); digest(runtime.runtimeBundleManifestDigest, 'runtime bundle digest');
  literal(runtime.sandboxBackend, 'linux_namespace', 'worker runtime backend');
  const toolchain = record(runtime.toolchain, guest
    ? ['kind', 'guestToolchainManifestRef', 'guestToolchainManifestDigest', 'guestImageRef', 'guestImageDigest'] : ['kind'], 'Linux toolchain');
  literal(toolchain.kind, guest ? 'guest_toolchain' : 'none', 'Linux toolchain');
  if (guest) for (const key of ['guestToolchainManifestRef', 'guestToolchainManifestDigest', 'guestImageRef', 'guestImageDigest']) digest(toolchain[key], key);
  const launcher = record(runtime.launcher, ['executableId', 'executableDigest'], 'sandbox launcher'); text(launcher.executableId, 'launcher id'); digest(launcher.executableDigest, 'launcher digest');
  rehash(runtime, 'runtimeDigest', 'launch runtime');
  const executable = record(spec.executable, guest
    ? ['kind', 'guestToolchainManifestRef', 'guestToolchainManifestDigest', 'toolId', 'role', 'executionPath', 'executableDigest']
    : ['kind', 'runtimeBundleRef', 'runtimeBundleManifestDigest', 'executableId', 'role', 'executionPath', 'executableDigest'], 'worker executable');
  literal(executable.kind, guest ? 'guest_toolchain' : 'runtime_bundle', 'Linux executable source');
  literal(executable.role, purpose === 'worker_activation' ? 'worker' : purpose === 'verifier' ? 'verifier' : script ? 'tool' : 'tool_adapter', 'executable role');
  if (guest) {
    digest(executable.guestToolchainManifestRef, 'guest manifest ref'); digest(executable.guestToolchainManifestDigest, 'guest manifest digest'); text(executable.toolId, 'guest tool id');
  } else {
    digest(executable.runtimeBundleRef, 'worker bundle ref'); digest(executable.runtimeBundleManifestDigest, 'worker bundle digest'); text(executable.executableId, 'worker executable id');
  }
  absolute(executable.executionPath, 'worker executable path'); digest(executable.executableDigest, 'worker executable digest');
  const invocation = record(spec.processInvocation, purpose === 'worker_activation'
    ? ['kind', 'purpose', 'recipe', 'runtimeSource', 'executableSource', 'argvSource', 'cwdSource', 'stdio']
    : ['kind', 'purpose', 'recipe', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'argvCwdSource', 'stdio',
      ...(script ? ['privateGitProtection'] : [])], 'process recipe');
  const recipe = purpose === 'worker_activation' ? { kind: 'worker_entrypoint', purpose, recipe: 'cliq-worker-entrypoint-v1',
    runtimeSource: 'launch_runtime', executableSource: 'launch_executable', argvSource: 'fixed_empty', cwdSource: 'generation_root' }
    : { kind: 'run_request', purpose, recipe: purpose === 'verifier' ? 'cliq-verifier-command-v1' : script ? 'cliq-builtin-tools-v1' : 'cliq-tool-launch-v1', requestRef: spec.requestRef, requestDigest: spec.requestDigest,
      targetRef: spec.targetRef, targetDigest: spec.targetDigest, argvCwdSource: 'trusted_recipe_decode_of_request_and_target',
      ...(script ? { privateGitProtection: 'existing_read_only' } : {}) };
  for (const [key, expected] of Object.entries(recipe)) literal(invocation[key], expected, `process recipe ${key}`);
  equal(record(invocation.stdio, ['stdin', 'stdout', 'stderr', 'extraFileDescriptors'], 'worker stdio'),
    { stdin: 'closed', stdout: 'captured', stderr: 'captured', extraFileDescriptors: purpose === 'worker_activation'
      ? 'authenticated_worker_channel_only' : 'authenticated_operation_channel_only' }, 'process stdio');
  environment(spec.environment);
  const filesystem = record(spec.filesystem, ['kind', 'generationRef', 'access', 'sourceProjectionRef', 'independentGit'], 'worker filesystem');
  literal(filesystem.kind, 'run_generation', 'filesystem kind');
  if (script) {
    if (filesystem.access !== 'read_only' && filesystem.access !== 'read_write') mismatch('script has an invalid closed access envelope');
  } else literal(filesystem.access, purpose === 'worker_activation' ? 'preactivated_readonly' : purpose === 'verifier' ? 'read_only' : 'read_write', 'filesystem access');
  digest(filesystem.generationRef, 'worker generation'); digest(filesystem.sourceProjectionRef, 'worker projection'); literal(filesystem.independentGit, true, 'worker private Git');
  mounts(spec.mounts, purpose === 'tool'); literal(digest(spec.mountsDigest, 'mount digest'), canonicalSha256(spec.mounts), 'mount digest');
  resources(spec.resources); literal(digest(spec.resourcesDigest, 'resources digest'), canonicalSha256(spec.resources), 'resources digest');
  for (const member of ['sandboxProfileRef', 'sandboxProfileDigest', 'containmentPlanRef', 'containmentPlanDigest']) digest(spec[member], member);
  time(spec.createdAt, 'launch creation'); rehash(spec, 'launchSpecDigest', 'worker launch');
  return spec as WorkerSpec | EditSpec | VerifierSpec;
}

export type WorkerLaunchClosureInput = {
  run: Run; workspaceGenerationRef: string; containmentPlanRef: string; sandboxLaunchSpecRef: string; launchId: string; spawnNonceDigest: string;
};

async function readExecutionEnvironment(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1, runSpec: RunSpec,
  spec: WorkerSpec | EditSpec | VerifierSpec, generation: WorkspaceGenerationIdentityV1) {
  const [assemblyValue, profileValue, bundle, lockValue, rootValue] = await joinResourceOperations([
    readCanonicalArtifact(artifacts, runSpec.assemblyRef), readCanonicalArtifact(artifacts, runSpec.sandboxProfileRef),
    readCanonicalArtifact<RuntimeBundleManifest>(artifacts, owner.runtimeBundleRef), readCanonicalArtifact(artifacts, owner.stateLockIdentityRef),
    readCanonicalArtifact(artifacts, generation.locator.stateRootIdentityRef)
  ]);
  let assembly: RunAssemblyV1;
  try { assembly = decodeRetainedRunAssembly(assemblyValue); } catch { mismatch('retained execution assembly is invalid'); }
  const profile = decodeSandboxProfile(profileValue);
  const lock = decodeStateLockIdentity(lockValue); const root = decodeStateRootIdentity(rootValue);
  if (root.identityDigest !== generation.locator.stateRootIdentityDigest || lock.stateRootIdentityRef !== generation.locator.stateRootIdentityRef || lock.stateRootIdentityDigest !== root.identityDigest) mismatch('generation does not belong to the current held state root');
  if (bundle.schemaVersion !== 1 || !Array.isArray(bundle.entries) || bundle.manifestDigest !== owner.runtimeBundleManifestDigest) mismatch('current StateOwner does not retain a signed execution bundle');
  const { signature: _signature, manifestDigest: _manifestDigest, ...bundleCore } = bundle;
  literal(bundle.manifestDigest, canonicalSha256(bundleCore), 'retained bundle digest');
  if (spec.executable.kind !== 'runtime_bundle' && !((spec.purpose === 'verifier' || spec.purpose === 'tool' &&
      spec.processInvocation.recipe === 'cliq-builtin-tools-v1') && spec.executable.kind === 'guest_toolchain')) mismatch('Linux executable does not resolve a supported signed source');
  for (const source of [assembly.runtime, spec.runtime, ...(spec.executable.kind === 'runtime_bundle' ? [spec.executable] : [])]) {
    if (source.runtimeBundleRef !== owner.runtimeBundleRef || source.runtimeBundleManifestDigest !== owner.runtimeBundleManifestDigest) mismatch('execution runtime is not the current verified StateOwner bundle');
  }
  literal(assembly.runtime.sandboxBackend, 'linux_namespace', 'assembly backend'); literal(profile.backend, assembly.runtime.sandboxBackend, 'profile backend');
  if (!profile.allowedOwners.includes(spec.owner.kind)) mismatch('sandbox profile forbids this launch owner');
  literal(spec.sandboxProfileRef, runSpec.sandboxProfileRef, 'frozen profile ref'); literal(spec.sandboxProfileDigest, profile.profileDigest, 'frozen profile digest'); equal(spec.resources, profile.resources, 'frozen resources');
  const selected = bundle.entries.find((entry) => spec.executable.kind === 'runtime_bundle' && entry.entryId === spec.executable.executableId);
  const launcher = bundle.entries.find((entry) => entry.entryId === spec.runtime.launcher.executableId);
  if ((spec.executable.kind === 'runtime_bundle' && (selected?.role !== spec.executable.role || !selected.executable || selected.digest !== spec.executable.executableDigest)) ||
      launcher?.role !== 'platform_helper' || !launcher.executable || launcher.digest !== spec.runtime.launcher.executableDigest) mismatch('executable or launcher does not resolve the exact signed entry');
  for (const mount of spec.mounts) {
    if (mount.kind === 'cas_artifact') await artifacts.readBytes(mount.artifactRef);
    if (mount.kind === 'run_generation' && (spec.filesystem.kind !== 'run_generation' || mount.generationRef !== spec.filesystem.generationRef)) mismatch('mount selects another generation');
  }
  for (const [purpose, target] of [['home', spec.environment.home], ['tmp', spec.environment.tmpdir]] as const) {
    if (!spec.mounts.some((mount) => mount.kind === 'private_ephemeral' && mount.purpose === purpose && mount.targetPath === target)) mismatch(`sandbox ${purpose} has no private ephemeral root`);
  }
  return { assembly, bundle, profile };
}

/** Validate retained artifacts against the already verified current StateOwner bundle. Does not observe a native launch. */
export async function readWorkerLaunchClosure(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1, input: WorkerLaunchClosureInput) {
  input = immutableSnapshot(input);
  const expectedOwner: WorkerOwner = { kind: 'worker_activation', runId: input.run.id, intendedLeaseEpoch: input.run.leaseEpoch + 1, workerLaunchId: input.launchId };
  return readWorkerExecutionClosure(artifacts, owner, input, expectedOwner, input.run.latestCheckpointId);
}

async function readWorkerExecutionClosure(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1, input: WorkerLaunchClosureInput,
  expectedOwner: WorkerOwner, sourceCheckpointId: string) {
  const [planValue, specValue, generationValue, runSpecValue] = await joinResourceOperations([
    readCanonicalArtifact(artifacts, input.containmentPlanRef), readCanonicalArtifact(artifacts, input.sandboxLaunchSpecRef),
    readCanonicalArtifact(artifacts, input.workspaceGenerationRef), readCanonicalArtifact(artifacts, input.run.specRef)
  ]);
  const plan = decodeWorkerContainmentPlan(planValue);
  const spec = decodeWorkerSandboxLaunchSpec(specValue);
  const generation = decodeWorkspaceGenerationIdentity(generationValue);
  const runSpec = decodeRunSpec(runSpecValue);
  equal(plan.owner, expectedOwner, 'plan owner'); equal(spec.owner, expectedOwner, 'launch owner');
  equal(plan.filesystemBinding, { kind: 'run-generation', generationRef: input.workspaceGenerationRef }, 'plan generation');
  literal(plan.launchNonceDigest, input.spawnNonceDigest, 'plan spawn nonce'); literal(spec.containmentPlanRef, input.containmentPlanRef, 'launch plan ref'); literal(spec.containmentPlanDigest, plan.planDigest, 'launch plan digest');
  equal(spec.filesystem, { kind: 'run_generation', generationRef: input.workspaceGenerationRef, access: 'preactivated_readonly', sourceProjectionRef: runSpec.sourceProjectionRef, independentGit: true }, 'launch generation envelope');
  if (generation.runId !== input.run.id || generation.sourceCheckpointId !== sourceCheckpointId || generation.locator.kind !== 'linux_directory') mismatch('generation does not bind this Run/checkpoint/Linux locator');
  const { assembly, bundle, profile } = await readExecutionEnvironment(artifacts, owner, runSpec, spec, generation);
  if (spec.executable.kind !== 'runtime_bundle' || spec.executable.executableId !== assembly.runtime.workerExecutableId ||
      spec.executable.executableDigest !== assembly.runtime.workerExecutableDigest) mismatch('worker does not resolve the assembly entry');
  return mint({ spec, plan, generation, runSpec, assembly, bundle, profile,
    sandboxLaunchSpecRef: input.sandboxLaunchSpecRef, containmentPlanRef: input.containmentPlanRef, workspaceGenerationRef: input.workspaceGenerationRef }, workerClosures);
}

export type WorkerLaunchClosure = Awaited<ReturnType<typeof readWorkerLaunchClosure>>;

/** Recovery observes an old blocked launch; it never adopts its handshake or
 * substitutes the successor's lease/spawner for the retained reservation. */
export async function readPreactivationWorkerLaunchClosure(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1, input: {
  run: Run; launch: WorkerLaunch; generation: WorkspaceGenerationStateV1;
}) {
  input = immutableSnapshot(input);
  const { run, launch, generation } = input;
  if (run.status !== 'queued' || run.activeWorkerLaunchId !== undefined ||
      !['reserved', 'preactivated'].includes(launch.phase) || launch.runId !== run.id || launch.leaseVersion !== 0 ||
      launch.generationWriteState !== 'preactivated_readonly' || generation.phase !== 'preactivated_readonly' ||
      generation.runId !== run.id || generation.generationRef !== launch.workspaceGenerationRef ||
      generation.sourceCheckpointId !== run.latestCheckpointId) mismatch('preactivation retirement requires its exact lease-free queued launch and readonly generation');
  const closure = await readWorkerExecutionClosure(artifacts, owner, { run, ...launch }, {
    kind: 'worker_activation', runId: run.id, intendedLeaseEpoch: run.leaseEpoch + 1, workerLaunchId: launch.launchId
  }, generation.sourceCheckpointId);
  if (closure.generation.identityDigest !== generation.generationIdentityDigest ||
      closure.generation.generationId !== generation.generationId ||
      closure.generation.sourceWorkspaceStateRef !== generation.sourceWorkspaceStateRef ||
      closure.generation.sourceWorkspaceStateDigest !== generation.sourceWorkspaceStateDigest) mismatch('preactivation generation differs from its immutable source');
  return closure;
}

/** Inspect the historical launch as retained, never as a fabricated future activation. */
export async function readRetainedWorkerLaunchClosure(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1, input: {
  run: Run; launch: WorkerLaunch; generation: WorkspaceGenerationStateV1;
}) {
  input = immutableSnapshot(input);
  const { run, launch, generation } = input;
  if (run.status !== 'waiting' || run.waitingReason !== 'reconciliation' || !run.waitingOnRef || run.activeWorkerLaunchId !== undefined ||
      launch.phase !== 'reconciling' || launch.runId !== run.id || launch.leaseEpoch !== run.leaseEpoch || !launch.processContainmentRef ||
      !launch.workerIdentityDigest || launch.generationWriteState !== 'fenced_reconciling' || generation.phase !== 'fenced_reconciling' ||
      generation.runId !== run.id || generation.generationRef !== launch.workspaceGenerationRef || generation.activeWorkerLaunchId !== launch.launchId ||
      generation.leaseEpoch !== launch.leaseEpoch || generation.waitingSubjectRef !== run.waitingOnRef || generation.waitingSubjectDigest !== run.waitingOnRef) {
    mismatch('retained worker inspection requires its exact fenced Run, launch and generation');
  }
  const closure = await readWorkerExecutionClosure(artifacts, owner, { run, ...launch }, {
    kind: 'worker_activation', runId: run.id, intendedLeaseEpoch: launch.leaseEpoch, workerLaunchId: launch.launchId
  }, generation.sourceCheckpointId);
  if (closure.generation.identityDigest !== generation.generationIdentityDigest || closure.generation.generationId !== generation.generationId ||
      closure.generation.sourceWorkspaceStateRef !== generation.sourceWorkspaceStateRef ||
      closure.generation.sourceWorkspaceStateDigest !== generation.sourceWorkspaceStateDigest) mismatch('retained generation differs from its immutable source identity');
  const [containmentValue, identityValue] = await joinResourceOperations([readCanonicalArtifact(artifacts, launch.processContainmentRef),
    readCanonicalArtifact(artifacts, launch.workerIdentityDigest)]);
  const containment = decodeWorkerProcessContainment(containmentValue);
  const identity = decodeWorkerIdentity(identityValue);
  assertActualWorkerClosure(closure, containment, identity, launch, launch.processContainmentRef, launch.supervisorInstanceId);
  return closure;
}

/** Current closed-quarantine inspection only. It reconstructs the original
 * launch, never fabricates a fenced Run or grants activation of the old tree. */
export async function readQuarantinedWorkerLaunchClosure(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, input: { run: Run; launch: WorkerLaunch; generation: WorkspaceGenerationStateV1 }) {
  input = immutableSnapshot(input);
  const { run, launch, generation } = input;
  const currentOwner = assertActiveStateOwner(driver, owner);
  if (launch.retirementKind === 'preparation') {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'preparation retirement requires its exact owning resource closure');
  }
  if (launch.phase !== 'retired') mismatch('retirement inspection requires its exact closed original launch');
  function current() {
    assertActiveStateOwner(driver, owner);
    equal(readRun(driver, run.id), run, 'quarantined retirement current Run');
    equal(readRequiredWorkerLaunch(driver, launch.launchId), launch, 'quarantined retirement current launch');
    equal(readRequiredWorkspaceGenerationByRef(driver, generation.generationRef), generation, 'quarantined retirement current generation');
  }
  current();
  if (generation.phase !== 'quarantined') mismatch('retirement inspection requires its exact original quarantine');
  const quarantine = await readCanonicalArtifact<import('../kernel/types.js').WorkspaceGenerationQuarantineEvidenceV1>(artifacts, generation.quarantineEvidenceRef);
  if (quarantine.reason === 'launch_aborted' || quarantine.reason === 'launch_died_before_activation') {
    if (run.status !== 'queued' || run.activeWorkerLaunchId !== undefined || generation.phase !== 'quarantined')
      mismatch('preactivation quarantine inspection requires its exact lease-free queued cut');
    await validatePreactivationQuarantine(artifacts, driver, run, generation, quarantine);
    const plan = decodeWorkerContainmentPlan(await readCanonicalArtifact(artifacts, launch.containmentPlanRef));
    if (quarantine.workerLaunchId !== launch.launchId) mismatch('preactivation retirement substitutes its original launch');
    // The original plan owns this epoch and source Checkpoint. A successor
    // may already have advanced both; never fabricate an old Run to read it.
    const closure = await readWorkerExecutionClosure(artifacts, currentOwner, { run, ...launch }, plan.owner, generation.sourceCheckpointId);
    if (closure.generation.identityDigest !== generation.generationIdentityDigest || closure.generation.generationId !== generation.generationId ||
        closure.generation.sourceWorkspaceStateRef !== generation.sourceWorkspaceStateRef ||
        closure.generation.sourceWorkspaceStateDigest !== generation.sourceWorkspaceStateDigest)
      mismatch('preactivation retirement substitutes its immutable generation');
    current(); return closure;
  }
  if (run.status !== 'queued' || run.activeWorkerLaunchId !== undefined || launch.phase !== 'retired' ||
      launch.generationWriteState !== 'fenced_reconciling' || launch.runId !== run.id || !launch.leaseEpoch || launch.leaseEpoch > run.leaseEpoch ||
      !launch.workerIdentityDigest || !launch.processContainmentRef || !launch.retirementEvidenceRef ||
      generation.phase !== 'quarantined' || generation.runId !== run.id || generation.generationRef !== launch.workspaceGenerationRef)
    mismatch('retirement inspection requires its exact closed original quarantine');
  if (quarantine.reason !== 'worker_recovery' || quarantine.fromPhase !== 'fenced_reconciling' ||
      quarantine.runId !== run.id || quarantine.generationRef !== generation.generationRef ||
      quarantine.generationIdentityDigest !== generation.generationIdentityDigest || quarantine.evidenceDigest !== generation.quarantineEvidenceDigest ||
      quarantine.evidenceDigest !== digestOmitting(quarantine, 'evidenceDigest')) mismatch('retirement has no exact original worker quarantine');
  const recovery = await readCanonicalArtifact<import('../kernel/types.js').WorkerRecoveryEvidenceV1>(artifacts, quarantine.workerRecoveryEvidenceRef);
  const wrapper = await readCanonicalArtifact<import('../kernel/types.js').ReconciliationProbeEvidenceV1>(artifacts, launch.retirementEvidenceRef);
  if (recovery.evidenceDigest !== quarantine.workerRecoveryEvidenceDigest || recovery.evidenceDigest !== digestOmitting(recovery, 'evidenceDigest') ||
      recovery.runId !== run.id || recovery.oldWorkerLaunchId !== launch.launchId || recovery.oldLeaseEpoch !== launch.leaseEpoch ||
      recovery.processContainmentRef !== launch.processContainmentRef || recovery.oldWorkerIdentityDigest !== launch.workerIdentityDigest ||
      recovery.workspaceGenerationRef !== generation.generationRef || wrapper.outcome !== 'subject_observation' ||
      wrapper.subjectEvidenceKind !== 'worker_recovery' || wrapper.subjectEvidenceRef !== quarantine.workerRecoveryEvidenceRef ||
      wrapper.subjectEvidenceDigest !== recovery.evidenceDigest || wrapper.evidenceDigest !== digestOmitting(wrapper, 'evidenceDigest'))
    mismatch('retirement substitutes its retained recovery and original launch');
  const closure = await readWorkerExecutionClosure(artifacts, currentOwner, { run, ...launch },
    { kind: 'worker_activation', runId: run.id, intendedLeaseEpoch: launch.leaseEpoch, workerLaunchId: launch.launchId }, generation.sourceCheckpointId);
  const containment = decodeWorkerProcessContainment(await readCanonicalArtifact(artifacts, launch.processContainmentRef));
  const identity = decodeWorkerIdentity(await readCanonicalArtifact(artifacts, launch.workerIdentityDigest));
  if (closure.generation.identityDigest !== generation.generationIdentityDigest || closure.generation.generationId !== generation.generationId ||
      closure.generation.sourceWorkspaceStateRef !== generation.sourceWorkspaceStateRef ||
      closure.generation.sourceWorkspaceStateDigest !== generation.sourceWorkspaceStateDigest) mismatch('retirement substitutes its immutable generation');
  assertActualWorkerClosure(closure, containment, identity, launch, launch.processContainmentRef, launch.supervisorInstanceId);
  current();
  return closure;
}

export type BuiltinEditLaunchClosureInput = {
  run: Run; launch: WorkerLaunch; generation: WorkspaceGenerationStateV1; prepared: InvocationJournalEntry;
  request: ToolRequestV1; target: ToolTargetV1; grant: ToolOperationGrantV1; call: ToolCallInputV1;
  dispatchId: string; sandboxLaunchSpecRef: string;
};

/** Consumes the owning reducer's reproduced grant/request/target; never evaluates permission or observes a native process. */
export async function readBuiltinEditLaunchClosure(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1, input: BuiltinEditLaunchClosureInput) {
  const result = await readBuiltinExecutionClosure(artifacts, owner, input, 'edit');
  return mint(result, editClosures);
}

async function readBuiltinExecutionClosure(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1,
  input: BuiltinEditLaunchClosureInput, kind: 'edit' | 'script') {
  input = immutableSnapshot(input);
  const { run, launch, generation: row, prepared, request, target, grant, call } = input;
  if (run.status !== 'running' || run.activeWorkerLaunchId !== launch.launchId || launch.phase !== 'activated' || launch.runId !== run.id ||
      launch.leaseEpoch !== run.leaseEpoch || launch.supervisorInstanceId !== owner.supervisorInstanceId || launch.generationWriteState !== 'active' ||
      row.phase !== 'active' || row.generationRef !== launch.workspaceGenerationRef || row.activeWorkerLaunchId !== launch.launchId || row.leaseEpoch !== run.leaseEpoch ||
      prepared.phase !== 'prepared' || prepared.opKind !== 'tool' || prepared.runId !== run.id || prepared.leaseEpoch !== run.leaseEpoch ||
      prepared.requestRef !== canonicalSha256(request) || prepared.target !== canonicalSha256(target) || prepared.grantRef !== canonicalSha256(grant) ||
      (kind === 'edit' ? request.toolName !== 'edit' || target.execution.kind !== 'builtin' || target.execution.adapterId !== 'edit'
        : !BUILTIN_SCRIPT_TOOL_NAMES.some(name => name === request.toolName) || target.execution.kind !== 'builtin_script') ||
      target.toolName !== request.toolName ||
      request.requestDigest !== digestOmitting(request, 'requestDigest') || target.targetDigest !== digestOmitting(target, 'targetDigest') ||
      grant.grantDigest !== digestOmitting(grant, 'grantDigest') || call.inputDigest !== digestOmitting(call, 'inputDigest') ||
      request.runId !== run.id || request.opId !== prepared.opId || request.targetRef !== prepared.target || request.targetDigest !== target.targetDigest ||
      grant.requestRef !== prepared.requestRef || grant.requestDigest !== request.requestDigest || grant.targetRef !== prepared.target || grant.targetDigest !== target.targetDigest ||
      grant.subject.callId !== call.callId || grant.subject.callIndex !== call.index || grant.subject.batchItemId !== request.batchItemId ||
      grant.subject.toolName !== request.toolName || grant.subject.toolContractDigest !== target.toolContractDigest ||
      grant.subject.replayClass !== prepared.replayClass || request.callId !== call.callId || request.callIndex !== call.index ||
      request.inputRef !== canonicalSha256(call) || call.disposition !== 'resolved' || call.toolName !== request.toolName || call.inputDigest !== request.inputDigest) mismatch('builtin launch does not bind the current validated preparation and activation');
  text(input.dispatchId, 'edit dispatch id');
  const [specValue, identityValue, runSpecValue] = await joinResourceOperations([readCanonicalArtifact(artifacts, input.sandboxLaunchSpecRef),
    readCanonicalArtifact(artifacts, row.generationRef), readCanonicalArtifact(artifacts, run.specRef)]);
  const spec = kind === 'edit' ? decodeBuiltinEditSandboxLaunchSpec(specValue) : decodeBuiltinScriptSandboxLaunchSpec(specValue);
  const plan = decodeLinuxContainmentPlan(await readCanonicalArtifact(artifacts, spec.containmentPlanRef), 'run_invocation');
  const generation = decodeWorkspaceGenerationIdentity(identityValue); const runSpec = decodeRunSpec(runSpecValue);
  const expectedOwner: InvocationOwner = { kind: 'run_invocation', runId: run.id, intendedLeaseEpoch: run.leaseEpoch,
    workerLaunchId: launch.launchId, opId: prepared.opId, attempt: prepared.attempt, dispatchId: input.dispatchId };
  equal(spec.owner, expectedOwner, 'edit launch owner'); equal(plan.owner, expectedOwner, 'edit plan owner');
  literal(spec.containmentPlanDigest, plan.planDigest, 'edit plan digest'); literal(spec.parentWorkerContainmentRef, launch.processContainmentRef, 'edit parent worker');
  literal(plan.parentContainmentRef, launch.processContainmentRef, 'edit plan parent worker');
  equal(plan.filesystemBinding, { kind: 'run-generation', generationRef: row.generationRef }, 'edit plan generation');
  equal(spec.filesystem, { kind: 'run_generation', generationRef: row.generationRef,
    access: kind === 'edit' || request.toolName === 'bash' ? 'read_write' : 'read_only',
    sourceProjectionRef: runSpec.sourceProjectionRef, independentGit: true }, 'exact builtin access envelope');
  if (generation.runId !== run.id || generation.identityDigest !== row.generationIdentityDigest || generation.generationId !== row.generationId ||
      generation.sourceCheckpointId !== row.sourceCheckpointId || generation.sourceWorkspaceStateRef !== row.sourceWorkspaceStateRef ||
      generation.sourceWorkspaceStateDigest !== row.sourceWorkspaceStateDigest) mismatch('edit generation differs from its active immutable identity');
  for (const [key, expected] of Object.entries({ operationGrantRef: prepared.grantRef, requestRef: prepared.requestRef,
    requestDigest: request.requestDigest, targetRef: prepared.target, targetDigest: target.targetDigest })) literal(spec[key as keyof EditSpec], expected, `edit ${key}`);
  if (kind === 'edit' && (target.execution.kind !== 'builtin' || spec.executable.kind !== 'runtime_bundle' ||
      spec.executable.executableId !== target.execution.adapterId || spec.executable.executableDigest !== target.execution.adapterCodeDigest)) mismatch('edit executable differs from the exact signed target adapter');
  const environment = await readExecutionEnvironment(artifacts, owner, runSpec, spec, generation);
  if (request.assemblyRef !== runSpec.assemblyRef) mismatch('edit request selects another assembly');
  const parent = decodeWorkerProcessContainment(await readCanonicalArtifact(artifacts, launch.processContainmentRef!));
  equal(parent.owner, { kind: 'worker_activation', runId: run.id, intendedLeaseEpoch: run.leaseEpoch, workerLaunchId: launch.launchId }, 'edit actual parent activation');
  equal(parent.filesystemBinding, plan.filesystemBinding, 'edit parent generation');
  literal(parent.planRef, launch.containmentPlanRef, 'edit parent plan'); literal(parent.sandboxLaunchSpecRef, launch.sandboxLaunchSpecRef, 'edit parent launch');
  if (parent.backend.kind !== 'linux' || plan.backend.kind !== 'linux' || !plan.backend.cgroupPath.startsWith(`${parent.backend.cgroupPath}/`)) mismatch('edit containment is not nested beneath the exact worker writer domain');
  // The literal recipe has no caller argv/cwd/environment overrides. The native adapter
  // must still derive paths from the held generation and observe the actual child domain.
  return { spec, plan, generation, runSpec, ...environment, request, target, grant, call,
    run, launch, prepared, sandboxLaunchSpecRef: input.sandboxLaunchSpecRef };
}

export type BuiltinEditLaunchClosure = Awaited<ReturnType<typeof readBuiltinEditLaunchClosure>>;

export async function readBuiltinScriptLaunchClosure(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1,
  input: BuiltinEditLaunchClosureInput, releaseKeys: readonly ReleaseTrustKey[], signal?: AbortSignal) {
  signal?.throwIfAborted();
  const result = await readBuiltinExecutionClosure(artifacts, owner, input, 'script');
  const execution = result.target.execution;
  if (execution.kind !== 'builtin_script') mismatch('script launch cannot borrow an executable adapter identity');
  const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, result.runSpec.policyRef);
  const profile = await readCanonicalArtifact<PolicyEngineProfileV1>(artifacts, policy.engine.profileRef);
  const manifest = await readCanonicalArtifact<ToolContractManifestV1>(artifacts, result.assembly.tools.manifestRef);
  if (manifest.manifestDigest !== result.assembly.tools.manifestDigest || digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest)
    mismatch('script launch substitutes its original tool manifest');
  const entry = manifest.entries.find(entry => entry.name === result.call.toolName);
  if (!entry || canonicalSha256(entry) !== result.target.toolContractDigest || result.call.inputSchemaRef !== entry.inputSchemaRef ||
      result.call.inputSchemaDigest !== entry.inputSchemaDigest) mismatch('script launch substitutes its exact tool contract');
  equal(entry.execution, execution, 'script contract execution');
  const inputSchema = await readCanonicalArtifact(artifacts, entry.inputSchemaRef);
  const resolver = loadToolContracts([{ ...entry, inputSchema }]);
  const projection = resolver.projectInvocation({ callId: result.call.callId, index: result.call.index,
    toolName: result.call.toolName, input: result.call.value! });
  if (projection.kind !== 'tool') mismatch('script launch requires a normalized ordinary tool call');
  equal(projection.invocation.input, result.call.value, 'script normalized call');
  const toolchain = await readToolRuntimeAuthority(artifacts, { assembly: result.assembly, bundle: result.bundle,
    policy, profile, tools: manifest.entries, releaseKeys, resources: result.spec.resources }, signal);
  if (!toolchain) mismatch('script launch has no complete original signed guest image');
  equal(result.spec.executable, { kind: 'guest_toolchain', guestToolchainManifestRef: toolchain.manifestRef,
    guestToolchainManifestDigest: toolchain.manifest.manifestDigest, toolId: 'node', role: 'tool',
    executionPath: '/usr/bin/node', executableDigest: toolchain.manifest.node.digest }, 'script guest executable');
  equal(result.spec.runtime.toolchain, { kind: 'guest_toolchain', guestToolchainManifestRef: toolchain.manifestRef,
    guestToolchainManifestDigest: toolchain.manifest.manifestDigest, guestImageRef: toolchain.manifest.guestImageRef,
    guestImageDigest: toolchain.manifest.guestImageDigest }, 'script runtime guest');
  const scriptEntry = result.bundle.entries.find(entry => entry.entryId === execution.adapterId)!;
  if (!isBuiltinScriptTool(result.call.toolName)) mismatch('script call selects an unsupported fixed tool');
  builtinToolInputBytes(result.call.toolName, result.call.value!, result.spec.resources);
  equal(result.spec.environment, result.call.toolName === 'bash' ? BUILTIN_SCRIPT_ENVIRONMENTS.bash : BUILTIN_SCRIPT_ENVIRONMENTS.read,
    'fixed script environment');
  equal(result.spec.mounts, BUILTIN_SCRIPT_PRIVATE_MOUNTS.map(mount => ({ ...mount,
    privateRootId: identityHash(result.spec.owner.dispatchId, mount.purpose) })), 'fixed script private mounts');
  signal?.throwIfAborted();
  return mint({ ...result, toolchain, scriptEntry }, scriptClosures);
}
export type BuiltinScriptLaunchClosure = Awaited<ReturnType<typeof readBuiltinScriptLaunchClosure>>;
export type BuiltinToolLaunchClosure = BuiltinEditLaunchClosure | BuiltinScriptLaunchClosure;

export type VerifierLaunchClosureInput = {
  run: Run; launch: WorkerLaunch; generation: WorkspaceGenerationStateV1; prepared: InvocationJournalEntry;
  request: VerifierRequestV1; target: VerifierTargetV1; grant: VerifierOperationGrantV1; evidence: VerifierPolicyChannelEvidenceV1;
  dispatchId: string; sandboxLaunchSpecRef: string;
};

/** The current owning preparation plus reproduced named policy are the only
 * entrance to this brand. It observes no native process and supplies no death
 * evidence; the physical launcher must still claim/release this exact attempt. */
export async function readVerifierLaunchClosure(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1,
  input: VerifierLaunchClosureInput, releaseKeys: readonly ReleaseTrustKey[], signal?: AbortSignal) {
  signal?.throwIfAborted(); input = immutableSnapshot(input);
  const { run, launch, generation: row, prepared, request, target, grant, evidence } = input;
  if (run.status !== 'running' || run.nextStep !== 'verify' || run.stopIntentRef !== undefined || run.cancelRequested || run.activeWorkerLaunchId !== launch.launchId ||
      launch.phase !== 'activated' || launch.runId !== run.id || launch.leaseEpoch !== run.leaseEpoch ||
      launch.supervisorInstanceId !== owner.supervisorInstanceId || launch.generationWriteState !== 'active' ||
      row.phase !== 'active' || row.generationRef !== launch.workspaceGenerationRef || row.activeWorkerLaunchId !== launch.launchId || row.leaseEpoch !== run.leaseEpoch ||
      prepared.phase !== 'prepared' || prepared.opKind !== 'verifier' || prepared.runId !== run.id || prepared.leaseEpoch !== run.leaseEpoch ||
      prepared.replayClass !== 'retry' || prepared.requestRef !== canonicalSha256(request) || prepared.target !== canonicalSha256(target) ||
      prepared.grantRef !== canonicalSha256(grant) || request.runId !== run.id || request.opId !== prepared.opId ||
      !Number.isSafeInteger(prepared.attempt) || prepared.attempt < 0 || grant.expiresAt > run.deadlineAt ||
      prepared.timestamp < grant.issuedAt || prepared.timestamp >= grant.expiresAt)
    mismatch('verifier launch does not bind its current validated preparation and activation');
  text(input.dispatchId, 'verifier dispatch id');
  const spec = decodeVerifierSandboxLaunchSpec(await readCanonicalArtifact(artifacts, input.sandboxLaunchSpecRef));
  const plan = decodeLinuxContainmentPlan(await readCanonicalArtifact(artifacts, spec.containmentPlanRef), 'run_invocation');
  const generation = decodeWorkspaceGenerationIdentity(await readCanonicalArtifact(artifacts, row.generationRef));
  const runSpec = decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef));
  if (!run.frontierRef) mismatch('verifier launch has no current frontier');
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef);
  record(frontier, ['schemaVersion', 'kind', 'phase', 'candidateItemId', 'resultSourceRef', 'verifierPlanRef', 'nextVerifierIndex', 'afterPass'], 'verifier frontier');
  if (frontier.kind !== 'verify' || frontier.phase !== 'verifiers' || frontier.candidateItemId !== target.candidateItemId ||
      frontier.verifierPlanRef !== target.verifierPlanRef || frontier.nextVerifierIndex !== target.verifierIndex ||
      frontier.schemaVersion !== 1 || frontier.resultSourceRef !== target.resultSourceRef ||
      frontier.afterPass !== (runSpec.operation === 'agent' ? 'finalize' : 'delivery_approval') ||
      request.frontierRef !== run.frontierRef || request.assemblyRef !== runSpec.assemblyRef) mismatch('verifier launch substitutes its current candidate frontier');
  const verifierPlan = decodeVerifierPlan(await readCanonicalArtifact(artifacts, target.verifierPlanRef));
  if (runSpec.dependencyPolicyRef !== undefined || verifierPlan.dependencyPlanRef !== undefined)
    mismatch('this verifier launch recipe does not implement dependency acquisition');
  const verifierSpec = decodeVerifierSpec(await readCanonicalArtifact(artifacts, runSpec.verifierSpecRef));
  const command = decodeVerifierCommand(await readCanonicalArtifact(artifacts, target.commandRef));
  const environment = decodeVerifierEnvironment(await readCanonicalArtifact(artifacts, target.environmentRef));
  const resultSource = decodeSourceManifest(await readCanonicalArtifact(artifacts, target.resultSourceRef));
  const state = decodeWorkspaceState(await readCanonicalArtifact(artifacts, generation.sourceWorkspaceStateRef));
  const projected = await readCandidateSource(artifacts, runSpec, generation.sourceWorkspaceStateRef, signal);
  if (resultSource.role !== 'result' || resultSource.manifestDigest !== target.sourceDigest || resultSource.sourceProjectionRef !== runSpec.sourceProjectionRef ||
      state.runId !== run.id || projected.sourceRef !== target.resultSourceRef || projected.source.manifestDigest !== target.sourceDigest ||
      state.sourceProjectionDigest !== resultSource.sourceProjectionDigest ||
      environment.sourceProjectionRef !== runSpec.sourceProjectionRef || environment.sourceAccess !== 'read_only' || environment.networkAccess !== 'denied')
    mismatch('verifier launch does not use its exact read-only candidate source');
  const expectedOwner: InvocationOwner = { kind: 'run_invocation', runId: run.id, intendedLeaseEpoch: run.leaseEpoch,
    workerLaunchId: launch.launchId, opId: prepared.opId, attempt: prepared.attempt, dispatchId: input.dispatchId };
  equal(spec.owner, expectedOwner, 'verifier launch owner'); equal(plan.owner, expectedOwner, 'verifier plan owner');
  literal(spec.containmentPlanDigest, plan.planDigest, 'verifier containment digest');
  literal(spec.parentWorkerContainmentRef, launch.processContainmentRef, 'verifier parent worker');
  literal(plan.parentContainmentRef, launch.processContainmentRef, 'verifier plan parent worker');
  equal(plan.filesystemBinding, { kind: 'run-generation', generationRef: row.generationRef }, 'verifier plan generation');
  equal(spec.filesystem, { kind: 'run_generation', generationRef: row.generationRef, access: 'read_only', sourceProjectionRef: runSpec.sourceProjectionRef,
    independentGit: true }, 'verifier read-only source envelope');
  if (generation.runId !== run.id || generation.identityDigest !== row.generationIdentityDigest || generation.generationId !== row.generationId ||
      generation.sourceCheckpointId !== row.sourceCheckpointId || generation.sourceWorkspaceStateRef !== row.sourceWorkspaceStateRef ||
      generation.sourceWorkspaceStateDigest !== row.sourceWorkspaceStateDigest) mismatch('verifier generation substitutes its active immutable identity');
  for (const [key, expected] of Object.entries({ operationGrantRef: prepared.grantRef, requestRef: prepared.requestRef,
    requestDigest: request.requestDigest, targetRef: prepared.target, targetDigest: target.targetDigest })) literal(spec[key as keyof VerifierSpec], expected, `verifier ${key}`);
  const execution = await readExecutionEnvironment(artifacts, owner, runSpec, spec, generation);
  const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, runSpec.policyRef);
  const profile = await readCanonicalArtifact<PolicyEngineProfileV1>(artifacts, policy.engine.profileRef);
  const tools = await readCanonicalArtifact<ToolContractManifestV1>(artifacts, execution.assembly.tools.manifestRef);
  const builtinToolchain = await readToolRuntimeAuthority(artifacts, { assembly: execution.assembly,
    bundle: execution.bundle, policy, profile, tools: tools.entries, releaseKeys, resources: spec.resources }, signal);
  const evaluator = loadVerifierPolicy({ policy, policyRef: runSpec.policyRef, assembly: execution.assembly, assemblyRef: runSpec.assemblyRef,
    principalId: policy.principalId, workspaceIdentityDigest: policy.workspaceIdentityDigest,
    context: { runId: run.id, frontierRef: run.frontierRef, assemblyRef: runSpec.assemblyRef, candidateItemId: frontier.candidateItemId,
      resultSourceRef: target.resultSourceRef, sourceDigest: resultSource.manifestDigest, verifierPlanRef: frontier.verifierPlanRef,
      plan: verifierPlan, verifierSpecRef: runSpec.verifierSpecRef, verifierSpec, verifierIndex: frontier.nextVerifierIndex, command, environment } });
  equal(evidence, evaluator.evaluate(request, target, evidence.evaluatedAt), 'verifier exact policy evidence');
  equal(grant, evaluator.grant(request, target, evidence, grant.issuedAt, grant.expiresAt), 'verifier exact operation grant');
  if (command.executable.kind !== 'guest_toolchain' || spec.executable.kind !== 'guest_toolchain' || spec.runtime.toolchain.kind !== 'guest_toolchain')
    mismatch('verifier requires its supported signed guest executable');
  const toolchain = builtinToolchain?.manifestRef === command.executable.guestToolchainManifestRef ? builtinToolchain : await readRetainedVerifierToolchain(artifacts, { bundle: execution.bundle, releaseKeys,
    guestToolchainManifestRef: command.executable.guestToolchainManifestRef, signal });
  const { abiFingerprint: _abi, ...commandExecutable } = command.executable;
  equal(commandExecutable, { kind: 'guest_toolchain', guestToolchainManifestRef: toolchain.manifestRef,
    guestToolchainManifestDigest: toolchain.manifest.manifestDigest, toolId: toolchain.manifest.node.logicalName,
    executionPath: toolchain.manifest.node.canonicalGuestPath, executableDigest: toolchain.manifest.node.digest }, 'verifier signed executable');
  literal(command.executable.abiFingerprint, toolchain.abiFingerprint, 'verifier ABI fingerprint');
  equal(spec.executable, { kind: 'guest_toolchain', guestToolchainManifestRef: toolchain.manifestRef,
    guestToolchainManifestDigest: toolchain.manifest.manifestDigest, toolId: toolchain.manifest.node.logicalName, role: 'verifier',
    executionPath: toolchain.manifest.node.canonicalGuestPath, executableDigest: toolchain.manifest.node.digest }, 'verifier launch executable');
  equal(spec.runtime.toolchain, { kind: 'guest_toolchain', guestToolchainManifestRef: toolchain.manifestRef,
    guestToolchainManifestDigest: toolchain.manifest.manifestDigest, guestImageRef: toolchain.manifest.guestImageRef,
    guestImageDigest: toolchain.manifest.guestImageDigest }, 'verifier runtime toolchain');
  if (environment.guestToolchainManifestRef !== toolchain.manifestRef || environment.guestToolchainManifestDigest !== toolchain.manifest.manifestDigest ||
      environment.runtimeBundleRef !== owner.runtimeBundleRef || environment.runtimeBundleManifestDigest !== owner.runtimeBundleManifestDigest ||
      execution.assembly.runtime.guestToolchainManifestRef !== toolchain.manifestRef || execution.assembly.runtime.guestToolchainManifestDigest !== toolchain.manifest.manifestDigest)
    mismatch('verifier frozen environment/assembly differs from its signed toolchain');
  const parent = decodeWorkerProcessContainment(await readCanonicalArtifact(artifacts, launch.processContainmentRef!));
  equal(parent.owner, { kind: 'worker_activation', runId: run.id, intendedLeaseEpoch: run.leaseEpoch, workerLaunchId: launch.launchId }, 'verifier actual parent');
  equal(parent.filesystemBinding, plan.filesystemBinding, 'verifier parent generation');
  literal(parent.planRef, launch.containmentPlanRef, 'verifier parent plan'); literal(parent.sandboxLaunchSpecRef, launch.sandboxLaunchSpecRef, 'verifier parent launch');
  if (parent.backend.kind !== 'linux' || plan.backend.kind !== 'linux' || !plan.backend.cgroupPath.startsWith(`${parent.backend.cgroupPath}/`)) mismatch('verifier containment is not nested beneath its original worker');
  signal?.throwIfAborted();
  return mint({ spec, plan, generation, runSpec, ...execution, request, target, grant, evidence, command, environment, toolchain,
    verifierEntry: verifierSpec.verifiers[frontier.nextVerifierIndex]!, run, launch, prepared, sandboxLaunchSpecRef: input.sandboxLaunchSpecRef }, verifierClosures);
}
export type VerifierLaunchClosure = Awaited<ReturnType<typeof readVerifierLaunchClosure>>;

export function decodeWorkerProcessContainment(value: unknown): ProcessContainment & { owner: WorkerOwner } {
  return decodeProcessContainment(value, 'worker_activation') as ProcessContainment & { owner: WorkerOwner };
}

/** Fixed invocation data, independent of its parent worker's lifetime. */
export function decodeBuiltinProcessContainment(value: unknown): ProcessContainment & { owner: InvocationOwner } {
  return decodeProcessContainment(value, 'run_invocation') as ProcessContainment & { owner: InvocationOwner };
}

function decodeProcessContainment(value: unknown, kind: 'worker_activation' | 'run_invocation'): ProcessContainment {
  const containment = record(value, ['schemaVersion', 'planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'owner', 'filesystemBinding', 'launchNonceDigest', 'backend', 'createdAt'], 'worker containment');
  literal(containment.schemaVersion, 1, 'containment schema');
  if (kind === 'worker_activation') workerOwner(containment.owner); else invocationOwner(containment.owner);
  filesystemBinding(containment.filesystemBinding);
  for (const key of ['planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'launchNonceDigest']) digest(containment[key], `containment ${key}`);
  const backend = record(containment.backend, ['kind', 'pidNamespaceReservationId', 'pidNamespaceId', 'cgroupPath', 'cgroupId', 'namespaceInitStartToken', 'subreaperStartToken'], 'Linux containment');
  literal(backend.kind, 'linux', 'containment backend'); absolute(backend.cgroupPath, 'containment cgroup');
  for (const key of ['pidNamespaceReservationId', 'pidNamespaceId', 'cgroupId', 'namespaceInitStartToken', 'subreaperStartToken']) text(backend[key], `containment ${key}`);
  time(containment.createdAt, 'containment creation');
  return containment as ProcessContainment;
}

export async function readWorkerPreactivationClosure(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1, input: {
  run: Run; launch: WorkerLaunch; processContainmentRef: string; identity: WorkerIdentity;
}) {
  if (input.launch.phase !== 'reserved') mismatch('worker preactivation requires its exact reserved launch');
  const closure = await readWorkerLaunchClosure(artifacts, owner, { run: input.run, ...input.launch });
  const containment = decodeWorkerProcessContainment(await readCanonicalArtifact(artifacts, input.processContainmentRef));
  assertActualWorkerClosure(closure, containment, input.identity, input.launch, input.processContainmentRef, owner.supervisorInstanceId);
  return Object.freeze({ closure, containment: immutableSnapshot(containment) });
}

function assertActualWorkerClosure(closure: WorkerLaunchClosure, containment: ReturnType<typeof decodeWorkerProcessContainment>,
  identity: WorkerIdentity, launch: WorkerLaunch, processContainmentRef: string, supervisorInstanceId: string): void {
  literal(containment.planRef, launch.containmentPlanRef, 'actual containment plan');
  literal(containment.sandboxLaunchSpecRef, launch.sandboxLaunchSpecRef, 'actual containment launch');
  literal(containment.sandboxLaunchSpecDigest, closure.spec.launchSpecDigest, 'actual containment launch digest');
  equal(containment.owner, closure.plan.owner, 'actual containment owner'); equal(containment.filesystemBinding, closure.plan.filesystemBinding, 'actual containment generation');
  literal(containment.launchNonceDigest, closure.plan.launchNonceDigest, 'actual containment nonce');
  if (containment.backend.kind !== 'linux' || closure.plan.backend.kind !== 'linux' || containment.backend.cgroupPath !== closure.plan.backend.cgroupPath ||
      containment.backend.pidNamespaceReservationId !== closure.plan.backend.pidNamespaceReservationId || containment.backend.subreaperStartToken !== closure.plan.backend.subreaperStartToken) mismatch('actual containment differs from the reserved backend locator');
  if (identity.executableRealpath !== (closure.spec.executable as { executionPath: string }).executionPath || identity.executableDigest !== (closure.spec.executable as { executableDigest: string }).executableDigest ||
      identity.processContainmentRef !== processContainmentRef || identity.launchId !== launch.launchId ||
      identity.intendedLeaseEpoch !== closure.plan.owner.intendedLeaseEpoch || identity.supervisorInstanceId !== supervisorInstanceId ||
      identity.spawnNonceDigest !== launch.spawnNonceDigest || identity.activationNonceDigest !== launch.activationNonceDigest) mismatch('worker identity differs from the closed reserved launch');
}
