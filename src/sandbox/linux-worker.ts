import { KernelStorageError, ResourceRetirementError } from '../state/errors.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { createHash } from 'node:crypto';
import { constants, fstatSync, readSync } from 'node:fs';
import { open, type FileHandle } from 'node:fs/promises';
import { Module } from 'node:module';
import { constants as osConstants } from 'node:os';
import path from 'node:path';
import { types as utilTypes } from 'node:util';
import { setImmediate, setTimeout as delay } from 'node:timers/promises';
import { assertArtifactRef, normalizeAbsolutePath } from '../kernel/identity.js';
import type { ProcessContainment, SanitizedSandboxEnvironmentV1 } from '../kernel/execution.js';
import type { WorkerIdentity, WorkerLaunch } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { sampleCanonicalNow } from '../state/canonical-time.js';
import { assertBuiltinEditLaunchClosure, assertWorkerLaunchClosure, assertVerifierLaunchClosure,
  type BuiltinEditLaunchClosure, type WorkerLaunchClosure, type VerifierLaunchClosure } from '../state/execution-closure.js';
import { borrowWorkerReservationForExecution, borrowSourceGitInputForExecution, borrowRetainedSourceGitInputForCleanup,
  borrowRegisteredAbsentSourceGitInputForCleanup,
  borrowPreparingGitInputForExecution,
  borrowRetainedPreparingGitInputForCleanup,
  type BorrowedGenerationForExecution, type HeldWorkerReservation, type HeldSourceGitInput,
  type HeldRetainedSourceGitInput, type HeldRegisteredAbsentSourceGitInput, type HeldPreparingGitInput, type HeldRetainedPreparingGitInput } from '../state/native-owner.js';
import { borrowRunWorkspaceForExecution, type RunWorkspaceGeneration } from '../workspace/run-workspace/generation.js';
import { loadInstalledWorkerNative, sealInstalledWorkerImage, withInstalledWorkerRoot, startInstalledGuestToolchain, closeInstalledGuestToolchain,
  sealInstalledSourceGitInspector, startInstalledSourceGitToolchain, closeInstalledSourceGitToolchain,
  type HeldInstalledAnchor, type HeldInstalledRuntime } from '../state/installed-runtime.js';
import { GUEST_EXTRACTOR_RECIPE, LINUX_VERIFIER_RESOURCE_MINIMUMS, type NativeGuestExtractorBinding, type NativeGuestToolchain,
  type NativeGuestExtractionInput, type NativeSourceGitToolchain } from './guest-toolchain.js';
import { guestToolchainExecutables, type RetainedVerifierToolchain } from '../state/guest-toolchain.js';

export class LinuxExecutionIdentityError extends Error {
  readonly code = 'UNSUPPORTED_EXECUTION_IDENTITY' as const;
  readonly retryable = false;
}

const fixedEnvironment: Omit<SanitizedSandboxEnvironmentV1, 'environmentDigest'> = {
  schemaVersion: 1, format: 'cliq-sanitized-sandbox-environment-v1', home: '/home/cliq', tmpdir: '/tmp',
  controlledPath: ['/runtime'], locale: { lang: 'C', lcAll: 'C' }, variables: [], networkMode: 'none',
  inheritedHostEnvironment: false, secretMaterial: 'none', brokerAccessAtSpawn: 'none'
};

/** Artifact planners consume the same closed recipe the native images execute.
 * This is a recipe, not a caller-selected process/environment configuration. */
export const LINUX_WORKER_RECIPE = immutableSnapshot({
  launcherId: 'linux_worker_controller', nativeModuleId: 'linux_worker_native', bubblewrapId: 'linux_bubblewrap',
  workerId: 'linux_worker', workerPath: '/runtime/cliq-linux-worker',
  editId: 'edit', editPath: '/runtime/cliq-linux-edit',
  environment: { ...fixedEnvironment, environmentDigest: canonicalSha256(fixedEnvironment) },
  mounts: [
    { kind: 'private_ephemeral', access: 'read_write', targetPath: '/home/cliq', purpose: 'home' },
    { kind: 'private_ephemeral', access: 'read_write', targetPath: '/tmp', purpose: 'tmp' }
  ],
  maxIpcFrameBytes: 16_777_216, maxQueuedIpcBytes: 67_108_864
} as const);

const verifierEnvironment = { ...fixedEnvironment, controlledPath: ['/usr/bin'] };
export const LINUX_VERIFIER_RECIPE = immutableSnapshot({
  launcherId: LINUX_WORKER_RECIPE.launcherId, nativeModuleId: LINUX_WORKER_RECIPE.nativeModuleId,
  guestExtractorId: GUEST_EXTRACTOR_RECIPE.entryId, nodePath: '/usr/bin/node',
  argumentPrefix: ['--no-addons'],
  environment: { ...verifierEnvironment, environmentDigest: canonicalSha256(verifierEnvironment) },
  mounts: LINUX_WORKER_RECIPE.mounts,
  maxIpcFrameBytes: LINUX_WORKER_RECIPE.maxIpcFrameBytes, maxQueuedIpcBytes: LINUX_WORKER_RECIPE.maxQueuedIpcBytes,
} as const);

export type NativeVerifierResult = Readonly<{
  startedAt: string; endedAt: string; durationMs: number;
  stdout: Uint8Array; stderr: Uint8Array; stdoutTruncated: boolean; stderrTruncated: boolean;
  death: NativeContainmentDeathObservation;
}> & (Readonly<{ terminationReason: 'exit'; exitCode: number }> |
  Readonly<{ terminationReason: 'signal'; signal: string }> |
  Readonly<{ terminationReason: 'spawn_error'; nativeErrorCode: number }> |
  Readonly<{ terminationReason: 'timeout' | 'resource_failure' | 'controller_stop' }>);
export type LinuxBlockedVerifier = Readonly<{
  containment: ProcessContainment;
  result(): Promise<NativeVerifierResult>;
  stop(): Promise<NativeContainmentDeathObservation>;
}>;
const verifierResults = new WeakMap<object, Readonly<{ stdout: Buffer; stderr: Buffer }>>();
export function assertNativeVerifierResult(value: unknown): asserts value is NativeVerifierResult {
  if (!value || typeof value !== 'object' || !verifierResults.has(value)) throw new TypeError('verifier result requires its original real native producer');
}

/** Synchronous inert snapshot for the original completion owner. Mutable
 * public Uint8Array views never become retained output authority. The returned
 * projection is not a branded native result or a new release capability. */
export function captureNativeVerifierResult(value: unknown): NativeVerifierResult {
  assertNativeVerifierResult(value);
  const bytes = verifierResults.get(value)!;
  return Object.freeze({ ...value, stdout: Buffer.from(bytes.stdout), stderr: Buffer.from(bytes.stderr) });
}

/** A native-created, one-use release, not a structural caller callback. */
export type LinuxBlockedInvocation = Readonly<{
  containment: ProcessContainment;
  observeProcess(): Promise<LinuxObservedProcess>;
  result(): Promise<'ok' | 'error'>;
  stop(): Promise<NativeContainmentDeathObservation>;
}>;

export type LinuxObservedProcess = Readonly<Pick<WorkerIdentity, 'pid' | 'processStartToken' | 'executableRealpath' | 'executableDigest'>>;
export type NativeContainmentDeathObservation = Readonly<{
  containment: ProcessContainment;
  cgroupPopulated: 0;
  namespaceInitDeadAndReaped: true;
  remainingTrackedDescendants: 0;
  observedAt: string;
}>;
export type NativePreactivationObservation = Readonly<{
  kind: 'no_spawn'; observedAt: string; cgroupObservation: Readonly<{ kind: 'absent' }>;
  pidNamespaceObservation: Readonly<{ kind: 'never_created'; pidNamespaceReservationId: string }>;
  matchingLaunchNonceProcessCount: 0;
}> | Readonly<{ kind: 'created'; containment: ProcessContainment; death: NativeContainmentDeathObservation }>;
const preactivationObservations = new WeakMap<object, string>();
export function assertNativePreactivationObservation(observation: NativePreactivationObservation, closure: WorkerLaunchClosure): void {
  assertWorkerLaunchClosure(closure);
  if (preactivationObservations.get(observation) !== canonicalSha256([closure.containmentPlanRef, closure.sandboxLaunchSpecRef])) {
    throw new TypeError('preactivation closure requires its exact fresh native producer');
  }
}

export type LinuxBlockedWorker = Readonly<{
  containment: ProcessContainment;
  assertHeld(): void;
  observeProcess(): Promise<LinuxObservedProcess>;
  activateCommitted(launch: WorkerLaunch): Promise<void>;
  createInvocation(closure: BuiltinEditLaunchClosure): Promise<LinuxBlockedInvocation>;
  createVerifier(closure: VerifierLaunchClosure, options?: { signal?: AbortSignal }): Promise<LinuxBlockedVerifier>;
  stop(): Promise<NativeContainmentDeathObservation>;
  closeAfterControllerJoin(): Promise<void>;
}>;
export type LinuxWorkerController = Readonly<{
  pid: number;
  processStartToken: string;
  subreaperStartToken: string;
  preparationBirth: NativeControllerPreparationBirth;
  openPreparingGit(input: { input: HeldPreparingGitInput; recipe: NativePreparingGitRecipe; toolchain: RetainedVerifierToolchain;
    signal?: AbortSignal }): Promise<HeldPreparingGitScope>;
  cleanupRetainedPreparingGit(input: { input: HeldRetainedPreparingGitInput; recipe: NativePreparingGitRecipe;
    signal?: AbortSignal }): Promise<NativeRetainedPreparingGitRetirement>;
  bindWorkerReservation(input: { closure: WorkerLaunchClosure; reservation: HeldWorkerReservation; activationNonceDigest: string }): Promise<NativeWorkerReservationBinding>;
  inspectPreactivation(input: { closure: WorkerLaunchClosure; reservation: HeldWorkerReservation; activationNonceDigest: string;
    containment?: ProcessContainment; workerIdentity?: WorkerIdentity }): Promise<NativePreactivationObservation>;
  launchWorker(input: { closure: WorkerLaunchClosure; generation: RunWorkspaceGeneration; activationNonceDigest: string }): Promise<LinuxBlockedWorker>;
  terminateRetained(input: { closure: WorkerLaunchClosure; containment: ProcessContainment; workerIdentity: WorkerIdentity;
    signal?: AbortSignal }): Promise<NativeContainmentDeathObservation>;
  closeRetained(): Promise<NativeRetainedWorkerRetirement>;
  closePreactivation(): Promise<NativePreactivationRetirement>;
  closePreparation(): Promise<NativeControllerPreparationRetirement>;
  close(): Promise<void>;
}>;
const linuxWorkerControllers = new WeakSet<LinuxWorkerController>();
/** Structural wrappers and borrowed birth data do not own this native
 * controller's productive channel or preparing lifecycle. */
export function assertLinuxWorkerController(controller: LinuxWorkerController): void {
  if (!controller || typeof controller !== 'object' || !linuxWorkerControllers.has(controller))
    throw new TypeError('worker controller requires its original real native owner');
}
export type LinuxWorkerLauncher = Readonly<{ startController(options?: { signal?: AbortSignal }): Promise<LinuxWorkerController>; close(): Promise<void> }>;
export type LinuxWorkerInstallation = {
  installationRoot: string;
  cgroupParent: string;
  runtimeAuthority: { bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[] };
};

type NativeObservation = {
  pid: number; processStartToken: string; namespaceInitStartToken: string; namespaceInitPid: number;
  cgroupId: string; pidNamespaceId: string; cgroupPopulated: number; namespaceInitDeadAndReaped: number;
  remainingTrackedDescendants: number; observedAtMs: number; imageFd: number; imageByteCount: number; executableRealpath: string;
};
export type NativeWorkerImage = { descriptor(): number; close(): void };
/** Only the fixed same-bundle data script producer can mint this native tag.
 * It is neither an executable selector nor a numerical descriptor export. */
export type NativeSourceGitInspectorImage = Readonly<{
  identity: Readonly<{ sha256: string; byteCount: number }>;
  close(): void;
}>;
/** Raw observations from the fixed source-only native family. None of these
 * data projections is a launch/SQL authority or a caller-selected descriptor. */
export type NativeSourceGitReservationObservation = Readonly<{
  cgroupPath: string; deviceId: string; fileId: string; cgroupId: string; ownerUid: number;
  observedAtMs: number; pidNamespaceReservationId: string; subreaperStartToken: string;
}>;
export type NativeSourceGitContainmentObservation = Readonly<{
  pid: number; namespaceInitPid: number; processStartToken: string; namespaceInitStartToken: string;
  cgroupId: string; pidNamespaceId: string; cgroupPopulated: number; remainingTrackedDescendants: number;
  namespaceInitDeadAndReaped: number; observedAtMs: number;
}>;
export type NativeSourceGitSnapshotObservation = Readonly<{
  snapshotDigest: string; byteCount: number; entryCount: number; shardCount: number;
}>;
export type NativeSourceGitOutputReader = Readonly<{
  identity: Readonly<{ sha256: string; byteCount: number }>;
  assertHeld(): void; readChunk(): Buffer | undefined; close(): void;
}>;
export type NativeSourceGitResult = Readonly<{
  death: NativeSourceGitContainmentObservation;
  files: Readonly<{ inspection: NativeSourceGitOutputReader; index: NativeSourceGitOutputReader;
    pack: NativeSourceGitOutputReader; packIndex: NativeSourceGitOutputReader }>;
  /** Independently authorized .git/info/exclude only; never Git/helper input.
   * null includes absence. This reader also joins before scope removal. */
  excludeRule: NativeSourceGitOutputReader | null;
}>;
export type NativeSourceGitRetirementObservation = Readonly<{
  observedAtMs: number; inspectionId: string; stagingNonceDigest: string; targetRef: string; inputIntentRef: string;
  reserved: 0 | 1; blocked: 0 | 1; released: 0 | 1; continued: 0 | 1;
  origin: 'original_owner_joined' | 'original_birth_current_checker' | 'original_birth_registered_absent_checker'; lastBirthKind: 0 | 2 | 4 | 5 | 6 | 7 | 8 | 9 | 11 | 12;
  originalControllerPid: number; originalControllerStartToken: string;
  cgroupDeviceId: string | null; cgroupId: string | null; launchNonceDigest: string | null;
  containmentPlanRef: string | null; sandboxLaunchRef: string | null; sandboxLaunchDigest: string | null;
  containment: NativeSourceGitContainmentObservation | null;
}> & (Readonly<{ snapshotDigest?: never; byteCount?: never; entryCount?: never; shardCount?: never }> |
  NativeSourceGitSnapshotObservation);
export type NativeRetainedSourceGitRetirementObservation = NativeSourceGitRetirementObservation & Readonly<{
  origin: 'original_birth_current_checker';
}>;
type NativeRetainedSourceGitScope = Readonly<{
  pollCleaned(): true | undefined;
  pollRetired(): NativeSourceGitRetirementObservation | undefined;
  pollLifecycleSnapshot(): Buffer | undefined;
  close(): void;
}>;
export type NativeSourceGitScope = Readonly<{
  pollReserved(): NativeSourceGitReservationObservation | undefined;
  createBlocked(planRef: string, sandboxLaunchRef: string, sandboxLaunchDigest: string): void;
  pollReady(): NativeSourceGitContainmentObservation | undefined;
  releaseCapture(): void; pollSealed(): NativeSourceGitSnapshotObservation | undefined;
  continueFixedGit(): void; pollResult(): NativeSourceGitResult | undefined;
  /** Revokes the original controller immediately. The poll is positive only
   * after its actual death, all reader closes and resource removal join. */
  stop(): void; pollStopped(): NativeSourceGitRetirementObservation | undefined;
  retire(): void; pollRetired(): NativeSourceGitRetirementObservation | undefined;
  pollLifecycleSnapshot(): Buffer | undefined;
}>;
export type NativeSourceGitRecipe = Readonly<import('../kernel/types.js').SandboxResourceSpec & {
  launchNonceDigest: string; repositoryIdentityDigest: string;
  /** Only the exact already-consumed read_scope grant for .git/info/exclude.
   * This value is data; the original SourceInspection SQL fence grants access. */
  excludeGrantDigest: string | null;
}>;
export type NativePreparingGitRecipe = Readonly<import('../kernel/types.js').SandboxResourceSpec & {
  stateOwnerEpoch: number; supervisorInstanceId: string; stateOwnerRowDigest: string; sessionId: string;
  sourceCheckpointId: string; sourceWorkspaceStateRef: string; repositoryIdentityDigest: string;
}>;
export type NativePreparingGitRetirementObservation = Readonly<{
  origin: 'original_owner_joined' | 'original_birth_current_checker'; observedAtMs: number; completed: 0 | 1; lastBirthPhase: number;
  runId: string; generationId: string; launchId: string; spawnNonceDigest: string; activationNonceDigest: string;
  generationCreationNonceDigest: string; generationRef: string; inputIntentRef: string;
  originalControllerPid: number; originalControllerStartToken: string;
  originalSupervisorPid: number; originalSupervisorStartToken: string;
}>;
export type NativePreparingGitScope = Readonly<{
  pollReserved(): NativeSourceGitReservationObservation | undefined;
  createBlocked(): void; pollReady(): NativeSourceGitContainmentObservation | undefined;
  releaseCapture(): void; declareInput(role: number, sha256: string, byteCount: number): boolean;
  writeInput(chunk: Buffer): boolean; endInput(): boolean; finishInput(): boolean;
  pollSealed(): NativeSourceGitSnapshotObservation | undefined; continueFixedGit(): void;
  pollResult(): NativeSourceGitResult | undefined;
  stop(): void; pollStopped(): NativePreparingGitRetirementObservation | undefined;
  retire(): void; pollRetired(): NativePreparingGitRetirementObservation | undefined;
}>;
export type HeldPreparingGitScope = Readonly<{
  signal: AbortSignal;
  recipe: NativePreparingGitRecipe;
  reserve(): NativePreparingGitScope;
  constructionRetirement(): Readonly<{ pollRetired(): NativePreparingGitRetirementObservation | undefined }> | undefined;
  /** Revoke first, then join actual input/read/CAS owners. This callback
   * supplies no proof; the native scope still proves its original closure. */
  registerStop(stop: (deadline: number) => Promise<void>): () => void;
  closeRuntime(): Promise<void>;
}>;
type NativeRetainedPreparingGitScope = Readonly<{
  pollCleaned(): true | undefined; pollRetired(): NativePreparingGitRetirementObservation | undefined; close(): void;
}>;
declare const retainedPreparingGitRetirementBrand: unique symbol;
export type NativeRetainedPreparingGitRetirement = Readonly<{ [retainedPreparingGitRetirementBrand]: true }>;
const retainedPreparingGitRetirements = new WeakMap<NativeRetainedPreparingGitRetirement,
  Readonly<{ observation: NativePreparingGitRetirementObservation; input: HeldRetainedPreparingGitInput; recipe: NativePreparingGitRecipe;
    checker: Readonly<{ pid: number; processStartToken: string; controllerBirthDigest: string; joined: true }> }>>();
export function readNativeRetainedPreparingGitRetirement(receipt: NativeRetainedPreparingGitRetirement) {
  const held = retainedPreparingGitRetirements.get(receipt);
  if (!held) throw new TypeError('retained preparing retirement requires its genuine joined checker');
  return Object.freeze({ observation: held.observation, input: held.input, recipe: held.recipe, checker: held.checker });
}
type NativeImage = NativeWorkerImage;
type NativeVerifierOutcome = Readonly<{ termination: number; exitCode: number; signal: number; nativeErrorCode: number;
  startedAtMs: number; endedAtMs: number; durationMs: number; stdout: Buffer; stderr: Buffer; stdoutTruncated: number; stderrTruncated: number;
  death: NativeObservation }>;
type NativeScope = { pollReady(): boolean; observe(): NativeObservation; activate(nonce: string): void; pollActivated(): boolean;
  release(): void; result(): number | NativeVerifierOutcome | undefined; stop(): void; pollStopped(): NativeObservation | undefined };
type ControllerPreparationDirectoryIdentity = Readonly<{
  deviceId: string; fileId: string; ownerUid: number; ownerGid: number; mode: number;
}>;
type NativeControllerPreparationBirthObservation = Readonly<{
  rootPath: string; root: ControllerPreparationDirectoryIdentity; parent: ControllerPreparationDirectoryIdentity;
  leafName: string; leaf: ControllerPreparationDirectoryIdentity; pid: number; processStartToken: string;
  readyObservedAtMs: number; observedAtMs: number;
}>;
type NativeController = { pid: number; processStartToken: string;
  pollReady(): boolean;
  bindReservation(reservation: number, config: object): void;
  pollBound(): boolean;
  inspectReservation(cgroup: number, reservation: number, config: object): void;
  pollReservation(): Readonly<{ kind: 'not_attempted'; cgroupPresent: boolean; cgroupId?: string; observedAtMs: number }> |
    (NativeObservation & Readonly<{ kind: 'created_dead'; observedAtMs: number }>) | undefined;
  createWorker(generation: number, cgroup: number, helper: NativeImage, worker: NativeImage, bwrap: NativeImage, config: object): NativeScope;
  createInvocation(generation: number, parent: NativeScope, helper: NativeImage, adapter: NativeImage, bwrap: NativeImage, input: NativeImage, config: object): NativeScope;
  createVerifier(generation: number, parent: NativeScope, helper: NativeImage, bwrap: NativeImage, guest: NativeGuestToolchain, config: object): NativeScope;
  reserveSourceGit(input: object, helper: NativeImage, bwrap: NativeImage, guest: NativeSourceGitToolchain,
    inspector: NativeSourceGitInspectorImage, recipe: NativeSourceGitRecipe): NativeSourceGitScope;
  reservePreparationGit(input: object, helper: NativeImage, bwrap: NativeImage, guest: NativeSourceGitToolchain,
    inspector: NativeSourceGitInspectorImage, recipe: NativePreparingGitRecipe): NativePreparingGitScope;
  preparationGitConstructionRetirement(input: object): Readonly<{ pollRetired(): NativePreparingGitRetirementObservation | undefined }> | undefined;
  cleanupRetainedPreparingGit(input: object, recipe: NativePreparingGitRecipe): NativeRetainedPreparingGitScope;
  sourceGitConstructionRetirement(input: object): Readonly<{ pollRetired(): NativeSourceGitRetirementObservation | undefined;
    pollLifecycleSnapshot(): Buffer | undefined }> | undefined;
  cleanupRetainedSourceGit(input: object): NativeRetainedSourceGitScope;
  cleanupRegisteredAbsentSourceGit(input: object): NativeRetainedSourceGitScope;
  terminateRetained(cgroup: number, config: object): void;
  pollRetained(): NativeObservation | undefined;
  assertRetainedRetired(cgroupRootFd: number): number;
  assertPreactivationRetired(cgroupRootFd: number, reservationFd: number): number;
  assertPreparationRetired(cgroupRootFd: number): number;
  observePreparationBirth(cgroupRootFd: number): NativeControllerPreparationBirthObservation;
  close(): Promise<void>;
};
export type NativeWorkerBinding = { interfaceVersion: 3; readonly verifierInterfaceVersion?: 1;
  readonly sourceInterfaceVersion: 1;
  readonly preparationInterfaceVersion: 1;
  sealSourceGitInspector(fd: number): NativeSourceGitInspectorImage;
  sealImage(fd: number): NativeImage; sealImageBuffer(input: Buffer): NativeImage;
  openController(helper: NativeImage, cgroupRootFd: number): NativeController };
type NativeBinding = NativeWorkerBinding;
type HeldGuestPreparation = Readonly<{ job: NativeGuestToolchain; close(): Promise<void> }>;
type HeldPreparingGitRuntime = Readonly<{ guest: NativeSourceGitToolchain; inspector: NativeSourceGitInspectorImage; close(): Promise<void> }>;
function preparingRecipe(value: NativePreparingGitRecipe): NativePreparingGitRecipe {
  const keys = ['maxProcesses', 'memoryBytes', 'cpuQuotaMicrosPerSecond', 'maxOpenFiles', 'maxSingleFileBytes', 'maxGenerationBytes',
    'maxInvocationOutputBytes', 'maxIpcFrameBytes', 'maxQueuedIpcBytes', 'stateOwnerEpoch', 'supervisorInstanceId', 'stateOwnerRowDigest',
    'sessionId', 'sourceCheckpointId', 'sourceWorkspaceStateRef', 'repositoryIdentityDigest'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || utilTypes.isProxy(value) || Reflect.ownKeys(value).length !== keys.length)
    throw new TypeError('preparing Git recipe must contain only its fixed own data fields');
  const copy: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw new TypeError('preparing Git recipe cannot contain accessors');
    copy[key] = descriptor.value;
  }
  for (const key of ['stateOwnerRowDigest', 'sourceWorkspaceStateRef', 'repositoryIdentityDigest']) {
    if (typeof copy[key] !== 'string') throw new TypeError('preparing artifact identity is invalid');
    assertArtifactRef(copy[key]);
  }
  for (const key of ['supervisorInstanceId', 'sessionId', 'sourceCheckpointId'])
    if (typeof copy[key] !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(copy[key])) throw new TypeError('preparing owner identity is invalid');
  for (const key of keys.slice(0, 10)) if (!Number.isSafeInteger(copy[key]) || (copy[key] as number) < 1)
    throw new TypeError('preparing resource or owner epoch is invalid');
  return Object.freeze(copy) as NativePreparingGitRecipe;
}

function controllerPreparationBirthIdentity(observed: NativeControllerPreparationBirthObservation) {
  if (!Number.isSafeInteger(observed.readyObservedAtMs) || observed.readyObservedAtMs < 1 ||
      !Number.isSafeInteger(observed.observedAtMs) || observed.observedAtMs < observed.readyObservedAtMs)
    mismatch('native controller preparation birth time is invalid');
  return immutableSnapshot({ rootPath: observed.rootPath, root: observed.root, parent: observed.parent,
    leafName: observed.leafName, leaf: observed.leaf, pid: observed.pid, processStartToken: observed.processStartToken,
    readyObservedAt: new Date(observed.readyObservedAtMs).toISOString() });
}

declare const controllerPreparationBirthBrand: unique symbol;
export type NativeControllerPreparationBirth = Readonly<{ [controllerPreparationBirthBrand]: true }>;
const controllerPreparationBirths = new WeakMap<NativeControllerPreparationBirth, {
  identity: ReturnType<typeof controllerPreparationBirthIdentity>; controllerBirthDigest: string;
  lastObservedAtMs: number; assertCurrent(): NativeControllerPreparationBirthObservation;
}>();
/** An authenticated HELLO birth, freshly reasserted by its original live owner.
 * The immutable identity is data; only this opaque token retains its producer. */
export function readNativeControllerPreparationBirth(birth: NativeControllerPreparationBirth) {
  const held = controllerPreparationBirths.get(birth);
  if (!held) throw new TypeError('invalid native controller preparation birth');
  let observed: NativeControllerPreparationBirthObservation;
  try { observed = held.assertCurrent(); }
  catch (error) {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw retirementError('controller preparation birth observation resources did not retire', error);
    throw error;
  }
  if (canonicalSha256(controllerPreparationBirthIdentity(observed)) !== held.controllerBirthDigest)
    mismatch('native controller preparation birth identity changed');
  if (observed.observedAtMs < held.lastObservedAtMs)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'native controller preparation birth clock regressed');
  held.lastObservedAtMs = observed.observedAtMs;
  return immutableSnapshot({ identity: held.identity, controllerBirthDigest: held.controllerBirthDigest,
    observedAt: new Date(observed.observedAtMs).toISOString() });
}

declare const workerReservationBindingBrand: unique symbol;
export type NativeWorkerReservationBinding = Readonly<{ [workerReservationBindingBrand]: true }>;
type WorkerReservationBindingData = Readonly<{ runId: string; launchId: string; generationRef: string;
  containmentPlanRef: string; sandboxLaunchSpecRef: string; spawnNonceDigest: string; activationNonceDigest: string;
  controllerBirthDigest: string; reservation: HeldWorkerReservation['identity'] }>;
const workerReservationBindings = new WeakMap<NativeWorkerReservationBinding,
  { data: WorkerReservationBindingData; assertCurrent(): void }>();

/** The original controller's durable BIND acknowledgement, not a phase string
 * or a caller's assertion that its reservation file was written. */
export function readNativeWorkerReservationBinding(receipt: NativeWorkerReservationBinding): WorkerReservationBindingData {
  const held = workerReservationBindings.get(receipt);
  if (!held) throw new TypeError('invalid native worker reservation binding');
  held.assertCurrent();
  return held.data;
}

declare const retiredControllerPreparationBrand: unique symbol;
export type NativeControllerPreparationRetirement = Readonly<{ [retiredControllerPreparationBrand]: true }>;
const retiredControllerPreparations = new WeakMap<NativeControllerPreparationRetirement,
  { pid: number; processStartToken: string; controllerBirthDigest: string; readyObservedAt: string; assertCurrent(): number }>();
/** Fresh closure of the original ordinary controller only. This supplies no
 * worker no-spawn, workspace or broker retirement authority. */
export function readNativeControllerPreparationRetirement(receipt: NativeControllerPreparationRetirement) {
  const held = retiredControllerPreparations.get(receipt);
  if (!held) throw new TypeError('invalid native controller preparation retirement');
  let observed: number;
  try { observed = held.assertCurrent(); }
  catch (error) {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw retirementError('controller preparation observation resources did not retire', error);
    throw error;
  }
  if (!Number.isSafeInteger(observed) || observed < 1) mismatch('native controller preparation retirement time is invalid');
  const observedAt = new Date(observed).toISOString();
  if (observedAt < held.readyObservedAt)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'native retirement clock precedes original controller birth');
  return immutableSnapshot({ pid: held.pid, processStartToken: held.processStartToken, controllerBirthDigest: held.controllerBirthDigest, observedAt,
    controllerJoined: true as const, controllerLeafAbsent: true as const, workerCreationRequested: false as const,
    liveContainmentCount: 0 as const, activeMountCount: 0 as const });
}

declare const retiredWorkerBrand: unique symbol;
export type NativeRetainedWorkerRetirement = Readonly<{ [retiredWorkerBrand]: true }>;
const retiredWorkers = new WeakMap<NativeRetainedWorkerRetirement,
  { containment: ProcessContainment; deathObservedAt: string; assertCurrent(): number }>();
/** Fresh physical check of a genuine joined native owner. No data decoder or
 * caller callback can mint this receipt or its zero resource observations. */
export function readNativeRetainedWorkerRetirement(receipt: NativeRetainedWorkerRetirement): Readonly<{
  containment: ProcessContainment; observedAt: string; liveContainmentCount: 0; activeMountCount: 0;
}> {
  const held = retiredWorkers.get(receipt);
  if (!held) throw new TypeError('invalid native retained worker retirement');
  let observed: number;
  try { observed = held.assertCurrent(); }
  catch (error) {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw retirementError('retained native inspection resource did not retire', error);
    throw error;
  }
  if (!Number.isSafeInteger(observed) || observed < 1) mismatch('native retirement observation time is invalid');
  const observedAt = new Date(observed).toISOString();
  if (observedAt < held.deathObservedAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'native retirement clock precedes original actual death');
  return immutableSnapshot({ containment: held.containment, observedAt, liveContainmentCount: 0, activeMountCount: 0 });
}

declare const retiredPreactivationBrand: unique symbol;
export type NativePreactivationRetirement = Readonly<{ [retiredPreactivationBrand]: true }>;
const retiredPreactivations = new WeakMap<NativePreactivationRetirement, {
  closure: WorkerLaunchClosure; activationNonceDigest: string; observation: NativePreactivationObservation; assertCurrent(): number;
}>();
/** The original birth witness plus a genuinely joined inspector, refreshed
 * synchronously at the consumer's cut. Historical proof data cannot mint it. */
export function readNativePreactivationRetirement(receipt: NativePreactivationRetirement) {
  const held = retiredPreactivations.get(receipt);
  if (!held) throw new TypeError('invalid native preactivation retirement');
  let observed: number;
  try { observed = held.assertCurrent(); }
  catch (error) {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw retirementError('preactivation native inspection resource did not retire', error);
    throw error;
  }
  if (!Number.isSafeInteger(observed) || observed < 1) mismatch('native preactivation retirement observation time is invalid');
  const observedAt = new Date(observed).toISOString(), original = held.observation;
  if (observedAt < (original.kind === 'no_spawn' ? original.observedAt : original.death.observedAt))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'native retirement clock precedes original preactivation closure');
  return immutableSnapshot({ kind: original.kind, planRef: held.closure.containmentPlanRef,
    sandboxLaunchSpecRef: held.closure.sandboxLaunchSpecRef, workspaceGenerationRef: held.closure.workspaceGenerationRef,
    workerLaunchId: held.closure.plan.owner.workerLaunchId, launchNonceDigest: held.closure.plan.launchNonceDigest,
    activationNonceDigest: held.activationNonceDigest,
    ...(original.kind === 'created' ? { containment: original.containment } : {}),
    observedAt, liveContainmentCount: 0 as const, activeMountCount: 0 as const });
}

export async function openInstalledLinuxWorkerLauncher(selected: HeldInstalledRuntime,
  anchor: HeldInstalledAnchor, options: { signal?: AbortSignal } = {}): Promise<LinuxWorkerLauncher> {
  options.signal?.throwIfAborted();
  let cgroupParent = '';
  withInstalledWorkerRoot(selected, anchor, (_fd, rootPath) => { cgroupParent = rootPath; });
  return openWorkerLauncher(selected.bundle, cgroupParent, {
    assertHeld() { withInstalledWorkerRoot(selected, anchor, () => {}); },
    withRoot(operation) { withInstalledWorkerRoot(selected, anchor, fd => operation(fd)); },
    loadNative: () => loadInstalledWorkerNative(selected, options.signal),
    image: entryId => sealInstalledWorkerImage(selected, entryId),
    async guest(toolchain, signal) {
      const job = await startInstalledGuestToolchain(selected, toolchain, { ...(signal ? { signal } : {}) });
      return Object.freeze({ job, close: () => closeInstalledGuestToolchain(selected, job) });
    },
    async preparing(toolchain, signal) {
      let inspector: NativeSourceGitInspectorImage | undefined, guest: NativeSourceGitToolchain | undefined;
      let closing: Promise<void> | undefined;
      const close = () => closing ??= (async () => {
        const failures: unknown[] = [];
        if (guest) try { await closeInstalledSourceGitToolchain(selected, guest); } catch (error) { failures.push(error); }
        if (inspector) try { inspector.close(); } catch (error) { failures.push(error); }
        if (failures.length) throw retirementError('preparing fixed runtime did not join', new AggregateError(failures));
      })();
      try {
        inspector = await sealInstalledSourceGitInspector(selected, signal);
        guest = await startInstalledSourceGitToolchain(selected, toolchain, { ...(signal ? { signal } : {}) });
        signal?.throwIfAborted();
        return Object.freeze({ guest, inspector, close });
      } catch (error) {
        try { await close(); } catch (cleanup) { throw retirementError('preparing runtime construction and join failed', new AggregateError([error, cleanup])); }
        throw error;
      }
    },
    async close() {},
  });
}

/** Same held signed composition as the resident-worker launcher, but a
 * separate native family: there is no Run/generation parent or image selector
 * supplied by its caller. The source owner retains the SQL/consent gates. */
export async function openInstalledSourceGitController(selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor,
  toolchain: RetainedVerifierToolchain, options: { signal?: AbortSignal } = {}): Promise<Readonly<{
    pid: number; processStartToken: string;
    reserve(input: HeldSourceGitInput, recipe: NativeSourceGitRecipe): NativeSourceGitScope;
    constructionRetirement(): Readonly<{ pollRetired(): NativeSourceGitRetirementObservation | undefined;
      pollLifecycleSnapshot(): Buffer | undefined }> | undefined;
    close(): Promise<void>;
  }>> {
  withInstalledWorkerRoot(selected, anchor, () => {});
  const signal = options.signal;
  signal?.throwIfAborted();
  let helper: NativeImage | undefined, bwrap: NativeImage | undefined, inspector: NativeSourceGitInspectorImage | undefined;
  let guest: NativeSourceGitToolchain | undefined, controller: NativeController | undefined, closePromise: Promise<void> | undefined;
  let reserved = false, closed = false, reservedInput: object | undefined;
  const close = () => {
    closed = true;
    return closePromise ??= (async () => {
      const failures: unknown[] = [];
      // Native close revokes synchronously before the first await. The source
      // domain and every borrowed output must join before runtime producers.
      if (controller) try { await joinController(controller); } catch (error) { failures.push(error); }
      if (guest) try { await closeInstalledSourceGitToolchain(selected, guest); } catch (error) { failures.push(error); }
      for (const image of [inspector, bwrap, helper]) if (image) try { image.close(); } catch (error) { failures.push(error); }
      if (failures.length) throw failures.find(error => error instanceof ResourceRetirementError) ??
        retirementError('source controller and signed runtime resources did not retire', new AggregateError(failures));
    })();
  };
  try {
    const binding = await loadInstalledWorkerNative(selected, signal);
    if (binding.sourceInterfaceVersion !== 1) throw new LinuxExecutionIdentityError('installed native source recipe is unavailable');
    helper = await sealInstalledWorkerImage(selected, LINUX_WORKER_RECIPE.launcherId); signal?.throwIfAborted();
    bwrap = await sealInstalledWorkerImage(selected, LINUX_WORKER_RECIPE.bubblewrapId); signal?.throwIfAborted();
    inspector = await sealInstalledSourceGitInspector(selected, signal);
    guest = await startInstalledSourceGitToolchain(selected, toolchain, options);
    const description = guest.describe(), manifest = toolchain.manifest;
    if (description.imageDigest !== manifest.guestImageDigest || description.nodePath !== '/usr/bin/node' ||
        description.nodeDigest !== manifest.node.digest || description.gitPath !== '/usr/bin/git' ||
        description.gitDigest !== manifest.git.digest || description.files.length < 2 || description.files.length > GUEST_EXTRACTOR_RECIPE.maxMappedFiles)
      mismatch('fixed source mappings differ from their exact retained signed toolchain');
    withInstalledWorkerRoot(selected, anchor, fd => { controller = binding.openController(helper!, fd); });
    await awaitNative(() => controller!.pollReady() ? true : undefined, close, signal);
    return Object.freeze({
      pid: controller!.pid, processStartToken: controller!.processStartToken,
      reserve(input: HeldSourceGitInput, recipe: NativeSourceGitRecipe) {
        if (closed || reserved) throw new KernelStorageError('RECOVERY_REQUIRED', 'source controller reservation was closed or consumed');
        withInstalledWorkerRoot(selected, anchor, () => {});
        const native = borrowSourceGitInputForExecution(input);
        signal?.throwIfAborted();
        // A failed dispatch is not retryable as a new source release.
        reserved = true;
        reservedInput = native;
        return controller!.reserveSourceGit(native, helper!, bwrap!, guest!, inspector!, recipe);
      },
      constructionRetirement() { return reservedInput ? controller!.sourceGitConstructionRetirement(reservedInput) : undefined; },
      close,
    });
  } catch (error) {
    try { await close(); } catch (failure) {
      if (failure instanceof ResourceRetirementError) throw failure;
      throw retirementError('source construction failed and resources did not retire', new AggregateError([error, failure]));
    }
    throw error;
  }
}

/** Cleanup only. The original birth is reopened by the current StateOwner;
 * no source/toolchain images, recipe, payload root or execution are accepted.
 * Failure preserves uncertainty; this never resumes an old source attempt. */
export async function closeInstalledRetainedSourceGit(selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor,
  input: HeldRetainedSourceGitInput, options: { signal?: AbortSignal } = {}): Promise<NativeJoinedSourceGitRetirement> {
  return closeInstalledSourceGitCleanup(selected, anchor, input, options, false);
}
export async function closeInstalledRegisteredAbsentSourceGit(selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor,
  input: HeldRegisteredAbsentSourceGitInput, options: { signal?: AbortSignal } = {}): Promise<NativeJoinedSourceGitRetirement> {
  return closeInstalledSourceGitCleanup(selected, anchor, input, options, true);
}
export type NativeJoinedSourceGitRetirement = Readonly<{
  observation: NativeSourceGitRetirementObservation; lifecycleSnapshot: Buffer;
}>;
async function closeInstalledSourceGitCleanup(selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor,
  input: HeldRetainedSourceGitInput | HeldRegisteredAbsentSourceGitInput, options: { signal?: AbortSignal }, registeredAbsent: boolean): Promise<NativeJoinedSourceGitRetirement> {
  withInstalledWorkerRoot(selected, anchor, () => {});
  const original = registeredAbsent ? borrowRegisteredAbsentSourceGitInputForCleanup(input as HeldRegisteredAbsentSourceGitInput)
    : borrowRetainedSourceGitInputForCleanup(input as HeldRetainedSourceGitInput);
  const signal = options.signal; signal?.throwIfAborted();
  let helper: NativeImage | undefined, controller: NativeController | undefined;
  let closing: Promise<void> | undefined;
  const close = () => closing ??= (async () => {
    const failures: unknown[] = [];
    if (controller) try { await joinController(controller); } catch (error) { failures.push(error); }
    if (helper) try { helper.close(); } catch (error) { failures.push(error); }
    if (failures.length) throw failures.find(error => error instanceof ResourceRetirementError) ??
      retirementError('retained source checker resources did not retire', new AggregateError(failures));
  })();
  try {
    const binding = await loadInstalledWorkerNative(selected, signal);
    if (binding.sourceInterfaceVersion !== 1) throw new LinuxExecutionIdentityError('installed source cleanup is unavailable');
    helper = await sealInstalledWorkerImage(selected, LINUX_WORKER_RECIPE.launcherId); signal?.throwIfAborted();
    withInstalledWorkerRoot(selected, anchor, fd => { controller = binding.openController(helper!, fd); });
    await awaitNative(() => controller!.pollReady() ? true : undefined, close, signal);
    const scope = registeredAbsent ? controller!.cleanupRegisteredAbsentSourceGit(original) : controller!.cleanupRetainedSourceGit(original);
    await awaitNative(() => scope.pollCleaned(), close, signal);
    await close();
    const observation = scope.pollRetired();
    const lifecycleSnapshot = scope.pollLifecycleSnapshot();
    if (!observation || observation.origin !== (registeredAbsent ? 'original_birth_registered_absent_checker' : 'original_birth_current_checker') ||
        observation.inspectionId !== input.identity.inspectionId || observation.stagingNonceDigest !== input.identity.stagingNonceDigest ||
        observation.targetRef !== input.identity.targetRef || observation.inputIntentRef !== input.identity.inputIntentRef ||
        !Buffer.isBuffer(lifecycleSnapshot) || lifecycleSnapshot.length < 1 || lifecycleSnapshot.length > 1_048_576)
      mismatch('retained source checker lost its original birth binding');
    return Object.freeze({ observation: immutableSnapshot(observation), lifecycleSnapshot: Buffer.from(lifecycleSnapshot) });
  } catch (error) {
    try { await close(); } catch (join) {
      if (join instanceof ResourceRetirementError) throw join;
      throw retirementError('retained source cleanup and current checker did not join', new AggregateError([error, join]));
    }
    throw error;
  }
}

export type LinuxInvocationClaim = Readonly<{
  runId: string;
  leaseEpoch: number;
  workerLaunchId: string;
  opId: string;
  attempt: number;
  dispatchId: string;
  sandboxLaunchSpecRef: string;
  requestRef: string;
  requestDigest: string;
  targetRef: string;
  targetDigest: string;
  operationGrantRef: string;
  parentWorkerContainmentRef: string;
}>;

const invocations = new WeakMap<object, { consumed: boolean; claim: LinuxInvocationClaim; release(): void }>();
const observedDeaths = new WeakSet<object>();

export function assertNativeContainmentDeath(value: NativeContainmentDeathObservation): void {
  if (!observedDeaths.has(value)) throw new TypeError('death requires an actual native containment observation');
}

/** Called synchronously by the existing immediate pre-I/O StateStore gate. */
export function releaseLinuxInvocation(value: unknown, expected: LinuxInvocationClaim): void {
  const held = value !== null && typeof value === 'object' ? invocations.get(value) : undefined;
  if (held === undefined) throw new TypeError('release requires an actual opaque invocation');
  if (canonicalSha256(held.claim) !== canonicalSha256(expected)) {
    throw new KernelStorageError('LEASE_FENCED', 'native invocation belongs to another permanent claim');
  }
  if (held.consumed) throw new KernelStorageError('LEASE_FENCED', 'invocation release was already consumed');
  // A failed send cannot be retried as another release. Recovery must inspect the claim.
  held.consumed = true;
  held.release();
}

function mismatch(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }
function same(value: unknown, expected: unknown, label: string): void {
  if (canonicalSha256(value) !== canonicalSha256(expected)) mismatch(`${label} differs from the installed execution authority`);
}

function retirementError(message: string, cause: unknown): ResourceRetirementError {
  return cause instanceof ResourceRetirementError ? cause : new ResourceRetirementError(message, cause);
}

async function retireFiles(handles: readonly FileHandle[]): Promise<void> {
  let failure: ResourceRetirementError | undefined;
  for (const handle of handles) {
    try { await handle.close(); }
    catch (error) { failure ??= retirementError('installed descriptor retirement failed', error); }
  }
  if (failure) throw failure;
}

async function joinController(controller: NativeController): Promise<void> {
  try { await controller.close(); }
  catch (error) { throw retirementError('native controller join failed', error); }
}

function retireImage(image: NativeImage): void {
  try { image.close(); }
  catch (error) { throw retirementError('native image retirement failed', error); }
}

function retireBorrow(borrowed: Readonly<{ close(): void }>, primary?: { error: unknown }): void {
  try { borrowed.close(); }
  catch (error) { throw retirementError('native execution descriptor did not retire',
    primary ? new AggregateError([primary.error, error], 'operation and descriptor retirement failures') : error); }
}

async function openDirectory(absolute: string): Promise<FileHandle> {
  normalizeAbsolutePath(absolute);
  let directory = await open('/', constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  const held = new Set([directory]);
  try {
    for (const component of absolute.split('/').slice(1)) {
      const next = await open(`/proc/self/fd/${directory.fd}/${component}`, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      held.add(next);
      await retireFiles([directory]); held.delete(directory); directory = next;
    }
    return directory;
  } catch (error) {
    try { await retireFiles([...held]); }
    catch (cleanup) { throw retirementError('directory lookup and retirement failed', new AggregateError([error, cleanup])); }
    throw error;
  }
}

async function openInstalledFile(directory: FileHandle, relative: string): Promise<FileHandle> {
  const parts = relative.split('/');
  if (parts.some(part => !part || part === '.' || part === '..' || part.includes('\\'))) mismatch('invalid installed image locator');
  const held: FileHandle[] = [];
  let file: FileHandle | undefined;
  try {
    let parent = directory;
    for (const component of parts.slice(0, -1)) {
      parent = await open(`/proc/self/fd/${parent.fd}/${component}`, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      held.push(parent);
    }
    file = await open(`/proc/self/fd/${parent.fd}/${parts.at(-1)!}`, constants.O_RDONLY | constants.O_NOFOLLOW);
    await retireFiles([...held].reverse());
    return file;
  } catch (error) {
    try { await retireFiles([...held].reverse().concat(file ? [file] : [])); }
    catch (cleanup) { throw retirementError('installed image lookup and retirement failed', new AggregateError([error, cleanup])); }
    throw error;
  }
}

async function hashHeld(fd: number, byteCount: number, recheck: () => void): Promise<string> {
  const before = fstatSync(fd, { bigint: true });
  if (!before.isFile() || before.size !== BigInt(byteCount) || byteCount <= 0 || byteCount > 268_435_456) mismatch('runtime image is not a bounded regular file');
  const buffer = Buffer.alloc(Math.min(byteCount, 1_048_576)); const hash = createHash('sha256');
  for (let offset = 0; offset < byteCount;) {
    await setImmediate(); recheck();
    const count = readSync(fd, buffer, 0, Math.min(buffer.length, byteCount - offset), offset);
    if (count === 0) mismatch('runtime image was truncated');
    hash.update(buffer.subarray(0, count)); offset += count;
  }
  const after = fstatSync(fd, { bigint: true });
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs) mismatch('runtime image changed while hashing');
  recheck(); return hash.digest('hex');
}

function guestInput(toolchain: RetainedVerifierToolchain): NativeGuestExtractionInput {
  const manifest = toolchain.manifest;
  if (manifest.architecture !== 'x86_64' || manifest.node.canonicalGuestPath !== LINUX_VERIFIER_RECIPE.nodePath ||
      manifest.guestImageByteCount > GUEST_EXTRACTOR_RECIPE.maxImageBytes || toolchain.abiFingerprint !== manifest.manifestDigest)
    throw new LinuxExecutionIdentityError('guest toolchain is outside the fixed Linux Node recipe');
  return { imageDigest: manifest.guestImageDigest, imageByteCount: manifest.guestImageByteCount,
    nodePath: manifest.node.canonicalGuestPath, nodeDigest: manifest.node.digest, architecture: 'x86_64',
    pinnedExecutables: guestToolchainExecutables(manifest).map(entry => ({ path: entry.canonicalGuestPath, digest: entry.digest })) };
}

function assertGuestDescription(owner: Pick<NativeGuestToolchain, 'describe'>, toolchain: RetainedVerifierToolchain): void {
  const description = owner.describe(), manifest = toolchain.manifest;
  if (description.imageDigest !== manifest.guestImageDigest || description.nodePath !== manifest.node.canonicalGuestPath ||
      description.nodeDigest !== manifest.node.digest || description.files.length < 2 || description.files.length > GUEST_EXTRACTOR_RECIPE.maxMappedFiles ||
      !description.files.some(file => file.path === manifest.node.canonicalGuestPath && file.digest === manifest.node.digest))
    mismatch('actual frozen Node mapping differs from its retained signed guest toolchain');
}

function scopeProjection(closure: WorkerLaunchClosure | BuiltinEditLaunchClosure | VerifierLaunchClosure, borrowed: BorrowedGenerationForExecution, activationNonceDigest: string) {
  const backend = closure.plan.backend;
  if (backend.kind !== 'linux') mismatch('worker requires the Linux containment plan');
  const device = Number(borrowed.identity.deviceId), inode = Number(borrowed.identity.fileId);
  if (!Number.isSafeInteger(device) || !Number.isSafeInteger(inode)) mismatch('generation native identifiers exceed the supported exact integer range');
  return { ...closure.spec.resources, generationDevice: device, generationInode: inode,
    cgroupName: path.posix.basename(backend.cgroupPath), spawnNonceDigest: closure.plan.launchNonceDigest, activationNonceDigest };
}

function reservationProjection(closure: WorkerLaunchClosure, reservation: HeldWorkerReservation, activationNonceDigest: string) {
  assertWorkerLaunchClosure(closure); assertArtifactRef(activationNonceDigest); reservation.assertHeld();
  const backend = closure.plan.backend, locator = closure.generation.locator;
  if (backend.kind !== 'linux' || !backend.nativeReservation || locator.kind !== 'linux_directory') {
    mismatch('the installed worker recipe requires a descriptor-bound physical witness');
  }
  same(reservation.identity, backend.nativeReservation, 'native reservation identity');
  const number = (value: string) => {
    const result = Number(value);
    if (!/^(0|[1-9][0-9]*)$/u.test(value) || !Number.isSafeInteger(result) || result < 0) mismatch('native identity exceeds the exact integer range');
    return result;
  };
  return { planRef: closure.containmentPlanRef, sandboxLaunchSpecRef: closure.sandboxLaunchSpecRef,
    sandboxLaunchSpecDigest: closure.spec.launchSpecDigest, workspaceGenerationRef: closure.workspaceGenerationRef,
    spawnNonceDigest: closure.plan.launchNonceDigest, activationNonceDigest,
    cgroupName: path.posix.basename(backend.cgroupPath), pidNamespaceReservationId: backend.pidNamespaceReservationId,
    subreaperStartToken: backend.subreaperStartToken, reservationDevice: number(reservation.identity.deviceId),
    reservationInode: number(reservation.identity.fileId), reservationOwnerUid: reservation.identity.ownerUid,
    generationDevice: number(locator.deviceId), generationInode: number(locator.directoryFileId) };
}

function supportedRecipe(closure: WorkerLaunchClosure | BuiltinEditLaunchClosure): void {
  const spec = closure.spec;
  if (canonicalSha256(spec.environment) !== canonicalSha256(LINUX_WORKER_RECIPE.environment) ||
      spec.runtime.launcher.executableId !== LINUX_WORKER_RECIPE.launcherId ||
      spec.resources.maxIpcFrameBytes !== LINUX_WORKER_RECIPE.maxIpcFrameBytes ||
      spec.resources.maxQueuedIpcBytes !== LINUX_WORKER_RECIPE.maxQueuedIpcBytes || spec.resources.maxProcesses < 8 ||
      spec.resources.maxSingleFileBytes > 268_435_456) {
    throw new LinuxExecutionIdentityError('launch environment/runtime is outside the installed closed recipe');
  }
  // Filesystem and the selected signed runtime/executable are the literal
  // recipe's RO/RW source. This first recipe implements only its two declared
  // fresh ephemeral roots, not arbitrary additional CAS/generation mounts.
  if (spec.mounts.length !== 2 || !spec.mounts.every(mount => mount.kind === 'private_ephemeral' && mount.access === 'read_write' &&
      ((mount.targetPath === '/home/cliq' && mount.purpose === 'home') || (mount.targetPath === '/tmp' && mount.purpose === 'tmp'))) ||
      new Set(spec.mounts.map(mount => mount.targetPath)).size !== 2) {
    throw new LinuxExecutionIdentityError('the installed recipe does not implement additional launch mounts');
  }
}

function supportedVerifierRecipe(closure: VerifierLaunchClosure): void {
  const { spec, command, environment, toolchain } = closure;
  const executable = command.executable;
  if (spec.purpose !== 'verifier' || executable.kind !== 'guest_toolchain' || spec.executable.kind !== 'guest_toolchain' ||
      executable.executionPath !== LINUX_VERIFIER_RECIPE.nodePath || executable.executableDigest !== toolchain.manifest.node.digest ||
      executable.guestToolchainManifestRef !== toolchain.manifestRef || executable.guestToolchainManifestDigest !== toolchain.manifest.manifestDigest ||
      command.argv.length !== 3 || command.argv[0]?.value !== '--test' || command.argv[1]?.value !== '--test-concurrency=1' ||
      !command.argv[2]?.value.endsWith('.mjs') || environment.variables.length !== 0 || environment.writableEphemeralPaths.length !== 0 ||
      canonicalSha256(spec.environment) !== canonicalSha256(LINUX_VERIFIER_RECIPE.environment) ||
      spec.runtime.launcher.executableId !== LINUX_VERIFIER_RECIPE.launcherId ||
      spec.resources.maxIpcFrameBytes !== LINUX_VERIFIER_RECIPE.maxIpcFrameBytes ||
      spec.resources.maxQueuedIpcBytes !== LINUX_VERIFIER_RECIPE.maxQueuedIpcBytes || spec.resources.maxProcesses < LINUX_VERIFIER_RESOURCE_MINIMUMS.maxProcesses ||
      spec.resources.maxSingleFileBytes < toolchain.manifest.guestImageByteCount || spec.resources.maxSingleFileBytes > GUEST_EXTRACTOR_RECIPE.maxImageBytes ||
      spec.filesystem.kind !== 'run_generation' || spec.filesystem.access !== 'read_only' ||
      spec.mounts.length !== 2 || !spec.mounts.every(mount => mount.kind === 'private_ephemeral' && mount.access === 'read_write' &&
        ((mount.targetPath === '/home/cliq' && mount.purpose === 'home') || (mount.targetPath === '/tmp' && mount.purpose === 'tmp'))) ||
      new Set(spec.mounts.map(mount => mount.targetPath)).size !== 2)
    throw new LinuxExecutionIdentityError('verifier is outside the fixed signed read-only Node test recipe');
}

function verifierOutcome(raw: NativeVerifierOutcome, containment: ProcessContainment): NativeVerifierResult {
  for (const value of [raw.startedAtMs, raw.endedAtMs, raw.durationMs])
    if (!Number.isSafeInteger(value) || value < 0) mismatch('native verifier time measurement is invalid');
  if (raw.startedAtMs === 0 || raw.endedAtMs < raw.startedAtMs || !Buffer.isBuffer(raw.stdout) || !Buffer.isBuffer(raw.stderr) ||
      ![0, 1].includes(raw.stdoutTruncated) || ![0, 1].includes(raw.stderrTruncated)) mismatch('native verifier result is invalid');
  const base = { startedAt: new Date(raw.startedAtMs).toISOString(), endedAt: new Date(raw.endedAtMs).toISOString(), durationMs: raw.durationMs,
    stdout: Buffer.from(raw.stdout), stderr: Buffer.from(raw.stderr), stdoutTruncated: raw.stdoutTruncated === 1, stderrTruncated: raw.stderrTruncated === 1,
    death: checkedDeath(raw.death, containment) };
  let result: NativeVerifierResult;
  if (raw.termination === 1 && Number.isInteger(raw.exitCode) && raw.exitCode >= 0 && raw.exitCode <= 255)
    result = Object.freeze({ ...base, terminationReason: 'exit', exitCode: raw.exitCode });
  else if (raw.termination === 2) {
    const signal = Object.entries(osConstants.signals).find(([, value]) => value === raw.signal)?.[0];
    if (!signal) mismatch('native verifier termination signal is invalid');
    result = Object.freeze({ ...base, terminationReason: 'signal', signal });
  } else if (raw.termination === 3 && Number.isInteger(raw.nativeErrorCode) && raw.nativeErrorCode > 0)
    result = Object.freeze({ ...base, terminationReason: 'spawn_error', nativeErrorCode: raw.nativeErrorCode });
  else if (raw.termination === 4 || raw.termination === 5)
    result = Object.freeze({ ...base, terminationReason: raw.termination === 4 ? 'timeout' : 'resource_failure' });
  else if (raw.termination === 6 && raw.exitCode === 0 && raw.signal === 0 && raw.nativeErrorCode === 0)
    result = Object.freeze({ ...base, terminationReason: 'controller_stop' });
  else mismatch('native verifier termination is unsupported');
  verifierResults.set(result, Object.freeze({ stdout: Buffer.from(raw.stdout), stderr: Buffer.from(raw.stderr) })); return result;
}

function actualContainment(closure: WorkerLaunchClosure | BuiltinEditLaunchClosure | VerifierLaunchClosure, observed: NativeObservation,
  createdAt = sampleCanonicalNow()): ProcessContainment {
  const backend = closure.plan.backend;
  if (backend.kind !== 'linux') mismatch('worker requires Linux containment');
  return immutableSnapshot({ schemaVersion: 1, planRef: canonicalSha256(closure.plan), sandboxLaunchSpecRef: closure.sandboxLaunchSpecRef,
    sandboxLaunchSpecDigest: closure.spec.launchSpecDigest, owner: closure.plan.owner, filesystemBinding: closure.plan.filesystemBinding,
    ...(closure.plan.parentContainmentRef ? { parentContainmentRef: closure.plan.parentContainmentRef } : {}),
    launchNonceDigest: closure.plan.launchNonceDigest,
    backend: { kind: 'linux', pidNamespaceReservationId: backend.pidNamespaceReservationId, pidNamespaceId: observed.pidNamespaceId,
      cgroupPath: backend.cgroupPath, cgroupId: observed.cgroupId, namespaceInitStartToken: observed.namespaceInitStartToken,
      subreaperStartToken: backend.subreaperStartToken }, createdAt });
}

async function awaitNative<T>(poll: () => T | undefined, close: () => Promise<void>, signal?: AbortSignal,
  observationTimeoutMs = 6000, pollIntervalMs = 1): Promise<T> {
  const deadline = performance.now() + observationTimeoutMs;
  let abortedJoin: Promise<void> | undefined;
  const abort = () => {
    // close revokes the actual native controller synchronously. Retain its
    // real join, rather than winning a timer race against productive work.
    try { abortedJoin = close(); } catch (error) { abortedJoin = Promise.reject(error); }
    void abortedJoin.catch(() => {}); // Observed by this operation's catch below.
  };
  signal?.addEventListener('abort', abort, { once: true });
  try {
    if (signal?.aborted) abort();
    for (;;) {
      signal?.throwIfAborted();
      const value = poll();
      signal?.throwIfAborted();
      if (value !== undefined) return value;
      if (performance.now() >= deadline) throw new KernelStorageError('RECOVERY_REQUIRED', 'native operation observation timed out');
      await delay(pollIntervalMs, undefined, { signal });
    }
  } catch (error) {
    try { await (abortedJoin ?? close()); }
    catch (failure) { throw retirementError('native operation failed and controller join did not complete', new AggregateError([error, failure])); }
    throw error;
  } finally { signal?.removeEventListener('abort', abort); }
}

async function death(scope: NativeScope, containment: ProcessContainment, controller: NativeController,
  recheck: () => void): Promise<NativeContainmentDeathObservation> {
  scope.stop();
  const observed = await awaitNative(() => scope.pollStopped(), () => joinController(controller));
  recheck();
  return checkedDeath(observed, containment);
}

function checkedDeath(observed: NativeObservation, containment: ProcessContainment): NativeContainmentDeathObservation {
  if (containment.backend.kind !== 'linux' || observed.cgroupId !== containment.backend.cgroupId ||
      observed.pidNamespaceId !== containment.backend.pidNamespaceId || observed.namespaceInitStartToken !== containment.backend.namespaceInitStartToken ||
      observed.cgroupPopulated !== 0 || observed.namespaceInitDeadAndReaped !== 1 || observed.remainingTrackedDescendants !== 0) mismatch('native death does not close the exact containment');
  if (!Number.isSafeInteger(observed.observedAtMs) || observed.observedAtMs < 1) mismatch('native death observation timestamp is invalid');
  const observedAt = new Date(observed.observedAtMs).toISOString();
  const observation: NativeContainmentDeathObservation = immutableSnapshot({ containment, cgroupPopulated: 0,
    namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0, observedAt });
  observedDeaths.add(observation); return observation;
}

async function observedProcess(scope: NativeScope, expectedDigest: string): Promise<LinuxObservedProcess> {
  const initial = scope.observe();
  const digest = await hashHeld(initial.imageFd, initial.imageByteCount, () => {
    const current = scope.observe();
    if (current.pid !== initial.pid || current.processStartToken !== initial.processStartToken || current.imageFd !== initial.imageFd) mismatch('worker identity changed during image verification');
  });
  if (digest !== expectedDigest) mismatch('native worker executable is not the exact signed image');
  return immutableSnapshot({ pid: initial.pid, processStartToken: initial.processStartToken,
    executableRealpath: initial.executableRealpath, executableDigest: digest });
}

/** Production execution is separate from the disposable M0 probe. Opening
 * verifies held signed images only: it never spawns a controller or worker. */
export async function openLinuxWorkerLauncher(options?: LinuxWorkerInstallation): Promise<LinuxWorkerLauncher> {
  if (process.platform !== 'linux') {
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'Linux worker execution is unavailable on this platform');
  }
  if (options === undefined) throw new LinuxExecutionIdentityError('a verified production worker installation is required');
  const bundle = immutableSnapshot(options.runtimeAuthority.bundle);
  verifyRuntimeBundle(bundle, options.runtimeAuthority.releaseKeys);
  const installation = await openDirectory(options.installationRoot);
  let cgroup: FileHandle;
  try { cgroup = await openDirectory(options.cgroupParent); }
  catch (error) {
    try { await retireFiles([installation]); }
    catch (cleanup) { throw retirementError('cgroup lookup and installation retirement failed', new AggregateError([error, cleanup])); }
    throw error;
  }
  let loadedBinding: NativeBinding | undefined;
  async function startSignedGuest(toolchain: RetainedVerifierToolchain, signal: AbortSignal | undefined, sourceGit: false): Promise<HeldGuestPreparation>;
  async function startSignedGuest(toolchain: RetainedVerifierToolchain, signal: AbortSignal | undefined, sourceGit: true): Promise<Readonly<{ job: NativeSourceGitToolchain; close(): Promise<void> }>>;
  async function startSignedGuest(toolchain: RetainedVerifierToolchain, signal: AbortSignal | undefined, sourceGit: boolean) {
    const entry = bundle.entries.find(value => value.entryId === GUEST_EXTRACTOR_RECIPE.entryId);
    const imageEntry = bundle.entries.find(value => value.digest === toolchain.manifest.guestImageRef);
    if (!entry || entry.role !== 'platform_helper' || !entry.executable || entry.version !== '1' ||
        !imageEntry || imageEntry.executable || imageEntry.role !== 'bundle_object' ||
        imageEntry.byteCount !== toolchain.manifest.guestImageByteCount) mismatch('signed guest helper/image closure is missing');
    const handles: FileHandle[] = []; let job: NativeGuestToolchain | NativeSourceGitToolchain | undefined;
    try {
      const addon = await openInstalledFile(installation, entry.relativePath); handles.push(addon);
      const image = await openInstalledFile(installation, imageEntry.relativePath); handles.push(image);
      const metadata = await addon.stat();
      if (!metadata.isFile() || metadata.mode & 0o022 || (metadata.uid !== process.geteuid!() && metadata.uid !== 0) || metadata.size !== entry.byteCount ||
          await hashHeld(addon.fd, entry.byteCount, () => signal?.throwIfAborted()) !== entry.digest)
        mismatch('native guest extractor is not the exact signed image');
      const loaded = new Module('cliq-linux-guest-extractor'); process.dlopen(loaded, `/proc/self/fd/${addon.fd}`);
      const extractor = loaded.exports as NativeGuestExtractorBinding;
      if (extractor.interfaceVersion !== 1 || (sourceGit ? typeof extractor.beginSourceGit !== 'function' : typeof extractor.begin !== 'function'))
        mismatch('unsupported signed guest extractor interface');
      job = sourceGit ? extractor.beginSourceGit!(image.fd, guestInput(toolchain)) : extractor.begin(image.fd, guestInput(toolchain));
      const original = job;
      await awaitNative(() => original.pollReady() ? true : undefined, () => original.close(), signal, 15_000);
      assertGuestDescription(original, toolchain);
      if (sourceGit) {
        const source = (original as NativeSourceGitToolchain).describe();
        if (toolchain.manifest.git.canonicalGuestPath !== '/usr/bin/git' || source.gitPath !== '/usr/bin/git' ||
            source.gitDigest !== toolchain.manifest.git.digest || !source.files.some(file => file.path === '/usr/bin/git' && file.digest === source.gitDigest))
          mismatch('actual frozen Git mapping differs from its retained signed guest toolchain');
      }
      return Object.freeze({ job: original, close: () => original.close() });
    } catch (error) {
      if (job) try { await job.close(); }
      catch (cleanup) { throw retirementError('signed guest construction and original extraction did not join', new AggregateError([error, cleanup])); }
      throw error;
    }
    finally {
      try { await retireFiles(handles); }
      catch (error) {
        if (job) try { await job.close(); }
        catch (cleanup) { throw retirementError('guest source and original extraction did not retire', new AggregateError([error, cleanup])); }
        throw error;
      }
    }
  }
  return openWorkerLauncher(bundle, options.cgroupParent, {
    assertHeld() {},
    withRoot(operation) { operation(cgroup.fd); },
    async loadNative(recheck) {
      const addonEntry = bundle.entries.find(entry => entry.entryId === 'linux_worker_native');
      if (!addonEntry || addonEntry.role !== 'platform_helper' || !addonEntry.executable) mismatch('signed worker native module is missing');
      const addon = await openInstalledFile(installation, addonEntry.relativePath);
      try {
        const metadata = await addon.stat();
        if ((metadata.mode & 0o022) !== 0 || (metadata.uid !== process.geteuid!() && metadata.uid !== 0) ||
            metadata.size !== addonEntry.byteCount ||
            await hashHeld(addon.fd, metadata.size, recheck) !== addonEntry.digest) mismatch('installed native worker module is not signed');
        const loaded = new Module('cliq-linux-worker-native');
        process.dlopen(loaded, `/proc/self/fd/${addon.fd}`);
        loadedBinding = loaded.exports as NativeBinding; return loadedBinding;
      } finally { await retireFiles([addon]); }
    },
    async image(entryId, binding) {
      const entry = bundle.entries.find(value => value.entryId === entryId)!;
      const source = await openInstalledFile(installation, entry.relativePath);
      let sealed: NativeImage | undefined, primary: { error: unknown } | undefined;
      try { sealed = binding.sealImage(source.fd); }
      catch (error) { primary = { error }; }
      try { await retireFiles([source]); }
      catch (error) {
        if (sealed) retireImage(sealed);
        throw error;
      }
      if (primary) throw primary.error;
      return sealed!;
    },
    async guest(toolchain, signal) {
      return startSignedGuest(toolchain, signal, false);
    },
    async preparing(toolchain, signal) {
      const entry = bundle.entries.find(value => value.entryId === 'source_git_inspector');
      if (!loadedBinding || loadedBinding.sourceInterfaceVersion !== 1 || !entry || entry.role !== 'platform_helper' || entry.executable ||
          entry.version !== '1' || entry.relativePath !== 'helpers/source-git-inspector.mjs' || entry.byteCount < 1 || entry.byteCount > 1_048_576)
        throw new LinuxExecutionIdentityError('the fixed signed preparing Git inspector is unavailable');
      let inspector: NativeSourceGitInspectorImage | undefined, guest: Awaited<ReturnType<typeof startSignedGuest>> | undefined;
      let closing: Promise<void> | undefined;
      const close = () => closing ??= (async () => {
        const failures: unknown[] = [];
        if (guest) try { await guest.close(); } catch (error) { failures.push(error); }
        if (inspector) try { inspector.close(); } catch (error) { failures.push(error); }
        if (failures.length) throw retirementError('signed preparing Git runtime did not join', new AggregateError(failures));
      })();
      try {
        const source = await openInstalledFile(installation, entry.relativePath);
        let sealingFailure: { error: unknown } | undefined;
        try {
          const metadata = await source.stat();
          if (!metadata.isFile() || metadata.mode & 0o022 || (metadata.uid !== process.geteuid!() && metadata.uid !== 0) || metadata.size !== entry.byteCount ||
              await hashHeld(source.fd, entry.byteCount, () => signal?.throwIfAborted()) !== entry.digest)
            mismatch('preparing inspector is not the exact signed image');
          inspector = loadedBinding.sealSourceGitInspector(source.fd);
          if (inspector.identity.sha256 !== entry.digest || inspector.identity.byteCount !== entry.byteCount)
            mismatch('preparing inspector differs from its signed bytes');
        } catch (error) { sealingFailure = { error }; }
        try { await retireFiles([source]); }
        catch (error) { throw retirementError('preparing inspector source did not join', new AggregateError([...(sealingFailure ? [sealingFailure.error] : []), error])); }
        if (sealingFailure) throw sealingFailure.error;
        guest = await startSignedGuest(toolchain, signal, true); signal?.throwIfAborted();
        return Object.freeze({ guest: guest.job, inspector: inspector!, close });
      } catch (error) {
        try { await close(); }
        catch (cleanup) { throw retirementError('signed preparing Git construction and join failed', new AggregateError([error, cleanup])); }
        throw error;
      }
    },
    close: () => retireFiles([cgroup, installation]),
  });
}

/** The two real installation adapters share one image/controller owner. Root
 * descriptors exist only inside fixed synchronous native operations. */
async function openWorkerLauncher(bundle: RuntimeBundleManifest, cgroupParent: string, source: {
  assertHeld(): void;
  withRoot(operation: (fd: number) => void): void;
  loadNative(recheck: () => void): Promise<NativeBinding>;
  image(entryId: string, binding: NativeBinding): Promise<NativeImage>;
  guest(toolchain: RetainedVerifierToolchain, signal?: AbortSignal): Promise<HeldGuestPreparation>;
  preparing?(toolchain: RetainedVerifierToolchain, signal?: AbortSignal): Promise<HeldPreparingGitRuntime>;
  close(): Promise<void>;
}): Promise<LinuxWorkerLauncher> {
  const controllers = new Set<NativeController>(); let closed = false, closing: Promise<void> | undefined;
  const installed = new Map<string, Promise<NativeImage>>();
  const guestOpenings = new Set<Promise<HeldGuestPreparation>>(), guests = new Set<HeldGuestPreparation>();
  const installationAbort = new AbortController();
  const receiver = () => {
    if (closed) throw new KernelStorageError('LEASE_FENCED', 'worker installation scope is closed');
    source.assertHeld();
  };
  async function closeInstallation(): Promise<void> {
    let failed = false, failure: unknown;
    const remember = (error: unknown) => { if (!failed) { failed = true; failure = error; } };
    // Each native close revokes synchronously; one failed join must not skip
    // revoking or joining the other actual controllers.
    const joins = [...controllers].map(controller => {
      return joinController(controller);
    });
    for (const result of await Promise.allSettled(joins)) if (result.status === 'rejected') remember(result.reason);
    controllers.clear();
    for (const opening of guestOpenings) {
      try { guests.add(await opening); } catch (error) { if (error instanceof ResourceRetirementError) remember(error); }
    }
    for (const guest of guests) try { await guest.close(); } catch (error) { remember(error); }
    guests.clear(); guestOpenings.clear();
    // The same cache owns in-flight seals too. Closing cannot outrun an image
    // still being validated, and a concurrent reader never creates a second seal.
    for (const opening of installed.values()) {
      let image: NativeImage;
      try { image = await opening; }
      catch (error) { if (error instanceof ResourceRetirementError) remember(error); continue; }
      try { retireImage(image); } catch (error) { remember(error); }
    }
    installed.clear();
    try { await source.close(); } catch (error) { remember(error); }
    if (failed) throw retirementError('worker installation retirement failed', failure);
  }
  try {
    const binding = await source.loadNative(receiver);
    receiver();
    if (binding.interfaceVersion !== 3 || typeof binding.sealImage !== 'function' || typeof binding.sealImageBuffer !== 'function' ||
        typeof binding.openController !== 'function') mismatch('unsupported installed native worker interface');
    function image(entryId: string, role: string): Promise<NativeImage> {
      receiver(); const existing = installed.get(entryId); if (existing) return existing;
      const entry = bundle.entries.find(value => value.entryId === entryId);
      if (!entry || entry.role !== role || !entry.executable) mismatch('executable is not in the signed production bundle');
      const opening = (async () => {
        const sealed = await source.image(entryId, binding);
        try {
          if (await hashHeld(sealed.descriptor(), entry.byteCount, receiver) !== entry.digest) mismatch('sealed installed image differs from its signed digest');
          return sealed;
        } catch (error) { retireImage(sealed); throw error; }
      })().catch(error => {
        // A transient failure owns no image after cleanup; keep uncertain
        // retirement observable by closeInstallation instead of erasing it.
        if (!(error instanceof ResourceRetirementError) && installed.get(entryId) === opening) installed.delete(entryId);
        throw error;
      });
      installed.set(entryId, opening);
      return opening;
    }
    const helper = await image('linux_worker_controller', 'platform_helper');
    const bwrap = await image('linux_bubblewrap', 'platform_helper');
    const launcher: LinuxWorkerLauncher = Object.freeze({
      async startController(controlOptions) {
        if (this !== launcher) throw new TypeError('invalid worker launcher receiver'); receiver();
        const signal = controlOptions?.signal;
        signal?.throwIfAborted();
        let native!: NativeController;
        let controllerClosed = false, controllerClosing: Promise<void> | undefined;
        const controllerAbort = new AbortController();
        const controllerGuestOpenings = new Set<Promise<HeldGuestPreparation>>(), controllerGuests = new Set<HeldGuestPreparation>();
        const preparingOpenings = new Set<Promise<HeldPreparingGitRuntime>>(), preparingRuntimes = new Set<HeldPreparingGitRuntime>();
        let preparingOpened = false;
        const controllerVerifierStops = new Set<(deadline: number) => Promise<void>>();
        let retainedDeath: NativeContainmentDeathObservation | undefined;
        let retired: NativeRetainedWorkerRetirement | undefined;
        let preactivation: { closure: WorkerLaunchClosure; reservation: HeldWorkerReservation;
          activationNonceDigest: string; observation: NativePreactivationObservation } | undefined;
        let retiredPreactivation: NativePreactivationRetirement | undefined;
        let retiredPreparation: NativeControllerPreparationRetirement | undefined;
        const closeController = () => {
          controllerClosed = true;
          if (!controllerClosing) {
            // Revoke the original released invocation synchronously, before
            // abort listeners can join this same close. Only its bounded STOP
            // and output observation remain live; every productive TS receiver
            // has already been revoked above. Ordinary/prepare closes still
            // enter the native channel revocation without this observation.
            const stops: Promise<void>[] = [], deadline = performance.now() + 2000;
            for (const stop of controllerVerifierStops) {
              try { stops.push(stop(deadline)); }
              catch (error) { stops.push(Promise.reject(error)); }
            }
            const joiningNative = stops.length === 0 && native ? joinController(native) : undefined;
            controllerClosing = (async () => {
              let failure: unknown;
              for (const stop of stops) try { await stop; } catch (error) { failure ??= error; }
              try { await (joiningNative ?? (native ? joinController(native) : Promise.resolve())); }
              catch (error) { failure ??= error; }
              for (const opening of controllerGuestOpenings) {
                try { controllerGuests.add(await opening); }
                catch (error) { if (error instanceof ResourceRetirementError) failure ??= error; }
              }
              for (const guest of controllerGuests) {
                try { await guest.close(); guests.delete(guest); }
                catch (error) { failure ??= error; }
              }
              controllerGuests.clear();
              for (const opening of preparingOpenings) {
                try { preparingRuntimes.add(await opening); }
                catch (error) { if (error instanceof ResourceRetirementError) failure ??= error; }
              }
              for (const runtime of preparingRuntimes) try { await runtime.close(); } catch (error) { failure ??= error; }
              preparingRuntimes.clear();
              if (failure !== undefined) throw retirementError('worker controller or guest extraction did not join', failure);
            })();
          }
          controllerAbort.abort();
          return controllerClosing;
        };
        const controllerReceiver = () => {
          receiver();
          if (controllerClosed) throw new KernelStorageError('LEASE_FENCED', 'worker controller scope is closed');
        };
        const retirementReceiver = () => {
          if (closed || controllerClosed) throw new KernelStorageError('LEASE_FENCED', 'worker controller scope is closed');
        };
        try {
          source.withRoot(fd => {
            native = binding.openController(helper, fd);
            // Capture and register before the borrow's postcheck can throw.
            controllers.add(native);
          });
          await awaitNative(() => native.pollReady() ? true : undefined, closeController, signal);
          controllerReceiver(); signal?.throwIfAborted();
          const observeBirth = () => {
            controllerReceiver(); let observed!: NativeControllerPreparationBirthObservation;
            source.withRoot(fd => { observed = native.observePreparationBirth(fd); });
            return observed;
          };
          const observedBirth = observeBirth(), birthIdentity = controllerPreparationBirthIdentity(observedBirth);
          const controllerBirthDigest = canonicalSha256(birthIdentity);
          const preparationBirth = Object.freeze({}) as NativeControllerPreparationBirth;
          controllerPreparationBirths.set(preparationBirth, { identity: birthIdentity, controllerBirthDigest,
            lastObservedAtMs: observedBirth.observedAtMs, assertCurrent: observeBirth });
          const subreaperStartToken = `linux-subreaper:${native.pid}:${native.processStartToken}`;
          const controller: LinuxWorkerController = Object.freeze({
            pid: native.pid, processStartToken: native.processStartToken, subreaperStartToken, preparationBirth,
            async openPreparingGit({ input, recipe, toolchain, signal: operationSignal }) {
              if (this !== controller) throw new TypeError('invalid worker controller'); controllerReceiver();
              if (preparingOpened || !source.preparing || binding.preparationInterfaceVersion !== 1)
                throw new LinuxExecutionIdentityError('same-controller fixed Git preparation is unavailable or consumed');
              const fixed = preparingRecipe(recipe), original = borrowPreparingGitInputForExecution(input);
              const preparingSignal = AbortSignal.any([controllerAbort.signal, ...(operationSignal ? [operationSignal] : [])]);
              preparingSignal.throwIfAborted(); preparingOpened = true;
              const opening = source.preparing(toolchain, preparingSignal); preparingOpenings.add(opening);
              let runtime: HeldPreparingGitRuntime;
              try { runtime = await opening; preparingRuntimes.add(runtime); preparingOpenings.delete(opening); }
              catch (error) { if (!(error instanceof ResourceRetirementError)) preparingOpenings.delete(opening); throw error; }
              try { controllerReceiver(); preparingSignal.throwIfAborted(); }
              catch (error) {
                try { await runtime.close(); preparingRuntimes.delete(runtime); }
                catch (cleanup) { throw retirementError('preparing runtime was revoked before reserve and failed to join', new AggregateError([error, cleanup])); }
                throw error;
              }
              let reserved = false, registered = false;
              let runtimeClosing: Promise<void> | undefined;
              const held: HeldPreparingGitScope = Object.freeze({
                signal: preparingSignal,
                recipe: fixed,
                reserve() {
                  if (this !== held || reserved) throw new TypeError('invalid or consumed preparing Git receiver');
                  controllerReceiver(); preparingSignal.throwIfAborted(); input.assertHeld();
                  reserved = true;
                  return native.reservePreparationGit(original, helper, bwrap, runtime.guest, runtime.inspector, fixed);
                },
                constructionRetirement() {
                  if (this !== held) throw new TypeError('invalid preparing construction receiver');
                  return reserved ? native.preparationGitConstructionRetirement(original) : undefined;
                },
                registerStop(stop: (deadline: number) => Promise<void>) {
                  if (this !== held || registered || typeof stop !== 'function') throw new TypeError('preparing stop owner is invalid or consumed');
                  controllerReceiver(); registered = true; controllerVerifierStops.add(stop);
                  return () => { controllerVerifierStops.delete(stop); };
                },
                closeRuntime() {
                  if (this !== held) throw new TypeError('invalid preparing runtime receiver');
                  return runtimeClosing ??= runtime.close().then(() => { preparingRuntimes.delete(runtime); });
                },
              });
              return held;
            },
            async cleanupRetainedPreparingGit({ input, recipe, signal: operationSignal }) {
              if (this !== controller) throw new TypeError('invalid preparing cleanup controller'); controllerReceiver();
              if (preparingOpened || binding.preparationInterfaceVersion !== 1)
                throw new LinuxExecutionIdentityError('cleanup-only preparing checker is unavailable or consumed');
              const fixed = preparingRecipe(recipe), original = borrowRetainedPreparingGitInputForCleanup(input);
              const cleanupSignal = AbortSignal.any([controllerAbort.signal, ...(operationSignal ? [operationSignal] : [])]);
              cleanupSignal.throwIfAborted(); preparingOpened = true;
              let scope: NativeRetainedPreparingGitScope | undefined;
              try {
                scope = native.cleanupRetainedPreparingGit(original, fixed);
                const actual = scope;
                await awaitNative(() => actual.pollCleaned(), closeController, cleanupSignal, 2000);
                await closeController();
                const observed = actual.pollRetired();
                if (!observed || observed.origin !== 'original_birth_current_checker' || observed.completed !== 0 ||
                    ![0, 2, 4, 5, 6, 7, 8, 9, 10].includes(observed.lastBirthPhase) ||
                    !Number.isSafeInteger(observed.observedAtMs) || observed.observedAtMs < 1)
                  throw new ResourceRetirementError('preparing cleanup has no complete original prefix and real joined checker', undefined);
                for (const key of ['runId', 'generationId', 'launchId', 'spawnNonceDigest', 'activationNonceDigest',
                  'generationCreationNonceDigest', 'generationRef', 'inputIntentRef', 'originalSupervisorPid', 'originalSupervisorStartToken'] as const)
                  if (observed[key] !== input.identity[key]) throw new ResourceRetirementError('preparing cleanup substitutes its original input', undefined);
                const receipt = Object.freeze({}) as NativeRetainedPreparingGitRetirement;
                retainedPreparingGitRetirements.set(receipt, { observation: immutableSnapshot(observed), input, recipe: fixed,
                  checker: Object.freeze({ pid: native.pid, processStartToken: native.processStartToken, controllerBirthDigest, joined: true }) });
                return receipt;
              } catch (error) {
                const construction = !scope ? native.preparationGitConstructionRetirement(original) : undefined;
                try { await closeController(); }
                catch (cleanup) { throw retirementError('preparing cleanup and original checker join failed', new AggregateError([error, cleanup])); }
                if (construction) {
                  try { if (!construction.pollRetired()) throw new ResourceRetirementError('preparing construction closure is incomplete', undefined); }
                  catch (cleanup) { throw retirementError('preparing cleanup construction did not retire', new AggregateError([error, cleanup])); }
                }
                throw error;
              }
            },
            async bindWorkerReservation({ closure, reservation, activationNonceDigest }) {
              if (this !== controller) throw new TypeError('invalid worker controller'); controllerReceiver();
              same(closure.bundle, bundle, 'reservation bundle');
              if (closure.plan.backend.kind !== 'linux' || closure.plan.backend.subreaperStartToken !== subreaperStartToken ||
                  path.posix.dirname(closure.plan.backend.cgroupPath) !== cgroupParent) mismatch('binding selects another native spawner');
              const config = reservationProjection(closure, reservation, activationNonceDigest);
              const borrowed = borrowWorkerReservationForExecution(reservation, closure.spec.owner.workerLaunchId, closure.plan.launchNonceDigest);
              let primary: { error: unknown } | undefined;
              try {
                borrowed.assertHeld(); native.bindReservation(borrowed.fd, config);
                await awaitNative(() => native.pollBound() ? true : undefined, closeController);
                controllerReceiver(); borrowed.assertHeld(); reservation.assertHeld();
                const receipt = Object.freeze({}) as NativeWorkerReservationBinding;
                workerReservationBindings.set(receipt, { data: immutableSnapshot({ runId: closure.spec.owner.runId,
                  launchId: closure.spec.owner.workerLaunchId, generationRef: closure.workspaceGenerationRef,
                  containmentPlanRef: closure.containmentPlanRef, sandboxLaunchSpecRef: closure.sandboxLaunchSpecRef,
                  spawnNonceDigest: closure.plan.launchNonceDigest, activationNonceDigest, controllerBirthDigest,
                  reservation: reservation.identity }), assertCurrent() {
                  controllerReceiver(); reservation.assertHeld(); readNativeControllerPreparationBirth(preparationBirth);
                  if (!native.pollBound()) mismatch('original native reservation BIND acknowledgement is unavailable');
                } });
                return receipt;
              } catch (error) { primary = { error }; throw error; }
              finally { retireBorrow(borrowed, primary); }
            },
            async inspectPreactivation({ closure, reservation, activationNonceDigest, containment, workerIdentity }) {
              if (this !== controller) throw new TypeError('invalid worker controller'); controllerReceiver();
              assertWorkerLaunchClosure(closure); same(closure.bundle, bundle, 'inspection bundle');
              const backend = closure.plan.backend;
              if (backend.kind !== 'linux' || backend.subreaperStartToken === subreaperStartToken ||
                  path.posix.dirname(backend.cgroupPath) !== cgroupParent) mismatch('inspection requires a fresh controller for the exact old reservation');
              const config = reservationProjection(closure, reservation, activationNonceDigest);
              const borrowed = borrowWorkerReservationForExecution(reservation, closure.spec.owner.workerLaunchId, closure.plan.launchNonceDigest);
              let primary: { error: unknown } | undefined;
              try {
                preactivation = undefined;
                borrowed.assertHeld(); source.withRoot(fd => { native.inspectReservation(fd, borrowed.fd, config); });
                const observed = await awaitNative(() => native.pollReservation(), closeController);
                controllerReceiver(); borrowed.assertHeld(); reservation.assertHeld();
                if (!Number.isSafeInteger(observed.observedAtMs) || observed.observedAtMs < 1) mismatch('native inspection timestamp is invalid');
                const observedAt = new Date(observed.observedAtMs).toISOString();
                let result: NativePreactivationObservation;
                if (observed.kind === 'not_attempted') {
                  if (observed.cgroupPresent || containment || workerIdentity) mismatch('no-spawn contradicts its physical scope or recorded worker');
                  result = immutableSnapshot({ kind: 'no_spawn', observedAt,
                    cgroupObservation: { kind: 'absent' },
                    pidNamespaceObservation: { kind: 'never_created', pidNamespaceReservationId: backend.pidNamespaceReservationId },
                    matchingLaunchNonceProcessCount: 0 });
                } else if (observed.kind === 'created_dead') {
                  const actual = actualContainment(closure, observed, observedAt);
                  if (containment) {
                    same({ ...actual, createdAt: containment.createdAt }, containment, 'retained actual containment');
                  }
                  if (workerIdentity && (workerIdentity.pid !== observed.pid || workerIdentity.processStartToken !== observed.processStartToken ||
                      workerIdentity.processContainmentRef !== canonicalSha256(containment))) mismatch('birth witness substitutes the recorded worker process');
                  const retained = immutableSnapshot(containment ?? actual);
                  result = Object.freeze({ kind: 'created', containment: retained, death: checkedDeath(observed, retained) });
                } else mismatch('unsupported native reservation observation');
                preactivationObservations.set(result, canonicalSha256([closure.containmentPlanRef, closure.sandboxLaunchSpecRef]));
                preactivation = { closure, reservation, activationNonceDigest, observation: result };
                return result;
              } catch (error) { primary = { error }; await closeController(); throw error; }
              finally { retireBorrow(borrowed, primary); }
            },
            async launchWorker({ closure, generation, activationNonceDigest }) {
              if (this !== controller) throw new TypeError('invalid controller receiver'); controllerReceiver(); assertArtifactRef(activationNonceDigest);
              assertWorkerLaunchClosure(closure);
              same(closure.bundle, bundle, 'worker bundle');
              const backend = closure.plan.backend;
              if (backend.kind !== 'linux' || backend.subreaperStartToken !== subreaperStartToken ||
                  path.posix.dirname(backend.cgroupPath) !== cgroupParent || !/^cliq-[0-9a-f]{64}$/u.test(path.posix.basename(backend.cgroupPath))) mismatch('worker plan selects another controller or cgroup reservation');
              supportedRecipe(closure);
              if (closure.spec.executable.kind !== 'runtime_bundle' || closure.spec.executable.executionPath !== LINUX_WORKER_RECIPE.workerPath ||
                  closure.spec.executable.executableId !== LINUX_WORKER_RECIPE.workerId) {
                throw new LinuxExecutionIdentityError('worker launch is outside the installed closed recipe');
              }
              const executable = await image(closure.spec.executable.executableId, 'worker');
              const workerDigest = closure.spec.executable.executableDigest;
              const borrowed = borrowRunWorkspaceForExecution(generation);
              let nativeScope: NativeScope | undefined;
              let dispatchStarted = false;
              try {
                borrowed.assertHeld(); borrowed.assertQuota(closure.spec.resources.maxGenerationBytes);
                if (closure.generation.locator.kind !== 'linux_directory' || closure.generation.locator.deviceId !== borrowed.identity.deviceId ||
                    closure.generation.locator.directoryFileId !== borrowed.identity.fileId) mismatch('worker selected a different physical generation');
                const config = scopeProjection(closure, borrowed, activationNonceDigest);
                source.withRoot(fd => {
                  dispatchStarted = true;
                  nativeScope = native.createWorker(borrowed.fd, fd, helper, executable, bwrap, config);
                });
                const created = nativeScope!;
                await awaitNative(() => created.pollReady() ? true : undefined, closeController); borrowed.assertHeld(); receiver();
                const containment = actualContainment(closure, created.observe()); let active = false, borrowRetired = false;
                const worker: LinuxBlockedWorker = Object.freeze({
                  containment,
                  assertHeld() {
                    if (this !== worker || !active) throw new KernelStorageError('LEASE_FENCED', 'model release requires the original active native worker');
                    controllerReceiver(); borrowed.assertHeld();
                    const current = created.observe();
                    same(actualContainment(closure, current, containment.createdAt), containment, 'current native worker containment');
                    controllerReceiver(); borrowed.assertHeld();
                  },
                  async observeProcess() { if (this !== worker) throw new TypeError('invalid blocked worker'); receiver(); borrowed.assertHeld(); return observedProcess(created, workerDigest); },
                  async activateCommitted(launch) {
                    if (this !== worker) throw new TypeError('invalid blocked worker'); borrowed.assertHeld();
                    if (active || launch.phase !== 'activated' || launch.launchId !== closure.spec.owner.workerLaunchId ||
                        launch.leaseEpoch !== closure.spec.owner.intendedLeaseEpoch || launch.processContainmentRef !== canonicalSha256(containment) ||
                        launch.sandboxLaunchSpecRef !== closure.sandboxLaunchSpecRef || launch.activationNonceDigest !== activationNonceDigest ||
                        launch.generationWriteState !== 'active') throw new KernelStorageError('LEASE_FENCED', 'worker activation does not match the committed launch');
                    active = true; created.activate(activationNonceDigest);
                    await awaitNative(() => created.pollActivated() ? true : undefined, closeController); receiver(); borrowed.assertHeld();
                  },
                  async createInvocation(invocationClosure) {
                    if (this !== worker || !active) throw new KernelStorageError('LEASE_FENCED', 'invocation requires the actual active parent worker');
                    receiver(); borrowed.assertHeld();
                    assertBuiltinEditLaunchClosure(invocationClosure);
                    same(invocationClosure.bundle, bundle, 'invocation bundle');
                    supportedRecipe(invocationClosure);
                    const invocationBackend = invocationClosure.plan.backend;
                    if (invocationBackend.kind !== 'linux' || invocationClosure.plan.parentContainmentRef !== canonicalSha256(containment) || invocationClosure.spec.parentWorkerContainmentRef !== canonicalSha256(containment) ||
                        invocationClosure.spec.executable.kind !== 'runtime_bundle' || invocationClosure.spec.executable.executionPath !== LINUX_WORKER_RECIPE.editPath ||
                        invocationClosure.spec.executable.executableId !== LINUX_WORKER_RECIPE.editId ||
                        invocationClosure.spec.filesystem.kind !== 'run_generation' || invocationClosure.spec.filesystem.generationRef !== closure.workspaceGenerationRef ||
                        path.posix.dirname(invocationBackend.cgroupPath) !== backend.cgroupPath) mismatch('invocation does not select the exact actual parent, recipe and generation');
                    const adapter = await image(invocationClosure.spec.executable.executableId, 'tool_adapter');
                    const adapterDigest = invocationClosure.spec.executable.executableDigest;
                    // The exact JCS input is transferred through the authenticated operation channel, never argv or a writable mount.
                    const input = canonicalJsonBytes(invocationClosure.call.value);
                    if (canonicalSha256(invocationClosure.request) !== invocationClosure.spec.requestRef ||
                        canonicalSha256(invocationClosure.target) !== invocationClosure.spec.targetRef ||
                        canonicalSha256(invocationClosure.grant) !== invocationClosure.spec.operationGrantRef ||
                        canonicalSha256(invocationClosure.call) !== invocationClosure.request.inputRef ||
                        invocationClosure.call.inputDigest !== invocationClosure.request.inputDigest) mismatch('edit input differs from the retained canonical input');
                    const inputImage = binding.sealImageBuffer(input);
                    let scope: NativeScope;
                    try { scope = native.createInvocation(borrowed.fd, created, helper, adapter, bwrap, inputImage,
                      scopeProjection(invocationClosure, borrowed, invocationClosure.plan.launchNonceDigest)); }
                    finally { retireImage(inputImage); }
                    let invocationContainment: ProcessContainment;
                    try {
                      await awaitNative(() => scope.pollReady() ? true : undefined, closeController); borrowed.assertHeld(); receiver();
                      invocationContainment = actualContainment(invocationClosure, scope.observe());
                    } catch (error) { await closeController(); throw error; }
                    const owner = invocationClosure.spec.owner;
                    const claim: LinuxInvocationClaim = immutableSnapshot({ runId: owner.runId, leaseEpoch: owner.intendedLeaseEpoch,
                      workerLaunchId: owner.workerLaunchId, opId: owner.opId, attempt: owner.attempt, dispatchId: owner.dispatchId,
                      sandboxLaunchSpecRef: invocationClosure.sandboxLaunchSpecRef, requestRef: invocationClosure.spec.requestRef,
                      requestDigest: invocationClosure.spec.requestDigest, targetRef: invocationClosure.spec.targetRef, targetDigest: invocationClosure.spec.targetDigest,
                      operationGrantRef: invocationClosure.spec.operationGrantRef, parentWorkerContainmentRef: invocationClosure.spec.parentWorkerContainmentRef });
                    const handle: LinuxBlockedInvocation = Object.freeze({ containment: invocationContainment,
                      async observeProcess() { if (this !== handle) throw new TypeError('invalid blocked invocation'); borrowed.assertHeld(); return observedProcess(scope, adapterDigest); },
                      async result() { if (this !== handle) throw new TypeError('invalid blocked invocation');
                        const status = await awaitNative(() => scope.result(), closeController);
                        if (status !== 0 && status !== 1) mismatch('invalid native edit result'); return status === 0 ? 'ok' : 'error'; },
                      async stop() { if (this !== handle) throw new TypeError('invalid blocked invocation'); return death(scope, invocationContainment, native, retirementReceiver); } });
                    invocations.set(handle, { consumed: false, claim, release() { receiver(); borrowed.assertHeld(); scope.release(); } });
                    return handle;
                  },
                  async createVerifier(verifierClosure, options) {
                    if (this !== worker || !active) throw new KernelStorageError('LEASE_FENCED', 'verifier requires the actual next active parent worker');
                    controllerReceiver(); borrowed.assertHeld(); assertVerifierLaunchClosure(verifierClosure);
                    same(verifierClosure.bundle, bundle, 'verifier bundle'); supportedVerifierRecipe(verifierClosure);
                    const verifierBackend = verifierClosure.plan.backend;
                    if (verifierBackend.kind !== 'linux' || verifierClosure.plan.parentContainmentRef !== canonicalSha256(containment) ||
                        verifierClosure.spec.parentWorkerContainmentRef !== canonicalSha256(containment) ||
                        verifierClosure.spec.filesystem.kind !== 'run_generation' || verifierClosure.spec.filesystem.generationRef !== closure.workspaceGenerationRef ||
                        path.posix.dirname(verifierBackend.cgroupPath) !== backend.cgroupPath || binding.verifierInterfaceVersion !== 1 ||
                        typeof native.createVerifier !== 'function')
                      mismatch('verifier does not select the exact actual parent, generation and fixed native recipe');
                    const signal = AbortSignal.any([installationAbort.signal, controllerAbort.signal, ...(options?.signal ? [options.signal] : [])]);
                    signal.throwIfAborted();
                    const opening = source.guest(verifierClosure.toolchain, signal).then(guest => {
                      guests.add(guest); controllerGuests.add(guest); return guest;
                    });
                    guestOpenings.add(opening); controllerGuestOpenings.add(opening);
                    let guest: HeldGuestPreparation | undefined;
                    try {
                      guest = await opening;
                      controllerReceiver(); borrowed.assertHeld(); signal.throwIfAborted();
                      assertGuestDescription(guest.job, verifierClosure.toolchain);
                      const entry = verifierClosure.verifierEntry;
                      const createdVerifier = native.createVerifier(borrowed.fd, created, helper, bwrap, guest.job, {
                        ...scopeProjection(verifierClosure, borrowed, verifierClosure.plan.launchNonceDigest),
                        arguments: verifierClosure.command.argv.map(argument => argument.value), environment: [],
                        cwd: verifierClosure.command.cwd === '.' ? '/work' : `/work/${verifierClosure.command.cwd}`,
                        timeoutMs: entry.timeoutMs, outputLimitBytes: entry.outputLimitBytes,
                      });
                      // The authenticated SCM_RIGHTS send gave the original
                      // controller its own sealed descriptors. Retire the
                      // extraction producer, not the controller's copies.
                      await guest.close(); guests.delete(guest); controllerGuests.delete(guest);
                      await awaitNative(() => createdVerifier.pollReady() ? true : undefined, closeController, signal);
                      controllerReceiver(); borrowed.assertHeld();
                      const invocationContainment = actualContainment(verifierClosure, createdVerifier.observe());
                      const launcherEntry = bundle.entries.find(entry => entry.entryId === LINUX_VERIFIER_RECIPE.launcherId)!;
                      // Before release this is the real trusted blocked helper,
                      // not a false observation that Node has already executed.
                      await observedProcess(createdVerifier, launcherEntry.digest);
                      const owner = verifierClosure.spec.owner;
                      const claim: LinuxInvocationClaim = immutableSnapshot({ runId: owner.runId, leaseEpoch: owner.intendedLeaseEpoch,
                        workerLaunchId: owner.workerLaunchId, opId: owner.opId, attempt: owner.attempt, dispatchId: owner.dispatchId,
                        sandboxLaunchSpecRef: verifierClosure.sandboxLaunchSpecRef, requestRef: verifierClosure.spec.requestRef,
                        requestDigest: verifierClosure.spec.requestDigest, targetRef: verifierClosure.spec.targetRef,
                        targetDigest: verifierClosure.spec.targetDigest, operationGrantRef: verifierClosure.spec.operationGrantRef,
                        parentWorkerContainmentRef: verifierClosure.spec.parentWorkerContainmentRef });
                      let result: NativeVerifierResult | undefined, resultPending: Promise<NativeVerifierResult> | undefined;
                      let stopping: Promise<NativeContainmentDeathObservation> | undefined;
                      let controlledStop: Promise<void> | undefined;
                      const readResult = () => {
                        if (result) return result;
                        const raw = createdVerifier.result();
                        if (raw === undefined) return undefined;
                        if (typeof raw !== 'object') mismatch('native verifier returned an edit acknowledgement');
                        result = verifierOutcome(raw, invocationContainment);
                        controllerVerifierStops.delete(stopForControllerClose);
                        return result;
                      };
                      const stopForControllerClose = (deadline: number): Promise<void> => {
                        if (controlledStop) return controlledStop;
                        // Native stop_requested permanently consumes release
                        // before returning, including an ordered pending ACK or
                        // POLL. No result measurement exists before RELEASE.
                        createdVerifier.stop();
                        controlledStop = (async () => {
                          const remaining = () => {
                            const value = deadline - performance.now();
                            if (value <= 0) throw new KernelStorageError('RECOVERY_REQUIRED', 'verifier controlled stop exceeded its existing bound');
                            return value;
                          };
                          await awaitNative(() => createdVerifier.pollStopped(), () => joinController(native), undefined, remaining());
                          await awaitNative(readResult, () => joinController(native), undefined, remaining());
                        })();
                        return controlledStop;
                      };
                      const handle: LinuxBlockedVerifier = Object.freeze({ containment: invocationContainment,
                        async result() {
                          if (this !== handle) throw new TypeError('invalid blocked verifier');
                          if (result) return result;
                          if (!resultPending) resultPending = awaitNative(readResult, closeController, signal, entry.timeoutMs + 10_000, 10).catch(error => {
                            // A real reply consumed during irreversible close
                            // still belongs to the original permanent claim.
                            // Its death timestamp is retained, never refreshed.
                            try { const received = readResult(); if (received) return received; } catch { /* No fabricated outcome. */ }
                            throw error;
                          });
                          return resultPending;
                        },
                        async stop() {
                          if (this !== handle) throw new TypeError('invalid blocked verifier');
                          if (controllerClosed && result) return result.death;
                          if (!stopping) stopping = death(createdVerifier, invocationContainment, native, retirementReceiver)
                            .finally(() => { stopping = undefined; });
                          return stopping;
                        } });
                      invocations.set(handle, { consumed: false, claim, release() {
                        controllerReceiver(); borrowed.assertHeld(); createdVerifier.release();
                        controllerVerifierStops.add(stopForControllerClose);
                      } });
                      return handle;
                    } catch (error) {
                      let failure: unknown;
                      if (guest) try { await guest.close(); guests.delete(guest); controllerGuests.delete(guest); } catch (cleanup) { failure = cleanup; }
                      try { await closeController(); } catch (cleanup) { failure ??= cleanup; }
                      if (failure !== undefined) throw retirementError('verifier construction and resource join failed', new AggregateError([error, failure]));
                      throw error;
                    } finally { guestOpenings.delete(opening); controllerGuestOpenings.delete(opening); }
                  },
                  async stop() {
                    if (this !== worker) throw new TypeError('invalid blocked worker'); active = false;
                    try { return await death(created, containment, native, retirementReceiver); }
                    finally {
                      // Fresh STOP uses only the original held native scope. A
                      // retired generation duplicate is never reopened/reused.
                      if (!borrowRetired) { retireBorrow(borrowed); borrowRetired = true; }
                    }
                  },
                  async closeAfterControllerJoin() {
                    if (this !== worker) throw new TypeError('invalid blocked worker');
                    active = false;
                    await closeController();
                    if (!borrowRetired) { retireBorrow(borrowed); borrowRetired = true; }
                  }
                });
                return worker;
              } catch (error) {
                try { if (dispatchStarted) await closeController(); }
                finally { retireBorrow(borrowed); }
                throw error;
              }
            },
            async terminateRetained({ closure, containment, workerIdentity, signal }) {
              if (this !== controller) throw new TypeError('invalid controller receiver'); controllerReceiver();
              retainedDeath = undefined;
              if (signal?.aborted) { await closeController(); signal.throwIfAborted(); }
              assertWorkerLaunchClosure(closure);
              same(closure.bundle, bundle, 'retained worker bundle');
              const planBackend = closure.plan.backend, actual = containment.backend;
              if (planBackend.kind !== 'linux' || actual.kind !== 'linux' ||
                  path.posix.dirname(actual.cgroupPath) !== cgroupParent || actual.cgroupPath !== planBackend.cgroupPath ||
                  containment.planRef !== canonicalSha256(closure.plan) || containment.sandboxLaunchSpecRef !== closure.sandboxLaunchSpecRef ||
                  workerIdentity.processContainmentRef !== canonicalSha256(containment) || actual.subreaperStartToken !== planBackend.subreaperStartToken) {
                mismatch('retained worker does not close the exact native reservation');
              }
              try {
                source.withRoot(fd => { native.terminateRetained(fd, { cgroupName: path.posix.basename(actual.cgroupPath),
                  cgroupId: Number(actual.cgroupId), pidNamespaceId: Number(actual.pidNamespaceId),
                  namespaceInitStartToken: actual.namespaceInitStartToken, subreaperStartToken: actual.subreaperStartToken,
                  workerPid: workerIdentity.pid, processStartToken: workerIdentity.processStartToken }); });
                const observed = await awaitNative(() => native.pollRetained(), closeController, signal);
                controllerReceiver(); signal?.throwIfAborted();
                const death = checkedDeath(observed, containment);
                retainedDeath = death;
                return death;
              } catch (error) { await closeController(); throw error; }
            },
            async closeRetained() {
              if (this !== controller) throw new TypeError('invalid controller receiver');
              const death = retainedDeath;
              if (!death) throw new KernelStorageError('RECOVERY_REQUIRED', 'retirement requires this inspector\'s actual full-containment death');
              await closeController();
              if (!retired) {
                const receipt = Object.freeze({}) as NativeRetainedWorkerRetirement;
                retiredWorkers.set(receipt, { containment: death.containment, deathObservedAt: death.observedAt, assertCurrent() {
                  receiver();
                  let observed!: number;
                  source.withRoot(fd => { observed = native.assertRetainedRetired(fd); });
                  return observed;
                } });
                retired = receipt;
              }
              readNativeRetainedWorkerRetirement(retired);
              return retired;
            },
            async closePreactivation() {
              if (this !== controller) throw new TypeError('invalid controller receiver');
              const inspected = preactivation;
              if (!inspected) throw new KernelStorageError('RECOVERY_REQUIRED', 'retirement requires this inspector\'s actual preactivation closure');
              await closeController();
              if (!retiredPreactivation) {
                const receipt = Object.freeze({}) as NativePreactivationRetirement;
                retiredPreactivations.set(receipt, { ...inspected, assertCurrent() {
                  receiver(); inspected.reservation.assertHeld();
                  const borrowed = borrowWorkerReservationForExecution(inspected.reservation,
                    inspected.closure.spec.owner.workerLaunchId, inspected.closure.plan.launchNonceDigest);
                  let primary: { error: unknown } | undefined;
                  try {
                    borrowed.assertHeld(); let observed!: number;
                    source.withRoot(fd => { observed = native.assertPreactivationRetired(fd, borrowed.fd); });
                    borrowed.assertHeld(); inspected.reservation.assertHeld(); return observed;
                  } catch (error) { primary = { error }; throw error; }
                  finally { retireBorrow(borrowed, primary); }
                } });
                retiredPreactivation = receipt;
              }
              readNativePreactivationRetirement(retiredPreactivation);
              return retiredPreactivation;
            },
            async closePreparation() {
              if (this !== controller) throw new TypeError('invalid controller receiver');
              await closeController();
              if (!retiredPreparation) {
                const receipt = Object.freeze({}) as NativeControllerPreparationRetirement;
                retiredControllerPreparations.set(receipt, { pid: birthIdentity.pid, processStartToken: birthIdentity.processStartToken,
                  controllerBirthDigest, readyObservedAt: birthIdentity.readyObservedAt,
                  assertCurrent() {
                    receiver(); let observed!: number;
                    source.withRoot(fd => { observed = native.assertPreparationRetired(fd); });
                    return observed;
                  } });
                retiredPreparation = receipt;
              }
              readNativeControllerPreparationRetirement(retiredPreparation);
              return retiredPreparation;
            },
            async close() { if (this !== controller) throw new TypeError('invalid worker controller'); await closeController(); controllers.delete(native); }
          });
          linuxWorkerControllers.add(controller);
          return controller;
        } catch (error) {
          // Native ownership already exists. Getter/wrapper construction
          // failure must join it just as a failed HELLO does.
          try { await closeController(); }
          catch (cleanup) { throw retirementError('controller construction and join failed', new AggregateError([error, cleanup])); }
          throw error;
        }
      },
      close() { if (this !== launcher) throw new TypeError('invalid worker launcher');
        if (closing) return closing;
        closed = true; installationAbort.abort(); closing = closeInstallation(); return closing; }
    });
    return launcher;
  } catch (error) {
    closed = true; installationAbort.abort();
    try { await closeInstallation(); }
    catch (cleanup) { throw retirementError('worker installation failed and cleanup did not complete', new AggregateError([error, cleanup])); }
    throw error;
  }
}
