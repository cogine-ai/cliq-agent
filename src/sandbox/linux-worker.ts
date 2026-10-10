import { KernelStorageError, ResourceRetirementError } from '../state/errors.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { createHash } from 'node:crypto';
import { constants, fstatSync, readSync } from 'node:fs';
import { open, type FileHandle } from 'node:fs/promises';
import { Module } from 'node:module';
import path from 'node:path';
import { setImmediate, setTimeout as delay } from 'node:timers/promises';
import { assertArtifactRef, normalizeAbsolutePath } from '../kernel/identity.js';
import type { ProcessContainment, SanitizedSandboxEnvironmentV1 } from '../kernel/execution.js';
import type { WorkerIdentity, WorkerLaunch } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { sampleCanonicalNow } from '../state/canonical-time.js';
import { assertBuiltinEditLaunchClosure, assertWorkerLaunchClosure, type BuiltinEditLaunchClosure, type WorkerLaunchClosure } from '../state/execution-closure.js';
import { borrowWorkerReservationForExecution, type BorrowedGenerationForExecution, type HeldWorkerReservation } from '../state/native-owner.js';
import { borrowRunWorkspaceForExecution, type RunWorkspaceGeneration } from '../workspace/run-workspace/generation.js';

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
  observeProcess(): Promise<LinuxObservedProcess>;
  activateCommitted(launch: WorkerLaunch): Promise<void>;
  createInvocation(closure: BuiltinEditLaunchClosure): Promise<LinuxBlockedInvocation>;
  stop(): Promise<NativeContainmentDeathObservation>;
}>;
export type LinuxWorkerController = Readonly<{
  pid: number;
  processStartToken: string;
  subreaperStartToken: string;
  bindWorkerReservation(input: { closure: WorkerLaunchClosure; reservation: HeldWorkerReservation; activationNonceDigest: string }): Promise<void>;
  inspectPreactivation(input: { closure: WorkerLaunchClosure; reservation: HeldWorkerReservation; activationNonceDigest: string;
    containment?: ProcessContainment; workerIdentity?: WorkerIdentity }): Promise<NativePreactivationObservation>;
  launchWorker(input: { closure: WorkerLaunchClosure; generation: RunWorkspaceGeneration; activationNonceDigest: string }): Promise<LinuxBlockedWorker>;
  terminateRetained(input: { closure: WorkerLaunchClosure; containment: ProcessContainment; workerIdentity: WorkerIdentity;
    signal?: AbortSignal }): Promise<NativeContainmentDeathObservation>;
  close(): Promise<void>;
}>;
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
type NativeImage = { descriptor(): number; close(): void };
type NativeScope = { pollReady(): boolean; observe(): NativeObservation; activate(nonce: string): void; pollActivated(): boolean;
  release(): void; result(): number | undefined; stop(): void; pollStopped(): NativeObservation | undefined };
type NativeController = { pid: number; processStartToken: string;
  pollReady(): boolean;
  bindReservation(reservation: number, config: object): void;
  pollBound(): boolean;
  inspectReservation(cgroup: number, reservation: number, config: object): void;
  pollReservation(): Readonly<{ kind: 'not_attempted'; cgroupPresent: boolean; cgroupId?: string; observedAtMs: number }> |
    (NativeObservation & Readonly<{ kind: 'created_dead'; observedAtMs: number }>) | undefined;
  createWorker(generation: number, cgroup: number, helper: NativeImage, worker: NativeImage, bwrap: NativeImage, config: object): NativeScope;
  createInvocation(generation: number, parent: NativeScope, helper: NativeImage, adapter: NativeImage, bwrap: NativeImage, input: NativeImage, config: object): NativeScope;
  terminateRetained(cgroup: number, config: object): void;
  pollRetained(): NativeObservation | undefined;
  close(): Promise<void>;
};
type NativeBinding = { interfaceVersion: 2; sealImage(fd: number): NativeImage; sealImageBuffer(input: Buffer): NativeImage;
  openController(helper: NativeImage): NativeController };

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

function scopeProjection(closure: WorkerLaunchClosure | BuiltinEditLaunchClosure, borrowed: BorrowedGenerationForExecution, activationNonceDigest: string) {
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

function actualContainment(closure: WorkerLaunchClosure | BuiltinEditLaunchClosure, observed: NativeObservation,
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

async function awaitNative<T>(poll: () => T | undefined, close: () => Promise<void>, signal?: AbortSignal): Promise<T> {
  const deadline = performance.now() + 6000;
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
      await delay(1, undefined, { signal });
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
  const controllers = new Set<NativeController>(); let closed = false, closing: Promise<void> | undefined;
  const installed = new Map<string, NativeImage>();
  const receiver = () => { if (closed) throw new KernelStorageError('LEASE_FENCED', 'worker installation scope is closed'); };
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
    for (const image of installed.values()) { try { retireImage(image); } catch (error) { remember(error); } }
    installed.clear();
    try { await retireFiles([cgroup, installation]); } catch (error) { remember(error); }
    if (failed) throw retirementError('worker installation retirement failed', failure);
  }
  try {
    const addonEntry = bundle.entries.find(entry => entry.entryId === 'linux_worker_native');
    if (!addonEntry || addonEntry.role !== 'platform_helper' || !addonEntry.executable) mismatch('signed worker native module is missing');
    const addon = await openInstalledFile(installation, addonEntry.relativePath);
    let binding: NativeBinding;
    try {
      const metadata = await addon.stat();
      if ((metadata.mode & 0o022) !== 0 || (metadata.uid !== process.geteuid!() && metadata.uid !== 0) ||
          metadata.size !== addonEntry.byteCount ||
          await hashHeld(addon.fd, metadata.size, receiver) !== addonEntry.digest) mismatch('installed native worker module is not signed');
      const loaded = new Module('cliq-linux-worker-native');
      process.dlopen(loaded, `/proc/self/fd/${addon.fd}`); binding = loaded.exports as NativeBinding;
      if (binding.interfaceVersion !== 2 || typeof binding.sealImage !== 'function' || typeof binding.sealImageBuffer !== 'function' ||
          typeof binding.openController !== 'function') mismatch('unsupported installed native worker interface');
    } finally { await retireFiles([addon]); }
    async function image(entryId: string, role: string): Promise<NativeImage> {
      receiver(); const existing = installed.get(entryId); if (existing) return existing;
      const entry = bundle.entries.find(value => value.entryId === entryId);
      if (!entry || entry.role !== role || !entry.executable) mismatch('executable is not in the signed production bundle');
      const source = await openInstalledFile(installation, entry.relativePath);
      try {
        const sealed = binding.sealImage(source.fd);
        try {
          if (await hashHeld(sealed.descriptor(), entry.byteCount, receiver) !== entry.digest) mismatch('sealed installed image differs from its signed digest');
          installed.set(entryId, sealed); return sealed;
        } catch (error) { retireImage(sealed); throw error; }
      } finally { await retireFiles([source]); }
    }
    const helper = await image('linux_worker_controller', 'platform_helper');
    const bwrap = await image('linux_bubblewrap', 'platform_helper');
    const launcher: LinuxWorkerLauncher = Object.freeze({
      async startController(controlOptions) {
        if (this !== launcher) throw new TypeError('invalid worker launcher receiver'); receiver();
        const signal = controlOptions?.signal;
        signal?.throwIfAborted();
        const native = binding.openController(helper); controllers.add(native);
        let controllerClosed = false, controllerClosing: Promise<void> | undefined;
        const closeController = () => {
          controllerClosed = true;
          if (!controllerClosing) {
            controllerClosing = joinController(native);
          }
          return controllerClosing;
        };
        const controllerReceiver = () => {
          receiver();
          if (controllerClosed) throw new KernelStorageError('LEASE_FENCED', 'worker controller scope is closed');
        };
        try {
          await awaitNative(() => native.pollReady() ? true : undefined, closeController, signal);
          controllerReceiver(); signal?.throwIfAborted();
        } catch (error) { await closeController(); throw error; }
        const subreaperStartToken = `linux-subreaper:${native.pid}:${native.processStartToken}`;
        const controller: LinuxWorkerController = Object.freeze({
          pid: native.pid, processStartToken: native.processStartToken, subreaperStartToken,
          async bindWorkerReservation({ closure, reservation, activationNonceDigest }) {
            if (this !== controller) throw new TypeError('invalid worker controller'); controllerReceiver();
            same(closure.bundle, bundle, 'reservation bundle');
            if (closure.plan.backend.kind !== 'linux' || closure.plan.backend.subreaperStartToken !== subreaperStartToken ||
                path.posix.dirname(closure.plan.backend.cgroupPath) !== options.cgroupParent) mismatch('binding selects another native spawner');
            const config = reservationProjection(closure, reservation, activationNonceDigest);
            const borrowed = borrowWorkerReservationForExecution(reservation, closure.spec.owner.workerLaunchId, closure.plan.launchNonceDigest);
            let primary: { error: unknown } | undefined;
            try {
              borrowed.assertHeld(); native.bindReservation(borrowed.fd, config);
              await awaitNative(() => native.pollBound() ? true : undefined, closeController);
              controllerReceiver(); borrowed.assertHeld(); reservation.assertHeld();
            } catch (error) { primary = { error }; throw error; }
            finally { retireBorrow(borrowed, primary); }
          },
          async inspectPreactivation({ closure, reservation, activationNonceDigest, containment, workerIdentity }) {
            if (this !== controller) throw new TypeError('invalid worker controller'); controllerReceiver();
            assertWorkerLaunchClosure(closure); same(closure.bundle, bundle, 'inspection bundle');
            const backend = closure.plan.backend;
            if (backend.kind !== 'linux' || backend.subreaperStartToken === subreaperStartToken ||
                path.posix.dirname(backend.cgroupPath) !== options.cgroupParent) mismatch('inspection requires a fresh controller for the exact old reservation');
            const config = reservationProjection(closure, reservation, activationNonceDigest);
            const borrowed = borrowWorkerReservationForExecution(reservation, closure.spec.owner.workerLaunchId, closure.plan.launchNonceDigest);
            let primary: { error: unknown } | undefined;
            try {
              borrowed.assertHeld(); native.inspectReservation(cgroup.fd, borrowed.fd, config);
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
              return result;
            } catch (error) { primary = { error }; throw error; }
            finally { retireBorrow(borrowed, primary); }
          },
          async launchWorker({ closure, generation, activationNonceDigest }) {
            if (this !== controller) throw new TypeError('invalid controller receiver'); controllerReceiver(); assertArtifactRef(activationNonceDigest);
            assertWorkerLaunchClosure(closure);
            same(closure.bundle, bundle, 'worker bundle');
            const backend = closure.plan.backend;
            if (backend.kind !== 'linux' || backend.subreaperStartToken !== subreaperStartToken ||
                path.posix.dirname(backend.cgroupPath) !== options.cgroupParent || !/^cliq-[0-9a-f]{64}$/u.test(path.posix.basename(backend.cgroupPath))) mismatch('worker plan selects another controller or cgroup reservation');
            supportedRecipe(closure);
            if (closure.spec.executable.kind !== 'runtime_bundle' || closure.spec.executable.executionPath !== LINUX_WORKER_RECIPE.workerPath ||
                closure.spec.executable.executableId !== LINUX_WORKER_RECIPE.workerId) {
              throw new LinuxExecutionIdentityError('worker launch is outside the installed closed recipe');
            }
            const executable = await image(closure.spec.executable.executableId, 'worker');
            const workerDigest = closure.spec.executable.executableDigest;
            const borrowed = borrowRunWorkspaceForExecution(generation);
            let nativeScope: NativeScope | undefined;
            try {
              borrowed.assertHeld(); borrowed.assertQuota(closure.spec.resources.maxGenerationBytes);
              if (closure.generation.locator.kind !== 'linux_directory' || closure.generation.locator.deviceId !== borrowed.identity.deviceId ||
                  closure.generation.locator.directoryFileId !== borrowed.identity.fileId) mismatch('worker selected a different physical generation');
              const created = native.createWorker(borrowed.fd, cgroup.fd, helper, executable, bwrap, scopeProjection(closure, borrowed, activationNonceDigest));
              nativeScope = created;
              await awaitNative(() => created.pollReady() ? true : undefined, closeController); borrowed.assertHeld(); receiver();
              const containment = actualContainment(closure, created.observe()); let active = false, borrowRetired = false;
              const worker: LinuxBlockedWorker = Object.freeze({
                containment,
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
                    async stop() { if (this !== handle) throw new TypeError('invalid blocked invocation'); return death(scope, invocationContainment, native, controllerReceiver); } });
                  invocations.set(handle, { consumed: false, claim, release() { receiver(); borrowed.assertHeld(); scope.release(); } });
                  return handle;
                },
                async stop() {
                  if (this !== worker) throw new TypeError('invalid blocked worker'); active = false;
                  try { return await death(created, containment, native, controllerReceiver); }
                  finally {
                    // Fresh STOP uses only the original held native scope. A
                    // retired generation duplicate is never reopened/reused.
                    if (!borrowRetired) { retireBorrow(borrowed); borrowRetired = true; }
                  }
                }
              });
              return worker;
            } catch (error) {
              try { if (nativeScope) await closeController(); }
              finally { retireBorrow(borrowed); }
              throw error;
            }
          },
          async terminateRetained({ closure, containment, workerIdentity, signal }) {
            if (this !== controller) throw new TypeError('invalid controller receiver'); controllerReceiver();
            if (signal?.aborted) { await closeController(); signal.throwIfAborted(); }
            assertWorkerLaunchClosure(closure);
            same(closure.bundle, bundle, 'retained worker bundle');
            const planBackend = closure.plan.backend, actual = containment.backend;
            if (planBackend.kind !== 'linux' || actual.kind !== 'linux' ||
                path.posix.dirname(actual.cgroupPath) !== options.cgroupParent || actual.cgroupPath !== planBackend.cgroupPath ||
                containment.planRef !== canonicalSha256(closure.plan) || containment.sandboxLaunchSpecRef !== closure.sandboxLaunchSpecRef ||
                workerIdentity.processContainmentRef !== canonicalSha256(containment) || actual.subreaperStartToken !== planBackend.subreaperStartToken) {
              mismatch('retained worker does not close the exact native reservation');
            }
            native.terminateRetained(cgroup.fd, { cgroupName: path.posix.basename(actual.cgroupPath),
              cgroupId: Number(actual.cgroupId), pidNamespaceId: Number(actual.pidNamespaceId),
              namespaceInitStartToken: actual.namespaceInitStartToken, subreaperStartToken: actual.subreaperStartToken,
              workerPid: workerIdentity.pid, processStartToken: workerIdentity.processStartToken });
            const observed = await awaitNative(() => native.pollRetained(), closeController, signal);
            controllerReceiver(); signal?.throwIfAborted();
            return checkedDeath(observed, containment);
          },
          async close() { if (this !== controller) throw new TypeError('invalid worker controller'); await closeController(); controllers.delete(native); }
        });
        return controller;
      },
      close() { if (this !== launcher) throw new TypeError('invalid worker launcher');
        if (closing) return closing;
        closed = true; closing = closeInstallation(); return closing; }
    });
    return launcher;
  } catch (error) {
    closed = true;
    try { await closeInstallation(); }
    catch (cleanup) { throw retirementError('worker installation failed and cleanup did not complete', new AggregateError([error, cleanup])); }
    throw error;
  }
}
