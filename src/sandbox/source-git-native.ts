import { types } from 'node:util';
import { setImmediate } from 'node:timers/promises';
import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { KernelStorageError, ResourceRetirementError } from '../state/errors.js';
import type { RetainedVerifierToolchain } from '../state/guest-toolchain.js';
import { withInstalledWorkerRoot, type HeldInstalledAnchor, type HeldInstalledRuntime } from '../state/installed-runtime.js';
import { borrowSourceGitInputForExecution, type HeldSourceGitInput, type HeldRetainedSourceGitInput,
  type HeldRegisteredAbsentSourceGitInput } from '../state/native-owner.js';
import { openInstalledSourceGitController, type NativeSourceGitRecipe, type NativeSourceGitReservationObservation,
  type NativeSourceGitContainmentObservation, type NativeSourceGitSnapshotObservation, type NativeSourceGitResult,
  closeInstalledRetainedSourceGit, closeInstalledRegisteredAbsentSourceGit, type NativeRetainedSourceGitRetirementObservation,
  type NativeSourceGitOutputReader, type NativeSourceGitRetirementObservation, type NativeSourceGitScope } from './linux-worker.js';

/** Data only. The native C tag/held controller and original StateOwner SQL
 * gates, not this projection or its TypeScript type, authorize the lifecycle. */
export type SourceGitReservation = NativeSourceGitReservationObservation;
export type SourceGitContainment = NativeSourceGitContainmentObservation;
export type SourceGitSnapshot = NativeSourceGitSnapshotObservation;
declare const sourceResultBrand: unique symbol;
export type SourceGitResult = Readonly<NativeSourceGitResult & { readonly [sourceResultBrand]: true }>;
declare const sourceRetirementBrand: unique symbol;
export type SourceGitRetirement = Readonly<{ readonly [sourceRetirementBrand]: true }>;
const sourceResults = new WeakMap<SourceGitResult, HeldSourceGitInput>();
const sourceRetirements = new WeakMap<SourceGitRetirement, { input: HeldSourceGitInput; observation: NativeSourceGitRetirementObservation }>;
const constructionRetirements = new WeakMap<HeldSourceGitInput, SourceGitRetirement>();
declare const recoveredSourceGitRetirementBrand: unique symbol;
export type RecoveredSourceGitRetirement = Readonly<{ readonly [recoveredSourceGitRetirementBrand]: true }>;
const recoveredRetirements = new WeakMap<RecoveredSourceGitRetirement,
  { input: HeldRetainedSourceGitInput; observation: NativeRetainedSourceGitRetirementObservation }>();
declare const registeredAbsentSourceRetirementBrand: unique symbol;
export type RegisteredAbsentSourceGitRetirement = Readonly<{ readonly [registeredAbsentSourceRetirementBrand]: true }>;
const registeredAbsentRetirements = new WeakMap<RegisteredAbsentSourceGitRetirement,
  { input: HeldRegisteredAbsentSourceGitInput; observation: NativeSourceGitRetirementObservation }>();
const lifecycleSnapshots = new WeakMap<object, Buffer>();

/** Copy of the actually parsed native birth after complete original/current
 * checker join. Matching data or a copied receipt cannot issue this result. */
export function readSourceGitNativeLifecycle(receipt: SourceGitRetirement | RecoveredSourceGitRetirement | RegisteredAbsentSourceGitRetirement,
  input: HeldSourceGitInput | HeldRegisteredAbsentSourceGitInput): Buffer {
  const original = sourceRetirements.get(receipt as SourceGitRetirement);
  const recovered = recoveredRetirements.get(receipt as RecoveredSourceGitRetirement);
  const absent = registeredAbsentRetirements.get(receipt as RegisteredAbsentSourceGitRetirement);
  if ((original ?? recovered ?? absent)?.input !== input) throw new TypeError('source lifecycle requires its exact actual joined native receipt and input');
  const snapshot = lifecycleSnapshots.get(receipt);
  if (!snapshot) throw new TypeError('source lifecycle was not captured by its actual joined native owner');
  return Buffer.from(snapshot);
}

export function assertSourceGitResult(result: SourceGitResult, input: HeldSourceGitInput): void {
  if (sourceResults.get(result) !== input) throw new TypeError('source result requires its original native input and scope');
}
export function readSourceGitRetirement(receipt: SourceGitRetirement, input: HeldSourceGitInput): NativeSourceGitRetirementObservation {
  const held = sourceRetirements.get(receipt);
  if (!held || held.input !== input) throw new TypeError('source retirement requires its original joined native producer');
  return held.observation;
}
/** Absence is uncertainty, never no-spawn or permission to remove the birth. */
export function readSourceGitConstructionRetirement(input: HeldSourceGitInput): SourceGitRetirement | undefined {
  return constructionRetirements.get(input);
}
export function readRecoveredSourceGitRetirement(receipt: RecoveredSourceGitRetirement,
  input: HeldRetainedSourceGitInput): NativeRetainedSourceGitRetirementObservation {
  const held = recoveredRetirements.get(receipt);
  if (!held || held.input !== input) throw new TypeError('recovered source retirement requires its exact original birth and joined checker');
  return held.observation;
}
/** Reopens no source payload and can never resume/release an old attempt.
 * This receipt records current checker closure, not possession of old FDs. */
export async function retireInstalledRetainedSourceGit(selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor,
  input: HeldRetainedSourceGitInput, options: { signal?: AbortSignal } = {}): Promise<RecoveredSourceGitRetirement> {
  const joined = await closeInstalledRetainedSourceGit(selected, anchor, input, options);
  const observation = decodeSourceGitRetirementObservation(joined.observation,
    'original_birth_current_checker');
  const receipt = Object.freeze({}) as RecoveredSourceGitRetirement;
  recoveredRetirements.set(receipt, { input, observation }); lifecycleSnapshots.set(receipt, Buffer.from(joined.lifecycleSnapshot)); return receipt;
}
export function readRegisteredAbsentSourceGitRetirement(receipt: RegisteredAbsentSourceGitRetirement,
  input: HeldRegisteredAbsentSourceGitInput): NativeSourceGitRetirementObservation {
  const held = registeredAbsentRetirements.get(receipt);
  if (!held || held.input !== input) throw new TypeError('registered absent retirement requires its exact current checker');
  return held.observation;
}
export async function retireInstalledRegisteredAbsentSourceGit(selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor,
  input: HeldRegisteredAbsentSourceGitInput, options: { signal?: AbortSignal } = {}): Promise<RegisteredAbsentSourceGitRetirement> {
  const joined = await closeInstalledRegisteredAbsentSourceGit(selected, anchor, input, options);
  const observation = decodeSourceGitRetirementObservation(joined.observation, 'original_birth_registered_absent_checker');
  const receipt = Object.freeze({}) as RegisteredAbsentSourceGitRetirement;
  registeredAbsentRetirements.set(receipt, { input, observation }); lifecycleSnapshots.set(receipt, Buffer.from(joined.lifecycleSnapshot)); return receipt;
}
function failure(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function retirementFailure(error: unknown): ResourceRetirementError {
  return error instanceof ResourceRetirementError ? error : new ResourceRetirementError('source native resources did not retire', error);
}
function cancellableOutput(reader: NativeSourceGitOutputReader, signal: AbortSignal): NativeSourceGitOutputReader {
  return Object.freeze({ identity: immutableSnapshot(reader.identity),
    assertHeld() { signal.throwIfAborted(); reader.assertHeld(); },
    readChunk() { signal.throwIfAborted(); return reader.readChunk(); },
    close() { try { reader.close(); } catch (error) { throw retirementFailure(error); } },
  });
}
function recipeData(value: NativeSourceGitRecipe): NativeSourceGitRecipe {
  const keys = ['maxProcesses', 'memoryBytes', 'cpuQuotaMicrosPerSecond', 'maxOpenFiles', 'maxSingleFileBytes',
    'maxGenerationBytes', 'maxInvocationOutputBytes', 'maxIpcFrameBytes', 'maxQueuedIpcBytes', 'launchNonceDigest', 'repositoryIdentityDigest', 'excludeGrantDigest'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value)) throw new TypeError('invalid fixed source native recipe');
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !fields[key] || !Object.hasOwn(fields[key]!, 'value')))
    throw new TypeError('invalid fixed source native recipe');
  const data = Object.fromEntries(keys.map(key => [key, fields[key]!.value])) as NativeSourceGitRecipe;
  const ranges = [
    ['maxProcesses', 3, 1024], ['memoryBytes', 268_435_456, 34_359_738_368], ['cpuQuotaMicrosPerSecond', 10_000, 1_600_000],
    ['maxOpenFiles', 64, 8192], ['maxSingleFileBytes', 1_048_576, 17_179_869_184],
    ['maxGenerationBytes', 268_435_456, 107_374_182_400], ['maxInvocationOutputBytes', 65_536, 67_108_864],
  ] as const;
  if (ranges.some(([key, min, max]) => !Number.isSafeInteger(data[key]) || data[key] < min || data[key] > max) ||
      data.maxIpcFrameBytes !== 16_777_216 || data.maxQueuedIpcBytes !== 67_108_864)
    throw new TypeError('invalid fixed source native recipe');
  assertArtifactRef(data.launchNonceDigest); assertArtifactRef(data.repositoryIdentityDigest);
  if (data.excludeGrantDigest !== null) assertArtifactRef(data.excludeGrantDigest);
  return Object.freeze(data);
}
function time(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1) failure('source native observation has no actual canonical time');
}
function recordRetirement(input: HeldSourceGitInput, observation: NativeSourceGitRetirementObservation, recipe: NativeSourceGitRecipe,
  lifecycle: Buffer | undefined): SourceGitRetirement {
  if (!Buffer.isBuffer(lifecycle) || lifecycle.length < 1 || lifecycle.length > 1_048_576) failure('source retirement lacks its full actual native birth snapshot');
  observation = decodeSourceGitRetirementObservation(observation, 'original_owner_joined');
  if (Object.hasOwn(observation, 'snapshotDigest')) snapshot(observation as NativeSourceGitSnapshotObservation, recipe);
  if (observation.inspectionId !== input.identity.inspectionId || observation.stagingNonceDigest !== input.identity.stagingNonceDigest ||
      observation.targetRef !== input.identity.targetRef || observation.inputIntentRef !== input.identity.inputIntentRef ||
      [observation.reserved, observation.blocked, observation.released, observation.continued].some(value => value !== 0 && value !== 1))
    failure('source retirement differs from the original same-attempt native scope');
  const receipt = Object.freeze({}) as SourceGitRetirement;
  sourceRetirements.set(receipt, { input, observation: immutableSnapshot(observation) });
  lifecycleSnapshots.set(receipt, Buffer.from(lifecycle)); return receipt;
}
/** Native projections are observations, never an authority substitute. Keep
 * original-owner joins separate from current-checker cleanup provenance. */
function retirementRecord(value: unknown, containmentAllowed: boolean): Readonly<Record<string, unknown>> {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) failure('source retirement requires plain observation data');
  const fields = Object.getOwnPropertyDescriptors(value), names = Reflect.ownKeys(fields);
  if (names.length > (containmentAllowed ? 24 : 10)) failure('source retirement exceeds its fixed observation shape');
  const result: Record<string, unknown> = {};
  for (const key of names) {
    if (typeof key !== 'string' || !fields[key]!.enumerable || !Object.hasOwn(fields[key]!, 'value'))
      failure('source retirement requires own observation data fields');
    const item: unknown = fields[key]!.value;
    if (item !== null && typeof item === 'object') {
      if (!containmentAllowed || key !== 'containment') failure('source retirement has an unknown nested observation');
      result[key] = retirementRecord(item, false);
    } else {
      if (item !== null && typeof item !== 'string' && typeof item !== 'number') failure('source retirement has an unsupported observation value');
      result[key] = item;
    }
  }
  return Object.freeze(result);
}
export function decodeSourceGitRetirementObservation<Origin extends 'original_owner_joined' | 'original_birth_current_checker' | 'original_birth_registered_absent_checker'>(value: unknown,
  origin: Origin): NativeSourceGitRetirementObservation & Readonly<{ origin: Origin }> {
  if (origin !== 'original_owner_joined' && origin !== 'original_birth_current_checker' && origin !== 'original_birth_registered_absent_checker')
    failure('source retirement requires its exact original observation origin');
  const observation = retirementRecord(value, true) as NativeSourceGitRetirementObservation;
  const keys = ['observedAtMs', 'inspectionId', 'stagingNonceDigest', 'targetRef', 'inputIntentRef',
    'reserved', 'blocked', 'released', 'continued', 'origin', 'lastBirthKind', 'originalControllerPid',
    'originalControllerStartToken', 'cgroupDeviceId', 'cgroupId', 'launchNonceDigest', 'containmentPlanRef',
    'sandboxLaunchRef', 'sandboxLaunchDigest', 'containment'];
  const hasSnapshot = Object.hasOwn(observation, 'snapshotDigest');
  if (hasSnapshot) keys.push('snapshotDigest', 'byteCount', 'entryCount', 'shardCount');
  if (Reflect.ownKeys(observation).length !== keys.length || keys.some(key => !Object.hasOwn(observation, key)) ||
      observation.origin !== origin || !(origin === 'original_owner_joined' ? [0, 12] : [0, 2, 4, 5, 6, 7, 8, 9, 11, 12]).includes(observation.lastBirthKind) ||
      !Number.isSafeInteger(observation.originalControllerPid) || observation.originalControllerPid < 1 ||
      !/^linux-proc-start-ticks:[1-9][0-9]{0,19}$/u.test(observation.originalControllerStartToken) ||
      [observation.reserved, observation.blocked, observation.released, observation.continued].some(flag => flag !== 0 && flag !== 1))
    failure('source retirement has incomplete original-owner provenance');
  time(observation.observedAtMs);
  if (!/^[A-Za-z0-9_-]{43}$/u.test(observation.inspectionId)) failure('source retirement has no canonical original inspection id');
  for (const ref of [observation.stagingNonceDigest, observation.targetRef, observation.inputIntentRef]) assertArtifactRef(ref);
  if (observation.lastBirthKind === 0 && (observation.reserved || observation.blocked || observation.released || observation.continued || hasSnapshot) ||
      observation.lastBirthKind !== 0 && !observation.reserved || observation.released && !observation.blocked || hasSnapshot && !observation.released ||
      observation.continued && (!observation.released || !hasSnapshot))
    failure('source retirement lifecycle differs from its complete original birth');
  if (origin !== 'original_owner_joined' && observation.lastBirthKind >= 2 && observation.lastBirthKind <= 9) {
    const kind = observation.lastBirthKind;
    if (observation.blocked !== (kind >= 5 ? 1 : 0) || observation.released !== (kind >= 6 ? 1 : 0) ||
        observation.continued !== (kind >= 8 ? 1 : 0) || hasSnapshot !== (kind >= 7) ||
        (observation.containmentPlanRef !== null) !== (kind >= 4))
      failure('source cleanup data differs from its exact original birth prefix');
  }
  if (observation.reserved) {
    decimal(observation.cgroupDeviceId!); decimal(observation.cgroupId!); assertArtifactRef(observation.launchNonceDigest!);
  } else if (observation.cgroupDeviceId !== null || observation.cgroupId !== null || observation.launchNonceDigest !== null)
    failure('source retirement invents an unregistered original cgroup');
  if (observation.containmentPlanRef === null) {
    if (observation.sandboxLaunchRef !== null || observation.sandboxLaunchDigest !== null || observation.containment !== null || observation.blocked)
      failure('source retirement invents an original blocked process');
  } else {
    if (!observation.reserved) failure('source retirement plan has no original reserved cgroup');
    assertArtifactRef(observation.containmentPlanRef); assertArtifactRef(observation.sandboxLaunchRef!); assertArtifactRef(observation.sandboxLaunchDigest!);
  }
  if (observation.containment !== null) {
    const death = observation.containment;
    const fields = ['pid', 'namespaceInitPid', 'processStartToken', 'namespaceInitStartToken', 'cgroupId', 'pidNamespaceId',
      'cgroupPopulated', 'remainingTrackedDescendants', 'namespaceInitDeadAndReaped', 'observedAtMs'];
    if (!observation.blocked || Reflect.ownKeys(death).length !== fields.length || fields.some(key => !Object.hasOwn(death, key)) ||
        !Number.isSafeInteger(death.pid) || death.pid < 1 || !Number.isSafeInteger(death.namespaceInitPid) || death.namespaceInitPid < 1 ||
        !/^linux-proc-start-ticks:[1-9][0-9]{0,19}$/u.test(death.processStartToken) ||
        !/^linux-namespace-init:[1-9][0-9]{0,19}:[1-9][0-9]{0,19}:monitor:[1-9][0-9]{0,19}:[1-9][0-9]{0,19}$/u.test(death.namespaceInitStartToken) ||
        death.namespaceInitStartToken.split(':')[1] !== String(death.namespaceInitPid) ||
        death.cgroupId !== observation.cgroupId || death.cgroupPopulated !== 0 || death.remainingTrackedDescendants !== 0 ||
        death.namespaceInitDeadAndReaped !== 1 || death.observedAtMs !== observation.observedAtMs)
      failure('source retirement lacks original whole-domain death');
    decimal(death.pidNamespaceId);
  } else if (observation.blocked) failure('source retirement lost its original blocked process');
  if (hasSnapshot && (typeof observation.snapshotDigest !== 'string' || !/^[0-9a-f]{64}$/u.test(observation.snapshotDigest) ||
      !Number.isSafeInteger(observation.byteCount) || observation.byteCount! < 1 || observation.byteCount! > 107_374_182_400 ||
      !Number.isSafeInteger(observation.entryCount) || observation.entryCount! < 1 || observation.entryCount! > 100_000 ||
      !Number.isSafeInteger(observation.shardCount) || observation.shardCount! < 1 || observation.shardCount! > 16))
    failure('source retirement snapshot is outside the closed native family bounds');
  return observation as NativeSourceGitRetirementObservation & Readonly<{ origin: Origin }>;
}
function decimal(value: string): void {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/u.test(value)) failure('source native identity is invalid');
}
function snapshot(value: NativeSourceGitSnapshotObservation, recipe: NativeSourceGitRecipe): SourceGitSnapshot {
  assertArtifactRef(value.snapshotDigest);
  if (!Number.isSafeInteger(value.byteCount) || value.byteCount < 1 || value.byteCount > recipe.maxGenerationBytes ||
      !Number.isSafeInteger(value.entryCount) || value.entryCount < 1 || value.entryCount > 100_000 ||
      !Number.isSafeInteger(value.shardCount) || value.shardCount < 1 || value.shardCount > 16)
    failure('source native sealed snapshot is outside its original bounds');
  return immutableSnapshot({ snapshotDigest: value.snapshotDigest, byteCount: value.byteCount,
    entryCount: value.entryCount, shardCount: value.shardCount });
}
export type InstalledSourceGitInspection = Readonly<{
  reservation(): Promise<SourceGitReservation>;
  createBlocked(planRef: string, sandboxLaunchRef: string, sandboxLaunchDigest: string): void;
  ready(): Promise<SourceGitContainment>;
  releaseCapture(): void;
  sealed(): Promise<SourceGitSnapshot>;
  /** Must be called only at the original fresh active-row SQL fence. No
   * caller digest, FD, path, command or replacement release is accepted. */
  continueFixedGit(): void;
  result(): Promise<SourceGitResult>;
  /** The owning task must first join every actual output/CAS consumer, on
   * success and failure. A result already proves the Git domain is dead. */
  retire(): Promise<SourceGitRetirement>;
  stop(): Promise<SourceGitRetirement>;
}>;

/** Fixed installed composition only. The caller supplies the original owned
 * cancellation lifetime (wall-time ∩ grant expiry); no new execution timeout
 * is invented here and no old source attempt can be resumed by this factory. */
export async function openInstalledSourceGitInspection(selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor,
  input: HeldSourceGitInput, toolchain: RetainedVerifierToolchain, recipe: NativeSourceGitRecipe,
  options: { signal: AbortSignal }): Promise<InstalledSourceGitInspection> {
  withInstalledWorkerRoot(selected, anchor, () => {});
  borrowSourceGitInputForExecution(input); // brand first, before caller data.
  if (!options || typeof options !== 'object' || types.isProxy(options)) throw new TypeError('source inspection requires its original owned cancellation lifetime');
  const fields = Object.getOwnPropertyDescriptors(options);
  if (Reflect.ownKeys(fields).length !== 1 || !fields.signal || !Object.hasOwn(fields.signal, 'value'))
    throw new TypeError('source inspection requires its original owned cancellation lifetime');
  const fixed = recipeData(recipe), signal: AbortSignal = fields.signal.value!;
  // Use the built-in branded getter, never a caller getter/proxy, before any
  // native producer is constructed. It accepts only an actual AbortSignal.
  Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!.call(signal);
  signal.throwIfAborted();
  const controller = await openInstalledSourceGitController(selected, anchor, toolchain, { signal });
  let scope: NativeSourceGitScope;
  try { scope = controller.reserve(input, fixed); }
  catch (error) {
    try {
      // Pin the original native receiver before async close can release the
      // last failed-construction wrapper. This observer cannot resume work.
      const cleanup = controller.constructionRetirement();
      await controller.close();
      const observation = cleanup?.pollRetired();
      if (cleanup && !observation) failure('failed source construction joined without its original retirement observation');
      if (observation) constructionRetirements.set(input, recordRetirement(input, observation, fixed, cleanup!.pollLifecycleSnapshot()));
    } catch (close) {
      if (close instanceof ResourceRetirementError) throw close;
      throw retirementFailure(new AggregateError([error, close]));
    }
    throw error;
  }
  let retired: Promise<SourceGitRetirement> | undefined;
  let originalReservation: SourceGitReservation | undefined, originalContainment: SourceGitContainment | undefined;
  let originalSnapshot: SourceGitSnapshot | undefined, originalResult: SourceGitResult | undefined;
  const finish = (normal: boolean) => retired ??= (async () => {
    try {
      let operationFailure: unknown;
      try { if (normal) scope.retire(); else scope.stop(); } catch (error) { operationFailure = error; }
      // Even a synchronous native refusal must not skip the original close.
      // A late close/RRE takes precedence over that operation failure.
      await controller.close();
      if (operationFailure !== undefined) throw operationFailure;
      const observation = scope.pollRetired();
      if (!observation) failure('source controller joined without its complete original retirement observation');
      if (originalSnapshot && canonicalSha256(snapshot(observation as NativeSourceGitSnapshotObservation, fixed)) !== canonicalSha256(originalSnapshot))
        failure('source retirement differs from the original same-attempt native scope');
      return recordRetirement(input, observation, fixed, scope.pollLifecycleSnapshot());
    } catch (error) { throw retirementFailure(error); }
    finally { signal.removeEventListener('abort', abort); }
  })();
  const abort = () => {
    // Before result borrowing there are no CAS consumers: stop the live
    // producer immediately. Afterwards its domain is already dead. Revoke
    // further reads via the original signal, but keep the scope until the
    // owning task has joined its actual readers and CAS work and calls stop.
    if (!originalResult) void finish(false).catch(() => {});
  };
  signal.addEventListener('abort', abort, { once: true });
  const wait = async <T>(poll: () => T | undefined): Promise<T> => {
    try {
      for (;;) {
        signal.throwIfAborted();
        const value = poll();
        signal.throwIfAborted();
        if (value !== undefined) return value;
        await setImmediate(undefined, { signal });
      }
    } catch (error) { await finish(false); throw error; }
  };
  const checked = async <T>(operation: () => Promise<T>): Promise<T> => {
    try { return await operation(); }
    catch (error) { await finish(false); throw error; }
  };
  const api: InstalledSourceGitInspection = Object.freeze({
    reservation: () => checked(async () => {
      if (originalReservation) return originalReservation;
      const value = await wait(() => scope.pollReserved()); time(value.observedAtMs);
      decimal(value.deviceId); decimal(value.fileId); decimal(value.cgroupId);
      if (value.fileId !== value.cgroupId || !Number.isSafeInteger(value.ownerUid) || value.ownerUid < 0 ||
          value.pidNamespaceReservationId !== `source-pending:${input.identity.stagingNonceDigest}` ||
          value.subreaperStartToken !== `linux-subreaper:${controller.pid}:${controller.processStartToken}`)
        failure('source reservation differs from its original cgroup/controller lifetime');
      originalReservation = immutableSnapshot(value); return originalReservation;
    }),
    createBlocked(planRef, sandboxLaunchRef, sandboxLaunchDigest) {
      if (!originalReservation) failure('source prepared birth requires its original reserved resources');
      signal.throwIfAborted(); assertArtifactRef(planRef); assertArtifactRef(sandboxLaunchRef); assertArtifactRef(sandboxLaunchDigest);
      scope.createBlocked(planRef, sandboxLaunchRef, sandboxLaunchDigest);
    },
    ready: () => checked(async () => {
      const value = await wait(() => scope.pollReady()); time(value.observedAtMs); decimal(value.pidNamespaceId);
      if (!originalReservation || value.cgroupId !== originalReservation.cgroupId || !Number.isSafeInteger(value.pid) || value.pid < 1 ||
          !Number.isSafeInteger(value.namespaceInitPid) || value.namespaceInitPid < 1 || value.cgroupPopulated !== 1 ||
          value.namespaceInitDeadAndReaped !== 0 || value.remainingTrackedDescendants !== 0)
        failure('source blocked process differs from its original reserved containment');
      originalContainment = immutableSnapshot(value); return originalContainment;
    }),
    releaseCapture() { signal.throwIfAborted(); if (!originalContainment) failure('source capture requires its original active blocked process'); scope.releaseCapture(); },
    sealed: () => checked(async () => { originalSnapshot = snapshot(await wait(() => scope.pollSealed()), fixed); return originalSnapshot; }),
    continueFixedGit() { signal.throwIfAborted(); if (!originalSnapshot) failure('source continuation requires its original sealed snapshot'); scope.continueFixedGit(); },
    result: () => checked(async () => {
      if (originalResult) throw new KernelStorageError('RECOVERY_REQUIRED', 'source outputs can be borrowed only once');
      const value = await wait(() => scope.pollResult()); time(value.death.observedAtMs);
      const death = value.death, alive = originalContainment;
      if (!alive || death.pid !== alive.pid || death.processStartToken !== alive.processStartToken ||
          death.namespaceInitPid !== alive.namespaceInitPid || death.namespaceInitStartToken !== alive.namespaceInitStartToken ||
          death.pidNamespaceId !== alive.pidNamespaceId || death.cgroupId !== alive.cgroupId ||
          death.cgroupPopulated !== 0 || death.namespaceInitDeadAndReaped !== 1 || death.remainingTrackedDescendants !== 0)
        failure('source result lacks its original exact whole-domain death');
      originalResult = Object.freeze({ death: immutableSnapshot(death), files: Object.freeze({
        inspection: cancellableOutput(value.files.inspection, signal), index: cancellableOutput(value.files.index, signal),
        pack: cancellableOutput(value.files.pack, signal), packIndex: cancellableOutput(value.files.packIndex, signal),
      }), excludeRule: value.excludeRule === null ? null : cancellableOutput(value.excludeRule, signal) }) as SourceGitResult;
      sourceResults.set(originalResult, input); return originalResult;
    }),
    async retire() { try { return await finish(true); } finally { signal.removeEventListener('abort', abort); } },
    async stop() { try { return await finish(false); } finally { signal.removeEventListener('abort', abort); } },
  });
  if (signal.aborted) { await finish(false); signal.throwIfAborted(); }
  return api;
}
