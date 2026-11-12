// Installed stdio composition. A copied report never becomes a live peer or
// a process/FD join; the exact selected C scope and owner retain that custody.
import { setTimeout as delay } from 'node:timers/promises';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord } from '../kernel/control-wire-data.js';
import { immutableSnapshot } from '../model/immutable.js';
import { KernelStorageError, ResourceRetirementError } from '../state/errors.js';
import { borrowMcpStdioInput, decodeMcpStdioLifecycleData, decodeMcpStdioCleanupData, decodeMcpStdioRecoveryLifecycleData, decodeMcpStdioRecoveryCleanupData, type HeldRecoveryMcpStdioInput, type RecoveryMcpStdioInputBinding, type HeldStateOwnerLock, type HeldRunMcpStdioInput,
  type HeldAdminMcpStdioInput, type RunMcpStdioInputBinding, type AdminMcpStdioInputBinding } from '../state/native-owner.js';
import type { McpStdioScopeObservation, McpStdioNativeLifecycle, McpStdioNativeCleanup, McpStdioRecoveryNativeLifecycle, McpStdioRecoveryNativeCleanup } from '../state/mcp-stdio-lifecycle.js';
import type { NativeMcpAdminOriginalRetirement } from './mcp-admin-retirement.js';
import type { NativeMcpStdioAdminOwner, NativeMcpStdioRunOwner, NativeMcpStdioAdminJoined, NativeMcpStdioRunJoined,
  NativeMcpStdioRecoveryOwner, NativeMcpStdioRecoveryClosure, NativeMcpStdioPeer, NativeMcpStdioServerImage } from '../state/mcp-stdio-broker-native.js';
import { withInstalledWorkerRoot, type HeldInstalledRuntime, type HeldInstalledAnchor } from '../state/installed-runtime.js';
import { assertLinuxWorkerController, reserveInstalledMcpStdioAdmin, reserveInstalledMcpStdioRun, reserveInstalledMcpStdioRecovery,
  cleanupInstalledMcpStdioAdmin, cleanupInstalledMcpStdioRun, cleanupInstalledMcpStdioRecovery, type LinuxWorkerController } from './linux-worker.js';
export type { McpStdioScopeObservation } from '../state/mcp-stdio-lifecycle.js';
declare const physicalJoined: unique symbol;
export type McpStdioPhysicalJoined = Readonly<{
  readonly [physicalJoined]: true;
  observation: McpStdioScopeObservation; deathJoined: true; outputAcknowledged: boolean; outputCustodyRetired: boolean;
}>;
export type NativeMcpStdioScope = NativeMcpStdioPeer & Readonly<{
  pollReserved(): McpStdioScopeObservation | undefined;
  assertReserved(observation: McpStdioScopeObservation): void;
  createBlocked(): void;
  pollReady(): McpStdioScopeObservation | undefined;
  assertReady(observation: McpStdioScopeObservation): void;
  stop(): void;
  pollJoined(): McpStdioPhysicalJoined | undefined;
  assertJoined(joined: McpStdioPhysicalJoined): void;
  beginOutputAck(): void;
  pollOutputAck(): boolean;
  pollLifecycleSnapshot(): Buffer | undefined;
}>;
declare const nativeCleanupProof: unique symbol;
type NativeMcpStdioCleanupProof = Readonly<{ readonly [nativeCleanupProof]: true }>;
export type NativeMcpStdioCleanupScope = Readonly<Pick<NativeMcpStdioScope,
  'stop' | 'pollJoined' | 'assertJoined' | 'beginOutputAck' | 'pollOutputAck' | 'pollLifecycleSnapshot'> & {
  pollCleanupObservation(): NativeMcpStdioCleanupProof | undefined;
  assertCleanupObservation(observation: NativeMcpStdioCleanupProof): void;
  pollCleanupSnapshot(): Buffer | undefined;
}>;
type Input = HeldRunMcpStdioInput | HeldAdminMcpStdioInput | HeldRecoveryMcpStdioInput;
type Owner = NativeMcpStdioRunOwner | NativeMcpStdioAdminOwner | NativeMcpStdioRecoveryOwner;
type OwnerJoined = NativeMcpStdioRunJoined | NativeMcpStdioAdminJoined | NativeMcpStdioRecoveryClosure;
type Construction = Readonly<{
  selected: HeldInstalledRuntime; anchor: HeldInstalledAnchor; controller: LinuxWorkerController; lock: HeldStateOwnerLock;
  serverImage: NativeMcpStdioServerImage; resources: SandboxResourceSpec; launchDeadlineMs: number; callDeadlineMs: number; signal?: AbortSignal;
}>;
type InstalledScope = Readonly<{
  peer: NativeMcpStdioPeer;
  controller: Readonly<{ pid: number; processStartToken: string }>;
  reservation(): Promise<McpStdioScopeObservation>;
  createBlocked(): void;
  ready(): Promise<McpStdioScopeObservation>;
  close(): Promise<void>;
  assertJoined(joined: McpStdioPhysicalJoined): void;
  lifecycleSnapshot(): Buffer;
}>;
export type InstalledMcpStdioRunScope = InstalledScope;
export type InstalledMcpStdioRecoveryScope = InstalledScope;
type AdminRetirementMethods = Readonly<{
  reobserveRetirement(): NativeMcpAdminOriginalRetirement;
  assertRetirementObservation(value: NativeMcpAdminOriginalRetirement): void;
}>;
export type InstalledMcpStdioAdminScope = InstalledScope & AdminRetirementMethods;
const scopes = new WeakMap<InstalledScope, {
  native: NativeMcpStdioScope; input: Input; purpose: 'admin' | 'run' | 'recovery'; processId: number; assertSelection(): void;
  joined?: McpStdioPhysicalJoined; ownerJoined?: OwnerJoined; containment?: McpStdioScopeObservation; reservation?: McpStdioScopeObservation; snapshot?: Buffer;
}>();
function heldScope(scope: InstalledScope, input?: Input, purpose?: 'admin' | 'run' | 'recovery') {
  const held = scopes.get(scope);
  if (!held || held.processId !== process.pid || input !== undefined && held.input !== input || purpose !== undefined && held.purpose !== purpose)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP stdio scope is not its original selected native owner');
  held.assertSelection(); return held;
}
function resourceBytes(input: Construction, purpose: 'admin' | 'run' | 'recovery'): Buffer {
  assertControlWireJson(input.resources);
  controlWireRecord(input.resources, ['maxProcesses', 'memoryBytes', 'cpuQuotaMicrosPerSecond', 'maxOpenFiles', 'maxSingleFileBytes', 'maxGenerationBytes',
    'maxInvocationOutputBytes', 'maxIpcFrameBytes', 'maxQueuedIpcBytes']);
  const resources = input.resources;
  const numbers = [controlWireInteger(resources.maxProcesses, 1, 1024), controlWireInteger(resources.memoryBytes, 268_435_456, 34_359_738_368),
    controlWireInteger(resources.cpuQuotaMicrosPerSecond, 10_000, 1_600_000), controlWireInteger(resources.maxOpenFiles, 64, 8192),
    controlWireInteger(resources.maxSingleFileBytes, 1_048_576, 17_179_869_184), controlWireInteger(resources.maxGenerationBytes, 268_435_456, 107_374_182_400),
    controlWireInteger(resources.maxInvocationOutputBytes, 65_536, 67_108_864), controlWireInteger(input.launchDeadlineMs, 1), controlWireInteger(input.callDeadlineMs, 1)];
  if (resources.maxIpcFrameBytes !== 16_777_216 || resources.maxQueuedIpcBytes !== 67_108_864 || input.launchDeadlineMs > input.callDeadlineMs)
    throw new TypeError('MCP stdio original resource/deadline recipe differs');
  const bytes = Buffer.alloc(88);
  bytes.writeUInt32LE(0x43534c31, 0); bytes.writeUInt32LE(1, 4); bytes.writeUInt32LE(purpose === 'admin' ? 1 : purpose === 'recovery' ? 3 : 2, 8);
  numbers.forEach((number, index) => bytes.writeBigUInt64LE(BigInt(number), 16 + index * 8));
  return bytes;
}
function prepare(input: Construction, physical: Input, binding: AdminMcpStdioInputBinding | RunMcpStdioInputBinding | RecoveryMcpStdioInputBinding, owner: Owner,
  purpose: 'admin' | 'run' | 'recovery'): InstalledScope {
  input.signal?.throwIfAborted(); assertLinuxWorkerController(input.controller);
  const assertSelection = () => withInstalledWorkerRoot(input.selected, input.anchor, () => {});
  assertSelection();
  if (purpose === 'run' && ('callDeadlineMs' in binding && (binding.callDeadlineMs !== input.callDeadlineMs || binding.launchDeadlineMs !== input.launchDeadlineMs)))
    throw new TypeError('MCP stdio input changes its original call/launch deadlines');
  if (purpose === 'recovery' && (!('probeDeadlineAtMs' in binding) || binding.probeDeadlineAtMs !== input.launchDeadlineMs ||
      binding.probeDeadlineAtMs !== input.callDeadlineMs))
    throw new TypeError('MCP recovery input changes its original fixed probe deadline');
  if (purpose === 'recovery' && 'adapterExecutableId' in binding) {
    const entries = input.selected.bundle.entries.filter(entry => entry.entryId === binding.adapterExecutableId), entry = entries[0];
    if (entries.length !== 1 || !entry || entry.role !== 'mcp_recovery_adapter' || entry.executable !== true ||
        entry.digest !== binding.adapterExecutableDigest || input.serverImage.identity.sha256 !== entry.digest ||
        input.serverImage.identity.byteCount !== entry.byteCount)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'recovery inspector is not independently rooted in the current signed Bundle');
  }
  const nativeInput = borrowMcpStdioInput(input.lock, physical, binding, purpose, false), config = resourceBytes(input, purpose);
  // The fixed native constructor returns this closeable receiver before any
  // await. It retains its original birth and registers recipe custody before
  // issuing its one authenticated RESERVE operation.
  const native = purpose === 'recovery' ? reserveInstalledMcpStdioRecovery(input.controller, nativeInput, owner.recipe, input.serverImage, config) : purpose === 'admin' ? reserveInstalledMcpStdioAdmin(input.controller, nativeInput, owner.recipe, input.serverImage, config) :
    reserveInstalledMcpStdioRun(input.controller, nativeInput, owner.recipe, input.serverImage, config);
  const started = new Set<Promise<unknown>>();
  const track = <T>(job: Promise<T>): Promise<T> => {
    started.add(job); void job.finally(() => started.delete(job)).catch(() => {}); return job;
  };
  let closing: Promise<void> | undefined, closingNow = false, creatingAt: number | undefined, actualReady = false;
  let reservation: Promise<McpStdioScopeObservation> | undefined, ready: Promise<McpStdioScopeObservation> | undefined;
  let controllerJoin: Promise<void> | undefined;
  const joinController = () => controllerJoin ??= input.controller.close();
  let scope!: InstalledScope;
  const wait = async (poll: () => McpStdioScopeObservation | undefined, deadline: number) => {
    for (;;) {
      if (closingNow) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio scope was revoked');
      input.signal?.throwIfAborted(); assertSelection();
      const value = poll();
      if (value) return value;
      if (performance.now() >= deadline || Date.now() >= input.launchDeadlineMs) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio original construction deadline elapsed');
      await delay(1);
    }
  };
  const close = (): Promise<void> => closing ??= (async () => {
    closingNow = true; input.signal?.removeEventListener('abort', abort);
    const deadline = performance.now() + 2000, failures: unknown[] = [];
    // Begin both original revocations without awaiting one. The dedicated
    // controller can interrupt its own pending CREATE; it owns no Run worker.
    let ownerClose: Promise<OwnerJoined>;
    try { ownerClose = owner.close(); } catch (error) { ownerClose = Promise.reject(error); }
    void ownerClose.catch(() => {});
    try { native.stop(); } catch (error) { failures.push(error); }
    if (!actualReady) { const pending = joinController(); void pending.catch(() => {}); }
    let joined: McpStdioPhysicalJoined | undefined, acknowledging = false;
    try {
      for (;;) {
        joined = native.pollJoined() ?? joined;
        if (joined?.deathJoined) {
          if (!acknowledging) { native.beginOutputAck(); acknowledging = true; }
          native.pollOutputAck(); joined = native.pollJoined() ?? joined;
          if (joined.outputCustodyRetired) break;
        }
        if (performance.now() >= deadline) throw new ResourceRetirementError('MCP stdio original scope did not join within Stop2', undefined);
        await delay(1);
      }
      native.assertJoined(joined);
    } catch (error) { failures.push(error); }
    // Preserve actual ACK facts; controller death alone never creates them.
    // After genuine graceful drain/ACK, retiring the platform controller also
    // joins its real children, channel and descriptor custody.
    const [all] = await Promise.all([Promise.allSettled([joinController(), ownerClose] as const), Promise.allSettled([...started])]);
    if (all[0]!.status === 'rejected') failures.push(all[0]!.reason);
    if (all[1]!.status === 'rejected') failures.push(all[1]!.reason);
    if (joined?.outputCustodyRetired && all[1]!.status === 'fulfilled') {
      try {
        joined = native.pollJoined() ?? joined; native.assertJoined(joined);
        const snapshot = native.pollLifecycleSnapshot();
        if (!snapshot) throw new ResourceRetirementError('MCP stdio original birth/progress custody is not complete', undefined);
        const held = scopes.get(scope)!; held.joined = joined; held.ownerJoined = all[1]!.value; held.snapshot = Buffer.from(snapshot);
      } catch (error) { failures.push(error); }
    }
    try { input.serverImage.close(); } catch (error) { failures.push(error); }
    if (failures.length) throw failures.find(error => error instanceof ResourceRetirementError) ??
      new ResourceRetirementError('MCP stdio original resources did not positively retire', new AggregateError(failures));
  })();
  const abort = () => { void close().catch(() => {}); };
  const retirement: Partial<AdminRetirementMethods> = purpose === 'admin' ? {
    reobserveRetirement() {
      const held = heldScope(scope, physical, 'admin');
      if (!held.joined || !held.ownerJoined || !held.snapshot) throw new ResourceRetirementError('MCP stdio Admin original closure is incomplete', undefined);
      return (native as NativeMcpStdioScope & AdminRetirementMethods).reobserveRetirement();
    },
    assertRetirementObservation(value) {
      heldScope(scope, physical, 'admin');
      (native as NativeMcpStdioScope & AdminRetirementMethods).assertRetirementObservation(value);
    }
  } : {};
  scope = Object.freeze({ ...retirement, peer: native, controller: Object.freeze({ pid: input.controller.pid, processStartToken: input.controller.processStartToken }),
    reservation() {
      heldScope(scope, physical, purpose);
      return reservation ??= track(wait(() => native.pollReserved(), performance.now() + 30000).then(observation => {
        native.assertReserved(observation); scopes.get(scope)!.reservation = observation; return immutableSnapshot(observation);
      }));
    },
    createBlocked() {
      heldScope(scope, physical, purpose);
      if (closingNow || creatingAt !== undefined) throw new TypeError('MCP stdio original creation cannot be repeated');
      creatingAt = performance.now(); native.createBlocked();
    },
    ready() {
      heldScope(scope, physical, purpose);
      if (creatingAt === undefined) throw new TypeError('MCP stdio original creation was not started');
      return ready ??= track(wait(() => native.pollReady(), creatingAt + 5000).then(observation => {
        native.assertReady(observation); actualReady = true; scopes.get(scope)!.containment = observation; return immutableSnapshot(observation);
      }));
    }, close,
    assertJoined(joined: McpStdioPhysicalJoined) { heldScope(scope, physical, purpose).native.assertJoined(joined); },
    lifecycleSnapshot() {
      const held = heldScope(scope, physical, purpose);
      if (!held.snapshot || !held.joined) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio original lifecycle is not joined');
      held.native.assertJoined(held.joined); return Buffer.from(held.snapshot);
    }
  });
  scopes.set(scope, { native, input: physical, purpose, processId: process.pid, assertSelection });
  input.signal?.addEventListener('abort', abort, { once: true }); if (input.signal?.aborted) abort();
  return scope;
}
export function prepareInstalledMcpStdioRun(input: Construction & Readonly<{ input: HeldRunMcpStdioInput; inputBinding: RunMcpStdioInputBinding; owner: NativeMcpStdioRunOwner }>): InstalledMcpStdioRunScope {
  return prepare(input, input.input, input.inputBinding, input.owner, 'run');
}
export function prepareInstalledMcpStdioAdmin(input: Construction & Readonly<{ input: HeldAdminMcpStdioInput; inputBinding: AdminMcpStdioInputBinding; owner: NativeMcpStdioAdminOwner }>): InstalledMcpStdioAdminScope {
  return prepare(input, input.input, input.inputBinding, input.owner, 'admin') as InstalledMcpStdioAdminScope;
}
export function prepareInstalledMcpStdioRecovery(input: Construction & Readonly<{
  input: HeldRecoveryMcpStdioInput; inputBinding: RecoveryMcpStdioInputBinding; owner: NativeMcpStdioRecoveryOwner;
}>): InstalledMcpStdioRecoveryScope { return prepare(input, input.input, input.inputBinding, input.owner, 'recovery'); }
function readJoined(scope: InstalledScope, input: Input, purpose: 'admin' | 'run' | 'recovery') {
  const held = heldScope(scope, input, purpose);
  if (!held.joined || !held.ownerJoined || !held.snapshot) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio scope lacks its original complete native join');
  held.native.assertJoined(held.joined);
  const lifecycleSnapshot = Buffer.from(held.snapshot), originalLifecycle = purpose === 'recovery' ?
    decodeMcpStdioRecoveryLifecycleData(lifecycleSnapshot) : decodeMcpStdioLifecycleData(lifecycleSnapshot);
  if (originalLifecycle.binding.kind !== purpose) throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP stdio original lifecycle substitutes its purpose');
  return { joined: held.joined, ownerJoined: held.ownerJoined, lifecycleSnapshot, originalLifecycle, containmentObservation: held.containment };
}
export function readInstalledMcpStdioRunJoined(scope: InstalledMcpStdioRunScope, input: HeldRunMcpStdioInput) {
  const value = readJoined(scope, input, 'run');
  if (value.ownerJoined.purpose !== 'run') throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP stdio Run closure substitutes an Admin owner');
  return { ...value, originalLifecycle: value.originalLifecycle as McpStdioNativeLifecycle, ownerJoined: value.ownerJoined };
}
export function readInstalledMcpStdioAdminJoined(scope: InstalledMcpStdioAdminScope, input: HeldAdminMcpStdioInput) {
  const value = readJoined(scope, input, 'admin');
  if (value.ownerJoined.purpose !== 'admin') throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP stdio Admin closure substitutes a Run owner');
  return { ...value, ownerJoined: value.ownerJoined };
}
export function readInstalledMcpStdioRunReady(scope: InstalledMcpStdioRunScope, input: HeldRunMcpStdioInput): McpStdioScopeObservation {
  const held = heldScope(scope, input, 'run');
  if (!held.containment) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio original server has no native READY observation');
  held.native.assertReady(held.containment); return immutableSnapshot(held.containment);
}
export function readInstalledMcpStdioAdminReady(scope: InstalledMcpStdioAdminScope, input: HeldAdminMcpStdioInput): McpStdioScopeObservation {
  const held = heldScope(scope, input, 'admin');
  if (!held.containment) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio original Admin has no native READY observation');
  held.native.assertReady(held.containment); return immutableSnapshot(held.containment);
}
export function readInstalledMcpStdioRunReservation(scope: InstalledMcpStdioRunScope, input: HeldRunMcpStdioInput) {
  const held = heldScope(scope, input, 'run');
  if (!held.reservation) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio original server has no native reservation');
  held.native.assertReserved(held.reservation);
  return { observation: immutableSnapshot(held.reservation), controller: scope.controller };
}

export function readInstalledMcpStdioRecoveryJoined(scope: InstalledMcpStdioRecoveryScope, input: HeldRecoveryMcpStdioInput) {
  const value = readJoined(scope, input, 'recovery');
  if (value.ownerJoined.purpose !== 'recovery') throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP recovery closure substitutes another purpose');
  return { ...value, originalLifecycle: value.originalLifecycle as McpStdioRecoveryNativeLifecycle, ownerJoined: value.ownerJoined };
}
export function readInstalledMcpStdioRecoveryReady(scope: InstalledMcpStdioRecoveryScope, input: HeldRecoveryMcpStdioInput): McpStdioScopeObservation {
  const held = heldScope(scope, input, 'recovery');
  if (!held.containment) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP recovery inspector has no original native READY');
  held.native.assertReady(held.containment); return immutableSnapshot(held.containment);
}
export function readInstalledMcpStdioRecoveryReservation(scope: InstalledMcpStdioRecoveryScope, input: HeldRecoveryMcpStdioInput) {
  const held = heldScope(scope, input, 'recovery');
  if (!held.reservation) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP recovery inspector has no original native reservation');
  held.native.assertReserved(held.reservation);
  return { observation: immutableSnapshot(held.reservation), controller: scope.controller };
}

declare const cleanupReceipt: unique symbol;
export type InstalledMcpStdioRunCleanup = Readonly<{ readonly [cleanupReceipt]: 'run' }>;
export type InstalledMcpStdioAdminCleanup = Readonly<{ readonly [cleanupReceipt]: 'admin' }>;
export type InstalledMcpStdioRecoveryCleanup = Readonly<{ readonly [cleanupReceipt]: 'recovery' }>;
type CleanupReceipt = InstalledMcpStdioRunCleanup | InstalledMcpStdioAdminCleanup | InstalledMcpStdioRecoveryCleanup;
const cleanupReceipts = new WeakMap<CleanupReceipt, {
  purpose: 'admin' | 'run' | 'recovery'; input: Input; pid: number; scope: NativeMcpStdioCleanupScope;
  observation: McpStdioNativeCleanup | McpStdioRecoveryNativeCleanup; proof: NativeMcpStdioCleanupProof; joined: McpStdioPhysicalJoined;
  lifecycleSnapshot: Buffer; cleanupSnapshot: Buffer; assertSelection(): void;
}>();
type CleanupConstruction = Readonly<{
  selected: HeldInstalledRuntime; anchor: HeldInstalledAnchor; controller: LinuxWorkerController; lock: HeldStateOwnerLock;
  checker: Readonly<{ supervisorInstanceId: string; stateOwnerEpoch: number }>; signal?: AbortSignal;
}>;
async function retire(input: CleanupConstruction, physical: Input, binding: AdminMcpStdioInputBinding | RunMcpStdioInputBinding | RecoveryMcpStdioInputBinding,
  purpose: 'admin' | 'run' | 'recovery'): Promise<CleanupReceipt> {
  input.signal?.throwIfAborted(); assertLinuxWorkerController(input.controller);
  const assertSelection = () => withInstalledWorkerRoot(input.selected, input.anchor, () => {});
  assertSelection();
  const nativeInput = borrowMcpStdioInput(input.lock, physical, binding, purpose, true);
  // This genuine receiver owns its authenticated cleanup before the first
  // await. The old raw chain stays immutable; the current checker has its own
  // mandatory reply, ACK, descriptors and separately encoded observation.
  const scope = purpose === 'recovery' ? cleanupInstalledMcpStdioRecovery(input.controller, nativeInput, input.checker) : purpose === 'admin' ? cleanupInstalledMcpStdioAdmin(input.controller, nativeInput, input.checker) :
    cleanupInstalledMcpStdioRun(input.controller, nativeInput, input.checker);
  let stopBy: number | undefined, stopError: unknown, controllerJoin: Promise<void> | undefined;
  const joinController = () => controllerJoin ??= input.controller.close();
  const stop = () => {
    if (stopBy !== undefined) return;
    stopBy = performance.now() + 2000;
    try { scope.stop(); } catch (error) { stopError = error; }
  };
  input.signal?.addEventListener('abort', stop, { once: true });
  if (input.signal?.aborted) stop();
  let proof: NativeMcpStdioCleanupProof | undefined, joined: McpStdioPhysicalJoined | undefined, acknowledging = false;
  let failure: unknown;
  try {
    const deadline = performance.now() + 30000;
    for (;;) {
      assertSelection();
      joined = scope.pollJoined() ?? joined;
      if (joined?.deathJoined) {
        if (!acknowledging) { scope.beginOutputAck(); acknowledging = true; }
        scope.pollOutputAck(); joined = scope.pollJoined() ?? joined;
      }
      proof = scope.pollCleanupObservation();
      if (proof && joined?.outputCustodyRetired) break;
      if (performance.now() >= Math.min(deadline, stopBy ?? deadline))
        throw new ResourceRetirementError('MCP stdio current checker exceeded its original observation/Stop bound', undefined);
      await delay(1);
    }
    scope.assertCleanupObservation(proof); scope.assertJoined(joined);
    if (stopError !== undefined) throw stopError;
  } catch (error) {
    failure = error; stop();
    // Join the already-issued current checker even when its semantic result
    // cannot be used. This bounded retirement never manufactures a receipt.
    try {
      while (performance.now() < stopBy!) {
        joined = scope.pollJoined() ?? joined;
        if (joined?.deathJoined) {
          if (!acknowledging) { scope.beginOutputAck(); acknowledging = true; }
          scope.pollOutputAck(); joined = scope.pollJoined() ?? joined;
          if (joined?.outputCustodyRetired) break;
        }
        await delay(1);
      }
    } catch (cleanup) { failure = new AggregateError([error, cleanup]); }
  } finally {
    input.signal?.removeEventListener('abort', stop);
    const [closed] = await Promise.allSettled([joinController()]);
    if (closed.status === 'rejected') failure = new AggregateError([failure, closed.reason]);
  }
  if (failure !== undefined || !proof || !joined?.outputCustodyRetired)
    throw failure instanceof ResourceRetirementError ? failure :
      new ResourceRetirementError('MCP stdio current checker has no positive complete native join', failure);
  // These native tag checks remain valid after the actual dedicated controller
  // has joined. Neither its death nor an original kind9 supplies this proof.
  scope.assertCleanupObservation(proof); scope.assertJoined(joined);
  const lifecycleSnapshot = scope.pollLifecycleSnapshot(), cleanupSnapshot = scope.pollCleanupSnapshot();
  if (!lifecycleSnapshot || !cleanupSnapshot) throw new ResourceRetirementError('MCP stdio current checker lost its original/separate custody bytes', undefined);
  const observation = purpose === 'recovery' ? decodeMcpStdioRecoveryCleanupData(cleanupSnapshot) : decodeMcpStdioCleanupData(cleanupSnapshot);
  const receipt = Object.freeze({}) as CleanupReceipt;
  cleanupReceipts.set(receipt, { purpose, input: physical, pid: process.pid, scope, observation, proof, joined,
    lifecycleSnapshot: Buffer.from(lifecycleSnapshot), cleanupSnapshot: Buffer.from(cleanupSnapshot), assertSelection });
  return receipt;
}
export async function retireInstalledRetainedMcpStdioRun(input: CleanupConstruction & Readonly<{
  input: HeldRunMcpStdioInput; inputBinding: RunMcpStdioInputBinding;
}>): Promise<InstalledMcpStdioRunCleanup> {
  return await retire(input, input.input, input.inputBinding, 'run') as InstalledMcpStdioRunCleanup;
}
export async function retireInstalledRetainedMcpStdioAdmin(input: CleanupConstruction & Readonly<{
  input: HeldAdminMcpStdioInput; inputBinding: AdminMcpStdioInputBinding;
}>): Promise<InstalledMcpStdioAdminCleanup> {
  return await retire(input, input.input, input.inputBinding, 'admin') as InstalledMcpStdioAdminCleanup;
}
export async function retireInstalledRetainedMcpStdioRecovery(input: CleanupConstruction & Readonly<{
  input: HeldRecoveryMcpStdioInput; inputBinding: RecoveryMcpStdioInputBinding;
}>): Promise<InstalledMcpStdioRecoveryCleanup> {
  return await retire(input, input.input, input.inputBinding, 'recovery') as InstalledMcpStdioRecoveryCleanup;
}
function readCleanup(receipt: CleanupReceipt, input: Input, purpose: 'admin' | 'run' | 'recovery') {
  const held = cleanupReceipts.get(receipt);
  if (!held || held.pid !== process.pid || held.input !== input || held.purpose !== purpose)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP stdio cleanup substitutes its original current checker');
  held.assertSelection(); held.scope.assertCleanupObservation(held.proof); held.scope.assertJoined(held.joined);
  return { observation: held.observation, joined: held.joined,
    lifecycleSnapshot: Buffer.from(held.lifecycleSnapshot), cleanupSnapshot: Buffer.from(held.cleanupSnapshot) };
}
export function readInstalledMcpStdioRunCleanup(receipt: InstalledMcpStdioRunCleanup, input: HeldRunMcpStdioInput) {
  const value = readCleanup(receipt, input, 'run'); return { ...value, observation: value.observation as McpStdioNativeCleanup };
}
export function readInstalledMcpStdioAdminCleanup(receipt: InstalledMcpStdioAdminCleanup, input: HeldAdminMcpStdioInput) {
  const value = readCleanup(receipt, input, 'admin'); return { ...value, observation: value.observation as McpStdioNativeCleanup };
}

export function readInstalledMcpStdioRecoveryCleanup(receipt: InstalledMcpStdioRecoveryCleanup, input: HeldRecoveryMcpStdioInput) {
  const value = readCleanup(receipt, input, 'recovery'); return { ...value, observation: value.observation as McpStdioRecoveryNativeCleanup };
}

