// Fixed installed Admin composition. Only the native same-process peer may
// cross into the broker; copied observations never become containment proof.
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import { controlWireRecord } from '../kernel/control-wire-data.js';
import { KernelStorageError, ResourceRetirementError } from '../state/errors.js';
import { borrowAdminMcpInputForExecution, borrowRetainedAdminMcpInputForCleanup, type AdminMcpInputBinding, type HeldAdminMcpInput, type HeldStateOwnerLock } from '../state/native-owner.js';
import { closeInstalledGuestToolchain, sealInstalledMcpAdminProbe, startInstalledGuestToolchain, withInstalledWorkerRoot, type HeldInstalledAnchor, type HeldInstalledRuntime } from '../state/installed-runtime.js';
import type { RetainedVerifierToolchain } from '../state/guest-toolchain.js';
import type { NativeGuestToolchain } from './guest-toolchain.js';
import { assertLinuxWorkerController, reserveInstalledMcpHttpAdmin, cleanupInstalledMcpHttpAdmin, type LinuxWorkerController } from './linux-worker.js';
import type { AdminMcpHttpBinding, NativeMcpAdminProbeImage, NativeMcpProtocolPeer } from '../state/mcp-broker-native.js';
export type McpAdminScopeObservation = Readonly<{
  pid: number;
  processStartToken: string;
  namespaceInitStartToken: string;
  namespaceInitPid: number;
  cgroupId: string;
  pidNamespaceId: string;
  cgroupPopulated: number;
  namespaceInitDeadAndReaped: number;
  remainingTrackedDescendants: number;
  observedAtMs: number;
}>;
export type McpAdminPhysicalJoined = Readonly<{
  observation: McpAdminScopeObservation;
  deathJoined: true;
  outputAcknowledged: boolean;
  outputCustodyRetired: boolean;
}>;
export type NativeMcpAdminScope = NativeMcpProtocolPeer & Readonly<{
  pollReserved(): McpAdminScopeObservation | undefined;
  createBlocked(): void;
  pollReady(): McpAdminScopeObservation | undefined;
  releaseRecipe(binding: AdminMcpHttpBinding): void;
  pollStageRequested(): Readonly<{
    phase: 'initialize' | 'initialized' | 'tools_list';
  }> | undefined;
  stop(): void;
  pollJoined(): McpAdminPhysicalJoined | undefined;
  assertJoined(observation: McpAdminPhysicalJoined): void;
  beginOutputAck(): void;
  pollOutputAck(): boolean;
  pollLifecycleSnapshot(): Buffer | undefined;
}>;
export type NativeAdminCleanupObservation = Readonly<{
  kind: 'mcp_admin_retained_cleanup_joined';
  originalBinding: AdminMcpInputBinding;
  originalBirthDigest: string;
  originalController: Readonly<{
    pid: number;
    processStartToken: string;
  }>;
  originalReservation: Readonly<{
    cgroupName: string;
    deviceId: string;
    fileId: string;
  }>;
  currentChecker: Readonly<{
    supervisorInstanceId: string;
    stateOwnerEpoch: number;
    supervisorPid: number;
    supervisorStartToken: string;
    controllerPid: number;
    controllerStartToken: string;
  }>;
  observedAtMs: number;
  priorSupervisorDead: true;
  priorControllerDead: true;
  networkJoined: true;
  outputCustodyRetired: true;
  remainingDescendants: 0;
}>;
export type NativeMcpAdminCleanupScope = Readonly<Pick<NativeMcpAdminScope, 'stop' | 'pollJoined' | 'assertJoined' | 'beginOutputAck' | 'pollOutputAck' | 'pollLifecycleSnapshot'> & {
  pollCleanupObservation(): NativeAdminCleanupObservation | undefined;
  assertCleanupObservation(value: NativeAdminCleanupObservation): void;
}>;
declare const cleanupReceiptBrand: unique symbol;
export type InstalledMcpAdminCleanup = Readonly<{
  readonly [cleanupReceiptBrand]: true;
}>;
const cleanupReceipts = new WeakMap<InstalledMcpAdminCleanup, {
  input: HeldAdminMcpInput;
  scope: NativeMcpAdminCleanupScope;
  observation: NativeAdminCleanupObservation;
  joined: McpAdminPhysicalJoined;
  bytes: Buffer;
}>();
export async function retireInstalledRetainedMcpHttpAdmin(selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor, controller: LinuxWorkerController, lock: HeldStateOwnerLock, input: HeldAdminMcpInput, binding: AdminMcpInputBinding, checker: {
  supervisorInstanceId: string;
  stateOwnerEpoch: number;
}, options: Readonly<{ signal?: AbortSignal }> = {}): Promise<InstalledMcpAdminCleanup> {
  options.signal?.throwIfAborted();
  withInstalledWorkerRoot(selected, anchor, () => {
  });
  const native = borrowRetainedAdminMcpInputForCleanup(lock, input, binding);
  const scope = cleanupInstalledMcpHttpAdmin(controller, native, checker);
  let observation: NativeAdminCleanupObservation | undefined;
  let physicalJoined: McpAdminPhysicalJoined | undefined;
  let stopBy: number | undefined, stopFailure: unknown;
  const stop = () => {
    if (stopBy !== undefined) return;
    stopBy = performance.now() + 2000;
    try {
      scope.stop();
    } catch (error) {
      stopFailure = error;
    }
  };
  // Reserve and register this actual checker before the first await. Aborting
  // joins the already-issued cleanup; it never abandons or adopts its recipe.
  options.signal?.addEventListener('abort', stop, { once: true });
  if (options.signal?.aborted) stop();
  try {
    const deadline = performance.now() + 30000;
    let acknowledging = false;
    for (;;) {
      const joined = scope.pollJoined();
      if (joined?.deathJoined) {
        physicalJoined = joined;
        if (!acknowledging) {
          scope.beginOutputAck();
          acknowledging = true;
        }
        scope.pollOutputAck();
      }
      observation = scope.pollCleanupObservation();
      if (observation) {
        break;
      }
      if (performance.now() >= (stopBy === undefined ? deadline : Math.min(deadline, stopBy))) {
        throw new KernelStorageError('RECOVERY_REQUIRED', 'original MCP Admin cleanup deadline elapsed');
      }
      await delay(1);
    }
    scope.assertCleanupObservation(observation);
    if (stopFailure !== undefined) {
      throw new ResourceRetirementError('MCP Admin cleanup stop did not positively join', stopFailure);
    }
    // Retain the actual post-ACK scope observation. The original lifecycle
    // bytes describe the old process and cannot stand in for this checker.
    physicalJoined = scope.pollJoined() ?? physicalJoined;
    if (!physicalJoined?.deathJoined || !physicalJoined.outputCustodyRetired) {
      throw new ResourceRetirementError('MCP Admin cleanup has no physical scope join', undefined);
    }
    scope.assertJoined(physicalJoined);
    const bytes = scope.pollLifecycleSnapshot();
    if (!bytes) {
      throw new ResourceRetirementError('original MCP Admin cleanup lost its retained birth bytes', undefined);
    }
    const receipt = Object.freeze({}) as InstalledMcpAdminCleanup;
    cleanupReceipts.set(receipt, {
      input,
      scope,
      observation,
      joined: physicalJoined,
      bytes: Buffer.from(bytes)
    });
    return receipt;
  }
  catch (error) {
    throw error instanceof ResourceRetirementError ? error : new ResourceRetirementError('MCP Admin cleanup checker has no positive joined receipt', error);
  }
  finally {
    options.signal?.removeEventListener('abort', stop);
  }
}
export function readInstalledMcpAdminCleanup(receipt: InstalledMcpAdminCleanup, input: HeldAdminMcpInput) {
  const held = cleanupReceipts.get(receipt);
  if (!held || held.input !== input) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP Admin cleanup is not its original current checker');
  }
  held.scope.assertCleanupObservation(held.observation);
  held.scope.assertJoined(held.joined);
  return {
    observation: held.observation,
    joined: held.joined,
    lifecycleSnapshot: Buffer.from(held.bytes)
  };
}
const scopes = new WeakMap<object, {
  scope: NativeMcpAdminScope;
  input: HeldAdminMcpInput;
  binding: AdminMcpInputBinding;
  pid: number;
  assertSelection(): void;
}>();
export type InstalledMcpHttpAdminScope = Readonly<{
  peer: NativeMcpProtocolPeer;
  controller: Readonly<{
    pid: number;
    processStartToken: string;
  }>;
  reservation(): Promise<McpAdminScopeObservation>;
  createBlocked(): void;
  ready(): Promise<McpAdminScopeObservation>;
  releaseRecipe(binding: AdminMcpHttpBinding): void;
  pollStageRequested: NativeMcpAdminScope['pollStageRequested'];
  beginOutputAck(): void;
  pollOutputAck(): boolean;
  close(): Promise<McpAdminPhysicalJoined>;
  assertJoined(observation: McpAdminPhysicalJoined): void;
  lifecycleSnapshot(): Buffer;
}>;
export function assertInstalledMcpAdminScope(scope: InstalledMcpHttpAdminScope, input: HeldAdminMcpInput): void {
  const held = scopes.get(scope);
  if (!held || held.input !== input || held.pid !== process.pid) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP Admin scope lost its original native input');
  }
  input.assertHeld();
}
/** A retired native input is closed. Validate its original tagged joined
 * receipt directly; the caller separately holds its current StateOwner. */
export function assertInstalledMcpAdminScopeJoined(scope: InstalledMcpHttpAdminScope, input: HeldAdminMcpInput,
  observation: McpAdminPhysicalJoined): void {
  const held = scopes.get(scope);
  if (!held || held.input !== input || held.pid !== process.pid) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP Admin join lost its original native scope');
  }
  held.assertSelection();
  held.scope.assertJoined(observation);
}
/** The caller persists original Admin prepared intent before entering here.
* All resources are closed before any construction failure may escape. */
export async function openInstalledMcpHttpAdminScope(selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor, controller: LinuxWorkerController, lock: HeldStateOwnerLock, input: HeldAdminMcpInput, inputBinding: AdminMcpInputBinding, toolchain: RetainedVerifierToolchain, configBytes: Buffer, options: Readonly<{
  signal?: AbortSignal;
}> = {}): Promise<InstalledMcpHttpAdminScope> {
  const nativeInput = borrowAdminMcpInputForExecution(lock, input, inputBinding);
  assertLinuxWorkerController(controller);
  const config = controlWireRecord(parseJsonStrict(new TextDecoder('utf8', {
    fatal: true
  }).decode(configBytes)), ['nonce', 'recipe']);
  if (!canonicalJsonBytes(config).equals(configBytes) || config.nonce !== inputBinding.nonce || configBytes.length > 3 * 1048576 + 4096) {
    throw new TypeError('MCP Admin helper configuration differs from its original input');
  }
  withInstalledWorkerRoot(selected, anchor, () => {
  });
  let script: NativeMcpAdminProbeImage | undefined;
  let guest: NativeGuestToolchain | undefined, original: NativeMcpAdminScope | undefined;
  let closing: Promise<McpAdminPhysicalJoined> | undefined;
  const close = () => closing ??= (async () => {
    const failures: unknown[] = [];
    try {
      original?.stop();
    }
    catch (error) {
      failures.push(error);
    }
    let joined: McpAdminPhysicalJoined | null = null;
    try {
      const deadline = performance.now() + 2000;
      let acknowledging = false;
      while (original) {
        joined = original.pollJoined() ?? null;
        if (joined?.deathJoined) {
          if (!acknowledging) {
            original.beginOutputAck();
            acknowledging = true;
          }
          if (original.pollOutputAck()) {
            joined = original.pollJoined() ?? null;
            if (joined?.outputCustodyRetired) {
              break;
            }
          }
        }
        if (performance.now() >= deadline) {
          throw new ResourceRetirementError('MCP Admin original scope did not join within Stop2', undefined);
        }
        await delay(1);
      }
    }
    catch (error) {
      failures.push(error);
    }
    if (guest) {
      try {
        await closeInstalledGuestToolchain(selected, guest);
      }
      catch (error) {
        failures.push(error);
      }
    }
    if (script) {
      try {
        script.close();
      }
      catch (error) {
        failures.push(error);
      }
    }
    if (failures.length) {
      throw failures.find(error => error instanceof ResourceRetirementError) ??
        new ResourceRetirementError('MCP Admin native resources did not retire', new AggregateError(failures));
    }
    if (original && (!joined || joined.deathJoined !== true || joined.outputCustodyRetired !== true)) {
      throw new ResourceRetirementError('MCP Admin peer joined without complete original custody retirement', undefined);
    }
    if (original && joined) original.assertJoined(joined);
    return joined!;
  })();
  const wait = async <T>(poll: () => T | null | undefined): Promise<T> => {
    const deadline = performance.now() + 5000;
    for (;;) {
      options.signal?.throwIfAborted();
      const value = poll();
      if (value !== undefined && value !== null) {
        return value;
      }
      if (performance.now() >= deadline) {
        throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP Admin original READY observation timed out');
      }
      await delay(1, undefined, options.signal ? {
        signal: options.signal
      } : undefined);
    }
  };
  try {
    script = await sealInstalledMcpAdminProbe(selected, options.signal);
    guest = await startInstalledGuestToolchain(selected, toolchain, options);
    options.signal?.throwIfAborted();
    original = reserveInstalledMcpHttpAdmin(controller, nativeInput, guest, script, Buffer.from(configBytes));
    let scope!: InstalledMcpHttpAdminScope;
    const current = () => {
      assertInstalledMcpAdminScope(scope, input);
      withInstalledWorkerRoot(selected, anchor, () => {
      });
    };
    scope = Object.freeze({
      peer: original,
      controller: Object.freeze({
        pid: controller.pid,
        processStartToken: controller.processStartToken
      }),
      reservation: () => wait(() => original!.pollReserved()),
      createBlocked() {
        current();
        original!.createBlocked();
      },
      ready: () => wait(() => original!.pollReady()),
      releaseRecipe(binding) {
        current();
        original!.releaseRecipe(binding);
      },
      pollStageRequested: () => original!.pollStageRequested(),
      beginOutputAck: () => original!.beginOutputAck(),
      pollOutputAck: () => original!.pollOutputAck(),
      close,
      assertJoined(observation) {
        assertInstalledMcpAdminScopeJoined(scope, input, observation);
      },
      lifecycleSnapshot() {
        const bytes = original!.pollLifecycleSnapshot();
        if (!bytes) {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP Admin original lifecycle custody is not complete');
        }
        return Buffer.from(bytes);
      }
    });
    scopes.set(scope, {
      scope: original,
      input,
      binding: inputBinding,
      pid: process.pid,
      assertSelection: () => withInstalledWorkerRoot(selected, anchor, () => {})
    });
    return scope;
  }
  catch (error) {
    try {
      await close();
    }
    catch (retirement) {
      throw retirement;
    }
    throw error;
  }
}
