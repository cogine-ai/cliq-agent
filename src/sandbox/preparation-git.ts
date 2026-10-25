import { createHash } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import type { ArtifactCatalog } from '../state/artifacts.js';
import { joinResourceOperations, KernelStorageError, ResourceRetirementError } from '../state/errors.js';
import type { RetainedVerifierToolchain } from '../state/guest-toolchain.js';
import { borrowPreparingGitInputForExecution, type HeldPreparingGitInput } from '../state/native-owner.js';
import { closeNativeGitOutputReader, nativeGitOutputStream } from '../state/source-git-result.js';
import { privateGitInspectionOutput, readPrivateGitData, type PrivateGitData } from '../workspace/private-git-data.js';
import { assertLinuxWorkerController, type LinuxWorkerController, type NativePreparingGitRecipe,
  type NativePreparingGitRetirementObservation, type NativePreparingGitScope, type NativeSourceGitContainmentObservation,
  type NativeSourceGitOutputReader, type NativeSourceGitReservationObservation, type NativeSourceGitResult,
  type NativeSourceGitSnapshotObservation } from './linux-worker.js';

declare const preparingGitCompletionBrand: unique symbol;
export type PreparingGitCompletion = Readonly<{ readonly [preparingGitCompletionBrand]: true }>;
type CompletionData = Readonly<{ privateGit: PrivateGitData; metadataRef: string;
  observation: NativePreparingGitRetirementObservation; recipe: NativePreparingGitRecipe }>;
const completions = new WeakMap<PreparingGitCompletion, { input: HeldPreparingGitInput; data: CompletionData }>();
export function readPreparingGitCompletion(completion: PreparingGitCompletion, input: HeldPreparingGitInput): CompletionData {
  const held = completions.get(completion);
  if (!held || held.input !== input) throw new TypeError('private Git completion requires its original joined native input');
  // The input has actually closed after native/CAS/runtime join. Requiring a
  // live token here would misrepresent that original completed lifecycle.
  return held.data;
}
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function retirement(error: unknown): ResourceRetirementError {
  return error instanceof ResourceRetirementError ? error : new ResourceRetirementError('private Git preparation did not fully retire', error);
}
type Leaf = Readonly<{ role: number; sha256: string; byteCount: number; metadata?: Buffer }>;
function declarations(leaves: readonly Leaf[]): string {
  const digest = createHash('sha256');
  for (const leaf of leaves) {
    const bytes = Buffer.alloc(96); bytes.write('CLIQGIC1', 0, 'ascii');
    bytes.writeUInt32LE(1, 8); bytes.writeUInt32LE(leaf.role, 12); bytes.writeBigUInt64LE(BigInt(leaf.byteCount), 24);
    bytes.write(leaf.sha256, 32, 'ascii'); digest.update(bytes);
  }
  return digest.digest('hex');
}
function wholeDeath(death: NativeSourceGitContainmentObservation, original: NativeSourceGitContainmentObservation): void {
  for (const key of ['pid', 'namespaceInitPid', 'processStartToken', 'namespaceInitStartToken', 'cgroupId', 'pidNamespaceId'] as const)
    if (death[key] !== original[key]) invalid('private Git preparation lost its original whole process domain');
  if (death.cgroupPopulated !== 0 || death.namespaceInitDeadAndReaped !== 1 || death.remainingTrackedDescendants !== 0 ||
      !Number.isSafeInteger(death.observedAtMs) || death.observedAtMs < original.observedAtMs)
    invalid('private Git preparation lacks actual whole-domain death');
}
function completed(value: NativePreparingGitRetirementObservation, input: HeldPreparingGitInput,
  controller: LinuxWorkerController, death: NativeSourceGitContainmentObservation): NativePreparingGitRetirementObservation {
  const keys = ['origin', 'observedAtMs', 'completed', 'lastBirthPhase', 'runId', 'generationId', 'launchId', 'spawnNonceDigest',
    'activationNonceDigest', 'generationCreationNonceDigest', 'generationRef', 'inputIntentRef', 'originalControllerPid', 'originalControllerStartToken',
    'originalSupervisorPid', 'originalSupervisorStartToken'];
  if (Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key)) ||
      value.origin !== 'original_owner_joined' || value.completed !== 1 || value.lastBirthPhase !== 10 ||
      !Number.isSafeInteger(value.observedAtMs) || value.observedAtMs < death.observedAtMs ||
      value.originalControllerPid !== controller.pid || value.originalControllerStartToken !== controller.processStartToken)
    invalid('private Git completion lacks its original complete normal retirement');
  if (value.originalSupervisorPid !== input.identity.originalSupervisorPid ||
      value.originalSupervisorStartToken !== input.identity.originalSupervisorStartToken)
    invalid('private Git completion substitutes its original physical StateOwner process');
  for (const key of ['runId', 'generationId', 'launchId', 'spawnNonceDigest', 'activationNonceDigest',
    'generationCreationNonceDigest', 'generationRef', 'inputIntentRef'] as const)
    if (value[key] !== input.identity[key]) invalid('private Git completion substitutes its original preparing birth');
  return immutableSnapshot(value);
}

export type InstalledPreparingGit = Readonly<{
  reservation(): Promise<NativeSourceGitReservationObservation>;
  createBlocked(): void;
  ready(): Promise<NativeSourceGitContainmentObservation>;
  releaseCapture(): void;
  transferInput(): Promise<NativeSourceGitSnapshotObservation>;
  continueFixedGit(): void;
  complete(): Promise<PreparingGitCompletion>;
  /** Revokes synchronously, then joins this exact task and all real resources. */
  close(): Promise<void>;
}>;

/** Same original controller/reservation/birth only. This fixed CAS transfer
 * cannot read a live workspace, choose commands, replace a final binding, or
 * reuse an old source proof. The owning StateOwner keeps the SQL fresh cuts. */
export async function openInstalledPreparingGit(controller: LinuxWorkerController, input: HeldPreparingGitInput,
  artifacts: ArtifactCatalog, selected: { privateGitStateRef: string; recipe: NativePreparingGitRecipe;
    toolchain: RetainedVerifierToolchain }, signal?: AbortSignal): Promise<InstalledPreparingGit> {
  assertLinuxWorkerController(controller); borrowPreparingGitInputForExecution(input);
  const held = await controller.openPreparingGit({ input, recipe: selected.recipe, toolchain: selected.toolchain, signal });
  const recipe = held.recipe;
  const resources: SandboxResourceSpec = { maxProcesses: recipe.maxProcesses, memoryBytes: recipe.memoryBytes,
    cpuQuotaMicrosPerSecond: recipe.cpuQuotaMicrosPerSecond, maxOpenFiles: recipe.maxOpenFiles,
    maxSingleFileBytes: recipe.maxSingleFileBytes, maxGenerationBytes: recipe.maxGenerationBytes,
    maxInvocationOutputBytes: recipe.maxInvocationOutputBytes, maxIpcFrameBytes: recipe.maxIpcFrameBytes,
    maxQueuedIpcBytes: recipe.maxQueuedIpcBytes };
  const cancelled = new AbortController(), lifetime = AbortSignal.any([held.signal, cancelled.signal]);
  const reads = artifacts.withReadSignal(lifetime), readerCloses = new Set<NativeSourceGitOutputReader>();
  let scope: NativePreparingGitScope | undefined, originalReservation: NativeSourceGitReservationObservation | undefined;
  let originalDomain: NativeSourceGitContainmentObservation | undefined, result: NativeSourceGitResult | undefined;
  let joined = false, inputClosed = false, closed = false, released = false, continued = false;
  let reservationRequested = false, blockedRequested = false, readyRequested = false, sealedInput: NativeSourceGitSnapshotObservation | undefined;
  let stopFailure: ResourceRetirementError | undefined;
  let construction: ReturnType<typeof held.constructionRetirement>;
  let opening: Promise<unknown> | undefined, transfer: Promise<NativeSourceGitSnapshotObservation> | undefined;
  let consuming: Promise<PreparingGitCompletion> | undefined, closing: Promise<void> | undefined;
  const revoke = () => { if (!cancelled.signal.aborted) cancelled.abort(new KernelStorageError('RECOVERY_REQUIRED', 'private Git preparation was revoked')); };
  const closeReaders = () => {
    const failures: unknown[] = [];
    for (const reader of result ? [...Object.values(result.files), ...(result.excludeRule ? [result.excludeRule] : [])] : [])
      try { closeNativeGitOutputReader(reader, readerCloses); } catch (error) { failures.push(error); }
    if (failures.length) throw retirement(new AggregateError(failures));
  };
  const wait = async <T>(poll: () => T | undefined, stopping = false, deadline?: number): Promise<T> => {
    for (;;) {
      if (!stopping) lifetime.throwIfAborted();
      if (deadline !== undefined && performance.now() >= deadline) throw retirement(new Error('private Git preparation exceeded its original close deadline'));
      const value = poll();
      if (value !== undefined) return value;
      await setImmediate();
    }
  };
  const joinTasks = async () => {
    const pending = [opening, transfer, consuming].filter((work): work is Promise<unknown> => work !== undefined);
    const settled = await Promise.allSettled(pending);
    const failures = settled.flatMap(item => item.status === 'rejected' && item.reason instanceof ResourceRetirementError ? [item.reason] : []);
    if (failures.length) throw retirement(new AggregateError(failures));
  };
  const stop = (deadline?: number): Promise<void> => {
    revoke(); closed = true;
    return closing ??= (async () => {
      const failures: unknown[] = stopFailure ? [stopFailure] : [];
      // Revoke the native producer before waiting for potentially slow input
      // reads. Once outputs are borrowed their domain is already dead; native
      // removal must wait for every actual reader/CAS consumer below.
      if (scope && !result && !joined) try { scope.stop(); } catch (error) { failures.push(error); }
      try { await joinTasks(); } catch (error) { failures.push(error); }
      try { closeReaders(); } catch (error) { failures.push(error); }
      if (scope && !joined) {
        try { scope.stop(); await wait(() => scope!.pollStopped(), true, deadline); joined = true; }
        catch (error) { failures.push(error); }
      }
      try { await held.closeRuntime(); } catch (error) { failures.push(error); }
      if (!scope && reservationRequested && construction && !construction.pollRetired())
        failures.push(retirement(new Error('private Git construction still requires its original controller join')));
      if ((!scope || joined) && !inputClosed) {
        try { input.close(); inputClosed = true; } catch (error) { failures.push(error); }
      }
      if (failures.length) throw retirement(new AggregateError(failures));
      unregister();
    })();
  };
  const unregister = held.registerStop(async deadline => {
    if (!scope && reservationRequested) {
      // No scope receiver returned. Its original controller still owns that
      // native construction and closes it before closing its runtime set.
      // Waiting for that close here would wait on this very callback.
      revoke(); closed = true; await joinTasks(); return;
    }
    await stop(deadline);
  });
  const aborted = () => {
    revoke();
    // A borrowed result owns its real readers until complete()/close() joins
    // them. Never let an abort callback race native scope removal over them.
    if (scope && !result && !joined) try { scope.stop(); } catch (error) { stopFailure ??= retirement(error); }
  };
  lifetime.addEventListener('abort', aborted, { once: true });
  let data!: PrivateGitData, leaves!: readonly Leaf[], inputDigest!: string;
  try {
    const loading = (async () => {
      data = await readPrivateGitData(reads, selected.privateGitStateRef,
        { repositoryIdentityDigest: recipe.repositoryIdentityDigest, resources }, lifetime);
      const metadata = canonicalJsonBytes(privateGitInspectionOutput(data));
      if (canonicalSha256(privateGitInspectionOutput(data)) !== input.identity.inputIntentRef || !data.pack)
        invalid('private Git preparation metadata differs from its registered original CAS intent');
      const originalMetadata = await reads.readBoundedBytes(input.identity.inputIntentRef,
        Math.min(resources.maxSingleFileBytes, resources.maxInvocationOutputBytes));
      lifetime.throwIfAborted();
      if (!originalMetadata.equals(metadata)) invalid('private Git preparation requires its original durable metadata leaf');
      leaves = [{ role: 0, sha256: input.identity.inputIntentRef, byteCount: metadata.length, metadata },
        { role: 1, sha256: data.index.canonicalIndexBytesRef, byteCount: data.index.canonicalIndexByteCount },
        { role: 2, sha256: data.pack.packBytesRef, byteCount: data.pack.packByteCount },
        { role: 3, sha256: data.pack.packIndexBytesRef, byteCount: data.pack.packIndexByteCount }];
      for (const leaf of leaves) assertArtifactRef(leaf.sha256);
      inputDigest = declarations(leaves);
    })();
    opening = loading; await loading; opening = undefined; lifetime.throwIfAborted();
  } catch (error) {
    opening = undefined;
    try { await stop(); } catch (cleanup) { throw retirement(new AggregateError([error, cleanup])); }
    throw error;
  }
  const assertOpen = () => { lifetime.throwIfAborted(); if (closed || joined) invalid('private Git preparing scope is closed or retired'); };
  const send = async (attempt: () => boolean) => { await wait(() => attempt() ? true : undefined); lifetime.throwIfAborted(); };
  const api: InstalledPreparingGit = Object.freeze({
    reservation() {
      assertOpen();
      if (reservationRequested) return Promise.reject(new TypeError('private Git reservation is single-use'));
      reservationRequested = true;
      try { scope = held.reserve(); } catch (error) { construction = held.constructionRetirement(); return Promise.reject(error); }
      return opening = (async () => {
        const value = await wait(() => scope!.pollReserved()); lifetime.throwIfAborted();
        if (value.subreaperStartToken !== controller.subreaperStartToken || value.fileId !== value.cgroupId ||
            value.ownerUid !== input.identity.generation.ownerUid || !Number.isSafeInteger(value.observedAtMs) || value.observedAtMs < 1)
          invalid('private Git reservation differs from its original controller/birth');
        originalReservation = immutableSnapshot(value); return originalReservation;
      })() as Promise<NativeSourceGitReservationObservation>;
    },
    createBlocked() { assertOpen(); if (!originalReservation || blockedRequested) invalid('private Git blocked creation requires its original reserved scope'); blockedRequested = true; scope!.createBlocked(); },
    ready() {
      assertOpen(); if (!scope || !blockedRequested || readyRequested) return Promise.reject(new TypeError('private Git ready is single-use'));
      readyRequested = true;
      return opening = (async () => {
        const value = await wait(() => scope!.pollReady()); lifetime.throwIfAborted();
        if (value.cgroupId !== originalReservation!.cgroupId || value.cgroupPopulated !== 1 || value.namespaceInitDeadAndReaped !== 0 ||
            value.remainingTrackedDescendants !== 0 || !Number.isSafeInteger(value.observedAtMs) || value.observedAtMs < originalReservation!.observedAtMs)
          invalid('private Git blocked process differs from its original reservation');
        originalDomain = immutableSnapshot(value); return originalDomain;
      })() as Promise<NativeSourceGitContainmentObservation>;
    },
    releaseCapture() { assertOpen(); if (!originalDomain || released) invalid('private Git transfer requires its original blocked domain'); scope!.releaseCapture(); released = true; },
    transferInput() {
      assertOpen(); if (!released || transfer) return Promise.reject(new TypeError('private Git input transfer is single-use'));
      return transfer = (async () => {
        for (const leaf of leaves) {
          await send(() => scope!.declareInput(leaf.role, leaf.sha256, leaf.byteCount));
          if (leaf.metadata) {
            for (let offset = 0; offset < leaf.metadata.length; offset += 65_536) {
              const bytes = leaf.metadata.subarray(offset, Math.min(offset + 65_536, leaf.metadata.length));
              await send(() => scope!.writeInput(bytes));
            }
          } else for await (const bytes of reads.readChunks(leaf.sha256, leaf.byteCount)) {
            lifetime.throwIfAborted();
            for (let offset = 0; offset < bytes.length; offset += 65_536) {
              const chunk = bytes.subarray(offset, Math.min(offset + 65_536, bytes.length)); await send(() => scope!.writeInput(chunk));
            }
          }
          await send(() => scope!.endInput());
        }
        await send(() => scope!.finishInput());
        const value = await wait(() => scope!.pollSealed()); lifetime.throwIfAborted();
        if (value.snapshotDigest !== inputDigest || value.entryCount !== 4 || value.shardCount !== 4 ||
            value.byteCount !== leaves.reduce((sum, leaf) => sum + leaf.byteCount, 0)) invalid('private Git sealed input differs from all four original complete CAS leaves');
        sealedInput = immutableSnapshot(value); return sealedInput;
      })();
    },
    continueFixedGit() { assertOpen(); if (!sealedInput || continued) invalid('private Git continuation requires its original sealed transfer'); scope!.continueFixedGit(); continued = true; },
    complete() {
      assertOpen(); if (!continued || consuming) return Promise.reject(new TypeError('private Git completion is single-use'));
      return consuming = (async () => {
        // Record the genuine borrowed result before any subsequent abort can
        // throw, so close() can always close every already-issued reader slot.
        const actual = await wait(() => { const value = scope!.pollResult(); if (value) result = value; return value; });
        try {
          lifetime.throwIfAborted(); wholeDeath(actual.death, originalDomain!);
          if (actual.excludeRule !== null) invalid('CAS-only preparation cannot borrow a source ignore-rule reader');
          const names = ['inspection', 'index', 'pack', 'packIndex'] as const;
          await joinResourceOperations(names.map(async (name, index) => {
            const reader = actual.files[name], leaf = leaves[index]!;
            if (reader.identity.sha256 !== leaf.sha256 || reader.identity.byteCount !== leaf.byteCount)
              invalid('fresh private Git output differs from its original registered CAS bytes');
            let offset = 0;
            for await (const bytes of nativeGitOutputStream(reader, readerCloses, leaf.byteCount, lifetime)) {
              if (leaf.metadata && !bytes.equals(leaf.metadata.subarray(offset, offset + bytes.length)))
                invalid('fresh private Git metadata differs from the complete original schema');
              offset += bytes.length; await setImmediate(); lifetime.throwIfAborted();
            }
          }));
        } finally { closeReaders(); }
        lifetime.throwIfAborted();
        await held.closeRuntime(); lifetime.throwIfAborted();
        scope!.retire();
        const observation = completed(await wait(() => scope!.pollRetired()), input, controller, actual.death);
        joined = true; input.close(); inputClosed = true; lifetime.throwIfAborted();
        const completion = Object.freeze({}) as PreparingGitCompletion;
        completions.set(completion, { input, data: immutableSnapshot({ privateGit: data, metadataRef: input.identity.inputIntentRef,
          observation, recipe }) });
        unregister(); lifetime.removeEventListener('abort', aborted); return completion;
      })();
    },
    async close() { try { await stop(); } finally { lifetime.removeEventListener('abort', aborted); } },
  });
  return api;
}
