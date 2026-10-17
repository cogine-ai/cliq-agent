import { constants, type BigIntStats } from 'node:fs';
import { open, type FileHandle } from 'node:fs/promises';
import { Module } from 'node:module';
import path from 'node:path';
import { isSea } from 'node:sea';
import { fileURLToPath } from 'node:url';
import { setImmediate } from 'node:timers/promises';
import { DatabaseSync } from 'node:sqlite';

import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, normalizeAbsolutePath } from '../kernel/identity.js';
import type { StateRootIdentityV1, WorkspaceGenerationIdentityV1 } from '../kernel/types.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { decodeWorkspaceGenerationIdentity } from './decoders.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { hashHeldProcessImage } from './process-image.js';

export const STATE_OWNER_NATIVE_ENTRY_ID = 'state_owner_native';
export const STATE_OWNER_NATIVE_RELATIVE_PATH = `native/${process.platform}-${process.arch}/state-owner.node`;
export const STATE_OWNER_NATIVE_PATH = isSea()
  ? path.join(path.dirname(process.execPath), STATE_OWNER_NATIVE_RELATIVE_PATH)
  : fileURLToPath(new URL(`../../dist/${STATE_OWNER_NATIVE_RELATIVE_PATH}`, import.meta.url));

type DescriptorIdentity = Readonly<{ deviceId: string; fileId: string; ownerUid: number }>;
/** Physical birth witness only. It grants neither activation nor death proof. */
export type HeldWorkerReservation = Readonly<{ identity: DescriptorIdentity; assertHeld(): void; close(): void }>;
type NativeWorkerReservation = HeldWorkerReservation & { borrow(): Readonly<{ fd: number; identity: DescriptorIdentity; assertHeld(): void; close(): void }> };
const workerReservations = new WeakMap<HeldWorkerReservation,
  { lock: HeldStateOwnerLock; native: NativeWorkerReservation; launchId: string; spawnNonceDigest: string; closed: boolean }>();
function checkedWorkerReservation(launchId: string, spawnNonceDigest: string): string {
  if (!/^[A-Za-z0-9_-]{43}$/u.test(launchId) || !/^[0-9a-f]{64}$/u.test(spawnNonceDigest)) {
    throw new KernelStorageError('INVALID_REQUEST', 'worker reservation requires the exact launch and spawn nonce');
  }
  return identityHash('cliq-worker-reservation-v1', launchId, spawnNonceDigest);
}
function workerReservationError(error: unknown): never {
  if (error instanceof KernelStorageError || error instanceof ResourceRetirementError) throw error;
  if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
    throw new ResourceRetirementError('worker reservation descriptors did not retire', error);
  }
  throw new KernelStorageError('RECOVERY_REQUIRED', 'exact native worker reservation is not held');
}
function wrapWorkerReservation(lock: HeldStateOwnerLock, native: NativeWorkerReservation, launchId: string,
  spawnNonceDigest: string): HeldWorkerReservation {
  const handle: HeldWorkerReservation = Object.freeze({ identity: Object.freeze({ ...native.identity }),
    assertHeld() {
      if (this !== handle) throw new TypeError('invalid worker reservation');
      try { lock.assertHeld(); native.assertHeld(); } catch (error) { workerReservationError(error); }
    },
    close() {
      if (this !== handle) throw new TypeError('invalid worker reservation');
      try { native.close(); workerReservations.get(handle)!.closed = true; } catch (error) { workerReservationError(error); }
    }
  });
  workerReservations.set(handle, { lock, native, launchId, spawnNonceDigest, closed: false });
  return handle;
}
/** Internal descriptor bridge between the two installed native modules. */
export function borrowWorkerReservationForExecution(reservation: HeldWorkerReservation, launchId: string,
  spawnNonceDigest: string) {
  const held = workerReservations.get(reservation);
  if (!held || held.launchId !== launchId || held.spawnNonceDigest !== spawnNonceDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'native witness belongs to a different launch reservation');
  }
  reservation.assertHeld();
  try { return held.native.borrow(); } catch (error) { workerReservationError(error); }
}
/** Only the exact original native close can set this joined state. It closes
 * every duplicate before returning, and any error keeps the StateOwner held. */
export function readWorkerReservationRetirement(lock: HeldStateOwnerLock, reservation: HeldWorkerReservation,
  launchId: string, spawnNonceDigest: string): DescriptorIdentity {
  const held = workerReservations.get(reservation);
  if (!held || held.lock !== lock || held.launchId !== launchId || held.spawnNonceDigest !== spawnNonceDigest)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'reservation retirement substitutes its exact original physical owner');
  lock.assertHeld();
  if (!held.closed) throw new KernelStorageError('RECOVERY_REQUIRED', 'original worker reservation descriptors are not joined');
  return reservation.identity;
}
export type SourceInspectionStagingIdentity = DescriptorIdentity & Readonly<{ mode: 448 }>;
/** Physical source-inspection reservation only, never a Run or execution FD. */
export type HeldSourceInspectionStaging = Readonly<{
  identity: SourceInspectionStagingIdentity;
  assertHeld(): void;
  close(): void;
}>;
export type SourceInspectionStagingRetirement = Readonly<{ kind: 'physical_source_staging_retirement' }>;
type SourceInspectionStagingBinding = Readonly<{
  lock: HeldStateOwnerLock;
  native: NativeSourceInspectionStaging;
  inspectionId: string;
  stagingNonceDigest: string;
  stagingIdentity: SourceInspectionStagingIdentity;
  created: boolean;
}>;
type NativeSourceInspectionStaging = Readonly<{
  identity: DescriptorIdentity;
  assertHeld(): void;
  close(): void;
  retireStep(): boolean;
  assertRetired(): void;
}>;
const sourceStagings = new WeakMap<HeldSourceInspectionStaging, SourceInspectionStagingBinding>();
const sourceRetirements = new WeakMap<SourceInspectionStagingRetirement, SourceInspectionStagingBinding>();
const sourceRetirementTasks = new WeakMap<HeldSourceInspectionStaging, Promise<SourceInspectionStagingRetirement>>();
const sourceRetirementsByLock = new WeakMap<HeldStateOwnerLock, Set<Promise<SourceInspectionStagingRetirement>>>();

function sourceStagingError(error: unknown): never {
  if (error instanceof KernelStorageError) throw error;
  if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
    throw new ResourceRetirementError('source staging resource retirement failed', error);
  }
  throw new KernelStorageError('RECOVERY_REQUIRED', 'source inspection staging identity or reservation is not valid');
}
function checkedSourceInspection(inspectionId: string, stagingNonceDigest: string): string {
  if (typeof inspectionId !== 'string' || typeof stagingNonceDigest !== 'string' ||
      !/^[A-Za-z0-9_-]{43}$/.test(inspectionId) || !/^[0-9a-f]{64}$/.test(stagingNonceDigest))
    throw new KernelStorageError('INVALID_REQUEST', 'source staging requires the canonical inspection id and nonce digest');
  return identityHash(inspectionId, stagingNonceDigest);
}
function wrapSourceInspectionStaging(lock: HeldStateOwnerLock, native: NativeSourceInspectionStaging,
  inspectionId: string, stagingNonceDigest: string, created: boolean): HeldSourceInspectionStaging {
  const identity: SourceInspectionStagingIdentity = Object.freeze({ ...native.identity, mode: 448 });
  const staging: HeldSourceInspectionStaging = Object.freeze({ identity,
    assertHeld() {
      if (this !== staging) throw new TypeError('invalid source inspection staging handle');
      try { native.assertHeld(); } catch (error) { sourceStagingError(error); }
    },
    close() {
      if (this !== staging) throw new TypeError('invalid source inspection staging handle');
      try { native.close(); } catch (error) { sourceStagingError(error); }
    }
  });
  sourceStagings.set(staging, Object.freeze({ lock, native, inspectionId, stagingNonceDigest, stagingIdentity: identity, created }));
  return staging;
}
function sourceStagingBinding(lock: HeldStateOwnerLock, staging: HeldSourceInspectionStaging): SourceInspectionStagingBinding {
  const binding = sourceStagings.get(staging);
  if (!binding || binding.lock !== lock) throw new KernelStorageError('ARTIFACT_MISMATCH', 'source staging was not minted by this exact StateOwner');
  lock.assertHeld();
  return binding;
}
/** Only a newly created actual reservation can authorize a capturing row. */
export function readSourceInspectionStaging(lock: HeldStateOwnerLock, staging: HeldSourceInspectionStaging):
  Readonly<{ inspectionId: string; stagingNonceDigest: string; stagingIdentity: SourceInspectionStagingIdentity }> {
  const binding = sourceStagingBinding(lock, staging);
  if (!binding.created) throw new KernelStorageError('ARTIFACT_MISMATCH', 'retained source staging cannot authorize a new reservation');
  staging.assertHeld();
  return Object.freeze({ inspectionId: binding.inspectionId, stagingNonceDigest: binding.stagingNonceDigest,
    stagingIdentity: binding.stagingIdentity });
}
/** The owning task must already have joined capture/process resources. This
 * proves only exact native staging cleanup/fsync, not those lifecycle facts. */
export function retireSourceInspectionStaging(lock: HeldStateOwnerLock, staging: HeldSourceInspectionStaging): Promise<SourceInspectionStagingRetirement> {
  const binding = sourceStagingBinding(lock, staging);
  const pending = sourceRetirementTasks.get(staging);
  if (pending) return pending;
  const task = (async () => {
    let operationError: unknown;
    try {
      // Cleanup cannot be cancelled early: the owning scope must await every
      // exact native step and descriptor closure before it can retire.
      for (;;) {
        await setImmediate(); lock.assertHeld();
        if (binding.native.retireStep()) break;
      }
    } catch (error) { operationError = error; sourceStagingError(error); }
    finally {
      try { binding.native.close(); }
      catch (error) { throw new ResourceRetirementError('source staging cleanup descriptors did not retire',
        new AggregateError(operationError === undefined ? [error] : [operationError, error])); }
    }
    const receipt: SourceInspectionStagingRetirement = Object.freeze({ kind: 'physical_source_staging_retirement' });
    sourceRetirements.set(receipt, binding);
    return receipt;
  })();
  sourceRetirementTasks.set(staging, task);
  let active = sourceRetirementsByLock.get(lock);
  if (!active) { active = new Set(); sourceRetirementsByLock.set(lock, active); }
  active.add(task);
  void task.then(() => active.delete(task), () => active.delete(task));
  void task.catch(() => { if (sourceRetirementTasks.get(staging) === task) sourceRetirementTasks.delete(staging); });
  return task;
}
export function readSourceInspectionStagingRetirement(lock: HeldStateOwnerLock, receipt: SourceInspectionStagingRetirement):
  Readonly<{ inspectionId: string; stagingNonceDigest: string; stagingIdentity: SourceInspectionStagingIdentity;
    stagingObservation: 'exact_reserved_root_absent'; directoryFsyncComplete: true }> {
  const binding = sourceRetirements.get(receipt);
  if (!binding || binding.lock !== lock) throw new KernelStorageError('ARTIFACT_MISMATCH', 'source staging retirement was not minted by this exact StateOwner');
  lock.assertHeld();
  // A later replacement at the same locator must not reuse a stale receipt.
  try { binding.native.assertRetired(); } catch (error) { sourceStagingError(error); }
  return Object.freeze({ inspectionId: binding.inspectionId, stagingNonceDigest: binding.stagingNonceDigest,
    stagingIdentity: binding.stagingIdentity, stagingObservation: 'exact_reserved_root_absent', directoryFsyncComplete: true });
}
/** Trusted composition-only staging handle. It is not a Linux/VM locator. */
export type HeldGenerationTree = Readonly<{
  identity: DescriptorIdentity;
  assertHeld(): void;
  close(): void;
}>;
export type BorrowedGenerationForExecution = Readonly<{
  fd: number;
  identity: DescriptorIdentity;
  assertHeld(): void;
  /** Actual filesystem total capacity, never free-space or a caller attestation.
   * Current Linux campaign requires a dedicated bounded StateRoot filesystem. */
  assertQuota(maxGenerationBytes: number): Readonly<{ totalBytes: number; filesystemType: string; identity: DescriptorIdentity }>;
  close(): void;
}>;
export type HeldGenerationFileReader = Readonly<{ readChunk(): Buffer | null; assertHeld(): void; close(): void }>;
export type HeldGenerationFileWriter = Readonly<{ writeChunk(bytes: Buffer): void; finish(): void; assertHeld(): void; close(): void }>;
export type GenerationSnapshotEntry = Readonly<{ path: string; kind: 'directory'; mode: number }> |
  Readonly<{ path: string; kind: 'symlink'; mode: number; target: string }> |
  Readonly<{ path: string; kind: 'file'; mode: number; byteCount: number; file: HeldGenerationFileReader }>;
export type HeldGenerationSnapshot = Readonly<{
  next(): GenerationSnapshotEntry | null;
  assertComplete(): void;
  close(): void;
}>;
type NativeGenerationTree = HeldGenerationTree & {
  mkdir(path: string): void;
  symlink(path: string, target: string): void;
  openSnapshot(): HeldGenerationSnapshot;
  openFileWriter(path: string, mode: number, byteCount: number): HeldGenerationFileWriter;
  borrow(): BorrowedGenerationForExecution;
  assertRetired(): number;
};
const nativeTrees = new WeakMap<HeldGenerationTree, NativeGenerationTree>();
const roots = new WeakMap<HeldStateOwnerLock, StateRootIdentityV1>();

export function stateRootIdentityForLock(lock: HeldStateOwnerLock): StateRootIdentityV1 {
  const root = roots.get(lock);
  if (!root) throw new TypeError('invalid StateOwner lock handle');
  lock.assertHeld();
  return root;
}

function wrapGenerationTree(native: NativeGenerationTree): HeldGenerationTree {
  const handle: HeldGenerationTree = Object.freeze({
    identity: Object.freeze({ ...native.identity }),
    assertHeld() { if (this !== handle) throw new TypeError('invalid private generation handle'); native.assertHeld(); },
    close() { if (this !== handle) throw new TypeError('invalid private generation handle'); native.close(); }
  });
  nativeTrees.set(handle, native);
  return handle;
}
function heldTree(tree: HeldGenerationTree): NativeGenerationTree {
  const native = nativeTrees.get(tree);
  if (!native) throw new TypeError('invalid private generation handle');
  native.assertHeld();
  return native;
}
/** Internal producer primitive, not a user/tool-selected filesystem operation. */
export function writeGenerationEntry(tree: HeldGenerationTree, entry:
  { path: string; kind: 'directory' } | { path: string; kind: 'symlink'; target: string }): void {
  const native = heldTree(tree);
  if (entry.kind === 'directory') native.mkdir(entry.path);
  else native.symlink(entry.path, entry.target);
}
/** Exhaustion, not opening a cursor, is the native rewalk/fsync observation. */
export function openGenerationSnapshot(tree: HeldGenerationTree): HeldGenerationSnapshot {
  return heldTree(tree).openSnapshot();
}
export function openGenerationFileWriter(tree: HeldGenerationTree, path: string, mode: 384 | 420 | 493,
  byteCount: number): HeldGenerationFileWriter {
  return heldTree(tree).openFileWriter(path, mode, byteCount);
}
/** Only a native-minted tree can transfer a duplicate to the closed launcher.
 * No public client accepts a number/path as an authority override. */
export function borrowGenerationForExecution(tree: HeldGenerationTree): BorrowedGenerationForExecution {
  return heldTree(tree).borrow();
}
/** Closed native owner, not a rescan, boolean or caller-supplied descriptor. */
export function assertRetiredGenerationTree(tree: HeldGenerationTree): number {
  const native = nativeTrees.get(tree);
  if (!native) throw new TypeError('invalid retired generation tree owner');
  try { return native.assertRetired(); }
  catch (error) {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('generation resources did not retire under their original StateOwner', error);
    throw new KernelStorageError('RECOVERY_REQUIRED', 'generation native resource owners are not retired', { cause: error });
  }
}
/** Native-minted process/image observation, never a caller attestation. */
export type NativePeerObservation = Readonly<{
  pid: number;
  uid: number;
  gid: number;
  processStartToken: string;
  listener: DescriptorIdentity;
  acceptedSocket: DescriptorIdentity;
  imageFd: number;
  imageByteCount: number;
  close(): void;
}>;
export type HeldControlPeer = Readonly<{
  /** Transfer one duplicate to Node's Socket; the native original stays held. */
  takeSocketFd(): number;
  capture(): NativePeerObservation;
  assertObservation(observation: NativePeerObservation): void;
  close(): void;
}>;
export type HeldControlListener = Readonly<{ assertHeld(): void; close(): void }>;
/** Fixed installed auth transport, independent of StateOwner and SQLite.
 * The native original root/runtime/socket/selected image survive FD transfer. */
export type HeldInstalledControlClient = Readonly<{
  server: Readonly<{ pid: number; uid: number; gid: number; processStartToken: string }>;
  takeSocketFd(): number;
  assertHeld(): void;
  close(): void;
}>;
/** A physical move observation only: no containment death, tree or SQLite authority. */
export type GenerationQuarantineMove = Readonly<{
  quarantineCanonicalRootRelativePath: string;
  quarantineDeviceId: string;
  quarantineFileId: string;
  originalLocatorAbsent: true;
  renameNoReplace: true;
  directoryFsyncComplete: true;
}>;
export type HeldStateOwnerLock = Readonly<{
  root: DescriptorIdentity;
  runtime: DescriptorIdentity;
  lock: DescriptorIdentity;
  assertHeld(): void;
  assertPriorProcessDead(pid: number, processStartToken: string): void;
  /** Native time after observing the exact prior lifetime absent or replaced.
   * This grants no broker, descendant, claim or token-revocation proof. */
  observePriorProcessDeath(pid: number, processStartToken: string): number;
  openControlListener(onAccept: (peer: HeldControlPeer) => void, onError: (error: Error) => void): HeldControlListener;
  createGenerationTree(runId: string, generationId: string): HeldGenerationTree;
  /** A fixed recovery intent additionally permits its exact archived locator;
   * retained observation handles cannot write or transfer execution authority. */
  openGenerationTree(generation: WorkspaceGenerationIdentityV1, sourceRowVersion?: number): HeldGenerationTree;
  createSourceInspectionStaging(inspectionId: string, stagingNonceDigest: string): HeldSourceInspectionStaging;
  /** Only trusted recovery consumes the retained immutable reservation. An
   * absent root is physical absence, never an owner/task/process join proof. */
  openSourceInspectionStaging(inspectionId: string, stagingNonceDigest: string,
    identity: SourceInspectionStagingIdentity): HeldSourceInspectionStaging;
  createWorkerReservation(launchId: string, spawnNonceDigest: string): HeldWorkerReservation;
  openWorkerReservation(launchId: string, spawnNonceDigest: string, identity: DescriptorIdentity): HeldWorkerReservation;
  /** Trusted Supervisor primitive. The caller must first fence/retire writers;
   * this neither revokes open descriptors/mounts nor commits generation state. */
  quarantineGeneration(generation: WorkspaceGenerationIdentityV1, sourceRowVersion: number): GenerationQuarantineMove;
  close(): void;
}>;

export type NativeStateOwner = Readonly<{
  acquireLock(stateRoot: string, createLayout: boolean): HeldStateOwnerLock;
  processStartToken(): string;
  observeCurrentProcess(): Promise<Readonly<{
    pid: number; uid: number; processStartToken: string; executableImageDigest: string;
  }>>;
  openWorkspaceRoot(workspacePath: string): HeldWorkspaceRoot;
}>;

const workspaceRoots = new WeakMap<HeldWorkspaceRoot, string>();
/** Structural objects cannot impersonate the native producer. This proves
 * physical descriptor ownership only, never Trust or source-read permission. */
export function assertHeldWorkspaceRoot(root: HeldWorkspaceRoot): void {
  if (!workspaceRoots.has(root)) throw new TypeError('invalid native source workspace handle');
  root.assertHeld();
}

/** The canonical path is bound when the native handle is opened, not supplied
 * by a later caller beside a structurally matching descriptor identity. */
export function heldWorkspaceRootPath(root: HeldWorkspaceRoot): string {
  const workspacePath = workspaceRoots.get(root);
  if (workspacePath === undefined) throw new TypeError('invalid native source workspace handle');
  root.assertHeld();
  return workspacePath;
}

/** Read-only physical source authority. Trust and read-scope decisions precede
 * opening; this handle neither grants permission nor exposes an execution FD. */
export type HeldWorkspaceRoot = Readonly<{
  identity: DescriptorIdentity;
  repositoryDirectory?: DescriptorIdentity;
  assertHeld(): void;
  readGitConfigChunk(): Buffer | null;
  /** Metadata only. Entries must be explicitly selected before content is opened. */
  openSnapshot(): HeldWorkspaceCursor;
  /** Fixed instruction recipe: skip Git metadata, read only AGENTS.md bytes. */
  openInstructionSnapshot(): HeldWorkspaceCursor;
  close(): void;
}>;

export type HeldWorkspaceFileReader = Readonly<{ readChunk(): Buffer | null; assertHeld(): void; close(): void }>;
export type HeldWorkspaceEntry = Readonly<{
  path: string;
  kind: 'directory' | 'file' | 'symlink' | 'unsupported';
  mode: number;
  byteCount: number;
  identity: DescriptorIdentity;
  linkCount: number;
  openFile(): HeldWorkspaceFileReader;
  openDirectory(): HeldWorkspaceCursor;
  readSymlink(): string;
  assertHeld(): void;
  /** Named path/leaf identity only; not directory-content snapshot evidence. */
  assertPathHeld(): void;
  close(): void;
}>;
export type HeldWorkspaceCursor = Readonly<{
  next(): HeldWorkspaceEntry | null;
  /** Exhaustion plus unchanged held directory metadata, not a global snapshot claim. */
  assertComplete(): void;
  close(): void;
}>;

type NativeLock = Omit<HeldStateOwnerLock, 'quarantineGeneration' | 'createGenerationTree' | 'openGenerationTree' |
  'createSourceInspectionStaging' | 'openSourceInspectionStaging' | 'createWorkerReservation' | 'openWorkerReservation'> & {
  moveGeneration(runId: string, generationId: string, quarantineId: string, deviceId: string, fileId: string): DescriptorIdentity;
  createGenerationTree(runId: string, generationId: string): NativeGenerationTree;
  openGenerationTree(runId: string, generationId: string, quarantineId?: string, deviceId?: string, fileId?: string): NativeGenerationTree;
  createSourceInspectionStaging(stagingId: string): NativeSourceInspectionStaging;
  openSourceInspectionStaging(stagingId: string, deviceId: string, fileId: string): NativeSourceInspectionStaging;
  createWorkerReservation(reservationId: string): NativeWorkerReservation;
  openWorkerReservation(reservationId: string, deviceId: string, fileId: string, ownerUid: number): NativeWorkerReservation;
};
type NativeCurrentProcess = Readonly<{
  pid: number; uid: number; processStartToken: string;
  imageFd: number; imageByteCount: number; imageIdentityKey: string;
  assertHeld(): void; close(): void;
}>;
type NativeInstalledKeeper = Readonly<{ assertHeld(): void; readyLocator(): Buffer; close(): void }>;
type NativeInstalledAnchor = Readonly<{ assertHeld(): void;
  withRoot(operation: (fd: number, rootPath: string) => void): void; close(): void }>;
type NativeCredentialScope = Readonly<{ generation: string; assertHeld(): void; close(): void;
  observeProducerLifetime(pid: number, ownerUid: number, processStartToken: string): 'present' | 'dead' }>;
type NativeBinding = { acquireLock(stateRoot: string, createLayout: boolean): NativeLock; processStartToken(): string;
  captureCurrentProcess(): NativeCurrentProcess;
  openWorkspaceRoot(workspacePath: string): HeldWorkspaceRoot;
  acquireCredentialScope?(rootFd: number, stateRoot: string, root: readonly bigint[]): NativeCredentialScope;
  connectInstalledControl?(rootFd: number, stateRoot: string, root: readonly bigint[],
    imageFd: number, image: readonly bigint[]): HeldInstalledControlClient;
  initializeInstalledKeeper?(stateRoot: string, bundleDigest: string, relativePath: string,
    image: readonly bigint[], root: readonly bigint[]): NativeInstalledKeeper;
  acquireInstalledAnchor?(stateRoot: string, bundleDigest: string, relativePath: string,
    image: readonly bigint[], root: readonly bigint[], locator: Buffer): NativeInstalledAnchor;
  executeInstalledImage?(fd: number, image: readonly bigint[], bootstrap: readonly bigint[], root: readonly bigint[],
    stateRoot: string, bundleDigest: string, relativePath: string, role: 'keeper' | 'supervisor' | 'endpoint' | 'credential', command?: string): never };
const nativeBindings = new WeakMap<NativeStateOwner, NativeBinding>();
// Byte-identical copies may dlopen as different images with different static
// VFS state. Credential bootstrap must use the actual first loaded image.
const loadedImageIdentities = new WeakMap<NativeStateOwner, BigIntStats>();

/** Composition-only bridge: the verified installed selection supplies its
 * original FileHandles, never a caller socket, PID or executable locator. */
export function openHeldInstalledControlClient(native: NativeStateOwner, input: Readonly<{
  root: FileHandle; rootIdentity: BigIntStats; stateRoot: string;
  image: FileHandle; imageIdentity: BigIntStats;
}>): HeldInstalledControlClient {
  const binding = nativeBindings.get(native);
  if (!binding || typeof binding.connectInstalledControl !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed helper lacks fixed control client');
  if (process.platform !== 'linux') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed control client requires Linux');
  const convert = (error: unknown): never => {
    if (error instanceof KernelStorageError || error instanceof ResourceRetirementError) throw error;
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('installed control client descriptors did not retire', error);
    throw new KernelStorageError('RECOVERY_REQUIRED', 'fixed installed Supervisor connection or identity is unavailable', { cause: error });
  };
  let owned: HeldInstalledControlClient | undefined;
  try {
    const root = input.rootIdentity, image = input.imageIdentity;
    owned = binding.connectInstalledControl(input.root.fd, input.stateRoot,
      [root.dev, root.ino, root.uid, root.gid, root.mode], input.image.fd,
      [image.dev, image.ino, image.uid, image.gid, image.mode, image.size, image.nlink, image.mtimeNs, image.ctimeNs]);
    owned.assertHeld();
  } catch (error) {
    if (owned) {
      try { owned.close(); }
      catch (retirement) { throw new ResourceRetirementError('installed control acquisition did not retire', new AggregateError([error, retirement])); }
    }
    return convert(error);
  }
  const held = owned;
  const client: HeldInstalledControlClient = Object.freeze({ server: Object.freeze({ ...held.server }),
    takeSocketFd() {
      if (this !== client) throw new TypeError('invalid installed control client');
      try { return held.takeSocketFd(); } catch (error) { return convert(error); }
    },
    assertHeld() {
      if (this !== client) throw new TypeError('invalid installed control client');
      try { held.assertHeld(); } catch (error) { return convert(error); }
    },
    close() {
      if (this !== client) throw new TypeError('invalid installed control client');
      try { held.close(); } catch (error) { return convert(error); }
    }
  });
  return client;
}

/** Private credential bridge, not a descriptor getter or loader selector.
 * The installed producer still owns and revalidates this signed FileHandle. */
export async function assertHeldCredentialNativeImage(native: NativeStateOwner, image: FileHandle): Promise<void> {
  const expected = loadedImageIdentities.get(native);
  if (!expected) throw new KernelStorageError('ARTIFACT_MISMATCH', 'credential native image has no actual load provenance');
  let actual: BigIntStats;
  try { actual = await image.stat({ bigint: true }); }
  catch { throw new KernelStorageError('ARTIFACT_MISMATCH', 'credential native image is no longer held'); }
  if (!['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'].every(key =>
    actual[key as keyof BigIntStats] === expected[key as keyof BigIntStats])) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'credential helper is not the physically loaded image; a fresh process is required');
  }
}

/** Fixed same-image/same-engine bridge. The producer retains both originals;
 * callers cannot select a data FD, VFS, extension entry, URI or SQLite engine. */
export async function withHeldCredentialNativeScope<T>(native: NativeStateOwner, input: Readonly<{
  image: FileHandle; root: FileHandle; rootIdentity: BigIntStats; stateRoot: string;
}>, operation: (scope: NativeCredentialScope) => Promise<T>): Promise<T> {
  const binding = nativeBindings.get(native);
  if (!binding || typeof binding.acquireCredentialScope !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed helper lacks credential scope acquisition');
  if (process.versions.node !== '24.21.0')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'credential authority requires the fixed installed Node 24.21.0 backend');
  await assertHeldCredentialNativeImage(native, input.image);
  let owned: NativeCredentialScope;
  const convert = (error: unknown): never => {
    if (error instanceof KernelStorageError || error instanceof TypeError) throw error;
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('credential scope descriptors did not retire', error);
    // Verified native reports this only after complete healthy acquisition
    // cleanup. Contention is not corruption or a request to recover state.
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_CREDENTIAL_BUSY') throw error;
    throw new KernelStorageError('RECOVERY_REQUIRED', 'credential scope could not hold its original physical bindings', { cause: error });
  };
  try {
    const root = input.rootIdentity;
    owned = binding.acquireCredentialScope(input.root.fd, input.stateRoot, [root.dev, root.ino, root.uid, root.gid, root.mode]);
  } catch (error) { return convert(error); }
  let result: T;
  let failed = false;
  let failure: unknown;
  try {
    owned.assertHeld();
    const bootstrap = new DatabaseSync(':memory:', { allowExtension: true });
    try {
      await assertHeldCredentialNativeImage(native, input.image);
      // This optional entrypoint is provided by the fixed 24.21.0 backend;
      // the repository's client-minimum Node typings predate that overload.
      (bootstrap.loadExtension as (image: string, entry: string) => void).call(bootstrap,
        `${process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd'}/${input.image.fd}`, 'sqlite3_cliqcredentialvfs_init');
      bootstrap.enableLoadExtension(false);
      owned.assertHeld();
    } finally {
      try { bootstrap.close(); }
      catch (error) { throw new ResourceRetirementError('credential SQLite bootstrap did not retire', error); }
    }
    result = await operation(owned);
  } catch (error) { failed = true; failure = error; }
  // A failed database retirement is not permission to close guards beneath a
  // potentially live pager. Native holds the context until a fresh process.
  if (failure instanceof ResourceRetirementError) throw failure;
  try { owned.close(); }
  catch (error) { throw new ResourceRetirementError('credential native scope did not retire',
    new AggregateError(failed ? [failure, error] : [error])); }
  if (failed) throw failure;
  return result!;
}

/** Private verified-installation bridge. The keeper owns only containment and
 * its independent image observation, never StateOwner or a caller-supplied FD. */
export function initializeHeldInstalledKeeper(native: NativeStateOwner, input: Readonly<{
  stateRoot: string; root: BigIntStats; image: BigIntStats; bundleDigest: string; relativePath: string;
}>): NativeInstalledKeeper {
  const binding = nativeBindings.get(native);
  if (process.platform !== 'linux') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed keeper requires Linux');
  if (!binding || typeof binding.initializeInstalledKeeper !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed native helper lacks keeper initialization');
  const failed = (error: unknown): never => {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('installed keeper descriptors did not retire', error);
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      (error as { message?: string } | null)?.message ?? 'installed native keeper refused its physical identity', { cause: error });
  };
  let owned: NativeInstalledKeeper;
  try {
    const image = input.image;
    owned = binding.initializeInstalledKeeper(input.stateRoot, input.bundleDigest, input.relativePath,
      [image.dev, image.ino, image.size, image.uid, image.gid, image.mode, image.nlink, image.mtimeNs, image.ctimeNs],
      [input.root.dev, input.root.ino, input.root.uid, input.root.gid, input.root.mode]);
  } catch (error) { failed(error); }
  const handle: NativeInstalledKeeper = Object.freeze({
    assertHeld() {
      if (this !== handle) throw new TypeError('invalid installed keeper handle');
      try { owned.assertHeld(); } catch (error) { failed(error); }
    },
    readyLocator() {
      if (this !== handle) throw new TypeError('invalid installed keeper handle');
      try { return owned.readyLocator(); } catch (error) { return failed(error); }
    },
    close() {
      if (this !== handle) throw new TypeError('invalid installed keeper handle');
      try { owned.close(); } catch (error) { failed(error); }
    },
  });
  return handle;
}

/** Private consumer bridge. The locator is untrusted; native acquisition binds
 * the live signed keeper and obtains its original pin through held procfs. */
export function acquireHeldInstalledAnchor(native: NativeStateOwner, input: Readonly<{
  stateRoot: string; root: BigIntStats; image: BigIntStats; bundleDigest: string; relativePath: string; locator: Buffer;
}>): NativeInstalledAnchor {
  const binding = nativeBindings.get(native);
  if (process.platform !== 'linux') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed anchor requires Linux');
  if (!binding || typeof binding.acquireInstalledAnchor !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed native helper lacks anchor acquisition');
  const failed = (error: unknown): never => {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('installed anchor descriptors did not retire', error);
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      (error as { message?: string } | null)?.message ?? 'installed native anchor refused its physical identity', { cause: error });
  };
  let owned: NativeInstalledAnchor;
  try {
    const image = input.image;
    owned = binding.acquireInstalledAnchor(input.stateRoot, input.bundleDigest, input.relativePath,
      [image.dev, image.ino, image.size, image.uid, image.gid, image.mode, image.nlink, image.mtimeNs, image.ctimeNs],
      [input.root.dev, input.root.ino, input.root.uid, input.root.gid, input.root.mode], input.locator);
  } catch (error) { failed(error); }
  const handle: NativeInstalledAnchor = Object.freeze({
    assertHeld() {
      if (this !== handle) throw new TypeError('invalid installed anchor handle');
      try { owned.assertHeld(); } catch (error) { failed(error); }
    },
    withRoot(operation) {
      if (this !== handle) throw new TypeError('invalid installed anchor handle');
      let callbackFailure: { error: unknown } | undefined;
      try { owned.withRoot((fd, rootPath) => {
        try { return operation(fd, rootPath); }
        catch (error) { callbackFailure = { error }; throw error; }
      }); } catch (error) {
        if (callbackFailure && error === callbackFailure.error) throw error;
        failed(error);
      }
    },
    close() {
      if (this !== handle) throw new TypeError('invalid installed anchor handle');
      try { owned.close(); } catch (error) { failed(error); }
    },
  });
  return handle;
}

/** Private installed-producer bridge, not a NativeStateOwner public operation.
 * Only the producer supplies these checked identities; C borrows the original
 * FileHandle and independently binds both filesystem images before exec. */
export function executeHeldInstalledImage(native: NativeStateOwner, file: FileHandle, input: Readonly<{
  stateRoot: string; root: BigIntStats; bootstrap: BigIntStats; image: BigIntStats;
  bundleDigest: string; relativePath: string; role: 'keeper' | 'supervisor' | 'endpoint' | 'credential'; command?: string;
}>): never {
  const binding = nativeBindings.get(native);
  if (process.platform !== 'linux') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed execution requires Linux');
  if (!binding || typeof binding.executeInstalledImage !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed native helper lacks fixed-role execution');
  const imageTuple = (info: BigIntStats) => [info.dev, info.ino, info.size, info.uid, info.gid, info.mode, info.nlink, info.mtimeNs, info.ctimeNs];
  try {
    binding.executeInstalledImage(file.fd, imageTuple(input.image), imageTuple(input.bootstrap),
      [input.root.dev, input.root.ino, input.root.uid, input.root.gid, input.root.mode],
      input.stateRoot, input.bundleDigest, input.relativePath, input.role,
      ...(input.role === 'credential' ? [input.command] : []));
  } catch (error) {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('installed native execution descriptors did not retire', error);
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed native execution refused its bootstrap or selected image', { cause: error });
  }
  throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed native execution unexpectedly returned');
}

/** One canonical projection for bootstrap and native filesystem consumers.
 * This derives bytes only; the caller must hold and validate the native lock. */
export function stateRootIdentityFromDescriptor(stateRoot: string, descriptor: DescriptorIdentity): StateRootIdentityV1 {
  const root: StateRootIdentityV1 = {
    schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: process.platform === 'linux' ? 'linux' : 'macos',
    canonicalAbsolutePath: stateRoot, ownerUid: descriptor.ownerUid, deviceId: descriptor.deviceId,
    directoryFileId: descriptor.fileId, mode: 448, openedNoFollow: true, layoutVersion: 1, identityDigest: ''
  };
  root.identityDigest = digestOmitting(root, 'identityDigest');
  return Object.freeze(root);
}

/** Hide the native locator arguments; callers supply only the frozen identity
 * and the durable source version. No caller-selected destination or fallback. */
function wrapLock(held: NativeLock, stateRoot: string): HeldStateOwnerLock {
  const root = stateRootIdentityFromDescriptor(stateRoot, held.root);
  const rootRef = canonicalSha256(root);
  const receiver = (value: unknown) => {
    if (value !== handle) throw new TypeError('invalid StateOwner lock handle');
  };
  const handle: HeldStateOwnerLock = {
    root: held.root, runtime: held.runtime, lock: held.lock,
    assertHeld() { receiver(this); held.assertHeld(); },
    assertPriorProcessDead(pid, token) { receiver(this); held.assertPriorProcessDead(pid, token); },
    observePriorProcessDeath(pid, token) {
      receiver(this);
      try { return held.observePriorProcessDeath(pid, token); }
      catch (error) {
        if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
          throw new ResourceRetirementError('prior process observation descriptors did not retire', error);
        throw error;
      }
    },
    openControlListener(onAccept, onError) {
      receiver(this);
      held.assertHeld();
      if (typeof onAccept !== 'function' || typeof onError !== 'function') throw new TypeError('control listener requires callbacks');
      return held.openControlListener(onAccept, onError);
    },
    createWorkerReservation(launchId, spawnNonceDigest) {
      receiver(this); held.assertHeld();
      const name = checkedWorkerReservation(launchId, spawnNonceDigest);
      try { return wrapWorkerReservation(handle, held.createWorkerReservation(name), launchId, spawnNonceDigest); }
      catch (error) { workerReservationError(error); }
    },
    openWorkerReservation(launchId, spawnNonceDigest, identity) {
      receiver(this); held.assertHeld();
      const name = checkedWorkerReservation(launchId, spawnNonceDigest);
      if (!identity || Object.keys(identity).length !== 3 || !/^(0|[1-9][0-9]*)$/u.test(identity.deviceId) ||
          !/^[1-9][0-9]*$/u.test(identity.fileId) || identity.ownerUid !== held.root.ownerUid ||
          identity.deviceId !== held.root.deviceId) throw new KernelStorageError('ARTIFACT_MISMATCH', 'worker witness has a foreign StateRoot identity');
      try { return wrapWorkerReservation(handle,
        held.openWorkerReservation(name, identity.deviceId, identity.fileId, identity.ownerUid), launchId, spawnNonceDigest); }
      catch (error) { workerReservationError(error); }
    },
    createGenerationTree(runId, generationId) {
      receiver(this); held.assertHeld();
      if (!/^[A-Za-z0-9_-]{1,128}$/.test(runId) || !/^[A-Za-z0-9_-]{43}$/.test(generationId)) {
        throw new KernelStorageError('INVALID_REQUEST', 'private generation requires canonical Run/generation ids');
      }
      return wrapGenerationTree(held.createGenerationTree(runId, generationId));
    },
    openGenerationTree(value, sourceRowVersion) {
      receiver(this); held.assertHeld();
      const generation = decodeWorkspaceGenerationIdentity(value);
      const locator = generation.locator;
      if (process.platform !== 'linux' || locator.kind !== 'linux_directory' ||
          locator.stateRootIdentityRef !== rootRef || locator.stateRootIdentityDigest !== root.identityDigest ||
          locator.ownerUid !== root.ownerUid ||
          locator.canonicalRootRelativePath !== `runs/${generation.runId}/generations/${generation.generationId}`) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'private generation open requires the exact Linux StateRoot locator');
      }
      if (sourceRowVersion !== undefined && (!Number.isSafeInteger(sourceRowVersion) || sourceRowVersion < 1)) {
        throw new KernelStorageError('INVALID_REQUEST', 'retained generation open requires the exact positive source version');
      }
      const tree = sourceRowVersion === undefined ? held.openGenerationTree(generation.runId, generation.generationId) :
        held.openGenerationTree(generation.runId, generation.generationId,
          identityHash(generation.generationId, String(sourceRowVersion)), locator.deviceId, locator.directoryFileId);
      if (tree.identity.deviceId !== locator.deviceId || tree.identity.fileId !== locator.directoryFileId ||
          tree.identity.ownerUid !== locator.ownerUid) {
        tree.close();
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'private generation descriptor differs from its frozen identity');
      }
      return wrapGenerationTree(tree);
    },
    createSourceInspectionStaging(inspectionId, stagingNonceDigest) {
      receiver(this); held.assertHeld();
      const stagingId = checkedSourceInspection(inspectionId, stagingNonceDigest);
      try { return wrapSourceInspectionStaging(handle, held.createSourceInspectionStaging(stagingId), inspectionId, stagingNonceDigest, true); }
      catch (error) { sourceStagingError(error); }
    },
    openSourceInspectionStaging(inspectionId, stagingNonceDigest, identity) {
      receiver(this); held.assertHeld();
      const stagingId = checkedSourceInspection(inspectionId, stagingNonceDigest);
      if (!identity || Object.keys(identity).length !== 4 || typeof identity.deviceId !== 'string' || typeof identity.fileId !== 'string' ||
          !/^(0|[1-9][0-9]*)$/.test(identity.deviceId) ||
          !/^(0|[1-9][0-9]*)$/.test(identity.fileId) || identity.deviceId !== held.root.deviceId ||
          identity.ownerUid !== held.root.ownerUid || identity.mode !== 448 ||
          BigInt(identity.deviceId) > 0xffffffffffffffffn || BigInt(identity.fileId) > 0xffffffffffffffffn)
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'retained source staging requires its exact same-device private identity');
      try { return wrapSourceInspectionStaging(handle, held.openSourceInspectionStaging(stagingId, identity.deviceId, identity.fileId),
        inspectionId, stagingNonceDigest, false); }
      catch (error) { sourceStagingError(error); }
    },
    close() {
      receiver(this);
      if (sourceRetirementsByLock.get(handle)?.size)
        throw new ResourceRetirementError('StateOwner cannot release during active source staging cleanup', new Error('source cleanup is not joined'));
      try { held.close(); }
      catch (error) {
        if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
          throw new ResourceRetirementError('native resource retirement prevents StateOwner release', error);
        throw error;
      }
    },
    quarantineGeneration(value, sourceRowVersion) {
      receiver(this);
      held.assertHeld();
      const generation = decodeWorkspaceGenerationIdentity(value);
      const locator = generation.locator;
      const linux = locator.kind === 'linux_directory';
      const source = `runs/${generation.runId}/generations/${generation.generationId}${linux ? '' : '.img'}`;
      if (!Number.isSafeInteger(sourceRowVersion) || sourceRowVersion < 1 ||
          generation.generationId !== identityHash(generation.runId, generation.sourceCheckpointId,
            generation.sourceWorkspaceStateRef, generation.creationNonceDigest) ||
          linux !== (process.platform === 'linux') || locator.stateRootIdentityRef !== rootRef ||
          locator.stateRootIdentityDigest !== root.identityDigest ||
          (linux ? locator.canonicalRootRelativePath : locator.backingStoreCanonicalRootRelativePath) !== source ||
          (linux ? locator.ownerUid : locator.backingStoreOwnerUid) !== root.ownerUid) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'generation quarantine requires the exact host, StateRoot, generation locator and source version');
      }
      const quarantineId = identityHash(generation.generationId, String(sourceRowVersion));
      const moved = held.moveGeneration(generation.runId, generation.generationId, quarantineId,
        linux ? locator.deviceId : locator.backingStoreDeviceId, linux ? locator.directoryFileId : locator.backingStoreFileId);
      return Object.freeze({
        quarantineCanonicalRootRelativePath: `quarantine/workspace-generations/${quarantineId}`,
        quarantineDeviceId: moved.deviceId, quarantineFileId: moved.fileId,
        originalLocatorAbsent: true, renameNoReplace: true, directoryFsyncComplete: true
      });
    }
  };
  roots.set(handle, root);
  return handle;
}

let loaded: { digest: string; implementation: NativeStateOwner } | undefined;
// Cache bytes, never authority. Every use still captures and revalidates the
// actual mapped image; the private key includes the complete native stat tuple.
let currentImageHash: { key: string; digest: string } | undefined;

async function observeCurrentProcess(binding: NativeBinding) {
  let observation: NativeCurrentProcess | undefined;
  let operationError: unknown;
  try {
    observation = binding.captureCurrentProcess();
    observation.assertHeld();
    const executableImageDigest = currentImageHash?.key === observation.imageIdentityKey
      ? currentImageHash.digest
      : await hashHeldProcessImage(observation.imageFd, observation.imageByteCount, () => observation!.assertHeld());
    observation.assertHeld();
    currentImageHash = { key: observation.imageIdentityKey, digest: executableImageDigest };
    return Object.freeze({ pid: observation.pid, uid: observation.uid,
      processStartToken: observation.processStartToken, executableImageDigest });
  } catch (error) {
    operationError = error;
    if (error instanceof KernelStorageError || error instanceof ResourceRetirementError) throw error;
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
      throw new ResourceRetirementError('Supervisor process image descriptors did not retire', error);
    }
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'actual Supervisor process image is unavailable or changed', { cause: error });
  } finally {
    try { observation?.close(); }
    catch (error) { throw new ResourceRetirementError('Supervisor process image descriptor did not retire',
      operationError === undefined ? error : new AggregateError([operationError, error])); }
  }
}

/** Load only the fixed host helper, through its verified held descriptor.
 * Bundle signature verification belongs to the trusted StateStore bootstrap. */
export async function loadNativeStateOwner(bundle?: RuntimeBundleManifest): Promise<NativeStateOwner> {
  if (process.platform !== 'darwin' && process.platform !== 'linux') {
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', `StateOwner is unsupported on ${process.platform}`);
  }
  const file = await open(STATE_OWNER_NATIVE_PATH, constants.O_RDONLY | constants.O_NOFOLLOW);
  let operationError: unknown;
  try {
    return await loadHeldStateOwnerImage(file, bundle);
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try { await file.close(); }
    catch (error) { throw new ResourceRetirementError('installed StateOwner image descriptor did not retire',
      operationError === undefined ? error : new AggregateError([operationError, error])); }
  }
}

/** Internal fixed-image bridge for the installed producer. The file is already
 * held by its owning scope; this routine neither closes it nor exposes a
 * descriptor/path selector through the installed public handle. */
export async function loadHeldStateOwnerImage(file: FileHandle, bundle?: RuntimeBundleManifest): Promise<NativeStateOwner> {
  const before = await file.stat({ bigint: true });
  if (!before.isFile() || before.uid !== BigInt(process.geteuid!()) || before.nlink !== 1n ||
      (before.mode & 0o7777n) !== 0o500n || before.size <= 0n || before.size > 16n * 1024n * 1024n) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper must be an owner-only 0500 regular file of at most 16 MiB');
  }
  const fd = file.fd;
  // Installed files survive several borrows. Positional reads never consume
  // their shared file offset, and a closed FileHandle cannot lend a reused fd.
  const digest = await hashHeldProcessImage(fd, Number(before.size), () => {
    if (file.fd !== fd) throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native image handle is closed');
  });
  const after = await file.stat({ bigint: true });
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
      before.uid !== after.uid || before.mode !== after.mode || before.nlink !== after.nlink ||
      before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper changed while being read');
  }
  if (bundle) {
    const entry = bundle.entries.find((candidate) => candidate.entryId === STATE_OWNER_NATIVE_ENTRY_ID);
    if (!entry || entry.role !== 'platform_helper' || !entry.executable || entry.version !== '1' ||
        entry.relativePath !== STATE_OWNER_NATIVE_RELATIVE_PATH || entry.digest !== digest || entry.byteCount !== Number(after.size)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper does not match the signed RuntimeBundle');
    }
  }
  if (loaded) {
    if (loaded.digest !== digest) throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper changed within this process');
    return loaded.implementation;
  }
  const nativeModule = new Module(STATE_OWNER_NATIVE_PATH);
  process.dlopen(nativeModule, `${process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd'}/${file.fd}`);
  const binding: NativeBinding = nativeModule.exports;
  if (typeof binding.acquireLock !== 'function' || typeof binding.processStartToken !== 'function' ||
      typeof binding.captureCurrentProcess !== 'function' || typeof binding.openWorkspaceRoot !== 'function') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper has an unsupported interface');
  }
  const implementation: NativeStateOwner = {
    acquireLock(stateRoot, createLayout) {
      if (normalizeAbsolutePath(stateRoot) !== stateRoot) throw new TypeError('StateOwner root must be canonical');
      const held = binding.acquireLock(stateRoot, createLayout);
      try { return wrapLock(held, stateRoot); } catch (error) { held.close(); throw error; }
    },
    processStartToken: () => binding.processStartToken(),
    observeCurrentProcess: () => observeCurrentProcess(binding),
    openWorkspaceRoot(workspacePath) {
      if (normalizeAbsolutePath(workspacePath) !== workspacePath) throw new TypeError('source workspace root must be canonical');
      const root = Object.freeze(binding.openWorkspaceRoot(workspacePath));
      workspaceRoots.set(root, workspacePath);
      return root;
    }
  };
  loaded = { digest, implementation: Object.freeze(implementation) };
  nativeBindings.set(loaded.implementation, binding);
  loadedImageIdentities.set(loaded.implementation, before);
  return loaded.implementation;
}

export function assertStateOwnerLock(lock: HeldStateOwnerLock): void {
  try {
    lock.assertHeld();
  } catch (error) {
    if (error instanceof ResourceRetirementError) throw error;
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('StateOwner retains unresolved resource retirement', error);
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner root/runtime/lock descriptor identity changed or closed');
  }
}
