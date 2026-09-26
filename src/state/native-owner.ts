import { constants } from 'node:fs';
import { open, type FileHandle } from 'node:fs/promises';
import { Module } from 'node:module';

import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, normalizeAbsolutePath, sha256Bytes } from '../kernel/identity.js';
import type { StateRootIdentityV1, WorkspaceGenerationIdentityV1 } from '../kernel/types.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { decodeWorkspaceGenerationIdentity } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { runtimeNativePath } from '../runtime-bundle/installed-paths.js';

export const STATE_OWNER_NATIVE_ENTRY_ID = 'state_owner_native';
export const STATE_OWNER_NATIVE_RELATIVE_PATH = `native/${process.platform}-${process.arch}/state-owner.node`;
export const STATE_OWNER_NATIVE_PATH = runtimeNativePath(STATE_OWNER_NATIVE_RELATIVE_PATH, import.meta.url);

type DescriptorIdentity = Readonly<{ deviceId: string; fileId: string; ownerUid: number }>;
export type LiveWorkspaceInspection = Readonly<{
  root: DescriptorIdentity;
  git?: Readonly<{ identity: DescriptorIdentity; configBytes?: Buffer }>;
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
  /** Read-only, component-wise no-follow root/.git/config observation while
   * this StateOwner lock is held. It is not a complete source-tree capture. */
  inspectWorkspaceIdentity(canonicalAbsolutePath: string): LiveWorkspaceInspection;
  /** Trusted Supervisor primitive. The caller must first fence/retire writers;
   * this neither revokes open descriptors/mounts nor commits generation state. */
  quarantineGeneration(generation: WorkspaceGenerationIdentityV1, sourceRowVersion: number): GenerationQuarantineMove;
  close(): void;
}>;

export type NativeStateOwner = Readonly<{
  acquireLock(stateRoot: string, createLayout: boolean): HeldStateOwnerLock;
  processStartToken(): string;
}>;

type NativeLock = Omit<HeldStateOwnerLock, 'quarantineGeneration'> & {
  moveGeneration(runId: string, generationId: string, quarantineId: string, deviceId: string, fileId: string): DescriptorIdentity;
};
type NativeBinding = { acquireLock(stateRoot: string, createLayout: boolean): NativeLock; processStartToken(): string };

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
    close() { receiver(this); held.close(); },
    inspectWorkspaceIdentity(workspacePath) {
      receiver(this);
      try { held.assertHeld(); } catch {
        throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner lock changed before workspace inspection');
      }
      if (normalizeAbsolutePath(workspacePath) !== workspacePath) {
        throw new TypeError('workspace path must be canonical');
      }
      let inspected: LiveWorkspaceInspection;
      try {
        inspected = held.inspectWorkspaceIdentity(workspacePath);
      } catch (error) {
        try { held.assertHeld(); } catch {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner lock changed during workspace inspection');
        }
        throw new KernelStorageError('INVALID_REQUEST', `workspace descriptor inspection failed: ${(error as Error).message}`);
      }
      try { held.assertHeld(); } catch {
        throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner lock changed during workspace inspection');
      }
      return inspected;
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
  return handle;
}

let loaded: { digest: string; implementation: NativeStateOwner; file: FileHandle } | undefined;

/** Load only the fixed host helper, through its verified held descriptor.
 * Bundle signature verification belongs to the trusted StateStore bootstrap. */
export async function loadNativeStateOwner(bundle?: RuntimeBundleManifest): Promise<NativeStateOwner> {
  if (process.platform !== 'darwin' && process.platform !== 'linux') {
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', `StateOwner is unsupported on ${process.platform}`);
  }
  const file = await open(STATE_OWNER_NATIVE_PATH, constants.O_RDONLY | constants.O_NOFOLLOW);
  let heldForProcess = false;
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.uid !== BigInt(process.geteuid!()) || before.nlink !== 1n ||
        (before.mode & 0o7777n) !== 0o500n || before.size <= 0n || before.size > 16n * 1024n * 1024n) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper must be an owner-only 0500 regular file of at most 16 MiB');
    }
    const bytes = await file.readFile();
    const after = await file.stat({ bigint: true });
    const digest = sha256Bytes(bytes);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
        before.uid !== after.uid || before.mode !== after.mode || before.nlink !== after.nlink ||
        before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs || BigInt(bytes.byteLength) !== after.size) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper changed while being read');
    }
    if (bundle) {
      const entry = bundle.entries.find((candidate) => candidate.entryId === STATE_OWNER_NATIVE_ENTRY_ID);
      if (!entry || entry.role !== 'platform_helper' || !entry.executable || entry.version !== '1' ||
          entry.relativePath !== STATE_OWNER_NATIVE_RELATIVE_PATH || entry.digest !== digest || entry.byteCount !== bytes.byteLength) {
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
    if (typeof binding.acquireLock !== 'function' || typeof binding.processStartToken !== 'function') {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper has an unsupported interface');
    }
    const implementation: NativeStateOwner = {
      acquireLock(stateRoot, createLayout) {
        if (normalizeAbsolutePath(stateRoot) !== stateRoot) throw new TypeError('StateOwner root must be canonical');
        const held = binding.acquireLock(stateRoot, createLayout);
        if (typeof held.inspectWorkspaceIdentity !== 'function') {
          held.close();
          throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper lacks descriptor-held workspace inspection');
        }
        try { return wrapLock(held, stateRoot); } catch (error) { held.close(); throw error; }
      },
      processStartToken: () => binding.processStartToken()
    };
    // Hold the fd used by dlopen for the mapped addon's lifetime. Reusing its
    // /proc/self/fd/N locator for another addon can alias the cached exports.
    loaded = { digest, implementation: Object.freeze(implementation), file };
    heldForProcess = true;
    return loaded.implementation;
  } finally {
    if (!heldForProcess) await file.close();
  }
}

export function assertStateOwnerLock(lock: HeldStateOwnerLock): void {
  try {
    lock.assertHeld();
  } catch {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner root/runtime/lock descriptor identity changed or closed');
  }
}
