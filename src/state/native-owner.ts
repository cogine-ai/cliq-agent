import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { Module } from 'node:module';
import { fileURLToPath } from 'node:url';

import { sha256Bytes } from '../kernel/identity.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { KernelStorageError } from './errors.js';

export const STATE_OWNER_NATIVE_ENTRY_ID = 'state_owner_native';
export const STATE_OWNER_NATIVE_RELATIVE_PATH = `native/${process.platform}-${process.arch}/state-owner.node`;
export const STATE_OWNER_NATIVE_PATH = fileURLToPath(new URL(`../../dist/${STATE_OWNER_NATIVE_RELATIVE_PATH}`, import.meta.url));

type DescriptorIdentity = Readonly<{ deviceId: string; fileId: string; ownerUid: number }>;
export type HeldStateOwnerLock = Readonly<{
  root: DescriptorIdentity;
  runtime: DescriptorIdentity;
  lock: DescriptorIdentity;
  assertHeld(): void;
  close(): void;
}>;

export type NativeStateOwner = Readonly<{
  acquireLock(stateRoot: string, createLayout: boolean): HeldStateOwnerLock;
  processStartToken(): string;
}>;

let loaded: { digest: string; implementation: NativeStateOwner } | undefined;

/** Load only the fixed host helper, through its verified held descriptor.
 * Bundle signature verification belongs to the trusted StateStore bootstrap. */
export async function loadNativeStateOwner(bundle?: RuntimeBundleManifest): Promise<NativeStateOwner> {
  if (process.platform !== 'darwin' && process.platform !== 'linux') {
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', `StateOwner is unsupported on ${process.platform}`);
  }
  const file = await open(STATE_OWNER_NATIVE_PATH, constants.O_RDONLY | constants.O_NOFOLLOW);
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
    const implementation: NativeStateOwner = nativeModule.exports;
    if (typeof implementation.acquireLock !== 'function' || typeof implementation.processStartToken !== 'function') {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper has an unsupported interface');
    }
    loaded = { digest, implementation: Object.freeze(implementation) };
    return loaded.implementation;
  } finally {
    await file.close();
  }
}

export function assertStateOwnerLock(lock: HeldStateOwnerLock): void {
  try {
    lock.assertHeld();
  } catch {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner root/runtime/lock descriptor identity changed or closed');
  }
}
