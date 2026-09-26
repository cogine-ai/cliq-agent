import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { Module } from 'node:module';
import { fileURLToPath } from 'node:url';

import { assertArtifactRef, normalizeAbsolutePath, sha256Bytes } from '../kernel/identity.js';
import type { ReleaseTrustKey, RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { KernelStorageError } from '../state/errors.js';
import { verifySignedRuntimeBundlePayloads } from './manifest.js';

export const PACKAGE_READER_NATIVE_RELATIVE_PATH = `native/${process.platform}-${process.arch}/package-reader.node`;
const LOCAL_BINARY = fileURLToPath(new URL(`../../dist/${PACKAGE_READER_NATIVE_RELATIVE_PATH}`, import.meta.url));
const MAX_NATIVE_BYTES = 16 * 1024 * 1024;
const CHUNK_BYTES = 1024 * 1024;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const PACKAGE_MANIFEST_NAME = 'runtime-bundle.json';

type BundleEntry = RuntimeBundleManifest['entries'][number];
type NativeEntry = { readChunk(size: number): Buffer; assertStable(): void; close(): void };
export type HeldPackageRoot = {
  openEntry(path: string, byteCount: number, executable: boolean): NativeEntry;
  manifestByteCount(): number;
  close(): void;
};
type NativeBinding = { openRoot(path: string): HeldPackageRoot };

function sameStat(before: import('node:fs').BigIntStats, after: import('node:fs').BigIntStats): boolean {
  return before.dev === after.dev && before.ino === after.ino && before.uid === after.uid &&
    before.gid === after.gid && before.mode === after.mode && before.nlink === after.nlink &&
    before.size === after.size && before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs;
}

let loaded: { digest: string; binding: NativeBinding } | undefined;
const heldRoots = new WeakSet<object>();

/** The expected helper digest must come from the trusted stable bootstrap. Test builds inject a fixture digest. */
export async function loadNativePackageReader(expectedHelperDigest: string): Promise<NativeBinding> {
  assertArtifactRef(expectedHelperDigest);
  if (process.platform !== 'darwin' && process.platform !== 'linux') {
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'native RuntimeBundle package reading is unavailable');
  }
  const file = await open(LOCAL_BINARY, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.uid !== BigInt(process.geteuid!()) || before.nlink !== 1n ||
        (before.mode & 0o7777n) !== 0o500n || before.size <= 0n || before.size > BigInt(MAX_NATIVE_BYTES)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'native package reader must be a private 0500 regular file');
    }
    const bytes = await file.readFile();
    const after = await file.stat({ bigint: true });
    const digest = sha256Bytes(bytes);
    if (!sameStat(before, after) || BigInt(bytes.byteLength) !== after.size || digest !== expectedHelperDigest) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'native package reader differs from its trusted bootstrap pin');
    }
    if (loaded) {
      if (loaded.digest !== digest) throw new KernelStorageError('ARTIFACT_MISMATCH', 'native package reader changed in process');
      return loaded.binding;
    }
    const nativeModule = new Module(LOCAL_BINARY);
    process.dlopen(nativeModule, `${process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd'}/${file.fd}`);
    const binding = nativeModule.exports as NativeBinding;
    if (typeof binding.openRoot !== 'function') {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'native package reader has an unsupported interface');
    }
    loaded = { digest, binding: Object.freeze(binding) };
    return loaded.binding;
  } finally {
    await file.close();
  }
}

export function openPackageRoot(binding: NativeBinding, absolutePath: string): HeldPackageRoot {
  if (binding !== loaded?.binding) throw new TypeError('package reader must come from the pinned native helper');
  if (normalizeAbsolutePath(absolutePath) !== absolutePath) {
    throw new TypeError('package root must have a canonical absolute path');
  }
  const root = binding.openRoot(absolutePath);
  heldRoots.add(root);
  return root;
}

/** Stream a signed entry from held descriptors. The consumer must stage bytes until this returns. */
export async function streamVerifiedPackageEntry(root: HeldPackageRoot, entry: Readonly<BundleEntry>,
  consume: (chunk: Buffer) => Promise<void> | void): Promise<void> {
  if (!heldRoots.has(root)) throw new TypeError('package root must come from the pinned native helper');
  assertArtifactRef(entry.digest);
  if (!Number.isSafeInteger(entry.byteCount) || entry.byteCount < 0 ||
      typeof entry.relativePath !== 'string' || typeof entry.executable !== 'boolean') {
    throw new TypeError('invalid signed package entry');
  }
  const file = root.openEntry(entry.relativePath, entry.byteCount, entry.executable);
  try {
    const hash = createHash('sha256');
    let remaining = entry.byteCount;
    while (remaining > 0) {
      const bytes = file.readChunk(Math.min(CHUNK_BYTES, remaining));
      if (!Buffer.isBuffer(bytes) || bytes.byteLength === 0 || bytes.byteLength > remaining) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'signed package entry ended before its byte count');
      }
      hash.update(bytes);
      remaining -= bytes.byteLength;
      await consume(Buffer.from(bytes));
    }
    if (file.readChunk(1).byteLength !== 0) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'signed package entry has trailing bytes');
    }
    file.assertStable();
    if (hash.digest('hex') !== entry.digest) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'signed package entry has a different complete-file digest');
    }
  } finally {
    file.close();
  }
}

/** Structured roots/members are bounded; larger guest images use the streaming form. */
export async function readVerifiedPackageEntryBytes(root: HeldPackageRoot,
  entry: Readonly<BundleEntry>): Promise<Buffer> {
  if (entry.byteCount > 16_777_216) throw new TypeError('structured package entry exceeds its byte limit');
  const chunks: Buffer[] = [];
  await streamVerifiedPackageEntry(root, entry, (chunk) => { chunks.push(chunk); });
  return Buffer.concat(chunks, entry.byteCount);
}

/** Read the fixed manifest through a held descriptor before selecting signed entry paths. */
export function readHeldPackageManifest(root: HeldPackageRoot): Buffer {
  if (!heldRoots.has(root)) throw new TypeError('package root must come from the pinned native helper');
  const byteCount = root.manifestByteCount();
  if (!Number.isSafeInteger(byteCount) || byteCount <= 0 || byteCount > MAX_MANIFEST_BYTES) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'fixed package manifest byte count is invalid');
  }
  const file = root.openEntry(PACKAGE_MANIFEST_NAME, byteCount, false);
  try {
    const chunks: Buffer[] = [];
    let remaining = byteCount;
    while (remaining > 0) {
      const bytes = file.readChunk(Math.min(CHUNK_BYTES, remaining));
      if (!Buffer.isBuffer(bytes) || bytes.byteLength === 0 || bytes.byteLength > remaining) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'fixed package manifest ended before its byte count');
      }
      chunks.push(Buffer.from(bytes));
      remaining -= bytes.byteLength;
    }
    if (file.readChunk(1).byteLength !== 0) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'fixed package manifest has trailing bytes');
    }
    file.assertStable();
    return Buffer.concat(chunks, byteCount);
  } finally {
    file.close();
  }
}

/** Preflight every signed package byte. Installation must independently copy and verify staged bytes. */
export async function verifyHeldPackage(root: HeldPackageRoot,
  releaseKeys: readonly ReleaseTrustKey[]): Promise<{ bundle: RuntimeBundleManifest; bundleRef: string }> {
  const manifest = readHeldPackageManifest(root);
  const decoded = await verifySignedRuntimeBundlePayloads(manifest, releaseKeys,
    (entry) => readVerifiedPackageEntryBytes(root, entry));
  for (const entry of decoded.bundle.entries) {
    await streamVerifiedPackageEntry(root, entry, () => {});
  }
  return decoded;
}
