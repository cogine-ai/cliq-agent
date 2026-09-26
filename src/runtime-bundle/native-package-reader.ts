import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { open, type FileHandle } from 'node:fs/promises';
import { Module } from 'node:module';
import path from 'node:path';

import { assertControlSocketPath } from '../control/socket-path.js';
import { assertArtifactRef, normalizeAbsolutePath, sha256Bytes } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ReleaseTrustKey, RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { KernelStorageError } from '../state/errors.js';
import { verifySignedRuntimeBundlePayloads } from './manifest.js';
import { runtimeNativePath } from './installed-paths.js';

export const PACKAGE_READER_NATIVE_RELATIVE_PATH = `native/${process.platform}-${process.arch}/package-reader.node`;
export const PACKAGE_READER_NATIVE_ENTRY_ID = 'runtime_bundle_package_reader';
const LOCAL_BINARY = runtimeNativePath(PACKAGE_READER_NATIVE_RELATIVE_PATH, import.meta.url);
const MAX_NATIVE_BYTES = 16 * 1024 * 1024;
const CHUNK_BYTES = 1024 * 1024;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const PACKAGE_MANIFEST_NAME = 'runtime-bundle.json';

type BundleEntry = RuntimeBundleManifest['entries'][number];
type PackageFile = Pick<BundleEntry, 'relativePath' | 'digest' | 'byteCount' | 'executable'>;
type NativeEntry = { readChunk(size: number): Buffer; assertStable(): void; close(): void };
type NativeStage = {
  writeChunk(chunk: Buffer): void;
  seal(): void;
  readChunk(size: number): Buffer;
  assertStable(): void;
  publish(): boolean;
  abort(): void;
};
type NativeCasArtifact = { readChunk(size: number): Buffer; assertStable(): void; close(): void };
export type HeldCasRoot = {
  beginStage(ref: string, byteCount: number, nonce: string): NativeStage;
  openArtifact(ref: string, byteCount: number): NativeCasArtifact;
  close(): void;
};
export type HeldPackageRoot = {
  openEntry(path: string, byteCount: number, executable: boolean, exactMode?: number): NativeEntry;
  manifestByteCount(): number;
  activeByteCount(): number;
  listEntries(): string[];
  close(): void;
};
export type HeldInitialSelectionWriter = {
  publishInitialActive(bytes: Buffer, nonce: string): void;
  close(): void;
};
export type HeldCandidateRoot = {
  copyEntry(source: HeldPackageRoot, path: string, byteCount: number, executable: boolean): void;
  seal(): void;
  publish(bundlesPath: string, bundleRef: string): void;
  close(): void;
};
export type NativePackageReader = {
  openRoot(path: string): HeldPackageRoot;
  openInstalledRoot(path: string): HeldPackageRoot;
  openRuntimeRoot(path: string): HeldPackageRoot;
  openInitialSelectionWriter(path: string): HeldInitialSelectionWriter;
  openCandidateRoot(path: string): HeldCandidateRoot;
  openCasRoot(path: string): HeldCasRoot;
};
type NativeBinding = NativePackageReader;

function sameStat(before: import('node:fs').BigIntStats, after: import('node:fs').BigIntStats): boolean {
  return before.dev === after.dev && before.ino === after.ino && before.uid === after.uid &&
    before.gid === after.gid && before.mode === after.mode && before.nlink === after.nlink &&
    before.size === after.size && before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs;
}

let loaded: { digest: string; binding: NativeBinding; file: FileHandle } | undefined;
const heldRoots = new WeakSet<object>();
const heldCasRoots = new WeakSet<object>();
const installedRoots = new WeakSet<object>();
const runtimeRoots = new WeakSet<object>();
const candidateRoots = new WeakMap<object, { path: string; verifiedRef?: string }>();

/** The expected helper digest must come from the trusted stable bootstrap. Test builds inject a fixture digest. */
export async function loadNativePackageReader(expectedHelperDigest: string,
  expectedByteCount?: number): Promise<NativeBinding> {
  assertArtifactRef(expectedHelperDigest);
  if (expectedByteCount !== undefined && (!Number.isSafeInteger(expectedByteCount) || expectedByteCount <= 0)) {
    throw new TypeError('native package reader signed byte count is invalid');
  }
  if (process.platform !== 'darwin' && process.platform !== 'linux') {
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'native RuntimeBundle package reading is unavailable');
  }
  const file = await open(LOCAL_BINARY, constants.O_RDONLY | constants.O_NOFOLLOW);
  let heldForProcess = false;
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.uid !== BigInt(process.geteuid!()) || before.nlink !== 1n ||
        (before.mode & 0o7777n) !== 0o500n || before.size <= 0n || before.size > BigInt(MAX_NATIVE_BYTES)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'native package reader must be a private 0500 regular file');
    }
    const bytes = await file.readFile();
    const after = await file.stat({ bigint: true });
    const digest = sha256Bytes(bytes);
    if (!sameStat(before, after) || BigInt(bytes.byteLength) !== after.size || digest !== expectedHelperDigest ||
        (expectedByteCount !== undefined && after.size !== BigInt(expectedByteCount))) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'native package reader differs from its trusted bootstrap pin');
    }
    if (loaded) {
      if (loaded.digest !== digest) throw new KernelStorageError('ARTIFACT_MISMATCH', 'native package reader changed in process');
      return loaded.binding;
    }
    const nativeModule = new Module(LOCAL_BINARY);
    process.dlopen(nativeModule, `${process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd'}/${file.fd}`);
    const binding = nativeModule.exports as NativeBinding;
    if (typeof binding.openRoot !== 'function' || typeof binding.openInstalledRoot !== 'function' ||
        typeof binding.openRuntimeRoot !== 'function' ||
        typeof binding.openInitialSelectionWriter !== 'function' ||
        typeof binding.openCandidateRoot !== 'function' ||
        typeof binding.openCasRoot !== 'function') {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'native package reader has an unsupported interface');
    }
    // Linux dlopen can cache /proc/self/fd/N by pathname. Reusing N for a
    // different addon would return the first addon's exports. Keep this verified
    // descriptor alive while its native code is mapped into the process.
    loaded = { digest, binding: Object.freeze(binding), file };
    heldForProcess = true;
    return loaded.binding;
  } finally {
    if (!heldForProcess) await file.close();
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

export function openInstalledBundleRoot(binding: NativeBinding, absolutePath: string): HeldPackageRoot {
  if (binding !== loaded?.binding) throw new TypeError('installed bundle reader must come from the pinned native helper');
  if (normalizeAbsolutePath(absolutePath) !== absolutePath) {
    throw new TypeError('installed bundle root must have a canonical absolute path');
  }
  const root = binding.openInstalledRoot(absolutePath);
  heldRoots.add(root);
  installedRoots.add(root);
  return root;
}

export function openRuntimeSelectionRoot(binding: NativeBinding, absolutePath: string): HeldPackageRoot {
  if (binding !== loaded?.binding) throw new TypeError('runtime selection reader must come from the pinned native helper');
  if (normalizeAbsolutePath(absolutePath) !== absolutePath) {
    throw new TypeError('runtime selection root must have a canonical absolute path');
  }
  const root = binding.openRuntimeRoot(absolutePath);
  runtimeRoots.add(root);
  return root;
}

/** A distinct native capability for the first-install filesystem cut. */
export function openInitialSelectionWriter(binding: NativeBinding, absolutePath: string): HeldInitialSelectionWriter {
  if (binding !== loaded?.binding) throw new TypeError('selection writer must come from the pinned native helper');
  if (normalizeAbsolutePath(absolutePath) !== absolutePath) {
    throw new TypeError('runtime selection directory must have a canonical absolute path');
  }
  return binding.openInitialSelectionWriter(absolutePath);
}

/** Open a fresh empty 0700 stage. The installer must place it outside StateRoot. */
export function openCandidateStageRoot(binding: NativeBinding, absolutePath: string): HeldCandidateRoot {
  if (binding !== loaded?.binding) throw new TypeError('candidate stage must come from the pinned native helper');
  if (normalizeAbsolutePath(absolutePath) !== absolutePath) {
    throw new TypeError('candidate stage must have a canonical absolute path');
  }
  const candidate = binding.openCandidateRoot(absolutePath);
  candidateRoots.set(candidate, { path: absolutePath });
  return candidate;
}

export function readHeldActiveSelection(root: HeldPackageRoot): Buffer {
  if (!runtimeRoots.has(root)) throw new TypeError('active selection root must come from the pinned native helper');
  const byteCount = root.activeByteCount();
  if (!Number.isSafeInteger(byteCount) || byteCount <= 0 || byteCount > 4096) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'active selection byte count is invalid');
  }
  const file = root.openEntry('active.json', byteCount, false, 0o400);
  try {
    const chunks: Buffer[] = [];
    let remaining = byteCount;
    while (remaining > 0) {
      const bytes = file.readChunk(remaining);
      if (!Buffer.isBuffer(bytes) || bytes.byteLength === 0 || bytes.byteLength > remaining) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'active runtime selection has invalid bytes');
      }
      chunks.push(Buffer.from(bytes));
      remaining -= bytes.byteLength;
    }
    if (file.readChunk(1).byteLength !== 0) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'active runtime selection has invalid bytes');
    }
    file.assertStable();
    return Buffer.concat(chunks, byteCount);
  } finally { file.close(); }
}

export function openNativeCasRoot(binding: NativeBinding, absolutePath: string): HeldCasRoot {
  if (binding !== loaded?.binding) throw new TypeError('CAS writer must come from the pinned native helper');
  if (normalizeAbsolutePath(absolutePath) !== absolutePath) {
    throw new TypeError('CAS root must have a canonical absolute path');
  }
  const root = binding.openCasRoot(absolutePath);
  heldCasRoots.add(root);
  return root;
}

/** Stream a signed entry from held descriptors. The consumer must stage bytes until this returns. */
export async function streamVerifiedPackageEntry(root: HeldPackageRoot, entry: Readonly<PackageFile>,
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

/** Verify the complete read-only installed tree, including absence of unsigned files. */
export async function verifyHeldInstalledBundle(root: HeldPackageRoot,
  releaseKeys: readonly ReleaseTrustKey[], expectedBundleRef: string): Promise<{
    bundle: RuntimeBundleManifest; bundleRef: string;
  }> {
  if (!installedRoots.has(root)) throw new TypeError('installed bundle root must come from the pinned native helper');
  assertArtifactRef(expectedBundleRef);
  const before = root.listEntries().sort();
  const decoded = await verifyHeldPackage(root, releaseKeys);
  if (decoded.bundleRef !== expectedBundleRef) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed bundle directory differs from its selected digest');
  }
  const expectedFiles = ['runtime-bundle.json', ...decoded.bundle.entries.map((entry) => entry.relativePath)];
  const expectedDirs = new Set<string>();
  for (const entry of expectedFiles) {
    const components = entry.split('/');
    for (let index = 1; index < components.length; index += 1) {
      expectedDirs.add(`${components.slice(0, index).join('/')}/`);
    }
  }
  const expected = [...expectedFiles, ...expectedDirs].sort();
  if (before.length !== expected.length || before.some((entry, index) => entry !== expected[index])) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed bundle contains missing or unsigned paths');
  }
  const after = root.listEntries().sort();
  if (after.length !== expected.length || after.some((entry, index) => entry !== expected[index])) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed bundle inventory changed during verification');
  }
  return decoded;
}

/** Copy a fully signed package into a private candidate and independently verify the sealed tree. */
export async function stageHeldPackageCandidate(source: HeldPackageRoot, candidate: HeldCandidateRoot,
  releaseKeys: readonly ReleaseTrustKey[]): Promise<{ bundle: RuntimeBundleManifest; bundleRef: string }> {
  const trustedKeys = immutableSnapshot(releaseKeys);
  const stage = candidateRoots.get(candidate);
  if (!heldRoots.has(source) || stage === undefined) {
    throw new TypeError('source and candidate must come from the pinned native helper');
  }
  const manifest = readHeldPackageManifest(source);
  const decoded = await verifyHeldPackage(source, trustedKeys);
  candidate.copyEntry(source, PACKAGE_MANIFEST_NAME, manifest.byteLength, false);
  for (const entry of decoded.bundle.entries) {
    candidate.copyEntry(source, entry.relativePath, entry.byteCount, entry.executable);
  }
  candidate.seal();
  const installed = openInstalledBundleRoot(loaded!.binding, stage.path);
  try {
    const verified = await verifyHeldInstalledBundle(installed, trustedKeys, decoded.bundleRef);
    stage.verifiedRef = verified.bundleRef;
    return verified;
  } finally { installed.close(); }
}

/** Publish an independently reverified candidate as an unselected digest-named bundle. */
export async function publishHeldPackageCandidate(candidate: HeldCandidateRoot, stateRoot: string,
  releaseKeys: readonly ReleaseTrustKey[]): Promise<{
    bundle: RuntimeBundleManifest; bundleRef: string; bundlePath: string;
  }> {
  const trustedKeys = immutableSnapshot(releaseKeys);
  const stage = candidateRoots.get(candidate);
  if (stage?.verifiedRef === undefined) throw new TypeError('candidate has not passed signed staging verification');
  if (normalizeAbsolutePath(stateRoot) !== stateRoot) throw new TypeError('StateRoot path must be canonical');
  assertControlSocketPath(stateRoot);
  const source = openInstalledBundleRoot(loaded!.binding, stage.path);
  try {
    await verifyHeldInstalledBundle(source, trustedKeys, stage.verifiedRef);
  } finally { source.close(); }
  const bundlesPath = path.join(stateRoot, 'runtime', 'bundles');
  const bundlePath = path.join(bundlesPath, stage.verifiedRef);
  candidate.publish(bundlesPath, stage.verifiedRef);
  const published = openInstalledBundleRoot(loaded!.binding, bundlePath);
  try {
    const verified = await verifyHeldInstalledBundle(published, trustedKeys, stage.verifiedRef);
    return { ...verified, bundlePath };
  } finally { published.close(); }
}

function rehashNativeReader(reader: NativeCasArtifact | NativeStage, byteCount: number): string {
  const hash = createHash('sha256');
  let remaining = byteCount;
  while (remaining > 0) {
    const bytes = reader.readChunk(Math.min(CHUNK_BYTES, remaining));
    if (!Buffer.isBuffer(bytes) || bytes.byteLength === 0 || bytes.byteLength > remaining) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'CAS artifact ended before its signed byte count');
    }
    hash.update(bytes);
    remaining -= bytes.byteLength;
  }
  if (reader.readChunk(1).byteLength !== 0) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'CAS artifact has trailing bytes');
  }
  reader.assertStable();
  return hash.digest('hex');
}

/** Recheck the published object through a held CAS descriptor, including an existing object. */
export function verifyNativeCasArtifact(cas: HeldCasRoot, entry: Readonly<PackageFile>): void {
  if (!heldCasRoots.has(cas)) throw new TypeError('CAS root must come from the pinned native helper');
  assertArtifactRef(entry.digest);
  if (!Number.isSafeInteger(entry.byteCount) || entry.byteCount < 0) throw new TypeError('invalid CAS entry');
  const artifact = cas.openArtifact(entry.digest, entry.byteCount);
  try {
    if (rehashNativeReader(artifact, entry.byteCount) !== entry.digest) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'CAS artifact differs from its signed digest');
    }
  } finally {
    artifact.close();
  }
}

/** Copy a signed source entry into CAS; no installer authority is published by this operation. */
export async function importVerifiedPackageEntryToCas(source: HeldPackageRoot, cas: HeldCasRoot,
  entry: Readonly<PackageFile>): Promise<void> {
  if (!heldCasRoots.has(cas)) throw new TypeError('CAS root must come from the pinned native helper');
  assertArtifactRef(entry.digest);
  if (!Number.isSafeInteger(entry.byteCount) || entry.byteCount < 0) throw new TypeError('invalid CAS entry');
  const stage = cas.beginStage(entry.digest, entry.byteCount, randomBytes(16).toString('hex'));
  let primaryError: unknown;
  try {
    await streamVerifiedPackageEntry(source, entry, (chunk) => { stage.writeChunk(chunk); });
    stage.seal();
    if (rehashNativeReader(stage, entry.byteCount) !== entry.digest) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'CAS stage differs from its signed digest');
    }
    stage.publish();
    verifyNativeCasArtifact(cas, entry);
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try {
      stage.abort();
    } catch (cleanupError) {
      if (primaryError !== undefined) {
        throw new AggregateError([primaryError, cleanupError], 'CAS import and stage cleanup both failed');
      }
      throw cleanupError;
    }
  }
}

/** Materialize only bounded structured objects; large images stay on the streaming path. */
export function readVerifiedNativeCasArtifactBytes(cas: HeldCasRoot,
  entry: Readonly<PackageFile>): Buffer {
  if (!heldCasRoots.has(cas)) throw new TypeError('CAS root must come from the pinned native helper');
  assertArtifactRef(entry.digest);
  if (!Number.isSafeInteger(entry.byteCount) || entry.byteCount < 0 || entry.byteCount > 16_777_216) {
    throw new TypeError('structured CAS artifact exceeds its byte limit');
  }
  const artifact = cas.openArtifact(entry.digest, entry.byteCount);
  try {
    const hash = createHash('sha256');
    const chunks: Buffer[] = [];
    let remaining = entry.byteCount;
    while (remaining > 0) {
      const bytes = artifact.readChunk(Math.min(CHUNK_BYTES, remaining));
      if (!Buffer.isBuffer(bytes) || bytes.byteLength === 0 || bytes.byteLength > remaining) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'CAS artifact ended before its signed byte count');
      }
      hash.update(bytes);
      chunks.push(Buffer.from(bytes));
      remaining -= bytes.byteLength;
    }
    if (artifact.readChunk(1).byteLength !== 0) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'CAS artifact has trailing bytes');
    }
    artifact.assertStable();
    if (hash.digest('hex') !== entry.digest) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'CAS artifact differs from its signed digest');
    }
    return Buffer.concat(chunks, entry.byteCount);
  } finally {
    artifact.close();
  }
}

/** Import a complete verified package into unselected CAS objects. Activation is a separate gate. */
export async function importHeldPackageToCas(source: HeldPackageRoot, cas: HeldCasRoot,
  releaseKeys: readonly ReleaseTrustKey[], expectedBundleRef?: string): Promise<{
    bundle: RuntimeBundleManifest; bundleRef: string;
  }> {
  if (expectedBundleRef !== undefined) assertArtifactRef(expectedBundleRef);
  const manifest = readHeldPackageManifest(source);
  const decoded = await verifySignedRuntimeBundlePayloads(manifest, releaseKeys,
    (entry) => readVerifiedPackageEntryBytes(source, entry));
  if (expectedBundleRef !== undefined && decoded.bundleRef !== expectedBundleRef) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'package manifest differs from the active signed StateOwner bundle');
  }
  for (const entry of decoded.bundle.entries) {
    await streamVerifiedPackageEntry(source, entry, () => {});
  }
  const manifestFile: PackageFile = {
    relativePath: PACKAGE_MANIFEST_NAME,
    digest: decoded.bundleRef,
    byteCount: manifest.byteLength,
    executable: false
  };
  await importVerifiedPackageEntryToCas(source, cas, manifestFile);
  for (const entry of decoded.bundle.entries) {
    await importVerifiedPackageEntryToCas(source, cas, entry);
  }
  await verifySignedRuntimeBundlePayloads(readVerifiedNativeCasArtifactBytes(cas, manifestFile), releaseKeys,
    async (entry) => readVerifiedNativeCasArtifactBytes(cas, entry));
  return decoded;
}
