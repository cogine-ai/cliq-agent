import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { lstat, mkdir, open, readdir, rename, type FileHandle } from 'node:fs/promises';
import { isMainThread } from 'node:worker_threads';

import { KERNEL_CAS_DIRECTORY } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, normalizeAbsolutePath, sha256Bytes } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, policyProfile, verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { ContentAddressedStore } from './cas.js';
import { joinResourceOperations, KernelStorageError, ResourceRetirementError } from './errors.js';
import { decodeSandboxRootProfile } from './execution-closure.js';
import { executeHeldInstalledImage, initializeHeldInstalledKeeper, loadHeldStateOwnerImage, STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_RELATIVE_PATH,
  type NativeStateOwner } from './native-owner.js';

export type HeldInstalledRuntime = Readonly<{
  bundle: RuntimeBundleManifest;
  bundleDigest: string;
  assertHeld(): Promise<void>;
  close(): Promise<void>;
}>;
/** A continuously held original containment anchor, not execution authority or
 * a transferable descriptor/PID locator. */
export type HeldInstalledKeeper = Readonly<{ assertHeld(): void; close(): void }>;

type InstalledDirectoryIdentity = Readonly<{ deviceId: string; fileId: string; ownerUid: number }>;
/** Trusted startup observation only. No descriptor or independently supplied
 * installation evidence can outlive the callback's held borrow. */
export type InstalledRuntimeBorrow = Readonly<{
  bundle: RuntimeBundleManifest;
  bundleDigest: string;
  stateRoot: InstalledDirectoryIdentity & Readonly<{ canonicalPath: string }>;
  casRoot: InstalledDirectoryIdentity;
  seed: readonly Readonly<{ artifactRef: string; byteCount: number; mediaType: string; schemaKind: string }>[];
  revalidate(): Promise<void>;
  loadStateOwner(): Promise<NativeStateOwner>;
}>;
type InstalledRuntimeBinding = {
  factory: InstalledRuntime;
  borrow<T>(operation: (installed: InstalledRuntimeBorrow) => Promise<T>): Promise<T>;
  execute(role: 'keeper' | 'supervisor'): Promise<never>;
  initializeKeeper(): Promise<HeldInstalledKeeper>;
};
const heldInstalledRuntimes = new WeakMap<HeldInstalledRuntime, InstalledRuntimeBinding>();

export function initializeInstalledKeeper(held: HeldInstalledRuntime): Promise<HeldInstalledKeeper> {
  const binding = heldInstalledRuntimes.get(held);
  if (binding === undefined) mismatch('installed runtime is not a verified held selection');
  return binding.initializeKeeper();
}

/** Look up the producer's private brand before observing any caller property.
 * Structural objects, proxies and clones cannot impersonate a held selection. */
export function withHeldInstalledRuntime<T>(held: HeldInstalledRuntime,
  operation: (installed: InstalledRuntimeBorrow) => Promise<T>): Promise<T> {
  const binding = heldInstalledRuntimes.get(held);
  if (binding === undefined) mismatch('installed runtime is not a verified held selection');
  return binding.borrow(operation);
}

type InstalledRuntime = Readonly<{
  installInitial(target: { packageRoot: string; stateRoot: string }): Promise<{ bundleDigest: string; manifestDigest: string }>;
  openSelected(stateRoot: string): Promise<HeldInstalledRuntime>;
  /** Bootstrap-only terminal operation. No StateOwner/control/worker may have
   * been acquired; the signed entry point enforces this fixed startup order. */
  executeSelected(held: HeldInstalledRuntime, role: 'keeper' | 'supervisor'): Promise<never>;
}>;
type Directory = { handle: FileHandle; info: BigIntStats; parent?: Directory; name: string; private: boolean };
type InstalledFile = { handle: FileHandle; info: BigIntStats; parent: Directory; name: string; digest?: string };
type VerifiedPackage = { root: Directory; manifest: InstalledFile; bundle: RuntimeBundleManifest;
  bundleDigest: string; manifestBytes: Buffer; entries: Map<string, InstalledFile>; roots: Map<string, Buffer> };

const SMALL_BYTES = 1_048_576;
const TRUST_BYTES = 16 * SMALL_BYTES;
const CHUNK_BYTES = 64 * 1024;
// Descriptor retirement is process authority, not the lifetime of a factory or
// selected handle. A fresh factory must not erase an uncertain close.
let retirementFailure: ResourceRetirementError | undefined;

function mismatch(message: string, cause?: unknown): never {
  throw new KernelStorageError('ARTIFACT_MISMATCH', message, cause === undefined ? undefined : { cause });
}
function healthy(): void { if (retirementFailure) throw retirementFailure; }
function supportedPlatform(): void {
  if (process.platform !== 'linux') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed runtime requires Linux descriptor-relative filesystem operations');
}
function rememberRetirement(error: unknown): void {
  if (error instanceof ResourceRetirementError) retirementFailure ??= error;
}
function effectiveUid(): bigint {
  if (typeof process.geteuid !== 'function') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed runtime requires effective-user identity');
  return BigInt(process.geteuid());
}
function childPath(directory: Directory, name: string): string {
  supportedPlatform();
  return `/proc/self/fd/${directory.handle.fd}/${name}`;
}
function sameDirectory(left: BigIntStats, right: BigIntStats): boolean {
  return ['dev', 'ino', 'uid', 'gid', 'mode'].every(key => left[key as keyof BigIntStats] === right[key as keyof BigIntStats]);
}
function sameFile(left: BigIntStats, right: BigIntStats): boolean {
  return ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs']
    .every(key => left[key as keyof BigIntStats] === right[key as keyof BigIntStats]);
}
function checkDirectory(info: BigIntStats, privateRoot: boolean): void {
  if (!info.isDirectory() || (privateRoot ? info.uid !== effectiveUid() || (info.mode & 0o7777n) !== 0o700n :
    info.uid !== 0n && info.uid !== effectiveUid())) mismatch('installed runtime directory ownership, type or mode is invalid');
}
function checkFile(info: BigIntStats, mode: number, byteCount?: number): void {
  if (!info.isFile() || info.uid !== effectiveUid() || info.nlink !== 1n || (info.mode & 0o7777n) !== BigInt(mode) ||
      info.size > BigInt(Number.MAX_SAFE_INTEGER) || (byteCount !== undefined && info.size !== BigInt(byteCount))) {
    mismatch('installed runtime file ownership, type, link count, size or mode is invalid');
  }
}

/** Own every opened descriptor immediately. Ownership is consumed before close,
 * including failed closes; a reused numeric fd is never retried. */
class Scope {
  readonly directories: Directory[] = [];
  private readonly handles = new Set<FileHandle>();
  private closePromise?: Promise<void>;

  own(handle: FileHandle): FileHandle { this.handles.add(handle); return handle; }
  take(handle: FileHandle): FileHandle {
    if (this.closePromise || !this.handles.delete(handle)) mismatch('installed execution image is not owned by its live scope');
    return handle;
  }
  async retire(handle: FileHandle): Promise<void> {
    if (!this.handles.delete(handle)) return;
    try { await handle.close(); }
    catch (cause) {
      const error = new ResourceRetirementError('installed runtime descriptor retirement failed', cause);
      rememberRetirement(error); throw error;
    }
  }
  close(): Promise<void> {
    return this.closePromise ??= (async () => {
      const handles = [...this.handles].reverse();
      const results = await Promise.allSettled(handles.map(handle => this.retire(handle)));
      const failures = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected');
      if (failures.length) throw retirementFailure ?? new ResourceRetirementError('installed runtime retirement did not join', failures.map(result => result.reason));
    })();
  }
  async assertDirectory(directory: Directory): Promise<void> {
    const held = await directory.handle.stat({ bigint: true });
    const named = await lstat(directory.parent ? childPath(directory.parent, directory.name) : '/', { bigint: true });
    checkDirectory(held, directory.private); checkDirectory(named, directory.private);
    if (!sameDirectory(directory.info, held) || !sameDirectory(held, named)) mismatch('installed runtime directory changed');
  }
  async assertDirectories(): Promise<void> {
    healthy();
    for (const directory of this.directories) await this.assertDirectory(directory);
  }
  async directory(parent: Directory, name: string, create = false): Promise<Directory> {
    await this.assertDirectory(parent);
    const known = this.directories.find(directory => directory.parent === parent && directory.name === name);
    if (known) { await this.assertDirectory(known); return known; }
    const filename = childPath(parent, name);
    if (create) await mkdir(filename, { mode: 0o700 });
    const named = await lstat(filename, { bigint: true });
    checkDirectory(named, true);
    const handle = this.own(await open(filename, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW));
    const info = await handle.stat({ bigint: true });
    checkDirectory(info, true);
    if (!sameDirectory(named, info)) mismatch('installed runtime directory changed while opening');
    const directory = { handle, info, parent, name, private: true };
    this.directories.push(directory);
    await this.assertDirectory(parent);
    return directory;
  }
  async root(filename: string, create = false): Promise<Directory> {
    const normalized = normalizeAbsolutePath(filename);
    if (normalized !== filename) mismatch('installed runtime root must be a canonical absolute path');
    const handle = this.own(await open('/', constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW));
    let directory: Directory = { handle, info: await handle.stat({ bigint: true }), name: '/', private: false };
    checkDirectory(directory.info, false); this.directories.push(directory);
    const components = filename.split('/').slice(1);
    for (let index = 0; index < components.length; index++) {
      const name = components[index]!;
      await this.assertDirectory(directory);
      const filename = childPath(directory, name);
      const last = index === components.length - 1;
      if (last && create) await mkdir(filename, { mode: 0o700 });
      const named = await lstat(filename, { bigint: true });
      checkDirectory(named, last);
      const handle = this.own(await open(filename, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW));
      const info = await handle.stat({ bigint: true }); checkDirectory(info, last);
      if (!sameDirectory(named, info)) mismatch('installed runtime root component changed while opening');
      const next: Directory = { handle, info, parent: directory, name, private: last };
      this.directories.push(next); directory = next;
    }
    await this.assertDirectories();
    return directory;
  }
  async parent(root: Directory, relative: string, create = false): Promise<{ parent: Directory; name: string }> {
    const components = relative.split('/');
    let parent = root;
    for (const component of components.slice(0, -1)) {
      const known = this.directories.find(directory => directory.parent === parent && directory.name === component);
      parent = known ? known : await this.directory(parent, component, create);
    }
    return { parent, name: components.at(-1)! };
  }
  async file(root: Directory, relative: string, mode: number, byteCount?: number, digest?: string): Promise<InstalledFile> {
    const { parent, name } = await this.parent(root, relative);
    await this.assertDirectory(parent);
    const filename = childPath(parent, name);
    const named = await lstat(filename, { bigint: true }); checkFile(named, mode, byteCount);
    const handle = this.own(await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK));
    const info = await handle.stat({ bigint: true }); checkFile(info, mode, byteCount);
    if (!sameFile(named, info)) mismatch('installed runtime file changed while opening');
    const file = { handle, info, parent, name, digest };
    await assertFile(file); await this.assertDirectory(parent);
    return file;
  }
}

async function assertFile(file: InstalledFile): Promise<void> {
  healthy();
  const held = await file.handle.stat({ bigint: true });
  const named = await lstat(childPath(file.parent, file.name), { bigint: true });
  if (!sameFile(file.info, held) || !sameFile(held, named)) mismatch('installed runtime held file or its independent path changed');
}
async function* chunks(file: InstalledFile): AsyncGenerator<Buffer> {
  await assertFile(file);
  const hash = createHash('sha256');
  const count = Number(file.info.size);
  let position = 0;
  while (position < count) {
    const buffer = Buffer.allocUnsafe(Math.min(CHUNK_BYTES, count - position));
    const { bytesRead } = await file.handle.read(buffer, 0, buffer.length, position);
    if (!bytesRead) mismatch('installed runtime file ended before its signed byte count');
    const bytes = buffer.subarray(0, bytesRead); hash.update(bytes); position += bytesRead;
    yield bytes;
  }
  const extra = await file.handle.read(Buffer.allocUnsafe(1), 0, 1, position);
  if (extra.bytesRead) mismatch('installed runtime file exceeds its signed byte count');
  await assertFile(file);
  if (file.digest !== undefined && hash.digest('hex') !== file.digest) mismatch('installed runtime signed file digest differs');
}
async function readSmall(file: InstalledFile, limit = SMALL_BYTES): Promise<Buffer> {
  if (file.info.size > BigInt(limit)) mismatch('installed runtime data exceeds its bounded decoding limit');
  const bytes: Buffer[] = [];
  for await (const chunk of chunks(file)) bytes.push(chunk);
  return Buffer.concat(bytes);
}
async function verifyBytes(file: InstalledFile): Promise<void> { for await (const _chunk of chunks(file)) { /* streamed integrity check */ } }
function checkCanonicalBytes(bytes: Buffer): unknown {
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
    let count = 0;
    while (pending.length) {
      const item = pending.pop()!;
      if (++count > 10_000 || item.depth > 32) mismatch('installed runtime canonical graph exceeds its decoding bound');
      if (item.value && typeof item.value === 'object') for (const child of Object.values(item.value)) pending.push({ value: child, depth: item.depth + 1 });
    }
    if (!canonicalJsonBytes(value).equals(bytes)) mismatch('installed runtime JSON bytes are not canonical');
    return value;
  } catch (cause) { if (cause instanceof KernelStorageError) throw cause; mismatch('installed runtime canonical data cannot be decoded', cause); }
}
function validateBundle(value: unknown, releaseKeys: readonly ReleaseTrustKey[]): RuntimeBundleManifest {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) mismatch('installed runtime manifest must be an object');
    const bundle = value as RuntimeBundleManifest;
    if (!Array.isArray(bundle.entries) || !Array.isArray(bundle.structuredArtifacts) || !Array.isArray(bundle.guestToolchainManifestRefs)) mismatch('installed runtime manifest graph must contain arrays');
    verifyRuntimeBundle(bundle, releaseKeys);
    if (bundle.guestToolchainManifestRefs.length || bundle.structuredArtifacts.length !== 1) mismatch('installed runtime contains unsupported structured roots');
    for (const entry of bundle.entries) {
      if (entry.relativePath.normalize('NFC') !== entry.relativePath || Buffer.byteLength(entry.relativePath) > 4096 ||
          entry.relativePath === 'manifest.json' || entry.relativePath.startsWith('manifest.json/') ||
          (entry.executable && entry.byteCount === 0) ||
          (['supervisor', 'worker', 'provider_adapter', 'tool_adapter', 'platform_helper', 'mcp_server', 'mcp_recovery_adapter', 'local_inference'].includes(entry.role) && !entry.executable) ||
          ['guest_toolchain', 'skill_bundle', 'mcp_recovery_profile', 'bundle_object', 'system_prompt', 'compaction_prompt'].includes(entry.role)) {
        mismatch('installed runtime entry path or role is unsupported');
      }
    }
    return immutableSnapshot(bundle);
  } catch (cause) { if (cause instanceof KernelStorageError) throw cause; mismatch('installed runtime release manifest failed validation', cause); }
}
function validateTrustStore(bytes: Buffer): void {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const certificates = text.match(/-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu);
    if (!certificates?.length || text.replace(/-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu, '').trim()) mismatch('signed HTTPS trust store must contain only PEM certificates');
    for (const certificate of certificates) new X509Certificate(certificate);
  } catch (cause) { if (cause instanceof KernelStorageError) throw cause; mismatch('signed HTTPS trust store is invalid', cause); }
}
async function checkPackageGraph(scope: Scope, root: Directory, bundle: RuntimeBundleManifest): Promise<void> {
  const expected = new Map<string, Set<string>>();
  for (const filename of ['manifest.json', ...bundle.entries.map(entry => entry.relativePath)]) {
    const components = filename.split('/');
    for (let index = 0; index < components.length; index++) {
      const parent = components.slice(0, index).join('/');
      const names = expected.get(parent) ?? new Set<string>(); names.add(components[index]!); expected.set(parent, names);
    }
  }
  for (const [relative, names] of expected) {
    const directory = relative ? (await scope.parent(root, `${relative}/_`)).parent : root;
    await scope.assertDirectory(directory);
    const observed = await readdir(childPath(directory, '.'));
    if (observed.length !== names.size || observed.some(name => !names.has(name))) mismatch('installed runtime graph contains missing or unsigned paths');
    await scope.assertDirectory(directory);
  }
}
async function checkSelectedVersion(scope: Scope, bundles: Directory, bundleDigest: string): Promise<void> {
  await scope.assertDirectory(bundles);
  const names = await readdir(childPath(bundles, '.'));
  if (names.length !== 1 || names[0] !== bundleDigest) mismatch('initial installed runtime contains an unselected version or object');
  await scope.assertDirectory(bundles);
}
async function verifyPackage(scope: Scope, root: Directory, releaseKeys: readonly ReleaseTrustKey[], expectedDigest?: string): Promise<VerifiedPackage> {
  const manifest = await scope.file(root, 'manifest.json', 0o400, undefined, expectedDigest);
  const manifestBytes = await readSmall(manifest);
  const bundleDigest = sha256Bytes(manifestBytes);
  const bundle = validateBundle(checkCanonicalBytes(manifestBytes), releaseKeys);
  manifest.digest = bundleDigest;
  const entries = new Map<string, InstalledFile>();
  const roots = new Map<string, Buffer>([[bundleDigest, manifestBytes]]);
  const inodes = new Set<string>();
  for (const entry of bundle.entries) {
    const file = await scope.file(root, entry.relativePath, entry.executable ? 0o500 : 0o400, entry.byteCount, entry.digest);
    const identity = `${file.info.dev}:${file.info.ino}`;
    if (inodes.has(identity)) mismatch('distinct signed entries alias one installed inode');
    inodes.add(identity); entries.set(entry.entryId, file);
    if (entry.role === 'policy_engine' || entry.role === 'sandbox_root_profile') {
      if (entry.executable) mismatch('signed structured roots must be data');
      const bytes = await readSmall(file); const value = checkCanonicalBytes(bytes);
      if (entry.role === 'policy_engine') {
        if (canonicalSha256(value) !== canonicalSha256(policyProfile())) mismatch('signed policy root is not the fixed supported evaluator profile');
      } else decodeSandboxRootProfile(value);
      roots.set(entry.digest, bytes);
    } else if (entry.role === 'trust_store') {
      const bytes = await readSmall(file, TRUST_BYTES); validateTrustStore(bytes); roots.set(entry.digest, bytes);
    } else await verifyBytes(file);
  }
  const profileEntry = bundle.entries.find(entry => entry.role === 'policy_engine')!;
  const profile = policyProfile();
  const structured = bundle.structuredArtifacts[0]!;
  if (!structured || !exactKeys(structured, ['artifactId', 'rootEntryId', 'artifactRef', 'semanticDigest', 'memberRefs', 'kind']) ||
      structured.kind !== 'policy_engine_profile' || typeof structured.artifactId !== 'string' || !structured.artifactId ||
      structured.rootEntryId !== profileEntry.entryId || structured.artifactRef !== profileEntry.digest ||
      structured.semanticDigest !== profile.profileDigest || !Array.isArray(structured.memberRefs) || structured.memberRefs.length !== 0) {
    mismatch('signed structured policy root is not its exact self-contained entry');
  }
  await checkPackageGraph(scope, root, bundle); await scope.assertDirectories();
  return { root, manifest, bundle, bundleDigest, manifestBytes, entries, roots };
}

async function writeChunks(scope: Scope, root: Directory, relative: string, source: AsyncIterable<Buffer>, mode: number): Promise<void> {
  const { parent, name } = await scope.parent(root, relative, true);
  await scope.assertDirectory(parent);
  const handle = scope.own(await open(childPath(parent, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600));
  let position = 0;
  for await (const bytes of source) {
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, position);
      if (!bytesWritten) mismatch('installed runtime copy made no progress');
      offset += bytesWritten; position += bytesWritten;
    }
  }
  await handle.chmod(mode); await handle.sync();
  await scope.retire(handle); await scope.assertDirectory(parent);
}
async function* bytesSource(bytes: Buffer): AsyncGenerator<Buffer> { yield bytes; }
async function syncDirectories(scope: Scope): Promise<void> {
  for (const directory of [...scope.directories].reverse()) {
    await scope.assertDirectory(directory); await directory.handle.sync(); await scope.assertDirectory(directory);
  }
}
async function absent(parent: Directory, name: string): Promise<void> {
  try { await lstat(childPath(parent, name)); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; throw error; }
  mismatch('initial runtime installation refuses an existing selection or version');
}
async function finish<T>(scope: Scope, operation: () => Promise<T>): Promise<T> {
  let result: T | undefined;
  let failure: unknown;
  try { result = await operation(); } catch (error) { rememberRetirement(error); failure = error; }
  try { await scope.close(); } catch (error) { rememberRetirement(error); throw error; }
  if (failure !== undefined) throw failure;
  healthy(); return result as T;
}

/** Trusted composition only: production supplies compiled release roots here.
 * Neither install nor selection accepts caller overrides, execution callbacks,
 * arbitrary loaders, StateStore authority or an upgrade/adoption operation. */
export function createInstalledRuntime(input: { releaseKeys: readonly ReleaseTrustKey[] }): InstalledRuntime {
  supportedPlatform();
  healthy();
  if (!exactKeys(input, ['releaseKeys'])) mismatch('installed runtime accepts only trusted composition keys');
  const releaseKeys = immutableSnapshot(input.releaseKeys);
  if (!Array.isArray(releaseKeys) || !releaseKeys.length || releaseKeys.some(key => !exactKeys(key, ['keyId', 'publicKeyPem']) ||
      typeof key.keyId !== 'string' || !key.keyId || typeof key.publicKeyPem !== 'string' || !key.publicKeyPem) ||
      new Set(releaseKeys.map(key => key.keyId)).size !== releaseKeys.length) mismatch('installed runtime requires fixed unambiguous trusted composition keys');
  const runtime: InstalledRuntime = Object.freeze({
    executeSelected(this: InstalledRuntime, held: HeldInstalledRuntime, role: 'keeper' | 'supervisor'): Promise<never> {
      // Reject receiver/brand/factory/primitive role before touching a caller
      // property, queue, or descriptor. Invalid calls do not consume a handle.
      if (this !== runtime) mismatch('installed runtime factory receiver is not its trusted instance');
      const binding = heldInstalledRuntimes.get(held);
      if (!binding || binding.factory !== runtime) mismatch('installed execution requires this factory\'s genuine held selection');
      if (role !== 'keeper' && role !== 'supervisor') mismatch('installed execution requires a fixed primitive role');
      if (!isMainThread) throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed execution requires the main thread');
      healthy();
      return binding.execute(role);
    },
    async installInitial(this: InstalledRuntime, target: { packageRoot: string; stateRoot: string }) {
      supportedPlatform();
      if (this !== runtime) mismatch('installed runtime factory receiver is not its trusted instance');
      healthy();
      if (!exactKeys(target, ['packageRoot', 'stateRoot'])) mismatch('initial runtime installation requires only fixed package and StateRoot locators');
      const { packageRoot, stateRoot } = target;
      const sourceScope = new Scope();
      const destination = new Scope();
      return finish(destination, async () => {
        let signed: VerifiedPackage;
        try {
          const sourceRoot = await sourceScope.root(packageRoot);
          signed = await verifyPackage(sourceScope, sourceRoot, releaseKeys);
          const state = await destination.root(stateRoot, true);
          const root = await destination.directory(state, 'runtime', true);
          const casRoot = await destination.directory(state, KERNEL_CAS_DIRECTORY, true);
          const bundles = await destination.directory(root, 'bundles', true);
          const stage = await destination.directory(bundles, `.stage-${randomBytes(16).toString('hex')}`, true);
          for (const entry of signed.bundle.entries) await writeChunks(destination, stage, entry.relativePath, chunks(signed.entries.get(entry.entryId)!), entry.executable ? 0o500 : 0o400);
          await writeChunks(destination, stage, 'manifest.json', bytesSource(signed.manifestBytes), 0o400);
          const supervisor = signed.bundle.entries.find(entry => entry.role === 'supervisor')!;
          await writeChunks(destination, root, 'bootstrap', chunks(signed.entries.get(supervisor.entryId)!), 0o500);
          // Existing CAS publication owns its durability protocol; all supported
          // complete roots precede durable selection, with no second ledger.
          const cas = new ContentAddressedStore(childPath(casRoot, '.'));
          const casFiles: InstalledFile[] = [];
          for (const [ref, bytes] of signed.roots) {
            await destination.assertDirectories();
            if (await cas.publish(bytes) !== ref) mismatch('installed runtime CAS publication changed its complete root identity');
            await destination.assertDirectories();
            casFiles.push(await destination.file(casRoot, ref, 0o400, bytes.length, ref));
          }
          await verifyPackage(destination, stage, releaseKeys, signed.bundleDigest);
          await verifyBytes(await destination.file(root, 'bootstrap', 0o500, supervisor.byteCount, supervisor.digest));
          await checkPackageGraph(sourceScope, sourceRoot, signed.bundle);
          await sourceScope.assertDirectories();
          for (const file of [signed.manifest, ...signed.entries.values()]) await verifyBytes(file);
          for (const file of casFiles) await verifyBytes(file);
          await syncDirectories(destination);
          // Retire source authority before publishing a selection. Source
          // deletion after this point cannot change installed identity.
          await sourceScope.close(); healthy();
          await absent(bundles, signed.bundleDigest);
          await rename(childPath(bundles, stage.name), childPath(bundles, signed.bundleDigest));
          stage.name = signed.bundleDigest;
          await bundles.handle.sync(); await destination.assertDirectories();
          await absent(root, 'active.json');
          const temporary = `.tmp-active-${randomBytes(16).toString('hex')}`;
          await writeChunks(destination, root, temporary, bytesSource(canonicalJsonBytes({ schemaVersion: 1, bundleDigest: signed.bundleDigest })), 0o600);
          healthy(); await rename(childPath(root, temporary), childPath(root, 'active.json'));
          await root.handle.sync(); await destination.assertDirectories();
          return { bundleDigest: signed.bundleDigest, manifestDigest: signed.bundle.manifestDigest };
        } catch (error) {
          rememberRetirement(error);
          await sourceScope.close(); throw error;
        }
      });
    },
    async openSelected(this: InstalledRuntime, stateRoot: string): Promise<HeldInstalledRuntime> {
      supportedPlatform();
      if (this !== runtime) mismatch('installed runtime factory receiver is not its trusted instance');
      healthy();
      const scope = new Scope();
      try {
        const state = await scope.root(stateRoot);
        const root = await scope.directory(state, 'runtime');
        const bundles = await scope.directory(root, 'bundles');
        const casRoot = await scope.directory(state, KERNEL_CAS_DIRECTORY);
        const active = await scope.file(root, 'active.json', 0o600);
        const activeBytes = await readSmall(active);
        const selection = checkCanonicalBytes(activeBytes) as { schemaVersion: number; bundleDigest: string };
        if (!selection || typeof selection !== 'object' || Array.isArray(selection) || !exactKeys(selection, ['schemaVersion', 'bundleDigest']) || selection.schemaVersion !== 1) mismatch('installed runtime selection has an invalid closed shape');
        try { assertArtifactRef(selection.bundleDigest); } catch (cause) { mismatch('installed runtime selection has an invalid complete bundle reference', cause); }
        active.digest = sha256Bytes(activeBytes);
        await checkSelectedVersion(scope, bundles, selection.bundleDigest);
        const version = await scope.directory(bundles, selection.bundleDigest);
        const signed = await verifyPackage(scope, version, releaseKeys, selection.bundleDigest);
        const supervisor = signed.bundle.entries.find(entry => entry.role === 'supervisor')!;
        const bootstrap = await scope.file(root, 'bootstrap', 0o500, supervisor.byteCount, supervisor.digest);
        const casFiles: InstalledFile[] = [];
        for (const [ref, bytes] of signed.roots) casFiles.push(await scope.file(casRoot, ref, 0o400, bytes.length, ref));
        let closed = false;
        let poisoned: unknown;
        let tail = Promise.resolve();
        let closePromise: Promise<void> | undefined;
        const revalidate = async () => {
          healthy(); await scope.assertDirectories();
          for (const file of [active, signed.manifest, bootstrap, ...signed.entries.values(), ...casFiles]) await verifyBytes(file);
          await checkPackageGraph(scope, version, signed.bundle);
          await checkSelectedVersion(scope, bundles, signed.bundleDigest); await scope.assertDirectories();
        };
        await revalidate();
        const checkedRevalidate = async () => {
          if (poisoned !== undefined) throw poisoned;
          try { await revalidate(); }
          catch (error) { rememberRetirement(error); poisoned = error; throw error; }
        };
        const loadSelectedNative = async (): Promise<NativeStateOwner> => {
          await checkedRevalidate();
          const entry = signed.bundle.entries.find(entry => entry.entryId === STATE_OWNER_NATIVE_ENTRY_ID);
          const file = signed.entries.get(STATE_OWNER_NATIVE_ENTRY_ID);
          if (!entry || !file || entry.role !== 'platform_helper' || !entry.executable || entry.version !== '1' ||
              entry.relativePath !== STATE_OWNER_NATIVE_RELATIVE_PATH || entry.byteCount <= 0 || entry.byteCount > TRUST_BYTES)
            mismatch('installed StateOwner requires its fixed signed native entry');
          const native = await loadHeldStateOwnerImage(file.handle, signed.bundle);
          await checkedRevalidate();
          return native;
        };
        const enqueue = <T>(operation: () => Promise<T>): Promise<T> => {
          if (closed) mismatch('installed runtime handle is closed');
          const pending = tail.then(operation);
          tail = pending.then(() => undefined, () => undefined);
          return pending;
        };
        const identity = (directory: Directory): InstalledDirectoryIdentity => Object.freeze({
          deviceId: directory.info.dev.toString(), fileId: directory.info.ino.toString(), ownerUid: Number(directory.info.uid),
        });
        const observation = Object.freeze({
          bundle: signed.bundle, bundleDigest: signed.bundleDigest,
          stateRoot: Object.freeze({ ...identity(state), canonicalPath: stateRoot }),
          casRoot: identity(casRoot),
          seed: Object.freeze([...signed.roots].map(([artifactRef, bytes]) => {
            const role = signed.bundle.entries.find(entry => entry.digest === artifactRef)?.role;
            const schemaKind = artifactRef === signed.bundleDigest ? 'cliq-runtime-bundle-v1' :
              role === 'policy_engine' ? 'cliq-policy-engine-profile-v1' :
              role === 'sandbox_root_profile' ? 'cliq-sandbox-root-profile-v1' :
              role === 'trust_store' ? 'cliq-https-trust-store-v1' : mismatch('installed seed contains an unsupported object');
            return Object.freeze({ artifactRef, byteCount: bytes.length,
              mediaType: role === 'trust_store' ? 'application/octet-stream' : 'application/json', schemaKind });
          })
            .sort((left, right) => left.artifactRef < right.artifactRef ? -1 : left.artifactRef > right.artifactRef ? 1 : 0)),
        });
        const selected: HeldInstalledRuntime = Object.freeze({
          bundle: signed.bundle, bundleDigest: signed.bundleDigest,
          async assertHeld(this: HeldInstalledRuntime): Promise<void> {
            if (this !== selected) mismatch('installed runtime handle receiver is not its held instance');
            return enqueue(checkedRevalidate);
          },
          close(this: HeldInstalledRuntime): Promise<void> {
            if (this !== selected) return Promise.reject(new KernelStorageError('ARTIFACT_MISMATCH', 'installed runtime handle receiver is not its held instance'));
            closed = true;
            return closePromise ??= tail.then(() => scope.close());
          },
        });
        heldInstalledRuntimes.set(selected, {
          factory: runtime,
          initializeKeeper(): Promise<HeldInstalledKeeper> {
            return enqueue(async () => {
              const native = await loadSelectedNative();
              const file = signed.entries.get(supervisor.entryId)!;
              const keeper = initializeHeldInstalledKeeper(native, {
                stateRoot, root: state.info, image: file.info, bundleDigest: signed.bundleDigest,
                relativePath: supervisor.relativePath,
              });
              try {
                await checkedRevalidate();
                keeper.assertHeld();
                const held: HeldInstalledKeeper = Object.freeze({
                  assertHeld() {
                    if (this !== held) throw new TypeError('invalid installed keeper handle');
                    try { healthy(); keeper.assertHeld(); } catch (error) { rememberRetirement(error); throw error; }
                  },
                  close() {
                    if (this !== held) throw new TypeError('invalid installed keeper handle');
                    // Sticky uncertainty revokes new authority, not cleanup.
                    try { keeper.close(); } catch (error) { rememberRetirement(error); throw error; }
                  },
                });
                return held;
              } catch (error) {
                rememberRetirement(error);
                // A minted native resource cannot escape a failed post-init
                // installation check. Join retirement; uncertainty wins.
                await joinResourceOperations([Promise.reject(error), Promise.resolve().then(() => {
                  try { keeper.close(); } catch (failure) { rememberRetirement(failure); throw failure; }
                })] as const);
                throw error;
              }
            }).catch(error => { rememberRetirement(error); throw error; });
          },
          execute(role): Promise<never> {
            if (closed) mismatch('installed runtime handle is closed');
            closed = true; // Consume synchronously; join existing borrows first.
            const pending = tail.then(async (): Promise<never> => {
              let image: FileHandle | undefined;
              let failure: unknown;
              try {
                const native = await loadSelectedNative();
                const file = signed.entries.get(supervisor.entryId)!;
                // The original FileHandle stays strongly owned by this terminal
                // operation. C borrows it; no numeric-fd ownership handoff.
                image = scope.take(file.handle);
                await scope.close();
                executeHeldInstalledImage(native, image, {
                  stateRoot, root: state.info, bootstrap: bootstrap.info,
                  image: file.info, bundleDigest: signed.bundleDigest,
                  relativePath: supervisor.relativePath, role,
                });
              } catch (error) { rememberRetirement(error); failure = error; }
              const retireImage = async () => {
                const owned = image; image = undefined; // Never retry a numeric fd.
                if (!owned) return;
                try { await owned.close(); }
                catch (cause) {
                  const error = new ResourceRetirementError('installed execution image descriptor did not retire',
                    new AggregateError([failure, cause]));
                  rememberRetirement(error); throw error;
                }
              };
              // Pre-terminal refusal still joins every known descriptor. A
              // retirement failure wins over an ordinary validation error.
              await joinResourceOperations([Promise.reject(failure), scope.close(), retireImage()] as const);
              throw new Error('installed terminal execution unexpectedly returned');
            });
            tail = pending.then(() => undefined, () => undefined);
            closePromise = pending.then(() => undefined, error => {
              if (error instanceof ResourceRetirementError) throw error;
            });
            void closePromise.catch(() => undefined);
            return pending;
          },
          borrow<T>(operation: (installed: InstalledRuntimeBorrow) => Promise<T>): Promise<T> {
            return enqueue(async () => {
              await checkedRevalidate();
              let active = true;
              const revalidations: Promise<void>[] = [];
              const installed: InstalledRuntimeBorrow = Object.freeze({
                ...observation,
                revalidate(): Promise<void> {
                  if (!active) mismatch('installed runtime borrow has ended');
                  const pending = checkedRevalidate();
                  revalidations.push(pending);
                  // The borrow owns joining even a caller-unawaited check.
                  void pending.catch(() => undefined);
                  return pending;
                },
                loadStateOwner(): Promise<NativeStateOwner> {
                  if (!active) mismatch('installed runtime borrow has ended');
                  const pending = loadSelectedNative();
                  // The borrow owns joining even an unawaited loader. Its sole
                  // file-owning Scope cannot close before this operation ends.
                  const joined = pending.then(() => undefined);
                  revalidations.push(joined);
                  void joined.catch(() => undefined);
                  return pending;
                },
              });
              const result = Promise.resolve().then(() => operation(installed));
              await result.then(() => undefined, () => undefined);
              active = false;
              // Join every check, preserving retirement uncertainty over an
              // ordinary callback or validation error.
              return (await joinResourceOperations([result, ...revalidations] as const))[0];
            });
          },
        });
        return selected;
      } catch (error) {
        rememberRetirement(error); await scope.close(); throw error;
      }
    },
  });
  return runtime;
}
