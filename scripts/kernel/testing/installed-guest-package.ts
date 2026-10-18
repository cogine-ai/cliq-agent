// Package construction only. The production metadata consumer authenticates
// the caller's completed Bundle; native ext4/ELF execution is separate proof.
import { createHash, sign, type KeyObject } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { copyFile, lstat, mkdir, open, type FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import type { GuestToolchainManifest } from '../../../src/kernel/execution.js';
import { assertArtifactRef, identityHash, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { exactKeys, type RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { GUEST_EXTRACTOR_RECIPE } from '../../../src/sandbox/guest-toolchain.js';
import { joinResourceOperations } from '../../../src/state/errors.js';
import { decodeGuestToolchainManifest } from '../../../src/state/guest-toolchain.js';

const MANIFEST_ID = 'installed-node-test-toolchain';
const ROOT_ENTRY_ID = 'installed-node-test-toolchain-root';
const MAX_METADATA_BYTES = 1_048_576;
const CHUNK_BYTES = 65_536;
type HeldFile = { filename: string; handle: FileHandle; identity: BigIntStats };
function fail(message: string): never { throw new TypeError(`installed guest package: ${message}`); }

function same(left: BigIntStats, right: BigIntStats) {
  return (['dev', 'ino', 'size', 'mode', 'uid', 'gid', 'nlink', 'mtimeNs', 'ctimeNs'] as const).every(key => left[key] === right[key]);
}
function protectedFile(info: BigIntStats, mode: number, maximum: number, exact?: number) {
  const uid = process.getuid?.();
  if (uid === undefined || !info.isFile() || info.nlink !== 1n || info.size < 1n || info.size > BigInt(maximum) ||
      exact !== undefined && info.size !== BigInt(exact) || (info.mode & 0o7777n) !== BigInt(mode) || info.uid !== 0n && info.uid !== BigInt(uid))
    fail('source is not a complete protected single-link regular file');
}
async function hold(filename: string, mode: number, maximum: number, handles: FileHandle[], exact?: number): Promise<HeldFile> {
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); handles.push(handle);
  const identity = await handle.stat({ bigint: true }); protectedFile(identity, mode, maximum, exact);
  if (!same(identity, await lstat(filename, { bigint: true }))) fail('source path differs from its held descriptor');
  return { filename, handle, identity };
}
async function observe(file: HeldFile) {
  if (!same(file.identity, await file.handle.stat({ bigint: true })) || !same(file.identity, await lstat(file.filename, { bigint: true })))
    fail('source changed while packaging');
}
async function completeHash(file: HeldFile, collect = false) {
  await observe(file);
  const hash = createHash('sha256'), bytes = Buffer.alloc(CHUNK_BYTES), chunks: Buffer[] = [];
  const expected = Number(file.identity.size); let offset = 0;
  while (offset < expected) {
    const count = Math.min(bytes.length, expected - offset), read = await file.handle.read(bytes, 0, count, offset);
    if (read.bytesRead < 1) fail('source ended before its complete byte count');
    const chunk = bytes.subarray(0, read.bytesRead); hash.update(chunk); if (collect) chunks.push(Buffer.from(chunk));
    offset += read.bytesRead;
  }
  await observe(file);
  return { digest: hash.digest('hex'), ...(collect ? { bytes: Buffer.concat(chunks) } : {}) };
}
async function directory(root: string, relative: string) {
  let selected = root;
  for (const component of relative ? relative.split('/') : []) {
    selected = path.join(selected, component);
    try { await mkdir(selected, { mode: 0o700 }); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    const info = await lstat(selected, { bigint: true }), uid = process.getuid?.();
    if (!info.isDirectory() || info.mode & 0o077n || uid === undefined || info.uid !== 0n && info.uid !== BigInt(uid))
      fail('package directory is not private and owned');
  }
}
function publisher(value: unknown, publisherKeyId: string): GuestToolchainManifest {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !exactKeys(value, ['schemaVersion', 'format', 'guestImageRef',
    'guestImageDigest', 'guestImageByteCount', 'guestImageFormat', 'architecture', 'kernelAbi', 'userspaceAbi', 'worker', 'shell', 'git',
    'node', 'searchTools', 'verifiers', 'admittedExecutables', 'files', 'extractedFileBytes', 'scope'])) fail('publisher input has an unknown shape');
  const data = value as Record<string, unknown>;
  if (data.schemaVersion !== 1 || data.format !== 'cliq-guest-toolchain-publisher-input-v1' ||
      data.guestImageByteCount !== GUEST_EXTRACTOR_RECIPE.maxImageBytes || data.architecture !== 'x86_64' ||
      data.kernelAbi !== 'linux-x86_64-v1' || data.userspaceAbi !== 'linux-x86_64-glibc-v1' ||
      data.scope !== 'actual build bytes only; not release-signed, execution-qualified or a Run proof' ||
      [data.searchTools, data.verifiers, data.admittedExecutables].some(value => !Array.isArray(value) || value.length !== 0))
    fail('publisher input is outside the fixed installed Node recipe');
  const manifest = { schemaVersion: 1, format: 'cliq-guest-toolchain-v1', guestImageRef: data.guestImageRef,
    guestImageDigest: data.guestImageDigest, guestImageByteCount: data.guestImageByteCount, guestImageFormat: data.guestImageFormat,
    architecture: data.architecture, kernelAbi: data.kernelAbi, userspaceAbi: data.userspaceAbi, worker: data.worker,
    shell: data.shell, git: data.git, node: data.node, searchTools: data.searchTools, verifiers: data.verifiers,
    admittedExecutables: data.admittedExecutables, publisherKeyId, manifestDigest: '', signatureRef: '0'.repeat(64) };
  const { manifestDigest: _, signatureRef: __, ...core } = manifest; manifest.manifestDigest = canonicalSha256(core);
  const decoded = decodeGuestToolchainManifest(manifest);
  if (decoded.node.logicalName !== 'node' || decoded.node.canonicalGuestPath !== '/usr/bin/node' || decoded.node.version !== '24.21.0' ||
      decoded.worker.logicalName !== 'cliq-worker' || decoded.worker.canonicalGuestPath !== '/runtime/cliq-linux-worker' || decoded.worker.version !== '1' ||
      decoded.shell.logicalName !== 'sh' || decoded.shell.canonicalGuestPath !== '/bin/sh' ||
      decoded.git.logicalName !== 'git' || decoded.git.canonicalGuestPath !== '/usr/bin/git') fail('publisher executable identity differs from the fixed recipe');
  if (!Array.isArray(data.files) || data.files.length < 4 || data.files.length > GUEST_EXTRACTOR_RECIPE.maxMappedFiles)
    fail('publisher file inventory exceeds its fixed bound');
  let prior: string | undefined, total = 0;
  const files = new Map<string, string>();
  for (const value of data.files) {
    if (!value || typeof value !== 'object' || Array.isArray(value) || !exactKeys(value, ['path', 'digest', 'byteCount'])) fail('publisher file inventory is not closed');
    const file = value as Record<string, unknown>, filename = file.path;
    if (typeof filename !== 'string' || filename.normalize('NFC') !== filename || Buffer.byteLength(filename) > 4096 ||
        !filename.startsWith('/') || filename.includes('\\') || filename.includes('\0') || filename.slice(1).split('/').some(part =>
          !part || part === '.' || part === '..' || Buffer.byteLength(part) > 255) ||
        prior !== undefined && Buffer.compare(Buffer.from(prior), Buffer.from(filename)) >= 0 ||
        typeof file.digest !== 'string' || typeof file.byteCount !== 'number' || !Number.isSafeInteger(file.byteCount) || file.byteCount < 1)
      fail('publisher file inventory is not canonical, unique, sorted and bounded');
    assertArtifactRef(file.digest); prior = filename; total += file.byteCount;
    if (!Number.isSafeInteger(total) || total > GUEST_EXTRACTOR_RECIPE.maxImageBytes - 16 * 1024 ** 2) fail('publisher files exceed the actual image bound');
    files.set(filename, file.digest);
  }
  if (total !== data.extractedFileBytes || [decoded.worker, decoded.shell, decoded.git, decoded.node]
    .some(entry => files.get(entry.canonicalGuestPath) !== entry.digest)) fail('publisher executable inventory is incomplete or inconsistent');
  return decoded;
}

export async function writeInstalledGuestToolchain(input: {
  packageRoot: string; guestImageRoot: string; extractorPath: string; publisherKeyId: string; privateKey: KeyObject;
}): Promise<{ manifest: GuestToolchainManifest; manifestRef: string; manifestId: typeof MANIFEST_ID;
  entries: RuntimeBundleManifest['entries']; root: RuntimeBundleManifest['structuredArtifacts'][number] }> {
  if (!exactKeys(input, ['packageRoot', 'guestImageRoot', 'extractorPath', 'publisherKeyId', 'privateKey']) ||
      ![input.packageRoot, input.guestImageRoot, input.extractorPath].every(path.isAbsolute) ||
      input.privateKey.type !== 'private' || input.privateKey.asymmetricKeyType !== 'ed25519') fail('invalid package paths or Ed25519 signing key');
  const packageInfo = await lstat(input.packageRoot, { bigint: true });
  if (!packageInfo.isDirectory() || packageInfo.mode & 0o077n || packageInfo.uid !== 0n && packageInfo.uid !== BigInt(process.getuid!()))
    fail('package root is not private and owned');
  const handles: FileHandle[] = [];
  try {
    const metadata = await hold(path.join(input.guestImageRoot, 'guest-toolchain-input.json'), 0o400, MAX_METADATA_BYTES, handles);
    const bytes = (await completeHash(metadata, true)).bytes!;
    const unsigned = publisher(parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), input.publisherKeyId);
    const image = await hold(path.join(input.guestImageRoot, 'guest-toolchain.ext4'), 0o400, GUEST_EXTRACTOR_RECIPE.maxImageBytes,
      handles, GUEST_EXTRACTOR_RECIPE.maxImageBytes);
    if ((await completeHash(image)).digest !== unsigned.guestImageDigest) fail('complete publisher image digest differs');
    const extractor = await hold(input.extractorPath, 0o500, GUEST_EXTRACTOR_RECIPE.maxImageBytes, handles);
    const extractorDigest = (await completeHash(extractor)).digest;
    const signature = sign(null, Buffer.from(`cliq-guest-toolchain-v1\0${unsigned.manifestDigest}`, 'utf8'), input.privateKey);
    const manifest = decodeGuestToolchainManifest({ ...unsigned, signatureRef: sha256Bytes(signature) });
    const manifestBytes = canonicalJsonBytes(manifest), manifestRef = sha256Bytes(manifestBytes);
    const entries: RuntimeBundleManifest['entries'] = [];
    async function small(entryId: string, role: string, relativePath: string, bytes: Buffer) {
      await directory(input.packageRoot, path.posix.dirname(relativePath));
      const handle = await open(path.join(input.packageRoot, relativePath), 'wx', 0o400); handles.push(handle);
      await handle.writeFile(bytes); await handle.sync();
      entries.push({ entryId, role, relativePath, digest: sha256Bytes(bytes), byteCount: bytes.length, executable: false, version: '1' });
    }
    async function copy(file: HeldFile, relativePath: string, digest: string, mode: number) {
      await directory(input.packageRoot, path.posix.dirname(relativePath)); await observe(file);
      const destination = path.join(input.packageRoot, relativePath);
      await copyFile(file.filename, destination, constants.COPYFILE_EXCL);
      await observe(file);
      const retained = await hold(destination, mode, GUEST_EXTRACTOR_RECIPE.maxImageBytes, handles, Number(file.identity.size));
      if ((await completeHash(retained)).digest !== digest) fail('retained package copy differs from its complete original bytes');
      await retained.handle.sync();
    }
    const imagePath = `objects/sha256/${manifest.guestImageRef.slice(0, 2)}/${manifest.guestImageRef}`;
    await copy(image, imagePath, manifest.guestImageDigest, 0o400);
    entries.push({ entryId: identityHash('runtime-bundle-object-v1', manifest.guestImageRef), role: 'bundle_object', relativePath: imagePath,
      digest: manifest.guestImageRef, byteCount: manifest.guestImageByteCount, executable: false, version: '1' });
    const signaturePath = `objects/sha256/${manifest.signatureRef.slice(0, 2)}/${manifest.signatureRef}`;
    await small(identityHash('runtime-bundle-object-v1', manifest.signatureRef), 'bundle_object', signaturePath, signature);
    await small(ROOT_ENTRY_ID, 'guest_toolchain', `profiles/guest-${manifestRef}.json`, manifestBytes);
    await copy(extractor, GUEST_EXTRACTOR_RECIPE.relativePath, extractorDigest, 0o500);
    entries.push({ entryId: GUEST_EXTRACTOR_RECIPE.entryId, role: 'platform_helper', relativePath: GUEST_EXTRACTOR_RECIPE.relativePath,
      digest: extractorDigest, byteCount: Number(extractor.identity.size), executable: true, version: GUEST_EXTRACTOR_RECIPE.version });
    await observe(metadata); await observe(image); await observe(extractor);
    return { manifest, manifestRef, manifestId: MANIFEST_ID, entries,
      root: { kind: 'guest_toolchain', artifactId: MANIFEST_ID, rootEntryId: ROOT_ENTRY_ID, artifactRef: manifestRef,
        semanticDigest: manifest.manifestDigest, memberRefs: [manifest.signatureRef, manifest.guestImageRef].sort() } };
  } finally { await joinResourceOperations(handles.map(handle => handle.close())); }
}
