// Retained signed data, never a physical executable/Run/StateOwner capability.
import { createPublicKey, verify } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { GuestExecutableIdentity, GuestToolchainManifest } from '../kernel/execution.js';
import { assertArtifactRef, identityHash, normalizeBoundedText, sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { GUEST_EXTRACTOR_RECIPE } from '../sandbox/guest-toolchain.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';

const MANIFEST_BYTES = 1_048_576;
function mismatch(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }
function closed(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      required.some(key => !Object.hasOwn(value, key)) ||
      Reflect.ownKeys(value).some(key => typeof key !== 'string' || !required.includes(key) && !optional.includes(key)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(property => !Object.hasOwn(property, 'value') || !property.enumerable))
    mismatch('guest toolchain has an invalid closed shape');
  return value as Record<string, unknown>;
}
function text(value: unknown, maximum = 512): string {
  if (typeof value !== 'string' || normalizeBoundedText(value, 1, maximum) !== value)
    mismatch('guest toolchain text is not canonical or bounded');
  return value;
}
function ref(value: unknown): string {
  if (typeof value !== 'string') mismatch('guest toolchain reference is invalid');
  try { assertArtifactRef(value); } catch { mismatch('guest toolchain reference is invalid'); }
  return value;
}
function executable(value: unknown): GuestExecutableIdentity {
  const entry = closed(value, ['logicalName', 'canonicalGuestPath', 'digest', 'version']);
  text(entry.logicalName); text(entry.version); ref(entry.digest);
  const path = text(entry.canonicalGuestPath, 4096);
  if (!path.startsWith('/') || path.includes('\\') || path.slice(1).split('/').some(part =>
    !part || part === '.' || part === '..' || Buffer.byteLength(part) > 255))
    mismatch('guest executable path is not absolute canonical guest data');
  return entry as GuestExecutableIdentity;
}
function inventory(value: unknown): void {
  if (!Array.isArray(value) || value.length > GUEST_EXTRACTOR_RECIPE.maxPinnedExecutables)
    mismatch('guest executable inventory exceeds its bound');
  const properties = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(properties).length !== value.length + 1 ||
      Array.from({ length: value.length }, (_, index) => properties[String(index)]).some(property =>
        !property || !Object.hasOwn(property, 'value') || !property.enumerable))
    mismatch('guest executable inventory is not dense data');
}

export function guestToolchainExecutables(manifest: GuestToolchainManifest): readonly GuestExecutableIdentity[] {
  return [manifest.worker, manifest.shell, manifest.git, manifest.node,
    ...(manifest.packageManager ? [manifest.packageManager] : []), ...manifest.searchTools, ...manifest.verifiers, ...manifest.admittedExecutables];
}

/** Shape and semantic digest only. The signature and complete image are
 * independently authenticated below, and native execution needs its own probe. */
export function decodeGuestToolchainManifest(value: unknown): GuestToolchainManifest {
  const manifest = closed(value, ['schemaVersion', 'format', 'guestImageRef', 'guestImageDigest', 'guestImageByteCount',
    'guestImageFormat', 'architecture', 'kernelAbi', 'userspaceAbi', 'worker', 'shell', 'git', 'node', 'searchTools',
    'verifiers', 'admittedExecutables', 'publisherKeyId', 'manifestDigest', 'signatureRef'], ['packageManager']);
  if (manifest.schemaVersion !== 1 || manifest.format !== 'cliq-guest-toolchain-v1' || manifest.guestImageFormat !== 'raw-ext4-v1' ||
      !['arm64', 'x86_64'].includes(text(manifest.architecture)) ||
      typeof manifest.guestImageByteCount !== 'number' || !Number.isSafeInteger(manifest.guestImageByteCount) || manifest.guestImageByteCount < 1 ||
      ref(manifest.guestImageRef) !== ref(manifest.guestImageDigest)) mismatch('guest image identity is invalid');
  text(manifest.kernelAbi); text(manifest.userspaceAbi); text(manifest.publisherKeyId); ref(manifest.signatureRef); ref(manifest.manifestDigest);
  for (const field of ['searchTools', 'verifiers', 'admittedExecutables']) inventory(manifest[field]);
  const entries = guestToolchainExecutables(manifest as GuestToolchainManifest).map(executable);
  if (entries.length > GUEST_EXTRACTOR_RECIPE.maxPinnedExecutables ||
      new Set(entries.map(entry => entry.logicalName)).size !== entries.length ||
      new Set(entries.map(entry => entry.canonicalGuestPath)).size !== entries.length)
    mismatch('guest executable inventory is ambiguous or exceeds its bound');
  const { manifestDigest: _digest, signatureRef: _signature, ...core } = manifest;
  if (canonicalSha256(core) !== manifest.manifestDigest || canonicalJsonBytes(manifest).length > MANIFEST_BYTES)
    mismatch('guest manifest semantic digest or byte bound differs');
  return immutableSnapshot(manifest as GuestToolchainManifest);
}

export type RetainedVerifierToolchain = Readonly<{ manifestRef: string; manifest: GuestToolchainManifest; abiFingerprint: string }>;

export function guestToolchainRoots(bundle: RuntimeBundleManifest) {
  const roots = bundle.structuredArtifacts.filter(root => root.kind === 'guest_toolchain');
  if (!Array.isArray(bundle.guestToolchainManifestRefs) ||
      canonicalSha256(bundle.guestToolchainManifestRefs) !== canonicalSha256(roots.map(root => root.artifactRef)) ||
      new Set(roots.map(root => root.artifactId)).size !== roots.length ||
      new Set(roots.map(root => root.rootEntryId)).size !== roots.length ||
      new Set(roots.map(root => root.artifactRef)).size !== roots.length)
    mismatch('guest discovery roots are missing, duplicated or out of order');
  for (const root of roots) {
    closed(root, ['kind', 'artifactId', 'rootEntryId', 'artifactRef', 'semanticDigest', 'memberRefs']);
    text(root.artifactId); text(root.rootEntryId); ref(root.artifactRef); ref(root.semanticDigest);
    const entry = bundle.entries.find(entry => entry.entryId === root.rootEntryId);
    if (!entry || entry.role !== 'guest_toolchain' || entry.executable || entry.digest !== root.artifactRef ||
        entry.byteCount < 1 || entry.byteCount > MANIFEST_BYTES)
      mismatch('guest root does not bind its exact signed data entry');
  }
  if (bundle.entries.some(entry => entry.role === 'guest_toolchain' && !roots.some(root => root.rootEntryId === entry.entryId)))
    mismatch('guest entry has no exact discovery root');
  return roots;
}

/** Reproduces the all-and-only signed closure without authenticating a key.
 * Historical genesis readers use this only under their original signed owner. */
export function guestToolchainMembers(bundle: RuntimeBundleManifest, manifestRef: string, manifest: GuestToolchainManifest) {
  const roots = guestToolchainRoots(bundle).filter(root => root.artifactRef === manifestRef);
  if (roots.length !== 1 || roots[0]!.semanticDigest !== manifest.manifestDigest)
    mismatch('guest manifest has no exact semantic discovery identity');
  const expected = [...new Set([manifest.guestImageRef, manifest.signatureRef])].sort();
  if (canonicalSha256(roots[0]!.memberRefs) !== canonicalSha256(expected)) mismatch('guest closure has missing or extra members');
  return expected.map(member => {
    const entries = bundle.entries.filter(entry => entry.digest === member), entry = entries[0];
    if (entries.length !== 1 || !entry || entry.executable || entry.role !== 'bundle_object' || entry.version !== '1' ||
        entry.entryId !== identityHash('runtime-bundle-object-v1', member) ||
        entry.relativePath !== `objects/sha256/${member.slice(0, 2)}/${member}` ||
        entry.byteCount !== (member === manifest.guestImageRef ? manifest.guestImageByteCount : 64))
      mismatch('guest member does not bind its complete canonical signed object entry');
    return entry;
  });
}

export function validateGuestToolchainMetadata(bundle: RuntimeBundleManifest, manifestRef: string,
  bytes: Buffer, signature: Buffer, releaseKeys: readonly ReleaseTrustKey[]): RetainedVerifierToolchain {
  verifyRuntimeBundle(bundle, releaseKeys);
  if (!Buffer.isBuffer(bytes) || bytes.length > MANIFEST_BYTES || sha256Bytes(bytes) !== ref(manifestRef))
    mismatch('guest manifest complete bytes differ');
  const value: unknown = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!canonicalJsonBytes(value).equals(bytes)) mismatch('guest manifest bytes are not canonical');
  const manifest = decodeGuestToolchainManifest(value);
  guestToolchainMembers(bundle, manifestRef, manifest);
  if (!Buffer.isBuffer(signature) || signature.length !== 64 || sha256Bytes(signature) !== manifest.signatureRef)
    mismatch('guest detached signature complete bytes differ');
  const keys = releaseKeys.filter(key => key.keyId === manifest.publisherKeyId);
  if (keys.length !== 1) mismatch('guest publisher has no unique trusted release key');
  const key = createPublicKey(keys[0]!.publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519' ||
      !verify(null, Buffer.from(`cliq-guest-toolchain-v1\0${manifest.manifestDigest}`), key, signature))
    mismatch('guest manifest release signature is invalid');
  return immutableSnapshot({ manifestRef, manifest, abiFingerprint: manifest.manifestDigest });
}

async function readBounded(artifacts: ArtifactCatalog, reference: string, count: number, maximum: number, signal?: AbortSignal): Promise<Buffer> {
  signal?.throwIfAborted();
  if (!Number.isSafeInteger(count) || count < 1 || count > maximum) mismatch('guest data object exceeds its bounded read');
  const chunks: Buffer[] = [];
  for await (const chunk of artifacts.readChunks(reference, count)) { signal?.throwIfAborted(); chunks.push(Buffer.from(chunk)); }
  signal?.throwIfAborted();
  return Buffer.concat(chunks);
}

/** Selects only the pinned original signed discovery graph. Exhausting the
 * image stream proves its complete content hash, not ext4/ELF executability. */
export async function readRetainedVerifierToolchain(artifacts: ArtifactCatalog, input: {
  bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[];
  guestToolchainManifestId?: string; guestToolchainManifestRef?: string;
  signal?: AbortSignal;
}): Promise<RetainedVerifierToolchain> {
  input.signal?.throwIfAborted();
  verifyRuntimeBundle(input.bundle, input.releaseKeys);
  const roots = guestToolchainRoots(input.bundle).filter(root =>
    (input.guestToolchainManifestId === undefined || root.artifactId === input.guestToolchainManifestId) &&
    (input.guestToolchainManifestRef === undefined || root.artifactRef === input.guestToolchainManifestRef));
  if (roots.length !== 1 || input.guestToolchainManifestId === undefined && input.guestToolchainManifestRef === undefined)
    mismatch('guest selection has no unique pinned signed root');
  const root = roots[0]!, entry = input.bundle.entries.find(entry => entry.entryId === root.rootEntryId)!;
  const bytes = await readBounded(artifacts, root.artifactRef, entry.byteCount, MANIFEST_BYTES, input.signal);
  const manifest = decodeGuestToolchainManifest(parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
  const signature = await readBounded(artifacts, manifest.signatureRef, 64, 64, input.signal);
  const selected = validateGuestToolchainMetadata(input.bundle, root.artifactRef, bytes, signature, input.releaseKeys);
  for await (const _chunk of artifacts.readChunks(manifest.guestImageRef, manifest.guestImageByteCount)) { input.signal?.throwIfAborted(); }
  input.signal?.throwIfAborted();
  return selected;
}
