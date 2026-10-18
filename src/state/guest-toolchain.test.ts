import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { GuestToolchainManifest } from '../kernel/execution.js';
import { identityHash, sha256Bytes } from '../kernel/identity.js';
import { policyProfile, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { decodeGuestToolchainManifest, readRetainedVerifierToolchain, validateGuestToolchainMetadata } from './guest-toolchain.js';
import { validateBundle, validateInstalledStructuredArtifacts } from './installed-artifacts.js';

// Real Ed25519/CAS data only. These deliberately non-ext4 bytes cannot qualify
// a native executable, installation, StateOwner or Run admission.
function fixture() {
  const keys = generateKeyPairSync('ed25519'), keyId = 'explicit-guest-data-test-root';
  const releaseKeys = [{ keyId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  const image = Buffer.from('guest image data, not an execution fixture\n');
  const executable = (logicalName: string) => ({ logicalName, canonicalGuestPath: `/runtime/${logicalName}`,
    digest: canonicalSha256({ logicalName }), version: '1' });
  const manifest: GuestToolchainManifest = { schemaVersion: 1, format: 'cliq-guest-toolchain-v1',
    guestImageRef: sha256Bytes(image), guestImageDigest: sha256Bytes(image), guestImageByteCount: image.length,
    guestImageFormat: 'raw-ext4-v1', architecture: 'x86_64', kernelAbi: 'linux-x86_64-v1', userspaceAbi: 'glibc-x86_64-v1',
    worker: executable('worker'), shell: executable('sh'), git: executable('git'), node: executable('node'),
    searchTools: [], verifiers: [], admittedExecutables: [], publisherKeyId: keyId, manifestDigest: '', signatureRef: '' };
  const { manifestDigest: _digest, signatureRef: _signature, ...core } = manifest;
  manifest.manifestDigest = canonicalSha256(core);
  const signature = sign(null, Buffer.from(`cliq-guest-toolchain-v1\0${manifest.manifestDigest}`), keys.privateKey);
  manifest.signatureRef = sha256Bytes(signature);
  const manifestBytes = canonicalJsonBytes(manifest), manifestRef = sha256Bytes(manifestBytes);
  const root = { kind: 'guest_toolchain', artifactId: 'guest-public-id', rootEntryId: 'guest-entry-id',
    artifactRef: manifestRef, semanticDigest: manifest.manifestDigest,
    memberRefs: [manifest.signatureRef, manifest.guestImageRef].sort() };
  const entry = (entryId: string, role: string, executable: boolean, digest = canonicalSha256({ entryId }), byteCount = 1) =>
    ({ entryId, role, executable, digest, byteCount, version: '1', relativePath: `test/${entryId}` });
  const profile = policyProfile(), profileRef = canonicalSha256(profile);
  const bundle: RuntimeBundleManifest = { schemaVersion: 1, bundleVersion: 'guest-data-only',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: 1 }, workerProtocolRange: { min: 1, max: 1 },
    entries: [entry('supervisor', 'supervisor', true), entry('worker', 'worker', true),
      entry('policy', 'policy_engine', false, profileRef, canonicalJsonBytes(profile).length),
      entry('default_https_trust_store', 'trust_store', false), entry('root', 'sandbox_root_profile', false),
      entry(root.rootEntryId, 'guest_toolchain', false, manifestRef, manifestBytes.length),
      ...[[manifest.signatureRef, signature], [manifest.guestImageRef, image]].map(([ref, bytes]) => ({
        ...entry(identityHash('runtime-bundle-object-v1', ref as string), 'bundle_object', false, ref as string, (bytes as Buffer).length),
        relativePath: `objects/sha256/${(ref as string).slice(0, 2)}/${ref as string}` }))],
    structuredArtifacts: [root, { kind: 'policy_engine_profile', artifactId: 'policy', rootEntryId: 'policy', artifactRef: profileRef,
      semanticDigest: profile.profileDigest, memberRefs: [] }], guestToolchainManifestRefs: [manifestRef], publisherKeyId: keyId, manifestDigest: '', signature: '' };
  const resign = () => {
    const { manifestDigest: _digest, signature: _signature, ...core } = bundle;
    bundle.manifestDigest = canonicalSha256(core);
    bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  };
  resign();
  return { bundle, root, manifest, manifestBytes, manifestRef, signature, image, keys, releaseKeys, resign, profile };
}

test('guest metadata binds the distinct signed public id, exact members and both digest domains', () => {
  const value = fixture();
  const selected = validateGuestToolchainMetadata(value.bundle, value.manifestRef, value.manifestBytes, value.signature, value.releaseKeys);
  assert.equal(selected.manifestRef, value.manifestRef);
  assert.equal(selected.abiFingerprint, value.manifest.manifestDigest);
  assert.notEqual(selected.manifestRef, selected.abiFingerprint);
  assert.deepEqual(selected.manifest, value.manifest);
  assert(Object.isFrozen(selected.manifest.node));
});

test('installed discovery describes every guest member without buffering the raw image as JSON', () => {
  const value = fixture();
  const objects = new Map([[value.manifestRef, value.manifestBytes], [value.manifest.signatureRef, value.signature],
    [canonicalSha256(value.profile), canonicalJsonBytes(value.profile)]]);
  const bundle = validateBundle(value.bundle, value.releaseKeys);
  const structured = validateInstalledStructuredArtifacts(bundle, objects);
  assert.equal(objects.has(value.manifest.guestImageRef), false, 'image content is verified through held streaming I/O, not this metadata map');
  assert.equal(structured.objects.find(object => object.artifactRef === value.manifest.guestImageRef)?.schemaKind, 'cliq-guest-image-raw-ext4-v1');
  assert.equal(structured.objects.find(object => object.artifactRef === value.manifest.signatureRef)?.schemaKind, 'cliq-ed25519-signature-v1');
  assert.equal(structured.objects.find(object => object.artifactRef === value.manifestRef)?.schemaKind, 'cliq-guest-toolchain-v1');
});

test('guest manifest rejects unknown fields, ambiguous executable identities and unsafe paths', () => {
  const value = fixture();
  for (const mutate of [
    (v: Record<string, any>) => { v.extension = true; },
    (v: Record<string, any>) => { v.node = { ...v.node, canonicalGuestPath: '/runtime/../node' }; },
    (v: Record<string, any>) => { v.git = { ...v.git, canonicalGuestPath: v.node.canonicalGuestPath }; },
    (v: Record<string, any>) => { v.git = { ...v.git, logicalName: v.node.logicalName }; },
    (v: Record<string, any>) => { v.guestImageDigest = '0'.repeat(64); },
    (v: Record<string, any>) => { v.guestImageByteCount = Number.MAX_SAFE_INTEGER + 1; },
    (v: Record<string, any>) => { v.node = { ...v.node, extension: true }; },
  ]) {
    const input = structuredClone(value.manifest); mutate(input);
    const { manifestDigest: _digest, signatureRef: _signature, ...core } = input;
    input.manifestDigest = canonicalSha256(core);
    assert.throws(() => decodeGuestToolchainManifest(input));
  }
});

test('guest authentication refuses substituted bytes, signature domains and untrusted keys', () => {
  const value = fixture();
  const verify = (bytes = value.manifestBytes, signature = value.signature, keys = value.releaseKeys) =>
    validateGuestToolchainMetadata(value.bundle, value.manifestRef, bytes, signature, keys);
  assert.throws(() => verify(Buffer.concat([value.manifestBytes, Buffer.from('\n')])));
  assert.throws(() => verify(undefined, Buffer.alloc(64)));
  const wrongDomain = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${value.manifest.manifestDigest}`), value.keys.privateKey);
  assert.throws(() => verify(undefined, wrongDomain));
  assert.throws(() => verify(undefined, undefined, []));
});

test('guest decoding rejects non-JSON properties and array accessors without invoking them', () => {
  const value = fixture();
  const hidden = structuredClone(value.manifest);
  Object.defineProperty(hidden, 'guestImageRef', { enumerable: false });
  assert.throws(() => decodeGuestToolchainManifest(hidden));
  for (const field of ['searchTools', 'verifiers', 'admittedExecutables'] as const) {
    const input = structuredClone(value.manifest);
    let called = false;
    Object.defineProperty(input[field], '0', { enumerable: true, get() { called = true; return input.node; } });
    assert.throws(() => decodeGuestToolchainManifest(input));
    assert.equal(called, false);
  }
});

test('a newly signed bundle cannot omit, retarget or add a guest closure member', () => {
  for (const mutate of [
    (v: ReturnType<typeof fixture>) => { v.root.memberRefs.pop(); },
    (v: ReturnType<typeof fixture>) => { v.root.semanticDigest = v.manifestRef; },
    (v: ReturnType<typeof fixture>) => { v.bundle.guestToolchainManifestRefs = []; },
    (v: ReturnType<typeof fixture>) => { v.root.memberRefs.push('f'.repeat(64)); v.root.memberRefs.sort(); },
    (v: ReturnType<typeof fixture>) => { v.bundle.entries.find(e => e.digest === v.manifest.guestImageRef)!.relativePath = 'unsigned/image'; },
  ]) {
    const value = fixture(); mutate(value); value.resign();
    assert.throws(() => validateGuestToolchainMetadata(value.bundle, value.manifestRef, value.manifestBytes, value.signature, value.releaseKeys));
  }
});

test('retained guest selection exhausts the actual image CAS stream and never resolves today\'s install', async () => {
  const value = fixture(), directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-guest-retained-'));
  const root = path.join(directory, 'cas');
  try {
    await mkdir(root, { mode: 0o700 });
    const artifacts = new ArtifactCatalog(new ContentAddressedStore(root));
    for (const bytes of [value.manifestBytes, value.signature, value.image]) await artifacts.publishBytes(bytes, 'application/octet-stream', 'guest-data-test');
    const selected = await readRetainedVerifierToolchain(artifacts, { bundle: value.bundle, releaseKeys: value.releaseKeys,
      guestToolchainManifestId: value.root.artifactId, guestToolchainManifestRef: value.manifestRef });
    assert.equal(selected.manifestRef, value.manifestRef);
    await assert.rejects(readRetainedVerifierToolchain(artifacts, { bundle: value.bundle, releaseKeys: value.releaseKeys,
      guestToolchainManifestId: value.root.rootEntryId }));
    await chmod(path.join(root, value.manifest.guestImageRef), 0o600);
    await writeFile(path.join(root, value.manifest.guestImageRef), Buffer.alloc(value.image.length));
    await chmod(path.join(root, value.manifest.guestImageRef), 0o400);
    await assert.rejects(readRetainedVerifierToolchain(artifacts, { bundle: value.bundle, releaseKeys: value.releaseKeys,
      guestToolchainManifestId: value.root.artifactId }));
  } finally { await rm(directory, { recursive: true, force: true }); }
});
