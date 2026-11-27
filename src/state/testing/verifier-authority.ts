import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import type { GuestToolchainManifest } from '../../kernel/execution.js';
import { identityHash, sha256Bytes } from '../../kernel/identity.js';
import { testFixture } from '../../model/testing/fixtures.js';
import type { RuntimeBundleManifest } from '../../policy/runtime-authority.js';
import { signedToolBundle } from './tool-authority.js';

/** Actual Ed25519 verification and retained CAS bytes only. The opaque image
 * is deliberately not an ext4/ELF execution or installed qualification. */
export async function signedVerifierAuthority(options: { imageByteCount?: number; builtinScriptBytes?: Buffer } = {}) {
  const assembly = testFixture().assembly;
  const prior = await signedToolBundle(assembly, []);
  const keys = generateKeyPairSync('ed25519');
  const prefix = Buffer.from('offline signed verifier image; never execute or mount\n');
  const image = options.imageByteCount === undefined ? prefix : Buffer.alloc(options.imageByteCount, 0);
  if (image.length < prefix.length) throw new TypeError('offline image must preserve its non-execution fixture label');
  prefix.copy(image);
  const imageRef = sha256Bytes(image);
  const executable = (logicalName: string) => ({ logicalName, canonicalGuestPath: logicalName === 'node' ? '/usr/bin/node' : `/opt/cliq/bin/${logicalName}`,
    version: '1', digest: canonicalSha256({ offlineVerifierExecutable: logicalName }) });
  const manifest: GuestToolchainManifest = { schemaVersion: 1, format: 'cliq-guest-toolchain-v1', guestImageRef: imageRef,
    guestImageDigest: imageRef, guestImageByteCount: image.length, guestImageFormat: 'raw-ext4-v1', architecture: 'x86_64',
    kernelAbi: 'offline-linux-abi', userspaceAbi: 'offline-userspace-abi', worker: executable('worker'), shell: executable('sh'),
    git: executable('git'), node: executable('node'), searchTools: [], verifiers: [],
    admittedExecutables: options.builtinScriptBytes ? [{ ...executable('bash'), canonicalGuestPath: '/bin/bash' }] : [],
    publisherKeyId: 'offline-verifier-release', manifestDigest: '', signatureRef: '' };
  const { manifestDigest: _manifest, signatureRef: _signature, ...core } = manifest;
  manifest.manifestDigest = canonicalSha256(core);
  const signature = sign(null, Buffer.from(`cliq-guest-toolchain-v1\0${manifest.manifestDigest}`), keys.privateKey);
  manifest.signatureRef = sha256Bytes(signature);
  const manifestBytes = canonicalJsonBytes(manifest), manifestRef = sha256Bytes(manifestBytes), manifestId = 'offline-node-toolchain';
  const objects = [{ ref: imageRef, bytes: image }, { ref: manifest.signatureRef, bytes: signature }];
  if (options.builtinScriptBytes && (!Buffer.isBuffer(options.builtinScriptBytes) || !options.builtinScriptBytes.length ||
      options.builtinScriptBytes.length > 1_048_576)) throw new TypeError('offline builtin script bytes exceed the fixed signed data bound');
  const bundle: RuntimeBundleManifest = { ...prior.bundle, publisherKeyId: manifest.publisherKeyId, entries: [...prior.bundle.entries,
    ...(options.builtinScriptBytes ? [{ entryId: 'builtin_tools', role: 'tool_adapter', version: '1',
      relativePath: 'adapters/builtin-tools.mjs', executable: false, digest: sha256Bytes(options.builtinScriptBytes), byteCount: options.builtinScriptBytes.length }] : []),
    { entryId: 'offline-guest-root-entry', role: 'guest_toolchain', version: '1', relativePath: 'profiles/guest.json',
      executable: false, digest: manifestRef, byteCount: manifestBytes.length }, ...objects.map(({ ref, bytes }) => ({
      entryId: identityHash('runtime-bundle-object-v1', ref), role: 'bundle_object', version: '1',
      relativePath: `objects/sha256/${ref.slice(0, 2)}/${ref}`, executable: false, digest: ref, byteCount: bytes.length }))],
    structuredArtifacts: [...prior.bundle.structuredArtifacts, { kind: 'guest_toolchain', artifactId: manifestId,
      rootEntryId: 'offline-guest-root-entry', artifactRef: manifestRef, semanticDigest: manifest.manifestDigest,
      memberRefs: objects.map(object => object.ref).sort() }].sort((a, b) => Buffer.compare(Buffer.from(a.kind), Buffer.from(b.kind))),
    guestToolchainManifestRefs: [manifestRef], manifestDigest: '', signature: '' };
  const { signature: _bundleSignature, manifestDigest: _bundleDigest, ...bundleCore } = bundle;
  bundle.manifestDigest = canonicalSha256(bundleCore);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  return { bundle, manifest, manifestRef, manifestId, objects: [...objects, { ref: manifestRef, bytes: manifestBytes },
    ...(options.builtinScriptBytes ? [{ ref: sha256Bytes(options.builtinScriptBytes), bytes: options.builtinScriptBytes }] : []),
    { ref: canonicalSha256(prior.profile), bytes: canonicalJsonBytes(prior.profile) }],
    releaseKeys: [{ keyId: bundle.publisherKeyId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }] };
}
