import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { sha256Bytes } from '../../kernel/identity.js';
import { signedVerifierAuthority } from './verifier-authority.js';

/** Real Ed25519 test-root metadata only; no installed/native qualification. */
export async function signedSourceInspectionMetadata() {
  const prior = await signedVerifierAuthority(), keys = generateKeyPairSync('ed25519');
  const bytes = Buffer.from('offline inspection metadata fixture; not a native or executable inspector\n');
  const entry = { entryId: 'source_git_inspector', role: 'platform_helper', version: '1',
    relativePath: 'helpers/source-git-inspector.mjs', executable: false, digest: sha256Bytes(bytes), byteCount: bytes.length };
  const bundle = { ...prior.bundle, publisherKeyId: 'offline-inspection-release', entries: [...prior.bundle.entries, entry], manifestDigest: '', signature: '' };
  const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  return { bundle, releaseKeys: [...prior.releaseKeys, { keyId: bundle.publisherKeyId,
    publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }], objects: [...prior.objects, { ref: entry.digest, bytes }] };
}
