// Signature and source identity only. This verification creates no installed
// handle, model-store lock, activation, native boundary or dispatch authority.
import { createPublicKey, verify } from 'node:crypto';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeLocalModelManifest, type LocalModelManifestV1 } from '../kernel/local-inference.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from './runtime-authority.js';

export const LOCAL_MODEL_SIGNATURE_DOMAIN = 'cliq-local-model-manifest-v1';

/** The original embedded release publisher is the first fixed model-trust
 * profile. Neither an enrollment package nor a Run can introduce a key. */
export function verifyLocalModelManifestAuthority(input: Readonly<{
  bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[];
  manifestBytes: Buffer; signatureBytes: Buffer;
}>): LocalModelManifestV1 {
  verifyRuntimeBundle(input.bundle, input.releaseKeys);
  if (!Buffer.isBuffer(input.manifestBytes) || input.manifestBytes.byteLength < 1 || input.manifestBytes.byteLength > 1_048_576 ||
      !Buffer.isBuffer(input.signatureBytes) || input.signatureBytes.byteLength !== 64)
    throw new TypeError('local model requires its complete bounded manifest and detached 64-byte signature');
  const parsed: unknown = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(input.manifestBytes));
  const manifest = decodeLocalModelManifest(parsed);
  if (!canonicalJsonBytes(manifest).equals(input.manifestBytes) || sha256Bytes(input.signatureBytes) !== manifest.signatureRef ||
      manifest.signerKeyId !== input.bundle.publisherKeyId)
    throw new TypeError('local model source bytes or original bundled publisher differ');
  const selected = input.releaseKeys.filter(key => key.keyId === manifest.signerKeyId);
  if (selected.length !== 1) throw new TypeError('local model has no unique original bundled trust key');
  const key = createPublicKey(selected[0]!.publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519' || !verify(null,
    Buffer.from(`${LOCAL_MODEL_SIGNATURE_DOMAIN}\0${manifest.modelManifestDigest}`, 'utf8'), key, input.signatureBytes))
    throw new TypeError('local model detached signature is invalid');
  const bootstrap = input.bundle.entries.filter(entry => entry.entryId === 'ollama_local_inference');
  if (bootstrap.length !== 1 || bootstrap[0]!.role !== 'local_inference' || !bootstrap[0]!.executable || bootstrap[0]!.byteCount < 1)
    throw new TypeError('local model requires its one exact signed managed bootstrap');
  return manifest;
}
