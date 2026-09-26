import { canonicalJsonBytes } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { verifyBundleStructuredPayloads, type BundleEntryReader } from './structured-payloads.js';

const MAX_MANIFEST_BYTES = 1_048_576;
const strictUtf8 = new TextDecoder('utf-8', { fatal: true });

/** Decode the exact signed manifest bytes before any installer path is selected. */
export function decodeSignedRuntimeBundle(bytes: Uint8Array, releaseKeys: readonly ReleaseTrustKey[]): {
  bundle: RuntimeBundleManifest;
  bundleRef: string;
} {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0 || bytes.byteLength > MAX_MANIFEST_BYTES) {
    throw new TypeError('RuntimeBundle manifest byte count is invalid');
  }
  const snapshot = Buffer.from(bytes);
  let value: unknown;
  try {
    value = JSON.parse(strictUtf8.decode(snapshot));
  } catch (error) {
    throw new TypeError('RuntimeBundle manifest is not valid UTF-8 JSON', { cause: error });
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      !canonicalJsonBytes(value).equals(snapshot)) {
    throw new TypeError('RuntimeBundle manifest is not byte-exact canonical JSON');
  }
  const bundle = value as RuntimeBundleManifest;
  verifyRuntimeBundle(bundle, releaseKeys);
  for (const range of [bundle.controlProtocolRange, bundle.headlessSchemaRange,
    bundle.stateSchemaRange, bundle.workerProtocolRange]) Object.freeze(range);
  for (const entry of bundle.entries) Object.freeze(entry);
  for (const artifact of bundle.structuredArtifacts) {
    Object.freeze(artifact.memberRefs);
    Object.freeze(artifact);
  }
  Object.freeze(bundle.entries);
  Object.freeze(bundle.structuredArtifacts);
  Object.freeze(bundle.guestToolchainManifestRefs);
  Object.freeze(bundle);
  return { bundle, bundleRef: sha256Bytes(snapshot) };
}

/** Byte and semantic gate for a held package reader; installation still owns descriptor safety and CAS publication. */
export async function verifySignedRuntimeBundlePayloads(bytes: Uint8Array,
  releaseKeys: readonly ReleaseTrustKey[], readEntry: BundleEntryReader): Promise<{
    bundle: RuntimeBundleManifest;
    bundleRef: string;
  }> {
  const decoded = decodeSignedRuntimeBundle(bytes, releaseKeys);
  await verifyBundleStructuredPayloads(decoded.bundle, releaseKeys, readEntry);
  return decoded;
}
