import { isProxy } from 'node:util/types';
import { assertControlWireJson } from '../kernel/control-wire-data.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { decodeEndpointRegistration, type EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import type { RuntimeBundleManifest, ReleaseTrustKey } from '../policy/runtime-authority.js';
import { verifyRuntimeBundle } from '../policy/runtime-authority.js';
import { sha256Bytes } from '../kernel/identity.js';
import { checkCanonicalBytes, validateBundle, validateTrustStore } from './installed-artifacts.js';
import { assertSignedKernelSchemaEntry, decodeSchemaConversion, decodeSignedKernelSchema } from './signed-schema.js';

/** Pure retained-data audit only. Trusted keys and current bundle are supplied
 * solely by the original held installation, never learned from retained data.
 * This does not create a selection, lock, credential grant or release permit. */
export function verifyRetainedInstalledEndpointData(input: {
  currentBundle: RuntimeBundleManifest;
  releaseKeys: readonly ReleaseTrustKey[];
  registration: EndpointRegistrationV1;
  originalBundleBytes: Buffer;
  originalTrustStoreBytes: Buffer;
  currentSchemaBytes?: Buffer;
  currentConversionBytes?: Buffer;
}): Readonly<{ bundle: RuntimeBundleManifest; supervisorImageDigest: string }> {
  if (!input || typeof input !== 'object' || isProxy(input) || Array.isArray(input) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(input)))
    throw new TypeError('retained installed data input is not a plain record');
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const required = ['currentBundle', 'releaseKeys', 'registration', 'originalBundleBytes', 'originalTrustStoreBytes'];
  const optional = ['currentSchemaBytes', 'currentConversionBytes'];
  if (required.some(key => !Object.hasOwn(descriptors, key)) || Reflect.ownKeys(descriptors).some(key =>
    typeof key !== 'string' || !required.includes(key) && !optional.includes(key) || !('value' in descriptors[key]!)))
    throw new TypeError('retained installed data contains unknown fields or accessors');
  const { currentBundle, releaseKeys, registration } = input;
  assertControlWireJson(currentBundle); assertControlWireJson(registration); assertControlWireJson(releaseKeys);
  decodeEndpointRegistration(registration);
  verifyRuntimeBundle(currentBundle, releaseKeys);
  const data = (bytes: Buffer | undefined, maximum = 1_048_576): Buffer => {
    if (!bytes || isProxy(bytes) || !Buffer.isBuffer(bytes) || bytes.length > maximum)
      throw new TypeError('retained installed data is not a bounded original byte buffer');
    return Buffer.from(bytes);
  };
  const bundleBytes = data(input.originalBundleBytes);
  const bundle = validateBundle(checkCanonicalBytes(bundleBytes), releaseKeys);
  const tls = registration.tls;
  if (sha256Bytes(bundleBytes) !== tls.trustStoreRuntimeBundleRef || bundle.manifestDigest !== tls.trustStoreRuntimeBundleManifestDigest)
    throw new TypeError('retained endpoint differs from its original signed bundle');
  const supervisor = bundle.entries.filter(entry => entry.role === 'supervisor');
  if (supervisor.length !== 1 || !supervisor[0]!.executable)
    throw new TypeError('retained endpoint has no exact original signed producer image');
  if (tls.trustStoreRuntimeBundleRef !== canonicalSha256(currentBundle)) {
    // This is the one published transition implemented by I4. A broad version
    // range or any other retained signed bundle is not an upgrade source.
    if (bundle.publisherKeyId !== currentBundle.publisherKeyId)
      throw new TypeError('retained endpoint and selected conversion have different publishers');
    assertSignedKernelSchemaEntry(currentBundle);
    const schema = currentBundle.entries.filter(entry => entry.entryId === 'kernel_schema');
    const conversions = currentBundle.entries.filter(entry => entry.entryId === 'schema_conversion');
    if (schema.length !== 1 || conversions.length !== 1) throw new TypeError('retained endpoint has no exact selected conversion');
    const conversion = conversions[0]!;
    if (conversion.role !== 'schema' || conversion.executable || conversion.version !== '7-to-8' ||
        conversion.relativePath !== 'schema/convert-v7-to-v8.json')
      throw new TypeError('retained endpoint conversion entry differs');
    const schemaBytes = data(input.currentSchemaBytes), conversionBytes = data(input.currentConversionBytes);
    if (schemaBytes.length !== schema[0]!.byteCount || sha256Bytes(schemaBytes) !== schema[0]!.digest ||
        conversionBytes.length !== conversion.byteCount || sha256Bytes(conversionBytes) !== conversion.digest)
      throw new TypeError('retained endpoint conversion bytes differ from their signed entries');
    const target = decodeSignedKernelSchema(checkCanonicalBytes(schemaBytes));
    const original = decodeSchemaConversion(checkCanonicalBytes(conversionBytes), bundle);
    if (original.targetSchemaRef !== canonicalSha256(target) || original.targetSchemaDigest !== target.profileDigest)
      throw new TypeError('retained endpoint conversion does not name the full selected target schema');
  } else if (!canonicalJsonBytes(bundle).equals(canonicalJsonBytes(currentBundle))) {
    throw new TypeError('retained current endpoint bundle differs');
  }
  const entries = bundle.entries.filter(entry => entry.entryId === 'default_https_trust_store');
  const entry = entries[0];
  if (entries.length !== 1 || !entry || entry.role !== 'trust_store' || entry.executable ||
      entry.digest !== tls.trustStoreRef || entry.digest !== tls.trustStoreDigest)
    throw new TypeError('retained endpoint trust store differs from its original signed entry');
  const trustBytes = data(input.originalTrustStoreBytes, 16 * 1_048_576);
  if (trustBytes.length !== entry.byteCount || sha256Bytes(trustBytes) !== entry.digest)
    throw new TypeError('retained endpoint trust store bytes differ');
  validateTrustStore(trustBytes);
  return Object.freeze({ bundle, supervisorImageDigest: supervisor[0]!.digest });
}

/** Leaf data check used only after the original endpoint source was fully
 * audited. A historical revocation by the current producer must still retain
 * its own original signed bundle; the present package cannot replace it. */
export function verifyRetainedInstalledCurrentProducerData(currentBundle: RuntimeBundleManifest,
  releaseKeys: readonly ReleaseTrustKey[], originalBundleBytes: Buffer, imageDigest: string): void {
  assertControlWireJson(currentBundle); assertControlWireJson(releaseKeys);
  verifyRuntimeBundle(currentBundle, releaseKeys);
  if (!originalBundleBytes || isProxy(originalBundleBytes) || !Buffer.isBuffer(originalBundleBytes) ||
      originalBundleBytes.length > 1_048_576 || typeof imageDigest !== 'string' || !/^[0-9a-f]{64}$/u.test(imageDigest))
    throw new TypeError('retained current producer data is not bounded original data');
  const bundle = validateBundle(checkCanonicalBytes(Buffer.from(originalBundleBytes)), releaseKeys);
  const supervisors = bundle.entries.filter(entry => entry.role === 'supervisor');
  if (!canonicalJsonBytes(bundle).equals(canonicalJsonBytes(currentBundle)) || supervisors.length !== 1 ||
      !supervisors[0]!.executable || supervisors[0]!.digest !== imageDigest)
    throw new TypeError('retained current producer differs from its exact original signed bundle');
}
