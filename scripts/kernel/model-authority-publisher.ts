// Package-build only. Signed publisher input is not evidence that a provider
// actually implements its advertised tools, usage or complete billing ceiling.
import { createPublicKey, sign, type KeyObject } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { sha256Bytes } from '../../src/kernel/identity.js';
import type { ProviderName } from '../../src/kernel/types.js';
import type { NormalizedModelCapabilityClaimsV1 } from '../../src/model/capabilities.js';
import { verifyInstalledModelAuthority, type InstalledModelAuthorityClosureV1,
  type SignedModelCatalogEntryV1 } from '../../src/model/installed-authority.js';
import { priceTableDigest, type ModelPriceTableV1, type ModelTokenComponents,
  type ModelTokenPrices } from '../../src/model/pricing.js';
import { verifyRuntimeBundle, type RuntimeBundleManifest } from '../../src/policy/runtime-authority.js';

export type PublishedModelDefinition = Readonly<{
  provider: Exclude<ProviderName, 'ollama'>;
  model: string;
  endpointIdentityDigest: string;
  adapterEntryId: string;
  claims: NormalizedModelCapabilityClaimsV1;
  prices: ModelTokenPrices;
  requestTokenCeiling: ModelTokenComponents;
  validFrom: string;
  validThrough: string;
}>;

/** Use the same package publisher, signed RuntimeBundle and existing companion
 * format for real providers and owned fixtures. Every price and ceiling is
 * explicit; no API call, key storage, endpoint registration or zero-price
 * fallback is performed. The installer still authenticates the whole closure. */
export function buildInstalledModelAuthority(input: {
  bundle: RuntimeBundleManifest;
  privateKey: KeyObject;
  models: readonly PublishedModelDefinition[];
}) {
  if (input.privateKey.type !== 'private' || input.privateKey.asymmetricKeyType !== 'ed25519')
    throw new TypeError('model authority requires the package Ed25519 private key');
  const { bundle } = input;
  const releaseKeys = [{ keyId: bundle.publisherKeyId,
    publicKeyPem: createPublicKey(input.privateKey).export({ type: 'spki', format: 'pem' }).toString() }];
  verifyRuntimeBundle(bundle, releaseKeys);
  if (!Array.isArray(input.models) || input.models.length < 1 || input.models.length > 32)
    throw new TypeError('model authority requires one to thirty-two explicit model definitions');
  const runtimeBundleRef = canonicalSha256(bundle);
  type ObjectKind = InstalledModelAuthorityClosureV1['objects'][number]['kind'];
  const objects = new Map<string, { bytes: Buffer; kind: ObjectKind }>();
  const retain = (bytes: Buffer, kind: ObjectKind) => {
    const ref = sha256Bytes(bytes), previous = objects.get(ref);
    if (previous && (previous.kind !== kind || !previous.bytes.equals(bytes)))
      throw new TypeError('model authority object identity is inconsistent');
    if (!previous) objects.set(ref, { bytes, kind });
    return ref;
  };
  const signature = (domain: string, digest: string) =>
    retain(sign(null, Buffer.from(`${domain}\0${digest}`, 'utf8'), input.privateKey), 'ed25519_signature');
  const tuples = new Set<string>();
  for (const model of input.models) {
    const tuple = canonicalJsonBytes([model.provider, model.model, model.endpointIdentityDigest]).toString('utf8');
    if (tuples.has(tuple)) throw new TypeError('model authority definition tuple is duplicated');
    tuples.add(tuple);
    const adapter = bundle.entries.find(entry => entry.entryId === model.adapterEntryId);
    if (!adapter?.executable || adapter.role !== 'provider_adapter')
      throw new TypeError('model authority adapter is not its signed executable');
    const catalogCore = { schemaVersion: 1 as const, format: 'cliq-signed-model-catalog-entry-v1' as const,
      signerKeyId: bundle.publisherKeyId, signatureAlgorithm: 'ed25519' as const, runtimeBundleRef,
      runtimeBundleManifestDigest: bundle.manifestDigest, provider: model.provider, model: model.model,
      endpointIdentityDigest: model.endpointIdentityDigest,
      adapter: { adapterId: adapter.entryId, version: adapter.version, codeDigest: adapter.digest },
      claims: { ...model.claims }, validFrom: model.validFrom, validThrough: model.validThrough };
    const catalogEntryDigest = canonicalSha256(catalogCore);
    const catalog: SignedModelCatalogEntryV1 = { ...catalogCore, catalogEntryDigest,
      signatureRef: signature('cliq-model-catalog-entry-v1', catalogEntryDigest) };
    retain(canonicalJsonBytes(catalog), 'model_catalog_entry');
    const table: ModelPriceTableV1 = { schemaVersion: 1, format: 'cliq-model-price-table-v1',
      signerKeyId: bundle.publisherKeyId, signatureAlgorithm: 'ed25519', signatureRef: '',
      provider: model.provider, model: model.model, endpointIdentityDigest: model.endpointIdentityDigest,
      currency: 'USD', unit: 'micros_per_million_tokens', prices: { ...model.prices },
      requestTokenCeiling: { ...model.requestTokenCeiling }, validFrom: model.validFrom,
      validThrough: model.validThrough, tableDigest: '' };
    table.tableDigest = priceTableDigest(table);
    table.signatureRef = signature('cliq-model-price-table-v1', table.tableDigest);
    retain(canonicalJsonBytes(table), 'model_price_table');
    if (table.requestTokenCeiling.inputTokens < catalog.claims.contextLimitTokens ||
        table.requestTokenCeiling.outputTokens < catalog.claims.maxOutputTokens)
      throw new TypeError('model authority billing ceiling does not cover its advertised model limits');
  }
  const inventory = [...objects].sort(([left], [right]) => left < right ? -1 : 1)
    .map(([artifactRef, object]) => ({ artifactRef, byteCount: object.bytes.byteLength, kind: object.kind }));
  const core = { schemaVersion: 1 as const, format: 'cliq-installed-model-authority-v1' as const,
    publisherKeyId: bundle.publisherKeyId, signatureAlgorithm: 'ed25519' as const, runtimeBundleRef,
    runtimeBundleManifestDigest: bundle.manifestDigest, objects: inventory };
  const closureDigest = canonicalSha256(core);
  const closure: InstalledModelAuthorityClosureV1 = { ...core, closureDigest,
    signature: sign(null, Buffer.from(`cliq-installed-model-authority-v1\0${closureDigest}`, 'utf8'), input.privateKey).toString('base64') };
  const verified = verifyInstalledModelAuthority({ closure, bundle, releaseKeys,
    objects: new Map([...objects].map(([ref, object]) => [ref, object.bytes])) });
  return { closure: verified.closure, models: verified.models, objects };
}
