// Secret-free signed discovery/import data. These decoders do not mint an
// installed handle, endpoint authority, credential scope, or billing proof.
import { createPublicKey, verify } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, normalizeBoundedText, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { ArtifactRef, ProviderName } from '../kernel/types.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import type { NormalizedModelCapabilityClaimsV1, ProviderAdapterIdentity } from './capabilities.js';
import { immutableSnapshot } from './immutable.js';
import { priceTableDigest, type ModelPriceTableV1 } from './pricing.js';

type RemoteProvider = Exclude<ProviderName, 'ollama'>;
export type SignedModelCatalogEntryV1 = {
  schemaVersion: 1; format: 'cliq-signed-model-catalog-entry-v1'; signerKeyId: string;
  signatureAlgorithm: 'ed25519'; signatureRef: ArtifactRef;
  runtimeBundleRef: ArtifactRef; runtimeBundleManifestDigest: string;
  provider: RemoteProvider; model: string; endpointIdentityDigest: string;
  adapter: ProviderAdapterIdentity; claims: NormalizedModelCapabilityClaimsV1;
  validFrom: string; validThrough: string; catalogEntryDigest: string;
};
export type InstalledModelAuthorityClosureV1 = {
  schemaVersion: 1; format: 'cliq-installed-model-authority-v1'; publisherKeyId: string;
  signatureAlgorithm: 'ed25519'; runtimeBundleRef: ArtifactRef; runtimeBundleManifestDigest: string;
  objects: Array<{ artifactRef: ArtifactRef; byteCount: number;
    kind: 'model_catalog_entry' | 'model_price_table' | 'ed25519_signature' }>;
  closureDigest: string; signature: string;
};
export type VerifiedInstalledModelAuthority = Readonly<{
  closureRef: ArtifactRef; closure: InstalledModelAuthorityClosureV1;
  models: readonly Readonly<{ catalog: Readonly<{ ref: ArtifactRef; value: SignedModelCatalogEntryV1 }>;
    priceTable: Readonly<{ ref: ArtifactRef; value: ModelPriceTableV1 }> }>[];
}>;
export type VerifiedModelAuthorityPair = VerifiedInstalledModelAuthority['models'][number];

const MAX_OBJECTS = 128, MAX_MODELS = 32, MAX_BYTES = 8 * 1024 * 1024, DATA_BYTES = 65536;
const REMOTE_PROVIDERS = ['openai', 'anthropic', 'openrouter', 'openai-compatible', 'zhipu'];
function closed(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Reflect.ownKeys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(property => !Object.hasOwn(property, 'value')))
    throw new TypeError('installed model authority has an invalid closed shape');
  return value as Record<string, unknown>;
}
function text(value: unknown): string {
  if (typeof value !== 'string' || normalizeBoundedText(value, 1, 512) !== value)
    throw new TypeError('installed model authority text is invalid');
  return value;
}
function ref(value: unknown): string {
  if (typeof value !== 'string') throw new TypeError('installed model authority reference is invalid');
  assertArtifactRef(value); return value;
}
function integer(value: unknown, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum)
    throw new TypeError('installed model authority integer is invalid');
  return value;
}
function interval(value: Record<string, unknown>): void {
  if (typeof value.validFrom !== 'string' || typeof value.validThrough !== 'string' ||
      parseCanonicalTime(value.validFrom) > parseCanonicalTime(value.validThrough))
    throw new TypeError('installed model authority validity is invalid');
}
function publicKey(bundle: RuntimeBundleManifest, keys: readonly ReleaseTrustKey[]) {
  verifyRuntimeBundle(bundle, keys);
  const selected = keys.filter(key => key.keyId === bundle.publisherKeyId);
  if (selected.length !== 1) throw new TypeError('installed model authority signer is ambiguous');
  const key = createPublicKey(selected[0]!.publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') throw new TypeError('installed model authority signer is not Ed25519');
  return key;
}
function signed(domain: string, digest: string, signature: Buffer, key: ReturnType<typeof publicKey>): void {
  if (signature.byteLength !== 64 || !verify(null, Buffer.from(`${domain}\0${digest}`, 'utf8'), key, signature))
    throw new TypeError('installed model authority signature is invalid');
}
function canonical(bytes: Buffer): unknown {
  if (bytes.byteLength > DATA_BYTES) throw new TypeError('installed model authority data exceeds its byte limit');
  const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!canonicalJsonBytes(value).equals(bytes)) throw new TypeError('installed model authority bytes are not canonical');
  return value;
}

function authorityObject(kind: 'model_catalog_entry' | 'model_price_table', artifactRef: string, bytes: Buffer,
  bundle: RuntimeBundleManifest, key: ReturnType<typeof publicKey>, signature: (reference: unknown) => Buffer) {
  if (!Buffer.isBuffer(bytes) || sha256Bytes(bytes) !== ref(artifactRef))
    throw new TypeError('installed model authority object bytes do not rehash');
  const catalog = kind === 'model_catalog_entry';
  const value = closed(canonical(bytes), catalog ? ['schemaVersion', 'format', 'signerKeyId', 'signatureAlgorithm', 'signatureRef',
    'runtimeBundleRef', 'runtimeBundleManifestDigest', 'provider', 'model', 'endpointIdentityDigest', 'adapter', 'claims',
    'validFrom', 'validThrough', 'catalogEntryDigest'] : ['schemaVersion', 'format', 'signerKeyId', 'signatureAlgorithm',
    'signatureRef', 'provider', 'model', 'endpointIdentityDigest', 'currency', 'unit', 'prices', 'requestTokenCeiling',
    'validFrom', 'validThrough', 'tableDigest']);
  if (value.schemaVersion !== 1 || value.format !== (catalog ? 'cliq-signed-model-catalog-entry-v1' : 'cliq-model-price-table-v1') ||
      text(value.signerKeyId) !== bundle.publisherKeyId || value.signatureAlgorithm !== 'ed25519' ||
      !REMOTE_PROVIDERS.includes(text(value.provider))) throw new TypeError('installed model authority object identity is invalid');
  const tuple = canonicalJsonBytes([value.provider, text(value.model), ref(value.endpointIdentityDigest)]).toString('utf8');
  interval(value);
  if (catalog) {
    if (ref(value.runtimeBundleRef) !== canonicalSha256(bundle) || ref(value.runtimeBundleManifestDigest) !== bundle.manifestDigest)
      throw new TypeError('installed model catalog belongs to another RuntimeBundle');
    const adapter = closed(value.adapter, ['adapterId', 'version', 'codeDigest']);
    const entry = bundle.entries.find(entry => entry.entryId === text(adapter.adapterId));
    if (!entry?.executable || entry.role !== 'provider_adapter' || entry.version !== text(adapter.version) || entry.digest !== ref(adapter.codeDigest))
      throw new TypeError('installed model catalog adapter is not its signed executable');
    const claims = closed(value.claims, ['nativeToolCalling', 'streaming', 'trustedUsageEvidence', 'contextLimitTokens', 'maxOutputTokens']);
    if (['nativeToolCalling', 'streaming', 'trustedUsageEvidence'].some(field => typeof claims[field] !== 'boolean') ||
        integer(claims.contextLimitTokens, 32768) < 32768 || integer(claims.maxOutputTokens, 1) > Math.floor(Number(claims.contextLimitTokens) / 4))
      throw new TypeError('installed model catalog claims are invalid');
    const { catalogEntryDigest: _digest, signatureRef: _signature, ...core } = value;
    const digest = ref(value.catalogEntryDigest);
    if (canonicalSha256(core) !== digest) throw new TypeError('installed model catalog semantic digest does not rehash');
    signed('cliq-model-catalog-entry-v1', digest, signature(value.signatureRef), key);
  } else {
    if (value.currency !== 'USD' || value.unit !== 'micros_per_million_tokens') throw new TypeError('installed model pricing units are invalid');
    const prices = closed(value.prices, ['input', 'output', 'cacheRead', 'cacheWrite']);
    Object.values(prices).forEach(rate => integer(rate));
    const ceiling = closed(value.requestTokenCeiling, ['inputTokens', 'outputTokens', 'cacheReadTokens', 'cacheWriteTokens']);
    Object.values(ceiling).forEach(tokens => integer(tokens));
    if (!Number.isSafeInteger(integer(ceiling.inputTokens, 1) + integer(ceiling.outputTokens, 1)))
      throw new TypeError('installed model price ceiling arithmetic is invalid');
    const digest = ref(value.tableDigest);
    if (priceTableDigest(value as unknown as ModelPriceTableV1) !== digest) throw new TypeError('installed model price semantic digest does not rehash');
    signed('cliq-model-price-table-v1', digest, signature(value.signatureRef), key);
  }
  return { tuple, ref: artifactRef, value };
}

/** Reauthenticate an admitted pair from its immutable CAS closure. Discovery
 * companion replacement/removal cannot change historical Run authority. */
export function verifyRetainedModelAuthorityPair(input: {
  bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[];
  catalogEntryRef: ArtifactRef; priceTableRef: ArtifactRef; objects: ReadonlyMap<string, Buffer>;
}): VerifiedModelAuthorityPair {
  const key = publicKey(input.bundle, input.releaseKeys), used = new Set([ref(input.catalogEntryRef), ref(input.priceTableRef)]);
  const signature = (reference: unknown): Buffer => {
    const digest = ref(reference), bytes = input.objects.get(digest);
    if (!Buffer.isBuffer(bytes) || bytes.byteLength !== 64) throw new TypeError('installed model authority detached signature is absent');
    if (sha256Bytes(bytes) !== digest) throw new TypeError('installed model authority object bytes do not rehash');
    used.add(digest); return bytes;
  };
  const catalog = authorityObject('model_catalog_entry', input.catalogEntryRef, input.objects.get(input.catalogEntryRef)!, input.bundle, key, signature);
  const priceTable = authorityObject('model_price_table', input.priceTableRef, input.objects.get(input.priceTableRef)!, input.bundle, key, signature);
  if (catalog.tuple !== priceTable.tuple) throw new TypeError('installed model authority lacks exact catalog/price pairing');
  if (input.objects.size !== used.size || [...input.objects.keys()].some(reference => !used.has(reference)))
    throw new TypeError('retained model authority contains missing or extra objects');
  return immutableSnapshot({ catalog: { ref: catalog.ref, value: catalog.value as unknown as SignedModelCatalogEntryV1 },
    priceTable: { ref: priceTable.ref, value: priceTable.value as unknown as ModelPriceTableV1 } });
}

/** Authenticate the bounded inventory before the installer opens its members.
 * Physical descriptor ownership is still the installed producer's duty. */
export function decodeInstalledModelAuthorityClosure(value: unknown,
  input: { bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[] }): InstalledModelAuthorityClosureV1 {
  const key = publicKey(input.bundle, input.releaseKeys);
  const closure = closed(value, ['schemaVersion', 'format', 'publisherKeyId', 'signatureAlgorithm', 'runtimeBundleRef',
    'runtimeBundleManifestDigest', 'objects', 'closureDigest', 'signature']);
  if (closure.schemaVersion !== 1 || closure.format !== 'cliq-installed-model-authority-v1' ||
      closure.signatureAlgorithm !== 'ed25519' || text(closure.publisherKeyId) !== input.bundle.publisherKeyId ||
      ref(closure.runtimeBundleRef) !== canonicalSha256(input.bundle) ||
      ref(closure.runtimeBundleManifestDigest) !== input.bundle.manifestDigest ||
      !Array.isArray(closure.objects) || closure.objects.length < 3 || closure.objects.length > MAX_OBJECTS ||
      canonicalJsonBytes(closure).byteLength > 1024 * 1024)
    throw new TypeError('installed model authority does not bind its signed RuntimeBundle');
  let previous = '', count = 0;
  for (const candidate of closure.objects) {
    const object = closed(candidate, ['artifactRef', 'byteCount', 'kind']);
    const digest = ref(object.artifactRef), byteCount = integer(object.byteCount, 1);
    if (digest <= previous || typeof object.kind !== 'string' || !['model_catalog_entry', 'model_price_table', 'ed25519_signature'].includes(object.kind) ||
        (object.kind === 'ed25519_signature' ? byteCount !== 64 : byteCount > DATA_BYTES) || (count += byteCount) > MAX_BYTES)
      throw new TypeError('installed model authority inventory is invalid');
    previous = digest;
  }
  const digest = ref(closure.closureDigest);
  const { closureDigest: _digest, signature: _signature, ...core } = closure;
  if (canonicalSha256(core) !== digest || typeof closure.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/u.test(closure.signature))
    throw new TypeError('installed model authority closure digest or signature encoding is invalid');
  const signature = Buffer.from(closure.signature, 'base64');
  if (signature.toString('base64') !== closure.signature) throw new TypeError('installed model authority signature encoding is not canonical');
  signed('cliq-installed-model-authority-v1', digest, signature, key);
  return immutableSnapshot(closure as unknown as InstalledModelAuthorityClosureV1);
}

/** Verify complete inventory bytes and every independently signed authority.
 * Signature validity is not real-provider capability or cost qualification. */
export function verifyInstalledModelAuthority(input: {
  closure: unknown; bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[];
  objects: ReadonlyMap<string, Buffer>;
}): VerifiedInstalledModelAuthority {
  const closure = decodeInstalledModelAuthorityClosure(input.closure, input);
  const key = publicKey(input.bundle, input.releaseKeys);
  if (input.objects.size !== closure.objects.length) throw new TypeError('installed model authority contains missing or extra objects');
  const inventory = new Map(closure.objects.map(object => [object.artifactRef, object]));
  const usedSignatures = new Set<string>();
  const catalogs = new Map<string, { ref: string; value: SignedModelCatalogEntryV1 }>();
  const tables = new Map<string, { ref: string; value: ModelPriceTableV1 }>();
  const signature = (reference: unknown): Buffer => {
    const digest = ref(reference), entry = inventory.get(digest), bytes = input.objects.get(digest);
    if (entry?.kind !== 'ed25519_signature' || !Buffer.isBuffer(bytes) || bytes.byteLength !== 64)
      throw new TypeError('installed model authority detached signature is absent');
    if (sha256Bytes(bytes) !== digest) throw new TypeError('installed model authority object bytes do not rehash');
    usedSignatures.add(digest); return bytes;
  };
  for (const object of closure.objects) {
    const bytes = input.objects.get(object.artifactRef);
    if (!Buffer.isBuffer(bytes) || bytes.byteLength !== object.byteCount || sha256Bytes(bytes) !== object.artifactRef)
      throw new TypeError('installed model authority object bytes do not rehash');
    if (object.kind === 'ed25519_signature') continue;
    const { tuple, value } = authorityObject(object.kind, object.artifactRef, bytes, input.bundle, key, signature);
    if (object.kind === 'model_catalog_entry') {
      if (catalogs.has(tuple)) throw new TypeError('installed model catalog tuple is ambiguous');
      catalogs.set(tuple, { ref: object.artifactRef, value: value as unknown as SignedModelCatalogEntryV1 });
    } else {
      if (tables.has(tuple)) throw new TypeError('installed model price tuple is ambiguous');
      tables.set(tuple, { ref: object.artifactRef, value: value as unknown as ModelPriceTableV1 });
    }
  }
  if (!catalogs.size || catalogs.size > MAX_MODELS || catalogs.size !== tables.size ||
      closure.objects.some(object => object.kind === 'ed25519_signature' && !usedSignatures.has(object.artifactRef)))
    throw new TypeError('installed model authority tuple or signature inventory is incomplete');
  const models = [...catalogs].sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right))).map(([tuple, catalog]) => {
    const priceTable = tables.get(tuple);
    if (!priceTable) throw new TypeError('installed model authority lacks exact catalog/price pairing');
    return { catalog, priceTable };
  });
  return immutableSnapshot({ closureRef: canonicalSha256(closure), closure, models });
}
