import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { test } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { decodeInstalledModelAuthorityClosure, decodeRetainedInstalledModelAuthorityClosure,
  validateRetainedInstalledModelAuthorityData, verifyInstalledModelAuthority, verifyRetainedModelAuthorityPair,
  type InstalledModelAuthorityClosureV1, type SignedModelCatalogEntryV1 } from './installed-authority.js';
import { priceTableDigest, type ModelPriceTableV1 } from './pricing.js';

type Member = InstalledModelAuthorityClosureV1['objects'][number];
type InnerOptions = { catalog?: (value: SignedModelCatalogEntryV1) => void; price?: (value: ModelPriceTableV1) => void;
  catalogDomain?: string; priceDomain?: string; catalogKey?: KeyObject; priceKey?: KeyObject };

/** Explicit disposable Ed25519 roots and literal secret-free object bytes.
 * These contracts establish neither a real installation nor provider billing. */
function fixture(options: InnerOptions = {}) {
  const keys = generateKeyPairSync('ed25519'), publisherKeyId = 'offline-companion-test-root';
  const literalEntry = (entryId: string, role: string, executable: boolean) => {
    const bytes = Buffer.from(`offline signed data fixture: ${entryId}`);
    return { entryId, role, version: '1', relativePath: `literal/${entryId}`, digest: sha256Bytes(bytes), byteCount: bytes.length, executable };
  };
  const bundle: RuntimeBundleManifest = { schemaVersion: 1, bundleVersion: 'offline-companion-test-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 }, stateSchemaRange: { min: 1, max: 1 },
    workerProtocolRange: { min: 1, max: 1 }, entries: [literalEntry('supervisor', 'supervisor', true), literalEntry('worker', 'worker', true),
      literalEntry('adapter', 'provider_adapter', true), literalEntry('policy', 'policy_engine', false),
      literalEntry('default_https_trust_store', 'trust_store', false), literalEntry('sandbox', 'sandbox_root_profile', false)],
    structuredArtifacts: [], guestToolchainManifestRefs: [], publisherKeyId, manifestDigest: '', signature: '' };
  const { manifestDigest: _digest, signature: _signature, ...bundleCore } = bundle;
  bundle.manifestDigest = canonicalSha256(bundleCore);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  const releaseKeys = [{ keyId: publisherKeyId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  const adapter = bundle.entries.find(entry => entry.entryId === 'adapter')!;
  const endpointIdentityDigest = canonicalSha256({ offlineEndpoint: 'one' });
  const catalog: SignedModelCatalogEntryV1 = { schemaVersion: 1, format: 'cliq-signed-model-catalog-entry-v1',
    signerKeyId: publisherKeyId, signatureAlgorithm: 'ed25519', signatureRef: '', runtimeBundleRef: canonicalSha256(bundle),
    runtimeBundleManifestDigest: bundle.manifestDigest, provider: 'openai-compatible', model: 'offline-model', endpointIdentityDigest,
    adapter: { adapterId: adapter.entryId, version: adapter.version, codeDigest: adapter.digest },
    claims: { nativeToolCalling: true, streaming: true, trustedUsageEvidence: false, contextLimitTokens: 32768, maxOutputTokens: 8192 },
    validFrom: '2026-09-01T00:00:00.000Z', validThrough: '2026-10-01T00:00:00.000Z', catalogEntryDigest: '' };
  const price: ModelPriceTableV1 = { schemaVersion: 1, format: 'cliq-model-price-table-v1', signerKeyId: publisherKeyId,
    signatureAlgorithm: 'ed25519', signatureRef: '', provider: catalog.provider, model: catalog.model, endpointIdentityDigest,
    currency: 'USD', unit: 'micros_per_million_tokens', prices: { input: 100, output: 200, cacheRead: 0, cacheWrite: 0 },
    requestTokenCeiling: { inputTokens: 32768, outputTokens: 8192, cacheReadTokens: 0, cacheWriteTokens: 0 },
    validFrom: catalog.validFrom, validThrough: catalog.validThrough, tableDigest: '' };
  options.catalog?.(catalog); options.price?.(price);
  const objects = new Map<string, Buffer>(), members: Member[] = [];
  const add = (bytes: Buffer, kind: Member['kind']) => {
    const artifactRef = sha256Bytes(bytes);
    assert.equal(objects.has(artifactRef), false, 'fixture members must have distinct exact bytes');
    objects.set(artifactRef, bytes); members.push({ artifactRef, byteCount: bytes.length, kind });
    return artifactRef;
  };
  const { catalogEntryDigest: _catalogDigest, signatureRef: _catalogSignature, ...catalogCore } = catalog;
  catalog.catalogEntryDigest = canonicalSha256(catalogCore);
  catalog.signatureRef = add(sign(null, Buffer.from(`${options.catalogDomain ?? 'cliq-model-catalog-entry-v1'}\0${catalog.catalogEntryDigest}`),
    options.catalogKey ?? keys.privateKey), 'ed25519_signature');
  const catalogRef = add(canonicalJsonBytes(catalog), 'model_catalog_entry');
  price.tableDigest = priceTableDigest(price);
  price.signatureRef = add(sign(null, Buffer.from(`${options.priceDomain ?? 'cliq-model-price-table-v1'}\0${price.tableDigest}`),
    options.priceKey ?? keys.privateKey), 'ed25519_signature');
  const priceRef = add(canonicalJsonBytes(price), 'model_price_table');
  function closure(inventory: readonly Member[] = members, domain = 'cliq-installed-model-authority-v1'): InstalledModelAuthorityClosureV1 {
    const core = { schemaVersion: 1 as const, format: 'cliq-installed-model-authority-v1' as const, publisherKeyId,
      signatureAlgorithm: 'ed25519' as const, runtimeBundleRef: canonicalSha256(bundle), runtimeBundleManifestDigest: bundle.manifestDigest,
      objects: inventory.map(member => ({ ...member })).sort((left, right) => left.artifactRef.localeCompare(right.artifactRef)) };
    const closureDigest = canonicalSha256(core);
    return { ...core, closureDigest, signature: sign(null, Buffer.from(`${domain}\0${closureDigest}`), keys.privateKey).toString('base64') };
  }
  return { bundle, releaseKeys, objects, members, catalog, catalogRef, price, priceRef, keys, closure };
}
const verify = (value: ReturnType<typeof fixture>, closure = value.closure(), objects = value.objects) =>
  verifyInstalledModelAuthority({ bundle: value.bundle, releaseKeys: value.releaseKeys, closure, objects });

test('retained companion data closes its original inventory without acquiring signing authority', () => {
  const decode = decodeRetainedInstalledModelAuthorityClosure, validate = validateRetainedInstalledModelAuthorityData;
  const value = fixture(), closure = value.closure();
  assert.deepEqual(decode(closure, { bundle: value.bundle }), closure);
  assert.equal(validate({ ...value, closure }), undefined, 'retained validation returns no Verified authority');
  const missing = new Map(value.objects); missing.delete(value.catalog.signatureRef);
  assert.throws(() => validate({ ...value, closure, objects: missing }), /missing or extra/);
  const changed = new Map(value.objects); changed.set(value.priceRef, Buffer.from('changed retained object'));
  assert.throws(() => validate({ ...value, closure, objects: changed }), /do not rehash/);
  assert.throws(() => decode({ ...closure, permission: true }, value), /closed shape/);
  assert.throws(() => decode({ ...closure, objects: [...closure.objects].reverse() }, value), /inventory is invalid/);
  const wrongBundle = { ...value.bundle, manifestDigest: canonicalSha256({ different: true }) };
  assert.throws(() => decode(closure, { bundle: wrongBundle }), /signed RuntimeBundle/);
  const mismatched = fixture({ price: price => { price.model = 'another-original-tuple'; } });
  assert.throws(() => validate({ ...mismatched, closure: mismatched.closure() }), /exact catalog\/price pairing/);
  const extra = new Map(value.objects), unused = Buffer.alloc(64, 7), unusedRef = sha256Bytes(unused);
  extra.set(unusedRef, unused);
  const unusedClosure = value.closure([...value.members, { artifactRef: unusedRef, byteCount: 64, kind: 'ed25519_signature' }]);
  assert.throws(() => validate({ ...value, closure: unusedClosure, objects: extra }), /signature inventory is incomplete/);
  // Structural rewalking does not authenticate keys: the genuinely held birth
  // did that once. The live importer must STILL reject these foreign signatures.
  const foreign = fixture({ catalogKey: generateKeyPairSync('ed25519').privateKey });
  assert.equal(validate({ ...foreign, closure: foreign.closure() }), undefined);
  assert.throws(() => verify(foreign), /signature is invalid/);
});

test('installed companion verifies exact signed bundle, catalog, price and executed adapter data', () => {
  const value = fixture(), verified = verify(value);
  assert.equal(verified.closureRef, canonicalSha256(value.closure()));
  assert.equal(verified.models.length, 1);
  assert.deepEqual(verified.models[0], { catalog: { ref: value.catalogRef, value: value.catalog }, priceTable: { ref: value.priceRef, value: value.price } });
  assert.equal(Object.isFrozen(verified.models[0]!.catalog.value.claims), true);
  assert.deepEqual(decodeInstalledModelAuthorityClosure(value.closure(), value), verified.closure);
});

test('retained catalog and price authenticate their exact signed bytes without a current companion', () => {
  const value = fixture(), admitted = verify(value).models[0]!;
  const retained = () => verifyRetainedModelAuthorityPair({ bundle: value.bundle, releaseKeys: value.releaseKeys,
    catalogEntryRef: admitted.catalog.ref, priceTableRef: admitted.priceTable.ref, objects: value.objects });
  assert.deepEqual(retained(), admitted);
  // Companion replacement/deletion is irrelevant to this historical read:
  // only the four frozen CAS objects and original signed bundle are inputs.
  value.closure = () => { throw new Error('a current discovery companion is not retained Run authority'); };
  assert.deepEqual(retained(), admitted);
  assert.equal(Object.isFrozen(retained().catalog.value.claims), true);
  const missing = new Map(value.objects); missing.delete(value.catalog.signatureRef);
  assert.throws(() => verifyRetainedModelAuthorityPair({ ...value, catalogEntryRef: value.catalogRef,
    priceTableRef: value.priceRef, objects: missing }), /missing or extra|signature is absent/);
});

test('retained authority preserves independent signatures, exact tuple and signed runtime identity', () => {
  const foreign = generateKeyPairSync('ed25519').privateKey;
  for (const options of [{ catalogKey: foreign }, { priceKey: foreign },
    { price: (price: ModelPriceTableV1) => { price.model = 'different-retained-model'; } },
    { catalog: (catalog: SignedModelCatalogEntryV1) => { catalog.runtimeBundleRef = canonicalSha256({ anotherBundle: true }); } }]) {
    const value = fixture(options);
    assert.throws(() => verifyRetainedModelAuthorityPair({ ...value, catalogEntryRef: value.catalogRef, priceTableRef: value.priceRef }),
      /signature is invalid|exact catalog\/price pairing|another RuntimeBundle/);
  }
  const value = fixture(), changed = new Map(value.objects);
  changed.set(value.priceRef, canonicalJsonBytes({ ...value.price, prices: { ...value.price.prices, input: 0 } }));
  assert.throws(() => verifyRetainedModelAuthorityPair({ ...value, objects: changed,
    catalogEntryRef: value.catalogRef, priceTableRef: value.priceRef }), /do not rehash/);
});

test('an outer-valid companion cannot substitute the catalog bundle pair or adapter identity', () => {
  for (const change of [
    (value: SignedModelCatalogEntryV1) => { value.runtimeBundleRef = canonicalSha256({ foreignBundle: true }); },
    (value: SignedModelCatalogEntryV1) => { value.runtimeBundleManifestDigest = canonicalSha256({ foreignManifest: true }); },
    (value: SignedModelCatalogEntryV1) => { value.adapter.codeDigest = canonicalSha256({ changedCode: true }); },
    (value: SignedModelCatalogEntryV1) => { value.adapter.version = 'another-version'; },
    (value: SignedModelCatalogEntryV1) => { value.adapter.adapterId = 'worker'; }
  ]) assert.throws(() => verify(fixture({ catalog: change })), /another RuntimeBundle|signed executable/);
});

test('valid outer signatures never replace either inner signature or its fixed signing domain', () => {
  const foreign = generateKeyPairSync('ed25519').privateKey;
  for (const options of [{ catalogDomain: 'cliq-model-price-table-v1' }, { priceDomain: 'cliq-model-catalog-entry-v1' },
    { catalogKey: foreign }, { priceKey: foreign }]) {
    const value = fixture(options);
    assert.doesNotThrow(() => decodeInstalledModelAuthorityClosure(value.closure(), value));
    assert.throws(() => verify(value), /signature is invalid/);
  }
  const value = fixture();
  assert.throws(() => verify(value, value.closure(value.members, 'cliq-runtime-bundle-v1')), /signature is invalid/);
});

test('installed companion refuses missing, extra and unreferenced signature objects without weakening inventory checks', () => {
  const value = fixture(), missing = new Map(value.objects);
  missing.delete(value.catalog.signatureRef);
  assert.throws(() => verify(value, value.closure(), missing), /missing or extra objects/);
  const extra = new Map(value.objects), bytes = sign(null, Buffer.from('unreferenced offline test signature'), value.keys.privateKey);
  const artifactRef = sha256Bytes(bytes);
  extra.set(artifactRef, bytes);
  assert.throws(() => verify(value, value.closure(), extra), /missing or extra objects/);
  const unreferenced = value.closure([...value.members, { artifactRef, byteCount: 64, kind: 'ed25519_signature' }]);
  assert.throws(() => verify(value, unreferenced, extra), /signature inventory is incomplete/);
  const omitted = value.closure(value.members.filter(member => member.artifactRef !== value.catalog.signatureRef));
  assert.throws(() => verify(value, omitted, missing), /detached signature is absent/);
  const substituted = new Map(value.objects);
  substituted.set(value.catalog.signatureRef, Buffer.alloc(64, 1));
  assert.throws(() => verify(value, value.closure(), substituted), /do not rehash/);
});

test('individually valid authority cannot pair different catalog and price tuples', () => {
  for (const change of [
    (value: ModelPriceTableV1) => { value.model = 'different-model'; },
    (value: ModelPriceTableV1) => { value.provider = 'anthropic'; },
    (value: ModelPriceTableV1) => { value.endpointIdentityDigest = canonicalSha256({ differentEndpoint: true }); }
  ]) assert.throws(() => verify(fixture({ price: change })), /exact catalog\/price pairing/);
  assert.throws(() => verify(fixture({ catalog: value => { value.claims.maxOutputTokens = 8193; } })), /claims are invalid/);
  assert.throws(() => verify(fixture({ price: value => { value.prices.input = -1; } })), /integer is invalid/);
});

test('two independently signed catalogs cannot make one installed model tuple ambiguous', () => {
  const value = fixture();
  const duplicate = { ...value.catalog, claims: { ...value.catalog.claims, streaming: false }, signatureRef: '', catalogEntryDigest: '' };
  const { signatureRef: _signature, catalogEntryDigest: _digest, ...core } = duplicate;
  duplicate.catalogEntryDigest = canonicalSha256(core);
  const signature = sign(null, Buffer.from(`cliq-model-catalog-entry-v1\0${duplicate.catalogEntryDigest}`), value.keys.privateKey);
  duplicate.signatureRef = sha256Bytes(signature);
  const bytes = canonicalJsonBytes(duplicate), catalogRef = sha256Bytes(bytes);
  const objects = new Map(value.objects);
  objects.set(duplicate.signatureRef, signature); objects.set(catalogRef, bytes);
  const closure = value.closure([...value.members,
    { artifactRef: duplicate.signatureRef, kind: 'ed25519_signature', byteCount: signature.length },
    { artifactRef: catalogRef, kind: 'model_catalog_entry', byteCount: bytes.length }]);
  assert.doesNotThrow(() => decodeInstalledModelAuthorityClosure(closure, value));
  assert.throws(() => verify(value, closure, objects), /catalog tuple is ambiguous/);
});

test('installed companion rejects closed-shape, sorted-inventory and trust-root ambiguity changes', () => {
  const value = fixture(), closure = value.closure();
  assert.throws(() => verify(value, { ...closure, permission: true } as InstalledModelAuthorityClosureV1), /closed shape/);
  assert.throws(() => verify(value, { ...closure, objects: [...closure.objects].reverse() }), /inventory is invalid/);
  assert.throws(() => verifyInstalledModelAuthority({ ...value, closure, releaseKeys: [...value.releaseKeys, ...value.releaseKeys] }), /unique trusted release signature/);
  const second = fixture();
  assert.throws(() => verifyInstalledModelAuthority({ ...value, closure, releaseKeys: second.releaseKeys }), /release signature is invalid/);
});
