import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { sha256Bytes } from '../../src/kernel/identity.js';
import { verifyInstalledModelAuthority } from '../../src/model/installed-authority.js';
import type { RuntimeBundleManifest } from '../../src/policy/runtime-authority.js';
import { buildInstalledModelAuthority, type PublishedModelDefinition } from './model-authority-publisher.js';

// Disposable signing material and secret-free data. No installation, provider
// request, capability observation or trusted billing evidence is created.
function publisher() {
  const keys = generateKeyPairSync('ed25519');
  const entry = (entryId: string, role: string, executable: boolean) => {
    const bytes = Buffer.from(`model publisher test ${entryId}`);
    return { entryId, role, version: '1', relativePath: `test/${entryId}`, digest: sha256Bytes(bytes), byteCount: bytes.length, executable };
  };
  const bundle: RuntimeBundleManifest = { schemaVersion: 2, installedLayout: 'single_cas_streams_v1', bundleVersion: 'publisher-test',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 }, stateSchemaRange: { min: 1, max: 1 },
    workerProtocolRange: { min: 1, max: 1 }, entries: [entry('supervisor', 'supervisor', true), entry('worker', 'worker', true),
      entry('adapter', 'provider_adapter', true), entry('policy', 'policy_engine', false),
      entry('default_https_trust_store', 'trust_store', false), entry('sandbox', 'sandbox_root_profile', false)],
    structuredArtifacts: [], guestToolchainManifestRefs: [], publisherKeyId: 'disposable-model-publisher-test', manifestDigest: '', signature: '' };
  const { manifestDigest: _digest, signature: _signature, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  const model: PublishedModelDefinition = { provider: 'openai-compatible', model: 'nonzero-price-test-model',
    endpointIdentityDigest: canonicalSha256({ endpoint: 'publisher-test' }), adapterEntryId: 'adapter',
    claims: { nativeToolCalling: true, streaming: true, trustedUsageEvidence: false, contextLimitTokens: 32768, maxOutputTokens: 8192 },
    prices: { input: 250000, output: 1000000, cacheRead: 25000, cacheWrite: 0 },
    requestTokenCeiling: { inputTokens: 32768, outputTokens: 8192, cacheReadTokens: 32768, cacheWriteTokens: 0 },
    validFrom: '2026-10-01T00:00:00.000Z', validThrough: '2026-11-01T00:00:00.000Z' };
  const releaseKeys = [{ keyId: bundle.publisherKeyId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  return { bundle, privateKey: keys.privateKey, model, releaseKeys };
}

test('explicit nonzero prices survive the actual installer decoder with the same signed package identity', () => {
  const value = publisher();
  const result = buildInstalledModelAuthority({ ...value, models: [value.model] });
  const objects = new Map([...result.objects].map(([ref, object]) => [ref, object.bytes]));
  const imported = verifyInstalledModelAuthority({ ...value, closure: result.closure, objects });
  assert.equal(result.closure.runtimeBundleRef, canonicalSha256(value.bundle));
  assert.equal(result.objects.size, 4);
  assert.deepEqual(imported.models, result.models);
  assert.deepEqual(imported.models[0]!.priceTable.value.prices, value.model.prices);
  assert.deepEqual(imported.models[0]!.priceTable.value.requestTokenCeiling, value.model.requestTokenCeiling);
  assert.equal(imported.models[0]!.catalog.value.claims.trustedUsageEvidence, false);
  const replay = buildInstalledModelAuthority({ ...value, models: [value.model] });
  assert.deepEqual(canonicalJsonBytes(replay.closure), canonicalJsonBytes(result.closure));
  objects.set(imported.models[0]!.priceTable.ref, Buffer.from('substituted prices'));
  assert.throws(() => verifyInstalledModelAuthority({ ...value, closure: result.closure, objects }), /do not rehash/);
});

test('publisher refuses a foreign signer, unsigned adapter and missing or insufficient billing data', () => {
  const value = publisher(), build = (model: PublishedModelDefinition) => buildInstalledModelAuthority({ ...value, models: [model] });
  assert.throws(() => buildInstalledModelAuthority({ ...value, privateKey: generateKeyPairSync('ed25519').privateKey,
    models: [value.model] }), /release signature is invalid/);
  assert.throws(() => build({ ...value.model, adapterEntryId: 'worker' }), /signed executable/);
  assert.throws(() => build({ ...value.model, requestTokenCeiling: { ...value.model.requestTokenCeiling, inputTokens: 32767 } }), /ceiling/);
  assert.throws(() => build({ ...value.model, requestTokenCeiling: { ...value.model.requestTokenCeiling, outputTokens: 8191 } }), /ceiling/);
  const { prices: _prices, ...missingPrices } = value.model;
  assert.throws(() => build(missingPrices as PublishedModelDefinition), /closed shape/);
  assert.throws(() => build({ ...value.model, prices: { ...value.model.prices, output: -1 } }), /integer/);
  assert.throws(() => build({ ...value.model, claims: { ...value.model.claims, nativeToolCalling: 'yes' as unknown as boolean } }), /claims/);
});

test('one bounded companion keeps distinct model pairs and requires an explicit zero-price fixture', () => {
  const value = publisher();
  const fixture: PublishedModelDefinition = { ...value.model, model: 'owned-nonbilling-fixture',
    prices: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } };
  const result = buildInstalledModelAuthority({ ...value, models: [value.model, fixture] });
  assert.equal(result.models.length, 2);
  assert.deepEqual(result.models.find(model => model.catalog.value.model === fixture.model)!.priceTable.value.prices, fixture.prices);
  assert.deepEqual(result.models.find(model => model.catalog.value.model === value.model.model)!.priceTable.value.prices, value.model.prices);
  assert.deepEqual(buildInstalledModelAuthority({ ...value, models: [fixture, value.model] }).closure, result.closure);
  assert.throws(() => buildInstalledModelAuthority({ ...value, models: [] }), /one to thirty-two/);
  assert.throws(() => buildInstalledModelAuthority({ ...value, models: Array(33).fill(value.model) }), /one to thirty-two/);
  assert.throws(() => buildInstalledModelAuthority({ ...value, models: [value.model, value.model] }), /duplicated/);
});
