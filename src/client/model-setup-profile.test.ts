import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { decodeModelSetupProfile, decodeModelSetupProfiles, encodeModelSetupProfiles,
  modelSetupEndpointCandidate, type ModelSetupProfileV1 } from './model-setup-profile.js';

const profile: ModelSetupProfileV1 = { schemaVersion: 1, id: 'default', provider: 'openai-compatible', model: 'deepseek-flash',
  target: { hostAscii: 'api.deepseek.com', port: 443, basePath: '/' },
  tls: { serverNameAscii: 'api.deepseek.com', spkiSha256Pins: ['b'.repeat(64), 'a'.repeat(64)] } };

test('model setup asset retains only bounded public choices and owns immutable canonical data', () => {
  const selected = decodeModelSetupProfiles({ schemaVersion: 1, format: 'cliq-model-setup-profiles-v1', profiles: [profile] });
  assert.deepEqual(selected.profiles[0]!.tls.spkiSha256Pins, ['a'.repeat(64), 'b'.repeat(64)]);
  assert.equal(Object.isFrozen(selected.profiles[0]!.target), true);
  assert.deepEqual(encodeModelSetupProfiles(selected.profiles), canonicalJsonBytes(selected));
  assert.deepEqual(decodeModelSetupProfiles(JSON.parse(encodeModelSetupProfiles([]).toString())).profiles, []);
  for (const field of ['apiKey', 'caPem', 'trustStoreRuntimeBundleRef', 'prices', 'claims', 'actualProviderQualified'])
    assert.throws(() => decodeModelSetupProfile({ ...profile, [field]: 'not-authority' }));
  assert.throws(() => decodeModelSetupProfile({ ...profile, tls: { ...profile.tls, caPem: 'not-a-setup-template-member' } }));
  assert.throws(() => decodeModelSetupProfiles({ ...selected, profiles: [profile, profile] }), /unique/);
  assert.throws(() => decodeModelSetupProfiles({ ...selected, profiles: Array(33).fill(profile) }));
});

test('owned HTTPS loopback setup remains public data with its independent server-name identity', () => {
  const selected = decodeModelSetupProfile({ ...profile, model: 'owned-nonbilling-fixture',
    target: { hostAscii: '127.0.0.1', port: 12345, basePath: '/' },
    tls: { serverNameAscii: 'installed-verifier-fixture.invalid', spkiSha256Pins: ['a'.repeat(64)] } });
  assert.equal(selected.target.hostAscii, '127.0.0.1');
  assert.equal(selected.tls.serverNameAscii, 'installed-verifier-fixture.invalid');
  assert.deepEqual(decodeModelSetupProfiles(JSON.parse(encodeModelSetupProfiles([selected]).toString())).profiles, [selected]);
});

test('model setup refuses ambiguous target, malformed pins and non-data fields without invoking getters', () => {
  for (const target of [
    { ...profile.target, hostAscii: 'API.deepseek.com' }, { ...profile.target, hostAscii: 'api.deepseek.com.' },
    { ...profile.target, hostAscii: 'bad_host' }, { ...profile.target, port: 0 },
    { ...profile.target, basePath: '/a/../b' }, { ...profile.target, basePath: '/a%2fb' },
    { ...profile.target, basePath: '/a?token=hidden' }, { ...profile.target, basePath: '//other.invalid/path' }
  ]) assert.throws(() => decodeModelSetupProfile({ ...profile, target }));
  for (const pins of [[], ['bad'], ['a'.repeat(64), 'a'.repeat(64)], Array.from({ length: 65 }, (_, i) => i.toString(16).padStart(64, '0'))])
    assert.throws(() => decodeModelSetupProfile({ ...profile, tls: { ...profile.tls, spkiSha256Pins: pins } }));
  let reads = 0;
  const hostile = { ...profile };
  Object.defineProperty(hostile, 'model', { enumerable: true, get() { reads++; return profile.model; } });
  assert.throws(() => decodeModelSetupProfile(hostile));
  const pins = ['a'.repeat(64)];
  Object.defineProperty(pins, '0', { enumerable: true, get() { reads++; return 'a'.repeat(64); } });
  assert.throws(() => decodeModelSetupProfile({ ...profile, tls: { ...profile.tls, spkiSha256Pins: pins } }));
  assert.equal(reads, 0);
});

test('endpoint candidate uses only the supplied bundle identity and does not produce registration or authority', () => {
  // Inert bundle data only: no release signature, installation or native proof.
  const bundle: RuntimeBundleManifest = { schemaVersion: 2, installedLayout: 'single_cas_streams_v1', bundleVersion: 'inert-profile-data',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 3, max: 3 }, stateSchemaRange: { min: 8, max: 8 },
    workerProtocolRange: { min: 1, max: 1 }, entries: [{ entryId: 'default_https_trust_store', role: 'trust_store',
      version: '1', relativePath: 'data/trust', digest: 'c'.repeat(64), byteCount: 1, executable: false }],
    structuredArtifacts: [], guestToolchainManifestRefs: [], publisherKeyId: 'inert', manifestDigest: 'd'.repeat(64), signature: '' };
  const result = modelSetupEndpointCandidate(profile, bundle);
  assert.equal(result.tls.trustStoreRuntimeBundleRef, canonicalSha256(bundle));
  assert.equal(result.tls.trustStoreRuntimeBundleManifestDigest, bundle.manifestDigest);
  assert.equal(result.tls.trustStoreRef, bundle.entries[0]!.digest);
  assert.equal(result.tlsPolicyDigest, canonicalSha256(result.tls));
  assert.equal(result.endpointIdentityDigest, canonicalSha256({ target: result.target, tlsPolicyDigest: result.tlsPolicyDigest }));
  assert.deepEqual(Object.keys(result).sort(), ['endpointIdentityDigest', 'target', 'tls', 'tlsPolicyDigest']);
  assert.notEqual(modelSetupEndpointCandidate(profile, { ...bundle, bundleVersion: 'other' }).endpointIdentityDigest, result.endpointIdentityDigest);
  assert.throws(() => modelSetupEndpointCandidate(profile, { ...bundle, entries: [] }));
  assert.throws(() => modelSetupEndpointCandidate(profile, { ...bundle, entries: [{ ...bundle.entries[0]!, executable: true }] }));
});
