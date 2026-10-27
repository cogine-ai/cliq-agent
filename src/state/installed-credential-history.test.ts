import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, X509Certificate } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { decodeEndpointRegistration, type EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { policyProfile, verifyRuntimeBundle } from '../policy/runtime-authority.js';
import { builtinInputContracts } from '../tools/builtin-inputs.js';
import { OFFLINE_MODEL_TRUST_STORE_PEM } from './testing/tool-authority.js';
import { schemaConversionProfile, signedKernelSchemaProfile } from './signed-schema.js';
import { verifyRetainedInstalledEndpointData, verifyRetainedInstalledCurrentProducerData } from './installed-credential-history.js';

/** Real signatures/certificate/SQLite byte data only. This fixture has no
 * installation, StateOwner, endpoint registry operation, credential or secret. */
function fixture() {
  const keys = generateKeyPairSync('ed25519');
  const releaseKeys = [{ keyId: 'owned-data-publisher', publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  const signBundle = (bundle: RuntimeBundleManifest) => {
    const result = structuredClone(bundle);
    const { signature: _signature, manifestDigest: _digest, ...core } = result;
    result.manifestDigest = canonicalSha256(core);
    result.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${result.manifestDigest}`), keys.privateKey).toString('base64');
    return result;
  };
  const trust = Buffer.from(OFFLINE_MODEL_TRUST_STORE_PEM);
  const policy = policyProfile(), policyBytes = canonicalJsonBytes(policy);
  const entry = (entryId: string, role: string, executable: boolean, bytes: Buffer = Buffer.from(entryId)) =>
    ({ entryId, role, version: '1', relativePath: `data/${entryId}`, executable, digest: sha256Bytes(bytes), byteCount: bytes.length });
  const source = signBundle({ schemaVersion: 1, bundleVersion: 'owned-original-seven-data', controlProtocolRange: { min: 1, max: 1 },
    headlessSchemaRange: { min: 1, max: 3 }, stateSchemaRange: { min: 7, max: 7 }, workerProtocolRange: { min: 1, max: 1 },
    entries: [entry('original-supervisor', 'supervisor', true), entry('worker', 'worker', true), entry('policy', 'policy_engine', false, policyBytes),
      entry('root', 'sandbox_root_profile', false), entry('default_https_trust_store', 'trust_store', false, trust),
      entry('installed-edit-input-schema', 'schema', false, canonicalJsonBytes(builtinInputContracts.edit.inputSchema))],
    structuredArtifacts: [{ artifactId: 'policy', rootEntryId: 'policy', kind: 'policy_engine_profile',
      artifactRef: sha256Bytes(policyBytes), semanticDigest: policy.profileDigest, memberRefs: [] }],
    guestToolchainManifestRefs: [], publisherKeyId: releaseKeys[0]!.keyId, manifestDigest: '', signature: '' });
  const schema = canonicalJsonBytes(signedKernelSchemaProfile()), conversion = canonicalJsonBytes(schemaConversionProfile(source));
  const target = structuredClone(source);
  target.bundleVersion = 'owned-target-eight-data'; target.stateSchemaRange = { min: 8, max: 8 };
  target.entries[0] = entry('target-supervisor', 'supervisor', true);
  target.entries.push({ ...entry('kernel_schema', 'schema', false, schema), version: '8', relativePath: 'schema/kernel-v8.json' },
    { ...entry('schema_conversion', 'schema', false, conversion), version: '7-to-8', relativePath: 'schema/convert-v7-to-v8.json' });
  const current = signBundle(target);
  verifyRuntimeBundle(source, releaseKeys); verifyRuntimeBundle(current, releaseKeys);
  const tls: EndpointRegistrationV1['tls'] = { serverNameAscii: 'owned-data.invalid', minimumVersion: 'TLSv1.3',
    trustStoreRuntimeBundleRef: canonicalSha256(source), trustStoreRuntimeBundleManifestDigest: source.manifestDigest,
    trustStoreEntryId: 'default_https_trust_store', trustStoreRef: sha256Bytes(trust), trustStoreDigest: sha256Bytes(trust),
    spkiSha256Pins: [sha256Bytes(new X509Certificate(trust).publicKey.export({ type: 'spki', format: 'der' }))] };
  const targetEndpoint: EndpointRegistrationV1['target'] = { scheme: 'https', hostAscii: 'owned-data.invalid', port: 443, basePath: '/api', redirectPolicy: 'reject_all' };
  const tlsPolicyDigest = canonicalSha256(tls);
  const body: EndpointRegistrationV1 = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1', registrationKind: 'user',
    endpointRegistrationId: 'original-data-endpoint', ownerPrincipalId: 'a'.repeat(43), purposes: ['model_endpoint'], target: targetEndpoint,
    tls, tlsPolicyDigest, endpointIdentityDigest: canonicalSha256({ target: targetEndpoint, tlsPolicyDigest }),
    createdAt: '2026-10-27T00:00:00.000Z', registrationDigest: '' };
  body.registrationDigest = digestOmitting(body, 'registrationDigest');
  const registration = decodeEndpointRegistration(body);
  const data = { currentBundle: current, releaseKeys, registration, originalBundleBytes: canonicalJsonBytes(source), originalTrustStoreBytes: trust,
    currentSchemaBytes: schema, currentConversionBytes: conversion };
  return { source, current, data, signBundle };
}

test('full original signed seven endpoint data survives the exact eight conversion without changing its original bytes', () => {
  const f = fixture(), database = new DatabaseSync(':memory:');
  try {
    database.exec('CREATE TABLE retained_data(ref TEXT PRIMARY KEY,bytes BLOB NOT NULL) STRICT');
    for (const bytes of [f.data.originalBundleBytes, f.data.originalTrustStoreBytes])
      database.prepare('INSERT INTO retained_data VALUES (?,?)').run(sha256Bytes(bytes), bytes);
    const input = { ...f.data,
      originalBundleBytes: Buffer.from(database.prepare('SELECT bytes FROM retained_data WHERE ref=?').get(f.data.registration.tls.trustStoreRuntimeBundleRef)!.bytes as Uint8Array),
      originalTrustStoreBytes: Buffer.from(database.prepare('SELECT bytes FROM retained_data WHERE ref=?').get(f.data.registration.tls.trustStoreRef)!.bytes as Uint8Array) };
    const original = Buffer.from(canonicalJsonBytes(input.registration));
    const result = verifyRetainedInstalledEndpointData(input);
    assert.deepEqual(result.bundle, f.source);
    assert.equal(result.supervisorImageDigest, f.source.entries[0]!.digest);
    assert.notEqual(result.supervisorImageDigest, f.current.entries[0]!.digest);
    assert(canonicalJsonBytes(input.registration).equals(original));
    assert(database.prepare('SELECT bytes FROM retained_data WHERE ref=?').get(canonicalSha256(f.source))!.bytes instanceof Uint8Array);
    assert.equal(database.prepare('SELECT count(*) AS n FROM retained_data').get()!.n, 2);
    assert(Object.isFrozen(result));
  } finally { database.close(); }
});

test('old endpoint source refuses missing, substituted, re-signed unrelated, malformed and alias data', () => {
  const f = fixture();
  for (const change of [
    { originalBundleBytes: Buffer.alloc(0) }, { originalBundleBytes: canonicalJsonBytes(f.current) },
    { originalTrustStoreBytes: Buffer.from('not a trust store') }, { currentSchemaBytes: Buffer.alloc(0) },
    { currentConversionBytes: Buffer.alloc(0) }, { currentConversionBytes: f.data.currentSchemaBytes },
    { currentSchemaBytes: f.data.currentConversionBytes }, { currentSchemaBytes: undefined }, { currentConversionBytes: undefined },
  ]) assert.throws(() => verifyRetainedInstalledEndpointData({ ...f.data, ...change }));
  const unrelated = f.signBundle({ ...f.source, bundleVersion: 'other-legitimate-signed-source' });
  assert.throws(() => verifyRetainedInstalledEndpointData({ ...f.data, originalBundleBytes: canonicalJsonBytes(unrelated) }));
  const noConversion = f.signBundle({ ...f.current, entries: f.current.entries.filter(e => e.entryId !== 'schema_conversion') });
  assert.throws(() => verifyRetainedInstalledEndpointData({ ...f.data, currentBundle: noConversion }));
  const rangeOnly = f.signBundle({ ...noConversion, stateSchemaRange: { min: 1, max: 8 } });
  assert.throws(() => verifyRetainedInstalledEndpointData({ ...f.data, currentBundle: rangeOnly }));
  const changed = structuredClone(f.data.registration); changed.tls.trustStoreRuntimeBundleManifestDigest = f.current.manifestDigest;
  assert.throws(() => verifyRetainedInstalledEndpointData({ ...f.data, registration: changed }));
  const extra = Object.assign({ ...f.data }, { allowPreviousRuntime: true });
  assert.throws(() => verifyRetainedInstalledEndpointData(extra));
  const extraRegistration = { ...f.data.registration, allowPreviousRuntime: true };
  assert.throws(() => verifyRetainedInstalledEndpointData({ ...f.data, registration: extraRegistration }));
  assert.throws(() => verifyRetainedInstalledEndpointData({ ...f.data, originalBundleBytes: Buffer.alloc(1_048_577) }));
  assert.throws(() => verifyRetainedInstalledEndpointData({ ...f.data, originalTrustStoreBytes: Buffer.alloc(16 * 1_048_576 + 1) }));
});

test('trusted publisher identity is the actual public key, never a matching label or key supplied by retained data', () => {
  const f = fixture(), other = generateKeyPairSync('ed25519');
  const roots = [{ keyId: f.data.releaseKeys[0]!.keyId, publicKeyPem: other.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  assert.throws(() => verifyRetainedInstalledEndpointData({ ...f.data, releaseKeys: roots }));
  assert.throws(() => verifyRetainedInstalledEndpointData({ ...f.data, releaseKeys: [...f.data.releaseKeys, ...roots] }));
  assert.throws(() => verifyRetainedInstalledEndpointData({ ...f.data, releaseKeys: [] }));
});

test('retained source data rejects getters and proxies before observing their traps', () => {
  const f = fixture(); let observed = 0;
  const trap = () => { observed++; throw Error('unexpected data access'); };
  assert.throws(() => verifyRetainedInstalledEndpointData(new Proxy(f.data, { get: trap, ownKeys: trap, getPrototypeOf: trap })));
  for (const key of ['currentBundle', 'registration', 'originalBundleBytes', 'currentConversionBytes']) {
    const bad = { ...f.data }; Object.defineProperty(bad, key, { enumerable: true, get: trap });
    assert.throws(() => verifyRetainedInstalledEndpointData(bad));
  }
  assert.throws(() => verifyRetainedInstalledEndpointData({ ...f.data, registration: new Proxy(f.data.registration, { get: trap, ownKeys: trap }) }));
  assert.throws(() => verifyRetainedInstalledEndpointData({ ...f.data, originalBundleBytes: new Proxy(f.data.originalBundleBytes, { get: trap }) }));
  assert.equal(observed, 0);
});

test('a current revocation producer requires its own complete retained signed bytes, without adopting the old producer', () => {
  const f = fixture(), bytes = canonicalJsonBytes(f.current), image = f.current.entries[0]!.digest;
  assert.doesNotThrow(() => verifyRetainedInstalledCurrentProducerData(f.current, f.data.releaseKeys, bytes, image));
  for (const original of [Buffer.alloc(0), f.data.originalBundleBytes, Buffer.from(bytes.subarray(1))])
    assert.throws(() => verifyRetainedInstalledCurrentProducerData(f.current, f.data.releaseKeys, original, image));
  assert.throws(() => verifyRetainedInstalledCurrentProducerData(f.current, f.data.releaseKeys, bytes, f.source.entries[0]!.digest));
  const other = f.signBundle({ ...f.current, bundleVersion: 'different-legitimate-bundle-with-same-image' });
  assert.throws(() => verifyRetainedInstalledCurrentProducerData(f.current, f.data.releaseKeys, canonicalJsonBytes(other), image));
  let touched = false;
  assert.throws(() => verifyRetainedInstalledCurrentProducerData(f.current, f.data.releaseKeys,
    new Proxy(bytes, { get() { touched = true; throw Error('unexpected bytes proxy'); } }), image));
  assert.equal(touched, false);
});
