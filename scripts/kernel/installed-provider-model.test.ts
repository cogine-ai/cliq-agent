import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { rootCertificates } from 'node:tls';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { decodeEndpointRegistration } from '../../src/kernel/credential-authority.js';
import { sha256Bytes } from '../../src/kernel/identity.js';
import { verifyInstalledModelAuthority } from '../../src/model/installed-authority.js';
import { parseJsonStrict } from '../../src/kernel/json.js';
import type { RuntimeBundleManifest } from '../../src/policy/runtime-authority.js';
import { buildInstalledModelPackageEntries } from './model-package.js';
import { providerModelDefinition, writeInstalledProviderModelAuthority, type InstalledProviderModelDefinition } from './installed-provider-model.js';
import { buildInstalledProviderQualificationPackage, buildInstalledSupervisorPackage } from './testing/installed-supervisor-package.js';

const definition: InstalledProviderModelDefinition = { provider: 'openai-compatible', model: 'deepseek-flash',
  target: { hostAscii: 'api.deepseek.com', port: 443, basePath: '/' },
  tls: { serverNameAscii: 'api.deepseek.com', spkiSha256Pins: ['a'.repeat(64)] },
  claims: { nativeToolCalling: true, streaming: true, trustedUsageEvidence: false, contextLimitTokens: 32768, maxOutputTokens: 8192 },
  prices: { input: 300000, output: 1200000, cacheRead: 6000, cacheWrite: 0 },
  requestTokenCeiling: { inputTokens: 1048576, outputTokens: 393216, cacheReadTokens: 1048576, cacheWriteTokens: 0 },
  validFrom: '2026-10-30T00:00:00.000Z', validThrough: '2026-10-31T00:00:00.000Z' };

test('provider package preflight rejects fixture prices and target/TLS overrides before building any image', async () => {
  const selected = providerModelDefinition(definition);
  assert.equal(Object.isFrozen(selected.prices), true);
  for (const prices of [undefined, { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    { ...definition.prices, output: 0 }, { ...definition.prices, cacheWrite: -1 }]) {
    const changed = { ...definition, prices } as InstalledProviderModelDefinition;
    assert.throws(() => providerModelDefinition(changed), /nonzero/);
    await assert.rejects(buildInstalledProviderQualificationPackage('/must-not-be-opened', changed), /nonzero/);
  }
  for (const changed of [
    { ...definition, target: { ...definition.target, hostAscii: 'API.deepseek.com' } },
    { ...definition, target: { ...definition.target, basePath: '/a/../b' } },
    { ...definition, tls: { ...definition.tls, caPem: 'caller CA override' } },
    { ...definition, tls: { ...definition.tls, spkiSha256Pins: [] } },
    { ...definition, tls: { ...definition.tls, spkiSha256Pins: ['a'.repeat(64), 'a'.repeat(64)] } },
    { ...definition, validThrough: definition.validFrom }
  ]) assert.throws(() => providerModelDefinition(changed));
  await assert.rejects(buildInstalledSupervisorPackage('/must-not-be-opened', 'retirement-native-missing', undefined,
    { providerModel: definition }), /complete signed native package/);
  await assert.rejects(buildInstalledSupervisorPackage('/must-not-be-opened', 'complete', {} as never,
    { providerModel: definition }), /cannot be combined/);
});

test('real-provider package writes the same installer closure with explicit billable prices and original bundle TLS binding', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-provider-package-data-'));
  try {
    // Inert data bytes and disposable crypto only. No executable is loaded,
    // installed, run or granted permission, and no provider call is made.
    const material = buildInstalledModelPackageEntries(definition, Buffer.from('inert broker'), Buffer.from('inert edit'));
    const entry = (entryId: string, role: string, executable: boolean) => ({ entryId, role, version: '1',
      relativePath: `inert/${entryId}`, executable, digest: sha256Bytes(Buffer.from(entryId)), byteCount: Buffer.byteLength(entryId) });
    const ca = Buffer.from(rootCertificates.join('\n')), keys = generateKeyPairSync('ed25519');
    const bundle: RuntimeBundleManifest = { schemaVersion: 2, installedLayout: 'single_cas_streams_v1', bundleVersion: 'provider-data-test',
      controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 3, max: 3 }, stateSchemaRange: { min: 1, max: 8 },
      workerProtocolRange: { min: 1, max: 1 }, entries: [entry('supervisor', 'supervisor', true), entry('worker', 'worker', true),
        entry('policy', 'policy_engine', false), entry('sandbox', 'sandbox_root_profile', false),
        { ...entry('default_https_trust_store', 'trust_store', false), digest: sha256Bytes(ca), byteCount: ca.length },
        ...material.entries.map(({ bytes, ...entry }) => ({ ...entry, version: '1', digest: sha256Bytes(bytes), byteCount: bytes.length }))],
      structuredArtifacts: material.structuredArtifacts, guestToolchainManifestRefs: [], publisherKeyId: 'disposable-provider-data-test', manifestDigest: '', signature: '' };
    const { manifestDigest: _digest, signature: _signature, ...core } = bundle;
    bundle.manifestDigest = canonicalSha256(core);
    bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
    const result = await writeInstalledProviderModelAuthority({ packageRoot: directory, bundle, privateKey: keys.privateKey,
      definition, material });
    assert.equal(result.actualProviderQualified, false); assert.equal(result.actualProviderCostQualified, false);
    assert.equal(result.officialReleaseQualified, false);
    const bytes = await readFile(path.join(directory, 'model-authority.json'));
    const closure = parseJsonStrict(bytes.toString('utf8'));
    assert.deepEqual(canonicalJsonBytes(closure), bytes);
    const objects = new Map<string, Buffer>();
    for (const object of result.closure.value.objects) {
      const bytes = await readFile(path.join(directory, 'model-objects/sha256', object.artifactRef.slice(0, 2), object.artifactRef));
      assert.equal(sha256Bytes(bytes), object.artifactRef); objects.set(object.artifactRef, bytes);
    }
    const verified = verifyInstalledModelAuthority({ bundle, closure, objects, releaseKeys: [{ keyId: bundle.publisherKeyId,
      publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }] });
    assert.deepEqual(verified.models[0]!.priceTable.value.prices, definition.prices);
    assert.deepEqual(verified.models[0]!.priceTable.value.requestTokenCeiling, definition.requestTokenCeiling);
    assert.equal(result.endpoint.tls.trustStoreRef, sha256Bytes(ca));
    assert.equal(result.endpoint.tls.trustStoreRuntimeBundleRef, canonicalSha256(bundle));
    const registrationCore = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1', endpointRegistrationId: 'data-test',
      registrationKind: 'user', ownerPrincipalId: 'inert-data-principal', purposes: ['model_endpoint'], ...result.endpoint, createdAt: definition.validFrom };
    // This invokes only the existing closed data decoder, never registration.
    assert.doesNotThrow(() => decodeEndpointRegistration({ ...registrationCore, registrationDigest: canonicalSha256(registrationCore) }));
    const wrong = path.join(directory, 'wrong'); await mkdir(wrong, { mode: 0o700 });
    await assert.rejects(writeInstalledProviderModelAuthority({ packageRoot: wrong, bundle,
      privateKey: generateKeyPairSync('ed25519').privateKey, definition, material }), /release signature/);
    await assert.rejects(readFile(path.join(wrong, 'model-authority.json')), { code: 'ENOENT' });
  } finally { await rm(directory, { recursive: true, force: true }); }
});
