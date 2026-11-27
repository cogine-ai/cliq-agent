import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import { decodeEndpointRegistration, type EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import { digestOmitting } from '../kernel/identity.js';
import type { DependencyPolicy } from '../kernel/dependency.js';
import { dependencyDescriptorSequence } from '../kernel/dependency-descriptors.js';
import { deriveDependencyPlan } from './dependency-plan.js';
import { planDependencyTransport } from './dependency-transport-plan.js';

const ref = (name: string) => canonicalSha256({ inertData: name });
function context() {
  const endpoint: EndpointRegistrationV1 = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1', endpointRegistrationId: 'public',
    registrationKind: 'user', ownerPrincipalId: 'principal', purposes: ['dependency_registry'],
    target: { scheme: 'https', hostAscii: 'registry.example', port: 443, basePath: '/', redirectPolicy: 'reject_all' },
    tls: { serverNameAscii: 'registry.example', minimumVersion: 'TLSv1.3', trustStoreRuntimeBundleRef: ref('bundle'),
      trustStoreRuntimeBundleManifestDigest: ref('bundle meaning'), trustStoreEntryId: 'default_https_trust_store', trustStoreRef: ref('CA bytes'),
      trustStoreDigest: ref('CA bytes'), spkiSha256Pins: [ref('SPKI')] }, endpointIdentityDigest: '', tlsPolicyDigest: '',
    createdAt: '2026-10-27T00:00:00.000Z', registrationDigest: '' };
  endpoint.tlsPolicyDigest = canonicalSha256(endpoint.tls);
  endpoint.endpointIdentityDigest = canonicalSha256({ target: endpoint.target, tlsPolicyDigest: endpoint.tlsPolicyDigest });
  endpoint.registrationDigest = digestOmitting(endpoint, 'registrationDigest'); decodeEndpointRegistration(endpoint);
  const packages = [{ packageName: 'typescript', packageVersion: '5.9.2', endpointRegistrationRef: canonicalSha256(endpoint),
    canonicalPackagePath: '/typescript/-/typescript-5.9.2.tgz', integrityAlgorithm: 'sha512' as const, integrityDigest: Buffer.alloc(64, 7).toString('base64') }];
  const registryEndpoints = [{ endpointRegistrationRef: canonicalSha256(endpoint), endpointIdentityDigest: endpoint.endpointIdentityDigest, tlsPolicyDigest: endpoint.tlsPolicyDigest }];
  const policy: DependencyPolicy = { schemaVersion: 1, mode: 'locked_node', allowedAdapters: ['npm-ci-v1'], registryEndpoints,
    credentialGrantRefs: [], installScriptsPolicy: 'deny', maxPackages: 50_000, maxDownloadBytes: 5 * 1024 ** 3 };
  const data = { packageManifestRef: ref('package'), lockfileRef: ref('lock'), bindingGyp: { kind: 'absent' as const }, packages, registryEndpoints };
  return { plan: deriveDependencyPlan(data, policy, ref('guest')), packages, endpoints: [endpoint], resources: { ...DEFAULT_SANDBOX_RESOURCES },
    sandboxLaunchSpecRef: ref('launch'), runRemainingMs: 60_000,
    storage: { maximumOwnerDataBytes: 67_108_864, descriptorPageStorageBytes: 4096, fixedOwnerStorageBytes: 16_384 } };
}
test('public dependency data keeps full plan, separate TLS/CA domains, pages and original package ceiling', () => {
  const input = context(), result = planDependencyTransport(input), config = JSON.parse(result.configurationBytes.toString('utf8'));
  assert.equal(config.planDigest, canonicalSha256(input.plan)); assert.notEqual(config.planDigest, input.plan.planDigest);
  assert.equal(config.trustStoreDigest, input.endpoints[0]!.tls.trustStoreDigest);
  assert.equal(config.targets[0].tlsPolicyDigest, input.endpoints[0]!.tlsPolicyDigest);
  assert.notEqual(config.targets[0].tlsPolicyDigest, config.trustStoreDigest);
  assert.equal(config.maxPackageBytes, 16 * 1024 ** 2); assert(config.maxPackageBytes > 1024 ** 2);
  assert.equal(config.maxTransferBytes, 5 * 1024 ** 3); assert.equal(config.runRemainingMs, 60_000);
  const sequence = dependencyDescriptorSequence(input.packages);
  assert.equal(config.descriptorSequenceDigest, sequence.descriptorSequenceDigest);
  assert.deepEqual(result.pages.map(bytes => JSON.parse(bytes.toString('utf8'))), sequence.pages);
  assert(result.ownerStorageBytes < 67_108_864);
  for (const changed of [ { ...input, packages: [] }, { ...input, runRemainingMs: 0 },
    { ...input, storage: { ...input.storage, maximumOwnerDataBytes: 67_108_865 } },
    { ...input, storage: { ...input.storage, fixedOwnerStorageBytes: 67_108_864 } },
    { ...input, endpoints: [] }, { ...input, endpoints: [input.endpoints[0]!, input.endpoints[0]!] } ])
    assert.throws(() => planDependencyTransport(changed));
  let accessed = 0;
  const proxy = new Proxy({}, { getPrototypeOf() { accessed++; throw new Error('foreign'); }, ownKeys() { accessed++; throw new Error('foreign'); } });
  assert.throws(() => planDependencyTransport(proxy as never)); assert.equal(accessed, 0);
});
