import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import { readNpmLockData, deriveDependencyPlan } from './dependency-plan.js';

const ref = (digit: string) => digit.repeat(64);
function endpoint(): EndpointRegistrationV1 {
  const value: EndpointRegistrationV1 = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1',
    endpointRegistrationId: 'registry', registrationKind: 'user', ownerPrincipalId: 'owner', purposes: ['dependency_registry'],
    target: { scheme: 'https', hostAscii: 'registry.example.com', port: 443, basePath: '/', redirectPolicy: 'reject_all' },
    tls: { serverNameAscii: 'registry.example.com', minimumVersion: 'TLSv1.3', trustStoreRuntimeBundleRef: ref('1'),
      trustStoreRuntimeBundleManifestDigest: ref('2'), trustStoreEntryId: 'default_https_trust_store',
      trustStoreRef: ref('3'), trustStoreDigest: ref('3'), spkiSha256Pins: [ref('4')] },
    endpointIdentityDigest: '', tlsPolicyDigest: '', createdAt: '2026-10-27T00:00:00.000Z', registrationDigest: '' };
  value.tlsPolicyDigest = canonicalSha256(value.tls);
  value.endpointIdentityDigest = canonicalSha256({ target: value.target, tlsPolicyDigest: value.tlsPolicyDigest });
  value.registrationDigest = digestOmitting(value, 'registrationDigest');
  return value;
}
const blob = Buffer.from('a real package archive is independently checked by the acquisition consumer');
const sri = `sha512-${createHash('sha512').update(blob).digest('base64')}`;
const manifest = () => ({ name: 'application', version: '1.0.0', dependencies: { dep: '1.2.3' }, scripts: { test: 'node test.cjs' } });
const lock = () => ({ name: 'application', version: '1.0.0', lockfileVersion: 3, requires: true, packages: {
  '': { name: 'application', version: '1.0.0', dependencies: { dep: '1.2.3' } },
  'node_modules/dep': { version: '1.2.3', resolved: 'https://registry.example.com/dep/-/dep-1.2.3.tgz', integrity: sri }
} });
const bytes = (value: unknown) => Buffer.from(JSON.stringify(value));
const read = (packageJson: unknown = manifest(), packageLock: unknown = lock(), endpoints = [endpoint()]) =>
  readNpmLockData({ packageJsonBytes: bytes(packageJson), packageLockBytes: bytes(packageLock), registryEndpoints: endpoints,
    maxPackages: 50_000, maxSingleFileBytes: 268_435_456, bindingGyp: { kind: 'absent' } });

test('Node dependency plan freezes exact original files and endpoint tuples without invoking npm', () => {
  const data = read(), policy = { schemaVersion: 1 as const, mode: 'locked_node' as const, allowedAdapters: ['npm-ci-v1' as const],
    registryEndpoints: [{ endpointRegistrationRef: canonicalSha256(endpoint()), endpointIdentityDigest: endpoint().endpointIdentityDigest,
      tlsPolicyDigest: endpoint().tlsPolicyDigest }], credentialGrantRefs: [], installScriptsPolicy: 'deny' as const,
    maxPackages: 50_000, maxDownloadBytes: 5 * 1_073_741_824 };
  const plan = deriveDependencyPlan(data, policy, ref('5'));
  assert.equal(plan.adapter, 'npm-ci-v1'); assert.equal(plan.lockfilePath, 'package-lock.json');
  assert.equal(plan.packageManifest.contentRef, sha256Bytes(bytes(manifest())));
  assert.equal(plan.lockfileRef, sha256Bytes(bytes(lock())));
  assert.equal(plan.allowInstallScripts, false); assert.equal(plan.planDigest, digestOmitting(plan, 'planDigest'));
  assert.deepEqual(data.packages, [{ packageName: 'dep', packageVersion: '1.2.3',
    endpointRegistrationRef: canonicalSha256(endpoint()), canonicalPackagePath: '/dep/-/dep-1.2.3.tgz',
    integrityAlgorithm: 'sha512', integrityDigest: sri.slice(7) }]);
  assert(Object.isFrozen(data) && Object.isFrozen(data.packages) && Object.isFrozen(data.packages[0]));
});

test('dependency input rejects unlocked or ambiguous layouts before an acquisition can be prepared', () => {
  const cases: Array<(value: ReturnType<typeof lock>) => unknown> = [
    value => ({ ...value, lockfileVersion: 2 }),
    value => ({ ...value, packages: { ...value.packages, 'packages/workspace': { version: '1.0.0', link: true } } }),
    value => ({ ...value, packages: { ...value.packages, 'node_modules/dep': { ...value.packages['node_modules/dep'], integrity: undefined } } }),
    value => ({ ...value, packages: { ...value.packages, 'node_modules/dep': { ...value.packages['node_modules/dep'], resolved: 'file:local.tgz' } } }),
    value => ({ ...value, packages: { ...value.packages, 'node_modules/dep': { ...value.packages['node_modules/dep'], resolved: 'https://foreign.example.com/dep.tgz' } } }),
    value => ({ ...value, packages: { ...value.packages, 'node_modules/../dep': value.packages['node_modules/dep'] } }),
    value => ({ ...value, packages: { ...value.packages, 'node_modules/dep': { ...value.packages['node_modules/dep'], integrity: `${sri} ${sri}` } } }),
    value => ({ ...value, packages: { ...value.packages, '': { ...value.packages[''], dependencies: { dep: '2.0.0' } } } }),
    value => ({ ...value, packages: { '': value.packages[''] } }),
    value => ({ ...value, packages: { ...value.packages, 'node_modules/dep': { ...value.packages['node_modules/dep'], version: '5.0.0' } } })
  ];
  for (const change of cases) assert.throws(() => read(manifest(), change(lock())), /dependency|lock|package|registry|integrity/i);
  assert.throws(() => read({ ...manifest(), workspaces: [] }), /workspace/i);
  assert.throws(() => readNpmLockData({ packageJsonBytes: bytes(manifest()), packageLockBytes: bytes(lock()), registryEndpoints: [endpoint()],
    maxPackages: 0, maxSingleFileBytes: 268_435_456, bindingGyp: { kind: 'absent' } }), /limit|bound|package/i);
});

test('frozen dependency graph uses npm semver and ancestor resolution rather than trusting lock declarations', () => {
  const packageJson = manifest(), packageLock = lock();
  packageJson.dependencies.dep = '^1.0.0 || >=2.0.0 <3.0.0';
  packageLock.packages[''].dependencies.dep = packageJson.dependencies.dep;
  assert.equal(read(packageJson, packageLock).packages[0]!.packageVersion, '1.2.3');
  packageLock.packages['node_modules/dep'].version = '1.2.3-beta.1';
  assert.throws(() => read(packageJson, packageLock), /dependency|range|version/i);
});

test('credentials, query aliases, dot aliases and duplicate JSON keys never become registry targets', () => {
  for (const resolved of ['https://user:pass@registry.example.com/dep.tgz', 'https://registry.example.com/dep.tgz?secret=value',
    'https://registry.example.com/dep.tgz#part', 'https://registry.example.com/a/../dep.tgz',
    'https://registry.example.com/%64ep.tgz', 'https://registry.example.com:443/dep.tgz']) {
    const value = lock(); value.packages['node_modules/dep'].resolved = resolved;
    assert.throws(() => read(manifest(), value), /registry|path|canonical|package|dependency/i);
  }
  const duplicate = bytes(lock()).toString().replace('"lockfileVersion":3', '"lockfileVersion":3,"lockfileVersion":3');
  assert.throws(() => readNpmLockData({ packageJsonBytes: bytes(manifest()), packageLockBytes: Buffer.from(duplicate),
    registryEndpoints: [endpoint()], maxPackages: 50_000, maxSingleFileBytes: 268_435_456, bindingGyp: { kind: 'absent' } }), /duplicate/i);
  assert.throws(() => readNpmLockData({ packageJsonBytes: Buffer.from([0x7b, 0x80, 0x7d]), packageLockBytes: bytes(lock()),
    registryEndpoints: [endpoint()], maxPackages: 50_000, maxSingleFileBytes: 268_435_456, bindingGyp: { kind: 'absent' } }), /UTF|encoded|encoding/i);
});

test('each candidate derives its own file refs and cannot redirect frozen policy endpoints', () => {
  const data = read(), target = endpoint(), policy = { schemaVersion: 1 as const, mode: 'locked_node' as const,
    allowedAdapters: ['npm-ci-v1' as const], registryEndpoints: [{ endpointRegistrationRef: canonicalSha256(target),
      endpointIdentityDigest: target.endpointIdentityDigest, tlsPolicyDigest: target.tlsPolicyDigest }], credentialGrantRefs: [],
    installScriptsPolicy: 'deny' as const, maxPackages: 50_000, maxDownloadBytes: 5 * 1_073_741_824 };
  const changed = manifest(); changed.scripts.test = 'node changed-test.cjs';
  const next = deriveDependencyPlan(read(changed), policy, ref('5'));
  assert.notEqual(next.planDigest, deriveDependencyPlan(data, policy, ref('5')).planDigest);
  assert.notEqual(next.packageManifest.contentRef, data.packageManifestRef);
  assert.throws(() => deriveDependencyPlan(data, { ...policy, registryEndpoints: [{ ...policy.registryEndpoints[0]!,
    endpointRegistrationRef: ref('e') }] }, ref('5')), /registry|endpoint/i);
});
