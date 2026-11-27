import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { dependencyDescriptorSequence } from '../kernel/dependency-descriptors.js';
import { dependencyNpmInput, decodeDependencyNpmInput, decodeDependencyNpmPackageInput, dependencyNpmPackageSequence,
  type DependencyNpmInputV1, type DependencyNpmPackageInputV1 } from './dependency-npm-data.js';
import { createHash } from 'node:crypto';

const ref = (name: string) => canonicalSha256({ inert: name });
function item(name = 'package'): DependencyNpmPackageInputV1 {
  return { packageName: name, packageVersion: '1.0.0', endpointRegistrationRef: ref('registered public endpoint'),
    canonicalPackagePath: `/${name}/-/${name}-1.0.0.tgz`, blobSha256: ref('large package'), blobBytes: 3_145_745,
    integrityAlgorithm: 'sha512', integrityDigest: createHash('sha512').update('fixture digest only; not package proof').digest('base64') };
}
function value(items = [item()]): DependencyNpmInputV1 {
  const sequence = dependencyDescriptorSequence(items.map(({ blobBytes: _bytes, blobSha256: _sha, ...descriptor }) => descriptor));
  return { schemaVersion: 1, format: 'cliq-dependency-npm-input-v1', dependencyPlanRef: ref('plan'), packageManifestDigest: ref('package'),
    lockfileDigest: ref('lock'), scriptConditionsDigest: ref('complete source conditions'), bindingGyp: { kind: 'absent' }, operationGrantRef: ref('grant'), allowInstallScripts: false,
    packageCount: sequence.packageCount, descriptorSequenceDigest: sequence.descriptorSequenceDigest, packageDescriptorBytes: sequence.packageDescriptorBytes,
    maxPackageBytes: 67_108_864, maxCacheBytes: 5 * 1_073_741_824 };
}
test('fixed npm small root and bounded records preserve the original descriptor sequence without graph JSON', () => {
  const input = value(), bytes = canonicalJsonBytes(input), record = canonicalJsonBytes(item());
  assert(bytes.length < 1_048_576); assert(item().blobBytes > 1_048_576);
  assert.deepEqual(decodeDependencyNpmInput(bytes), input); assert.deepEqual(decodeDependencyNpmPackageInput(record), item());
  const sequence = dependencyNpmPackageSequence(input); sequence.append(record); sequence.finish();
  assert.throws(() => sequence.finish()); assert.throws(() => sequence.append(record));
  const empty = dependencyNpmPackageSequence(value([])); empty.finish();
  for (const changed of [
    { ...input, command: 'npm install' }, { ...input, allowInstallScripts: 'true' }, { ...input, maxPackageBytes: 67_108_865 },
    { ...input, packages: [] }, { ...input, packageCount: 200_001 }, { ...input, packageDescriptorBytes: 0 },
  ]) assert.throws(() => dependencyNpmInput(changed));
  for (const changed of [{ ...item(), path: '/host/package' }, { ...item(), blobBytes: 67_108_865 },
    { ...item(), integrityDigest: `${item().integrityDigest}\n` }]) assert.throws(() => decodeDependencyNpmPackageInput(canonicalJsonBytes(changed)));
  assert.throws(() => decodeDependencyNpmInput(Buffer.concat([bytes, Buffer.from('\n')])));
  assert.throws(() => decodeDependencyNpmInput(Buffer.alloc(1_048_577)));
});
test('fixed npm metadata rejects getters, proxies, duplicates, missing/suffix records and wrong exact original roots', () => {
  const input = value(); let invoked = 0;
  assert.throws(() => dependencyNpmInput(new Proxy(input, { get() { invoked++; return undefined; } })));
  assert.throws(() => dependencyNpmInput(Object.defineProperty({ ...input }, 'packageCount', { enumerable: true, get() { invoked++; return 1; } })));
  assert.equal(invoked, 0);
  for (const changed of [{ ...input, descriptorSequenceDigest: ref('different') }, { ...input, packageDescriptorBytes: input.packageDescriptorBytes + 1 }]) {
    const sequence = dependencyNpmPackageSequence(changed); sequence.append(canonicalJsonBytes(item())); assert.throws(() => sequence.finish());
  }
  const missing = dependencyNpmPackageSequence(input); assert.throws(() => missing.finish());
  const suffix = dependencyNpmPackageSequence(input); suffix.append(canonicalJsonBytes(item())); assert.throws(() => suffix.append(canonicalJsonBytes(item())));
  for (const changed of [{ ...input, maxPackageBytes: item().blobBytes - 1 }, { ...input, maxCacheBytes: item().blobBytes - 1 }])
    assert.throws(() => dependencyNpmPackageSequence(changed).append(canonicalJsonBytes(item())));
  const two = [item('a'), item('b')], sequence = dependencyNpmPackageSequence(value(two));
  sequence.append(canonicalJsonBytes(two[0])); assert.throws(() => sequence.append(canonicalJsonBytes(two[0])));
});

test('fixed npm root binding.gyp condition is closed data and rejects any absence substitution', () => {
  const input = value();
  for (const bindingGyp of [null, { kind: 'absent', contentDigest: ref('unobserved') }, { kind: 'present' },
    { kind: 'other' }, { kind: 'present', contentDigest: 'bad' }])
    assert.throws(() => dependencyNpmInput({ ...input, bindingGyp }));
  const present = { ...input, bindingGyp: { kind: 'present' as const, contentDigest: ref('actual full gyp bytes') } };
  assert.deepEqual(decodeDependencyNpmInput(canonicalJsonBytes(dependencyNpmInput(present))), present);
  let invoked = 0;
  const accessor = Object.defineProperty({}, 'kind', { enumerable: true, get() { invoked++; return 'absent'; } });
  assert.throws(() => dependencyNpmInput({ ...input, bindingGyp: accessor }));
  assert.equal(invoked, 0);
});
