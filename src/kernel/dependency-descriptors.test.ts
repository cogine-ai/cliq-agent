import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { canonicalJsonBytes } from './canonical.js';
import { dependencyDescriptorSequence, DEPENDENCY_DESCRIPTOR_FORMAT } from './dependency-descriptors.js';
import type { DependencyPackageDescriptorV1 } from './dependency.js';

function packages(count: number, path = '/owned/-/owned-1.0.0.tgz'): DependencyPackageDescriptorV1[] {
  return Array.from({ length: count }, (_, index) => ({ packageName: `owned-${String(index).padStart(4, '0')}`, packageVersion: '1.0.0',
    endpointRegistrationRef: 'a'.repeat(64), canonicalPackagePath: path, integrityAlgorithm: 'sha512', integrityDigest: Buffer.alloc(64, 17).toString('base64') }));
}
test('whole dependency descriptor digest covers every ordered original record while each data page keeps the original small frame', () => {
  const records = packages(65), result = dependencyDescriptorSequence(records);
  assert.equal(result.packageCount, 65); assert.deepEqual(result.pages.map(page => page.descriptors.length), [32, 32, 1]);
  assert.deepEqual(result.pages.map(page => page.firstIndex), [0, 32, 64]);
  const expected = createHash('sha256').update('cliq-dependency-package-descriptors-v1\0', 'ascii'); let total = 0;
  for (const record of records) {
    const bytes = canonicalJsonBytes(record), length = Buffer.alloc(4); length.writeUInt32LE(bytes.length); total += 4 + bytes.length;
    expected.update(length); expected.update(bytes);
  }
  assert.equal(result.descriptorSequenceDigest, expected.digest('hex')); assert.equal(result.packageDescriptorBytes, total);
  for (const page of result.pages) assert(canonicalJsonBytes(page).length <= 65_536);
  const changed = records.map((record, index) => index === 32 ? { ...record, canonicalPackagePath: '/other/-/other-1.0.0.tgz' } : record);
  assert.notEqual(dependencyDescriptorSequence(changed).descriptorSequenceDigest, result.descriptorSequenceDigest);
  assert.throws(() => dependencyDescriptorSequence([...records].reverse()));
  assert.throws(() => dependencyDescriptorSequence([records[0]!, records[0]!]));
  const empty = dependencyDescriptorSequence([]); assert.equal(empty.packageCount, 0); assert.equal(empty.packageDescriptorBytes, 0); assert.equal(empty.pages.length, 0);
  assert.equal(empty.descriptorSequenceDigest, createHash('sha256').update(DEPENDENCY_DESCRIPTOR_FORMAT.domain).digest('hex'));
});
test('fixed byte budget splits long records before 32 without truncation or a giant JSON array', () => {
  const records = packages(33, `/${'x'.repeat(4000)}/owned.tgz`), sequence = dependencyDescriptorSequence(records);
  assert(sequence.pages.length > 2);
  assert.equal(sequence.pages.reduce((count, page) => count + page.descriptors.length, 0), records.length);
  for (const page of sequence.pages) { assert(page.descriptors.length <= 32); assert(canonicalJsonBytes(page).length <= 65_536); }
  let called = 0;
  assert.throws(() => dependencyDescriptorSequence(new Proxy(records, { get() { called++; throw new Error('must not run'); } })));
  assert.throws(() => dependencyDescriptorSequence([Object.defineProperty({ ...records[0] }, 'packageName', { get() { called++; return 'owned'; } })] as DependencyPackageDescriptorV1[]));
  assert.throws(() => dependencyDescriptorSequence(new Array(1)));
  assert.equal(called, 0);
});
