import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { canonicalJsonBytes } from './canonical.js';
import { assertDependencyCacheManifestCapacity } from './dependency-cache-capacity.js';
import { parseJsonStrict, MAX_JSON_CONTAINER_ENTRIES } from './json.js';
const descriptor = (index: number) => ({ packageName: `owned${index}`, packageVersion: '1.0.0', canonicalPackagePath: `/owned${index}/-/owned-${index}.tgz`,
  endpointRegistrationRef: 'a'.repeat(64), integrityAlgorithm: 'sha512' as const, integrityDigest: createHash('sha512').update('only capacity fixture').digest('base64') });
test('whole cache success envelope includes all three HTTP attempts before claim or GET without changing JSON bounds', () => {
  const input = Array.from({ length: 200 }, (_, index) => descriptor(index));
  const capacity = assertDependencyCacheManifestCapacity(input, 67_108_864, 5 * 1_073_741_824);
  assert(capacity.maximumBytes <= 1_048_576 && capacity.maximumContainerEntries <= MAX_JSON_CONTAINER_ENTRIES);
  assert.throws(() => assertDependencyCacheManifestCapacity(Array.from({ length: 500 }, (_, index) => descriptor(index)), 67_108_864, 5 * 1_073_741_824));
  // The same graph's raw descriptor page/lock may fit. That does not entitle
  // the larger complete observation envelope to bypass the original parser.
  assert.doesNotThrow(() => parseJsonStrict(canonicalJsonBytes(Array.from({ length: 500 }, (_, index) => descriptor(index))).toString('utf8')));
  const long = Array.from({ length: 250 }, (_, index) => ({ ...descriptor(index), canonicalPackagePath: '/' + 'a'.repeat(4095) }));
  assert.throws(() => assertDependencyCacheManifestCapacity(long, 67_108_864, 5 * 1_073_741_824));
});
test('cache capacity rejects malformed caller data without network, artifact publication or accessors', () => {
  let invoked = 0; const input = [descriptor(0)];
  assert.throws(() => assertDependencyCacheManifestCapacity(new Proxy(input, { get() { invoked++; return undefined; } }), 64, 64));
  assert.throws(() => assertDependencyCacheManifestCapacity(Object.defineProperty([], '0', { enumerable: true, get() { invoked++; return descriptor(0); } }), 64, 64));
  assert.equal(invoked, 0);
  assert.throws(() => assertDependencyCacheManifestCapacity(input, 67_108_865, 64));
});
