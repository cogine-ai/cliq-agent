// Conservative data-size admission only. No placeholder below is published,
// consumed as a future observation, or used to establish network success.
import { types } from 'node:util';
import { canonicalJsonBytes } from './canonical.js';
import { MAX_JSON_CONTAINER_ENTRIES } from './json.js';
import { decodeDependencyPackageDescriptor, DEPENDENCY_DESCRIPTOR_FORMAT } from './dependency-descriptors.js';
import type { DependencyPackageDescriptorV1 } from './dependency.js';

const MAXIMUM_JSON_BYTES = 1_048_576;
function fail(): never { throw new TypeError('complete dependency cache metadata cannot fit the original JSON bounds'); }
function entries(value: unknown): number {
  if (value === null || typeof value !== 'object') return 0;
  if (Array.isArray(value)) return value.length + value.reduce((n, item) => n + entries(item), 0);
  return Object.keys(value).length + Object.values(value).reduce<number>((n, item) => n + entries(item), 0);
}
export function assertDependencyCacheManifestCapacity(packages: readonly DependencyPackageDescriptorV1[],
  maximumPackageBytes: number, maximumTransferredBytes: number): Readonly<{ maximumBytes: number; maximumContainerEntries: number }> {
  if (!Array.isArray(packages) || types.isProxy(packages) || packages.length > DEPENDENCY_DESCRIPTOR_FORMAT.maximumCount ||
      !Number.isSafeInteger(maximumPackageBytes) || maximumPackageBytes < 1 || maximumPackageBytes > 67_108_864 ||
      !Number.isSafeInteger(maximumTransferredBytes) || maximumTransferredBytes < 1 || maximumTransferredBytes > 20 * 1_073_741_824) fail();
  const own = Object.getOwnPropertyDescriptors(packages);
  if (Reflect.ownKeys(own).length !== packages.length + 1) fail();
  const digest = 'f'.repeat(64);
  // Quotes maximize JSON escaping per byte of the retained bounded Run id.
  // This is inert upper-bound data, not the actual Run/source/ref or time.
  const envelope = { schemaVersion: 1, format: 'cliq-package-cache-manifest-v1', runId: '"'.repeat(128), resultSourceRef: digest,
    dependencyPlanRef: digest, lockfileRef: digest, lockfileDigest: digest, entries: [], packageCount: packages.length,
    totalTransferredBytes: maximumTransferredBytes, manifestDigest: digest, createdAt: '9999-12-31T23:59:59.999Z' };
  let bytes = canonicalJsonBytes(envelope).length, nodes = entries(envelope);
  for (let index = 0; index < packages.length; index++) {
    const property = own[String(index)]; if (!property || !('value' in property) || !property.enumerable) fail();
    const descriptor = decodeDependencyPackageDescriptor(property.value);
    const failed = (attempt: 1 | 2) => ({ attempt, outcome: 'http_error', httpStatus: 599, receivedBytes: maximumPackageBytes, observationDigest: digest });
    const item = { ...descriptor, blobRef: digest, blobDigest: digest, blobBytes: maximumPackageBytes,
      fetchAttempts: [failed(1), failed(2), { attempt: 3, outcome: 'completed', receivedBytes: maximumPackageBytes, observationDigest: digest }] };
    bytes += canonicalJsonBytes(item).length + (index ? 1 : 0); nodes += 1 + entries(item);
    if (bytes > MAXIMUM_JSON_BYTES || nodes > MAX_JSON_CONTAINER_ENTRIES) fail();
  }
  return Object.freeze({ maximumBytes: bytes, maximumContainerEntries: nodes });
}
