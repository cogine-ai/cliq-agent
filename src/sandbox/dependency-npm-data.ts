// Fixed recipe data, never a native release or script permission. Package
// payloads and their complete metadata sequence use separate held FD channels.
import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { assertArtifactRef } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { DEPENDENCY_DESCRIPTOR_FORMAT, decodeDependencyPackageDescriptor, dependencyDescriptorKey } from '../kernel/dependency-descriptors.js';
import type { DependencyPackageDescriptorV1 } from '../kernel/dependency.js';
import { immutableSnapshot } from '../model/immutable.js';

export type DependencyNpmInputV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-dependency-npm-input-v1'; dependencyPlanRef: string;
  packageManifestDigest: string; lockfileDigest: string; scriptConditionsDigest: string;
  bindingGyp: { kind: 'absent' } | { kind: 'present'; contentDigest: string };
  allowInstallScripts: boolean; operationGrantRef: string;
  packageCount: number; descriptorSequenceDigest: string; packageDescriptorBytes: number;
  maxPackageBytes: number; maxCacheBytes: number;
}>;
export type DependencyNpmPackageInputV1 = DependencyPackageDescriptorV1 & Readonly<{ blobBytes: number; blobSha256: string }>;
export const DEPENDENCY_NPM_PACKAGE_INPUTS = Object.freeze({ recordBytes: 65_536, totalBytes: 67_108_864 } as const);
function fail(): never { throw new TypeError('fixed npm input is outside its closed recipe'); }
function record(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const data = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(data).length !== fields.length || fields.some(key => !data[key] || !('value' in data[key]!) || !data[key]!.enumerable)) fail();
  return Object.fromEntries(fields.map(key => [key, data[key]!.value]));
}
function ref(value: unknown): void { if (typeof value !== 'string') fail(); assertArtifactRef(value); }
function integer(value: unknown, minimum: number, maximum: number): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) fail();
}
export function dependencyNpmInput(value: unknown): DependencyNpmInputV1 {
  const data = record(value, ['schemaVersion', 'format', 'dependencyPlanRef', 'packageManifestDigest', 'lockfileDigest', 'scriptConditionsDigest',
    'bindingGyp', 'allowInstallScripts', 'operationGrantRef', 'packageCount', 'descriptorSequenceDigest', 'packageDescriptorBytes', 'maxPackageBytes', 'maxCacheBytes']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-dependency-npm-input-v1' || typeof data.allowInstallScripts !== 'boolean') fail();
  for (const key of ['dependencyPlanRef', 'packageManifestDigest', 'lockfileDigest', 'scriptConditionsDigest', 'operationGrantRef', 'descriptorSequenceDigest']) ref(data[key]);
  if (!data.bindingGyp || typeof data.bindingGyp !== 'object' || types.isProxy(data.bindingGyp)) fail();
  const kind = Object.getOwnPropertyDescriptor(data.bindingGyp, 'kind');
  const gypHeader = record(data.bindingGyp, kind && 'value' in kind && kind.value === 'present' ? ['kind', 'contentDigest'] : ['kind']);
  if (gypHeader.kind === 'present') ref(gypHeader.contentDigest);
  else if (gypHeader.kind !== 'absent' || Object.hasOwn(gypHeader, 'contentDigest')) fail();
  data.bindingGyp = gypHeader;
  integer(data.packageCount, 0, DEPENDENCY_DESCRIPTOR_FORMAT.maximumCount);
  integer(data.packageDescriptorBytes, 0, DEPENDENCY_DESCRIPTOR_FORMAT.totalBytes);
  if ((data.packageCount === 0) !== (data.packageDescriptorBytes === 0)) fail();
  integer(data.maxPackageBytes, 1, 67_108_864); integer(data.maxCacheBytes, 1, 20 * 1_073_741_824);
  const result = immutableSnapshot(data) as DependencyNpmInputV1;
  // This remains the metadata/wire JSON ceiling. It is independent of the
  // number of bounded records or the package payload data channel.
  if (canonicalJsonBytes(result).length > 1_048_576) fail();
  return result;
}
function strictData(bytes: Buffer, maximum: number): unknown {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > maximum) fail();
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  const data = parseJsonStrict(text);
  if (!canonicalJsonBytes(data).equals(bytes)) fail();
  return data;
}
export function decodeDependencyNpmInput(bytes: Buffer): DependencyNpmInputV1 {
  return dependencyNpmInput(strictData(bytes, 1_048_576));
}
export function decodeDependencyNpmPackageInput(bytes: Buffer): DependencyNpmPackageInputV1 {
  const data = record(strictData(bytes, DEPENDENCY_NPM_PACKAGE_INPUTS.recordBytes), ['blobBytes', 'blobSha256', 'canonicalPackagePath',
    'endpointRegistrationRef', 'integrityAlgorithm', 'integrityDigest', 'packageName', 'packageVersion']);
  integer(data.blobBytes, 1, 67_108_864); ref(data.blobSha256);
  const descriptor = decodeDependencyPackageDescriptor({ canonicalPackagePath: data.canonicalPackagePath,
    endpointRegistrationRef: data.endpointRegistrationRef, integrityAlgorithm: data.integrityAlgorithm,
    integrityDigest: data.integrityDigest, packageName: data.packageName, packageVersion: data.packageVersion });
  return immutableSnapshot({ ...descriptor, blobBytes: data.blobBytes, blobSha256: data.blobSha256 }) as DependencyNpmPackageInputV1;
}
/** Data-only streaming validator. The producer is the genuine native owner,
 * and the fixed program additionally reads and joins its actual sealed FD4.
 * No graph-wide JSON, package list cache, native brand or completion is made. */
export function dependencyNpmPackageSequence(value: DependencyNpmInputV1) {
  const input = dependencyNpmInput(value), hash = createHash('sha256').update(DEPENDENCY_DESCRIPTOR_FORMAT.domain, 'ascii');
  let count = 0, metadataBytes = 0, descriptorBytes = 0, payloadBytes = 0, previous: string | undefined, finished = false;
  return Object.freeze({
    append(bytes: Buffer): DependencyNpmPackageInputV1 {
      if (finished || count >= input.packageCount) fail();
      const item = decodeDependencyNpmPackageInput(bytes), key = dependencyDescriptorKey(item);
      if (previous !== undefined && Buffer.compare(Buffer.from(previous), Buffer.from(key)) >= 0) fail();
      if (item.blobBytes > input.maxPackageBytes) fail();
      const descriptor = canonicalJsonBytes({ canonicalPackagePath: item.canonicalPackagePath, endpointRegistrationRef: item.endpointRegistrationRef,
        integrityAlgorithm: item.integrityAlgorithm, integrityDigest: item.integrityDigest, packageName: item.packageName, packageVersion: item.packageVersion });
      const length = Buffer.alloc(4); length.writeUInt32LE(descriptor.length); hash.update(length).update(descriptor);
      metadataBytes += 4 + bytes.length; descriptorBytes += 4 + descriptor.length; payloadBytes += item.blobBytes;
      if (!Number.isSafeInteger(payloadBytes) || payloadBytes > input.maxCacheBytes || metadataBytes > DEPENDENCY_NPM_PACKAGE_INPUTS.totalBytes ||
          descriptorBytes > input.packageDescriptorBytes) fail();
      previous = key; count++; return item;
    },
    finish(): void {
      if (finished || count !== input.packageCount || descriptorBytes !== input.packageDescriptorBytes || hash.digest('hex') !== input.descriptorSequenceDigest) fail();
      finished = true;
    },
  });
}
