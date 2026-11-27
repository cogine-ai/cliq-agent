import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { canonicalJsonBytes } from './canonical.js';
import { assertArtifactRef, normalizeBoundedText } from './identity.js';
import type { DependencyPackageDescriptorV1 } from './dependency.js';
import { immutableSnapshot } from '../model/immutable.js';

export const DEPENDENCY_DESCRIPTOR_FORMAT = Object.freeze({ domain: 'cliq-dependency-package-descriptors-v1\0',
  maximumCount: 200_000, pageEntries: 32, pageBytes: 65_536, totalBytes: 67_108_864 } as const);
function fail(): never { throw new TypeError('dependency descriptors violate their exact bounded sequence'); }
const fields = ['packageName', 'packageVersion', 'endpointRegistrationRef', 'canonicalPackagePath', 'integrityAlgorithm', 'integrityDigest'] as const;
export function decodeDependencyPackageDescriptor(value: unknown): DependencyPackageDescriptorV1 {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const data = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(data).length !== fields.length || fields.some(key => !data[key] || !('value' in data[key]!) || !data[key]!.enumerable)) fail();
  const result = Object.fromEntries(fields.map(key => [key, data[key]!.value])) as Record<typeof fields[number], unknown>;
  for (const key of fields) if (typeof result[key] !== 'string' || normalizeBoundedText(result[key], 1, 4096) !== result[key]) fail();
  if (Buffer.byteLength(result.packageName as string) > 214 || !/^[A-Za-z0-9.+-]+$/u.test(result.packageVersion as string) || !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/u.test(result.packageName as string) ||
      !/^\/[A-Za-z0-9_~.@+/-]+$/u.test(result.canonicalPackagePath as string) ||
      (result.canonicalPackagePath as string).slice(1).split('/').some(part => !part || part === '.' || part === '..') ||
      result.integrityAlgorithm !== 'sha256' && result.integrityAlgorithm !== 'sha512') fail();
  assertArtifactRef(result.endpointRegistrationRef as string);
  const digest = Buffer.from(result.integrityDigest as string, 'base64');
  if (digest.length !== (result.integrityAlgorithm === 'sha256' ? 32 : 64) || digest.toString('base64') !== result.integrityDigest) fail();
  return immutableSnapshot(result) as DependencyPackageDescriptorV1;
}
export function dependencyDescriptorKey(value: DependencyPackageDescriptorV1): string {
  return fields.map(key => value[key]).join('\0');
}
export type DependencyDescriptorPageV1 = Readonly<{ schemaVersion: 1; firstIndex: number; descriptors: readonly DependencyPackageDescriptorV1[] }>;
/** No JSON array spanning the package graph, per-page CAS objects or second
 * ledger. This is the original bounded queued-data channel's fixed sequence. */
export function dependencyDescriptorSequence(value: readonly DependencyPackageDescriptorV1[]) {
  if (!Array.isArray(value) || types.isProxy(value) || value.length > DEPENDENCY_DESCRIPTOR_FORMAT.maximumCount) fail();
  const own = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(own).length !== value.length + 1) fail();
  const hash = createHash('sha256').update(DEPENDENCY_DESCRIPTOR_FORMAT.domain, 'ascii');
  const pages: DependencyDescriptorPageV1[] = []; let pending: DependencyPackageDescriptorV1[] = [], firstIndex = 0, total = 0, previous: string | undefined;
  const page = (entries: DependencyPackageDescriptorV1[]) => ({ schemaVersion: 1 as const, firstIndex, descriptors: entries });
  const flush = () => { if (pending.length) { pages.push(immutableSnapshot(page(pending))); firstIndex += pending.length; pending = []; } };
  for (let index = 0; index < value.length; index++) {
    const descriptor = own[String(index)]; if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) fail();
    const item = decodeDependencyPackageDescriptor(descriptor.value), key = dependencyDescriptorKey(item), bytes = canonicalJsonBytes(item);
    if (previous !== undefined && Buffer.compare(Buffer.from(previous), Buffer.from(key)) >= 0) fail();
    previous = key;
    if (pending.length >= DEPENDENCY_DESCRIPTOR_FORMAT.pageEntries || canonicalJsonBytes(page([...pending, item])).length > DEPENDENCY_DESCRIPTOR_FORMAT.pageBytes) flush();
    if (canonicalJsonBytes(page([item])).length > DEPENDENCY_DESCRIPTOR_FORMAT.pageBytes) fail();
    pending.push(item); const length = Buffer.alloc(4); length.writeUInt32LE(bytes.length);
    hash.update(length).update(bytes); total += 4 + bytes.length;
    if (total > DEPENDENCY_DESCRIPTOR_FORMAT.totalBytes) fail();
  }
  flush();
  return Object.freeze({ packageCount: value.length, descriptorSequenceDigest: hash.digest('hex'), packageDescriptorBytes: total, pages: Object.freeze(pages) });
}
