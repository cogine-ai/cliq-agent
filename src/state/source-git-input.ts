import { types } from 'node:util';
import type { SourceInspectionInputV2 } from '../kernel/execution.js';
import { decodeSandboxResourceOptions } from '../kernel/control-submit.js';
import { digestOmitting } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { ArtifactCatalog } from './artifacts.js';

const KEYS = ['schemaVersion', 'format', 'inspectionId', 'targetRef', 'targetDigest', 'repositoryIdentityDigest',
  'inspectionGrantId', 'inspectionReceiptRef', 'inspectionReceiptDigest', 'recipe', 'snapshotPolicy', 'resources', 'inputDigest'];
const RESOURCE_KEYS = ['maxProcesses', 'memoryBytes', 'cpuQuotaMicrosPerSecond', 'maxOpenFiles', 'maxSingleFileBytes',
  'maxGenerationBytes', 'maxInvocationOutputBytes', 'maxIpcFrameBytes', 'maxQueuedIpcBytes'];
function reject(): never { throw new TypeError('source Git input intent has an invalid closed schema'); }
function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return reject();
  const properties = Object.getOwnPropertyDescriptors(value), actual = Reflect.ownKeys(properties);
  if (actual.length !== keys.length || actual.some(key => typeof key !== 'string' || !keys.includes(key)) ||
      keys.some(key => !Object.hasOwn(properties, key) || !properties[key]!.enumerable || !Object.hasOwn(properties[key]!, 'value'))) return reject();
  return value as Record<string, unknown>;
}

/** Closed durable data only. This cannot open input, mint a native handle,
 * prove a seal, release a process, or replace the owning fresh SQL fence. */
export function decodeSourceGitInputIntent(value: unknown): SourceInspectionInputV2 {
  const data = record(value, KEYS), resources = record(data.resources, RESOURCE_KEYS);
  if (data.schemaVersion !== 2 || data.format !== 'cliq-source-inspection-input-v2' ||
      data.recipe !== 'cliq-source-git-inspection-v1' || data.snapshotPolicy !== 'ephemeral_native_sealed_shards' ||
      ['inspectionId', 'inspectionGrantId'].some(key => typeof data[key] !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(data[key])) ||
      ['targetRef', 'targetDigest', 'repositoryIdentityDigest', 'inspectionReceiptRef', 'inspectionReceiptDigest', 'inputDigest']
        .some(key => typeof data[key] !== 'string' || !/^[0-9a-f]{64}$/u.test(data[key]))) return reject();
  const decodedResources = decodeSandboxResourceOptions(resources);
  if (data.inputDigest !== digestOmitting(data, 'inputDigest')) return reject();
  return immutableSnapshot({ ...data, resources: decodedResources } as SourceInspectionInputV2);
}

/** Complete bounded immutable intent data, never a native input borrow. The
 * ordinary inline strict-JSON guards remain independent of graph artifacts. */
export async function readSourceGitInputIntent(artifacts: ArtifactCatalog, ref: string, signal?: AbortSignal): Promise<SourceInspectionInputV2> {
  signal?.throwIfAborted();
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const bytes = await reads.readBoundedBytes(ref, 1_048_576);
  const input = decodeSourceGitInputIntent(parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
  if (!canonicalJsonBytes(input).equals(bytes)) return reject();
  signal?.throwIfAborted(); return input;
}
