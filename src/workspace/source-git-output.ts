import { types } from 'node:util';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { decodeSandboxResourceOptions } from '../kernel/control-submit.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { digestOmitting } from '../kernel/identity.js';
import type { GitIndexSnapshotV1, PrivateGitStateManifest, SanitizedGitConfigV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';

export type SourceGitInspectionOutputV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-source-git-inspection-output-v1'; repositoryIdentityDigest: string; objectFormat: 'sha1' | 'sha256';
  head: PrivateGitStateManifest['head']; refs: PrivateGitStateManifest['refs'];
  index: { entries: GitIndexSnapshotV1['entries']; indexTreeObjectId: string; byteCount: number; sha256: string };
  pack: { byteCount: number; sha256: string; trailerObjectHash: string; indexByteCount: number; indexSha256: string; objectIds: string[] };
  sanitizedConfig: SanitizedGitConfigV1;
}>;
const typedArray = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedLength = Object.getOwnPropertyDescriptor(typedArray, 'byteLength')!.get!;
const typedOffset = Object.getOwnPropertyDescriptor(typedArray, 'byteOffset')!.get!;
const typedBuffer = Object.getOwnPropertyDescriptor(typedArray, 'buffer')!.get!;
function invalid(): never { throw new TypeError('source Git output has an invalid closed schema'); }
function record(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return invalid();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (required.some(key => !Object.hasOwn(descriptors, key)) || Reflect.ownKeys(descriptors).some(key => typeof key !== 'string' ||
      !required.includes(key) && !optional.includes(key) || !descriptors[key]!.enumerable ||
      !Object.hasOwn(descriptors[key]!, 'value') || descriptors[key]!.value === undefined)) return invalid();
  return value as Record<string, unknown>;
}
function integer(value: unknown, maximum: number, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) return invalid();
  return value;
}
function digest(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 64 || !/^[0-9a-f]+$/u.test(value)) return invalid(); return value;
}
export function sourceGitObjectId(value: unknown, format: 'sha1' | 'sha256'): string {
  if (typeof value !== 'string' || value.length !== (format === 'sha1' ? 40 : 64) || !/^[0-9a-f]+$/u.test(value) || /^0+$/u.test(value)) return invalid();
  return value;
}
/** Canonical Git ref data only, not permission to open a source path. */
export function sourceGitRefName(value: unknown): string {
  if (typeof value !== 'string' || value !== value.normalize('NFC') || !value.startsWith('refs/') || Buffer.byteLength(value) > 4096 ||
      value.includes('..') || value.includes('@{') || /[\x00-\x20\x7f~^:?*\[\\]/u.test(value) || value.endsWith('.') ||
      value.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock') || Buffer.byteLength(part) > 255)) return invalid();
  return value;
}
function sortedStrings(value: unknown, decode: (value: unknown) => string): string[] {
  if (!Array.isArray(value) || value.length > 100_000) return invalid();
  const result = value.map(decode);
  if (result.some((item, index) => index > 0 && Buffer.compare(Buffer.from(result[index - 1]!), Buffer.from(item)) >= 0)) return invalid();
  return result;
}
function config(value: unknown, format: 'sha1' | 'sha256'): SanitizedGitConfigV1 {
  const data = record(value, ['schemaVersion', 'format', 'core', 'configDigest'], ['extensions']);
  const core = record(data.core, ['repositoryFormatVersion', 'fileMode', 'bare'], ['logAllRefUpdates', 'ignoreCase', 'precomposeUnicode']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-sanitized-git-config-v1' ||
      core.repositoryFormatVersion !== 0 && core.repositoryFormatVersion !== 1 || core.bare !== false || typeof core.fileMode !== 'boolean' ||
      ['logAllRefUpdates', 'ignoreCase', 'precomposeUnicode'].some(key => Object.hasOwn(core, key) && typeof core[key] !== 'boolean')) return invalid();
  if (data.extensions !== undefined && record(data.extensions, ['objectFormat']).objectFormat !== format) return invalid();
  if (format === 'sha256' && (core.repositoryFormatVersion !== 1 || data.extensions === undefined) ||
      digest(data.configDigest) !== digestOmitting(data, 'configDigest')) return invalid();
  return data as SanitizedGitConfigV1;
}

/** Verifies only the fixed output's canonical data and cross-field shape.
 * Native ownership, whole-death/join, and trusted Git's actual full pack/index
 * validation are independent mandatory consumers, never inferred here. */
export function decodeSourceGitInspectionOutput(bytes: Uint8Array, expected: Readonly<{ repositoryIdentityDigest: string;
  resources: SandboxResourceSpec }>): SourceGitInspectionOutputV1 {
  const expectation = record(expected, ['repositoryIdentityDigest', 'resources']); digest(expectation.repositoryIdentityDigest);
  const resources = decodeSandboxResourceOptions(record(expectation.resources, ['maxProcesses', 'memoryBytes', 'cpuQuotaMicrosPerSecond',
    'maxOpenFiles', 'maxSingleFileBytes', 'maxGenerationBytes', 'maxInvocationOutputBytes', 'maxIpcFrameBytes', 'maxQueuedIpcBytes']));
  if (types.isProxy(bytes) || !types.isUint8Array(bytes)) return invalid();
  const length = typedLength.call(bytes) as number;
  if (length < 1 || length > Math.min(resources.maxInvocationOutputBytes, resources.maxSingleFileBytes)) return invalid();
  // Snapshot only the bounded underlying binary data. Own getters, iterators
  // and an asynchronously mutable caller buffer are not the parser's input.
  const snapshot = Buffer.from(new Uint8Array(typedBuffer.call(bytes) as ArrayBuffer, typedOffset.call(bytes) as number, length));
  let raw: unknown;
  try { raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(snapshot)); } catch { return invalid(); }
  // Exact JCS also rejects duplicate JSON keys, alternate spellings and trivia.
  try { if (!canonicalJsonBytes(raw).equals(snapshot)) return invalid(); } catch { return invalid(); }
  const data = record(raw, ['schemaVersion', 'format', 'repositoryIdentityDigest', 'objectFormat', 'head', 'refs', 'index', 'pack', 'sanitizedConfig']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-source-git-inspection-output-v1' || data.repositoryIdentityDigest !== expectation.repositoryIdentityDigest ||
      data.objectFormat !== 'sha1' && data.objectFormat !== 'sha256') return invalid();
  const format = data.objectFormat, head = record(data.head, ['kind'], ['branch', 'ref', 'objectId']);
  const pack = record(data.pack, ['byteCount', 'sha256', 'trailerObjectHash', 'indexByteCount', 'indexSha256', 'objectIds']);
  const objects = sortedStrings(pack.objectIds, value => sourceGitObjectId(value, format)), objectSet = new Set(objects);
  const packCount = integer(pack.byteCount, resources.maxSingleFileBytes, 12 + (format === 'sha1' ? 20 : 32));
  const packIndexCount = integer(pack.indexByteCount, resources.maxSingleFileBytes, 8 + 1024 + (format === 'sha1' ? 40 : 64));
  digest(pack.sha256); digest(pack.indexSha256); sourceGitObjectId(pack.trailerObjectHash, format);
  if (!Array.isArray(data.refs) || data.refs.length > 100_000) return invalid();
  let previous = '';
  const refs = new Map<string, string>();
  for (const value of data.refs) {
    const entry = record(value, ['name', 'objectId']), name = sourceGitRefName(entry.name), id = sourceGitObjectId(entry.objectId, format);
    if (previous && Buffer.compare(Buffer.from(previous), Buffer.from(name)) >= 0 || !objectSet.has(id)) return invalid();
    previous = name; refs.set(name, id);
  }
  if (head.kind === 'unborn') {
    record(head, ['kind', 'branch']);
    if (typeof head.branch !== 'string' || refs.has(sourceGitRefName(`refs/heads/${head.branch}`))) return invalid();
  } else if (head.kind === 'symbolic') {
    record(head, ['kind', 'ref']); if (!refs.has(sourceGitRefName(head.ref))) return invalid();
  } else if (head.kind === 'detached') {
    record(head, ['kind', 'objectId']); if (!objectSet.has(sourceGitObjectId(head.objectId, format))) return invalid();
  } else return invalid();
  const index = record(data.index, ['entries', 'indexTreeObjectId', 'byteCount', 'sha256']);
  const indexCount = integer(index.byteCount, resources.maxSingleFileBytes, 12 + (format === 'sha1' ? 20 : 32)); digest(index.sha256);
  sourceGitObjectId(index.indexTreeObjectId, format);
  if (!Array.isArray(index.entries) || index.entries.length > 100_000) return invalid();
  previous = ''; const folded = new Set<string>();
  for (const value of index.entries) {
    const entry = record(value, ['canonicalRootRelativePath', 'stage', 'mode', 'objectId', 'assumeValid', 'skipWorktree']);
    const path = entry.canonicalRootRelativePath;
    if (typeof path !== 'string' || !path || path !== path.normalize('NFC') || Buffer.byteLength(path) > 4096 || path.includes('\\') || path.includes('\0') ||
        path.split('/').some(part => !part || part === '.' || part === '..' || part.toLowerCase() === '.git' || Buffer.byteLength(part) > 255) ||
        previous && Buffer.compare(Buffer.from(previous), Buffer.from(path)) >= 0 || folded.has(path.toLowerCase()) ||
        entry.stage !== 0 || ![33188, 33261, 40960].includes(entry.mode as number) || typeof entry.assumeValid !== 'boolean' || entry.skipWorktree !== false ||
        !objectSet.has(sourceGitObjectId(entry.objectId, format))) return invalid();
    folded.add(path.toLowerCase()); previous = path;
  }
  if (packCount + packIndexCount + indexCount + length > resources.maxGenerationBytes) return invalid();
  config(data.sanitizedConfig, format);
  return immutableSnapshot(data as SourceGitInspectionOutputV1);
}
