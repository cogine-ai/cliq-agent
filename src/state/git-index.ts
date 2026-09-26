import { createHash } from 'node:crypto';

import { normalizeCanonicalText } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { GitIndexSnapshotV1, RepositoryIdentityV1, SourceManifest } from '../kernel/types.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';

type TreeNode = { kind: 'tree'; children: Map<string, TreeNode | TreeLeaf> };
type TreeLeaf = { kind: 'leaf'; mode: 33188 | 33261 | 40960; objectId: string };

/** Both the held source bytes and expanded canonical v2 bytes must fit. */
export const MAX_GIT_INDEX_BYTES = 64 * 1024 * 1024;

function mismatch(message: string): never {
  throw new KernelStorageError('ARTIFACT_MISMATCH', message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactly(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function requireRef(value: unknown, label: string): string {
  if (typeof value !== 'string') mismatch(`${label} is not an ArtifactRef`);
  try { assertArtifactRef(value); } catch { mismatch(`${label} is not an ArtifactRef`); }
  return value;
}

function requireObjectId(value: unknown, format: 'sha1' | 'sha256', label: string): string {
  const pattern = format === 'sha1' ? /^[0-9a-f]{40}$/u : /^[0-9a-f]{64}$/u;
  if (typeof value !== 'string' || !pattern.test(value)) mismatch(`${label} is not a ${format} object id`);
  return value;
}

function requireIndexPath(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) mismatch('Git index path is empty');
  let normalized: string;
  try { normalized = normalizeCanonicalText(value); }
  catch { mismatch('Git index path is not canonical UTF-8 text'); }
  const parts = value.split('/');
  if (normalized !== value || value.startsWith('/') || value.includes('\\') ||
      Buffer.byteLength(value, 'utf8') > 4096 ||
      parts.some((part) => part === '' || part === '.' || part === '..' || part.toLowerCase() === '.git' ||
        Buffer.byteLength(part, 'utf8') > 255)) {
    mismatch('Git index path is not a canonical in-root path');
  }
  return value;
}

export function decodeGitIndexSnapshot(value: unknown): GitIndexSnapshotV1 {
  const keys = ['schemaVersion', 'format', 'repositoryIdentityDigest', 'objectFormat',
    'canonicalIndexVersion', 'entries', 'canonicalIndexBytesRef',
    'canonicalIndexBytesDigest', 'canonicalIndexByteCount', 'indexTreeObjectId', 'snapshotDigest'];
  if (!isRecord(value) || !hasExactly(value, keys) || value.schemaVersion !== 1 ||
      value.format !== 'cliq-git-index-snapshot-v1' || value.canonicalIndexVersion !== 2 ||
      (value.objectFormat !== 'sha1' && value.objectFormat !== 'sha256') ||
      !Array.isArray(value.entries) || value.entries.length > 0xffff_ffff) {
    mismatch('Git index snapshot has an invalid closed shape');
  }
  const format = value.objectFormat;
  requireRef(value.repositoryIdentityDigest, 'Git index repository identity digest');
  const bytesRef = requireRef(value.canonicalIndexBytesRef, 'Git index canonical bytes ref');
  if (requireRef(value.canonicalIndexBytesDigest, 'Git index canonical bytes digest') !== bytesRef) {
    mismatch('Git index canonical bytes ref and digest differ');
  }
  if (!Number.isSafeInteger(value.canonicalIndexByteCount) ||
      (value.canonicalIndexByteCount as number) <= 0 ||
      (value.canonicalIndexByteCount as number) > MAX_GIT_INDEX_BYTES) {
    mismatch('Git index canonical byte count is invalid');
  }
  requireObjectId(value.indexTreeObjectId, format, 'Git index tree');
  requireRef(value.snapshotDigest, 'Git index snapshot digest');
  let previousPath: string | undefined;
  for (const [index, item] of value.entries.entries()) {
    if (!isRecord(item) || !hasExactly(item, ['canonicalRootRelativePath', 'stage', 'mode',
      'objectId', 'assumeValid', 'skipWorktree'])) {
      mismatch(`Git index entry ${index} has an invalid closed shape`);
    }
    const entryPath = requireIndexPath(item.canonicalRootRelativePath);
    if (previousPath !== undefined &&
        Buffer.compare(Buffer.from(previousPath), Buffer.from(entryPath)) >= 0) {
      mismatch('Git index paths must be byte-sorted and unique');
    }
    previousPath = entryPath;
    if (item.stage !== 0 || (item.mode !== 33188 && item.mode !== 33261 && item.mode !== 40960) ||
        typeof item.assumeValid !== 'boolean' || item.skipWorktree !== false) {
      mismatch(`Git index entry ${index} is not a supported stage-zero entry`);
    }
    requireObjectId(item.objectId, format, `Git index entry ${index} object`);
  }
  const snapshot = value as GitIndexSnapshotV1;
  if (digestOmitting(snapshot, 'snapshotDigest') !== snapshot.snapshotDigest) {
    mismatch('Git index snapshot digest does not rehash');
  }
  return snapshot;
}

export function encodeCanonicalGitIndex(snapshot: GitIndexSnapshotV1): Buffer {
  const hashAlgorithm = snapshot.objectFormat;
  const objectIdBytes = hashAlgorithm === 'sha1' ? 20 : 32;
  let canonicalByteCount = 12 + objectIdBytes;
  for (const entry of snapshot.entries) {
    const entryBytes = Math.ceil((40 + objectIdBytes + 2 +
      Buffer.byteLength(entry.canonicalRootRelativePath, 'utf8') + 1) / 8) * 8;
    canonicalByteCount += entryBytes;
    if (canonicalByteCount > MAX_GIT_INDEX_BYTES) mismatch('canonical Git index exceeds the byte ceiling');
  }
  const header = Buffer.alloc(12);
  header.write('DIRC', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(snapshot.entries.length, 8);
  const records = snapshot.entries.map((entry) => {
    const name = Buffer.from(entry.canonicalRootRelativePath, 'utf8');
    const startOfName = 40 + objectIdBytes + 2;
    const length = Math.ceil((startOfName + name.byteLength + 1) / 8) * 8;
    const record = Buffer.alloc(length);
    record.writeUInt32BE(entry.mode, 24);
    Buffer.from(entry.objectId, 'hex').copy(record, 40);
    record.writeUInt16BE((entry.assumeValid ? 0x8000 : 0) | Math.min(name.byteLength, 0x0fff),
      40 + objectIdBytes);
    name.copy(record, startOfName);
    return record;
  });
  const content = Buffer.concat([header, ...records]);
  return Buffer.concat([content, createHash(hashAlgorithm).update(content).digest()]);
}

export type ParsedSourceGitIndex = Readonly<{
  snapshot: GitIndexSnapshotV1;
  canonicalBytes: Buffer;
  sourceVersion: 2 | 3 | 4;
}>;

/** Parse a complete held source index without asking Git to interpret source
 * config, filters, extensions or the working tree. Object existence and pack
 * closure are separate admission gates. */
export function parseSourceGitIndex(
  source: Uint8Array,
  repositoryIdentityDigest: string,
  objectFormat: 'sha1' | 'sha256'
): ParsedSourceGitIndex {
  requireRef(repositoryIdentityDigest, 'source Git index repository identity digest');
  if (objectFormat !== 'sha1' && objectFormat !== 'sha256') mismatch('source Git index object format is unsupported');
  if (source.byteLength > MAX_GIT_INDEX_BYTES) mismatch('source Git index exceeds the byte ceiling');
  const raw = Buffer.from(source);
  const objectIdBytes = objectFormat === 'sha1' ? 20 : 32;
  const bodyEnd = raw.byteLength - objectIdBytes;
  if (bodyEnd < 12 || raw.readUInt32BE(0) !== 0x44495243) mismatch('source Git index header is invalid');
  const version = raw.readUInt32BE(4);
  if (version !== 2 && version !== 3 && version !== 4) mismatch('source Git index version is unsupported');
  const declaredEntries = raw.readUInt32BE(8);
  const minimumEntryBytes = 40 + objectIdBytes + 2 + 1;
  if (declaredEntries > Math.floor((bodyEnd - 12) / minimumEntryBytes) ||
      !createHash(objectFormat).update(raw.subarray(0, bodyEnd)).digest()
        .equals(raw.subarray(bodyEnd))) {
    mismatch('source Git index entry count or checksum is invalid');
  }
  const entries: GitIndexSnapshotV1['entries'] = [];
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let canonicalByteCount = 12 + objectIdBytes;
  let offset = 12;
  let priorPath = Buffer.alloc(0);
  for (let index = 0; index < declaredEntries; index += 1) {
    const entryStart = offset;
    const fixedEnd = offset + 40 + objectIdBytes + 2;
    if (fixedEnd > bodyEnd) mismatch(`source Git index entry ${index} is truncated`);
    const mode = raw.readUInt32BE(offset + 24);
    if (mode !== 33188 && mode !== 33261 && mode !== 40960) {
      mismatch(`source Git index entry ${index} has an unsupported mode`);
    }
    const oid = raw.subarray(offset + 40, offset + 40 + objectIdBytes);
    if (oid.every((byte) => byte === 0)) mismatch(`source Git index entry ${index} has an empty object id`);
    const flags = raw.readUInt16BE(offset + 40 + objectIdBytes);
    if ((flags & 0x3000) !== 0 || (version === 2 && (flags & 0x4000) !== 0)) {
      mismatch(`source Git index entry ${index} has an unsupported stage or v2 flag`);
    }
    offset = fixedEnd;
    if ((flags & 0x4000) !== 0) {
      if (offset + 2 > bodyEnd || raw.readUInt16BE(offset) !== 0) {
        mismatch(`source Git index entry ${index} has unsupported extended flags`);
      }
      offset += 2;
    }
    let prefix = Buffer.alloc(0);
    if (version === 4) {
      if (offset >= bodyEnd) mismatch(`source Git index entry ${index} has invalid path compression`);
      let byte = raw[offset++]!;
      let removed = byte & 0x7f;
      while ((byte & 0x80) !== 0) {
        if (offset >= bodyEnd || removed > priorPath.byteLength) {
          mismatch(`source Git index entry ${index} has invalid path compression`);
        }
        byte = raw[offset++]!;
        removed = (removed + 1) * 128 + (byte & 0x7f);
      }
      if (removed > priorPath.byteLength) {
        mismatch(`source Git index entry ${index} has invalid path compression`);
      }
      prefix = priorPath.subarray(0, priorPath.byteLength - removed);
    }
    const terminator = raw.indexOf(0, offset);
    if (terminator < offset || terminator >= bodyEnd || terminator - offset > 4096) {
      mismatch(`source Git index entry ${index} has an unterminated or oversized path`);
    }
    const pathBytes = Buffer.concat([prefix, raw.subarray(offset, terminator)]);
    let entryPath: string;
    try { entryPath = requireIndexPath(decoder.decode(pathBytes)); }
    catch { mismatch(`source Git index entry ${index} has a noncanonical path`); }
    if (Buffer.compare(priorPath, pathBytes) >= 0 ||
        (flags & 0x0fff) !== Math.min(pathBytes.byteLength, 0x0fff)) {
      mismatch(`source Git index entry ${index} is unsorted or has a wrong path length`);
    }
    canonicalByteCount += Math.ceil((40 + objectIdBytes + 2 + pathBytes.byteLength + 1) / 8) * 8;
    if (canonicalByteCount > MAX_GIT_INDEX_BYTES) {
      mismatch('canonical Git index exceeds the byte ceiling');
    }
    priorPath = pathBytes;
    offset = terminator + 1;
    if (version !== 4) {
      const paddedEnd = entryStart + Math.ceil((offset - entryStart) / 8) * 8;
      if (paddedEnd > bodyEnd || !raw.subarray(offset, paddedEnd).every((byte) => byte === 0)) {
        mismatch(`source Git index entry ${index} has invalid padding`);
      }
      offset = paddedEnd;
    }
    entries.push({ canonicalRootRelativePath: entryPath, stage: 0,
      mode, objectId: oid.toString('hex'), assumeValid: (flags & 0x8000) !== 0,
      skipWorktree: false });
  }
  const extensions = new Set<string>();
  while (offset < bodyEnd) {
    if (bodyEnd - offset < 8) mismatch('source Git index extension header is truncated');
    const signature = raw.toString('latin1', offset, offset + 4);
    const size = raw.readUInt32BE(offset + 4);
    if (raw[offset]! < 0x41 || raw[offset]! > 0x5a || extensions.has(signature) ||
        size > bodyEnd - offset - 8) {
      mismatch(`source Git index has unsupported or invalid extension ${signature}`);
    }
    extensions.add(signature);
    offset += 8 + size;
  }
  const snapshot: GitIndexSnapshotV1 = {
    schemaVersion: 1, format: 'cliq-git-index-snapshot-v1',
    repositoryIdentityDigest, objectFormat, canonicalIndexVersion: 2, entries,
    canonicalIndexBytesRef: '', canonicalIndexBytesDigest: '', canonicalIndexByteCount: 0,
    indexTreeObjectId: '', snapshotDigest: ''
  };
  const canonicalBytes = encodeCanonicalGitIndex(snapshot);
  snapshot.canonicalIndexBytesRef = sha256Bytes(canonicalBytes);
  snapshot.canonicalIndexBytesDigest = snapshot.canonicalIndexBytesRef;
  snapshot.canonicalIndexByteCount = canonicalBytes.byteLength;
  snapshot.indexTreeObjectId = gitIndexTreeObjectId(snapshot);
  snapshot.snapshotDigest = digestOmitting(snapshot, 'snapshotDigest');
  return { snapshot: decodeGitIndexSnapshot(snapshot), canonicalBytes, sourceVersion: version };
}

export function gitIndexTreeObjectId(snapshot: GitIndexSnapshotV1): string {
  const root: TreeNode = { kind: 'tree', children: new Map() };
  for (const entry of snapshot.entries) {
    const parts = entry.canonicalRootRelativePath.split('/');
    let parent = root;
    for (const part of parts.slice(0, -1)) {
      const existing = parent.children.get(part);
      if (existing?.kind === 'leaf') mismatch('Git index has a file/directory path conflict');
      const child: TreeNode = existing ?? { kind: 'tree', children: new Map() };
      parent.children.set(part, child);
      parent = child;
    }
    const name = parts.at(-1)!;
    if (parent.children.has(name)) mismatch('Git index has a file/directory path conflict');
    parent.children.set(name, { kind: 'leaf', mode: entry.mode, objectId: entry.objectId });
  }
  const hashTree = (tree: TreeNode): string => {
    const children = [...tree.children].sort(([leftName, left], [rightName, right]) =>
      Buffer.compare(
        Buffer.from(`${leftName}${left.kind === 'tree' ? '/' : '\0'}`, 'utf8'),
        Buffer.from(`${rightName}${right.kind === 'tree' ? '/' : '\0'}`, 'utf8')
      ));
    const body = Buffer.concat(children.flatMap(([name, child]) => {
      const mode = child.kind === 'tree' ? '40000' : child.mode.toString(8);
      const objectId = child.kind === 'tree' ? hashTree(child) : child.objectId;
      return [Buffer.from(`${mode} ${name}\0`, 'utf8'), Buffer.from(objectId, 'hex')];
    }));
    return createHash(snapshot.objectFormat)
      .update(Buffer.from(`tree ${body.byteLength}\0`, 'utf8'))
      .update(body)
      .digest('hex');
  };
  return hashTree(root);
}

export async function readVerifiedGitIndexSnapshot(
  artifacts: ArtifactCatalog,
  ref: string,
  repositoryIdentityDigest: string,
  objectFormat: 'sha1' | 'sha256'
): Promise<GitIndexSnapshotV1> {
  const snapshot = decodeGitIndexSnapshot(await artifacts.readCanonical(ref));
  if (snapshot.repositoryIdentityDigest !== repositoryIdentityDigest ||
      snapshot.objectFormat !== objectFormat) {
    mismatch('Git index does not match the admitted repository identity');
  }
  const bytes = await artifacts.readBytes(snapshot.canonicalIndexBytesRef);
  if (bytes.byteLength !== snapshot.canonicalIndexByteCount ||
      !bytes.equals(encodeCanonicalGitIndex(snapshot))) {
    mismatch('Git index canonical bytes do not match its semantic snapshot');
  }
  if (gitIndexTreeObjectId(snapshot) !== snapshot.indexTreeObjectId) {
    mismatch('Git index tree does not match its semantic entries');
  }
  return snapshot;
}

export async function validateGitSourceIndex(
  artifacts: ArtifactCatalog,
  git: NonNullable<SourceManifest['git']>,
  repository: RepositoryIdentityV1
): Promise<GitIndexSnapshotV1> {
  if (git.repositoryIdentityDigest !== repository.repositoryIdentityDigest) {
    mismatch('SourceManifest Git identity differs from its retained repository');
  }
  const snapshot = await readVerifiedGitIndexSnapshot(
    artifacts, git.indexRef, repository.repositoryIdentityDigest, repository.objectFormat
  );
  if (git.indexTreeObjectId !== snapshot.indexTreeObjectId) {
    mismatch('SourceManifest Git tree differs from its index snapshot');
  }
  if (git.head.kind !== 'unborn') {
    requireObjectId(git.head.objectId, repository.objectFormat, 'SourceManifest Git HEAD');
  }
  return snapshot;
}
