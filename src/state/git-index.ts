import { createHash } from 'node:crypto';

import { normalizeCanonicalText } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting } from '../kernel/identity.js';
import type { GitIndexSnapshotV1, RepositoryIdentityV1, SourceManifest } from '../kernel/types.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';

type TreeNode = { kind: 'tree'; children: Map<string, TreeNode | TreeLeaf> };
type TreeLeaf = { kind: 'leaf'; mode: 33188 | 33261 | 40960; objectId: string };

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
      (value.canonicalIndexByteCount as number) <= 0) {
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
