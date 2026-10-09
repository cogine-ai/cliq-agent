import { createHash } from 'node:crypto';
import { KernelStorageError } from '../state/errors.js';

export type GitIndexEntry = Readonly<{
  canonicalRootRelativePath: string;
  stage: 0;
  mode: 33188 | 33261 | 40960;
  objectId: string;
  assumeValid: boolean;
  skipWorktree: false;
}>;
export type NormalizedGitIndex = Readonly<{
  entries: readonly GitIndexEntry[];
  canonicalBytes: Buffer;
  indexTreeObjectId: string;
}>;
type ObjectFormat = 'sha1' | 'sha256';
type Limits = Readonly<{ maxBytes: number; maxEntries: number }>;
function invalid(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', `Git index ${message}`); }
function checkedPath(bytes: Buffer): string {
  const path = bytes.toString('utf8');
  if (!Buffer.from(path).equals(bytes) || path !== path.normalize('NFC') || bytes.length > 4096 || path.includes('\\') ||
      path.includes('\0') || path.split('/').some(part => !part || part === '.' || part === '..' ||
        part.toLowerCase() === '.git' || Buffer.byteLength(part) > 255)) invalid('path is not canonical NFC root-relative UTF-8');
  return path;
}
function parse(bytes: Buffer, format: ObjectFormat, maxEntries: number): GitIndexEntry[] {
  const hashSize = format === 'sha1' ? 20 : 32, end = bytes.length - hashSize;
  if (end < 12 || !bytes.subarray(0, 4).equals(Buffer.from('DIRC'))) invalid('header is missing');
  if (!createHash(format).update(bytes.subarray(0, end)).digest().equals(bytes.subarray(end))) invalid('checksum differs');
  const version = bytes.readUInt32BE(4), count = bytes.readUInt32BE(8);
  if (![2, 3, 4].includes(version)) invalid('version is unsupported');
  if (count > maxEntries || count > Math.floor((end - 12) / (44 + hashSize))) invalid('entry count exceeds the bounded input');
  const entries: GitIndexEntry[] = [], folded = new Set<string>();
  let offset = 12;
  let previous: Buffer = Buffer.alloc(0);
  const take = (length: number) => {
    if (length > end - offset) invalid('entry or extension is truncated');
    const chunk = bytes.subarray(offset, offset + length); offset += length; return chunk;
  };
  for (let index = 0; index < count; index++) {
    const start = offset, fixed = take(42 + hashSize), flags = fixed.readUInt16BE(40 + hashSize);
    const mode = fixed.readUInt32BE(24), objectId = fixed.subarray(40, 40 + hashSize).toString('hex');
    if (![0o100644, 0o100755, 0o120000].includes(mode)) invalid('mode is not a regular file or symlink (gitlinks/sparse entries unsupported)');
    if (/^0+$/.test(objectId)) invalid('object id is zero');
    if (flags & 0x3000) invalid('unmerged stages are unsupported');
    if (flags & 0x4000) {
      if (version === 2) invalid('v2 extended flags are forbidden');
      if (take(2).readUInt16BE() !== 0) invalid('extended flags (intent-to-add/skip-worktree/reserved) are unsupported');
    }
    let remove = 0;
    if (version === 4) {
      // Git's OFS_DELTA encoding is not ULEB128. Each continuation adds one
      // before the next seven-bit shift (official Git varint.c).
      let octet = take(1)[0]; remove = octet & 0x7f;
      while (octet & 0x80) {
        octet = take(1)[0]; remove = (remove + 1) * 128 + (octet & 0x7f);
        if (!Number.isSafeInteger(remove) || remove > previous.length) invalid('v4 prefix removal is outside the previous path');
      }
      if (remove > previous.length) invalid('v4 prefix removal is outside the previous path');
    }
    const nul = bytes.indexOf(0, offset);
    if (nul < offset || nul >= end) invalid('path is not terminated');
    const suffix = take(nul - offset); take(1);
    const name = version === 4 ? Buffer.concat([previous.subarray(0, previous.length - remove), suffix]) : suffix;
    if ((flags & 0xfff) !== Math.min(name.length, 0xfff)) invalid('declared path length differs');
    const path = checkedPath(name);
    if (index && Buffer.compare(previous, name) >= 0) invalid('paths are duplicate or not byte-sorted');
    if (folded.has(path.toLowerCase())) invalid('paths have a case collision');
    folded.add(path.toLowerCase());
    if (version !== 4) {
      const padding = (8 - ((offset - start) % 8)) % 8;
      if (take(padding).some(byte => byte !== 0)) invalid('entry padding is nonzero');
    }
    previous = name;
    entries.push(Object.freeze({ canonicalRootRelativePath: path, stage: 0, mode: mode as GitIndexEntry['mode'],
      objectId, assumeValid: !!(flags & 0x8000), skipWorktree: false }));
  }
  while (offset < end) {
    const extension = take(8), signature = extension.subarray(0, 4), size = extension.readUInt32BE(4);
    if (signature[0] < 65 || signature[0] > 90) invalid('mandatory/split/sparse extension is unsupported');
    take(size); // Optional accelerator data has no semantic authority and is discarded.
  }
  return entries;
}
type Tree = { kind: 'tree'; children: Map<string, Node>; folded: Map<string, string>; objectId?: string };
type Node = Tree | { kind: 'entry'; entry: GitIndexEntry };
function treeObjectId(entries: readonly GitIndexEntry[], format: ObjectFormat): string {
  const root: Tree = { kind: 'tree', children: new Map(), folded: new Map() }, trees = [root];
  for (const entry of entries) {
    const parts = entry.canonicalRootRelativePath.split('/'); let tree = root;
    for (let index = 0; index < parts.length; index++) {
      const name = parts[index], folded = name.toLowerCase(), priorName = tree.folded.get(folded);
      if (priorName !== undefined && priorName !== name) invalid('directory ancestors have a case collision');
      tree.folded.set(folded, name);
      const existing = tree.children.get(name);
      if (index === parts.length - 1) {
        if (existing) invalid('file/directory path prefixes collide');
        tree.children.set(name, { kind: 'entry', entry });
      } else {
        if (existing?.kind === 'entry') invalid('file/directory path prefixes collide');
        if (existing) tree = existing;
        else {
          const child: Tree = { kind: 'tree', children: new Map(), folded: new Map() };
          tree.children.set(name, child); trees.push(child); tree = child;
        }
      }
    }
  }
  // Reverse creation order is bottom-up, without a call-stack limit.
  for (const tree of trees.reverse()) {
    const children = [...tree.children].sort(([a, left], [b, right]) =>
      Buffer.compare(Buffer.from(a + (left.kind === 'tree' ? '/' : '\0')), Buffer.from(b + (right.kind === 'tree' ? '/' : '\0'))));
    const body = Buffer.concat(children.flatMap(([name, node]) => [
      Buffer.from(`${node.kind === 'tree' ? '40000' : node.entry.mode.toString(8)} ${name}\0`),
      Buffer.from(node.kind === 'tree' ? node.objectId! : node.entry.objectId, 'hex')
    ]));
    tree.objectId = createHash(format).update(Buffer.from(`tree ${body.length}\0`)).update(body).digest('hex');
  }
  return root.objectId!;
}

/** Pure bounded metadata codec, not a Git-object existence or admission proof.
 * The trusted inspector separately validates every referenced blob/type and
 * exact reachable closure before publishing GitIndexSnapshot authority. */
export function normalizeGitIndex(input: Uint8Array, format: ObjectFormat, limits: Limits): NormalizedGitIndex {
  if (!(input instanceof Uint8Array) || (format !== 'sha1' && format !== 'sha256') ||
      !Number.isSafeInteger(limits.maxBytes) || limits.maxBytes < 1 || !Number.isSafeInteger(limits.maxEntries) || limits.maxEntries < 0 ||
      input.byteLength > limits.maxBytes) invalid('requires bounded bytes and an explicit object format');
  const entries = parse(Buffer.from(input), format, limits.maxEntries), hashSize = format === 'sha1' ? 20 : 32;
  const header = Buffer.from('444952430000000200000000', 'hex'); header.writeUInt32BE(entries.length, 8);
  const parts = [header]; let size = 12 + hashSize;
  for (const entry of entries) {
    const name = Buffer.from(entry.canonicalRootRelativePath), length = Math.ceil((42 + hashSize + name.length + 1) / 8) * 8;
    if (length > limits.maxBytes - size) invalid('canonical v2 bytes exceed the byte limit');
    const bytes = Buffer.alloc(length); bytes.writeUInt32BE(entry.mode, 24);
    Buffer.from(entry.objectId, 'hex').copy(bytes, 40);
    bytes.writeUInt16BE((entry.assumeValid ? 0x8000 : 0) | Math.min(name.length, 0xfff), 40 + hashSize);
    name.copy(bytes, 42 + hashSize); parts.push(bytes); size += length;
  }
  const body = Buffer.concat(parts); const canonicalBytes = Buffer.concat([body, createHash(format).update(body).digest()]);
  const reparsed = parse(canonicalBytes, format, limits.maxEntries);
  if (JSON.stringify(reparsed) !== JSON.stringify(entries)) invalid('canonical v2 reparse differs');
  return Object.freeze({ entries: Object.freeze(entries), canonicalBytes, indexTreeObjectId: treeObjectId(entries, format) });
}
