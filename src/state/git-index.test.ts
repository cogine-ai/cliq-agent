import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { GitIndexSnapshotV1, SourceManifest } from '../kernel/types.js';
import { decodeSourceManifest } from './decoders.js';
import {
  decodeGitIndexSnapshot,
  encodeCanonicalGitIndex,
  gitIndexTreeObjectId,
  parseSourceGitIndex,
  readVerifiedGitIndexSnapshot
} from './git-index.js';
import { openStateStore } from './store.js';

// Produced independently by Git 2.x using update-index --index-info on an
// empty SHA-1 repository, before Git adds its optional TREE cache extension.
const GIT_V2_SINGLE_FILE_HEX =
  '444952430000000200000001000000000000000000000000000000000000000000000000000081a4' +
  '0000000000000000000000002e65efe2a145dda7ee51d1741299f848e5bf752e00086669' +
  '6c652e747874000051aa82942005b61a5ef54f18357cb34ad22fd988';
const GIT_SINGLE_FILE_TREE_ID = 'a850b92ee00d4305535f8410f485631e68197856';
const GIT_SHA256_V2_SINGLE_FILE_HEX =
  '444952430000000200000001000000000000000000000000000000000000000000000000000081a4' +
  '000000000000000000000000eb337bcee2061c5313c9a1392116b6c76039e9e30d71467ae' +
  '359b36277e17dc7000866696c652e747874000000000000ccd436c08461e3b367f3dbb3' +
  'dc4b2dfb06ffde6ee4d7fe417d1718d74a951d3a';

function indexWithChecksum(content: Buffer, format: 'sha1' | 'sha256'): Buffer {
  return Buffer.concat([content, createHash(format).update(content).digest()]);
}

function oneFileSnapshot(): GitIndexSnapshotV1 {
  const bytes = Buffer.from(GIT_V2_SINGLE_FILE_HEX, 'hex');
  const ref = sha256Bytes(bytes);
  const snapshot: GitIndexSnapshotV1 = {
    schemaVersion: 1, format: 'cliq-git-index-snapshot-v1',
    repositoryIdentityDigest: 'a'.repeat(64), objectFormat: 'sha1',
    canonicalIndexVersion: 2,
    entries: [{
      canonicalRootRelativePath: 'file.txt', stage: 0, mode: 33188,
      objectId: '2e65efe2a145dda7ee51d1741299f848e5bf752e',
      assumeValid: false, skipWorktree: false
    }],
    canonicalIndexBytesRef: ref, canonicalIndexBytesDigest: ref,
    canonicalIndexByteCount: bytes.byteLength,
    indexTreeObjectId: GIT_SINGLE_FILE_TREE_ID, snapshotDigest: ''
  };
  snapshot.snapshotDigest = digestOmitting(snapshot, 'snapshotDigest');
  return snapshot;
}

test('canonical Git v2 bytes and tree id match an independently produced Git index', () => {
  const snapshot = oneFileSnapshot();
  assert.deepEqual(decodeGitIndexSnapshot(snapshot), snapshot);
  assert.equal(encodeCanonicalGitIndex(snapshot).toString('hex'), GIT_V2_SINGLE_FILE_HEX);
  assert.equal(gitIndexTreeObjectId(snapshot), GIT_SINGLE_FILE_TREE_ID);
  const empty: GitIndexSnapshotV1 = {
    ...snapshot, entries: [], canonicalIndexByteCount: 32,
    indexTreeObjectId: '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
  };
  assert.equal(gitIndexTreeObjectId(empty), empty.indexTreeObjectId);

  const nested: GitIndexSnapshotV1 = {
    ...snapshot,
    entries: [
      { ...snapshot.entries[0]!, canonicalRootRelativePath: 'a.txt' },
      { canonicalRootRelativePath: 'sub/b.txt', stage: 0, mode: 33261,
        objectId: '63d8dbd40c23542e740659a7168a0ce3138ea748',
        assumeValid: false, skipWorktree: false }
    ]
  };
  assert.equal(gitIndexTreeObjectId(nested), '4be3403442aae4335992ab28ac39de789000db7a');
  assert.throws(() => gitIndexTreeObjectId({ ...nested,
    entries: [{ ...nested.entries[0]!, canonicalRootRelativePath: 'sub' }, nested.entries[1]!]
  }), /path conflict/);
});

test('SHA-256 Git index bytes and tree id match Git object-format sha256', () => {
  const sha1 = oneFileSnapshot();
  const sha256: GitIndexSnapshotV1 = {
    ...sha1, objectFormat: 'sha256',
    entries: [{ ...sha1.entries[0]!,
      objectId: 'eb337bcee2061c5313c9a1392116b6c76039e9e30d71467ae359b36277e17dc7'
    }],
    indexTreeObjectId: '208d6923681d52d8033bedb526c8c4d68312e6b44c24eec6f36dfc847c047745',
    canonicalIndexBytesRef: sha256Bytes(Buffer.from(GIT_SHA256_V2_SINGLE_FILE_HEX, 'hex')),
    canonicalIndexBytesDigest: sha256Bytes(Buffer.from(GIT_SHA256_V2_SINGLE_FILE_HEX, 'hex')),
    canonicalIndexByteCount: Buffer.from(GIT_SHA256_V2_SINGLE_FILE_HEX, 'hex').byteLength,
    snapshotDigest: ''
  };
  sha256.snapshotDigest = digestOmitting(sha256, 'snapshotDigest');
  assert.deepEqual(decodeGitIndexSnapshot(sha256), sha256);
  assert.equal(encodeCanonicalGitIndex(sha256).toString('hex'), GIT_SHA256_V2_SINGLE_FILE_HEX);
  assert.equal(gitIndexTreeObjectId(sha256), sha256.indexTreeObjectId);
});

test('source Git index v2/v3 and SHA-256 bytes normalize to the exact retained v2 image', () => {
  const source = Buffer.from(GIT_V2_SINGLE_FILE_HEX, 'hex');
  const parsed = parseSourceGitIndex(source, 'a'.repeat(64), 'sha1');
  assert.equal(parsed.sourceVersion, 2);
  assert.deepEqual(parsed.canonicalBytes, source);
  assert.equal(parsed.snapshot.indexTreeObjectId, GIT_SINGLE_FILE_TREE_ID);
  assert.deepEqual(parsed.snapshot.entries, oneFileSnapshot().entries);

  const version3 = Buffer.from(source.subarray(0, -20));
  version3.writeUInt32BE(3, 4);
  const parsedV3 = parseSourceGitIndex(indexWithChecksum(version3, 'sha1'), 'a'.repeat(64), 'sha1');
  assert.equal(parsedV3.sourceVersion, 3);
  assert.deepEqual(parsedV3.canonicalBytes, source);

  const extendedHeader = Buffer.from(version3.subarray(0, 12));
  const fixedEntry = Buffer.from(source.subarray(12, 74));
  fixedEntry.writeUInt16BE(0x4000 | 8, 60);
  const extendedEntry = Buffer.concat([
    fixedEntry, Buffer.alloc(2), Buffer.from('file.txt\0'), Buffer.alloc(7)
  ]);
  const extendedV3 = indexWithChecksum(Buffer.concat([extendedHeader, extendedEntry]), 'sha1');
  assert.deepEqual(parseSourceGitIndex(extendedV3, 'a'.repeat(64), 'sha1').canonicalBytes, source);

  const sha256Source = Buffer.from(GIT_SHA256_V2_SINGLE_FILE_HEX, 'hex');
  const parsedSha256 = parseSourceGitIndex(sha256Source, 'a'.repeat(64), 'sha256');
  assert.equal(parsedSha256.snapshot.objectFormat, 'sha256');
  assert.deepEqual(parsedSha256.canonicalBytes, sha256Source);

  const empty = Buffer.alloc(12);
  empty.write('DIRC', 0, 'ascii');
  empty.writeUInt32BE(2, 4);
  const parsedEmpty = parseSourceGitIndex(indexWithChecksum(empty, 'sha1'), 'a'.repeat(64), 'sha1');
  assert.deepEqual(parsedEmpty.snapshot.entries, []);
  assert.equal(parsedEmpty.snapshot.indexTreeObjectId, '4b825dc642cb6eb9a060e54bf8d69288fbee4904');
});

test('source Git index rejects bad checksum, stage, gitlink, path, object and mandatory extension', () => {
  const source = Buffer.from(GIT_V2_SINGLE_FILE_HEX, 'hex');
  const mutate = (change: (content: Buffer) => void): Buffer => {
    const content = Buffer.from(source.subarray(0, -20));
    change(content);
    return indexWithChecksum(content, 'sha1');
  };
  const corrupt = Buffer.from(source);
  corrupt[corrupt.length - 1] ^= 1;
  assert.throws(() => parseSourceGitIndex(corrupt, 'a'.repeat(64), 'sha1'), /checksum/);
  assert.throws(() => parseSourceGitIndex(mutate((content) => { content[0] |= 0x80; }),
    'a'.repeat(64), 'sha1'), /header/);
  assert.throws(() => parseSourceGitIndex(mutate((content) => { content[72] |= 0x10; }),
    'a'.repeat(64), 'sha1'), /stage/);
  assert.throws(() => parseSourceGitIndex(mutate((content) => { content.writeUInt32BE(0o160000, 36); }),
    'a'.repeat(64), 'sha1'), /mode/);
  assert.throws(() => parseSourceGitIndex(mutate((content) => { content.fill(0, 52, 72); }),
    'a'.repeat(64), 'sha1'), /empty object id/);
  assert.throws(() => parseSourceGitIndex(mutate((content) => { content[74] = 0xff; }),
    'a'.repeat(64), 'sha1'), /noncanonical path/);
  assert.throws(() => parseSourceGitIndex(mutate((content) => { content[73] = 7; }),
    'a'.repeat(64), 'sha1'), /wrong path length/);
  const body = source.subarray(0, -20);
  const extension = Buffer.alloc(8);
  extension.write('link', 0, 'ascii');
  assert.throws(() => parseSourceGitIndex(indexWithChecksum(Buffer.concat([body, extension]), 'sha1'),
    'a'.repeat(64), 'sha1'), /extension/);
  extension.write('TREE', 0, 'ascii');
  assert.equal(parseSourceGitIndex(indexWithChecksum(Buffer.concat([body, extension]), 'sha1'),
    'a'.repeat(64), 'sha1').snapshot.entries.length, 1);
});

test('source Git index v4 path compression matches a Git-produced index', async () => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-git-v4-'));
  try {
    execFileSync('git', ['init', '-q', root]);
    await writeFile(path.join(root, 'alpha.txt'), 'alpha');
    await writeFile(path.join(root, 'alphabet.txt'), 'alphabet');
    const longA = `${'a'.repeat(180)}.txt`;
    const longB = `${'b'.repeat(180)}.txt`;
    await writeFile(path.join(root, longA), 'a');
    await writeFile(path.join(root, longB), 'b');
    execFileSync('git', ['-C', root, 'add', '--', longA, longB, 'alpha.txt', 'alphabet.txt']);
    execFileSync('git', ['-C', root, 'update-index', '--index-version', '4']);
    const source = await readFile(path.join(root, '.git', 'index'));
    const parsed = parseSourceGitIndex(source, 'a'.repeat(64), 'sha1');
    assert.equal(parsed.sourceVersion, 4);
    assert.deepEqual(parsed.snapshot.entries.map((entry) => entry.canonicalRootRelativePath),
      [longA, 'alpha.txt', 'alphabet.txt', longB]);
    assert.equal(parsed.canonicalBytes.readUInt32BE(4), 2);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('Git index snapshot rejects rehashed unsupported entry semantics', () => {
  const snapshot = oneFileSnapshot();
  const rehash = (entries: GitIndexSnapshotV1['entries']) => {
    const changed = { ...snapshot, entries, snapshotDigest: '' };
    changed.snapshotDigest = digestOmitting(changed, 'snapshotDigest');
    return changed;
  };
  assert.throws(() => decodeGitIndexSnapshot(rehash([
    { ...snapshot.entries[0]!, stage: 1 as 0 }
  ])), /stage-zero/);
  assert.throws(() => decodeGitIndexSnapshot(rehash([
    { ...snapshot.entries[0]!, skipWorktree: true as false }
  ])), /stage-zero/);
  assert.throws(() => decodeGitIndexSnapshot(rehash([
    { ...snapshot.entries[0]!, canonicalRootRelativePath: '../escape' }
  ])), /in-root path/);
  assert.throws(() => decodeGitIndexSnapshot(rehash([
    { ...snapshot.entries[0]!, canonicalRootRelativePath: '.GiT/config' }
  ])), /in-root path/);
  assert.throws(() => decodeGitIndexSnapshot({ ...snapshot, extra: 'extension' }), /closed shape/);
});

test('SourceManifest rejects rehashed Git extensions and invalid HEAD forms', () => {
  const source: SourceManifest = {
    schemaVersion: 1, format: 'cliq-source-manifest-v1', role: 'base',
    workspaceIdentityDigest: 'a'.repeat(64), entriesRef: 'b'.repeat(64),
    sourceProjectionRef: 'c'.repeat(64), sourceProjectionDigest: 'd'.repeat(64),
    frozenIgnoreRulesRef: 'e'.repeat(64), frozenIgnoreRulesDigest: 'f'.repeat(64),
    git: { repositoryIdentityDigest: 'a'.repeat(64),
      head: { kind: 'unborn', branch: 'refs/heads/main' }, indexRef: 'b'.repeat(64),
      indexTreeObjectId: GIT_SINGLE_FILE_TREE_ID },
    treeDigest: 'a'.repeat(64), manifestDigest: ''
  };
  source.manifestDigest = digestOmitting(source, 'manifestDigest');
  assert.deepEqual(decodeSourceManifest(source), source);
  const extension = { ...source, unexpected: true, manifestDigest: '' };
  extension.manifestDigest = digestOmitting(extension, 'manifestDigest');
  assert.throws(() => decodeSourceManifest(extension), /closed shape/);
  const gitExtension = { ...source, git: { ...source.git!, unexpected: true }, manifestDigest: '' };
  gitExtension.manifestDigest = digestOmitting(gitExtension, 'manifestDigest');
  assert.throws(() => decodeSourceManifest(gitExtension), /git.*closed shape/i);
  const badHead = { ...source, git: { ...source.git!,
    head: { kind: 'unborn', branch: 'refs/heads/../unsafe' } }, manifestDigest: '' };
  badHead.manifestDigest = digestOmitting(badHead, 'manifestDigest');
  assert.throws(() => decodeSourceManifest(badHead), /head ref/);
  const wrongPair = { ...source, git: { ...source.git!, indexRef: 'invalid' }, manifestDigest: '' };
  wrongPair.manifestDigest = digestOmitting(wrongPair, 'manifestDigest');
  assert.throws(() => decodeSourceManifest(wrongPair), /ArtifactRef/);
});

test('Git index closure reopens and compares exact CAS bytes and tree', async () => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-git-index-'));
  await chmod(root, 0o700);
  const store = await openStateStore(root);
  try {
    const snapshot = oneFileSnapshot();
    await store.artifacts.publishBytes(
      Buffer.from(GIT_V2_SINGLE_FILE_HEX, 'hex'), 'application/octet-stream', 'cliq-git-index-canonical-v2'
    );
    const saved = await store.artifacts.publishCanonical(snapshot, snapshot.format);
    assert.deepEqual(await readVerifiedGitIndexSnapshot(
      store.artifacts, saved.ref, snapshot.repositoryIdentityDigest, 'sha1'
    ), snapshot);
    await assert.rejects(() => readVerifiedGitIndexSnapshot(
      store.artifacts, saved.ref, snapshot.repositoryIdentityDigest, 'sha256'
    ), /repository identity/);
    const wrongTree = { ...snapshot, indexTreeObjectId: '0'.repeat(40), snapshotDigest: '' };
    wrongTree.snapshotDigest = digestOmitting(wrongTree, 'snapshotDigest');
    const wrongTreeRef = (await store.artifacts.publishCanonical(wrongTree, snapshot.format)).ref;
    await assert.rejects(() => readVerifiedGitIndexSnapshot(
      store.artifacts, wrongTreeRef, snapshot.repositoryIdentityDigest, 'sha1'
    ), /tree does not match/);
    const wrongBytes = { ...snapshot,
      canonicalIndexBytesRef: '0'.repeat(64), canonicalIndexBytesDigest: '0'.repeat(64),
      snapshotDigest: '' };
    wrongBytes.snapshotDigest = digestOmitting(wrongBytes, 'snapshotDigest');
    const wrongBytesRef = (await store.artifacts.publishCanonical(wrongBytes, snapshot.format)).ref;
    await assert.rejects(() => readVerifiedGitIndexSnapshot(
      store.artifacts, wrongBytesRef, snapshot.repositoryIdentityDigest, 'sha1'
    ));
  } finally {
    await store.close();
    await rm(root, { recursive: true, force: true });
  }
});
