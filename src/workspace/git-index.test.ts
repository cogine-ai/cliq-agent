import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { devNull, tmpdir } from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { normalizeGitIndex } from './git-index.js';

async function gitFixture(t: TestContext, objectFormat: 'sha1' | 'sha256') {
  const directory = await mkdtemp(path.join(tmpdir(), 'cliq-index-codec-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const environment = { PATH: process.env.PATH, HOME: directory, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: devNull, GIT_ATTR_NOSYSTEM: '1', GIT_OPTIONAL_LOCKS: '0' };
  const git = (args: string[], indexFile?: string, input?: string) => {
    const result = spawnSync('git', args, { cwd: directory, env: { ...environment, ...(indexFile ? { GIT_INDEX_FILE: indexFile } : {}) }, encoding: 'utf8', input });
    assert.equal(result.status, 0, result.stderr); return result.stdout;
  };
  git(['init', '--quiet', '--initial-branch=main', `--object-format=${objectFormat}`]);
  await mkdir(path.join(directory, 'dir'));
  await writeFile(path.join(directory, 'dir', 'x'), 'nested\n');
  await writeFile(path.join(directory, 'dir.z'), 'directory sort\n');
  await writeFile(path.join(directory, 'exec'), '#!/bin/sh\n'); await chmod(path.join(directory, 'exec'), 0o755);
  await symlink('dir/x', path.join(directory, 'link'));
  git(['add', '--', 'dir', 'dir.z', 'exec', 'link']);
  git(['update-index', '--assume-unchanged', '--', 'exec']);
  git(['update-index', '--index-version=2']);
  return { directory, git, indexPath: path.join(directory, '.git', 'index') };
}

for (const kind of ['unmerged', 'gitlink', 'intent-to-add', 'skip-worktree', 'split', 'sparse'] as const) {
  test(`real Git ${kind} index is rejected rather than normalized into an admissible stage-0 tree`, async t => {
    const { directory, git, indexPath } = await gitFixture(t, 'sha1');
    const oid = git(['rev-parse', ':dir/x']).trim();
    if (kind === 'unmerged') git(['update-index', '--index-info'], undefined, `100644 ${oid} 1\tconflict\n`);
    if (kind === 'gitlink') git(['update-index', '--add', '--cacheinfo', `160000,${oid},module`]);
    if (kind === 'intent-to-add') {
      await writeFile(path.join(directory, 'intent'), 'not staged'); git(['add', '--intent-to-add', '--', 'intent']);
      assert.equal((await readFile(indexPath)).readUInt32BE(4), 3);
    }
    if (kind === 'skip-worktree') git(['update-index', '--skip-worktree', '--', 'dir/x']);
    if (kind === 'split') git(['update-index', '--split-index']);
    if (kind === 'sparse') {
      await mkdir(path.join(directory, 'other')); await writeFile(path.join(directory, 'other', 'file'), 'outside cone');
      git(['add', '--', 'other']);
      git(['-c', 'user.name=IndexCodec', '-c', 'user.email=codec@example.invalid', 'commit', '--quiet', '-m', 'fixture']);
      git(['sparse-checkout', 'init', '--cone', '--sparse-index']); git(['sparse-checkout', 'set', 'dir']);
    }
    const raw = await readFile(indexPath);
    assert.throws(() => normalizeGitIndex(raw, 'sha1', { maxBytes: 1024 * 1024, maxEntries: 100 }), { code: 'ARTIFACT_MISMATCH' });
  });
}

test('canonical v2 index roundtrips real Git entries and independently agrees with Git tree construction', async t => {
  const { directory, git, indexPath } = await gitFixture(t, 'sha1');
  const bytes = await readFile(indexPath);
  const expectedStage = git(['ls-files', '--stage', '-z']), expectedTree = git(['write-tree']).trim();
  const normalized = normalizeGitIndex(bytes, 'sha1', { maxBytes: 1024 * 1024, maxEntries: 100 });
  assert.equal(normalized.indexTreeObjectId, expectedTree);
  assert.deepEqual(normalized.entries.map(entry => [entry.canonicalRootRelativePath, entry.mode, entry.assumeValid]),
    [['dir.z', 0o100644, false], ['dir/x', 0o100644, false], ['exec', 0o100755, true], ['link', 0o120000, false]]);
  const canonical = path.join(directory, 'canonical-index'); await writeFile(canonical, normalized.canonicalBytes);
  assert.equal(git(['ls-files', '--stage', '-z'], canonical), expectedStage);
  assert.equal(git(['write-tree'], canonical).trim(), expectedTree);
  assert.equal(normalized.canonicalBytes.readUInt32BE(4), 2);
  const reparsed = normalizeGitIndex(normalized.canonicalBytes, 'sha1', { maxBytes: 1024 * 1024, maxEntries: 100 });
  assert.deepEqual(reparsed.entries, normalized.entries);
  assert.deepEqual(reparsed.canonicalBytes, normalized.canonicalBytes);
});

function rechecksum(bytes: Buffer, format: 'sha1' | 'sha256'): Buffer {
  const width = format === 'sha1' ? 20 : 32, body = bytes.subarray(0, bytes.length - width);
  return Buffer.concat([body, createHash(format).update(body).digest()]);
}

test('checksummed non-DIRC high-bit headers cannot be accepted as an ASCII lookalike', async t => {
  const { indexPath } = await gitFixture(t, 'sha1');
  const bytes = await readFile(indexPath); bytes[0] |= 0x80;
  assert.throws(() => normalizeGitIndex(rechecksum(bytes, 'sha1'), 'sha1', { maxBytes: 1024 * 1024, maxEntries: 100 }), /header/);
});

for (const format of ['sha1', 'sha256'] as const) {
  test(`${format} real Git v2/v4 and Git-validated v3 normalize to one extension-free zero-stat v2`, async t => {
    const { directory, git, indexPath } = await gitFixture(t, format);
    // Different 180-byte names exercise the real v4 multi-byte OFS_DELTA varint.
    const a = 'a'.repeat(180), b = 'b'.repeat(180);
    await writeFile(path.join(directory, a), 'long-a'); await writeFile(path.join(directory, b), 'long-b');
    git(['add', '--', a, b]); git(['update-index', '--index-version=2']);
    const v2 = await readFile(indexPath);
    assert.equal(v2.readUInt32BE(4), 2);
    const stage = git(['ls-files', '--stage', '-z']), tree = git(['write-tree']).trim();
    const limits = { maxBytes: 1024 * 1024, maxEntries: 100 };
    const baseline = normalizeGitIndex(v2, format, limits);
    // Git's writer demotes v3 without extended bits to v2. Change only the
    // legal version header/checksum, then independently let Git validate v3.
    const v3Body = Buffer.from(v2); v3Body.writeUInt32BE(3, 4);
    const v3 = rechecksum(v3Body, format), v3Path = path.join(directory, 'v3-index');
    await writeFile(v3Path, v3);
    assert.equal(git(['ls-files', '--stage', '-z'], v3Path), stage);
    assert.equal(git(['write-tree'], v3Path).trim(), tree);
    git(['update-index', '--index-version=4']);
    const v4 = await readFile(indexPath); assert.equal(v4.readUInt32BE(4), 4);
    for (const input of [v2, v3, v4]) {
      const normalized = normalizeGitIndex(input, format, limits);
      assert.deepEqual(normalized.canonicalBytes, baseline.canonicalBytes);
      assert.equal(normalized.indexTreeObjectId, tree);
    }
    const canonical = path.join(directory, 'canonical-index'); await writeFile(canonical, baseline.canonicalBytes);
    assert.equal(git(['ls-files', '--stage', '-z'], canonical), stage);
    const debug = git(['ls-files', '--debug'], canonical);
    assert.equal((debug.match(/ctime:\s+0:0/g) ?? []).length, baseline.entries.length);
    assert.equal((debug.match(/mtime:\s+0:0/g) ?? []).length, baseline.entries.length);
    assert.equal(git(['write-tree'], canonical).trim(), tree);
  });
}

test('complete input parsing rejects checksum, padding, framing, flags and malformed path/object metadata', async t => {
  const { indexPath } = await gitFixture(t, 'sha1'), raw = await readFile(indexPath);
  const limits = { maxBytes: 1024 * 1024, maxEntries: 100 };
  const mutations: [string, (bytes: Buffer) => void][] = [
    ['unsupported version', bytes => bytes.writeUInt32BE(5, 4)],
    ['impossible count', bytes => bytes.writeUInt32BE(0xffffffff, 8)],
    ['invalid mode', bytes => bytes.writeUInt32BE(0o100600, 12 + 24)],
    ['zero object id', bytes => bytes.fill(0, 12 + 40, 12 + 60)],
    ['v2 extended flags', bytes => bytes.writeUInt16BE(bytes.readUInt16BE(12 + 60) | 0x4000, 12 + 60)],
    ['false name length', bytes => bytes.writeUInt16BE(1, 12 + 60)],
    ['absolute path', bytes => { bytes[12 + 62] = 47; }],
    ['embedded NUL', bytes => { bytes[12 + 64] = 0; }],
    ['forbidden Git path', bytes => { Buffer.from('.git/').copy(bytes, 12 + 62); }],
    ['duplicate path', bytes => { Buffer.from('dir/x').copy(bytes, 12 + 62); }],
    ['invalid UTF-8', bytes => { bytes[12 + 62] = 0xff; }],
    ['nonzero padding', bytes => { bytes[12 + 68] = 1; }]
  ];
  for (const [label, mutate] of mutations) {
    const changed = Buffer.from(raw); mutate(changed);
    assert.throws(() => normalizeGitIndex(rechecksum(changed, 'sha1'), 'sha1', limits), { code: 'ARTIFACT_MISMATCH' }, label);
  }
  const zeroChecksum = Buffer.from(raw); zeroChecksum.fill(0, raw.length - 20);
  assert.throws(() => normalizeGitIndex(zeroChecksum, 'sha1', limits), /checksum/);
  const corrupted = Buffer.from(raw); corrupted[12] ^= 1;
  assert.throws(() => normalizeGitIndex(corrupted, 'sha1', limits), /checksum/);
  assert.throws(() => normalizeGitIndex(raw.subarray(0, raw.length - 1), 'sha1', limits), { code: 'ARTIFACT_MISMATCH' });
  assert.throws(() => normalizeGitIndex(raw, 'sha256', limits), /checksum/);
  assert.throws(() => normalizeGitIndex(raw, 'sha1', { ...limits, maxBytes: raw.length - 1 }), /bounded bytes/);
  assert.throws(() => normalizeGitIndex(raw, 'sha1', { ...limits, maxEntries: 3 }), /entry count/);
});

test('optional accelerator extensions are discarded but mandatory or truncated extensions are rejected', async t => {
  const { indexPath } = await gitFixture(t, 'sha1'), raw = await readFile(indexPath);
  const limits = { maxBytes: 1024 * 1024, maxEntries: 100 }, base = normalizeGitIndex(raw, 'sha1', limits);
  const extension = (signature: string, size: number, data: Buffer) => {
    const header = Buffer.alloc(8); header.write(signature, 0, 4, 'ascii'); header.writeUInt32BE(size, 4);
    const body = Buffer.concat([raw.subarray(0, raw.length - 20), header, data]);
    return Buffer.concat([body, createHash('sha1').update(body).digest()]);
  };
  assert.deepEqual(normalizeGitIndex(extension('ZZZZ', 3, Buffer.from('xyz')), 'sha1', limits).canonicalBytes, base.canonicalBytes);
  for (const mandatory of ['link', 'sdir', 'abcd'])
    assert.throws(() => normalizeGitIndex(extension(mandatory, 0, Buffer.alloc(0)), 'sha1', limits), /mandatory/);
  assert.throws(() => normalizeGitIndex(extension('TREE', 100, Buffer.alloc(1)), 'sha1', limits), /truncated/);
});

for (const paths of [['caf\u00e9', 'cafe\u0301'], ['File', 'file'], ['A/x', 'a/y']] as const) {
  test(`Git-index semantic path validation rejects ${JSON.stringify(paths)} without normalizing names`, async t => {
    const { directory, git, indexPath } = await gitFixture(t, 'sha1'), oid = git(['rev-parse', ':dir/x']).trim();
    // --index-info addresses raw metadata, independent of host filesystem
    // Unicode/case folding; Git itself permits these exact distinct names.
    const input = paths.map(name => `100644 ${oid}\t${name}\n`).join('');
    const alternate = path.join(directory, 'paths-index');
    git(['update-index', '--index-info'], alternate, input);
    const raw = await readFile(alternate);
    assert.throws(() => normalizeGitIndex(raw, 'sha1', { maxBytes: 1024 * 1024, maxEntries: 100 }), /NFC|case collision/);
    assert.ok((await readFile(indexPath)).length > 0);
  });
}

test('v4 malformed prefix varints cannot escape the previous-name bound or expand past canonical byte limits', async t => {
  const { directory, git, indexPath } = await gitFixture(t, 'sha1');
  for (let index = 0; index < 40; index++) {
    const name = `shared-${'x'.repeat(150)}-${String(index).padStart(3, '0')}`;
    await writeFile(path.join(directory, name), 'x'); git(['add', '--', name]);
  }
  git(['update-index', '--index-version=4']); const v4 = await readFile(indexPath);
  assert.equal(v4.readUInt32BE(4), 4);
  const limits = { maxBytes: 1024 * 1024, maxEntries: 100 };
  const corrupt = Buffer.from(v4); corrupt[12 + 62] = 0x7f;
  assert.throws(() => normalizeGitIndex(rechecksum(corrupt, 'sha1'), 'sha1', limits), /prefix removal/);
  const continuation = Buffer.from(v4); continuation.fill(0x80, 12 + 62, 12 + 72);
  assert.throws(() => normalizeGitIndex(rechecksum(continuation, 'sha1'), 'sha1', limits), /prefix removal/);
  assert.throws(() => normalizeGitIndex(v4, 'sha1', { ...limits, maxBytes: v4.length }), /canonical v2 bytes/);
});

for (const format of ['sha1', 'sha256'] as const) {
  test(`empty ${format} index has Git's exact empty tree identity and remains a checksummed canonical index`, async t => {
    const { directory, git } = await gitFixture(t, format);
    const alternate = path.join(directory, 'empty-index'); git(['read-tree', '--empty'], alternate);
    const bytes = await readFile(alternate);
    const result = normalizeGitIndex(bytes, format, { maxBytes: bytes.length, maxEntries: 0 });
    assert.deepEqual(result.entries, []);
    // read-tree writes an optional TREE accelerator even for the empty index;
    // canonical output must discard it, not preserve Git's raw bytes.
    assert.equal(result.canonicalBytes.length, format === 'sha1' ? 32 : 44);
    assert.deepEqual(result.canonicalBytes.subarray(0, 12), Buffer.from('444952430000000200000000', 'hex'));
    assert.equal(result.indexTreeObjectId, git(['write-tree'], alternate).trim());
    await writeFile(alternate, result.canonicalBytes);
    assert.equal(git(['ls-files', '-z'], alternate), '');
    assert.equal(git(['write-tree'], alternate).trim(), result.indexTreeObjectId);
  });
}
