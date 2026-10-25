import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import { compileFrozenIgnoreRules, isFrozenPathIgnored, readFrozenIgnoreRules, validateFrozenIgnoreRules } from './frozen-ignore.js';
import { ArtifactCatalog } from '../state/artifacts.js';
import { ContentAddressedStore } from '../state/cas.js';

const repositoryIdentityDigest = 'a'.repeat(64);
const rules = (text: string) => compileFrozenIgnoreRules([{ kind: 'gitignore', path: '.gitignore', bytes: Buffer.from(text) }], repositoryIdentityDigest);

test('frozen ignore rules preserve source order, escaped syntax and canonical source identities', () => {
  const input = [{ kind: 'gitignore' as const, path: 'nested/.gitignore', bytes: Buffer.from('!keep\n') },
    { kind: 'git_info_exclude' as const, path: '.git/info/exclude', bytes: Buffer.from('*.tmp\n') },
    { kind: 'gitignore' as const, path: '.gitignore', bytes: Buffer.from('# comment\n\\#literal\n\\!literal\nspace\\ \n') }];
  const result = compileFrozenIgnoreRules(input, repositoryIdentityDigest);
  assert.deepEqual(result.sources.map(item => item.canonicalRootRelativePath), ['.git/info/exclude', '.gitignore', 'nested/.gitignore']);
  assert.equal(result.sources[0]!.contentDigest, sha256Bytes(input[1]!.bytes));
  assert.equal(result.sources[0]!.contentRef, result.sources[0]!.contentDigest);
  assert.deepEqual(result.rules.map(item => item.order), [0, 1, 2, 3, 4]);
  assert.equal(result.rulesDigest, digestOmitting(result, 'rulesDigest'));
  assert.deepEqual(validateFrozenIgnoreRules(result), result);
  for (const file of ['#literal', '!literal', 'space ', 'nested/file.tmp']) assert(isFrozenPathIgnored(result, file, false));
  assert.equal(isFrozenPathIgnored(result, 'nested/keep', false), false);
  assert(Object.isFrozen(result)); assert(Object.isFrozen(result.rules));
});

test('frozen ignore matching handles slash boundaries, globstar, classes and excluded-parent re-inclusion', () => {
  const input = rules('*.log\n/root-only\ncache/\n!cache/keep\na/**/z\n**/deep\nx[0-9].txt\nq[!ab]\nfile?.tmp\n');
  for (const file of ['file.log', 'nested/file.log', 'root-only', 'cache/file', 'cache/keep', 'a/z', 'a/b/c/z',
    'deep', 'n/deep', 'x4.txt', 'qc', 'file1.tmp']) assert(isFrozenPathIgnored(input, file, false), file);
  for (const file of ['nested/root-only', 'cache-file', 'a/b/y', 'xa.txt', 'qa', 'file12.tmp'])
    assert.equal(isFrozenPathIgnored(input, file, false), false, file);
  assert(isFrozenPathIgnored(input, 'cache', true)); assert.equal(isFrozenPathIgnored(input, 'cache', false), false);
  const reinclude = rules('cache/*\n!cache/keep\n');
  assert.equal(isFrozenPathIgnored(reinclude, 'cache/keep', false), false);
  assert(isFrozenPathIgnored(reinclude, 'cache/other', false));
});

test('closed frozen rule metadata rejects extra/private/foreign ordering and cannot manufacture content or a read scope', () => {
  const value = rules('*.tmp\n');
  for (const change of [{ extra: true }, { repositoryIdentityDigest: true }, { sources: [{ ...value.sources[0]!, contentRef: 'b'.repeat(64) }] },
    { rules: [{ ...value.rules[0]!, sourceIndex: 1 }] }, { rules: [{ ...value.rules[0]!, order: 1 }] },
    { rules: [{ ...value.rules[0]!, baseDirectory: 'foreign' }] }, { rules: [{ ...value.rules[0]!, authority: true }] }]) {
    const bad = { ...value, ...change, rulesDigest: '' }; bad.rulesDigest = digestOmitting(bad, 'rulesDigest');
    assert.throws(() => validateFrozenIgnoreRules(bad), TypeError);
  }
  let traps = 0;
  const getter = { ...value }; Object.defineProperty(getter, 'rules', { enumerable: true, get() { traps++; return value.rules; } });
  assert.throws(() => validateFrozenIgnoreRules(getter), TypeError);
  const proxy = new Proxy(value, { getPrototypeOf() { traps++; return Object.prototype; }, ownKeys() { traps++; return []; } });
  assert.throws(() => validateFrozenIgnoreRules(proxy), TypeError); assert.equal(traps, 0);
  const nested = new Proxy(value.rules, { get() { traps++; throw new Error('private trap must never execute'); } });
  assert.throws(() => validateFrozenIgnoreRules({ ...value, rules: nested }), TypeError); assert.equal(traps, 0);
  const bytes = Buffer.from('*.tmp\n');
  Object.defineProperty(bytes, 'byteLength', { get() { traps++; throw new Error('private byte getter must never execute'); } });
  assert.equal(compileFrozenIgnoreRules([{ kind: 'gitignore', path: '.gitignore', bytes }], repositoryIdentityDigest).rules.length, 1);
  assert.equal(traps, 0);
  for (const bytes of [Buffer.from([0xff]), Buffer.from('a\0b'), Buffer.alloc(1024 * 1024 + 1)])
    assert.throws(() => compileFrozenIgnoreRules([{ kind: 'gitignore', path: '.gitignore', bytes }], repositoryIdentityDigest), TypeError);
  assert.throws(() => compileFrozenIgnoreRules([{ kind: 'gitignore', path: '.git/config', bytes: Buffer.from('x') }], repositoryIdentityDigest), TypeError);
  assert.throws(() => isFrozenPathIgnored(value, '../outside', false), TypeError);
});

test('the fixed matcher agrees with real Git on owned ordinary rules without using Git as production authority', async () => {
  // Host Git is an offline data oracle in this owned fixture only. No grant,
  // StateOwner, native scope, signed image or installed proof is constructed.
  const root = await mkdtemp(path.join(await realpath(tmpdir()), 'frozen-ignore-oracle-'));
  const home = path.join(root, 'home'), repo = path.join(root, 'repo');
  await mkdir(home, { mode: 0o700 }); await mkdir(repo, { mode: 0o700 });
  const environment = { PATH: '/usr/bin:/bin', HOME: home, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_OPTIONAL_LOCKS: '0' };
  const git = async (args: string[], input?: Buffer): Promise<{ code: number | null; bytes: Buffer }> => {
    const child = spawn('/usr/bin/git', args, { cwd: repo, env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
    const output: Buffer[] = []; let total = 0, error: unknown, overflow = false;
    child.once('error', value => { error = value; }); child.stdin.on('error', () => {});
    child.stdout.on('data', (bytes: Buffer) => { total += bytes.length; if (total <= 65536) output.push(bytes); else { overflow = true; child.kill(); } });
    child.stderr.on('data', (bytes: Buffer) => { total += bytes.length; if (total > 65536) { overflow = true; child.kill(); } });
    child.stdin.end(input);
    const code = await new Promise<number | null>(resolve => child.once('close', resolve));
    if (error) throw error; assert.equal(overflow, false); return { code, bytes: Buffer.concat(output) };
  };
  try {
    assert.equal((await git(['-c', 'init.defaultBranch=main', 'init', '--quiet'])).code, 0);
    const text = '*.log\n/root-only\ncache/\n!cache/keep\na/**/z\n**/deep\nx[0-9].txt\nq[!ab]\nfile?.tmp\n\\#literal\nspace\\ \n';
    await writeFile(path.join(repo, '.gitignore'), text, { mode: 0o600 });
    const paths = ['file.log', 'nested/file.log', 'root-only', 'nested/root-only', 'cache/file', 'cache/keep', 'cache-file',
      'a/z', 'a/b/c/z', 'a/b/y', 'deep', 'n/deep', 'x4.txt', 'xa.txt', 'qc', 'qa', 'file1.tmp', 'file12.tmp', '#literal', 'space '];
    const actual = await git(['check-ignore', '--no-index', '-z', '--stdin'], Buffer.from(`${paths.join('\0')}\0`));
    assert.equal(actual.code, 0);
    const ignored = new Set(actual.bytes.toString('utf8').split('\0').filter(Boolean)), frozen = rules(text);
    for (const candidate of paths) assert.equal(isFrozenPathIgnored(frozen, candidate, false), ignored.has(candidate), candidate);
    await mkdir(path.join(repo, 'foo/a'), { recursive: true, mode: 0o700 });
    const directories = new Set(['foo', 'foo/a']);
    const probes = ['a', 'b', 'abc', 'foo', 'foo/bar', 'foo/a', 'foo/a/bar', 'foo/a/b/bar', 'a/foo', 'abc[', 'x1', 'xA',
      'éx', 'ex', '#literal', '!literal', 'space ', 'space', 'trailing\\'];
    for (const pattern of ['**/foo', 'foo/**', 'foo/**/bar', 'foo/*/bar', 'a**/foo', 'abc[', 'x[[:digit:]]', 'x[[:upper:]]',
      '[ab]', '[!ab]', '[^ab]', '[-a]', '[a-]', '[]a]', '?x', '\\#literal', '\\!literal', 'space ', 'space\\ ', 'foo\\/', 'trailing\\']) {
      await writeFile(path.join(repo, '.gitignore'), `${pattern}\n`, { mode: 0o600 });
      const result = await git(['check-ignore', '--no-index', '-z', '--stdin'], Buffer.from(`${probes.join('\0')}\0`));
      assert(result.code === 0 || result.code === 1);
      const gitIgnored = new Set(result.bytes.toString('utf8').split('\0').filter(Boolean));
      for (const candidate of probes) {
        if (candidate.includes('\\')) continue; // Source path semantics reject backslashes independently of Git.
        assert.equal(isFrozenPathIgnored(rules(`${pattern}\n`), candidate, directories.has(candidate)), gitIgnored.has(candidate),
          `pattern ${JSON.stringify(pattern)} path ${JSON.stringify(candidate)}`);
      }
    }
    assert.equal(canonicalSha256(frozen), canonicalSha256(compileFrozenIgnoreRules([{ kind: 'gitignore', path: '.gitignore', bytes: Buffer.from(text) }], repositoryIdentityDigest)));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('retained ignore closure completely reads owned CAS contents and rejects a rehashed invented parse', async () => {
  const root = await mkdtemp(path.join(await realpath(tmpdir()), 'frozen-ignore-cas-'));
  try {
    const artifacts = new ArtifactCatalog(new ContentAddressedStore(root));
    const bytes = Buffer.from('*.tmp\n!keep.tmp\n'), compiled = rules(bytes.toString('utf8'));
    const source = await artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-frozen-ignore-content-v1');
    assert.equal(source.ref, compiled.sources[0]!.contentRef);
    const published = await artifacts.publishCanonical(compiled, compiled.format);
    assert.deepEqual(await readFrozenIgnoreRules(artifacts, published.ref, repositoryIdentityDigest), compiled);
    const invented = { ...compiled, rules: [{ ...compiled.rules[0]!, pattern: '*.private' }, compiled.rules[1]!], rulesDigest: '' };
    invented.rulesDigest = digestOmitting(invented, 'rulesDigest');
    const wrong = await artifacts.publishCanonical(invented, invented.format);
    await assert.rejects(readFrozenIgnoreRules(artifacts, wrong.ref, repositoryIdentityDigest), /complete retained contents/u);
    await assert.rejects(readFrozenIgnoreRules(artifacts, published.ref, 'b'.repeat(64)), /repository identity/u);
    const cancellation = new AbortController(), reason = new Error('own retained-rule cancellation'); cancellation.abort(reason);
    await assert.rejects(readFrozenIgnoreRules(artifacts, published.ref, repositoryIdentityDigest, cancellation.signal), error => error === reason);
  } finally { await rm(root, { recursive: true, force: true }); }
});
