import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const repository = fileURLToPath(new URL('../..', import.meta.url));
const builder = path.join(repository, 'scripts/kernel/build-state-owner-native.mjs');
const vendor = path.join(repository, 'native/vendor/node-sqlite-v24.21.0');
const pins = {
  'sqlite3.h': '919e7f2e8ed1d8f56ac17b412b8971c76aa5d1a879752cc6058f75e7d5910e1d',
  'sqlite3ext.h': 'ac9645e5c9ff0cf176efdd6e75cb5e98f46295d38e02db5c4d208826a39ab4be',
};

function offlineIncludes(script = builder) {
  return spawnSync(process.execPath, ['--input-type=module', '-e', `
    import { pathToFileURL } from 'node:url';
    globalThis.fetch = () => { throw new Error('build must not fetch headers'); };
    const script = process.argv[1];
    process.argv = [process.execPath, script, '--print-includes'];
    await import(pathToFileURL(script).href);
  `, script], { encoding: 'utf8', timeout: 30_000 });
}

test('native builder exposes the pinned SQLite extension headers without network access', async () => {
  const result = offlineIncludes();
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  const includes: unknown = JSON.parse(result.stdout);
  assert.ok(Array.isArray(includes) && includes.every(value => typeof value === 'string'));
  assert.ok(includes.includes(vendor), 'the native builder must provide its fixed vendored SQLite headers');
  for (const [name, digest] of Object.entries(pins)) {
    assert.equal(createHash('sha256').update(await readFile(path.join(vendor, name))).digest('hex'), digest);
  }
  const syntax = spawnSync('cc', ['-std=c11', '-Wall', '-Wextra', '-Werror', '-fsyntax-only',
    ...includes.flatMap(value => ['-I', value]), '-x', 'c', '-'], {
    encoding: 'utf8', timeout: 30_000,
    input: '#include <sqlite3ext.h>\nSQLITE_EXTENSION_INIT1\nint cliq_header_probe(void) { return (int)sizeof(sqlite3_api_routines); }\n',
  });
  assert.equal(syntax.error, undefined);
  assert.equal(syntax.status, 0, syntax.stderr);
});

test('the fixed probe compiles offline with the same pinned extension headers', async t => {
  const fixture = await mkdtemp(path.join(tmpdir(), 'cliq-sqlite-header-build-'));
  t.after(() => rm(fixture, { recursive: true, force: true }));
  // This only compiles an image. It neither loads a VFS nor qualifies the
  // ambient client's SQLite engine; SEA engine qualification stays separate.
  const nodeRoot = path.resolve(path.dirname(realpathSync(process.execPath)), '..');
  const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `
    import { pathToFileURL } from 'node:url';
    globalThis.fetch = () => { throw new Error('build must not fetch headers'); };
    const [script, fixture, nodeRoot] = process.argv.slice(1);
    const { buildCredentialVfsProbe } = await import(pathToFileURL(script).href);
    console.log(JSON.stringify(await buildCredentialVfsProbe(fixture, nodeRoot)));
  `, path.join(repository, 'scripts/kernel/testing/sqlite-vfs-mechanism-build.ts'), fixture, nodeRoot], {
    cwd: repository, encoding: 'utf8', timeout: 60_000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  const built = JSON.parse(result.stdout);
  assert.ok((await readFile(built.helper)).length > 0);
  assert.deepEqual(built.construction.headers, pins);
  assert.ok(built.construction.compilerArguments.includes(vendor));
  assert.equal(built.construction.secondSqliteEngineLinked, false);
});

test('the native include query refuses changed or missing pinned header bytes', async t => {
  for (const name of Object.keys(pins)) {
    for (const condition of ['changed', 'missing'] as const) await t.test(`${name}: ${condition}`, async t => {
      const fixture = await mkdtemp(path.join(tmpdir(), 'cliq-sqlite-header-refusal-'));
      t.after(() => rm(fixture, { recursive: true, force: true }));
      const scripts = path.join(fixture, 'scripts/kernel');
      const copiedVendor = path.join(fixture, 'native/vendor/node-sqlite-v24.21.0');
      await mkdir(scripts, { recursive: true });
      await mkdir(copiedVendor, { recursive: true });
      for (const leaf of ['build-state-owner-native.mjs', 'sqlite-extension-headers.mjs'])
        await copyFile(path.join(repository, 'scripts/kernel', leaf), path.join(scripts, leaf));
      for (const leaf of Object.keys(pins)) {
        if (leaf === name && condition === 'missing') continue;
        const bytes = await readFile(path.join(vendor, leaf));
        if (leaf === name) bytes[bytes.length - 1] ^= 1;
        await writeFile(path.join(copiedVendor, leaf), bytes, { flag: 'wx' });
      }
      const result = offlineIncludes(path.join(scripts, 'build-state-owner-native.mjs'));
      assert.equal(result.error, undefined);
      assert.notEqual(result.status, 0, 'unverified headers must not become compiler inputs');
      assert.equal(result.stdout, '', 'the failed query must not publish an include list');
      if (condition === 'changed') assert.ok(result.stderr.includes(`vendored ${name} checksum mismatch`));
      else assert.ok(result.stderr.includes('ENOENT') && result.stderr.includes(name));
    });
  }
});

test('the native compiler inputs cannot shadow pinned SQLite headers with other include directories', async t => {
  const fixture = await mkdtemp(path.join(tmpdir(), 'cliq-sqlite-header-shadow-'));
  t.after(() => rm(fixture, { recursive: true, force: true }));
  await writeFile(path.join(fixture, 'sqlite3ext.h'), '#error ambient_sqlite_headers_must_not_be_used\n', { flag: 'wx' });
  const result = offlineIncludes();
  assert.equal(result.status, 0, result.stderr);
  const includes = JSON.parse(result.stdout) as string[];
  // Model Node/libuv include directories that also contain an unrelated
  // SQLite header. Preserve the builder's ordering and its fixed vendor path.
  const shadowed = includes.map(include => include === vendor ? include : fixture);
  const syntax = spawnSync('cc', ['-std=c11', '-Wall', '-Wextra', '-Werror', '-fsyntax-only',
    ...shadowed.flatMap(include => ['-I', include]), '-x', 'c', '-'], {
    encoding: 'utf8', timeout: 30_000,
    input: '#include <sqlite3ext.h>\n#if SQLITE_VERSION_NUMBER != 3053004\n#error fixed_sqlite_header_version_required\n#endif\n',
  });
  assert.equal(syntax.error, undefined);
  assert.equal(syntax.status, 0, syntax.stderr);
});
