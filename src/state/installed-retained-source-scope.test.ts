import assert from 'node:assert/strict';
import { chmod, cp, mkdir, mkdtemp, readFile, readdir, readlink, realpath, rename, rm, writeFile, type FileHandle } from 'node:fs/promises';
import type { BigIntStats } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { test } from 'node:test';
import { build } from 'esbuild';
import ts from 'typescript';
import { canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import type { ReleaseTrustKey, RuntimeBundleManifest } from '../policy/runtime-authority.js';

type DataDirectory = { handle: FileHandle; info: BigIntStats; parent?: DataDirectory; name: string; private: boolean };
type DataFile = { handle: FileHandle; info: BigIntStats; parent: DataDirectory; name: string; digest?: string };
type DataScope = { root(name: string): Promise<DataDirectory>; directory(parent: DataDirectory, name: string): Promise<DataDirectory>;
  file(parent: DataDirectory, name: string, mode: number, bytes?: number, digest?: string): Promise<DataFile>;
  verifyDiscard(files: readonly DataFile[]): Promise<void>; assertMetadata(files: readonly DataFile[]): void; close(): Promise<void> };
type DataApi = { Scope: new () => DataScope;
  verifyRetainedSourcePackage(scope: DataScope, root: DataDirectory, keys: readonly ReleaseTrustKey[], ref: string,
    casRoot: DataDirectory): Promise<{ manifest: DataFile; bundle: RuntimeBundleManifest; delegatedPaths: ReadonlySet<string> }>;
  writeInstallerOnlyPackage(root: string, prompt?: undefined, supervisor?: Buffer): Promise<{ bundle: RuntimeBundleManifest; releaseKeys: ReleaseTrustKey[] }> };

/** Compile the actual private data helpers, with only test exports appended.
 * No body, guard, native binding, owner or authority is replaced. Unused
 * imports are omitted for this data-only component; no Store is opened. */
export async function compileRetainedScopeDataProgram(directory: string): Promise<string> {
  const runtime = fileURLToPath(new URL('./installed-runtime.ts', import.meta.url));
  const fixture = fileURLToPath(new URL('./installed-runtime.test.ts', import.meta.url));
  const result = await build({ stdin: { contents: `export { Scope,verifyRetainedSourcePackage } from 'private:runtime';\nexport { writeInstallerOnlyPackage } from 'private:fixture';`,
    resolveDir: path.dirname(runtime), sourcefile: 'retained-scope-data-entry.ts' }, bundle: true, write: false, treeShaking: true,
    platform: 'node', target: 'node22', format: 'esm', logLevel: 'silent', plugins: [{ name: 'exact-private-data-helpers', setup(builder) {
      builder.onResolve({ filter: /^private:/ }, args => ({ path: args.path === 'private:runtime' ? runtime : fixture, namespace: 'private-data' }));
      builder.onLoad({ filter: /.*/, namespace: 'private-data' }, async args => {
        const text = await readFile(args.path, 'utf8');
        if (args.path === runtime) {
          const parsed = ts.createSourceFile(args.path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
          for (const name of ['Scope', 'verifyRetainedSourcePackage']) assert(parsed.statements.some(node =>
            (ts.isClassDeclaration(node) || ts.isFunctionDeclaration(node)) && node.name?.text === name));
          return { contents: `${text}\nexport { Scope,verifyRetainedSourcePackage };`, resolveDir: path.dirname(runtime), loader: 'ts' };
        }
        const parsed = ts.createSourceFile(args.path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
        const make = parsed.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'writeInstallerOnlyPackage');
        assert(make);
        const imports = parsed.statements.filter(ts.isImportDeclaration).map(node => node.getText(parsed)).join('\n');
        return { contents: `${imports}\n${make.getText(parsed)}\nexport { writeInstallerOnlyPackage };`, resolveDir: path.dirname(fixture), loader: 'ts' };
      });
      builder.onResolve({ filter: /^\./ }, async args => {
        if (args.pluginData?.resolved) return undefined;
        const found = await builder.resolve(args.path, { resolveDir: args.resolveDir, kind: args.kind, pluginData: { resolved: true } });
        return { path: found.path, namespace: found.namespace, external: found.external, sideEffects: false, errors: found.errors, warnings: found.warnings };
      });
    } }] });
  const bytes = result.outputFiles[0]!.contents;
  const output = path.join(directory, 'actual-retained-scope-data.mjs'); await writeFile(output, bytes, { mode: 0o400 }); return output;
}

async function descriptorTargets(): Promise<string[]> {
  const targets: string[] = [];
  for (const fd of await readdir('/proc/self/fd')) try { targets.push(await readlink(`/proc/self/fd/${fd}`)); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  return targets;
}

/** Actual owned files and private Scope lifecycle only. Opaque executable
 * fixture bytes are never executed; no selection/StateOwner is manufactured. */
export async function exerciseRetainedScopeData(directory: string, api: DataApi): Promise<void> {
  const packageRoot = path.join(directory, 'source-package');
  const originalBytes = Buffer.from('owned historical executable data, never executed\n');
  const signed = await api.writeInstallerOnlyPackage(packageRoot, undefined, originalBytes);
  const scope = new api.Scope();
  try {
    const root = await scope.root(directory), original = await scope.directory(root, 'source-package');
    await mkdir(path.join(directory, 'cas'), { mode: 0o700 });
    const casRoot = await scope.directory(root, 'cas');
    const currentBytes = Buffer.from('owned current read data, never executed\n');
    await writeFile(path.join(directory, 'current-image'), currentBytes, { mode: 0o500 });
    const current = await scope.file(root, 'current-image', 0o500, currentBytes.length, sha256Bytes(currentBytes));
    const source = await api.verifyRetainedSourcePackage(scope, original, signed.releaseKeys, canonicalSha256(signed.bundle), casRoot);
    assert.deepEqual(Object.keys(source).sort(), ['bundle', 'delegatedPaths', 'manifest']);
    assert.deepEqual([...source.delegatedPaths], [], 'this original executable-only package delegates no CAS data');
    const image = path.join(packageRoot, 'supervisor');
    assert(!(await descriptorTargets()).includes(image), 'historical executable FD must be actually closed before returning metadata');
    assert((await descriptorTargets()).includes(path.join(packageRoot, 'manifest.json')), 'the source manifest stays held by the current metadata scope');
    await chmod(image, 0o600); await writeFile(image, Buffer.alloc(originalBytes.length, 0x78)); await chmod(image, 0o500);
    // These are the actual unchanged current read bodies. The old executable
    // is not a selected execution image, and no old successful hash is reused.
    await scope.verifyDiscard([current, source.manifest]);
    await assert.rejects(api.verifyRetainedSourcePackage(scope, original, signed.releaseKeys, canonicalSha256(signed.bundle), casRoot),
      { code: 'ARTIFACT_MISMATCH' });
    assert(!(await descriptorTargets()).includes(image), 'failed fresh historical reads also close their original image descriptors');
    await chmod(image, 0o600); await writeFile(image, originalBytes); await chmod(image, 0o500);
    await api.verifyRetainedSourcePackage(scope, original, signed.releaseKeys, canonicalSha256(signed.bundle), casRoot);
    await writeFile(path.join(packageRoot, 'unsigned'), 'owned unknown data', { mode: 0o400 });
    await assert.rejects(api.verifyRetainedSourcePackage(scope, original, signed.releaseKeys, canonicalSha256(signed.bundle), casRoot),
      { code: 'ARTIFACT_MISMATCH' });
    await rm(path.join(packageRoot, 'unsigned'));
    const worker = signed.bundle.entries.find(entry => entry.role === 'worker')!.relativePath;
    const workerBytes = await readFile(path.join(packageRoot, worker));
    await rm(path.join(packageRoot, worker));
    await assert.rejects(api.verifyRetainedSourcePackage(scope, original, signed.releaseKeys, canonicalSha256(signed.bundle), casRoot),
      error => (error as NodeJS.ErrnoException).code === 'ENOENT');
    await writeFile(path.join(packageRoot, worker), workerBytes, { mode: 0o500 });
    // A byte-identical replacement of the captured source directory cannot
    // become that held object. This fails before any replacement is read.
    const moved = path.join(directory, 'moved-source'); await rename(packageRoot, moved); await cp(moved, packageRoot, { recursive: true });
    await assert.rejects(api.verifyRetainedSourcePackage(scope, original, signed.releaseKeys, canonicalSha256(signed.bundle), casRoot),
      { code: 'ARTIFACT_MISMATCH' });
    assert.throws(() => scope.assertMetadata([current]), { code: 'ARTIFACT_MISMATCH' },
      'current metadata still refuses replacement of the original retained source directory');
  } finally { await scope.close(); }
  assert(!(await descriptorTargets()).some(target => target.startsWith(`${directory}/`)), 'all actual owned package/data descriptors must join');
}

test('the private historical-scope data program exposes no installation or StateOwner entry', async () => {
  const root = await mkdtemp(path.join(await realpath(os.tmpdir()), 'cliq-retained-program-'));
  try {
    const program = await compileRetainedScopeDataProgram(root);
    const api = await import(pathToFileURL(program).href);
    assert.deepEqual(Object.keys(api).sort(), ['Scope', 'verifyRetainedSourcePackage', 'writeInstallerOnlyPackage']);
    assert.deepEqual(await readdir(root), ['actual-retained-scope-data.mjs'], 'loading data helpers creates no database or control state');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('historical installed package reads join independently while every current selected byte remains verified', async t => {
  if (process.platform !== 'linux') { t.skip('actual /proc descriptor scope requires supported Linux; no borrowed platform proof'); return; }
  const root = await mkdtemp(path.join(await realpath(os.tmpdir()), 'cliq-retained-scope-'));
  try {
    const program = await compileRetainedScopeDataProgram(root);
    const api = await import(pathToFileURL(program).href) as DataApi;
    await exerciseRetainedScopeData(root, api);
  } finally { await rm(root, { recursive: true, force: true }); }
});
