// Fixed production-client bundling contract, not a runtime trust root.
import assert from 'node:assert/strict';
import { constants, openSync, closeSync, fstatSync, lstatSync, readSync, realpathSync } from 'node:fs';
import { createRequire, isBuiltin } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, type Plugin, type BuildOptions } from 'esbuild';
import { sha256Bytes } from '../../../src/kernel/identity.js';
const sourcePins = Object.freeze({
  'reconciler.js': { digest: '856e28cd8dbfe4d7ca89203cbd6b73f39aa91562c3447d1f444b2b7015cde84a', size: 10368, conditions: 2 },
  'ink.js': { digest: 'd0b8bd7c09a7587b21641ff8b70d33dbd1c9d411ae325722b1ef3e7fe46ffe60', size: 33428, conditions: 1 }
});
const condition = "process.env['DEV'] === 'true'";
/** Pure negative/closed data seam. Never changes dependency files on disk. */
export function fixedInstalledInkSource(name: string, bytes: Buffer): string {
  assert(Object.hasOwn(sourcePins, name)); const pin = sourcePins[name as keyof typeof sourcePins];
  const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  assert.equal(source.split(condition).length - 1, pin.conditions, 'fixed Ink DevTools condition count changed');
  assert.equal(bytes.length, pin.size); assert.equal(sha256Bytes(bytes), pin.digest, 'fixed Ink source hash changed');
  return source.split(condition).join('false');
}
const metadata = ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs'] as const;
function readFixed(filename: string, maximum: number, expectedUid?: bigint): { bytes: Buffer; uid: bigint } {
  const before = lstatSync(filename, { bigint: true });
  assert(before.isFile() && before.nlink === 1n && (expectedUid === undefined || before.uid === expectedUid) && [0o644n, 0o444n].includes(before.mode & 0o7777n) && before.size > 0 && before.size <= BigInt(maximum));
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    for (const key of metadata) assert.equal(fstatSync(fd, { bigint: true })[key], before[key]);
    const bytes = Buffer.alloc(Number(before.size) + 1); let count = 0;
    for (;;) { const read = readSync(fd, bytes, count, bytes.length - count, null); count += read;
      assert(count < bytes.length); if (read === 0) break; }
    assert.equal(count, Number(before.size));
    for (const after of [fstatSync(fd, { bigint: true }), lstatSync(filename, { bigint: true })])
      for (const key of metadata) assert.equal(after[key], before[key]);
    return { bytes: bytes.subarray(0, count), uid: before.uid };
  } finally { closeSync(fd); }
}
/** All normal Ink code stays bundled. DevTools' optional ambient package and
 * local network hook are absent from this fixed client image. Literal Node
 * builtins keep their original semantics with the canonical node: namespace. */
export function installedClientBuildOptions(sourceRoot = fileURLToPath(new URL('../../..', import.meta.url))): Pick<BuildOptions, 'plugins' | 'banner'> {
  assert(path.isAbsolute(sourceRoot));
  const root = path.resolve(sourceRoot), directory = path.join(root, 'node_modules', 'ink');
  assert.equal(realpathSync(root), root);
  assert.equal(realpathSync(directory), directory, 'fixed Ink dependency must belong to the selected source root');
  const resolved = createRequire(path.join(root, 'package.json')).resolve('ink');
  assert.equal(realpathSync(resolved), path.join(directory, 'build', 'index.js'), 'fixed Ink entry must belong to the selected source root');
  const heldPackage = readFixed(path.join(directory, 'package.json'), 65536), packageBytes = heldPackage.bytes;
  assert.equal(sha256Bytes(packageBytes), '875318166ca415fb9e04d724df326e12a0ac4b1dafc6540bb04e0f30fd8778cc');
  assert.equal((JSON.parse(packageBytes.toString('utf8')) as { version: string }).version, '7.0.2');
  const plugin: Plugin = { name: 'fixed-installed-client-dependencies', setup(build) {
    build.onResolve({ filter: /^[^./]/ }, args => isBuiltin(args.path)
      ? { path: args.path.startsWith('node:') ? args.path : `node:${args.path}`, external: true } : undefined);
    build.onLoad({ filter: /[/\\]ink[/\\]build[/\\](?:ink|reconciler)\.js$/ }, args => {
      const name = path.basename(args.path), expected = path.join(directory, 'build', name);
      assert.equal(realpathSync(args.path), realpathSync(expected));
      return { contents: fixedInstalledInkSource(name, readFixed(expected, 65536, heldPackage.uid).bytes), loader: 'js', resolveDir: path.dirname(expected) };
    });
  } };
  return { plugins: [plugin], banner: { js: "import { createRequire as cliqClientCreateRequire } from 'node:module';\nconst require = cliqClientCreateRequire(import.meta.url);" } };
}

/** The installed journey stages this exact real consumer. Keep its locked
 * Ink compilation and complete Node-only/size closure in one build contract. */
export async function buildInstalledClientDriver(outfile: string): Promise<Uint8Array> {
  const result = await build({ entryPoints: [fileURLToPath(new URL('./installed-control-client-driver.ts', import.meta.url))],
    outfile, bundle: true, platform: 'node', format: 'esm', target: 'node22.13', metafile: true, write: false,
    ...installedClientBuildOptions() });
  assert(Object.values(result.metafile!.outputs).flatMap(value => value.imports).every(value => value.external && value.path.startsWith('node:')));
  assert.equal(result.outputFiles!.length, 1);
  const bytes = result.outputFiles![0]!.contents;
  assert(bytes.length > 0 && bytes.length <= 16 * 1024 * 1024);
  return bytes;
}
