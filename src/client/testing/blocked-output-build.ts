import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { lstat, mkdir, mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, type BuildOptions } from 'esbuild';
import { STATE_OWNER_NATIVE_PATH } from '../../state/native-owner.js';

/** Build the actual component before creating its stdio. A runtime TSX/esbuild
 * subprocess may inherit stderr; that is absent from the shipped JS entry. */
export async function buildBlockedOutputFixture() {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-blocked-output-'));
  const close = () => rm(directory, { recursive: true });
  try {
    const entry = path.join(directory, 'src/state/blocked-output.mjs');
    await mkdir(path.dirname(entry), { recursive: true });
    const { installedClientBuildOptions }: { installedClientBuildOptions(): Pick<BuildOptions, 'plugins' | 'banner'> } =
      await import(new URL('../../../scripts/kernel/testing/installed-client-build.ts', import.meta.url).href);
    const result = await build({ ...installedClientBuildOptions(), entryPoints: [fileURLToPath(new URL('./blocked-output.ts', import.meta.url))],
      outfile: entry, bundle: true, platform: 'node', format: 'esm', target: 'node22.13', write: false, metafile: true });
    assert.equal(result.outputFiles.length, 1);
    assert(result.outputFiles[0]!.contents.length > 0 && result.outputFiles[0]!.contents.length <= 16 * 1024 * 1024);
    assert(Object.values(result.metafile.outputs).every(output => output.imports.every(item => item.external && item.path.startsWith('node:'))));
    await writeFile(entry, result.outputFiles[0]!.contents, { flag: 'wx', mode: 0o444 });
    const original = await open(STATE_OWNER_NATIVE_PATH, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const before = await original.stat({ bigint: true });
      assert(before.isFile() && before.nlink === 1n && before.uid === BigInt(process.geteuid!()) &&
        (before.mode & 0o7777n) === 0o500n && before.size > 0n && before.size <= 16n * 1024n * 1024n);
      const bytes = await original.readFile(); assert.equal(BigInt(bytes.length), before.size);
      for (const after of [await original.stat({ bigint: true }), await lstat(STATE_OWNER_NATIVE_PATH, { bigint: true })])
        for (const key of ['dev', 'ino', 'mode', 'uid', 'gid', 'size', 'nlink', 'mtimeNs', 'ctimeNs'] as const) assert.equal(after[key], before[key]);
      const native = path.join(directory, 'dist/native', `${process.platform}-${process.arch}`, 'state-owner.node');
      await mkdir(path.dirname(native), { recursive: true });
      await writeFile(native, bytes, { flag: 'wx', mode: 0o500 });
      assert((await readFile(native)).equals(bytes));
    } finally { await original.close(); }
    return Object.freeze({ entry, close });
  } catch (error) { await close(); throw error; }
}
