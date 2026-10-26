import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, mkdtemp, readdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { installQualificationDependencies } from './qualification-dependencies.js';
import { readQualificationSource } from './qualification-source.js';

test('actual isolated npm-ci uses the original lock and binds its complete dependency cut to the original session', async () => {
  const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-original-lock-')));
  const writable = async (directory: string): Promise<void> => {
    await chmod(directory, 0o700);
    for (const name of await readdir(directory)) { const filename = path.join(directory, name), info = await lstat(filename);
      if (info.isDirectory() && !info.isSymbolicLink()) await writable(filename); }
  };
  try {
    const root = path.join(temporary, 'source'); await mkdir(path.join(root, 'src'), { mode: 0o700, recursive: true });
    const files = new Map([['src/config.ts', Buffer.from('export const KERNEL_STATE_SCHEMA_VERSION = 7;\n')],
      ['package.json', canonicalJsonBytes({ name: 'owned-original-empty-build', version: '1.0.0', private: true })],
      ['package-lock.json', canonicalJsonBytes({ name: 'owned-original-empty-build', version: '1.0.0', lockfileVersion: 3,
        requires: true, packages: { '': { name: 'owned-original-empty-build', version: '1.0.0' } } })]]);
    for (const [name, bytes] of files) await writeFile(path.join(root, name), bytes, { flag: 'wx', mode: 0o444 });
    const manifest = canonicalJsonBytes({ inventory: [...files].map(([name, bytes]) => ({ path: name, mode: '100644', size: bytes.length, sha256: sha256Bytes(bytes) })) });
    const manifestPath = path.join(temporary, 'source.json'); await writeFile(manifestPath, manifest, { flag: 'wx', mode: 0o400 });
    const source = Object.freeze({ root, manifestPath, manifestSha256: sha256Bytes(manifest) });
    const before = await readQualificationSource(source); await installQualificationDependencies(source);
    const after = await readQualificationSource(source); assert.equal(after.memberCount, before.memberCount); assert.equal(after.manifestSha256, before.manifestSha256);
    assert.notEqual(after.physicalCutDigest, before.physicalCutDigest); assert.deepEqual(await readQualificationSource(source), after);
    await assert.rejects(readQualificationSource({ ...source }), /original installation session/);
    assert.deepEqual(await (await import('node:fs/promises')).readFile(path.join(root, 'package-lock.json')), files.get('package-lock.json'));
    const originalModules = path.join(temporary, 'original-node-modules');
    await chmod(path.join(root, 'node_modules'), 0o700);
    await rename(path.join(root, 'node_modules'), originalModules);
    await symlink(await realpath(fileURLToPath(new URL('../../../node_modules', import.meta.url))), path.join(root, 'node_modules'));
    await assert.rejects(readQualificationSource(source), /cannot switch to a borrowed tree/);
    await rm(path.join(root, 'node_modules')); await rename(originalModules, path.join(root, 'node_modules'));
    await chmod(path.join(root, 'node_modules'), 0o700); await writeFile(path.join(root, 'node_modules', 'extra'), 'foreign dependency');
    await assert.rejects(readQualificationSource(source), /dependencies changed/);
  } finally { await writable(temporary); await rm(temporary, { recursive: true, force: true }); }
});
