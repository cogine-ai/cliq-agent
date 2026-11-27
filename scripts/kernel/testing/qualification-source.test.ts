import assert from 'node:assert/strict';
import { chmod, link, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { readLegacyUpgradeSource, LEGACY_UPGRADE_SOURCE } from './legacy-upgrade-source.js';
import { readQualificationSource } from './qualification-source.js';

test('a complete frozen source requires actual modes, all members and stable complete bytes', async () => {
  const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-build-source-')));
  try {
    const root = path.join(temporary, 'source'); await mkdir(path.join(root, 'src'), { recursive: true, mode: 0o700 });
    const bytes = Buffer.from('export const KERNEL_STATE_SCHEMA_VERSION = 7;\n');
    const filename = path.join(root, 'src/config.ts'); await writeFile(filename, bytes, { mode: 0o444, flag: 'wx' });
    const manifestPath = path.join(temporary, 'inventory.json');
    const manifest = canonicalJsonBytes({ inventory: [{ path: 'src/config.ts', mode: '100644', size: bytes.length, sha256: sha256Bytes(bytes) }] });
    await writeFile(manifestPath, manifest, { mode: 0o400, flag: 'wx' });
    const input = { root, manifestPath, manifestSha256: sha256Bytes(manifest) };
    const first = await readQualificationSource(input);
    assert.equal(first.schemaVersion, 7); assert.equal(first.memberCount, 1); assert.equal(first.totalBytes, bytes.length);
    assert.deepEqual(await readQualificationSource(input), first);
    await chmod(filename, 0o555); await assert.rejects(readQualificationSource(input), /logical mode/); await chmod(filename, 0o444);
    const extra = path.join(root, 'extra'); await writeFile(extra, 'unexpected');
    await assert.rejects(readQualificationSource(input), /undeclared member/); await rm(extra);
    const saved = path.join(temporary, 'original'); await link(filename, saved);
    await assert.rejects(readQualificationSource(input), /single|bounded owned file/); await rm(saved);
    await rm(filename); await symlink(manifestPath, filename);
    await assert.rejects(readQualificationSource(input), /alias/); await rm(filename);
    await writeFile(filename, Buffer.alloc(bytes.length, 0), { mode: 0o444, flag: 'wx' });
    await assert.rejects(readQualificationSource(input), /member differs/);
    assert.deepEqual(await readFile(manifestPath), manifest);
  } finally { await rm(temporary, { recursive: true, force: true }); }
});

test('the compact legacy descriptor does not bless a small, aliased or mode-substituted tree', async () => {
  assert.equal(LEGACY_UPGRADE_SOURCE.memberCount, 1178);
  assert.equal(Object.keys(LEGACY_UPGRADE_SOURCE).length, 6);
  const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-old-source-')));
  try {
    await writeFile(path.join(temporary, 'only-file'), 'incomplete', { mode: 0o444 });
    await assert.rejects(readLegacyUpgradeSource(temporary), /complete fixed product inventory/);
    await symlink(path.join(temporary, 'only-file'), path.join(temporary, 'alias'));
    await assert.rejects(readLegacyUpgradeSource(temporary), /protected original object/);
  } finally { await rm(temporary, { recursive: true, force: true }); }
});
