import assert from 'node:assert/strict';
import { link, mkdir, mkdtemp, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { loadNativeStateOwner } from './native-owner.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';

test('held StateOwner streams an unchanged source file from its exact root and accepts source hardlinks',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-source-file-'));
    const stateRoot = path.join(parent, 'state');
    const workspace = path.join(parent, 'workspace');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(workspace, { mode: 0o700 });
    await mkdir(path.join(workspace, 'nested'), { mode: 0o700 });
    const bytes = Buffer.alloc(2 * 1024 * 1024 + 17, 0x61);
    await writeFile(path.join(workspace, 'nested', 'source.bin'), bytes, { mode: 0o600 });
    await link(path.join(workspace, 'nested', 'source.bin'), path.join(parent, 'source-link'));
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const root = held.inspectWorkspaceIdentity(workspace).root;
      const file = held.openWorkspaceSourceFile(workspace, root, 'nested/source.bin');
      try {
        assert.equal(file.size, bytes.byteLength);
        assert.equal(file.mode, 0o600);
        assert.equal(file.linkCount, 2);
        assert.equal(file.identity.ownerUid, process.geteuid!());
        const chunks: Buffer[] = [];
        while (chunks.reduce((size, chunk) => size + chunk.byteLength, 0) < file.size) {
          chunks.push(file.readChunk(1024 * 1024));
        }
        assert.deepEqual(Buffer.concat(chunks), bytes);
        file.assertStable();
        assert.equal(file.readChunk(1).byteLength, 0);
        assert.throws(() => file.readChunk.call({} as never, 1), /invalid workspace source file handle/);
      } finally { file.close(); }
      assert.throws(() => file.readChunk(1), /workspace source file changed/);
      const revoked = held.openWorkspaceSourceFile(workspace, root, 'nested/source.bin');
      held.close();
      try { assert.throws(() => revoked.readChunk(1), /workspace source file changed/); }
      finally { revoked.close(); }
    } finally { held.close(); await rm(parent, { recursive: true, force: true }); }
  });

test('held source reader rejects aliases, changes and displaced roots',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-source-swap-'));
    const stateRoot = path.join(parent, 'state');
    const workspace = path.join(parent, 'workspace');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(workspace, { mode: 0o700 });
    await mkdir(path.join(workspace, 'nested'), { mode: 0o700 });
    const source = path.join(workspace, 'nested', 'source.txt');
    await writeFile(source, 'first', { mode: 0o600 });
    await symlink(source, path.join(workspace, 'alias.txt'));
    await symlink(path.join(workspace, 'nested'), path.join(workspace, 'nested-alias'));
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const root = held.inspectWorkspaceIdentity(workspace).root;
      assert.throws(() => held.openWorkspaceSourceFile(workspace, root, 'alias.txt'), /unsafe or changed/);
      assert.throws(() => held.openWorkspaceSourceFile(workspace, root, 'nested-alias/source.txt'), /unsafe or changed/);
      assert.throws(() => held.openWorkspaceSourceFile(workspace, root, '.git/config'), /root-relative/);
      assert.throws(() => held.openWorkspaceSourceFile(workspace, root, '.Git/config'), /root-relative/);
      assert.throws(() => held.openWorkspaceSourceFile(workspace, root, '../source.txt'), /root-relative/);
      const file = held.openWorkspaceSourceFile(workspace, root, 'nested/source.txt');
      try {
        assert.equal(file.readChunk(2).toString('utf8'), 'fi');
        assert.throws(() => file.assertStable(), /incomplete/);
        await writeFile(source, 'other');
        assert.throws(() => file.readChunk(1), /changed/);
      } finally { file.close(); }
      const displacedFile = held.openWorkspaceSourceFile(workspace, root, 'nested/source.txt');
      await rename(workspace, path.join(parent, 'displaced'));
      await mkdir(workspace, { mode: 0o700 });
      try { assert.throws(() => displacedFile.readChunk(1), /changed/); }
      finally { displacedFile.close(); }
      assert.throws(() => held.openWorkspaceSourceFile(workspace, root, 'nested/source.txt'), /unsafe or changed/);
    } finally { held.close(); await rm(parent, { recursive: true, force: true }); }
  });
