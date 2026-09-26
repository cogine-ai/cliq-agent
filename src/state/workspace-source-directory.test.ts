import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { loadNativeStateOwner } from './native-owner.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';

test('held StateOwner lists literal source entries and refuses unsafe directory contents',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-source-directory-'));
    const stateRoot = path.join(parent, 'state');
    const workspace = path.join(parent, 'workspace');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(workspace, { mode: 0o700 });
    await mkdir(path.join(workspace, 'nested'), { mode: 0o700 });
    await writeFile(path.join(workspace, 'source.txt'), 'source', { mode: 0o600 });
    await symlink('source.txt', path.join(workspace, 'alias'));
    await symlink('nested', path.join(workspace, 'nested-alias'));
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const root = held.inspectWorkspaceIdentity(workspace).root;
      const entries = held.listWorkspaceSourceDirectory(workspace, root, '');
      assert.deepEqual(entries.map((entry) => [entry.name, entry.kind]).sort((a, b) =>
        Buffer.compare(Buffer.from(String(a[0])), Buffer.from(String(b[0])))), [
        ['alias', 'symlink'], ['nested', 'directory'], ['nested-alias', 'symlink'], ['source.txt', 'file']
      ]);
      assert.equal(entries.find((entry) => entry.name === 'source.txt')?.size, 6);
      assert.deepEqual(held.listWorkspaceSourceDirectory(workspace, root, 'nested'), []);
      assert.throws(() => held.listWorkspaceSourceDirectory(workspace, root, 'nested-alias'), /unsafe or changed/);
      assert.throws(() => held.listWorkspaceSourceDirectory(workspace, root, 'Nested'), /unsafe or changed/);
      assert.throws(() => held.listWorkspaceSourceDirectory(workspace, root, '.Git'), /root-relative/);
      const fifo = path.join(workspace, 'special');
      execFileSync('mkfifo', [fifo]);
      assert.throws(() => held.listWorkspaceSourceDirectory(workspace, root, ''), /unsafe or changed/);
      await rm(fifo);
      if (process.platform === 'linux') {
        const invalidUtf8 = Buffer.concat([Buffer.from(`${workspace}/`), Buffer.from([0xff])]);
        await writeFile(invalidUtf8, 'invalid');
        try { assert.throws(() => held.listWorkspaceSourceDirectory(workspace, root, ''), /unsafe or changed/); }
        finally { await rm(invalidUtf8); }
        const decomposed = path.join(workspace, 'e\u0301');
        await writeFile(decomposed, 'decomposed');
        try { assert.throws(() => held.listWorkspaceSourceDirectory(workspace, root, ''), /noncanonical entry name/); }
        finally { await rm(decomposed); }
      }
      held.close();
      assert.throws(() => held.listWorkspaceSourceDirectory(workspace, root, ''),
        (error: unknown) => error instanceof Error && 'code' in error && error.code === 'RECOVERY_REQUIRED');
    } finally { held.close(); await rm(parent, { recursive: true, force: true }); }
  });
