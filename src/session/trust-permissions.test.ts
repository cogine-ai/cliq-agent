import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { test } from 'node:test';

test('persisted Trust stays private and passes the original source gate with a permissive umask', async () => {
  // Only this child changes umask. The parent and other test processes retain
  // their original creation policy, and the real native reader stays strict.
  const source = `
    import assert from 'node:assert/strict';
    import { mkdir, mkdtemp, readdir, realpath, rm, stat } from 'node:fs/promises';
    import { tmpdir } from 'node:os';
    import path from 'node:path';
    import { createWorkspaceTrustContext, workspaceTrustRecordPath,
      writePersistedWorkspaceTrust } from ${JSON.stringify(new URL('./trust.js', import.meta.url).href)};
    import { loadNativeStateOwner } from ${JSON.stringify(new URL('../state/native-owner.js', import.meta.url).href)};
    import { holdWorkspaceSourceTrust } from ${JSON.stringify(new URL('../state/source-trust.js', import.meta.url).href)};
    const native = await loadNativeStateOwner();
    for (const mask of [0o000, 0o002, 0o022, 0o077]) {
      process.umask(mask);
      const root = await mkdtemp(path.join(await realpath(tmpdir()), 'cliq-trust-permissions-'));
      const home = path.join(root, 'home'), workspace = path.join(root, 'workspace');
      await mkdir(home, {mode: 0o700}); await mkdir(workspace, {mode: 0o700});
      const context = await createWorkspaceTrustContext(workspace, home);
      const record = workspaceTrustRecordPath(context);
      try {
        for (const decision of ['trusted', 'denied', 'trusted']) {
          await writePersistedWorkspaceTrust(context, decision);
          assert.equal((await stat(path.join(home, 'workspaces'))).mode & 0o777, 0o700);
          assert.equal((await stat(path.dirname(record))).mode & 0o777, 0o700);
          assert.equal((await stat(record)).mode & 0o777, 0o600);
          assert.deepEqual(await readdir(path.dirname(record)), ['trust.json']);
          const heldHome = native.openWorkspaceRoot(home);
          try {
            if (decision === 'denied') {
              await assert.rejects(holdWorkspaceSourceTrust(heldHome, context.workspaceRealPath), /persisted Workspace Trust/);
            } else {
              const trust = await holdWorkspaceSourceTrust(heldHome, context.workspaceRealPath);
              try { trust.assertCurrent(); } finally { trust.close(); }
            }
            heldHome.assertHeld();
          } finally { heldHome.close(); }
        }
      } finally { await rm(root, {recursive: true, force: true}); }
    }
  `;
  const result = await promisify(execFile)(process.execPath,
    ['--import', 'tsx', '--input-type=module', '-e', source]);
  assert.equal(result.stdout, '');
});
