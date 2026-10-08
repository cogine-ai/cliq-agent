import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { createWorkspaceTrustContext, workspaceTrustRecordPath, writePersistedWorkspaceTrust } from '../session/trust.js';
import { loadNativeStateOwner } from './native-owner.js';
import { assertWorkspaceSourceTrust, holdWorkspaceSourceTrust } from './source-trust.js';

test('source Trust reads the exact persisted user decision and remains bound to held record bytes', async t => {
  const container = await mkdtemp(path.join(process.cwd(), '.cliq-source-trust-'));
  t.after(() => rm(container, { recursive: true, force: true }));
  const home = path.join(container, 'home'), workspace = path.join(container, 'workspace');
  await mkdir(home, { mode: 0o700 }); await mkdir(workspace);
  const context = await createWorkspaceTrustContext(workspace, home);
  await writePersistedWorkspaceTrust(context, 'trusted');
  const heldHome = (await loadNativeStateOwner()).openWorkspaceRoot(home);
  t.after(() => heldHome.close());
  const trust = await holdWorkspaceSourceTrust(heldHome, workspace);
  try {
    trust.assertCurrent();
    assertWorkspaceSourceTrust(trust, workspace);
    assert.throws(() => assertWorkspaceSourceTrust(trust, home), /another workspace/);
    assert.throws(() => assertWorkspaceSourceTrust({ assertCurrent() {}, close() {} }, workspace), /another workspace/);
    await writeFile(path.join(home, 'unrelated-state'), 'not a Trust decision');
    trust.assertCurrent();
    await writePersistedWorkspaceTrust(context, 'denied');
    assert.throws(() => trust.assertCurrent(), /Trust|changed/);
  } finally { trust.close(); heldHome.close(); }
  assert.throws(() => trust.assertCurrent(), /closed/);
});

test('source Trust rejects denial, path substitution, symlink records and missing decisions', async t => {
  const container = await mkdtemp(path.join(process.cwd(), '.cliq-source-trust-'));
  t.after(() => rm(container, { recursive: true, force: true }));
  const home = path.join(container, 'home'), workspace = path.join(container, 'workspace');
  await mkdir(home, { mode: 0o700 }); await mkdir(workspace);
  const context = await createWorkspaceTrustContext(workspace, home);
  const heldHome = (await loadNativeStateOwner()).openWorkspaceRoot(home);
  t.after(() => heldHome.close());
  await assert.rejects(holdWorkspaceSourceTrust(heldHome, workspace), /persisted Workspace Trust/);
  await writePersistedWorkspaceTrust(context, 'denied');
  await assert.rejects(holdWorkspaceSourceTrust(heldHome, workspace), /persisted Workspace Trust/);
  await writeFile(workspaceTrustRecordPath(context), JSON.stringify({ version: 1, workspaceId: context.workspaceId,
    workspaceRealPath: home, decision: 'trusted', decidedAt: new Date().toISOString() }));
  await assert.rejects(holdWorkspaceSourceTrust(heldHome, workspace), /persisted Workspace Trust/);
  await writePersistedWorkspaceTrust(context, 'trusted');
  const other = path.join(container, 'external-trust');
  await writeFile(other, JSON.stringify({ version: 1, workspaceId: context.workspaceId,
    workspaceRealPath: workspace, decision: 'trusted', decidedAt: new Date().toISOString() }), { mode: 0 });
  await rm(workspaceTrustRecordPath(context));
  await symlink(other, workspaceTrustRecordPath(context));
  await assert.rejects(holdWorkspaceSourceTrust(heldHome, workspace), /persisted Workspace Trust/);
  heldHome.assertHeld();
});
