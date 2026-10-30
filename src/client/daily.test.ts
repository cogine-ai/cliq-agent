import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, realpath, rm, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { dailyTrustOption, trustDailyWorkspace } from './daily.js';
import { parseClientInvocation } from './commands.js';
import { installedClientDataPath } from './installed-data.js';
import { createWorkspaceTrustContext, readPersistedWorkspaceTrust, writePersistedWorkspaceTrust } from '../session/trust.js';

test('Trust is an explicit option, never a literal objective or another option value', () => {
  const options = ['--provider', 'ollama', '--model', 'inert'];
  const ordinary = dailyTrustOption(['run', 'Fix it', '--trust-workspace', ...options]);
  assert.equal(ordinary.explicit, true);
  assert.equal(parseClientInvocation(ordinary.args, '/workspace').kind, 'run');
  const literal = dailyTrustOption(['run', ...options, '--', '--trust-workspace']);
  assert.equal(literal.explicit, false);
  const parsed = parseClientInvocation(literal.args, '/workspace');
  assert.equal(parsed.kind, 'run'); if (parsed.kind === 'run') assert.equal(parsed.intent.objective, '--trust-workspace');
  const invalid = dailyTrustOption(['run', 'Fix it', ...options, '--policy', '--trust-workspace', 'yolo']);
  assert.equal(invalid.explicit, false);
  assert.throws(() => parseClientInvocation(invalid.args, '/workspace'));
  assert.throws(() => dailyTrustOption(['run', 'Fix it', '--trust-workspace', '--trust-workspace']));
});

test('client data partitions actual physical installations and canonical locators independently of bundle updates', () => {
  const root = { canonicalPath: '/account/.cliq/kernel-v1', deviceId: '1', fileId: '2', ownerUid: 123 };
  const original = installedClientDataPath('/account', root);
  assert.match(original, /^\/account\/\.cliq\/client-v1\/installations\/[a-f0-9]{64}$/u);
  for (const changed of [{ ...root, deviceId: '9' }, { ...root, fileId: '9' }, { ...root, ownerUid: 999 },
    { ...root, canonicalPath: '/account/other-installation' }]) assert.notEqual(installedClientDataPath('/account', changed), original);
  assert.equal(installedClientDataPath('/account', { ...root }), original);
});

test('daily Trust returns the same canonical workspace for aliases without granting tool permission', async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'cliq-daily-trust-'));
  const input = new PassThrough(), output = new PassThrough();
  const io = { input, output, diagnostic: output, workspacePath: temporary };
  try {
    const workspace = path.join(temporary, 'repository'), alias = path.join(temporary, 'alias');
    const controlledHome = path.join(temporary, 'private-home');
    await mkdir(workspace); await symlink(workspace, alias);
    await assert.rejects(trustDailyWorkspace(io, alias, controlledHome, false), /interactive terminal/);
    const context = await createWorkspaceTrustContext(workspace, controlledHome);
    assert.equal(await readPersistedWorkspaceTrust(context), undefined);
    const canonical = await trustDailyWorkspace(io, alias, controlledHome, true);
    assert.equal(canonical, await realpath(workspace));
    assert.equal(await trustDailyWorkspace(io, workspace, controlledHome, false), canonical);
    const invocation = parseClientInvocation(['run', 'Inspect', '--provider', 'ollama', '--model', 'inert'], canonical);
    assert.equal(invocation.kind, 'run');
    if (invocation.kind === 'run') {
      assert.equal(invocation.intent.workspacePath, canonical);
      assert.equal(invocation.intent.policyMode, 'default');
      assert.equal(invocation.intent.allowUnverified, false);
    }
    await writePersistedWorkspaceTrust(context, 'denied');
    await assert.rejects(trustDailyWorkspace(io, alias, controlledHome, true), /retained denied/);
    assert.equal(await readPersistedWorkspaceTrust(context), 'denied');
    const controller = new AbortController(); controller.abort();
    await assert.rejects(trustDailyWorkspace({ ...io, signal: controller.signal }, workspace, controlledHome, true),
      { name: 'AbortError' });
  } finally { input.destroy(); output.destroy(); await rm(temporary, { recursive: true, force: true }); }
});
