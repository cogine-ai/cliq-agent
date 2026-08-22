import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { KernelStorageError } from './errors.js';
import {
  captureLiveWorkspaceIdentity,
  hostPlatform,
  recaptureLiveWorkspaceIdentity
} from './workspace-identity.js';

async function makePrivateDir(prefix: string): Promise<string> {
  const directory = await mkdtemp(path.join(process.cwd(), prefix));
  await chmod(directory, 0o700);
  return directory;
}

test('hostPlatform identifies Linux and Darwin hosts', () => {
  if (process.platform === 'linux') assert.equal(hostPlatform(), 'linux');
  else if (process.platform === 'darwin') assert.equal(hostPlatform(), 'macos');
  else assert.throws(() => hostPlatform(), /unsupported/i);
});

test('captureLiveWorkspaceIdentity records sha256 git objectFormat from config', async () => {
  const workspace = await makePrivateDir('.cliq-ws-id-sha256-');
  await mkdir(path.join(workspace, '.git'), { mode: 0o700 });
  await writeFile(path.join(workspace, '.git', 'config'), '[core]\n\tobjectFormat = sha256\n', { mode: 0o600 });
  try {
    const captured = await captureLiveWorkspaceIdentity({
      workspacePath: workspace,
      ownerPrincipalId: 'cliq-test-principal'
    });
    assert.equal(captured.identity.kind, 'live');
    assert.equal(captured.repository?.objectFormat, 'sha256');
    assert.equal(typeof captured.repository?.repositoryIdentityDigest, 'string');
    const replayed = await recaptureLiveWorkspaceIdentity(captured.identity, workspace);
    assert.equal(replayed.identityDigest, captured.identity.identityDigest);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test('recaptureLiveWorkspaceIdentity rejects repository identity drift', async () => {
  const workspace = await makePrivateDir('.cliq-ws-id-drift-');
  await mkdir(path.join(workspace, '.git'), { mode: 0o700 });
  await writeFile(path.join(workspace, '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n', {
    mode: 0o600
  });
  try {
    const captured = await captureLiveWorkspaceIdentity({
      workspacePath: workspace,
      ownerPrincipalId: 'cliq-test-principal'
    });
    await writeFile(path.join(workspace, '.git', 'config'), '[core]\n\tobjectFormat = sha256\n', { mode: 0o600 });
    await assert.rejects(
      () => recaptureLiveWorkspaceIdentity(captured.identity, workspace),
      (error: unknown) =>
        error instanceof KernelStorageError &&
        error.code === 'ARTIFACT_MISMATCH' &&
        /repository identity changed/i.test(error.message)
    );
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test('captureLiveWorkspaceIdentity rejects a workspace .git file', async () => {
  const workspace = await makePrivateDir('.cliq-ws-id-gitfile-');
  await writeFile(path.join(workspace, '.git'), 'not-a-directory', { mode: 0o600 });
  try {
    await assert.rejects(
      () =>
        captureLiveWorkspaceIdentity({
          workspacePath: workspace,
          ownerPrincipalId: 'cliq-test-principal'
        }),
      (error: unknown) =>
        error instanceof KernelStorageError &&
        error.code === 'INVALID_REQUEST' &&
        /in-root directory/i.test(error.message)
    );
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});
