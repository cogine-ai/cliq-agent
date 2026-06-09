import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  isPathInsideWorkspace,
  resolveWorkspaceEntry,
  resolveWorkspacePath,
  WORKSPACE_PATH_ERROR
} from './path.js';

test('isPathInsideWorkspace accepts the workspace root and nested paths', () => {
  const workspace = '/tmp/workspace';
  assert.equal(isPathInsideWorkspace(workspace, workspace), true);
  assert.equal(isPathInsideWorkspace(workspace, path.join(workspace, 'src', 'app.ts')), true);
});

test('isPathInsideWorkspace rejects paths outside the workspace', () => {
  const workspace = '/tmp/workspace';
  assert.equal(isPathInsideWorkspace(workspace, '/tmp/outside'), false);
  assert.equal(isPathInsideWorkspace(workspace, path.join(workspace, '..', 'outside')), false);
});

test('resolveWorkspacePath rejects absolute and parent-relative inputs', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-path-resolve-'));
  try {
    await writeFile(path.join(cwd, 'notes.txt'), 'hello\n', 'utf8');

    await assert.rejects(
      () => resolveWorkspacePath(cwd, path.join(cwd, 'notes.txt')),
      new RegExp(WORKSPACE_PATH_ERROR)
    );
    await assert.rejects(() => resolveWorkspacePath(cwd, '../outside'), new RegExp(WORKSPACE_PATH_ERROR));
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('resolveWorkspacePath resolves workspace-relative paths through realpath', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-path-real-'));
  try {
    await mkdir(path.join(cwd, 'src'), { recursive: true });
    await writeFile(path.join(cwd, 'src', 'app.ts'), 'export {}\n', 'utf8');

    const resolved = await resolveWorkspacePath(cwd, 'src/app.ts');

    assert.equal(resolved.relativePath, path.join('src', 'app.ts'));
    assert.match(resolved.targetRealPath, /app\.ts$/);
    assert.equal(isPathInsideWorkspace(resolved.workspaceRealPath, resolved.targetRealPath), true);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('resolveWorkspacePath rejects symlink targets outside the workspace', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-path-symlink-'));
  const outside = await mkdtemp(path.join(os.tmpdir(), 'cliq-path-outside-'));
  try {
    await writeFile(path.join(outside, 'secret.txt'), 'secret\n', 'utf8');
    await symlink(path.join(outside, 'secret.txt'), path.join(cwd, 'secret-link.txt'));

    await assert.rejects(() => resolveWorkspacePath(cwd, 'secret-link.txt'), new RegExp(WORKSPACE_PATH_ERROR));
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('resolveWorkspaceEntry returns null for symlinks and outside targets', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-path-entry-'));
  const outside = await mkdtemp(path.join(os.tmpdir(), 'cliq-path-entry-outside-'));
  try {
    await mkdir(path.join(cwd, 'src'), { recursive: true });
    await writeFile(path.join(cwd, 'src', 'app.ts'), 'export {}\n', 'utf8');
    await writeFile(path.join(outside, 'secret.txt'), 'secret\n', 'utf8');
    await symlink(path.join(outside, 'secret.txt'), path.join(cwd, 'src', 'secret-link.txt'));

    const workspaceRealPath = await resolveWorkspacePath(cwd, '.').then((resolved) => resolved.workspaceRealPath);
    const inside = await resolveWorkspaceEntry(workspaceRealPath, path.join(cwd, 'src', 'app.ts'));
    const symlinked = await resolveWorkspaceEntry(workspaceRealPath, path.join(cwd, 'src', 'secret-link.txt'));

    assert.ok(inside);
    assert.equal(inside?.relativePath, path.join('src', 'app.ts'));
    assert.equal(symlinked, null);
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});
