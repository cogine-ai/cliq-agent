import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createSession } from '../session/store.js';
import { editTool } from './edit.js';

async function runEdit(path: string, old_text = 'a', new_text = 'b') {
  const session = createSession('/tmp/workspace');
  return editTool.execute({ edit: { path, old_text, new_text } }, { cwd: '/tmp/workspace', session });
}

test('editTool rejects absolute paths', async () => {
  const result = await runEdit('/tmp/workspace/file.txt');

  assert.equal(result.status, 'error');
  assert.match(result.content, /workspace-relative path|absolute path|outside workspace/i);
  assert.match(String(result.meta.error), /workspace-relative path|absolute path|outside workspace/i);
});

test('editTool rejects paths outside the workspace', async () => {
  const result = await runEdit('../other/file.txt');

  assert.equal(result.status, 'error');
  assert.match(result.content, /workspace-relative path|outside workspace/i);
});

test('editTool rejects symlink escapes outside the workspace', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-edit-link-'));
  const outside = await mkdtemp(path.join(os.tmpdir(), 'cliq-edit-outside-'));
  try {
    await writeFile(path.join(outside, 'secret.txt'), 'a\n', 'utf8');
    await symlink(path.join(outside, 'secret.txt'), path.join(cwd, 'secret-link.txt'));

    const session = createSession(cwd);
    const result = await editTool.execute(
      { edit: { path: 'secret-link.txt', old_text: 'a', new_text: 'b' } },
      { cwd, session }
    );

    assert.equal(result.status, 'error');
    assert.match(result.content, /workspace-relative path|outside workspace/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});
