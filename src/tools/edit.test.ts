import test from 'node:test';
import assert from 'node:assert/strict';

import { createSession } from '../session/store.js';
import { editTool } from './edit.js';

test('editTool rejects absolute paths', async () => {
  const session = createSession('/tmp/workspace');
  const result = await editTool.execute(
    { edit: { path: '/tmp/workspace/file.txt', old_text: 'a', new_text: 'b' } },
    { cwd: '/tmp/workspace', session }
  );

  assert.equal(result.status, 'error');
  assert.match(result.content, /workspace-relative path|absolute path|outside workspace/i);
});

test('editTool rejects paths outside the workspace', async () => {
  const session = createSession('/tmp/workspace');
  const result = await editTool.execute(
    { edit: { path: '../other/file.txt', old_text: 'a', new_text: 'b' } },
    { cwd: '/tmp/workspace', session }
  );

  assert.equal(result.status, 'error');
  assert.match(result.content, /workspace-relative path|outside workspace/i);
});
