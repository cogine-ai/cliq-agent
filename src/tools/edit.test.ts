import test from 'node:test';
import assert from 'node:assert/strict';

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
});

test('editTool rejects paths outside the workspace', async () => {
  const result = await runEdit('../other/file.txt');

  assert.equal(result.status, 'error');
  assert.match(result.content, /workspace-relative path|outside workspace/i);
});
