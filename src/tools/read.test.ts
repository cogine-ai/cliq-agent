import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createSession } from '../session/store.js';
import { readTool } from './read.js';

test('readTool returns numbered lines for a workspace file', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-read-'));
  await writeFile(path.join(cwd, 'notes.txt'), 'alpha\nbeta\ngamma\n', 'utf8');

  const result = await readTool.execute(
    { read: { path: 'notes.txt', start_line: 2, end_line: 3 } },
    { cwd, session: createSession(cwd) }
  );

  assert.equal(result.status, 'ok');
  assert.match(result.content, /2\| beta/);
  assert.match(result.content, /3\| gamma/);
});
