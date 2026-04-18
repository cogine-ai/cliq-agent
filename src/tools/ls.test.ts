import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createSession } from '../session/store.js';
import { lsTool } from './ls.js';

test('lsTool lists directory entries in sorted order', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-ls-'));
  await mkdir(path.join(cwd, 'src'));
  await writeFile(path.join(cwd, 'README.md'), '# demo\n', 'utf8');

  const result = await lsTool.execute({ ls: { path: '.' } }, { cwd, session: createSession(cwd) });

  assert.equal(result.status, 'ok');
  assert.match(result.content, /dir\s+src\//);
  assert.match(result.content, /file\s+README\.md/);
});
