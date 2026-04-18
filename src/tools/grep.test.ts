import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createSession } from '../session/store.js';
import { grepTool } from './grep.js';

test('grepTool returns line matches with file and line numbers', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-grep-'));
  await mkdir(path.join(cwd, 'src'));
  await writeFile(path.join(cwd, 'src', 'runner.ts'), 'export function runTurn() {}\n', 'utf8');

  const result = await grepTool.execute({ grep: { path: 'src', pattern: 'runTurn' } }, { cwd, session: createSession(cwd) });

  assert.equal(result.status, 'ok');
  assert.match(result.content, /src\/runner\.ts:1:/);
  assert.match(result.content, /runTurn/);
});
