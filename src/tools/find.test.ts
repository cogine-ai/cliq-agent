import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createSession } from '../session/store.js';
import { findTool } from './find.js';

test('findTool returns matching relative paths', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-find-'));
  await mkdir(path.join(cwd, 'src'));
  await writeFile(path.join(cwd, 'src', 'runner.ts'), 'export {};\n', 'utf8');
  await writeFile(path.join(cwd, 'src', 'other.ts'), 'export {};\n', 'utf8');

  const result = await findTool.execute({ find: { path: 'src', name: 'runner' } }, { cwd, session: createSession(cwd) });

  assert.equal(result.status, 'ok');
  assert.match(result.content, /src\/runner\.ts/);
  assert.doesNotMatch(result.content, /other\.ts/);
});

test('findTool records error reason for paths outside the workspace', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-find-error-'));
  try {
    const result = await findTool.execute({ find: { path: '..', name: 'runner' } }, { cwd, session: createSession(cwd) });

    assert.equal(result.status, 'error');
    assert.match(result.content, /workspace-relative/i);
    assert.match(String(result.meta.error), /workspace-relative/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
