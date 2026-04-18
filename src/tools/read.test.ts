import assert from 'node:assert/strict';
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createSession } from '../session/store.js';
import { readTool } from './read.js';

test('readTool returns numbered lines for a workspace file', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-read-'));
  try {
    await writeFile(path.join(cwd, 'notes.txt'), 'alpha\nbeta\ngamma\n', 'utf8');

    const result = await readTool.execute(
      { read: { path: 'notes.txt', start_line: 2, end_line: 3 } },
      { cwd, session: createSession(cwd) }
    );

    assert.equal(result.status, 'ok');
    assert.match(result.content, /2\| beta/);
    assert.match(result.content, /3\| gamma/);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('readTool clamps ranges that start after the end of the file', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-read-range-'));
  try {
    await writeFile(path.join(cwd, 'notes.txt'), 'alpha\nbeta\ngamma\n', 'utf8');

    const result = await readTool.execute(
      { read: { path: 'notes.txt', start_line: 99, end_line: 120 } },
      { cwd, session: createSession(cwd) }
    );

    assert.equal(result.status, 'ok');
    assert.deepEqual(result.meta.start_line, 4);
    assert.deepEqual(result.meta.end_line, 4);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('readTool rejects symlink escapes outside the workspace', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-read-link-'));
  const outside = await mkdtemp(path.join(os.tmpdir(), 'cliq-read-outside-'));
  try {
    await writeFile(path.join(outside, 'secret.txt'), 'secret\n', 'utf8');
    await symlink(path.join(outside, 'secret.txt'), path.join(cwd, 'secret-link.txt'));

    const result = await readTool.execute(
      { read: { path: 'secret-link.txt' } },
      { cwd, session: createSession(cwd) }
    );

    assert.equal(result.status, 'error');
    assert.match(result.content, /workspace-relative/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});
