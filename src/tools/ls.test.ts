import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { LIST_MAX_ENTRIES } from '../config.js';
import { createSession } from '../session/store.js';
import { lsTool } from './ls.js';

test('lsTool lists directory entries in sorted order', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-ls-'));
  try {
    await mkdir(path.join(cwd, 'src'));
    await writeFile(path.join(cwd, 'README.md'), '# demo\n', 'utf8');

    const result = await lsTool.execute({ ls: { path: '.' } }, { cwd, session: createSession(cwd) });

    assert.equal(result.status, 'ok');
    assert.match(result.content, /dir\s+src\//);
    assert.match(result.content, /file\s+README\.md/);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('lsTool shows when directory output is truncated', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-ls-truncated-'));
  try {
    for (let index = 0; index < LIST_MAX_ENTRIES + 1; index += 1) {
      await writeFile(path.join(cwd, `file-${index.toString().padStart(3, '0')}.txt`), 'demo\n', 'utf8');
    }

    const result = await lsTool.execute({ ls: { path: '.' } }, { cwd, session: createSession(cwd) });

    assert.equal(result.status, 'ok');
    assert.match(result.content, new RegExp(`truncated, showing ${LIST_MAX_ENTRIES} of ${LIST_MAX_ENTRIES + 1} entries`));
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
