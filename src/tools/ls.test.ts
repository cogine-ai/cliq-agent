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
    const readmeIndex = result.content.indexOf('file README.md');
    const srcIndex = result.content.indexOf('dir src/');
    assert.notEqual(readmeIndex, -1);
    assert.notEqual(srcIndex, -1);
    assert.ok(readmeIndex < srcIndex, 'entries should be listed in sorted order');
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

test('lsTool records error reason for paths outside the workspace', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-ls-error-'));
  try {
    const result = await lsTool.execute({ ls: { path: '..' } }, { cwd, session: createSession(cwd) });

    assert.equal(result.status, 'error');
    assert.match(result.content, /workspace-relative/i);
    assert.match(String(result.meta.error), /workspace-relative/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
