import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createPassthroughWriter } from './workspace-writer.js';

test('PassthroughWriter.read returns real workspace content', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-writer-read-'));
  try {
    await writeFile(path.join(cwd, 'a.txt'), 'hello', 'utf8');
    const writer = createPassthroughWriter(cwd);
    assert.equal(await writer.read('a.txt'), 'hello');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('PassthroughWriter.replaceText replaces unique substring exactly once', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-writer-replace-'));
  try {
    await writeFile(path.join(cwd, 'a.txt'), 'foo bar baz', 'utf8');
    const writer = createPassthroughWriter(cwd);
    await writer.replaceText('a.txt', 'bar', 'BAR');
    assert.equal(await readFile(path.join(cwd, 'a.txt'), 'utf8'), 'foo BAR baz');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('PassthroughWriter.replaceText rejects non-unique match', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-writer-dup-'));
  try {
    await writeFile(path.join(cwd, 'a.txt'), 'x x x', 'utf8');
    const writer = createPassthroughWriter(cwd);
    await assert.rejects(() => writer.replaceText('a.txt', 'x', 'y'), /matched 3 times/);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
