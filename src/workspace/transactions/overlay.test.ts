import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile, mkdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createOverlayWriter } from './overlay.js';

test('OverlayWriter.read returns overlay content if staged, else real', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-overlay-read-'));
  const overlay = await mkdtemp(path.join(os.tmpdir(), 'cliq-overlay-stg-'));
  try {
    await writeFile(path.join(cwd, 'a.txt'), 'real', 'utf8');
    const writer = createOverlayWriter(cwd, overlay);
    assert.equal(await writer.read('a.txt'), 'real');
    await writer.replaceText('a.txt', 'real', 'STAGED');
    assert.equal(await writer.read('a.txt'), 'STAGED');
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(overlay, { recursive: true, force: true });
  }
});

test('OverlayWriter.replaceText writes to overlay and never modifies real workspace', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-overlay-write-'));
  const overlay = await mkdtemp(path.join(os.tmpdir(), 'cliq-overlay-write-stg-'));
  try {
    await writeFile(path.join(cwd, 'a.txt'), 'hello world', 'utf8');
    const writer = createOverlayWriter(cwd, overlay);
    await writer.replaceText('a.txt', 'world', 'WORLD');
    assert.equal(await readFile(path.join(cwd, 'a.txt'), 'utf8'), 'hello world');
    assert.equal(await readFile(path.join(overlay, 'a.txt'), 'utf8'), 'hello WORLD');
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(overlay, { recursive: true, force: true });
  }
});

test('OverlayWriter.replaceText accumulates multiple edits to the same path', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-overlay-multi-'));
  const overlay = await mkdtemp(path.join(os.tmpdir(), 'cliq-overlay-multi-stg-'));
  try {
    await writeFile(path.join(cwd, 'a.txt'), 'one two three', 'utf8');
    const writer = createOverlayWriter(cwd, overlay);
    await writer.replaceText('a.txt', 'one', '1');
    await writer.replaceText('a.txt', 'two', '2');
    assert.equal(await readFile(path.join(cwd, 'a.txt'), 'utf8'), 'one two three');
    assert.equal(await readFile(path.join(overlay, 'a.txt'), 'utf8'), '1 2 three');
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(overlay, { recursive: true, force: true });
  }
});
