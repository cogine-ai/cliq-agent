import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile, mkdir, symlink } from 'node:fs/promises';
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

test('OverlayWriter rejects path-traversal inputs that would escape overlay or cwd', async () => {
  const outer = await mkdtemp(path.join(os.tmpdir(), 'cliq-overlay-traversal-'));
  const cwd = path.join(outer, 'workspace');
  const overlay = path.join(outer, 'overlay');
  try {
    await writeFile(path.join(outer, 'secret.txt'), 'OUTSIDE', 'utf8');
    await mkdir(cwd, { recursive: true });
    await mkdir(overlay, { recursive: true });
    const writer = createOverlayWriter(cwd, overlay);
    // ../foo / a/../../foo would otherwise resolve outside overlay or cwd.
    await assert.rejects(() => writer.read('../secret.txt'), /must stay inside/i);
    await assert.rejects(
      () => writer.replaceText('../secret.txt', 'OUT', 'PWND'),
      /must stay inside/i
    );
    await assert.rejects(() => writer.read('a/../../secret.txt'), /must stay inside/i);
    await assert.rejects(() => writer.read('/etc/passwd'), /must be relative/i);
    // Outer file untouched.
    assert.equal(await readFile(path.join(outer, 'secret.txt'), 'utf8'), 'OUTSIDE');
  } finally {
    await rm(outer, { recursive: true, force: true });
  }
});

test('OverlayWriter rejects symlink ancestors that escape the overlay root', async () => {
  // Defense-in-depth: a lexically inside path can still reach outside the
  // overlay if any ancestor on disk is a symlink. resolveInside realpaths
  // the longest existing prefix and re-checks containment to catch this.
  const outer = await mkdtemp(path.join(os.tmpdir(), 'cliq-overlay-symlink-'));
  const cwd = path.join(outer, 'workspace');
  const overlay = path.join(outer, 'overlay');
  const escape = path.join(outer, 'escape');
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(overlay, { recursive: true });
    await mkdir(escape, { recursive: true });
    await writeFile(path.join(escape, 'secret.txt'), 'OUTSIDE', 'utf8');
    // overlay/link -> ../escape; lexical guard alone would let
    // overlay/link/secret.txt through.
    await symlink(escape, path.join(overlay, 'link'));

    const writer = createOverlayWriter(cwd, overlay);
    await assert.rejects(
      () => writer.read('link/secret.txt'),
      /must stay inside root \(symlink-resolved\)/i
    );
    await assert.rejects(
      () => writer.replaceText('link/secret.txt', 'OUTSIDE', 'PWND'),
      /must stay inside root \(symlink-resolved\)/i
    );

    assert.equal(await readFile(path.join(escape, 'secret.txt'), 'utf8'), 'OUTSIDE');
  } finally {
    await rm(outer, { recursive: true, force: true });
  }
});
