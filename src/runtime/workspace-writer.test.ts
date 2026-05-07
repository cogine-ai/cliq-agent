import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
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

test('PassthroughWriter writes $-prefixed replacement text literally (no $& expansion)', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-writer-dollar-'));
  try {
    // Edit a Makefile-shaped file: replace `target:` with `$@: $$VAR` literally.
    // Naive `replace(old, new)` would expand `$&` etc. and silently corrupt content.
    await writeFile(path.join(cwd, 'Makefile'), 'target:\n\techo done\n', 'utf8');
    const writer = createPassthroughWriter(cwd);
    await writer.replaceText('Makefile', 'target:', '$@: $$VAR');
    const out = await readFile(path.join(cwd, 'Makefile'), 'utf8');
    assert.equal(out, '$@: $$VAR\n\techo done\n');
    // Also verify `$&` (whole match) is not expanded.
    await writeFile(path.join(cwd, 'sh.sh'), 'great\n', 'utf8');
    await writer.replaceText('sh.sh', 'great', '$&-end');
    const out2 = await readFile(path.join(cwd, 'sh.sh'), 'utf8');
    assert.equal(out2, '$&-end\n');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('PassthroughWriter rejects path-traversal inputs (../, absolute, sneaky)', async () => {
  const outer = await mkdtemp(path.join(os.tmpdir(), 'cliq-writer-traversal-'));
  const cwd = path.join(outer, 'workspace');
  try {
    await writeFile(path.join(outer, 'secret.txt'), 'TOP_SECRET', 'utf8');
    await mkdir(cwd, { recursive: true });
    const writer = createPassthroughWriter(cwd);
    // Naive `path.join(cwd, rel)` would let these escape cwd.
    await assert.rejects(() => writer.read('../secret.txt'), /must stay inside/i);
    await assert.rejects(
      () => writer.replaceText('../secret.txt', 'TOP', 'PWND'),
      /must stay inside/i
    );
    await assert.rejects(() => writer.read('a/../../secret.txt'), /must stay inside/i);
    await assert.rejects(() => writer.read('/etc/passwd'), /must be relative/i);
    // Verify the outer file was never modified.
    assert.equal(await readFile(path.join(outer, 'secret.txt'), 'utf8'), 'TOP_SECRET');
  } finally {
    await rm(outer, { recursive: true, force: true });
  }
});
