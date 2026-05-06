import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { computeDiff, summarizeDiff } from './diff.js';

test('computeDiff returns one modify entry per staged file', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-diff-cwd-'));
  const overlay = await mkdtemp(path.join(os.tmpdir(), 'cliq-diff-ov-'));
  try {
    await writeFile(path.join(cwd, 'a.txt'), 'one', 'utf8');
    await writeFile(path.join(overlay, 'a.txt'), 'ONE', 'utf8');
    const diff = await computeDiff(cwd, overlay);
    assert.deepEqual(diff.files, [{ path: 'a.txt', op: 'modify', oldContent: 'one', newContent: 'ONE' }]);
    assert.deepEqual(diff.outOfBand, []);
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(overlay, { recursive: true, force: true });
  }
});

test('computeDiff descends nested directories', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-diff-nest-cwd-'));
  const overlay = await mkdtemp(path.join(os.tmpdir(), 'cliq-diff-nest-ov-'));
  try {
    await mkdir(path.join(cwd, 'src'), { recursive: true });
    await mkdir(path.join(overlay, 'src'), { recursive: true });
    await writeFile(path.join(cwd, 'src', 'a.ts'), '1', 'utf8');
    await writeFile(path.join(overlay, 'src', 'a.ts'), '2', 'utf8');
    const diff = await computeDiff(cwd, overlay);
    assert.equal(diff.files.length, 1);
    assert.equal(diff.files[0].path, path.join('src', 'a.ts'));
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(overlay, { recursive: true, force: true });
  }
});

test('computeDiff returns empty files[] for empty overlay', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-diff-empty-cwd-'));
  const overlay = await mkdtemp(path.join(os.tmpdir(), 'cliq-diff-empty-ov-'));
  try {
    const diff = await computeDiff(cwd, overlay);
    assert.deepEqual(diff.files, []);
    assert.deepEqual(diff.outOfBand, []);
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(overlay, { recursive: true, force: true });
  }
});

test('summarizeDiff counts files and approximate line deltas', async () => {
  const summary = summarizeDiff({
    files: [
      { path: 'a.txt', op: 'modify', oldContent: 'a\nb', newContent: 'a\nb\nc\nd' },
      { path: 'b.txt', op: 'modify', oldContent: 'x\ny\nz', newContent: 'x' }
    ],
    outOfBand: []
  });
  assert.equal(summary.filesChanged, 2);
  assert.deepEqual(summary.modifies, ['a.txt', 'b.txt']);
  assert.deepEqual(summary.creates, []);
  assert.deepEqual(summary.deletes, []);
  assert.equal(summary.additions, 2);
  assert.equal(summary.deletions, 2);
});
