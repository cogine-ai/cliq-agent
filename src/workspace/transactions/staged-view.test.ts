import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, mkdir, writeFile, readFile, lstat, readlink, chmod } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { materializeStagedView } from './staged-view.js';

test('materializeStagedView symlinks bindPaths and copies other files', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-bind-cwd-'));
  const overlay = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-bind-ov-'));
  const target = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-bind-tg-'));
  try {
    await mkdir(path.join(cwd, 'src'), { recursive: true });
    await writeFile(path.join(cwd, 'src', 'a.ts'), '1', 'utf8');
    await mkdir(path.join(cwd, 'node_modules', 'foo'), { recursive: true });
    await writeFile(path.join(cwd, 'node_modules', 'foo', 'index.js'), 'dep', 'utf8');

    await materializeStagedView({
      cwd,
      overlayRoot: overlay,
      target,
      bindPaths: ['node_modules'],
      copyMode: 'copy'
    });

    assert.equal(await readFile(path.join(target, 'src', 'a.ts'), 'utf8'), '1');
    const nm = await lstat(path.join(target, 'node_modules'));
    assert.ok(nm.isSymbolicLink(), 'node_modules should be a symlink');
    assert.equal(await readlink(path.join(target, 'node_modules')), path.join(cwd, 'node_modules'));
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(overlay, { recursive: true, force: true });
    await rm(target, { recursive: true, force: true });
  }
});

test('materializeStagedView writes overlay-shadowed files into target', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-shadow-cwd-'));
  const overlay = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-shadow-ov-'));
  const target = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-shadow-tg-'));
  try {
    await mkdir(path.join(cwd, 'src'), { recursive: true });
    await writeFile(path.join(cwd, 'src', 'a.ts'), '1', 'utf8');
    await mkdir(path.join(overlay, 'src'), { recursive: true });
    await writeFile(path.join(overlay, 'src', 'a.ts'), '2', 'utf8');

    await materializeStagedView({
      cwd,
      overlayRoot: overlay,
      target,
      bindPaths: [],
      copyMode: 'copy'
    });

    assert.equal(await readFile(path.join(target, 'src', 'a.ts'), 'utf8'), '2');
    assert.equal(await readFile(path.join(cwd, 'src', 'a.ts'), 'utf8'), '1');
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(overlay, { recursive: true, force: true });
    await rm(target, { recursive: true, force: true });
  }
});

test('materializeStagedView copyMode auto reports fallback consistently', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-auto-cwd-'));
  const overlay = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-auto-ov-'));
  const target = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-auto-tg-'));
  try {
    await writeFile(path.join(cwd, 'a.txt'), 'hello', 'utf8');

    let warned = false;
    const result = await materializeStagedView({
      cwd,
      overlayRoot: overlay,
      target,
      bindPaths: [],
      copyMode: 'auto',
      onWarn: () => {
        warned = true;
      }
    });

    // If reflink succeeded on the underlying fs, no warning. If it fell back, warned.
    assert.equal(result.usedCopyFallback, warned);
    assert.equal(await readFile(path.join(target, 'a.txt'), 'utf8'), 'hello');
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(overlay, { recursive: true, force: true });
    await rm(target, { recursive: true, force: true });
  }
});

test('materializeStagedView with reflink mode throws when copy is impossible', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-rl-cwd-'));
  const overlay = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-rl-ov-'));
  const target = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-rl-tg-'));
  try {
    await writeFile(path.join(cwd, 'a.txt'), 'hello', 'utf8');
    // Make the target directory read-only so cp cannot create files inside it.
    // Both `cp -c` (macOS) and `cp --reflink=always` (Linux) fail with EACCES here.
    await chmod(target, 0o500);
    try {
      await assert.rejects(
        materializeStagedView({
          cwd,
          overlayRoot: overlay,
          target,
          bindPaths: [],
          copyMode: 'reflink'
        })
      );
    } finally {
      // Restore writable perms so the cleanup `rm` can remove the tree.
      await chmod(target, 0o700);
    }
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(overlay, { recursive: true, force: true });
    await rm(target, { recursive: true, force: true });
  }
});

test('materializeStagedView writes do not propagate to cwd', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-iso-cwd-'));
  const overlay = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-iso-ov-'));
  const target = await mkdtemp(path.join(os.tmpdir(), 'cliq-sv-iso-tg-'));
  try {
    await mkdir(path.join(cwd, 'src'), { recursive: true });
    await writeFile(path.join(cwd, 'src', 'a.ts'), '1', 'utf8');

    await materializeStagedView({
      cwd,
      overlayRoot: overlay,
      target,
      bindPaths: [],
      copyMode: 'copy'
    });

    // Mutate the materialized file
    await writeFile(path.join(target, 'src', 'a.ts'), 'leak', 'utf8');

    // cwd unchanged
    assert.equal(await readFile(path.join(cwd, 'src', 'a.ts'), 'utf8'), '1');
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(overlay, { recursive: true, force: true });
    await rm(target, { recursive: true, force: true });
  }
});
