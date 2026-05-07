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

test('OverlayWriter rejects overlay-side symlink ancestors that escape the overlay root', async () => {
  // Defense-in-depth: a lexically inside path can still reach outside the
  // overlay if any ancestor inside the overlay is a symlink.
  // resolveInsideOverlay realpaths the longest existing prefix and
  // re-checks containment to catch this on the write surface.
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
      /must stay inside overlay root \(symlink-resolved\)/i
    );
    await assert.rejects(
      () => writer.replaceText('link/secret.txt', 'OUTSIDE', 'PWND'),
      /must stay inside overlay root \(symlink-resolved\)/i
    );

    assert.equal(await readFile(path.join(escape, 'secret.txt'), 'utf8'), 'OUTSIDE');
  } finally {
    await rm(outer, { recursive: true, force: true });
  }
});

test('OverlayWriter refuses to operate when the overlay root itself is a symlink', async () => {
  // Tripwire: cliq always creates the overlay dir with fs.mkdir, so a
  // symlink AT THE LEAF (e.g., someone substituted <txDir>/overlay with
  // a redirect) is anomalous. Fail loud rather than silently redirecting
  // every write into the link target.
  const outer = await mkdtemp(path.join(os.tmpdir(), 'cliq-overlay-rootsym-'));
  const cwd = path.join(outer, 'workspace');
  const realOverlay = path.join(outer, 'real-overlay');
  const overlayLink = path.join(outer, 'overlay');
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(realOverlay, { recursive: true });
    await symlink(realOverlay, overlayLink);

    const writer = createOverlayWriter(cwd, overlayLink);
    await assert.rejects(
      () => writer.replaceText('foo.ts', 'OLD', 'NEW'),
      /overlay root must not be a symlink/i
    );
    await assert.rejects(() => writer.read('foo.ts'), /overlay root must not be a symlink/i);
  } finally {
    await rm(outer, { recursive: true, force: true });
  }
});

test('OverlayWriter accepts an ancestor symlink above the overlay root', async () => {
  // Counterpart to the leaf-rejection above: a symlink ABOVE the overlay
  // root (e.g., $CLIQ_HOME itself being symlinked, common on machines
  // that put cliq home on a separate volume) is fine — realpath resolves
  // it and the containment check uses the resolved root.
  const outer = await mkdtemp(path.join(os.tmpdir(), 'cliq-overlay-ancestor-'));
  const realHome = path.join(outer, 'real-home');
  const homeLink = path.join(outer, 'home');
  const cwd = path.join(outer, 'workspace');
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(path.join(realHome, 'tx_x', 'overlay'), { recursive: true });
    await symlink(realHome, homeLink);
    // overlayRoot is path-via-symlink-ancestor; the leaf itself is a real dir.
    const overlay = path.join(homeLink, 'tx_x', 'overlay');
    await writeFile(path.join(cwd, 'a.txt'), 'hi', 'utf8');

    const writer = createOverlayWriter(cwd, overlay);
    // Read fall-through to cwd works.
    assert.equal(await writer.read('a.txt'), 'hi');
    // Write into overlay-via-ancestor-symlink succeeds and writes through to
    // the real home.
    await writer.replaceText('a.txt', 'hi', 'HI');
    assert.equal(await readFile(path.join(realHome, 'tx_x', 'overlay', 'a.txt'), 'utf8'), 'HI');
  } finally {
    await rm(outer, { recursive: true, force: true });
  }
});

test('OverlayWriter still honours legitimate cwd-side symlinks (read fall-through)', async () => {
  // Real-world workspaces frequently use symlinks (pnpm node_modules,
  // monorepo `packages/<x> -> ../<x>`, framework conventions). The
  // overlay reader must NOT reject those: cwd reads are read-only and
  // the user is the source of truth for what their workspace looks like.
  const outer = await mkdtemp(path.join(os.tmpdir(), 'cliq-overlay-cwd-symlink-'));
  const cwd = path.join(outer, 'workspace');
  const overlay = path.join(outer, 'overlay');
  const sibling = path.join(outer, 'sibling-pkg');
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(overlay, { recursive: true });
    await mkdir(sibling, { recursive: true });
    await writeFile(path.join(sibling, 'shared.ts'), 'export const X = 1;\n', 'utf8');
    // cwd/packages/foo -> ../sibling-pkg (legit monorepo-ish layout).
    await mkdir(path.join(cwd, 'packages'), { recursive: true });
    await symlink(sibling, path.join(cwd, 'packages', 'foo'));

    const writer = createOverlayWriter(cwd, overlay);
    // Read should follow the user's symlink and succeed.
    assert.equal(await writer.read('packages/foo/shared.ts'), 'export const X = 1;\n');
    // Edit goes to overlay (not the symlink target).
    await writer.replaceText('packages/foo/shared.ts', 'X = 1', 'X = 42');
    assert.equal(await readFile(path.join(sibling, 'shared.ts'), 'utf8'), 'export const X = 1;\n');
    assert.equal(
      await readFile(path.join(overlay, 'packages', 'foo', 'shared.ts'), 'utf8'),
      'export const X = 42;\n'
    );
  } finally {
    await rm(outer, { recursive: true, force: true });
  }
});
