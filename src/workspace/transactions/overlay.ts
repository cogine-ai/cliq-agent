import { promises as fs } from 'node:fs';
import path from 'node:path';
import type { WorkspaceWriter } from '../../runtime/workspace-writer.js';

/**
 * Resolves a workspace-relative path inside `root` and asserts the result
 * stays within `root`. Rejects absolute paths and any input that resolves
 * outside the root (e.g., `../foo`, `a/../../b`). This is the security
 * boundary that keeps the overlay isolated from the real workspace and
 * vice versa: without it, `path.join(overlayRoot, '../foo')` would escape
 * the overlay and write straight into cwd.
 */
function resolveInsideLexical(root: string, rel: string): string {
  if (path.isAbsolute(rel)) {
    throw new Error(`workspace path must be relative: ${rel}`);
  }
  const normalizedRoot = path.resolve(root);
  const target = path.resolve(normalizedRoot, rel);
  const relative = path.relative(normalizedRoot, target);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`workspace path must stay inside root: ${rel}`);
  }
  return target;
}

/**
 * Defense-in-depth on top of {@link resolveInsideLexical}, scoped to paths
 * that resolve inside the **overlay** root: realpath the longest existing
 * prefix of the resolved target and re-check that it is still inside the
 * root. This catches the case where some ancestor inside the overlay is
 * itself a symlink pointing outside; lexical normalisation cannot detect
 * that.
 *
 * Why overlay-only: the overlay is cliq's private staging area and is only
 * written to via this writer (and by the tx machinery itself, which never
 * creates symlinks). Any symlink found there is therefore unexpected and a
 * legitimate signal of tampering / a write that needs to be rejected.
 *
 * The cwd intentionally does **not** go through realpath. The cwd is the
 * user's real workspace and routinely contains legitimate symlinks (pnpm
 * `node_modules`, monorepo `packages/<x> -> ../<x>`, etc.). Forcing reads
 * to stay strictly inside `realpath(cwd)` would break those workflows
 * while not adding security: cwd reads here are read-only, and the
 * overlay realpath check on the write side already prevents writes from
 * escaping the staging area.
 *
 * Limitation: pure Node.js cannot do `openat(O_NOFOLLOW)` and an inherent
 * TOCTOU window remains between this check and the subsequent fs call. We
 * accept that — closing it would require native bindings — but the realpath
 * pass still raises the bar significantly above plain lexical validation
 * for the overlay write surface.
 */
async function resolveInsideOverlay(overlayRoot: string, rel: string): Promise<string> {
  const target = resolveInsideLexical(overlayRoot, rel);
  const normalizedRoot = path.resolve(overlayRoot);
  // Resolve the root once. realpath(root) is invariant across the probe
  // walk, and conflating its ENOENT with a missing probe component would
  // make the loop body burn cycles on a meaningless symlink check.
  let realRoot: string;
  try {
    realRoot = await fs.realpath(normalizedRoot);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    // overlayRoot itself doesn't exist on disk yet (fresh transaction). The
    // lexical guard already enforced syntactic containment; with no root to
    // anchor a symlink-resolved check we fall through and trust it.
    return target;
  }

  // Walk upwards until we hit an existing path, then realpath it.
  let probe = target;
  while (true) {
    try {
      const real = await fs.realpath(probe);
      const realRel = path.relative(realRoot, real);
      if (realRel.startsWith('..') || path.isAbsolute(realRel)) {
        throw new Error(`overlay path must stay inside overlay root (symlink-resolved): ${rel}`);
      }
      return target;
    } catch (err) {
      // Only ENOENT from probing the current path is recoverable. Any other
      // error (EACCES on an ancestor, EIO, ELOOP) must propagate.
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      const parent = path.dirname(probe);
      // Reached the filesystem root without finding any existing ancestor
      // (extremely defensive — normalizedRoot exists, so the walk should
      // have terminated there). Fall back to the lexical guarantee.
      if (parent === probe) return target;
      probe = parent;
    }
  }
}

export function createOverlayWriter(cwd: string, overlayRoot: string): WorkspaceWriter {
  return {
    async read(rel) {
      const stagedPath = await resolveInsideOverlay(overlayRoot, rel);
      try {
        return await fs.readFile(stagedPath, 'utf8');
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      }
      // cwd reads honour the user's symlinks (lexical guard only).
      return fs.readFile(resolveInsideLexical(cwd, rel), 'utf8');
    },
    async replaceText(rel, oldText, newText) {
      const stagedPath = await resolveInsideOverlay(overlayRoot, rel);
      let current: string;
      try {
        current = await fs.readFile(stagedPath, 'utf8');
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
        current = await fs.readFile(resolveInsideLexical(cwd, rel), 'utf8');
      }
      const matches = current.split(oldText).length - 1;
      if (matches !== 1) {
        throw new Error(`expected old_text to match exactly once, but matched ${matches} times`);
      }
      await fs.mkdir(path.dirname(stagedPath), { recursive: true });
      // Use the function form of replace() so `$&`, `` $` ``, `$'`, `$$`,
      // `$n` in newText are written literally (e.g., `$VAR`, `$@`).
      await fs.writeFile(stagedPath, current.replace(oldText, () => newText), 'utf8');
    }
  };
}
