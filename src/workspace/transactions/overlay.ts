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
 * Defense-in-depth on top of {@link resolveInsideLexical}: realpath the
 * longest existing prefix of the resolved target and re-check that it is
 * still inside `root`. This catches the case where some ancestor on disk
 * is a symlink pointing outside the overlay/cwd; lexical normalisation
 * alone cannot detect that.
 *
 * Limitation: pure Node.js cannot do `openat(O_NOFOLLOW)` and an inherent
 * TOCTOU window remains between this check and the subsequent fs call. We
 * accept that — closing it would require native bindings — but the realpath
 * pass still raises the bar significantly above plain lexical validation.
 */
async function resolveInside(root: string, rel: string): Promise<string> {
  const target = resolveInsideLexical(root, rel);
  const normalizedRoot = path.resolve(root);
  // Walk upwards until we hit an existing path, then realpath it.
  let probe = target;
  while (true) {
    try {
      const real = await fs.realpath(probe);
      const realRoot = await fs.realpath(normalizedRoot);
      const realRel = path.relative(realRoot, real);
      if (realRel.startsWith('..') || path.isAbsolute(realRel)) {
        throw new Error(`workspace path must stay inside root (symlink-resolved): ${rel}`);
      }
      return target;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      const parent = path.dirname(probe);
      // Reached the filesystem root — nothing to realpath; fall back to the
      // lexical guarantee. This happens for fresh overlays that don't exist
      // on disk yet.
      if (parent === probe) return target;
      probe = parent;
    }
  }
}

export function createOverlayWriter(cwd: string, overlayRoot: string): WorkspaceWriter {
  return {
    async read(rel) {
      const stagedPath = await resolveInside(overlayRoot, rel);
      try {
        return await fs.readFile(stagedPath, 'utf8');
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      }
      return fs.readFile(await resolveInside(cwd, rel), 'utf8');
    },
    async replaceText(rel, oldText, newText) {
      const stagedPath = await resolveInside(overlayRoot, rel);
      let current: string;
      try {
        current = await fs.readFile(stagedPath, 'utf8');
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
        current = await fs.readFile(await resolveInside(cwd, rel), 'utf8');
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
