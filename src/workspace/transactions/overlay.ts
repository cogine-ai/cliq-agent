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
function resolveInside(root: string, rel: string): string {
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

export function createOverlayWriter(cwd: string, overlayRoot: string): WorkspaceWriter {
  return {
    async read(rel) {
      const stagedPath = resolveInside(overlayRoot, rel);
      try {
        return await fs.readFile(stagedPath, 'utf8');
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      }
      return fs.readFile(resolveInside(cwd, rel), 'utf8');
    },
    async replaceText(rel, oldText, newText) {
      const stagedPath = resolveInside(overlayRoot, rel);
      let current: string;
      try {
        current = await fs.readFile(stagedPath, 'utf8');
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
        current = await fs.readFile(resolveInside(cwd, rel), 'utf8');
      }
      const matches = current.split(oldText).length - 1;
      if (matches !== 1) {
        throw new Error(`expected old_text to match exactly once, but matched ${matches} times`);
      }
      await fs.mkdir(path.dirname(stagedPath), { recursive: true });
      await fs.writeFile(stagedPath, current.replace(oldText, newText), 'utf8');
    }
  };
}
