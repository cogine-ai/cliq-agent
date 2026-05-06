import { promises as fs } from 'node:fs';
import path from 'node:path';
import type { WorkspaceWriter } from '../../runtime/workspace-writer.js';

export function createOverlayWriter(cwd: string, overlayRoot: string): WorkspaceWriter {
  return {
    async read(rel) {
      const stagedPath = path.join(overlayRoot, rel);
      try {
        return await fs.readFile(stagedPath, 'utf8');
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      }
      return fs.readFile(path.join(cwd, rel), 'utf8');
    },
    async replaceText(rel, oldText, newText) {
      const stagedPath = path.join(overlayRoot, rel);
      let current: string;
      try {
        current = await fs.readFile(stagedPath, 'utf8');
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
        current = await fs.readFile(path.join(cwd, rel), 'utf8');
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
