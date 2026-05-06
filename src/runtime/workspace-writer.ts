import { promises as fs } from 'node:fs';
import path from 'node:path';

export type WorkspaceWriter = {
  read(workspaceRelativePath: string): Promise<string>;
  replaceText(workspaceRelativePath: string, oldText: string, newText: string): Promise<void>;
};

export function createPassthroughWriter(cwd: string): WorkspaceWriter {
  return {
    async read(rel) {
      return fs.readFile(path.join(cwd, rel), 'utf8');
    },
    async replaceText(rel, oldText, newText) {
      const target = path.join(cwd, rel);
      const current = await fs.readFile(target, 'utf8');
      const matches = current.split(oldText).length - 1;
      if (matches !== 1) {
        throw new Error(`expected old_text to match exactly once, but matched ${matches} times`);
      }
      await fs.writeFile(target, current.replace(oldText, newText), 'utf8');
    }
  };
}
