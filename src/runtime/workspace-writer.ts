import { promises as fs } from 'node:fs';
import path from 'node:path';

export type WorkspaceWriter = {
  read(workspaceRelativePath: string): Promise<string>;
  replaceText(workspaceRelativePath: string, oldText: string, newText: string): Promise<void>;
};

/**
 * Resolves a workspace-relative path inside `cwd` and asserts the result
 * stays within `cwd`. Rejects absolute paths and any input that resolves
 * outside the workspace (e.g., `../etc/passwd`, `a/../../b`).
 */
function resolveWorkspacePath(cwd: string, rel: string): string {
  if (path.isAbsolute(rel)) {
    throw new Error(`workspace path must be relative: ${rel}`);
  }
  const normalizedCwd = path.resolve(cwd);
  const target = path.resolve(normalizedCwd, rel);
  const relative = path.relative(normalizedCwd, target);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`workspace path must stay inside the workspace: ${rel}`);
  }
  return target;
}

export function createPassthroughWriter(cwd: string): WorkspaceWriter {
  return {
    async read(rel) {
      return fs.readFile(resolveWorkspacePath(cwd, rel), 'utf8');
    },
    async replaceText(rel, oldText, newText) {
      const target = resolveWorkspacePath(cwd, rel);
      const current = await fs.readFile(target, 'utf8');
      const matches = current.split(oldText).length - 1;
      if (matches !== 1) {
        throw new Error(`expected old_text to match exactly once, but matched ${matches} times`);
      }
      // Use the function form of replace() to bypass `$&`, `` $` ``, `$'`,
      // `$$`, `$n` substitution that would otherwise apply when newText
      // contains shell variables (`$VAR`), Makefile targets (`$@`), or any
      // literal `$`-prefixed sequence the user is editing into the file.
      // The function form is exempt from that interpretation.
      await fs.writeFile(target, current.replace(oldText, () => newText), 'utf8');
    }
  };
}
