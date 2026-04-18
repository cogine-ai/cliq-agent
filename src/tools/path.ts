import path from 'node:path';

export function resolveWorkspacePath(cwd: string, inputPath: string) {
  const target = path.resolve(cwd, inputPath);
  const relativePath = path.relative(cwd, target) || '.';

  if (path.isAbsolute(inputPath) || relativePath.startsWith('..')) {
    throw new Error('path must stay inside the workspace and be workspace-relative');
  }

  return { target, relativePath };
}
