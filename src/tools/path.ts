import { promises as fs } from 'node:fs';
import path from 'node:path';

export const WORKSPACE_PATH_ERROR = 'path must stay inside the workspace and be workspace-relative';

export function isPathInsideWorkspace(workspaceRealPath: string, targetRealPath: string) {
  const relativePath = path.relative(workspaceRealPath, targetRealPath);
  return relativePath === '' || (!relativePath.startsWith('..') && !path.isAbsolute(relativePath));
}

export async function resolveWorkspacePath(cwd: string, inputPath: string) {
  const target = path.resolve(cwd, inputPath);
  const relativePath = path.relative(cwd, target) || '.';

  if (path.isAbsolute(inputPath) || relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
    throw new Error(WORKSPACE_PATH_ERROR);
  }

  const workspaceRealPath = await fs.realpath(cwd);
  const targetRealPath = await fs.realpath(target);

  if (!isPathInsideWorkspace(workspaceRealPath, targetRealPath)) {
    throw new Error(WORKSPACE_PATH_ERROR);
  }

  return { target, relativePath, workspaceRealPath, targetRealPath };
}

export async function resolveWorkspaceEntry(workspaceRealPath: string, target: string) {
  const stat = await fs.lstat(target);
  if (stat.isSymbolicLink()) {
    return null;
  }

  const targetRealPath = await fs.realpath(target);
  if (!isPathInsideWorkspace(workspaceRealPath, targetRealPath)) {
    return null;
  }

  return {
    stat,
    targetRealPath,
    relativePath: path.relative(workspaceRealPath, targetRealPath) || '.'
  };
}
