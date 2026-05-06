import { promises as fs } from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { TxCopyMode } from '../config.js';

const execFileAsync = promisify(execFile);

export type CopyResult = 'reflinked' | 'copied';

export type StagedViewOptions = {
  cwd: string;
  overlayRoot: string;
  target: string;
  bindPaths: string[];
  copyMode: TxCopyMode;
  onWarn?: (message: string) => void;
};

export async function materializeStagedView(opts: StagedViewOptions): Promise<{ usedCopyFallback: boolean }> {
  await fs.mkdir(opts.target, { recursive: true });
  const bindSet = new Set(opts.bindPaths);
  let usedCopyFallback = false;
  await walkAndMaterialize(opts.cwd, opts.target, '', bindSet, async (src, dst) => {
    const result = await materializeFile(src, dst, opts.copyMode);
    if (result === 'copied' && opts.copyMode === 'auto') usedCopyFallback = true;
    return result;
  });
  // Apply overlay shadows
  await walkOverlay(opts.overlayRoot, opts.target);
  if (usedCopyFallback && opts.onWarn) {
    opts.onWarn('staged-view falling back to byte copy; reflink unsupported on this filesystem');
  }
  return { usedCopyFallback };
}

async function walkAndMaterialize(
  cwd: string,
  target: string,
  prefix: string,
  bindSet: Set<string>,
  copyOne: (src: string, dst: string) => Promise<CopyResult>
): Promise<void> {
  const fullSrc = path.join(cwd, prefix);
  const entries = await fs.readdir(fullSrc, { withFileTypes: true });
  for (const entry of entries) {
    const rel = prefix ? path.join(prefix, entry.name) : entry.name;
    const srcPath = path.join(cwd, rel);
    const dstPath = path.join(target, rel);
    if (bindSet.has(rel)) {
      await fs.symlink(srcPath, dstPath);
      continue;
    }
    if (entry.isDirectory()) {
      await fs.mkdir(dstPath, { recursive: true });
      await walkAndMaterialize(cwd, target, rel, bindSet, copyOne);
    } else if (entry.isFile()) {
      await copyOne(srcPath, dstPath);
    }
  }
}

async function walkOverlay(overlayRoot: string, target: string): Promise<void> {
  const stack: string[] = [''];
  while (stack.length) {
    const prefix = stack.pop()!;
    let entries;
    try {
      entries = await fs.readdir(path.join(overlayRoot, prefix), { withFileTypes: true });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw err;
    }
    for (const entry of entries) {
      const rel = prefix ? path.join(prefix, entry.name) : entry.name;
      if (entry.isDirectory()) {
        stack.push(rel);
        continue;
      }
      const overlayPath = path.join(overlayRoot, rel);
      const targetPath = path.join(target, rel);
      await fs.mkdir(path.dirname(targetPath), { recursive: true });
      await fs.copyFile(overlayPath, targetPath);
    }
  }
}

async function materializeFile(src: string, dst: string, mode: TxCopyMode): Promise<CopyResult> {
  if (mode === 'copy') {
    await fs.copyFile(src, dst);
    return 'copied';
  }
  // reflink path
  try {
    if (process.platform === 'darwin') {
      await execFileAsync('cp', ['-c', src, dst]);
    } else {
      await execFileAsync('cp', ['--reflink=always', src, dst]);
    }
    return 'reflinked';
  } catch (err) {
    if (mode === 'reflink') throw err;
    await fs.copyFile(src, dst);
    return 'copied';
  }
}
