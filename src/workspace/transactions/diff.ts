import { promises as fs } from 'node:fs';
import path from 'node:path';
import type { Diff, DiffEntry, DiffSummary } from './types.js';

export async function computeDiff(cwd: string, overlayRoot: string): Promise<Diff> {
  const files: DiffEntry[] = [];
  await walk(overlayRoot, '', async (rel) => {
    const newContent = await fs.readFile(path.join(overlayRoot, rel), 'utf8');
    const oldContent = await fs.readFile(path.join(cwd, rel), 'utf8');
    files.push({ path: rel, op: 'modify', oldContent, newContent });
  });
  return { files, outOfBand: [] };
}

async function walk(root: string, prefix: string, visit: (rel: string) => Promise<void>): Promise<void> {
  let entries;
  try {
    entries = await fs.readdir(path.join(root, prefix), { withFileTypes: true });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw err;
  }
  for (const entry of entries) {
    const next = prefix ? path.join(prefix, entry.name) : entry.name;
    if (entry.isDirectory()) {
      await walk(root, next, visit);
    } else if (entry.isFile()) {
      await visit(next);
    }
  }
}

export function summarizeDiff(diff: Diff): DiffSummary {
  const summary: DiffSummary = {
    filesChanged: diff.files.length,
    additions: 0,
    deletions: 0,
    creates: [],
    modifies: [],
    deletes: []
  };
  for (const f of diff.files) {
    if (f.op === 'modify') {
      summary.modifies.push(f.path);
      const oldLines = f.oldContent.split('\n');
      const newLines = f.newContent.split('\n');
      summary.additions += Math.max(0, newLines.length - oldLines.length);
      summary.deletions += Math.max(0, oldLines.length - newLines.length);
    }
  }
  return summary;
}
