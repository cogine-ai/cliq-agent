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
  // Refuse to materialize when target is cwd itself or a descendant. Otherwise
  // walkAndMaterialize would re-enter the target tree it is currently writing,
  // producing infinite recursion / unbounded copying. This is a safety net for
  // misconfiguration; legitimate callers always point target outside cwd.
  const cwdResolved = path.resolve(opts.cwd);
  const targetResolved = path.resolve(opts.target);
  if (targetResolved === cwdResolved || targetResolved.startsWith(cwdResolved + path.sep)) {
    throw new Error(
      `materializeStagedView: target ${opts.target} is inside cwd ${opts.cwd}; refusing to recursively copy`
    );
  }
  await fs.mkdir(opts.target, { recursive: true });
  const bindSet = new Set(opts.bindPaths);
  let usedCopyFallback = false;
  // Once a reflink attempt falls back to byte copy in 'auto' mode we know
  // the filesystem can't reflink between cwd and target. Latch into 'copy'
  // for the rest of the walk so we don't pay the cp(1) spawn + failure
  // cost (and the resulting noise in process tables) on every subsequent
  // file. The original opts.copyMode is preserved for the final warning
  // decision below.
  let effectiveMode: TxCopyMode = opts.copyMode;
  await walkAndMaterialize(opts.cwd, opts.target, '', bindSet, async (src, dst) => {
    const result = await materializeFile(src, dst, effectiveMode);
    if (result === 'copied' && opts.copyMode === 'auto' && effectiveMode === 'auto') {
      usedCopyFallback = true;
      effectiveMode = 'copy';
    }
    return result;
  });
  // Apply overlay shadows. We pass the bindSet down so the overlay walk can
  // refuse to write through a bind-mounted symlink — without this guard,
  // copying overlay/<bindPath>/foo would follow the symlink we just wrote
  // for that bindPath and silently mutate the real workspace, defeating the
  // staged-view isolation contract.
  await walkOverlay(opts.overlayRoot, opts.target, bindSet);
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
    // Materialization rules for `walkAndMaterialize`:
    //   - Entries whose path is in `bindPaths` (held in `bindSet`) are surfaced
    //     as symlinks pointing back into the live `cwd` (e.g. `node_modules`,
    //     `.git`) so validators see the workspace's existing state without
    //     paying the cost of a full copy.
    //   - Directories are walked recursively; intermediate dirs are created
    //     under `target` before descending.
    //   - Regular files are copied via `copyOne` (which dispatches to reflink
    //     or byte-copy depending on the configured `copyMode`).
    //   - Symlinks NOT listed in `bindPaths` are intentionally skipped
    //     (entry.isFile()/isDirectory() are both false for them); we do not
    //     follow them, to avoid escaping the workspace root.
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
    // Other dirent types (symlinks, sockets, block/character devices) are
    // intentionally skipped: a staged view is meant to mirror project source,
    // not arbitrary filesystem objects. Symlinks specifically are handled via
    // the explicit `bindPaths` opt-in above so the operator decides which
    // paths get bound (see materializeStagedView). Sources outside that list
    // are dropped to keep the staged view self-contained.
  }
}

async function walkOverlay(overlayRoot: string, target: string, bindSet: Set<string>): Promise<void> {
  // Overlay files are always copied via fs.copyFile (NOT materializeFile/reflink).
  // Rationale: overlays only ever hold the agent's edited bytes for the current
  // tx, which are small (handfuls of source files), and they are written to a
  // different filesystem region than cwd in practice (cliq home vs. workspace).
  // reflink across fs boundaries would just fall back to byte copy anyway, so
  // skipping the cp(1) probe avoids spawning a child process per file with no
  // payoff. Large binary overlays are out of scope for v0.8.
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
      if (overlapsBind(rel, bindSet)) {
        // bindPaths are materialized as symlinks pointing back into cwd, so a
        // copy under one would follow the symlink and write into the real
        // workspace. Refuse loudly — an overlay file under a bind-mounted
        // path is a contract violation by the caller (the writer/coordinator
        // should not have produced such a path) and silently dropping it
        // would mask data loss.
        throw new Error(
          `overlay path overlaps bind-mounted path: ${rel} (bindPaths must not also be staged via overlay)`
        );
      }
      if (entry.isDirectory()) {
        stack.push(rel);
        continue;
      }
      const overlayPath = path.join(overlayRoot, rel);
      const targetPath = path.join(target, rel);
      // Defensive: if any ancestor of targetPath is a symlink (a bindPath
      // pointing back into cwd), writing through it would land in the real
      // workspace and break staged-view isolation. WorkspaceWriter does not
      // emit overlay entries under bindPaths today, but the check guards
      // against future drift.
      if (await ancestorIsSymlink(target, rel)) {
        continue;
      }
      await fs.mkdir(path.dirname(targetPath), { recursive: true });
      await fs.copyFile(overlayPath, targetPath);
    }
  }
}

async function ancestorIsSymlink(root: string, rel: string): Promise<boolean> {
  const segments = rel.split(path.sep);
  // Walk root → root/seg0 → root/seg0/seg1 → ... up to but excluding the leaf.
  // If any intermediate is a symlink, the write path crosses into something
  // outside the staged-view target tree.
  let current = root;
  for (let i = 0; i < segments.length - 1; i++) {
    current = path.join(current, segments[i]);
    try {
      const stat = await fs.lstat(current);
      if (stat.isSymbolicLink()) return true;
    } catch {
      // ENOENT etc. — the ancestor doesn't exist yet, mkdir will create it
      // as a regular directory below; not a symlink, safe to proceed.
      return false;
    }
  }
  return false;
}

function overlapsBind(rel: string, bindSet: Set<string>): boolean {
  for (const bind of bindSet) {
    if (rel === bind) return true;
    if (rel.startsWith(`${bind}${path.sep}`)) return true;
  }
  return false;
}

export async function cleanupStagedView(target: string): Promise<void> {
  await fs.rm(target, { recursive: true, force: true });
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
