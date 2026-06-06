import { promises as fs, type Dirent } from 'node:fs';
import path from 'node:path';

import type { TxBashPolicy } from '../workspace/config.js';
import type { BashEffect } from '../workspace/transactions/types.js';

export type BashPolicyDecision =
  | { decision: 'allow' }
  | { decision: 'deny'; code: 'tx-overlay-error'; message: string };

export type EnforceBashPolicyOptions = {
  policy: TxBashPolicy;
  txMode: 'off' | 'edit';
  headless: boolean;
};

/**
 * Tx overlay for bash under edit-tx mode. PolicyEngine handles interactive
 * prompts; this layer only enforces tx-specific hard limits:
 *   - `deny` always wins
 *   - `confirm` promotes to deny under headless (CI safety net)
 *   - `passthrough` and interactive `confirm` allow (no second prompt)
 */
export async function enforceBashPolicy(opts: EnforceBashPolicyOptions): Promise<BashPolicyDecision> {
  if (opts.txMode === 'off') {
    return { decision: 'allow' };
  }

  if (opts.policy === 'deny') {
    return {
      decision: 'deny',
      code: 'tx-overlay-error',
      message: 'bashPolicy=deny rejects bash invocations under tx mode'
    };
  }

  if (opts.policy === 'confirm' && opts.headless) {
    return {
      decision: 'deny',
      code: 'tx-overlay-error',
      message: 'bashPolicy=confirm cannot prompt in --headless mode; promoted to deny'
    };
  }

  return { decision: 'allow' };
}

export type MtimeMap = Map<string, number>;

export async function snapshotMtimes(cwd: string, options: { ignore?: Set<string> } = {}): Promise<MtimeMap> {
  const ignore = options.ignore ?? new Set(['.git', 'node_modules']);
  const map: MtimeMap = new Map();
  await walk(cwd, '', map, ignore);
  return map;
}

async function walk(root: string, prefix: string, out: MtimeMap, ignore: Set<string>): Promise<void> {
  let entries: Dirent[];
  try {
    entries = (await fs.readdir(path.join(root, prefix), { withFileTypes: true })) as Dirent[];
  } catch (err) {
    // Only swallow ENOENT (directory disappeared between snapshot calls).
    // Permission, I/O, and other errors must surface so an incomplete snapshot
    // is never silently used as the "before" of a BashEffect diff.
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw err;
  }
  for (const entry of entries) {
    if (ignore.has(entry.name)) continue;
    const rel = prefix ? path.join(prefix, entry.name) : entry.name;
    const abs = path.join(root, rel);
    if (entry.isDirectory()) {
      await walk(root, rel, out, ignore);
    } else if (entry.isFile() || entry.isSymbolicLink()) {
      // Track symlinks via lstat so a bash command that adds, removes, or
      // retargets a symlink is detected as a path change. Without this,
      // `ln -sfn /new/target ./alias` would slip past mtime diffing because
      // symlinks aren't reported as files. Use lstat for symlinks and stat
      // for regular files so deref'd targets don't influence the timestamp.
      try {
        const st = entry.isSymbolicLink()
          ? await fs.lstat(abs)
          : await fs.stat(abs);
        out.set(rel, st.mtimeMs);
      } catch (err) {
        // Race-condition tolerance: a file that vanished between readdir and
        // stat is acceptable to skip. Other errors (EACCES, EIO, EMFILE)
        // must propagate.
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      }
    }
  }
}

export function diffMtimes(before: MtimeMap, after: MtimeMap): string[] {
  const changed = new Set<string>();
  for (const [p, mt] of after) {
    if (!before.has(p) || before.get(p) !== mt) {
      changed.add(p);
    }
  }
  for (const p of before.keys()) {
    if (!after.has(p)) {
      changed.add(p);
    }
  }
  return Array.from(changed).sort();
}

export function recordBashEffect(opts: {
  command: string;
  exitCode: number;
  pathsChanged: string[];
  ts?: string;
}): BashEffect {
  return {
    command: opts.command,
    exitCode: opts.exitCode,
    ts: opts.ts ?? new Date().toISOString(),
    pathsChanged: opts.pathsChanged,
    outOfBand: true
  };
}
