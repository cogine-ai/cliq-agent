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
  confirm?: () => Promise<boolean>; // user prompt in interactive mode
};

export async function enforceBashPolicy(opts: EnforceBashPolicyOptions): Promise<BashPolicyDecision> {
  // When tx mode is off, bash always passes through.
  if (opts.txMode === 'off') {
    return { decision: 'allow' };
  }
  switch (opts.policy) {
    case 'passthrough':
      return { decision: 'allow' };
    case 'confirm':
      if (opts.headless) {
        return {
          decision: 'deny',
          code: 'tx-overlay-error',
          message: 'bashPolicy=confirm cannot prompt in --headless mode; promoted to deny'
        };
      }
      if (!opts.confirm) {
        // No confirm function provided in interactive mode → conservative deny.
        return {
          decision: 'deny',
          code: 'tx-overlay-error',
          message: 'bashPolicy=confirm requires an interactive prompt callback'
        };
      }
      const confirmed = await opts.confirm();
      if (confirmed) return { decision: 'allow' };
      return {
        decision: 'deny',
        code: 'tx-overlay-error',
        message: 'bash invocation rejected by user'
      };
    case 'deny':
      return {
        decision: 'deny',
        code: 'tx-overlay-error',
        message: 'bashPolicy=deny rejects bash invocations under tx mode'
      };
  }
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
  } catch {
    return;
  }
  for (const entry of entries) {
    if (ignore.has(entry.name)) continue;
    const rel = prefix ? path.join(prefix, entry.name) : entry.name;
    const abs = path.join(root, rel);
    if (entry.isDirectory()) {
      await walk(root, rel, out, ignore);
    } else if (entry.isFile()) {
      try {
        const stat = await fs.stat(abs);
        out.set(rel, stat.mtimeMs);
      } catch {
        // skip vanished entries
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
