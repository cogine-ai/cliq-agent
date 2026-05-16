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
  /**
   * Set when the caller has already obtained an approval through the
   * PolicyEngine path (preset / decision table / user confirm / hook).
   * The transactional bash overlay then only enforces tx-specific
   * tightening on top of that decision, so `passthrough` and `confirm`
   * collapse to allow (no double prompt) and `deny` still wins.
   *
   * This is the bash-side of merging the historical dual-track surface
   * (PolicyMode + TxBashPolicy) into a single decision flow. See #62-A
   * commit "merge bash dual-track" for the rationale.
   *
   * Default `false` for backward compatibility with existing call sites
   * and tests; the runner-driven tool execute path always passes `true`.
   */
  policyAlreadyApproved?: boolean;
  confirm?: () => Promise<boolean>; // user prompt in interactive mode (legacy)
};

export async function enforceBashPolicy(opts: EnforceBashPolicyOptions): Promise<BashPolicyDecision> {
  // When tx mode is off, bash always passes through.
  if (opts.txMode === 'off') {
    return { decision: 'allow' };
  }

  // Tx-specific hard limits run regardless of the upstream PolicyEngine
  // decision: `deny` always wins so the tx overlay can refuse bash even
  // after the user said yes to PolicyEngine's prompt.
  if (opts.policy === 'deny') {
    return {
      decision: 'deny',
      code: 'tx-overlay-error',
      message: 'bashPolicy=deny rejects bash invocations under tx mode'
    };
  }

  // Headless + bashPolicy=confirm is an explicit CI safety net: even when the
  // upstream PolicyEngine has approved (e.g. via preset='auto' or a decision
  // table allow), the operator deliberately set bashPolicy=confirm so that
  // unattended runs can't execute bash. That guarantee must hold regardless
  // of policyAlreadyApproved.
  if (opts.policy === 'confirm' && opts.headless) {
    return {
      decision: 'deny',
      code: 'tx-overlay-error',
      message: 'bashPolicy=confirm cannot prompt in --headless mode; promoted to deny'
    };
  }

  if (opts.policyAlreadyApproved) {
    // Trust the upstream decision (preset / decision table / user / hook).
    // `passthrough` and `confirm` both collapse to allow here: passthrough
    // is "tx adds no extra friction beyond PolicyEngine", and confirm is
    // "PolicyEngine already prompted the user; don't ask twice". The
    // headless+confirm case is handled above so the CI safety net stays.
    //
    // TODO(#50, #46): once auto-validate/auto-approve wiring (#50) and the
    // overrides+reason pipeline (#46) land, the tx overlay can reuse the
    // override surface here so an approved tx can carry a per-command
    // reason instead of just collapsing to allow.
    return { decision: 'allow' };
  }

  switch (opts.policy) {
    case 'passthrough':
      return { decision: 'allow' };
    case 'confirm': {
      if (!opts.confirm) {
        // No confirm function provided in interactive mode → conservative deny.
        return {
          decision: 'deny',
          code: 'tx-overlay-error',
          message: 'bashPolicy=confirm requires an interactive prompt callback'
        };
      }
      // The prompt callback may throw (closed stdin, broken pipe, user-supplied
      // function bug). Convert any failure into a structured deny instead of
      // letting the exception escape and bypass the BashPolicyDecision contract.
      let confirmed = false;
      try {
        confirmed = await opts.confirm();
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          decision: 'deny',
          code: 'tx-overlay-error',
          message: `bashPolicy=confirm prompt failed: ${message}; promoted to deny`
        };
      }
      if (confirmed) return { decision: 'allow' };
      return {
        decision: 'deny',
        code: 'tx-overlay-error',
        message: 'bash invocation rejected by user'
      };
    }
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
