import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { Validator, Finding } from '../types.js';

const execFileAsync = promisify(execFile);

/**
 * Parses git's `--porcelain=v2 -z` output. Records are NUL-terminated;
 * rename/copy records carry an extra NUL-terminated origPath right after
 * the new path. We use `-z` instead of textual output to avoid C-quoting
 * ambiguities (paths with spaces, tabs, quotes, backslashes are all
 * unambiguous under -z).
 *
 * Record types we care about:
 *   1 <XY> ...8 fields... <path>            ordinary changed
 *   2 <XY> ...9 fields... <path>\0<origPath> renamed/copied
 *   u <xy> ...10 fields... <path>           unmerged (merge conflict)
 *
 * `XY` first char is `.` when the index is unchanged at this stage. Anything
 * else means the index is dirty for that path. Unmerged entries are always
 * a dirty-index condition; their `xy` field encodes conflict types.
 */
type StagedEntry = { path: string; xy: string; kind: 'ordinary' | 'rename' | 'unmerged' };

function parsePorcelainV2Z(output: string): StagedEntry[] {
  const entries: StagedEntry[] = [];
  // Buffer is a NUL-separated sequence of records. The TRAILING NUL after
  // the last record produces an empty final segment we want to skip.
  // For renamed records we consume an extra segment (origPath).
  const segments = output.split('\0');
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (!seg) continue;
    if (seg.startsWith('# ')) continue; // header lines (branch info)
    if (seg.startsWith('? ')) continue; // untracked (we run with -uno; defensive)
    if (seg.startsWith('! ')) continue; // ignored
    if (seg.startsWith('1 ')) {
      // ordinary: "1 XY sub mH mI mW hH hI path"
      const xy = seg.slice(2, 4);
      if (xy[0] === '.') continue;
      const path = nthFieldRest(seg, 8);
      if (path) entries.push({ path, xy, kind: 'ordinary' });
    } else if (seg.startsWith('2 ')) {
      // renamed/copied: "2 XY sub mH mI mW hH hI X-score path"
      // The next NUL-terminated segment is origPath; consume it so we don't
      // re-parse origPath as a record on the next iteration.
      const xy = seg.slice(2, 4);
      const path = nthFieldRest(seg, 9);
      i += 1; // skip origPath
      if (xy[0] === '.') continue;
      if (path) entries.push({ path, xy, kind: 'rename' });
    } else if (seg.startsWith('u ')) {
      // unmerged: "u xy sub m1 m2 m3 mW h1 h2 h3 path" — always dirty index
      const xy = seg.slice(2, 4);
      const path = nthFieldRest(seg, 10);
      if (path) entries.push({ path, xy, kind: 'unmerged' });
    }
    // unknown record types are ignored; new git versions may add some.
  }
  return entries;
}

/**
 * Returns the substring of `seg` after the Nth space-delimited field. The
 * path field is treated as the rest-of-line (it may itself contain spaces,
 * which `-z` allows because record separation is by NUL not space).
 */
function nthFieldRest(seg: string, n: number): string {
  let pos = 0;
  for (let f = 0; f < n; f++) {
    const idx = seg.indexOf(' ', pos);
    if (idx === -1) return '';
    pos = idx + 1;
  }
  return seg.slice(pos);
}

export const indexClean: Validator = {
  name: 'builtin:index-clean',
  defaultSeverity: 'blocking',
  async run(ctx) {
    const start = Date.now();
    let stdout: string;
    try {
      ({ stdout } = await execFileAsync(
        'git',
        ['status', '--porcelain=v2', '--renames', '-uno', '-z'],
        // Bound the git invocation: a hung pre-commit hook, a credential
        // prompt, or an LFS network call would otherwise block the entire
        // apply/abort pipeline because index-clean is a blocking validator.
        // On timeout, Node kills the child with ETIMEDOUT and we land in the
        // catch path with status='error', not a silent skip.
        { cwd: ctx.realCwd, timeout: 10_000 }
      ));
    } catch (err) {
      // Only "not a git repository" should skip the check. Other failures
      // (git missing, hung, killed, permission denied, hook crash, etc.)
      // must surface as `status: 'error'` so they do not silently bypass
      // a blocking validator.
      const stderr =
        typeof (err as { stderr?: unknown }).stderr === 'string'
          ? ((err as { stderr: string }).stderr)
          : err instanceof Error
            ? err.message
            : String(err);
      const notGitRepo = /not a git repository/i.test(stderr);
      if (notGitRepo) {
        return {
          name: 'builtin:index-clean',
          severity: 'blocking',
          status: 'pass',
          durationMs: Date.now() - start,
          message: 'not a git repository — index check skipped'
        };
      }
      return {
        name: 'builtin:index-clean',
        severity: 'blocking',
        status: 'error',
        durationMs: Date.now() - start,
        message: `git status failed: ${stderr.slice(0, 256)}`
      };
    }
    const findings: Finding[] = [];
    for (const entry of parsePorcelainV2Z(stdout)) {
      const message =
        entry.kind === 'rename'
          ? `staged rename: ${entry.xy}`
          : entry.kind === 'unmerged'
            ? `unmerged: ${entry.xy}`
            : `staged: ${entry.xy}`;
      findings.push({ path: entry.path, message });
    }
    return {
      name: 'builtin:index-clean',
      severity: 'blocking',
      status: findings.length === 0 ? 'pass' : 'fail',
      durationMs: Date.now() - start,
      findings: findings.length ? findings : undefined
    };
  }
};
