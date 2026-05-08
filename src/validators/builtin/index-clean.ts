import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { Validator, Finding } from '../types.js';

const execFileAsync = promisify(execFile);

export const indexClean: Validator = {
  name: 'builtin:index-clean',
  defaultSeverity: 'blocking',
  async run(ctx) {
    const start = Date.now();
    let stdout: string;
    try {
      ({ stdout } = await execFileAsync('git', ['status', '--porcelain=v2', '--renames', '-uno'], { cwd: ctx.realCwd }));
    } catch (err) {
      const e = err as NodeJS.ErrnoException & { stderr?: string | Buffer };
      const stderr = (e.stderr ?? '').toString();
      const isNotRepo = /not a git repository/i.test(stderr) || /not a git repository/i.test(e.message ?? '');
      if (isNotRepo) {
        return {
          name: 'builtin:index-clean',
          severity: 'blocking',
          status: 'pass',
          durationMs: Date.now() - start,
          message: 'not a git repository — index check skipped'
        };
      }
      // Real failure (git binary missing, permission denied, corrupted repo, etc.).
      // Surface it as a blocking failure so the operator can investigate rather
      // than silently masking it as a "skipped" pass.
      return {
        name: 'builtin:index-clean',
        severity: 'blocking',
        status: 'fail',
        durationMs: Date.now() - start,
        message: `git status failed: ${e.message ?? String(err)}${stderr ? ` (stderr: ${stderr.trim()})` : ''}`
      };
    }
    const findings: Finding[] = [];
    for (const line of stdout.split('\n')) {
      if (!line) continue;
      if (line.startsWith('1 ')) {
        // Porcelain v2: `1 XY sub mH mI mW hH hI path`. Path is the trailing
        // field and may contain spaces, so we count the eight whitespace
        // separators rather than splitting and taking the tail.
        const xy = line.slice(2, 4);
        if (xy[0] !== '.') {
          const idx = nthSpaceIndex(line, 8);
          if (idx === -1) continue;
          const p = line.slice(idx + 1);
          findings.push({ path: p, message: `staged: ${xy}` });
        }
      } else if (line.startsWith('2 ')) {
        // Porcelain v2 rename/copy: `2 XY sub mH mI mW hH hI X<score> path\torigPath`.
        // Nine whitespace separators precede the path; the path itself may
        // contain spaces, and `\t` separates the new path from the original.
        const xy = line.slice(2, 4);
        if (xy[0] !== '.') {
          const idx = nthSpaceIndex(line, 9);
          if (idx === -1) continue;
          const tail = line.slice(idx + 1);
          const newPath = tail.split('\t')[0];
          findings.push({ path: newPath, message: `staged rename: ${xy}` });
        }
      }
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

function nthSpaceIndex(s: string, n: number): number {
  let count = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === ' ') {
      count++;
      if (count === n) return i;
    }
  }
  return -1;
}
