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
    } catch {
      return {
        name: 'builtin:index-clean',
        severity: 'blocking',
        status: 'pass',
        durationMs: Date.now() - start,
        message: 'not a git repository — index check skipped'
      };
    }
    const findings: Finding[] = [];
    for (const line of stdout.split('\n')) {
      if (!line) continue;
      if (line.startsWith('1 ')) {
        // 1 XY sub mH mI mW hH hI path
        const xy = line.slice(2, 4);
        if (xy[0] !== '.') {
          const fields = line.split(' ');
          const p = fields[fields.length - 1];
          findings.push({ path: p, message: `staged: ${xy}` });
        }
      } else if (line.startsWith('2 ')) {
        const xy = line.slice(2, 4);
        if (xy[0] !== '.') {
          const fields = line.split(' ');
          // For renames: ... origPath\tnewPath; the path field contains a tab
          const last = fields[fields.length - 1];
          findings.push({ path: last.split('\t')[0], message: `staged rename: ${xy}` });
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
