import { promises as fs } from 'node:fs';
import path from 'node:path';
import type { Validator } from '../types.js';
import { diffJsonPath, resolveTxRoot } from '../../workspace/transactions/store.js';
import { resolveCliqHome } from '../../session/store.js';

export const diffSanity: Validator = {
  name: 'builtin:diff-sanity',
  defaultSeverity: 'blocking',
  async run(ctx) {
    const start = Date.now();
    const findings: Array<{ path?: string; message: string }> = [];
    const root = resolveTxRoot(resolveCliqHome());
    const diffPath = diffJsonPath(root, ctx.txId);
    // Defensive parse: a missing, unreadable, or malformed diff.json must produce
    // a structured fail (not a TypeError/ENOENT that crashes the validator runner
    // and skips downstream validators). The runner converts thrown errors into
    // status='error' but keeping the failure self-typed as 'fail' surfaces the
    // diff problem in the validator-fail summary alongside other diff issues.
    let parsed: unknown;
    try {
      parsed = JSON.parse(await fs.readFile(diffPath, 'utf8'));
    } catch (err) {
      const errCode =
        err && typeof err === 'object' && 'code' in err
          ? String((err as { code: unknown }).code)
          : err instanceof SyntaxError
            ? 'invalid-json'
            : 'unknown';
      const message = err instanceof Error ? err.message : String(err);
      return {
        name: 'builtin:diff-sanity',
        severity: 'blocking',
        status: 'fail',
        durationMs: Date.now() - start,
        findings: [{ message: `invalid diff (${errCode}): ${message}` }]
      };
    }
    const files = (parsed as { files?: unknown })?.files;
    if (!Array.isArray(files)) {
      return {
        name: 'builtin:diff-sanity',
        severity: 'blocking',
        status: 'fail',
        durationMs: Date.now() - start,
        findings: [{ message: 'invalid diff: files must be an array' }]
      };
    }
    for (const rawEntry of files) {
      if (
        !rawEntry ||
        typeof rawEntry !== 'object' ||
        typeof (rawEntry as { path?: unknown }).path !== 'string' ||
        typeof (rawEntry as { op?: unknown }).op !== 'string'
      ) {
        findings.push({ message: 'invalid diff entry shape: missing string path or op' });
        continue;
      }
      const entry = rawEntry as { path: string; op: string; oldContent?: string; newContent?: string };
      if (entry.op !== 'modify') {
        findings.push({ path: entry.path, message: `op=${entry.op} not allowed in v0.8` });
      }
      // Check by path SEGMENTS, not substring: `entry.path.includes('..')`
      // would false-positive `foo..bar.ts`. We split on either separator and
      // look for an exact `..` segment, then catch absolute paths separately.
      const segments = entry.path.split(/[\\/]/);
      const hasParentSegment = segments.some((seg: string) => seg === '..');
      if (hasParentSegment || path.isAbsolute(entry.path)) {
        findings.push({ path: entry.path, message: 'path escapes workspace' });
      }
      const text = (entry.oldContent ?? '') + (entry.newContent ?? '');
      if (text.includes('\u0000')) {
        findings.push({ path: entry.path, message: 'binary content detected' });
      }
    }
    return {
      name: 'builtin:diff-sanity',
      severity: 'blocking',
      status: findings.length === 0 ? 'pass' : 'fail',
      durationMs: Date.now() - start,
      findings: findings.length ? findings : undefined
    };
  }
};
