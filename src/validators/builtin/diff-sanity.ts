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
    const diff = JSON.parse(await fs.readFile(diffPath, 'utf8'));
    for (const entry of diff.files) {
      if (entry.op !== 'modify') {
        findings.push({ path: entry.path, message: `op=${entry.op} not allowed in v0.8` });
      }
      if (entry.path.includes('..') || path.isAbsolute(entry.path)) {
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
