import { promises as fs } from 'node:fs';
import type { Validator, Finding } from '../types.js';
import { diffJsonPath, resolveTxRoot } from '../../workspace/transactions/store.js';
import { resolveCliqHome } from '../../session/store.js';

export const DEFAULT_SIZE_LIMIT_LINES = 5000;

export function createSizeLimit(thresholdLines = DEFAULT_SIZE_LIMIT_LINES): Validator {
  return {
    name: 'builtin:size-limit',
    defaultSeverity: 'advisory',
    async run(ctx) {
      const start = Date.now();
      const findings: Finding[] = [];
      const root = resolveTxRoot(resolveCliqHome());
      const diff = JSON.parse(await fs.readFile(diffJsonPath(root, ctx.txId), 'utf8'));
      for (const entry of diff.files) {
        const content: string = entry.newContent ?? '';
        // Empty content has 0 lines (not 1). A trailing newline does not
        // create an empty extra line. `split('\n').length` would miscount
        // both edges: '' → 1, 'a\nb\n' → 3.
        const lineCount =
          content.length === 0
            ? 0
            : content.split(/\r?\n/).length - (content.endsWith('\n') ? 1 : 0);
        if (lineCount > thresholdLines) {
          findings.push({ path: entry.path, message: `${lineCount} lines exceeds ${thresholdLines}-line limit` });
        }
      }
      return {
        name: 'builtin:size-limit',
        severity: 'advisory',
        status: findings.length === 0 ? 'pass' : 'fail',
        durationMs: Date.now() - start,
        findings: findings.length ? findings : undefined
      };
    }
  };
}

export const sizeLimit = createSizeLimit();
