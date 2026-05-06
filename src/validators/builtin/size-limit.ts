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
        const lineCount = content.split('\n').length;
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
