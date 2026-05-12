import { promises as fs } from 'node:fs';
import path from 'node:path';

import { readBashEffects } from './bash-effects.js';
import { summarizeDiff } from './diff.js';
import { readAudit, readDiff, readTxState, validatorsDir } from './store.js';
import { validatorSummaryFromResults } from './types.js';
import type {
  AuditEntry,
  BashEffect,
  Diff,
  DiffEntry,
  DiffSummary,
  Transaction,
  ValidatorResultSummary
} from './types.js';
import type { ValidatorResult as FullValidatorResult } from '../../validators/types.js';

export type TxReviewSnapshot = {
  tx: Transaction;
  diff: Diff | null;
  audit: AuditEntry[];
  bashEffects: BashEffect[];
  validatorResults: ValidatorResultSummary[];
  validatorArtifactResults: FullValidatorResult[];
  validatorArtifactErrors: string[];
  artifactRef: string;
};

export async function readTxReviewSnapshot(opts: {
  root: string;
  txId: string;
}): Promise<TxReviewSnapshot> {
  const tx = await readTxState(opts.root, opts.txId);
  if (!tx) throw new Error(`tx not found: ${opts.txId}`);

  const [diff, audit, bashEffects, validatorArtifacts] = await Promise.all([
    readDiff(opts.root, opts.txId),
    readAudit(opts.root, opts.txId),
    readBashEffects(opts.root, opts.txId),
    readValidatorArtifacts(opts.root, opts.txId)
  ]);

  return {
    tx,
    diff,
    audit,
    bashEffects,
    validatorResults: tx.validators ?? [],
    validatorArtifactResults: validatorArtifacts.results,
    validatorArtifactErrors: validatorArtifacts.errors,
    artifactRef: `tx/${opts.txId}/`
  };
}

export function formatTxDiff(snapshot: TxReviewSnapshot): string {
  const files = snapshot.diff?.files ?? [];
  if (files.length === 0) return 'No staged file changes.';
  return files.map(formatDiffEntry).join('\n');
}

export function formatTxShow(snapshot: TxReviewSnapshot): string {
  const summary = getDiffSummary(snapshot);
  const lines = [
    `tx: ${snapshot.tx.id}`,
    `state: ${snapshot.tx.state}`,
    `workspace: ${snapshot.tx.workspaceId}`,
    `session: ${snapshot.tx.sessionId}`,
    `created: ${snapshot.tx.createdAt}`,
    `updated: ${snapshot.tx.updatedAt}`,
    `diff: ${formatDiffSummary(summary)}`,
    `validators: ${formatValidatorSummary(snapshot.validatorResults)}`,
    `bash effects: ${snapshot.bashEffects.length}`,
    `artifact: ${snapshot.artifactRef}`
  ];
  if (snapshot.validatorArtifactErrors.length > 0) {
    lines.push(`validator artifact errors: ${snapshot.validatorArtifactErrors.join('; ')}`);
  }
  return lines.join('\n');
}

export function formatTxValidators(snapshot: TxReviewSnapshot): string {
  const validators = snapshot.validatorResults;
  const lines = validators.map((v) =>
    `${v.status.toUpperCase()} ${v.severity} ${v.name} ${v.durationMs}ms`
  );
  for (const error of snapshot.validatorArtifactErrors) {
    lines.push(`ERROR artifact ${error}`);
  }
  return lines.length > 0 ? lines.join('\n') : 'No validators recorded.';
}

export function formatTxApplyReview(snapshot: TxReviewSnapshot): string {
  const summary = getDiffSummary(snapshot);
  const blockingFailures = snapshot.tx.blockingFailures ?? [];
  const lines = [
    `Transaction ${snapshot.tx.id} is ready to apply.`,
    '',
    `Files changed: ${summary.filesChanged} (+${summary.additions}/-${summary.deletions})`,
    `Validators: ${formatValidatorSummary(snapshot.validatorResults)}`,
    `Blocking failures: ${blockingFailures.length > 0 ? blockingFailures.join(', ') : 'none'}`,
    `Bash effects: ${snapshot.bashEffects.length}`,
    `Artifact: ${snapshot.artifactRef}`
  ];

  if (snapshot.bashEffects.length > 0) {
    lines.push('', 'Bash effects:');
    for (const effect of snapshot.bashEffects) {
      const paths = effect.pathsChanged.length > 0 ? ` [${effect.pathsChanged.join(', ')}]` : '';
      lines.push(`- ${effect.command} (exit ${effect.exitCode})${paths}`);
    }
  }

  if (snapshot.validatorArtifactErrors.length > 0) {
    lines.push('', 'Validator artifact errors:');
    for (const error of snapshot.validatorArtifactErrors) lines.push(`- ${error}`);
  }

  return lines.join('\n');
}

async function readValidatorArtifacts(
  root: string,
  txId: string
): Promise<{ results: FullValidatorResult[]; errors: string[] }> {
  let filenames: string[];
  try {
    filenames = await fs.readdir(validatorsDir(root, txId));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { results: [], errors: [] };
    throw err;
  }

  const results: FullValidatorResult[] = [];
  const errors: string[] = [];
  for (const filename of filenames.filter((name) => name.endsWith('.json')).sort()) {
    const fullPath = path.join(validatorsDir(root, txId), filename);
    let raw: string;
    try {
      raw = await fs.readFile(fullPath, 'utf8');
      results.push(JSON.parse(raw) as FullValidatorResult);
    } catch (err) {
      if (err instanceof SyntaxError) {
        errors.push(`${filename}: invalid JSON`);
      } else {
        throw err;
      }
    }
  }
  return { results, errors };
}

function formatDiffEntry(entry: DiffEntry): string {
  if (entry.op === 'create') return `A ${entry.path} (+${countLines(entry.newContent)}/-0)`;
  if (entry.op === 'delete') return `D ${entry.path} (+0/-${countLines(entry.oldContent)})`;
  // Match summarizeDiff's coarse line-count delta. This is intentionally not
  // an LCS diff, so replacements can show as net +0/-0.
  const oldLines = countLines(entry.oldContent);
  const newLines = countLines(entry.newContent);
  return `M ${entry.path} (net +${Math.max(0, newLines - oldLines)}/-${Math.max(0, oldLines - newLines)})`;
}

function countLines(value: string): number {
  if (value.length === 0) return 0;
  const lines = value.endsWith('\n') ? value.slice(0, -1) : value;
  if (lines.length === 0) return 0;
  return lines.split('\n').length;
}

function getDiffSummary(snapshot: TxReviewSnapshot): DiffSummary {
  return snapshot.tx.diffSummary ?? (snapshot.diff ? summarizeDiff(snapshot.diff) : emptyDiffSummary());
}

function emptyDiffSummary(): DiffSummary {
  return {
    filesChanged: 0,
    additions: 0,
    deletions: 0,
    creates: [],
    modifies: [],
    deletes: []
  };
}

function formatDiffSummary(summary: DiffSummary): string {
  return `${summary.filesChanged} files changed (net +${summary.additions}/-${summary.deletions})`;
}

function formatValidatorSummary(validators: ValidatorResultSummary[]): string {
  const summary = validatorSummaryFromResults(validators);
  return `blocking ${summary.blocking.pass} pass / ${summary.blocking.fail} fail, advisory ${summary.advisory.pass} pass / ${summary.advisory.fail} fail`;
}
