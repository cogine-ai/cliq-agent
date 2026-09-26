import { isDeepStrictEqual } from 'node:util';

import type { FrozenIgnoreRuleV1, FrozenIgnoreRulesV1 } from '../kernel/types.js';
import { mapArtifactReads } from './bounded-artifact-reads.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';

type IgnoreSource = FrozenIgnoreRulesV1['sources'][number];

export const MAX_FROZEN_IGNORE_SOURCE_BYTES = 4 * 1024 * 1024;

/** Git 2.45's trim_trailing_spaces treats a backslash and its next byte as
 * one literal unit. Only unescaped ASCII spaces at the end are removed. */
function trimTrailingSpaces(line: string): string {
  let firstTrailingSpace = -1;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === ' ') {
      if (firstTrailingSpace < 0) firstTrailingSpace = index;
    } else if (character === '\\') {
      index += 1;
      if (index === line.length) return line;
      firstTrailingSpace = -1;
    } else {
      firstTrailingSpace = -1;
    }
  }
  return firstTrailingSpace < 0 ? line : line.slice(0, firstTrailingSpace);
}

/** Parse Git 2.45 ignore-file lines into the immutable Kernel representation.
 * Wildmatch evaluation is a separate gate; this parser binds every retained
 * rule to its exact CAS-backed input line. */
export function parseFrozenIgnoreSourceBytes(
  bytes: Uint8Array,
  source: IgnoreSource,
  firstOrder = 0
): FrozenIgnoreRuleV1[] {
  if (bytes.byteLength > MAX_FROZEN_IGNORE_SOURCE_BYTES) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore source exceeds the byte ceiling');
  }
  if (bytes.includes(0)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore source contains NUL');
  }
  let text: string;
  try {
    // Keep the first BOM visible so exactly one is removed below, as in Git.
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore source is not UTF-8');
  }
  if (text.startsWith('\uFEFF')) text = text.slice(1);

  const rules: FrozenIgnoreRuleV1[] = [];
  for (const [index, rawLine] of text.split('\n').entries()) {
    // Git appends a synthetic newline to a file without one. It removes one
    // CR immediately before each newline, including that synthetic newline.
    const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;
    if (line === '' || line.startsWith('#')) continue;
    const trimmed = trimTrailingSpaces(line);
    const negated = trimmed.startsWith('!');
    let pattern = negated ? trimmed.slice(1) : trimmed;
    const directoryOnly = pattern.endsWith('/');
    if (directoryOnly) pattern = pattern.slice(0, -1);
    const anchored = pattern.includes('/');
    if (pattern.startsWith('/')) pattern = pattern.slice(1);
    // Git retains empty effective patterns internally, but they cannot match
    // any canonical nonempty workspace path and have no projection effect.
    if (pattern === '') continue;
    rules.push({
      order: firstOrder + rules.length,
      sourceIndex: source.index,
      sourceLine: index + 1,
      baseDirectory: source.baseDirectory,
      negated,
      directoryOnly,
      anchored,
      pattern
    });
  }
  return rules;
}

/** Reparse every retained raw source and require a byte-exact canonical rule
 * graph. This runs in admission and recovery before frozen rules are trusted. */
export async function validateFrozenIgnoreSourceBytes(
  artifacts: ArtifactCatalog,
  manifest: FrozenIgnoreRulesV1
): Promise<void> {
  const ruleSets = await mapArtifactReads(manifest.sources, async (source) =>
    parseFrozenIgnoreSourceBytes(await artifacts.readBytes(source.contentRef), source)
  );
  const parsed: FrozenIgnoreRuleV1[] = [];
  for (const sourceRules of ruleSets) {
    for (const rule of sourceRules) parsed.push({ ...rule, order: parsed.length });
  }
  if (!isDeepStrictEqual(parsed, manifest.rules)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore rules differ from retained source bytes');
  }
}
