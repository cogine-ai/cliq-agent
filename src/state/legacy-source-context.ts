// Pure fixed source projection. The original native source/backup lifecycle
// and actual Owner transaction independently authenticate and commit it.
import { canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import { assertArtifactRef, parseCanonicalTime, normalizeAbsolutePath } from '../kernel/identity.js';
import { assertControlWireJson, controlWireRecord, controlWireText } from '../kernel/control-wire-data.js';
import { decodeLegacyContextPayload, legacySessionItemId, type LegacyContextPayloadV1 } from '../kernel/legacy-context.js';
import type { LegacySessionSourceItem } from './legacy-source-stream.js';

type SourceRecord = Record<string, unknown>;
export type ImportedLegacySessionMetadata = Readonly<{ legacySessionId: string; legacyWorkspacePath: string;
  legacyWorkspaceDisplayPath: string;
  createdAt: string; originalUpdatedAt: string; updatedAt: string; name?: string }>;
export type ProjectedLegacyItem = Readonly<{ payload: Readonly<LegacyContextPayloadV1>; itemId: string;
  payloadRef: string; createdAt: string }>;
function invalid(): never { throw new TypeError('legacy source differs from its fixed nonexecution context profile'); }
function text(value: unknown): string { if (typeof value !== 'string') return invalid(); return normalizeCanonicalText(value); }
function record(value: unknown): SourceRecord {
  assertControlWireJson(value);
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid();
  return value as SourceRecord;
}
function sourceSessionId(path: string): string {
  const match = /^sessions\/[0-9]{4}\/[0-9]{2}\/[0-9]{2}\/([A-Za-z0-9_-]{1,128})\.json$/u.exec(path);
  if (!match) invalid(); return match[1]!;
}

/** The new Kernel index append is prepared at real staging time T (possibly
 * original P0). The final receipt samples its distinct P only after the whole
 * candidate verifies, so C >= P >= T; a sealed preview is never rewritten to P.
 * Historical dates stay in the
 * payload; an old fork's copied records must not pretend to have been appended
 * to its new Kernel child before that Session existed. P is data here, never a
 * clock/owner grant; the original transaction later samples actual C >= T. */
export function projectLegacySessionItem(input: Readonly<{ sourcePath: string; item: LegacySessionSourceItem;
  publicationPreparedAt: string }>): ProjectedLegacyItem {
  const legacySessionId = sourceSessionId(input.sourcePath), data = record(input.item.value);
  parseCanonicalTime(input.publicationPreparedAt);
  let content: Record<string, unknown>, schema: 'record-v1' | 'compaction-v1' | 'bookmark-v1';
  if (input.item.kind === 'legacy_record') {
    const role = data.kind === 'assistant' ? 'assistant' : data.kind === 'system' ? 'system' : 'user';
    if (data.role !== role) invalid();
    content = { recordId: text(data.id), recordedAt: data.ts, recordKind: data.kind, contentUtf8: text(data.content),
      ...(data.kind === 'tool' ? { toolName: text(data.tool), toolStatus: data.status } : {}) };
    schema = 'record-v1';
  } else if (input.item.kind === 'legacy_compaction') {
    const range = record(data.coveredRange);
    content = { compactionId: text(data.id), createdAt: data.createdAt, status: data.status,
      coveredRange: { startIndexInclusive: range.startIndexInclusive, endIndexExclusive: range.endIndexExclusive },
      firstKeptRecordId: text(data.firstKeptRecordId), summaryMarkdown: text(data.summaryMarkdown) };
    schema = 'compaction-v1';
  } else if (input.item.kind === 'legacy_bookmark') {
    content = { bookmarkId: text(data.id), createdAt: data.createdAt, legacyKind: data.kind,
      recordIndex: data.recordIndex, turn: data.turn, ...(Object.hasOwn(data, 'name') ? { name: text(data.name) } : {}) };
    schema = 'bookmark-v1';
  } else return invalid();
  const core = { schemaVersion: 1, format: 'cliq-legacy-portable-payload-v1', kind: input.item.kind,
    legacySessionId, sourceSchemaId: schema, sourceOrdinal: input.item.ordinal,
    sourceCanonicalRootRelativePath: input.sourcePath, content };
  const payload = decodeLegacyContextPayload({ ...core, payloadDigest: canonicalSha256(core) });
  return Object.freeze({ payload, itemId: legacySessionItemId(payload), payloadRef: canonicalSha256(payload),
    createdAt: input.publicationPreparedAt });
}

export function projectLegacySessionMetadata(sourcePath: string, value: unknown,
  publicationPreparedAt: string): ImportedLegacySessionMetadata {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['version', 'app', 'cwd', 'createdAt', 'updatedAt'], ['id', 'name']);
  const legacySessionId = sourceSessionId(sourcePath);
  if (typeof data.version !== 'number' || !Number.isSafeInteger(data.version) || data.version < 1 || data.version > 5 ||
      data.app !== 'cliq' || data.id !== undefined && data.id !== legacySessionId) invalid();
  if (typeof data.cwd !== 'string' || Buffer.byteLength(data.cwd) > 4096) return invalid();
  const workspace = data.cwd, workspaceDisplay = controlWireText(text(workspace), 4096);
  const createdAt = controlWireText(data.createdAt), originalUpdatedAt = controlWireText(data.updatedAt);
  const created = parseCanonicalTime(createdAt), updated = parseCanonicalTime(originalUpdatedAt), prepared = parseCanonicalTime(publicationPreparedAt);
  if (created > updated || updated > prepared) invalid();
  const name = data.name === undefined ? undefined : controlWireText(text(data.name), 256, 0);
  return Object.freeze({ legacySessionId, legacyWorkspacePath: workspace, legacyWorkspaceDisplayPath: workspaceDisplay, createdAt, originalUpdatedAt,
    updatedAt: publicationPreparedAt, ...(name ? { name } : {}) });
}

/** Eligibility only, never a workspace identity/Trust decision. Linux can
 * contain distinct NFD and NFC directory objects; a canonical display path may
 * not be substituted for the original lookup bytes. An unrepresentable source
 * uses only legacy_unavailable display, or is refused if that display itself
 * cannot satisfy the existing closed platform locator contract. */
export function legacyWorkspaceLookupPath(metadata: ImportedLegacySessionMetadata): string | undefined {
  if (metadata.legacyWorkspacePath !== metadata.legacyWorkspaceDisplayPath) return undefined;
  try { return normalizeAbsolutePath(metadata.legacyWorkspacePath) === metadata.legacyWorkspacePath ? metadata.legacyWorkspacePath : undefined; }
  catch (error) { if (error instanceof TypeError) return undefined; throw error; }
}

/** Complete canonical payload bytes remain the identity. A descriptor label or
 * admission field supplied by a caller cannot turn this result into authority. */
export function assertProjectedLegacyItem(value: ProjectedLegacyItem): void {
  const payload = decodeLegacyContextPayload(value.payload);
  assertArtifactRef(value.payloadRef);
  if (value.payloadRef !== canonicalSha256(payload) || value.itemId !== legacySessionItemId(payload)) invalid();
  parseCanonicalTime(value.createdAt);
}
