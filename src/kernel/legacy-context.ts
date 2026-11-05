// Finite context data only. These values never restore a legacy execution
// role, tool call, plan approval, skill, permission or recovery checkpoint.
import { canonicalJsonBytes } from './canonical.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from './identity.js';
import { assertBoundedJsonValue } from './json.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireText } from './control-wire-data.js';
import { immutableSnapshot } from '../model/immutable.js';

export const LEGACY_SESSION_CONTEXT_KINDS = ['legacy_record', 'legacy_compaction', 'legacy_plan', 'legacy_handoff', 'legacy_bookmark'] as const;
export type LegacySessionContextKind = typeof LEGACY_SESSION_CONTEXT_KINDS[number];

/** Exact portable payload envelope from the migration contract. Its content
 * receives the fixed, narrower context projection below before consumption.
 * A payload is data; only its original committed Session index is authority. */
export type LegacyPortablePayloadV1 = Readonly<{
  schemaVersion: 1;
  format: 'cliq-legacy-portable-payload-v1';
  kind: LegacySessionContextKind;
  legacySessionId: string;
  sourceSchemaId: 'session-v1' | 'session-v2' | 'record-v1' | 'compaction-v1' | 'plan-v1' | 'handoff-v1' | 'bookmark-v1';
  sourceOrdinal: number;
  sourceCanonicalRootRelativePath: string;
  content: null | boolean | number | string | unknown[] | Record<string, unknown>;
  payloadDigest: string;
}>;

type LegacyRecordContent = Readonly<{
  recordId: string; recordedAt: string;
  recordKind: 'system' | 'user' | 'assistant' | 'tool' | 'tx-opened' | 'tx-applied' | 'tx-aborted';
  contentUtf8: string;
  toolName?: string; toolStatus?: 'ok' | 'error';
}>;
type LegacyCompactionContent = Readonly<{
  compactionId: string; createdAt: string; status: 'active' | 'superseded';
  coveredRange: Readonly<{ startIndexInclusive: number; endIndexExclusive: number }>;
  firstKeptRecordId: string; summaryMarkdown: string;
}>;
type LegacyPlanContent = Readonly<{
  planId: string; title: string; contentMarkdown: string;
  status: 'draft' | 'finalized' | 'approved' | 'rejected' | 'canceled';
  items: readonly Readonly<{ id: string; title: string; status: 'pending' | 'in_progress' | 'completed'; notes?: string }>[];
}>;
type LegacyHandoffContent = Readonly<{
  handoffId: string; createdAt: string;
  summarySource: 'active-compaction' | 'handoff-only'; summaryMarkdown: string;
}>;
type LegacyBookmarkContent = Readonly<{
  bookmarkId: string; name?: string; createdAt: string;
  legacyKind: 'auto' | 'manual' | 'restore-safety' | 'handoff'; recordIndex: number; turn: number;
}>;
type LegacyContextContents = {
  legacy_record: LegacyRecordContent;
  legacy_compaction: LegacyCompactionContent;
  legacy_plan: LegacyPlanContent;
  legacy_handoff: LegacyHandoffContent;
  legacy_bookmark: LegacyBookmarkContent;
};
export type LegacyContextPayloadV1 = {
  [Kind in LegacySessionContextKind]: Omit<LegacyPortablePayloadV1, 'kind' | 'content'> &
    Readonly<{ kind: Kind; content: LegacyContextContents[Kind] }>
}[LegacySessionContextKind];

const sourceSchema = {
  legacy_record: 'record-v1', legacy_compaction: 'compaction-v1', legacy_plan: 'plan-v1',
  legacy_handoff: 'handoff-v1', legacy_bookmark: 'bookmark-v1',
} as const;
const TEXT_BYTES = 262_144;
function invalid(): never { throw new TypeError('legacy context payload differs from its closed non-execution projection'); }
export function isLegacySessionContextKind(value: unknown): value is LegacySessionContextKind {
  return typeof value === 'string' && (LEGACY_SESSION_CONTEXT_KINDS as readonly string[]).includes(value);
}
function text(value: unknown, maximum = TEXT_BYTES, minimum = 0): void { controlWireText(value, maximum, minimum); }
function time(value: unknown): void {
  if (typeof value !== 'string') invalid();
  parseCanonicalTime(value);
}
function relativePath(value: unknown): void {
  const path = controlWireText(value, 4096);
  if (path.startsWith('/') || path.includes('\\') || path.includes('\0') || path.split('/').some(part =>
    part === '' || part === '.' || part === '..' || Buffer.byteLength(part) > 255)) invalid();
  // Authentication is inventoried only through its separate secret-free
  // source observation. It can never masquerade as a context source file.
  if (path === 'auth.json' || path.endsWith('/auth.json')) invalid();
}
function content(kind: LegacySessionContextKind, value: unknown): void {
  if (kind === 'legacy_record') {
    const data = controlWireRecord(value, ['recordId', 'recordedAt', 'recordKind', 'contentUtf8'], ['toolName', 'toolStatus']);
    controlWireText(data.recordId); time(data.recordedAt); text(data.contentUtf8);
    if (!['system', 'user', 'assistant', 'tool', 'tx-opened', 'tx-applied', 'tx-aborted'].includes(data.recordKind as string)) invalid();
    if (data.recordKind === 'tool') {
      controlWireText(data.toolName); if (!['ok', 'error'].includes(data.toolStatus as string)) invalid();
    } else if (Object.hasOwn(data, 'toolName') || Object.hasOwn(data, 'toolStatus')) invalid();
  } else if (kind === 'legacy_compaction') {
    const data = controlWireRecord(value, ['compactionId', 'createdAt', 'status', 'coveredRange', 'firstKeptRecordId', 'summaryMarkdown']);
    controlWireText(data.compactionId); time(data.createdAt); controlWireText(data.firstKeptRecordId); text(data.summaryMarkdown);
    if (!['active', 'superseded'].includes(data.status as string)) invalid();
    const range = controlWireRecord(data.coveredRange, ['startIndexInclusive', 'endIndexExclusive']);
    const start = controlWireInteger(range.startIndexInclusive); controlWireInteger(range.endIndexExclusive, start + 1);
  } else if (kind === 'legacy_plan') {
    const data = controlWireRecord(value, ['planId', 'title', 'contentMarkdown', 'status', 'items']);
    controlWireText(data.planId); text(data.title, 256); text(data.contentMarkdown);
    if (!['draft', 'finalized', 'approved', 'rejected', 'canceled'].includes(data.status as string) || !Array.isArray(data.items)) invalid();
    const seen = new Set<string>();
    for (const raw of data.items) {
      const item = controlWireRecord(raw, ['id', 'title', 'status'], ['notes']);
      const id = controlWireText(item.id); text(item.title, 4096);
      if (seen.has(id) || !['pending', 'in_progress', 'completed'].includes(item.status as string)) invalid();
      seen.add(id); if (Object.hasOwn(item, 'notes')) text(item.notes);
    }
  } else if (kind === 'legacy_handoff') {
    const data = controlWireRecord(value, ['handoffId', 'createdAt', 'summarySource', 'summaryMarkdown']);
    controlWireText(data.handoffId); time(data.createdAt); text(data.summaryMarkdown);
    if (!['active-compaction', 'handoff-only'].includes(data.summarySource as string)) invalid();
  } else {
    const data = controlWireRecord(value, ['bookmarkId', 'createdAt', 'legacyKind', 'recordIndex', 'turn'], ['name']);
    controlWireText(data.bookmarkId); time(data.createdAt); controlWireInteger(data.recordIndex); controlWireInteger(data.turn);
    if (!['auto', 'manual', 'restore-safety', 'handoff'].includes(data.legacyKind as string)) invalid();
    if (Object.hasOwn(data, 'name')) text(data.name, 256);
  }
}

export function decodeLegacyContextPayload(value: unknown): Readonly<LegacyContextPayloadV1> {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'legacy context payload');
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'kind', 'legacySessionId', 'sourceSchemaId',
    'sourceOrdinal', 'sourceCanonicalRootRelativePath', 'content', 'payloadDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-legacy-portable-payload-v1' || !isLegacySessionContextKind(data.kind)) invalid();
  controlWireText(data.legacySessionId); controlWireInteger(data.sourceOrdinal); relativePath(data.sourceCanonicalRootRelativePath);
  if (data.sourceSchemaId !== sourceSchema[data.kind]) invalid();
  assertArtifactRef(data.payloadDigest as string);
  if (digestOmitting(data, 'payloadDigest') !== data.payloadDigest || canonicalJsonBytes(data).byteLength > 1_048_576) invalid();
  content(data.kind, data.content);
  return immutableSnapshot(data) as Readonly<LegacyContextPayloadV1>;
}

/** Stable data identity for the importer's immutable Session index. It is
 * never an admission id, grant, invocation id or proof of an actual import. */
export function legacySessionItemId(payload: Readonly<LegacyContextPayloadV1>): string {
  return identityHash('cliq-legacy-session-item-v1', payload.legacySessionId, payload.kind, payload.sourceOrdinal, payload.payloadDigest);
}

/** Only this explicit visible projection reaches model/summary/handoff prose.
 * Source paths, auth/config fields, active actions and recovery coordinates do
 * not belong to any accepted content shape. Literal user prose stays data. */
export function legacyContextVisibleText(payload: Readonly<LegacyContextPayloadV1>): string {
  return canonicalJsonBytes({ format: 'cliq-legacy-context-prompt-v1', kind: payload.kind, content: payload.content }).toString('utf8');
}
