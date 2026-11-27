// Closed immutable context data. A page/ref is never a Session index,
// authenticated compaction, Workspace Trust decision or execution authority.
import { canonicalJsonBytes } from './canonical.js';
import { assertArtifactRef, digestOmitting } from './identity.js';
import { assertBoundedJsonValue } from './json.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireText } from './control-wire-data.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { SessionContextProjection, SessionContextSegment } from './types.js';

export const SESSION_CONTEXT_PAGE_BYTES = 262_144;
export const SESSION_CONTEXT_PAGE_SEGMENTS = 64;
export const SESSION_CONTEXT_PAGE_RAW_ITEMS = 256;
export const SESSION_CONTEXT_PAGE_CHILDREN = 128;
export const SESSION_CONTEXT_TREE_HEIGHT = 7;

export type SessionContextPageEdge = Readonly<{ fromItemSeq: number; throughItemSeq: number; ref: string }>;
export type SessionContextLeafPage = Readonly<{
  schemaVersion: 1; format: 'cliq-session-context-page-v1'; kind: 'leaf'; height: 0;
  fromItemSeq: number; throughItemSeq: number; segments: readonly SessionContextSegment[];
}>;
export type SessionContextBranchPage = Readonly<{
  schemaVersion: 1; format: 'cliq-session-context-page-v1'; kind: 'branch'; height: number;
  fromItemSeq: number; throughItemSeq: number; children: readonly SessionContextPageEdge[];
}>;
export type SessionContextPage = SessionContextLeafPage | SessionContextBranchPage;
export type SessionContextProjectionV2 = Readonly<{
  schemaVersion: 2; format: 'cliq-session-context-v2'; sessionId: string;
  contextRevision: number; throughItemSeq: number; rootPageRef: string | null;
  pageHeight: number; projectionDigest: string;
}>;
export type SessionContextHead = SessionContextProjection | SessionContextProjectionV2;
const rawKinds = new Set(['run_terminal', 'legacy_record', 'legacy_compaction', 'legacy_plan', 'legacy_handoff', 'legacy_bookmark']);
function invalid(): never { throw new TypeError('Session context page is not a bounded contiguous closed graph'); }

/** The same segment semantics as v1. Unlike a whole Session, every v2 leaf
 * is explicitly bounded. Summary justification remains the StateOwner reader's
 * job; accepting this data alone can never manufacture a compaction. */
export function decodeSessionContextPageSegment(value: unknown): SessionContextSegment {
  assertControlWireJson(value);
  const kind = (value as { kind?: unknown } | null)?.kind;
  const data = controlWireRecord(value, kind === 'raw' ? ['kind', 'fromItemSeq', 'throughItemSeq', 'items'] :
    kind === 'summary' ? ['kind', 'fromItemSeq', 'throughItemSeq', 'compactionItemId', 'summaryRef', 'summaryDigest', 'sourceItemsDigest', 'retainedItemIds'] :
      ['kind', 'fromItemSeq', 'throughItemSeq', 'sourceItemsDigest']);
  if (!['raw', 'summary', 'excluded_control'].includes(kind as string)) invalid();
  const from = controlWireInteger(data.fromItemSeq, 1), through = controlWireInteger(data.throughItemSeq, from);
  if (kind === 'raw') {
    if (!Array.isArray(data.items) || data.items.length > SESSION_CONTEXT_PAGE_RAW_ITEMS || data.items.length !== through - from + 1) invalid();
    for (const [index, raw] of data.items.entries()) {
      const item = controlWireRecord(raw, ['sourceSessionId', 'itemSeq', 'itemId', 'kind', 'payloadRef']);
      controlWireText(item.sourceSessionId); controlWireText(item.itemId); assertArtifactRef(item.payloadRef as string);
      if (item.itemSeq !== from + index || !rawKinds.has(item.kind as string)) invalid();
    }
  } else {
    assertArtifactRef(data.sourceItemsDigest as string);
    if (kind === 'summary') {
      controlWireText(data.compactionItemId); assertArtifactRef(data.summaryRef as string); assertArtifactRef(data.summaryDigest as string);
      if (!Array.isArray(data.retainedItemIds) || data.retainedItemIds.length > 256 ||
          new Set(data.retainedItemIds).size !== data.retainedItemIds.length) invalid();
      data.retainedItemIds.forEach(id => controlWireText(id));
    }
  }
  return immutableSnapshot(data) as SessionContextSegment;
}
function bounded(value: unknown): void {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'Session context page');
  if (canonicalJsonBytes(value).length > SESSION_CONTEXT_PAGE_BYTES) invalid();
}
export function decodeSessionContextPage(value: unknown): SessionContextPage {
  bounded(value);
  const kind = (value as { kind?: unknown } | null)?.kind;
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'kind', 'height', 'fromItemSeq', 'throughItemSeq', kind === 'leaf' ? 'segments' : 'children']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-session-context-page-v1' || !['leaf', 'branch'].includes(kind as string)) invalid();
  const height = controlWireInteger(data.height, 0, SESSION_CONTEXT_TREE_HEIGHT);
  const from = controlWireInteger(data.fromItemSeq, 1), through = controlWireInteger(data.throughItemSeq, from);
  let next = from;
  if (kind === 'leaf') {
    if (height !== 0 || !Array.isArray(data.segments) || !data.segments.length || data.segments.length > SESSION_CONTEXT_PAGE_SEGMENTS) invalid();
    let rawItems = 0;
    for (const value of data.segments) {
      const segment = decodeSessionContextPageSegment(value);
      if (segment.fromItemSeq !== next) invalid(); next = segment.throughItemSeq + 1;
      if (segment.kind === 'raw') rawItems += segment.items.length;
    }
    if (rawItems > SESSION_CONTEXT_PAGE_RAW_ITEMS) invalid();
  } else {
    if (height === 0 || !Array.isArray(data.children) || !data.children.length || data.children.length > SESSION_CONTEXT_PAGE_CHILDREN) invalid();
    for (const value of data.children) {
      const edge = controlWireRecord(value, ['fromItemSeq', 'throughItemSeq', 'ref']);
      if (edge.fromItemSeq !== next) invalid();
      next = controlWireInteger(edge.throughItemSeq, next) + 1; assertArtifactRef(edge.ref as string);
    }
  }
  if (next - 1 !== through) invalid();
  return immutableSnapshot(data) as SessionContextPage;
}
export function decodeSessionContextHeadV2(value: unknown): SessionContextProjectionV2 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'sessionId', 'contextRevision', 'throughItemSeq',
    'rootPageRef', 'pageHeight', 'projectionDigest']);
  if (data.schemaVersion !== 2 || data.format !== 'cliq-session-context-v2') invalid();
  controlWireText(data.sessionId); controlWireInteger(data.contextRevision, 1);
  const through = controlWireInteger(data.throughItemSeq);
  const height = controlWireInteger(data.pageHeight, 0, SESSION_CONTEXT_TREE_HEIGHT);
  if (through === 0 ? data.rootPageRef !== null || height !== 0 : typeof data.rootPageRef !== 'string') invalid();
  if (data.rootPageRef !== null) assertArtifactRef(data.rootPageRef as string);
  assertArtifactRef(data.projectionDigest as string);
  if (digestOmitting(data, 'projectionDigest') !== data.projectionDigest) invalid();
  return immutableSnapshot(data) as SessionContextProjectionV2;
}
