// Shared deterministic Session revision algorithms. Existing request/Owner/
// frame/unique-transaction authority remains in session-continuity.ts.
import { createHash } from 'node:crypto';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { SESSION_CONTEXT_PAGE_RAW_ITEMS, type SessionContextHead } from '../kernel/session-context-pages.js';
import { walkSessionContextSegments, type SessionContextPageReader } from '../kernel/session-context-page-reader.js';
import type { SessionContextSegment } from '../kernel/types.js';
import type { SessionCompactionItem } from '../kernel/session-continuity.js';
import type { ArtifactCatalog } from './artifacts.js';
import { publishSessionContextGraph } from './session-context-graph.js';

function invalid(): never { throw new TypeError('Session revision requires exact whole raw segment boundaries'); }
function* bounded(segment: SessionContextSegment): IterableIterator<SessionContextSegment> {
  if (segment.kind !== 'raw') { yield segment; return; }
  for (let offset = 0; offset < segment.items.length; offset += SESSION_CONTEXT_PAGE_RAW_ITEMS) {
    const items = segment.items.slice(offset, offset + SESSION_CONTEXT_PAGE_RAW_ITEMS);
    yield { kind: 'raw', fromItemSeq: items[0]!.itemSeq, throughItemSeq: items.at(-1)!.itemSeq, items };
  }
}
export async function scanSessionCompactionRange(artifacts: SessionContextPageReader, head: SessionContextHead,
  input: Readonly<{ fromItemSeq: number; throughItemSeq: number; retainedItemIds: readonly string[] }>, signal?: AbortSignal) {
  if (!Number.isSafeInteger(input.fromItemSeq) || !Number.isSafeInteger(input.throughItemSeq) || input.fromItemSeq < 1 ||
      input.throughItemSeq < input.fromItemSeq || input.throughItemSeq > head.throughItemSeq || input.retainedItemIds.length > 256 ||
      new Set(input.retainedItemIds).size !== input.retainedItemIds.length) invalid();
  const wanted = new Set(input.retainedItemIds), retainedItemIds: string[] = [], hash = createHash('sha256').update('[');
  let next = input.fromItemSeq, count = 0;
  for await (const segment of walkSessionContextSegments(artifacts, head, { signal })) {
    if (segment.throughItemSeq < input.fromItemSeq || segment.fromItemSeq > input.throughItemSeq) continue;
    if (segment.kind !== 'raw' || segment.fromItemSeq !== next || segment.throughItemSeq > input.throughItemSeq) invalid();
    for (const source of segment.items) {
      if (count++) hash.update(',');
      hash.update(canonicalJsonBytes({ itemSeq: source.itemSeq, kind: source.kind, payloadRef: source.payloadRef }));
      if (wanted.has(source.itemId)) retainedItemIds.push(source.itemId);
    }
    next = segment.throughItemSeq + 1;
  }
  if (next - 1 !== input.throughItemSeq || retainedItemIds.length !== wanted.size) invalid();
  return Object.freeze({ sourceItemsDigest: hash.update(']').digest('hex'), retainedItemIds: Object.freeze(retainedItemIds) });
}
export async function* sessionContextPrefixSegments(artifacts: SessionContextPageReader, head: SessionContextHead,
  through: number, signal?: AbortSignal): AsyncIterableIterator<SessionContextSegment> {
  if (!Number.isSafeInteger(through) || through < 0 || through > head.throughItemSeq) invalid();
  let last = 0;
  for await (const segment of walkSessionContextSegments(artifacts, head, { signal })) {
    if (segment.fromItemSeq <= through && segment.throughItemSeq > through) invalid();
    if (segment.throughItemSeq <= through) { last = segment.throughItemSeq; yield* bounded(segment); }
  }
  if (last !== through) invalid();
}
export async function* compactedSessionContextSegments(artifacts: SessionContextPageReader, previous: SessionContextHead,
  payload: SessionCompactionItem, itemId: string, payloadRef: string, signal?: AbortSignal): AsyncIterableIterator<SessionContextSegment> {
  let replaced = false, next = payload.fromItemSeq;
  for await (const segment of walkSessionContextSegments(artifacts, previous, { signal })) {
    if (segment.throughItemSeq < payload.fromItemSeq || segment.fromItemSeq > payload.throughItemSeq) { yield* bounded(segment); continue; }
    if (segment.kind !== 'raw' || segment.fromItemSeq !== next || segment.throughItemSeq > payload.throughItemSeq) invalid();
    if (!replaced) {
      yield { kind: 'summary', fromItemSeq: payload.fromItemSeq, throughItemSeq: payload.throughItemSeq, compactionItemId: itemId,
        sourceItemsDigest: payload.sourceItemsDigest, summaryRef: payload.summaryRef, summaryDigest: payload.summaryDigest,
        retainedItemIds: [...payload.retainedItemIds] };
      replaced = true;
    }
    next = segment.throughItemSeq + 1;
  }
  if (!replaced || next - 1 !== payload.throughItemSeq) invalid();
  const itemSeq = previous.throughItemSeq + 1, hash = createHash('sha256');
  hash.update(canonicalJsonBytes([{ itemSeq, kind: 'compaction', payloadRef }]));
  yield { kind: 'excluded_control', fromItemSeq: itemSeq, throughItemSeq: itemSeq, sourceItemsDigest: hash.digest('hex') };
}
/** Read-only reconstruction for first-response auditing. Only an expected
 * content ref is returned: local plans are never exposed as published/native
 * evidence, registered in a catalog, or used to skip the actual retained graph
 * read. The same bounded encoder prevents producer/auditor layout drift. */
export async function plannedSessionContextGraphRef(artifacts: Pick<ArtifactCatalog, 'assertReadActive'>,
  input: Readonly<{ sessionId: string; contextRevision: number; throughItemSeq: number;
    segments: AsyncIterable<SessionContextSegment> | Iterable<SessionContextSegment> }>, signal?: AbortSignal): Promise<string> {
  const planned = await publishSessionContextGraph({ assertReadActive: () => artifacts.assertReadActive(),
    async publishCanonical(value: unknown, schemaKind: string) {
      const plan = planCanonicalArtifact(value, schemaKind);
      return { ref: plan.ref, mediaType: plan.mediaType, schemaKind: plan.schemaKind, byteLength: plan.bytes.byteLength };
    } }, input, { signal });
  return planned.artifact.ref;
}
