// Complete immutable page data only. Original callers provide their actual
// verified/joined artifact channel; no StateOwner, SQL or native scope is created.
import { setImmediate } from 'node:timers/promises';
import { canonicalJsonBytes } from './canonical.js';
import { parseJsonStrict } from './json.js';
import { assertControlWireJson } from './control-wire-data.js';
import { decodeSessionContextData } from './session-context-data.js';
import { decodeSessionContextHeadV2, decodeSessionContextPage, SESSION_CONTEXT_PAGE_BYTES,
  type SessionContextHead, type SessionContextPage, type SessionContextPageEdge } from './session-context-pages.js';
import type { SessionContextSegment } from './types.js';

export type SessionContextPageReader = Readonly<{
  /** Complete ref-verified bytes, bounded before allocation, actual read joined. */
  readBoundedBytes(ref: string, maximum: number, pagePath?: readonly number[]): Promise<Buffer>;
  assertReadActive(): void;
}>;
export type SessionContextGraphReadOptions = Readonly<{ signal?: AbortSignal }>;
export type SessionContextGraphPageEdge = SessionContextPageEdge & Readonly<{ height: number }>;
function corrupt(message = 'Session context page differs from its complete immutable graph'): never { throw new TypeError(message); }
function active(artifacts: SessionContextPageReader, options: SessionContextGraphReadOptions): void {
  options.signal?.throwIfAborted(); artifacts.assertReadActive();
}
async function yieldTurn(artifacts: SessionContextPageReader, options: SessionContextGraphReadOptions): Promise<void> {
  active(artifacts, options); await setImmediate(); active(artifacts, options);
}
export function decodeSessionContextHead(value: unknown): SessionContextHead {
  try { assertControlWireJson(value); return (value as { schemaVersion?: unknown } | null)?.schemaVersion === 2
    ? decodeSessionContextHeadV2(value) : decodeSessionContextData(value); }
  catch (error) { if (error instanceof TypeError) return corrupt(); throw error; }
}
export async function readSessionContextPage(artifacts: SessionContextPageReader, edge: SessionContextGraphPageEdge, options: SessionContextGraphReadOptions, pagePath?: readonly number[]): Promise<SessionContextPage> {
  active(artifacts, options);
  // The original CAS reader verifies all bytes and joins its real descriptors.
  // A second pageDigest would repeat its content identity without adding a
  // semantic assertion; exact canonical-byte equality is checked instead.
  const bytes = await artifacts.readBoundedBytes(edge.ref, SESSION_CONTEXT_PAGE_BYTES, pagePath);
  active(artifacts, options);
  let page: SessionContextPage;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    page = decodeSessionContextPage(parseJsonStrict(text));
    if (!canonicalJsonBytes(page).equals(bytes)) return corrupt('Session page bytes are not their exact canonical representation');
  } catch (error) { if (error instanceof TypeError || error instanceof SyntaxError) return corrupt(); throw error; }
  if (page.height !== edge.height || page.fromItemSeq !== edge.fromItemSeq || page.throughItemSeq !== edge.throughItemSeq) return corrupt();
  return page;
}

/** DFS retains at most one bounded page per fixed tree level. It never builds
 * a giant v1 projection/segments list. Each edge is visited with its own range
 * and purpose, even when bytes/ref repeat; the height decreases on every edge,
 * so cycles cannot consume an unbounded recursion or masquerade as a leaf. */
export async function* walkSessionContextSegments(artifacts: SessionContextPageReader, head: SessionContextHead,
  options: SessionContextGraphReadOptions = {}): AsyncIterableIterator<SessionContextSegment> {
  active(artifacts, options);
  if (head.schemaVersion === 1) {
    // Historical v1 keeps its actual old data contract; it is not copied into
    // a second synthetic v1 object or claimed to have v2's bounded storage.
    for (const segment of head.segments) { active(artifacts, options); yield segment; await yieldTurn(artifacts, options); }
    return;
  }
  const checked = decodeSessionContextHeadV2(head);
  if (checked.rootPageRef === null) return;
  let next = 1;
  async function* visit(edge: SessionContextGraphPageEdge, path: readonly number[]): AsyncIterableIterator<SessionContextSegment> {
    const page = await readSessionContextPage(artifacts, edge, options, path);
    if (page.kind === 'leaf') {
      for (const segment of page.segments) {
        active(artifacts, options); if (segment.fromItemSeq !== next) return corrupt();
        next = segment.throughItemSeq + 1; yield segment;
      }
    } else for (const [index, child] of page.children.entries()) {
      active(artifacts, options); yield* visit({ ...child, height: page.height - 1 }, [...path, index]);
    }
    await yieldTurn(artifacts, options);
  }
  yield* visit({ ref: checked.rootPageRef, height: checked.pageHeight, fromItemSeq: 1, throughItemSeq: checked.throughItemSeq }, []);
  if (next - 1 !== checked.throughItemSeq) return corrupt();
}

/** A GC caller consumes *all* page edges before any deletion decision. This
 * index only supplies page/raw/summary reference edges; original typed payload
 * readers must independently validate each (ref,purpose) and compaction graph.
 * Early return/unknown family can never establish complete reachability. */
export async function* walkSessionContextPageEdges(artifacts: SessionContextPageReader, head: SessionContextHead,
  options: SessionContextGraphReadOptions = {}): AsyncIterableIterator<Readonly<{ ref: string; purpose: 'session_context_page' }>> {
  if (head.schemaVersion === 1 || head.rootPageRef === null) return;
  const checked = decodeSessionContextHeadV2(head);
  async function* visit(edge: SessionContextGraphPageEdge): AsyncIterableIterator<Readonly<{ ref: string; purpose: 'session_context_page' }>> {
    const page = await readSessionContextPage(artifacts, edge, options);
    yield Object.freeze({ ref: edge.ref, purpose: 'session_context_page' });
    if (page.kind === 'branch') for (const child of page.children) yield* visit({ ...child, height: page.height - 1 });
    await yieldTurn(artifacts, options);
  }
  yield* visit({ ref: checked.rootPageRef!, height: checked.pageHeight, fromItemSeq: 1, throughItemSeq: checked.throughItemSeq });
}
