// The only v2 Session page publisher/walker. All callers retain the original
// immutable SQL lineage/compaction checks; this module owns no authority.
import { setImmediate } from 'node:timers/promises';
import { digestOmitting } from '../kernel/identity.js';
import { decodeSessionContextHeadV2, decodeSessionContextPage, decodeSessionContextPageSegment,
  SESSION_CONTEXT_PAGE_BYTES, SESSION_CONTEXT_PAGE_SEGMENTS, SESSION_CONTEXT_PAGE_RAW_ITEMS,
  SESSION_CONTEXT_PAGE_CHILDREN, SESSION_CONTEXT_TREE_HEIGHT,
  type SessionContextProjectionV2, type SessionContextPage,
  type SessionContextPageEdge, type SessionContextLeafPage, type SessionContextBranchPage } from '../kernel/session-context-pages.js';
import type { SessionContextSegment } from '../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { KernelStorageError } from './errors.js';

import { readSessionContextPage as readPage, type SessionContextPageReader as Reader } from '../kernel/session-context-page-reader.js';
export { decodeSessionContextHead, walkSessionContextSegments, walkSessionContextPageEdges } from '../kernel/session-context-page-reader.js';
type Writer = Pick<ArtifactCatalog, 'publishCanonical' | 'assertReadActive'>;
type PageEdge = SessionContextPageEdge & Readonly<{ height: number }>;
export type ContextGraphOptions = Readonly<{ signal?: AbortSignal;
  /** Original metadata transaction/stage consumes each publication immediately.
   * Nothing accumulates the whole page graph in a metadata array. */
  onPublished?: (artifact: PublishedArtifact) => void | Promise<void> }>;
function corrupt(message = 'Session context page differs from its complete immutable graph'): never {
  throw new KernelStorageError('RECOVERY_REQUIRED', message);
}
function active(artifacts: Pick<ArtifactCatalog, 'assertReadActive'>, options: ContextGraphOptions): void {
  options.signal?.throwIfAborted(); artifacts.assertReadActive();
}
async function yieldTurn(artifacts: Pick<ArtifactCatalog, 'assertReadActive'>, options: ContextGraphOptions): Promise<void> {
  active(artifacts, options); await setImmediate(); active(artifacts, options);
}
function leaf(segments: readonly SessionContextSegment[]): SessionContextLeafPage {
  return { schemaVersion: 1, format: 'cliq-session-context-page-v1', kind: 'leaf', height: 0,
    fromItemSeq: segments[0]!.fromItemSeq, throughItemSeq: segments.at(-1)!.throughItemSeq, segments };
}
function branch(children: readonly PageEdge[], height: number): SessionContextBranchPage {
  return { schemaVersion: 1, format: 'cliq-session-context-page-v1', kind: 'branch', height,
    fromItemSeq: children[0]!.fromItemSeq, throughItemSeq: children.at(-1)!.throughItemSeq,
    children: children.map(({ ref, fromItemSeq, throughItemSeq }) => ({ ref, fromItemSeq, throughItemSeq })) };
}
function fits(segments: readonly SessionContextSegment[]): boolean {
  if (!segments.length || segments.length > SESSION_CONTEXT_PAGE_SEGMENTS ||
      segments.reduce((count, segment) => count + (segment.kind === 'raw' ? segment.items.length : 0), 0) > SESSION_CONTEXT_PAGE_RAW_ITEMS) return false;
  try { decodeSessionContextPage(leaf(segments)); return true; }
  catch (error) { if (error instanceof TypeError) return false; throw error; }
}
async function publishPage(artifacts: Writer, page: SessionContextPage, options: ContextGraphOptions): Promise<PageEdge> {
  active(artifacts, options); decodeSessionContextPage(page);
  const item = await artifacts.publishCanonical(page, 'cliq-session-context-page-v1');
  active(artifacts, options); await options.onPublished?.(item); active(artifacts, options);
  return Object.freeze({ ref: item.ref, height: page.height, fromItemSeq: page.fromItemSeq, throughItemSeq: page.throughItemSeq });
}
async function publishHead(artifacts: Writer, input: Readonly<{ sessionId: string; contextRevision: number; throughItemSeq: number }>,
  root: PageEdge | null, options: ContextGraphOptions): Promise<Readonly<{ head: SessionContextProjectionV2; artifact: PublishedArtifact }>> {
  const value = { schemaVersion: 2, format: 'cliq-session-context-v2', sessionId: input.sessionId,
    contextRevision: input.contextRevision, throughItemSeq: input.throughItemSeq,
    rootPageRef: root?.ref ?? null, pageHeight: root?.height ?? 0, projectionDigest: '' };
  value.projectionDigest = digestOmitting(value, 'projectionDigest');
  const head = decodeSessionContextHeadV2(value);
  active(artifacts, options); const artifact = await artifacts.publishCanonical(head, 'cliq-session-context-v2');
  active(artifacts, options); await options.onPublished?.(artifact); active(artifacts, options);
  return Object.freeze({ head, artifact });
}

/** Streaming bulk publisher. Level buffers have fixed fanout; complete child
 * pages are durable before their parent, and every caller publication is joined
 * before another source item can be consumed. No source/SQL iterator is held by
 * this module and no partial tree is returned as a complete head. */
export async function publishSessionContextGraph(artifacts: Writer,
  input: Readonly<{ sessionId: string; contextRevision: number; throughItemSeq: number;
    segments: AsyncIterable<SessionContextSegment> | Iterable<SessionContextSegment> }>,
  options: ContextGraphOptions = {}): Promise<Readonly<{ head: SessionContextProjectionV2; artifact: PublishedArtifact }>> {
  let pending: SessionContextSegment[] = [], next = 1;
  const levels: PageEdge[][] = [];
  const add = async (edge: PageEdge): Promise<void> => {
    active(artifacts, options);
    if (edge.height > SESSION_CONTEXT_TREE_HEIGHT) return corrupt('Session context exceeded its fixed tree profile');
    const rows = levels[edge.height] ?? (levels[edge.height] = []);
    if (rows.length && rows.at(-1)!.throughItemSeq + 1 !== edge.fromItemSeq) return corrupt();
    rows.push(edge);
    if (rows.length === SESSION_CONTEXT_PAGE_CHILDREN) {
      if (edge.height === SESSION_CONTEXT_TREE_HEIGHT) return corrupt('Session context exceeded its fixed tree profile');
      const parent = await publishPage(artifacts, branch(rows, edge.height + 1), options);
      levels[edge.height] = []; await add(parent);
    }
  };
  const flush = async (): Promise<void> => {
    if (!pending.length) return;
    await add(await publishPage(artifacts, leaf(pending), options)); pending = [];
    await yieldTurn(artifacts, options);
  };
  for await (const source of input.segments) {
    active(artifacts, options); const segment = decodeSessionContextPageSegment(source);
    if (segment.fromItemSeq !== next) return corrupt(); next = segment.throughItemSeq + 1;
    if (!fits([...pending, segment])) await flush();
    if (!fits([segment])) return corrupt('one Session segment exceeds the fixed page profile');
    pending.push(segment);
  }
  if (next - 1 !== input.throughItemSeq) return corrupt('Session graph source is not the complete declared prefix');
  await flush();
  for (let height = 0; height < levels.length; height++) {
    const rows = levels[height]!;
    if (!rows.length) continue;
    const above = levels.slice(height + 1).some(level => level.length);
    if (rows.length === 1 && !above) return publishHead(artifacts, input, rows[0]!, options);
    if (height === SESSION_CONTEXT_TREE_HEIGHT) return corrupt('Session context exceeded its fixed tree profile');
    const parent = await publishPage(artifacts, branch(rows, height + 1), options);
    levels[height] = []; await add(parent);
  }
  if (input.throughItemSeq !== 0) return corrupt();
  return publishHead(artifacts, input, null, options);
}

/** Normal append updates only the original immutable right-hand path; it
 * never loads/rebuilds the whole Session. Existing untouched subtrees retain
 * exact refs. Original SQL/Session checks and the sole terminal transaction
 * remain with the caller; publication supplies no permission to append. */
export async function appendSessionContextGraph(artifacts: Reader & Writer, head: SessionContextProjectionV2,
  source: SessionContextSegment, options: ContextGraphOptions = {}) {
  const previous = decodeSessionContextHeadV2(head), segment = decodeSessionContextPageSegment(source);
  if (segment.fromItemSeq !== previous.throughItemSeq + 1 || !fits([segment])) return corrupt();
  const path: SessionContextBranchPage[] = [];
  let edge: PageEdge | null = previous.rootPageRef === null ? null : { ref: previous.rootPageRef,
    height: previous.pageHeight, fromItemSeq: 1, throughItemSeq: previous.throughItemSeq };
  let oldLeaf: SessionContextLeafPage | undefined;
  while (edge) {
    const page = await readPage(artifacts, edge, options);
    if (page.kind === 'leaf') { oldLeaf = page; break; }
    path.push(page); edge = { ...page.children.at(-1)!, height: page.height - 1 };
  }
  let updated: PageEdge, carry: PageEdge | undefined;
  if (!oldLeaf) updated = await publishPage(artifacts, leaf([segment]), options);
  else if (fits([...oldLeaf.segments, segment])) updated = await publishPage(artifacts, leaf([...oldLeaf.segments, segment]), options);
  else { updated = edge!; carry = await publishPage(artifacts, leaf([segment]), options); }
  for (const parent of path.reverse()) {
    const children: PageEdge[] = parent.children.map(child => ({ ...child, height: parent.height - 1 }));
    children[children.length - 1] = updated;
    if (carry && children.length < SESSION_CONTEXT_PAGE_CHILDREN) { children.push(carry); carry = undefined; }
    const next = await publishPage(artifacts, branch(children, parent.height), options);
    if (carry) carry = await publishPage(artifacts, branch([carry], parent.height), options);
    updated = next; await yieldTurn(artifacts, options);
  }
  if (carry) {
    if (updated.height === SESSION_CONTEXT_TREE_HEIGHT) return corrupt('Session context exceeded its fixed tree profile');
    updated = await publishPage(artifacts, branch([updated, carry], updated.height + 1), options);
  }
  return publishHead(artifacts, { sessionId: previous.sessionId, contextRevision: previous.contextRevision + 1,
    throughItemSeq: segment.throughItemSeq }, updated, options);
}
