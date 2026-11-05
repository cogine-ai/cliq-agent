import type { SessionContextHead } from '../kernel/session-context-pages.js';
import type { SessionContextSegment } from '../kernel/types.js';
import { SESSION_CONTEXT_PAGE_RAW_ITEMS } from '../kernel/session-context-pages.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { assertSqliteConnectionOwnedBy, type SqliteDriver } from './sqlite-driver.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import { appendSessionContextGraph, publishSessionContextGraph } from './session-context-graph.js';

/** Internal pages are durable CAS children, not public catalog members or SQL
 * roots. The caller registers only the complete head in its original unique
 * Session/Run transaction. Failure may leave inert CAS bytes, never metadata
 * committed outside that transaction. Complete typed retention follows every
 * page from its retained head, independently of catalog declarations; the
 * enclosing productive scope holds account SH and deletion requires EX. */
function publicationOptions(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, signal?: AbortSignal) {
  assertSqliteConnectionOwnedBy(driver, driver);
  const current = () => { signal?.throwIfAborted(); artifacts.assertReadActive(); assertActiveStateOwner(driver, owner); };
  current();
  return { signal, onPublished: current };
}
export async function publishOwnedSessionContextGraph(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: Readonly<{ sessionId: string; contextRevision: number; throughItemSeq: number;
    segments: AsyncIterable<SessionContextSegment> | Iterable<SessionContextSegment> }>, signal?: AbortSignal) {
  return publishSessionContextGraph(artifacts, input, publicationOptions(driver, artifacts, owner, signal));
}
export async function publishSessionContextAppend(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  head: SessionContextHead, segment: SessionContextSegment, signal?: AbortSignal) {
  if (segment.fromItemSeq !== head.throughItemSeq + 1 || !Number.isSafeInteger(head.contextRevision + 1))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'Session append differs from its exact original cursor');
  const options = publicationOptions(driver, artifacts, owner, signal);
  if (head.schemaVersion === 2) return appendSessionContextGraph(artifacts, head, segment, options);
  async function* migratedSegments(): AsyncIterableIterator<SessionContextSegment> {
    // The previous v1 bytes/source graph remain unchanged. Only this new v2
    // revision normalizes a long raw range into bounded whole raw segments;
    // summaries/excluded controls retain their exact semantic boundaries.
    for (const previous of head.schemaVersion === 1 ? head.segments : []) {
      signal?.throwIfAborted(); artifacts.assertReadActive();
      if (previous.kind !== 'raw') { yield previous; continue; }
      for (let offset = 0; offset < previous.items.length; offset += SESSION_CONTEXT_PAGE_RAW_ITEMS) {
        const items = previous.items.slice(offset, offset + SESSION_CONTEXT_PAGE_RAW_ITEMS);
        yield { kind: 'raw', fromItemSeq: items[0]!.itemSeq, throughItemSeq: items.at(-1)!.itemSeq, items };
      }
    }
    yield segment;
  }
  return publishSessionContextGraph(artifacts, { sessionId: head.sessionId, contextRevision: head.contextRevision + 1,
    throughItemSeq: segment.throughItemSeq, segments: migratedSegments() }, options);
}
