import { canonicalJsonBytes } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeSessionContextHead, walkSessionContextSegments } from '../kernel/session-context-page-reader.js';
import type { Session } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';

/** Display boundaries only. This is neither a truncated context projection
 * nor proof of Session lineage, compaction, or permission to mutate it. */
export type InstalledSessionContextBoundary = Readonly<{ kind: 'raw' | 'excluded_control'; fromItemSeq: number; throughItemSeq: number }>
  | Readonly<{ kind: 'summary'; fromItemSeq: number; throughItemSeq: number; retainedItemCount: number; summaryRef: string }>;
export type InstalledSessionContextPresentation = Readonly<{
  kind: 'head'; sessionId: string; contextRevision: number; throughItemSeq: number;
}> | Readonly<{ kind: 'boundary'; boundary: InstalledSessionContextBoundary }>
  | Readonly<{ kind: 'complete' }>;

/** The captured head and every page share the original 64 MiB presentation
 * ceiling. Each read uses the existing complete hash/EOF/join consumer. A
 * missing/corrupt page or cancellation fails the read; it never selects a new
 * head, retries, silently clips history, or emits a completion marker. */
export async function* readInstalledSessionContext(session: Readonly<{
  artifact(digest: string, options: Readonly<{ maxBytes: number; signal?: AbortSignal }>): Promise<Buffer>;
  contextPage(snapshot: Session, path: readonly number[], expectedRef: string,
    options: Readonly<{ maxBytes: number; signal?: AbortSignal }>): Promise<Buffer>;
}>, snapshot: Session,
  signal?: AbortSignal): AsyncGenerator<InstalledSessionContextPresentation> {
  const original = immutableSnapshot(snapshot);
  let remaining = 64 * 1024 * 1024;
  const reader = {
    assertReadActive() { signal?.throwIfAborted(); },
    async readBoundedBytes(ref: string, maximum: number, pagePath?: readonly number[]) {
      signal?.throwIfAborted();
      if (remaining === 0) throw new RangeError('Session context presentation exceeds its cumulative byte ceiling');
      const options = { maxBytes: Math.min(maximum, remaining), signal };
      const bytes = pagePath === undefined ? await session.artifact(ref, options) : await session.contextPage(original, pagePath, ref, options);
      signal?.throwIfAborted();
      remaining -= bytes.length;
      return bytes;
    }
  };
  const bytes = await reader.readBoundedBytes(original.contextProjectionRef, remaining);
  const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!canonicalJsonBytes(value).equals(bytes)) throw new TypeError('Session projection bytes are not canonical');
  const head = decodeSessionContextHead(value);
  if (head.sessionId !== original.id || head.contextRevision !== original.contextRevision || head.throughItemSeq !== original.latestItemSeq)
    throw new TypeError('Session projection differs from its original captured snapshot');
  yield Object.freeze({ kind: 'head', sessionId: head.sessionId, contextRevision: head.contextRevision, throughItemSeq: head.throughItemSeq });
  for await (const segment of walkSessionContextSegments(reader, head, { signal })) {
    const range = { kind: segment.kind, fromItemSeq: segment.fromItemSeq, throughItemSeq: segment.throughItemSeq };
    const boundary: InstalledSessionContextBoundary = segment.kind === 'summary'
      ? { ...range, kind: 'summary', retainedItemCount: segment.retainedItemIds.length, summaryRef: segment.summaryRef }
      : { ...range, kind: segment.kind };
    yield Object.freeze({ kind: 'boundary', boundary: Object.freeze(boundary) });
  }
  signal?.throwIfAborted();
  yield Object.freeze({ kind: 'complete' });
}
