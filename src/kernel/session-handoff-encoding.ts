// Deterministic full export bytes only. Source/lineage/Owner authority is
// checked by the caller; this module creates no connection, clock or proof.
import { createHash } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { canonicalJsonBytes } from './canonical.js';
import type { SessionHandoffEntryV1 } from './session-continuity.js';
import { decodeSessionHandoffHeader as header, decodeSessionHandoffEntry as entry, decodeSessionHandoffExcludedRange as excluded,
  type SessionHandoffHeader, type SessionHandoffExcludedRange } from './session-handoff-data.js';
export type { SessionHandoffHeader, SessionHandoffExcludedRange } from './session-handoff-data.js';
export { encodeSessionHandoffMarkdown } from './session-handoff-data.js';

function* chunks(bytes: Buffer, signal?: AbortSignal): IterableIterator<Buffer> {
  for (let offset = 0; offset < bytes.length; offset += 65_536) { signal?.throwIfAborted(); yield bytes.subarray(offset, offset + 65_536); }
}

export async function* encodeSessionHandoffJson(input: SessionHandoffHeader, entries: AsyncIterable<SessionHandoffEntryV1>,
  ranges: AsyncIterable<SessionHandoffExcludedRange>, signal?: AbortSignal): AsyncIterableIterator<Buffer> {
  const data = header(input), hash = createHash('sha256');
  const emit = (value: Buffer) => { signal?.throwIfAborted(); hash.update(value); return chunks(value, signal); };
  const start = canonicalJsonBytes({ contextProjectionDigest: data.contextProjectionDigest, contextProjectionRef: data.contextProjectionRef,
    contextRevision: data.contextRevision });
  yield* emit(Buffer.concat([start.subarray(0, -1), Buffer.from(',"entries":[')]));
  let count = 0;
  for await (const value of entries) {
    signal?.throwIfAborted(); const checked = entry(value, count, data.throughItemSeq);
    if (count++) yield* emit(Buffer.from(','));
    yield* emit(canonicalJsonBytes(checked)); await setImmediate(); signal?.throwIfAborted();
  }
  yield* emit(Buffer.from('],"excludedRanges":['));
  let rangeCount = 0, through = 0;
  for await (const value of ranges) {
    signal?.throwIfAborted(); const checked = excluded(value, through, data.throughItemSeq); through = checked.throughItemSeq;
    if (rangeCount++) yield* emit(Buffer.from(',')); yield* emit(canonicalJsonBytes(checked));
    await setImmediate(); signal?.throwIfAborted();
  }
  yield* emit(Buffer.from('],"format":"cliq-session-handoff-v1"'));
  const tailObject = { schemaVersion: 1, sessionId: data.sessionId, throughItemSeq: data.throughItemSeq,
    workspaceIdentityDigest: data.workspaceIdentityDigest, workspaceIdentityRef: data.workspaceIdentityRef };
  const tailBytes = canonicalJsonBytes(tailObject), tail = Buffer.concat([Buffer.from(','), tailBytes.subarray(1)]);
  // Independent semantic omission digest; CAS will separately identify the
  // complete output bytes, including this field. No future/self object ref.
  hash.update(tail); const handoffDigest = hash.digest('hex');
  signal?.throwIfAborted(); yield Buffer.from(`,"handoffDigest":${JSON.stringify(handoffDigest)}`);
  yield* chunks(tail, signal);
}
