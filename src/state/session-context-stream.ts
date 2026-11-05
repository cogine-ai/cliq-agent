// Complete retained context consumption, one bounded page/payload at a time.
// It returns a cut only after every source edge and typed payload was checked;
// a callback's partial output is inert until the original caller commits it.
import { createHash } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import { controlWireRecord, decodeWireSession } from '../kernel/control-wire-data.js';
import { isLegacySessionContextKind } from '../kernel/legacy-context.js';
import { verifyModelText } from '../model/attempt.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import type { Session, SessionContextSegment, SessionItem } from '../kernel/types.js';
import type { ProviderName } from '../kernel/types.js';
import { MODEL_REQUEST_BODY_LIMIT_BYTES, sessionContextUserWireByteLowerBound } from '../model/request.js';
import type { SessionCompactionItem } from '../kernel/session-continuity.js';
import type { SessionContextHead } from '../kernel/session-context-pages.js';
import { decodeSessionContextHead, walkSessionContextSegments } from '../kernel/session-context-page-reader.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import { readSessionContextSourceEntry, type SessionContextEntry, type SessionCompactionIndex } from './session-context.js';
import { assertSessionContextIndex, captureSessionContextIndex, readSessionContextIndexItems,
  sessionContextIndexJustification, type SessionContextIndexCut } from './session-context-index.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { sessionFromRow } from './rows.js';
import { SessionContextRequestLimitError } from './session-context-limit.js';

type RawSource = Extract<SessionContextSegment, { kind: 'raw' }>['items'][number];
export type SessionContextGraphRead = Readonly<{ cut: SessionContextIndexCut; projection: SessionContextHead }>;
function corrupt(message = 'Session context lost its complete original source graph'): never {
  throw new KernelStorageError('RECOVERY_REQUIRED', message);
}
function sourceHash() { return createHash('sha256').update('['); }
function addSource(hash: ReturnType<typeof sourceHash>, source: Pick<SessionItem, 'itemSeq' | 'kind' | 'payloadRef'>, count: number): void {
  if (count) hash.update(','); hash.update(canonicalJsonBytes({ itemSeq: source.itemSeq, kind: source.kind, payloadRef: source.payloadRef }));
}
function sameSource(actual: SessionItem | undefined, source: RawSource): void {
  if (!actual || actual.sessionId !== source.sourceSessionId || actual.itemSeq !== source.itemSeq ||
      actual.itemId !== source.itemId || actual.kind !== source.kind || actual.payloadRef !== source.payloadRef) return corrupt();
}
export async function readBoundedSessionContextJson<T>(artifacts: ArtifactCatalog, ref: string): Promise<T> {
  const bytes = await artifacts.readBoundedBytes(ref, 1_048_576);
  artifacts.assertReadActive();
  try {
    const data = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!canonicalJsonBytes(data).equals(bytes)) return corrupt('Session artifact is not its exact canonical bytes');
    return data as T;
  } catch (error) { if (error instanceof TypeError || error instanceof SyntaxError) return corrupt(); throw error; }
}
/** V1 retains its actual historical profile. A v2 root has its ceiling checked
 * before a whole-object allocation; exact canonical bytes/schema are then
 * independently checked. The profile selector itself supplies no authority. */
export async function readSessionContextGraphHead(artifacts: ArtifactCatalog, ref: string): Promise<SessionContextHead> {
  const bytes = await artifacts.readSessionContextHeadBytes(ref);
  try {
    const data: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!canonicalJsonBytes(data).equals(bytes)) return corrupt('Session context head is not its exact canonical bytes');
    return decodeSessionContextHead(data);
  } catch (error) { if (error instanceof TypeError || error instanceof SyntaxError) return corrupt(); throw error; }
}

export async function* readSessionContextEntryStream(artifacts: ArtifactCatalog, projection: SessionContextHead,
  options: Readonly<{ source?: Readonly<{ driver: SqliteDriver; cut: SessionContextIndexCut }>;
    compactionIndex?: SessionCompactionIndex; signal?: AbortSignal }> = {}): AsyncIterableIterator<SessionContextEntry> {
  const { signal } = options, sourceIndex = options.source;
  let index = 0;
  const bounded = { readCanonical: <T>(ref: string) => readBoundedSessionContextJson<T>(artifacts, ref) };
  const current = () => { signal?.throwIfAborted(); artifacts.assertReadActive(); };
  for await (const segment of walkSessionContextSegments(artifacts, projection, { signal })) {
    current();
    if (segment.kind === 'raw') {
      const rows = sourceIndex && readSessionContextIndexItems(sourceIndex.driver, sourceIndex.cut,
        { from: segment.fromItemSeq, through: segment.throughItemSeq, signal })[Symbol.asyncIterator]();
      try {
        for (const source of segment.items) {
          if (rows) { const actual = await rows.next(); sameSource(actual.done ? undefined : actual.value, source); }
          current(); yield await readSessionContextSourceEntry(bounded, source, index++);
        }
        if (rows && !(await rows.next()).done) return corrupt();
      } finally { await rows?.return?.(); }
    } else if (segment.kind === 'excluded_control') {
      // Original admitted raw-only CAS closure has no index dependency. A
      // current/frozen SQL consumer supplies sourceIndex and verifies the
      // complete excluded range; neither case emits its authority payload.
      if (!sourceIndex) continue;
      const hash = sourceHash(); let count = 0;
      for await (const row of readSessionContextIndexItems(sourceIndex.driver, sourceIndex.cut, { from: segment.fromItemSeq, through: segment.throughItemSeq, signal })) {
        if (row.kind === 'run_terminal' || projection.schemaVersion === 2 && isLegacySessionContextKind(row.kind)) return corrupt();
        addSource(hash, row, count++);
      }
      if (hash.update(']').digest('hex') !== segment.sourceItemsDigest) return corrupt();
    } else {
      const justification = sourceIndex ? sessionContextIndexJustification(sourceIndex.driver, sourceIndex.cut, segment.compactionItemId) :
        options.compactionIndex?.(segment.compactionItemId);
      if (!justification) return corrupt('Session summary requires its original immutable compaction index');
      const metadata = justification.item;
      const data = controlWireRecord(await readBoundedSessionContextJson(artifacts, metadata.payloadRef), ['schemaVersion', 'kind', 'fromItemSeq', 'throughItemSeq', 'sourceItemsDigest',
        'summaryRef', 'summaryDigest', 'retainedItemIds', 'previousProjectionRef', 'createdAt']) as unknown as SessionCompactionItem;
      if (data.schemaVersion !== 1 || data.kind !== 'compaction' || metadata.kind !== 'compaction' || metadata.itemId !== segment.compactionItemId ||
          metadata.createdAt !== data.createdAt || data.fromItemSeq !== segment.fromItemSeq || data.throughItemSeq !== segment.throughItemSeq ||
          data.sourceItemsDigest !== segment.sourceItemsDigest || data.summaryRef !== segment.summaryRef || data.summaryDigest !== segment.summaryDigest ||
          data.throughItemSeq > justification.sourceThroughItemSeq || !Array.isArray(data.retainedItemIds) ||
          canonicalJsonBytes(data.retainedItemIds).compare(canonicalJsonBytes(segment.retainedItemIds)) !== 0) return corrupt();
      const previous = await readSessionContextGraphHead(artifacts, data.previousProjectionRef);
      if (previous.sessionId !== metadata.sessionId || previous.throughItemSeq !== metadata.itemSeq - 1) return corrupt();
      const sources = sourceHash(), retained: RawSource[] = [], wanted = new Set(segment.retainedItemIds); let count = 0, next = segment.fromItemSeq;
      const rows = sourceIndex && readSessionContextIndexItems(sourceIndex.driver, sourceIndex.cut,
        { from: segment.fromItemSeq, through: segment.throughItemSeq, signal })[Symbol.asyncIterator]();
      try {
        // Walk the whole original head, including the unselected page edges.
        // Selected tuples are the exact original whole raw segment range;
        // summary/straddling/control/recompaction never becomes valid by paging.
        for await (const selected of walkSessionContextSegments(artifacts, previous, { signal })) {
          if (selected.throughItemSeq < segment.fromItemSeq || selected.fromItemSeq > segment.throughItemSeq) continue;
          if (selected.kind !== 'raw' || selected.fromItemSeq !== next || selected.throughItemSeq > segment.throughItemSeq) return corrupt();
          options.compactionIndex?.(segment.compactionItemId, selected.items);
          for (const source of selected.items) {
            if (rows) { const actual = await rows.next(); sameSource(actual.done ? undefined : actual.value, source); }
            addSource(sources, source, count++); if (wanted.has(source.itemId)) retained.push(source);
          }
          next = selected.throughItemSeq + 1;
        }
        if (next - 1 !== segment.throughItemSeq || rows && !(await rows.next()).done ||
            sources.update(']').digest('hex') !== segment.sourceItemsDigest || retained.length !== wanted.size ||
            canonicalJsonBytes(retained.map(source => source.itemId)).compare(canonicalJsonBytes(segment.retainedItemIds)) !== 0) return corrupt();
      } finally { await rows?.return?.(); }
      const text = await readBoundedSessionContextJson<ModelTextV1>(artifacts, segment.summaryRef); verifyModelText(text);
      if (text.textDigest !== segment.summaryDigest || text.byteCount < 1 || text.byteCount > 262_144) return corrupt();
      current(); yield { index: index++, sourceKind: 'summary', fromItemSeq: segment.fromItemSeq, throughItemSeq: segment.throughItemSeq,
        sourceRef: metadata.payloadRef, sourceDigest: segment.summaryDigest, sourceItemId: segment.compactionItemId, contentUtf8: text.utf8 };
      for (const source of retained) { current(); yield await readSessionContextSourceEntry(bounded, source, index++); }
    }
    if (!Number.isSafeInteger(index)) return corrupt('Session context entry sequence is exhausted');
  }
}

/** Opens the exact captured Session, independent of today's mutable head.
 * The consumer's backpressure bounds live prose memory. All entries/pages and
 * source rows must finish before a validated cut is returned; early break or
 * callback failure joins generators and supplies no completion result. */
export async function consumeFrozenSessionContext(driver: SqliteDriver, artifacts: ArtifactCatalog, principalId: string,
  input: Session, consume: (entry: SessionContextEntry) => void | Promise<void>, signal?: AbortSignal,
  check?: (connection: SqliteConnection) => void): Promise<SessionContextGraphRead> {
  const session = decodeWireSession(input), projection = await readSessionContextGraphHead(artifacts, session.contextProjectionRef);
  if (projection.sessionId !== session.id || projection.contextRevision !== session.contextRevision || projection.throughItemSeq !== session.latestItemSeq) return corrupt();
  const cut = await captureSessionContextIndex(driver, principalId, session, signal);
  for await (const entry of readSessionContextEntryStream(artifacts, projection, { source: { driver, cut }, signal })) {
    signal?.throwIfAborted(); artifacts.assertReadActive(); await consume(entry);
  }
  signal?.throwIfAborted(); artifacts.assertReadActive();
  driver.readSnapshot(connection => { check?.(connection); assertSessionContextIndex(connection, cut); });
  return Object.freeze({ cut, projection });
}
function assertCurrentHead(connection: SqliteConnection, cut: Pick<SessionContextIndexCut, 'session' | 'principalId'>): void {
  const row = connection.prepare('SELECT * FROM sessions WHERE id=? AND principal_id=?').get(cut.session.id, cut.principalId);
  if (!row || canonicalSha256(sessionFromRow(row)) !== canonicalSha256(cut.session))
    throw new KernelStorageError('REVISION_CONFLICT', 'Session changed during its complete paged context read');
}
export function assertCurrentSessionContextGraph(connection: SqliteConnection, cut: SessionContextIndexCut): void {
  assertCurrentHead(connection, cut); assertSessionContextIndex(connection, cut);
}
/** Current-head reader for productive admission and context mutations. A
 * model-profile lower bound can only refuse a certainly impossible new Run;
 * it never approves dispatch or replaces exact wire/token admission. Even after
 * crossing it, every remaining graph/source/payload is validated with no prose
 * retained. No Run/claim/worker has been created by this read. */
type SessionContextModelProfile = Readonly<{ provider: ProviderName; model: string }>;
export async function readCurrentSessionContextGraph(driver: SqliteDriver, artifacts: ArtifactCatalog, principalId: string,
  sessionId: string, expectedRevision?: number, options: Readonly<{ signal?: AbortSignal;
    modelProfile?: SessionContextModelProfile | (() => Promise<SessionContextModelProfile>);
    consume?: (entry: SessionContextEntry) => void | Promise<void> }> = {}): Promise<SessionContextGraphRead> {
  const snapshot = driver.readSnapshot(connection => {
    const row = connection.prepare('SELECT * FROM sessions WHERE id=? AND principal_id=?').get(sessionId, principalId);
    if (!row) throw new KernelStorageError('NOT_FOUND', 'Session is unavailable');
    return decodeWireSession(sessionFromRow(row));
  });
  if (expectedRevision !== undefined && snapshot.contextRevision !== expectedRevision)
    throw new KernelStorageError('REVISION_CONFLICT', 'Session context revision changed');
  let minimumBodyBytes = 0;
  const selectedProfile = options.modelProfile;
  let modelProfile = typeof selectedProfile === 'function' ? undefined : selectedProfile;
  const result = await consumeFrozenSessionContext(driver, artifacts, principalId, snapshot, async entry => {
    if (selectedProfile) {
      modelProfile ??= typeof selectedProfile === 'function' ? await selectedProfile() : selectedProfile;
      options.signal?.throwIfAborted(); artifacts.assertReadActive();
      minimumBodyBytes += sessionContextUserWireByteLowerBound(modelProfile.provider, modelProfile.model, entry.contentUtf8);
      if (!Number.isSafeInteger(minimumBodyBytes)) return corrupt('Session model lower bound exceeded the exact counter domain');
    }
    await options.consume?.(entry);
  }, options.signal, connection => assertCurrentHead(connection, { session: snapshot, principalId }));
  if (selectedProfile && minimumBodyBytes > MODEL_REQUEST_BODY_LIMIT_BYTES)
    throw new SessionContextRequestLimitError();
  return result;
}
/** Terminal history keeps its original exact one-item raw source through a
 * legitimate later compaction. This walks immutable pages/previous root, never
 * expands the complete tree to v1 or treats today's head as an old response. */
export async function assertPagedSessionTerminalContext(driver: SqliteDriver, artifacts: ArtifactCatalog, principalId: string,
  snapshot: Session, expected: Readonly<{ itemSeq: number; itemId: string; payloadRef: string }>): Promise<void> {
  const context = await consumeFrozenSessionContext(driver, artifacts, principalId, snapshot, () => undefined);
  const selected = readSessionContextIndexItems(driver, context.cut, { from: expected.itemSeq, through: expected.itemSeq });
  let source: SessionItem | undefined;
  for await (const item of selected) { if (source) return corrupt(); source = item; }
  if (!source || source.sessionId !== snapshot.id || source.kind !== 'run_terminal' || source.itemId !== expected.itemId ||
      source.payloadRef !== expected.payloadRef) return corrupt();
  async function containing(head: SessionContextHead): Promise<SessionContextSegment> {
    let found: SessionContextSegment | undefined;
    for await (const segment of walkSessionContextSegments(artifacts, head))
      if (segment.fromItemSeq <= expected.itemSeq && segment.throughItemSeq >= expected.itemSeq) {
        if (found) return corrupt(); found = segment;
      }
    return found ?? corrupt();
  }
  let segment = await containing(context.projection);
  if (segment.kind === 'summary') {
    const metadata = sessionContextIndexJustification(driver, context.cut, segment.compactionItemId).item;
    const payload = controlWireRecord(await readBoundedSessionContextJson(artifacts, metadata.payloadRef), ['schemaVersion', 'kind', 'fromItemSeq', 'throughItemSeq',
      'sourceItemsDigest', 'summaryRef', 'summaryDigest', 'retainedItemIds', 'previousProjectionRef', 'createdAt']) as unknown as SessionCompactionItem;
    segment = await containing(await readSessionContextGraphHead(artifacts, payload.previousProjectionRef));
  }
  const original = { kind: 'raw', fromItemSeq: expected.itemSeq, throughItemSeq: expected.itemSeq,
    items: [{ sourceSessionId: snapshot.id, itemSeq: expected.itemSeq, itemId: expected.itemId, kind: 'run_terminal', payloadRef: expected.payloadRef }] };
  if (canonicalSha256(segment) !== canonicalSha256(original)) return corrupt('terminal Session item lost its original exact one-item raw proof');
}
