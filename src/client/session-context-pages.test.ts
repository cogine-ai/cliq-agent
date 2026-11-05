import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { readInstalledSessionContext } from '../control/session.js';
import type { InstalledSessionContextPresentation } from '../control/session-context.js';
import { createClientApplication, type ClientUpdate } from './application.js';
import { initialClientView, reduceClientView, sessionContextLines } from './view.js';
import { protocolClient, sessionSnapshot, ref } from './testing/protocol.js';

// Immutable protocol data only: no StateOwner/Run or source/compaction proof.
function paged(segments: readonly unknown[][], beforeRead?: (digest: string, offset: number) => void | Promise<void>) {
  const bytes = new Map<string, Buffer>();
  const put = (value: unknown) => { const digest = canonicalSha256(value); bytes.set(digest, canonicalJsonBytes(value)); return digest; };
  let height = 0, edges = segments.map(values => {
    const first = values[0] as { fromItemSeq: number }, last = values.at(-1) as { throughItemSeq: number };
    const range = { fromItemSeq: first.fromItemSeq, throughItemSeq: last.throughItemSeq };
    return { ...range, ref: put({ schemaVersion: 1, format: 'cliq-session-context-page-v1', kind: 'leaf', height: 0, ...range, segments: values }) };
  });
  const leaves = edges.map(edge => edge.ref);
  while (edges.length > 1) {
    height++; const parents: typeof edges = [];
    for (let index = 0; index < edges.length; index += 128) {
      const children = edges.slice(index, index + 128), range = { fromItemSeq: children[0]!.fromItemSeq, throughItemSeq: children.at(-1)!.throughItemSeq };
      parents.push({ ...range, ref: put({ schemaVersion: 1, format: 'cliq-session-context-page-v1', kind: 'branch', height, ...range, children }) });
    }
    edges = parents;
  }
  const head = { schemaVersion: 2, format: 'cliq-session-context-v2', sessionId: 'session', contextRevision: 7,
    throughItemSeq: edges[0]?.throughItemSeq ?? 0, rootPageRef: edges[0]?.ref ?? null, pageHeight: height, projectionDigest: '' };
  head.projectionDigest = digestOmitting(head, 'projectionDigest');
  const snapshot = sessionSnapshot(); snapshot.session.latestItemSeq = head.throughItemSeq; snapshot.session.contextProjectionRef = put(head);
  const reads: string[] = [];
  const f = protocolClient({ 'session.get': async (request: { contextPage?: { contextProjectionRef: string; expectedContextRevision: number; path: number[] } }) => {
    const actualSnapshot = { ...snapshot, session: { ...snapshot.session, contextRevision: head.contextRevision } };
    const result = { method: 'session.get', snapshot: actualSnapshot, items: [], highWaterItemSeq: head.throughItemSeq, nextItemSeq: head.throughItemSeq };
    if (!request.contextPage) return { protocolVersion: 1, ok: true, result };
    assert.equal(request.contextPage.contextProjectionRef, snapshot.session.contextProjectionRef);
    assert.equal(request.contextPage.expectedContextRevision, head.contextRevision);
    let selected = head.rootPageRef;
    for (const index of request.contextPage.path) {
      const parent = JSON.parse(bytes.get(selected!)!.toString()); selected = parent.children[index].ref;
    }
    if (!selected) throw new TypeError('empty original head has no context page');
    reads.push(selected); await beforeRead?.(selected, 0);
    const body = bytes.get(selected); if (!body) throw new TypeError('original referenced page is unavailable');
    return { protocolVersion: 1, ok: true, result: { ...result, contextPage: { contextProjectionRef: snapshot.session.contextProjectionRef,
      contextRevision: head.contextRevision, path: request.contextPage.path,
      artifact: { schemaVersion: 1, ref: selected, digest: selected, sizeBytes: body.length, mediaType: 'application/json' }, bytesBase64: body.toString('base64') } } };
  }, 'artifact.get': async (request: { digest: string; offset: number; length: number }) => {
    assert.equal(request.digest, snapshot.session.contextProjectionRef, 'internal pages are not public catalog members');
    if (request.offset === 0) reads.push(request.digest);
    await beforeRead?.(request.digest, request.offset);
    const body = bytes.get(request.digest); if (!body) throw new TypeError('original referenced head is unavailable');
    const end = Math.min(body.length, request.offset + request.length);
    return { protocolVersion: 1, ok: true, result: { method: 'artifact.get',
      artifact: { schemaVersion: 1, ref: request.digest, digest: request.digest, sizeBytes: body.length, mediaType: 'application/json' },
      offset: request.offset, nextOffset: end, bytesBase64: body.subarray(request.offset, end).toString('base64'), eof: end === body.length } };
  } });
  return { ...f, snapshot, head, bytes, put, leaves, reads };
}
function raw(from: number, count: number, longIds = false) {
  return { kind: 'raw', fromItemSeq: from, throughItemSeq: from + count - 1, items: Array.from({ length: count }, (_, index) => ({
    sourceSessionId: longIds ? 's'.repeat(128) : 'session', itemSeq: from + index,
    itemId: longIds ? String(from + index).padStart(128, 'i') : `item-${from + index}`, kind: 'run_terminal', payloadRef: ref })) };
}
async function collect(values: AsyncIterable<InstalledSessionContextPresentation>) {
  const result: InstalledSessionContextPresentation[] = []; for await (const value of values) result.push(value); return result;
}

test('long v2 presentation traverses bounded pages without rebuilding the whole raw tuple list', async () => {
  const segments = Array.from({ length: 16 }, (_, index) => raw(index * 200 + 1, 200));
  assert.throws(() => parseJsonStrict(JSON.stringify(segments)), /container entries/u);
  const f = paged(segments.map(segment => [segment]));
  try {
    const updates = await collect(readInstalledSessionContext(f.session, f.snapshot.session));
    const boundaries = updates.flatMap(value => value.kind === 'boundary' ? [value.boundary] : []);
    assert.equal(boundaries.length, 16); assert.equal(boundaries[0]!.fromItemSeq, 1); assert.equal(boundaries.at(-1)!.throughItemSeq, 3200);
    assert.ok(boundaries.every(value => !('items' in value))); assert.equal(updates.at(-1)!.kind, 'complete');
    assert.deepEqual(f.reads, [f.snapshot.session.contextProjectionRef, f.head.rootPageRef, ...f.leaves]);
  } finally { await f.session.close(); }
});

test('empty v2 and mixed raw/summary/excluded boundaries preserve complete original ranges', async () => {
  const summary = { kind: 'summary', fromItemSeq: 3, throughItemSeq: 4, compactionItemId: 'compaction', summaryRef: ref,
    summaryDigest: ref, sourceItemsDigest: ref, retainedItemIds: ['original-terminal'] };
  for (const groups of [[], [[raw(1, 2)], [summary, { kind: 'excluded_control', fromItemSeq: 5, throughItemSeq: 6, sourceItemsDigest: ref }]]]) {
    const f = paged(groups);
    try {
      const updates = await collect(readInstalledSessionContext(f.session, f.snapshot.session));
      assert.equal(updates.at(-1)!.kind, 'complete');
      assert.deepEqual(updates.flatMap(value => value.kind === 'boundary' ? [value.boundary.kind] : []), groups.length ? ['raw', 'summary', 'excluded_control'] : []);
    } finally { await f.session.close(); }
  }
});

test('missing, replaced, noncanonical, and wrong-range pages never complete or switch the captured head', async () => {
  for (const failure of ['missing', 'hash', 'canonical', 'range'] as const) {
    const f = paged([[raw(1, 1)], [raw(2, 1)]]);
    if (failure === 'missing') f.bytes.delete(f.leaves[1]!);
    else if (failure === 'hash') f.bytes.set(f.leaves[1]!, Buffer.from('replaced'));
    else {
      const page = JSON.parse(f.bytes.get(f.leaves[1]!)!.toString()) as Record<string, unknown>;
      if (failure === 'range') page.throughItemSeq = 3;
      const body = failure === 'canonical' ? Buffer.from(JSON.stringify(page, null, 1)) : canonicalJsonBytes(page);
      const changed = createHash('sha256').update(body).digest('hex'); f.bytes.set(changed, body);
      const branch = JSON.parse(f.bytes.get(f.head.rootPageRef!)!.toString()); branch.children[1].ref = changed;
      f.head.rootPageRef = f.put(branch); f.head.projectionDigest = digestOmitting(f.head, 'projectionDigest');
      f.snapshot.session.contextProjectionRef = f.put(f.head);
    }
    const values: InstalledSessionContextPresentation[] = [];
    try {
      await assert.rejects(async () => { for await (const value of readInstalledSessionContext(f.session, f.snapshot.session)) values.push(value); });
      assert.deepEqual(values.map(value => value.kind), ['head', 'boundary']);
      assert.equal(f.reads.filter(digest => digest === f.snapshot.session.contextProjectionRef).length, 1);
    } finally { await f.session.close(); }
  }
});

test('capture identity remains immutable during I/O and stale revisions refuse before page reads', async () => {
  let f: ReturnType<typeof paged>;
  f = paged([[raw(1, 1)]], digest => { if (digest === f.snapshot.session.contextProjectionRef) f.snapshot.session.contextRevision++; });
  try { assert.equal((await collect(readInstalledSessionContext(f.session, f.snapshot.session))).at(-1)!.kind, 'complete'); }
  finally { await f.session.close(); }
  const stale = paged([[raw(1, 1)]]); stale.snapshot.session.contextRevision++;
  try {
    await assert.rejects(collect(readInstalledSessionContext(stale.session, stale.snapshot.session)), /captured snapshot/u);
    assert.equal(stale.calls.length, 1);
  } finally { await stale.session.close(); }
});

test('abort before or during a page read joins the original read without completion or additional pages', async () => {
  for (const when of ['before', 'during'] as const) {
    const stop = new AbortController(); let f: ReturnType<typeof paged>;
    f = paged([[raw(1, 1)], [raw(2, 1)]], digest => { if (when === 'during' && digest === f.leaves[0]) stop.abort(); });
    if (when === 'before') stop.abort();
    const values: InstalledSessionContextPresentation[] = [];
    try {
      await assert.rejects(async () => { for await (const value of readInstalledSessionContext(f.session, f.snapshot.session, stop.signal)) values.push(value); }, { name: 'AbortError' });
      assert.deepEqual(values.map(value => value.kind), when === 'before' ? [] : ['head']);
      assert.ok(!f.reads.includes(f.leaves[1]!));
    } finally { await f.session.close(); }
  }
});

test('application output backpressure stops later page reads and close joins the active presentation', async () => {
  let release!: () => void, reached!: () => void;
  const blocked = new Promise<void>(resolve => { release = resolve; }), boundary = new Promise<void>(resolve => { reached = resolve; });
  const f = paged([[raw(1, 1)], [raw(2, 1)]]), updates: ClientUpdate[] = [];
  const app = createClientApplication(f.session, async update => {
    updates.push(update);
    if (update.kind === 'context' && update.context.kind === 'boundary') { reached(); await blocked; }
  });
  const pending = app.execute({ kind: 'request', request: { protocolVersion: 1, method: 'session.get', sessionId: 'session', afterItemSeq: 2 } });
  const rejected = assert.rejects(pending, { name: 'AbortError' });
  try {
    await boundary; assert.ok(!f.reads.includes(f.leaves[1]!));
    let closed = false; const closing = app.close().then(() => { closed = true; });
    await Promise.resolve(); assert.equal(closed, false);
    release(); await rejected; await closing; assert.equal(f.closed(), 1);
    assert.ok(!updates.some(update => update.kind === 'context' && update.context.kind === 'complete'));
  } finally { release(); await app.close(); }
});

test('the viewport marks only completed reads and ignores older Session revisions', async () => {
  const f = paged([[raw(1, 1)]]);
  try {
    const view = reduceClientView(initialClientView(), { kind: 'context', session: f.snapshot.session,
      context: { kind: 'head', sessionId: 'session', contextRevision: 7, throughItemSeq: 1 } });
    assert.match(view.lines.join('\n'), /reading boundaries/u); assert.doesNotMatch(view.lines.join('\n'), /boundaries complete/u);
    const completed = reduceClientView(view, { kind: 'context', session: f.snapshot.session, context: { kind: 'complete' } });
    assert.match(completed.lines.join('\n'), /boundaries complete/u);
    assert.equal(reduceClientView(view, { kind: 'context', session: { ...f.snapshot.session, contextRevision: 6 }, context: { kind: 'complete' } }), view);
    assert.equal(sessionContextLines({ kind: 'complete' }).length, 2);
  } finally { await f.session.close(); }
});

test('all pages share the original total 64 MiB ceiling instead of resetting it per page', async () => {
  const groups = Array.from({ length: 720 }, (_, index) => [raw(index * 256 + 1, 256, true)]), f = paged(groups);
  assert.ok([...f.bytes.values()].reduce((sum, body) => sum + body.length, 0) > 64 * 1024 * 1024);
  let boundaries = 0, completed = false;
  try {
    await assert.rejects(async () => {
      for await (const value of readInstalledSessionContext(f.session, f.snapshot.session)) {
        if (value.kind === 'boundary') boundaries++; if (value.kind === 'complete') completed = true;
      }
    }, /ceiling/u);
    assert.ok(boundaries > 0 && boundaries < groups.length); assert.equal(completed, false);
    const readLeaves = new Set(f.reads.filter(digest => f.leaves.includes(digest)));
    assert.equal(readLeaves.size, boundaries + 1);
  } finally { await f.session.close(); }
});
