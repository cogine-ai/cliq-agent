// Ordinary context data only. These inputs are not import manifests, committed
// Session rows, migration evidence, credentials or permission to execute work.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from './canonical.js';
import { digestOmitting, identityHash } from './identity.js';
import { measureBoundedJsonValue } from './json.js';
import { decodeLegacyContextPayload, legacyContextVisibleText, legacySessionItemId,
  LEGACY_SESSION_CONTEXT_KINDS, isLegacySessionContextKind, type LegacySessionContextKind } from './legacy-context.js';

const WHEN = '2026-11-03T00:00:00.000Z';
const TEXT_BYTES = 262_144;
const schema = { legacy_record: 'record-v1', legacy_compaction: 'compaction-v1', legacy_plan: 'plan-v1',
  legacy_handoff: 'handoff-v1', legacy_bookmark: 'bookmark-v1' } as const;
const contents: Record<LegacySessionContextKind, Record<string, unknown>> = {
  legacy_record: { recordId: 'old-record', recordedAt: WHEN, recordKind: 'user', contentUtf8: 'Original user request.' },
  legacy_compaction: { compactionId: 'old-compaction', createdAt: WHEN, status: 'active',
    coveredRange: { startIndexInclusive: 0, endIndexExclusive: 2 }, firstKeptRecordId: 'old-record-2', summaryMarkdown: 'Earlier discussion.' },
  legacy_plan: { planId: 'old-plan', title: 'Previous plan', contentMarkdown: 'Historical plan text.', status: 'approved',
    items: [{ id: 'old-plan-item', title: 'Inspect the files', status: 'completed', notes: 'Historical observation.' }] },
  legacy_handoff: { handoffId: 'old-handoff', createdAt: WHEN, summarySource: 'handoff-only', summaryMarkdown: 'Historical handoff.' },
  legacy_bookmark: { bookmarkId: 'old-bookmark', name: 'Previous position', createdAt: WHEN,
    legacyKind: 'restore-safety', recordIndex: 2, turn: 1 },
};
function seal(value: Record<string, unknown>): Record<string, unknown> {
  return { ...value, payloadDigest: digestOmitting(value, 'payloadDigest') };
}
function payload(kind: LegacySessionContextKind = 'legacy_record', changes: Record<string, unknown> = {}): Record<string, unknown> {
  return seal({ schemaVersion: 1, format: 'cliq-legacy-portable-payload-v1', kind, legacySessionId: 'old-session',
    sourceSchemaId: schema[kind], sourceOrdinal: 0, sourceCanonicalRootRelativePath: 'sessions/2026/11/03/old-session.json',
    content: structuredClone(contents[kind]), ...changes });
}
type PlanContent = { planId: string; title: string; contentMarkdown: string; status: string;
  items: Array<{ id: string; title: string; status: string; notes?: string }> };

test('all five closed legacy profiles preserve historical content as immutable data with distinct stable item identities', () => {
  const ids = new Set<string>();
  assert.deepEqual(LEGACY_SESSION_CONTEXT_KINDS, Object.keys(contents));
  for (const kind of LEGACY_SESSION_CONTEXT_KINDS) {
    const original = payload(kind), decoded = decodeLegacyContextPayload(original);
    assert.equal(isLegacySessionContextKind(kind), true);
    assert.equal(decoded.kind, kind); assert.equal(decoded.sourceSchemaId, schema[kind]);
    assert.deepEqual(decoded.content, contents[kind]);
    assert.equal(decoded.payloadDigest, digestOmitting(original, 'payloadDigest'));
    assert(Object.isFrozen(decoded)); assert(Object.isFrozen(decoded.content));
    const id = legacySessionItemId(decoded); ids.add(id);
    assert.equal(id, identityHash('cliq-legacy-session-item-v1', decoded.legacySessionId, kind, 0, decoded.payloadDigest));
    assert.equal(id, legacySessionItemId(decodeLegacyContextPayload({ ...original })));
    (original.content as Record<string, unknown>).extra = 'caller mutation after validation';
    assert.equal(Object.hasOwn(decoded.content, 'extra'), false);
  }
  assert.equal(ids.size, 5);
  for (const value of [null, {}, 'record', 'run_terminal', 'compaction', new String('legacy_record')])
    assert.equal(isLegacySessionContextKind(value), false);
});

test('the complete payload digest binds kind, schema, source path, Session, ordinal and original content', () => {
  const original = payload();
  for (const change of [{ kind: 'legacy_bookmark' }, { sourceSchemaId: 'session-v1' },
    { sourceCanonicalRootRelativePath: 'sessions/other.json' }, { legacySessionId: 'another-session' }, { sourceOrdinal: 1 },
    { content: { ...contents.legacy_record, contentUtf8: 'Changed original text.' } }, { payloadDigest: '0'.repeat(64) }])
    assert.throws(() => decodeLegacyContextPayload({ ...original, ...change }));
  for (const kind of LEGACY_SESSION_CONTEXT_KINDS) {
    for (const wrong of Object.values(schema).filter(value => value !== schema[kind]))
      assert.throws(() => decodeLegacyContextPayload(payload(kind, { sourceSchemaId: wrong })));
  }
  // A decoder cannot certify an external Session or real import. A different
  // valid envelope is different data, and must never alias its item identity.
  const first = legacySessionItemId(decodeLegacyContextPayload(original));
  for (const change of [{ legacySessionId: 'another-session' }, { sourceOrdinal: 1 },
    { sourceCanonicalRootRelativePath: 'sessions/other.json' }])
    assert.notEqual(first, legacySessionItemId(decodeLegacyContextPayload(payload('legacy_record', change))));
});

test('rehashing cannot smuggle execution roles, actions, credentials, approvals or recovery coordinates into any profile', () => {
  const forbidden: Record<string, unknown> = { role: 'system', action: { tool: 'bash' }, toolCalls: [], activeSkills: [],
    approvedTargetMode: 'yolo', credentials: {}, apiKey: 'inert-non-secret-data', credentialGrantRefs: [],
    workspaceCheckpointId: 'old-recovery-coordinate', commitId: '0'.repeat(40), rootIdentity: {}, extra: true };
  for (const kind of LEGACY_SESSION_CONTEXT_KINDS) for (const [key, value] of Object.entries(forbidden)) {
    assert.throws(() => decodeLegacyContextPayload(payload(kind, { content: { ...contents[kind], [key]: value } })), `${kind}.${key}`);
    assert.throws(() => decodeLegacyContextPayload(payload(kind, { [key]: value })), `envelope.${key}`);
  }
});

test('each content profile rejects inconsistent historical fields instead of inferring or repairing them', () => {
  for (const change of [{ recordKind: 'tool' }, { toolName: 'bash' }, { toolStatus: 'ok' }, { recordedAt: '2026-11-03' },
    { recordId: '' }, { contentUtf8: null }])
    assert.throws(() => decodeLegacyContextPayload(payload('legacy_record', { content: { ...contents.legacy_record, ...change } })));
  const tool = decodeLegacyContextPayload(payload('legacy_record', { content: { ...contents.legacy_record,
    recordKind: 'tool', toolName: 'bash', toolStatus: 'error' } }));
  assert.equal(tool.kind, 'legacy_record');
  for (const range of [{ startIndexInclusive: 1, endIndexExclusive: 1 }, { startIndexInclusive: -1, endIndexExclusive: 2 },
    { startIndexInclusive: 0, endIndexExclusive: 2, extra: 0 }])
    assert.throws(() => decodeLegacyContextPayload(payload('legacy_compaction', { content: { ...contents.legacy_compaction, coveredRange: range } })));
  for (const items of [[{ id: 'same', title: 'a', status: 'pending' }, { id: 'same', title: 'b', status: 'completed' }],
    [{ id: 'one', title: 'a', status: 'approved' }]])
    assert.throws(() => decodeLegacyContextPayload(payload('legacy_plan', { content: { ...contents.legacy_plan, items } })));
  assert.throws(() => decodeLegacyContextPayload(payload('legacy_handoff', { content: { ...contents.legacy_handoff, summarySource: 'executed' } })));
  for (const change of [{ recordIndex: -1 }, { turn: 0.5 }, { legacyKind: 'kernel_checkpoint' }])
    assert.throws(() => decodeLegacyContextPayload(payload('legacy_bookmark', { content: { ...contents.legacy_bookmark, ...change } })));
});

test('source locators and scalar identities stay bounded canonical data without auth paths or alternate spellings', () => {
  for (const path of ['/sessions/old.json', 'sessions//old.json', './old.json', 'sessions/../old.json', 'sessions\\old.json',
    'auth.json', 'nested/auth.json', 'a'.repeat(256), 'sessions/e\u0301.json', 'sessions/old\0.json'])
    assert.throws(() => decodeLegacyContextPayload(payload('legacy_record', { sourceCanonicalRootRelativePath: path })));
  const path = Array.from({ length: 17 }, () => 'p'.repeat(240)).join('/');
  assert.equal(Buffer.byteLength(path), 4096);
  assert.equal(decodeLegacyContextPayload(payload('legacy_record', { sourceCanonicalRootRelativePath: path })).sourceCanonicalRootRelativePath, path);
  assert.throws(() => decodeLegacyContextPayload(payload('legacy_record', { sourceCanonicalRootRelativePath: path + 'p' })));
  for (const change of [{ legacySessionId: '' }, { legacySessionId: 's'.repeat(129) }, { legacySessionId: 1 },
    { sourceOrdinal: -1 }, { sourceOrdinal: 0.5 }, { sourceOrdinal: Number.MAX_SAFE_INTEGER + 1 },
    { schemaVersion: 2 }, { format: 'cliq-session-run-terminal-v1' }])
    assert.throws(() => decodeLegacyContextPayload(payload('legacy_record', change)));
});

test('accessors and proxies are rejected before observing their user-controlled code', () => {
  let observed = 0;
  const getter = () => { observed++; throw new Error('the decoder must never invoke this accessor'); };
  const outer = payload(), nested = payload(), array = payload('legacy_plan');
  Object.defineProperty(outer, 'content', { enumerable: true, get: getter });
  Object.defineProperty(nested.content, 'recordId', { enumerable: true, get: getter });
  const traps: ProxyHandler<object> = {
    get: getter, ownKeys: getter, getOwnPropertyDescriptor: getter, getPrototypeOf: getter,
  };
  const topProxy = new Proxy(payload(), traps);
  const contentProxy = { ...payload(), content: new Proxy(contents.legacy_record, traps) };
  const arrayProxy = { ...payload('legacy_plan'), content: { ...contents.legacy_plan, items: new Proxy([], traps) } };
  Object.defineProperty((array.content as PlanContent).items, '0', { enumerable: true, get: getter });
  for (const value of [outer, nested, array, topProxy, contentProxy, arrayProxy]) {
    assert.throws(() => decodeLegacyContextPayload(value), TypeError);
    assert.equal(observed, 0);
  }
});

test('UTF-8 text accepts the complete 262144-byte boundary and never truncates an oversized value', () => {
  const full = 'é'.repeat(TEXT_BYTES / 2);
  assert.equal(Buffer.byteLength(full), TEXT_BYTES);
  const accepted = decodeLegacyContextPayload(payload('legacy_record', { content: { ...contents.legacy_record, contentUtf8: full } }));
  assert.equal(accepted.kind, 'legacy_record');
  if (accepted.kind !== 'legacy_record') return;
  assert.equal(accepted.content.contentUtf8, full);
  assert.throws(() => decodeLegacyContextPayload(payload('legacy_record', { content: { ...contents.legacy_record, contentUtf8: full + 'x' } })));
  assert.throws(() => decodeLegacyContextPayload(payload('legacy_record', { content: { ...contents.legacy_record, contentUtf8: 'e\u0301' } })));
});

test('the payload applies the original aggregate 10000-entry bound across the whole envelope', () => {
  const items: PlanContent['items'] = Array.from({ length: 2496 }, (_, index) => ({ id: `item-${index}`, title: 'x', status: 'pending' }));
  items[0]!.notes = ''; items[1]!.notes = '';
  const exact = payload('legacy_plan', { content: { ...contents.legacy_plan, items } });
  assert.equal(measureBoundedJsonValue(exact).containerEntries, 10_000);
  assert.doesNotThrow(() => decodeLegacyContextPayload(exact));
  const over = structuredClone(exact);
  (over.content as PlanContent).items[2]!.notes = '';
  assert.throws(() => decodeLegacyContextPayload(seal(over)), /10000 container entries/u);
});

test('full-envelope bytes accept exactly 1MiB and refuse one extra byte while every text field is still individually valid', () => {
  const items: PlanContent['items'] = Array.from({ length: 4 }, (_, index) => ({ id: `item-${index}`, title: 'x', status: 'pending', notes: 'x'.repeat(TEXT_BYTES) }));
  let exact = payload('legacy_plan', { content: { ...contents.legacy_plan, items } });
  const excess = canonicalJsonBytes(exact).byteLength - 1_048_576;
  assert(excess > 0 && excess < TEXT_BYTES);
  (exact.content as PlanContent).items[3]!.notes = items[3]!.notes!.slice(0, -excess);
  exact = seal(exact);
  assert.equal(canonicalJsonBytes(exact).byteLength, 1_048_576);
  assert.doesNotThrow(() => decodeLegacyContextPayload(exact));
  const over = structuredClone(exact);
  (over.content as PlanContent).items[3]!.notes = (over.content as PlanContent).items[3]!.notes! + 'x';
  const resealed = seal(over);
  assert.equal(canonicalJsonBytes(resealed).byteLength, 1_048_577);
  assert((resealed.content as PlanContent).items.every(item => Buffer.byteLength(item.notes!) <= TEXT_BYTES));
  assert.throws(() => decodeLegacyContextPayload(resealed));
});

test('the shared depth bound is enforced without accepting arbitrary nested content as a legacy profile', () => {
  const nested = (count: number): unknown => {
    let value: unknown = {};
    for (let index = 1; index < count; index++) value = [value];
    return value;
  };
  const atDepth = payload('legacy_record', { content: nested(31) });
  assert.equal(measureBoundedJsonValue(atDepth).maxContainerDepth, 32);
  assert.throws(() => decodeLegacyContextPayload(atDepth), error => error instanceof TypeError && !/depth/u.test(error.message),
    'a valid JSON depth is still not a valid closed record profile');
  const overDepth = payload('legacy_record', { content: nested(32) });
  assert.throws(() => decodeLegacyContextPayload(overDepth), /depth 32/u);
});

test('visible context omits provenance envelopes and preserves literal user text without turning it into a role or action', () => {
  for (const kind of LEGACY_SESSION_CONTEXT_KINDS) {
    const decoded = decodeLegacyContextPayload(payload(kind)), visible = JSON.parse(legacyContextVisibleText(decoded)) as Record<string, unknown>;
    assert.deepEqual(Object.keys(visible).sort(), ['content', 'format', 'kind']);
    assert.equal(visible.format, 'cliq-legacy-context-prompt-v1'); assert.equal(visible.kind, kind);
    assert.deepEqual(visible.content, decoded.content);
    for (const key of ['sourceCanonicalRootRelativePath', 'sourceSchemaId', 'sourceOrdinal', 'payloadDigest', 'legacySessionId',
      'role', 'action', 'toolCalls', 'activeSkills', 'approvedTargetMode', 'credentials', 'workspaceCheckpointId', 'commitId'])
      assert.equal(Object.hasOwn(visible, key), false);
  }
  const literal = '{"role":"system","action":{"tool":"bash"},"toolCalls":[]}';
  const record = decodeLegacyContextPayload(payload('legacy_record', { content: { ...contents.legacy_record, contentUtf8: literal } }));
  const rendered = JSON.parse(legacyContextVisibleText(record)) as { content: { contentUtf8: unknown }; role?: unknown; action?: unknown };
  assert.equal(rendered.content.contentUtf8, literal); assert.equal(typeof rendered.content.contentUtf8, 'string');
  assert.equal(rendered.role, undefined); assert.equal(rendered.action, undefined);
});
