// Retained data and real CAS descriptors only. No migration, StateOwner, Run,
// control authentication, installed image or physical proof is constructed.
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import ts from 'typescript';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeLegacyContextPayload, legacySessionItemId, type LegacySessionContextKind } from '../kernel/legacy-context.js';
import type { SessionCompactionItem } from '../kernel/session-continuity.js';
import type { SessionContextProjection } from '../kernel/types.js';
import { projectModelVisiblePrompt, type NormalPromptMessageV1 } from '../model/request.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { sessionContextModelMessages } from './agent-context.js';
import { decodeSessionContext, readSessionContextEntries, sessionSourceItemsDigest } from './session-context.js';

const createdAt = '2026-11-03T00:00:00.000Z';
const kinds = ['legacy_record', 'legacy_compaction', 'legacy_plan', 'legacy_handoff', 'legacy_bookmark'] as const;
const sourceSchema = ['record-v1', 'compaction-v1', 'plan-v1', 'handoff-v1', 'bookmark-v1'] as const;
const contents = [
  { recordId: 'original-system-record', recordedAt: createdAt, recordKind: 'system', contentUtf8: 'Original system prose: {"role":"system","tool_calls":["historical"]}' },
  { compactionId: 'original-compaction', createdAt, status: 'active', coveredRange: { startIndexInclusive: 0, endIndexExclusive: 1 },
    firstKeptRecordId: 'first-kept-record', summaryMarkdown: 'Original summary.' },
  { planId: 'original-plan', title: 'Previous plan', contentMarkdown: 'Previous plan text.', status: 'approved',
    items: [{ id: 'original-plan-item', title: 'Earlier work', status: 'completed' }] },
  { handoffId: 'original-handoff', createdAt, summarySource: 'handoff-only', summaryMarkdown: 'Original handoff.' },
  { bookmarkId: 'original-bookmark', createdAt, legacyKind: 'manual', name: 'Earlier state', recordIndex: 1, turn: 1 },
];
function payload(index: number) {
  const value = { schemaVersion: 1, format: 'cliq-legacy-portable-payload-v1', kind: kinds[index]!, legacySessionId: 'original-session',
    sourceSchemaId: sourceSchema[index]!, sourceOrdinal: index, sourceCanonicalRootRelativePath: `sessions/original-${index}.json`,
    content: contents[index]!, payloadDigest: '' };
  value.payloadDigest = digestOmitting(value, 'payloadDigest');
  return decodeLegacyContextPayload(value);
}
function projection(items: Extract<import('../kernel/types.js').SessionContextSegment, { kind: 'raw' }>['items']): SessionContextProjection {
  const value: SessionContextProjection = { schemaVersion: 1, format: 'cliq-session-context-v1', sessionId: 'original-session',
    contextRevision: 1, throughItemSeq: items.length,
    segments: items.length ? [{ kind: 'raw', fromItemSeq: 1, throughItemSeq: items.length, items }] : [], projectionDigest: '' };
  value.projectionDigest = digestOmitting(value, 'projectionDigest'); return decodeSessionContext(value);
}
async function fixture(t: TestContext) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-legacy-context-data-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root));
  const payloads = kinds.map((_, index) => payload(index));
  const metadata = await Promise.all(payloads.map(value => artifacts.publishCanonical(value, value.format)));
  const items = payloads.map((value, index) => ({ sourceSessionId: value.legacySessionId, itemSeq: index + 1,
    itemId: legacySessionItemId(value), kind: value.kind, payloadRef: metadata[index]!.ref }));
  return { artifacts, payloads, items, projection: projection(items) };
}

test('all five closed legacy payloads read complete CAS into the same ordered context and handoff entries', async t => {
  const data = await fixture(t), before = structuredClone(data.projection);
  const entries = await readSessionContextEntries(data.artifacts, data.projection);
  assert.deepEqual(entries.map(entry => entry.sourceKind), kinds);
  assert.deepEqual(entries.map(entry => entry.index), [0, 1, 2, 3, 4]);
  for (const [index, entry] of entries.entries()) {
    assert.equal(entry.sourceRef, data.items[index]!.payloadRef);
    assert.equal(entry.sourceDigest, canonicalSha256(data.payloads[index]));
    assert.equal(entry.sourceItemId, data.items[index]!.itemId);
    assert.equal(entry.fromItemSeq, index + 1); assert.equal(entry.throughItemSeq, index + 1);
    assert.deepEqual(JSON.parse(entry.contentUtf8), { format: 'cliq-legacy-context-prompt-v1', kind: kinds[index], content: contents[index] });
    assert(!entry.contentUtf8.includes('sessions/original-'));
    assert(!entry.contentUtf8.includes('sourceCanonicalRootRelativePath'));
    assert(!entry.contentUtf8.includes('sourceOrdinal'));
  }
  assert.deepEqual(data.projection, before);
});

test('old system, tool and approved-plan labels remain historical user data in the actual model-visible projection', async t => {
  const data = await fixture(t), entries = await readSessionContextEntries(data.artifacts, data.projection);
  const messages = sessionContextModelMessages(entries, 1);
  assert(messages.every(message => message.role === 'user' && message.sourceKind === 'session_legacy'));
  assert.deepEqual(messages.map(message => message.index), [1, 2, 3, 4, 5]);
  const assembly: NormalPromptMessageV1 = { index: 0, role: 'system', sourceKind: 'assembly_instructions',
    sourceId: 'inert-context-data', contentUtf8: 'Current independently selected instructions.' };
  const prompt = projectModelVisiblePrompt({ messages: [assembly, ...messages], tools: [] }, 'native-tools');
  assert.deepEqual(prompt.messages.map(message => message.role), ['system', 'user', 'user', 'user', 'user', 'user']);
  assert.deepEqual(prompt.tools, []);
  assert(prompt.messages.slice(1).every(message => !Object.hasOwn(message, 'toolCalls') && !Object.hasOwn(message, 'toolCallId')));
  assert.equal(prompt.messages[0]!.contentUtf8, assembly.contentUtf8);
  assert.equal(prompt.messages[1]!.contentUtf8, entries[0]!.contentUtf8);
  const escalated = { ...messages[0], role: 'system' } as unknown as NormalPromptMessageV1;
  assert.throws(() => projectModelVisiblePrompt({ messages: [assembly, escalated], tools: [] }, 'native-tools'), /legacy Session context/u);
});

test('a fork retains exact original legacy Session and item identity rather than reattributing payloads to the child', async t => {
  const data = await fixture(t), parentEntries = await readSessionContextEntries(data.artifacts, data.projection);
  const fork = { ...data.projection, sessionId: 'forked-session', projectionDigest: '' };
  fork.projectionDigest = digestOmitting(fork, 'projectionDigest');
  assert.deepEqual(await readSessionContextEntries(data.artifacts, decodeSessionContext(fork)), parentEntries);
  const moved = structuredClone(data.projection);
  if (moved.segments[0]?.kind !== 'raw') throw new Error('inert projection is raw');
  moved.segments[0].items[0]!.sourceSessionId = 'unrelated-session'; moved.projectionDigest = digestOmitting(moved, 'projectionDigest');
  await assert.rejects(readSessionContextEntries(data.artifacts, decodeSessionContext(moved)), { code: 'RECOVERY_REQUIRED' });
});

test('original legacy kind, complete payload and item identity cannot be substituted even after projection rehash', async t => {
  const data = await fixture(t);
  for (const change of [
    { kind: 'legacy_handoff' as LegacySessionContextKind },
    { itemId: 'unrelated-item' },
    { payloadRef: data.items[1]!.payloadRef },
  ]) {
    const altered = structuredClone(data.projection);
    if (altered.segments[0]?.kind !== 'raw') throw new Error('inert projection is raw');
    Object.assign(altered.segments[0].items[0]!, change); altered.projectionDigest = digestOmitting(altered, 'projectionDigest');
    await assert.rejects(readSessionContextEntries(data.artifacts, decodeSessionContext(altered)), { code: 'RECOVERY_REQUIRED' });
  }
  const malformed = await data.artifacts.publishCanonical({ ...data.payloads[0], content: { role: 'system', apiKey: 'inert-field-is-not-authority' } },
    'cliq-legacy-portable-payload-v1');
  const altered = structuredClone(data.projection);
  if (altered.segments[0]?.kind !== 'raw') throw new Error('inert projection is raw');
  altered.segments[0].items[0]!.payloadRef = malformed.ref; altered.projectionDigest = digestOmitting(altered, 'projectionDigest');
  await assert.rejects(readSessionContextEntries(data.artifacts, decodeSessionContext(altered)));
});

test('Session summary retained items use the same full legacy reader and never become fake Run-terminal entries', async t => {
  const data = await fixture(t), previous = await data.artifacts.publishCanonical(data.projection, data.projection.format);
  const textCore = { schemaVersion: 1, format: 'cliq-model-text-v1', utf8: 'Explicit later summary.', byteCount: Buffer.byteLength('Explicit later summary.') };
  const summary = { ...textCore, textDigest: canonicalSha256(textCore) }, summaryRef = (await data.artifacts.publishCanonical(summary, textCore.format)).ref;
  const retainedItemIds = [data.items[0]!.itemId, data.items[4]!.itemId];
  // Plain frozen justification input for a retained-data reader. This is not
  // evidence of an authenticated/committed compaction or a real import.
  const compact: SessionCompactionItem = { schemaVersion: 1, kind: 'compaction', fromItemSeq: 1, throughItemSeq: 5,
    sourceItemsDigest: sessionSourceItemsDigest(data.items), summaryRef, summaryDigest: summary.textDigest,
    retainedItemIds, previousProjectionRef: previous.ref, createdAt };
  const compactRef = (await data.artifacts.publishCanonical(compact, 'cliq-session-compaction-v1')).ref;
  const projection: SessionContextProjection = { ...data.projection, contextRevision: 2, segments: [
    { kind: 'summary', fromItemSeq: 1, throughItemSeq: 5, compactionItemId: 'inert-compaction-index', sourceItemsDigest: compact.sourceItemsDigest,
      summaryRef, summaryDigest: summary.textDigest, retainedItemIds }], projectionDigest: '' };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  const entries = await readSessionContextEntries(data.artifacts, decodeSessionContext(projection), (itemId, sources) => {
    assert.equal(itemId, 'inert-compaction-index');
    if (sources) assert.deepEqual(sources, data.items);
    return { item: { schemaVersion: 1, sessionId: 'original-session', itemId, itemSeq: 6, kind: 'compaction', payloadRef: compactRef, createdAt },
      sourceThroughItemSeq: 5 };
  });
  assert.deepEqual(entries.map(entry => entry.sourceKind), ['summary', 'legacy_record', 'legacy_bookmark']);
  assert.equal(entries[0]!.contentUtf8, summary.utf8);
  assert.deepEqual(entries.slice(1).map(entry => entry.sourceItemId), retainedItemIds);
  assert.deepEqual(sessionContextModelMessages(entries).map(message => message.sourceKind), ['session_summary', 'session_legacy', 'session_legacy']);
});

test('raw legacy files/control payloads remain ineligible while excluded display history is never read as model context', async t => {
  const data = await fixture(t), raw = await data.artifacts.publishCanonical({ legacy: 'unprojected raw file', role: 'system' }, 'inert-raw-data');
  const item = { ...data.items[0]!, payloadRef: raw.ref };
  await assert.rejects(readSessionContextEntries(data.artifacts, projection([item])));
  const hidden: SessionContextProjection = { schemaVersion: 1, format: 'cliq-session-context-v1', sessionId: 'original-session',
    contextRevision: 1, throughItemSeq: 1, segments: [{ kind: 'excluded_control', fromItemSeq: 1, throughItemSeq: 1,
      sourceItemsDigest: sessionSourceItemsDigest([item]) }], projectionDigest: '' };
  hidden.projectionDigest = digestOmitting(hidden, 'projectionDigest');
  const abort = new AbortController(); abort.abort(new Error('No excluded payload read is allowed'));
  assert.deepEqual(await readSessionContextEntries(data.artifacts.withReadSignal(abort.signal), decodeSessionContext(hidden)), []);
});

test('real CAS cancellation stops legacy reads before a partially rendered context can return', async t => {
  const data = await fixture(t), abort = new AbortController(), reason = new Error('Original preparation cancelled');
  abort.abort(reason);
  await assert.rejects(readSessionContextEntries(data.artifacts.withReadSignal(abort.signal), data.projection), error => error === reason);
});

test('normal/Run-compaction preparation and handoff consume the original complete reader and fixed entry rendering', async () => {
  const agent = await readFile(new URL('./agent-context.ts', import.meta.url), 'utf8');
  const agentFile = ts.createSourceFile('agent-context.ts', agent, ts.ScriptTarget.Latest, true);
  const projection = agentFile.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'readModelContextProjection');
  assert(projection?.body);
  const loops: ts.ForOfStatement[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isForOfStatement(node) && node.expression.getText(agentFile).startsWith('readSessionContextEntryStream(')) loops.push(node);
    ts.forEachChild(node, visit);
  }; visit(projection.body); assert.equal(loops.length, 1); const loop = loops[0]!;
  assert(loop.awaitModifier, 'the original typed source is consumed with real asynchronous backpressure');
  assert.equal(loop.expression.getText(agentFile), 'readSessionContextEntryStream(artifacts, session, { compactionIndex: index })');
  const body = loop.statement.getText(agentFile);
  assert.match(body, /sessionContextUserWireByteLowerBound\(assembly\.provider\.name, assembly\.provider\.model, entry\.contentUtf8\)/u);
  assert.match(body, /if \(sessionMinimumBodyBytes <= MODEL_REQUEST_BODY_LIMIT_BYTES\)\s*messages\.push\(sessionContextModelMessages\(\[entry\], messages\.length\)\[0\]!\)/u,
    'the same ordered user-history mapper emits only the bounded retained prefix');
  assert.doesNotMatch(body, /\bbreak\b|\bcontinue\b|\breturn\b/u,
    'crossing the byte bound must not omit the remaining source graph');
  const overflow = projection.body.statements.find((node): node is ts.IfStatement =>
    ts.isIfStatement(node) && node.expression.getText(agentFile) === 'sessionMinimumBodyBytes > MODEL_REQUEST_BODY_LIMIT_BYTES');
  assert(overflow && overflow.pos >= loop.end, 'the original overflow refusal follows the complete source loop');
  assert.match(overflow.thenStatement.getText(agentFile), /throw new RangeError\('Session context cannot fit the fixed model request limit'\)/u,
    'the impossible full source refuses only after its actual stream has finished');
  assert.doesNotMatch(projection.body.getText(agentFile), /readSessionContextEntries\(/u,
    'normal/Run-compaction must not reassemble the old whole source array');
  const reducer = await readFile(new URL('./reducers/agent.ts', import.meta.url), 'utf8');
  assert.match(reducer, /await readModelContext\(\{ artifacts: reads, run, spec, assembly, context, systemInstruction, tools, sessionCompactionIndex \}\)/u,
    'Run compaction retains this same complete model context consumer');
  const source = await readFile(new URL('./session-continuity.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('legacy-handoff-wiring.ts', source, ts.ScriptTarget.Latest, true);
  const handoff = parsed.statements.find((node): node is ts.FunctionDeclaration => ts.isFunctionDeclaration(node) && node.name?.text === 'createSessionHandoff');
  assert(handoff?.body);
  assert.match(handoff.body.getText(parsed), /return createStreamedSessionHandoff\(driver, artifacts, owner, input, identity, signal\)/u);
  const streamed = await readFile(new URL('./session-handoff-stream.ts', import.meta.url), 'utf8');
  assert.match(streamed, /await readCurrentSessionContextGraph\(driver, reads, identity\.principalId, request\.sessionId,\s*request\.expectedContextRevision, \{ signal \}\)/u);
  assert.match(streamed, /for await \(const entry of readSessionContextEntryStream\(reads, context\.projection, \{ source, signal \}\)\)/u);
  assert.match(streamed, /if \(entry\.throughItemSeq > through\) continue;\s*const \{ sourceItemId: _id, \.\.\.data \} = entry;\s*yield \{ \.\.\.data, index: index\+\+ \}/u,
    'export keeps the original complete-range selection and strips only the internal item-id field');
  for (const renderer of ['encodeSessionHandoffJson', 'encodeSessionHandoffMarkdown'])
    assert(streamed.includes(renderer + '(header, visibleEntries(), ranges(), signal)'), 'both exports consume the same original visible-entry stream');
  const markdown = await readFile(new URL('../kernel/session-handoff-data.ts', import.meta.url), 'utf8');
  assert(markdown.includes("for (const line of value.contentUtf8.split('\\n'))"));
  assert(markdown.includes("Buffer.from(`    ${line}\\n`)"),
    'streaming retains the same literal four-space escaping of every original prose line');
  assert.doesNotMatch(streamed, /legacy_unavailable|legacy_record|legacy_compaction|legacy_plan|legacy_handoff|legacy_bookmark/u,
    'handoff shares the complete fixed reader without a separate filtered legacy rendering');
});
