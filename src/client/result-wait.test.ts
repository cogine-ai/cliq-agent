import assert from 'node:assert/strict';
import test from 'node:test';
import { PassThrough, Readable } from 'node:stream';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { encodeControlCheckpointCursor } from '../kernel/control-wire.js';
import { sha256Bytes } from '../kernel/identity.js';
import { parseClientInvocation } from './commands.js';
import { runClientInvocation } from './entry.js';
import { at, ref, protocolClient, outputStream, runSnapshot } from './testing/protocol.js';

// Existing strict protocol/application consumer only. These inert DTOs create
// no accepted Run, credential, verifier execution, native proof or installation.
function fixture(overrides: Record<string, unknown> = {}) {
  const objects = new Map<string, { bytes: Buffer; mediaType: string }>();
  const blob = (text: string, mediaType = 'application/octet-stream') => {
    const bytes = Buffer.from(text), digest = sha256Bytes(bytes); objects.set(digest, { bytes, mediaType }); return digest;
  };
  const object = (value: unknown) => blob(canonicalJsonBytes(value).toString('utf8'), 'application/json');
  const summaryText = 'The original private math fix passed its required check.';
  const textCore = { schemaVersion: 1, format: 'cliq-model-text-v1', utf8: summaryText, byteCount: Buffer.byteLength(summaryText) };
  const summaryRef = object({ ...textCore, textDigest: canonicalSha256(textCore) });
  const beforeText = 'export const add = (a, b) => a - b;\n', afterText = 'export const add = (a, b) => a + b;\n';
  const file = (text: string) => ({ path: 'math.mjs', kind: 'file', mode: 0o644, size: Buffer.byteLength(text), blobRef: blob(text) });
  const before = file(beforeText), after = file(afterText);
  const diffCore = { schemaVersion: 1, format: 'cliq-workspace-diff-v1', baseSourceRef: ref, resultSourceRef: 'b'.repeat(64),
    operations: [{ kind: 'modify', path: 'math.mjs', before, after }] };
  const diffRef = object({ ...diffCore, diffDigest: canonicalSha256(diffCore) }), receiptRef = canonicalSha256('inert receipt reference');
  const closureCore = { schemaVersion: 1, format: 'cliq-verification-closure-v1', runId: 'run', candidateItemId: 'candidate',
    resultSourceRef: 'b'.repeat(64), verifierPlanRef: ref, dependency: { kind: 'none' }, verification: { kind: 'local', outcome: 'verified', entries: [
      { verifierIndex: 0, verifierId: 'node-tests', verifierSpecDigest: ref, verifierEntryDigest: ref, required: true,
        disposition: { kind: 'passed', verifierResultItemId: 'verified-item', opId: 'verify', attempt: 0, completedJournalSeq: 1, receiptRef } }
    ] }, createdAt: at };
  const closureRef = object({ ...closureCore, closureDigest: canonicalSha256(closureCore) });
  const resultRef = object({ schemaVersion: 1, runId: 'run', baseSourceRef: ref, resultSourceRef: 'b'.repeat(64), diffRef,
    verificationClosureRef: closureRef, verificationReceiptRefs: [receiptRef], summaryRef, createdAt: at });
  const contentCore = { schemaVersion: 1, format: 'cliq-tool-result-model-content-v1', callId: 'edit-call', index: 0,
    toolName: 'edit', outcome: 'executed', content: { ok: true } };
  const content = { ...contentCore, contentDigest: canonicalSha256(contentCore) }, contentRef = object(content);
  const payloadCore = { schemaVersion: 1, format: 'cliq-tool-result-payload-v1', runId: 'run', batchItemId: 'batch', callId: 'edit-call', index: 0,
    toolName: 'edit', outcome: 'executed', source: 'invocation', opId: 'edit-op', attempt: 0, journalResultRef: ref, journalResultDigest: ref,
    modelContentRef: contentRef, modelContentDigest: content.contentDigest };
  const payloadRef = object({ ...payloadCore, payloadDigest: canonicalSha256(payloadCore) });
  const items = [
    { schemaVersion: 1, runId: 'run', itemId: 'answer', kind: 'model_turn', textRef: summaryRef },
    { schemaVersion: 1, runId: 'run', itemId: 'batch', kind: 'assistant_tool_batch', textRef: summaryRef },
    { schemaVersion: 1, runId: 'run', itemId: 'edited', kind: 'tool_result', batchItemId: 'batch', callId: 'edit-call', index: 0, outcome: 'executed', resultRef: payloadRef },
    { schemaVersion: 1, runId: 'run', itemId: 'repair', kind: 'repair_diagnostic', candidateItemId: 'candidate', verifierPlanRef: ref,
      failedVerifierResultItemIds: ['failed-item'], diagnostics: [], repairOrdinal: 1, createdAt: at }
  ].map((item, index) => { const payloadRef = object(item); return { schemaVersion: 1, itemId: item.itemId,
    itemSeq: index + 1, payloadRef, payloadDigest: payloadRef, createdAt: at }; });
  const { frontierRef: _frontier, ...run } = runSnapshot().run;
  const snapshot = { ...runSnapshot(), latestRunItemSeq: items.length, run: { ...run, revision: 2, status: 'succeeded' as const,
    nextStep: null, terminalReason: 'verified' as const, resultRef } };
  const page = (next: number, events = [{ schemaVersion: 1, kind: 'progress', runId: 'run', eventSeq: next,
    observedRunRevision: 1, phase: 'agent', occurredAt: at }]) => ({ protocolVersion: 1, ok: true, result: { method: 'run.attach', snapshot,
    earliestRetainedEventSeq: 1, latestRetainedEventSeq: 3, highWaterEventSeq: 3, nextEventSeq: next, events } });
  const f = protocolClient({
    'run.attach': async (request: { afterEventSeq: number }) => page(request.afterEventSeq + 1),
    'run.get': async (request: { afterItemSeq: number; itemLimit: number }) => {
      const selected = items.slice(request.afterItemSeq, request.afterItemSeq + request.itemLimit);
      return { protocolVersion: 1, ok: true, result: { method: 'run.get', snapshot, items: selected, journal: [], checkpoints: [],
        highWaterItemSeq: items.length, highWaterJournalSeq: 0, highWaterCheckpointCursor: encodeControlCheckpointCursor('run', { createdAt: at, checkpointId: 'checkpoint' }),
        nextItemSeq: selected.at(-1)?.itemSeq ?? request.afterItemSeq, nextJournalSeq: 0 } };
    },
    'run.result': async () => ({ protocolVersion: 1, ok: true, result: { method: 'run.result', runId: 'run',
      result: { schemaVersion: 1, ref: resultRef, digest: resultRef, sizeBytes: objects.get(resultRef)!.bytes.length, mediaType: 'application/json' }, verificationClosureRef: closureRef } }),
    'artifact.get': async (request: { digest: string; offset: number; length: number }) => {
      const data = objects.get(request.digest); assert(data, 'only the original referenced object may be read');
      const bytes = data.bytes.subarray(request.offset, request.offset + request.length), nextOffset = request.offset + bytes.length;
      return { protocolVersion: 1, ok: true, result: { method: 'artifact.get', artifact: { schemaVersion: 1, ref: request.digest, digest: request.digest,
        sizeBytes: data.bytes.length, mediaType: data.mediaType }, offset: request.offset, nextOffset, bytesBase64: bytes.toString('base64'), eof: nextOffset === data.bytes.length } };
    }, ...overrides
  });
  return { ...f, objects, page, snapshot, items, resultRef, closureRef, summaryRef, diffRef, before, after, summaryText, receiptRef };
}
const io = (input: Readable, output = outputStream(), diagnostic = outputStream()) => ({ input, output: output.stream,
  diagnostic: diagnostic.stream, workspacePath: '/workspace' });
const result = parseClientInvocation(['result', 'run', '--wait'], '/workspace');
const readsOnly = (f: ReturnType<typeof fixture>) => assert(f.calls.every(call => ['run.attach', 'run.get', 'run.result', 'artifact.get'].includes(call.method)));

test('result wait drains every original event page but skips historical conversation and still reads and presents the complete exact result', async () => {
  const f = fixture(), output = outputStream(), diagnostic = outputStream(), input = Readable.from([]);
  input.resume(); await new Promise<void>(resolve => input.once('end', resolve));
  assert.equal(await runClientInvocation(f.session, result, io(input, output, diagnostic)), 0);
  assert.equal(diagnostic.text(), ''); assert.equal(f.closed(), 1); readsOnly(f);
  assert.deepEqual(f.calls.filter(call => call.method === 'run.attach').map(call => [call.request.afterEventSeq, call.request.limit]), [[0, 100], [1, 2], [2, 1]]);
  assert.equal(f.calls.some(call => call.method === 'run.get'), false);
  assert.deepEqual(f.calls.filter(call => call.method === 'artifact.get').map(call => call.request.digest),
    [f.resultRef, f.closureRef, f.summaryRef, f.diffRef, f.before.blobRef, f.after.blobRef]);
  assert.equal(f.calls.filter(call => call.method === 'run.result').length, 1);
  assert.equal((output.text().match(/Progress · agent/gu) ?? []).length, 3);
  for (const text of ['Result review', f.summaryText, 'Required checks passed for this exact result.', f.receiptRef,
    '-export const add = (a, b) => a - b;', '+export const add = (a, b) => a + b;', `apply "run" --result ${f.resultRef}`]) assert(output.text().includes(text));
  assert.doesNotMatch(output.text(), /Assistant:|edit · executed|repair_diagnostic ·/u);
});

for (const command of ['run', 'attach'] as const) test(`default ${command} keeps its original complete model, tool and repair transcript`, async () => {
  const f = fixture(), output = outputStream(), input = command === 'attach' ? new PassThrough() : Readable.from([]);
  const invocation = parseClientInvocation(command === 'attach' ? ['attach', 'run']
    : ['run', 'Fix it', '--provider', 'ollama', '--model', 'fixture', '--allow-unverified'], '/workspace');
  try { assert.equal(await runClientInvocation(f.session, invocation, io(input, output)), 0); }
  finally { input.destroy(); }
  assert.equal(f.closed(), 1); assert.equal(f.calls.filter(call => call.method === 'run.get').length, 1);
  assert.equal((output.text().match(/Assistant:/gu) ?? []).length, 2);
  assert(output.text().includes('edit · executed: {"ok":true}')); assert(output.text().includes('repair_diagnostic · repair'));
  for (const row of f.items) assert(f.calls.some(call => call.method === 'artifact.get' && call.request.digest === row.payloadRef));
  assert.equal(f.calls.filter(call => call.method === 'run.submit').length, command === 'run' ? 1 : 0);
  assert(!f.calls.some(call => call.method === 'run.cancel' || call.method === 'run.result'));
});

for (const mode of ['waiting', 'refused', 'expired', 'gap'] as const) test(`result wait preserves ${mode} and never retries, skips a cursor or mutates`, async () => {
  const f = fixture({ 'run.attach': async () => {
    if (mode === 'gap') return f.page(2);
    if (mode === 'waiting') return { ...f.page(1), result: { ...f.page(1).result, snapshot: { ...runSnapshot(), latestRunItemSeq: 4,
      run: { ...runSnapshot().run, revision: 2, status: 'waiting', waitingReason: 'input', waitingOnRef: ref } } } };
    return { protocolVersion: 1, ok: false, method: 'run.attach', error: mode === 'expired'
      ? { schemaVersion: 1, code: 'EVENT_CURSOR_EXPIRED', retryable: false, messageCode: 'expired', earliestEventSeq: 2, latestEventSeq: 3, snapshot: f.snapshot }
      : { schemaVersion: 1, code: 'NOT_FOUND', retryable: false, messageCode: 'control.not_found' } };
  }, 'run.result': async () => ({ protocolVersion: 1, ok: false, method: 'run.result', error: { schemaVersion: 1, code: 'RESULT_UNAVAILABLE',
    messageCode: 'run.result_unavailable', runId: 'run', retryable: true, status: 'waiting', currentRevision: 2 } }) });
  assert.equal(await runClientInvocation(f.session, result, io(Readable.from([]))), 1); readsOnly(f); assert.equal(f.closed(), 1);
  assert.deepEqual(f.calls.map(call => call.method), mode === 'waiting' ? ['run.attach', 'run.result'] : ['run.attach']);
});

test('result wait cancellation joins the original attach and sends no replacement or Run cancellation', async () => {
  let entered!: () => void, release!: () => void, joined = false;
  const ready = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
  const f = fixture({ 'run.attach': async () => { entered(); await gate; joined = true; return f.page(1); } }), abort = new AbortController();
  const pending = runClientInvocation(f.session, result, { ...io(Readable.from([])), signal: abort.signal });
  await ready; abort.abort(); release();
  assert.equal(await pending, 1); assert.equal(joined, true); assert.equal(f.closed(), 1);
  assert.deepEqual(f.calls.map(call => call.method), ['run.attach']);
});

test('state-only result presentation still refuses changed original file bytes instead of displaying a successful review', async () => {
  const f = fixture(), output = outputStream();
  f.objects.get(f.before.blobRef)!.bytes[0] ^= 1;
  assert.equal(await runClientInvocation(f.session, result, io(Readable.from([]), output)), 1); readsOnly(f);
  assert.equal(f.closed(), 1); assert(!output.text().includes('Result review'));
  assert.equal(f.calls.some(call => call.method === 'run.get'), false);
  assert.equal(f.calls.filter(call => call.method === 'run.result').length, 1);
});
