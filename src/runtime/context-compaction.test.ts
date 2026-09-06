import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { ContextManifest, ContinuationItem, ToolBatchItem } from '../kernel/types.js';
import type { NormalPromptMessageV1, NormalPromptProjectionV1 } from '../model/request.js';
import { ref, testFixture } from '../model/testing/fixtures.js';
import { contextSourceDigest, planContextCompaction, validateContextItems, type ContextItem } from './context-compaction.js';

function history(texts: string[], inputAnswer?: string) {
  const authority = testFixture();
  const items: ContextItem[] = [];
  const context: ContextManifest = { schemaVersion: 1, format: 'cliq-context-manifest-v1', runId: 'run', throughItemSeq: 0,
    admittedContextRef: ref(1), assemblyRef: authority.assemblyRef, segments: [], projectionDigest: '' };
  const messages: NormalPromptMessageV1[] = [{ index: 0, role: 'system', sourceKind: 'assembly_instructions', sourceId: 'fixed', contentUtf8: 'system' }];
  const append = (item: ContinuationItem) => {
    const entry = { itemSeq: items.length + 1, itemRef: canonicalSha256(item), item };
    items.push(entry);
    context.segments.push(item.kind === 'assistant_tool_batch' || item.kind === 'context_compaction' || item.kind === 'input_request'
      ? { kind: 'excluded_control', fromItemSeq: entry.itemSeq, throughItemSeq: entry.itemSeq, sourceItemsDigest: contextSourceDigest([entry]) }
      : { kind: 'raw', fromItemSeq: entry.itemSeq, throughItemSeq: entry.itemSeq, items: [{ itemSeq: entry.itemSeq, itemRef: entry.itemRef }] });
  };
  texts.forEach((text, n) => {
    const hasInput = n === 0 && inputAnswer !== undefined;
    const base = { schemaVersion: 1 as const, runId: 'run', createdAt: '2026-09-05T00:00:00.000Z' };
    append({ ...base, kind: 'model_turn', itemId: `turn-${n}`, modelOpId: `op-${n}`, modelAttempt: 0,
      modelTurnRef: ref(4), textRef: ref(5), stopReason: 'tool_calls' });
    const batch: ToolBatchItem = { ...base, kind: 'assistant_tool_batch', itemId: `batch-${n}`, modelOpId: `op-${n}`, modelAttempt: 0,
      modelTurnRef: ref(4), textRef: ref(5), calls: [{ callId: `call-${n}`, index: 0, toolName: hasInput ? 'request_input' : 'read', inputRef: ref(6), inputDigest: ref(7) }] };
    append(batch);
    if (hasInput) {
      const identity = { ...base, batchItemId: batch.itemId, callId: `call-${n}`, index: 0, promptRef: ref(12), promptDigest: ref(13) };
      append({ ...identity, kind: 'input_request', itemId: `question-${n}` });
      append({ ...identity, kind: 'user_input', itemId: `answer-${n}`, inputRequestItemId: `question-${n}`,
        inputRef: ref(14), inputDigest: ref(15), modelContentRef: ref(16), modelContentDigest: ref(17), principalId: 'principal' });
    }
    append({ ...base, kind: 'tool_result', itemId: `result-${n}`, batchItemId: batch.itemId,
      callId: `call-${n}`, index: 0, outcome: hasInput ? 'executed' : 'error', resultRef: ref(8) });
    messages.push({ index: messages.length, role: 'assistant', sourceItemId: `turn-${n}`, contentUtf8: text,
      toolCalls: batch.calls.map((call) => ({ ...call, arguments: { encoding: 'jcs_json', value: { path: 'file' } } })) });
    messages.push({ index: messages.length, role: 'tool', sourceItemId: `result-${n}`, toolCallId: `call-${n}`,
      contentUtf8: hasInput ? JSON.stringify(inputAnswer) : '{"code":"TOOL_INPUT_INVALID"}' });
    if (hasInput) messages.push({ index: messages.length, role: 'user', sourceKind: 'user_input', sourceId: `answer-${n}`, contentUtf8: inputAnswer! });
  });
  context.throughItemSeq = items.length;
  context.projectionDigest = digestOmitting(context, 'projectionDigest');
  const projection: NormalPromptProjectionV1 = { schemaVersion: 1, format: 'cliq-normal-prompt-projection-v1', runId: 'run',
    basedOnRunRevision: 1, frontierDigest: ref(10), runSpecRef: ref(11), assemblyRef: authority.assemblyRef,
    assemblyDigest: authority.assembly.assemblyDigest, contextManifestRef: canonicalSha256(context),
    contextManifestDigest: context.projectionDigest, messages, tools: [], projectionDigest: '' };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  return { context, contextRef: canonicalSha256(context), projection, items, policy: authority.assembly.context,
    createdAt: baseTime };
}
const baseTime = '2026-09-05T00:00:00.000Z';

test('compaction selects the greatest closed prefix and excludes fixed instructions and audit refs from its source', () => {
  const input = history(['a'.repeat(20_000), 'b'.repeat(20_000), 'c'.repeat(28_000)]);
  const selected = planContextCompaction(input);
  assert.equal(selected.kind, 'compact');
  if (selected.kind !== 'compact') return;
  assert.equal(selected.plan.compactThroughItemSeq, 6);
  assert.equal(selected.plan.sourceItemsDigest, contextSourceDigest(input.items.slice(0, 6)));
  assert.doesNotMatch(selected.sourceContextUtf8, /system|inputRef|inputDigest|sourceItemId|modelTurnRef/);
  assert.equal(selected.plan.sourceProjectedTokens, Math.ceil(Buffer.byteLength(selected.sourceContextUtf8) / 3));
  assert.equal(selected.plan.maxSummaryBytes, 3 * selected.plan.summaryTokenCap);
  assert.ok(selected.sourceContextUtf8.includes('b'.repeat(20_000)));
  assert.equal(selected.sourceContextUtf8.includes('c'.repeat(28_000)), false);
  assert.deepEqual(planContextCompaction(input), selected);
});

test('small prompts do not compact; an oversized indivisible prefix or protected suffix fails closed', () => {
  assert.equal(planContextCompaction(history(['small'])).kind, 'normal');
  assert.equal(planContextCompaction(history(['a'.repeat(60_000), 'b'.repeat(28_000)])).kind, 'exhausted');
  assert.equal(planContextCompaction(history(['x'.repeat(70_000)])).kind, 'exhausted');
});

test('normal dispatch cannot overtake an incomplete or out-of-order batch, even below the compaction threshold', () => {
  const input = history(['small']);
  input.items.pop();
  input.context.segments.pop();
  input.context.throughItemSeq--;
  input.context.projectionDigest = digestOmitting(input.context, 'projectionDigest');
  input.contextRef = canonicalSha256(input.context);
  assert.throws(() => planContextCompaction(input), /open batch/);
  const reordered = history(['small']);
  const result = reordered.items[2]!.item;
  assert.equal(result.kind, 'tool_result');
  if (result.kind !== 'tool_result') return;
  result.index = 1;
  reordered.items[2]!.itemRef = canonicalSha256(result);
  const segment = reordered.context.segments[2]!;
  assert.equal(segment.kind, 'raw');
  if (segment.kind !== 'raw') return;
  segment.items[0]!.itemRef = canonicalSha256(result);
  reordered.context.projectionDigest = digestOmitting(reordered.context, 'projectionDigest');
  reordered.contextRef = canonicalSha256(reordered.context);
  assert.throws(() => planContextCompaction(reordered), /provider order/);
});

test('context validation rejects gaps, hidden model content and the old non-normative control digest', () => {
  for (const mutate of [
    (input: ReturnType<typeof history>) => { input.context.segments[1]!.fromItemSeq++; },
    (input: ReturnType<typeof history>) => { input.context.segments[0] = { kind: 'excluded_control', fromItemSeq: 1, throughItemSeq: 1,
      sourceItemsDigest: contextSourceDigest(input.items.slice(0, 1)) }; },
    (input: ReturnType<typeof history>) => { const segment = input.context.segments[1]!;
      if (segment.kind === 'excluded_control') segment.sourceItemsDigest = canonicalSha256([{ itemSeq: 2, itemRef: input.items[1]!.itemRef }]); }
  ]) {
    const input = history(['small']);
    mutate(input);
    input.context.projectionDigest = digestOmitting(input.context, 'projectionDigest');
    assert.throws(() => validateContextItems(input.context, input.items));
  }
});

test('compaction preserves deferred user-message order and keeps the input/result batch indivisible', () => {
  const input = history(['a'.repeat(20_000), 'b'.repeat(20_000), 'c'.repeat(28_000)], 'Alice');
  const selected = planContextCompaction(input);
  assert.equal(selected.kind, 'compact');
  if (selected.kind !== 'compact') return;
  assert.equal(selected.plan.compactThroughItemSeq, 8);
  const source = JSON.parse(selected.sourceContextUtf8) as { role: string; content: unknown }[];
  assert.deepEqual(source.map((message) => message.role), ['assistant', 'tool', 'user', 'assistant', 'tool']);
  assert.doesNotMatch(selected.sourceContextUtf8, /promptRef|inputRef|principal|question-0/);

  const hidden = history(['small'], 'Alice');
  hidden.context.segments[3] = { kind: 'excluded_control', fromItemSeq: 4, throughItemSeq: 4,
    sourceItemsDigest: contextSourceDigest(hidden.items.slice(3, 4)) };
  hidden.context.projectionDigest = digestOmitting(hidden.context, 'projectionDigest');
  assert.throws(() => validateContextItems(hidden.context, hidden.items), /model-visible items cannot be hidden/);

  const open = history(['small'], 'Alice');
  open.items.pop();
  open.context.segments.pop();
  open.context.throughItemSeq--;
  open.context.projectionDigest = digestOmitting(open.context, 'projectionDigest');
  open.contextRef = canonicalSha256(open.context);
  assert.throws(() => planContextCompaction(open), /open batch/);
});
