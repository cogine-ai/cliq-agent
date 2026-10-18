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
    provider: authority.assembly.provider, compactionEnvelope: authority.material.compactionEnvelope,
    createdAt: baseTime };
}
const baseTime = '2026-09-05T00:00:00.000Z';

function largeWindow(input: ReturnType<typeof history>) {
  Object.assign(input.policy, { contextLimitTokens: 1_048_576, hardPromptTokens: 1_044_480,
    triggerThresholdTokens: 734_003, protectedRecentTokens: 32_768, summaryTokenCap: 8192,
    sourceInputTokenCap: 524_288 });
  input.provider.negotiation.contextLimitTokens = input.policy.contextLimitTokens;
  return input;
}

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
  const tokenExhausted = planContextCompaction(history(['x'.repeat(70_000)]));
  assert.ok(tokenExhausted.kind === 'exhausted');
  assert.equal(Object.hasOwn(tokenExhausted.evidence, 'trigger'), false);
  assert.equal(Object.hasOwn(tokenExhausted.evidence, 'requestBodyBytes'), false);
});

test('verifier audit is excluded but a repair message cannot be hidden or split from its closed transcript', () => {
  const input = history(['small']), createdAt = baseTime;
  const append = (item: ContinuationItem, visible: boolean) => {
    const itemSeq = input.items.length + 1, itemRef = canonicalSha256(item), entry = { item, itemRef, itemSeq };
    input.items.push(entry);
    input.context.segments.push(visible ? { kind: 'raw', fromItemSeq: itemSeq, throughItemSeq: itemSeq, items: [{ itemSeq, itemRef }] }
      : { kind: 'excluded_control', fromItemSeq: itemSeq, throughItemSeq: itemSeq, sourceItemsDigest: contextSourceDigest([entry]) });
    input.context.throughItemSeq = itemSeq;
    input.context.projectionDigest = digestOmitting(input.context, 'projectionDigest'); input.contextRef = canonicalSha256(input.context);
  };
  append({ schemaVersion: 1, kind: 'verifier_result', itemId: 'verifier-result', runId: 'run', candidateItemId: 'candidate',
    verifierPlanRef: ref(1), verifierIndex: 0, verifierId: 'tests', opId: 'verifier', attempt: 0, outcome: 'assertion_failed', receiptRef: ref(2), createdAt }, false);
  const auditSegment = structuredClone(input.context.segments.at(-1)!);
  append({ schemaVersion: 1, kind: 'repair_diagnostic', itemId: 'repair', runId: 'run', candidateItemId: 'candidate', verifierPlanRef: ref(1),
    failedVerifierResultItemIds: ['verifier-result'], diagnostics: [{ verifierId: 'tests', diagnosticRef: ref(3), diagnosticDigest: ref(4),
      modelContentRef: ref(5), modelContentDigest: ref(6) }], repairOrdinal: 1, createdAt }, true);
  input.projection.messages.push({ index: input.projection.messages.length, role: 'user', sourceKind: 'verifier_repair', sourceId: 'repair',
    contentUtf8: 'Verifier "tests" failed an assertion (exit 1). Revise the candidate and try again.' });
  validateContextItems(input.context, input.items); assert.equal(planContextCompaction(input).kind, 'normal');
  const invalid = structuredClone(input.context), repair = input.items.at(-1)!;
  invalid.segments[invalid.segments.length - 1] = { kind: 'excluded_control', fromItemSeq: repair.itemSeq, throughItemSeq: repair.itemSeq,
    sourceItemsDigest: contextSourceDigest([repair]) };
  invalid.projectionDigest = digestOmitting(invalid, 'projectionDigest');
  assert.throws(() => validateContextItems(invalid, input.items), /cannot be hidden/);
  const audit = input.items.at(-2)!;
  invalid.segments[invalid.segments.length - 1] = structuredClone(input.context.segments.at(-1)!);
  invalid.segments[invalid.segments.length - 2] = { kind: 'raw', fromItemSeq: audit.itemSeq, throughItemSeq: audit.itemSeq,
    items: [{ itemSeq: audit.itemSeq, itemRef: audit.itemRef }] };
  invalid.projectionDigest = digestOmitting(invalid, 'projectionDigest');
  assert.throws(() => validateContextItems(invalid, input.items), /control items/);
  assert.equal(auditSegment.kind, 'excluded_control');
});

test('a normal request exceeding the wire bound compacts a safe whole prefix even below the token trigger', () => {
  const input = largeWindow(history(['a'.repeat(40_000), '"'.repeat(540_000)]));
  const selected = planContextCompaction(input);
  assert.equal(selected.kind, 'compact');
  if (selected.kind !== 'compact') return;
  assert.equal(selected.plan.compactThroughItemSeq, 3);
  assert.ok(selected.sourceContextUtf8.includes('a'.repeat(40_000)));
  assert.deepEqual((JSON.parse(selected.sourceContextUtf8) as { contentUtf8: string }[]).map(message => message.contentUtf8),
    ['a'.repeat(40_000), '{"code":"TOOL_INPUT_INVALID"}']);
});

test('the greatest safe prefix must fit the actual compaction envelope after source JSON is escaped again', () => {
  const selected = planContextCompaction(largeWindow(history([
    'a'.repeat(100_000), '"'.repeat(400_000), 'z'.repeat(200_000)
  ])));
  assert.equal(selected.kind, 'compact');
  if (selected.kind !== 'compact') return;
  assert.equal(selected.plan.compactThroughItemSeq, 3);
  assert.ok(selected.sourceContextUtf8.includes('a'.repeat(100_000)));
  assert.deepEqual((JSON.parse(selected.sourceContextUtf8) as { contentUtf8: string }[]).map(message => message.contentUtf8),
    ['a'.repeat(100_000), '{"code":"TOOL_INPUT_INVALID"}']);
});

test('no byte-safe complete prefix yields exact wire exhaustion rather than a truncated or over-limit request', () => {
  const input = largeWindow(history(['"'.repeat(300_000), 'z'.repeat(500_000)]));
  const selected = planContextCompaction(input);
  assert.equal(selected.kind, 'exhausted');
  if (selected.kind !== 'exhausted') return;
  assert.ok('trigger' in selected.evidence);
  assert.equal(selected.evidence.trigger, 'request_body_bytes');
  assert.ok(selected.evidence.nextPromptTokens <= selected.evidence.triggerThresholdTokens);
  assert.ok(selected.evidence.requestBodyBytes > 1_048_576);
  assert.equal(selected.evidence.requestBodyLimitBytes, 1_048_576);
  assert.match(selected.evidence.modelVisiblePromptDigest, /^[a-f0-9]{64}$/u);
  assert.equal(selected.evidence.contextManifestRef, input.contextRef);
  assert.deepEqual(planContextCompaction(input), selected);
});

test('two ordinary 700 KiB results select the largest complete byte-safe prefix without changing frozen token caps', () => {
  const input = largeWindow(history(['a'.repeat(700 * 1024), 'b'.repeat(700 * 1024)]));
  const before = structuredClone(input.policy);
  const selected = planContextCompaction(input);
  assert.equal(selected.kind, 'compact');
  if (selected.kind !== 'compact') return;
  assert.equal(selected.plan.compactThroughItemSeq, 3);
  assert.ok(selected.sourceContextUtf8.includes('a'.repeat(700 * 1024)));
  assert.equal(selected.sourceContextUtf8.includes('b'.repeat(700 * 1024)), false);
  assert.deepEqual(input.policy, before);
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
