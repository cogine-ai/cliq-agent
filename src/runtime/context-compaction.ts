import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import type { ContextManifest, ContextSegment, ContinuationItem, RunAssemblyV1, RunContextCompactionPlan } from '../kernel/types.js';
import { estimatePromptTokens, estimateTextTokens, projectModelVisiblePrompt,
  type NormalPromptMessageV1, type NormalPromptProjectionV1 } from '../model/request.js';

export type ContextItem = { itemSeq: number; itemRef: string; item: ContinuationItem };

/** The logical source identity, also used for excluded-control segments. */
export function contextSourceDigest(items: readonly ContextItem[]): string {
  return canonicalSha256(items.map(({ itemSeq, itemRef, item }) => ({ itemSeq, kind: item.kind, payloadRef: itemRef })));
}

/** Validate the complete partition against durable rows, never infer missing context from display text. */
export function validateContextItems(context: ContextManifest, items: readonly ContextItem[]): void {
  const exactKeys = (value: object, keys: string[]) => Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
  if (!exactKeys(context, ['schemaVersion', 'format', 'runId', 'throughItemSeq', 'admittedContextRef', 'segments', 'assemblyRef', 'projectionDigest']) ||
      context.schemaVersion !== 1 || context.format !== 'cliq-context-manifest-v1') throw new TypeError('invalid context schema');
  if (context.throughItemSeq !== items.length || digestOmitting(context, 'projectionDigest') !== context.projectionDigest) {
    throw new TypeError('context cursor or digest differs from durable items');
  }
  const byId = new Map(items.map((entry) => [entry.item.itemId, entry]));
  if (byId.size !== items.length) throw new TypeError('context item ids are not unique');
  items.forEach((entry, index) => {
    if (entry.itemSeq !== index + 1 || entry.item.runId !== context.runId || canonicalSha256(entry.item) !== entry.itemRef) {
      throw new TypeError('context source differs from its durable row');
    }
  });
  let through = 0;
  for (const segment of context.segments) {
    if (!exactKeys(segment, ['kind', 'fromItemSeq', 'throughItemSeq', ...(segment.kind === 'raw' ? ['items']
      : segment.kind === 'summary' ? ['compactionItemId', 'summaryRef', 'summaryDigest', 'sourceItemsDigest', 'preservedItemRefs']
        : ['sourceItemsDigest'])])) throw new TypeError('invalid context segment schema');
    if (segment.fromItemSeq !== through + 1 || !Number.isSafeInteger(segment.throughItemSeq) ||
        segment.throughItemSeq < segment.fromItemSeq || segment.throughItemSeq > items.length) {
      throw new TypeError('context segments must be a complete nonoverlapping partition');
    }
    const source = items.slice(segment.fromItemSeq - 1, segment.throughItemSeq);
    if (segment.kind === 'raw') {
      if (canonicalSha256(segment.items) !== canonicalSha256(source.map(({ itemSeq, itemRef }) => ({ itemSeq, itemRef })))) {
        throw new TypeError('raw context does not match its source rows');
      }
      if (source.some(({ item }) => item.kind !== 'model_turn' && item.kind !== 'tool_result' && item.kind !== 'user_input')) {
        throw new TypeError('control items cannot enter raw model context');
      }
    } else {
      if (segment.sourceItemsDigest !== contextSourceDigest(source)) throw new TypeError('context source digest mismatch');
      if (segment.kind === 'summary') {
        const compaction = byId.get(segment.compactionItemId)?.item;
        if (compaction?.kind !== 'context_compaction' || compaction.coveredFromItemSeq !== segment.fromItemSeq ||
            compaction.coveredThroughItemSeq !== segment.throughItemSeq || compaction.summaryRef !== segment.summaryRef ||
            compaction.summaryDigest !== segment.summaryDigest || compaction.sourceItemsDigest !== segment.sourceItemsDigest ||
            new Set(segment.preservedItemRefs).size !== segment.preservedItemRefs.length ||
            segment.preservedItemRefs.some((ref) => !source.some((entry) => entry.itemRef === ref))) {
          throw new TypeError('summary is not backed by its exact compaction item and source range');
        }
      } else if (segment.kind !== 'excluded_control' || source.some(({ item }) =>
        item.kind !== 'assistant_tool_batch' && item.kind !== 'context_compaction' && item.kind !== 'policy_decision' && item.kind !== 'input_request')) {
        throw new TypeError('model-visible items cannot be hidden as excluded control');
      }
    }
    through = segment.throughItemSeq;
  }
  if (through !== items.length) throw new TypeError('context partition has a missing suffix');
}

function segmentMessages(segment: ContextSegment, items: readonly ContextItem[], projection: NormalPromptProjectionV1) {
  const ids = new Set(segment.kind === 'raw'
    ? items.slice(segment.fromItemSeq - 1, segment.throughItemSeq).map(({ item }) => item.itemId)
    : segment.kind === 'summary'
      ? [segment.compactionItemId, ...items.filter(({ itemRef }) => segment.preservedItemRefs.includes(itemRef)).map(({ item }) => item.itemId)]
      : []);
  return projection.messages.filter((message) => ids.has('sourceItemId' in message ? message.sourceItemId : message.sourceId));
}

function visibleMessages(messages: NormalPromptMessageV1[], projection: NormalPromptProjectionV1) {
  return projectModelVisiblePrompt({ ...projection, messages: [...messages].sort((a, b) => a.index - b.index), tools: [] }, 'text-only').messages;
}

/** Only closed whole batches can be separated; a protected result protects its assistant call as well. */
function closedBoundaries(items: readonly ContextItem[]): Set<number> {
  const closed = new Set<number>();
  let batch: Extract<ContinuationItem, { kind: 'assistant_tool_batch' }> | undefined;
  let awaitingBatch = false;
  let nextIndex = 0;
  for (const { item, itemSeq } of items) {
    if (item.kind === 'model_turn') {
      if (batch || awaitingBatch) throw new TypeError('model turn cannot overtake an open tool batch');
      awaitingBatch = item.stopReason === 'tool_calls';
    } else if (item.kind === 'assistant_tool_batch') {
      if (!awaitingBatch || batch || item.calls.length === 0) throw new TypeError('tool batch is not preceded by a model turn');
      batch = item;
      awaitingBatch = false;
      nextIndex = 0;
    } else if (item.kind === 'tool_result') {
      if (!batch || item.batchItemId !== batch.itemId || item.index !== nextIndex || batch.calls[nextIndex]?.callId !== item.callId) {
        throw new TypeError('tool results must close their batch once in provider order');
      }
      if (++nextIndex === batch.calls.length) batch = undefined;
    } else if (item.kind === 'input_request' || item.kind === 'user_input') {
      if (!batch || item.batchItemId !== batch.itemId || item.index !== nextIndex || item.callId !== batch.calls[nextIndex]?.callId) {
        throw new TypeError('input control item cannot overtake its open call');
      }
    } else if (item.kind !== 'context_compaction' && item.kind !== 'policy_decision') throw new TypeError('unsupported live context item');
    if (!batch && !awaitingBatch) closed.add(itemSeq);
  }
  if (batch || awaitingBatch) throw new TypeError('normal model context contains an open batch');
  return closed;
}

export function planContextCompaction(input: {
  context: ContextManifest; contextRef: string; items: readonly ContextItem[];
  projection: NormalPromptProjectionV1; policy: RunAssemblyV1['context']; createdAt: string;
}) {
  const { context, contextRef, items, projection, policy } = input;
  parseCanonicalTime(input.createdAt);
  if (canonicalSha256(context) !== contextRef) throw new TypeError('compaction context reference mismatch');
  validateContextItems(context, items);
  const closed = closedBoundaries(items);
  const nextPromptTokens = estimatePromptTokens(projectModelVisiblePrompt(projection, 'native-tools'));
  if (nextPromptTokens <= policy.triggerThresholdTokens) return { kind: 'normal' as const };
  const groups = context.segments.map((segment) => segmentMessages(segment, items, projection));
  const contentTokens = groups.map((messages) => {
    const prompt = projectModelVisiblePrompt({ ...projection, messages, tools: [] }, 'text-only');
    return estimatePromptTokens(prompt) - 4 * messages.length - estimateTextTokens('[]');
  });
  let protectedFrom = context.throughItemSeq + 1;
  let recentTokens = 0;
  for (let i = context.segments.length - 1; i >= 0 && recentTokens < policy.protectedRecentTokens; i--) {
    protectedFrom = context.segments[i]!.fromItemSeq;
    recentTokens += contentTokens[i]!;
  }
  const prefix: NormalPromptMessageV1[] = [];
  let selected: { through: number; sourceContextUtf8: string; sourceProjectedTokens: number } | undefined;
  for (const [index, segment] of context.segments.entries()) {
    if (segment.throughItemSeq >= protectedFrom) break;
    prefix.push(...groups[index]!);
    if (!closed.has(segment.throughItemSeq)) continue;
    // Retain exactly the model-visible messages, including opaque reasoning and typed arguments, without audit refs.
    const sourceContextUtf8 = canonicalJsonBytes(visibleMessages(prefix, projection)).toString('utf8');
    const sourceProjectedTokens = estimateTextTokens(sourceContextUtf8);
    if (sourceProjectedTokens <= policy.sourceInputTokenCap && sourceProjectedTokens >= policy.summaryTokenCap + 512) {
      selected = { through: segment.throughItemSeq, sourceContextUtf8, sourceProjectedTokens };
    }
  }
  if (!selected) {
    const fixedTokens = nextPromptTokens - contentTokens.reduce((sum, value) => sum + value, 0);
    return { kind: 'exhausted' as const, evidence: {
      schemaVersion: 1, format: 'cliq-context-window-exhausted-evidence-v1', runId: context.runId,
      contextManifestRef: contextRef, promptProjectionDigest: projection.projectionDigest,
      nextPromptTokens, triggerThresholdTokens: policy.triggerThresholdTokens, hardPromptTokens: policy.hardPromptTokens,
      protectedFromItemSeq: protectedFrom, protectedTokens: fixedTokens + recentTokens,
      sourceInputTokenCap: policy.sourceInputTokenCap, summaryTokenCap: policy.summaryTokenCap
    } };
  }
  const plan: RunContextCompactionPlan = { schemaVersion: 1, runId: context.runId, sourceContextManifestRef: contextRef,
    compactFromItemSeq: 1, compactThroughItemSeq: selected.through, preservedItemIds: [],
    sourceItemsDigest: contextSourceDigest(items.slice(0, selected.through)), summaryFormat: 'cliq-context-summary-markdown-v1',
    maxSummaryBytes: Math.min(policy.maxSummaryBytes, 3 * policy.summaryTokenCap),
    contextLimitTokens: policy.contextLimitTokens, reservedNormalOutputTokens: policy.reservedOutputTokens,
    triggerThresholdTokens: policy.triggerThresholdTokens, protectedRecentTokens: policy.protectedRecentTokens,
    summaryTokenCap: policy.summaryTokenCap, promptEnvelopeRef: policy.compactionPromptEnvelopeRef,
    promptEnvelopeDigest: policy.compactionPromptEnvelopeDigest, promptOverheadTokens: policy.compactionEnvelopeTokens,
    sourceInputTokenCap: policy.sourceInputTokenCap, sourceProjectedTokens: selected.sourceProjectedTokens, createdAt: input.createdAt };
  return { kind: 'compact' as const, plan, sourceContextUtf8: selected.sourceContextUtf8 };
}
