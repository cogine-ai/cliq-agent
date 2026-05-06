import type { ChatMessage, ModelClient, ResolvedModelConfig } from '../model/types.js';
import type { ResolvedAutoCompactConfig } from './auto-compact-config.js';
import { createCompaction } from './compaction.js';
import type { CompactionArtifact, Session, SessionRecord } from './types.js';

const TOKEN_MESSAGE_OVERHEAD = 4;

export type TokenEstimate = {
  tokens: number;
  messages: number;
  source: 'approx';
};

export type AutoCompactRange = {
  endIndexExclusive: number;
  firstKeptRecordId: string;
  previousCompactionId?: string;
  compactableNewTokens: number;
  splitTurnPrefix: boolean;
};

export type AutoCompactState = {
  thresholdCompactionsThisTurn: number;
  thresholdSuppressed: boolean;
};

export type AutoCompactSkipReason =
  | 'disabled'
  | 'unknown-context-window'
  | 'threshold-suppressed'
  | 'max-threshold-per-turn'
  | 'too-small'
  | 'no-safe-range'
  | 'max-overflow-retries';

export type AutoCompactResult =
  | { status: 'disabled' | 'skipped'; reason: AutoCompactSkipReason }
  | { status: 'compacted'; artifact: CompactionArtifact; estimatedTokensBefore: number; estimatedTokensAfter: number }
  | { status: 'error'; error: Error };

const SUMMARY_PROMPT = `You are compacting a local agent session.

Write a durable markdown summary with these headings:
## Objective
## Current State
## Decisions And Constraints
## Relevant Artifacts
## Validation
## Open Questions And Risks
## Next Steps

Preserve exact paths, commands, identifiers, constraints, and errors. Mark absent sections as (none).`;

export function estimateTextTokens(text: string) {
  return Math.ceil(text.length / 4);
}

export function estimateRecordTokens(record: SessionRecord): TokenEstimate {
  return {
    tokens: estimateTextTokens(record.content) + TOKEN_MESSAGE_OVERHEAD,
    messages: 1,
    source: 'approx'
  };
}

export function estimateMessagesTokens(messages: ChatMessage[]): TokenEstimate {
  return {
    tokens: messages.reduce((total, message) => total + estimateTextTokens(message.content) + TOKEN_MESSAGE_OVERHEAD, 0),
    messages: messages.length,
    source: 'approx'
  };
}

function estimateRecordsTokens(records: SessionRecord[]) {
  return records.reduce((total, record) => total + estimateRecordTokens(record).tokens, 0);
}

function isAssistantToolAction(record: SessionRecord) {
  return record.kind === 'assistant' && record.action !== null && !('message' in record.action);
}

function isSafeSplitPoint(records: SessionRecord[], index: number) {
  const firstKept = records[index];
  if (!firstKept || firstKept.kind === 'tool') {
    return false;
  }

  const previous = records[index - 1];
  if (!previous) {
    return false;
  }

  if (isAssistantToolAction(previous)) {
    return false;
  }
  if (previous.kind === 'tool') {
    return true;
  }
  if (firstKept.kind === 'user') {
    return true;
  }
  if (firstKept.kind === 'assistant') {
    return true;
  }

  return false;
}

function activeCompaction(session: Session) {
  return session.compactions.find((artifact) => artifact.status === 'active') ?? null;
}

function userBoundaryCandidates(records: SessionRecord[]) {
  const candidates: number[] = [];
  for (let index = 1; index < records.length; index += 1) {
    if (records[index]?.kind === 'user') {
      candidates.push(index);
    }
  }
  return candidates;
}

function safeBoundaryCandidates(records: SessionRecord[]) {
  const candidates = userBoundaryCandidates(records);
  for (let index = 1; index < records.length; index += 1) {
    if (isSafeSplitPoint(records, index) && !candidates.includes(index)) {
      candidates.push(index);
    }
  }
  return candidates.sort((a, b) => a - b);
}

type TxSpan = { openIndex: number; closeIndex: number };

function findExplicitTxSpans(records: SessionRecord[]): TxSpan[] {
  const spans: TxSpan[] = [];
  const openByTxId = new Map<string, number>();
  for (let i = 0; i < records.length; i += 1) {
    const r = records[i];
    if (!r) continue;
    if (r.kind === 'tx-opened') {
      openByTxId.set(r.meta.txId, i);
    } else if (r.kind === 'tx-applied' || r.kind === 'tx-aborted') {
      const open = openByTxId.get(r.meta.txId);
      if (open !== undefined) {
        spans.push({ openIndex: open, closeIndex: i });
        openByTxId.delete(r.meta.txId);
      }
    }
  }
  // Unmatched tx-opened: span extends to records.length (still-open explicit tx).
  for (const [, openIndex] of openByTxId) {
    spans.push({ openIndex, closeIndex: records.length });
  }
  return spans;
}

function adjustCutForTxSpans(rawCutIndex: number, spans: TxSpan[]): number {
  let cut = rawCutIndex;
  let changed = true;
  // Multiple passes in case adjusting into one span lands inside an earlier span.
  while (changed) {
    changed = false;
    for (const span of spans) {
      // Cut at openIndex is safe (cut before the tx); cut > closeIndex is also safe.
      if (cut > span.openIndex && cut <= span.closeIndex) {
        cut = span.openIndex;
        changed = true;
      }
    }
  }
  return cut;
}

export function selectAutoCompactRange({
  session,
  keepRecentTokens,
  minNewTokens
}: {
  session: Session;
  keepRecentTokens: number;
  minNewTokens: number;
}): AutoCompactRange | null {
  if (session.records.length < 2) {
    return null;
  }

  const active = activeCompaction(session);
  const previousEnd = active?.coveredRange.endIndexExclusive ?? 0;
  const candidates = safeBoundaryCandidates(session.records).filter(
    (index) => index > previousEnd && index < session.records.length
  );

  let selected: number | null = null;
  for (const index of candidates) {
    const tailTokens = estimateRecordsTokens(session.records.slice(index));
    if (tailTokens >= keepRecentTokens) {
      selected = index;
    }
  }

  selected ??= candidates[0] ?? null;
  if (selected === null) {
    return null;
  }

  // Move cut out of any explicit-tx span so we never split between
  // tx-opened and its matching tx-applied/tx-aborted (or the still-open tail).
  const spans = findExplicitTxSpans(session.records);
  const adjusted = adjustCutForTxSpans(selected, spans);
  if (adjusted <= previousEnd) {
    return null;
  }
  selected = adjusted;

  const compactableNewTokens = estimateRecordsTokens(session.records.slice(previousEnd, selected));
  if (compactableNewTokens < minNewTokens) {
    return null;
  }

  return {
    endIndexExclusive: selected,
    firstKeptRecordId: session.records[selected]!.id,
    previousCompactionId: active?.id,
    compactableNewTokens,
    splitTurnPrefix: !userBoundaryCandidates(session.records).includes(selected)
  };
}

export function serializeRecordForSummary(record: SessionRecord, maxToolPayloadChars: number) {
  if (record.kind === 'tool') {
    const original = record.content;
    const clipped =
      original.length <= maxToolPayloadChars
        ? original
        : `${original.slice(0, maxToolPayloadChars)}\n[cliq truncated summarizer tool payload: originalChars=${original.length}]`;
    return [
      `<record id="${record.id}" kind="tool" tool="${record.tool}" status="${record.status}">`,
      `tool=${record.tool}`,
      `status=${record.status}`,
      clipped,
      '</record>'
    ].join('\n');
  }

  if (record.kind === 'tx-opened') {
    const name = record.meta.name ? ` "${record.meta.name}"` : '';
    const body = `[Transaction opened${name} (${record.meta.txId})]`;
    return [
      `<record id="${record.id}" kind="tx-opened" txId="${record.meta.txId}">`,
      body,
      '</record>'
    ].join('\n');
  }

  if (record.kind === 'tx-applied') {
    const ds = record.meta.diffSummary;
    const blocking = record.meta.validators.blocking;
    const blockingTotal = blocking.pass + blocking.fail;
    const modifies = ds.modifies.join(', ');
    const body = `[Transaction ${record.meta.txId} applied: ${ds.filesChanged} files changed (+${ds.additions} -${ds.deletions}); modifies: ${modifies}; validators: ${blocking.pass}/${blockingTotal} blocking pass]`;
    return [
      `<record id="${record.id}" kind="tx-applied" txId="${record.meta.txId}">`,
      body,
      '</record>'
    ].join('\n');
  }

  if (record.kind === 'tx-aborted') {
    const partial = record.meta.appliedPartial
      ? `; partial: ${record.meta.appliedPartial.partialFiles.join(', ')} (restoreConfirmed=${record.meta.appliedPartial.restoreConfirmed})`
      : '';
    const failed = record.meta.failedValidators?.length
      ? `; failedValidators: ${record.meta.failedValidators.join(', ')}`
      : '';
    const body = `[Transaction ${record.meta.txId} aborted: ${record.meta.reason}${failed}${partial}]`;
    return [
      `<record id="${record.id}" kind="tx-aborted" txId="${record.meta.txId}">`,
      body,
      '</record>'
    ].join('\n');
  }

  return [`<record id="${record.id}" kind="${record.kind}" role="${record.role}">`, record.content, '</record>'].join(
    '\n'
  );
}

function buildSummaryMessages(input: string): ChatMessage[] {
  return [
    { role: 'system', content: SUMMARY_PROMPT },
    { role: 'user', content: input }
  ];
}

function summaryInputBudget(config: ResolvedAutoCompactConfig) {
  if (config.contextWindowTokens === null) {
    return null;
  }

  const promptOverheadTokens = estimateMessagesTokens(buildSummaryMessages('')).tokens;
  return config.contextWindowTokens - config.reserveTokens - promptOverheadTokens;
}

function buildSummarizerInput({
  rollingSummary,
  chunk
}: {
  rollingSummary: string;
  chunk: string;
}) {
  return [
    rollingSummary ? `Previous summary:\n${rollingSummary}` : '',
    `Records to summarize:\n${chunk}`
  ]
    .filter(Boolean)
    .join('\n\n');
}

function fitsSummarizerBudget(input: string, totalBudgetTokens: number) {
  return estimateMessagesTokens(buildSummaryMessages(input)).tokens <= totalBudgetTokens;
}

function throwIfAborted(signal?: AbortSignal) {
  if (signal?.aborted) {
    const error = new Error('run cancelled');
    error.name = 'AbortError';
    throw error;
  }
}

async function summarizeChunks({
  model,
  previousSummary,
  serializedRecords,
  summaryInputBudgetTokens,
  totalBudgetTokens,
  signal
}: {
  model: ModelClient;
  previousSummary?: string;
  serializedRecords: string[];
  summaryInputBudgetTokens: number;
  totalBudgetTokens: number;
  signal?: AbortSignal;
}) {
  let rollingSummary = previousSummary ?? '';
  let index = 0;

  while (index < serializedRecords.length) {
    let chunk = '';
    let consumed = 0;

    while (index + consumed < serializedRecords.length) {
      const next = serializedRecords[index + consumed]!;
      const candidateChunk = chunk ? `${chunk}\n\n${next}` : next;
      const candidateInput = buildSummarizerInput({ rollingSummary, chunk: candidateChunk });
      if (!fitsSummarizerBudget(candidateInput, totalBudgetTokens)) {
        break;
      }
      chunk = candidateChunk;
      consumed += 1;
    }

    if (consumed === 0) {
      const singleRecordTokens = estimateTextTokens(serializedRecords[index]!);
      if (singleRecordTokens > summaryInputBudgetTokens) {
        throw new Error('single compact summary input record exceeds summarizer budget');
      }
      throw new Error('compact summarizer chunk exceeds input budget');
    }

    const input = buildSummarizerInput({ rollingSummary, chunk });
    const completion = await model.complete(buildSummaryMessages(input), { signal });
    throwIfAborted(signal);
    rollingSummary = completion.content.trim();
    if (!rollingSummary) {
      throw new Error('compact summarizer returned an empty summary');
    }
    if (estimateTextTokens(rollingSummary) > summaryInputBudgetTokens) {
      throw new Error('compact summarizer output exceeds input budget');
    }
    index += consumed;
  }

  return rollingSummary;
}

function recordRole(record: SessionRecord): ChatMessage['role'] {
  return record.kind === 'assistant' ? 'assistant' : 'user';
}

export async function maybeAutoCompact({
  cwd,
  session,
  model,
  modelConfig,
  config,
  instructions,
  phase,
  trigger,
  state,
  signal,
  estimateOverrideTokens
}: {
  cwd: string;
  session: Session;
  model: ModelClient;
  modelConfig: ResolvedModelConfig;
  config: ResolvedAutoCompactConfig;
  instructions: ChatMessage[];
  phase: 'pre-model' | 'mid-loop';
  trigger: 'threshold' | 'overflow';
  state: AutoCompactState;
  signal?: AbortSignal;
  estimateOverrideTokens?: number;
}): Promise<AutoCompactResult> {
  if (config.enabled === 'off') {
    return { status: 'disabled', reason: 'disabled' };
  }
  if (config.contextWindowTokens === null || config.usableLimitTokens === null) {
    return { status: 'skipped', reason: 'unknown-context-window' };
  }
  if (trigger === 'threshold' && state.thresholdSuppressed) {
    return { status: 'skipped', reason: 'threshold-suppressed' };
  }
  if (trigger === 'threshold' && state.thresholdCompactionsThisTurn >= config.maxThresholdCompactionsPerTurn) {
    return { status: 'skipped', reason: 'max-threshold-per-turn' };
  }

  const estimatedTokensBefore =
    estimateOverrideTokens ??
    estimateMessagesTokens([
      ...instructions,
      ...session.records.map((record) => ({ role: recordRole(record), content: record.content }))
    ]).tokens;

  if (trigger === 'threshold' && estimatedTokensBefore < config.usableLimitTokens) {
    return { status: 'skipped', reason: 'too-small' };
  }

  const range = selectAutoCompactRange({
    session,
    keepRecentTokens: config.keepRecentTokens,
    minNewTokens: config.minNewTokens
  });
  if (!range) {
    return { status: 'skipped', reason: 'no-safe-range' };
  }

  const inputBudget = summaryInputBudget(config);
  if (inputBudget === null || inputBudget <= 0) {
    return { status: 'error', error: new Error('compact summarizer input budget is not positive') };
  }

  try {
    const previous = range.previousCompactionId
      ? session.compactions.find((artifact) => artifact.id === range.previousCompactionId)
      : undefined;
    const startIndex = previous?.coveredRange.endIndexExclusive ?? 0;
    const records = session.records.slice(startIndex, range.endIndexExclusive);
    const serializedRecords = records.map((record) => serializeRecordForSummary(record, Math.floor(inputBudget * 4)));
    const totalBudgetTokens = config.contextWindowTokens - config.reserveTokens;
    const summaryMarkdown = await summarizeChunks({
      model,
      previousSummary: previous?.summaryMarkdown,
      serializedRecords,
      summaryInputBudgetTokens: inputBudget,
      totalBudgetTokens,
      signal
    });
    throwIfAborted(signal);
    const estimatedTokensAfter =
      estimateRecordsTokens(session.records.slice(range.endIndexExclusive)) + estimateTextTokens(summaryMarkdown);
    const artifact = await createCompaction(cwd, session, {
      endIndexExclusive: range.endIndexExclusive,
      summaryMarkdown,
      createdBy: {
        provider: modelConfig.provider,
        model: modelConfig.model
      },
      auto: {
        trigger,
        phase,
        estimatedTokensBefore,
        estimatedTokensAfter,
        usableLimitTokens: config.usableLimitTokens,
        contextWindowTokens: config.contextWindowTokens,
        contextWindowSource: config.contextWindowSource ?? undefined,
        keepRecentTokens: config.keepRecentTokens,
        summaryInputBudgetTokens: inputBudget,
        previousCompactionId: range.previousCompactionId
      }
    });

    if (trigger === 'threshold') {
      state.thresholdCompactionsThisTurn += 1;
    }
    return { status: 'compacted', artifact, estimatedTokensBefore, estimatedTokensAfter };
  } catch (error) {
    return { status: 'error', error: error instanceof Error ? error : new Error(String(error)) };
  }
}
