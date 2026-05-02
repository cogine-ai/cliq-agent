import type { ChatMessage } from '../model/types.js';
import type { Session, SessionRecord } from './types.js';

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

  return [`<record id="${record.id}" kind="${record.kind}" role="${record.role}">`, record.content, '</record>'].join(
    '\n'
  );
}
