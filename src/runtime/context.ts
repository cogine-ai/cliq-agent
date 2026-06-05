import type { InstructionMessage } from '../instructions/types.js';
import type { ChatMessage, ModelPromptInputItem } from '../model/types.js';
import type { CompactionArtifact, Session, SessionRecord } from '../session/types.js';

function recordToMessage(record: SessionRecord): ChatMessage {
  return record.kind === 'tool'
    ? { role: 'user', content: record.content }
    : { role: record.role, content: record.content };
}

function activeCompaction(session: Session): CompactionArtifact | null {
  const active = session.compactions.filter((artifact) => artifact.status === 'active');
  if (active.length > 1) {
    throw new Error(`session has multiple active compactions: ${active.map((artifact) => artifact.id).join(', ')}`);
  }
  return active[0] ?? null;
}

function compactionSummaryMessage(artifact: CompactionArtifact): ChatMessage {
  return {
    role: 'system',
    content: `COMPACTED SESSION SUMMARY\n${artifact.summaryMarkdown}`
  };
}

function recordToPromptInput(record: SessionRecord): ModelPromptInputItem {
  if (record.kind === 'tool') {
    return {
      kind: 'tool_result',
      toolName: record.tool,
      status: record.status,
      content: record.content,
      ...(typeof record.meta?.modelToolCallId === 'string' ? { callId: record.meta.modelToolCallId } : {}),
      ...(record.meta ? { meta: record.meta } : {})
    };
  }
  return {
    kind: 'message',
    role: record.role,
    content: record.content,
    ...(record.kind === 'assistant' && record.toolCalls ? { toolCalls: record.toolCalls } : {})
  };
}

function compactionSummaryInput(artifact: CompactionArtifact): ModelPromptInputItem {
  return {
    kind: 'message',
    role: 'system',
    content: `COMPACTED SESSION SUMMARY\n${artifact.summaryMarkdown}`
  };
}

function tailRecords(session: Session, artifact: CompactionArtifact) {
  const firstKeptIndex = session.records.findIndex((record) => record.id === artifact.firstKeptRecordId);
  if (firstKeptIndex === -1) {
    throw new Error(`active compaction first kept record not found: ${artifact.firstKeptRecordId}`);
  }
  return session.records.slice(firstKeptIndex);
}

export function buildContextMessages(session: Session, instructions: InstructionMessage[]): ChatMessage[] {
  const head = instructions.map<ChatMessage>(({ role, content }) => ({ role, content }));
  const artifact = activeCompaction(session);
  if (!artifact) {
    return [...head, ...session.records.map(recordToMessage)];
  }

  return [
    ...head,
    compactionSummaryMessage(artifact),
    ...tailRecords(session, artifact).map(recordToMessage)
  ];
}

export function buildPromptInput(session: Session): ModelPromptInputItem[] {
  const artifact = activeCompaction(session);
  if (!artifact) {
    return session.records.map(recordToPromptInput);
  }

  return [
    compactionSummaryInput(artifact),
    ...tailRecords(session, artifact).map(recordToPromptInput)
  ];
}
