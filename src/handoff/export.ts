import { promises as fs } from 'node:fs';
import path from 'node:path';

import { createCheckpoint } from '../session/checkpoints.js';
import { makeId, nowIso, resolveCliqHome } from '../session/store.js';
import type { CompactionArtifact, Session, SessionCheckpoint, SessionRecord } from '../session/types.js';

export type HandoffArtifact = {
  id: string;
  createdAt: string;
  sessionId: string;
  parentSessionId?: string;
  checkpointId: string;
  activeCompactionId?: string;
  summarySource: 'active-compaction' | 'handoff-only';
  provider: string;
  model: string;
  workspaceCheckpointId?: string;
  summaryMarkdown: string;
  paths: {
    json: string;
    markdown: string;
  };
};

export type ExportHandoffOptions = {
  checkpointId?: string;
};

export function handoffDirPath(handoffId: string, cliqHome = resolveCliqHome()) {
  return path.join(cliqHome, 'handoffs', handoffId);
}

function activeCompaction(session: Session): CompactionArtifact | null {
  const active = session.compactions.filter((artifact) => artifact.status === 'active');
  if (active.length > 1) {
    throw new Error(`session has multiple active compactions: ${active.map((artifact) => artifact.id).join(', ')}`);
  }
  return active[0] ?? null;
}

function recordLine(record: SessionRecord) {
  if (record.kind === 'tool') {
    return `- tool ${record.tool} ${record.status}: ${record.content}`;
  }
  return `- ${record.role}: ${record.content}`;
}

function rawTail(session: Session, artifact: CompactionArtifact) {
  const firstKeptIndex = session.records.findIndex((record) => record.id === artifact.firstKeptRecordId);
  if (firstKeptIndex === -1) {
    throw new Error(`active compaction first kept record not found: ${artifact.firstKeptRecordId}`);
  }
  return session.records.slice(firstKeptIndex);
}

function buildSummaryFromActiveCompaction(session: Session, artifact: CompactionArtifact) {
  const tail = rawTail(session, artifact);
  const tailMarkdown = tail.length > 0 ? tail.map(recordLine).join('\n') : '- No raw tail records.';
  return `${artifact.summaryMarkdown}\n\n## Recent Raw Tail\n${tailMarkdown}`;
}

function buildHandoffOnlySummary(session: Session) {
  const firstUser = session.records.find((record) => record.kind === 'user');
  const recent = session.records.slice(-8);
  const recentMarkdown = recent.length > 0 ? recent.map(recordLine).join('\n') : '- No session records.';
  return [
    '## Objective',
    firstUser?.content ?? 'No explicit user objective recorded.',
    '',
    '## Current State',
    recentMarkdown,
    '',
    '## Decisions And Constraints',
    '- No compact artifact is active. This summary was generated only for handoff export.',
    '',
    '## Open Questions And Risks',
    '- Review the raw session if more detail is needed.'
  ].join('\n');
}

async function resolveCheckpoint(cwd: string, session: Session, checkpointId?: string): Promise<SessionCheckpoint> {
  if (checkpointId) {
    const checkpoint = session.checkpoints.find((candidate) => candidate.id === checkpointId);
    if (!checkpoint) {
      throw new Error(`checkpoint not found: ${checkpointId}`);
    }
    return checkpoint;
  }

  return await createCheckpoint(cwd, session, { kind: 'handoff' });
}

function renderHandoffMarkdown(artifact: HandoffArtifact) {
  return [
    '# Handoff',
    '',
    `Session: ${artifact.sessionId}`,
    `Checkpoint: ${artifact.checkpointId}`,
    `Model: ${artifact.provider}/${artifact.model}`,
    artifact.activeCompactionId ? `Active compaction: ${artifact.activeCompactionId}` : 'Active compaction: none',
    '',
    artifact.summaryMarkdown,
    ''
  ].join('\n');
}

export async function exportHandoff(
  cwd: string,
  session: Session,
  options: ExportHandoffOptions = {}
): Promise<HandoffArtifact> {
  const checkpoint = await resolveCheckpoint(cwd, session, options.checkpointId);
  const active = activeCompaction(session);
  const id = makeId('handoff');
  const dir = handoffDirPath(id);
  const jsonPath = path.join(dir, 'handoff.json');
  const markdownPath = path.join(dir, 'HANDOFF.md');
  const artifact: HandoffArtifact = {
    id,
    createdAt: nowIso(),
    sessionId: session.id,
    parentSessionId: session.parentSessionId,
    checkpointId: checkpoint.id,
    activeCompactionId: active?.id,
    summarySource: active ? 'active-compaction' : 'handoff-only',
    provider: session.model.provider,
    model: session.model.model,
    workspaceCheckpointId: checkpoint.workspaceCheckpointId,
    summaryMarkdown: active ? buildSummaryFromActiveCompaction(session, active) : buildHandoffOnlySummary(session),
    paths: {
      json: jsonPath,
      markdown: markdownPath
    }
  };

  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(jsonPath, JSON.stringify(artifact, null, 2));
  await fs.writeFile(markdownPath, renderHandoffMarkdown(artifact));
  return artifact;
}
