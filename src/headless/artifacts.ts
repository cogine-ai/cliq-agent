import { readHandoffArtifact } from '../handoff/export.js';
import { getWorkspaceCheckpoint } from '../session/checkpoints.js';
import { ensureSession, loadSessionById } from '../session/store.js';
import type {
  CompactionArtifact,
  Session,
  SessionCheckpoint,
  SessionRecord,
  WorkspaceCheckpoint
} from '../session/types.js';
import type {
  ArtifactView,
  CheckpointView,
  CompactionView,
  HandoffView,
  SessionRecordView,
  SessionView,
  WorkspaceCheckpointView
} from './contract.js';

const TOOL_PREVIEW_CHARS = 240;
const TRUNCATION_MARKER = '\n[cliq preview truncated]';
const SAFE_ARTIFACT_ID = /^[A-Za-z0-9_-]+$/;

function artifactNotFound(artifactId: string): never {
  throw new Error(`artifact not found: ${artifactId}`);
}

function isMissingArtifactError(error: unknown) {
  if (error && typeof error === 'object' && (error as NodeJS.ErrnoException).code === 'ENOENT') {
    return true;
  }
  return error instanceof Error && /\bENOENT\b|not found/i.test(error.message);
}

function preview(value: string, limit = TOOL_PREVIEW_CHARS) {
  if (value.length <= limit) {
    return value;
  }
  return `${value.slice(0, Math.max(0, limit - TRUNCATION_MARKER.length))}${TRUNCATION_MARKER}`;
}

function actionType(record: Extract<SessionRecord, { kind: 'assistant' }>): SessionRecordView {
  if (record.action && 'message' in record.action) {
    return {
      id: record.id,
      ts: record.ts,
      kind: 'assistant',
      role: 'assistant',
      actionType: 'message',
      message: record.action.message
    };
  }

  if (record.action) {
    return {
      id: record.id,
      ts: record.ts,
      kind: 'assistant',
      role: 'assistant',
      actionType: 'tool-call'
    };
  }

  return {
    id: record.id,
    ts: record.ts,
    kind: 'assistant',
    role: 'assistant',
    actionType: record.content.trim() ? 'invalid' : 'none'
  };
}

export function toSessionRecordView(record: SessionRecord): SessionRecordView {
  switch (record.kind) {
    case 'system':
      return {
        id: record.id,
        ts: record.ts,
        kind: 'system',
        role: 'system',
        text: record.content
      };
    case 'user':
      return {
        id: record.id,
        ts: record.ts,
        kind: 'user',
        role: 'user',
        text: record.content
      };
    case 'tool':
      return {
        id: record.id,
        ts: record.ts,
        kind: 'tool',
        role: 'user',
        tool: record.tool,
        status: record.status,
        contentPreview: preview(record.content),
        ...(record.meta ? { meta: record.meta } : {})
      };
    case 'assistant':
      return actionType(record);
  }
}

export function toCheckpointView(checkpoint: SessionCheckpoint): CheckpointView {
  return {
    id: checkpoint.id,
    ...(checkpoint.name ? { name: checkpoint.name } : {}),
    kind: checkpoint.kind,
    createdAt: checkpoint.createdAt,
    recordIndex: checkpoint.recordIndex,
    turn: checkpoint.turn,
    ...(checkpoint.workspaceCheckpointId ? { workspaceCheckpointId: checkpoint.workspaceCheckpointId } : {})
  };
}

export function toWorkspaceCheckpointView(checkpoint: WorkspaceCheckpoint): WorkspaceCheckpointView {
  if (checkpoint.kind === 'unavailable') {
    return {
      id: checkpoint.id,
      kind: checkpoint.kind,
      status: checkpoint.status,
      createdAt: checkpoint.createdAt,
      workspaceRealPath: checkpoint.workspaceRealPath,
      reason: checkpoint.reason
    };
  }

  return {
    id: checkpoint.id,
    kind: checkpoint.kind,
    status: checkpoint.status,
    createdAt: checkpoint.createdAt,
    workspaceRealPath: checkpoint.workspaceRealPath,
    gitRootRealPath: checkpoint.gitRootRealPath,
    commitId: checkpoint.commitId,
    ...(checkpoint.warnings.length > 0 ? { warnings: checkpoint.warnings } : {})
  };
}

export function toCompactionView(compaction: CompactionArtifact): CompactionView {
  return {
    id: compaction.id,
    status: compaction.status,
    createdAt: compaction.createdAt,
    coveredRange: compaction.coveredRange,
    firstKeptRecordId: compaction.firstKeptRecordId,
    ...(compaction.anchorCheckpointId ? { anchorCheckpointId: compaction.anchorCheckpointId } : {}),
    createdBy: compaction.createdBy,
    summaryMarkdown: compaction.summaryMarkdown,
    ...(compaction.auto
      ? {
          auto: {
            trigger: compaction.auto.trigger,
            phase: compaction.auto.phase,
            estimatedTokensBefore: compaction.auto.estimatedTokensBefore,
            ...(compaction.auto.estimatedTokensAfter !== undefined
              ? { estimatedTokensAfter: compaction.auto.estimatedTokensAfter }
              : {})
          }
        }
      : {})
  };
}

export function toSessionView(session: Session): SessionView {
  return {
    id: session.id,
    cwd: session.cwd,
    model: session.model,
    lifecycle: session.lifecycle,
    ...(session.parentSessionId ? { parentSessionId: session.parentSessionId } : {}),
    ...(session.forkedFromCheckpointId ? { forkedFromCheckpointId: session.forkedFromCheckpointId } : {}),
    records: session.records.map(toSessionRecordView),
    checkpoints: session.checkpoints.map(toCheckpointView),
    compactions: session.compactions.map(toCompactionView)
  };
}

async function toHandoffView(handoffId: string): Promise<HandoffView> {
  const handoff = await readHandoffArtifact(handoffId);
  const artifact = handoff.json;
  return {
    id: artifact.id,
    createdAt: artifact.createdAt,
    sessionId: artifact.sessionId,
    ...(artifact.parentSessionId ? { parentSessionId: artifact.parentSessionId } : {}),
    checkpointId: artifact.checkpointId,
    ...(artifact.activeCompactionId ? { activeCompactionId: artifact.activeCompactionId } : {}),
    summarySource: artifact.summarySource,
    provider: artifact.provider,
    model: artifact.model,
    ...(artifact.workspaceCheckpointId ? { workspaceCheckpointId: artifact.workspaceCheckpointId } : {}),
    summaryMarkdown: artifact.summaryMarkdown,
    markdown: handoff.markdown
  };
}

async function getWorkspaceCheckpointView(artifactId: string) {
  try {
    return toWorkspaceCheckpointView(await getWorkspaceCheckpoint(artifactId));
  } catch (error) {
    if (isMissingArtifactError(error)) {
      artifactNotFound(artifactId);
    }
    throw error;
  }
}

async function getHandoffView(artifactId: string) {
  try {
    return await toHandoffView(artifactId);
  } catch (error) {
    if (isMissingArtifactError(error)) {
      artifactNotFound(artifactId);
    }
    throw error;
  }
}

function sessionNotFound(sessionId: string): never {
  throw new Error(`session not found: ${sessionId}`);
}

async function sessionForView(cwd: string, sessionId?: string): Promise<Session> {
  if (!sessionId) {
    return await ensureSession(cwd);
  }

  return (await loadSessionById(cwd, sessionId)) ?? sessionNotFound(sessionId);
}

export async function getSessionView(cwd: string, sessionId?: string): Promise<SessionView> {
  return toSessionView(await sessionForView(cwd, sessionId));
}

export async function getArtifactViewForRequest(
  cwd: string,
  artifactId: string,
  sessionId?: string
): Promise<ArtifactView> {
  return await getArtifactView(await sessionForView(cwd, sessionId), artifactId);
}

export async function getArtifactView(session: Session, artifactId: string): Promise<ArtifactView> {
  if (!SAFE_ARTIFACT_ID.test(artifactId)) {
    artifactNotFound(artifactId);
  }

  const checkpoint = session.checkpoints.find((candidate) => candidate.id === artifactId);
  if (checkpoint) {
    const checkpointView = toCheckpointView(checkpoint);
    const workspaceCheckpoint = checkpoint.workspaceCheckpointId
      ? await getWorkspaceCheckpointView(checkpoint.workspaceCheckpointId)
      : undefined;
    return {
      kind: 'checkpoint',
      checkpoint: checkpointView,
      ...(workspaceCheckpoint ? { workspaceCheckpoint } : {})
    };
  }

  if (artifactId.startsWith('wchk_')) {
    return {
      kind: 'workspace-checkpoint',
      workspaceCheckpoint: await getWorkspaceCheckpointView(artifactId)
    };
  }

  const compaction = session.compactions.find((candidate) => candidate.id === artifactId);
  if (compaction) {
    return {
      kind: 'compaction',
      compaction: toCompactionView(compaction)
    };
  }

  if (artifactId.startsWith('handoff_')) {
    return {
      kind: 'handoff',
      handoff: await getHandoffView(artifactId)
    };
  }

  artifactNotFound(artifactId);
}
