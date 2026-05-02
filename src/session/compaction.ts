import { makeId, mutateSession, nowIso } from './store.js';
import type { CompactionArtifact, Session } from './types.js';

export type CreateCompactionOptions = {
  endIndexExclusive: number;
  summaryMarkdown: string;
  anchorCheckpointId?: string;
  createdBy?: CompactionArtifact['createdBy'];
  details?: CompactionArtifact['details'];
  auto?: CompactionArtifact['auto'];
};

function activeCompactions(session: Session) {
  return session.compactions.filter((artifact) => artifact.status === 'active');
}

function validateCompactionRange(session: Session, endIndexExclusive: number) {
  if (!Number.isInteger(endIndexExclusive) || endIndexExclusive <= 0) {
    throw new Error(`compact end index must be a positive integer: ${endIndexExclusive}`);
  }

  if (endIndexExclusive >= session.records.length) {
    throw new Error('compact must leave a non-empty tail');
  }

  const active = activeCompactions(session);
  const currentEnd = Math.max(0, ...active.map((artifact) => artifact.coveredRange.endIndexExclusive));
  if (active.length > 0 && endIndexExclusive <= currentEnd) {
    throw new Error('new compaction range must advance beyond the active compaction');
  }
}

export async function createCompaction(
  cwd: string,
  session: Session,
  options: CreateCompactionOptions
): Promise<CompactionArtifact> {
  const summaryMarkdown = options.summaryMarkdown.trim();
  if (!summaryMarkdown) {
    throw new Error('compact summary cannot be empty');
  }

  return await mutateSession(cwd, session, (current) => {
    validateCompactionRange(current, options.endIndexExclusive);

    const artifact: CompactionArtifact = {
      id: makeId('cmp'),
      status: 'active',
      createdAt: nowIso(),
      coveredRange: {
        startIndexInclusive: 0,
        endIndexExclusive: options.endIndexExclusive
      },
      firstKeptRecordId: current.records[options.endIndexExclusive]!.id,
      anchorCheckpointId: options.anchorCheckpointId,
      createdBy: options.createdBy ?? {
        provider: current.model.provider,
        model: current.model.model
      },
      summaryMarkdown,
      details: options.details,
      auto: options.auto
    };

    for (const active of activeCompactions(current)) {
      active.status = 'superseded';
    }
    current.compactions.push(artifact);
    return artifact;
  });
}
