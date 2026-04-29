import { createSession, saveSession } from './store.js';
import type { Session, SessionCheckpoint, SessionRecord } from './types.js';

export type ForkSessionOptions = {
  name?: string;
};

function cloneRecords(records: SessionRecord[]) {
  return structuredClone(records);
}

function cloneCheckpoints(checkpoints: SessionCheckpoint[]) {
  return structuredClone(checkpoints);
}

export async function forkSessionFromCheckpoint(
  cwd: string,
  parent: Session,
  checkpointId: string,
  options: ForkSessionOptions = {}
): Promise<Session> {
  const checkpointIndex = parent.checkpoints.findIndex((candidate) => candidate.id === checkpointId);
  if (checkpointIndex === -1) {
    throw new Error(`checkpoint not found: ${checkpointId}`);
  }
  const checkpoint = parent.checkpoints[checkpointIndex]!;

  if (checkpoint.recordIndex < 0 || checkpoint.recordIndex > parent.records.length) {
    throw new Error(`checkpoint has invalid record index: ${checkpoint.id}`);
  }

  const child = createSession(cwd);
  const name = options.name?.trim();
  child.name = name || undefined;
  child.parentSessionId = parent.id;
  child.forkedFromCheckpointId = checkpoint.id;
  child.model = { ...parent.model };
  child.lifecycle.turn = checkpoint.turn;
  child.records = cloneRecords(parent.records.slice(0, checkpoint.recordIndex));
  child.checkpoints = cloneCheckpoints(parent.checkpoints.slice(0, checkpointIndex + 1));

  await saveSession(cwd, child);
  return child;
}
