import { assertArtifactRef, parseCanonicalTime, requiredSafeInteger } from '../../kernel/identity.js';
import type { RunEvent, RunSnapshotV1, RunStatus, RunNextStep, WaitingReason, RunTerminalReason } from '../../kernel/types.js';
import type { ArtifactCatalog } from '../artifacts.js';
import { decodeRunSpec } from '../decoders.js';
import { KernelStorageError } from '../errors.js';
import { readRun } from '../rows.js';
import type { SqliteDriver, SqliteRow } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';

export type AttachRunInput = {
  principalId: string;
  runId: string;
  afterEventSeq: number;
  limit?: number;
};

export type AttachRunResult = {
  method: 'run.attach';
  snapshot: RunSnapshotV1;
  earliestRetainedEventSeq: number;
  latestRetainedEventSeq: number;
  highWaterEventSeq: number;
  events: RunEvent[];
  nextEventSeq: number;
};

export class EventCursorExpiredError extends KernelStorageError {
  constructor(readonly earliestEventSeq: number, readonly latestEventSeq: number,
              readonly snapshot: RunSnapshotV1) {
    super('EVENT_CURSOR_EXPIRED', 'Run event cursor precedes retained display events');
  }
}

const STATUS = new Set<RunStatus>([
  'queued', 'running', 'waiting', 'succeeded', 'completed_unverified', 'failed', 'cancelled'
]);
const NEXT_STEP = new Set<Exclude<RunNextStep, null>>(['agent', 'tool', 'verify', 'finalize', 'delivery']);
const WAITING_REASON = new Set<WaitingReason>(['approval', 'input', 'child', 'reconciliation']);
const TERMINAL_REASON = new Set<RunTerminalReason>([
  'verified', 'no_required_verifier', 'verification_failed', 'verifier_infrastructure_failed',
  'verifier_mutated_source', 'budget_exhausted', 'runtime_failed', 'cancelled_by_user', 'parent_cancelled'
]);
const PROGRESS_PHASE = new Set(['agent', 'tool', 'verify', 'recovery', 'delivery']);

function exactRecord(value: unknown, required: readonly string[], optional: readonly string[] = []):
  value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
}

function optionalRef(value: unknown): boolean {
  if (value === undefined) return true;
  if (typeof value !== 'string') return false;
  try { assertArtifactRef(value); return true; } catch { return false; }
}

function eventFromRow(row: SqliteRow, runId: string): RunEvent {
  try {
    if (typeof row.payload_json !== 'string' || typeof row.occurred_at !== 'string') {
      throw new TypeError('Run event row has invalid storage types');
    }
    const value: unknown = JSON.parse(row.payload_json);
    if (!exactRecord(value, ['schemaVersion', 'kind', 'runId', 'eventSeq', 'occurredAt'], [
      'runRevision', 'status', 'nextStep', 'waitingReason', 'waitingOnRef', 'frontierRef',
      'latestRunItemSeq', 'resultRef', 'terminalReason', 'terminalDetailRef',
      'observedRunRevision', 'phase', 'opId', 'messageRef', 'completedUnits', 'totalUnits'
    ]) || value.schemaVersion !== 1 || value.runId !== runId ||
        value.eventSeq !== requiredSafeInteger(row.event_seq, 'RunEvent.eventSeq') ||
        value.occurredAt !== row.occurred_at) {
      throw new TypeError('Run event row and payload disagree');
    }
    parseCanonicalTime(value.occurredAt as string);
    if (value.kind === 'state_changed') {
      if (!exactRecord(value, ['schemaVersion', 'kind', 'runId', 'eventSeq', 'runRevision',
        'status', 'nextStep', 'latestRunItemSeq', 'occurredAt'], [
        'waitingReason', 'waitingOnRef', 'frontierRef', 'resultRef', 'terminalReason', 'terminalDetailRef'
      ]) || !Number.isSafeInteger(value.runRevision) || (value.runRevision as number) < 1 ||
          !Number.isSafeInteger(value.latestRunItemSeq) || (value.latestRunItemSeq as number) < 0 ||
          !STATUS.has(value.status as RunStatus) ||
          (value.nextStep !== null && !NEXT_STEP.has(value.nextStep as Exclude<RunNextStep, null>)) ||
          (value.waitingReason !== undefined && !WAITING_REASON.has(value.waitingReason as WaitingReason)) ||
          (value.terminalReason !== undefined && !TERMINAL_REASON.has(value.terminalReason as RunTerminalReason)) ||
          !optionalRef(value.waitingOnRef) || !optionalRef(value.frontierRef) ||
          !optionalRef(value.resultRef) || !optionalRef(value.terminalDetailRef)) {
        throw new TypeError('Run state event has invalid fields');
      }
      return value as RunEvent;
    }
    if (value.kind === 'progress') {
      if (!exactRecord(value, ['schemaVersion', 'kind', 'runId', 'eventSeq',
        'observedRunRevision', 'phase', 'occurredAt'], [
        'opId', 'messageRef', 'completedUnits', 'totalUnits'
      ]) || !Number.isSafeInteger(value.observedRunRevision) ||
          (value.observedRunRevision as number) < 1 || !PROGRESS_PHASE.has(value.phase as string) ||
          (value.opId !== undefined && (typeof value.opId !== 'string' || value.opId.length > 128)) ||
          !optionalRef(value.messageRef) ||
          (value.completedUnits !== undefined &&
            (!Number.isSafeInteger(value.completedUnits) || (value.completedUnits as number) < 0)) ||
          (value.totalUnits !== undefined &&
            (!Number.isSafeInteger(value.totalUnits) || (value.totalUnits as number) < 0))) {
        throw new TypeError('Run progress event has invalid fields');
      }
      return value as RunEvent;
    }
    throw new TypeError('unknown Run event kind');
  } catch (error) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'retained Run event is invalid', { cause: error });
  }
}

function nonnegativeSafeInteger(value: unknown, label: string): number {
  try {
    const integer = requiredSafeInteger(value, label);
    if (integer < 0) throw new TypeError(`${label} is negative`);
    return integer;
  } catch (error) {
    throw new KernelStorageError('RECOVERY_REQUIRED', `${label} is invalid`, { cause: error });
  }
}

/** Retained display events never become execution or recovery authority. */
export async function attachRun(driver: SqliteDriver, artifacts: ArtifactCatalog,
                                owner: StateOwnerContext, input: AttachRunInput): Promise<AttachRunResult> {
  if (typeof input.principalId !== 'string' || !input.principalId ||
      typeof input.runId !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(input.runId) ||
      !Number.isSafeInteger(input.afterEventSeq) || input.afterEventSeq < 0 ||
      (input.limit !== undefined &&
        (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 1000))) {
    throw new KernelStorageError('INVALID_REQUEST', 'invalid Run attach request');
  }
  assertActiveStateOwner(driver, owner);
  const initial = driver.prepare('SELECT principal_id, spec_ref FROM runs WHERE id = ?')
    .get<{ principal_id: string; spec_ref: string }>(input.runId);
  if (!initial || initial.principal_id !== input.principalId) {
    throw new KernelStorageError('NOT_FOUND', 'Run does not exist for this principal');
  }
  let operation: RunSnapshotV1['operation'];
  try {
    operation = decodeRunSpec(await artifacts.readCanonical(initial.spec_ref)).operation;
  } catch (error) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'RunSpec required for attach is invalid', { cause: error });
  }
  return driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const row = connection.prepare('SELECT principal_id, spec_ref FROM runs WHERE id = ?')
      .get<{ principal_id: string; spec_ref: string }>(input.runId);
    if (!row || row.principal_id !== input.principalId) {
      throw new KernelStorageError('NOT_FOUND', 'Run does not exist for this principal');
    }
    if (row.spec_ref !== initial.spec_ref) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'RunSpec changed during attach');
    }
    const run = readRun(connection, input.runId);
    const itemHighWater = connection.prepare('SELECT max(item_seq) AS max_seq FROM items WHERE run_id = ?')
      .get<{ max_seq: number | bigint | null }>(input.runId);
    const latestRunItemSeq = itemHighWater?.max_seq === null || itemHighWater?.max_seq === undefined
      ? 0 : nonnegativeSafeInteger(itemHighWater.max_seq, 'Run latest item sequence');
    const snapshot: RunSnapshotV1 = { schemaVersion: 1, operation, run, latestRunItemSeq };
    const bounds = connection.prepare(
      'SELECT min(event_seq) AS first_seq, max(event_seq) AS last_seq FROM run_events WHERE run_id = ?'
    ).get<{ first_seq: number | bigint | null; last_seq: number | bigint | null }>(input.runId);
    if (bounds?.first_seq === null || bounds?.first_seq === undefined ||
        bounds.last_seq === null || bounds.last_seq === undefined) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'Run has no retained display event');
    }
    const earliestRetainedEventSeq = nonnegativeSafeInteger(bounds.first_seq, 'earliest Run event');
    const latestRetainedEventSeq = nonnegativeSafeInteger(bounds.last_seq, 'latest Run event');
    if (earliestRetainedEventSeq < 1 || latestRetainedEventSeq < earliestRetainedEventSeq) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'Run event bounds are invalid');
    }
    const highWaterEventSeq = latestRetainedEventSeq;
    if (input.afterEventSeq < earliestRetainedEventSeq - 1) {
      throw new EventCursorExpiredError(earliestRetainedEventSeq, latestRetainedEventSeq, snapshot);
    }
    if (input.afterEventSeq > highWaterEventSeq) {
      throw new KernelStorageError('INVALID_REQUEST', 'Run event cursor exceeds high-water');
    }
    const rows = connection.prepare(
      'SELECT event_seq, payload_json, occurred_at FROM run_events ' +
      'WHERE run_id = ? AND event_seq > ? AND event_seq <= ? ORDER BY event_seq LIMIT ?'
    ).all(input.runId, input.afterEventSeq, highWaterEventSeq, input.limit ?? 100);
    const events: RunEvent[] = [];
    let expectedSeq = input.afterEventSeq + 1;
    for (const row of rows) {
      const event = eventFromRow(row, input.runId);
      if (event.eventSeq !== expectedSeq) {
        throw new KernelStorageError('RECOVERY_REQUIRED', 'retained Run events have a sequence gap');
      }
      events.push(event);
      expectedSeq += 1;
    }
    if (events.length === 0 && input.afterEventSeq < highWaterEventSeq) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'Run event is missing before high-water');
    }
    return {
      method: 'run.attach' as const, snapshot, earliestRetainedEventSeq,
      latestRetainedEventSeq, highWaterEventSeq, events,
      nextEventSeq: events.at(-1)?.eventSeq ?? input.afterEventSeq
    };
  });
}
