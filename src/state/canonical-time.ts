import {
  assertArtifactRef,
  digestOmitting,
  encodeCanonicalTime,
  parseCanonicalTime,
  requiredSafeInteger
} from '../kernel/identity.js';
import type { CanonicalTimeFenceV1 } from '../kernel/types.js';
import { KernelStorageError } from './errors.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';

function fenceFromRow(row: {
  state_owner_epoch: unknown;
  last_accepted_at: string;
  observed_wall_clock_at: string;
  state: CanonicalTimeFenceV1['state'];
  updated_at: string;
  fence_digest: string;
}): CanonicalTimeFenceV1 {
  let stateOwnerEpoch: number;
  try {
    stateOwnerEpoch = requiredSafeInteger(row.state_owner_epoch, 'state owner epoch');
    if (stateOwnerEpoch < 1) throw new TypeError('state owner epoch must be positive');
    parseCanonicalTime(row.last_accepted_at);
    parseCanonicalTime(row.observed_wall_clock_at);
    parseCanonicalTime(row.updated_at);
    assertArtifactRef(row.fence_digest);
  } catch {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence fields are invalid');
  }
  if (row.state !== 'healthy' && row.state !== 'clock_regressed') {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence state is invalid');
  }
  const fence: CanonicalTimeFenceV1 = {
    schemaVersion: 1,
    format: 'cliq-canonical-time-fence-v1',
    stateOwnerEpoch,
    lastAcceptedAt: row.last_accepted_at,
    observedWallClockAt: row.observed_wall_clock_at,
    state: row.state,
    updatedAt: row.updated_at,
    fenceDigest: row.fence_digest
  };
  if (digestOmitting(fence, 'fenceDigest') !== fence.fenceDigest) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence digest does not rehash');
  }
  if (
    fence.updatedAt !== fence.lastAcceptedAt ||
    (fence.state === 'healthy' && fence.observedWallClockAt !== fence.lastAcceptedAt)
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence ordering is invalid');
  }
  return fence;
}

export function readTimeFence(connection: SqliteConnection | SqliteDriver): CanonicalTimeFenceV1 | undefined {
  const row = connection
    .prepare(
      `SELECT state_owner_epoch, last_accepted_at, observed_wall_clock_at, state, updated_at, fence_digest
       FROM canonical_time_fence WHERE id = 1`
    )
    .get<{
      state_owner_epoch: unknown;
      last_accepted_at: string;
      observed_wall_clock_at: string;
      state: CanonicalTimeFenceV1['state'];
      updated_at: string;
      fence_digest: string;
    }>();
  return row === undefined ? undefined : fenceFromRow(row);
}

export function insertGenesisTimeFence(
  connection: SqliteConnection,
  stateOwnerEpoch: number,
  now: string
): CanonicalTimeFenceV1 {
  const fence: CanonicalTimeFenceV1 = {
    schemaVersion: 1,
    format: 'cliq-canonical-time-fence-v1',
    stateOwnerEpoch,
    lastAcceptedAt: now,
    observedWallClockAt: now,
    state: 'healthy',
    updatedAt: now,
    fenceDigest: ''
  };
  fence.fenceDigest = digestOmitting(fence, 'fenceDigest');
  connection
    .prepare(
      `INSERT INTO canonical_time_fence (
         id, state_owner_epoch, last_accepted_at, observed_wall_clock_at, state, updated_at, fence_digest
       ) VALUES (1, ?, ?, ?, ?, ?, ?)`
    )
    .run(BigInt(stateOwnerEpoch), now, now, fence.state, now, fence.fenceDigest);
  return fence;
}

export function sampleCanonicalNow(): string {
  return encodeCanonicalTime(Date.now());
}

export type TimeFenceAdvance = 'healthy' | 'clock_regressed' | 'still_regressed';

function persistRegressedFence(
  connection: SqliteConnection,
  current: CanonicalTimeFenceV1,
  observed: string
): void {
  const regressed: CanonicalTimeFenceV1 = {
    ...current,
    observedWallClockAt: observed,
    state: 'clock_regressed',
    updatedAt: current.updatedAt,
    fenceDigest: ''
  };
  regressed.fenceDigest = digestOmitting(regressed, 'fenceDigest');
  connection
    .prepare(
      `UPDATE canonical_time_fence
       SET observed_wall_clock_at = ?, state = ?, fence_digest = ?
       WHERE id = 1`
    )
    .run(observed, 'clock_regressed', regressed.fenceDigest);
}

// Admission must omit sampledNow so a stale pre-CAS timestamp cannot trip clock_regressed.
export function advanceTimeFence(
  connection: SqliteConnection,
  stateOwnerEpoch: number,
  sampledNow?: string
): TimeFenceAdvance {
  const current = readTimeFence(connection);
  if (current === undefined) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence is missing');
  }
  if (current.stateOwnerEpoch !== stateOwnerEpoch) {
    throw new KernelStorageError(
      'RECOVERY_REQUIRED',
      'canonical time fence is owned by a different state owner epoch'
    );
  }
  const observed = sampledNow ?? sampleCanonicalNow();
  const observedMs = parseCanonicalTime(observed);
  const lastAcceptedMs = parseCanonicalTime(current.lastAcceptedAt);

  if (observedMs < lastAcceptedMs) {
    persistRegressedFence(connection, current, observed);
    return 'clock_regressed';
  }

  if (current.state === 'clock_regressed') {
    return 'still_regressed';
  }

  const next: CanonicalTimeFenceV1 = {
    schemaVersion: 1,
    format: 'cliq-canonical-time-fence-v1',
    stateOwnerEpoch,
    lastAcceptedAt: observed,
    observedWallClockAt: observed,
    state: 'healthy',
    updatedAt: observed,
    fenceDigest: ''
  };
  next.fenceDigest = digestOmitting(next, 'fenceDigest');
  connection
    .prepare(
      `UPDATE canonical_time_fence
       SET state_owner_epoch = ?, last_accepted_at = ?, observed_wall_clock_at = ?,
           state = ?, updated_at = ?, fence_digest = ?
       WHERE id = 1`
    )
    .run(BigInt(stateOwnerEpoch), observed, observed, 'healthy', observed, next.fenceDigest);
  return 'healthy';
}

export function transferTimeFenceOwner(
  connection: SqliteConnection,
  priorOwnerEpoch: number,
  nextOwnerEpoch: number,
  sampledNow?: string
): TimeFenceAdvance {
  if (!Number.isSafeInteger(nextOwnerEpoch) || nextOwnerEpoch !== priorOwnerEpoch + 1) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'state owner epochs must advance contiguously');
  }
  const current = readTimeFence(connection);
  if (current === undefined || current.stateOwnerEpoch !== priorOwnerEpoch) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence does not match the prior owner');
  }
  const observed = sampledNow ?? sampleCanonicalNow();
  if (parseCanonicalTime(observed) < parseCanonicalTime(current.lastAcceptedAt)) {
    persistRegressedFence(connection, current, observed);
    return 'clock_regressed';
  }
  const state = current.state;

  const next: CanonicalTimeFenceV1 = {
    schemaVersion: 1,
    format: 'cliq-canonical-time-fence-v1',
    stateOwnerEpoch: nextOwnerEpoch,
    lastAcceptedAt: state === 'healthy' ? observed : current.lastAcceptedAt,
    observedWallClockAt: observed,
    state,
    updatedAt: state === 'healthy' ? observed : current.updatedAt,
    fenceDigest: ''
  };
  next.fenceDigest = digestOmitting(next, 'fenceDigest');
  const result = connection
    .prepare(
      `UPDATE canonical_time_fence
       SET state_owner_epoch = ?, last_accepted_at = ?, observed_wall_clock_at = ?,
           state = ?, updated_at = ?, fence_digest = ?
       WHERE id = 1 AND state_owner_epoch = ? AND fence_digest = ?`
    )
    .run(
      BigInt(nextOwnerEpoch),
      next.lastAcceptedAt,
      next.observedWallClockAt,
      next.state,
      next.updatedAt,
      next.fenceDigest,
      BigInt(priorOwnerEpoch),
      current.fenceDigest
    );
  if (result.changes !== 1n) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence changed during owner transfer');
  }
  return next.state === 'healthy' ? 'healthy' : 'still_regressed';
}

export function recoverRegressedTimeFence(
  connection: SqliteConnection,
  stateOwnerEpoch: number,
  sampledNow?: string
): TimeFenceAdvance {
  const current = readTimeFence(connection);
  if (current === undefined || current.stateOwnerEpoch !== stateOwnerEpoch) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence does not belong to the active owner');
  }
  if (current.state === 'healthy') return 'healthy';
  const observed = sampledNow ?? sampleCanonicalNow();
  if (parseCanonicalTime(observed) < parseCanonicalTime(current.lastAcceptedAt)) {
    persistRegressedFence(connection, current, observed);
    return 'still_regressed';
  }
  const recovered: CanonicalTimeFenceV1 = {
    schemaVersion: 1,
    format: 'cliq-canonical-time-fence-v1',
    stateOwnerEpoch,
    lastAcceptedAt: observed,
    observedWallClockAt: observed,
    state: 'healthy',
    updatedAt: observed,
    fenceDigest: ''
  };
  recovered.fenceDigest = digestOmitting(recovered, 'fenceDigest');
  const result = connection
    .prepare(
      `UPDATE canonical_time_fence
       SET last_accepted_at = ?, observed_wall_clock_at = ?, state = 'healthy',
           updated_at = ?, fence_digest = ?
       WHERE id = 1 AND state_owner_epoch = ? AND state = 'clock_regressed' AND fence_digest = ?`
    )
    .run(
      observed,
      observed,
      observed,
      recovered.fenceDigest,
      BigInt(stateOwnerEpoch),
      current.fenceDigest
    );
  if (result.changes !== 1n) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence changed during recovery');
  }
  return 'healthy';
}
