import { digestOmitting, encodeCanonicalTime, parseCanonicalTime } from '../kernel/identity.js';
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
  const fence: CanonicalTimeFenceV1 = {
    schemaVersion: 1,
    format: 'cliq-canonical-time-fence-v1',
    stateOwnerEpoch: Number(row.state_owner_epoch),
    lastAcceptedAt: row.last_accepted_at,
    observedWallClockAt: row.observed_wall_clock_at,
    state: row.state,
    updatedAt: row.updated_at,
    fenceDigest: row.fence_digest
  };
  if (digestOmitting(fence, 'fenceDigest') !== fence.fenceDigest) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence digest does not rehash');
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

export function advanceTimeFence(
  connection: SqliteConnection,
  stateOwnerEpoch: number,
  sampledNow = sampleCanonicalNow()
): TimeFenceAdvance {
  const current = readTimeFence(connection);
  if (current === undefined) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence is missing');
  }
  const observed = sampledNow;
  const observedMs = parseCanonicalTime(observed);
  const lastAcceptedMs = parseCanonicalTime(current.lastAcceptedAt);

  if (observedMs < lastAcceptedMs) {
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
