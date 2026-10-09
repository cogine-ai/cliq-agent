import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, requiredSafeInteger } from '../kernel/identity.js';
import type {
  CanonicalTimeFenceV1,
  WorkerDeathWait,
  StateOwnerRecordV1,
  StateOwnerTransitionEvidenceV1
} from '../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { insertArtifactMetadata } from './artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { decodeStateOwnerRecord } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { readCanonicalArtifact } from './agent-context.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { assertStateOwnerLock, type HeldStateOwnerLock } from './native-owner.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';

export type StateOwnerContext = {
  ownerEpoch: number;
  supervisorInstanceId: string;
  rowDigest: string;
  processIdentityRef: string;
  processIdentityDigest: string;
  stateLockIdentityRef: string;
  stateLockIdentityDigest: string;
  stateRootIdentityRef: string;
  stateRootIdentityDigest: string;
  filesystem: HeldStateOwnerLock;
};

type StateOwnerSqlRow = {
  owner_epoch: unknown;
  supervisor_instance_id: string;
  record_json: string;
  state: string;
  row_digest: string;
};

function stateOwnerFromSqlRow(row: StateOwnerSqlRow): StateOwnerRecordV1 {
  let value: unknown;
  try {
    value = JSON.parse(row.record_json);
  } catch {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'state owner row is not valid JSON');
  }
  let record: StateOwnerRecordV1;
  try {
    record = decodeStateOwnerRecord(value);
  } catch (error) {
    if (error instanceof KernelStorageError) {
      throw new KernelStorageError('RECOVERY_REQUIRED', `invalid state owner record: ${error.message}`);
    }
    throw error;
  }
  const ownerEpoch = requiredSafeInteger(row.owner_epoch, 'state owner epoch');
  if (
    record.schemaVersion !== 1 ||
    record.ownerEpoch !== ownerEpoch ||
    record.supervisorInstanceId !== row.supervisor_instance_id ||
    record.state !== row.state ||
    record.rowDigest !== row.row_digest
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'state owner row does not match its canonical record');
  }
  return record;
}

export function readStateOwner(
  connection: SqliteConnection | SqliteDriver,
  ownerEpoch: number
): StateOwnerRecordV1 | undefined {
  const row = connection
    .prepare(
      `SELECT owner_epoch, supervisor_instance_id, record_json, state, row_digest
       FROM state_owners WHERE owner_epoch = ?`
    )
    .get<StateOwnerSqlRow>(BigInt(ownerEpoch));
  return row === undefined ? undefined : stateOwnerFromSqlRow(row);
}

export function readLatestStateOwner(
  connection: SqliteConnection | SqliteDriver
): StateOwnerRecordV1 | undefined {
  const row = connection
    .prepare(
      `SELECT owner_epoch, supervisor_instance_id, record_json, state, row_digest
       FROM state_owners ORDER BY owner_epoch DESC LIMIT 1`
    )
    .get<StateOwnerSqlRow>();
  return row === undefined ? undefined : stateOwnerFromSqlRow(row);
}

export function readActiveStateOwner(
  connection: SqliteConnection | SqliteDriver
): Extract<StateOwnerRecordV1, { state: 'active' }> | undefined {
  const rows = connection
    .prepare(
      `SELECT owner_epoch, supervisor_instance_id, record_json, state, row_digest
       FROM state_owners WHERE state = 'active'`
    )
    .all<StateOwnerSqlRow>();
  if (rows.length > 1) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'more than one state owner is active');
  }
  if (rows[0] === undefined) return undefined;
  const record = stateOwnerFromSqlRow(rows[0]);
  if (record.state !== 'active') {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'active owner query returned a terminal record');
  }
  return record;
}

export function contextFromStateOwner(
  record: Extract<StateOwnerRecordV1, { state: 'active' }>,
  filesystem: HeldStateOwnerLock,
  stateRootIdentity: { ref: string; digest: string }
): StateOwnerContext {
  return {
    ownerEpoch: record.ownerEpoch,
    supervisorInstanceId: record.supervisorInstanceId,
    rowDigest: record.rowDigest,
    processIdentityRef: record.processIdentityRef,
    processIdentityDigest: record.processIdentityDigest,
    stateLockIdentityRef: record.stateLockIdentityRef,
    stateLockIdentityDigest: record.stateLockIdentityDigest,
    stateRootIdentityRef: stateRootIdentity.ref,
    stateRootIdentityDigest: stateRootIdentity.digest,
    filesystem
  };
}

export function assertActiveStateOwner(
  connection: SqliteConnection | SqliteDriver,
  expected: StateOwnerContext
): Extract<StateOwnerRecordV1, { state: 'active' }> {
  assertStateOwnerLock(expected.filesystem);
  const active = readActiveStateOwner(connection);
  if (
    active === undefined ||
    active.state !== 'active' ||
    active.ownerEpoch !== expected.ownerEpoch ||
    active.supervisorInstanceId !== expected.supervisorInstanceId ||
    active.rowDigest !== expected.rowDigest ||
    active.processIdentityRef !== expected.processIdentityRef ||
    active.processIdentityDigest !== expected.processIdentityDigest ||
    active.stateLockIdentityRef !== expected.stateLockIdentityRef ||
    active.stateLockIdentityDigest !== expected.stateLockIdentityDigest
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'state owner authority is stale or no longer active');
  }
  const fence = readTimeFence(connection);
  if (fence === undefined || fence.stateOwnerEpoch !== expected.ownerEpoch) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence does not belong to the active owner');
  }
  return active;
}

export function assertContiguousStateOwnerHistory(connection: SqliteConnection | SqliteDriver): void {
  const rows = connection
    .prepare('SELECT owner_epoch FROM state_owners ORDER BY owner_epoch')
    .all<{ owner_epoch: unknown }>();
  for (let index = 0; index < rows.length; index += 1) {
    if (requiredSafeInteger(rows[index]!.owner_epoch, 'state owner epoch') !== index + 1) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'state owner epochs are not contiguous');
    }
  }
}

export function terminalStateOwnerRecord(
  active: Extract<StateOwnerRecordV1, { state: 'active' }>,
  evidence: StateOwnerTransitionEvidenceV1,
  evidenceRef: string,
  releasedAt: string
): Extract<StateOwnerRecordV1, { state: 'terminal' }> {
  const record: Extract<StateOwnerRecordV1, { state: 'terminal' }> = {
    ...active,
    state: 'terminal',
    rowVersion: 2,
    releasedAt,
    terminalReason: evidence.kind,
    transitionEvidenceRef: evidenceRef,
    transitionEvidenceDigest: evidence.evidenceDigest,
    rowDigest: ''
  };
  record.rowDigest = digestOmitting(record, 'rowDigest');
  return record;
}

export async function gracefullyReleaseStateOwner(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  expected: StateOwnerContext
): Promise<StateOwnerRecordV1> {
  const active = assertActiveStateOwner(driver, expected);
  assertSourceInspectionsRetired(driver);
  const waitingCut = readWaitingRunCut(driver);
  for (const row of waitingCut) {
    const wait = await readCanonicalArtifact<WorkerDeathWait>(artifacts, row.waiting_on_ref);
    if (wait.kind !== 'reconciliation' || wait.subject?.kind !== 'worker_death' ||
        (wait.probeState?.phase !== 'automatic_in_flight' && wait.probeState?.phase !== 'user_in_flight')) continue;
    await readRecoveryClosure(driver, artifacts, row.id);
    if (wait.probeState.dispatch.owningSupervisorInstanceId === expected.supervisorInstanceId) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'graceful release requires the exact worker inspection cancellation and join closure');
    }
  }
  const fence = readTimeFence(driver);
  if (fence === undefined) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence is missing');
  }
  const observedAt = sampleCanonicalNow();
  const evidence: StateOwnerTransitionEvidenceV1 = {
    schemaVersion: 1,
    format: 'cliq-state-owner-transition-evidence-v1',
    priorOwnerEpoch: active.ownerEpoch,
    priorSupervisorInstanceId: active.supervisorInstanceId,
    priorProcessIdentityRef: active.processIdentityRef,
    priorProcessIdentityDigest: active.processIdentityDigest,
    stateLockIdentityRef: active.stateLockIdentityRef,
    stateLockIdentityDigest: active.stateLockIdentityDigest,
    observedAt,
    evidenceDigest: '',
    kind: 'graceful_release',
    releasingProcessIdentityRef: active.processIdentityRef,
    releasingProcessIdentityDigest: active.processIdentityDigest
  };
  evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest');
  const published = await artifacts.publishCanonical(
    evidence,
    'cliq-state-owner-transition-evidence-v1'
  );
  let terminal!: Extract<StateOwnerRecordV1, { state: 'terminal' }>;

  driver.transaction((connection) => {
    assertActiveStateOwner(connection, expected);
    assertSourceInspectionsRetired(connection);
    // No new or replaced wait can slip between retained validation and the final owner transition.
    if (canonicalSha256(readWaitingRunCut(connection)) !== canonicalSha256(waitingCut)) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'worker inspection cut changed during graceful release');
    }
    const transactionObservedAt = sampleCanonicalNow();
    const lockedFence = readTimeFence(connection);
    if (lockedFence === undefined) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence is missing');
    }
    const recordedAt = maxCanonicalTime(transactionObservedAt, lockedFence.lastAcceptedAt);
    advanceTimeFence(connection, active.ownerEpoch, transactionObservedAt);
    terminal = terminalStateOwnerRecord(active, evidence, published.ref, recordedAt);
    insertArtifactMetadata(connection, published, recordedAt);
    const result = connection
      .prepare(
        `UPDATE state_owners
         SET record_json = ?, state = 'terminal', row_digest = ?
         WHERE owner_epoch = ? AND state = 'active' AND row_digest = ?`
      )
      .run(JSON.stringify(terminal), terminal.rowDigest, BigInt(active.ownerEpoch), active.rowDigest);
    if (result.changes !== 1n) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'state owner changed during graceful release');
    }
  });
  return terminal;
}

function assertSourceInspectionsRetired(connection: SqliteConnection | SqliteDriver): void {
  if (connection.prepare("SELECT inspection_id FROM source_inspection_attempts WHERE phase != 'retired' LIMIT 1").get()) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'source inspection requires actual resource retirement before owner release');
  }
}

function readWaitingRunCut(connection: SqliteConnection | SqliteDriver) {
  return connection.prepare(`SELECT id, revision, status, waiting_reason, waiting_on_ref
    FROM runs WHERE waiting_on_ref IS NOT NULL ORDER BY id`)
    .all<{ id: string; revision: unknown; status: string; waiting_reason: string | null; waiting_on_ref: string }>()
    .map(row => ({ ...row, revision: requiredSafeInteger(row.revision, 'waiting Run revision') }));
}

export function insertStateOwnerArtifacts(
  connection: SqliteConnection,
  artifacts: readonly PublishedArtifact[],
  createdAt: string
): void {
  for (const artifact of artifacts) insertArtifactMetadata(connection, artifact, createdAt);
}

export function assertFenceHealthy(fence: CanonicalTimeFenceV1 | undefined): CanonicalTimeFenceV1 {
  if (fence === undefined) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence is missing');
  }
  if (fence.state !== 'healthy') {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence is clock_regressed');
  }
  return fence;
}

function maxCanonicalTime(left: string, right: string): string {
  return left >= right ? left : right;
}
