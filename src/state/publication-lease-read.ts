import { canonicalSha256 } from '../kernel/canonical.js';
import { parseCanonicalTime } from '../kernel/identity.js';
import type { BoundWorkerLaunch, Run, WorkerLaunch } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { KernelStorageError } from './errors.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import { readRun } from './rows.js';
import { assertAgentLeaseReadExecution, assertDeliveryPublicationExecution, type DeliveryPublicationTask, type RunExecutionWorkerIdentity } from './run-execution.js';
import { assertSqliteConnectionOwnedBy, sqliteConnectionBelongsTo, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

type RecordedLeases = Readonly<{ initial: BoundWorkerLaunch; latest: BoundWorkerLaunch; rows: ReadonlyMap<number, string> }>;
type Binding = { driver: SqliteDriver; owner: StateOwnerContext; leases: RecordedLeases };
const holders = new Map<string, Map<SqliteDriver, Binding>>();

/** Pure comparison data. Returned projections never replace recovery facts. */
export function projectRecordedPublicationLeases(leases: RecordedLeases, current: WorkerLaunch,
  rows: readonly WorkerLaunch[]): readonly WorkerLaunch[] {
  if (current.phase !== 'activated' || current.generationWriteState !== 'active') return rows;
  requireEqual(current, leases.latest, 'publication lease read requires the latest original renewal');
  return rows.map(row => {
    if (row.launchId !== leases.initial.launchId || row.phase !== 'activated' || row.generationWriteState !== 'active') return row;
    if (leases.rows.get(row.leaseVersion) !== canonicalSha256(row))
      throw new KernelStorageError('LEASE_FENCED', 'publication read substituted an unrecorded worker lease');
    return leases.initial;
  });
}

function projected(connection: SqliteConnection, runId: string, rows: readonly WorkerLaunch[]): readonly WorkerLaunch[] {
  const candidates = holders.get(runId);
  const binding = candidates && [...candidates.values()].find(value => sqliteConnectionBelongsTo(value.driver, connection));
  if (!binding) return rows;
  assertSqliteConnectionOwnedBy(binding.driver, connection);
  const current = readRequiredWorkerLaunch(connection, binding.leases.initial.launchId);
  return projectRecordedPublicationLeases(binding.leases, current, rows);
}

export function assertPublicationLeaseReadRows(connection: SqliteConnection, runId: string, actual: readonly WorkerLaunch[],
  expected: readonly WorkerLaunch[], message: string): void {
  // Lifecycle changes retain ordinary full-row equality, including retirement.
  if (canonicalSha256(actual) === canonicalSha256(expected)) return;
  requireEqual(projected(connection, runId, actual), projected(connection, runId, expected), message);
}

export function publicationLeaseSnapshotDigest(connection: SqliteConnection,
  snapshot: { run: { id: string }; launches: readonly WorkerLaunch[] }): string {
  return canonicalSha256({ ...snapshot, launches: projected(connection, snapshot.run.id, snapshot.launches) });
}

export type WorkerLeaseReads = Readonly<{ record(previous: BoundWorkerLaunch, renewed: BoundWorkerLaunch): void; close(): void }>;

/** Data checks only. The caller separately requires its genuine holder,
 * original StateOwner and the exact row returned by the real SQL renewal. */
export function validatePublicationLeaseRenewal(previous: BoundWorkerLaunch, renewed: BoundWorkerLaunch, run: Run): void {
  requireEqual({ ...renewed, leaseVersion: previous.leaseVersion, leaseExpiresAt: previous.leaseExpiresAt }, previous,
    'publication renewal changed immutable worker fields');
  if (renewed.leaseVersion !== previous.leaseVersion + 1 || !previous.leaseExpiresAt || !renewed.leaseExpiresAt ||
      renewed.leaseExpiresAt <= previous.leaseExpiresAt || parseCanonicalTime(renewed.leaseExpiresAt) > parseCanonicalTime(run.deadlineAt) ||
      run.status !== 'running' || run.cancelRequested || run.stopIntentRef || run.activeWorkerLaunchId !== previous.launchId ||
      run.leaseEpoch !== previous.leaseEpoch)
    throw new KernelStorageError('LEASE_FENCED', 'publication renewal lost its original live Run');
}

/** Issued by the genuine publication holder. Only actual SQL renewals enter
 * this bounded-lifetime read equivalence; release still uses the latest row. */
export function beginPublicationLeaseReads(driver: SqliteDriver, owner: StateOwnerContext, execution: unknown,
  worker: RunExecutionWorkerIdentity, task: DeliveryPublicationTask): WorkerLeaseReads {
  assertDeliveryPublicationExecution(driver, owner, execution, worker, task);
  return beginWorkerLeaseReads(driver, owner, worker);
}

/** The original activated agent worker owns its history-read equivalence. */
export function beginAgentLeaseReads(driver: SqliteDriver, owner: StateOwnerContext, execution: unknown): WorkerLeaseReads {
  return beginWorkerLeaseReads(driver, owner, assertAgentLeaseReadExecution(driver, owner, execution));
}

function beginWorkerLeaseReads(driver: SqliteDriver, owner: StateOwnerContext, worker: RunExecutionWorkerIdentity): WorkerLeaseReads {
  const initial = readRequiredWorkerLaunch(driver, worker.launchId);
  if (initial.phase !== 'activated' || initial.generationWriteState !== 'active')
    throw new KernelStorageError('LEASE_FENCED', 'publication lease reads require the original active launch');
  const active = holders.get(worker.runId) ?? new Map<SqliteDriver, Binding>();
  if (active.has(driver)) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'publication lease reader is already held');
  const rows = new Map([[initial.leaseVersion, canonicalSha256(initial)]]);
  const binding: Binding = { driver, owner, leases: { initial: immutableSnapshot(initial), latest: immutableSnapshot(initial), rows } };
  active.set(driver, binding); holders.set(worker.runId, active);
  const scope: WorkerLeaseReads = Object.freeze({
    record(this: unknown, previous: BoundWorkerLaunch, renewed: BoundWorkerLaunch) {
      if (this !== scope || active.get(driver) !== binding) throw new TypeError('publication lease reader is closed or foreign');
      assertActiveStateOwner(driver, binding.owner);
      requireEqual(previous, binding.leases.latest, 'publication original previous lease');
      requireEqual(readRequiredWorkerLaunch(driver, initial.launchId), renewed, 'publication actual returned SQL renewal');
      validatePublicationLeaseRenewal(previous, renewed, readRun(driver, worker.runId));
      rows.set(renewed.leaseVersion, canonicalSha256(renewed));
      binding.leases = { ...binding.leases, latest: immutableSnapshot(renewed) };
    },
    close(this: unknown) {
      if (this !== scope) throw new TypeError('publication lease reader requires its original receiver');
      if (active.get(driver) !== binding) return;
      active.delete(driver); rows.clear();
      if (!active.size) holders.delete(worker.runId);
    },
  });
  return scope;
}
