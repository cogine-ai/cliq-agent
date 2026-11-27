// Global bounded inspection concurrency over the existing Run wait pointers.
// This snapshot supplies backpressure only, never inspection/death authority.
import { controlWireRecord } from '../kernel/control-wire-data.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';

export const MAX_SUPERVISOR_RECONCILIATION_PROBES = 16;
type WaitPointer = { id: string; waiting_on_ref: string };
const pointers = (connection: Pick<SqliteConnection, 'prepare'>) => connection.prepare(
  "SELECT id,waiting_on_ref FROM runs WHERE status='waiting' AND waiting_reason='reconciliation' ORDER BY id").all<WaitPointer>();
export class ReconciliationProbeCapacityError extends KernelStorageError {
  readonly controlError = Object.freeze({ schemaVersion: 1, code: 'RESOURCE_EXHAUSTED', retryable: true,
    resourceKind: 'reconciliation_probes', retryAfterMs: 1000, messageCode: 'run.reconciliation_capacity' } as const);
  constructor() { super('INVALID_REQUEST', 'Supervisor reconciliation inspection capacity is occupied'); this.name = 'ReconciliationProbeCapacityError'; }
}

export async function readReconciliationProbeCapacity(driver: SqliteDriver, artifacts: ArtifactCatalog) {
  const rows = pointers(driver);
  const counts = await artifacts.mapReads(rows, async row => {
    const value = await readCanonicalArtifact<Record<string, unknown>>(artifacts, row.waiting_on_ref);
    if (value.schemaVersion !== 1 || value.kind !== 'reconciliation' || value.runId !== row.id || !value.probeState ||
        typeof value.probeState !== 'object' || Array.isArray(value.probeState))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'global reconciliation capacity lost an original current wait');
    const phase = (value.probeState as Record<string, unknown>).phase;
    if (!['manual_only', 'automatic_pending', 'automatic_exhausted', 'automatic_in_flight', 'user_in_flight'].includes(phase as string))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'global reconciliation capacity has an unknown probe phase');
    if (phase !== 'automatic_in_flight' && phase !== 'user_in_flight') return 0;
    // Count even a malformed in-flight subject conservatively. This check
    // cannot validate or authorize any probe; its owning reader still must.
    const state = value.probeState as Record<string, unknown>;
    controlWireRecord(state.dispatch, ['schemaVersion', 'format', 'runId', 'reconciliationSubjectDigest', 'probeKind', 'probeOrdinal',
      'probeNonceDigest', 'probeStartedAt', 'probeDeadlineAt', 'owningSupervisorInstanceId', 'dispatchDigest', 'subjectKind'],
    ['brokerDispatchId', 'brokerRequestDigest', 'brokerTargetDigest', 'brokerFenceTokenDigest', 'previousWaitingSubjectRef', 'preparationRef',
      'preparationDigest', 'inspectorTaskId', 'inspectionTargetDigest', 'controlRequestId', 'controlRequestDigest']);
    return 1;
  });
  const active = counts.reduce<number>((total, count) => total + count, 0);
  return { active, limit: MAX_SUPERVISOR_RECONCILIATION_PROBES,
    assertAvailable(connection: SqliteConnection) {
      const current = pointers(connection);
      if (current.length !== rows.length || current.some((row, index) => row.id !== rows[index]!.id || row.waiting_on_ref !== rows[index]!.waiting_on_ref))
        throw new ReconciliationProbeCapacityError();
      if (active >= MAX_SUPERVISOR_RECONCILIATION_PROBES) throw new ReconciliationProbeCapacityError();
    } };
}
