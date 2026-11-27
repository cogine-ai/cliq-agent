import { assertRunConcurrency } from '../kernel/run-scheduling.js';
import type { SqliteConnection } from './sqlite-driver.js';

/** Pure SQL backpressure, never a retirement or execution proof. */
export function installedWorkerSlotAvailable(connection: Pick<SqliteConnection, 'prepare'>, runId: string, concurrency: number): boolean {
  assertRunConcurrency(concurrency);
  const rows = connection.prepare("SELECT DISTINCT run_id FROM worker_launches WHERE run_id != ? AND phase != 'retired' LIMIT ?")
    .all<{ run_id: string }>(runId, concurrency);
  return rows.length < concurrency;
}

/** A losing capacity race creates no preparation or physical resource. */
export class InstalledWorkerCapacityError extends Error {
  constructor() { super('installed worker capacity is occupied'); this.name = 'InstalledWorkerCapacityError'; }
}
