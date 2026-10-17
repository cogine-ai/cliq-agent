import { KernelStorageError } from './errors.js';
import type { SqliteConnection } from './sqlite-driver.js';

export const INSTALLED_RUN_INVENTORY_LIMIT = 1000;

/** Fixed public refusal, not a caller-selected retry or execution permit. */
export class InstalledRunCapacityError extends KernelStorageError {
  readonly controlError = Object.freeze({ schemaVersion: 1, code: 'RESOURCE_EXHAUSTED', retryable: true,
    messageCode: 'run.queue_capacity', resourceKind: 'run_queue', retryAfterMs: 1000 } as const);
  constructor() {
    super('INVALID_REQUEST', 'installed Run inventory is at capacity');
    this.name = 'InstalledRunCapacityError';
  }
}

/** Read-only capacity check, never a reservation or admission authority. An
 * advisory preflight must still be repeated in the installed caller's original
 * write transaction, held through the subsequent insert. */
export function assertInstalledRunAdmissionCapacity(connection: Pick<SqliteConnection, 'prepare'>): void {
  const full = connection.prepare(`SELECT 1 FROM runs
    WHERE status IN ('queued','running','waiting') LIMIT 1 OFFSET ?`).get(INSTALLED_RUN_INVENTORY_LIMIT - 1);
  if (full !== undefined)
    throw new InstalledRunCapacityError();
}
