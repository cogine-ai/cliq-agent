import { KernelStorageError } from './errors.js';
import type { SqliteConnection } from './sqlite-driver.js';

export const INSTALLED_RUN_INVENTORY_LIMIT = 1000;

/** Read-only capacity check, not admission authority. The installed caller
 * must hold its original write transaction through the subsequent insert. */
export function assertInstalledRunAdmissionCapacity(connection: Pick<SqliteConnection, 'prepare'>): void {
  const full = connection.prepare(`SELECT 1 FROM runs
    WHERE status IN ('queued','running','waiting') LIMIT 1 OFFSET ?`).get(INSTALLED_RUN_INVENTORY_LIMIT - 1);
  if (full !== undefined)
    throw new KernelStorageError('INVALID_REQUEST', 'installed Run inventory is at capacity');
}
