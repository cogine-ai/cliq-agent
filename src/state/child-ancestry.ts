import { parseCanonicalTime } from '../kernel/identity.js';
import type { Run } from '../kernel/types.js';
import { KernelStorageError } from './errors.js';
import { readIncomingChildAllocation } from './repositories/child-allocations.js';
import { readRun } from './rows.js';
import type { SqliteConnection } from './sqlite-driver.js';

/** Last synchronous release fence, not a source of child authority. The loaded
 * Run history separately reconstructs the complete original capability/grant/
 * admission graph. Every final gate reads this original SQL ancestry anew;
 * asynchronous Stop propagation cannot provide the release decision. */
export function assertChildAncestryRelease(connection: SqliteConnection, runId: string, now: string): void {
  parseCanonicalTime(now);
  let child = readRun(connection, runId), remainingDepth: number | undefined;
  const seen = new Set<string>();
  for (let depth = 0; ; depth++) {
    if (seen.has(child.id) || depth > 8) throw new KernelStorageError('RECOVERY_REQUIRED', 'child ancestry is cyclic or exceeds the original maximum depth');
    seen.add(child.id);
    const incoming = readIncomingChildAllocation(connection, child.id);
    if (!child.parentRunId) {
      if (incoming) throw new KernelStorageError('RECOVERY_REQUIRED', 'root Run acquired an incoming child allocation');
      return;
    }
    if (!incoming || incoming.childRunId !== child.id || incoming.parentRunId !== child.parentRunId ||
        incoming.state !== 'reserved' || incoming.createdAt !== child.createdAt || incoming.childDeadlineAt !== child.deadlineAt ||
        incoming.grantedChildDepth > 8 || incoming.grantedChildConcurrency > 64 ||
        remainingDepth !== undefined && incoming.grantedChildDepth <= remainingDepth)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'child release has no exact live immutable parent allocation');
    const parent = readRun(connection, child.parentRunId);
    const principal = (run: Run) => connection.prepare('SELECT principal_id FROM runs WHERE id = ?').get<{ principal_id: string }>(run.id)?.principal_id;
    if (parent.id === child.id || parent.sessionId !== child.sessionId || !principal(child) || principal(parent) !== principal(child) ||
        parent.createdAt > child.createdAt || parent.deadlineAt < child.deadlineAt)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'child ancestry changed its principal, Session or absolute lifetime');
    if (parent.cancelRequested || parent.stopIntentRef || ['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(parent.status) ||
        now >= parent.deadlineAt)
      throw new KernelStorageError('LEASE_FENCED', 'an ancestor Run has stopped or reached its original deadline');
    remainingDepth = incoming.grantedChildDepth;
    child = parent;
  }
}
