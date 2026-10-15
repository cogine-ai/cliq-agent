// Test-only read diagnostic. Neither a SQLite row nor this projection creates
// StateOwner, worker, renewal or native containment authority.
import { lstatSync, type BigIntStats } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../../../src/config.js';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { encodeCanonicalTime, parseCanonicalTime } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeWorkerLaunch } from '../../../src/state/invariants.js';

export type InstalledWorkerLeaseExpected = { uid: number; runId: string; launchId: string; leaseEpoch: number;
  runRevision: number; supervisorInstanceId: string; deadlineAt: string };
export type InstalledWorkerLeaseInspection = Readonly<{ diagnosticOnly: true; databaseIdentity: string;
  launchInvariantDigest: string; leaseVersion: number; leaseExpiresAt: string; observedAt: string }>;
const identityFields = ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink'] as const;
const refused = 'installed worker lease inspection refused';
function requireValue(value: unknown): asserts value { if (!value) throw new Error(refused); }
function identity(value: BigIntStats) {
  return Object.fromEntries(identityFields.map(field => [field, value[field].toString()]));
}

/** A fresh short-lived readonly connection observes one joined SQL cut. */
export function inspectInstalledWorkerLease(stateRoot: string,
  expected: InstalledWorkerLeaseExpected): InstalledWorkerLeaseInspection {
  try {
    requireValue(Object.keys(expected).sort().join(',') ===
      'deadlineAt,launchId,leaseEpoch,runId,runRevision,supervisorInstanceId,uid');
    for (const value of [expected.uid, expected.leaseEpoch, expected.runRevision])
      requireValue(Number.isSafeInteger(value) && value > 0);
    for (const value of [expected.runId, expected.launchId, expected.supervisorInstanceId])
      requireValue(typeof value === 'string' && value.length > 0 && value.length <= 256);
    requireValue(typeof expected.deadlineAt === 'string'); parseCanonicalTime(expected.deadlineAt);
    const filename = path.join(stateRoot, KERNEL_DATABASE_FILENAME);
    const root = lstatSync(stateRoot, { bigint: true }), file = lstatSync(filename, { bigint: true });
    requireValue(root.isDirectory() && !root.isSymbolicLink() && root.uid === BigInt(expected.uid) && (root.mode & 0o7777n) === 0o700n);
    requireValue(file.isFile() && !file.isSymbolicLink() && file.uid === BigInt(expected.uid) && file.nlink === 1n && (file.mode & 0o7777n) === 0o600n);
    const databaseIdentity = canonicalSha256({ root: identity(root), file: identity(file) });
    const database = new DatabaseSync(filename, { readOnly: true, allowExtension: false });
    let launch;
    try {
      // Connection-local waiting only; never changes journal mode or data.
      database.exec('PRAGMA busy_timeout=1000');
      requireValue(database.prepare('PRAGMA user_version').get()?.user_version === KERNEL_STATE_SCHEMA_VERSION);
      const rows = database.prepare(`SELECT r.id AS run_id, r.active_worker_launch_id, r.status, r.lease_epoch,
        r.revision, r.cancel_requested, r.stop_intent_ref, r.deadline_at,
        w.launch_id, w.run_id AS worker_run_id, w.phase, w.retired_at,
        CASE WHEN typeof(w.row_json) = 'text' AND length(CAST(w.row_json AS BLOB)) BETWEEN 1 AND 65536
          THEN w.row_json ELSE NULL END AS row_json
        FROM runs r JOIN worker_launches w ON w.run_id = r.id AND w.launch_id = r.active_worker_launch_id
        WHERE r.id = ? AND w.launch_id = ? LIMIT 2`).all(expected.runId, expected.launchId);
      requireValue(rows.length === 1);
      const row = rows[0]!;
      requireValue(row.run_id === expected.runId && row.worker_run_id === expected.runId &&
        row.launch_id === expected.launchId && row.active_worker_launch_id === expected.launchId && row.status === 'running' &&
        row.lease_epoch === expected.leaseEpoch && row.revision === expected.runRevision && row.cancel_requested === 0 &&
        row.stop_intent_ref === null && row.deadline_at === expected.deadlineAt && row.phase === 'activated' && row.retired_at === null &&
        typeof row.row_json === 'string' && Buffer.byteLength(row.row_json) <= 65536);
      launch = decodeWorkerLaunch(parseJsonStrict(row.row_json));
      requireValue(launch.runId === row.worker_run_id && launch.launchId === row.launch_id && launch.phase === row.phase &&
        launch.generationWriteState === 'active' && launch.supervisorInstanceId === expected.supervisorInstanceId &&
        launch.leaseEpoch === expected.leaseEpoch && launch.retiredAt === undefined);
    } finally { database.close(); }
    requireValue(databaseIdentity === canonicalSha256({ root: identity(lstatSync(stateRoot, { bigint: true })),
      file: identity(lstatSync(filename, { bigint: true })) }));
    const observedAt = encodeCanonicalTime(Date.now());
    requireValue(launch.leaseExpiresAt && launch.leaseExpiresAt > observedAt && launch.leaseExpiresAt <= expected.deadlineAt);
    const { leaseVersion, leaseExpiresAt, ...invariant } = launch;
    return Object.freeze({ diagnosticOnly: true, databaseIdentity, launchInvariantDigest: canonicalSha256(invariant),
      leaseVersion, leaseExpiresAt: leaseExpiresAt!, observedAt });
  } catch { throw new Error(refused); }
}

/** Pure data comparison only; callers must independently observe the same real
 * installed process and worker. Neither supplied timestamps nor hashes attest it. */
export function assertInstalledWorkerLeaseRenewed(before: InstalledWorkerLeaseInspection,
  after: InstalledWorkerLeaseInspection, deadlineAt: string): void {
  try {
    requireValue(typeof deadlineAt === 'string'); parseCanonicalTime(deadlineAt);
    for (const value of [before, after]) {
      requireValue(Object.keys(value).sort().join(',') ===
        'databaseIdentity,diagnosticOnly,launchInvariantDigest,leaseExpiresAt,leaseVersion,observedAt');
      requireValue(value.diagnosticOnly === true && Number.isSafeInteger(value.leaseVersion) && value.leaseVersion > 0);
      for (const hash of [value.databaseIdentity, value.launchInvariantDigest])
        requireValue(typeof hash === 'string' && /^[0-9a-f]{64}$/u.test(hash));
      requireValue(typeof value.leaseExpiresAt === 'string' && typeof value.observedAt === 'string');
      parseCanonicalTime(value.leaseExpiresAt); parseCanonicalTime(value.observedAt);
      requireValue(value.leaseExpiresAt > value.observedAt && value.leaseExpiresAt <= deadlineAt);
    }
    requireValue(before.databaseIdentity === after.databaseIdentity && before.launchInvariantDigest === after.launchInvariantDigest &&
      after.leaseVersion > before.leaseVersion && after.leaseExpiresAt > before.leaseExpiresAt && after.observedAt > before.leaseExpiresAt);
  } catch { throw new Error('installed worker lease renewal diagnostic refused'); }
}
