// Shared independent read-only client/inspection for the actual installed tests.
import assert from 'node:assert/strict';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as delay } from 'node:timers/promises';
import { KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../../../src/config.js';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { digestOmitting, parseCanonicalTime } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { CanonicalTimeFenceV1, StateOwnerRecordV1 } from '../../../src/kernel/types.js';
import type { RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';

const ownerKeys = ['schemaVersion', 'ownerEpoch', 'supervisorInstanceId', 'runtimeBundleRef', 'runtimeBundleManifestDigest',
  'supervisorEntryId', 'supervisorEntryVersion', 'supervisorExecutableDigest', 'processIdentityRef', 'processIdentityDigest',
  'stateLockIdentityRef', 'stateLockIdentityDigest', 'acquisitionEvidenceRef', 'acquisitionEvidenceDigest',
  'instanceNonceDigest', 'acquiredAt', 'rowDigest', 'state', 'rowVersion'];
const terminalKeys = ['releasedAt', 'terminalReason', 'transitionEvidenceRef', 'transitionEvidenceDigest'];

export type InstalledOwnerHistoryReadStage = 'open' | 'snapshot' | 'schema' | 'rows' | 'records' | 'fence' | 'commit';

export function inspectInstalledOwnerHistory(stateRoot: string, observer?: (stage: InstalledOwnerHistoryReadStage) => void) {
  const note = (stage: InstalledOwnerHistoryReadStage) => {
    try { observer?.(stage); } catch { /* Observation cannot decide or replace the original read. */ }
  };
  note('open');
  const database = new DatabaseSync(path.join(stateRoot, KERNEL_DATABASE_FILENAME), { readOnly: true, allowExtension: false });
  try {
    note('snapshot');
    database.exec('BEGIN');
    note('schema');
    assert.equal(database.prepare('PRAGMA user_version').get()?.user_version, KERNEL_STATE_SCHEMA_VERSION);
    note('rows');
    const rows = database.prepare('SELECT owner_epoch, supervisor_instance_id, record_json, state, row_digest FROM state_owners ORDER BY owner_epoch').all();
    note('records');
    const owners = rows.map((row, index) => {
      assert.equal(typeof row.record_json, 'string');
      const owner = parseJsonStrict(row.record_json as string) as StateOwnerRecordV1;
      assert.equal(owner.ownerEpoch, index + 1); assert.equal(owner.ownerEpoch, row.owner_epoch);
      assert.equal(owner.supervisorInstanceId, row.supervisor_instance_id);
      assert.equal(owner.state, row.state); assert.equal(owner.rowDigest, row.row_digest);
      assert.equal(owner.rowDigest, digestOmitting(owner, 'rowDigest'));
      assert.equal(owner.schemaVersion, 1); parseCanonicalTime(owner.acquiredAt);
      assert.match(owner.instanceNonceDigest, /^[0-9a-f]{64}$/u);
      assert.deepEqual(Object.keys(owner).sort(), [...ownerKeys, ...(owner.state === 'terminal' ? terminalKeys : [])].sort());
      if (owner.state === 'active') {
        assert.equal(index, rows.length - 1); assert.equal(owner.rowVersion, 1);
      } else {
        assert.equal(owner.state, 'terminal'); assert.equal(owner.rowVersion, 2); parseCanonicalTime(owner.releasedAt);
        assert(['graceful_release', 'superseded_after_owner_death'].includes(owner.terminalReason));
      }
      return owner;
    });
    note('fence');
    const fences = database.prepare('SELECT * FROM canonical_time_fence').all();
    assert.equal(fences.length, owners.length ? 1 : 0);
    let fence: CanonicalTimeFenceV1 | undefined;
    if (owners.length) {
      const row = fences[0]!; assert.equal(row.id, 1);
      fence = { schemaVersion: 1, format: 'cliq-canonical-time-fence-v1', stateOwnerEpoch: row.state_owner_epoch as number,
        lastAcceptedAt: row.last_accepted_at as string, observedWallClockAt: row.observed_wall_clock_at as string,
        state: row.state as CanonicalTimeFenceV1['state'], updatedAt: row.updated_at as string, fenceDigest: row.fence_digest as string };
      assert.equal(fence.stateOwnerEpoch, owners.length); assert.equal(fence.fenceDigest, digestOmitting(fence, 'fenceDigest'));
      for (const value of [fence.lastAcceptedAt, fence.observedWallClockAt, fence.updatedAt]) parseCanonicalTime(value);
      assert(['healthy', 'clock_regressed'].includes(fence.state)); assert.equal(fence.updatedAt, fence.lastAcceptedAt);
      if (fence.state === 'healthy') assert.equal(fence.observedWallClockAt, fence.lastAcceptedAt);
    }
    note('commit');
    database.exec('COMMIT');
    return { owners, fence };
  } finally { database.close(); }
}

/** Re-observe the complete SQL cut after an asynchronous retained-evidence walk.
 * Owner lineage must remain byte-for-byte current, but its time fence may have
 * advanced through ordinary transactions by that same owner. This read-only
 * qualification check creates no ownership or execution authority. */
export function assertInstalledOwnerHistoryCurrent(stateRoot: string, expected: ReturnType<typeof inspectInstalledOwnerHistory>): void {
  const current = inspectInstalledOwnerHistory(stateRoot);
  assert.deepEqual(current.owners, expected.owners);
  if (expected.fence === undefined) {
    assert.equal(current.fence, undefined);
    return;
  }
  assert(current.fence);
  assert.equal(current.fence.stateOwnerEpoch, expected.fence.stateOwnerEpoch);
  assert(parseCanonicalTime(current.fence.lastAcceptedAt) >= parseCanonicalTime(expected.fence.lastAcceptedAt),
    'the same owner canonical accepted time must not regress');
  assert(parseCanonicalTime(current.fence.updatedAt) >= parseCanonicalTime(expected.fence.updatedAt),
    'the same owner canonical fence update must not regress');
}

export function observeInstalledOwnerHistory(stateRoot: string) {
  try { return inspectInstalledOwnerHistory(stateRoot); }
  catch (error) {
    const sqlite = error as Error & { code?: unknown; errcode?: unknown };
    if (error instanceof Error && sqlite.code === 'ERR_SQLITE_ERROR' && typeof sqlite.errcode === 'number' &&
        Number.isSafeInteger(sqlite.errcode) && sqlite.errcode >= 0 && sqlite.errcode % 256 === 5) return undefined;
    throw error;
  }
}

/** Only the caller's original absolute readiness budget permits waiting.
 * Every attempt closes its actual read transaction before yielding. */
export async function waitForInstalledOwnerHistory(stateRoot: string, by: number) {
  assert(Number.isSafeInteger(by) && by >= 0);
  for (;;) {
    assert(Date.now() < by, 'installed owner history exceeded the original readiness budget');
    const history = observeInstalledOwnerHistory(stateRoot);
    if (history !== undefined) {
      assert(Date.now() < by, 'installed owner history exceeded the original readiness budget');
      return history;
    }
    await delay(20);
  }
}

/** One readiness observation, not a successful owner/death/recovery proof.
 * A live startup writer may briefly hold the rollback-journal schema lock;
 * the caller's existing deadline/poll loop owns waiting, never this reader. */
export function inspectInstalledOwner(stateRoot: string): StateOwnerRecordV1 | undefined {
  return observeInstalledOwnerHistory(stateRoot)?.owners.at(-1);
}

export function assertInstalledReadExchanges(stdout: string, owner: StateOwnerRecordV1, bundle: RuntimeBundleManifest): void {
  const exchanges = parseJsonStrict(stdout.trim()) as Array<{ hello: string; status: string }>;
  assert.equal(exchanges.length, 2);
  const summary = { schemaVersion: 1, runtimeBundleRef: owner.runtimeBundleRef,
    bundleDigest: owner.runtimeBundleRef, bundleVersion: bundle.bundleVersion };
  for (const exchange of exchanges) {
    const hello = parseJsonStrict(exchange.hello) as Record<string, any>;
    const status = parseJsonStrict(exchange.status) as Record<string, any>;
    assert.equal(canonicalJsonBytes(hello).toString('utf8'), exchange.hello);
    assert.equal(canonicalJsonBytes(status).toString('utf8'), exchange.status);
    assert.equal(hello.protocolVersion, 1); assert.equal(status.protocolVersion, 1);
    assert.equal(hello.ok, true); assert.equal(hello.result.method, 'control.hello');
    assert.equal(hello.result.protocolVersion, 1); assert.equal(hello.result.serverBuild, 'cliq-installed-v1');
    assert.deepEqual(canonicalJsonBytes(hello.result.controlSchemaRange), canonicalJsonBytes({ min: 1, max: 1 }));
    assert.equal(hello.result.supervisorInstanceId, owner.supervisorInstanceId);
    assert.deepEqual(canonicalJsonBytes(hello.result.activeRuntimeBundle), canonicalJsonBytes(summary));
    assert.deepEqual(canonicalJsonBytes(hello.result.headlessSchemaRange), canonicalJsonBytes({ min: 1, max: 1 }));
    assert.deepEqual(hello.result.enabledFeatureIds, ['supervisor.status']); assert.equal(status.ok, true);
    assert.deepEqual(canonicalJsonBytes(status.result), canonicalJsonBytes({ method: 'supervisor.status', health: 'degraded',
      supervisorInstanceId: owner.supervisorInstanceId, queue: { queuedRuns: 0, runningRuns: 0, capacity: 0 },
      stateSchemaVersion: KERNEL_STATE_SCHEMA_VERSION, activeRuntimeBundle: summary, installedRuntimeBundles: [summary],
      incompatiblePinnedRunCount: 0 }));
  }
}

const helloBytes = canonicalJsonBytes({ protocolVersion: 1, method: 'control.hello',
  clientBuild: 'installed-startup-qualification', controlSchemaRange: { min: 1, max: 1 },
  headlessSchemaRange: { min: 1, max: 1 }, requestedFeatureIds: ['supervisor.status'] }).toString('base64');
const statusBytes = canonicalJsonBytes({ protocolVersion: 1, method: 'supervisor.status' }).toString('base64');
// The caller runs this ordinary Node client as the disposable unprivileged UID.
// It controls only its sockets, never installation or authority evidence.
export const installedReadClientScript = `import assert from 'node:assert/strict';
import net from 'node:net';
const exchanges = [];
for (let attempt = 0; attempt < 2; attempt++) {
  const socket = net.createConnection(process.argv[1]);
  let input = Buffer.alloc(0), waiter, error;
  socket.on('data', chunk => {
    try {
      input = Buffer.concat([input, chunk]);
      assert(input.length <= 1048580);
      while (input.length >= 4) {
        const length = input.readUInt32BE(0);
        assert(length >= 1 && length <= 1048576);
        if (input.length < 4 + length) break;
        const json = new TextDecoder('utf-8', {fatal:true}).decode(input.subarray(4, 4 + length));
        input = input.subarray(4 + length);
        assert(waiter, 'unsolicited response frame');
        const complete = waiter; waiter = undefined; complete.resolve(json);
      }
    } catch (failure) { error = failure; waiter?.reject(failure); socket.destroy(); }
  });
  socket.on('error', failure => { error = failure; waiter?.reject(failure); });
  socket.on('close', () => { error ??= new Error('peer closed before response'); waiter?.reject(error); });
  const closed = new Promise(resolve => socket.once('close', resolve));
  try {
    await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
    const request = async bytes => {
      if (error) throw error;
      assert(!waiter, 'one fixed request is outstanding at a time');
      return await new Promise((resolve, reject) => {
        waiter = {resolve,reject};
        const header = Buffer.alloc(4); header.writeUInt32BE(bytes.length);
        try { socket.write(Buffer.concat([header, bytes])); }
        catch (failure) { waiter = undefined; reject(failure); }
      });
    };
    const hello = await request(Buffer.from(${JSON.stringify(helloBytes)}, 'base64'));
    const status = await request(Buffer.from(${JSON.stringify(statusBytes)}, 'base64'));
    exchanges.push({hello,status});
  } finally { socket.destroy(); await closed; }
}
console.log(JSON.stringify(exchanges));`;
