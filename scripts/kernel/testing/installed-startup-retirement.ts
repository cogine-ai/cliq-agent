// Negative retained-state startup regression only. No Run is admitted and no
// READY, physical reservation, controller birth or death evidence is produced.
import assert from 'node:assert/strict';
import { lstat, readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { DatabaseSync } from 'node:sqlite';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../../../src/config.js';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { digestOmitting, identityHash, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { PlatformProcessIdentityV1, ProcessContainmentPlanV1, StateOwnerRecordV1, WorkerLaunch } from '../../../src/kernel/types.js';
import type { RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { decodeWorkerContainmentPlan } from '../../../src/state/execution-closure.js';
import { decodeWorkerLaunch } from '../../../src/state/invariants.js';
import { inspectInstalledOwnerHistory } from './installed-read-control.js';
import { qualifyInstalledOwnerLinks, readInstalledCasJson } from './installed-owner-history.js';

type CommandResult = { status: number | null; stdout: string; stderr: string };

/** Runs as the exact disposable UID. These deliberately invalid, orphaned
 * rows are test fixture bytes, never a repository mutation/admission receipt.
 * Foreign keys are disabled only in this closed negative-fixture process. */
export const invalidRetainedStartupFixtureScript = String.raw`
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { constants, lstatSync, openSync, fstatSync, writeSync, fsyncSync, closeSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
const [root, encoded, ...extra] = process.argv.slice(1);
assert(root && path.isAbsolute(root) && encoded && extra.length === 0 && encoded.length <= 16384);
const input = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
assert(process.geteuid() === input.uid && process.getegid() === input.uid && input.uid > 0);
const rootInfo = lstatSync(root); assert(rootInfo.isDirectory() && !rootInfo.isSymbolicLink());
assert(rootInfo.uid === input.uid && (rootInfo.mode & 0o7777) === 0o700);
const filename = path.join(root, ${JSON.stringify(KERNEL_DATABASE_FILENAME)});
const databaseInfo = lstatSync(filename);
assert(databaseInfo.isFile() && !databaseInfo.isSymbolicLink() && databaseInfo.nlink === 1);
assert(databaseInfo.uid === input.uid && (databaseInfo.mode & 0o7777) === 0o600);
const cas = path.join(root, ${JSON.stringify(KERNEL_CAS_DIRECTORY)}), casInfo = lstatSync(cas);
assert(casInfo.isDirectory() && !casInfo.isSymbolicLink() && casInfo.uid === input.uid && (casInfo.mode & 0o7777) === 0o700);
assert(/^[a-f0-9]{64}$/.test(input.planRef));
const bytes = Buffer.from(input.planBytes, 'base64');
assert(bytes.length > 0 && bytes.length <= 8192);
assert(createHash('sha256').update(bytes).digest('hex') === input.planRef);
const database = new DatabaseSync(filename);
try {
  const owners = database.prepare('SELECT record_json FROM state_owners ORDER BY owner_epoch').all();
  assert(owners.length === 1 && JSON.parse(owners[0].record_json).rowDigest === input.ownerDigest);
  const prior = JSON.parse(owners[0].record_json);
  assert(prior.state === 'terminal' && prior.terminalReason === 'graceful_release');
  for (const table of ['runs', 'worker_launches', 'workspace_generations', 'run_journal'])
    assert(database.prepare('SELECT count(*) AS count FROM ' + table).get().count === 0);
  const fd = openSync(path.join(cas, input.planRef), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o400);
  try {
    const info = fstatSync(fd); assert(info.isFile() && info.uid === input.uid && info.nlink === 1 && (info.mode & 0o7777) === 0o400);
    let offset = 0;
    while (offset < bytes.length) { const written = writeSync(fd, bytes, offset, bytes.length - offset); assert(written > 0); offset += written; }
    fsyncSync(fd);
  } finally { closeSync(fd); }
  const parent = openSync(cas, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(parent); } finally { closeSync(parent); }
  database.exec('PRAGMA foreign_keys = OFF');
  database.exec('BEGIN IMMEDIATE');
  try {
    const change = database.prepare('INSERT INTO worker_launches (launch_id, run_id, phase, row_json, retired_at) VALUES (?, ?, ?, ?, NULL)')
      .run(input.launch.launchId, input.launch.runId, 'reserved', JSON.stringify(input.launch));
    assert(change.changes === 1); database.exec('COMMIT');
  } catch (error) { database.exec('ROLLBACK'); throw error; }
} finally { database.close(); }
console.log(JSON.stringify({ diagnosticOnly: true, scope: 'invalid-orphaned-retained-startup-fixture',
  admittedRuns: 0, readyEvidence: false, deathEvidence: false, planRef: input.planRef, launch: input.launch }));
`;

function makeFixture(uid: number, owner: StateOwnerRecordV1, rootPath: string) {
  const launchId = identityHash('cliq-invalid-installed-startup-v1', owner.runtimeBundleRef, 'reserved');
  const runId = identityHash('cliq-invalid-installed-startup-v1', launchId, 'orphaned-no-admission');
  const createdAt = new Date().toISOString();
  const generationRef = sha256Bytes(Buffer.from('invalid retained startup: no generation exists'));
  const spawnNonceDigest = sha256Bytes(Buffer.from(`${launchId}:no-real-spawn`));
  const plan: ProcessContainmentPlanV1 = {
    schemaVersion: 1, format: 'cliq-process-containment-plan-v1',
    owner: { kind: 'worker_activation', runId, intendedLeaseEpoch: 1, workerLaunchId: launchId },
    filesystemBinding: { kind: 'run-generation', generationRef }, launchNonceDigest: spawnNonceDigest,
    backend: { kind: 'linux', cgroupPath: path.posix.join(rootPath, 'invalid-fixture-never-created'),
      cgroupNameReservationDigest: sha256Bytes(Buffer.from(`${launchId}:no-cgroup-reservation`)),
      pidNamespaceReservationId: 'invalid-fixture-no-namespace', subreaperStartToken: 'invalid-fixture-no-controller',
      nativeReservation: { deviceId: '0', fileId: '0', ownerUid: uid } },
    createdAt, planDigest: '',
  };
  plan.planDigest = digestOmitting(plan, 'planDigest');
  decodeWorkerContainmentPlan(plan);
  const planBytes = canonicalJsonBytes(plan), planRef = sha256Bytes(planBytes);
  const launch: WorkerLaunch = {
    schemaVersion: 1, launchId, runId, plannedRunRevision: 1, supervisorInstanceId: owner.supervisorInstanceId,
    spawnNonceDigest, activationNonceDigest: sha256Bytes(Buffer.from(`${launchId}:no-real-activation`)),
    phase: 'reserved', workspaceGenerationRef: generationRef, containmentPlanRef: planRef,
    sandboxLaunchSpecRef: sha256Bytes(Buffer.from('invalid retained startup: no launch spec exists')),
    leaseVersion: 0, generationWriteState: 'preactivated_readonly', createdAt,
    activationDeadlineAt: new Date(Date.parse(createdAt) + 120000).toISOString(),
  };
  decodeWorkerLaunch(launch);
  return { uid, ownerDigest: owner.rowDigest, planRef, planBytes: planBytes.toString('base64'), launch };
}

export async function qualifyInstalledStartupRetirement(input: {
  stateRoot: string; uid: number; rootPath: string; bundle: RuntimeBundleManifest; owner: StateOwnerRecordV1;
  report: Record<string, unknown>;
  fixture(encoded: string): CommandResult;
  start(): CommandResult;
  show(): Record<string, string>;
  stopAndJoin(observation: Record<string, unknown>): Promise<unknown>;
  journal(invocationId: string, pid: string): Record<string, unknown>[];
}): Promise<void> {
  input.report.diagnosticOnly = true; input.report.qualified = false;
  input.report.scope = 'invalid retained-state startup refusal only; not admission, READY, death or I1 execution';
  assert(!input.bundle.entries.some(entry => entry.entryId === 'linux_worker_native'),
    'this negative package deliberately has no worker-native capability');
  const stopped: Record<string, unknown> = {}; input.report.initialStop = stopped;
  await input.stopAndJoin(stopped);
  const history = inspectInstalledOwnerHistory(input.stateRoot);
  assert.equal(history.owners.length, 1);
  const prior = history.owners[0]!;
  assert(prior.state === 'terminal' && prior.terminalReason === 'graceful_release');
  assert.equal(prior.supervisorInstanceId, input.owner.supervisorInstanceId);
  const fixture = makeFixture(input.uid, prior, input.rootPath);
  const prepared = input.fixture(Buffer.from(canonicalJsonBytes(fixture)).toString('base64'));
  input.report.fixture = prepared; assert.equal(prepared.status, 0, prepared.stderr);
  const observation = parseJsonStrict(prepared.stdout.trim()) as Record<string, unknown>;
  assert.equal(observation.scope, 'invalid-orphaned-retained-startup-fixture');
  assert.equal(observation.admittedRuns, 0); assert.equal(observation.readyEvidence, false); assert.equal(observation.deathEvidence, false);
  assert.equal(observation.planRef, fixture.planRef); assert.deepEqual(observation.launch, fixture.launch);
  assert.deepEqual(await readInstalledCasJson({ stateRoot: input.stateRoot, uid: input.uid }, fixture.planRef),
    decodeWorkerContainmentPlan(JSON.parse(Buffer.from(fixture.planBytes, 'base64').toString('utf8'))));
  const socket = path.join(input.stateRoot, 'runtime/control-v1.sock');
  await assert.rejects(lstat(socket), { code: 'ENOENT' });
  const rootInventory = async () => (await readdir(input.rootPath, { withFileTypes: true }))
    .filter(entry => entry.isDirectory()).map(entry => entry.name).sort();
  const inventory = await rootInventory(); assert.deepEqual(inventory, ['keeper']);
  const start = input.start(); input.report.start = start; assert.equal(start.status, 0, start.stderr);
  let joined = false;
  try {
    const deadline = Date.now() + 10000;
    let failed: Record<string, string>;
    for (;;) {
      failed = input.show(); input.report.unit = failed;
      await assert.rejects(lstat(socket), { code: 'ENOENT' }, 'failed startup must not publish a Store/control socket');
      if (failed.MainPID === '0' && ['failed', 'inactive', 'activating'].includes(failed.ActiveState!)) break;
      if (Date.now() >= deadline) {
        input.report.redCause = 'bounded-startup-hang-with-no-control';
        throw new Error('installed startup retirement did not complete within its bounded refusal window');
      }
      await delay(20);
    }
    const captured = { ...failed }; input.report.exit = captured;
    const joinedReport: Record<string, unknown> = {}; input.report.join = joinedReport;
    await input.stopAndJoin(joinedReport); joined = true;
    input.report.historyAfterJoin = inspectInstalledOwnerHistory(input.stateRoot);
    let records: Record<string, unknown>[] = [], exact = false;
    for (let attempt = 0; attempt < 20 && !exact; attempt++) {
      records = input.journal(captured.InvocationID!, captured.ExecMainPID!);
      exact = records.some(record => {
        if (record._UID !== String(input.uid) || record._PID !== captured.ExecMainPID ||
            record._TRANSPORT !== 'stdout' || typeof record.MESSAGE !== 'string') return false;
        try {
          const value = parseJsonStrict(record.MESSAGE) as Record<string, unknown>;
          return value.diagnosticOnly === true && value.scope === 'installed-read-startup' &&
            value.code === 'RECOVERY_REQUIRED' && value.message === 'abandoned native launch closure is unresolved';
        } catch { return false; }
      });
      if (!exact) await delay(50);
    }
    input.report.journal = records; input.report.exactRefusal = exact;
    if (!exact) input.report.redCause = 'exit-without-specific-retirement-refusal';
    assert.equal(captured.Result, 'exit-code', 'a pending Promise disappearing as exit 0 is not a retirement refusal');
    assert.equal(captured.ExecMainCode, '1'); assert.equal(captured.ExecMainStatus, '1');
    assert(exact, 'installed startup must report its specific unresolved-retirement error, not an unrelated early exit');
    const after = inspectInstalledOwnerHistory(input.stateRoot); input.report.historyAfter = after;
    assert.equal(after.owners.length, 2, 'stop must join/cancel retry before a third failed owner acquisition');
    assert.deepEqual(after.owners[0], prior);
    const successor = after.owners[1]!;
    assert.equal(successor.state, 'active', 'unresolved retirement must not gracefully release the failed-opening owner');
    assert.equal(successor.ownerEpoch, 2); assert.equal(successor.stateLockIdentityRef, prior.stateLockIdentityRef);
    const ownerLinks: Record<string, unknown> = {}; input.report.ownerLinks = ownerLinks;
    assert.deepEqual(await qualifyInstalledOwnerLinks({ stateRoot: input.stateRoot, uid: input.uid,
      bundle: input.bundle, imageDigest: prior.supervisorExecutableDigest, report: ownerLinks }), after);
    const database = new DatabaseSync(path.join(input.stateRoot, KERNEL_DATABASE_FILENAME), { readOnly: true, allowExtension: false });
    try {
      const rows = database.prepare('SELECT launch_id, run_id, phase, row_json, retired_at FROM worker_launches').all();
      assert.equal(rows.length, 1);
      assert.equal(rows[0]!.launch_id, fixture.launch.launchId); assert.equal(rows[0]!.run_id, fixture.launch.runId);
      assert.equal(rows[0]!.phase, 'reserved'); assert.equal(rows[0]!.retired_at, null);
      assert.deepEqual(parseJsonStrict(rows[0]!.row_json as string), fixture.launch);
      for (const table of ['runs', 'run_journal', 'workspace_generations'])
        assert.equal(database.prepare(`SELECT count(*) AS count FROM ${table}`).get()!.count, 0);
    } finally { database.close(); }
    const identity = await readInstalledCasJson<PlatformProcessIdentityV1>(input, successor.processIdentityRef);
    assert(Number.isSafeInteger(identity.pid) && identity.pid > 0 && identity.pid <= 0x7fffffff);
    assert.match(identity.processStartToken, /^linux-proc-start-ticks:(0|[1-9][0-9]*)$/u);
    assert.equal(String(identity.pid), captured.ExecMainPID, 'the joined lifetime must be the refused opening attempt');
    const raw = await readFile(`/proc/${identity.pid}/stat`, 'utf8').catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT' || error.code === 'ESRCH') return undefined; throw error;
    });
    if (raw !== undefined) {
      const fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/u);
      assert.notEqual(`linux-proc-start-ticks:${fields[19]}`, identity.processStartToken);
    }
    input.report.failedOpeningLifetimeGone = true;
    input.report.unresolvedOwnerNotGracefullyReleased = true;
    input.report.physicalLockUntilExitQualified = false; // No trace-stop was used to observe that ephemeral cut.
    assert.deepEqual(await rootInventory(), inventory, 'refusal must create no controller leaf');
    await assert.rejects(lstat(socket), { code: 'ENOENT' });
    input.report.qualified = true;
  } finally {
    if (!joined) {
      const errorJoin: Record<string, unknown> = {}; input.report.errorJoin = errorJoin;
      await input.stopAndJoin(errorJoin);
    }
  }
}
