import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { readReconciliationProbeCapacity, ReconciliationProbeCapacityError, MAX_SUPERVISOR_RECONCILIATION_PROBES } from './reconciliation-capacity.js';

const startedAt = '2026-11-04T01:02:03.000Z', deadline = '2026-11-04T01:02:33.000Z';
const ref = (value: string) => canonicalSha256(value);
type Purpose = 'worker_recovery' | 'publication' | 'mcp_recovery';
// Real SQLite + immutable CAS data only. These exact dispatch shapes are
// source records, not a StateOwner, process, native fence or task join.
function inFlight(id: string, purpose: Purpose, user = false) {
  assert.ok(purpose !== 'worker_recovery' || !user);
  const subject = purpose === 'worker_recovery' ? { kind: 'worker_death', oldWorkerLaunchId: `${id}:launch`, oldLeaseEpoch: 1,
    oldWorkerIdentity: ref(`${id}:worker`), processContainmentRef: ref(`${id}:containment`), workspaceGenerationRef: ref(`${id}:generation`), openInvocationRefs: [] }
    : purpose === 'publication' ? { kind: 'publication_path', deliveryPlanRef: ref(`${id}:plan`), pathOperationId: `${id}:path`, attempt: 0 }
    : { kind: 'invocation', recovery: 'mcp_reconcile', opKind: 'mcp', opId: `${id}:effect`, attempt: 0,
        registryRevisionRef: ref(`${id}:registry`), registryManifestDigest: ref(`${id}:manifest`), serverToolName: 'effect', profileId: 'signed-profile',
        profileDigest: ref(`${id}:profile`), statusRequestTemplateRef: ref(`${id}:template`), statusRequestTemplateDigest: ref(`${id}:template-data`),
        completedPredicateRef: ref(`${id}:completed`), completedPredicateDigest: ref(`${id}:completed-data`),
        failedPredicateRef: ref(`${id}:failed`), failedPredicateDigest: ref(`${id}:failed-data`) };
  const common = { schemaVersion: 1, format: 'cliq-reconciliation-probe-dispatch-v1', runId: id,
    reconciliationSubjectDigest: canonicalSha256(subject), probeKind: user ? 'user_requested' : 'automatic', probeOrdinal: 1,
    probeNonceDigest: ref(`${id}:nonce`), probeStartedAt: startedAt, probeDeadlineAt: deadline, owningSupervisorInstanceId: 'original-supervisor' };
  const core = { ...common, subjectKind: purpose, ...(purpose === 'mcp_recovery'
    ? { brokerDispatchId: `${id}:broker`, brokerRequestDigest: ref(`${id}:request`), brokerTargetDigest: ref(`${id}:target`),
        brokerFenceTokenDigest: ref(`${id}:token`), previousWaitingSubjectRef: ref(`${id}:previous`), preparationRef: ref(`${id}:preparation`),
        preparationDigest: ref(`${id}:preparation-data`) }
    : { inspectorTaskId: `${id}:task`, inspectionTargetDigest: ref(`${id}:target`),
        ...(purpose === 'publication' ? { previousWaitingSubjectRef: ref(`${id}:previous`) } : {}) }),
    ...(user ? { controlRequestId: `${id}:control`, controlRequestDigest: ref(`${id}:control-data`) } : {}) };
  const dispatch = { ...core, dispatchDigest: canonicalSha256(core) };
  return { schemaVersion: 1, kind: 'reconciliation', runId: id, createdFromRevision: 1, createdAt: startedAt,
    frontierRef: ref(`${id}:frontier`), subject,
    probeState: user ? { phase: 'user_in_flight', automaticProbeCount: 8, userProbeCount: 1, dispatch }
      : { phase: 'automatic_in_flight', automaticProbeCount: 1, userProbeCount: 0, dispatch } };
}
function pending(id: string) {
  return { schemaVersion: 1, kind: 'reconciliation', runId: id, createdFromRevision: 1, createdAt: startedAt,
    frontierRef: ref(`${id}:frontier`), subject: { kind: 'worker_death', oldWorkerLaunchId: `${id}:launch`, oldLeaseEpoch: 1,
      oldWorkerIdentity: ref(`${id}:worker`), processContainmentRef: ref(`${id}:containment`), workspaceGenerationRef: ref(`${id}:generation`), openInvocationRefs: [] },
    probeState: { phase: 'automatic_pending', automaticProbeCount: 0, userProbeCount: 0, nextProbeAt: startedAt } };
}
async function fixture(t: TestContext) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-reconciliation-capacity-')), objects = path.join(root, 'objects');
  await mkdir(objects, { mode: 0o700 }); const driver = openSqliteDriver(path.join(root, 'data.sqlite'));
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(objects));
  t.after(async () => { driver.close(); await rm(root, { recursive: true, force: true }); });
  driver.exec('CREATE TABLE runs(id TEXT PRIMARY KEY,status TEXT NOT NULL,waiting_reason TEXT,waiting_on_ref TEXT,nonce TEXT,charged INTEGER NOT NULL)');
  const add = async (value: ReturnType<typeof pending> | ReturnType<typeof inFlight>) => {
    const artifact = await artifacts.publishCanonical(value, 'cliq-waiting-subject-v1');
    driver.prepare("INSERT INTO runs(id,status,waiting_reason,waiting_on_ref,nonce,charged) VALUES (?,'waiting','reconciliation',?,NULL,1)").run(value.runId, artifact.ref);
    return artifact.ref;
  };
  const rows = () => driver.prepare('SELECT * FROM runs ORDER BY id').all();
  return { driver, artifacts, add, rows };
}

test('15/16 global inspection bound counts exact worker/publication/MCP dispatches and user probes without a clock or authority alias', async t => {
  const { driver, artifacts, add } = await fixture(t), purposes: Purpose[] = ['worker_recovery', 'publication', 'mcp_recovery'];
  for (let index = 0; index < 15; index++) await add(inFlight(`active-${index}`, purposes[index % 3]!, index === 7 || index === 8));
  await add(pending('candidate'));
  const capacity = await readReconciliationProbeCapacity(driver, artifacts);
  assert.equal(capacity.active, 15); assert.equal(capacity.limit, MAX_SUPERVISOR_RECONCILIATION_PROBES); assert.equal(capacity.limit, 16);
  const next = await artifacts.publishCanonical(inFlight('candidate', 'mcp_recovery'), 'cliq-waiting-subject-v1');
  driver.transaction(connection => {
    capacity.assertAvailable(connection);
    connection.prepare("UPDATE runs SET waiting_on_ref=?,nonce='one-original-nonce' WHERE id='candidate'").run(next.ref);
  });
  const full = await readReconciliationProbeCapacity(driver, artifacts); assert.equal(full.active, 16);
  assert.throws(() => driver.transaction(connection => full.assertAvailable(connection)), ReconciliationProbeCapacityError);
  // Wall-clock expiry never retires a process or closes an original nonce.
  assert.equal((await readReconciliationProbeCapacity(driver, artifacts)).active, 16);
  driver.prepare("UPDATE runs SET status='queued',waiting_reason=NULL,waiting_on_ref=NULL WHERE id='active-0'").run();
  assert.equal((await readReconciliationProbeCapacity(driver, artifacts)).active, 15);
});

test('two real CAS/SQLite snapshots admit only the first transaction; stale loser changes no pointer, nonce or original charge', async t => {
  const { driver, artifacts, add, rows } = await fixture(t);
  for (let index = 0; index < 15; index++) await add(inFlight(`active-${index}`, index % 2 ? 'publication' : 'worker_recovery'));
  await add(pending('first')); await add(pending('second'));
  const [one, two] = await Promise.all([readReconciliationProbeCapacity(driver, artifacts), readReconciliationProbeCapacity(driver, artifacts)]);
  assert.equal(one.active, 15); assert.equal(two.active, 15);
  const first = await artifacts.publishCanonical(inFlight('first', 'mcp_recovery'), 'cliq-waiting-subject-v1');
  const second = await artifacts.publishCanonical(inFlight('second', 'publication'), 'cliq-waiting-subject-v1');
  driver.transaction(connection => { one.assertAvailable(connection);
    connection.prepare("UPDATE runs SET waiting_on_ref=?,nonce='first-original-nonce' WHERE id='first'").run(first.ref); });
  const before = rows();
  assert.throws(() => driver.transaction(connection => { two.assertAvailable(connection);
    connection.prepare("UPDATE runs SET waiting_on_ref=?,nonce='forbidden-new-nonce',charged=charged+1 WHERE id='second'").run(second.ref);
  }), ReconciliationProbeCapacityError);
  assert.deepEqual(rows(), before);
  assert.equal((await readReconciliationProbeCapacity(driver, artifacts)).active, 16);
});

test('a changed pending pointer also refuses the exact stale snapshot even when its old count would fit', async t => {
  const { driver, artifacts, add, rows } = await fixture(t); await add(pending('one')); await add(pending('two'));
  const snapshot = await readReconciliationProbeCapacity(driver, artifacts); assert.equal(snapshot.active, 0);
  const moved = await artifacts.publishCanonical({ ...pending('one'), createdAt: '2026-11-04T01:02:04.000Z' }, 'cliq-waiting-subject-v1');
  driver.prepare("UPDATE runs SET waiting_on_ref=? WHERE id='one'").run(moved.ref); const before = rows();
  assert.throws(() => driver.transaction(connection => { snapshot.assertAvailable(connection);
    connection.prepare("UPDATE runs SET nonce='forbidden' WHERE id='two'").run(); }), ReconciliationProbeCapacityError);
  assert.deepEqual(rows(), before); assert.equal((await readReconciliationProbeCapacity(driver, artifacts)).active, 0);
});
