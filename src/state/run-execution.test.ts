import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { openStateStore } from './store.js';
import { assertDeliveryExecution, assertDeliveryPublicationExecution, readOwnedPublicationExecutionResources,
  assertOwnedNoOpDeliveryTask, readOwnedNoOpDeliveryExecutionResources, assertDeliveryPublicationMaintenanceExecution, assertDeliveryPublicationReceivedExecution,
  assertDeliveryPublicationReconciliationExecution,
  assertOwnedPublicationReconciliationTask,
  isPublicationStopRevisionConflict,
  type DeliveryPublicationTask, type DeliveryNoOpTask, type DeliveryPublicationMaintenanceTask } from './run-execution.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { KernelStorageError } from './errors.js';

test('known publication Stop-race retention is only a retry classification, never Stop or result authority', () => {
  const conflict = new KernelStorageError('REVISION_CONFLICT', 'the original Stop changed the current SQL cut');
  for (const kind of ['publication_received', 'publication_reconciliation'] as const) {
    assert.equal(isPublicationStopRevisionConflict(kind, conflict, 'a'.repeat(64)), true);
    assert.equal(isPublicationStopRevisionConflict(kind, conflict, null), false);
    assert.equal(isPublicationStopRevisionConflict(kind, new KernelStorageError('LEASE_FENCED', 'fenced'), 'a'.repeat(64)), false);
    assert.equal(isPublicationStopRevisionConflict(kind, { code: 'REVISION_CONFLICT' }, 'a'.repeat(64)), false);
    assert.equal(isPublicationStopRevisionConflict(kind, new Error('REVISION_CONFLICT'), 'a'.repeat(64)), false);
  }
  for (const kind of ['tool', 'final_turn', 'verifier', 'publication', 'publication_maintenance'] as const)
    assert.equal(isPublicationStopRevisionConflict(kind, conflict, 'a'.repeat(64)), false);
});

test('publication cannot borrow a structurally forged execution or execute its callback', () => {
  let called = false;
  const forged = { assertCurrentDeliveryWorker() { called = true; } };
  assert.throws(() => assertDeliveryExecution(undefined as unknown as SqliteDriver, undefined as unknown as StateOwnerContext,
    forged, { runId: 'original', leaseEpoch: 1, launchId: 'launch', generationRef: 'a'.repeat(64), workerIdentityDigest: 'b'.repeat(64) }), TypeError);
  assert.equal(called, false);
});

test('an in-flight publication cannot borrow a structural task, callback or another execution', () => {
  let accessed = false;
  const forged = Object.defineProperty({}, 'assertCurrentDeliveryWorker', { get() {
    accessed = true; throw new Error('must refuse the execution brand before inspecting caller data');
  } });
  const task = Object.defineProperty({}, 'assertCurrent', { get() {
    accessed = true; throw new Error('must refuse the task brand before inspecting caller data');
  } }) as DeliveryPublicationTask;
  const worker = Object.defineProperty({}, 'runId', { get() {
    accessed = true; throw new Error('must refuse both brands before reading the supplied worker');
  } });
  assert.throws(() => assertDeliveryPublicationExecution(undefined as unknown as SqliteDriver,
    undefined as unknown as StateOwnerContext, forged, worker as never, task), TypeError);
  assert.equal(accessed, false);
});

test('publication retirement cannot borrow structural roots, callbacks or a forged execution before storage access', async () => {
  let accessed = false;
  const refuse = () => { accessed = true; throw new Error('forged resources must not be inspected'); };
  const driver = Object.defineProperty({}, 'prepare', { get: refuse }) as SqliteDriver;
  const owner = Object.defineProperty({}, 'filesystem', { get: refuse }) as StateOwnerContext;
  const execution = Object.defineProperty({}, 'resources', { get: refuse });
  const publication = Object.defineProperty({}, 'task', { get: refuse });
  await assert.rejects(readOwnedPublicationExecutionResources(driver, owner, execution, publication as never),
    /genuine same-owner execution/);
  assert.equal(accessed, false);
});

test('no-op and stopped publication tasks reject forged authority before inspecting storage, roots or the Catalog', async () => {
  let accessed = false;
  const refuse = () => { accessed = true; throw new Error('caller properties are not task authority'); };
  const driver = Object.defineProperty({}, 'prepare', { get: refuse }) as SqliteDriver;
  const owner = Object.defineProperty({}, 'filesystem', { get: refuse }) as StateOwnerContext;
  const execution = Object.defineProperty({}, 'assertOwned', { get: refuse });
  const task = Object.defineProperty({}, 'resources', { get: refuse });
  const catalog = Object.defineProperty({}, 'readCanonical', { get: refuse });
  assert.throws(() => assertOwnedNoOpDeliveryTask(driver, owner, execution, task as DeliveryNoOpTask, catalog as never), TypeError);
  await assert.rejects(readOwnedNoOpDeliveryExecutionResources(driver, owner, execution, task as DeliveryNoOpTask, catalog as never), TypeError);
  assert.throws(() => assertDeliveryPublicationMaintenanceExecution(driver, owner, execution,
    task as DeliveryPublicationMaintenanceTask, catalog as never), TypeError);
  assert.throws(() => assertDeliveryPublicationReceivedExecution(driver, owner, execution,
    task as never, catalog as never), TypeError);
  assert.throws(() => assertDeliveryPublicationReconciliationExecution(driver, owner, execution,
    task as never, catalog as never), TypeError);
  assert.throws(() => assertOwnedPublicationReconciliationTask(driver, owner, execution,
    task as never, catalog as never), TypeError);
  assert.equal(accessed, false);
});

test('a model-free execution selector neither reads model material nor reinterprets an Agent Run', async () => {
  const fixture = await createAgentFixture('execution-operation-selector', undefined, { tools: ['edit'], mode: 'accept-edits' });
  try {
    const original = await fixture.store.readRecoveryClosure(fixture.runId);
    let readMaterial = false;
    const input = Object.defineProperty({ runId: fixture.runId, operation: 'delivery' as const }, 'material', {
      get() { readMaterial = true; throw new Error('delivery must not read model material'); }
    });
    await assert.rejects(fixture.store.loadRunExecution(input), { code: 'INVALID_REQUEST' });
    assert.equal(readMaterial, false);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), original);
  } finally { await disposeFixture(fixture); }
});

test('opening Run execution without an installed native backend leaves every retained authority unchanged', async () => {
  const fixture = await createAgentFixture('execution-installation', undefined, { tools: ['edit'], mode: 'accept-edits' });
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material }),
      { code: process.platform === 'linux' ? 'UNSUPPORTED_EXECUTION_IDENTITY' : 'UNSUPPORTED_PLATFORM' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('Run execution reserves one resource owner during load and releases it when opening fails', async () => {
  const fixture = await createAgentFixture('execution-owner', undefined, { tools: ['edit'], mode: 'accept-edits' });
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const input = { runId: fixture.runId, material: fixture.authority.material };
    const refused = { code: process.platform === 'linux' ? 'UNSUPPORTED_EXECUTION_IDENTITY' : 'UNSUPPORTED_PLATFORM' };
    const first = assert.rejects(fixture.store.loadRunExecution(input), refused);
    await assert.rejects(fixture.store.loadRunExecution(input), { code: 'REVISION_CONFLICT' });
    await first;
    await assert.rejects(fixture.store.loadRunExecution(input), refused);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('StateStore shutdown joins a refused resource-free execution opening and permits a successor', async () => {
  const fixture = await createAgentFixture('execution-refused-shutdown', undefined, { tools: ['edit'], mode: 'accept-edits' });
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const refused = assert.rejects(fixture.store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material }),
      { code: process.platform === 'linux' ? 'UNSUPPORTED_EXECUTION_IDENTITY' : 'UNSUPPORTED_PLATFORM' });
    const closing = fixture.store.close();
    await refused;
    await closing;
    fixture.store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
