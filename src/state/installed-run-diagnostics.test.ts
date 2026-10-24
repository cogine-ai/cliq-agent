// Fixed data only: these tests create no StateOwner, Run or native evidence.
import assert from 'node:assert/strict';
import { channel } from 'node:diagnostics_channel';
import { test } from 'node:test';
import { KernelStorageError } from './errors.js';

test('an apply diagnostic preserves the original rejection and emits only its fixed failure projection', async () => {
  const { beginInstalledApplyDiagnostic } = await import('./installed-run-diagnostics.js');
  const records: unknown[] = [], diagnostic = channel('cliq.installed.run.failures.v1');
  const receive = (record: unknown) => { try { records.push(record); } catch {} };
  diagnostic.subscribe(receive);
  try {
    const observer = beginInstalledApplyDiagnostic(); assert(observer);
    observer.stage('postcommit_load');
    const original = new KernelStorageError('RECOVERY_REQUIRED', 'private diagnostic input must not escape');
    Object.defineProperty(original, 'path', { get() { throw new Error('must not read'); } });
    await assert.rejects((async () => {
      try { throw original; }
      catch (error) { observer.failure(error, false); throw error; }
    })(), error => error === original);
    assert.deepEqual(records, [{ kind: 'apply_failure', stage: 'postcommit_load', closing: false,
      errorClass: 'kernel', code: 'RECOVERY_REQUIRED', sqliteCode: null }]);
    assert(Object.isFrozen(records[0]));
    assert.equal(JSON.stringify(records).includes('private'), false);
  } finally { diagnostic.unsubscribe(receive); }
});

test('scheduler failures retain the last actual phase and distinguish closing from an earlier failure', async () => {
  const { beginInstalledSchedulerDiagnostic } = await import('./installed-run-diagnostics.js');
  const records: unknown[] = [], diagnostic = channel('cliq.installed.run.failures.v1');
  const receive = (record: unknown) => { try { records.push(record); } catch {} };
  diagnostic.subscribe(receive);
  try {
    const observer = beginInstalledSchedulerDiagnostic('drive'); assert(observer);
    observer.phase('result_recovery_history_candidate');
    observer.failure(new TypeError('private'), false);
    const maintenance = beginInstalledSchedulerDiagnostic('maintenance'); assert(maintenance);
    maintenance.failure(new KernelStorageError('LEASE_FENCED', 'private'), true);
    assert.deepEqual(records, [
      { kind: 'scheduler_failure', origin: 'drive', phase: 'result_recovery_history_candidate', closing: false,
        errorClass: 'type', code: 'none', sqliteCode: null },
      { kind: 'scheduler_failure', origin: 'maintenance', phase: 'unavailable', closing: true,
        errorClass: 'kernel', code: 'LEASE_FENCED', sqliteCode: null }
    ]);
  } finally { diagnostic.unsubscribe(receive); }
});

test('the pre-revocation snapshot copies only current counts and fixed phase multiplicities', async () => {
  const { noteInstalledStoreStop } = await import('./installed-run-diagnostics.js');
  const records: unknown[] = [], diagnostic = channel('cliq.installed.run.failures.v1');
  const receive = (record: unknown) => { try { records.push(record); } catch {} };
  diagnostic.subscribe(receive);
  try {
    const phases = ['scheduled', 'result_recovery_history_candidate', 'scheduled'];
    noteInstalledStoreStop({ driverTasks: 3, agentLoads: 0, admissions: 1, retainedFailures: 0, globalFailure: false, phases });
    phases.length = 0;
    assert.deepEqual(records, [{ kind: 'store_stop', driverTasks: 3, agentLoads: 0, admissions: 1, retainedFailures: 0,
      globalFailure: false, phases: { result_recovery_history_candidate: 1, scheduled: 2 } }]);
    assert(Object.isFrozen(records[0]) && Object.isFrozen((records[0] as { phases: object }).phases));
  } finally { diagnostic.unsubscribe(receive); }
});

test('unsubscribed diagnostics allocate no tracker and do not inspect hostile input or sample clocks', async () => {
  const { beginInstalledApplyDiagnostic, beginInstalledSchedulerDiagnostic, noteInstalledStoreStop,
    installedRunDiagnosticsSubscribed } = await import('./installed-run-diagnostics.js');
  assert.equal(installedRunDiagnosticsSubscribed(), false);
  let accesses = 0;
  const hostile = new Proxy({}, { get() { accesses++; throw 0; }, ownKeys() { accesses++; throw 0; },
    getPrototypeOf() { accesses++; throw 0; }, getOwnPropertyDescriptor() { accesses++; throw 0; } });
  const originalClock = process.hrtime.bigint;
  try {
    process.hrtime.bigint = () => { accesses++; throw new Error('clock must not be sampled'); };
    assert.equal(beginInstalledApplyDiagnostic(), undefined);
    assert.equal(beginInstalledSchedulerDiagnostic('drive'), undefined);
    noteInstalledStoreStop(hostile);
    assert.equal(accesses, 0);
  } finally { process.hrtime.bigint = originalClock; }
});

test('error projection never invokes getters, proxy traps or stringification', async () => {
  const { beginInstalledApplyDiagnostic } = await import('./installed-run-diagnostics.js');
  const records: any[] = [], diagnostic = channel('cliq.installed.run.failures.v1');
  const receive = (record: unknown) => { try { records.push(record); } catch {} };
  diagnostic.subscribe(receive);
  try {
    let accesses = 0;
    const bad = () => { accesses++; throw new Error('must not inspect private data'); };
    const original = new Error();
    for (const key of ['code', 'errcode', 'message', 'stack', 'path', 'cause']) Object.defineProperty(original, key, { get: bad });
    const observer = beginInstalledApplyDiagnostic()!;
    observer.stage(Object.defineProperty({}, 'toString', { get: bad }) as never);
    observer.failure(original, false);
    observer.failure(new Proxy(original, { get: bad, ownKeys: bad, getPrototypeOf: bad, getOwnPropertyDescriptor: bad }), false);
    observer.failure({ get code() { return bad(); } }, false);
    assert.equal(accesses, 0);
    assert.equal(records.length, 3);
    assert(records.every(row => row.stage === 'request' && row.errorClass === 'other' && row.code === 'none' && row.sqliteCode === null));
  } finally { diagnostic.unsubscribe(receive); }
});

test('a real in-memory SQLite error contributes only its closed native code and integer', async () => {
  const { DatabaseSync } = await import('node:sqlite');
  const { beginInstalledApplyDiagnostic } = await import('./installed-run-diagnostics.js');
  const records: unknown[] = [], diagnostic = channel('cliq.installed.run.failures.v1');
  const receive = (record: unknown) => { try { records.push(record); } catch {} };
  const database = new DatabaseSync(':memory:');
  diagnostic.subscribe(receive);
  try {
    let original: unknown;
    try { database.prepare('SELECT absent_column'); } catch (error) { original = error; }
    assert(original instanceof Error);
    const observer = beginInstalledApplyDiagnostic()!; observer.stage('admit'); observer.failure(original, false);
    assert.deepEqual(records, [{ kind: 'apply_failure', stage: 'admit', closing: false,
      errorClass: 'sqlite', code: 'ERR_SQLITE_ERROR', sqliteCode: 1 }]);
  } finally { diagnostic.unsubscribe(receive); database.close(); }
});

test('malformed pre-close snapshots cannot invoke accessors or fabricate a phase count', async () => {
  const { noteInstalledStoreStop } = await import('./installed-run-diagnostics.js');
  const records: unknown[] = [], diagnostic = channel('cliq.installed.run.failures.v1');
  const receive = (record: unknown) => { try { records.push(record); } catch {} };
  diagnostic.subscribe(receive);
  try {
    let accesses = 0;
    const bad = () => { accesses++; throw 0; };
    const valid = () => ({ driverTasks: 1, agentLoads: 0, admissions: 0, retainedFailures: 0, globalFailure: false, phases: ['scheduled'] });
    const getter = Object.defineProperty(valid(), 'driverTasks', { get: bad });
    const hidden = Object.defineProperty(valid(), 'driverTasks', { value: 1, enumerable: false });
    const symbol = { ...valid(), [Symbol('private')]: 'private' };
    const index = ['scheduled']; Object.defineProperty(index, '0', { get: bad });
    for (const value of [getter, hidden, symbol, { ...valid(), phases: index }, { ...valid(), phases: ['other'] },
      { ...valid(), phases: new Proxy(['scheduled'], { ownKeys: bad }) }, { ...valid(), driverTasks: 0 },
      { ...valid(), driverTasks: true }, { ...valid(), admissions: -1 }, { ...valid(), phases: new Array(1) },
      new Proxy(valid(), { get: bad, ownKeys: bad, getPrototypeOf: bad })]) noteInstalledStoreStop(value);
    assert.equal(accesses, 0); assert.deepEqual(records, []);
  } finally { diagnostic.unsubscribe(receive); }
});
