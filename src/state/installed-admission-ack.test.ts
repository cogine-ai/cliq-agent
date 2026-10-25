// Exercise the actual handler tail and driver join with an existing core
// StateStore, SQLite admission and real owned CAS query. This creates no
// installed selection, launcher or native execution/qualification evidence.
import assert from 'node:assert/strict';
import { promises as fs, readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { setImmediate } from 'node:timers/promises';
import ts from 'typescript';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { KernelStorageError } from './errors.js';
import { readCheckpoint, readRun } from './rows.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { createQueuedFixture, disposeFixture } from './testing/fixtures.js';

const source = readFileSync(new URL('./store.ts', import.meta.url), 'utf8');
const file = ts.createSourceFile('store.ts', source, ts.ScriptTarget.Latest, true);
function method(name: string) {
  const result: ts.MethodDeclaration[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isMethodDeclaration(node) && node.name.getText(file) === name) result.push(node);
    ts.forEachChild(node, visit);
  };
  visit(file); assert.equal(result.length, 1); assert(result[0]!.body);
  return result[0]!.body!;
}
const compile = (text: string) => ts.transpileModule(text, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
}).outputText;
function acknowledgement(name: 'submitInstalledRunOwned' | 'applyInstalledRunOwned') {
  const body = method(name).statements.find(ts.isTryStatement)!.tryBlock;
  const start = body.statements.findIndex(statement => statement.getText(file).includes('this.retainInstalledAgent(runId,'));
  assert(start >= 0);
  return Function(compile('return async function(runId, assembled, admission, diagnosis) {' +
    body.statements.slice(start).map(statement => statement.getText(file)).join('\n') + '}'))() as
    (this: object, id: string, assembled: object, admission: Promise<unknown>, diagnosis?: unknown) => Promise<unknown>;
}
function driverJoin() {
  const statements = method('driveInstalledRun').statements;
  const first = statements.findIndex(statement => statement.getText(file) === "this.installedRunPhases.set(runId, 'drive_agent');");
  const last = statements.findIndex((statement, index) => index > first && statement.getText(file) ===
    "this.installedRunPhases.set(runId, 'drive_material');");
  assert(first >= 0 && last > first, 'deadline load must join before material work');
  return Function('readRun', compile('return async function(runId) {let run;' +
    statements.slice(first, last).map(statement => statement.getText(file)).join('\n') + ';return {agent,run};}'))(readRun) as
    (this: object, id: string) => Promise<unknown>;
}
function gate() {
  let release!: () => void;
  return { promise: new Promise<void>(resolve => { release = resolve; }), release };
}

for (const handler of ['submitInstalledRunOwned', 'applyInstalledRunOwned'] as const)
  for (const scenario of ['complete', 'close', 'slot_blocked'] as const) test(`${handler} acknowledges durable SQL and joins its original owned read before ${scenario}`, async t => {
    const closing = scenario === 'close';
    const fixture = await createQueuedFixture('admission-ack');
    const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    const original = fixture.store.getRun(fixture.runId);
    const checkpoint = readCheckpoint(driver, original.latestCheckpointId);
    const row = driver.prepare("SELECT response_ref FROM control_requests WHERE principal_id=? AND method='run.submit'")
      .get<{ response_ref: string }>(fixture.principalId)!;
    assert(row);
    const response = await fixture.store.artifacts.readCanonical(row.response_ref);
    const accepted = { run: original, response };
    const identity = await publishInProcessChannel(fixture.store);
    const entered = gate(), released = gate(), open = fs.open.bind(fs), active = new Set<object>();
    const scheduled: string[] = [], phases: string[] = [];
    let held = false, acknowledged = false, loaded = false, joined = false, slotQueries = 0;
    let reading: Promise<unknown> | undefined, driving: Promise<unknown> | undefined, stopped: Promise<void> | undefined,
      acknowledgedResponse: Promise<unknown> | undefined;
    t.after(async () => {
      released.release(); await Promise.allSettled([reading, driving, stopped, acknowledgedResponse].filter(value => value !== undefined));
      t.mock.restoreAll(); driver.close(); await disposeFixture(fixture);
    });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
      const handle = await open(...args); active.add(handle);
      const close = handle.close.bind(handle);
      t.mock.method(handle, 'close', async () => { await close(); assert(active.delete(handle)); });
      if (args[0] === path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, original.specRef)) {
        const read = handle.read.bind(handle);
        const pending = async (...values: unknown[]) => {
          const result = await Reflect.apply(read, handle, values) as { bytesRead: number };
          if (!held && result.bytesRead > 0) { held = true; entered.release(); await released.promise; }
          return result;
        };
        t.mock.method(handle, 'read', pending as typeof handle.read);
      }
      return handle;
    });
    reading = fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: fixture.runId }, identity);
    void reading.then(() => { loaded = true; }, () => {});
    const pendingRead = reading;
    const owner = { driver, installedRunPhases: { set(_id: string, phase: string) { phases.push(phase); } },
      retainInstalledAgent: () => pendingRead, supportsInstalledRuns: () => true,
      executions: new Map(), installedWorkerSlotAvailable() { slotQueries++; return scenario !== 'slot_blocked'; },
      scheduleInstalledRun(id: string) { scheduled.push(id); } };
    const ack = acknowledgedResponse = acknowledgement(handler).call(owner, fixture.runId, { material: undefined }, Promise.resolve(accepted));
    void ack.then(() => { acknowledged = true; }, () => {});
    await entered.promise; await setImmediate();
    assert.equal(acknowledged, true, 'committed admission must not wait for nonproductive reconstruction');
    assert.equal(await ack, accepted); assert.deepEqual(scheduled, [fixture.runId]);
    assert.equal(loaded, false); assert(active.size >= 2, 'the original CAS file and root remain actually held');
    driving = driverJoin().call(owner, fixture.runId);
    void driving.then(() => { joined = true; }, () => {});
    await setImmediate(); assert.equal(joined, false);
    assert.equal(slotQueries, 0, 'a slot return cannot hide the pending original load or its error');
    assert.deepEqual(phases, ['drive_agent'], 'material/native work cannot precede the original load');
    assert.deepEqual(fixture.store.getRun(fixture.runId), original);
    if (closing) {
      const rejected = assert.rejects(driving, error => error instanceof KernelStorageError && error.code === 'LEASE_FENCED');
      let closed = false; stopped = fixture.store.close().then(() => { closed = true; });
      await setImmediate(); assert.equal(closed, false);
      assert.equal(driver.prepare("SELECT state FROM state_owners WHERE state='active'").get()?.state, 'active');
      released.release(); await rejected; await stopped;
      assert.equal(active.size, 0); assert.equal(loaded, false); assert.equal(slotQueries, 0); assert.deepEqual(phases, ['drive_agent']);
      t.mock.restoreAll();
      fixture.store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
      const successor = await publishInProcessChannel(fixture.store);
      const cut = await fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: fixture.runId }, successor);
      assert.equal(cut.method, 'run.get');
      if (cut.method !== 'run.get') assert.fail();
      assert.deepEqual(cut.snapshot.run, original, 'acknowledged queued Run and initial Checkpoint survive actual owner close/reopen');
      assert.deepEqual(cut.checkpoints.find(value => value.id === checkpoint.id), checkpoint);
      assert(canonicalJsonBytes(await fixture.store.artifacts.readCanonical(row.response_ref)).equals(canonicalJsonBytes(response)));
    } else {
      released.release(); const value = await driving;
      assert(loaded && joined); assert.equal(active.size, 0); assert.equal(slotQueries, 1);
      if (scenario === 'slot_blocked') assert.equal(value, undefined, 'waiting for capacity never enters material/native work');
      else assert.deepEqual((value as { run: unknown }).run, original);
    }
  });

test('both admission replays retain the existing load only for nonterminal Runs and keep the original queue failure owner', () => {
  for (const name of ['submitInstalledRunOwned', 'applyInstalledRunOwned']) {
    const text = method(name).getText(file);
    assert.match(text, /\['queued', 'running', 'waiting'\]\.includes\(readRun\(this\.driver, replay\.run\.id\)\.status\)/u);
    assert.equal(/await this\.retainInstalledAgent\(replay\.run\.id\)/u.test(text), false,
      'replaying a durable response must not wait for its already-owned load');
    const registration = text.indexOf('this.retainInstalledAgent(runId,');
    assert(registration >= 0 && registration < text.indexOf('const result = await admission;', registration));
  }
  const queue = method('scheduleInstalledRun').getText(file);
  assert.match(queue, /await this\.driveInstalledRun\(runId\)/u);
  assert.match(queue, /this\.installedRunFailures\.set\(runId, error\)/u);
  assert.match(queue, /if \(error instanceof ResourceRetirementError\) this\.schedulerFailure \?\?= error/u);
});
