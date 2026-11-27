import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import { admitChildRun, completeChildAdmissionRefusal, isChildAdmissionRefused } from './child-run-admission.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { offlineDelegateRequest } from './testing/child-runs.js';
import { disposeFixture } from './testing/fixtures.js';
import { batch } from './testing/tool-calls.js';
import { retireFixtureToolSelection } from './testing/tool-effects.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';

async function fixture(label: string, count = 1) {
  const original = await createAgentFixture(label, { modelTokens: 200_000, childDepth: 1 }, { mode: 'yolo', tools: ['delegate', 'await_children', 'read'] });
  try {
    await batch(original, Array.from({length: count}, (_, i) => ({ name: 'delegate', input: offlineDelegateRequest(`Inspect refusal ${i}`) })));
    const selected = await original.agent.prepareTool({ expectedRunRevision: original.store.getRun(original.runId).revision, leaseEpoch: original.leaseEpoch });
    if (selected.disposition !== 'retirement_required') throw new Error('original parent must retire');
    await retireFixtureToolSelection(original, selected);
    return { ...original, driver: Reflect.get(original.store, 'driver') as SqliteDriver, owner: Reflect.get(original.store, 'owner') as StateOwnerContext };
  } catch (error) { await disposeFixture(original); throw error; }
}
async function refusal(f: Awaited<ReturnType<typeof fixture>>) {
  let observed: unknown;
  await assert.rejects(admitChildRun(f.driver, f.store.artifacts, f.owner, { runId: f.runId,
    expectedRunRevision: f.store.getRun(f.runId).revision, releaseKeys: f.signed.releaseKeys }), error => {
      assert(isChildAdmissionRefused(error)); observed = error; return true;
    });
  return observed;
}

// Real ordinary Store/SQLite/CAS/source/owner, existing inert model/death
// fixture. Corrupt data below is only negative input and is restored before
// any successful read/close. No authority or platform evidence is fabricated.
test('a genuine no-child attempt joins CAS failure and SQL rollback before committing one normal result without an allocation', async () => {
  const f = await fixture('child-no-admission-faults');
  try {
    const observed = await refusal(f), before = await f.store.readRecoveryClosure(f.runId), publish = f.store.artifacts.publishBytes.bind(f.store.artifacts);
    f.store.artifacts.publishBytes = async (bytes, media, kind) => {
      const value = await publish(bytes, media, kind);
      if (kind === 'cliq-child-admission-refusal-v1') throw new Error('injected no-child actual CAS failure'); return value;
    };
    try { await assert.rejects(completeChildAdmissionRefusal(f.driver, f.store.artifacts, f.owner, observed), /injected no-child actual CAS failure/); }
    finally { f.store.artifacts.publishBytes = publish; }
    assert.deepEqual(await f.store.readRecoveryClosure(f.runId), before);
    f.driver.exec("CREATE TRIGGER fail_no_child BEFORE INSERT ON checkpoints WHEN EXISTS(SELECT 1 FROM run_journal WHERE run_id=NEW.run_id AND op_kind='child_admission' AND phase='completed') BEGIN SELECT RAISE(ABORT,'injected no-child Checkpoint failure'); END");
    try { await assert.rejects(completeChildAdmissionRefusal(f.driver, f.store.artifacts, f.owner, observed), /injected no-child Checkpoint failure/); }
    finally { f.driver.exec('DROP TRIGGER fail_no_child'); }
    assert.deepEqual(await f.store.readRecoveryClosure(f.runId), before);
    const result = await completeChildAdmissionRefusal(f.driver, f.store.artifacts, f.owner, observed), after = await f.store.readRecoveryClosure(f.runId);
    assert.equal(result.run.revision, before.run.revision + 1); assert.equal(after.journal.length, before.journal.length + 3);
    assert.equal(after.run.budgetConsumed.toolCalls, before.run.budgetConsumed.toolCalls + 1); assert.deepEqual(after.childAllocations, []);
    assert.equal(f.driver.prepare('SELECT count(*) AS n FROM runs WHERE parent_run_id=?').get<{n:bigint}>(f.runId)!.n, 0n);
    assert.equal(f.driver.prepare("SELECT count(*) AS n FROM items WHERE run_id=? AND kind='child_handle'").get<{n:bigint}>(f.runId)!.n, 0n);
    await assert.rejects(completeChildAdmissionRefusal(f.driver, f.store.artifacts, f.owner, observed));
    assert.deepEqual(await f.store.readRecoveryClosure(f.runId), after);
  } finally { await disposeFixture(f); }
});

test('two legal no-child responses in one real provider batch cannot substitute one another in retained local history', async () => {
  const f = await fixture('child-no-admission-response-alias', 2);
  try {
    await completeChildAdmissionRefusal(f.driver, f.store.artifacts, f.owner, await refusal(f));
    await completeChildAdmissionRefusal(f.driver, f.store.artifacts, f.owner, await refusal(f));
    const after = await f.store.readRecoveryClosure(f.runId), rows = after.journal.filter(row => row.opKind === 'child_admission' && row.phase === 'completed');
    assert.equal(rows.length, 2); assert.notEqual(rows[0]!.resultRef, rows[1]!.resultRef);
    const trigger = f.driver.prepare("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='run_journal_immutable_update'").get<{sql:string}>()!.sql,
      original = f.driver.prepare('SELECT entry_json FROM run_journal WHERE run_id=? AND seq=?').get<{entry_json:string}>(f.runId, rows[0]!.seq)!.entry_json,
      corrupted = { ...parseJsonStrict(original) as Record<string, unknown>, resultRef: rows[1]!.resultRef };
    const replace = (value: string) => f.driver.transaction(connection => {
      connection.exec('DROP TRIGGER run_journal_immutable_update');
      connection.prepare('UPDATE run_journal SET entry_json=? WHERE run_id=? AND seq=?').run(value, f.runId, rows[0]!.seq); connection.exec(trigger);
    });
    replace(canonicalJsonBytes(corrupted).toString('utf8'));
    try { await assert.rejects(f.store.readRecoveryClosure(f.runId)); }
    finally { replace(original); }
    assert.deepEqual(await f.store.readRecoveryClosure(f.runId), after);
  } finally { await disposeFixture(f); }
});
