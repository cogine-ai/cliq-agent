// Real SQLite constraints and migration only. These inert referential rows
// are never loaded as StateOwner, child admission, permission or execution proof.
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { KERNEL_SQLITE_APPLICATION_ID } from '../config.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import type { ChildAllocationV1 } from '../kernel/types.js';
import { applyKernelSchema, KERNEL_SCHEMA_V1_SQL, KERNEL_SCHEMA_V2_SQL, KERNEL_SCHEMA_V3_SQL,
  KERNEL_SCHEMA_V4_SQL, KERNEL_SCHEMA_V5_SQL, KERNEL_SCHEMA_V6_SQL, KERNEL_SCHEMA_V7_SQL, readSchemaUserVersion } from './schema.js';
import { openSqliteDriver, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';

const time = '2026-10-26T00:00:00.000Z', ref = 'a'.repeat(64);
const budget = { modelTokens: 10, costMicros: 10, toolCalls: 10, repairAttempts: 1 };
const json = (value: unknown) => canonicalJsonBytes(value).toString('utf8');
type ReservedAllocation = Extract<ChildAllocationV1, { state: 'reserved' }>;
const reserved = (childRunId = 'c0', parentRunId = 'p0'): ReservedAllocation => ({
  schemaVersion: 1, parentRunId, childRunId, admissionKey: 'admission0', delegateBatchItemId: 'batch0',
  delegateCallId: 'call0', delegateCallIndex: 0, delegateOpId: 'op0', delegateOperationGrantRef: ref,
  capabilityGrantRef: ref, mode: 'read_only', grantedAdditiveCeilings: budget, grantedChildDepth: 0,
  grantedChildConcurrency: 1, childDeadlineAt: '2026-10-26T00:01:00.000Z', createdAt: time, state: 'reserved' });
const terminal = (base: ReservedAllocation): Extract<ChildAllocationV1, { state: 'child_terminal' }> => ({ ...base, state: 'child_terminal',
  terminal: { mode: 'read_only', status: 'succeeded', resultRef: ref, modelContentRef: ref, modelContentDigest: ref },
  inclusiveBudgetUsage: { modelTokens: 2, costMicros: 3, toolCalls: 1, repairAttempts: 0 }, terminalAt: '2026-10-26T00:00:01.000Z' });
const settled = (base: ReservedAllocation): Extract<ChildAllocationV1, { state: 'settled' }> => ({ ...terminal(base), state: 'settled',
  childResultItemId: 'result0', parentSettlementRevision: 2,
  releasedUnusedBudget: { modelTokens: 8, costMicros: 7, toolCalls: 9, repairAttempts: 1 }, settledAt: '2026-10-26T00:00:02.000Z' });
function insert(db: SqliteDriver, value: ChildAllocationV1) {
  db.prepare('INSERT INTO child_allocations(parent_run_id,child_run_id,state,row_json) VALUES(?,?,?,?)')
    .run(value.parentRunId, value.childRunId, value.state, json(value));
}
function update(db: SqliteDriver, value: ChildAllocationV1) {
  db.prepare('UPDATE child_allocations SET state=?,row_json=? WHERE parent_run_id=? AND child_run_id=?')
    .run(value.state, json(value), value.parentRunId, value.childRunId);
}
const rows = (db: SqliteDriver) => db.prepare('SELECT * FROM child_allocations ORDER BY parent_run_id,child_run_id').all().map(row => ({ ...row }));
async function fixture(version: 'current' | 7 = 'current') {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-child-schema-'));
  const db = openSqliteDriver(path.join(root, 'kernel.sqlite3'));
  try {
    if (version === 'current') applyKernelSchema(db);
    else db.transaction(connection => {
      connection.exec(`PRAGMA application_id=${KERNEL_SQLITE_APPLICATION_ID}`);
      connection.exec([KERNEL_SCHEMA_V1_SQL, KERNEL_SCHEMA_V2_SQL, KERNEL_SCHEMA_V3_SQL,
        KERNEL_SCHEMA_V4_SQL, KERNEL_SCHEMA_V5_SQL, KERNEL_SCHEMA_V6_SQL, KERNEL_SCHEMA_V7_SQL].join('\n'));
      connection.exec('PRAGMA user_version=7');
    });
    db.transaction(connection => {
      connection.prepare(`INSERT INTO sessions(id,workspace_identity_ref,context_revision,latest_item_seq,context_projection_ref,
        created_at,updated_at,principal_id,admission_method,admission_key,admission_intent_digest)
        VALUES('session',?,1,0,?,?,?,'principal','session.create','session-key',?)`).run(ref, ref, time, time, ref);
      for (const id of ['p0', 'p1', 'c0', 'c1', 'c2', 'c3', 'c4']) {
        connection.prepare(`INSERT INTO runs(id,session_id,spec_ref,status,revision,lease_epoch,latest_checkpoint_id,
          budget_reserved_json,budget_consumed_json,repair_count,cancel_requested,created_at,deadline_at,updated_at,
          principal_id,admission_method,admission_key,admission_intent_digest,admitted_request_digest)
          VALUES(?,'session',?,'queued',1,0,?,?,?,0,0,?,?,?,'principal','run.submit',?,?,?)`)
          .run(id, ref, 'cp-' + id, json(budget), json(budget), time, time, time, 'key-' + id, ref, ref);
        connection.prepare(`INSERT INTO checkpoints(id,schema_version,run_id,based_on_run_revision,run_item_seq,
          context_manifest_ref,journal_seq,workspace_state_ref,created_at,reason) VALUES(?,1,?,1,0,?,0,?,?,'initial')`)
          .run('cp-' + id, id, ref, ref, time);
      }
    });
    return { db, async close() { db.close(); await rm(root, { recursive: true, force: true }); } };
  } catch (error) { db.close(); await rm(root, { recursive: true, force: true }); throw error; }
}

test('allocation SQL permits one monotonic terminal and settlement while retaining original identity and usage', async () => {
  const f = await fixture();
  try {
    const original = reserved(); insert(f.db, original);
    assert.throws(() => update(f.db, settled(original)), /allocation/);
    assert.throws(() => update(f.db, { ...terminal(original), capabilityGrantRef: 'b'.repeat(64) }), /allocation/);
    assert.throws(() => f.db.prepare('DELETE FROM child_allocations').run(), /allocation/);
    assert.deepEqual(rows(f.db), [{ parent_run_id: 'p0', child_run_id: 'c0', state: 'reserved', row_json: json(original) }]);
    const done = terminal(original); update(f.db, done);
    assert.throws(() => update(f.db, original), /allocation/);
    assert.throws(() => update(f.db, { ...settled(original), terminalAt: time }), /allocation/);
    const final = settled(original); update(f.db, final);
    assert.throws(() => update(f.db, { ...final, parentSettlementRevision: 3 } as ChildAllocationV1), /allocation/);
    assert.throws(() => f.db.prepare('DELETE FROM child_allocations').run(), /allocation/);
    assert.equal(rows(f.db)[0]!.row_json, json(final));
  } finally { await f.close(); }
});

test('parent cancellation is a first-set immutable post-birth child fence, not a seeded winner or terminal rewrite', async () => {
  const f = await fixture();
  try {
    const columns = f.db.prepare('PRAGMA table_info(runs)').all<{ name: string }>().map(row => row.name);
    assert.throws(() => f.db.prepare(`INSERT INTO runs(${columns.join(',')}) SELECT ${columns.map(name =>
      name === 'id' ? "'seeded-observation'" : name === 'parent_cancellation_ref' ? '?' : name).join(',')}
      FROM runs WHERE id='c0'`).run(ref), /observed after child birth/);
    const update = (set: string) => f.db.prepare(`UPDATE runs SET ${set} WHERE id='c0'`).run();
    const rejectedFence = /parent cancellation (?:requires its nonterminal child fence transaction|dispatch fence cannot be cleared)/;
    assert.throws(() => update(`parent_cancellation_ref='${ref}',cancel_requested=1,stop_intent_ref='${ref}',revision=2`), rejectedFence);
    update("parent_run_id='p0'");
    for (const set of [
      `parent_cancellation_ref='${ref}',revision=2`,
      `parent_cancellation_ref='${ref}',cancel_requested=1,revision=2`,
      `parent_cancellation_ref='${ref}',cancel_requested=1,stop_intent_ref='${ref}'`,
      `parent_cancellation_ref='${ref}',cancel_requested=1,stop_intent_ref='${ref}',revision=2,status='cancelled'`
    ]) {
      const before = f.db.prepare("SELECT * FROM runs WHERE id='c0'").get();
      assert.throws(() => update(set), rejectedFence);
      assert.deepEqual(f.db.prepare("SELECT * FROM runs WHERE id='c0'").get(), before);
    }
    assert.throws(() => update(`parent_cancellation_ref='invalid',cancel_requested=1,stop_intent_ref='${ref}',revision=2`), /CHECK constraint/);
    update(`parent_cancellation_ref='${ref}',cancel_requested=1,stop_intent_ref='${ref}',revision=2`);
    for (const set of ["parent_cancellation_ref=NULL", `parent_cancellation_ref='${'b'.repeat(64)}'`])
      assert.throws(() => update(set), /immutable/);
    for (const set of ['cancel_requested=0', 'stop_intent_ref=NULL', 'parent_run_id=NULL', "parent_run_id='p1'", "status='succeeded'", "status='completed_unverified'"])
      assert.throws(() => update(set), /dispatch fence cannot be cleared/);
    update('revision=3');
    update("status='cancelled',revision=4");
    assert.equal(f.db.prepare("SELECT parent_cancellation_ref FROM runs WHERE id='c0'").get<{parent_cancellation_ref:string}>()!.parent_cancellation_ref, ref);
    assert.throws(() => f.db.prepare(`UPDATE runs SET parent_run_id='p0',status='cancelled',cancel_requested=1,
      stop_intent_ref=?,parent_cancellation_ref=?,revision=2 WHERE id='c1'`).run(ref, ref), rejectedFence);
    assert.throws(() => f.db.prepare(`UPDATE runs SET parent_run_id='p0',cancel_requested=1,
      stop_intent_ref=?,parent_cancellation_ref=?,revision=2 WHERE id='c1'`).run(ref, ref), rejectedFence);
  } finally { await f.close(); }
});

test('a child and each original delegate identity can be allocated only once', async () => {
  const f = await fixture();
  try {
    const original = reserved(); insert(f.db, original);
    const distinct = { ...reserved('c1'), admissionKey: 'other-admission', delegateBatchItemId: 'other-batch',
      delegateCallId: 'other-call', delegateCallIndex: 1, delegateOpId: 'other-op' };
    const conflicts: ChildAllocationV1[] = [
      { ...distinct, parentRunId: 'p1', childRunId: 'c0' },
      { ...distinct, admissionKey: original.admissionKey }, { ...distinct, delegateOpId: original.delegateOpId },
      { ...distinct, delegateBatchItemId: original.delegateBatchItemId, delegateCallIndex: original.delegateCallIndex },
      { ...distinct, delegateBatchItemId: original.delegateBatchItemId, delegateCallId: original.delegateCallId }
    ];
    for (const conflict of conflicts) assert.throws(() => insert(f.db, conflict), /UNIQUE constraint failed/);
    assert.equal(rows(f.db).length, 1);
    assert.throws(() => insert(f.db, terminal(distinct)), /allocation/);
    insert(f.db, distinct); assert.equal(rows(f.db).length, 2);
  } finally { await f.close(); }
});

test('schema migration rejects original invalid UTF-8 instead of accepting replacement-character identities', async () => {
  const f = await fixture(7);
  try {
    insert(f.db, reserved());
    const bytes = Buffer.from(json(reserved())), at = bytes.indexOf('admission0');
    assert(at >= 0); bytes[at] = 0x80;
    f.db.prepare('UPDATE child_allocations SET row_json=CAST(? AS TEXT)').run(bytes);
    const raw = f.db.prepare('SELECT CAST(row_json AS BLOB) AS bytes,json_valid(row_json) AS valid FROM child_allocations')
      .get<{ bytes: Uint8Array; valid: bigint }>()!;
    assert.equal(raw.valid, 1n, 'SQLite JSON accepts this string despite its invalid original UTF-8');
    assert.deepEqual(Buffer.from(raw.bytes), bytes);
    const before = rows(f.db);
    assert.throws(() => applyKernelSchema(f.db), { code: 'RECOVERY_REQUIRED' });
    assert.equal(readSchemaUserVersion(f.db), 7);
    assert.deepEqual(rows(f.db), before);
    assert.deepEqual(Buffer.from(f.db.prepare('SELECT CAST(row_json AS BLOB) AS bytes FROM child_allocations')
      .get<{ bytes: Uint8Array }>()!.bytes), bytes);
  } finally { await f.close(); }
});

test('schema 7 migration retains original allocation bytes and adds the same schema 8 guards', async () => {
  const f = await fixture(7);
  try {
    insert(f.db, reserved()); const before = rows(f.db);
    applyKernelSchema(f.db); assert.equal(readSchemaUserVersion(f.db), 8);
    assert.deepEqual(rows(f.db), before);
    assert.throws(() => insert(f.db, { ...reserved('c0', 'p1'), admissionKey: 'other' }), /UNIQUE constraint failed/);
    assert.throws(() => f.db.prepare('DELETE FROM child_allocations').run(), /allocation/);
    applyKernelSchema(f.db); assert.deepEqual(rows(f.db), before);
  } finally { await f.close(); }
});

test('schema 8 retains every original physical Journal guard and closes local operations without native authority', async () => {
  const f = await fixture(7);
  const guard = () => f.db.prepare("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='run_journal_validate_insert'")
    .get<{ sql: string }>()!.sql;
  try {
    const original = guard(); applyKernelSchema(f.db); const current = guard();
    const first = current.indexOf("    WHEN NEW.op_kind IN ('child_admission', 'child_merge')");
    const last = current.indexOf('    WHEN NEW.attempt < 0', first);
    assert(first >= 0 && last > first);
    const addedKinds = ", 'child_admission', 'child_merge', 'child_await', 'skill_resource'";
    assert.equal(current.split(addedKinds).length, 2, 'only the four exact schema-8 local kinds extend the original whitelist');
    assert.equal((current.slice(0, first) + current.slice(last)).replace(addedKinds, ''), original,
      'all original physical kind, sequencing, claim, terminal, UNKNOWN and settlement checks remain byte-identical');
    let seq = 0;
    for (const opKind of ['child_admission', 'child_merge', 'child_await', 'skill_resource']) {
      const prepared = { seq: seq + 1, runId: 'p0', opId: opKind, opKind, attempt: 0, leaseEpoch: 0, phase: 'prepared',
        target: ref, requestRef: ref, replayClass: 'retry', idempotencyKey: opKind, ...(opKind === 'child_await' ? {} : { grantRef: ref }),
        budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, timestamp: time, localCommittedAt: time };
      const write = (row: typeof prepared & Record<string, unknown>, connection: SqliteConnection | SqliteDriver = f.db) => connection.prepare(`INSERT INTO run_journal(run_id,seq,op_id,op_kind,attempt,phase,entry_json)
        VALUES(?,?,?,?,?,?,?)`).run(row.runId, row.seq, row.opId, row.opKind, row.attempt, row.phase, json(row));
      for (const field of ['sandboxLaunchSpecRef', 'brokerFenceTokenDigest', 'receiptRef', 'errorRef', 'evidenceRef', 'evidenceDigest', 'attestationRef'])
        assert.throws(() => write({ ...prepared, [field]: ref }), /local child journal/);
      assert.throws(() => write({ ...prepared, leaseEpoch: 1 }), /local child journal/);
      if (opKind === 'child_await') assert.throws(() => write({ ...prepared, grantRef: ref }), /local child journal/);
      else { const { grantRef: _grant, ...noGrant } = prepared; assert.throws(() => write(noGrant), /local child journal/); }
      assert.throws(() => write({ ...prepared, budgetDelta: { ...prepared.budgetDelta, modelTokens: false } } as never), /local child journal/);
      f.db.transaction(connection => {
        write(prepared, connection);
        const claim = { ...prepared, seq: prepared.seq + 1, phase: 'dispatch_claimed',
          dispatchId: 'claim-' + opKind, supervisorInstanceId: 'instance', stateOwnerEpoch: 1,
          budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 } };
        assert.throws(() => write({ ...claim, requestRef: 'b'.repeat(64) }, connection), /original request grant and commit cut/);
        write(claim, connection);
        const completed = { ...claim, seq: claim.seq + 1, phase: 'completed', resultRef: ref, budgetSettlementRef: ref,
          budgetDelta: prepared.budgetDelta };
        assert.throws(() => write({ ...completed, stateOwnerEpoch: 2 }, connection), /original local claim/);
        assert.throws(() => write({ ...completed, phase: 'unknown' }, connection), /local child journal/);
        write(completed, connection);
      });
      seq += 3;
    }
    assert.equal(f.db.prepare('SELECT count(*) AS n FROM run_journal').get<{ n: bigint }>()!.n, 12n);
  } finally { await f.close(); }
});

test('invalid retained allocation or duplicate incoming parent rolls back the entire schema 8 migration', async t => {
  for (const mode of ['shape', 'duplicate'] as const) await t.test(mode, async () => {
    const f = await fixture(7);
    const snapshot = () => ({ version: readSchemaUserVersion(f.db), rows: rows(f.db),
      schema: f.db.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').all() });
    try {
      insert(f.db, reserved());
      if (mode === 'shape') f.db.prepare('UPDATE child_allocations SET row_json=?').run(json({ ...reserved(), state: 'settled' }));
      else insert(f.db, reserved('c0', 'p1'));
      const before = snapshot(); assert.throws(() => applyKernelSchema(f.db)); assert.deepEqual(snapshot(), before);
    } finally { await f.close(); }
  });
});
