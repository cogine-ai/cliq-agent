import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { addCanonicalDuration, digestOmitting } from '../kernel/identity.js';
import type { Checkpoint, InvocationJournalEntry, RunItemReferenceV1, SessionContextProjection, SessionItem } from '../kernel/types.js';
import { EventCursorExpiredError } from './control-read.js';
import { KernelStorageError } from './errors.js';
import { openSqliteDriver, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel, type StateStore } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { admissionKey, createActiveFixture, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

const isCode = (code: KernelStorageError['code']) => (error: unknown) => error instanceof KernelStorageError && error.code === code;

test('control reads expose the empty Session and the admitted Run initial checkpoint without payload bytes', async () => {
  const fixture = await createActiveFixture('control-read-initial');
  const inspector = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const footprint = () => ({ fence: inspector.prepare('SELECT * FROM canonical_time_fence').get(),
      requests: inspector.prepare('SELECT count(*) AS n FROM control_requests').get() });
    const before = footprint();
    const run = fixture.store.getRun(fixture.runId);
    const session = await fixture.store.readControl({ protocolVersion: 1, method: 'session.get', sessionId: run.sessionId }, identity);
    assert.ok(session.method === 'session.get');
    assert.deepEqual(session, { method: 'session.get', snapshot: { schemaVersion: 1, session: fixture.store.getSession(run.sessionId) },
      items: [], highWaterItemSeq: 0, nextItemSeq: 0 });

    const result = await fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: run.id }, identity);
    assert.ok(result.method === 'run.get');
    assert.deepEqual(result.snapshot, { schemaVersion: 1, operation: 'agent', run, latestRunItemSeq: 0 });
    assert.deepEqual(result.items, []);
    assert.deepEqual(result.journal, []);
    assert.equal(result.highWaterItemSeq, 0);
    assert.equal(result.highWaterJournalSeq, 0);
    assert.equal(result.nextItemSeq, 0);
    assert.equal(result.nextJournalSeq, 0);
    assert.equal(result.checkpoints.length, 1);
    const checkpoint = result.checkpoints[0]!;
    assert.equal(checkpoint.id, run.latestCheckpointId);
    assert.equal(checkpoint.reason, 'initial');
    const cursor = canonicalJsonBytes({ schemaVersion: 1, runId: run.id, createdAt: checkpoint.createdAt, checkpointId: checkpoint.id })
      .toString('base64url');
    assert.equal(result.highWaterCheckpointCursor, cursor);
    assert.equal(result.nextCheckpointCursor, cursor);
    const caughtUp = await fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: run.id,
      afterItemSeq: 0, afterJournalSeq: 0, checkpointCursor: cursor }, identity);
    assert.ok(caughtUp.method === 'run.get');
    assert.deepEqual(caughtUp.checkpoints, []);
    assert.equal(caughtUp.nextCheckpointCursor, cursor);
    assert.equal(caughtUp.highWaterCheckpointCursor, cursor);
    const attached = await fixture.store.readControl({ protocolVersion: 1, method: 'run.attach', runId: run.id, afterEventSeq: 0 }, identity);
    assert.ok(attached.method === 'run.attach');
    // Query authority is read-only: it does not advance canonical time or allocate mutator replay rows.
    assert.deepEqual(footprint(), before);
  } finally { inspector.close(); await disposeFixture(fixture); }
});

/** Explicit retained display fixtures for the query algorithm, not execution/fork qualification. */
async function seedSessionView(store: StateStore, driver: SqliteDriver, sessionId: string, physical: SessionItem[], logical: SessionItem[],
  lineage?: { parentSessionId: string; forkedThroughItemSeq: number }): Promise<void> {
  const session = store.getSession(sessionId);
  const projection: SessionContextProjection = { schemaVersion: 1, format: 'cliq-session-context-v1', sessionId,
    contextRevision: session.contextRevision + 1, throughItemSeq: logical.length,
    segments: logical.length === 0 ? [] : [{ kind: 'excluded_control', fromItemSeq: 1, throughItemSeq: logical.length,
      sourceItemsDigest: canonicalSha256(logical.map(({ itemSeq, kind, payloadRef }) => ({ itemSeq, kind, payloadRef }))) }], projectionDigest: '' };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  const artifact = await store.artifacts.publishCanonical(projection, projection.format);
  driver.transaction(connection => {
    for (const item of physical) connection.prepare(`INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at)
      VALUES (?, ?, NULL, ?, ?, ?, ?)`).run(item.itemId, sessionId, item.itemSeq, item.kind, item.payloadRef, item.createdAt);
    connection.prepare(`UPDATE sessions SET latest_item_seq = ?, context_revision = ?, context_projection_ref = ?,
      parent_session_id = ?, forked_through_item_seq = ? WHERE id = ?`)
      .run(logical.length, projection.contextRevision, artifact.ref, lineage?.parentSessionId ?? null, lineage?.forkedThroughItemSeq ?? null, sessionId);
  });
}

test('Session pages expose the frozen logical nested-fork prefix, not later ancestor items or compactions', async () => {
  const fixture = await createActiveFixture('control-read-lineage');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const parentId = fixture.store.getRun(fixture.runId).sessionId;
    const payload = await fixture.store.artifacts.publishCanonical({ fixture: 'retained-display', secretBody: 'not-in-query-result' }, 'cliq-display-query-fixture-v1');
    const createdAt = fixture.store.getSession(parentId).createdAt;
    const item = (sessionId: string, itemSeq: number, itemId: string): SessionItem => ({ schemaVersion: 1, sessionId, itemSeq,
      itemId, kind: 'legacy_bookmark', payloadRef: payload.ref, createdAt });
    const parent = [item(parentId, 1, 'parent-1'), item(parentId, 2, 'parent-2'), item(parentId, 3, 'parent-3')];
    await seedSessionView(fixture.store, driver, parentId, parent, parent);
    const makeChild = async (label: string) => (await fixture.store.createSession({ ...identity, requestId: uuidv7(),
      admissionKey: admissionKey(label), workspacePath: fixture.workspace })).session.id;
    const childId = await makeChild('read-child');
    const child = item(childId, 3, 'child-3');
    await seedSessionView(fixture.store, driver, childId, [child], [...parent.slice(0, 2), child],
      { parentSessionId: parentId, forkedThroughItemSeq: 2 });
    const grandchildId = await makeChild('read-grandchild');
    const grandchild = item(grandchildId, 4, 'grandchild-4');
    await seedSessionView(fixture.store, driver, grandchildId, [grandchild], [...parent.slice(0, 2), child, grandchild],
      { parentSessionId: childId, forkedThroughItemSeq: 3 });
    const request = { protocolVersion: 1 as const, method: 'session.get' as const, sessionId: grandchildId, limit: 1 };
    const first = await fixture.store.readControl(request, identity);
    assert.ok(first.method === 'session.get');
    assert.deepEqual(first.items, [parent[0]]);
    assert.equal(first.highWaterItemSeq, 4);
    assert.equal(first.nextItemSeq, 1);
    const parentAppend = item(parentId, 4, 'parent-4');
    const parentCompaction = { ...item(parentId, 5, 'parent-compaction'), kind: 'legacy_compaction' as const };
    await seedSessionView(fixture.store, driver, parentId, [parentAppend, parentCompaction], [...parent, parentAppend, parentCompaction]);
    const childAppend = item(childId, 4, 'child-4');
    await seedSessionView(fixture.store, driver, childId, [childAppend], [...parent.slice(0, 2), child, childAppend],
      { parentSessionId: parentId, forkedThroughItemSeq: 2 });
    const rest = await fixture.store.readControl({ ...request, afterItemSeq: first.nextItemSeq, limit: 1000 }, identity);
    assert.ok(rest.method === 'session.get');
    assert.deepEqual(rest.items, [parent[1], child, grandchild]);
    assert.equal(rest.snapshot.session.contextRevision, first.snapshot.session.contextRevision);
    assert.equal(rest.highWaterItemSeq, 4);
    assert.equal(rest.nextItemSeq, 4);
    assert.equal(canonicalJsonBytes(rest).includes(Buffer.from('not-in-query-result')), false);
    const caughtUp = await fixture.store.readControl({ ...request, afterItemSeq: rest.nextItemSeq }, identity);
    assert.ok(caughtUp.method === 'session.get');
    assert.deepEqual(caughtUp.items, []);
    assert.equal(caughtUp.nextItemSeq, 4);
    await assert.rejects(fixture.store.readControl({ ...request, afterItemSeq: 5 }, identity), isCode('INVALID_REQUEST'));
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('Session pagination defaults to 100, accepts the 1000 upper bound, and keeps payloads as bounded references', async () => {
  const fixture = await createActiveFixture('control-read-session-pages');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const session = fixture.store.getSession(fixture.store.getRun(fixture.runId).sessionId);
    const payload = await fixture.store.artifacts.publishBytes(Buffer.alloc(1024 * 1024, 0x61), 'application/octet-stream', 'cliq-display-query-fixture-v1');
    const items: SessionItem[] = Array.from({ length: 1001 }, (_, index) => ({ schemaVersion: 1, sessionId: session.id,
      itemId: `display-${index + 1}`.padEnd(128, 'd'), itemSeq: index + 1, kind: 'legacy_bookmark', payloadRef: payload.ref, createdAt: session.createdAt }));
    await seedSessionView(fixture.store, driver, session.id, items, items);
    const request = { protocolVersion: 1 as const, method: 'session.get' as const, sessionId: session.id };
    const defaultPage = await fixture.store.readControl(request, identity);
    assert.ok(defaultPage.method === 'session.get');
    assert.deepEqual(defaultPage.items, items.slice(0, 100));
    assert.equal(defaultPage.nextItemSeq, 100);
    assert.equal(defaultPage.highWaterItemSeq, 1001);
    const largePage = await fixture.store.readControl({ ...request, afterItemSeq: defaultPage.nextItemSeq, limit: 1000 }, identity);
    assert.ok(largePage.method === 'session.get');
    assert.deepEqual(largePage.items, items.slice(100));
    assert.equal(largePage.nextItemSeq, 1001);
    assert.ok(canonicalJsonBytes(largePage.items).byteLength <= 1024 * 1024);
    const single = await fixture.store.readControl({ ...request, afterItemSeq: 1000, limit: 1 }, identity);
    assert.ok(single.method === 'session.get');
    assert.deepEqual(single.items, [items[1000]]);
    assert.ok(canonicalJsonBytes(single.items).byteLength < 1024);
    const caughtUp = await fixture.store.readControl({ ...request, afterItemSeq: 1001 }, identity);
    assert.ok(caughtUp.method === 'session.get');
    assert.deepEqual(caughtUp.items, []);
    assert.equal(caughtUp.nextItemSeq, 1001);
    // Corrupt retained metadata is not a legitimate large item and must not become a stalled empty page.
    const malformed: SessionItem = { ...items[0]!, itemId: 'x'.repeat(1024 * 1024), itemSeq: 1002 };
    await seedSessionView(fixture.store, driver, session.id, [malformed], [...items, malformed]);
    await assert.rejects(fixture.store.readControl({ ...request, afterItemSeq: 1001, limit: 1 }, identity), isCode('RECOVERY_REQUIRED'));
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('checkpoint pages sort equal timestamps by bytewise id and require an exact canonical retained Run-bound cursor', async () => {
  const fixture = await createActiveFixture('control-read-checkpoints');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const initial = (await fixture.store.readRecoveryClosure(fixture.runId)).latestCheckpoint;
    // Retained metadata fixture: no worker/fork/execution backend is claimed by these additional rows.
    const before: Checkpoint = { ...initial, id: '!checkpoint', basedOnRunRevision: fixture.runRevision, reason: 'auto' };
    const after: Checkpoint = { ...initial, id: '~checkpoint', basedOnRunRevision: fixture.runRevision, reason: 'auto' };
    for (const checkpoint of [after, before]) driver.prepare(`INSERT INTO checkpoints
      (id, schema_version, run_id, based_on_run_revision, run_item_seq, context_manifest_ref, journal_seq, workspace_state_ref, created_at, reason)
      VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(checkpoint.id, checkpoint.runId, checkpoint.basedOnRunRevision, checkpoint.runItemSeq, checkpoint.contextManifestRef,
        checkpoint.journalSeq, checkpoint.workspaceStateRef, checkpoint.createdAt, checkpoint.reason);
    const encode = (value: unknown) => canonicalJsonBytes(value).toString('base64url');
    const core = { schemaVersion: 1, runId: fixture.runId, createdAt: initial.createdAt, checkpointId: initial.id };
    const beforeCursor = encode({ ...core, checkpointId: before.id });
    const initialCursor = encode(core);
    const afterCursor = encode({ ...core, checkpointId: after.id });
    const request = { protocolVersion: 1 as const, method: 'run.get' as const, runId: fixture.runId, checkpointLimit: 1 };
    const first = await fixture.store.readControl(request, identity);
    assert.ok(first.method === 'run.get');
    assert.deepEqual(first.checkpoints, [before]);
    assert.equal(first.nextCheckpointCursor, beforeCursor);
    assert.equal(first.highWaterCheckpointCursor, afterCursor);
    const second = await fixture.store.readControl({ ...request, checkpointCursor: first.nextCheckpointCursor }, identity);
    assert.ok(second.method === 'run.get');
    assert.deepEqual(second.checkpoints, [initial]);
    assert.equal(second.nextCheckpointCursor, initialCursor);
    const third = await fixture.store.readControl({ ...request, checkpointCursor: second.nextCheckpointCursor }, identity);
    assert.ok(third.method === 'run.get');
    assert.deepEqual(third.checkpoints, [after]);
    assert.equal(third.nextCheckpointCursor, afterCursor);
    const all = await fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: fixture.runId }, identity);
    assert.ok(all.method === 'run.get');
    assert.deepEqual(all.checkpoints, [before, initial, after]);
    const end = await fixture.store.readControl({ ...request, checkpointCursor: afterCursor }, identity);
    assert.ok(end.method === 'run.get');
    assert.deepEqual(end.checkpoints, []);
    assert.equal(end.nextCheckpointCursor, afterCursor);
    assert.equal(end.highWaterCheckpointCursor, afterCursor);
    const badCursors: unknown[] = [null, 0, '', '!', afterCursor + '=', 'x'.repeat(1025),
      Buffer.from(JSON.stringify(core)).toString('base64url'), // Same object, non-JCS key order.
      Buffer.from(`{"schemaVersion":1,"runId":"${fixture.runId}","createdAt":"${initial.createdAt}","checkpointId":"${initial.id}","checkpointId":"${initial.id}"}`).toString('base64url'),
      Buffer.from([0xff, 0xfe]).toString('base64url'),
      encode({ ...core, unknown: true }), encode({ ...core, schemaVersion: 2 }), encode({ ...core, runId: 'other-run' }),
      encode({ ...core, checkpointId: 'missing-checkpoint' }), encode({ ...core, createdAt: addCanonicalDuration(initial.createdAt, 1) }),
      encode({ ...core, createdAt: initial.createdAt.replace(/\.\d{3}Z/u, 'Z') }),
      encode({ ...core, createdAt: '2026-10-06T00:00:00+00:00' }), encode({ ...core, checkpointId: 'e\u0301' })];
    for (const checkpointCursor of badCursors) await assert.rejects(fixture.store.readControl(
      { ...request, checkpointCursor } as Parameters<StateStore['readControl']>[0], identity), isCode('INVALID_REQUEST'));
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('checkpoint bounds reject independently malformed first-page and high-water keys without changing their ordering', async () => {
  // Each corrupt row gets its own database, so a first-page failure cannot mask
  // a malformed maximum being omitted from the captured high-water.
  for (const field of ['id', 'createdAt'] as const) for (const prefix of ['!', '~~']) {
    const fixture = await createActiveFixture(`control-read-checkpoint-bound-${field}-${prefix.length}`);
    const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const identity = await publishInProcessChannel(fixture.store);
      const initial = (await fixture.store.readRecoveryClosure(fixture.runId)).latestCheckpoint;
      const malformed = { ...initial, id: 'malformed-checkpoint', [field]: prefix + 'x'.repeat(1_048_576) };
      // SQL must bound text before materializing it, but sorting must still use
      // the original keys, not the NULL sentinel from the guarded projection.
      driver.prepare(`INSERT INTO checkpoints
        (id, schema_version, run_id, based_on_run_revision, run_item_seq, context_manifest_ref, journal_seq, workspace_state_ref, created_at, reason)
        VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(malformed.id, initial.runId, initial.basedOnRunRevision, initial.runItemSeq,
          initial.contextManifestRef, initial.journalSeq, initial.workspaceStateRef, malformed.createdAt, initial.reason);
      await assert.rejects(fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: fixture.runId,
        checkpointLimit: 1000 }, identity), isCode('RECOVERY_REQUIRED'));
    } finally { driver.close(); await disposeFixture(fixture); }
  }
});

async function assertMetadataCap(exact: boolean): Promise<void> {
  const fixture = await createActiveFixture(`control-read-byte-${exact ? 'exact' : 'priority'}`);
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const run = fixture.store.getRun(fixture.runId);
    const payload = await fixture.store.artifacts.publishCanonical({ fixture: 'metadata-cap', body: 'not-embedded' }, 'cliq-query-metadata-fixture-v1');
    const items: RunItemReferenceV1[] = Array.from({ length: 1000 }, (_, index) => ({ schemaVersion: 1,
      itemId: `item-${index + 1}`.padEnd(128, 'i'), itemSeq: index + 1, payloadRef: payload.ref, payloadDigest: payload.ref, createdAt: run.createdAt }));
    // Closed-decodable retained metadata only: this golden fixture does not claim real dispatch,
    // settlement or sandbox qualification. Real reducer-generated Journal/reopen is tested separately.
    const journalEntry = (seq: number, target?: string): InvocationJournalEntry => {
      const op = Math.floor((seq - 1) / 3) + 1;
      // Same target within each three-phase attempt; all ids remain within 128 UTF-8 bytes.
      const padding = exact ? (op <= 2 ? 127 : op === 196 ? 102 : 0) : (op === 1 ? 100 : op === 2 ? 66 : 0);
      const phase = (['prepared', 'dispatch_claimed', 'completed'] as const)[(seq - 1) % 3]!;
      const entry: InvocationJournalEntry = { seq, runId: run.id, opId: `op-${op}`.padEnd(128, 'o'), opKind: 'tool',
        attempt: 0, leaseEpoch: 1, phase, target: target ?? 't' + 'p'.repeat(padding), requestRef: payload.ref,
        replayClass: 'retry', idempotencyKey: 'i'.repeat(128), grantRef: payload.ref,
        budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, timestamp: run.createdAt };
      if (phase !== 'prepared') Object.assign(entry, { sandboxLaunchSpecRef: payload.ref, dispatchId: 'd'.repeat(128),
        supervisorInstanceId: 's'.repeat(128), stateOwnerEpoch: 1, brokerFenceTokenDigest: payload.ref });
      if (phase === 'completed') Object.assign(entry, { resultRef: payload.ref, receiptRef: payload.ref, budgetSettlementRef: payload.ref });
      return entry;
    };
    const journal = Array.from({ length: 588 }, (_, index) => journalEntry(index + 1));
    const insertJournal = (connection: SqliteConnection, entry: InvocationJournalEntry) =>
      connection.prepare(`INSERT INTO run_journal (run_id, seq, op_id, op_kind, attempt, phase, entry_json) VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .run(run.id, entry.seq, entry.opId, entry.opKind, entry.attempt, entry.phase, canonicalJsonBytes(entry).toString('utf8'));
    driver.transaction(connection => {
      for (const item of items) connection.prepare(`INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at)
        VALUES (?, NULL, ?, ?, 'model_turn', ?, ?)`).run(item.itemId, run.id, item.itemSeq, item.payloadRef, item.createdAt);
      for (const entry of journal) insertJournal(connection, entry);
    });
    const request = { protocolVersion: 1 as const, method: 'run.get' as const, runId: run.id, itemLimit: 1000, journalLimit: 1000, checkpointLimit: 1000 };
    const defaults = await fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: run.id }, identity);
    assert.ok(defaults.method === 'run.get');
    assert.equal(defaults.items.length, 100);
    assert.equal(defaults.journal.length, 100);
    assert.equal(defaults.nextItemSeq, 100);
    assert.equal(defaults.nextJournalSeq, 100);
    assert.equal(defaults.checkpoints.length, 1);
    const capped = await fixture.store.readControl(request, identity);
    const count = 587;
    assert.ok(capped.method === 'run.get');
    assert.equal(capped.journal.length, count);
    assert.deepEqual(capped.items, items);
    assert.deepEqual(capped.journal, journal.slice(0, count));
    assert.deepEqual(capped.checkpoints, []);
    assert.equal(capped.nextItemSeq, 1000);
    assert.equal(capped.highWaterItemSeq, 1000);
    assert.equal(capped.nextJournalSeq, count);
    assert.equal(capped.highWaterJournalSeq, 588);
    assert.equal(capped.nextCheckpointCursor, undefined);
    const arrays = { items: capped.items, journal: capped.journal, checkpoints: capped.checkpoints };
    assert.equal(canonicalJsonBytes(arrays).byteLength, exact ? 1_048_576 : 1_048_108);
    assert.ok(canonicalJsonBytes({ ...arrays, journal: journal.slice(0, count + 1) }).byteLength > 1_048_576);
    const checkpoint = await fixture.store.readControl({ ...request, afterItemSeq: 1000, afterJournalSeq: 588 }, identity);
    assert.ok(checkpoint.method === 'run.get');
    assert.equal(checkpoint.checkpoints.length, 1);
    // The checkpoint would fit, but may not leapfrog the earlier oversized Journal candidate.
    if (!exact) assert.ok(canonicalJsonBytes({ ...arrays, checkpoints: checkpoint.checkpoints }).byteLength <= 1_048_576);
    const rest = await fixture.store.readControl({ ...request, afterItemSeq: capped.nextItemSeq, afterJournalSeq: capped.nextJournalSeq }, identity);
    assert.ok(rest.method === 'run.get');
    assert.deepEqual(rest.items, []);
    assert.deepEqual(rest.journal, journal.slice(count));
    assert.deepEqual(rest.checkpoints, checkpoint.checkpoints);
    assert.equal(rest.nextItemSeq, 1000);
    assert.equal(rest.nextJournalSeq, 588);
    assert.equal(rest.nextCheckpointCursor, rest.highWaterCheckpointCursor);
    const end = await fixture.store.readControl({ ...request, afterItemSeq: rest.nextItemSeq, afterJournalSeq: rest.nextJournalSeq,
      checkpointCursor: rest.nextCheckpointCursor }, identity);
    assert.ok(end.method === 'run.get');
    assert.deepEqual([end.items, end.journal, end.checkpoints], [[], [], []]);
    assert.equal(end.nextItemSeq, 1000);
    assert.equal(end.nextJournalSeq, 588);
    // Malformed retained metadata cannot force an unbounded response or a forever-empty middle page.
    insertJournal(driver, journalEntry(589, 'x'.repeat(1_048_576)));
    await assert.rejects(fixture.store.readControl({ ...request, afterItemSeq: 1000, afterJournalSeq: 588 }, identity), isCode('RECOVERY_REQUIRED'));
  } finally { driver.close(); await disposeFixture(fixture); }
}

test('run.get caps exact JCS metadata bytes inclusively and stops all streams at the first non-fitting candidate', async () => {
  await assertMetadataCap(false);
  await assertMetadataCap(true);
});

test('terminal event retention accepts earliest minus one and expiry carries the same authoritative snapshot and bounds', async () => {
  // Existing signed/offline worker fixture proves SQLite reducers, not actual OS containment or provider I/O.
  const fixture = await createAgentFixture('control-read-retention', undefined, { mode: 'plan' });
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const stopped = await fixture.agent.cancelRun({ ...identity, requestId: uuidv7(), expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    const proof = await quiescedToolCheckpoint(fixture, stopped.checkpointId);
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: stopped.run.revision, checkpoint: proof.checkpoint });
    const request = { protocolVersion: 1 as const, method: 'run.attach' as const, runId: fixture.runId, afterEventSeq: 0 };
    const before = await fixture.store.readControl(request, identity);
    assert.ok(before.method === 'run.attach');
    const anchor = before.events.at(-1)!;
    assert.ok(anchor.kind === 'state_changed');
    assert.equal(anchor.status, 'cancelled');
    assert.equal(anchor.nextStep, null);
    assert.equal(anchor.terminalReason, 'cancelled_by_user');
    assert.ok(anchor.eventSeq > 1);
    // Display-retention fixture represents the post-window GC state; the authoritative Run is unchanged.
    driver.prepare('DELETE FROM run_events WHERE run_id = ? AND event_seq < ?').run(fixture.runId, anchor.eventSeq);
    const retained = await fixture.store.readControl({ ...request, afterEventSeq: anchor.eventSeq - 1 }, identity);
    assert.ok(retained.method === 'run.attach');
    assert.deepEqual(retained.events, [anchor]);
    assert.equal(retained.earliestRetainedEventSeq, anchor.eventSeq);
    assert.equal(retained.latestRetainedEventSeq, anchor.eventSeq);
    assert.equal(retained.highWaterEventSeq, anchor.eventSeq);
    assert.equal(retained.nextEventSeq, anchor.eventSeq);
    assert.deepEqual(retained.snapshot.run, terminal.run);
    await assert.rejects(fixture.store.readControl({ ...request, afterEventSeq: anchor.eventSeq - 2 }, identity), error => {
      assert.ok(error instanceof EventCursorExpiredError);
      assert.equal(error.code, 'EVENT_CURSOR_EXPIRED');
      assert.equal(error.retryable, false);
      assert.equal(error.earliestEventSeq, anchor.eventSeq);
      assert.equal(error.latestEventSeq, anchor.eventSeq);
      assert.deepEqual(error.snapshot, retained.snapshot);
      return true;
    });
    const caughtUp = await fixture.store.readControl({ ...request, afterEventSeq: anchor.eventSeq }, identity);
    assert.ok(caughtUp.method === 'run.attach');
    assert.deepEqual(caughtUp.events, []);
    assert.equal(caughtUp.nextEventSeq, anchor.eventSeq);
    await assert.rejects(fixture.store.readControl({ ...request, afterEventSeq: anchor.eventSeq + 1 }, identity), isCode('INVALID_REQUEST'));
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('attach refuses a missing event inside its retained interval instead of advancing a reconnect cursor past it', async () => {
  const fixture = await createActiveFixture('control-read-event-gap');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const artifact = await fixture.store.artifacts.publishCanonical({ fixture: 'retained-event-gap' }, 'cliq-tool-request-v1');
    await fixture.store.prepareInvocation({ runId: fixture.runId, expectedRunRevision: fixture.runRevision,
      leaseEpoch: fixture.leaseEpoch, opId: 'retained-event-gap', opKind: 'tool', target: 'fixture.read', requestRef: artifact.ref,
      replayClass: 'retry', idempotencyKey: 'retained-event-gap-0',
      reservation: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 } });
    const request = { protocolVersion: 1 as const, method: 'run.attach' as const, runId: fixture.runId, afterEventSeq: 0 };
    const intact = await fixture.store.readControl(request, identity);
    assert.ok(intact.method === 'run.attach');
    assert.deepEqual(intact.events.map(event => event.eventSeq), [1, 2, 3]);
    const authoritative = fixture.store.getRun(fixture.runId);
    // Corruption inside the retained range is not legal prefix retention. Bounds stay 1..3.
    driver.prepare('DELETE FROM run_events WHERE run_id = ? AND event_seq = 2').run(fixture.runId);
    await assert.rejects(fixture.store.readControl(request, identity), isCode('RECOVERY_REQUIRED'));
    const firstPage = await fixture.store.readControl({ ...request, limit: 1 }, identity);
    assert.ok(firstPage.method === 'run.attach');
    assert.deepEqual(firstPage.events.map(event => event.eventSeq), [1]);
    assert.equal(firstPage.earliestRetainedEventSeq, 1);
    assert.equal(firstPage.highWaterEventSeq, 3);
    assert.equal(firstPage.nextEventSeq, 1);
    await assert.rejects(fixture.store.readControl({ ...request, afterEventSeq: firstPage.nextEventSeq, limit: 1 }, identity),
      isCode('RECOVERY_REQUIRED'));
    assert.deepEqual(fixture.store.getRun(fixture.runId), authoritative, 'display corruption cannot rewrite authoritative Run state');
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('retained event metadata rejects coercible arrays and malformed scalar bounds instead of echoing them', async () => {
  const fixture = await createActiveFixture('control-read-bad-events');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const row = driver.prepare('SELECT event_seq, payload_json FROM run_events WHERE run_id = ? ORDER BY event_seq LIMIT 1')
      .get<{ event_seq: bigint; payload_json: string }>(fixture.runId)!;
    const state = JSON.parse(row.payload_json) as Record<string, unknown>;
    const progress = { schemaVersion: 1, kind: 'progress', runId: fixture.runId, eventSeq: Number(row.event_seq),
      observedRunRevision: fixture.runRevision, phase: 'agent', occurredAt: state.occurredAt };
    const malformed = [
      { ...state, status: ['queued'] }, { ...state, nextStep: ['agent'] },
      { ...state, frontierRef: [state.frontierRef] }, { ...state, latestRunItemSeq: -1 },
      { ...progress, phase: ['agent'] }, { ...progress, messageRef: ['a'.repeat(64)] },
      { ...progress, completedUnits: 0.5 }, { ...progress, totalUnits: Number.MAX_SAFE_INTEGER + 1 }
    ];
    const request = { protocolVersion: 1 as const, method: 'run.attach' as const, runId: fixture.runId, afterEventSeq: 0 };
    for (const event of malformed) {
      // Display-row corruption fixtures never change authoritative Run state or native process identity.
      driver.prepare('UPDATE run_events SET payload_json = ? WHERE run_id = ? AND event_seq = ?')
        .run(JSON.stringify(event), fixture.runId, row.event_seq);
      await assert.rejects(fixture.store.readControl(request, identity), isCode('RECOVERY_REQUIRED'));
    }
    driver.prepare('UPDATE run_events SET payload_json = ? WHERE run_id = ? AND event_seq = ?')
      .run(row.payload_json, fixture.runId, row.event_seq);
    const restored = await fixture.store.readControl(request, identity);
    assert.ok(restored.method === 'run.attach');
    assert.deepEqual(canonicalJsonBytes(restored.events[0]), canonicalJsonBytes(state));
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('control queries reject future cursors, malformed bounds and identifiers, and every mutation-only field', async () => {
  const fixture = await createActiveFixture('control-read-validation');
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const sessionId = fixture.store.getRun(fixture.runId).sessionId;
    const valid = [
      { protocolVersion: 1, method: 'session.get', sessionId },
      { protocolVersion: 1, method: 'run.get', runId: fixture.runId },
      { protocolVersion: 1, method: 'run.attach', runId: fixture.runId, afterEventSeq: 0 }
    ];
    const reject = (request: unknown) => assert.rejects(
      fixture.store.readControl(request as Parameters<StateStore['readControl']>[0], identity), isCode('INVALID_REQUEST')
    );
    for (const request of valid) {
      for (const field of ['requestId', 'requestDigest', 'admissionKey', 'principalId', 'channelIdentityRef', 'unexpected']) {
        await reject({ ...request, [field]: 'not-a-query-field' });
      }
      await reject({ ...request, protocolVersion: 2 });
      const idField = request.method === 'session.get' ? 'sessionId' : 'runId';
      for (const id of ['', 'x'.repeat(129), 'e\u0301', 'x\0y', '\ud800', 1, null]) await reject({ ...request, [idField]: id });
    }
    for (const value of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, '1', null]) {
      await reject({ ...valid[0], afterItemSeq: value });
      await reject({ ...valid[1], afterItemSeq: value });
      await reject({ ...valid[1], afterJournalSeq: value });
      await reject({ ...valid[2], afterEventSeq: value });
    }
    for (const limit of [0, -1, 1.5, 1001, Number.MAX_SAFE_INTEGER + 1, '1', null]) {
      await reject({ ...valid[0], limit });
      await reject({ ...valid[1], itemLimit: limit });
      await reject({ ...valid[1], journalLimit: limit });
      await reject({ ...valid[1], checkpointLimit: limit });
      await reject({ ...valid[2], limit });
    }
    await reject({ ...valid[0], afterItemSeq: 1 });
    await reject({ ...valid[1], afterItemSeq: 1 });
    await reject({ ...valid[1], afterJournalSeq: 1 });
    const attached = await fixture.store.readControl(valid[2] as Parameters<StateStore['readControl']>[0], identity);
    assert.ok(attached.method === 'run.attach');
    await reject({ ...valid[2], afterEventSeq: attached.highWaterEventSeq + 1 });
    await reject({ protocolVersion: 1, method: 'run.attach', runId: fixture.runId });
    await reject({ protocolVersion: 1, method: 'run.list' });
    await reject(null);
    await assert.rejects(fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: 'missing' }, identity), isCode('NOT_FOUND'));
    await assert.rejects(fixture.store.readControl({ protocolVersion: 1, method: 'session.get', sessionId: 'missing' }, identity), isCode('NOT_FOUND'));
  } finally { await disposeFixture(fixture); }
});

test('a later attach page sees a committed reducer transition, while the earlier snapshot and cut remain unchanged', async () => {
  const fixture = await createActiveFixture('control-read-events');
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const request = { protocolVersion: 1 as const, method: 'run.attach' as const, runId: fixture.runId, afterEventSeq: 0, limit: 1 };
    const first = await fixture.store.readControl(request, identity);
    assert.ok(first.method === 'run.attach');
    assert.equal(first.events.length, 1);
    assert.equal(first.events[0]!.eventSeq, 1);
    assert.equal(first.nextEventSeq, 1);
    assert.equal(first.earliestRetainedEventSeq, 1);
    assert.ok(first.nextEventSeq < first.highWaterEventSeq);
    const beforeBytes = canonicalJsonBytes(first);
    const artifact = await fixture.store.artifacts.publishCanonical({ fixture: 'control-read-invocation' }, 'cliq-tool-request-v1');
    const prepared = await fixture.store.prepareInvocation({ runId: fixture.runId, expectedRunRevision: fixture.runRevision,
      leaseEpoch: fixture.leaseEpoch, opId: 'control-read-op', opKind: 'tool', target: 'fixture.read', requestRef: artifact.ref,
      replayClass: 'retry', idempotencyKey: 'control-read-op-0',
      reservation: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 } });
    const second = await fixture.store.readControl({ ...request, afterEventSeq: first.nextEventSeq, limit: 100 }, identity);
    assert.ok(second.method === 'run.attach');
    assert.equal(second.highWaterEventSeq, first.highWaterEventSeq + 1);
    assert.equal(second.latestRetainedEventSeq, second.highWaterEventSeq);
    assert.equal(second.snapshot.run.revision, prepared.run.revision);
    assert.deepEqual(second.events.map(event => event.eventSeq),
      Array.from({ length: second.highWaterEventSeq - 1 }, (_, index) => index + 2));
    const transition = second.events.at(-1)!;
    assert.ok(transition.kind === 'state_changed');
    assert.equal(transition.runRevision, prepared.run.revision);
    assert.equal(second.nextEventSeq, second.highWaterEventSeq);
    assert.deepEqual(canonicalJsonBytes(first), beforeBytes);
    const caughtUp = await fixture.store.readControl({ ...request, afterEventSeq: second.nextEventSeq }, identity);
    assert.ok(caughtUp.method === 'run.attach');
    assert.deepEqual(caughtUp.events, []);
    assert.equal(caughtUp.nextEventSeq, second.nextEventSeq);
  } finally { await disposeFixture(fixture); }
});

test('run journal cursors and checkpoint cursors survive owner reopen with a fresh authenticated channel', async () => {
  const fixture = await createActiveFixture('control-read-reopen');
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const artifact = await fixture.store.artifacts.publishCanonical({ fixture: 'reopen-request' }, 'cliq-tool-request-v1');
    const prepared = await fixture.store.prepareInvocation({ runId: fixture.runId, expectedRunRevision: fixture.runRevision,
      leaseEpoch: fixture.leaseEpoch, opId: 'reopen-op', opKind: 'tool', target: 'fixture.read', requestRef: artifact.ref,
      replayClass: 'retry', idempotencyKey: 'reopen-op-0',
      reservation: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 } });
    const first = await fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: fixture.runId, journalLimit: 1 }, identity);
    assert.ok(first.method === 'run.get');
    assert.deepEqual(first.journal, [prepared.entry]);
    assert.equal(first.highWaterJournalSeq, 1);
    assert.equal(first.nextJournalSeq, 1);
    const errorArtifact = await fixture.store.artifacts.publishCanonical({ fixture: 'not-dispatched' }, 'cliq-tool-error-v1');
    const failed = await fixture.store.failInvocationBeforeDispatch({ runId: fixture.runId, opId: prepared.entry.opId, attempt: 0,
      expectedRunRevision: prepared.run.revision, errorRef: errorArtifact.ref });
    assert.equal(first.snapshot.run.revision, prepared.run.revision);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot);
    const fresh = await publishInProcessChannel(fixture.store);
    assert.equal(fresh.principalId, identity.principalId);
    assert.notEqual(fresh.channelIdentityRef, identity.channelIdentityRef);
    const request = { protocolVersion: 1 as const, method: 'run.get' as const, runId: fixture.runId,
      afterJournalSeq: first.nextJournalSeq, checkpointCursor: first.nextCheckpointCursor };
    const next = await fixture.store.readControl(request, fresh);
    assert.ok(next.method === 'run.get');
    assert.deepEqual(next.journal, [failed.entry]);
    assert.equal(next.snapshot.run.revision, failed.run.revision);
    assert.equal(next.highWaterJournalSeq, 2);
    assert.equal(next.nextJournalSeq, 2);
    assert.deepEqual(next.checkpoints, []);
    assert.equal(next.nextCheckpointCursor, first.nextCheckpointCursor);
    assert.equal(next.highWaterCheckpointCursor, first.highWaterCheckpointCursor);
    assert.deepEqual(await fixture.store.readControl(request, fresh), next);
    // In-process provenance identifies this same host process/root, not the retired owner epoch.
    assert.deepEqual(await fixture.store.readControl(request, identity), next);
  } finally { await disposeFixture(fixture); }
});
