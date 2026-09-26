import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_DATABASE_FILENAME } from '../../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import { identityHash } from '../../kernel/identity.js';
import { sampleCanonicalNow } from '../canonical-time.js';
import { KernelStorageError } from '../errors.js';
import { ZERO_BUDGET } from '../rows.js';
import { openSqliteDriver } from '../sqlite-driver.js';
import { createActiveFixture } from '../testing/fixtures.js';

test('run.get captures three high-waters and round-trips exclusive checkpoint and item cursors', async () => {
  const fixture = await createActiveFixture('run-get-query');
  const { store, runId, stateRoot, workspace } = fixture;
  const principalId = 'cliq-m2-principal';
  try {
    const initial = await store.queryRun({ principalId, runId });
    assert.equal(initial.method, 'run.get');
    assert.equal(initial.snapshot.run.id, runId);
    assert.equal(initial.highWaterItemSeq, 0);
    assert.equal(initial.highWaterJournalSeq, 0);
    assert.deepEqual(initial.items, []);
    assert.deepEqual(initial.journal, []);
    assert.equal(initial.checkpoints.length, 1);
    assert.equal(initial.nextCheckpointCursor, initial.highWaterCheckpointCursor);
    const caughtUp = await store.queryRun({ principalId, runId,
      checkpointCursor: initial.nextCheckpointCursor });
    assert.deepEqual(caughtUp.checkpoints, []);
    assert.equal(caughtUp.nextCheckpointCursor, initial.nextCheckpointCursor);

    const writer = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const payload = await store.artifacts.publishCanonical({ kind: 'run-query-fixture' }, 'cliq-run-query-fixture-v1');
      const appendItem = (seq: number) => writer.prepare(
        'INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at) ' +
        'VALUES (?, NULL, ?, ?, ?, ?, ?)'
      ).run(identityHash('run-query-item', runId, seq), runId, seq, 'model_turn', payload.ref, sampleCanonicalNow());
      appendItem(1);
      appendItem(2);
      const journal = { seq: 1, runId, opId: 'query-op', opKind: 'model', attempt: 0,
        leaseEpoch: 1, phase: 'prepared', target: 'query-target',
        requestRef: canonicalSha256('query-request'), replayClass: 'manual',
        budgetDelta: ZERO_BUDGET, timestamp: sampleCanonicalNow() };
      writer.prepare('INSERT INTO run_journal (run_id, seq, op_id, op_kind, attempt, phase, entry_json) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?)').run(runId, 1, journal.opId, journal.opKind,
        journal.attempt, journal.phase, JSON.stringify(journal));

      const first = await store.queryRun({ principalId, runId, itemLimit: 1, journalLimit: 1,
        checkpointCursor: initial.nextCheckpointCursor });
      assert.equal(first.highWaterItemSeq, 2);
      assert.equal(first.highWaterJournalSeq, 1);
      assert.deepEqual(first.items.map((item) => item.itemSeq), [1]);
      assert.equal(first.nextItemSeq, 1);
      assert.deepEqual(first.journal.map((entry) => entry.seq), [1]);
      assert.equal(first.nextJournalSeq, 1);
      assert.deepEqual(first.checkpoints, []);

      appendItem(3);
      assert.equal(first.highWaterItemSeq, 2);
      const second = await store.queryRun({ principalId, runId, afterItemSeq: first.nextItemSeq,
        afterJournalSeq: first.nextJournalSeq, checkpointCursor: first.nextCheckpointCursor,
        itemLimit: 1 });
      assert.equal(second.highWaterItemSeq, 3);
      assert.deepEqual(second.items.map((item) => item.itemSeq), [2]);
      const last = await store.queryRun({ principalId, runId, afterItemSeq: second.nextItemSeq,
        afterJournalSeq: second.nextJournalSeq, checkpointCursor: second.nextCheckpointCursor });
      assert.deepEqual(last.items.map((item) => item.itemSeq), [3]);
      assert.equal(last.nextItemSeq, last.highWaterItemSeq);
    } finally {
      writer.close();
    }

    const invalid: Array<Parameters<typeof store.queryRun>[0]> = [
      { principalId, runId, afterItemSeq: 99 },
      { principalId, runId, afterJournalSeq: 99 },
      { principalId, runId, checkpointCursor: 'not-base64url!' },
      { principalId, runId, checkpointCursor: Buffer.from(canonicalJsonBytes({ schemaVersion: 1,
        runId: identityHash('other-run'), createdAt: initial.checkpoints[0]!.createdAt,
        checkpointId: initial.checkpoints[0]!.id })).toString('base64url') },
      { principalId, runId, checkpointCursor: Buffer.from(canonicalJsonBytes({ schemaVersion: 1,
        runId, createdAt: initial.checkpoints[0]!.createdAt,
        checkpointId: identityHash('nonexistent-checkpoint') })).toString('base64url') },
      { principalId, runId, afterItemSeq: null as never },
      { principalId, runId, itemLimit: 1001 }
    ];
    for (const input of invalid) {
      await assert.rejects(store.queryRun(input),
        (error) => error instanceof KernelStorageError && error.code === 'INVALID_REQUEST');
    }
    await assert.rejects(store.queryRun({ principalId: 'foreign-principal', runId }),
      (error) => error instanceof KernelStorageError && error.code === 'NOT_FOUND');
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('run.get applies the combined metadata cap in item, Journal, Checkpoint priority', async () => {
  const fixture = await createActiveFixture('run-get-cap');
  const { store, runId, stateRoot, workspace } = fixture;
  const principalId = 'cliq-m2-principal';
  try {
    const request = await store.artifacts.publishCanonical({ kind: 'query-cap-request' }, 'cliq-query-cap-request-v1');
    const writer = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      for (const seq of [1, 2]) {
        const entry = { seq, runId, opId: `large-query-${seq}`, opKind: 'model', attempt: 0,
          leaseEpoch: 1, phase: 'prepared', target: 'x'.repeat(560_000),
          requestRef: request.ref, replayClass: 'manual', budgetDelta: ZERO_BUDGET,
          timestamp: sampleCanonicalNow() };
        writer.prepare('INSERT INTO run_journal (run_id, seq, op_id, op_kind, attempt, phase, entry_json) ' +
          'VALUES (?, ?, ?, ?, ?, ?, ?)').run(runId, seq, entry.opId, entry.opKind,
          entry.attempt, entry.phase, JSON.stringify(entry));
      }
    } finally {
      writer.close();
    }
    const first = await store.queryRun({ principalId, runId });
    assert.equal(first.highWaterJournalSeq, 2);
    assert.deepEqual(first.journal.map((entry) => entry.seq), [1]);
    assert.equal(first.nextJournalSeq, 1);
    assert.deepEqual(first.checkpoints, []);
    assert.ok(canonicalJsonBytes({ items: first.items, journal: first.journal,
      checkpoints: first.checkpoints }).byteLength <= 1_048_576);
    const second = await store.queryRun({ principalId, runId, afterJournalSeq: first.nextJournalSeq });
    assert.deepEqual(second.journal.map((entry) => entry.seq), [2]);
    assert.equal(second.nextJournalSeq, second.highWaterJournalSeq);
    assert.equal(second.checkpoints.length, 1);
    assert.equal(second.nextCheckpointCursor, second.highWaterCheckpointCursor);
    const oversized = { seq: 3, runId, opId: 'oversized-query', opKind: 'model', attempt: 0,
      leaseEpoch: 1, phase: 'prepared', target: 'y'.repeat(1_050_000),
      requestRef: request.ref, replayClass: 'manual', budgetDelta: ZERO_BUDGET,
      timestamp: sampleCanonicalNow() };
    const oversizedWriter = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      oversizedWriter.prepare('INSERT INTO run_journal (run_id, seq, op_id, op_kind, attempt, phase, entry_json) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?)').run(runId, 3, oversized.opId, oversized.opKind,
        oversized.attempt, oversized.phase, JSON.stringify(oversized));
    } finally {
      oversizedWriter.close();
    }
    await assert.rejects(store.queryRun({ principalId, runId, afterJournalSeq: 2,
      checkpointCursor: second.nextCheckpointCursor }),
      (error) => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED');
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});
