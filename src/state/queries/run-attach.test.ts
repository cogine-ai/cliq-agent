import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_DATABASE_FILENAME } from '../../config.js';
import { sampleCanonicalNow } from '../canonical-time.js';
import { KernelStorageError } from '../errors.js';
import { openSqliteDriver } from '../sqlite-driver.js';
import { createActiveFixture } from '../testing/fixtures.js';
import { EventCursorExpiredError } from './run-attach.js';

test('run.attach uses a stable event high-water and returns a snapshot for expired cursors', async () => {
  const fixture = await createActiveFixture('attach-query');
  const principalId = 'cliq-m2-principal';
  const { store, runId, stateRoot, workspace } = fixture;
  try {
    const first = await store.attachRun({ principalId, runId, afterEventSeq: 0, limit: 1 });
    assert.equal(first.method, 'run.attach');
    assert.equal(first.earliestRetainedEventSeq, 1);
    assert.equal(first.events.length, 1);
    assert.equal(first.events[0]!.eventSeq, 1);
    assert.equal(first.nextEventSeq, 1);
    assert.ok(first.highWaterEventSeq >= 1);
    const initialHighWater = first.highWaterEventSeq;
    const writer = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const nextSeq = initialHighWater + 1;
      const event = {
        schemaVersion: 1, kind: 'progress', runId, eventSeq: nextSeq,
        observedRunRevision: store.getRun(runId).revision,
        phase: 'agent', completedUnits: 1, totalUnits: 2,
        occurredAt: sampleCanonicalNow()
      };
      writer.prepare('INSERT INTO run_events (run_id, event_seq, payload_json, occurred_at) VALUES (?, ?, ?, ?)')
        .run(runId, nextSeq, JSON.stringify(event), event.occurredAt);
      assert.equal(first.highWaterEventSeq, initialHighWater);
      const continuation = await store.attachRun({
        principalId, runId, afterEventSeq: first.nextEventSeq, limit: 100
      });
      assert.equal(continuation.highWaterEventSeq, nextSeq);
      assert.equal(continuation.nextEventSeq, nextSeq);
      assert.equal(continuation.events.at(-1)?.kind, 'progress');
      const empty = await store.attachRun({ principalId, runId, afterEventSeq: nextSeq });
      assert.deepEqual(empty.events, []);
      assert.equal(empty.nextEventSeq, nextSeq);
      await assert.rejects(store.attachRun({ principalId, runId, afterEventSeq: nextSeq + 1 }),
        (error) => error instanceof KernelStorageError && error.code === 'INVALID_REQUEST');
      await assert.rejects(store.attachRun({ principalId: 'foreign-principal', runId, afterEventSeq: 0 }),
        (error) => error instanceof KernelStorageError && error.code === 'NOT_FOUND');

      // Simulate a retention cut. The query must give the caller a snapshot to
      // reset from, even though this fixture does not run the pruning policy.
      writer.prepare('DELETE FROM run_events WHERE run_id = ? AND event_seq = 1').run(runId);
      await assert.rejects(store.attachRun({ principalId, runId, afterEventSeq: 0 }),
        (error) => error instanceof EventCursorExpiredError &&
          error.earliestEventSeq === 2 && error.latestEventSeq === nextSeq &&
          error.snapshot.run.id === runId);
      const retained = await store.attachRun({ principalId, runId, afterEventSeq: 1 });
      assert.equal(retained.events[0]?.eventSeq, 2);
      const invalid = {
        schemaVersion: 1, kind: 'progress', runId, eventSeq: nextSeq + 1,
        observedRunRevision: store.getRun(runId).revision,
        phase: 'unrecognized', occurredAt: sampleCanonicalNow()
      };
      writer.prepare('INSERT INTO run_events (run_id, event_seq, payload_json, occurred_at) VALUES (?, ?, ?, ?)')
        .run(runId, invalid.eventSeq, JSON.stringify(invalid), invalid.occurredAt);
      await assert.rejects(store.attachRun({ principalId, runId, afterEventSeq: nextSeq }),
        (error) => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED');
    } finally {
      writer.close();
    }
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});
