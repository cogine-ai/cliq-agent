import assert from 'node:assert/strict';
import { chmod, mkdtemp, realpath, rm } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_DATABASE_FILENAME } from '../../config.js';
import { identityHash } from '../../kernel/identity.js';
import { sampleCanonicalNow } from '../canonical-time.js';
import { KernelStorageError } from '../errors.js';
import { openSqliteDriver } from '../sqlite-driver.js';
import { openStateStore, publishInProcessChannel } from '../store.js';
import { admissionKey, uuidv7 } from '../testing/fixtures.js';

async function privateDirectory(prefix: string): Promise<string> {
  const directory = await mkdtemp(path.join(await realpath('/tmp'), prefix));
  await chmod(directory, 0o700);
  return directory;
}

test('session.get pages a captured high-water and enforces principal and cursor bounds', async () => {
  const stateRoot = await privateDirectory('.cliq-query-state-');
  const workspace = await privateDirectory('.cliq-query-workspace-');
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'query-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const created = await store.createSession({
      principalId,
      requestId: uuidv7(),
      admissionKey: admissionKey('query-session'),
      workspacePath: workspace,
      ...channel
    });
    const sessionId = created.session.id;
    const empty = store.querySession({ principalId, sessionId });
    assert.equal(empty.highWaterItemSeq, 0);
    assert.equal(empty.nextItemSeq, 0);
    assert.deepEqual(empty.items, []);

    const payload = await store.artifacts.publishCanonical({ kind: 'query-test' }, 'cliq-test-query-item-v1');
    const writer = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    const append = (seq: number): void => {
      const now = sampleCanonicalNow();
      writer.transaction((connection) => {
        connection.prepare(
          "INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at) " +
          "VALUES (?, ?, NULL, ?, 'legacy_record', ?, ?)"
        ).run(identityHash('query-item', sessionId, seq), sessionId, seq, payload.ref, now);
        connection.prepare('UPDATE sessions SET latest_item_seq = ?, updated_at = ? WHERE id = ?')
          .run(seq, now, sessionId);
      });
    };
    try {
      append(1);
      append(2);
      const first = store.querySession({ principalId, sessionId, limit: 1 });
      assert.equal(first.highWaterItemSeq, 2);
      assert.deepEqual(first.items.map((item) => item.itemSeq), [1]);
      assert.equal(first.nextItemSeq, 1);
      append(3);
      assert.equal(first.highWaterItemSeq, 2);
      const second = store.querySession({ principalId, sessionId, afterItemSeq: first.nextItemSeq, limit: 1 });
      assert.equal(second.highWaterItemSeq, 3);
      assert.deepEqual(second.items.map((item) => item.itemSeq), [2]);
      const tail = store.querySession({ principalId, sessionId, afterItemSeq: second.nextItemSeq });
      assert.deepEqual(tail.items.map((item) => item.itemSeq), [3]);
      assert.equal(tail.nextItemSeq, tail.highWaterItemSeq);
      assert.deepEqual(store.querySession({ principalId, sessionId, afterItemSeq: 3 }).items, []);
      assert.throws(() => store.querySession({ principalId: 'another-principal', sessionId }),
        (error) => error instanceof KernelStorageError && error.code === 'NOT_FOUND');
      assert.throws(() => store.querySession({ principalId, sessionId, afterItemSeq: 4 }),
        (error) => error instanceof KernelStorageError && error.code === 'INVALID_REQUEST');
      assert.throws(() => store.querySession({ principalId, sessionId, limit: 1001 }),
        (error) => error instanceof KernelStorageError && error.code === 'INVALID_REQUEST');

      writer.prepare('UPDATE sessions SET latest_item_seq = 4 WHERE id = ?').run(sessionId);
      assert.throws(() => store.querySession({ principalId, sessionId, afterItemSeq: 3 }),
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
