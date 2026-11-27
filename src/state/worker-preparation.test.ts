// These negative Store cuts never create a physical generation, native
// controller, delivery permission or successful publication proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import { identityHash } from '../kernel/identity.js';
import { beginWorkerPreparation } from './worker-preparation.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { createQueuedFixture, disposeFixture } from './testing/fixtures.js';

for (const mutation of ['session_context', 'session_principal', 'run_items'] as const) test(
  `worker preparation rechecks ${mutation} inside the real birth transaction`, async () => {
  const fixture = await createQueuedFixture(`preparing-${mutation}`);
  const { driver, owner } = fixture.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
  const original = driver.transaction;
  const transaction = (operation: (connection: SqliteConnection) => unknown): unknown => Reflect.apply(original, driver, [operation]);
  const acceptedChangedCut = new Error('worker preparation incorrectly accepted the changed Session cut');
  try {
    const run = fixture.store.getRun(fixture.runId);
    let originalRecoveryCut = true;
    driver.transaction = ((operation: (connection: SqliteConnection) => unknown) => {
      // Preserve readRecoveryClosure's original SQL snapshot. The fault is in
      // the subsequent real birth transaction, after the asynchronous reads.
      if (originalRecoveryCut) { originalRecoveryCut = false; return transaction(operation); }
      return transaction((connection): void => {
        if (mutation === 'session_context')
          connection.prepare('UPDATE sessions SET context_revision=context_revision+1 WHERE id=?').run(run.sessionId);
        else if (mutation === 'session_principal') {
          connection.exec('DROP TRIGGER sessions_admission_identity_immutable');
          connection.prepare('UPDATE sessions SET principal_id=? WHERE id=?').run('changed-untrusted-principal', run.sessionId);
        } else connection.prepare('INSERT INTO items(item_id,session_id,run_id,item_seq,kind,payload_ref,created_at) VALUES (?,NULL,?,1,?,?,?)')
          .run(identityHash('untrusted-preparing-item'), run.id, 'not-a-proof', 'a'.repeat(64), run.createdAt);
        operation(connection);
        // Also roll back the old implementation's incorrectly accepted logical
        // launch: this test never fabricates or leaves physical birth authority.
        throw acceptedChangedCut;
      });
    }) as SqliteDriver['transaction'];
    await assert.rejects(beginWorkerPreparation(driver, fixture.store.artifacts, owner, {
      runId: run.id, expectedRunRevision: run.revision, launchId: identityHash('preparing-session-cut'),
      spawnNonceDigest: 'a'.repeat(64), activationNonceDigest: 'b'.repeat(64), generationCreationNonceDigest: 'c'.repeat(64)
    }), { code: 'REVISION_CONFLICT' });
    assert.deepEqual(fixture.store.getRun(run.id), run);
    assert.equal(driver.prepare('SELECT count(*) AS count FROM worker_launches WHERE run_id=?').get<{ count: bigint }>(run.id)!.count, 0n);
  } finally { driver.transaction = original; await disposeFixture(fixture); }
});
