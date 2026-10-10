import assert from 'node:assert/strict';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { ProcessContainmentDeathEvidenceV1 } from '../kernel/execution.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

async function sealedHistory(t: TestContext, label: string) {
  let clock = Date.now();
  t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture(label, undefined, { mode: 'accept-edits' });
  try {
    const proof = await quiescedToolCheckpoint(fixture, `${label}-checkpoint`);
    const initial = await fixture.store.artifacts.readCanonical<ProcessContainmentDeathEvidenceV1>(proof.checkpoint.retirementEvidenceRef);
    clock += 100;
    const snapshot = { ...proof.snapshot, observedAt: new Date(clock).toISOString() };
    snapshot.evidenceDigest = digestOmitting(snapshot, 'evidenceDigest');
    const retainedSnapshot = await fixture.store.artifacts.publishCanonical(snapshot, snapshot.format);
    clock += 5_900;
    // This is an offline canonical graph over real SQLite/CAS, not native death evidence.
    const final = { ...initial, observedAt: new Date(clock).toISOString() };
    final.evidenceDigest = digestOmitting(final, 'evidenceDigest');
    const retirement = await fixture.store.artifacts.publishCanonical(final, 'cliq-process-containment-death-evidence-v1');
    clock += 125;
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const generation = before.workspaceGenerations.find(row => row.generationRef === fixture.generationRef)!;
    if (generation.phase !== 'checkpointing') assert.fail('fixture must be checkpointing');
    const sealed = await fixture.store.sealWorkerGeneration({ launchId: fixture.launchId,
      expectedRunRevision: before.run.revision, expectedGenerationRowVersion: generation.rowVersion,
      quiesceId: generation.quiesceId, checkpointId: snapshot.checkpointId,
      contextManifestRef: before.latestCheckpoint.contextManifestRef, workspaceStateRef: proof.workspaceStateRef,
      snapshotEvidenceRef: retainedSnapshot.ref, snapshotEvidenceDigest: snapshot.evidenceDigest,
      retirementEvidenceRef: retirement.ref, checkpointReason: 'auto' });
    return { fixture, initial, final, snapshot, sealed, advanceClock: (ms: number) => { clock += ms; } };
  } catch (error) { await disposeFixture(fixture); throw error; }
}

test('queued typed Run recovery rejects a substituted final retirement after a successful seal', async t => {
  const { fixture, final, sealed } = await sealedHistory(t, 'seal-history-final');
  const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    assert.equal((await fixture.store.readRecoveryClosure(fixture.runId)).run.status, 'queued');
    const substituted = { ...final, launchNonceDigest: canonicalSha256('another-worker-launch') };
    substituted.evidenceDigest = digestOmitting(substituted, 'evidenceDigest');
    const forged = await fixture.store.artifacts.publishCanonical(substituted, 'cliq-process-containment-death-evidence-v1');
    const guard = writer.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'worker_launches' AND sql LIKE '%BEFORE UPDATE%'")
      .get<{ name: string; sql: string }>()!;
    // Simulate a damaged image beyond its SQL immutability guard; inspect only through StateStore.
    writer.exec(`DROP TRIGGER ${guard.name}`);
    try {
      writer.prepare('UPDATE worker_launches SET row_json = ? WHERE launch_id = ?')
        .run(JSON.stringify({ ...sealed.launch, retirementEvidenceRef: forged.ref }), fixture.launchId);
      await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
      await fixture.store.close();
      fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
      await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
    } finally {
      writer.prepare('UPDATE worker_launches SET row_json = ? WHERE launch_id = ?').run(JSON.stringify(sealed.launch), fixture.launchId);
      writer.exec(guard.sql);
    }
  } finally { writer.close(); await disposeFixture(fixture); t.mock.restoreAll(); }
});

test('historical seals remain valid after the observing owner retires and live freshness expires', async t => {
  const { fixture, advanceClock } = await sealedHistory(t, 'seal-history-owner');
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    advanceClock(6_000);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    assert.equal(fixture.store.ownerEpoch, 2);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); t.mock.restoreAll(); }
});

test('public recovery rejects rehashed D0 and D1 evidence that no longer closes its sealed checkpoint', async t => {
  const { fixture, initial, final, snapshot, sealed } = await sealedHistory(t, 'seal-history-closure');
  const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  const guards = ['worker_launches', 'workspace_generations'].map(table =>
    writer.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ? AND sql LIKE '%BEFORE UPDATE%'")
      .get<{ name: string; sql: string }>(table)!);
  try {
    // The fault seam deliberately bypasses storage's write guards; every
    // behavioral assertion still crosses the public recovery interface.
    for (const guard of guards) writer.exec(`DROP TRIGGER ${guard.name}`);
    for (const [name, observedAt] of [
      ['stale final death', new Date(Date.parse(sealed.checkpoint.createdAt) - 5_001).toISOString()],
      ['future final death', new Date(Date.parse(sealed.checkpoint.createdAt) + 1).toISOString()],
      ['final death before snapshot', new Date(Date.parse(snapshot.observedAt) - 1).toISOString()]
    ] as const) {
      await t.test(name, async () => {
        const candidate = { ...final, observedAt };
        candidate.evidenceDigest = digestOmitting(candidate, 'evidenceDigest');
        const artifact = await fixture.store.artifacts.publishCanonical(candidate, 'cliq-process-containment-death-evidence-v1');
        writer.prepare('UPDATE worker_launches SET row_json = ? WHERE launch_id = ?')
          .run(JSON.stringify({ ...sealed.launch, retirementEvidenceRef: artifact.ref }), fixture.launchId);
        try { await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' }); }
        finally { writer.prepare('UPDATE worker_launches SET row_json = ? WHERE launch_id = ?').run(JSON.stringify(sealed.launch), fixture.launchId); }
      });
    }
    await t.test('substituted snapshot quiescence', async () => {
      const candidateDeath = { ...initial, launchNonceDigest: canonicalSha256('another-quiesced-worker') };
      candidateDeath.evidenceDigest = digestOmitting(candidateDeath, 'evidenceDigest');
      const death = await fixture.store.artifacts.publishCanonical(candidateDeath, 'cliq-process-containment-death-evidence-v1');
      const candidate = { ...snapshot, quiescenceEvidenceRef: death.ref };
      candidate.evidenceDigest = digestOmitting(candidate, 'evidenceDigest');
      const artifact = await fixture.store.artifacts.publishCanonical(candidate, snapshot.format);
      writer.prepare('UPDATE workspace_generations SET row_json = ? WHERE generation_id = ?')
        .run(JSON.stringify({ ...sealed.generation, snapshotEvidenceRef: artifact.ref, snapshotEvidenceDigest: candidate.evidenceDigest }), sealed.generation.generationId);
      try { await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' }); }
      finally { writer.prepare('UPDATE workspace_generations SET row_json = ? WHERE generation_id = ?').run(JSON.stringify(sealed.generation), sealed.generation.generationId); }
    });
    await t.test('missing snapshot quiescence', async () => {
      const { quiescenceEvidenceRef: _quiescence, ...candidate } = snapshot;
      candidate.evidenceDigest = digestOmitting(candidate, 'evidenceDigest');
      const artifact = await fixture.store.artifacts.publishCanonical(candidate, snapshot.format);
      writer.prepare('UPDATE workspace_generations SET row_json = ? WHERE generation_id = ?')
        .run(JSON.stringify({ ...sealed.generation, snapshotEvidenceRef: artifact.ref, snapshotEvidenceDigest: candidate.evidenceDigest }), sealed.generation.generationId);
      try { await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'ARTIFACT_MISMATCH', message: /quiescenceEvidenceRef/ }); }
      finally { writer.prepare('UPDATE workspace_generations SET row_json = ? WHERE generation_id = ?').run(JSON.stringify(sealed.generation), sealed.generation.generationId); }
    });
    await fixture.store.readRecoveryClosure(fixture.runId);
  } finally {
    writer.prepare('UPDATE worker_launches SET row_json = ? WHERE launch_id = ?').run(JSON.stringify(sealed.launch), fixture.launchId);
    writer.prepare('UPDATE workspace_generations SET row_json = ? WHERE generation_id = ?').run(JSON.stringify(sealed.generation), sealed.generation.generationId);
    for (const guard of guards) writer.exec(guard.sql);
    writer.close(); await disposeFixture(fixture); t.mock.restoreAll();
  }
});
