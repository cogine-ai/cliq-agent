import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { KERNEL_CAS_DIRECTORY } from '../config.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';
import { postEffectObservation, quiescedToolCheckpoint } from './testing/tool-effects.js';

async function completeAfterSettlementDelay(t: TestContext, elapsedMs: number) {
  let clock = Date.now();
  t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('seal-late-settlement', undefined, { mode: 'accept-edits', tools: ['edit'] });
  try {
    await batch(fixture, [{ name: 'edit', input: { path: 'a', old_text: 'old', new_text: 'new' } }]);
    const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared);
    const proof = await postEffectObservation(fixture, await observation(fixture, claimed, { changed: true }), prepared.checkpointId);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const sample = await fs.open(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, proof.observationRef), 'r');
    const prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] };
    const writeFile = prototype.writeFile;
    await sample.close();
    let delayed = 0;
    t.mock.method(prototype, 'writeFile', async function(this: FileHandle, ...args: unknown[]) {
      await Reflect.apply(writeFile, this, args);
      if (Buffer.isBuffer(args[0]) && args[0].toString('utf8').includes('"format":"cliq-budget-settlement-v1"')) {
        const settlement = JSON.parse(args[0].toString('utf8')) as { runId: string; opId: string; settledAt: string };
        if (settlement.runId === fixture.runId && settlement.opId === prepared.entry.opId) {
          assert.equal(Date.parse(settlement.settledAt), clock, 'delay follows the actual settlement timestamp and file write');
          delayed += 1;
          clock += elapsedMs;
        }
      }
    });
    const completion = fixture.agent.completeTool({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
      expectedRunRevision: prepared.run.revision, observationRef: proof.observationRef });
    await completion.catch(() => {});
    assert.equal(delayed, 1, 'the real late publication boundary must be reached exactly once');
    if (elapsedMs < 0 || elapsedMs > 5_000) {
      await assert.rejects(completion, { code: 'RECOVERY_REQUIRED', message: /retirement proof is stale/ });
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before,
        'expired authority cannot commit a result, settlement, budget, frontier, checkpoint or generation seal');
    } else {
      const completed = await completion;
      const after = await fixture.store.readRecoveryClosure(fixture.runId);
      assert.equal(completed.entry.phase, 'completed');
      assert.equal(after.run.status, 'queued');
      assert.equal(after.run.activeWorkerLaunchId, undefined);
      assert.equal(after.run.budgetConsumed.toolCalls, 1);
      assert.equal(after.run.budgetReserved.toolCalls, 0);
      assert.equal(after.latestCheckpoint.workspaceStateRef, proof.workspaceStateRef);
      assert.notEqual(after.latestCheckpoint.id, before.latestCheckpoint.id);
      assert.equal(after.workspaceGenerations.find(row => row.generationRef === fixture.generationRef)!.phase, 'sealed');
    }
  } finally { t.mock.restoreAll(); await disposeFixture(fixture); }
}

test('tool completion rejects death evidence that expires while its already-timestamped settlement is published',
  t => completeAfterSettlementDelay(t, 5_001));

test('tool completion accepts the exact five-second retirement freshness boundary',
  t => completeAfterSettlementDelay(t, 5_000));

test('tool completion refuses a transaction clock that regressed behind its staged settlement',
  t => completeAfterSettlementDelay(t, -1));

test('a direct worker seal rejects future observations after a clock correction above the stored fence', async t => {
  const initial = Date.now();
  let clock = initial;
  t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('seal-clock-correction', undefined, { mode: 'accept-edits' });
  try {
    const sample = await fs.open(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, fixture.store.getRun(fixture.runId).specRef), 'r');
    const prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] };
    const writeFile = prototype.writeFile;
    await sample.close();
    let advanced = 0;
    const writer = t.mock.method(prototype, 'writeFile', async function(this: FileHandle, ...args: unknown[]) {
      await Reflect.apply(writeFile, this, args);
      if (Buffer.isBuffer(args[0]) && args[0].toString('utf8').includes('"format":"cliq-workspace-state-v1"')) {
        const state = JSON.parse(args[0].toString('utf8')) as { runId: string };
        if (state.runId === fixture.runId) { advanced += 1; clock += 2_000; }
      }
    });
    // The readonly/checkpointing transactions use initial; only artifact
    // observation/publication sees the later clock. No evidence is rewritten.
    const proof = await quiescedToolCheckpoint(fixture, 'seal-clock-correction-checkpoint');
    writer.mock.restore();
    assert.equal(advanced, 1);
    assert.equal(Date.parse(proof.snapshot.observedAt), initial + 2_000);
    clock = initial;
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const generation = before.workspaceGenerations.find(row => row.generationRef === fixture.generationRef)!;
    if (generation.phase !== 'checkpointing') assert.fail('fixture must be checkpointing');
    await assert.rejects(fixture.store.sealWorkerGeneration({ launchId: fixture.launchId,
      expectedRunRevision: before.run.revision, expectedGenerationRowVersion: generation.rowVersion,
      quiesceId: generation.quiesceId, checkpointId: proof.snapshot.checkpointId,
      contextManifestRef: before.latestCheckpoint.contextManifestRef, workspaceStateRef: proof.workspaceStateRef,
      snapshotEvidenceRef: proof.checkpoint.snapshotEvidenceRef, snapshotEvidenceDigest: proof.snapshot.evidenceDigest,
      retirementEvidenceRef: proof.checkpoint.retirementEvidenceRef, checkpointReason: 'auto' }),
    { code: 'RECOVERY_REQUIRED', message: /retirement proof is stale/ });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { t.mock.restoreAll(); await disposeFixture(fixture); }
});
