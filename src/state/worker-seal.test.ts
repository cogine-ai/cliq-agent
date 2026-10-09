import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

test('a typed worker seal cannot replace whole-containment retirement proof with arbitrary retained bytes', async () => {
  const fixture = await createAgentFixture('seal-retirement', undefined, { mode: 'accept-edits' });
  try {
    const proof = await quiescedToolCheckpoint(fixture, 'seal-retirement-checkpoint');
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const generation = before.workspaceGenerations.find(row => row.generationRef === fixture.generationRef)!;
    if (generation.phase !== 'checkpointing') assert.fail('fixture must be checkpointing');
    const forged = await fixture.store.artifacts.publishCanonical({ callerSaidDead: true }, 'cliq-process-containment-death-evidence-v1');
    await assert.rejects(fixture.store.sealWorkerGeneration({ launchId: fixture.launchId,
      expectedRunRevision: before.run.revision, expectedGenerationRowVersion: generation.rowVersion,
      quiesceId: generation.quiesceId, checkpointId: proof.snapshot.checkpointId,
      contextManifestRef: before.latestCheckpoint.contextManifestRef, workspaceStateRef: proof.workspaceStateRef,
      snapshotEvidenceRef: proof.checkpoint.snapshotEvidenceRef, snapshotEvidenceDigest: proof.snapshot.evidenceDigest,
      retirementEvidenceRef: forged.ref, checkpointReason: 'auto' }), /retirement proof/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
