import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { activateFixtureWorker, disposeFixture } from './testing/fixtures.js';
import { batch, prepareTool } from './testing/tool-calls.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

test('queued allow is a pure worker requirement and only a new active cut can create its grant and Journal', async () => {
  const fixture = await createAgentFixture('queued-tool-selection', undefined, { mode: 'yolo', tools: ['read'] });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }]);
    const checkpointId = 'offline-worker-free-selection';
    const proof = await quiescedToolCheckpoint(fixture, checkpointId);
    const retiring = await fixture.store.readRecoveryClosure(fixture.runId);
    const launch = retiring.workerLaunches.find(row => row.launchId === retiring.run.activeWorkerLaunchId)!;
    const generation = retiring.workspaceGenerations.find(row => row.generationRef === launch.workspaceGenerationRef)!;
    // Existing inert SQL/CAS evidence fixture, not a physical worker proof.
    await fixture.store.sealWorkerGeneration({ launchId: launch.launchId, expectedRunRevision: retiring.run.revision,
      expectedGenerationRowVersion: generation.rowVersion, quiesceId: generation.quiesceId!, checkpointId,
      contextManifestRef: retiring.latestCheckpoint.contextManifestRef, ...proof.checkpoint,
      snapshotEvidenceDigest: proof.snapshot.evidenceDigest, checkpointReason: 'pre-effect' });
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const decision = await fixture.agent.prepareTool({ expectedRunRevision: before.run.revision, leaseEpoch: before.run.leaseEpoch });
    assert.equal(decision.disposition, 'worker_required');
    for (const key of ['entry', 'grant', 'request', 'target', 'waitingOnRef']) assert(!Object.hasOwn(decision, key));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    Object.assign(fixture, await activateFixtureWorker(fixture, 'fresh-selected-worker'));
    const prepared = await prepareTool(fixture);
    assert.equal(prepared.entry.leaseEpoch, fixture.leaseEpoch);
    assert.equal(prepared.entry.leaseEpoch, before.run.leaseEpoch + 1);
    assert.notEqual(prepared.run.revision, decision.run.revision);
  } finally { await disposeFixture(fixture); }
});

test('active ask cannot publish a wait or grant before the original worker retirement', async () => {
  const fixture = await createAgentFixture('active-ask-selection', undefined, { mode: 'default', tools: ['bash'] });
  try {
    await batch(fixture, [{ name: 'bash', input: { command: 'printf allowed_after_approval' } }]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const decision = await fixture.agent.prepareTool({ expectedRunRevision: before.run.revision, leaseEpoch: before.run.leaseEpoch });
    assert.equal(decision.disposition, 'retirement_required');
    if (decision.disposition !== 'retirement_required') throw new Error('expected original worker retirement');
    assert.equal(decision.reason, 'approval');
    for (const key of ['entry', 'grant', 'request', 'target', 'waitingOnRef', 'evidenceRef']) assert(!Object.hasOwn(decision, key));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    await assert.rejects(fixture.agent.retireToolSelection({ expectedRunRevision: before.run.revision,
      checkpointId: decision.checkpointId, checkpoint: {} as never }));
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
