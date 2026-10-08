import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createActiveFixture, disposeFixture, prepareFixtureGeneration } from './testing/fixtures.js';
import { publishFixtureWorkerLaunch } from './testing/worker-launch.js';
import { digest, createQueuedFixture } from './testing/fixtures.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { WorkspaceGenerationIdentityV1, WorkspaceGenerationSnapshotEvidenceV1 } from '../kernel/types.js';

test('worker recovery can materialize one distinct read-only replacement without clearing the fence or activating it', async () => {
  const fixture = await createActiveFixture('replacement-wait');
  try {
    const waiting = await fixture.store.beginWorkerRecovery({ runId: fixture.runId, expectedRunRevision: fixture.runRevision });
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    // These are canonical retained StateStore fixtures, not physical materialization or platform qualification.
    const replacement = await prepareFixtureGeneration(fixture, 'replacement');
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(after.run, waiting);
    assert.deepEqual(after.workerLaunches, before.workerLaunches);
    assert.deepEqual(after.workspaceGenerations.find(row => row.generationRef === fixture.generationRef), before.workspaceGenerations[0]);
    assert.notEqual(replacement.generationId, fixture.generationId);
    assert.equal(replacement.preactivatedGeneration.phase, 'preactivated_readonly');
    await assert.rejects(prepareFixtureGeneration(fixture, 'second-replacement'), { code: 'STATE_TRANSITION_INVALID' });
    const intent = await publishFixtureWorkerLaunch(fixture, replacement.generationArtifact.ref, 'premature-replacement');
    await assert.rejects(fixture.store.reserveWorkerLaunch(intent.input), { code: 'STATE_TRANSITION_INVALID' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), after);
  } finally { await disposeFixture(fixture); }
});

test('generation transitions retain the exact inputs checked before asynchronous artifact reads', async t => {
  const fixture = await createQueuedFixture('generation-input-snapshot');
  try {
    const original = await prepareFixtureGeneration(fixture, 'generation-input-snapshot');
    const identity = await fixture.store.artifacts.readCanonical<WorkspaceGenerationIdentityV1>(original.generationArtifact.ref);
    if (identity.locator.kind !== 'linux_directory') throw new Error('fixture must retain a Linux identity');
    const nonce = digest('generation-input-snapshot:replacement');
    const generationId = identityHash(identity.runId, identity.sourceCheckpointId, identity.sourceWorkspaceStateRef, nonce);
    const replacement: WorkspaceGenerationIdentityV1 = { ...identity, generationId, creationNonceDigest: nonce,
      locator: { ...identity.locator, canonicalRootRelativePath: `runs/${identity.runId}/generations/${generationId}` } };
    replacement.identityDigest = digestOmitting(replacement, 'identityDigest');
    const artifact = await fixture.store.artifacts.publishCanonical(replacement, replacement.format);
    const unrelated = await fixture.store.artifacts.publishCanonical({ unrelated: true }, 'cliq-test-unrelated-v1');
    const registerInput = { runId: fixture.runId, generationRef: artifact.ref, generationIdentityDigest: replacement.identityDigest };
    const describe = fixture.store.artifacts.describe.bind(fixture.store.artifacts);
    async function pauseDescription(ref: string, start: () => Promise<unknown>, mutate: () => void) {
      let reached!: () => void, release!: () => void;
      const described = new Promise<void>(resolve => { reached = resolve; });
      const barrier = new Promise<void>(resolve => { release = resolve; });
      const mock = t.mock.method(fixture.store.artifacts, 'describe', async (...args: Parameters<typeof describe>) => {
        const metadata = await describe(...args);
        if (args[0] === ref) { reached(); await barrier; }
        return metadata;
      });
      try {
        const pending = start();
        await described;
        mutate(); release();
        return await pending;
      } finally { release(); mock.mock.restore(); }
    }
    await pauseDescription(artifact.ref, () => fixture.store.registerWorkspaceGeneration(registerInput), () => {
      registerInput.generationRef = unrelated.ref;
      registerInput.generationIdentityDigest = unrelated.ref;
    });
    const materializing = (await fixture.store.readRecoveryClosure(fixture.runId)).workspaceGenerations.find(row => row.generationId === generationId)!;
    assert.equal(materializing.generationRef, artifact.ref);
    const source = await fixture.store.artifacts.readCanonical<WorkspaceGenerationSnapshotEvidenceV1>(original.preactivatedGeneration.snapshotEvidenceRef);
    const snapshot = { ...source, generationRef: artifact.ref, generationIdentityDigest: replacement.identityDigest };
    snapshot.evidenceDigest = digestOmitting(snapshot, 'evidenceDigest');
    const snapshotArtifact = await fixture.store.artifacts.publishCanonical(snapshot, snapshot.format);
    const preactivateInput = { generationId, expectedRowVersion: materializing.rowVersion,
      snapshotEvidenceRef: snapshotArtifact.ref, snapshotEvidenceDigest: snapshot.evidenceDigest };
    await pauseDescription(snapshotArtifact.ref, () => fixture.store.recordWorkspaceGenerationPreactivated(preactivateInput), () => {
      preactivateInput.snapshotEvidenceRef = unrelated.ref;
      preactivateInput.snapshotEvidenceDigest = unrelated.ref;
    });
    const preactivated = (await fixture.store.readRecoveryClosure(fixture.runId)).workspaceGenerations.find(row => row.generationId === generationId)!;
    assert.equal(preactivated.phase, 'preactivated_readonly');
    if (preactivated.phase !== 'preactivated_readonly') assert.fail('generation must remain preactivated');
    assert.equal(preactivated.snapshotEvidenceRef, snapshotArtifact.ref);
  } finally { await disposeFixture(fixture); }
});
