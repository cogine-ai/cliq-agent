import path from 'node:path';
import { KERNEL_DATABASE_FILENAME } from '../../config.js';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { digestOmitting } from '../../kernel/identity.js';
import type { ToolObservationV1 } from '../../kernel/tool-authorization.js';
import type { SupervisorInspectorIdentityV1, WorkspaceEntryManifest, WorkspaceGenerationSnapshotEvidenceV1, WorkspaceStateManifest } from '../../kernel/types.js';
import { sampleCanonicalNow } from '../canonical-time.js';
import { openSqliteDriver } from '../sqlite-driver.js';
import { readActiveStateOwner } from '../state-owner.js';
import type { createAgentFixture } from './agent-fixtures.js';

export async function fixtureInspector(fixture: Awaited<ReturnType<typeof createAgentFixture>>) {
  const reader = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  let owner;
  try { owner = readActiveStateOwner(reader)!; } finally { reader.close(); }
  const supervisor = fixture.signed!.bundle.entries.find((entry) => entry.role === 'supervisor')!;
  const inspector: SupervisorInspectorIdentityV1 = { schemaVersion: 1, format: 'cliq-supervisor-inspector-identity-v1',
    supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: owner.ownerEpoch,
    runtimeBundleRef: fixture.authority.assembly.runtime.runtimeBundleRef,
    runtimeBundleManifestDigest: fixture.authority.assembly.runtime.runtimeBundleManifestDigest,
    supervisorEntryId: supervisor.entryId, supervisorEntryVersion: supervisor.version, supervisorExecutableDigest: supervisor.digest,
    processIdentityRef: owner.processIdentityRef, processIdentityDigest: owner.processIdentityDigest,
    stateLockIdentityRef: owner.stateLockIdentityRef, stateLockIdentityDigest: owner.stateLockIdentityDigest,
    instanceNonceDigest: owner.instanceNonceDigest, activatedAt: owner.acquiredAt, identityDigest: '' };
  inspector.identityDigest = digestOmitting(inspector, 'identityDigest');
  const artifact = await fixture.store.artifacts.publishCanonical(inspector, inspector.format);
  return { inspector, identity: { inspectorIdentityRef: artifact.ref, inspectorIdentityDigest: inspector.identityDigest } };
}

/** Retained offline proof fixtures; no process is launched, killed or treated as platform-qualified. */
export async function quiescedToolCheckpoint(fixture: Awaited<ReturnType<typeof createAgentFixture>>, checkpointId: string, changedWorkspace = false) {
  const { store, runId } = fixture;
  const closure = await store.readRecoveryClosure(runId);
  const launch = closure.workerLaunches.find((launch) => launch.launchId === closure.run.activeWorkerLaunchId)!;
  const generation = closure.workspaceGenerations.find((generation) => generation.generationRef === launch.workspaceGenerationRef)!;
  const revoking = store.beginGenerationRevocation({ launchId: launch.launchId, expectedLeaseVersion: launch.leaseVersion,
    expectedGenerationRowVersion: generation.rowVersion, quiesceId: 'tool-test-quiesce' });
  store.beginGenerationCheckpoint({ launchId: launch.launchId, expectedLeaseVersion: launch.leaseVersion,
    expectedGenerationRowVersion: revoking.generation.rowVersion, quiesceId: 'tool-test-quiesce' });
  const workspace = await store.artifacts.readCanonical<WorkspaceStateManifest>(closure.latestCheckpoint.workspaceStateRef);
  let entries = await store.artifacts.readCanonical<WorkspaceEntryManifest>(workspace.entriesRef);
  if (changedWorkspace) {
    const bytes = Buffer.from('post-effect file contents');
    const blob = await store.artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-workspace-file-v1');
    entries = { schemaVersion: 1, format: 'cliq-workspace-entries-v1',
      entries: [{ kind: 'file', path: 'a', mode: 0o644, size: bytes.byteLength, blobRef: blob.ref }], entryCount: 1, byteCount: bytes.byteLength, treeDigest: '' };
    entries.treeDigest = digestOmitting(entries, 'treeDigest');
    workspace.entriesRef = (await store.artifacts.publishCanonical(entries, entries.format)).ref;
    workspace.stateDigest = digestOmitting(workspace, 'stateDigest');
  }
  const state = await store.artifacts.publishCanonical(workspace, workspace.format);
  const { inspector, identity } = await fixtureInspector(fixture);
  const containment = await store.artifacts.readCanonical<{ owner: unknown; backend: object; sandboxLaunchSpecDigest: string }>(launch.processContainmentRef!);
  const deathCore = { schemaVersion: 1, kind: 'containment_all_descendants_dead', containmentRef: launch.processContainmentRef,
    planRef: launch.containmentPlanRef, sandboxLaunchSpecRef: launch.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: containment.sandboxLaunchSpecDigest,
    owner: containment.owner, launchNonceDigest: launch.spawnNonceDigest, inspectorSupervisorInstanceId: inspector.supervisorInstanceId,
    ...identity,
    backend: { ...containment.backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 },
    observedAt: sampleCanonicalNow() };
  const death = await store.artifacts.publishCanonical({ ...deathCore, evidenceDigest: canonicalSha256(deathCore) }, 'cliq-process-containment-death-evidence-v1');
  const snapshot: WorkspaceGenerationSnapshotEvidenceV1 = { schemaVersion: 1, format: 'cliq-workspace-generation-snapshot-evidence-v1',
    purpose: 'sealed_to_checkpoint', runId, generationRef: generation.generationRef, generationIdentityDigest: generation.generationIdentityDigest,
    checkpointId, workspaceStateRef: state.ref, workspaceStateDigest: workspace.stateDigest, entriesRef: workspace.entriesRef, treeDigest: entries.treeDigest,
    ...(workspace.privateGitStateRef ? { privateGitStateRef: workspace.privateGitStateRef } : {}),
    descriptorRewalkComplete: true, fileFsyncComplete: true, directoryFsyncComplete: true, observedAt: sampleCanonicalNow(), evidenceDigest: '' };
  snapshot.evidenceDigest = digestOmitting(snapshot, 'evidenceDigest');
  const snapshotArtifact = await store.artifacts.publishCanonical(snapshot, snapshot.format);
  return { checkpoint: { workspaceStateRef: state.ref, snapshotEvidenceRef: snapshotArtifact.ref, retirementEvidenceRef: death.ref },
    snapshot, workspaceStateRef: state.ref, priorWorkspaceStateRef: closure.latestCheckpoint.workspaceStateRef };
}

export async function postEffectObservation(fixture: Awaited<ReturnType<typeof createAgentFixture>>, observationRef: string, checkpointId: string) {
  const observation = await fixture.store.artifacts.readCanonical<ToolObservationV1>(observationRef);
  const proof = await quiescedToolCheckpoint(fixture, checkpointId, true);
  observation.postEffect = proof.checkpoint;
  observation.observationDigest = digestOmitting(observation, 'observationDigest');
  const complete = await fixture.store.artifacts.publishCanonical(observation, observation.format);
  return { ...proof, observationRef: complete.ref, observation };
}
