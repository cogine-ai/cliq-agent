import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { Run, RunAssemblyV1, RunSpec, SupervisorInspectorIdentityV1 } from '../kernel/types.js';
import type { ToolObservationV1 } from '../kernel/tool-authorization.js';
import { exactKeys, requireEqual, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeSourceManifest, decodeWorkspaceEntries, decodeWorkspaceGenerationSnapshotEvidence, decodeWorkspaceState } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { readRequiredWorkerLaunch, updateWorkerLaunch } from './repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef, updateWorkspaceGeneration } from './repositories/workspace-generations.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';

type ToolPostEffectCheckpoint = NonNullable<ToolObservationV1['postEffect']>;

export const toolCheckpointId = (runId: string, opId: string, attempt: number) =>
  identityHash('cliq-tool-checkpoint-v1', runId, opId, String(attempt));

type DeathEvidence = {
  schemaVersion: 1; kind: 'containment_all_descendants_dead'; containmentRef: string; planRef: string;
  sandboxLaunchSpecRef: string; sandboxLaunchSpecDigest: string;
  owner: { kind: 'worker_activation'; runId: string; intendedLeaseEpoch: number; workerLaunchId: string };
  launchNonceDigest: string; inspectorSupervisorInstanceId: string; inspectorIdentityRef: string; inspectorIdentityDigest: string;
  backend: Record<string, unknown> & { kind: 'linux' | 'macos-vm' };
  observedAt: string; evidenceDigest: string;
};

/** Consume a quiesced generation's retained proof; never turn a pre-effect checkpoint or a worker boolean into post-effect truth. */
export async function prepareToolCheckpoint(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: {
  run: Run; spec: RunSpec; assembly: RunAssemblyV1; checkpointId: string; observedAt: string; postEffect: ToolPostEffectCheckpoint;
}) {
  const { run, spec, assembly, checkpointId, observedAt, postEffect } = input;
  if (!run.activeWorkerLaunchId) throw new TypeError('post-effect result has no owning worker launch');
  const launch = readRequiredWorkerLaunch(driver, run.activeWorkerLaunchId);
  const generation = readRequiredWorkspaceGenerationByRef(driver, launch.workspaceGenerationRef);
  if (launch.phase !== 'activated' || launch.generationWriteState !== 'checkpointing' || !launch.quiesceId ||
      generation.phase !== 'checkpointing' || generation.quiesceId !== launch.quiesceId ||
      generation.activeWorkerLaunchId !== launch.launchId || generation.leaseEpoch !== run.leaseEpoch ||
      launch.leaseEpoch !== run.leaseEpoch) throw new KernelStorageError('LEASE_FENCED', 'tool result requires a quiesced checkpointing generation');
  const state = decodeWorkspaceState(await readCanonicalArtifact(artifacts, postEffect.workspaceStateRef));
  const entries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, state.entriesRef));
  const source = decodeSourceManifest(await readCanonicalArtifact(artifacts, spec.baseWorkspaceManifestRef));
  const snapshot = decodeWorkspaceGenerationSnapshotEvidence(await readCanonicalArtifact(artifacts, postEffect.snapshotEvidenceRef));
  if (state.runId !== run.id || state.baseWorkspaceManifestRef !== spec.baseWorkspaceManifestRef ||
      state.sourceProjectionDigest !== source.sourceProjectionDigest || snapshot.purpose !== 'sealed_to_checkpoint' ||
      snapshot.runId !== run.id || snapshot.checkpointId !== checkpointId || snapshot.workspaceStateRef !== postEffect.workspaceStateRef ||
      snapshot.workspaceStateDigest !== state.stateDigest || snapshot.entriesRef !== state.entriesRef || snapshot.treeDigest !== entries.treeDigest ||
      snapshot.privateGitStateRef !== state.privateGitStateRef || snapshot.generationRef !== generation.generationRef ||
      snapshot.generationIdentityDigest !== generation.generationIdentityDigest || snapshot.observedAt < observedAt) {
    throw new TypeError('post-effect snapshot differs from its result, generation or workspace closure');
  }
  for (const entry of entries.entries) if (entry.kind === 'file') {
    if ((await artifacts.readBytes(entry.blobRef)).byteLength !== entry.size) throw new TypeError('post-effect workspace file byte count mismatch');
  }
  if (state.privateGitStateRef) await artifacts.readBytes(state.privateGitStateRef);
  const death = await readCanonicalArtifact<DeathEvidence>(artifacts, postEffect.retirementEvidenceRef);
  if (!exactKeys(death, ['schemaVersion', 'kind', 'containmentRef', 'planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'owner',
    'launchNonceDigest', 'inspectorSupervisorInstanceId', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'backend', 'observedAt', 'evidenceDigest']) ||
      death.schemaVersion !== 1 || death.kind !== 'containment_all_descendants_dead' || digestOmitting(death, 'evidenceDigest') !== death.evidenceDigest ||
      death.containmentRef !== launch.processContainmentRef || death.planRef !== launch.containmentPlanRef ||
      death.sandboxLaunchSpecRef !== launch.sandboxLaunchSpecRef || death.launchNonceDigest !== launch.spawnNonceDigest ||
      death.inspectorSupervisorInstanceId !== owner.supervisorInstanceId || death.observedAt > snapshot.observedAt || death.observedAt < observedAt) {
    throw new TypeError('tool checkpoint has no exact post-effect containment retirement proof');
  }
  parseCanonicalTime(death.observedAt);
  requireEqual(death.owner, { kind: 'worker_activation', runId: run.id, intendedLeaseEpoch: run.leaseEpoch, workerLaunchId: launch.launchId }, 'retired worker owner');
  const containment = await readCanonicalArtifact<{
    schemaVersion: number; planRef: string; sandboxLaunchSpecRef: string; sandboxLaunchSpecDigest: string;
    owner: DeathEvidence['owner']; filesystemBinding: unknown; launchNonceDigest: string;
    backend: Record<string, unknown>; createdAt: string;
  }>(artifacts, death.containmentRef);
  if (containment.schemaVersion !== 1 || containment.planRef !== death.planRef || containment.sandboxLaunchSpecRef !== death.sandboxLaunchSpecRef ||
      containment.sandboxLaunchSpecDigest !== death.sandboxLaunchSpecDigest || containment.launchNonceDigest !== death.launchNonceDigest) {
    throw new TypeError('retirement evidence substitutes a containment identity');
  }
  requireEqual(containment.owner, death.owner, 'containment owner');
  requireEqual(containment.filesystemBinding, { kind: 'run-generation', generationRef: generation.generationRef }, 'containment workspace generation');
  const proof = death.backend;
  const identityKeys = proof.kind === 'linux' ? ['kind', 'pidNamespaceReservationId', 'pidNamespaceId', 'cgroupPath', 'cgroupId',
    'namespaceInitStartToken', 'subreaperStartToken'] : ['kind', 'vmReservationId', 'vmInstanceId', 'vmProcessStartToken', 'guestBootId'];
  const positive = proof.kind === 'linux' ? { cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 }
    : { vmProcessDeadAndReaped: true, guestRetired: true };
  if (!['linux', 'macos-vm'].includes(proof.kind) || !exactKeys(proof, [...identityKeys, ...Object.keys(positive)]) ||
      identityKeys.some((key) => proof[key] !== containment.backend[key] || typeof proof[key] !== 'string' || !proof[key]) ||
      Object.entries(positive).some(([key, value]) => proof[key] !== value)) throw new TypeError('containment retirement is not positive all-descendant death');
  const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, death.inspectorIdentityRef);
  const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, assembly.runtime.runtimeBundleRef);
  const supervisor = bundle.entries.find((entry) => entry.role === 'supervisor');
  if (!exactKeys(inspector, ['schemaVersion', 'format', 'supervisorInstanceId', 'stateOwnerEpoch', 'runtimeBundleRef',
    'runtimeBundleManifestDigest', 'supervisorEntryId', 'supervisorEntryVersion', 'supervisorExecutableDigest',
    'processIdentityRef', 'processIdentityDigest', 'stateLockIdentityRef', 'stateLockIdentityDigest', 'instanceNonceDigest', 'activatedAt', 'identityDigest']) ||
      inspector.schemaVersion !== 1 || inspector.format !== 'cliq-supervisor-inspector-identity-v1' ||
      inspector.identityDigest !== death.inspectorIdentityDigest || digestOmitting(inspector, 'identityDigest') !== inspector.identityDigest ||
      inspector.supervisorInstanceId !== owner.supervisorInstanceId || inspector.stateOwnerEpoch !== owner.ownerEpoch ||
      inspector.runtimeBundleRef !== assembly.runtime.runtimeBundleRef || inspector.runtimeBundleManifestDigest !== assembly.runtime.runtimeBundleManifestDigest ||
      inspector.processIdentityRef !== owner.processIdentityRef || inspector.processIdentityDigest !== owner.processIdentityDigest ||
      inspector.stateLockIdentityRef !== owner.stateLockIdentityRef || inspector.stateLockIdentityDigest !== owner.stateLockIdentityDigest ||
      inspector.supervisorEntryId !== supervisor?.entryId || inspector.supervisorEntryVersion !== supervisor.version ||
      inspector.supervisorExecutableDigest !== supervisor.digest || !supervisor.executable || inspector.activatedAt > death.observedAt) {
    throw new TypeError('retirement inspector does not match the current trusted state owner');
  }
  assertArtifactRef(inspector.instanceNonceDigest);
  parseCanonicalTime(inspector.activatedAt);
  const launchSpec = await readCanonicalArtifact<{ launchSpecDigest: string }>(artifacts, launch.sandboxLaunchSpecRef);
  if (launchSpec.launchSpecDigest !== death.sandboxLaunchSpecDigest || digestOmitting(launchSpec, 'launchSpecDigest') !== launchSpec.launchSpecDigest) throw new TypeError('retirement launch spec digest mismatch');
  await artifacts.readBytes(death.planRef);
  await artifacts.readBytes(inspector.processIdentityRef);
  await artifacts.readBytes(inspector.stateLockIdentityRef);
  const metadata = await Promise.all([
    [postEffect.workspaceStateRef, state.format], [state.entriesRef, entries.format],
    [postEffect.snapshotEvidenceRef, snapshot.format], [postEffect.retirementEvidenceRef, 'cliq-process-containment-death-evidence-v1'],
    [death.inspectorIdentityRef, 'cliq-supervisor-inspector-identity-v1']
  ].map(([ref, format]) => artifacts.describe(ref!, 'application/json', format!)));
  return { metadata, commit(connection: SqliteConnection, currentRun: Run, createdAt: string) {
    if (createdAt < snapshot.observedAt || currentRun.activeWorkerLaunchId !== launch.launchId || currentRun.leaseEpoch !== run.leaseEpoch ||
        canonicalSha256(readRequiredWorkerLaunch(connection, launch.launchId)) !== canonicalSha256(launch) ||
        canonicalSha256(readRequiredWorkspaceGenerationByRef(connection, launch.workspaceGenerationRef)) !== canonicalSha256(generation)) {
      throw new KernelStorageError('REVISION_CONFLICT', 'post-effect generation changed before atomic completion');
    }
    updateWorkspaceGeneration(connection, generation, {
      schemaVersion: 1, generationId: generation.generationId, runId: run.id, generationRef: generation.generationRef,
      generationIdentityDigest: generation.generationIdentityDigest, rowVersion: generation.rowVersion + 1,
      sourceCheckpointId: generation.sourceCheckpointId, sourceWorkspaceStateRef: generation.sourceWorkspaceStateRef,
      sourceWorkspaceStateDigest: generation.sourceWorkspaceStateDigest, lastVerifiedTreeDigest: snapshot.treeDigest,
      updatedAt: createdAt, phase: 'sealed', snapshotEvidenceRef: postEffect.snapshotEvidenceRef, snapshotEvidenceDigest: snapshot.evidenceDigest
    });
    updateWorkerLaunch(connection, launch, { ...launch, phase: 'retired', generationWriteState: 'sealed',
      retiredAt: createdAt, retirementEvidenceRef: postEffect.retirementEvidenceRef });
    connection.prepare("UPDATE runs SET status = 'queued', active_worker_launch_id = NULL WHERE id = ?").run(run.id);
  } };
}
