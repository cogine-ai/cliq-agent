import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { Run, RunAssemblyV1, RunSpec, StateOwnerRecordV1, SupervisorInspectorIdentityV1, WorkerLaunch, WorkspaceGenerationStateV1 } from '../kernel/types.js';
import type { ToolCheckpointProof } from '../kernel/tool-authorization.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeSourceManifest, decodeWorkspaceEntries, decodeWorkspaceGenerationSnapshotEvidence, decodeWorkspaceState } from './decoders.js';
import { joinResourceOperations, KernelStorageError } from './errors.js';
import { readRequiredWorkerLaunch, updateWorkerLaunch } from './repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef, updateWorkspaceGeneration } from './repositories/workspace-generations.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readStateOwner, type StateOwnerContext } from './state-owner.js';
import { readCheckpoint } from './rows.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { assertNativeContainmentDeath, type NativeContainmentDeathObservation } from '../sandbox/linux-worker.js';

/** Private live-scope dependency. Retained canonical evidence cannot mint it. */
export type NativeWorkerRetirement = () => Promise<NativeContainmentDeathObservation>;

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

export async function readWorkerCheckpointProof(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1, input: {
  run: Run; spec: RunSpec; assembly: RunAssemblyV1; checkpointId: string; observedAt: string; postEffect: ToolCheckpointProof;
  launch: WorkerLaunch; generation: WorkspaceGenerationStateV1;
}) {
  const { run, spec, assembly, checkpointId, observedAt, postEffect, launch, generation } = input;
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
    // Exhaustion verifies the exact size, retained inode and content hash. Do
    // not retain a full workspace file merely to validate a ready Checkpoint.
    for await (const _chunk of artifacts.readChunks(entry.blobRef, entry.size)) { /* bounded verification */ }
  }
  if (state.privateGitStateRef) await artifacts.readBytes(state.privateGitStateRef);
  const death = await readCanonicalArtifact<DeathEvidence>(artifacts, snapshot.quiescenceEvidenceRef);
  if (!exactKeys(death, ['schemaVersion', 'kind', 'containmentRef', 'planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'owner',
    'launchNonceDigest', 'inspectorSupervisorInstanceId', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'backend', 'observedAt', 'evidenceDigest']) ||
      death.schemaVersion !== 1 || death.kind !== 'containment_all_descendants_dead' || digestOmitting(death, 'evidenceDigest') !== death.evidenceDigest ||
      death.containmentRef !== launch.processContainmentRef || death.planRef !== launch.containmentPlanRef ||
      death.sandboxLaunchSpecRef !== launch.sandboxLaunchSpecRef || death.launchNonceDigest !== launch.spawnNonceDigest ||
      death.inspectorSupervisorInstanceId !== owner.supervisorInstanceId || death.observedAt > snapshot.observedAt || death.observedAt < observedAt) {
    throw new TypeError('tool checkpoint has no exact post-effect containment retirement proof');
  }
  parseCanonicalTime(death.observedAt);
  requireEqual(death.owner, { kind: 'worker_activation', runId: run.id, intendedLeaseEpoch: launch.leaseEpoch, workerLaunchId: launch.launchId }, 'retired worker owner');
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
  await readSupervisorInspector(artifacts, owner, assembly, death);
  const launchSpec = await readCanonicalArtifact<{ launchSpecDigest: string }>(artifacts, launch.sandboxLaunchSpecRef);
  if (launchSpec.launchSpecDigest !== death.sandboxLaunchSpecDigest || digestOmitting(launchSpec, 'launchSpecDigest') !== launchSpec.launchSpecDigest) throw new TypeError('retirement launch spec digest mismatch');
  await artifacts.readBytes(death.planRef);
  const finalDeath = await readCanonicalArtifact<DeathEvidence>(artifacts, postEffect.retirementEvidenceRef);
  if (!exactKeys(finalDeath, Object.keys(death)) || digestOmitting(finalDeath, 'evidenceDigest') !== finalDeath.evidenceDigest ||
      typeof finalDeath.observedAt !== 'string' || finalDeath.observedAt < death.observedAt) {
    throw new TypeError('tool checkpoint has no exact final containment retirement proof');
  }
  parseCanonicalTime(finalDeath.observedAt);
  requireEqual(finalDeath.owner, death.owner, 'retired worker owner');
  requireEqual(finalDeath.backend, death.backend, 'containment retirement is not positive all-descendant death');
  requireEqual({ ...finalDeath, owner: death.owner, backend: death.backend,
    observedAt: death.observedAt, evidenceDigest: death.evidenceDigest }, death,
    'final retirement proof of containment death and inspector');
  const metadata = await joinResourceOperations([
    [postEffect.workspaceStateRef, state.format], [state.entriesRef, entries.format],
    [postEffect.snapshotEvidenceRef, snapshot.format], [snapshot.quiescenceEvidenceRef, 'cliq-process-containment-death-evidence-v1'],
    [postEffect.retirementEvidenceRef, 'cliq-process-containment-death-evidence-v1'],
    [death.inspectorIdentityRef, 'cliq-supervisor-inspector-identity-v1']
  ].map(([ref, format]) => artifacts.describe(ref!, 'application/json', format!)));
  return { metadata, snapshot, quiescence: death, death: finalDeath, deathObservedAt: finalDeath.observedAt };
}

/** All immutable closure I/O is already verified. Only genuine current death
 * and its small canonical publication may be retried, never the tool effect. */
export function prepareWorkerRetirement(artifacts: ArtifactCatalog,
  proof: Awaited<ReturnType<typeof readWorkerCheckpointProof>>, retirementEvidenceRef: string,
  reobserve?: NativeWorkerRetirement) {
  let observedAt = proof.deathObservedAt, finalRef = retirementEvidenceRef, attempts = 0;
  return {
    metadata: proof.metadata,
    get retirementEvidenceRef() { return finalRef; },
    async refresh() {
      if (!reobserve) return;
      while (attempts < 3) {
        attempts++;
        const observation = await reobserve();
        assertNativeContainmentDeath(observation);
        if (canonicalSha256(observation.containment) !== proof.quiescence.containmentRef) {
          throw new KernelStorageError('LEASE_FENCED', 'native retirement observation belongs to another containment');
        }
        parseCanonicalTime(observation.observedAt);
        if (observation.observedAt < proof.snapshot.observedAt) {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'native retirement proof predates the prepared snapshot');
        }
        const death = { ...proof.quiescence, observedAt: observation.observedAt, evidenceDigest: '' };
        death.evidenceDigest = digestOmitting(death, 'evidenceDigest');
        const artifact = await artifacts.publishCanonical(death, 'cliq-process-containment-death-evidence-v1');
        const now = sampleCanonicalNow();
        if (now < death.observedAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'native retirement proof is in the future');
        if (parseCanonicalTime(now) - parseCanonicalTime(death.observedAt) > 5_000) continue;
        finalRef = artifact.ref; observedAt = death.observedAt; proof.metadata.push(artifact);
        return;
      }
      throw new KernelStorageError('RECOVERY_REQUIRED', 'worker retirement proof is stale after bounded native reobservation');
    },
    assertFresh(createdAt: string) {
      const now = sampleCanonicalNow();
      if (now < createdAt || observedAt < proof.snapshot.observedAt || observedAt > createdAt ||
          parseCanonicalTime(now) - parseCanonicalTime(observedAt) > 5_000) {
        throw new KernelStorageError('RECOVERY_REQUIRED', 'worker retirement proof is stale; reobserve containment death');
      }
    }
  };
}

/** Shared worker seal for tool completion, control waits and terminal stop. Only this path accepts current authority for mutation. */
export async function prepareToolCheckpoint(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: {
  run: Run; spec: RunSpec; assembly: RunAssemblyV1; checkpointId: string; observedAt: string; postEffect: ToolCheckpointProof;
}, reobserve?: NativeWorkerRetirement) {
  const { run, postEffect } = input;
  if (!run.activeWorkerLaunchId) throw new TypeError('post-effect result has no owning worker launch');
  const launch = readRequiredWorkerLaunch(driver, run.activeWorkerLaunchId);
  const generation = readRequiredWorkspaceGenerationByRef(driver, launch.workspaceGenerationRef);
  if (launch.phase !== 'activated' || launch.generationWriteState !== 'checkpointing' || !launch.quiesceId ||
      generation.phase !== 'checkpointing' || generation.quiesceId !== launch.quiesceId ||
      generation.activeWorkerLaunchId !== launch.launchId || generation.leaseEpoch !== run.leaseEpoch ||
      launch.leaseEpoch !== run.leaseEpoch) throw new KernelStorageError('LEASE_FENCED', 'tool result requires a quiesced checkpointing generation');
  const proof = await readWorkerCheckpointProof(artifacts, assertActiveStateOwner(driver, owner), { ...input, launch, generation });
  const { snapshot } = proof;
  const retirement = prepareWorkerRetirement(artifacts, proof, postEffect.retirementEvidenceRef, reobserve);
  return { metadata: retirement.metadata, refresh: retirement.refresh, commit(connection: SqliteConnection, currentRun: Run, createdAt: string) {
    retirement.assertFresh(createdAt);
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
      retiredAt: createdAt, retirementEvidenceRef: retirement.retirementEvidenceRef });
    connection.prepare("UPDATE runs SET status = 'queued', active_worker_launch_id = NULL WHERE id = ?").run(run.id);
  } };
}

/** Historical seal validation, never authority to retire or adopt an old worker. */
export async function validateRetainedWorkerSeal(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  run: Run; spec: RunSpec; assembly: RunAssemblyV1; launch: WorkerLaunch; generation: WorkspaceGenerationStateV1;
}) {
  const { launch, generation } = input;
  if (launch.phase !== 'retired' || launch.generationWriteState !== 'sealed' || !launch.retirementEvidenceRef || !launch.activatedAt || !launch.retiredAt ||
      generation.phase !== 'sealed' || !generation.snapshotEvidenceRef) throw new TypeError('stop has no positively sealed historical worker');
  const snapshot = decodeWorkspaceGenerationSnapshotEvidence(await readCanonicalArtifact(artifacts, generation.snapshotEvidenceRef));
  const checkpoint = readCheckpoint(driver, snapshot.checkpointId);
  if (checkpoint.runId !== input.run.id || checkpoint.workspaceStateRef !== snapshot.workspaceStateRef || checkpoint.createdAt !== launch.retiredAt ||
      snapshot.observedAt > launch.retiredAt) throw new TypeError('retired worker has no owning sealed checkpoint');
  const death = await readCanonicalArtifact<DeathEvidence>(artifacts, launch.retirementEvidenceRef);
  const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, death.inspectorIdentityRef);
  const owner = readStateOwner(driver, inspector.stateOwnerEpoch);
  if (!owner || owner.acquiredAt > death.observedAt || (owner.state === 'terminal' && owner.releasedAt < death.observedAt)) throw new TypeError('historical inspector was not the state owner at retirement');
  const { deathObservedAt } = await readWorkerCheckpointProof(artifacts, owner, { ...input, checkpointId: checkpoint.id, observedAt: launch.activatedAt,
    postEffect: { workspaceStateRef: checkpoint.workspaceStateRef, snapshotEvidenceRef: generation.snapshotEvidenceRef, retirementEvidenceRef: launch.retirementEvidenceRef } });
  if (deathObservedAt < snapshot.observedAt || deathObservedAt > launch.retiredAt ||
      parseCanonicalTime(launch.retiredAt) - parseCanonicalTime(deathObservedAt) > 5_000) throw new TypeError('historical retirement proof was stale at commit');
}
