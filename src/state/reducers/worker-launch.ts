import { assertArtifactRef, addCanonicalDuration, parseCanonicalTime } from '../../kernel/identity.js';
import type { Checkpoint, Run, RunEvent, WorkerIdentity, WorkerLaunch, WorkspaceGenerationStateV1 } from '../../kernel/types.js';
import type { ArtifactCatalog } from '../artifacts.js';
import { insertArtifactMetadata } from '../artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import {
  decodeContextManifest,
  decodeWorkerIdentity,
  decodeWorkspaceEntries,
  decodeWorkspaceGenerationIdentity,
  decodeWorkspaceGenerationSnapshotEvidence,
  decodeWorkspaceState
} from '../decoders.js';
import { KernelStorageError } from '../errors.js';
import { insertRunEvent, readRun } from '../rows.js';
import {
  insertWorkerLaunch,
  readRequiredWorkerLaunch,
  readWorkerLaunchesForRun,
  updateWorkerLaunch
} from '../repositories/worker-launches.js';
import {
  readRequiredWorkspaceGeneration,
  readRequiredWorkspaceGenerationByRef,
  updateWorkspaceGeneration
} from '../repositories/workspace-generations.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';

const ACTIVATION_DEADLINE_MS = 120_000;
const MAX_LEASE_EXTENSION_MS = 60_000;

function requireHealthyFence(outcome: TimeFenceAdvance | undefined): void {
  if (outcome === 'clock_regressed' || outcome === 'still_regressed') {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical clock is not healthy');
  }
}

function assertRunCanActivate(run: Run, now: string, expectedRevision: number): void {
  if (run.revision !== expectedRevision) {
    throw new KernelStorageError('REVISION_CONFLICT', 'Run revision changed before worker activation');
  }
  if (run.status !== 'queued' || run.activeWorkerLaunchId !== undefined) {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker activation requires a lease-free queued Run');
  }
  if (run.cancelRequested || run.stopIntentRef !== undefined) {
    throw new KernelStorageError('LEASE_FENCED', 'Run is stopping and cannot activate a worker');
  }
  if (parseCanonicalTime(now) >= parseCanonicalTime(run.deadlineAt)) {
    throw new KernelStorageError('LEASE_FENCED', 'Run deadline has elapsed');
  }
}

function latestRunItemSequence(connection: SqliteConnection, runId: string): number {
  const row = connection
    .prepare('SELECT COALESCE(max(item_seq), 0) AS item_seq FROM items WHERE run_id = ?')
    .get<{ item_seq: unknown }>(runId);
  return Number(row?.item_seq ?? 0);
}

function nextRunEventSequence(connection: SqliteConnection, runId: string): number {
  const row = connection
    .prepare('SELECT COALESCE(max(event_seq), 0) + 1 AS event_seq FROM run_events WHERE run_id = ?')
    .get<{ event_seq: unknown }>(runId);
  const value = Number(row?.event_seq);
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'Run event sequence overflowed');
  }
  return value;
}

function appendRunStateEvent(connection: SqliteConnection, run: Run, occurredAt: string): void {
  const event: Extract<RunEvent, { kind: 'state_changed' }> = {
    schemaVersion: 1,
    kind: 'state_changed',
    runId: run.id,
    eventSeq: nextRunEventSequence(connection, run.id),
    runRevision: run.revision,
    status: run.status,
    nextStep: run.nextStep,
    latestRunItemSeq: latestRunItemSequence(connection, run.id),
    occurredAt
  };
  if (run.frontierRef !== undefined) event.frontierRef = run.frontierRef;
  if (run.waitingReason !== undefined) event.waitingReason = run.waitingReason;
  if (run.waitingOnRef !== undefined) event.waitingOnRef = run.waitingOnRef;
  if (run.resultRef !== undefined) event.resultRef = run.resultRef;
  if (run.terminalReason !== undefined) event.terminalReason = run.terminalReason;
  if (run.terminalDetailRef !== undefined) event.terminalDetailRef = run.terminalDetailRef;
  insertRunEvent(connection, event);
}

export type ReserveWorkerLaunchInput = {
  launchId: string;
  runId: string;
  expectedRunRevision: number;
  spawnNonceDigest: string;
  activationNonceDigest: string;
  workspaceGenerationRef: string;
  containmentPlanRef: string;
  sandboxLaunchSpecRef: string;
};

export async function reserveWorkerLaunch(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: ReserveWorkerLaunchInput
): Promise<WorkerLaunch> {
  for (const ref of [
    input.spawnNonceDigest,
    input.activationNonceDigest,
    input.workspaceGenerationRef,
    input.containmentPlanRef,
    input.sandboxLaunchSpecRef
  ]) assertArtifactRef(ref);
  const identity = decodeWorkspaceGenerationIdentity(
    await artifacts.readCanonical(input.workspaceGenerationRef)
  );
  if (identity.runId !== input.runId) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace generation belongs to another Run');
  }
  await Promise.all([
    artifacts.readBytes(input.containmentPlanRef),
    artifacts.readBytes(input.sandboxLaunchSpecRef)
  ]);
  const authorityMetadata = await Promise.all([
    artifacts.describe(input.workspaceGenerationRef, 'application/json', 'cliq-workspace-generation-identity-v1'),
    artifacts.describe(input.containmentPlanRef, 'application/json', 'cliq-process-containment-plan-v1'),
    artifacts.describe(input.sandboxLaunchSpecRef, 'application/json', 'cliq-sandbox-launch-spec-v1')
  ]);

  let reserved!: WorkerLaunch;
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (fenceOutcome !== 'healthy') return;
    const run = readRun(connection, input.runId);
    assertRunCanActivate(run, now, input.expectedRunRevision);
    if (readWorkerLaunchesForRun(connection, input.runId, true).length !== 0) {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'Run already has an unretired worker launch');
    }
    const generation = readRequiredWorkspaceGeneration(connection, identity.generationId);
    if (
      generation.phase !== 'preactivated_readonly' ||
      generation.generationRef !== input.workspaceGenerationRef ||
      generation.generationIdentityDigest !== identity.identityDigest ||
      generation.sourceCheckpointId !== run.latestCheckpointId
    ) {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker launch requires the ready preactivated generation');
    }
    reserved = {
      schemaVersion: 1,
      launchId: input.launchId,
      runId: input.runId,
      plannedRunRevision: input.expectedRunRevision,
      supervisorInstanceId: owner.supervisorInstanceId,
      spawnNonceDigest: input.spawnNonceDigest,
      activationNonceDigest: input.activationNonceDigest,
      phase: 'reserved',
      workspaceGenerationRef: input.workspaceGenerationRef,
      containmentPlanRef: input.containmentPlanRef,
      sandboxLaunchSpecRef: input.sandboxLaunchSpecRef,
      leaseVersion: 0,
      generationWriteState: 'preactivated_readonly',
      createdAt: now,
      activationDeadlineAt: addCanonicalDuration(now, ACTIVATION_DEADLINE_MS)
    };
    for (const artifact of authorityMetadata) insertArtifactMetadata(connection, artifact, now);
    insertWorkerLaunch(connection, reserved);
  });
  requireHealthyFence(fenceOutcome);
  return reserved;
}

export type RecordWorkerPreactivatedInput = {
  launchId: string;
  workerIdentityDigest: string;
  processContainmentRef: string;
};

export async function recordWorkerPreactivated(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: RecordWorkerPreactivatedInput
): Promise<WorkerLaunch> {
  assertArtifactRef(input.workerIdentityDigest);
  assertArtifactRef(input.processContainmentRef);
  const identity = decodeWorkerIdentity(await artifacts.readCanonical(input.workerIdentityDigest));
  await artifacts.readBytes(input.processContainmentRef);
  const identityMetadata = await artifacts.describe(
    input.workerIdentityDigest,
    'application/json',
    'cliq-worker-identity-v1'
  );
  const containmentMetadata = await artifacts.describe(
    input.processContainmentRef,
    'application/json',
    'cliq-process-containment-v1'
  );

  let updated!: WorkerLaunch;
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (fenceOutcome !== 'healthy') return;
    const current = readRequiredWorkerLaunch(connection, input.launchId);
    if (current.phase !== 'reserved') {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'only a reserved worker can preactivate');
    }
    const run = readRun(connection, current.runId);
    assertRunCanActivate(run, now, current.plannedRunRevision);
    assertWorkerIdentityMatches(identity, current, run.leaseEpoch + 1, input.processContainmentRef, owner);
    if (parseCanonicalTime(now) > parseCanonicalTime(current.activationDeadlineAt)) {
      throw new KernelStorageError('LEASE_FENCED', 'worker activation deadline elapsed');
    }
    updated = {
      ...current,
      phase: 'preactivated',
      workerIdentityDigest: input.workerIdentityDigest,
      processContainmentRef: input.processContainmentRef
    };
    insertArtifactMetadata(connection, identityMetadata, now);
    insertArtifactMetadata(connection, containmentMetadata, now);
    updateWorkerLaunch(connection, current, updated);
  });
  requireHealthyFence(fenceOutcome);
  return updated;
}

function assertWorkerIdentityMatches(
  identity: WorkerIdentity,
  launch: WorkerLaunch,
  intendedLeaseEpoch: number,
  processContainmentRef: string,
  owner: StateOwnerContext
): void {
  if (
    identity.launchId !== launch.launchId ||
    identity.supervisorInstanceId !== owner.supervisorInstanceId ||
    identity.spawnNonceDigest !== launch.spawnNonceDigest ||
    identity.activationNonceDigest !== launch.activationNonceDigest ||
    identity.intendedLeaseEpoch !== intendedLeaseEpoch ||
    identity.processContainmentRef !== processContainmentRef
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'WorkerIdentity does not match the reserved launch');
  }
}

export type ActivateWorkerLeaseInput = {
  launchId: string;
  expectedRunRevision: number;
  expectedGenerationRowVersion: number;
  leaseDurationMs: number;
};

export function activateWorkerLease(
  driver: SqliteDriver,
  owner: StateOwnerContext,
  input: ActivateWorkerLeaseInput
): { run: Run; launch: WorkerLaunch; generation: WorkspaceGenerationStateV1 } {
  if (!Number.isSafeInteger(input.leaseDurationMs) || input.leaseDurationMs < 1 || input.leaseDurationMs > MAX_LEASE_EXTENSION_MS) {
    throw new KernelStorageError('INVALID_REQUEST', 'worker lease duration is outside 1..60000ms');
  }
  let result!: { run: Run; launch: WorkerLaunch; generation: WorkspaceGenerationStateV1 };
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (fenceOutcome !== 'healthy') return;
    const currentLaunch = readRequiredWorkerLaunch(connection, input.launchId);
    if (
      currentLaunch.phase !== 'preactivated' ||
      currentLaunch.supervisorInstanceId !== owner.supervisorInstanceId ||
      currentLaunch.workerIdentityDigest === undefined ||
      currentLaunch.processContainmentRef === undefined
    ) {
      throw new KernelStorageError('LEASE_FENCED', 'worker launch is not preactivated by the current owner');
    }
    const run = readRun(connection, currentLaunch.runId);
    assertRunCanActivate(run, now, input.expectedRunRevision);
    const leaseExpiresAt = addCanonicalDuration(now, input.leaseDurationMs);
    if (parseCanonicalTime(leaseExpiresAt) > parseCanonicalTime(run.deadlineAt)) {
      throw new KernelStorageError('INVALID_REQUEST', 'initial worker lease exceeds the Run deadline');
    }
    if (currentLaunch.plannedRunRevision !== run.revision) {
      throw new KernelStorageError('REVISION_CONFLICT', 'worker launch was planned for another Run revision');
    }
    const currentGeneration = findGenerationByRef(connection, currentLaunch.workspaceGenerationRef);
    if (
      currentGeneration.phase !== 'preactivated_readonly' ||
      currentGeneration.rowVersion !== input.expectedGenerationRowVersion ||
      currentGeneration.generationRef !== currentLaunch.workspaceGenerationRef
    ) {
      throw new KernelStorageError('LEASE_FENCED', 'workspace generation is no longer preactivated');
    }
    const leaseEpoch = run.leaseEpoch + 1;
    if (!Number.isSafeInteger(leaseEpoch)) throw new KernelStorageError('RECOVERY_REQUIRED', 'Run lease epoch overflowed');
    const launch: WorkerLaunch = {
      ...currentLaunch,
      phase: 'activated',
      leaseEpoch,
      leaseVersion: 1,
      leaseExpiresAt,
      generationWriteState: 'active',
      activatedAt: now
    };
    const generation: WorkspaceGenerationStateV1 = {
      ...currentGeneration,
      phase: 'active',
      rowVersion: currentGeneration.rowVersion + 1,
      updatedAt: now,
      activeWorkerLaunchId: launch.launchId,
      leaseEpoch
    };
    updateWorkspaceGeneration(connection, currentGeneration, generation);
    updateWorkerLaunch(connection, currentLaunch, launch);
    const update = connection
      .prepare(
        `UPDATE runs SET status = 'running', revision = revision + 1, lease_epoch = ?,
           active_worker_launch_id = ?, updated_at = ?
         WHERE id = ? AND status = 'queued' AND revision = ? AND lease_epoch = ?
           AND active_worker_launch_id IS NULL AND cancel_requested = 0 AND stop_intent_ref IS NULL`
      )
      .run(
        BigInt(leaseEpoch),
        launch.launchId,
        now,
        run.id,
        BigInt(run.revision),
        BigInt(run.leaseEpoch)
      );
    if (update.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'Run activation CAS failed');
    const activatedRun = readRun(connection, run.id);
    appendRunStateEvent(connection, activatedRun, now);
    result = { run: activatedRun, launch, generation };
  });
  requireHealthyFence(fenceOutcome);
  return result;
}

export type RenewWorkerLeaseInput = {
  launchId: string;
  expectedLeaseVersion: number;
  runId: string;
  leaseEpoch: number;
  workerIdentityDigest: string;
  newLeaseExpiresAt: string;
};

export function renewWorkerLease(
  driver: SqliteDriver,
  owner: StateOwnerContext,
  input: RenewWorkerLeaseInput
): WorkerLaunch {
  let renewed!: WorkerLaunch;
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (fenceOutcome !== 'healthy') return;
    const current = readRequiredWorkerLaunch(connection, input.launchId);
    if (
      current.phase !== 'activated' ||
      current.supervisorInstanceId !== owner.supervisorInstanceId ||
      current.runId !== input.runId ||
      current.leaseEpoch !== input.leaseEpoch ||
      current.leaseVersion !== input.expectedLeaseVersion ||
      current.workerIdentityDigest !== input.workerIdentityDigest ||
      current.generationWriteState !== 'active'
    ) {
      throw new KernelStorageError('LEASE_FENCED', 'worker heartbeat identity or version is stale');
    }
    const run = readRun(connection, input.runId);
    if (
      run.status !== 'running' ||
      run.activeWorkerLaunchId !== current.launchId ||
      run.leaseEpoch !== current.leaseEpoch ||
      run.cancelRequested ||
      run.stopIntentRef !== undefined
    ) {
      throw new KernelStorageError('LEASE_FENCED', 'Run no longer grants this worker lease');
    }
    if (
      current.leaseExpiresAt === undefined ||
      parseCanonicalTime(now) >= parseCanonicalTime(current.leaseExpiresAt) ||
      parseCanonicalTime(now) >= parseCanonicalTime(run.deadlineAt)
    ) {
      throw new KernelStorageError('LEASE_FENCED', 'expired worker lease or Run deadline cannot be renewed');
    }
    const generation = findGenerationByRef(connection, current.workspaceGenerationRef);
    if (
      generation.phase !== 'active' ||
      generation.activeWorkerLaunchId !== current.launchId ||
      generation.leaseEpoch !== current.leaseEpoch
    ) {
      throw new KernelStorageError('LEASE_FENCED', 'workspace generation no longer grants writes');
    }
    const nextExpiryMs = parseCanonicalTime(input.newLeaseExpiresAt);
    const nowMs = parseCanonicalTime(now);
    if (
      nextExpiryMs <= nowMs ||
      nextExpiryMs > nowMs + MAX_LEASE_EXTENSION_MS ||
      nextExpiryMs > parseCanonicalTime(run.deadlineAt)
    ) {
      throw new KernelStorageError('INVALID_REQUEST', 'new worker lease expiry is outside the live renewal window');
    }
    renewed = {
      ...current,
      leaseVersion: current.leaseVersion + 1,
      leaseExpiresAt: input.newLeaseExpiresAt
    };
    updateWorkerLaunch(connection, current, renewed);
  });
  requireHealthyFence(fenceOutcome);
  return renewed;
}

function findGenerationByRef(connection: SqliteConnection, generationRef: string): WorkspaceGenerationStateV1 {
  return readRequiredWorkspaceGenerationByRef(connection, generationRef);
}

export type BeginGenerationRevocationInput = {
  launchId: string;
  expectedLeaseVersion: number;
  expectedGenerationRowVersion: number;
  quiesceId: string;
};

export function beginGenerationRevocation(
  driver: SqliteDriver,
  owner: StateOwnerContext,
  input: BeginGenerationRevocationInput
): { launch: WorkerLaunch; generation: WorkspaceGenerationStateV1 } {
  let result!: { launch: WorkerLaunch; generation: WorkspaceGenerationStateV1 };
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (fenceOutcome !== 'healthy') return;
    const currentLaunch = readRequiredWorkerLaunch(connection, input.launchId);
    if (
      currentLaunch.phase !== 'activated' ||
      currentLaunch.leaseVersion !== input.expectedLeaseVersion ||
      currentLaunch.generationWriteState !== 'active'
    ) throw new KernelStorageError('LEASE_FENCED', 'worker launch cannot begin revocation');
    const run = readRun(connection, currentLaunch.runId);
    if (run.status !== 'running' || run.activeWorkerLaunchId !== currentLaunch.launchId) {
      throw new KernelStorageError('LEASE_FENCED', 'Run no longer points at the worker launch');
    }
    const currentGeneration = findGenerationByRef(connection, currentLaunch.workspaceGenerationRef);
    if (
      currentGeneration.phase !== 'active' ||
      currentGeneration.rowVersion !== input.expectedGenerationRowVersion ||
      currentGeneration.activeWorkerLaunchId !== currentLaunch.launchId ||
      currentGeneration.leaseEpoch !== currentLaunch.leaseEpoch
    ) throw new KernelStorageError('LEASE_FENCED', 'workspace generation cannot begin revocation');
    const launch: WorkerLaunch = {
      ...currentLaunch,
      generationWriteState: 'revoking',
      quiesceId: input.quiesceId
    };
    const generation: WorkspaceGenerationStateV1 = {
      ...currentGeneration,
      phase: 'revoking',
      rowVersion: currentGeneration.rowVersion + 1,
      updatedAt: now,
      quiesceId: input.quiesceId
    };
    updateWorkspaceGeneration(connection, currentGeneration, generation);
    updateWorkerLaunch(connection, currentLaunch, launch);
    result = { launch, generation };
  });
  requireHealthyFence(fenceOutcome);
  return result;
}

export type BeginGenerationCheckpointInput = {
  launchId: string;
  expectedLeaseVersion: number;
  expectedGenerationRowVersion: number;
  quiesceId: string;
};

export function beginGenerationCheckpoint(
  driver: SqliteDriver,
  owner: StateOwnerContext,
  input: BeginGenerationCheckpointInput
): { launch: WorkerLaunch; generation: WorkspaceGenerationStateV1 } {
  let result!: { launch: WorkerLaunch; generation: WorkspaceGenerationStateV1 };
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (fenceOutcome !== 'healthy') return;
    const currentLaunch = readRequiredWorkerLaunch(connection, input.launchId);
    if (
      currentLaunch.phase !== 'activated' ||
      currentLaunch.leaseVersion !== input.expectedLeaseVersion ||
      currentLaunch.generationWriteState !== 'revoking' ||
      currentLaunch.quiesceId !== input.quiesceId
    ) throw new KernelStorageError('LEASE_FENCED', 'worker launch is not revoking under this quiesce id');
    const currentGeneration = findGenerationByRef(connection, currentLaunch.workspaceGenerationRef);
    if (
      currentGeneration.phase !== 'revoking' ||
      currentGeneration.rowVersion !== input.expectedGenerationRowVersion ||
      currentGeneration.quiesceId !== input.quiesceId ||
      currentGeneration.activeWorkerLaunchId !== currentLaunch.launchId ||
      currentGeneration.leaseEpoch !== currentLaunch.leaseEpoch
    ) throw new KernelStorageError('LEASE_FENCED', 'workspace generation is not revoking under this quiesce id');
    const launch: WorkerLaunch = {
      ...currentLaunch,
      generationWriteState: 'checkpointing'
    };
    const generation: WorkspaceGenerationStateV1 = {
      ...currentGeneration,
      phase: 'checkpointing',
      rowVersion: currentGeneration.rowVersion + 1,
      updatedAt: now
    };
    updateWorkspaceGeneration(connection, currentGeneration, generation);
    updateWorkerLaunch(connection, currentLaunch, launch);
    result = { launch, generation };
  });
  requireHealthyFence(fenceOutcome);
  return result;
}

export type SealWorkerGenerationInput = {
  launchId: string;
  expectedRunRevision: number;
  expectedGenerationRowVersion: number;
  quiesceId: string;
  checkpointId: string;
  contextManifestRef: string;
  workspaceStateRef: string;
  snapshotEvidenceRef: string;
  snapshotEvidenceDigest: string;
  retirementEvidenceRef: string;
  checkpointReason: 'auto' | 'manual' | 'pre-effect' | 'handoff';
};

export async function sealWorkerGeneration(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: SealWorkerGenerationInput
): Promise<{ run: Run; checkpoint: Checkpoint; launch: WorkerLaunch; generation: WorkspaceGenerationStateV1 }> {
  const [context, workspaceState, snapshot] = await Promise.all([
    artifacts.readCanonical(input.contextManifestRef).then(decodeContextManifest),
    artifacts.readCanonical(input.workspaceStateRef).then(decodeWorkspaceState),
    artifacts.readCanonical(input.snapshotEvidenceRef).then(decodeWorkspaceGenerationSnapshotEvidence)
  ]);
  const workspaceEntries = decodeWorkspaceEntries(
    await artifacts.readCanonical(workspaceState.entriesRef)
  );
  await artifacts.readBytes(input.retirementEvidenceRef);
  const checkpointMetadata = await Promise.all([
    artifacts.describe(input.contextManifestRef, 'application/json', 'cliq-context-manifest-v1'),
    artifacts.describe(input.workspaceStateRef, 'application/json', 'cliq-workspace-state-v1'),
    artifacts.describe(
      input.snapshotEvidenceRef,
      'application/json',
      'cliq-workspace-generation-snapshot-evidence-v1'
    ),
    artifacts.describe(
      input.retirementEvidenceRef,
      'application/json',
      'cliq-process-containment-death-evidence-v1'
    )
  ]);
  if (
    snapshot.evidenceDigest !== input.snapshotEvidenceDigest ||
    snapshot.purpose !== 'sealed_to_checkpoint' ||
    snapshot.checkpointId !== input.checkpointId ||
    snapshot.workspaceStateRef !== input.workspaceStateRef ||
    snapshot.workspaceStateDigest !== workspaceState.stateDigest ||
    snapshot.entriesRef !== workspaceState.entriesRef ||
    snapshot.treeDigest !== workspaceEntries.treeDigest ||
    snapshot.privateGitStateRef !== workspaceState.privateGitStateRef
  ) throw new KernelStorageError('ARTIFACT_MISMATCH', 'sealed snapshot does not match the new Checkpoint');

  let result!: { run: Run; checkpoint: Checkpoint; launch: WorkerLaunch; generation: WorkspaceGenerationStateV1 };
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (fenceOutcome !== 'healthy') return;
    const currentLaunch = readRequiredWorkerLaunch(connection, input.launchId);
    const run = readRun(connection, currentLaunch.runId);
    if (
      run.status !== 'running' ||
      run.revision !== input.expectedRunRevision ||
      run.activeWorkerLaunchId !== currentLaunch.launchId ||
      currentLaunch.phase !== 'activated' ||
      currentLaunch.generationWriteState !== 'checkpointing' ||
      currentLaunch.quiesceId !== input.quiesceId
    ) throw new KernelStorageError('LEASE_FENCED', 'Run and WorkerLaunch are not checkpointing together');
    const currentGeneration = findGenerationByRef(connection, currentLaunch.workspaceGenerationRef);
    if (
      currentGeneration.phase !== 'checkpointing' ||
      currentGeneration.rowVersion !== input.expectedGenerationRowVersion ||
      currentGeneration.quiesceId !== input.quiesceId ||
      snapshot.runId !== run.id ||
      snapshot.generationRef !== currentGeneration.generationRef ||
      snapshot.generationIdentityDigest !== currentGeneration.generationIdentityDigest ||
      context.runId !== run.id ||
      workspaceState.runId !== run.id
    ) throw new KernelStorageError('ARTIFACT_MISMATCH', 'checkpoint artifacts do not match the active generation');
    const runItemSeq = latestRunItemSequence(connection, run.id);
    if (context.throughItemSeq !== runItemSeq) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'ContextManifest does not cover the current Run items');
    }
    const journalSeqRow = connection
      .prepare('SELECT COALESCE(max(seq), 0) AS seq FROM run_journal WHERE run_id = ?')
      .get<{ seq: unknown }>(run.id);
    const journalSeq = Number(journalSeqRow?.seq ?? 0);
    const checkpoint: Checkpoint = {
      id: input.checkpointId,
      schemaVersion: 1,
      runId: run.id,
      basedOnRunRevision: run.revision,
      runItemSeq,
      contextManifestRef: input.contextManifestRef,
      journalSeq,
      workspaceStateRef: input.workspaceStateRef,
      createdAt: now,
      reason: input.checkpointReason
    };
    for (const artifact of checkpointMetadata) insertArtifactMetadata(connection, artifact, now);
    connection
      .prepare(
        `INSERT INTO checkpoints (
           id, schema_version, run_id, based_on_run_revision, run_item_seq,
           context_manifest_ref, journal_seq, workspace_state_ref, created_at, reason
         ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        checkpoint.id,
        checkpoint.runId,
        BigInt(checkpoint.basedOnRunRevision),
        BigInt(checkpoint.runItemSeq),
        checkpoint.contextManifestRef,
        BigInt(checkpoint.journalSeq),
        checkpoint.workspaceStateRef,
        checkpoint.createdAt,
        checkpoint.reason
      );
    const generation: WorkspaceGenerationStateV1 = {
      schemaVersion: 1,
      generationId: currentGeneration.generationId,
      runId: currentGeneration.runId,
      generationRef: currentGeneration.generationRef,
      generationIdentityDigest: currentGeneration.generationIdentityDigest,
      rowVersion: currentGeneration.rowVersion + 1,
      sourceCheckpointId: currentGeneration.sourceCheckpointId,
      sourceWorkspaceStateRef: currentGeneration.sourceWorkspaceStateRef,
      sourceWorkspaceStateDigest: currentGeneration.sourceWorkspaceStateDigest,
      lastVerifiedTreeDigest: snapshot.treeDigest,
      updatedAt: now,
      phase: 'sealed',
      snapshotEvidenceRef: input.snapshotEvidenceRef,
      snapshotEvidenceDigest: snapshot.evidenceDigest
    };
    const launch: WorkerLaunch = {
      ...currentLaunch,
      phase: 'retired',
      generationWriteState: 'sealed',
      retiredAt: now,
      retirementEvidenceRef: input.retirementEvidenceRef
    };
    updateWorkspaceGeneration(connection, currentGeneration, generation);
    updateWorkerLaunch(connection, currentLaunch, launch);
    const update = connection
      .prepare(
        `UPDATE runs SET status = 'queued', revision = revision + 1,
           active_worker_launch_id = NULL, latest_checkpoint_id = ?, updated_at = ?
         WHERE id = ? AND status = 'running' AND revision = ? AND active_worker_launch_id = ?`
      )
      .run(checkpoint.id, now, run.id, BigInt(run.revision), launch.launchId);
    if (update.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'Run checkpoint CAS failed');
    const updatedRun = readRun(connection, run.id);
    appendRunStateEvent(connection, updatedRun, now);
    result = { run: updatedRun, checkpoint, launch, generation };
  });
  requireHealthyFence(fenceOutcome);
  return result;
}
