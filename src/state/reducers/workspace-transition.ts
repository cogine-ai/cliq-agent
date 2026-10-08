import { assertArtifactRef } from '../../kernel/identity.js';
import { immutableSnapshot } from '../../model/immutable.js';
import type {
  WorkspaceGenerationStateV1,
  WorkspaceGenerationSnapshotEvidenceV1
} from '../../kernel/types.js';
import type { ArtifactCatalog } from '../artifacts.js';
import { insertArtifactMetadata } from '../artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import {
  decodeWorkspaceGenerationIdentity,
  decodeWorkspaceGenerationSnapshotEvidence,
  decodeWorkspaceEntries,
  decodeWorkspaceState
} from '../decoders.js';
import { KernelStorageError } from '../errors.js';
import { readRecoveryClosure } from '../recovery-closure.js';
import { requireEqual } from '../../policy/runtime-authority.js';
import { readRequiredWorkerLaunch } from '../repositories/worker-launches.js';
import {
  insertWorkspaceGeneration,
  readRequiredWorkspaceGeneration,
  readRequiredWorkspaceGenerationByRef,
  readWorkspaceGenerationsForRun,
  updateWorkspaceGeneration
} from '../repositories/workspace-generations.js';
import { readCheckpoint, readRun } from '../rows.js';
import type { SqliteDriver } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';

export type RegisterWorkspaceGenerationInput = {
  runId: string;
  generationRef: string;
  generationIdentityDigest: string;
};

function requireHealthyFence(outcome: TimeFenceAdvance | undefined): void {
  if (outcome === 'clock_regressed' || outcome === 'still_regressed') {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical clock is not healthy');
  }
}

export async function registerWorkspaceGeneration(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: RegisterWorkspaceGenerationInput
): Promise<WorkspaceGenerationStateV1> {
  input = immutableSnapshot(input);
  assertArtifactRef(input.generationRef);
  const identity = decodeWorkspaceGenerationIdentity(
    await artifacts.readCanonical(input.generationRef)
  );
  const identityMetadata = await artifacts.describe(
    input.generationRef,
    'application/json',
    'cliq-workspace-generation-identity-v1'
  );
  if (
    identity.identityDigest !== input.generationIdentityDigest ||
    identity.runId !== input.runId
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace generation identity does not match the request');
  }
  const checkpoint = readCheckpoint(driver, identity.sourceCheckpointId);
  if (checkpoint.runId !== input.runId || checkpoint.workspaceStateRef !== identity.sourceWorkspaceStateRef) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace generation source Checkpoint does not match');
  }
  const workspaceState = decodeWorkspaceState(
    await artifacts.readCanonical(identity.sourceWorkspaceStateRef)
  );
  const sourceEntries = decodeWorkspaceEntries(
    await artifacts.readCanonical(workspaceState.entriesRef)
  );
  if (
    workspaceState.runId !== input.runId ||
    workspaceState.stateDigest !== identity.sourceWorkspaceStateDigest ||
    sourceEntries.treeDigest !== identity.sourceTreeDigest
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace generation source state does not match');
  }

  // Preparing a replacement is nonproductive. It must not clear or bypass the
  // exact worker-loss wait, and it may consume only that Run's latest ready cut.
  const selected = readRun(driver, input.runId);
  const recovery = selected.status === 'waiting' ? await readRecoveryClosure(driver, artifacts, input.runId) : undefined;
  if (recovery && (recovery.run.waitingReason !== 'reconciliation' || !recovery.run.waitingOnRef ||
      recovery.latestCheckpoint.id !== identity.sourceCheckpointId ||
      recovery.latestCheckpoint.workspaceStateRef !== identity.sourceWorkspaceStateRef ||
      recovery.workspaceGenerations.some(row => row.generationId === identity.generationId))) {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'replacement must be distinct and restore the exact worker recovery ready Checkpoint');
  }

  let created!: WorkspaceGenerationStateV1;
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (fenceOutcome !== 'healthy') return;
    const run = readRun(connection, input.runId);
    if (run.activeWorkerLaunchId !== undefined || (run.status !== 'queued' && !recovery)) {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'workspace generation requires a lease-free queued Run');
    }
    if (recovery) {
      requireEqual(run, recovery.run, 'replacement worker recovery Run');
      for (const launch of recovery.workerLaunches) {
        requireEqual(readRequiredWorkerLaunch(connection, launch.launchId), launch, 'replacement predecessor launch');
      }
      for (const generation of recovery.workspaceGenerations) {
        requireEqual(readRequiredWorkspaceGenerationByRef(connection, generation.generationRef), generation, 'replacement retained generation');
      }
      if (readWorkspaceGenerationsForRun(connection, run.id).some(row =>
        row.phase === 'materializing' || row.phase === 'preactivated_readonly')) {
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker recovery already has a nonproductive replacement');
      }
    }
    const lockedCheckpoint = readCheckpoint(connection, identity.sourceCheckpointId);
    if (
      lockedCheckpoint.runId !== input.runId ||
      lockedCheckpoint.workspaceStateRef !== identity.sourceWorkspaceStateRef
    ) {
      throw new KernelStorageError('REVISION_CONFLICT', 'workspace generation source Checkpoint changed');
    }
    created = {
      schemaVersion: 1,
      generationId: identity.generationId,
      runId: input.runId,
      generationRef: input.generationRef,
      generationIdentityDigest: identity.identityDigest,
      rowVersion: 1,
      sourceCheckpointId: identity.sourceCheckpointId,
      sourceWorkspaceStateRef: identity.sourceWorkspaceStateRef,
      sourceWorkspaceStateDigest: identity.sourceWorkspaceStateDigest,
      lastVerifiedTreeDigest: identity.sourceTreeDigest,
      updatedAt: now,
      phase: 'materializing'
    };
    insertArtifactMetadata(connection, identityMetadata, now);
    insertWorkspaceGeneration(connection, created);
  });
  requireHealthyFence(fenceOutcome);
  return created;
}

export type RecordWorkspaceGenerationPreactivatedInput = {
  generationId: string;
  expectedRowVersion: number;
  snapshotEvidenceRef: string;
  snapshotEvidenceDigest: string;
};

export async function recordWorkspaceGenerationPreactivated(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: RecordWorkspaceGenerationPreactivatedInput
): Promise<Extract<WorkspaceGenerationStateV1, { phase: 'preactivated_readonly' }>> {
  input = immutableSnapshot(input);
  assertArtifactRef(input.snapshotEvidenceRef);
  const evidence = decodeWorkspaceGenerationSnapshotEvidence(
    await artifacts.readCanonical(input.snapshotEvidenceRef)
  );
  const evidenceMetadata = await artifacts.describe(
    input.snapshotEvidenceRef,
    'application/json',
    'cliq-workspace-generation-snapshot-evidence-v1'
  );
  const evidenceWorkspaceState = decodeWorkspaceState(
    await artifacts.readCanonical(evidence.workspaceStateRef)
  );
  const evidenceEntries = decodeWorkspaceEntries(
    await artifacts.readCanonical(evidenceWorkspaceState.entriesRef)
  );
  if (
    evidence.evidenceDigest !== input.snapshotEvidenceDigest ||
    evidence.purpose !== 'materialized_from_checkpoint' ||
    evidenceWorkspaceState.stateDigest !== evidence.workspaceStateDigest ||
    evidenceWorkspaceState.entriesRef !== evidence.entriesRef ||
    evidenceEntries.treeDigest !== evidence.treeDigest ||
    evidenceWorkspaceState.privateGitStateRef !== evidence.privateGitStateRef
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'materialization evidence does not match');
  }

  let updated!: Extract<WorkspaceGenerationStateV1, { phase: 'preactivated_readonly' }>;
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (fenceOutcome !== 'healthy') return;
    const current = readRequiredWorkspaceGeneration(connection, input.generationId);
    if (current.phase !== 'materializing' || current.rowVersion !== input.expectedRowVersion) {
      throw new KernelStorageError('REVISION_CONFLICT', 'workspace generation is not at the expected materializing version');
    }
    assertSnapshotMatchesGeneration(evidence, current);
    updated = {
      ...current,
      phase: 'preactivated_readonly',
      rowVersion: current.rowVersion + 1,
      lastVerifiedTreeDigest: evidence.treeDigest,
      updatedAt: now,
      snapshotEvidenceRef: input.snapshotEvidenceRef,
      snapshotEvidenceDigest: evidence.evidenceDigest
    };
    insertArtifactMetadata(connection, evidenceMetadata, now);
    updateWorkspaceGeneration(connection, current, updated);
  });
  requireHealthyFence(fenceOutcome);
  return updated;
}

function assertSnapshotMatchesGeneration(
  evidence: WorkspaceGenerationSnapshotEvidenceV1,
  generation: WorkspaceGenerationStateV1
): void {
  if (
    evidence.runId !== generation.runId ||
    evidence.generationRef !== generation.generationRef ||
    evidence.generationIdentityDigest !== generation.generationIdentityDigest ||
    evidence.checkpointId !== generation.sourceCheckpointId ||
    evidence.workspaceStateRef !== generation.sourceWorkspaceStateRef ||
    evidence.workspaceStateDigest !== generation.sourceWorkspaceStateDigest
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'snapshot evidence is not bound to the workspace generation');
  }
}
