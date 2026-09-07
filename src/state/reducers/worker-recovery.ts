import { canonicalSha256 } from '../../kernel/canonical.js';
import type { Run, WorkerDeathWait, WorkspaceGenerationStateV1 } from '../../kernel/types.js';
import { immutableSnapshot } from '../../model/immutable.js';
import { exactKeys } from '../../policy/runtime-authority.js';
import { insertArtifactMetadata, type ArtifactCatalog } from '../artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import { KernelStorageError, stateOperation } from '../errors.js';
import { readRecoveryClosure } from '../recovery-closure.js';
import { nextJournalSequence } from '../repositories/journal.js';
import { readRequiredWorkerLaunch, updateWorkerLaunch } from '../repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef, updateWorkspaceGeneration } from '../repositories/workspace-generations.js';
import { readRun } from '../rows.js';
import type { SqliteDriver } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';
import { openWorkerInvocations } from '../worker-recovery.js';
import { appendRunStateEvent, requireHealthyFence } from './invocation.js';

export type BeginWorkerRecoveryInput = { runId: string; expectedRunRevision: number };

/** Revocation, never death proof. The Supervisor must install this wait before any worker-loss quarantine. */
export const beginWorkerRecovery = stateOperation('RECOVERY_REQUIRED', async (
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: BeginWorkerRecoveryInput
): Promise<Run> => {
  input = immutableSnapshot(input);
  if (!exactKeys(input, ['runId', 'expectedRunRevision']) || typeof input.runId !== 'string' || !input.runId ||
      !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1) {
    throw new KernelStorageError('INVALID_REQUEST', 'worker recovery requires a Run id and expected revision only');
  }
  assertActiveStateOwner(driver, owner);
  const cut = await readRecoveryClosure(driver, artifacts, input.runId);
  const { run } = cut;
  if (run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'worker recovery Run revision changed');
  const launch = cut.workerLaunches.find(launch => launch.launchId === run.activeWorkerLaunchId);
  const generation = cut.workspaceGenerations.find(generation => generation.generationRef === launch?.workspaceGenerationRef);
  if (run.status !== 'running' || !run.frontierRef || !launch || !generation || cut.workerLaunches.length !== 1 ||
      launch.phase !== 'activated' || !launch.workerIdentityDigest || !launch.processContainmentRef ||
      (generation.phase !== 'active' && generation.phase !== 'revoking' && generation.phase !== 'checkpointing')) {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker recovery requires the exact activated worker and pointer-bound generation');
  }
  const createdAt = sampleCanonicalNow();
  const open = openWorkerInvocations(cut.journal);
  const wait: WorkerDeathWait = {
    schemaVersion: 1, kind: 'reconciliation', runId: run.id, createdFromRevision: run.revision,
    createdAt, frontierRef: run.frontierRef,
    subject: { kind: 'worker_death', oldWorkerLaunchId: launch.launchId, oldLeaseEpoch: run.leaseEpoch,
      oldWorkerIdentity: launch.workerIdentityDigest, processContainmentRef: launch.processContainmentRef,
      workspaceGenerationRef: generation.generationRef, openInvocationRefs: open.map(canonicalSha256) },
    probeState: { phase: 'automatic_pending', automaticProbeCount: 0, userProbeCount: 0, nextProbeAt: createdAt }
  };
  const metadata = await Promise.all([
    ...open.map(entry => artifacts.publishCanonical(entry, 'cliq-invocation-journal-entry-v1')),
    artifacts.publishCanonical(wait, 'cliq-waiting-subject-v1')
  ]);
  const waitingOnRef = canonicalSha256(wait);
  let outcome: TimeFenceAdvance | undefined, updated!: Run;
  driver.transaction(connection => {
    assertActiveStateOwner(connection, owner);
    if (canonicalSha256(readRun(connection, run.id)) !== canonicalSha256(run) ||
        canonicalSha256(readRequiredWorkerLaunch(connection, launch.launchId)) !== canonicalSha256(launch) ||
        canonicalSha256(readRequiredWorkspaceGenerationByRef(connection, generation.generationRef)) !== canonicalSha256(generation) ||
        nextJournalSequence(connection, run.id) !== cut.journal.length + 1) {
      throw new KernelStorageError('REVISION_CONFLICT', 'worker recovery cut changed before its fence transaction');
    }
    const now = sampleCanonicalNow();
    outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (outcome !== 'healthy') return;
    if (now < createdAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'worker recovery commit precedes its wait');
    const fence = { phase: 'fenced_reconciling' as const, rowVersion: generation.rowVersion + 1, updatedAt: now,
      waitingSubjectRef: waitingOnRef, waitingSubjectDigest: waitingOnRef };
    const fenced: WorkspaceGenerationStateV1 = generation.phase === 'active'
      ? { ...generation, ...fence, fencedFromPhase: 'active' }
      : { ...generation, ...fence, fencedFromPhase: generation.phase };
    for (const artifact of metadata) insertArtifactMetadata(connection, artifact, now);
    updateWorkspaceGeneration(connection, generation, fenced);
    updateWorkerLaunch(connection, launch, { ...launch, phase: 'reconciling', generationWriteState: 'fenced_reconciling' });
    connection.prepare(`UPDATE runs SET status = 'waiting', waiting_reason = 'reconciliation', waiting_on_ref = ?,
      active_worker_launch_id = NULL, revision = revision + 1, updated_at = ? WHERE id = ?`)
      .run(waitingOnRef, now, run.id);
    updated = readRun(connection, run.id);
    appendRunStateEvent(connection, updated, now);
  });
  requireHealthyFence(outcome);
  return immutableSnapshot(updated);
});
