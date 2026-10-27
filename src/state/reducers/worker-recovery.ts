import { randomBytes } from 'node:crypto';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { addCanonicalDuration, digestOmitting, identityHash, sha256Bytes } from '../../kernel/identity.js';
import type { ReconciliationProbeCancellationClosureV1 } from '../../kernel/reconciliation.js';
import type { ProcessContainmentDeathEvidenceV1, ReconciliationProbeEvidenceV1, ReconciliationProbeTimeoutClosureV1, Run, SupervisorInspectorIdentityV1,
  WorkerDeathWait, WorkerRecoveryEvidenceV1, WorkspaceGenerationQuarantineEvidenceV1, WorkspaceGenerationStateV1 } from '../../kernel/types.js';
import { immutableSnapshot } from '../../model/immutable.js';
import { decodeRetainedRunAssembly } from '../../model/run-assembly.js';
import { exactKeys } from '../../policy/runtime-authority.js';
import { assertNativeContainmentDeath, type NativeContainmentDeathObservation, type NativeRetainedWorkerRetirement } from '../../sandbox/linux-worker.js';
import { observeRetainedRunWorkspace, readRetainedWorkspaceObservation } from '../../workspace/run-workspace/generation.js';
import { insertArtifactMetadata, type ArtifactCatalog } from '../artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import { joinResourceOperations, KernelStorageError, stateOperation } from '../errors.js';
import { readRetainedWorkerLaunchClosure } from '../execution-closure.js';
import { readRecoveryClosure } from '../recovery-closure.js';
import { nextJournalSequence, readInvocationJournal } from '../repositories/journal.js';
import { readRequiredWorkerLaunch, readWorkerLaunchesForRun, updateWorkerLaunch } from '../repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef, readWorkspaceGenerationsForRun, updateWorkspaceGeneration } from '../repositories/workspace-generations.js';
import { readRun } from '../rows.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';
import { hasOnlySettledInstalledModelUnknowns, openWorkerInvocations, readWorkerProbeOwnerDeath, readWorkerRecoveryAnchor, WORKER_PROBE_BACKOFF_MS } from '../worker-recovery.js';
import { assertWorkerRecoveryTaskReceipt, type WorkerRecoveryTaskReceipt } from '../worker-recovery-task.js';
import { assertInstalledBrokerQuiescence, type InstalledBrokerQuiescence } from '../store.js';
import { appendRunStateEvent, requireHealthyFence } from './invocation.js';
import { prepareWorkerRecoveryTerminalPlan, type WorkerRecoveryTerminalPlan } from '../worker-recovery-terminal.js';
import { hasOnlySettledPrivateToolUnknowns } from '../private-tool-rollback.js';
import { hasOnlySettledVerifierUnknowns } from '../verifier-unknown-retirement.js';

export type BeginWorkerRecoveryInput = { runId: string; expectedRunRevision: number };

export const closeWorkerRecoveryProbe = stateOperation('RECOVERY_REQUIRED', async (
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: BeginWorkerRecoveryInput,
  joinedTask?: WorkerRecoveryTaskReceipt, closureKind: 'deadline' | 'shutdown' = 'deadline'
): Promise<Run> => {
  input = immutableSnapshot(input);
  if (!exactKeys(input, ['runId', 'expectedRunRevision']) || typeof input.runId !== 'string' || !input.runId ||
      !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1 ||
      !['deadline', 'shutdown'].includes(closureKind)) {
    throw new KernelStorageError('INVALID_REQUEST', 'worker timeout requires a Run id and expected revision only');
  }
  const inspectingOwner = assertActiveStateOwner(driver, owner);
  const cut = await readRecoveryClosure(driver, artifacts, input.runId);
  const { run } = cut;
  if (run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'worker timeout Run revision changed');
  if (run.status !== 'waiting' || run.waitingReason !== 'reconciliation' || !run.waitingOnRef) {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker timeout requires an installed inspection');
  }
  const wait = await artifacts.readCanonical<WorkerDeathWait>(run.waitingOnRef);
  if (wait.probeState.phase !== 'automatic_in_flight' || wait.probeState.dispatch.subjectKind !== 'worker_recovery') {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker timeout has no exact in-flight worker task');
  }
  const dispatch = wait.probeState.dispatch;
  const closedAt = sampleCanonicalNow();
  if (closureKind === 'deadline' && closedAt < dispatch.probeDeadlineAt)
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker inspection deadline has not elapsed');
  let taskClosure;
  if (dispatch.owningSupervisorInstanceId === inspectingOwner.supervisorInstanceId) {
    assertWorkerRecoveryTaskReceipt(joinedTask, { run, wait, owner }, closedAt);
    taskClosure = { closureKind: 'cancelled_and_joined' as const, inspectorTaskCancelledAndJoined: true as const };
  } else {
    if (closureKind === 'shutdown') throw new KernelStorageError('RECOVERY_REQUIRED', 'shutdown cannot adopt another owner worker inspection');
    if (joinedTask !== undefined) throw new KernelStorageError('RECOVERY_REQUIRED', 'successor cannot substitute a task receipt for observed owner death');
    taskClosure = await readWorkerProbeOwnerDeath(artifacts, driver, dispatch);
  }
  const inspector: SupervisorInspectorIdentityV1 = { schemaVersion: 1, format: 'cliq-supervisor-inspector-identity-v1',
    supervisorInstanceId: inspectingOwner.supervisorInstanceId, stateOwnerEpoch: inspectingOwner.ownerEpoch,
    runtimeBundleRef: inspectingOwner.runtimeBundleRef, runtimeBundleManifestDigest: inspectingOwner.runtimeBundleManifestDigest,
    supervisorEntryId: inspectingOwner.supervisorEntryId, supervisorEntryVersion: inspectingOwner.supervisorEntryVersion,
    supervisorExecutableDigest: inspectingOwner.supervisorExecutableDigest, processIdentityRef: inspectingOwner.processIdentityRef,
    processIdentityDigest: inspectingOwner.processIdentityDigest, stateLockIdentityRef: inspectingOwner.stateLockIdentityRef,
    stateLockIdentityDigest: inspectingOwner.stateLockIdentityDigest, instanceNonceDigest: inspectingOwner.instanceNonceDigest,
    activatedAt: inspectingOwner.acquiredAt, identityDigest: '' };
  inspector.identityDigest = digestOmitting(inspector, 'identityDigest');
  const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const inspectorPair = { inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest };
  const common = { schemaVersion: 1 as const, runId: run.id, waitingSubjectRef: run.waitingOnRef, probeKind: 'automatic' as const, probeOrdinal: dispatch.probeOrdinal,
    probeNonceDigest: dispatch.probeNonceDigest, probeDispatchDigest: dispatch.dispatchDigest, probeDeadlineAt: dispatch.probeDeadlineAt,
    ...inspectorPair, closedAt, closureDigest: '', subjectKind: 'worker_recovery' as const, oldWorkerLaunchId: wait.subject.oldWorkerLaunchId,
    processContainmentRef: wait.subject.processContainmentRef, inspectorTaskId: dispatch.inspectorTaskId };
  const closure: Extract<ReconciliationProbeCancellationClosureV1 | ReconciliationProbeTimeoutClosureV1, { subjectKind: 'worker_recovery' }> =
    closureKind === 'shutdown' ? { ...common, format: 'cliq-reconciliation-probe-cancellation-closure-v1', reason: 'owning_supervisor_shutdown',
      taskClosure: taskClosure as Extract<typeof taskClosure, { closureKind: 'cancelled_and_joined' }> }
      : { ...common, format: 'cliq-reconciliation-probe-timeout-closure-v1', taskClosure };
  closure.closureDigest = digestOmitting(closure, 'closureDigest');
  const closureArtifact = await artifacts.publishCanonical(closure, closure.format);
  const wrapper: ReconciliationProbeEvidenceV1 = { schemaVersion: 1, format: 'cliq-reconciliation-probe-evidence-v1', runId: run.id,
    waitingSubjectRef: run.waitingOnRef, waitingSubjectDigest: run.waitingOnRef, probeKind: 'automatic', probeOrdinal: dispatch.probeOrdinal,
    probeNonceDigest: dispatch.probeNonceDigest, probeDispatchDigest: dispatch.dispatchDigest, probeStartedAt: dispatch.probeStartedAt,
    probeDeadlineAt: dispatch.probeDeadlineAt, ...inspectorPair, observedAt: closedAt, evidenceDigest: '', ...(closureKind === 'shutdown'
      ? { outcome: 'probe_cancelled' as const, cancellationReason: 'owning_supervisor_shutdown' as const,
        cancellationClosureRef: closureArtifact.ref, cancellationClosureDigest: closure.closureDigest }
      : { outcome: 'probe_timeout' as const, timeoutReason: 'no_authoritative_observation_before_deadline' as const,
        timeoutClosureRef: closureArtifact.ref, timeoutClosureDigest: closure.closureDigest }) };
  wrapper.evidenceDigest = digestOmitting(wrapper, 'evidenceDigest');
  const wrapperArtifact = await artifacts.publishCanonical(wrapper, wrapper.format);
  const evidence = { lastProbeEvidenceRef: wrapperArtifact.ref, lastProbeEvidenceDigest: wrapper.evidenceDigest };
  const count = wait.probeState.automaticProbeCount;
  const backoffFrom = closedAt < dispatch.probeDeadlineAt ? dispatch.probeDeadlineAt : closedAt;
  const nextWait: WorkerDeathWait = { ...wait, probeState: count === 8
    ? { phase: 'automatic_exhausted', automaticProbeCount: 8, userProbeCount: 0, ...evidence }
    : { phase: 'automatic_pending', automaticProbeCount: count, userProbeCount: 0,
      nextProbeAt: addCanonicalDuration(backoffFrom, WORKER_PROBE_BACKOFF_MS[count - 1]!), ...evidence } };
  const nextWaitArtifact = await artifacts.publishCanonical(nextWait, 'cliq-waiting-subject-v1');
  const launch = cut.workerLaunches[0]!;
  const generation = cut.workspaceGenerations.find(value => value.generationRef === wait.subject.workspaceGenerationRef)!;
  if (generation.phase !== 'fenced_reconciling') throw new KernelStorageError('RECOVERY_REQUIRED', 'worker timeout has no exact fenced generation');
  let outcome: TimeFenceAdvance | undefined, updated!: Run;
  driver.transaction(connection => {
    assertActiveStateOwner(connection, owner);
    if (canonicalSha256(readRun(connection, run.id)) !== canonicalSha256(run) ||
        canonicalSha256(readRequiredWorkerLaunch(connection, launch.launchId)) !== canonicalSha256(launch) ||
        canonicalSha256(readRequiredWorkspaceGenerationByRef(connection, generation.generationRef)) !== canonicalSha256(generation) ||
        nextJournalSequence(connection, run.id) !== cut.journal.length + 1) {
      throw new KernelStorageError('REVISION_CONFLICT', 'worker timeout cut changed before its nonce closure');
    }
    const now = sampleCanonicalNow();
    outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (outcome !== 'healthy') return;
    if (now < closedAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'worker timeout commit precedes its task closure');
    for (const artifact of [inspectorArtifact, closureArtifact, wrapperArtifact, nextWaitArtifact]) insertArtifactMetadata(connection, artifact, now);
    updateWorkspaceGeneration(connection, generation, { ...generation, rowVersion: generation.rowVersion + 1,
      updatedAt: now, waitingSubjectRef: nextWaitArtifact.ref, waitingSubjectDigest: nextWaitArtifact.ref });
    connection.prepare('UPDATE runs SET waiting_on_ref=?, revision=revision+1, updated_at=? WHERE id=?')
      .run(nextWaitArtifact.ref, now, run.id);
    updated = readRun(connection, run.id);
    appendRunStateEvent(connection, updated, now);
  });
  requireHealthyFence(outcome);
  return immutableSnapshot(updated);
});

export const beginWorkerRecoveryProbe = stateOperation('RECOVERY_REQUIRED', async (
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: BeginWorkerRecoveryInput,
  onCommitted?: (run: Run, wait: WorkerDeathWait) => void
): Promise<Run> => {
  input = immutableSnapshot(input);
  if (!exactKeys(input, ['runId', 'expectedRunRevision']) || typeof input.runId !== 'string' || !input.runId ||
      !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1) {
    throw new KernelStorageError('INVALID_REQUEST', 'worker inspection requires a Run id and expected revision only');
  }
  assertActiveStateOwner(driver, owner);
  const cut = await readRecoveryClosure(driver, artifacts, input.runId);
  const { run } = cut;
  if (run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'worker inspection Run revision changed');
  if (run.status !== 'waiting' || run.waitingReason !== 'reconciliation' || !run.waitingOnRef) {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker inspection requires the installed worker wait');
  }
  const wait = await artifacts.readCanonical<WorkerDeathWait>(run.waitingOnRef);
  if (wait.subject.kind !== 'worker_death' || wait.probeState.phase !== 'automatic_pending') {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker inspection cannot replace an in-flight dispatch');
  }
  const generation = cut.workspaceGenerations.find(value => value.generationRef === wait.subject.workspaceGenerationRef)!;
  if (generation.phase !== 'fenced_reconciling') throw new KernelStorageError('RECOVERY_REQUIRED', 'worker inspection has no exact fenced generation');
  const launch = cut.workerLaunches[0]!;
  const probeStartedAt = sampleCanonicalNow();
  if (probeStartedAt < wait.probeState.nextProbeAt) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker inspection is not due');
  const probeOrdinal = (wait.probeState.automaticProbeCount + 1) as 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;
  const reconciliationSubjectDigest = canonicalSha256(wait.subject);
  const probeNonceDigest = sha256Bytes(randomBytes(32));
  const anchorArtifact = wait.probeState.automaticProbeCount === 0
    ? await artifacts.publishCanonical(generation, 'cliq-workspace-generation-state-v1') : undefined;
  const inspectionTargetDigest = anchorArtifact?.ref ?? canonicalSha256((await readWorkerRecoveryAnchor(artifacts, wait, generation)).anchor);
  const dispatch = { schemaVersion: 1 as const, format: 'cliq-reconciliation-probe-dispatch-v1' as const, runId: run.id,
    reconciliationSubjectDigest, probeKind: 'automatic' as const, probeOrdinal, probeNonceDigest, probeStartedAt,
    probeDeadlineAt: addCanonicalDuration(probeStartedAt, 30_000), owningSupervisorInstanceId: owner.supervisorInstanceId,
    subjectKind: 'worker_recovery' as const,
    inspectorTaskId: identityHash(run.id, reconciliationSubjectDigest, 'automatic', probeOrdinal, probeNonceDigest),
    inspectionTargetDigest, dispatchDigest: '' };
  dispatch.dispatchDigest = digestOmitting(dispatch, 'dispatchDigest');
  const nextWait: WorkerDeathWait = { ...wait, probeState: { phase: 'automatic_in_flight', automaticProbeCount: probeOrdinal,
    userProbeCount: 0, dispatch } };
  const metadata = [...(anchorArtifact ? [anchorArtifact] : []), ...await joinResourceOperations([artifacts.publishCanonical(dispatch, dispatch.format),
    artifacts.publishCanonical(nextWait, 'cliq-waiting-subject-v1')])];
  const waitingOnRef = canonicalSha256(nextWait);
  let outcome: TimeFenceAdvance | undefined, updated!: Run;
  driver.transaction(connection => {
    assertActiveStateOwner(connection, owner);
    if (canonicalSha256(readRun(connection, run.id)) !== canonicalSha256(run) ||
        canonicalSha256(readRequiredWorkerLaunch(connection, launch.launchId)) !== canonicalSha256(launch) ||
        canonicalSha256(readRequiredWorkspaceGenerationByRef(connection, generation.generationRef)) !== canonicalSha256(generation) ||
        nextJournalSequence(connection, run.id) !== cut.journal.length + 1) {
      throw new KernelStorageError('REVISION_CONFLICT', 'worker inspection cut changed before dispatch publication');
    }
    const now = sampleCanonicalNow();
    outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (outcome !== 'healthy') return;
    if (now < probeStartedAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'worker inspection commit precedes dispatch');
    for (const artifact of metadata) insertArtifactMetadata(connection, artifact, now);
    updateWorkspaceGeneration(connection, generation, { ...generation, rowVersion: generation.rowVersion + 1,
      updatedAt: now, waitingSubjectRef: waitingOnRef, waitingSubjectDigest: waitingOnRef });
    connection.prepare('UPDATE runs SET waiting_on_ref = ?, revision = revision + 1, updated_at = ? WHERE id = ?')
      .run(waitingOnRef, now, run.id);
    updated = readRun(connection, run.id);
    appendRunStateEvent(connection, updated, now);
  });
  requireHealthyFence(outcome);
  onCommitted?.(immutableSnapshot(updated), immutableSnapshot(nextWait));
  return immutableSnapshot(updated);
});

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
  const metadata = await joinResourceOperations([
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
      waitingSubjectRef: waitingOnRef, waitingSubjectDigest: waitingOnRef, fencedJournalSeq: cut.journal.length };
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

/** Internal owning reducer. A control client cannot supply proof, a path or a tree observation. */
export const completeWorkerRecoveryProbe = stateOperation('RECOVERY_REQUIRED', async (
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: BeginWorkerRecoveryInput,
  death: NativeContainmentDeathObservation, signal?: AbortSignal, brokerQuiescence?: InstalledBrokerQuiescence,
  stoppedOwner?: { retire(): Promise<NativeRetainedWorkerRetirement>; finish(plan: WorkerRecoveryTerminalPlan): Promise<Run> }
): Promise<Run> => {
  input = immutableSnapshot(input);
  signal?.throwIfAborted();
  assertNativeContainmentDeath(death);
  if (!exactKeys(input, ['runId', 'expectedRunRevision']) || typeof input.runId !== 'string' || !input.runId ||
      !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1) {
    throw new KernelStorageError('INVALID_REQUEST', 'worker recovery completion requires a Run id and expected revision');
  }
  const inspectingOwner = assertActiveStateOwner(driver, owner);
  let cut = await readRecoveryClosure(driver, artifacts, input.runId);
  signal?.throwIfAborted();
  let { run } = cut;
  if (run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'worker recovery completion Run revision changed');
  if (run.status !== 'waiting' || run.waitingReason !== 'reconciliation' || !run.waitingOnRef) {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker recovery completion has no installed inspection');
  }
  const workerWaitingSubjectRef = run.waitingOnRef;
  const wait = await artifacts.readCanonical<WorkerDeathWait>(workerWaitingSubjectRef);
  signal?.throwIfAborted();
  if (wait.subject.kind !== 'worker_death' || wait.probeState.phase !== 'automatic_in_flight' ||
      wait.probeState.dispatch.owningSupervisorInstanceId !== owner.supervisorInstanceId) {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker recovery completion cannot resolve another inspection nonce');
  }
  function refreshStopCut(connection: SqliteConnection): boolean {
    signal?.throwIfAborted();
    assertActiveStateOwner(connection, owner);
    const current = readRun(connection, run.id);
    const unchanged = canonicalSha256(current) === canonicalSha256(run);
    const stable = ({ revision: _revision, updatedAt: _time, stopIntentRef: _intent, cancelRequested: _cancel, parentCancellationRef: _parentCancellation, ...data }: Run) => data;
    if ((!unchanged && (!stoppedOwner || !brokerQuiescence || !current.stopIntentRef || current.revision <= run.revision ||
        current.updatedAt < run.updatedAt || run.cancelRequested && !current.cancelRequested ||
        canonicalSha256(stable(current)) !== canonicalSha256(stable(run)))) ||
        canonicalSha256(readInvocationJournal(connection, run.id)) !== canonicalSha256(cut.journal) ||
        canonicalSha256(readWorkerLaunchesForRun(connection, run.id, true)) !== canonicalSha256(cut.workerLaunches) ||
        canonicalSha256(readWorkspaceGenerationsForRun(connection, run.id)) !== canonicalSha256(cut.workspaceGenerations)) {
      throw new KernelStorageError('REVISION_CONFLICT', 'worker recovery completion cut changed');
    }
    if (unchanged) return false;
    run = current; cut = { ...cut, run };
    return true;
  }
  let open = openWorkerInvocations(cut.journal);
  if (cut.runSpec.operation === 'delivery' && open.length === 1 && open[0]!.opKind === 'publish') {
    const history = cut.journal.filter(row => row.opId === open[0]!.opId && row.attempt === open[0]!.attempt);
    if (history.length === 2 && history[1]!.phase === 'dispatch_claimed') {
      const publication = await import('../publication-invocation.js');
      const initial = await publication.prepareOwnedPublicationInitialAmbiguity(driver, artifacts, owner,
        { runId: run.id, expectedRunRevision: run.revision }, death, signal);
      const { preparePublicationInitialAmbiguitySettlement } = await import('../publication-settlement.js');
      const settlement = await preparePublicationInitialAmbiguitySettlement(driver, artifacts, owner, initial);
      await settlement.settle({ expectedRunRevision: run.revision });
      // The new CP is a true excluded-control continuation of the same W_M,
      // not the old generation fence or a replacement worker/path wait.
      const current = await readRecoveryClosure(driver, artifacts, run.id);
      if (current.run.status !== 'waiting' || current.run.waitingOnRef !== run.waitingOnRef ||
          current.latestCheckpoint.workspaceStateRef !== cut.latestCheckpoint.workspaceStateRef ||
          canonicalSha256(current.workerLaunches) !== canonicalSha256(cut.workerLaunches) ||
          canonicalSha256(current.workspaceGenerations) !== canonicalSha256(cut.workspaceGenerations))
        throw new KernelStorageError('RECOVERY_REQUIRED', 'initial publication ambiguity changed the original worker-death fence');
      cut = current; run = current.run; open = openWorkerInvocations(cut.journal);
    }
  }
  const assembly = open.length ? decodeRetainedRunAssembly(await artifacts.readCanonical(cut.runSpec.assemblyRef)) : undefined;
  let publicationUnknown: Awaited<ReturnType<typeof import('../publication-worker-retirement.js')['readUnresolvedPublicationWorkerCut']>> | undefined;
  // The closure, wait and assembly reads may yield to a real StopIntent. Decide
  // only after checking the current exact subject and immutable resource cut.
  refreshStopCut(driver);
  if (open.length !== 0) {
    // Effect ambiguity is not physical release authority. Only this exact
    // fully validated, fully charged broker branch may remain unknown while
    // its worker is quarantined; every other open invocation still blocks.
    const privateRollback = !!run.stopIntentRef && hasOnlySettledPrivateToolUnknowns(cut.journal);
    const undispatched = !!run.stopIntentRef && open.every(prepared => cut.journal.filter(entry =>
      entry.opId === prepared.opId && entry.attempt === prepared.attempt).length === 1);
    const publication = cut.runSpec.operation === 'delivery' && open.some(entry => entry.opKind === 'publish')
      ? await (await import('../publication-worker-retirement.js')).readUnresolvedPublicationWorkerCut(driver, artifacts, cut) : undefined;
    publicationUnknown = publication;
    if ((!hasOnlySettledInstalledModelUnknowns(assembly!, cut.journal) &&
        !(run.stopIntentRef && hasOnlySettledVerifierUnknowns(cut.journal)) &&
        !(run.stopIntentRef && (await import('../dependency-unknown-retirement.js')).hasOnlySettledDependencyUnknowns(cut.journal)) &&
        !privateRollback && !undispatched && !publication) || !brokerQuiescence) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'open worker invocations require their typed settlement or explicit manual-risk wait before quarantine');
    }
    assertInstalledBrokerQuiescence(brokerQuiescence, driver, owner, run.id);
    if (cut.workspaceGenerations.some(row => row.phase === 'materializing' || row.phase === 'preactivated_readonly')) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'unknown model worker quarantine cannot select an existing replacement generation');
    }
  }
  let stopping = !!run.stopIntentRef || run.cancelRequested || sampleCanonicalNow() >= run.deadlineAt;
  if (stopping && (!stoppedOwner || !run.stopIntentRef || !brokerQuiescence)) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'stopped worker recovery requires its terminal quiescence reducer');
  }
  const launch = cut.workerLaunches[0]!;
  const generation = cut.workspaceGenerations.find(value => value.generationRef === wait.subject.workspaceGenerationRef)!;
  if (generation.phase !== 'fenced_reconciling') throw new KernelStorageError('RECOVERY_REQUIRED', 'worker recovery has no exact fenced generation');
  const intent = await readWorkerRecoveryAnchor(artifacts, wait, generation);
  signal?.throwIfAborted();
  const closure = await readRetainedWorkerLaunchClosure(artifacts, inspectingOwner, { run, launch, generation });
  signal?.throwIfAborted();
  if (canonicalSha256(death.containment) !== launch.processContainmentRef || death.containment.backend.kind !== 'linux' ||
      death.observedAt < wait.probeState.dispatch.probeStartedAt || death.observedAt > wait.probeState.dispatch.probeDeadlineAt) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'native worker death does not observe this persisted inspection');
  }
  const workspaceRetirement = await observeRetainedRunWorkspace({ filesystem: owner.filesystem, artifacts,
    identity: closure.generation, sourceRowVersion: intent.sourceRowVersion, signal, gitResources: closure.spec.resources });
  const observation = readRetainedWorkspaceObservation(workspaceRetirement);
  signal?.throwIfAborted();
  if (observation.generationRef !== generation.generationRef || observation.generationIdentityDigest !== generation.generationIdentityDigest ||
      observation.observedAt < death.observedAt || observation.observedAt > wait.probeState.dispatch.probeDeadlineAt) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'private generation observation does not bind this exact worker inspection');
  }
  const replacements = cut.workspaceGenerations.filter(value => value.phase === 'preactivated_readonly' &&
    value.generationRef !== generation.generationRef && value.sourceCheckpointId === cut.latestCheckpoint.id &&
    value.sourceWorkspaceStateRef === cut.latestCheckpoint.workspaceStateRef);
  if (replacements.length > 1) throw new KernelStorageError('RECOVERY_REQUIRED', 'worker recovery has multiple candidate replacement generations');
  const replacement = replacements[0];
  const probeDeadlineAt = wait.probeState.dispatch.probeDeadlineAt;
  // No await between the final cut/owner check and the descriptor-relative no-replace move.
  function requireCurrentCut(connection: SqliteConnection) {
    signal?.throwIfAborted();
    assertActiveStateOwner(connection, owner);
    publicationUnknown?.assertSourceCut(connection);
    if (open.length !== 0) {
      assertInstalledBrokerQuiescence(brokerQuiescence!, driver, owner, run.id);
      // A readonly replacement registration need not change Run revision or
      // Journal high-water. Re-read its inventory at both exact final cuts.
      if (readWorkspaceGenerationsForRun(connection, run.id).some(row =>
        row.phase === 'materializing' || row.phase === 'preactivated_readonly')) {
        throw new KernelStorageError('REVISION_CONFLICT', 'unknown model worker quarantine acquired a competing replacement generation');
      }
    }
    if (refreshStopCut(connection)) stopping = true;
    if (canonicalSha256(readRequiredWorkerLaunch(connection, launch.launchId)) !== canonicalSha256(launch) ||
        canonicalSha256(readRequiredWorkspaceGenerationByRef(connection, generation.generationRef)) !== canonicalSha256(generation) ||
        (replacement && canonicalSha256(readRequiredWorkspaceGenerationByRef(connection, replacement.generationRef)) !== canonicalSha256(replacement)) ||
        nextJournalSequence(connection, run.id) !== cut.journal.length + 1) {
      throw new KernelStorageError('REVISION_CONFLICT', 'worker recovery completion cut changed');
    }
    const now = sampleCanonicalNow();
    if (now >= probeDeadlineAt || (!stopping && now >= run.deadlineAt)) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'worker recovery inspection expired before its exact completion cut');
    }
    return now;
  }
  const observedAt = observation.observedAt;
  const inspector: SupervisorInspectorIdentityV1 = { schemaVersion: 1, format: 'cliq-supervisor-inspector-identity-v1',
    supervisorInstanceId: inspectingOwner.supervisorInstanceId, stateOwnerEpoch: inspectingOwner.ownerEpoch,
    runtimeBundleRef: inspectingOwner.runtimeBundleRef, runtimeBundleManifestDigest: inspectingOwner.runtimeBundleManifestDigest,
    supervisorEntryId: inspectingOwner.supervisorEntryId, supervisorEntryVersion: inspectingOwner.supervisorEntryVersion,
    supervisorExecutableDigest: inspectingOwner.supervisorExecutableDigest, processIdentityRef: inspectingOwner.processIdentityRef,
    processIdentityDigest: inspectingOwner.processIdentityDigest, stateLockIdentityRef: inspectingOwner.stateLockIdentityRef,
    stateLockIdentityDigest: inspectingOwner.stateLockIdentityDigest, instanceNonceDigest: inspectingOwner.instanceNonceDigest,
    activatedAt: inspectingOwner.acquiredAt, identityDigest: '' };
  inspector.identityDigest = digestOmitting(inspector, 'identityDigest');
  const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  signal?.throwIfAborted();
  const inspectorPair = { inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest };
  const deathEvidence: ProcessContainmentDeathEvidenceV1 = { schemaVersion: 1, kind: 'containment_all_descendants_dead',
    containmentRef: launch.processContainmentRef!, planRef: launch.containmentPlanRef, sandboxLaunchSpecRef: launch.sandboxLaunchSpecRef,
    sandboxLaunchSpecDigest: closure.spec.launchSpecDigest, owner: closure.plan.owner, launchNonceDigest: launch.spawnNonceDigest,
    inspectorSupervisorInstanceId: inspectingOwner.supervisorInstanceId, ...inspectorPair,
    backend: { ...death.containment.backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 },
    observedAt: death.observedAt, evidenceDigest: '' };
  deathEvidence.evidenceDigest = digestOmitting(deathEvidence, 'evidenceDigest');
  const deathArtifact = await artifacts.publishCanonical(deathEvidence, 'cliq-process-containment-death-evidence-v1');
  signal?.throwIfAborted();
  const recovery: WorkerRecoveryEvidenceV1 = { schemaVersion: 1, format: 'cliq-worker-recovery-evidence-v1', runId: run.id,
    waitingSubjectRef: workerWaitingSubjectRef, oldWorkerLaunchId: launch.launchId, oldLeaseEpoch: launch.leaseEpoch!,
    oldWorkerIdentityDigest: launch.workerIdentityDigest!, processContainmentRef: launch.processContainmentRef!,
    containmentDeathEvidenceRef: deathArtifact.ref, containmentDeathEvidenceDigest: deathEvidence.evidenceDigest,
    workspaceGenerationRef: generation.generationRef, generationTreeDigest: generation.lastVerifiedTreeDigest, ...inspectorPair,
    observedAt, evidenceDigest: '', ...(replacement ? { generationDisposition: 'restored_from_checkpoint',
      restoredCheckpointId: cut.latestCheckpoint.id, restoredWorkspaceStateRef: cut.latestCheckpoint.workspaceStateRef,
      replacementWorkspaceGenerationRef: replacement.generationRef } : { generationDisposition: 'quarantined' }) };
  recovery.evidenceDigest = digestOmitting(recovery, 'evidenceDigest');
  const recoveryArtifact = await artifacts.publishCanonical(recovery, recovery.format);
  signal?.throwIfAborted();
  requireCurrentCut(driver);
  const move = owner.filesystem.quarantineGeneration(closure.generation, intent.sourceRowVersion);
  const quarantineObservedAt = sampleCanonicalNow();
  const quarantine: WorkspaceGenerationQuarantineEvidenceV1 = { schemaVersion: 1, format: 'cliq-workspace-generation-quarantine-evidence-v1',
    runId: run.id, generationRef: generation.generationRef, generationIdentityDigest: generation.generationIdentityDigest,
    sourceRowVersion: intent.sourceRowVersion, observedState: observation.observedState, ...inspectorPair, ...move,
    observedAt: quarantineObservedAt, evidenceDigest: '', reason: 'worker_recovery', fromPhase: 'fenced_reconciling',
    workerRecoveryEvidenceRef: recoveryArtifact.ref, workerRecoveryEvidenceDigest: recovery.evidenceDigest };
  quarantine.evidenceDigest = digestOmitting(quarantine, 'evidenceDigest');
  const quarantineArtifact = await artifacts.publishCanonical(quarantine, quarantine.format);
  signal?.throwIfAborted();
  const wrapper: ReconciliationProbeEvidenceV1 = { schemaVersion: 1, format: 'cliq-reconciliation-probe-evidence-v1', runId: run.id,
    waitingSubjectRef: workerWaitingSubjectRef, waitingSubjectDigest: workerWaitingSubjectRef, probeKind: 'automatic',
    probeOrdinal: wait.probeState.automaticProbeCount, probeNonceDigest: wait.probeState.dispatch.probeNonceDigest,
    probeDispatchDigest: wait.probeState.dispatch.dispatchDigest, probeStartedAt: wait.probeState.dispatch.probeStartedAt,
    probeDeadlineAt: wait.probeState.dispatch.probeDeadlineAt, ...inspectorPair, observedAt, evidenceDigest: '',
    outcome: 'subject_observation', subjectEvidenceKind: 'worker_recovery', subjectEvidenceRef: recoveryArtifact.ref,
    subjectEvidenceDigest: recovery.evidenceDigest };
  wrapper.evidenceDigest = digestOmitting(wrapper, 'evidenceDigest');
  const wrapperArtifact = await artifacts.publishCanonical(wrapper, wrapper.format);
  signal?.throwIfAborted();
  const metadata = [inspectorArtifact, deathArtifact, recoveryArtifact, quarantineArtifact, wrapperArtifact];
  requireCurrentCut(driver);
  if (stopping) {
    if (launch.phase !== 'reconciling') throw new KernelStorageError('RECOVERY_REQUIRED', 'stopped recovery lost its original reconciling launch');
    const nativeRetirement = await stoppedOwner!.retire();
    requireCurrentCut(driver);
    const plan = await prepareWorkerRecoveryTerminalPlan(driver, artifacts, owner, { cut, wait, launch, generation,
      quarantine, quarantineArtifact, wrapperArtifact, metadata, nativeRetirement, workspaceRetirement,
      brokerQuiescence: brokerQuiescence! });
    if (cut.runSpec.operation === 'delivery' && cut.journal.some(entry => entry.opKind === 'publish' && entry.phase === 'dispatch_claimed')) {
      const { commitStoppedPublicationWorkerRetirement, commitUnresolvedPublicationWorkerRetirement } = await import('../publication-worker-retirement.js');
      return publicationUnknown ? commitUnresolvedPublicationWorkerRetirement(driver, artifacts, owner, plan, run.id, signal)
        : commitStoppedPublicationWorkerRetirement(driver, artifacts, owner, plan, run.id, signal);
    }
    return stoppedOwner!.finish(plan);
  }
  let outcome: TimeFenceAdvance | undefined, updated!: Run;
  driver.transaction(connection => {
    const now = requireCurrentCut(connection);
    if (now < quarantineObservedAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'worker recovery commit precedes its physical quarantine observation');
    outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (outcome !== 'healthy') return;
    for (const artifact of metadata) insertArtifactMetadata(connection, artifact, now);
    const next: WorkspaceGenerationStateV1 = { schemaVersion: 1, generationId: generation.generationId, runId: generation.runId,
      generationRef: generation.generationRef, generationIdentityDigest: generation.generationIdentityDigest,
      rowVersion: generation.rowVersion + 1, sourceCheckpointId: generation.sourceCheckpointId,
      sourceWorkspaceStateRef: generation.sourceWorkspaceStateRef, sourceWorkspaceStateDigest: generation.sourceWorkspaceStateDigest,
      lastVerifiedTreeDigest: generation.lastVerifiedTreeDigest, updatedAt: now, phase: 'quarantined',
      quarantineEvidenceRef: quarantineArtifact.ref, quarantineEvidenceDigest: quarantine.evidenceDigest, observedState: quarantine.observedState };
    updateWorkspaceGeneration(connection, generation, next);
    updateWorkerLaunch(connection, launch, { ...launch, phase: 'retired', retiredAt: now, retirementEvidenceRef: wrapperArtifact.ref });
    connection.prepare(`UPDATE runs SET status='queued', waiting_reason=NULL, waiting_on_ref=NULL,
      revision=revision+1, updated_at=? WHERE id=?`).run(now, run.id);
    updated = readRun(connection, run.id);
    appendRunStateEvent(connection, updated, now);
  });
  requireHealthyFence(outcome);
  return immutableSnapshot(updated);
});
