import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import type { BoundWorkerLaunch, InvocationJournalEntry, RecoveryClosureV1, WorkerDeathWait, WorkspaceGenerationQuarantineEvidenceV1,
  WorkspaceGenerationRetirementEvidenceV1, WorkspaceGenerationStateV1 } from '../kernel/types.js';
import { readNativeRetainedWorkerRetirement, type NativeRetainedWorkerRetirement } from '../sandbox/linux-worker.js';
import { readRetainedWorkspaceRetirement, type RetainedWorkspaceObservation } from '../workspace/run-workspace/generation.js';
import { type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { nextJournalSequence } from './repositories/journal.js';
import { readRequiredWorkerLaunch, updateWorkerLaunch } from './repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef, updateWorkspaceGeneration } from './repositories/workspace-generations.js';
import { readRun } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { assertInstalledBrokerQuiescence, type InstalledBrokerQuiescence } from './store.js';
import { hasOnlySettledPrivateToolUnknowns, readPrivateRollbackClaim, type PrivateToolRollbackV1 } from './private-tool-rollback.js';
import type { ToolRequestV1 } from '../kernel/tool-authorization.js';
import { decodeWorkspaceGenerationIdentity } from './decoders.js';
import { immutableSnapshot } from '../model/immutable.js';
import { prepareVerifierUnknownParentClosure } from './verifier-unknown-retirement.js';

declare const terminalRecoveryBrand: unique symbol;
/** Internal original-owner closure. A data/ref or a stopped row cannot mint it. */
export type WorkerRecoveryTerminalPlan = Readonly<{ [terminalRecoveryBrand]: true }>;
type RetiredGeneration = Extract<WorkspaceGenerationStateV1, { phase: 'retired' }>;
type Plan = {
  driver: SqliteDriver; owner: StateOwnerContext; cut: RecoveryClosureV1;
  metadata: PublishedArtifact[]; quarantineMetadata: PublishedArtifact[]; generation: RetiredGeneration;
  verifierAbandoned: import('../kernel/types.js').TerminalDetail['abandonedRetryInvocations'];
  rollback?: { prepared: InvocationJournalEntry; claim: InvocationJournalEntry; unknown: InvocationJournalEntry;
    evidence: PrivateToolRollbackV1; artifact: PublishedArtifact; request: ToolRequestV1 };
  reobserve(connection: SqliteConnection): void;
  validate(connection: SqliteConnection | SqliteDriver, now: string): void;
  validateQuarantined(connection: SqliteConnection, now: string): void;
  commitQuarantined(connection: SqliteConnection, now: string): void;
  commit(connection: SqliteConnection, now: string): void;
};
const plans = new WeakMap<WorkerRecoveryTerminalPlan, Plan>();

/** All artifacts are prepared while SQL retains its valid original worker wait.
 * The terminal reducer commits retirement with its Checkpoint/Session. A known
 * stopped publication may instead preserve the original Checkpoint and commit
 * only quarantine, then use the existing physical quarantine-retirement path. */
export async function prepareWorkerRecoveryTerminalPlan(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, input: {
    cut: RecoveryClosureV1; wait: WorkerDeathWait; launch: BoundWorkerLaunch;
    generation: Extract<WorkspaceGenerationStateV1, { phase: 'fenced_reconciling' }>;
    quarantine: Extract<WorkspaceGenerationQuarantineEvidenceV1, { reason: 'worker_recovery' }>;
    quarantineArtifact: PublishedArtifact; wrapperArtifact: PublishedArtifact; metadata: PublishedArtifact[];
    nativeRetirement: NativeRetainedWorkerRetirement; workspaceRetirement: RetainedWorkspaceObservation;
    brokerQuiescence: InstalledBrokerQuiescence;
  }): Promise<WorkerRecoveryTerminalPlan> {
  // Copy retained data only. Opaque native owners below must remain the exact
  // original objects registered by their physical producers.
  const cut = immutableSnapshot(input.cut), wait = immutableSnapshot(input.wait), launch = immutableSnapshot(input.launch),
    generation = immutableSnapshot(input.generation), quarantine = immutableSnapshot(input.quarantine), run = cut.run;
  const inspector = assertActiveStateOwner(driver, owner);
  if (!run.stopIntentRef || run.status !== 'waiting' || run.waitingReason !== 'reconciliation' ||
      run.waitingOnRef !== canonicalSha256(wait) || wait.subject.kind !== 'worker_death' ||
      wait.probeState.phase !== 'automatic_in_flight' || wait.probeState.dispatch.owningSupervisorInstanceId !== owner.supervisorInstanceId ||
      launch.phase !== 'reconciling' || launch.launchId !== wait.subject.oldWorkerLaunchId ||
      generation.waitingSubjectRef !== run.waitingOnRef || generation.generationRef !== wait.subject.workspaceGenerationRef ||
      quarantine.generationRef !== generation.generationRef || quarantine.reason !== 'worker_recovery' ||
      quarantine.evidenceDigest !== digestOmitting(quarantine, 'evidenceDigest') ||
      input.quarantineArtifact.ref !== canonicalSha256(quarantine)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'stopped recovery lacks its original worker wait and quarantine producer');
  }
  const dispatch = wait.probeState.dispatch;
  const identity = decodeWorkspaceGenerationIdentity(await artifacts.readCanonical(generation.generationRef));
  function observeNativeOwners(): readonly string[] {
    const native = readNativeRetainedWorkerRetirement(input.nativeRetirement);
    const workspace = readRetainedWorkspaceRetirement(owner.filesystem, input.workspaceRetirement);
    assertInstalledBrokerQuiescence(input.brokerQuiescence, driver, owner, run.id);
    const move = owner.filesystem.quarantineGeneration(identity, quarantine.sourceRowVersion);
    if (canonicalSha256(native.containment) !== launch.processContainmentRef ||
        workspace.generationRef !== generation.generationRef || workspace.generationIdentityDigest !== generation.generationIdentityDigest ||
        canonicalSha256(workspace.observedState) !== canonicalSha256(quarantine.observedState) ||
        move.quarantineCanonicalRootRelativePath !== quarantine.quarantineCanonicalRootRelativePath ||
        move.quarantineDeviceId !== quarantine.quarantineDeviceId || move.quarantineFileId !== quarantine.quarantineFileId) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'stopped recovery requires its original fresh joined native resource owners');
    }
    return Object.freeze([native.observedAt, workspace.observedAt]);
  }
  function assertFreshNativeOwners(observations: readonly string[], now: string): void {
    if (observations.some(time => time > now || parseCanonicalTime(now) - parseCanonicalTime(time) > 5000)) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'stopped recovery requires its original fresh joined native resource owners');
    }
  }
  const preparedObservations = observeNativeOwners();
  const observedAt = sampleCanonicalNow();
  assertFreshNativeOwners(preparedObservations, observedAt);
  const retirement: WorkspaceGenerationRetirementEvidenceV1 = { schemaVersion: 1,
    format: 'cliq-workspace-generation-retirement-evidence-v1', runId: run.id,
    generationRef: generation.generationRef, generationIdentityDigest: generation.generationIdentityDigest,
    inspectorIdentityRef: quarantine.inspectorIdentityRef, inspectorIdentityDigest: quarantine.inspectorIdentityDigest,
    observedAt, evidenceDigest: '', fromPhase: 'quarantined', quarantineEvidenceRef: input.quarantineArtifact.ref,
    quarantineEvidenceDigest: quarantine.evidenceDigest, sourceQuarantinedRowVersion: generation.rowVersion + 1,
    activeRunPointerCount: 0, nonretiredWorkerLaunchCount: 0, liveContainmentCount: 0,
    activeMountCount: 0, releasableBrokerClaimCount: 0 };
  retirement.evidenceDigest = digestOmitting(retirement, 'evidenceDigest');
  const artifact = await artifacts.publishCanonical(retirement, retirement.format);
  const verifier = await prepareVerifierUnknownParentClosure(driver, artifacts, cut, { launch, generation,
    quarantine, quarantineRef: input.quarantineArtifact.ref, retirement, retirementRef: artifact.ref });
  let rollback: Plan['rollback'];
  if (hasOnlySettledPrivateToolUnknowns(cut.journal)) {
    const unknown = [...cut.journal].reverse().find(entry => entry.phase === 'unknown' && entry.opKind === 'tool')!;
    const prepared = cut.journal.find(entry => entry.opId === unknown.opId && entry.attempt === unknown.attempt && entry.phase === 'prepared')!;
    const claim = cut.journal.find(entry => entry.opId === unknown.opId && entry.attempt === unknown.attempt && entry.phase === 'dispatch_claimed')!;
    const { request, spec } = await readPrivateRollbackClaim(artifacts, prepared, claim, unknown, generation);
    if (spec.owner.workerLaunchId !== launch.launchId || spec.parentWorkerContainmentRef !== launch.processContainmentRef ||
        generation.sourceWorkspaceStateRef !== cut.latestCheckpoint.workspaceStateRef)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'private rollback differs from the original worker or last ready Checkpoint');
    const evidence: PrivateToolRollbackV1 = { schemaVersion: 1, format: 'cliq-private-tool-rollback-v1', code: 'TOOL_EXECUTION_FAILED',
      failureKind: 'private_effect_rolled_back', runId: run.id, opId: prepared.opId, attempt: prepared.attempt,
      dispatchId: claim.dispatchId!, preparedJournalSeq: prepared.seq, claimJournalSeq: claim.seq, unknownJournalSeq: unknown.seq,
      requestRef: prepared.requestRef, targetRef: prepared.target, grantRef: prepared.grantRef!, sandboxLaunchSpecRef: claim.sandboxLaunchSpecRef!,
      workerLaunchId: launch.launchId, leaseEpoch: launch.leaseEpoch!, generationRef: generation.generationRef,
      generationIdentityDigest: generation.generationIdentityDigest, checkpointId: cut.latestCheckpoint.id,
      workspaceStateRef: cut.latestCheckpoint.workspaceStateRef, quarantineEvidenceRef: input.quarantineArtifact.ref,
      quarantineEvidenceDigest: quarantine.evidenceDigest, retirementEvidenceRef: artifact.ref, retirementEvidenceDigest: retirement.evidenceDigest,
      inspectorIdentityRef: retirement.inspectorIdentityRef, inspectorIdentityDigest: retirement.inspectorIdentityDigest,
      observedAt: sampleCanonicalNow(), evidenceDigest: '' };
    evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest');
    rollback = { prepared, claim, unknown, evidence, request, artifact: await artifacts.publishCanonical(evidence, evidence.format) };
  }
  const base = { schemaVersion: generation.schemaVersion, generationId: generation.generationId, runId: generation.runId,
    generationRef: generation.generationRef, generationIdentityDigest: generation.generationIdentityDigest,
    rowVersion: generation.rowVersion, sourceCheckpointId: generation.sourceCheckpointId,
    sourceWorkspaceStateRef: generation.sourceWorkspaceStateRef, sourceWorkspaceStateDigest: generation.sourceWorkspaceStateDigest,
    lastVerifiedTreeDigest: generation.lastVerifiedTreeDigest, updatedAt: generation.updatedAt };
  const retired: RetiredGeneration = { ...base, phase: 'retired', rowVersion: generation.rowVersion + 2,
    retirementEvidenceRef: artifact.ref, retirementEvidenceDigest: retirement.evidenceDigest };
  let fresh: { connection: SqliteConnection; observations: readonly string[] } | undefined;
  function assertOriginalCut(connection: SqliteConnection | SqliteDriver): void {
    if (assertActiveStateOwner(connection, owner).ownerEpoch !== inspector.ownerEpoch ||
        canonicalSha256(readRun(connection, run.id)) !== canonicalSha256(run) ||
        canonicalSha256(readRequiredWorkerLaunch(connection, launch.launchId)) !== canonicalSha256(launch) ||
        canonicalSha256(readRequiredWorkspaceGenerationByRef(connection, generation.generationRef)) !== canonicalSha256(generation) ||
        nextJournalSequence(connection, run.id) !== cut.journal.length + 1) {
      throw new KernelStorageError('REVISION_CONFLICT', 'stopped recovery original wait or Journal changed before terminal commit');
    }
  }
  function validate(connection: SqliteConnection | SqliteDriver, now: string): void {
    assertOriginalCut(connection);
    if (now < observedAt || now >= dispatch.probeDeadlineAt ||
        parseCanonicalTime(now) - parseCanonicalTime(observedAt) > 5000) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'stopped recovery original probe or retirement observation expired');
    }
    if (!fresh || fresh.connection !== connection) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'stopped recovery has no original native observations for this transaction');
    }
    assertFreshNativeOwners(fresh.observations, now);
  }
  function commitGenerationQuarantine(connection: SqliteConnection, now: string) {
    const quarantined: Extract<WorkspaceGenerationStateV1, { phase: 'quarantined' }> = { ...base,
      phase: 'quarantined', rowVersion: generation.rowVersion + 1, updatedAt: now,
      quarantineEvidenceRef: input.quarantineArtifact.ref, quarantineEvidenceDigest: quarantine.evidenceDigest,
      observedState: quarantine.observedState };
    updateWorkspaceGeneration(connection, generation, quarantined);
    return quarantined;
  }
  function validateQuarantined(connection: SqliteConnection, now: string) {
    assertOriginalCut(connection);
    if (now < quarantine.observedAt || now >= dispatch.probeDeadlineAt)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'publication quarantine exceeds its original observation or worker probe');
    if (!fresh || fresh.connection !== connection)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'publication quarantine has no actual resource observations for this transaction');
    // This branch does not register/consume the separately prepared terminal
    // retirement artifact. Its own physical freshness is the actual same-FD
    // native/workspace observation just performed in this transaction.
    assertFreshNativeOwners(fresh.observations, now);
  }
  function retireLaunch(connection: SqliteConnection, now: string) {
    updateWorkerLaunch(connection, launch, { ...launch, phase: 'retired', retiredAt: now,
      retirementEvidenceRef: input.wrapperArtifact.ref });
  }
  const token = Object.freeze({}) as WorkerRecoveryTerminalPlan;
  plans.set(token, { driver, owner, cut, metadata: [...input.metadata, artifact, ...verifier.metadata, ...(rollback ? [rollback.artifact] : [])],
    quarantineMetadata: [...input.metadata],
    generation: retired, rollback, verifierAbandoned: verifier.abandoned,
    reobserve(connection) {
      // Each real native assertion produces a new physical observation time.
      // Finish all of them before the transaction's sole clock sample. Never
      // reuse an earlier attempt or refresh again after that canonical cut.
      fresh = undefined;
      assertOriginalCut(connection);
      const observations = observeNativeOwners();
      fresh = { connection, observations };
    },
    validate,
    validateQuarantined,
    commitQuarantined(connection, now) {
      validateQuarantined(connection, now);
      commitGenerationQuarantine(connection, now); retireLaunch(connection, now);
    },
    commit(connection, now) {
      validate(connection, now);
      const quarantined = commitGenerationQuarantine(connection, now);
      // Both monotone CAS transitions belong to this one terminal transaction;
      // no reader can observe a worker wait whose required fenced row vanished.
      updateWorkspaceGeneration(connection, quarantined, { ...retired, updatedAt: now });
      retireLaunch(connection, now);
    } });
  return token;
}

export function readWorkerRecoveryTerminalPlan(driver: SqliteDriver, owner: StateOwnerContext,
  token: WorkerRecoveryTerminalPlan, runId: string) {
  const plan = plans.get(token);
  if (!plan || plan.driver !== driver || plan.owner !== owner || plan.cut.run.id !== runId)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'terminal worker recovery requires its exact original live producer');
  return plan;
}
