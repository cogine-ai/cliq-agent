import { canonicalSha256 } from '../kernel/canonical.js';
import { addCanonicalDuration, assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { InvocationJournalEntry, ProcessContainmentDeathEvidenceV1, ReconciliationProbeDispatchV1, ReconciliationProbeEvidenceV1,
  ReconciliationProbeTimeoutClosureV1, ReconciliationInspectorTaskClosureV1,
  RecoveryClosureV1, SupervisorInspectorIdentityV1, WorkerDeathWait, WorkerRecoveryEvidenceV1,
  WorkspaceGenerationQuarantineEvidenceV1, WorkspaceGenerationStateV1 } from '../kernel/types.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';
import { joinResourceOperations } from './errors.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readStateOwner } from './state-owner.js';
import { readStateOwnerDeath } from './state-owner-death.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef } from './repositories/workspace-generations.js';
import { readCheckpoint } from './rows.js';
import { decodeRunSpec, decodeStateOwnerAcquisitionEvidence, decodeWorkerIdentity, decodeWorkspaceGenerationIdentity } from './decoders.js';
import { decodeWorkspaceGenerationState } from './invariants.js';
import { decodeWorkerContainmentPlan, decodeWorkerProcessContainment, decodeWorkerSandboxLaunchSpec } from './execution-closure.js';

/** Immutable witnesses of existing Journal facts, not a second invocation state machine. */
export function openWorkerInvocations(journal: readonly InvocationJournalEntry[]): InvocationJournalEntry[] {
  const latest = new Map<string, InvocationJournalEntry>();
  for (const entry of journal) latest.set(`${entry.opId}\0${entry.attempt}`, entry);
  return journal.filter(entry => entry.phase === 'prepared' &&
    ['prepared', 'dispatch_claimed', 'unknown'].includes(latest.get(`${entry.opId}\0${entry.attempt}`)!.phase));
}

type WorkerCut = Pick<RecoveryClosureV1, 'run' | 'journal' | 'workerLaunches' | 'workspaceGenerations'>;

export const WORKER_PROBE_BACKOFF_MS = [1000, 5000, 30_000, 120_000, 600_000, 1_800_000, 3_600_000] as const;

/** Retained acquisition closes this exact dead owner's task, not the worker containment. */
export async function readWorkerProbeOwnerDeath(artifacts: ArtifactCatalog, driver: SqliteDriver,
  dispatch: ReconciliationProbeDispatchV1) {
  const death = await readStateOwnerDeath(artifacts, driver,
    { supervisorInstanceId: dispatch.owningSupervisorInstanceId, ownedAt: dispatch.probeStartedAt });
  return { closureKind: 'owner_process_dead' as const, ownerDeathAcquisitionEvidenceRef: death.acquisitionEvidenceRef,
    ownerDeathAcquisitionEvidenceDigest: death.acquisitionEvidenceDigest };
}

/** The first real fenced row is a retained inspection target, not permission to mutate it. */
export async function readWorkerRecoveryAnchor(artifacts: ArtifactCatalog, wait: WorkerDeathWait, generation: WorkspaceGenerationStateV1) {
  let inspection = wait;
  let closed = false;
  if ((wait.probeState.phase === 'automatic_pending' && wait.probeState.automaticProbeCount > 0) || wait.probeState.phase === 'automatic_exhausted') {
    const wrapper = await readCanonicalArtifact<ReconciliationProbeEvidenceV1>(artifacts, wait.probeState.lastProbeEvidenceRef!);
    if (wrapper.evidenceDigest !== wait.probeState.lastProbeEvidenceDigest || wrapper.evidenceDigest !== digestOmitting(wrapper, 'evidenceDigest')) {
      throw new TypeError('worker quarantine intent has no retained closed probe');
    }
    inspection = await readCanonicalArtifact<WorkerDeathWait>(artifacts, wrapper.waitingSubjectRef);
    requireEqual({ ...inspection, probeState: wait.probeState }, wait, 'worker closed probe frozen wait');
    if (inspection.probeState.automaticProbeCount !== wait.probeState.automaticProbeCount) throw new TypeError('worker closed probe count changed');
    closed = true;
  }
  if (inspection.probeState.phase !== 'automatic_in_flight' || inspection.probeState.dispatch.subjectKind !== 'worker_recovery') {
    throw new TypeError('worker quarantine intent requires its persisted worker inspection');
  }
  const anchor = decodeWorkspaceGenerationState(await readCanonicalArtifact(artifacts, inspection.probeState.dispatch.inspectionTargetDigest));
  if (anchor.phase !== 'fenced_reconciling' || anchor.waitingSubjectDigest !== anchor.waitingSubjectRef ||
      !Number.isSafeInteger(anchor.rowVersion + 1)) throw new TypeError('worker quarantine anchor is not an exact fenced row');
  const initialWait = await readCanonicalArtifact<WorkerDeathWait>(artifacts, anchor.waitingSubjectRef);
  requireEqual(initialWait, { ...wait, probeState: { phase: 'automatic_pending', automaticProbeCount: 0, userProbeCount: 0,
    nextProbeAt: wait.createdAt } }, 'worker quarantine original wait');
  const mutable = new Set(['rowVersion', 'updatedAt', 'waitingSubjectRef', 'waitingSubjectDigest']);
  const frozen = (value: WorkspaceGenerationStateV1) => Object.fromEntries(Object.entries(value).filter(([key]) => !mutable.has(key)));
  if (generation.phase === 'fenced_reconciling') requireEqual(frozen(anchor), frozen(generation), 'worker quarantine frozen cut');
  else {
    for (const key of ['schemaVersion', 'generationId', 'runId', 'generationRef', 'generationIdentityDigest', 'sourceCheckpointId',
      'sourceWorkspaceStateRef', 'sourceWorkspaceStateDigest', 'lastVerifiedTreeDigest'] as const) {
      requireEqual(anchor[key], generation[key], `quarantined worker anchor ${key}`);
    }
  }
  const expectedSource = anchor.rowVersion + 2 * inspection.probeState.automaticProbeCount - 1;
  if (generation.rowVersion !== expectedSource + (closed || generation.phase === 'quarantined' ? 1 : 0) ||
      anchor.updatedAt < wait.createdAt || anchor.updatedAt > inspection.probeState.dispatch.probeStartedAt) {
    throw new TypeError('worker quarantine anchor has no exact probe metadata lineage');
  }
  return { anchor, sourceRowVersion: anchor.rowVersion + 1 };
}

async function validateWorkerProbeState(artifacts: ArtifactCatalog, wait: WorkerDeathWait, generation: WorkspaceGenerationStateV1,
  driver: SqliteDriver, specRef: string): Promise<void> {
  const state = wait.probeState;
  if (state.phase === 'automatic_pending' && state.automaticProbeCount === 0) {
    requireEqual(state, { phase: 'automatic_pending', automaticProbeCount: 0, userProbeCount: 0, nextProbeAt: wait.createdAt },
      'initial worker inspection state');
    return;
  }
  if (state.phase === 'automatic_pending' || state.phase === 'automatic_exhausted') {
    const keys = ['phase', 'automaticProbeCount', 'userProbeCount', 'lastProbeEvidenceRef', 'lastProbeEvidenceDigest'];
    if (state.phase === 'automatic_pending') keys.push('nextProbeAt');
    if (!exactKeys(state, keys) || !Number.isSafeInteger(state.automaticProbeCount) || state.automaticProbeCount < 1 ||
        (state.phase === 'automatic_pending' ? state.automaticProbeCount > 7 : state.automaticProbeCount !== 8) || state.userProbeCount !== 0) {
      throw new TypeError('worker closed probe has no bounded automatic schedule');
    }
    const wrapper = await readCanonicalArtifact<ReconciliationProbeEvidenceV1>(artifacts, state.lastProbeEvidenceRef!);
    const prior = await readCanonicalArtifact<WorkerDeathWait>(artifacts, wrapper.waitingSubjectRef);
    requireEqual({ ...prior, probeState: state }, wait, 'worker closed probe wait');
    if (prior.probeState.phase !== 'automatic_in_flight' || prior.probeState.automaticProbeCount !== state.automaticProbeCount ||
        prior.probeState.dispatch.subjectKind !== 'worker_recovery') throw new TypeError('worker closed probe has no exact old dispatch');
    const dispatch = prior.probeState.dispatch;
    await validateWorkerInFlightDispatch(artifacts, prior, generation);
    requireEqual(wrapper, { schemaVersion: 1, format: 'cliq-reconciliation-probe-evidence-v1', runId: wait.runId,
      waitingSubjectRef: canonicalSha256(prior), waitingSubjectDigest: canonicalSha256(prior), probeKind: 'automatic',
      probeOrdinal: state.automaticProbeCount, probeNonceDigest: dispatch.probeNonceDigest, probeDispatchDigest: dispatch.dispatchDigest,
      probeStartedAt: dispatch.probeStartedAt, probeDeadlineAt: dispatch.probeDeadlineAt,
      inspectorIdentityRef: wrapper.inspectorIdentityRef, inspectorIdentityDigest: wrapper.inspectorIdentityDigest,
      observedAt: wrapper.observedAt, evidenceDigest: state.lastProbeEvidenceDigest, outcome: 'probe_timeout',
      timeoutReason: 'no_authoritative_observation_before_deadline', timeoutClosureRef: wrapper.outcome === 'probe_timeout' ? wrapper.timeoutClosureRef : undefined,
      timeoutClosureDigest: wrapper.outcome === 'probe_timeout' ? wrapper.timeoutClosureDigest : undefined }, 'worker timeout probe wrapper');
    if (wrapper.outcome !== 'probe_timeout' || wrapper.evidenceDigest !== digestOmitting(wrapper, 'evidenceDigest') ||
        wrapper.observedAt < dispatch.probeDeadlineAt || wrapper.observedAt > generation.updatedAt) throw new TypeError('worker timeout wrapper has no exact deadline');
    const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, wrapper.inspectorIdentityRef);
    const inspectingOwner = readStateOwner(driver, inspector.stateOwnerEpoch);
    if (!inspectingOwner || (inspectingOwner.state === 'terminal' && wrapper.observedAt > inspectingOwner.releasedAt)) {
      throw new TypeError('worker timeout has no exact live inspector lifetime');
    }
    const runSpec = decodeRunSpec(await readCanonicalArtifact(artifacts, specRef));
    await readSupervisorInspector(artifacts, inspectingOwner,
      decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, runSpec.assemblyRef)), wrapper);
    const timeout = await readCanonicalArtifact<ReconciliationProbeTimeoutClosureV1>(artifacts, wrapper.timeoutClosureRef);
    if (timeout.subjectKind !== 'worker_recovery') throw new TypeError('worker timeout closure substitutes another subject');
    let taskClosure: ReconciliationInspectorTaskClosureV1;
    if (timeout.taskClosure.closureKind === 'cancelled_and_joined') {
      taskClosure = { closureKind: 'cancelled_and_joined', inspectorTaskCancelledAndJoined: true };
      if (inspectingOwner.supervisorInstanceId !== dispatch.owningSupervisorInstanceId ||
          dispatch.probeStartedAt < inspectingOwner.acquiredAt) {
        throw new TypeError('only the owning live inspector may attest actual task cancellation and join');
      }
    } else if (timeout.taskClosure.closureKind === 'owner_process_dead') {
      if (inspectingOwner.supervisorInstanceId === dispatch.owningSupervisorInstanceId) throw new TypeError('owner cannot attest its own predecessor death');
      taskClosure = await readWorkerProbeOwnerDeath(artifacts, driver, dispatch);
      const acquisition = decodeStateOwnerAcquisitionEvidence(await readCanonicalArtifact(artifacts, taskClosure.ownerDeathAcquisitionEvidenceRef));
      if (inspectingOwner.ownerEpoch < acquisition.ownerEpoch || wrapper.observedAt < acquisition.acquiredAt) {
        throw new TypeError('worker timeout inspector precedes its owner death closure');
      }
    } else throw new TypeError('worker timeout task closure has no closed XOR');
    requireEqual(timeout, { schemaVersion: 1, format: 'cliq-reconciliation-probe-timeout-closure-v1', runId: wait.runId,
      waitingSubjectRef: canonicalSha256(prior), probeKind: 'automatic', probeOrdinal: state.automaticProbeCount,
      probeNonceDigest: dispatch.probeNonceDigest, probeDispatchDigest: dispatch.dispatchDigest, probeDeadlineAt: dispatch.probeDeadlineAt,
      inspectorIdentityRef: wrapper.inspectorIdentityRef, inspectorIdentityDigest: wrapper.inspectorIdentityDigest,
      closedAt: wrapper.observedAt, closureDigest: wrapper.timeoutClosureDigest, subjectKind: 'worker_recovery',
      oldWorkerLaunchId: wait.subject.oldWorkerLaunchId, processContainmentRef: wait.subject.processContainmentRef,
      inspectorTaskId: dispatch.inspectorTaskId, taskClosure }, 'worker exact task timeout closure');
    if (timeout.closureDigest !== digestOmitting(timeout, 'closureDigest')) throw new TypeError('worker timeout closure does not rehash');
    if (state.phase === 'automatic_pending' && state.nextProbeAt !== addCanonicalDuration(wrapper.observedAt, WORKER_PROBE_BACKOFF_MS[state.automaticProbeCount - 1]!)) {
      throw new TypeError('worker timeout changed the bounded schedule');
    }
    await readWorkerRecoveryAnchor(artifacts, wait, generation);
    return;
  }
  await validateWorkerInFlightDispatch(artifacts, wait, generation);
  await readWorkerRecoveryAnchor(artifacts, wait, generation);
}

async function validateWorkerInFlightDispatch(artifacts: ArtifactCatalog, wait: WorkerDeathWait,
  generation: WorkspaceGenerationStateV1): Promise<void> {
  const state = wait.probeState;
  if (state.phase !== 'automatic_in_flight' || !exactKeys(state, ['phase', 'automaticProbeCount', 'userProbeCount', 'dispatch']) ||
      !Number.isSafeInteger(state.automaticProbeCount) || state.automaticProbeCount < 1 || state.automaticProbeCount > 8 || state.userProbeCount !== 0) {
    throw new TypeError('unsupported or invalid worker inspection state');
  }
  const dispatch = state.dispatch;
  assertArtifactRef(dispatch.probeNonceDigest);
  parseCanonicalTime(dispatch.probeStartedAt);
  if (!exactKeys(dispatch, ['schemaVersion', 'format', 'runId', 'reconciliationSubjectDigest', 'probeKind', 'probeOrdinal',
    'probeNonceDigest', 'probeStartedAt', 'probeDeadlineAt', 'owningSupervisorInstanceId', 'dispatchDigest', 'subjectKind', 'inspectorTaskId', 'inspectionTargetDigest']) ||
      dispatch.schemaVersion !== 1 || dispatch.format !== 'cliq-reconciliation-probe-dispatch-v1' || dispatch.runId !== wait.runId ||
      dispatch.subjectKind !== 'worker_recovery' || dispatch.probeKind !== 'automatic' || dispatch.probeOrdinal !== state.automaticProbeCount ||
      dispatch.reconciliationSubjectDigest !== canonicalSha256(wait.subject) ||
      dispatch.inspectorTaskId !== identityHash(wait.runId, canonicalSha256(wait.subject), 'automatic', dispatch.probeOrdinal, dispatch.probeNonceDigest) ||
      dispatch.probeStartedAt < wait.createdAt || dispatch.probeStartedAt > generation.updatedAt ||
      dispatch.probeDeadlineAt !== addCanonicalDuration(dispatch.probeStartedAt, 30_000) ||
      typeof dispatch.owningSupervisorInstanceId !== 'string' || !dispatch.owningSupervisorInstanceId ||
      dispatch.dispatchDigest !== digestOmitting(dispatch, 'dispatchDigest')) {
    throw new TypeError('worker inspection dispatch substitutes its exact frozen task');
  }
  requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(dispatch)), dispatch, 'worker persisted inspection dispatch');
}

/** Retained closed artifacts can be replay-validated, but cannot mint a live native observation. */
async function validateWorkerQuarantines(artifacts: ArtifactCatalog, cut: WorkerCut, driver: SqliteDriver): Promise<void> {
  for (const generation of cut.workspaceGenerations) {
    if (generation.phase !== 'quarantined') continue;
    const quarantine = await readCanonicalArtifact<WorkspaceGenerationQuarantineEvidenceV1>(artifacts, generation.quarantineEvidenceRef);
    if (quarantine.reason !== 'worker_recovery') continue; // Other reasons remain their owning producer's responsibility.
    const recovery = await readCanonicalArtifact<WorkerRecoveryEvidenceV1>(artifacts, quarantine.workerRecoveryEvidenceRef);
    const wait = await readCanonicalArtifact<WorkerDeathWait>(artifacts, recovery.waitingSubjectRef);
    const launch = readRequiredWorkerLaunch(driver, recovery.oldWorkerLaunchId);
    const containment = decodeWorkerProcessContainment(await readCanonicalArtifact(artifacts, recovery.processContainmentRef));
    const plan = decodeWorkerContainmentPlan(await readCanonicalArtifact(artifacts, launch.containmentPlanRef));
    const spec = decodeWorkerSandboxLaunchSpec(await readCanonicalArtifact(artifacts, launch.sandboxLaunchSpecRef));
    const worker = decodeWorkerIdentity(await readCanonicalArtifact(artifacts, launch.workerIdentityDigest!));
    const identity = decodeWorkspaceGenerationIdentity(await readCanonicalArtifact(artifacts, generation.generationRef));
    const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, recovery.inspectorIdentityRef);
    const historicalOwner = readStateOwner(driver, inspector.stateOwnerEpoch);
    const runSpec = decodeRunSpec(await readCanonicalArtifact(artifacts, cut.run.specRef));
    const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, runSpec.assemblyRef));
    if (!historicalOwner) throw new TypeError('worker recovery has no retained inspecting StateOwner');
    await readSupervisorInspector(artifacts, historicalOwner, assembly, recovery);
    if (wait.subject.kind !== 'worker_death' || wait.probeState.phase !== 'automatic_in_flight') throw new TypeError('worker quarantine has no persisted inspection');
    parseCanonicalTime(wait.createdAt);
    parseCanonicalTime(quarantine.observedAt);
    if (!Number.isSafeInteger(wait.createdFromRevision) || wait.createdFromRevision <= launch.plannedRunRevision ||
        wait.createdAt < launch.activatedAt!) throw new TypeError('quarantined wait has no prior activated cut');
    await validateWorkerProbeState(artifacts, wait, generation, driver, cut.run.specRef);
    const intent = await readWorkerRecoveryAnchor(artifacts, wait, generation);
    if (intent.anchor.activeWorkerLaunchId !== launch.launchId || intent.anchor.leaseEpoch !== launch.leaseEpoch ||
        intent.anchor.quiesceId !== launch.quiesceId || intent.anchor.fencedJournalSeq > cut.journal.length ||
        cut.journal.slice(intent.anchor.fencedJournalSeq).some(entry => entry.leaseEpoch <= launch.leaseEpoch! &&
          (entry.phase === 'prepared' || entry.phase === 'dispatch_claimed'))) {
      throw new TypeError('worker quarantine anchor substitutes its retained launch or frozen Journal cut');
    }
    requireEqual(wait.subject.openInvocationRefs,
      openWorkerInvocations(cut.journal.slice(0, intent.anchor.fencedJournalSeq)).map(canonicalSha256),
      'quarantined worker frozen invocation witnesses');
    const expectedSubject = { kind: 'worker_death', oldWorkerLaunchId: launch.launchId, oldLeaseEpoch: launch.leaseEpoch,
      oldWorkerIdentity: launch.workerIdentityDigest, processContainmentRef: launch.processContainmentRef,
      workspaceGenerationRef: generation.generationRef, openInvocationRefs: wait.subject.openInvocationRefs };
    requireEqual(wait.subject, expectedSubject, 'quarantined worker subject');
    requireEqual(wait, { schemaVersion: 1, kind: 'reconciliation', runId: cut.run.id, createdFromRevision: wait.createdFromRevision,
      createdAt: wait.createdAt, frontierRef: wait.frontierRef, subject: expectedSubject, probeState: wait.probeState }, 'quarantined worker wait');
    assertArtifactRef(wait.frontierRef);
    let priorWitnessSeq = 0;
    for (const ref of wait.subject.openInvocationRefs) {
      const witness = await readCanonicalArtifact<InvocationJournalEntry>(artifacts, ref);
      const entry = cut.journal.find(entry => entry.seq === witness.seq);
      if (!entry || entry.phase !== 'prepared' || entry.runId !== cut.run.id || entry.seq <= priorWitnessSeq ||
          entry.timestamp > wait.probeState.dispatch.probeStartedAt) throw new TypeError('quarantine open invocation witness is not its ordered Journal fact');
      requireEqual(witness, entry, 'quarantine open invocation witness');
      priorWitnessSeq = entry.seq;
    }
    if (wait.runId !== cut.run.id || launch.runId !== cut.run.id || launch.phase !== 'retired' ||
        launch.generationWriteState !== 'fenced_reconciling' || launch.workspaceGenerationRef !== generation.generationRef ||
        recovery.schemaVersion !== 1 || recovery.format !== 'cliq-worker-recovery-evidence-v1' || recovery.runId !== cut.run.id ||
        recovery.oldLeaseEpoch !== launch.leaseEpoch || recovery.oldWorkerIdentityDigest !== canonicalSha256(worker) ||
        recovery.processContainmentRef !== launch.processContainmentRef || recovery.workspaceGenerationRef !== generation.generationRef ||
        recovery.generationTreeDigest !== generation.lastVerifiedTreeDigest || recovery.evidenceDigest !== quarantine.workerRecoveryEvidenceDigest ||
        recovery.evidenceDigest !== digestOmitting(recovery, 'evidenceDigest') || recovery.inspectorIdentityDigest !== inspector.identityDigest ||
        recovery.observedAt < wait.probeState.dispatch.probeStartedAt || recovery.observedAt > wait.probeState.dispatch.probeDeadlineAt ||
        wait.probeState.dispatch.owningSupervisorInstanceId !== historicalOwner.supervisorInstanceId) {
      throw new TypeError('worker recovery evidence substitutes its retained launch or inspection');
    }
    const common = ['schemaVersion', 'format', 'runId', 'waitingSubjectRef', 'oldWorkerLaunchId', 'oldLeaseEpoch', 'oldWorkerIdentityDigest',
      'processContainmentRef', 'containmentDeathEvidenceRef', 'containmentDeathEvidenceDigest', 'workspaceGenerationRef', 'generationTreeDigest',
      'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'evidenceDigest', 'generationDisposition'];
    if (recovery.generationDisposition === 'restored_from_checkpoint') {
      const checkpoint = readCheckpoint(driver, recovery.restoredCheckpointId);
      const replacement = readRequiredWorkspaceGenerationByRef(driver, recovery.replacementWorkspaceGenerationRef);
      if (!exactKeys(recovery, [...common, 'restoredCheckpointId', 'restoredWorkspaceStateRef', 'replacementWorkspaceGenerationRef']) ||
          checkpoint.runId !== cut.run.id || checkpoint.workspaceStateRef !== recovery.restoredWorkspaceStateRef ||
          replacement.runId !== cut.run.id || replacement.generationRef === generation.generationRef ||
          replacement.sourceCheckpointId !== checkpoint.id || replacement.sourceWorkspaceStateRef !== checkpoint.workspaceStateRef) {
        throw new TypeError('worker recovery does not retain its distinct replacement checkpoint');
      }
    } else if (recovery.generationDisposition !== 'quarantined' || !exactKeys(recovery, common)) {
      throw new TypeError('worker recovery disposition is not its closed XOR');
    }
    requireEqual(plan.owner, spec.owner, 'worker quarantine plan owner');
    requireEqual(containment.owner, plan.owner, 'worker quarantine actual owner');
    requireEqual(plan.filesystemBinding, { kind: 'run-generation', generationRef: generation.generationRef }, 'quarantine planned generation');
    requireEqual(containment.filesystemBinding, { kind: 'run-generation', generationRef: generation.generationRef }, 'quarantine containment generation');
    requireEqual(spec.filesystem, { kind: 'run_generation', generationRef: generation.generationRef, access: 'preactivated_readonly',
      sourceProjectionRef: runSpec.sourceProjectionRef, independentGit: true }, 'quarantine launch generation');
    requireEqual(plan.owner, { kind: 'worker_activation', runId: cut.run.id, intendedLeaseEpoch: launch.leaseEpoch, workerLaunchId: launch.launchId }, 'quarantine historical owner');
    if (containment.sandboxLaunchSpecRef !== launch.sandboxLaunchSpecRef || containment.sandboxLaunchSpecDigest !== spec.launchSpecDigest ||
        containment.planRef !== launch.containmentPlanRef || spec.containmentPlanRef !== launch.containmentPlanRef || spec.containmentPlanDigest !== plan.planDigest ||
        plan.launchNonceDigest !== launch.spawnNonceDigest || containment.launchNonceDigest !== launch.spawnNonceDigest ||
        worker.processContainmentRef !== launch.processContainmentRef || worker.launchId !== launch.launchId ||
        worker.supervisorInstanceId !== launch.supervisorInstanceId || worker.spawnNonceDigest !== launch.spawnNonceDigest ||
        worker.activationNonceDigest !== launch.activationNonceDigest || worker.intendedLeaseEpoch !== launch.leaseEpoch) {
      throw new TypeError('worker quarantine substitutes its actual containment');
    }
    if (plan.backend.kind !== 'linux' || containment.backend.kind !== 'linux' ||
        plan.backend.cgroupPath !== containment.backend.cgroupPath ||
        plan.backend.pidNamespaceReservationId !== containment.backend.pidNamespaceReservationId ||
        plan.backend.subreaperStartToken !== containment.backend.subreaperStartToken ||
        spec.runtime.runtimeBundleRef !== assembly.runtime.runtimeBundleRef ||
        spec.runtime.runtimeBundleManifestDigest !== assembly.runtime.runtimeBundleManifestDigest ||
        spec.executable.kind !== 'runtime_bundle' || spec.executable.executableId !== assembly.runtime.workerExecutableId ||
        spec.executable.executableDigest !== assembly.runtime.workerExecutableDigest || worker.executableDigest !== spec.executable.executableDigest) {
      throw new TypeError('quarantined worker did not bind its frozen executable or native reservation');
    }
    const death = await readCanonicalArtifact<ProcessContainmentDeathEvidenceV1>(artifacts, recovery.containmentDeathEvidenceRef);
    parseCanonicalTime(death.observedAt);
    requireEqual(death, { schemaVersion: 1, kind: 'containment_all_descendants_dead', containmentRef: launch.processContainmentRef,
      planRef: launch.containmentPlanRef, sandboxLaunchSpecRef: launch.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: spec.launchSpecDigest,
      owner: plan.owner, launchNonceDigest: launch.spawnNonceDigest, inspectorSupervisorInstanceId: historicalOwner.supervisorInstanceId,
      inspectorIdentityRef: recovery.inspectorIdentityRef, inspectorIdentityDigest: recovery.inspectorIdentityDigest,
      backend: { ...containment.backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 },
      observedAt: death.observedAt, evidenceDigest: recovery.containmentDeathEvidenceDigest }, 'worker recovery all-descendant death');
    if (death.evidenceDigest !== digestOmitting(death, 'evidenceDigest') || death.observedAt < wait.probeState.dispatch.probeStartedAt ||
        death.observedAt > recovery.observedAt) throw new TypeError('worker death evidence has no exact inspection time');
    const wrapper = await readCanonicalArtifact<ReconciliationProbeEvidenceV1>(artifacts, launch.retirementEvidenceRef!);
    requireEqual(wrapper, { schemaVersion: 1, format: 'cliq-reconciliation-probe-evidence-v1', runId: cut.run.id,
      waitingSubjectRef: recovery.waitingSubjectRef, waitingSubjectDigest: recovery.waitingSubjectRef,
      probeKind: 'automatic', probeOrdinal: wait.probeState.automaticProbeCount, probeNonceDigest: wait.probeState.dispatch.probeNonceDigest,
      probeDispatchDigest: wait.probeState.dispatch.dispatchDigest, probeStartedAt: wait.probeState.dispatch.probeStartedAt,
      probeDeadlineAt: wait.probeState.dispatch.probeDeadlineAt, inspectorIdentityRef: recovery.inspectorIdentityRef,
      inspectorIdentityDigest: recovery.inspectorIdentityDigest, observedAt: recovery.observedAt, evidenceDigest: wrapper.evidenceDigest,
      outcome: 'subject_observation', subjectEvidenceKind: 'worker_recovery', subjectEvidenceRef: quarantine.workerRecoveryEvidenceRef,
      subjectEvidenceDigest: recovery.evidenceDigest }, 'worker recovery outer probe wrapper');
    if (wrapper.evidenceDigest !== digestOmitting(wrapper, 'evidenceDigest')) throw new TypeError('worker recovery wrapper does not rehash');
    requireEqual(quarantine, { schemaVersion: 1, format: 'cliq-workspace-generation-quarantine-evidence-v1', runId: cut.run.id,
      generationRef: generation.generationRef, generationIdentityDigest: identity.identityDigest, sourceRowVersion: intent.sourceRowVersion,
      observedState: generation.observedState, inspectorIdentityRef: recovery.inspectorIdentityRef,
      inspectorIdentityDigest: recovery.inspectorIdentityDigest,
      quarantineCanonicalRootRelativePath: `quarantine/workspace-generations/${identityHash(generation.generationId, String(intent.sourceRowVersion))}`,
      quarantineDeviceId: quarantine.quarantineDeviceId, quarantineFileId: quarantine.quarantineFileId,
      originalLocatorAbsent: true, renameNoReplace: true, directoryFsyncComplete: true,
      observedAt: quarantine.observedAt, evidenceDigest: generation.quarantineEvidenceDigest, reason: 'worker_recovery',
      fromPhase: 'fenced_reconciling', workerRecoveryEvidenceRef: quarantine.workerRecoveryEvidenceRef,
      workerRecoveryEvidenceDigest: recovery.evidenceDigest }, 'worker generation quarantine closure');
    if (quarantine.observedAt < recovery.observedAt || quarantine.observedAt > generation.updatedAt ||
        generation.updatedAt >= wait.probeState.dispatch.probeDeadlineAt ||
        quarantine.evidenceDigest !== digestOmitting(quarantine, 'evidenceDigest') || !/^(0|[1-9][0-9]*)$/.test(quarantine.quarantineDeviceId) ||
        !/^(0|[1-9][0-9]*)$/.test(quarantine.quarantineFileId)) throw new TypeError('worker quarantine identity or digest is invalid');
    if (generation.observedState.kind === 'complete_tree') {
      if (!exactKeys(generation.observedState, ['kind', 'treeDigest'])) throw new TypeError('quarantine tree is not closed');
      assertArtifactRef(generation.observedState.treeDigest);
    } else if (!exactKeys(generation.observedState, ['kind', 'failureCode']) ||
        !['descriptor_io_failed', 'artifact_missing_or_corrupt', 'path_or_entry_invalid', 'git_closure_invalid'].includes(generation.observedState.failureCode)) {
      throw new TypeError('quarantine failure is not closed');
    }
  }
}

/** Validate the installed wait from the same SQLite cut as the Run, launch, generation and Journal. */
export async function validateWorkerRecoveryWait(artifacts: ArtifactCatalog, cut: WorkerCut, driver: SqliteDriver): Promise<void> {
  await validateWorkerQuarantines(artifacts, cut, driver);
  const { run, workerLaunches: launches, workspaceGenerations: generations } = cut;
  const reconciling = launches.filter(launch => launch.phase === 'reconciling');
  const fenced = generations.filter(generation => generation.phase === 'fenced_reconciling');
  if (run.waitingReason !== 'reconciliation' && reconciling.length === 0 && fenced.length === 0) return;
  if (run.status !== 'waiting' || run.waitingReason !== 'reconciliation' || !run.waitingOnRef ||
      run.activeWorkerLaunchId !== undefined || !run.frontierRef || reconciling.length !== 1 ||
      launches.length !== 1 || fenced.length !== 1) throw new TypeError('worker recovery requires one pointer-free Run, reconciling launch and fenced generation');
  const launch = reconciling[0]!;
  const generation = fenced[0]!;
  if (launch.runId !== run.id || launch.leaseEpoch !== run.leaseEpoch || !launch.workerIdentityDigest ||
      !launch.processContainmentRef || generation.runId !== run.id || generation.activeWorkerLaunchId !== launch.launchId ||
      generation.leaseEpoch !== launch.leaseEpoch || generation.generationRef !== launch.workspaceGenerationRef ||
      launch.generationWriteState !== 'fenced_reconciling' || generation.waitingSubjectRef !== run.waitingOnRef ||
      generation.waitingSubjectDigest !== run.waitingOnRef || generation.quiesceId !== launch.quiesceId) {
    throw new TypeError('worker recovery wait substitutes its retained launch, epoch or generation');
  }
  const wait = await readCanonicalArtifact<WorkerDeathWait>(artifacts, run.waitingOnRef);
  if (!Number.isSafeInteger(wait.createdFromRevision) || wait.createdFromRevision <= launch.plannedRunRevision ||
      wait.createdFromRevision >= run.revision || parseCanonicalTime(wait.createdAt) < parseCanonicalTime(launch.activatedAt!) ||
      wait.createdAt > generation.updatedAt || generation.updatedAt > run.updatedAt) {
    throw new TypeError('worker recovery wait has no prior activated Run cut');
  }
  if (generation.fencedJournalSeq > cut.journal.length || cut.journal.slice(generation.fencedJournalSeq)
      .some(entry => entry.phase === 'prepared' || entry.phase === 'dispatch_claimed')) {
    throw new TypeError('worker recovery Journal cut is missing or followed by productive work');
  }
  // The wait freezes membership at fencing, not the current settlement state.
  // Journal sequence distinguishes either side even when timestamps are equal.
  const open = openWorkerInvocations(cut.journal.slice(0, generation.fencedJournalSeq));
  const refs = open.map(canonicalSha256);
  requireEqual(wait.subject?.openInvocationRefs, refs, 'worker recovery open invocation witnesses');
  await joinResourceOperations(open.map(async entry => {
    if (entry.timestamp > generation.updatedAt) throw new TypeError('worker recovery witness is not a prior prepared invocation');
    requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(entry)), entry, 'open invocation Journal witness');
  }));
  const expected: WorkerDeathWait = {
    schemaVersion: 1, kind: 'reconciliation', runId: run.id, createdFromRevision: wait.createdFromRevision,
    createdAt: wait.createdAt, frontierRef: run.frontierRef,
    subject: { kind: 'worker_death', oldWorkerLaunchId: launch.launchId, oldLeaseEpoch: launch.leaseEpoch!,
      oldWorkerIdentity: launch.workerIdentityDigest, processContainmentRef: launch.processContainmentRef,
      workspaceGenerationRef: generation.generationRef, openInvocationRefs: refs },
    probeState: wait.probeState
  };
  requireEqual(wait, expected, 'installed worker death wait');
  await validateWorkerProbeState(artifacts, wait, generation, driver, cut.run.specRef);
}
