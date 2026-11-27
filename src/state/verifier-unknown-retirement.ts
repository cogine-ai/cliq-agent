import path from 'node:path';
import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { BoundWorkerLaunch, InvocationJournalEntry, RecoveryClosureV1, TerminalDetail,
  WorkspaceGenerationQuarantineEvidenceV1, WorkspaceGenerationRetirementEvidenceV1, WorkspaceGenerationStateV1,
  WorkerRecoveryEvidenceV1, StateOwnerRecordV1 } from '../kernel/types.js';
import type { VerifierRequestV1, VerifierTargetV1 } from '../kernel/verifier-invocation.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { LINUX_VERIFIER_RECIPE } from '../sandbox/linux-worker.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { decodeBudgetSettlement, decodeSourceManifest, decodeWorkspaceState } from './decoders.js';
import { decodeBuiltinEditContainmentPlan, decodeVerifierSandboxLaunchSpec, decodeWorkerProcessContainment,
  decodeWorkerSandboxLaunchSpec } from './execution-closure.js';
import { readRetiredGenerationSource } from './generation-retirement.js';
import { decodeGuestToolchainManifest } from './guest-toolchain.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readStateOwner } from './state-owner.js';
import { readVerifierProgress } from './verifier-recovery.js';
import { decodeVerifierCommand } from './verifier-artifacts.js';
import { verifierOperationId } from './verifier-policy.js';
import { validateRetainedWorkerQuarantines } from './worker-recovery.js';
import { readCandidateSource, type CandidateSourceReader } from './result-source.js';

type Abandonment = TerminalDetail['abandonedRetryInvocations'][number];
/** Retained data only. This is neither a child death/no-spawn observation nor
 * permission to execute, retry, refund or resolve the original UNKNOWN. */
export type VerifierParentDomainDispatchClosureV1 = {
  schemaVersion: 1; format: 'cliq-invocation-dispatch-closure-evidence-v1'; runId: string; opId: string;
  attempt: number; dispatchId: string; unknownJournalSeq: number;
  closure: { kind: 'verifier_parent_domain_dead'; claimJournalSeq: number;
    claimingSupervisorInstanceId: string; claimingStateOwnerEpoch: number;
    requestRef: string; targetRef: string; grantRef: string; sandboxLaunchSpecRef: string;
    workerLaunchId: string; leaseEpoch: number; generationRef: string; parentContainmentRef: string;
    parentDeathEvidenceRef: string; parentDeathEvidenceDigest: string;
    quarantineEvidenceRef: string; quarantineEvidenceDigest: string;
    retirementEvidenceRef: string; retirementEvidenceDigest: string;
    controllerLifetime: 'original_subreaper_absent_and_inspector_joined' };
  observedAt: string; evidenceDigest: string;
};

/** Eligibility data only; the owning recovery plan must still obtain and
 * freshly reassert the real parent death, controller join and workspace proof. */
export function hasOnlySettledVerifierUnknowns(journal: readonly InvocationJournalEntry[]): boolean {
  const latest = new Map<string, InvocationJournalEntry>();
  for (const entry of journal) latest.set(`${entry.opId}\0${entry.attempt}`, entry);
  const open = [...latest.values()].filter(entry => ['prepared', 'dispatch_claimed', 'unknown'].includes(entry.phase));
  return open.length === 1 && open.every(unknown => {
    const attempt = journal.filter(entry => entry.opId === unknown.opId && entry.attempt === unknown.attempt);
    const [prepared, claim] = attempt;
    return attempt.length === 3 && prepared?.phase === 'prepared' && claim?.phase === 'dispatch_claimed' &&
      attempt[2] === unknown && attempt.every(entry => entry.opKind === 'verifier' && entry.replayClass === 'retry') &&
      unknown.phase === 'unknown' && !!unknown.budgetSettlementRef && !!unknown.evidenceRef && !!unknown.evidenceDigest &&
      canonicalSha256(unknown.budgetDelta) === canonicalSha256(prepared.budgetDelta);
  });
}

export function decodeVerifierParentDomainDispatchClosure(value: VerifierParentDomainDispatchClosureV1) {
  const closure = value?.closure;
  if (!exactKeys(value, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dispatchId', 'unknownJournalSeq',
    'closure', 'observedAt', 'evidenceDigest']) || value.schemaVersion !== 1 ||
      value.format !== 'cliq-invocation-dispatch-closure-evidence-v1' ||
      !exactKeys(closure, ['kind', 'claimJournalSeq', 'claimingSupervisorInstanceId', 'claimingStateOwnerEpoch', 'requestRef',
        'targetRef', 'grantRef', 'sandboxLaunchSpecRef', 'workerLaunchId', 'leaseEpoch', 'generationRef', 'parentContainmentRef',
        'parentDeathEvidenceRef', 'parentDeathEvidenceDigest', 'quarantineEvidenceRef', 'quarantineEvidenceDigest',
        'retirementEvidenceRef', 'retirementEvidenceDigest', 'controllerLifetime']) ||
      closure.kind !== 'verifier_parent_domain_dead' || closure.controllerLifetime !== 'original_subreaper_absent_and_inspector_joined' ||
      [value.runId, value.opId, value.dispatchId, closure.workerLaunchId, closure.claimingSupervisorInstanceId]
        .some(id => typeof id !== 'string' || !id || Buffer.byteLength(id) > 256 || id.includes('\0')) ||
      !Number.isSafeInteger(value.attempt) || value.attempt < 0 ||
      [value.unknownJournalSeq, closure.claimJournalSeq, closure.claimingStateOwnerEpoch, closure.leaseEpoch]
        .some(seq => !Number.isSafeInteger(seq) || seq < 1) || closure.claimJournalSeq >= value.unknownJournalSeq ||
      value.evidenceDigest !== digestOmitting(value, 'evidenceDigest'))
    throw new TypeError('verifier abandonment requires its closed original parent-domain proof');
  for (const ref of [closure.requestRef, closure.targetRef, closure.grantRef, closure.sandboxLaunchSpecRef, closure.generationRef,
    closure.parentContainmentRef, closure.parentDeathEvidenceRef, closure.parentDeathEvidenceDigest, closure.quarantineEvidenceRef,
    closure.quarantineEvidenceDigest, closure.retirementEvidenceRef, closure.retirementEvidenceDigest, value.evidenceDigest]) assertArtifactRef(ref);
  parseCanonicalTime(value.observedAt);
  return value;
}

async function originalClaim(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  generation: WorkspaceGenerationStateV1, launch: BoundWorkerLaunch) {
  if (!hasOnlySettledVerifierUnknowns(cut.journal)) throw new TypeError('parent-domain retirement requires one original settled verifier UNKNOWN');
  const unknown = cut.journal.filter(entry => entry.opKind === 'verifier' && entry.phase === 'unknown').at(-1)!;
  const claim = cut.journal.find(entry => entry.opId === unknown.opId && entry.attempt === unknown.attempt && entry.phase === 'dispatch_claimed')!;
  const issuer = claim.stateOwnerEpoch ? readStateOwner(driver, claim.stateOwnerEpoch) : undefined;
  const target = await readCanonicalArtifact<VerifierTargetV1>(artifacts, claim.target);
  const progress = await readVerifierProgress(driver, artifacts, cut, target.candidateItemId);
  return validateVerifierUnknownOriginalClaim(artifacts, cut, generation, launch, issuer, progress);
}

/** Read-only relationships, not a claim, native receipt or permission issuer.
 * The private production entry above always obtains fresh SQL owner/progress;
 * callers cannot supply this data to any execution or terminal writer. */
export async function validateVerifierUnknownOriginalClaim(artifacts: CandidateSourceReader,
  cut: Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'journal'>, generation: WorkspaceGenerationStateV1,
  launch: BoundWorkerLaunch, issuer: StateOwnerRecordV1 | undefined,
  progress: Pick<Awaited<ReturnType<typeof readVerifierProgress>>, 'candidate' | 'planRef'>) {
  if (!hasOnlySettledVerifierUnknowns(cut.journal)) throw new TypeError('parent-domain retirement requires one original settled verifier UNKNOWN');
  const unknown = cut.journal.filter(entry => entry.opKind === 'verifier' && entry.phase === 'unknown').at(-1)!;
  const attempt = cut.journal.filter(entry => entry.opId === unknown.opId && entry.attempt === unknown.attempt);
  const [prepared, claim] = attempt as [InvocationJournalEntry, InvocationJournalEntry, InvocationJournalEntry];
  for (const key of ['runId', 'opId', 'opKind', 'attempt', 'leaseEpoch', 'requestRef', 'target', 'grantRef', 'replayClass'] as const)
    requireEqual([claim[key], unknown[key]], [prepared[key], prepared[key]], 'verifier original UNKNOWN identity');
  for (const key of ['dispatchId', 'sandboxLaunchSpecRef', 'supervisorInstanceId', 'stateOwnerEpoch'] as const)
    requireEqual(unknown[key], claim[key], 'verifier original permanent claim');
  if (!claim.sandboxLaunchSpecRef || !claim.dispatchId || !claim.stateOwnerEpoch || !claim.supervisorInstanceId || !prepared.grantRef ||
      claim.brokerFenceTokenDigest !== undefined || unknown.timestamp < claim.timestamp || claim.timestamp < prepared.timestamp ||
      claim.seq <= prepared.seq || unknown.seq <= claim.seq || launch.runId !== cut.run.id ||
      generation.phase === 'active' && launch.launchId !== generation.activeWorkerLaunchId || launch.workspaceGenerationRef !== generation.generationRef ||
      launch.leaseEpoch !== claim.leaseEpoch || launch.supervisorInstanceId !== claim.supervisorInstanceId)
    throw new TypeError('verifier UNKNOWN substitutes its original parent activation');
  if (!issuer || issuer.supervisorInstanceId !== claim.supervisorInstanceId || issuer.acquiredAt > claim.timestamp ||
      issuer.state === 'terminal' && issuer.releasedAt < claim.timestamp) throw new TypeError('verifier UNKNOWN has a foreign claiming owner');
  requireEqual(await readCanonicalArtifact(artifacts, unknown.evidenceRef!), { schemaVersion: 1, format: 'cliq-verifier-ambiguity-v1',
    runId: cut.run.id, opId: claim.opId, attempt: claim.attempt, dispatchId: claim.dispatchId, claimJournalSeq: claim.seq,
    requestRef: claim.requestRef, targetRef: claim.target, grantRef: claim.grantRef,
    reason: 'original_producer_joined_without_result' }, 'original verifier ambiguity');
  if (unknown.evidenceDigest !== unknown.evidenceRef || unknown.resultRef !== undefined || unknown.receiptRef !== undefined)
    throw new TypeError('verifier UNKNOWN cannot substitute a received result');
  const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, unknown.budgetSettlementRef!));
  if (settlement.runId !== cut.run.id || settlement.opId !== claim.opId || settlement.attempt !== claim.attempt ||
      settlement.preparedJournalSeq !== prepared.seq || settlement.terminalJournalSeq !== unknown.seq || settlement.terminalPhase !== 'unknown' ||
      settlement.settledAt !== unknown.timestamp) throw new TypeError('verifier UNKNOWN substitutes its original settlement');
  for (const value of [prepared.budgetDelta, unknown.budgetDelta, settlement.reserved, settlement.consumed, settlement.released])
    requireEqual(value, { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, 'verifier original full charge');
  const target = await readCanonicalArtifact<VerifierTargetV1>(artifacts, prepared.target);
  const request = await readCanonicalArtifact<VerifierRequestV1>(artifacts, prepared.requestRef);
  // Reproduce the complete candidate/plan/request/grant/policy/settlement graph,
  // including when a terminal Run no longer has a frontier.
  if (prepared.opId !== verifierOperationId(cut.run.id, target.candidateItemId, progress.planRef, target.verifierIndex) ||
      target.runId !== cut.run.id || request.runId !== cut.run.id || request.opId !== prepared.opId ||
      request.candidateItemId !== progress.candidate.itemId || request.verifierIndex !== target.verifierIndex ||
      request.verifierPlanRef !== progress.planRef || target.verifierPlanRef !== progress.planRef)
    throw new TypeError('verifier abandonment substitutes another frozen candidate operation');
  const resultSource = decodeSourceManifest(await readCanonicalArtifact(artifacts, target.resultSourceRef));
  const state = decodeWorkspaceState(await readCanonicalArtifact(artifacts, generation.sourceWorkspaceStateRef));
  const projected = await readCandidateSource(artifacts, cut.runSpec, generation.sourceWorkspaceStateRef);
  if (resultSource.role !== 'result' || resultSource.manifestDigest !== target.sourceDigest ||
      resultSource.sourceProjectionRef !== cut.runSpec.sourceProjectionRef || state.runId !== cut.run.id ||
      projected.sourceRef !== target.resultSourceRef || projected.source.manifestDigest !== target.sourceDigest ||
      target.resultSourceRef !== progress.candidate.resultSourceRef || target.sourceDigest !== progress.candidate.sourceDigest ||
      state.sourceProjectionDigest !== resultSource.sourceProjectionDigest)
    throw new TypeError('verifier UNKNOWN generation source differs from its exact candidate');
  const spec = decodeVerifierSandboxLaunchSpec(await readCanonicalArtifact(artifacts, claim.sandboxLaunchSpecRef));
  const plan = decodeBuiltinEditContainmentPlan(await readCanonicalArtifact(artifacts, spec.containmentPlanRef));
  const parent = decodeWorkerProcessContainment(await readCanonicalArtifact(artifacts, launch.processContainmentRef!));
  const parentSpec = decodeWorkerSandboxLaunchSpec(await readCanonicalArtifact(artifacts, launch.sandboxLaunchSpecRef));
  const command = decodeVerifierCommand(await readCanonicalArtifact(artifacts, target.commandRef));
  if (command.executable.kind !== 'guest_toolchain') throw new TypeError('verifier abandonment requires its fixed signed guest recipe');
  const executable = command.executable;
  const guest = decodeGuestToolchainManifest(await readCanonicalArtifact(artifacts, executable.guestToolchainManifestRef));
  requireEqual(spec.executable, { kind: 'guest_toolchain', guestToolchainManifestRef: executable.guestToolchainManifestRef,
    guestToolchainManifestDigest: guest.manifestDigest, toolId: executable.toolId, role: 'verifier',
    executionPath: executable.executionPath, executableDigest: executable.executableDigest }, 'abandoned verifier exact frozen executable');
  const runtime = { ...parentSpec.runtime, toolchain: { kind: 'guest_toolchain',
    guestToolchainManifestRef: executable.guestToolchainManifestRef, guestToolchainManifestDigest: guest.manifestDigest,
    guestImageRef: guest.guestImageRef, guestImageDigest: guest.guestImageDigest }, runtimeDigest: '' };
  runtime.runtimeDigest = digestOmitting(runtime, 'runtimeDigest');
  requireEqual(spec.runtime, runtime, 'abandoned verifier exact frozen runtime');
  requireEqual(spec.environment, LINUX_VERIFIER_RECIPE.environment, 'abandoned verifier exact fixed environment');
  requireEqual(spec.mounts, LINUX_VERIFIER_RECIPE.mounts.map(mount => ({ ...mount,
    privateRootId: identityHash(claim.dispatchId!, mount.purpose) })), 'abandoned verifier exact private mounts');
  requireEqual(spec.resources, parentSpec.resources, 'abandoned verifier frozen resources');
  requireEqual(spec.filesystem, { ...parentSpec.filesystem, access: 'read_only' }, 'abandoned verifier exact source mount');
  const owner = { kind: 'run_invocation', runId: cut.run.id, intendedLeaseEpoch: claim.leaseEpoch,
    workerLaunchId: launch.launchId, opId: claim.opId, attempt: claim.attempt, dispatchId: claim.dispatchId };
  requireEqual(spec.owner, owner, 'abandoned verifier child owner'); requireEqual(plan.owner, owner, 'abandoned verifier child plan');
  requireEqual(plan.filesystemBinding, { kind: 'run-generation', generationRef: generation.generationRef }, 'abandoned verifier generation');
  requireEqual(parent.owner, { kind: 'worker_activation', runId: cut.run.id, intendedLeaseEpoch: claim.leaseEpoch,
    workerLaunchId: launch.launchId }, 'abandoned verifier exact parent');
  if (spec.requestRef !== prepared.requestRef || spec.requestDigest !== request.requestDigest || spec.targetRef !== prepared.target ||
      spec.targetDigest !== target.targetDigest || spec.operationGrantRef !== prepared.grantRef ||
      spec.parentWorkerContainmentRef !== launch.processContainmentRef || plan.parentContainmentRef !== launch.processContainmentRef ||
      plan.planDigest !== spec.containmentPlanDigest || spec.filesystem.kind !== 'run_generation' ||
      spec.filesystem.generationRef !== generation.generationRef || spec.filesystem.sourceProjectionRef !== cut.runSpec.sourceProjectionRef ||
      spec.runtime.runtimeBundleRef !== issuer.runtimeBundleRef || spec.runtime.runtimeBundleManifestDigest !== issuer.runtimeBundleManifestDigest ||
      spec.sandboxProfileRef !== parentSpec.sandboxProfileRef || spec.sandboxProfileDigest !== parentSpec.sandboxProfileDigest ||
      spec.createdAt < prepared.timestamp || spec.createdAt > claim.timestamp || plan.createdAt < prepared.timestamp || plan.createdAt > claim.timestamp ||
      parent.backend.kind !== 'linux' || plan.backend.kind !== 'linux' ||
      path.posix.dirname(plan.backend.cgroupPath) !== parent.backend.cgroupPath ||
      plan.backend.cgroupNameReservationDigest !== canonicalSha256(['cliq-verifier-cgroup-v1', claim.dispatchId]) ||
      path.posix.basename(plan.backend.cgroupPath) !== `cliq-${plan.backend.cgroupNameReservationDigest}` ||
      plan.backend.pidNamespaceReservationId !== identityHash('cliq-verifier-namespace-v1', claim.dispatchId) ||
      plan.backend.subreaperStartToken !== parent.backend.subreaperStartToken)
    throw new TypeError('verifier UNKNOWN is not confined to its exact retired parent domain');
  return { prepared, claim, unknown, spec };
}

/** Called only inside the existing genuine worker-retirement plan, after its
 * native read has checked original subreaper absence and joined the inspector.
 * Returned data alone is not a WorkerRecoveryTerminalPlan or execution grant. */
export async function prepareVerifierUnknownParentClosure(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  input: { launch: BoundWorkerLaunch; generation: WorkspaceGenerationStateV1;
    quarantine: Extract<WorkspaceGenerationQuarantineEvidenceV1, { reason: 'worker_recovery' }>; quarantineRef: string;
    retirement: WorkspaceGenerationRetirementEvidenceV1; retirementRef: string }) {
  if (!hasOnlySettledVerifierUnknowns(cut.journal)) return { metadata: [] as PublishedArtifact[], abandoned: [] as Abandonment[] };
  if (!cut.run.stopIntentRef || input.quarantine.observedState.kind !== 'complete_tree' ||
      input.quarantine.observedState.treeDigest !== input.generation.lastVerifiedTreeDigest)
    throw new TypeError('verifier parent abandonment requires an unchanged fully observed private source');
  const { claim, unknown } = await originalClaim(driver, artifacts, cut, input.generation, input.launch);
  const recovery = await readCanonicalArtifact<WorkerRecoveryEvidenceV1>(artifacts, input.quarantine.workerRecoveryEvidenceRef);
  const evidence: VerifierParentDomainDispatchClosureV1 = { schemaVersion: 1,
    format: 'cliq-invocation-dispatch-closure-evidence-v1', runId: cut.run.id, opId: claim.opId, attempt: claim.attempt,
    dispatchId: claim.dispatchId!, unknownJournalSeq: unknown.seq, closure: { kind: 'verifier_parent_domain_dead',
      claimJournalSeq: claim.seq, claimingSupervisorInstanceId: claim.supervisorInstanceId!, claimingStateOwnerEpoch: claim.stateOwnerEpoch!,
      requestRef: claim.requestRef, targetRef: claim.target, grantRef: claim.grantRef!, sandboxLaunchSpecRef: claim.sandboxLaunchSpecRef!,
      workerLaunchId: input.launch.launchId, leaseEpoch: claim.leaseEpoch, generationRef: input.generation.generationRef,
      parentContainmentRef: input.launch.processContainmentRef!, parentDeathEvidenceRef: recovery.containmentDeathEvidenceRef,
      parentDeathEvidenceDigest: recovery.containmentDeathEvidenceDigest, quarantineEvidenceRef: input.quarantineRef,
      quarantineEvidenceDigest: input.quarantine.evidenceDigest, retirementEvidenceRef: input.retirementRef,
      retirementEvidenceDigest: input.retirement.evidenceDigest, controllerLifetime: 'original_subreaper_absent_and_inspector_joined' },
    observedAt: input.retirement.observedAt, evidenceDigest: '' };
  if (evidence.observedAt < unknown.timestamp) throw new TypeError('verifier parent retirement predates its original UNKNOWN');
  evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest'); decodeVerifierParentDomainDispatchClosure(evidence);
  const artifact = await artifacts.publishCanonical(evidence, evidence.format);
  return { metadata: [artifact], abandoned: [{ opId: unknown.opId, attempt: unknown.attempt, unknownJournalSeq: unknown.seq,
    budgetSettlementRef: unknown.budgetSettlementRef!, dispatchFenceOrDeathEvidenceRef: artifact.ref }] };
}

/** Retained-only acceptance rewalks both the original child claim and the full
 * parent's quarantine/retirement graph. No fresh native capability is minted. */
export async function validateVerifierUnknownTerminalHistory(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: RecoveryClosureV1, detail: TerminalDetail): Promise<Abandonment[]> {
  const sequences = new Set(cut.journal.filter(entry => entry.opKind === 'verifier' && entry.phase === 'unknown').map(entry => entry.seq));
  const entries = detail.abandonedRetryInvocations.filter(entry => sequences.has(entry.unknownJournalSeq));
  if (!entries.length) return [];
  if (entries.length !== 1 || !['failed', 'cancelled'].includes(cut.run.status) || !cut.run.stopIntentRef)
    throw new TypeError('verifier abandonment requires its unique stopped parent-domain closure');
  const entry = entries[0]!, evidence = decodeVerifierParentDomainDispatchClosure(await readCanonicalArtifact(artifacts, entry.dispatchFenceOrDeathEvidenceRef));
  const closure = evidence.closure, launch = readRequiredWorkerLaunch(driver, closure.workerLaunchId);
  const generation = cut.workspaceGenerations.find(row => row.generationRef === closure.generationRef);
  if (!generation || generation.phase !== 'retired' || launch.phase !== 'retired' || launch.retirementKind === 'preparation')
    throw new TypeError('verifier abandonment requires the actual retired parent and generation');
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, cut.runSpec.assemblyRef));
  const retired = await readRetiredGenerationSource(driver, artifacts, { run: cut.run, spec: cut.runSpec, assembly, generation });
  if (retired.source.phase !== 'quarantined' || retired.source.quarantineEvidenceRef !== closure.quarantineEvidenceRef ||
      generation.retirementEvidenceRef !== closure.retirementEvidenceRef || generation.retirementEvidenceDigest !== closure.retirementEvidenceDigest)
    throw new TypeError('verifier abandonment substitutes a sealed or unrelated generation');
  await validateRetainedWorkerQuarantines(artifacts, { run: cut.run, journal: cut.journal,
    workerLaunches: [launch], workspaceGenerations: [retired.source] }, driver);
  const quarantine = await readCanonicalArtifact<Extract<WorkspaceGenerationQuarantineEvidenceV1, { reason: 'worker_recovery' }>>(
    artifacts, closure.quarantineEvidenceRef);
  const rebuilt = await originalClaim(driver, artifacts, cut, generation, launch);
  const retirement = await readCanonicalArtifact<WorkspaceGenerationRetirementEvidenceV1>(artifacts, closure.retirementEvidenceRef);
  const recovery = await readCanonicalArtifact<WorkerRecoveryEvidenceV1>(artifacts, quarantine.workerRecoveryEvidenceRef);
  const { claim, unknown } = rebuilt;
  requireEqual(closure, { kind: 'verifier_parent_domain_dead', claimJournalSeq: claim.seq,
    claimingSupervisorInstanceId: claim.supervisorInstanceId, claimingStateOwnerEpoch: claim.stateOwnerEpoch,
    requestRef: claim.requestRef, targetRef: claim.target, grantRef: claim.grantRef, sandboxLaunchSpecRef: claim.sandboxLaunchSpecRef,
    workerLaunchId: launch.launchId, leaseEpoch: claim.leaseEpoch, generationRef: generation.generationRef,
    parentContainmentRef: launch.processContainmentRef, parentDeathEvidenceRef: recovery.containmentDeathEvidenceRef,
    parentDeathEvidenceDigest: recovery.containmentDeathEvidenceDigest, quarantineEvidenceRef: retired.source.quarantineEvidenceRef,
    quarantineEvidenceDigest: quarantine.evidenceDigest, retirementEvidenceRef: generation.retirementEvidenceRef,
    retirementEvidenceDigest: retirement.evidenceDigest, controllerLifetime: 'original_subreaper_absent_and_inspector_joined' }, 'retained verifier parent domain');
  if (evidence.runId !== cut.run.id || evidence.opId !== claim.opId || evidence.attempt !== claim.attempt ||
      evidence.dispatchId !== claim.dispatchId || evidence.unknownJournalSeq !== unknown.seq ||
      entry.opId !== unknown.opId || entry.attempt !== unknown.attempt || entry.unknownJournalSeq !== unknown.seq ||
      entry.budgetSettlementRef !== unknown.budgetSettlementRef || evidence.observedAt !== retirement.observedAt ||
      evidence.observedAt < unknown.timestamp || evidence.observedAt > detail.createdAt || detail.createdAt > cut.run.updatedAt ||
      parseCanonicalTime(cut.run.updatedAt) - parseCanonicalTime(evidence.observedAt) > 5000 ||
      quarantine.observedState.kind !== 'complete_tree' || quarantine.observedState.treeDigest !== generation.lastVerifiedTreeDigest ||
      recovery.oldWorkerLaunchId !== launch.launchId || recovery.oldLeaseEpoch !== claim.leaseEpoch ||
      recovery.processContainmentRef !== closure.parentContainmentRef || recovery.workspaceGenerationRef !== generation.generationRef)
    throw new TypeError('verifier abandonment loses its original unknown, charge, parent death or terminal freshness');
  return entries;
}
