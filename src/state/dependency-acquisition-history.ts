import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeDependencyAcquisitionClosure, decodeDependencyAcquisitionRetirement } from '../kernel/dependency-acquisition.js';
import { decodeDependencyClaimEvidence } from '../kernel/dependency-claim.js';
import { decodeDependencyFailureItem, type DependencyFailureItem } from '../kernel/dependency.js';
import { decodeDependencyOperationGrant, decodeDependencyRequest, decodeDependencyTarget } from '../kernel/dependency-invocation.js';
import type { RecoveryClosureV1 } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeBudgetSettlement, decodeContextManifest, decodeWorkspaceGenerationSnapshotEvidence } from './decoders.js';
import { readRetainedDependencyCandidate } from './dependency-candidate.js';
import { planDependencyInvocation } from './dependency-invocation-plan.js';
import { dependencyFailureItemId, dependencyReadyCheckpointId } from './dependency-retirement.js';
import { readDependencyScriptsTemplateHistoryData } from './dependency-script-history.js';
import { readRetainedDependencyLaunchEnvironment } from './execution-closure.js';
import { readRetiredGenerationSource } from './generation-retirement.js';
import { readInvocationAttempt } from './repositories/journal.js';
import { readCheckpoint } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readStateOwner } from './state-owner.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { validateMatchingWorkerDeath, validateRetainedWorkerSeal } from './tool-checkpoint.js';

/** Reproduce a negative execution observation under its original signed
 * broker/claim/inspector and a real unchanged parent seal. This is not a
 * missing-result fallback and never asserts a process birth or death. */
export async function readFailedDependencyAcquisition(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'items' | 'journal' | 'workspaceGenerations'>, supplied: DependencyFailureItem) {
  const item = decodeDependencyFailureItem(supplied);
  const rows = readInvocationAttempt(driver, item.runId, item.opId, item.attempt), [prepared, claim, terminal] = rows;
  if (item.failureKind !== 'acquisition_failed' || item.runId !== cut.run.id || item.attempt !== 0 ||
      item.itemId !== dependencyFailureItemId(item.runId, item.opId, item.attempt) || item.checkpointId !== dependencyReadyCheckpointId(item.runId, item.opId, item.attempt) ||
      rows.length !== 3 || prepared?.phase !== 'prepared' || prepared.opKind !== 'tool' || prepared.target !== 'builtin:dependency-acquire' ||
      !prepared.grantRef || claim?.phase !== 'dispatch_claimed' || !claim.evidenceRef || !claim.evidenceDigest ||
      !claim.brokerFenceTokenDigest || claim.sandboxLaunchSpecRef !== undefined || terminal?.phase !== 'failed' ||
      !terminal.errorRef || !terminal.evidenceRef || !terminal.evidenceDigest || !terminal.budgetSettlementRef || terminal.errorRef !== item.receiptRef)
    throw new TypeError('dependency acquisition failure has no unique original claimed failed Journal');
  requireEqual(cut.journal.filter(row => row.opId === item.opId && row.attempt === item.attempt), rows, 'dependency acquisition complete original rows');
  const proof = decodeDependencyAcquisitionRetirement(await readCanonicalArtifact(artifacts, terminal.errorRef));
  const observation = decodeDependencyAcquisitionClosure(await readCanonicalArtifact(artifacts, terminal.evidenceRef));
  const evidence = decodeDependencyClaimEvidence(await readCanonicalArtifact(artifacts, claim.evidenceRef));
  const request = decodeDependencyRequest(await readCanonicalArtifact(artifacts, prepared.requestRef));
  const target = decodeDependencyTarget(await readCanonicalArtifact(artifacts, request.targetRef));
  const grant = decodeDependencyOperationGrant(await readCanonicalArtifact(artifacts, prepared.grantRef));
  const source = await readRetainedDependencyCandidate(driver, artifacts, item.runId, { candidateItemId: request.candidateItemId,
    sourceCheckpointId: evidence.sourceCheckpointId, dependencyPlanRef: item.planRef, resultSourceRef: request.resultSourceRef,
    releaseKeys: artifacts.releaseTrustRoots() });
  requireEqual(source.run, cut.run, 'dependency acquisition original complete Run'); requireEqual(source.spec, cut.runSpec, 'dependency acquisition immutable Run spec');
  const scripts = target.scriptAuthorizationTemplateRef ? await readDependencyScriptsTemplateHistoryData(driver, artifacts,
    { bundle: source.bundle, releaseKeys: artifacts.releaseTrustRoots() }, { runId: item.runId, templateRef: target.scriptAuthorizationTemplateRef }) : undefined;
  const planned = planDependencyInvocation({ runId: item.runId, principalId: source.principalId, policyRef: source.spec.policyRef,
    frontierRef: request.frontierRef, assemblyRef: source.spec.assemblyRef, workspaceIdentityRef: source.session.workspaceIdentityRef,
    workspaceIdentityDigest: source.workspaceIdentity.identityDigest, candidateItemId: source.candidate.itemId, candidateOrdinal: source.candidateOrdinal,
    resultSourceRef: request.resultSourceRef, sourceDigest: source.candidate.sourceDigest, dependencyPolicyRef: source.spec.dependencyPolicyRef!,
    policy: source.policy, dependencyPlanRef: item.planRef, plan: source.plan, conditions: source.conditions, deadlineAt: cut.run.deadlineAt,
    ...(scripts ? { scripts: { templateRef: scripts.templateRef, template: scripts.template } } : {}) });
  requireEqual(request, planned.request, 'dependency acquisition original complete request'); requireEqual(target, planned.target, 'dependency acquisition original source target');
  requireEqual(grant, planned.grant(grant.issuedAt, grant.expiresAt), 'dependency acquisition original source consent');
  if (proof.runId !== item.runId || proof.opId !== item.opId || proof.attempt !== item.attempt || proof.dependencyPlanRef !== item.planRef ||
      proof.checkpointId !== item.checkpointId || proof.acquisitionClosureRef !== terminal.evidenceRef ||
      proof.acquisitionClosureDigest !== observation.evidenceDigest || terminal.evidenceDigest !== observation.evidenceDigest ||
      observation.runId !== item.runId || observation.opId !== item.opId || observation.attempt !== item.attempt ||
      observation.claimEvidenceRef !== claim.evidenceRef || observation.dispatchId !== claim.dispatchId || observation.dispatchJournalSeq !== claim.seq ||
      observation.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest || evidence.evidenceDigest !== claim.evidenceDigest ||
      evidence.dispatchId !== claim.dispatchId || evidence.requestRef !== prepared.requestRef || evidence.requestDigest !== request.requestDigest ||
      evidence.targetRef !== request.targetRef || evidence.targetDigest !== target.targetDigest || evidence.grantRef !== prepared.grantRef ||
      evidence.dependencyPlanRef !== item.planRef || evidence.leaseEpoch !== claim.leaseEpoch ||
      evidence.stateOwnerEpoch !== claim.stateOwnerEpoch || evidence.supervisorInstanceId !== claim.supervisorInstanceId ||
      evidence.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest || prepared.timestamp < grant.issuedAt ||
      claim.timestamp < prepared.timestamp || claim.timestamp >= grant.expiresAt || observation.observedAt < claim.timestamp ||
      observation.observedAt > terminal.timestamp || item.createdAt !== terminal.timestamp ||
      observation.closure.transferredBytes > source.plan.maxDownloadBytes ||
      observation.closure.connectionCount > source.data.packages.length * 3)
    throw new TypeError('dependency acquisition failure substitutes original claim, bound or time');
  const owner = claim.stateOwnerEpoch && readStateOwner(driver, claim.stateOwnerEpoch);
  if (!owner || owner.supervisorInstanceId !== claim.supervisorInstanceId) throw new TypeError('dependency acquisition lost its original StateOwner');
  const inspector = await readSupervisorInspector(artifacts, owner, source.assembly, observation);
  if (inspector.stateOwnerEpoch !== claim.stateOwnerEpoch || inspector.supervisorInstanceId !== claim.supervisorInstanceId)
    throw new TypeError('dependency acquisition inspector did not own the original live broker');
  const environment = await readRetainedDependencyLaunchEnvironment(artifacts, owner, cut.runSpec, evidence.sandboxLaunchSpecRef);
  requireEqual(environment.bundle, source.bundle, 'dependency acquisition original complete signed native recipe');
  if (environment.spec.owner.workerLaunchId !== evidence.workerLaunchId || environment.spec.requestRef !== prepared.requestRef ||
      environment.spec.requestDigest !== request.requestDigest || environment.spec.targetRef !== request.targetRef ||
      environment.spec.operationGrantRef !== prepared.grantRef || environment.spec.owner.dispatchId !== claim.dispatchId ||
      environment.spec.launchSpecDigest !== evidence.sandboxLaunchSpecDigest || environment.spec.filesystem.kind !== 'run_generation')
    throw new TypeError('dependency acquisition receipt substitutes its fixed original recipe');
  const checkpoint = readCheckpoint(driver, item.checkpointId);
  const snapshot = decodeWorkspaceGenerationSnapshotEvidence(await readCanonicalArtifact(artifacts, proof.snapshotEvidenceRef));
  const row = source.items.find(row => row.itemId === item.itemId);
  if (!row || row.payloadRef !== canonicalSha256(item) || row.createdAt !== item.createdAt ||
      checkpoint.runId !== item.runId || checkpoint.runItemSeq !== row.itemSeq || checkpoint.journalSeq !== terminal.seq ||
      checkpoint.createdAt < item.createdAt || checkpoint.workspaceStateRef !== proof.workspaceStateRef ||
      proof.workspaceStateRef !== source.checkpoint.workspaceStateRef || snapshot.purpose !== 'sealed_to_checkpoint' ||
      snapshot.checkpointId !== checkpoint.id || snapshot.workspaceStateRef !== checkpoint.workspaceStateRef ||
      snapshot.observedAt < observation.observedAt || snapshot.observedAt > checkpoint.createdAt)
    throw new TypeError('dependency acquisition failure has no actual unchanged atomic parent Checkpoint');
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  validateContextItems(context, await artifacts.mapReads(source.items.slice(0, row.itemSeq), async row => ({ itemSeq: row.itemSeq,
    itemRef: row.payloadRef, item: await readCanonicalArtifact<import('../kernel/types.js').ContinuationItem>(artifacts, row.payloadRef) })));
  if (context.runId !== item.runId || context.throughItemSeq !== checkpoint.runItemSeq || context.assemblyRef !== source.spec.assemblyRef ||
      context.admittedContextRef !== source.spec.admittedContextRef) throw new TypeError('dependency acquisition failure lost its complete context');
  const generations = await artifacts.mapReads(source.generations, async generation => generation.phase === 'retired'
    ? (await readRetiredGenerationSource(driver, artifacts, { run: cut.run, spec: cut.runSpec, assembly: source.assembly, generation })).source : generation);
  const generation = generations.find(generation => generation.phase === 'sealed' && generation.generationRef === snapshot.generationRef && generation.snapshotEvidenceRef === proof.snapshotEvidenceRef);
  const launch = source.workers.find(launch => launch.launchId === evidence.workerLaunchId);
  if (!generation || generation.phase !== 'sealed' || !launch || launch.phase !== 'retired' || launch.generationWriteState !== 'sealed' ||
      launch.workspaceGenerationRef !== generation.generationRef || !launch.retirementEvidenceRef)
    throw new TypeError('dependency acquisition failure has no real original parent retirement');
  validateMatchingWorkerDeath(await readCanonicalArtifact(artifacts, proof.parentRetirementEvidenceRef),
    await readCanonicalArtifact(artifacts, launch.retirementEvidenceRef), 'dependency acquisition original parent continuous retirement');
  await validateRetainedWorkerSeal(driver, artifacts, { run: cut.run, spec: cut.runSpec, assembly: source.assembly, launch, generation });
  const budget = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, terminal.budgetSettlementRef));
  requireEqual(prepared.budgetDelta, { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, 'dependency acquisition one reservation');
  requireEqual(claim.budgetDelta, { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, 'dependency acquisition no second charge');
  requireEqual(terminal.budgetDelta, prepared.budgetDelta, 'dependency acquisition original one charge');
  if (budget.runId !== item.runId || budget.opId !== item.opId || budget.attempt !== item.attempt ||
      budget.preparedJournalSeq !== prepared.seq || budget.terminalJournalSeq !== terminal.seq || budget.terminalPhase !== 'failed')
    throw new TypeError('dependency acquisition failure lost its unique settlement');
  scripts?.assertUnchanged(driver); source.assertUnchanged(driver); artifacts.assertReadActive();
  return { item, source, proof, checkpoint, snapshot, assertUnchanged: source.assertUnchanged };
}
