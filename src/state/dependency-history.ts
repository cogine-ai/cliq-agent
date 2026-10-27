import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeDependencyReadyItem, decodeDependencyFailureItem, type DependencyReadyItem, type DependencyFailureItem } from '../kernel/dependency.js';
import { decodeDependencyClaimEvidence } from '../kernel/dependency-claim.js';
import { decodeDependencyOperationGrant, decodeDependencyRequest, decodeDependencyTarget } from '../kernel/dependency-invocation.js';
import type { RecoveryClosureV1, RunFrontier } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readRetainedDependencyCandidate } from './dependency-candidate.js';
import { planDependencyInvocation, dependencyOperationId } from './dependency-invocation-plan.js';
import { readAcquiredDependencyReady, readFailedDependencyResult } from './dependency-retirement.js';
import { readDependencyScriptsTemplateHistoryData } from './dependency-script-history.js';
import { finalCandidateCheckpointId } from './final-candidate-plan.js';
import { decodeFinalCandidateItem } from './result-artifacts.js';
import { readStateOwner } from './state-owner.js';
import { readRetainedDependencyLaunchEnvironment } from './execution-closure.js';
import type { SqliteDriver } from './sqlite-driver.js';

export type DependencyHistoryCut = Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'items' | 'journal' | 'workspaceGenerations'>;
export type DependencyProgress = { planRef: string; dependencyPolicyRef: string; initialFrontier: Extract<RunFrontier, { kind: 'verify' }>;
  ready?: DependencyReadyItem; failed?: DependencyFailureItem; completedJournalSeq?: number };

/** Every dependency operation is validated here before the ordinary tool
 * history may omit this distinct fixed purpose. This reader grants nothing
 * and never calls recovery, creates a worker or infers a retry from death. */
export async function readDependencyHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: DependencyHistoryCut) {
  const readyItems: DependencyReadyItem[] = [], failureItems: DependencyFailureItem[] = [];
  for (const row of cut.items) {
    const item = await readCanonicalArtifact<{ kind: string }>(artifacts, row.payloadRef);
    if (item.kind === 'dependency_failure') {
      const failed = decodeDependencyFailureItem(item);
      if (failed.itemId !== row.itemId || failed.runId !== cut.run.id || failed.createdAt !== row.createdAt) throw new TypeError('dependency failure differs from its real registered item');
      failureItems.push(failed); continue;
    }
    if (item.kind !== 'dependency_ready') continue;
    const ready = decodeDependencyReadyItem(item);
    if (ready.itemId !== row.itemId || ready.runId !== cut.run.id || ready.createdAt !== row.createdAt)
      throw new TypeError('dependency ready differs from its actual registered item');
    readyItems.push(ready);
  }
  const preparations = cut.journal.filter(row => row.phase === 'prepared' && row.opKind === 'tool' && row.target === 'builtin:dependency-acquire');
  if (!cut.runSpec.dependencyPolicyRef) {
    if (preparations.length || readyItems.length || failureItems.length) throw new TypeError('dependency history has no original frozen policy');
    return new Map<string, DependencyProgress>();
  }
  const result = new Map<string, DependencyProgress>(), consumed = new Set<string>(), consumedReady = new Set<string>(), consumedFailure = new Set<string>();
  for (const row of cut.items) {
    const raw = await readCanonicalArtifact<{ kind: string }>(artifacts, row.payloadRef);
    if (raw.kind !== 'final_candidate') continue;
    const candidate = decodeFinalCandidateItem(raw);
    const requests = await artifacts.mapReads(preparations, async prepared => ({ prepared,
      request: decodeDependencyRequest(await readCanonicalArtifact(artifacts, prepared.requestRef)) }));
    const selected = requests.filter(entry => entry.request.candidateItemId === candidate.itemId);
    if (selected.length > 1) throw new TypeError('dependency candidate has more than its one original acquisition');
    const entry = selected[0];
    let planRef: string;
    if (entry) planRef = entry.request.dependencyPlanRef;
    else {
      const plans = await (await import('./final-candidate-plan.js')).readCandidateVerificationData(artifacts, cut.runSpec,
        { runId: cut.run.id, candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef });
      if (!plans.dependency) throw new TypeError('locked dependency candidate lost its original complete plan');
      planRef = canonicalSha256(plans.dependency.plan);
    }
    let sourceCheckpointId = finalCandidateCheckpointId(cut.run.id, candidate.producingItemId);
    const rows = entry ? cut.journal.filter(item => item.opId === entry.prepared.opId && item.attempt === entry.prepared.attempt) : [];
    const claim = rows.find(item => item.phase === 'dispatch_claimed');
    const evidence = claim?.evidenceRef ? decodeDependencyClaimEvidence(await readCanonicalArtifact(artifacts, claim.evidenceRef)) : undefined;
    if (evidence) sourceCheckpointId = evidence.sourceCheckpointId;
    const source = await readRetainedDependencyCandidate(driver, artifacts, cut.run.id, { candidateItemId: candidate.itemId,
      sourceCheckpointId, dependencyPlanRef: planRef, resultSourceRef: candidate.resultSourceRef, releaseKeys: artifacts.releaseTrustRoots() });
    const initialFrontier: Extract<RunFrontier, { kind: 'verify' }> = { schemaVersion: 1, kind: 'verify', phase: 'dependencies',
      candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef, verifierPlanRef: source.verifierPlanRef,
      dependencyPlanRef: planRef, nextVerifierIndex: 0, afterPass: cut.runSpec.operation === 'delivery' ? 'delivery_approval' : 'finalize' };
    requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(initialFrontier)), initialFrontier, 'original dependency candidate frontier');
    const progress: DependencyProgress = { planRef, dependencyPolicyRef: cut.runSpec.dependencyPolicyRef, initialFrontier }; result.set(candidate.itemId, progress);
    const ownOpId = dependencyOperationId(cut.run.id, candidate.itemId, planRef);
    const inheritedId = (await import('./dependency-inherited.js')).inheritedDependencyItemId(cut.run.id, candidate.itemId, planRef);
    const ready = readyItems.filter(item => item.planRef === planRef && (item.origin === 'acquired' ? item.opId === ownOpId : item.itemId === inheritedId)),
      failures = failureItems.filter(item => item.planRef === planRef && item.opId === ownOpId);
    for (const item of ready) consumedReady.add(item.itemId); for (const item of failures) consumedFailure.add(item.itemId);
    if (failures.length > 1 || ready.length && failures.length) throw new TypeError('dependency candidate has conflicting terminal outcomes');
    if (ready.length > 1) throw new TypeError('dependency candidate acquired multiple ready outcomes');
    if (!entry) {
      if (failures.length || ready.some(item => item.origin !== 'inherited_parent_ready')) throw new TypeError('dependency result has no original acquisition');
      if (ready[0]?.origin === 'inherited_parent_ready') {
        const checked = await (await import('./dependency-inherited.js')).readInheritedDependencyReady(driver, artifacts, cut, ready[0]); progress.ready = checked.item;
      }
      source.assertUnchanged(driver); continue;
    }
    consumed.add(entry.prepared.opId);
    const { prepared, request } = entry;
    if (!prepared.grantRef || prepared.attempt !== 0 || prepared.opId !== dependencyOperationId(cut.run.id, candidate.itemId, planRef) ||
        request.runId !== cut.run.id || prepared.requestRef !== canonicalSha256(request) ||
        prepared.replayClass !== 'workspace-rollback-retry') throw new TypeError('dependency original preparation identity differs');
    const target = decodeDependencyTarget(await readCanonicalArtifact(artifacts, request.targetRef));
    const grant = decodeDependencyOperationGrant(await readCanonicalArtifact(artifacts, prepared.grantRef));
    const scripts = target.scriptAuthorizationTemplateRef ? await readDependencyScriptsTemplateHistoryData(driver, artifacts,
      { bundle: source.bundle, releaseKeys: artifacts.releaseTrustRoots() }, { runId: cut.run.id, templateRef: target.scriptAuthorizationTemplateRef }) : undefined;
    const expected = planDependencyInvocation({ runId: cut.run.id, principalId: source.principalId, policyRef: cut.runSpec.policyRef,
      frontierRef: canonicalSha256(initialFrontier), assemblyRef: cut.runSpec.assemblyRef, workspaceIdentityRef: source.session.workspaceIdentityRef,
      workspaceIdentityDigest: source.workspaceIdentity.identityDigest, candidateItemId: candidate.itemId, candidateOrdinal: source.candidateOrdinal,
      resultSourceRef: candidate.resultSourceRef, sourceDigest: candidate.sourceDigest, dependencyPolicyRef: cut.runSpec.dependencyPolicyRef,
      policy: source.policy, dependencyPlanRef: planRef, plan: source.plan, conditions: source.conditions, deadlineAt: cut.run.deadlineAt,
      ...(scripts ? { scripts: { templateRef: scripts.templateRef, template: scripts.template } } : {}) });
    requireEqual(request, expected.request, 'dependency complete retained request'); requireEqual(target, expected.target, 'dependency complete retained target');
    requireEqual(grant, expected.grant(grant.issuedAt, grant.expiresAt), 'dependency original policy and exact source consent');
    requireEqual(prepared.budgetDelta, { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, 'dependency one reservation');
    const phases = rows.map(row => row.phase).join(',');
    if (!['prepared', 'prepared,dispatch_claimed', 'prepared,dispatch_claimed,unknown', 'prepared,dispatch_claimed,completed', 'prepared,dispatch_claimed,failed'].includes(phases) ||
        prepared.timestamp < grant.issuedAt || prepared.timestamp >= grant.expiresAt) throw new TypeError('dependency retained lifecycle is not implemented or is out of authority');
    if (claim) {
      if (!evidence || evidence.runId !== cut.run.id || evidence.opId !== prepared.opId || evidence.attempt !== prepared.attempt ||
          evidence.dispatchId !== claim.dispatchId || evidence.workerLaunchId === '' || evidence.requestRef !== prepared.requestRef ||
          evidence.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest || evidence.dependencyPlanRef !== planRef ||
          evidence.evidenceDigest !== claim.evidenceDigest || claim.sandboxLaunchSpecRef !== undefined || claim.timestamp >= grant.expiresAt)
        throw new TypeError('dependency claim substitutes its complete original native owner');
      const owner = claim.stateOwnerEpoch && readStateOwner(driver, claim.stateOwnerEpoch);
      if (!owner || owner.supervisorInstanceId !== claim.supervisorInstanceId) throw new TypeError('dependency claim lost its actual original owner');
      const environment = await readRetainedDependencyLaunchEnvironment(artifacts, owner, cut.runSpec, evidence.sandboxLaunchSpecRef);
      if (environment.spec.owner.dispatchId !== claim.dispatchId || environment.spec.requestRef !== prepared.requestRef ||
          environment.spec.operationGrantRef !== prepared.grantRef || environment.spec.owner.workerLaunchId !== evidence.workerLaunchId)
        throw new TypeError('dependency claim original recipe identity differs');
    }
    if (rows.at(-1)?.phase === 'completed') {
      if (ready.length !== 1 || ready[0]!.origin !== 'acquired') throw new TypeError('dependency completion lacks its original ready Checkpoint');
      const checked = await readAcquiredDependencyReady(driver, artifacts, cut, ready[0]);
      progress.ready = checked.item; progress.completedJournalSeq = rows.at(-1)!.seq;
    } else if (rows.at(-1)?.phase === 'failed') {
      if (failures.length !== 1 || ready.length) throw new TypeError('dependency known failure lacks its original real post-effect Checkpoint');
      const checked = await readFailedDependencyResult(driver, artifacts, cut, failures[0]!); progress.failed = checked.item;
    } else if (ready.length || failures.length) throw new TypeError('dependency unknown or pending claim cannot assert a known result');
    else if (rows.at(-1)?.phase === 'unknown')
      await (await import('./dependency-unknown-retirement.js')).validateDependencyUnknownClaim(driver, artifacts, source, prepared, claim!, rows.at(-1)!);
    scripts?.assertUnchanged(driver); source.assertUnchanged(driver);
  }
  if (preparations.some(row => !consumed.has(row.opId))) throw new TypeError('dependency Journal has no original candidate');
  if (readyItems.some(item => !consumedReady.has(item.itemId)) || failureItems.some(item => !consumedFailure.has(item.itemId)))
    throw new TypeError('dependency result has no unique actual candidate owner');
  artifacts.assertReadActive(); return result;
}

/** Closed receipt projection only. The owning consumer must first run the
 * complete history above; this is never permission to acquire or execute. */
export function dependencyVerificationProjection(progress?: DependencyProgress): import('../kernel/types.js').VerificationClosureV1['dependency'] {
  if (!progress) return { kind: 'none' };
  const ready = progress.ready;
  if (!ready) throw new TypeError('verification has no complete original dependency readiness');
  const core = { kind: 'ready' as const, dependencyPolicyRef: progress.dependencyPolicyRef, dependencyPlanRef: progress.planRef,
    dependencyReadyItemId: ready.itemId, readyCheckpointId: ready.readyCheckpointId };
  if (ready.origin === 'inherited_parent_ready') return { ...core, origin: 'inherited_parent_ready', parentRunId: ready.parentRunId,
    parentReadyItemRef: ready.parentReadyItemRef, childAdmissionRequestRef: ready.childAdmissionRequestRef };
  if (!progress.completedJournalSeq) throw new TypeError('acquired readiness lost its original completed Journal');
  return { ...core, origin: 'acquired', acquisitionOpId: ready.opId, acquisitionAttempt: ready.attempt, completedJournalSeq: progress.completedJournalSeq };
}
