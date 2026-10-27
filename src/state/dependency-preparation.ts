import { canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireRecord } from '../kernel/control-wire-data.js';
import type { RunFrontier } from '../kernel/types.js';
import { decodeDependencyOperationGrant } from '../kernel/dependency-invocation.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual, type ReleaseTrustKey } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { readCurrentDependencyCandidate, readRetainedDependencyCandidate, type DependencyCandidateData } from './dependency-candidate.js';
import { planDependencyInvocation } from './dependency-invocation-plan.js';
import { prepareDependencyScriptApproval, readRetainedDependencyScriptsCandidateTemplate } from './dependency-script-approval.js';
import { readDependencyScriptsTemplateHistory } from './dependency-script-history.js';
import { sameDependencyScriptInputs } from './dependency-script-source.js';
import { KernelStorageError } from './errors.js';
import { readHighestPreparedAttempt, readInvocationAttempt } from './repositories/journal.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef } from './repositories/workspace-generations.js';
import { assertLiveDispatchState, prepareValidatedInvocation } from './reducers/invocation.js';
import { readRun } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

const RESERVATION = Object.freeze({ modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 });
function invalid(message: string): never { throw new KernelStorageError('STATE_TRANSITION_INVALID', message); }
/** Worker-free selection only. Exact script consent is resolved before any
 * native parent, acquisition grant, reservation or permanent claim is made. */
export async function selectDependencyBeforeWorker(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { runId: string; expectedRunRevision: number }, releaseKeys: readonly ReleaseTrustKey[], signal?: AbortSignal) {
  assertControlWireJson(input); controlWireRecord(input, ['runId', 'expectedRunRevision']); input = immutableSnapshot(input);
  const source = await readCurrentDependencyCandidate(driver, artifacts, input.runId, { releaseKeys, signal });
  assertActiveStateOwner(driver, owner);
  if (source.run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'dependency source revision changed');
  if (source.run.parentRunId) {
    const run = await (await import('./dependency-inherited.js')).commitInheritedCandidateReady(driver, signal ? artifacts.withReadSignal(signal) : artifacts, owner, source.run.id, source.run.revision);
    return Object.freeze({ disposition: 'ready' as const, run });
  }
  if (source.plan.allowInstallScripts) {
    const selected = await prepareDependencyScriptApproval(driver, artifacts, owner, { bundle: source.bundle, releaseKeys }, input, signal);
    if (selected.disposition !== 'authorized') return selected;
  }
  source.assertUnchanged(driver);
  return Object.freeze({ disposition: 'worker_required' as const, run: source.run });
}
async function actualActiveSource(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { runId: string; expectedRunRevision: number; leaseEpoch: number }, releaseKeys: readonly ReleaseTrustKey[], signal?: AbortSignal) {
  const run = readRun(driver, input.runId), live = assertLiveDispatchState(driver, owner, input.runId, input.expectedRunRevision, input.leaseEpoch, sampleCanonicalNow());
  if (run.nextStep !== 'verify' || !run.frontierRef || run.parentRunId) invalid('dependency acquisition requires its exact root/Delivery candidate');
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef);
  if (frontier.kind !== 'verify' || frontier.phase !== 'dependencies' || !frontier.dependencyPlanRef || frontier.nextVerifierIndex !== 0)
    invalid('dependency acquisition has no original unconsumed dependencies frontier');
  const launch = readRequiredWorkerLaunch(driver, run.activeWorkerLaunchId!);
  if (launch.phase !== 'activated') invalid('dependency acquisition requires its actual activated original parent');
  const generation = readRequiredWorkspaceGenerationByRef(driver, launch.workspaceGenerationRef);
  requireEqual(generation, live.generation, 'dependency exact current original generation');
  const source = await readRetainedDependencyCandidate(driver, artifacts, run.id, { candidateItemId: frontier.candidateItemId,
    sourceCheckpointId: generation.sourceCheckpointId, dependencyPlanRef: frontier.dependencyPlanRef, resultSourceRef: frontier.resultSourceRef, releaseKeys, signal });
  requireEqual(source.run, run, 'dependency active original candidate Run'); source.assertUnchanged(driver);
  return { source, frontier, sourceCheckpointId: generation.sourceCheckpointId };
}
async function scriptAuthority(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  source: DependencyCandidateData, releaseKeys: readonly ReleaseTrustKey[], signal?: AbortSignal) {
  if (!source.plan.allowInstallScripts) return undefined;
  if (!source.policy.installScriptsGrantRef) invalid('dependency lifecycle has no original admission template');
  const runtime = { bundle: source.bundle, releaseKeys }, at = sampleCanonicalNow();
  const initial = await (await import('./dependency-initial-consent.js')).readInitialDependencyScriptsConsent(driver, artifacts, source, signal);
  if (initial.template.runId === source.run.id && initial.template.provenance.kind === 'run_admission' && sameDependencyScriptInputs(initial.template.scriptConditions, source.conditions) &&
      source.candidateOrdinal < initial.template.maxCandidateGenerations && at < initial.template.expiresAt) return initial;
  const candidate = await readRetainedDependencyScriptsCandidateTemplate(driver, artifacts, owner, runtime, { runId: source.run.id,
    candidateItemId: source.candidate.itemId, sourceCheckpointId: source.checkpoint.id, dependencyPlanRef: source.dependencyPlanRef,
    resultSourceRef: source.candidate.resultSourceRef }, signal);
  if (!candidate || at >= candidate.template.expiresAt) invalid('dependency lifecycle requires its current exact committed candidate consent');
  return candidate;
}
/** The actual activated parent is reread after selection/consent. Its original
 * source and committed consent are reconstructed, never carried as booleans
 * or an authority-bearing snapshot from the earlier worker-free cut. */
export async function prepareActiveDependencyInvocation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { runId: string; expectedRunRevision: number; leaseEpoch: number }, releaseKeys: readonly ReleaseTrustKey[], signal?: AbortSignal) {
  assertControlWireJson(input); controlWireRecord(input, ['runId', 'expectedRunRevision', 'leaseEpoch']); input = immutableSnapshot(input);
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const selected = await actualActiveSource(driver, reads, owner, input, releaseKeys, signal), source = selected.source;
  const scripts = await scriptAuthority(driver, reads, owner, source, releaseKeys, signal);
  const plan = planDependencyInvocation({ runId: source.run.id, principalId: source.principalId, policyRef: source.spec.policyRef,
    frontierRef: source.run.frontierRef!, assemblyRef: source.spec.assemblyRef, workspaceIdentityRef: source.session.workspaceIdentityRef,
    workspaceIdentityDigest: source.workspaceIdentity.identityDigest, candidateItemId: source.candidate.itemId, candidateOrdinal: source.candidateOrdinal,
    resultSourceRef: source.candidate.resultSourceRef, sourceDigest: source.candidate.sourceDigest,
    dependencyPolicyRef: source.spec.dependencyPolicyRef!, policy: source.policy, dependencyPlanRef: source.dependencyPlanRef,
    plan: source.plan, conditions: source.conditions, deadlineAt: source.run.deadlineAt,
    ...(scripts ? { scripts: { templateRef: scripts.templateRef, template: scripts.template } } : {}) });
  const prior = readHighestPreparedAttempt(driver, source.run.id, plan.request.opId);
  if (prior) {
    const rows = readInvocationAttempt(driver, source.run.id, prior.opId, prior.attempt);
    if (rows.length !== 1 || rows[0]?.phase !== 'prepared' || prior.opKind !== 'tool' || prior.target !== 'builtin:dependency-acquire' ||
        prior.requestRef !== canonicalSha256(plan.request) || prior.leaseEpoch !== input.leaseEpoch || !prior.grantRef)
      invalid('dependency cannot redispatch a claimed, terminal or unresolved original acquisition');
    const grant = decodeDependencyOperationGrant(await readCanonicalArtifact(reads, prior.grantRef));
    requireEqual(grant, plan.grant(grant.issuedAt, grant.expiresAt), 'dependency original unclaimed preparation grant');
    if (sampleCanonicalNow() >= grant.expiresAt) throw new KernelStorageError('LEASE_FENCED', 'dependency original preparation grant expired');
    source.assertUnchanged(driver); scripts?.assertUnchanged(driver);
    return Object.freeze({ disposition: 'prepared' as const, run: source.run, entry: prior, request: plan.request, target: plan.target,
      grant, source, sourceCheckpointId: selected.sourceCheckpointId });
  }
  const now = sampleCanonicalNow(), grant = plan.grant(now, scripts && scripts.template.expiresAt < source.run.deadlineAt ? scripts.template.expiresAt : source.run.deadlineAt);
  const published = await reads.publishCanonicalTriple([{ value: plan.request, schemaKind: plan.request.format },
    { value: plan.target, schemaKind: plan.target.format }, { value: grant, schemaKind: grant.format }]);
  if (published[0].ref !== canonicalSha256(plan.request) || published[1].ref !== canonicalSha256(plan.target) || published[2].ref !== canonicalSha256(grant))
    invalid('dependency original prepared artifacts changed during publication');
  const prepared = await prepareValidatedInvocation(driver, reads, owner, { runId: source.run.id, expectedRunRevision: source.run.revision,
    leaseEpoch: source.run.leaseEpoch, opId: plan.request.opId, opKind: 'tool', target: 'builtin:dependency-acquire',
    requestRef: published[0].ref, grantRef: published[2].ref, replayClass: 'workspace-rollback-retry', reservation: RESERVATION }, {
    metadata: [...published],
    validate(connection, run, attempt, at) {
      reads.assertReadActive(); assertActiveStateOwner(connection, owner); source.assertUnchanged(connection); scripts?.assertUnchanged(connection);
      requireEqual(run, source.run, 'dependency exact original active preparation Run');
      if (attempt !== 0 || at < grant.issuedAt || at >= grant.expiresAt) throw new KernelStorageError('LEASE_FENCED', 'dependency original attempt or consent expired');
    }
  });
  return Object.freeze({ disposition: 'prepared' as const, ...prepared, request: plan.request, target: plan.target, grant, source,
    sourceCheckpointId: selected.sourceCheckpointId });
}
export type PreparedDependencyInvocation = Awaited<ReturnType<typeof prepareActiveDependencyInvocation>>;
