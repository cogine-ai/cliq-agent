import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { VerifierPlan } from '../kernel/result.js';
import type { RunAssemblyV1, VerifierSpec } from '../kernel/types.js';
import type { VerifierCommandV1, VerifierEnvironmentV1 } from '../kernel/verifier.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import type { VerifierOperationGrantV1, VerifierPolicyChannelEvidenceV1, VerifierRequestV1, VerifierTargetV1 } from '../kernel/verifier-invocation.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { assertRunPolicySnapshot, evaluateFrozenPolicyKey } from '../policy/tool-policy.js';
import { decodeVerifierPlan } from './result-artifacts.js';
import { decodeVerifierCommand, decodeVerifierEnvironment, decodeVerifierSpec } from './verifier-artifacts.js';

export type VerifierRequestContext = {
  runId: string; frontierRef: string; assemblyRef: string; candidateItemId: string; resultSourceRef: string; sourceDigest: string;
  verifierPlanRef: string; plan: VerifierPlan; verifierSpecRef: string; verifierSpec: VerifierSpec; verifierIndex: number;
  command: VerifierCommandV1; environment: VerifierEnvironmentV1;
};
export function verifierOperationId(runId: string, candidateItemId: string, verifierPlanRef: string, index: number): string {
  return identityHash('cliq-verifier-operation-v1', runId, candidateItemId, verifierPlanRef, String(index));
}

/** Deterministic plan projection, never permission or physical execution. */
export function planVerifierRequest(input: VerifierRequestContext) {
  const { runId, frontierRef, assemblyRef, candidateItemId, resultSourceRef, sourceDigest, verifierPlanRef, verifierSpecRef,
    verifierIndex, command, environment } = input;
  const plan = decodeVerifierPlan(input.plan), spec = decodeVerifierSpec(input.verifierSpec);
  decodeVerifierCommand(command); decodeVerifierEnvironment(environment);
  for (const ref of [frontierRef, assemblyRef, resultSourceRef, sourceDigest, verifierPlanRef, verifierSpecRef]) assertArtifactRef(ref);
  if (plan.runId !== runId || plan.candidateItemId !== candidateItemId || plan.resultSourceRef !== resultSourceRef ||
      canonicalSha256(plan) !== verifierPlanRef || plan.verifierSpecRef !== verifierSpecRef || canonicalSha256(spec) !== verifierSpecRef ||
      plan.verifierSpecDigest !== spec.specDigest || !Number.isSafeInteger(verifierIndex) || verifierIndex < 0 ||
      plan.entries.length !== spec.verifiers.length) throw new TypeError('verifier request differs from its candidate and frozen plan');
  const entries = spec.verifiers.map(entry => ({ index: entry.index, verifierId: entry.id, verifierSpecDigest: spec.specDigest,
    verifierEntryDigest: entry.entryDigest, commandRef: entry.commandRef, commandDigest: entry.commandDigest,
    environmentRef: entry.environmentRef, environmentDigest: entry.environmentDigest, required: entry.gate === 'required', maxAttempts: entry.retries + 1 }));
  requireEqual(plan.entries, entries, 'complete frozen verifier plan');
  const entry = spec.verifiers[verifierIndex];
  if (!entry || entry.commandRef !== canonicalSha256(command) || entry.commandDigest !== command.commandDigest ||
      entry.environmentRef !== canonicalSha256(environment) || entry.environmentDigest !== environment.environmentDigest ||
      command.verifierId !== entry.id || command.verifierVersion !== entry.version || environment.verifierId !== entry.id ||
      environment.verifierVersion !== entry.version || environment.commandRef !== entry.commandRef || environment.commandDigest !== entry.commandDigest)
    throw new TypeError('verifier request substitutes its frozen command or environment');
  const targetCore = { schemaVersion: 1 as const, format: 'cliq-verifier-target-v1' as const, runId, candidateItemId, resultSourceRef, sourceDigest,
    verifierPlanRef, verifierPlanDigest: plan.planDigest, verifierSpecRef, verifierSpecDigest: spec.specDigest, verifierIndex,
    verifierId: entry.id, verifierVersion: entry.version, verifierEntryDigest: entry.entryDigest,
    commandRef: entry.commandRef, commandDigest: entry.commandDigest, environmentRef: entry.environmentRef, environmentDigest: entry.environmentDigest,
    required: entry.gate === 'required', maxAttempts: entry.retries + 1 };
  const target: VerifierTargetV1 = { ...targetCore, targetDigest: canonicalSha256(targetCore) };
  const requestCore = { schemaVersion: 1 as const, format: 'cliq-verifier-request-v1' as const, runId,
    opId: verifierOperationId(runId, candidateItemId, verifierPlanRef, verifierIndex), frontierRef, assemblyRef, candidateItemId,
    verifierPlanRef, verifierIndex, targetRef: canonicalSha256(target), targetDigest: target.targetDigest };
  const request: VerifierRequestV1 = { ...requestCore, requestDigest: canonicalSha256(requestCore) };
  return immutableSnapshot({ request, target, entry });
}

/** Named verifier effects share the same validated policy snapshot and rule
 * precedence as tools; a coarse mode or identity-read grant is never enough. */
export function loadVerifierPolicy(input: {
  policy: RunPolicySnapshotV1; policyRef: string; assembly: RunAssemblyV1; assemblyRef: string;
  principalId: string; workspaceIdentityDigest: string; context: VerifierRequestContext;
}) {
  const { policy, policyRef, assembly, assemblyRef, principalId, workspaceIdentityDigest, context } = immutableSnapshot(input);
  assertRunPolicySnapshot({ policy, policyRef, assembly, principalId, workspaceIdentityDigest });
  if (context.assemblyRef !== assemblyRef) throw new TypeError('verifier permission selects another assembly');
  const planned = planVerifierRequest(context);
  function evaluate(request: VerifierRequestV1, target: VerifierTargetV1, evaluatedAt: string): VerifierPolicyChannelEvidenceV1 {
    parseCanonicalTime(evaluatedAt);
    if (evaluatedAt < policy.createdAt) throw new TypeError('verifier permission precedes its frozen policy');
    requireEqual(request, planned.request, 'verifier request'); requireEqual(target, planned.target, 'verifier target');
    const namedAction = { kind: 'verifier' as const, candidateItemId: target.candidateItemId, verifierPlanRef: target.verifierPlanRef, verifierId: target.verifierId };
    const identityKey = `verifier/${target.verifierId}`;
    const winning = evaluateFrozenPolicyKey(policy, 'verifier', 'named-action', identityKey);
    const core = { schemaVersion: 1 as const, format: 'cliq-policy-channel-evidence-v1' as const, principalId, runId: request.runId,
      policyRef, policyDigest: policy.policyDigest, frontierRef: request.frontierRef, opId: request.opId,
      requestRef: canonicalSha256(request), requestDigest: request.requestDigest, targetRef: request.targetRef, targetDigest: request.targetDigest,
      actionClass: 'verifier' as const, decisionSource: winning.ruleId === undefined ? 'mode_fallthrough' as const : 'rule' as const,
      matchedRuleIds: winning.ruleId === undefined ? [] : [winning.ruleId], effectiveDisposition: winning.disposition,
      evaluatedAt, channel: 'named-action' as const, namedAction, identityKey };
    return immutableSnapshot({ ...core, evidenceDigest: canonicalSha256(core) });
  }
  function grant(request: VerifierRequestV1, target: VerifierTargetV1, evidence: VerifierPolicyChannelEvidenceV1,
    issuedAt: string, expiresAt: string): VerifierOperationGrantV1 {
    requireEqual(evidence, evaluate(request, target, evidence.evaluatedAt), 'verifier policy channel evidence');
    if (evidence.effectiveDisposition !== 'allow' || parseCanonicalTime(issuedAt) < parseCanonicalTime(evidence.evaluatedAt) ||
        parseCanonicalTime(expiresAt) <= parseCanonicalTime(issuedAt)) throw new TypeError('only an exact direct allow can mint a verifier grant');
    const decision = { policyRef, channelEvidenceRef: canonicalSha256(evidence), channelEvidenceDigest: evidence.evidenceDigest,
      actionClass: 'verifier' as const, requestDigest: request.requestDigest, targetDigest: target.targetDigest,
      matchedRuleIds: evidence.matchedRuleIds, effectiveDisposition: 'allow' as const };
    const subject: VerifierOperationGrantV1['subject'] = { kind: 'verifier_launch', candidateItemId: target.candidateItemId,
      resultSourceRef: target.resultSourceRef, verifierPlanRef: target.verifierPlanRef, verifierIndex: target.verifierIndex,
      verifierId: target.verifierId, verifierSpecDigest: target.verifierSpecDigest, required: target.required };
    const core = { schemaVersion: 1 as const, format: 'cliq-operation-grant-v1' as const,
      grantId: identityHash('cliq-operation-grant-v1', request.runId, request.opId, request.requestDigest, subject, issuedAt),
      principalId, runId: request.runId, policyRef, frontierRef: request.frontierRef, opId: request.opId,
      requestRef: canonicalSha256(request), requestDigest: request.requestDigest, targetRef: request.targetRef, targetDigest: target.targetDigest,
      subject, provenance: { kind: 'policy_snapshot' as const, actionClass: 'verifier' as const,
        channelEvidenceRef: decision.channelEvidenceRef, channelEvidenceDigest: decision.channelEvidenceDigest,
        matchedRuleIds: evidence.matchedRuleIds, effectiveDisposition: 'allow' as const, decisionDigest: canonicalSha256(decision) },
      maxDispatchedAttempts: target.maxAttempts, issuedAt, expiresAt };
    return immutableSnapshot({ ...core, grantDigest: canonicalSha256(core) });
  }
  return Object.freeze({ evaluate, grant });
}
