import { canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireRecord } from '../kernel/control-wire-data.js';
import { decodeDependencyAcquisitionPlan, decodeDependencyInstallScriptsTemplate, decodeDependencyPolicy,
  decodeDependencyScriptConditions, dependencyRegistryTargetsDigest, type DependencyAcquisitionPlan, type DependencyInstallScriptsAuthorizationTemplateV1,
  type DependencyPolicy, type DependencyScriptConditionsV1 } from '../kernel/dependency.js';
import { decodeDependencyOperationGrant, decodeDependencyRequest, decodeDependencyTarget,
  type DependencyOperationGrantV1 } from '../kernel/dependency-invocation.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { sameDependencyScriptInputs } from './dependency-script-source.js';

export type DependencyInvocationContext = {
  runId: string; principalId: string; policyRef: string; frontierRef: string; assemblyRef: string;
  workspaceIdentityRef: string; workspaceIdentityDigest: string; candidateItemId: string; candidateOrdinal: number;
  resultSourceRef: string; sourceDigest: string; dependencyPolicyRef: string; policy: DependencyPolicy;
  dependencyPlanRef: string; plan: DependencyAcquisitionPlan; conditions: DependencyScriptConditionsV1; deadlineAt: string;
  scripts?: { templateRef: string; template: DependencyInstallScriptsAuthorizationTemplateV1 };
};
export const dependencyOperationId = (runId: string, candidateItemId: string, dependencyPlanRef: string) =>
  identityHash('cliq-dependency-acquire-operation-v1', runId, candidateItemId, dependencyPlanRef);

/** Deterministic data only. Template registration/consumption is independently
 * read by its original history and every native release checks the live cut. */
export function planDependencyInvocation(input: DependencyInvocationContext) {
  assertControlWireJson(input);
  controlWireRecord(input, ['runId', 'principalId', 'policyRef', 'frontierRef', 'assemblyRef', 'workspaceIdentityRef',
    'workspaceIdentityDigest', 'candidateItemId', 'candidateOrdinal', 'resultSourceRef', 'sourceDigest', 'dependencyPolicyRef',
    'policy', 'dependencyPlanRef', 'plan', 'conditions', 'deadlineAt'], ['scripts']);
  if (input.scripts) controlWireRecord(input.scripts, ['templateRef', 'template']);
  const context = immutableSnapshot(input), policy = decodeDependencyPolicy(context.policy), plan = decodeDependencyAcquisitionPlan(context.plan);
  const conditions = decodeDependencyScriptConditions(context.conditions);
  for (const ref of [context.policyRef, context.frontierRef, context.assemblyRef, context.workspaceIdentityRef,
    context.workspaceIdentityDigest, context.resultSourceRef, context.sourceDigest, context.dependencyPolicyRef, context.dependencyPlanRef]) assertArtifactRef(ref);
  if (canonicalSha256(policy) !== context.dependencyPolicyRef || canonicalSha256(plan) !== context.dependencyPlanRef ||
      policy.mode !== 'locked_node' || plan.adapter !== 'npm-ci-v1' || !policy.allowedAdapters.includes(plan.adapter) ||
      plan.lockfileDigest !== conditions.lockfileDigest || plan.packageManifest.contentDigest !== conditions.packageManifestDigest ||
      plan.guestToolchainManifestRef !== conditions.execution.guestToolchainManifestRef || plan.maxPackages !== policy.maxPackages ||
      plan.maxDownloadBytes !== policy.maxDownloadBytes || canonicalSha256(plan.registryEndpoints) !== canonicalSha256(policy.registryEndpoints) ||
      canonicalSha256(plan.credentialGrantRefs) !== canonicalSha256(policy.credentialGrantRefs) || plan.credentialGrantRefs.length ||
      conditions.execution.registryTargetsDigest !== dependencyRegistryTargetsDigest(policy) ||
      conditions.source.sourceManifestRef !== context.resultSourceRef || conditions.source.sourceManifestDigest !== context.sourceDigest ||
      conditions.source.sourceRole !== 'result' || !Number.isSafeInteger(context.candidateOrdinal) || context.candidateOrdinal < 0 ||
      plan.allowInstallScripts !== (policy.installScriptsPolicy === 'exact_lockfile_grant') || plan.allowInstallScripts !== !!context.scripts)
    throw new TypeError('dependency invocation differs from its complete frozen candidate inputs');
  requireEqual(plan.bindingGyp.kind === 'absent' ? { kind: 'absent' } : { kind: 'present', contentDigest: plan.bindingGyp.contentDigest },
    conditions.bindingGyp, 'dependency invocation binding.gyp');
  if (context.scripts) {
    const template = decodeDependencyInstallScriptsTemplate(context.scripts.template);
    if (canonicalSha256(template) !== context.scripts.templateRef || template.runId !== context.runId ||
        template.ownerPrincipalId !== context.principalId || template.workspaceIdentityDigest !== context.workspaceIdentityDigest ||
        template.guestToolchainManifestRef !== plan.guestToolchainManifestRef || !template.allowedAdapters.includes(plan.adapter) ||
        template.lockfilePath !== plan.lockfilePath || template.lockfileRef !== plan.lockfileRef || template.lockfileDigest !== plan.lockfileDigest ||
        template.packageManifestRef !== plan.packageManifest.contentRef || template.packageManifestDigest !== plan.packageManifest.contentDigest ||
        template.registryTargetsDigest !== conditions.execution.registryTargetsDigest || template.maxDispatchedAttemptsPerPlan !== 1 ||
        context.candidateOrdinal >= template.maxCandidateGenerations || !sameDependencyScriptInputs(template.scriptConditions, conditions) ||
        template.expiresAt > context.deadlineAt)
      throw new TypeError('dependency lifecycle template differs from its whole program and candidate inputs');
    if (template.provenance.kind === 'candidate_approval' && (template.provenance.candidateOrdinal !== context.candidateOrdinal ||
        template.provenance.dependencyPlanRef !== context.dependencyPlanRef || template.provenance.resultSourceRef !== context.resultSourceRef))
      throw new TypeError('dependency candidate approval belongs to another original candidate');
  }
  const targetCore = { schemaVersion: 1 as const, format: 'cliq-dependency-target-v1' as const, runId: context.runId,
    candidateItemId: context.candidateItemId, workspaceIdentityRef: context.workspaceIdentityRef, workspaceIdentityDigest: context.workspaceIdentityDigest,
    resultSourceRef: context.resultSourceRef, sourceDigest: context.sourceDigest, dependencyPlanRef: context.dependencyPlanRef,
    dependencyPlanDigest: plan.planDigest, scriptConditions: conditions, allowInstallScripts: plan.allowInstallScripts,
    ...(context.scripts ? { scriptAuthorizationTemplateRef: context.scripts.templateRef } : {}) };
  const target = decodeDependencyTarget({ ...targetCore, targetDigest: canonicalSha256(targetCore) });
  const requestCore = { schemaVersion: 1 as const, format: 'cliq-dependency-request-v1' as const, runId: context.runId,
    opId: dependencyOperationId(context.runId, context.candidateItemId, context.dependencyPlanRef), frontierRef: context.frontierRef,
    assemblyRef: context.assemblyRef, candidateItemId: context.candidateItemId, resultSourceRef: context.resultSourceRef,
    dependencyPlanRef: context.dependencyPlanRef, dependencyPlanDigest: plan.planDigest,
    targetRef: canonicalSha256(target), targetDigest: target.targetDigest };
  const request = decodeDependencyRequest({ ...requestCore, requestDigest: canonicalSha256(requestCore) });
  function grant(issuedAt: string, expiresAt: string): DependencyOperationGrantV1 {
    if (parseCanonicalTime(issuedAt) >= parseCanonicalTime(expiresAt) || expiresAt > context.deadlineAt ||
        context.scripts && expiresAt > context.scripts.template.expiresAt)
      throw new TypeError('dependency grant exceeds its original Run or lifecycle consent deadline');
    const subject = { kind: 'dependency_acquisition' as const, dependencyPlanRef: context.dependencyPlanRef,
      lockfileDigest: plan.lockfileDigest, resultSourceRef: context.resultSourceRef, installScripts: plan.allowInstallScripts };
    const provenance: DependencyOperationGrantV1['provenance'] = context.scripts
      ? { kind: 'dependency_install_scripts_template', dependencyPolicyRef: context.dependencyPolicyRef,
          templateRef: context.scripts.templateRef, candidateOrdinal: context.candidateOrdinal }
      : { kind: 'dependency_policy', dependencyPolicyRef: context.dependencyPolicyRef, dependencyPolicyDigest: canonicalSha256(policy) };
    const core = { schemaVersion: 1 as const, format: 'cliq-operation-grant-v1' as const,
      grantId: identityHash('cliq-operation-grant-v1', context.runId, request.opId, request.requestDigest, subject, issuedAt),
      principalId: context.principalId, runId: context.runId, policyRef: context.policyRef, frontierRef: context.frontierRef,
      opId: request.opId, requestRef: canonicalSha256(request), requestDigest: request.requestDigest,
      targetRef: request.targetRef, targetDigest: target.targetDigest, subject, provenance,
      maxDispatchedAttempts: (plan.allowInstallScripts ? 1 : 2) as 1 | 2, issuedAt, expiresAt, grantDigest: '' };
    core.grantDigest = digestOmitting(core, 'grantDigest'); return immutableSnapshot(decodeDependencyOperationGrant(core));
  }
  return Object.freeze({ request: immutableSnapshot(request), target: immutableSnapshot(target), grant });
}
