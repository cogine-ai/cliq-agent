import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { DependencyAcquisitionPlan, DependencyInstallScriptsAuthorizationTemplateV1, DependencyPolicy,
  DependencyScriptConditionsV1 } from '../kernel/dependency.js';
import { planDependencyInvocation, type DependencyInvocationContext } from './dependency-invocation-plan.js';

// Pure inert data. These values are no registration, capture, consent or Run.
const ref = (name: string) => canonicalSha256({ inertFixture: name });
function data(scripts = false): DependencyInvocationContext {
  const conditions: DependencyScriptConditionsV1 = { profile: 'npm-ci-v1', lockfilePath: 'package-lock.json', lockfileDigest: ref('lock'),
    packageManifestDigest: ref('package'), bindingGyp: { kind: 'absent' }, source: { sourceManifestRef: ref('result source'),
      sourceManifestDigest: ref('result source meaning'), sourceRole: 'result', projectedEntriesRef: ref('projected entries'),
      projectedTreeDigest: ref('projected tree'), sourceProjectionRef: ref('projection'), sourceProjectionDigest: ref('projection meaning'),
      workspaceEntriesRef: ref('all entries'), workspaceTreeDigest: ref('all tree'), scriptInputTreeDigest: ref('program inputs'), privateGit: { kind: 'absent' } },
    execution: { runtimeBundleRef: ref('runtime'), runtimeBundleManifestDigest: ref('runtime meaning'), guestToolchainManifestRef: ref('guest'),
      guestToolchainManifestDigest: ref('guest meaning'), nodeExecutionPath: '/usr/bin/node', nodeExecutableDigest: ref('node'),
      adapterCodeRef: ref('adapter'), npmDataRef: ref('npm data'), registryTargetsDigest: ref('registry inputs'), environmentDigest: ref('env') } };
  const endpoints = [{ endpointRegistrationRef: ref('registration'), endpointIdentityDigest: ref('endpoint'), tlsPolicyDigest: ref('TLS policy') }];
  conditions.execution.registryTargetsDigest = canonicalSha256({ registryEndpoints: endpoints, credentialGrantRefs: [] });
  const template: DependencyInstallScriptsAuthorizationTemplateV1 = { schemaVersion: 1, format: 'cliq-dependency-install-scripts-authorization-v1',
    runId: 'run', ownerPrincipalId: 'principal', workspaceIdentityDigest: ref('workspace meaning'),
    provenance: { kind: 'run_admission', sourceAuthorizationGrantId: 'grant', sourceConsumptionReceiptRef: ref('receipt') },
    scriptConditions: { ...conditions, source: { ...conditions.source, sourceManifestRef: ref('original base'), sourceManifestDigest: ref('base meaning'), sourceRole: 'base' } },
    guestToolchainManifestRef: conditions.execution.guestToolchainManifestRef, allowedAdapters: ['npm-ci-v1'], lockfilePath: 'package-lock.json',
    lockfileRef: conditions.lockfileDigest, lockfileDigest: conditions.lockfileDigest, packageManifestRef: conditions.packageManifestDigest,
    packageManifestDigest: conditions.packageManifestDigest, bindingGyp: { kind: 'absent' }, registryTargetsDigest: conditions.execution.registryTargetsDigest,
    maxCandidateGenerations: 3, maxDispatchedAttemptsPerPlan: 1, expiresAt: '2026-10-27T01:00:00.000Z', templateDigest: '' };
  template.templateDigest = digestOmitting(template, 'templateDigest');
  const policy: DependencyPolicy = { schemaVersion: 1, mode: 'locked_node', allowedAdapters: ['npm-ci-v1'], registryEndpoints: endpoints, credentialGrantRefs: [],
    installScriptsPolicy: scripts ? 'exact_lockfile_grant' : 'deny', ...(scripts ? { installScriptsGrantRef: canonicalSha256(template) } : {}),
    maxPackages: 50_000, maxDownloadBytes: 5 * 1_073_741_824 };
  const plan: DependencyAcquisitionPlan = { schemaVersion: 1, format: 'cliq-dependency-acquisition-plan-v1', ecosystem: 'node', adapter: 'npm-ci-v1',
    lockfilePath: 'package-lock.json', guestToolchainManifestRef: conditions.execution.guestToolchainManifestRef,
    packageManifest: { canonicalRootRelativePath: 'package.json', contentRef: conditions.packageManifestDigest, contentDigest: conditions.packageManifestDigest },
    bindingGyp: { kind: 'absent' }, lockfileRef: conditions.lockfileDigest, lockfileDigest: conditions.lockfileDigest,
    registryEndpoints: policy.registryEndpoints, credentialGrantRefs: [], allowInstallScripts: scripts, maxPackages: policy.maxPackages,
    maxDownloadBytes: policy.maxDownloadBytes, packageCount: 0, packageDescriptorBytes: 0, descriptorSequenceDigest: ref('empty sequence'), planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest');
  return { runId: 'run', principalId: 'principal', policyRef: ref('policy'), frontierRef: ref('frontier'), assemblyRef: ref('assembly'),
    workspaceIdentityRef: ref('workspace'), workspaceIdentityDigest: ref('workspace meaning'), candidateItemId: 'candidate', candidateOrdinal: 0,
    resultSourceRef: conditions.source.sourceManifestRef, sourceDigest: conditions.source.sourceManifestDigest,
    dependencyPolicyRef: canonicalSha256(policy), policy, dependencyPlanRef: canonicalSha256(plan), plan, conditions,
    deadlineAt: '2026-10-27T01:00:00.000Z', ...(scripts ? { scripts: { templateRef: canonicalSha256(template), template } } : {}) };
}

test('whole dependency data uses one stable operation and preserves the script dispatch ceiling', () => {
  for (const scripts of [false, true]) {
    const context = data(scripts), selected = planDependencyInvocation(context);
    const grant = selected.grant('2026-10-27T00:00:00.000Z', '2026-10-27T00:00:30.000Z');
    assert.equal(grant.maxDispatchedAttempts, scripts ? 1 : 2);
    assert.equal(grant.provenance.kind, scripts ? 'dependency_install_scripts_template' : 'dependency_policy');
    assert.equal(selected.request.opId, planDependencyInvocation(structuredClone(context)).request.opId);
    assert.equal(grant.requestRef, canonicalSha256(selected.request)); assert.equal(grant.targetRef, canonicalSha256(selected.target));
    assert.throws(() => selected.grant('2026-10-27T01:00:00.000Z', '2026-10-27T01:00:01.000Z'));
    assert(Object.isFrozen(selected.request)); assert(Object.isFrozen(selected.target.scriptConditions.source));
  }
});

test('lifecycle data refuses root/ignored program, package, gyp, registry and candidate substitution', () => {
  const context = data(true);
  for (const changed of [
    { ...context, conditions: { ...context.conditions, source: { ...context.conditions.source, scriptInputTreeDigest: ref('changed ignored program') } } },
    { ...context, conditions: { ...context.conditions, packageManifestDigest: ref('changed package scripts') } },
    { ...context, conditions: { ...context.conditions, bindingGyp: { kind: 'present', contentDigest: ref('new gyp') } } },
    { ...context, conditions: { ...context.conditions, execution: { ...context.conditions.execution, registryTargetsDigest: ref('other registries') } } },
    { ...context, candidateOrdinal: 3 }, { ...context, scripts: undefined }, { ...context, dependencyPlanRef: ref('other plan') }
  ]) assert.throws(() => planDependencyInvocation(changed as DependencyInvocationContext));
  let reads = 0; const fake = { get runId() { reads++; return 'run'; } };
  assert.throws(() => planDependencyInvocation(fake as unknown as DependencyInvocationContext)); assert.equal(reads, 0);
  const changed = data(false); changed.conditions.source.scriptInputTreeDigest = ref('different source without scripts');
  assert.doesNotThrow(() => planDependencyInvocation(changed));
});
