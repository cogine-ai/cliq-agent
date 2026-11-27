import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { digestOmitting } from './identity.js';
import type { DependencyScriptConditionsV1 } from './dependency.js';
import { decodeDependencyOperationGrant, decodeDependencyRequest, decodeDependencyTarget } from './dependency-invocation.js';

const ref = (name: string) => canonicalSha256(name);
const conditions: DependencyScriptConditionsV1 = {
  profile: 'npm-ci-v1', lockfilePath: 'package-lock.json', lockfileDigest: ref('lock'), packageManifestDigest: ref('package'), bindingGyp: { kind: 'absent' },
  source: { sourceManifestRef: ref('source'), sourceManifestDigest: ref('source meaning'), sourceRole: 'result',
    projectedEntriesRef: ref('projected'), projectedTreeDigest: ref('tree'), sourceProjectionRef: ref('projection'), sourceProjectionDigest: ref('projection meaning'),
    workspaceEntriesRef: ref('all entries'), workspaceTreeDigest: ref('all tree'), scriptInputTreeDigest: ref('program tree'), privateGit: { kind: 'absent' } },
  execution: { runtimeBundleRef: ref('runtime'), runtimeBundleManifestDigest: ref('runtime meaning'), guestToolchainManifestRef: ref('guest'),
    guestToolchainManifestDigest: ref('guest meaning'), nodeExecutionPath: '/usr/bin/node', nodeExecutableDigest: ref('node'),
    adapterCodeRef: ref('adapter'), npmDataRef: ref('npm'), registryTargetsDigest: ref('registry'), environmentDigest: ref('environment') }
};
const target = () => {
  const data = { schemaVersion: 1, format: 'cliq-dependency-target-v1', runId: 'run', candidateItemId: 'candidate',
    workspaceIdentityRef: ref('workspace'), workspaceIdentityDigest: ref('workspace meaning'), resultSourceRef: ref('source'),
    sourceDigest: ref('source meaning'), dependencyPlanRef: ref('plan'), dependencyPlanDigest: ref('plan meaning'),
    scriptConditions: conditions, allowInstallScripts: false, targetDigest: '' };
  data.targetDigest = digestOmitting(data, 'targetDigest'); return data;
};
const grant = (scripts: boolean) => {
  const data = { schemaVersion: 1, format: 'cliq-operation-grant-v1', grantId: 'grant', principalId: 'owner', runId: 'run', policyRef: ref('policy'),
    frontierRef: ref('frontier'), opId: 'operation', requestRef: ref('request'), requestDigest: ref('request meaning'), targetRef: ref('target'), targetDigest: ref('target meaning'),
    subject: { kind: 'dependency_acquisition', dependencyPlanRef: ref('plan'), lockfileDigest: ref('lock'), resultSourceRef: ref('source'), installScripts: scripts },
    provenance: scripts ? { kind: 'dependency_install_scripts_template', dependencyPolicyRef: ref('dependency policy'), templateRef: ref('explicit template'), candidateOrdinal: 0 }
      : { kind: 'dependency_policy', dependencyPolicyRef: ref('dependency policy'), dependencyPolicyDigest: ref('dependency policy meaning') },
    maxDispatchedAttempts: scripts ? 1 : 2, issuedAt: '2026-10-01T00:00:00.000Z', expiresAt: '2026-10-01T00:01:00.000Z', grantDigest: '' };
  data.grantDigest = digestOmitting(data, 'grantDigest'); return data;
};

test('dependency request and target preserve one entire plan and actual result-source conditions', () => {
  assert.deepEqual(decodeDependencyTarget(target()), target());
  const request = { schemaVersion: 1, format: 'cliq-dependency-request-v1', runId: 'run', opId: 'operation', frontierRef: ref('frontier'),
    assemblyRef: ref('assembly'), candidateItemId: 'candidate', resultSourceRef: ref('source'), dependencyPlanRef: ref('plan'),
    dependencyPlanDigest: ref('plan meaning'), targetRef: ref('target'), targetDigest: ref('target meaning'), requestDigest: '' };
  request.requestDigest = digestOmitting(request, 'requestDigest'); assert.deepEqual(decodeDependencyRequest(request), request);
  for (const bad of [{ ...target(), resultSourceRef: ref('another source') }, { ...target(), allowInstallScripts: true },
    { ...target(), scriptAuthorizationTemplateRef: ref('unused template') }, { ...target(), arbitraryFlags: [] }]) {
    bad.targetDigest = digestOmitting(bad, 'targetDigest'); assert.throws(() => decodeDependencyTarget(bad));
  }
  assert.throws(() => decodeDependencyRequest({ ...request, opId: 'different operation' }));
});

test('dependency scripts use only explicit template provenance and its one-dispatch ceiling', () => {
  for (const scripts of [false, true]) assert.deepEqual(decodeDependencyOperationGrant(grant(scripts)), grant(scripts));
  const explicit = grant(true), deny = grant(false);
  for (const bad of [{ ...explicit, provenance: deny.provenance }, { ...deny, provenance: explicit.provenance },
    { ...explicit, maxDispatchedAttempts: 2 }, { ...deny, maxDispatchedAttempts: 3 },
    { ...explicit, provenance: { ...explicit.provenance, candidateOrdinal: -1 } },
    { ...explicit, expiresAt: explicit.issuedAt }, { ...explicit, maxLaunches: 1 }]) {
    bad.grantDigest = digestOmitting(bad, 'grantDigest'); assert.throws(() => decodeDependencyOperationGrant(bad));
  }
  let reads = 0; const fake = { get schemaVersion() { reads++; return 1; } };
  assert.throws(() => decodeDependencyRequest(fake)); assert.throws(() => decodeDependencyTarget(fake));
  assert.throws(() => decodeDependencyOperationGrant(fake)); assert.equal(reads, 0);
});
