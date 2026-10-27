import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from './canonical.js';
import { decodeDependencyScriptConditions, decodeDependencyInstallScriptsTemplate, type DependencyScriptConditionsV1, type DependencyInstallScriptsAuthorizationTemplateV1 } from './dependency.js';
import { decodeAuthorizationCreateRequest, decodeInstalledControlEnvelope } from './control-wire.js';
import { createSourceInspectionErrorResponse, assertSourceInspectionErrorResponse, DependencyScriptAuthorizationRequired } from '../state/source-inspection-error.js';
import { identityHash, digestOmitting } from './identity.js';

const ref = (name: string) => canonicalSha256({ inertFixture: name });
function conditions(): DependencyScriptConditionsV1 {
  return { profile: 'npm-ci-v1', lockfilePath: 'package-lock.json', lockfileDigest: ref('lock'), packageManifestDigest: ref('package'), bindingGyp: { kind: 'absent' },
    source: { sourceManifestRef: ref('manifest bytes'), sourceManifestDigest: ref('manifest meaning'), sourceRole: 'base',
      projectedEntriesRef: ref('projection entries'), projectedTreeDigest: ref('projection tree'), sourceProjectionRef: ref('projection'),
      sourceProjectionDigest: ref('projection meaning'), workspaceEntriesRef: ref('complete entries'), workspaceTreeDigest: ref('complete tree'), scriptInputTreeDigest: ref('derived actual program inputs'), privateGit: { kind: 'absent' } },
    execution: { runtimeBundleRef: ref('runtime'), runtimeBundleManifestDigest: ref('runtime meaning'), guestToolchainManifestRef: ref('guest'),
      guestToolchainManifestDigest: ref('guest meaning'), nodeExecutionPath: '/usr/bin/node', nodeExecutableDigest: ref('node'),
      adapterCodeRef: ref('adapter'), npmDataRef: ref('official npm data'), registryTargetsDigest: ref('targets'), environmentDigest: ref('environment') } };
}
function decision() {
  return { kind: 'dependency_install_scripts' as const, purpose: 'dependency_install_scripts' as const,
    target: { sessionId: 'existing-session', sourceInspectionId: identityHash('dependency-source-consent-fixture', 'original'), expectedWorkspaceIdentityDigest: ref('workspace'), conditions: conditions() } };
}
test('script consent retains full source and signed interpreter conditions as inert data with distinct digest domains', () => {
  const value = conditions();
  assert.deepEqual(canonicalJsonBytes(decodeDependencyScriptConditions(value)), canonicalJsonBytes(value));
  assert.notEqual(value.source.sourceManifestRef, value.source.sourceManifestDigest);
  const core = { protocolVersion: 1 as const, method: 'authorization.create' as const, requestId: '00000000-0000-7000-8000-000000000001', decision: decision() };
  const request = { ...core, requestDigest: canonicalSha256(core) };
  assert.deepEqual(decodeAuthorizationCreateRequest(request), request);
  for (const target of [
    { lockfilePath: 'package-lock.json', lockfileDigest: ref('lock') },
    { ...core.decision.target, conditions: { ...value, source: { ...value.source, guessedPath: '/host' } } },
    { ...core.decision.target, conditions: { ...value, source: { ...value.source, privateGit: { kind: 'absent', stateRef: ref('old') } } } },
    { ...core.decision.target, conditions: { ...value, execution: { ...value.execution, nodeExecutionPath: '/host/node' } } },
    { ...core.decision.target, conditions: { ...value, bindingGyp: { kind: 'present' } } },
    { ...core.decision.target, conditions: { ...value, profile: 'pnpm-frozen-v1' } },
  ]) {
    const changed = { ...core, decision: { ...core.decision, target } };
    assert.throws(() => decodeAuthorizationCreateRequest({ ...changed, requestDigest: canonicalSha256(changed) }));
  }
  let invoked = 0;
  const unsafe = { ...value, execution: Object.defineProperty({}, 'runtimeBundleRef', { enumerable: true, get() { invoked++; return ref('runtime'); } }) };
  assert.throws(() => decodeDependencyScriptConditions(unsafe));
  assert.throws(() => decodeDependencyScriptConditions(new Proxy(value, { get() { invoked++; throw new Error('must not call'); } })));
  assert.equal(invoked, 0);
});
test('retained source consent refusal is original wire data, cancellation dominates it and old error UUIDs remain independent', () => {
  const id = identityHash('dependency-source-consent-fixture', 'original'), required = new DependencyScriptAuthorizationRequired(decision());
  const response = createSourceInspectionErrorResponse(required, id, false, 'run.submit');
  assertSourceInspectionErrorResponse(response, id, 'run.submit');
  assert.deepEqual(decodeInstalledControlEnvelope(response, 'run.submit'), response);
  assert.equal(response.error.code, 'AUTHORIZATION_REQUIRED');
  assert.throws(() => assertSourceInspectionErrorResponse(response, identityHash('dependency-source-consent-fixture', 'other'), 'run.submit'), { code: 'RECOVERY_REQUIRED' });
  assert.throws(() => decodeInstalledControlEnvelope({ ...response, method: 'run.apply' }, 'run.apply'));
  assert.throws(() => assertSourceInspectionErrorResponse(response, id, 'run.apply'), { code: 'RECOVERY_REQUIRED' });
  if (response.error.code !== 'AUTHORIZATION_REQUIRED') assert.fail('wrong refusal');
  assert.throws(() => decodeInstalledControlEnvelope({ ...response, error: { ...response.error, raw: 'secret' } }, 'run.submit'));
  const cancelled = createSourceInspectionErrorResponse(required, id, true, 'run.submit');
  assert.equal(cancelled.error.code, 'CANCEL_REQUESTED');
  assertSourceInspectionErrorResponse(cancelled, id, 'run.submit');
  const original = createSourceInspectionErrorResponse(new Error('never returned'), id, false, 'run.submit');
  assert.equal(original.error.code, 'INTERNAL');
  assertSourceInspectionErrorResponse(original, id, 'run.submit');
  assert.throws(() => assertSourceInspectionErrorResponse({ ...response, error: { ...response.error, requiredAuthorization: {
    ...decision(), target: { ...decision().target, conditions: { ...conditions(), workspaceAuthority: true } } } } }, id, 'run.submit'), { code: 'RECOVERY_REQUIRED' });
});
test('script intent locator is mandatory and cannot borrow another inspection correlation', () => {
  const original = decision(), { sourceInspectionId: _locator, ...without } = original.target;
  const core = { protocolVersion: 1, method: 'authorization.create', requestId: '00000000-0000-7000-8000-000000000003',
    decision: { ...original, target: without } };
  assert.throws(() => decodeAuthorizationCreateRequest({ ...core, requestDigest: canonicalSha256(core) }));
  let read = false;
  const accessor = { ...original.target };
  Object.defineProperty(accessor, 'sourceInspectionId', { enumerable: true, get() { read = true; return original.target.sourceInspectionId; } });
  const changed = { ...core, decision: { ...original, target: accessor } };
  assert.throws(() => decodeAuthorizationCreateRequest({ ...changed, requestDigest: ref('not traversing getter') }));
  assert.equal(read, false);
  const foreign = identityHash('dependency-source-consent-fixture', 'foreign');
  const response = createSourceInspectionErrorResponse(new DependencyScriptAuthorizationRequired(original), foreign, false, 'run.submit');
  assert.throws(() => assertSourceInspectionErrorResponse(response, foreign, 'run.submit'), { code: 'RECOVERY_REQUIRED' });
});

test('one script template closes real admission or current candidate approval provenance without a lock-only compatibility path', () => {
  const scriptConditions = conditions();
  const value: DependencyInstallScriptsAuthorizationTemplateV1 = { schemaVersion: 1, format: 'cliq-dependency-install-scripts-authorization-v1',
    runId: 'existing-run', ownerPrincipalId: 'owner', workspaceIdentityDigest: ref('workspace'),
    provenance: { kind: 'run_admission', sourceAuthorizationGrantId: 'original-grant', sourceConsumptionReceiptRef: ref('receipt') },
    scriptConditions, guestToolchainManifestRef: scriptConditions.execution.guestToolchainManifestRef, allowedAdapters: ['npm-ci-v1'],
    lockfilePath: 'package-lock.json', lockfileRef: scriptConditions.lockfileDigest, lockfileDigest: scriptConditions.lockfileDigest,
    packageManifestRef: scriptConditions.packageManifestDigest, packageManifestDigest: scriptConditions.packageManifestDigest,
    bindingGyp: { kind: 'absent' }, registryTargetsDigest: scriptConditions.execution.registryTargetsDigest, maxCandidateGenerations: 3,
    maxDispatchedAttemptsPerPlan: 1, expiresAt: '2026-10-27T01:00:00.000Z', templateDigest: '' };
  const decode = (data: DependencyInstallScriptsAuthorizationTemplateV1) => decodeDependencyInstallScriptsTemplate({ ...data, templateDigest: digestOmitting(data, 'templateDigest') });
  assert.equal(decode(value).provenance.kind, 'run_admission');
  const candidate: DependencyInstallScriptsAuthorizationTemplateV1 = { ...value, provenance: { kind: 'candidate_approval',
    waitingSubjectRef: ref('wait'), decisionRef: ref('decision'), responseRef: ref('response'), requestId: '00000000-0000-7000-8000-000000000002',
    requestDigest: ref('request'), candidateOrdinal: 2, dependencyPlanRef: ref('plan'), resultSourceRef: ref('result') } };
  assert.equal(decode(candidate).provenance.kind, 'candidate_approval');
  for (const changed of [
    { ...value, provenance: { ...value.provenance, decisionRef: ref('unrelated decision') } },
    { ...value, packageManifestDigest: ref('root lifecycle drift') }, { ...value, registryTargetsDigest: ref('registry drift') },
    { ...value, bindingGyp: { kind: 'present', contentRef: ref('gyp'), contentDigest: ref('gyp') } },
    { ...candidate, provenance: { ...candidate.provenance, candidateOrdinal: 3 } },
    { ...candidate, provenance: { ...candidate.provenance, sourceConsumptionReceiptRef: ref('fake run-admission time') } },
  ]) assert.throws(() => decode(changed as DependencyInstallScriptsAuthorizationTemplateV1));
  const { scriptConditions: _conditions, ...legacy } = value;
  assert.throws(() => decode(legacy as DependencyInstallScriptsAuthorizationTemplateV1));
});
