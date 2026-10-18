// Pure request/policy data regressions; these neither mint a native launch nor
// establish installed execution or all-descendant retirement qualification.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { VerifierPlan } from '../kernel/result.js';
import type { VerifierSpec } from '../kernel/types.js';
import type { VerifierCommandV1, VerifierEnvironmentV1 } from '../kernel/verifier.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import { testFixture } from '../model/testing/fixtures.js';
import { BUILTIN_POLICY_RULES, modeDecisions } from '../policy/tool-policy.js';
import { loadVerifierPolicy, planVerifierRequest } from './verifier-policy.js';

function data() {
  const assembly = testFixture().assembly, ref = canonicalSha256;
  const command: VerifierCommandV1 = { schemaVersion: 1, format: 'cliq-verifier-command-v1', verifierId: 'tests', verifierVersion: '1',
    executable: { kind: 'guest_toolchain', guestToolchainManifestRef: ref('guest'), guestToolchainManifestDigest: ref('guest-digest'), toolId: 'node',
      executionPath: '/usr/bin/node', executableDigest: ref('node'), abiFingerprint: ref('guest-digest') },
    argv: [{ kind: 'non_secret_literal', value: '--test' }, { kind: 'non_secret_literal', value: '--test-concurrency=1' },
      { kind: 'non_secret_literal', value: 'test.mjs' }], cwd: '.', commandDigest: '' };
  command.commandDigest = digestOmitting(command, 'commandDigest');
  const environment: VerifierEnvironmentV1 = { schemaVersion: 1, format: 'cliq-verifier-environment-v1', verifierId: 'tests', verifierVersion: '1',
    commandRef: ref(command), commandDigest: command.commandDigest, variables: [], writableEphemeralPaths: [], sourceProjectionRef: ref('projection'),
    sourceAccess: 'read_only', networkAccess: 'denied', sandboxProfile: 'cliq-verifier-readonly-v1', runtimeBundleRef: assembly.runtime.runtimeBundleRef,
    runtimeBundleManifestDigest: assembly.runtime.runtimeBundleManifestDigest, guestToolchainManifestRef: ref('guest'),
    guestToolchainManifestDigest: ref('guest-digest'), environmentDigest: '' };
  environment.environmentDigest = digestOmitting(environment, 'environmentDigest');
  const entry: VerifierSpec['verifiers'][number] = { index: 0, id: 'tests', version: '1', gate: 'required', commandRef: ref(command),
    commandDigest: command.commandDigest, environmentRef: ref(environment), environmentDigest: environment.environmentDigest,
    timeoutMs: 1000, retries: 1, outputLimitBytes: 65_536, entryDigest: '' };
  entry.entryDigest = digestOmitting(entry, 'entryDigest');
  const verifierSpec: VerifierSpec = { schemaVersion: 1, format: 'cliq-verifier-spec-v1', verifiers: [entry], specDigest: '' };
  verifierSpec.specDigest = digestOmitting(verifierSpec, 'specDigest');
  const plan: VerifierPlan = { schemaVersion: 1, runId: 'run-1', candidateItemId: 'candidate-1', resultSourceRef: ref('source'),
    verifierSpecRef: ref(verifierSpec), verifierSpecDigest: verifierSpec.specDigest, entries: [{ index: 0, verifierId: entry.id,
      verifierSpecDigest: verifierSpec.specDigest, verifierEntryDigest: entry.entryDigest, commandRef: entry.commandRef, commandDigest: entry.commandDigest,
      environmentRef: entry.environmentRef, environmentDigest: entry.environmentDigest, required: true, maxAttempts: 2 }], planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest');
  const policy: RunPolicySnapshotV1 = { schemaVersion: 1, format: 'cliq-run-policy-v1', principalId: 'principal-1', workspaceIdentityDigest: ref('workspace'),
    mode: 'yolo', engine: { id: 'cliq-policy-v1', version: '1', runtimeBundleRef: assembly.runtime.runtimeBundleRef,
      profileEntryId: 'policy', profileRef: ref('profile'), profileDigest: ref('profile-digest') }, toolManifestRef: assembly.tools.manifestRef,
    toolManifestDigest: assembly.tools.manifestDigest, decisions: modeDecisions('yolo'), decisionRules: [...BUILTIN_POLICY_RULES], repositoryRequestRefs: [],
    createdAt: '2026-10-18T00:00:00.000Z', policyDigest: '' };
  policy.policyDigest = digestOmitting(policy, 'policyDigest');
  const context = { runId: plan.runId, frontierRef: ref('frontier'), assemblyRef: ref(assembly), candidateItemId: plan.candidateItemId,
    resultSourceRef: plan.resultSourceRef, sourceDigest: ref('source-tree'), verifierPlanRef: ref(plan), plan, verifierSpecRef: ref(verifierSpec),
    verifierSpec, verifierIndex: 0, command, environment };
  const load = (value = policy) => loadVerifierPolicy({ policy: value, policyRef: ref(value), assembly, assemblyRef: ref(assembly),
    principalId: policy.principalId, workspaceIdentityDigest: policy.workspaceIdentityDigest, context });
  return { context, policy, load };
}

test('verifier permission binds the full frozen candidate/request graph and direct named-action evidence', () => {
  const { context, load } = data(), { request, target } = planVerifierRequest(context), evaluator = load();
  const now = '2026-10-18T00:01:00.000Z', expiry = '2026-10-18T00:02:00.000Z';
  const evidence = evaluator.evaluate(request, target, now);
  assert.equal(evidence.channel, 'named-action'); assert.equal(evidence.identityKey, 'verifier/tests');
  assert.deepEqual(evidence.namedAction, { kind: 'verifier', candidateItemId: 'candidate-1', verifierPlanRef: context.verifierPlanRef, verifierId: 'tests' });
  const grant = evaluator.grant(request, target, evidence, now, expiry);
  assert.equal(grant.subject.kind, 'verifier_launch'); assert.equal(grant.subject.resultSourceRef, context.resultSourceRef);
  assert.equal(grant.maxDispatchedAttempts, 2); assert.equal(grant.grantDigest, digestOmitting(grant, 'grantDigest'));
  assert.equal(grant.provenance.channelEvidenceRef, canonicalSha256(evidence));
  assert.deepEqual(Object.keys(grant.provenance).sort(), ['actionClass', 'channelEvidenceDigest', 'channelEvidenceRef',
    'decisionDigest', 'effectiveDisposition', 'kind', 'matchedRuleIds']);
  for (const patch of [{ sourceDigest: canonicalSha256('other') }, { required: false }, { verifierIndex: 1 }, { candidateItemId: 'another' }]) {
    const changed = { ...target, ...patch }; changed.targetDigest = digestOmitting(changed, 'targetDigest');
    const altered = { ...request, targetRef: canonicalSha256(changed), targetDigest: changed.targetDigest };
    altered.requestDigest = digestOmitting(altered, 'requestDigest');
    assert.throws(() => evaluator.evaluate(altered, changed, now));
  }
  const forged = { ...evidence, matchedRuleIds: ['caller-allow'], evidenceDigest: '' };
  forged.evidenceDigest = digestOmitting(forged, 'evidenceDigest');
  assert.throws(() => evaluator.grant(request, target, forged, now, expiry));
  assert.throws(() => planVerifierRequest({ ...context, plan: { ...context.plan, entries: [{ ...context.plan.entries[0]!, maxAttempts: 3 }] } }));
});

test('named verifier policy uses the original precedence and neither deny nor ask becomes a grant', () => {
  const { context, policy, load } = data(), { request, target } = planVerifierRequest(context), now = '2026-10-18T00:01:00.000Z';
  for (const mode of ['default', 'plan', 'yolo'] as const) {
    const value = { ...policy, mode, decisions: modeDecisions(mode) }; value.policyDigest = digestOmitting(value, 'policyDigest');
    const evaluator = load(value), evidence = evaluator.evaluate(request, target, now);
    assert.equal(evidence.effectiveDisposition, mode === 'default' ? 'ask' : mode === 'plan' ? 'deny' : 'allow');
    if (mode !== 'yolo') assert.throws(() => evaluator.grant(request, target, evidence, now, '2026-10-18T00:02:00.000Z'));
  }
  const value = structuredClone(policy);
  value.decisionRules.push(...(['allow', 'deny'] as const).map((disposition, index) => ({ ruleId: `named-${disposition}`, order: index + 3,
    source: 'cli' as const, sourceRef: canonicalSha256('fixed-cli-request'), channel: 'named-action' as const, pattern: 'verifier/tests', disposition })));
  value.policyDigest = digestOmitting(value, 'policyDigest');
  const evaluator = load(value), evidence = evaluator.evaluate(request, target, now);
  assert.equal(evidence.effectiveDisposition, 'deny'); assert.deepEqual(evidence.matchedRuleIds, ['named-deny']);
});
