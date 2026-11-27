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
import { toolApprovalDecision } from '../policy/tool-approval.js';
import type { VerifierAuthorizationTemplateV1 } from '../kernel/verifier-invocation.js';
import { decodeVerifierAuthorizationTemplate } from './verifier-template.js';
import { verifierDenial, verifierPolicyItem } from './verifier-permission-history.js';
import { decodeVerifierSkipItem } from './verifier-artifacts.js';

function data(required = true) {
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
  const entry: VerifierSpec['verifiers'][number] = { index: 0, id: 'tests', version: '1', gate: required ? 'required' : 'advisory', commandRef: ref(command),
    commandDigest: command.commandDigest, environmentRef: ref(environment), environmentDigest: environment.environmentDigest,
    timeoutMs: 1000, retries: 1, outputLimitBytes: 65_536, entryDigest: '' };
  entry.entryDigest = digestOmitting(entry, 'entryDigest');
  const verifierSpec: VerifierSpec = { schemaVersion: 1, format: 'cliq-verifier-spec-v1', verifiers: [entry], specDigest: '' };
  verifierSpec.specDigest = digestOmitting(verifierSpec, 'specDigest');
  const plan: VerifierPlan = { schemaVersion: 1, runId: 'run-1', candidateItemId: 'candidate-1', resultSourceRef: ref('source'),
    verifierSpecRef: ref(verifierSpec), verifierSpecDigest: verifierSpec.specDigest, entries: [{ index: 0, verifierId: entry.id,
      verifierSpecDigest: verifierSpec.specDigest, verifierEntryDigest: entry.entryDigest, commandRef: entry.commandRef, commandDigest: entry.commandDigest,
      environmentRef: entry.environmentRef, environmentDigest: entry.environmentDigest, required, maxAttempts: 2 }], planDigest: '' };
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

for (const mode of ['default', 'accept-edits'] as const) test(`${mode} verifier selection preserves ask and requires its exact candidate approval`, () => {
  const f = data(), policy = { ...f.policy, mode, decisions: modeDecisions(mode) };
  policy.policyDigest = digestOmitting(policy, 'policyDigest');
  const evaluator = f.load(policy), { request, target } = planVerifierRequest(f.context);
  const at = '2026-10-18T00:01:00.000Z', decidedAt = '2026-10-18T00:01:01.000Z', deadline = '2026-10-18T00:05:00.000Z';
  const evidence = evaluator.evaluate(request, target, at), wait = evaluator.approvalWait(request, target, evidence, 9);
  assert.equal(evidence.effectiveDisposition, 'ask'); assert.equal(wait.subject.resultSourceRef, target.resultSourceRef);
  assert.throws(() => evaluator.grant(request, target, evidence, at, deadline));
  const input = { principalId: policy.principalId, channelIdentityRef: canonicalSha256('actual-channel-data'), channelIdentityDigest: canonicalSha256('channel-digest'),
    requestId: '019a1cb4-5000-7000-8000-000000000001', expectedRunRevision: 10, waitingOnRef: canonicalSha256(wait), decision: 'allow' as const, ttlMs: 1000 };
  const decision = toolApprovalDecision(wait, input, decidedAt, deadline), grant = evaluator.approve(request, target, evidence, wait, decision, deadline)!;
  assert.equal(grant.provenance.kind, 'user_approval'); assert.equal(grant.expiresAt, '2026-10-18T00:01:02.000Z');
  assert.equal(grant.maxDispatchedAttempts, target.maxAttempts); assert.equal(evidence.effectiveDisposition, 'ask');
  const denied = toolApprovalDecision(wait, { ...input, decision: 'deny' }, decidedAt, deadline);
  assert.equal(evaluator.approve(request, target, evidence, wait, denied, deadline), undefined);
  assert.equal(denied.grantExpiresAt, undefined);
  for (const change of [{ runId: 'another-run' }, { subject: { ...wait.subject, resultSourceRef: canonicalSha256('another-source') } },
    { subject: { ...wait.subject, required: false } }, { frontierRef: canonicalSha256('later-frontier') }])
    assert.throws(() => evaluator.approve(request, target, evidence, { ...wait, ...change }, decision, deadline));
  assert.throws(() => toolApprovalDecision(wait, { ...input, expectedRunRevision: 11 }, decidedAt, deadline));
  assert.throws(() => toolApprovalDecision(wait, input, deadline, deadline));
});

test('a pure bounded verifier template retains ask and cannot change Run, identity, candidate ordinal or attempt ceiling', () => {
  const f = data(), policy = { ...f.policy, mode: 'default' as const, decisions: modeDecisions('default') };
  policy.policyDigest = digestOmitting(policy, 'policyDigest');
  const evaluator = f.load(policy), { request, target } = planVerifierRequest(f.context), at = '2026-10-18T00:01:00.000Z';
  const evidence = evaluator.evaluate(request, target, at);
  const template: VerifierAuthorizationTemplateV1 = { schemaVersion: 1, format: 'cliq-verifier-authorization-template-v1',
    runId: request.runId, verifierSpecRef: target.verifierSpecRef, verifierSpecDigest: target.verifierSpecDigest,
    verifierIndex: target.verifierIndex, verifierId: target.verifierId, verifierVersion: target.verifierVersion,
    verifierEntryDigest: target.verifierEntryDigest, commandRef: target.commandRef, commandDigest: target.commandDigest,
    environmentRef: target.environmentRef, environmentDigest: target.environmentDigest, sourceProjectionRef: f.context.environment.sourceProjectionRef,
    maxCandidateGenerations: 2, maxAttempts: 2, expiresAt: '2026-10-18T00:05:00.000Z', decisionRef: canonicalSha256('original-consumption-data'), templateDigest: '' };
  template.templateDigest = digestOmitting(template, 'templateDigest'); decodeVerifierAuthorizationTemplate(template);
  const grant = evaluator.templateGrant(request, target, evidence, template, 1, at);
  assert.deepEqual(grant.provenance, { kind: 'verifier_template', templateRef: canonicalSha256(template), candidateOrdinal: 1, decisionRef: template.decisionRef });
  assert.equal(evidence.effectiveDisposition, 'ask'); assert.equal(grant.expiresAt, template.expiresAt);
  for (const ordinal of [-1, 2, 3, 0.5, Number.MAX_SAFE_INTEGER]) assert.throws(() => evaluator.templateGrant(request, target, evidence, template, ordinal, at));
  for (const change of [{ runId: 'another-run' }, { verifierId: 'another-check' }, { maxAttempts: 3 },
    { sourceProjectionRef: canonicalSha256('other-projection') }, { commandRef: canonicalSha256('other-command') },
    { environmentDigest: canonicalSha256('other-environment') }, { expiresAt: at }])
    assert.throws(() => evaluator.templateGrant(request, target, evidence, { ...template, ...change }, 0, at));
  for (const change of [{ templateDigest: canonicalSha256('forged') }, { automaticRenewal: true }, { operationGrantRef: canonicalSha256('forged') }])
    assert.throws(() => decodeVerifierAuthorizationTemplate({ ...template, ...change }));
  const deniedPolicy = { ...policy, mode: 'plan' as const, decisions: modeDecisions('plan') };
  deniedPolicy.policyDigest = digestOmitting(deniedPolicy, 'policyDigest');
  const denied = f.load(deniedPolicy), deniedEvidence = denied.evaluate(request, target, at);
  assert.throws(() => denied.templateGrant(request, target, deniedEvidence, template, 0, at));
});

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

for (const required of [true, false]) test(`${required ? 'required refusal cancels' : 'advisory refusal skips'} without fabricating verification or changing ask evidence`, () => {
  const f = data(required), policy = { ...f.policy, mode: 'default' as const, decisions: modeDecisions('default') };
  policy.policyDigest = digestOmitting(policy, 'policyDigest');
  const evaluator = f.load(policy), { request, target } = planVerifierRequest(f.context);
  const at = '2026-10-18T00:01:00.000Z', deadline = '2026-10-18T00:05:00.000Z';
  const evidence = evaluator.evaluate(request, target, at), wait = evaluator.approvalWait(request, target, evidence, 9);
  const decision = toolApprovalDecision(wait, { principalId: policy.principalId, channelIdentityRef: canonicalSha256('channel'),
    channelIdentityDigest: canonicalSha256('channel-digest'), requestId: '019a1cb4-5000-7000-8000-000000000002',
    expectedRunRevision: 10, waitingOnRef: canonicalSha256(wait), decision: 'deny' }, at, deadline);
  const context = { run: { id: request.runId }, request, target }, ref = canonicalSha256(decision);
  const outcome = verifierDenial(context, evidence, ref, at, decision), item = verifierPolicyItem(context, evidence, ref, at, undefined, decision);
  assert.equal(evidence.effectiveDisposition, 'ask'); assert.equal(evaluator.approve(request, target, evidence, wait, decision, deadline), undefined);
  assert.equal(item.decisionSource, 'interactive_approval'); assert.equal(item.decision, 'deny');
  if (item.decision !== 'deny') assert.fail('refusal item');
  assert.equal('grantRef' in item, false); assert.equal('receiptRef' in item, false);
  if (required) {
    assert.equal(outcome.skip, undefined); assert.equal(outcome.stop?.origin, 'user_cancel'); assert.equal(outcome.stop?.targetStatus, 'cancelled');
    assert.deepEqual(item.denialOutcome, { kind: 'stop_intent', subjectKind: 'verifier_launch', stopIntentRef: canonicalSha256(outcome.stop) });
  } else {
    assert.equal(outcome.stop, undefined); assert(outcome.skip);
    assert.equal(outcome.skip.outcome, 'skipped_by_user'); assert.equal('policyChannelEvidenceDigest' in outcome.skip, false);
    assert.deepEqual(decodeVerifierSkipItem(outcome.skip), outcome.skip);
    assert.deepEqual(item.denialOutcome, { kind: 'advisory_verifier_skipped', subjectKind: 'verifier_launch', verifierSkipItemRef: canonicalSha256(outcome.skip) });
    for (const extra of [{ receiptRef: canonicalSha256('forged-receipt') }, { outcome: 'passed' },
      { policyChannelEvidenceDigest: evidence.evidenceDigest }, { grantRef: canonicalSha256('forged-grant') }])
      assert.throws(() => decodeVerifierSkipItem({ ...outcome.skip, ...extra }));
    const deniedPolicy = { ...policy, mode: 'plan' as const, decisions: modeDecisions('plan') };
    deniedPolicy.policyDigest = digestOmitting(deniedPolicy, 'policyDigest');
    const deniedEvidence = f.load(deniedPolicy).evaluate(request, target, at);
    assert.equal(deniedEvidence.effectiveDisposition, 'deny');
    const policySkip = verifierDenial(context, deniedEvidence, canonicalSha256(deniedEvidence), at).skip!;
    assert.equal(policySkip.outcome, 'skipped_by_policy'); assert.deepEqual(decodeVerifierSkipItem(policySkip), policySkip);
    const { policyChannelEvidenceDigest: _digest, ...missing } = policySkip; assert.throws(() => decodeVerifierSkipItem(missing));
  }
});
