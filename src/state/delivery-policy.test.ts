// Pure frozen-policy regressions; no approval transaction or native authority.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { DeliveryPlan } from '../kernel/publication.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import { testFixture } from '../model/testing/fixtures.js';
import { BUILTIN_POLICY_RULES, modeDecisions } from '../policy/tool-policy.js';
import { deliveryApprovalDecision, derivePublicationGrant, derivePublicationMaintenance, loadDeliveryPolicy, planDeliveryRequest } from './delivery-policy.js';

function data(mode: RunPolicySnapshotV1['mode'] = 'yolo') {
  const assembly = testFixture().assembly, ref = canonicalSha256;
  const plan: DeliveryPlan = { schemaVersion: 1, deliveryRunId: 'delivery', sourceRunResultRef: ref('original result'),
    sourceBaseRef: ref('B'), sourceDesiredRef: ref('S'), capturedWorkspaceRef: ref('A'), captureTopologyRef: ref('topology'),
    captureTopologyDigest: ref('topology-digest'), desiredSourceRef: ref('M'), diffRef: ref('diff'),
    mergeAlgorithm: 'cliq-diff3-v1', publicationStateMachine: 'cliq-publish-v1', forwardOperations: [], abortOperations: [] };
  const context = { runId: 'delivery', frontierRef: ref('approval-frontier'), assemblyRef: ref(assembly), plan,
    planRef: ref(plan), workspaceIdentityRef: ref('workspace'), workspaceIdentityDigest: ref('workspace-digest') };
  const policy: RunPolicySnapshotV1 = { schemaVersion: 1, format: 'cliq-run-policy-v1', principalId: 'principal',
    workspaceIdentityDigest: context.workspaceIdentityDigest, mode, engine: { id: 'cliq-policy-v1', version: '1',
      runtimeBundleRef: assembly.runtime.runtimeBundleRef, profileEntryId: 'policy', profileRef: ref('profile'), profileDigest: ref('profile-digest') },
    toolManifestRef: assembly.tools.manifestRef, toolManifestDigest: assembly.tools.manifestDigest, decisions: modeDecisions(mode),
    decisionRules: [...BUILTIN_POLICY_RULES], repositoryRequestRefs: [], createdAt: '2026-10-18T00:00:00.000Z', policyDigest: '' };
  policy.policyDigest = digestOmitting(policy, 'policyDigest');
  return { context, policy, load: () => loadDeliveryPolicy({ policy, policyRef: ref(policy), assembly,
    assemblyRef: ref(assembly), principalId: 'principal', workspaceIdentityDigest: context.workspaceIdentityDigest, context }) };
}

test('delivery policy binds complete plan and creates only an approval parent with zero dispatches', () => {
  const { context, load } = data(), { request, target } = planDeliveryRequest(context), evaluator = load();
  const now = '2026-10-18T00:01:00.000Z', deadline = '2026-10-18T00:05:00.000Z';
  const evidence = evaluator.evaluate(request, target, now), grant = evaluator.grant(request, target, evidence, now, deadline);
  assert.equal(evidence.identityKey, `delivery/${target.operationSetDigest}`);
  assert.equal(grant.maxDispatchedAttempts, 0); assert.equal(grant.expiresAt, deadline);
  assert.equal(grant.subject.kind, 'delivery_plan'); assert.equal(grant.subject.deliveryPlanRef, context.planRef);
  assert.equal(grant.grantDigest, digestOmitting(grant, 'grantDigest'));
  for (const patch of [{ deliveryPlanRef: canonicalSha256('other') }, { operationSetDigest: canonicalSha256('other') },
    { workspaceIdentityRef: canonicalSha256('other') }]) {
    const changed = { ...target, ...patch }; changed.targetDigest = digestOmitting(changed, 'targetDigest');
    const altered = { ...request, targetRef: canonicalSha256(changed), targetDigest: changed.targetDigest };
    altered.requestDigest = digestOmitting(altered, 'requestDigest');
    assert.throws(() => evaluator.evaluate(altered, changed, now));
  }
  assert.throws(() => evaluator.grant(request, target, { ...evidence, effectiveDisposition: 'allow', matchedRuleIds: ['invented'] }, now, deadline));
});

test('Workspace Trust, a verified result and ask/deny policies do not become publication grants', () => {
  for (const mode of ['default', 'accept-edits', 'plan'] as const) {
    const { context, load } = data(mode), { request, target } = planDeliveryRequest(context), evaluator = load();
    const evidence = evaluator.evaluate(request, target, '2026-10-18T00:01:00.000Z');
    assert.equal(evidence.effectiveDisposition, mode === 'plan' ? 'deny' : 'ask');
    assert.throws(() => evaluator.grant(request, target, evidence, '2026-10-18T00:01:00.000Z', '2026-10-18T00:05:00.000Z'));
  }
});

test('explicit delivery approval retains the exact ask and absolute deadline, not a shorter tool TTL', () => {
  const { context, load } = data('default'), { request, target } = planDeliveryRequest(context), evaluator = load();
  const now = '2026-10-18T00:01:00.000Z', deadline = '2026-10-18T00:05:00.000Z';
  const evidence = evaluator.evaluate(request, target, now), wait = evaluator.approvalWait(request, target, evidence, 4);
  const input = { principalId: 'principal', channelIdentityRef: canonicalSha256('channel'), channelIdentityDigest: canonicalSha256('channel-digest'),
    requestId: '019a0000-0000-7000-8000-000000000001', expectedRunRevision: 5, waitingOnRef: canonicalSha256(wait), decision: 'allow' as const, ttlMs: 1 };
  const decision = deliveryApprovalDecision(wait, input, now, deadline);
  assert.equal(decision.grantExpiresAt, deadline); assert.equal(decision.requestedTtlMs, 1);
  const grant = evaluator.approve(request, target, evidence, wait, decision, deadline)!;
  assert.equal(grant.expiresAt, deadline); assert.equal(grant.maxDispatchedAttempts, 0);
  assert.equal(grant.provenance.kind, 'user_approval');
  const deny = deliveryApprovalDecision(wait, { ...input, decision: 'deny' }, now, deadline);
  assert.equal(evaluator.approve(request, target, evidence, wait, deny, deadline), undefined);
  for (const patch of [{ principalId: 'another' }, { expectedRunRevision: 6 }, { frontierRef: canonicalSha256('other') },
    { grantExpiresAt: '2026-10-18T00:01:00.001Z' }, { subject: { ...wait.subject, operationSetDigest: canonicalSha256('other') } }])
    assert.throws(() => evaluator.approve(request, target, evidence, wait, { ...decision, ...patch }, deadline));
});

test('publication derives one fresh path frontier grant, preserving its parent and complete operation binding', () => {
  const { context, load } = data(), ref = canonicalSha256;
  context.plan.forwardOperations.push({ index: 0, operationId: identityHash('test-publication-operation'), path: 'answer.txt',
    parent: { kind: 'existing_directory', expectedIdentityDigest: ref('root') }, kind: 'create', expected: { kind: 'absent' },
    desired: { kind: 'file', mode: 0o644, digest: ref('content') }, stagingName: '.stage', stagingExpected: { kind: 'absent' } });
  context.planRef = ref(context.plan);
  const { request, target } = planDeliveryRequest(context), evaluator = load();
  const now = '2026-10-18T00:01:00.000Z', deadline = '2026-10-18T00:05:00.000Z';
  const evidence = evaluator.evaluate(request, target, now), parent = evaluator.grant(request, target, evidence, now, deadline);
  const decision = { schemaVersion: 1 as const, itemId: 'decision', runId: 'delivery', kind: 'delivery_decision' as const,
    deliveryPlanRef: context.planRef, approvalOpId: parent.opId, decision: 'allow' as const,
    decisionRef: ref(evidence), grantRef: ref(parent), createdAt: now };
  const input = { context: { ...context, frontierRef: ref('first-publish-frontier') }, parent, parentRef: ref(parent),
    decision, sequence: 'forward' as const, operationIndex: 0, issuedAt: now };
  const child = derivePublicationGrant(input);
  assert.notEqual(child.grant.frontierRef, parent.frontierRef);
  assert.equal(child.grant.frontierRef, input.context.frontierRef);
  assert.equal(child.grant.maxDispatchedAttempts, 1); assert.equal(child.grant.expiresAt, parent.expiresAt);
  assert.equal(child.grant.subject.operationDigest, ref(context.plan.forwardOperations[0]));
  assert.equal(child.grant.grantDigest, digestOmitting(child.grant, 'grantDigest'));
  for (const patch of [{ operationIndex: 1 }, { issuedAt: deadline }, { decision: { ...decision, decision: 'deny' as const } },
    { decision: { ...decision, grantRef: ref('other') } }, { parent: { ...parent, maxDispatchedAttempts: 1 } }])
    assert.throws(() => derivePublicationGrant({ ...input, ...patch }));
});

test('post-stop directory maintenance is distinct retained authority, never an expired productive grant', () => {
  const { context, load } = data(), ref = canonicalSha256;
  const creatorId = identityHash('directory creator'), abortId = identityHash('directory abort');
  context.plan.forwardOperations.push({ index: 0, operationId: creatorId, path: 'directory',
    parent: { kind: 'existing_directory', expectedIdentityDigest: ref('root') }, kind: 'mkdir',
    expected: { kind: 'absent' }, desired: { kind: 'directory', mode: 0o755 } });
  context.plan.abortOperations.push({ index: 0, operationId: abortId, path: 'directory',
    kind: 'abort_rmdir', createdByOperationId: creatorId, quarantineName: 'preimage', quarantineExpected: { kind: 'absent' } });
  context.planRef = ref(context.plan);
  const { request, target } = planDeliveryRequest(context), evaluator = load();
  const now = '2026-10-18T00:01:00.000Z', deadline = '2026-10-18T00:05:00.000Z';
  const evidence = evaluator.evaluate(request, target, now), parent = evaluator.grant(request, target, evidence, now, deadline);
  const decision = { schemaVersion: 1 as const, itemId: 'decision', runId: 'delivery', kind: 'delivery_decision' as const,
    deliveryPlanRef: context.planRef, approvalOpId: parent.opId, decision: 'allow' as const,
    decisionRef: ref(evidence), grantRef: ref(parent), createdAt: now };
  const input = { context: { ...context, frontierRef: ref('stopping abort frontier') }, parent,
    parentRef: ref(parent), decision, operationIndex: 0, issuedAt: '2026-10-18T00:06:00.000Z',
    stopIntentRef: ref('original stop'), creatorReceiptRef: ref('actual original creator receipt') };
  const maintenance = derivePublicationMaintenance(input);
  assert.equal(maintenance.request.sequence, 'abort');
  assert.equal(maintenance.operation.createdByOperationId, creatorId);
  assert.equal(maintenance.grant.format, 'cliq-publication-maintenance-authority-v1');
  assert.equal(maintenance.grant.maxDispatchedAttempts, 1);
  assert.equal(maintenance.grant.subject.kind, 'publication_abort_maintenance');
  assert.equal(maintenance.grant.subject.stopIntentRef, input.stopIntentRef);
  assert.equal(maintenance.grant.subject.creatorReceiptRef, input.creatorReceiptRef);
  assert.equal(maintenance.grant.authorityDigest, digestOmitting(maintenance.grant, 'authorityDigest'));
  assert.equal(Object.hasOwn(maintenance.grant, 'expiresAt'), false);
  // The data projection above is not a native claim or proof of this receipt.
  // Its owning reader/producer must independently verify Stop, creator, prefix,
  // current owner, empty directory, zero charge, and both physical gates.
  for (const patch of [{ operationIndex: 1 }, { stopIntentRef: '' }, { creatorReceiptRef: '' },
    { issuedAt: '2026-10-18T00:00:00.000Z' }, { decision: { ...decision, decision: 'deny' as const } },
    { parent: { ...parent, maxDispatchedAttempts: 1 } }, { expiresAt: deadline }, { reservation: { toolCalls: 1 } }])
    assert.throws(() => derivePublicationMaintenance({ ...input, ...patch }));
  assert.throws(() => derivePublicationGrant({ ...input, sequence: 'abort' }));
  assert.throws(() => derivePublicationGrant({ ...input, sequence: 'forward' }));
});
