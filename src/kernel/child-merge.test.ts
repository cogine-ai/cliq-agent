import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { digestOmitting, identityHash } from './identity.js';
import { childMergeOperationId, decodeChildMergeRequest, decodeChildMergeTarget, decodeChildMergePolicyEvidence,
  decodeChildMergeGrant, decodeChildMergeApprovalWait, decodeChildMergeApprovalDecision,
  type ChildMergeBindingV1, type ChildMergePolicyEvidenceV1 } from './child-merge.js';

const ref = (value: string) => canonicalSha256(value), time = '2026-10-26T00:00:00.000Z';
const original: ChildMergeBindingV1 = { runId: 'parent', mergeBatchItemId: 'merge-batch', callId: 'merge-call', callIndex: 0,
  childRunId: 'child', childResultItemId: 'child-result', patchManifestRef: ref('patch'), parentRunSnapshotRef: ref('source-run'),
  sourceCheckpointId: 'source-cp', workspaceStateRef: ref('workspace'), sourceBaseRef: ref('B'), sourceDesiredRef: ref('S'), capturedWorkspaceRef: ref('A') };
const target = () => {
  const core = { ...original, schemaVersion: 1 as const, format: 'cliq-child-merge-target-v1' as const,
    workspaceIdentityRef: ref('identity'), workspaceIdentityDigest: ref('identity-digest'), changedPathsDigest: canonicalSha256(['a', 'b']),
    execution: { kind: 'supervisor_operation' as const, handlerId: 'child_merge' as const, supervisorEntryId: 'supervisor',
      supervisorEntryVersion: '1', supervisorExecutableDigest: ref('image') } };
  return { ...core, targetDigest: canonicalSha256(core) };
};
const request = () => {
  const selected = target(), core = { ...original, schemaVersion: 1 as const, format: 'cliq-child-merge-request-v1' as const,
    opId: childMergeOperationId(original), assemblyRef: ref('assembly'), frontierRef: ref('frontier'), targetRef: canonicalSha256(selected), targetDigest: selected.targetDigest };
  return { ...core, requestDigest: canonicalSha256(core) };
};
function evidence(): ChildMergePolicyEvidenceV1 {
  const selected = request(), core = { schemaVersion: 1 as const, format: 'cliq-policy-channel-evidence-v1' as const, principalId: 'principal', runId: 'parent',
    policyRef: ref('policy'), policyDigest: ref('policy-digest'), frontierRef: selected.frontierRef, opId: selected.opId,
    requestRef: canonicalSha256(selected), requestDigest: selected.requestDigest, targetRef: selected.targetRef, targetDigest: selected.targetDigest,
    actionClass: 'write' as const, channel: 'fs-write' as const, canonicalRootRelativePaths: ['a', 'b'],
    pathDecisions: [{ path: 'a', decisionSource: 'rule' as const, matchedRuleIds: ['allow-a'], effectiveDisposition: 'allow' as const },
      { path: 'b', decisionSource: 'rule' as const, matchedRuleIds: ['deny-b'], effectiveDisposition: 'deny' as const }],
    matchedRuleIds: ['allow-a', 'deny-b'], effectiveDisposition: 'deny' as const, evaluatedAt: time };
  return { ...core, evidenceDigest: canonicalSha256(core) };
}

// Pure closed data, not a StateOwner, source capture, policy decision,
// permission, accepted local Journal or native execution fixture.
test('child merge data binds disjoint signed-handler and stable original CP/call identities', () => {
  const selected = target(), call = request();
  assert.deepEqual(decodeChildMergeTarget(selected), selected); assert(Object.isFrozen(decodeChildMergeRequest(call)));
  const moved = { ...call, sourceCheckpointId: 'another-cp', requestDigest: '' }; moved.requestDigest = digestOmitting(moved, 'requestDigest');
  assert.throws(() => decodeChildMergeRequest(moved), /stable local identity/);
  for (const handlerId of ['delegate', 'request_input', 'edit']) {
    const substituted = { ...selected, execution: { ...selected.execution, handlerId }, targetDigest: '' };
    substituted.targetDigest = digestOmitting(substituted, 'targetDigest'); assert.throws(() => decodeChildMergeTarget(substituted));
  }
  assert.throws(() => decodeChildMergeTarget({ ...selected, brokerFenceTokenDigest: ref('broker') }));
  let accessed = false;
  const getter = { ...call }; Object.defineProperty(getter, 'targetRef', { enumerable: true, get() { accessed = true; return call.targetRef; } });
  assert.throws(() => decodeChildMergeRequest(getter)); assert.equal(accessed, false);
  assert.throws(() => decodeChildMergeRequest(new Proxy(call, { get() { accessed = true; throw new Error('trap'); } })));
  assert.equal(accessed, false);
});

test('child merge evidence cannot omit, reorder or downgrade a path refusal even with a new self digest', () => {
  const original = evidence(); assert.deepEqual(decodeChildMergePolicyEvidence(original), original);
  const reseal = <T extends { evidenceDigest: string }>(value: T) => ({ ...value, evidenceDigest: digestOmitting(value, 'evidenceDigest') });
  assert.throws(() => decodeChildMergePolicyEvidence(reseal({ ...original, effectiveDisposition: 'allow' })));
  assert.throws(() => decodeChildMergePolicyEvidence(reseal({ ...original, pathDecisions: original.pathDecisions.slice(0, 1) })));
  assert.throws(() => decodeChildMergePolicyEvidence(reseal({ ...original, canonicalRootRelativePaths: ['b', 'a'] })));
  assert.throws(() => decodeChildMergePolicyEvidence(reseal({ ...original, matchedRuleIds: ['allow-a'] })));
  assert.throws(() => decodeChildMergePolicyEvidence(reseal({ ...original, canonicalRootRelativePaths: ['.git', 'b'] })));
});

test('child merge local grant and approval are closed and cannot masquerade as inherited or native authority', () => {
  const selected = request(), proof = evidence(), subject = { ...original, kind: 'child_merge' as const, changedPathsDigest: target().changedPathsDigest };
  const core = { schemaVersion: 1 as const, format: 'cliq-operation-grant-v1' as const,
    grantId: identityHash('cliq-operation-grant-v1', selected.runId, selected.opId, selected.requestDigest, subject, time), principalId: 'principal',
    runId: selected.runId, policyRef: proof.policyRef, frontierRef: selected.frontierRef, opId: selected.opId,
    requestRef: canonicalSha256(selected), requestDigest: selected.requestDigest, targetRef: selected.targetRef, targetDigest: selected.targetDigest,
    subject, provenance: { kind: 'policy_snapshot' as const, actionClass: 'write' as const, channelEvidenceRef: canonicalSha256(proof),
      channelEvidenceDigest: proof.evidenceDigest, matchedRuleIds: ['allow-a'], effectiveDisposition: 'allow' as const, decisionDigest: ref('decision') },
    maxDispatchedAttempts: 1 as const, issuedAt: time, expiresAt: '2026-10-26T00:01:00.000Z' };
  const grant = { ...core, grantDigest: canonicalSha256(core) }; assert.deepEqual(decodeChildMergeGrant(grant), grant);
  for (const extra of [{ leaseEpoch: 1 }, { sandboxLaunchSpecRef: ref('sandbox') }, { brokerFenceTokenDigest: ref('token') }])
    assert.throws(() => decodeChildMergeGrant({ ...grant, ...extra }));
  assert.throws(() => decodeChildMergeGrant({ ...grant, provenance: { kind: 'delivery_plan_derivation' } }));
  const waiting = { schemaVersion: 1, kind: 'approval', runId: 'parent', createdFromRevision: 3, createdAt: time, frontierRef: selected.frontierRef,
    subject: { ...subject, opId: selected.opId, target: selected.targetRef, policyChannelEvidenceRef: canonicalSha256(proof), policyChannelEvidenceDigest: proof.evidenceDigest } };
  assert.deepEqual(decodeChildMergeApprovalWait(waiting), waiting);
  const requestId = '019a0000-0000-7000-8000-000000000001', waitingSubjectRef = canonicalSha256(waiting), requestDigest = ref('approve-request');
  const decisionCore = { schemaVersion: 1, format: 'cliq-approval-decision-v1',
    decisionId: identityHash('principal', 'parent', waitingSubjectRef, requestId, requestDigest), principalId: 'principal',
    channelIdentityRef: ref('channel'), channelIdentityDigest: ref('channel-digest'), stateOwnerEpoch: 1, supervisorInstanceId: 'original-owner',
    inspectorIdentityRef: ref('inspector'), inspectorIdentityDigest: ref('inspector-digest'), runId: 'parent', waitingSubjectRef,
    waitingSubjectDigest: waitingSubjectRef, frontierRef: selected.frontierRef, subject: waiting.subject, subjectDigest: canonicalSha256(waiting.subject),
    requestId, requestDigest, expectedRunRevision: 4, decision: 'allow', requestedTtlMs: 5000, grantExpiresAt: '2026-10-26T00:00:05.000Z', createdAt: time };
  const decision = { ...decisionCore, decisionDigest: canonicalSha256(decisionCore) };
  assert.deepEqual(decodeChildMergeApprovalDecision(decision), decision);
  const replaced = { ...decision, subjectDigest: ref('another-subject'), decisionDigest: '' }; replaced.decisionDigest = digestOmitting(replaced, 'decisionDigest');
  assert.throws(() => decodeChildMergeApprovalDecision(replaced));
});
