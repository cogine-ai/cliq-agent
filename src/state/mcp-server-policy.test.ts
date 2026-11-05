// Pure immutable request/policy data, not signed-runtime qualification,
// authenticated approval, native exec, a Journal claim or death evidence.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeMcpServerApprovalDecision, decodeMcpServerApprovalWait, decodeMcpServerOperationGrant,
  decodeMcpServerLaunchTarget, decodeMcpServerLaunchRequest } from '../kernel/mcp-server-authorization.js';
import { countMcpServerLaunchClaims, decodeMcpServerLaunchFailure, decodeMcpServerFailedStoppedItem } from '../kernel/mcp-server-authorization.js';
import type { InvocationJournalEntry } from '../kernel/types.js';
import { mcpServerLaunchOperationId } from '../kernel/mcp-stdio.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import { testFixture } from '../model/testing/fixtures.js';
import { BUILTIN_POLICY_RULES, modeDecisions } from '../policy/tool-policy.js';
import { toolApprovalDecision } from '../policy/tool-approval.js';
import { loadMcpServerPolicy } from './mcp-server-policy.js';

const ref = canonicalSha256, at = '2026-11-01T00:00:00.000Z', evaluated = '2026-11-01T00:01:00.000Z', expiry = '2026-11-01T00:10:00.000Z';
function data(mode: RunPolicySnapshotV1['mode'] = 'yolo') {
  const assembly = testFixture().assembly;
  const targetCore = { schemaVersion: 1, format: 'cliq-mcp-server-launch-target-v1', runId: 'run-1', registrationId: 'owned-server',
    registryRevisionRef: ref('registry'), registryManifestDigest: ref('manifest'), lifecycleSeq: 0, batchItemId: 'batch-1', callId: 'call-1', callIndex: 0,
    toolRequestRef: ref('exact owning tool request'), toolRequestDigest: ref('exact owning tool request digest'),
    executableIdentityRef: ref('static server identity'), executableIdentityDigest: ref('static server identity digest'), argv: ['--stdio', ''],
    initializeDigest: ref('initialize'), capabilityDigest: ref('capabilities'), probedToolsListDigest: ref('interfaces'),
    maxLaunches: 2, launchTimeoutMs: 300000, callTimeoutMs: 3600000 };
  const target = decodeMcpServerLaunchTarget({ ...targetCore, targetDigest: ref(targetCore) });
  const requestCore = { schemaVersion: 1, format: 'cliq-mcp-server-launch-request-v1', runId: target.runId,
    opId: mcpServerLaunchOperationId(target.runId, target.batchItemId, target.callIndex, target.callId, target.registryManifestDigest, target.lifecycleSeq),
    frontierRef: ref('exact tool frontier'), assemblyRef: ref(assembly), registryRevisionRef: target.registryRevisionRef,
    registryManifestDigest: target.registryManifestDigest, lifecycleSeq: target.lifecycleSeq, batchItemId: target.batchItemId,
    callId: target.callId, callIndex: target.callIndex, toolRequestRef: target.toolRequestRef, toolRequestDigest: target.toolRequestDigest,
    targetRef: ref(target), targetDigest: target.targetDigest };
  const request = decodeMcpServerLaunchRequest({ ...requestCore, requestDigest: ref(requestCore) });
  const policy: RunPolicySnapshotV1 = { schemaVersion: 1, format: 'cliq-run-policy-v1', principalId: 'principal-1', workspaceIdentityDigest: ref('workspace'),
    mode, engine: { id: 'cliq-policy-v1', version: '1', runtimeBundleRef: assembly.runtime.runtimeBundleRef,
      profileEntryId: 'policy', profileRef: ref('profile'), profileDigest: ref('profile digest') }, toolManifestRef: assembly.tools.manifestRef,
    toolManifestDigest: assembly.tools.manifestDigest, decisions: modeDecisions(mode), decisionRules: [...BUILTIN_POLICY_RULES], repositoryRequestRefs: [],
    createdAt: at, policyDigest: '' };
  policy.policyDigest = digestOmitting(policy, 'policyDigest');
  const load = (value = policy) => loadMcpServerPolicy({ policy: value, policyRef: ref(value), assembly, principalId: policy.principalId,
    workspaceIdentityDigest: policy.workspaceIdentityDigest, request, target });
  return { policy, request, target, load };
}
test('server launch has the exact independent named MCP key and cannot borrow a tool or identity-read grant', () => {
  const { request, target, load } = data(), evaluator = load(), evidence = evaluator.evaluate(evaluated);
  assert.equal(evidence.actionClass, 'mcp'); assert.equal(evidence.channel, 'named-action');
  assert.equal(evidence.identityKey, `mcp_server_launch/${target.registryManifestDigest}/0`);
  assert.equal(evidence.namedAction.originatingBatchItemId, request.batchItemId);
  const grant = evaluator.grant(evidence, evaluated, expiry);
  assert.equal(grant.subject.kind, 'mcp_server_launch'); assert.equal(grant.maxLaunches, 2); assert.equal(grant.maxDispatchedAttempts, 2);
  assert.equal(grant.grantDigest, digestOmitting(grant, 'grantDigest'));
  assert.deepEqual(Object.keys(grant.provenance).sort(), ['actionClass', 'channelEvidenceDigest', 'channelEvidenceRef', 'decisionDigest', 'effectiveDisposition', 'kind', 'matchedRuleIds']);
  for (const change of [{ subject: { kind: 'tool_call' } }, { provenance: { kind: 'execution_identity_read', receiptRef: ref('receipt') } },
    { maxLaunches: 4 }, { maxLaunches: undefined }, { endpoint: 'https://unused.invalid' }])
    assert.throws(() => decodeMcpServerOperationGrant({ ...grant, ...change }));
  const forged = { ...evidence, identityKey: 'mcp/owned-server/owned-tool' }; forged.evidenceDigest = digestOmitting(forged, 'evidenceDigest');
  assert.throws(() => evaluator.grant(forged, evaluated, expiry));
});
for (const mode of ['default', 'accept-edits', 'plan', 'yolo'] as const) test(`server launch preserves ${mode} policy fallthrough`, () => {
  const f = data(mode), evaluator = f.load(), evidence = evaluator.evaluate(evaluated);
  assert.equal(evidence.effectiveDisposition, mode === 'yolo' ? 'allow' : mode === 'plan' ? 'deny' : 'ask');
  if (mode !== 'yolo') assert.throws(() => evaluator.grant(evidence, evaluated, expiry));
  if (mode === 'default' || mode === 'accept-edits') {
    const wait = evaluator.approvalWait(evidence, 7), input = { principalId: f.policy.principalId, channelIdentityRef: ref('channel data'),
      channelIdentityDigest: ref('channel digest'), requestId: '01900000-0000-7000-8000-000000000001', expectedRunRevision: 8,
      waitingOnRef: ref(wait), decision: 'allow' as const, ttlMs: 1000 };
    const decision = decodeMcpServerApprovalDecision(toolApprovalDecision(wait, input, evaluated, expiry));
    const grant = evaluator.approve(evidence, wait, decision, expiry)!;
    assert.equal(grant.provenance.kind, 'user_approval'); assert.equal(grant.expiresAt, '2026-11-01T00:01:01.000Z');
    for (const change of [{ lifecycleSeq: 1 }, { originatingCallIndex: 1 }, { originatingCallId: 'different-call' },
      { originatingBatchItemId: 'different-batch' }, { registryManifestDigest: ref('different manifest') }])
      assert.throws(() => evaluator.approve(evidence, { ...wait, subject: { ...wait.subject, ...change } }, decision, expiry));
    assert.throws(() => decodeMcpServerApprovalWait({ ...wait, subject: { ...wait.subject, toolName: 'borrowed-effect' } }));
  }
});
test('server launch reuses the original rule precedence, and yolo cannot override a named deny', () => {
  const f = data(), policy = structuredClone(f.policy);
  policy.decisionRules.push(...(['allow', 'deny'] as const).map((disposition, index) => ({ ruleId: `server-${disposition}`, order: index + 3,
    source: 'cli' as const, sourceRef: ref('authenticated immutable cli source'), channel: 'named-action' as const,
    pattern: `mcp_server_launch/${f.target.registryManifestDigest}/0`, disposition })));
  policy.policyDigest = digestOmitting(policy, 'policyDigest');
  const evaluator = f.load(policy), evidence = evaluator.evaluate(evaluated);
  assert.equal(evidence.effectiveDisposition, 'deny'); assert.deepEqual(evidence.matchedRuleIds, ['server-deny']);
  assert.throws(() => evaluator.grant(evidence, evaluated, expiry));
});
test('new retained launch target preserves all original argv and lifecycle bounds and has no guessed deadline', () => {
  const f = data(), changed = { ...f.target, argv: Array.from({ length: 128 }, (_, index) => index < 2 ? 'x'.repeat(8192) : ''), targetDigest: '' };
  changed.targetDigest = digestOmitting(changed, 'targetDigest'); assert.doesNotThrow(() => decodeMcpServerLaunchTarget(changed));
  for (const patch of [{ argv: Array.from({ length: 129 }, () => '') }, { argv: ['a\0b'] }, { callTimeoutMs: 3600001 },
    { launchTimeoutMs: 300001 }, { callDeadlineMs: 1793491201000 }]) {
    const value = { ...f.target, ...patch, targetDigest: '' }; value.targetDigest = digestOmitting(value, 'targetDigest');
    assert.throws(() => decodeMcpServerLaunchTarget(value));
  }
});
test('all original server claims count across replacement lifecycle ids, attempts and new grants without resetting the immutable ceiling', () => {
  const f = data(), requests = new Map<string, typeof f.request>(), journal: InvocationJournalEntry[] = [];
  function add(lifecycleSeq: number, attempt: number, grant: string) {
    const core = { ...f.request, lifecycleSeq, opId: mcpServerLaunchOperationId(f.request.runId, f.request.batchItemId,
      f.request.callIndex, f.request.callId, f.request.registryManifestDigest, lifecycleSeq), requestDigest: '' };
    core.requestDigest = digestOmitting(core, 'requestDigest'); const request = decodeMcpServerLaunchRequest(core), requestRef = ref(request);
    requests.set(requestRef, request);
    const common = { runId: request.runId, opId: request.opId, opKind: 'mcp-server' as const, attempt, leaseEpoch: 1,
      target: request.targetRef, requestRef, replayClass: 'retry' as const, grantRef: ref(grant), timestamp: evaluated };
    journal.push({ ...common, seq: journal.length + 1, phase: 'prepared', budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 } });
    journal.push({ ...common, seq: journal.length + 1, phase: 'dispatch_claimed', budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 },
      dispatchId: `data-dispatch-${lifecycleSeq}-${attempt}`, supervisorInstanceId: 'data-owner', stateOwnerEpoch: 1 });
  }
  const call = { runId: f.request.runId, batchItemId: f.request.batchItemId, callId: f.request.callId, callIndex: f.request.callIndex,
    registryRevisionRef: f.request.registryRevisionRef, registryManifestDigest: f.request.registryManifestDigest };
  add(0, 0, 'original permission'); add(0, 1, 'original permission'); add(1, 0, 'new explicit permission');
  assert.equal(countMcpServerLaunchClaims(journal, requests, call), 3);
  assert(countMcpServerLaunchClaims(journal, requests, call) > f.target.maxLaunches, 'new permission cannot refund or reset earlier original claims');
  assert.throws(() => countMcpServerLaunchClaims([...journal, { ...journal[1]!, seq: journal.length + 1 }], requests, call));
  assert.throws(() => countMcpServerLaunchClaims(journal, new Map(), call));
});
test('an owning-call-unknown audit preserves unknown remote effect and requires the exact initialized/dead local closure branch', () => {
  const core = { schemaVersion: 1, format: 'cliq-mcp-server-launch-failure-v1', runId: 'run-1', launchOpId: 'launch-1', attempt: 0,
    preparedJournalSeq: 8, claimedJournalSeq: 9, targetRef: ref('target'), requestRef: ref('request'), grantRef: ref('grant'),
    dispatchId: 'original-dispatch', sandboxLaunchSpecRef: ref('spec'), nativeClosure: { kind: 'linux_original_join', lifecycleRawRef: ref('raw'), lifecycleProjectionRef: ref('projection') },
    stoppedAt: evaluated, instance: 'initialized', instanceIdentityRef: ref('instance'), instanceIdentityDigest: ref('instance digest'),
    closure: 'containment_dead', processContainmentRef: ref('containment'), containmentDeathEvidenceRef: ref('death'),
    reason: 'owning_call_unknown', stoppedItemId: 'original-stopped' };
  const value = { ...core, failureDigest: ref(core) }; assert.equal(decodeMcpServerLaunchFailure(value).reason, 'owning_call_unknown');
  for (const change of [{ instance: 'not_initialized' }, { closure: 'plan_quiescent' }, { remoteEffectFailed: true },
    { nativeClosure: { kind: 'linux_original_join', lifecycleRawRef: ref('raw') } }, { reason: 'effect_failed' }]) {
    const changed = { ...core, ...change, failureDigest: '' }; changed.failureDigest = digestOmitting(changed, 'failureDigest');
    assert.throws(() => decodeMcpServerLaunchFailure(changed));
  }
  const { stoppedItemId: _stopped, ...missingStopped } = core;
  assert.throws(() => decodeMcpServerLaunchFailure({ ...missingStopped, failureDigest: ref(missingStopped) }));
});
test('initialized preclaim Stop/expiry is a distinct closed local audit and cannot borrow unknown, no-spawn or renewal data', () => {
  const core = { schemaVersion: 1, format: 'cliq-mcp-server-launch-failure-v1', runId: 'run-1', launchOpId: 'launch-1', attempt: 0,
    preparedJournalSeq: 8, claimedJournalSeq: 9, targetRef: ref('target'), requestRef: ref('request'), grantRef: ref('grant'),
    dispatchId: 'original-dispatch', sandboxLaunchSpecRef: ref('spec'), nativeClosure: { kind: 'linux_original_join', lifecycleRawRef: ref('raw'), lifecycleProjectionRef: ref('projection') },
    stoppedAt: evaluated, instance: 'initialized', instanceIdentityRef: ref('instance'), instanceIdentityDigest: ref('instance digest'),
    closure: 'containment_dead', processContainmentRef: ref('containment'), containmentDeathEvidenceRef: ref('death'),
    disposition: 'owning_call_not_dispatched', reason: 'cancel', stoppedItemId: 'original-stopped', owningCallClosureCause: { kind: 'stop_intent', stopIntentRef: ref('actual original Stop') } };
  assert.equal(decodeMcpServerLaunchFailure({ ...core, failureDigest: ref(core) }).disposition, 'owning_call_not_dispatched');
  const expired = { ...core, reason: 'deadline', owningCallClosureCause: { kind: 'original_call_deadline', deadlineMs: Date.parse(evaluated) } };
  assert.equal(decodeMcpServerLaunchFailure({ ...expired, failureDigest: ref(expired) }).reason, 'deadline');
  for (const change of [{ reason: 'owning_call_unknown' }, { instance: 'not_initialized' }, { closure: 'plan_quiescent' },
    { owningCallClosureCause: { kind: 'original_call_deadline', deadlineMs: Date.parse(expiry) } },
    { owningCallClosureCause: { kind: 'new_call_deadline', deadlineMs: Date.parse(expiry) } }, { disposition: 'effect_not_executed' }]) {
    const data = { ...core, ...change }; assert.throws(() => decodeMcpServerLaunchFailure({ ...data, failureDigest: ref(data) }));
  }
  const stopped = { schemaVersion: 1, kind: 'mcp_server_stopped', disposition: 'owning_call_not_dispatched', itemId: 'stopped-1', runId: 'run-1',
    batchItemId: 'batch-1', callId: 'call-1', callIndex: 0, serverManifestRef: ref('registry'), lifecycleSeq: 0, launchOpId: 'launch-1',
    instanceIdentityRef: ref('instance'), instanceIdentityDigest: ref('instance digest'), launchFailureRef: ref('local failure'), launchFailureDigest: ref('local failure digest'),
    cause: 'cancel', containmentEvidenceRef: ref('actual death locator'), createdAt: evaluated };
  assert.equal(decodeMcpServerFailedStoppedItem(stopped).cause, 'cancel');
  assert.throws(() => decodeMcpServerFailedStoppedItem({ ...stopped, cause: 'lease_release' }));
  assert.throws(() => decodeMcpServerFailedStoppedItem({ ...stopped, disposition: 'owning_call_unknown' }));
});

test('unclaimed launch failure is explicit no-spawn data and cannot borrow a claim, initialized instance or remote outcome', () => {
  const core = { schemaVersion: 1, format: 'cliq-mcp-server-launch-failure-v1', runId: 'run-1', launchOpId: 'launch-1', attempt: 0,
    preparedJournalSeq: 8, claimStatus: 'not_claimed', targetRef: ref('target'), requestRef: ref('request'), grantRef: ref('grant'),
    dispatchId: 'planned-dispatch', sandboxLaunchSpecRef: ref('spec'), nativeClosure: { kind: 'linux_original_join', lifecycleRawRef: ref('raw'), lifecycleProjectionRef: ref('projection') },
    stoppedAt: evaluated, instance: 'not_initialized', closure: 'plan_quiescent', noSpawnEvidenceRef: ref('inert no-spawn'), reason: 'cancel' };
  assert.equal(decodeMcpServerLaunchFailure({ ...core, failureDigest: ref(core) }).claimStatus, 'not_claimed');
  for (const change of [{ claimedJournalSeq: 9 }, { claimStatus: 'claimed' }, { instance: 'initialized' }, { closure: 'containment_dead' },
    { reason: 'owning_call_unknown' }, { disposition: 'owning_call_not_dispatched' }, { effectNotExecuted: true }]) {
    const data = { ...core, ...change }; assert.throws(() => decodeMcpServerLaunchFailure({ ...data, failureDigest: ref(data) }));
  }
});
