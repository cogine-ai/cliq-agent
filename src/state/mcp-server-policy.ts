// The server launch is its own named productive action. This module derives
// immutable request/policy projections; State commits permission and native
// custody independently before any exec or protocol write.
import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { decodeMcpRegistryRevision, type McpRegistryRevisionV1 } from '../kernel/mcp.js';
import { mcpServerLaunchOperationId, decodeMcpStdioExecutableIdentity } from '../kernel/mcp-stdio.js';
export { decodeMcpStdioExecutableIdentity } from '../kernel/mcp-stdio.js';
import { decodeMcpServerLaunchRequest, decodeMcpServerLaunchTarget, decodeMcpServerOperationGrant,
  decodeMcpServerPolicyChannelEvidence, decodeMcpServerApprovalWait, mcpServerLaunchSubject,
  type McpServerLaunchRequestV1, type McpServerLaunchTargetV1, type McpServerOperationGrantV1,
  type McpServerPolicyChannelEvidenceV1, type McpServerApprovalWait, type McpServerApprovalDecisionV1 } from '../kernel/mcp-server-authorization.js';
import type { RunAssemblyV1 } from '../kernel/types.js';
import type { RunPolicySnapshotV1, ToolRequestV1, ToolTargetV1 } from '../kernel/tool-authorization.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { assertRunPolicySnapshot, evaluateFrozenPolicyKey } from '../policy/tool-policy.js';
import { toolApprovalDecision } from '../policy/tool-approval.js';

export function planMcpServerLaunch(input: Readonly<{
  request: ToolRequestV1; target: ToolTargetV1; registryRef: string; registry: McpRegistryRevisionV1; lifecycleSeq: number;
}>) {
  const { request: tool, target: effect, registryRef, lifecycleSeq } = input, registry = decodeMcpRegistryRevision(input.registry);
  if (registry.transport.kind !== 'stdio' ||
      registry.transport.executable.kind !== 'runtime_bundle' || effect.execution.kind !== 'mcp' ||
      effect.execution.registryRevisionRef !== registryRef || effect.execution.registryManifestDigest !== registry.manifestDigest ||
      tool.targetRef !== canonicalSha256(effect) || tool.targetDigest !== effect.targetDigest ||
      effect.execution.registrationId !== registry.registrationId || registryRef !== canonicalSha256(registry))
    throw new TypeError('MCP server launch differs from its exact supported frozen call/registry');
  const serverToolName = effect.execution.serverToolName, registered = registry.tools.find(entry => entry.name === serverToolName);
  if (!registered || registered.toolContractDigest !== effect.execution.toolContractDigest)
    throw new TypeError('MCP server launch substitutes its exact registered tool contract');
  const executable = decodeMcpStdioExecutableIdentity(registry.transport.executable);
  const targetCore = { schemaVersion: 1 as const, format: 'cliq-mcp-server-launch-target-v1' as const, runId: tool.runId,
    registrationId: registry.registrationId, registryRevisionRef: registryRef, registryManifestDigest: registry.manifestDigest,
    lifecycleSeq, batchItemId: tool.batchItemId, callId: tool.callId, callIndex: tool.callIndex,
    toolRequestRef: canonicalSha256(tool), toolRequestDigest: tool.requestDigest,
    executableIdentityRef: canonicalSha256(executable), executableIdentityDigest: canonicalSha256(executable),
    argv: registry.transport.argv.map(value => value.value), initializeDigest: registry.initializeDigest,
    capabilityDigest: registry.capabilityDigest, probedToolsListDigest: registry.probedToolsListDigest,
    maxLaunches: registry.lifecycle.maxLaunchesPerCall, launchTimeoutMs: registry.lifecycle.launchTimeoutMs, callTimeoutMs: registry.lifecycle.callTimeoutMs };
  const target = decodeMcpServerLaunchTarget({ ...targetCore, targetDigest: canonicalSha256(targetCore) });
  const core = { schemaVersion: 1 as const, format: 'cliq-mcp-server-launch-request-v1' as const, runId: tool.runId,
    opId: mcpServerLaunchOperationId(tool.runId, tool.batchItemId, tool.callIndex, tool.callId, registry.manifestDigest, lifecycleSeq),
    frontierRef: tool.frontierRef, assemblyRef: tool.assemblyRef, registryRevisionRef: registryRef, registryManifestDigest: registry.manifestDigest,
    lifecycleSeq, batchItemId: tool.batchItemId, callId: tool.callId, callIndex: tool.callIndex,
    toolRequestRef: canonicalSha256(tool), toolRequestDigest: tool.requestDigest, targetRef: canonicalSha256(target), targetDigest: target.targetDigest };
  return immutableSnapshot({ request: decodeMcpServerLaunchRequest({ ...core, requestDigest: canonicalSha256(core) }), target });
}

export function loadMcpServerPolicy(input: Readonly<{
  policy: RunPolicySnapshotV1; policyRef: string; assembly: RunAssemblyV1; principalId: string; workspaceIdentityDigest: string;
  request: McpServerLaunchRequestV1; target: McpServerLaunchTargetV1;
}>) {
  const { policy, policyRef, assembly, principalId, workspaceIdentityDigest } = immutableSnapshot(input);
  const request = decodeMcpServerLaunchRequest(input.request), target = decodeMcpServerLaunchTarget(input.target);
  assertRunPolicySnapshot({ policy, policyRef, assembly, principalId, workspaceIdentityDigest });
  if (request.targetRef !== canonicalSha256(target) || request.targetDigest !== target.targetDigest || request.runId !== target.runId ||
      request.registryRevisionRef !== target.registryRevisionRef || request.registryManifestDigest !== target.registryManifestDigest ||
      request.lifecycleSeq !== target.lifecycleSeq || request.batchItemId !== target.batchItemId || request.callId !== target.callId ||
      request.callIndex !== target.callIndex || request.toolRequestRef !== target.toolRequestRef || request.toolRequestDigest !== target.toolRequestDigest)
    throw new TypeError('MCP launch policy substitutes the launch request/target');
  const namedAction = mcpServerLaunchSubject(target), identityKey = `mcp_server_launch/${target.registryManifestDigest}/${target.lifecycleSeq}`;
  function evaluate(at: string): McpServerPolicyChannelEvidenceV1 {
    if (parseCanonicalTime(at) < parseCanonicalTime(policy.createdAt)) throw new TypeError('MCP launch policy precedes its retained source');
    const winning = evaluateFrozenPolicyKey(policy, 'mcp', 'named-action', identityKey);
    const core = { schemaVersion: 1 as const, format: 'cliq-policy-channel-evidence-v1' as const, principalId, runId: request.runId,
      policyRef, policyDigest: policy.policyDigest, frontierRef: request.frontierRef, opId: request.opId, requestRef: canonicalSha256(request),
      requestDigest: request.requestDigest, targetRef: request.targetRef, targetDigest: target.targetDigest, actionClass: 'mcp' as const,
      decisionSource: winning.ruleId === undefined ? 'mode_fallthrough' as const : 'rule' as const,
      matchedRuleIds: winning.ruleId === undefined ? [] : [winning.ruleId], effectiveDisposition: winning.disposition,
      evaluatedAt: at, channel: 'named-action' as const, namedAction, identityKey };
    return decodeMcpServerPolicyChannelEvidence({ ...core, evidenceDigest: canonicalSha256(core) });
  }
  function operationGrant(provenance: McpServerOperationGrantV1['provenance'], issuedAt: string, expiresAt: string) {
    const core = { schemaVersion: 1 as const, format: 'cliq-operation-grant-v1' as const,
      grantId: identityHash('cliq-operation-grant-v1', request.runId, request.opId, request.requestDigest, namedAction, issuedAt),
      principalId, runId: request.runId, policyRef, frontierRef: request.frontierRef, opId: request.opId,
      requestRef: canonicalSha256(request), requestDigest: request.requestDigest, targetRef: request.targetRef, targetDigest: target.targetDigest,
      subject: namedAction, provenance, maxDispatchedAttempts: target.maxLaunches, maxLaunches: target.maxLaunches, issuedAt, expiresAt };
    return decodeMcpServerOperationGrant({ ...core, grantDigest: canonicalSha256(core) });
  }
  function grant(evidence: McpServerPolicyChannelEvidenceV1, issuedAt: string, expiresAt: string) {
    requireEqual(evidence, evaluate(evidence.evaluatedAt), 'MCP launch exact direct policy evidence');
    if (evidence.effectiveDisposition !== 'allow' || issuedAt < evidence.evaluatedAt || expiresAt <= issuedAt)
      throw new TypeError('MCP server grant requires its exact direct allow and positive lifetime');
    const decision = { policyRef, channelEvidenceRef: canonicalSha256(evidence), channelEvidenceDigest: evidence.evidenceDigest,
      actionClass: 'mcp' as const, requestDigest: request.requestDigest, targetDigest: target.targetDigest,
      matchedRuleIds: [...evidence.matchedRuleIds], effectiveDisposition: 'allow' as const };
    return operationGrant({ kind: 'policy_snapshot', actionClass: 'mcp', channelEvidenceRef: decision.channelEvidenceRef,
      channelEvidenceDigest: decision.channelEvidenceDigest, matchedRuleIds: [...evidence.matchedRuleIds],
      effectiveDisposition: 'allow', decisionDigest: canonicalSha256(decision) }, issuedAt, expiresAt);
  }
  function approvalWait(evidence: McpServerPolicyChannelEvidenceV1, revision: number): McpServerApprovalWait {
    requireEqual(evidence, evaluate(evidence.evaluatedAt), 'MCP launch exact asking policy evidence');
    if (evidence.effectiveDisposition !== 'ask') throw new TypeError('MCP launch wait requires the exact asking policy');
    return decodeMcpServerApprovalWait({ schemaVersion: 1, kind: 'approval', runId: request.runId, createdFromRevision: revision,
      createdAt: evidence.evaluatedAt, frontierRef: request.frontierRef, subject: { ...namedAction, opId: request.opId,
        target: request.targetRef, policyChannelEvidenceRef: canonicalSha256(evidence), policyChannelEvidenceDigest: evidence.evidenceDigest } });
  }
  function approve(evidence: McpServerPolicyChannelEvidenceV1, wait: McpServerApprovalWait, decision: McpServerApprovalDecisionV1, deadlineAt: string) {
    requireEqual(wait, approvalWait(evidence, wait.createdFromRevision), 'MCP launch original approval wait');
    requireEqual(decision, toolApprovalDecision(wait, { principalId, channelIdentityRef: decision.channelIdentityRef,
      channelIdentityDigest: decision.channelIdentityDigest, requestId: decision.requestId, expectedRunRevision: decision.expectedRunRevision,
      waitingOnRef: canonicalSha256(wait), decision: decision.decision,
      ...(decision.requestedTtlMs === undefined ? {} : { ttlMs: decision.requestedTtlMs }) }, decision.createdAt, deadlineAt), 'MCP launch exact approval decision');
    if (decision.decision === 'deny') return undefined;
    return operationGrant({ kind: 'user_approval', waitingSubjectRef: canonicalSha256(wait), decisionRef: canonicalSha256(decision),
      requestId: decision.requestId, channelEvidenceRef: canonicalSha256(evidence), channelEvidenceDigest: evidence.evidenceDigest }, decision.createdAt, decision.grantExpiresAt!);
  }
  return Object.freeze({ request, target, evaluate, grant, approvalWait, approve });
}
