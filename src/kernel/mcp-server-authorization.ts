// Closed retained data for the independently authorized productive server
// launch. An identity-read receipt or an ordinary tools/call grant is never
// convertible to this grant, and decoding supplies no execution authority.
import type { ArtifactRef } from './types.js';
import type { InvocationJournalEntry } from './types.js';
import type { PolicyDisposition, ToolApprovalDecisionV1, ToolOperationGrantV1 } from './tool-authorization.js';
import { digestOmitting, parseCanonicalTime } from './identity.js';
import { canonicalSha256 } from './canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { assertBoundedJsonValue } from './json.js';
import { mcpServerLaunchOperationId } from './mcp-stdio.js';
import type { McpServerLaunchReceiptV1 } from './mcp-stdio.js';
import { immutableSnapshot } from '../model/immutable.js';

export type McpServerLaunchSubject = Readonly<{
  kind: 'mcp_server_launch'; registryRevisionRef: ArtifactRef; registryManifestDigest: string; lifecycleSeq: number;
  originatingBatchItemId: string; originatingCallId: string; originatingCallIndex: number;
}>;
export type McpServerLaunchTargetV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-server-launch-target-v1'; runId: string; registrationId: string;
  registryRevisionRef: ArtifactRef; registryManifestDigest: string; lifecycleSeq: number;
  batchItemId: string; callId: string; callIndex: number; toolRequestRef: ArtifactRef; toolRequestDigest: string;
  executableIdentityRef: ArtifactRef; executableIdentityDigest: string; argv: readonly string[];
  initializeDigest: string; capabilityDigest: string; probedToolsListDigest: string;
  maxLaunches: number; launchTimeoutMs: number; callTimeoutMs: number; targetDigest: string;
}>;
export type McpServerLaunchRequestV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-server-launch-request-v1'; runId: string; opId: string; frontierRef: ArtifactRef;
  assemblyRef: ArtifactRef; registryRevisionRef: ArtifactRef; registryManifestDigest: string; lifecycleSeq: number;
  batchItemId: string; callId: string; callIndex: number; toolRequestRef: ArtifactRef; toolRequestDigest: string;
  targetRef: ArtifactRef; targetDigest: string; requestDigest: string;
}>;
export type McpServerLaunchPreparationV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-server-launch-preparation-v1'; runId: string; principalId: string; launchOpId: string; attempt: number;
  batchItemId: string; callId: string; callIndex: number; lifecycleSeq: number; registryRef: ArtifactRef; manifestDigest: string;
  toolRequestRef: ArtifactRef; toolRequestDigest: string; requestRef: ArtifactRef; requestDigest: string; targetRef: ArtifactRef; targetDigest: string;
  grantRef: ArtifactRef; grantDigest: string; workerLaunchId: string; leaseEpoch: number; supervisorInstanceId: string; stateOwnerEpoch: number;
  originalSupervisor: Readonly<{ pid: number; processStartToken: string }>;
  controller: Readonly<{ pid: number; processStartToken: string }>; nonce: string; dispatchId: string; nativeRecipeRef: ArtifactRef;
  plannedContainmentRef: ArtifactRef; plannedContainmentDigest: string; sandboxLaunchSpecRef: ArtifactRef; sandboxLaunchSpecDigest: string;
  callDeadlineMs: number; launchDeadlineMs: number; createdAt: string; preparationDigest: string;
}>;
export type McpServerPolicyChannelEvidenceV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-policy-channel-evidence-v1'; principalId: string; runId: string;
  policyRef: ArtifactRef; policyDigest: string; frontierRef: ArtifactRef; opId: string;
  requestRef: ArtifactRef; requestDigest: string; targetRef: ArtifactRef; targetDigest: string; actionClass: 'mcp';
  decisionSource: 'rule' | 'mode_fallthrough'; matchedRuleIds: readonly string[]; effectiveDisposition: PolicyDisposition;
  evaluatedAt: string; evidenceDigest: string; channel: 'named-action'; namedAction: McpServerLaunchSubject;
  identityKey: string;
}>;
export type McpServerOperationGrantV1 = Readonly<Omit<ToolOperationGrantV1, 'subject' | 'provenance'> & {
  subject: McpServerLaunchSubject; maxLaunches: number;
  provenance: (Extract<ToolOperationGrantV1['provenance'], { kind: 'policy_snapshot' }> & { actionClass: 'mcp' }) |
    Extract<ToolOperationGrantV1['provenance'], { kind: 'user_approval' }>;
}>;
export type McpServerApprovalSubject = McpServerLaunchSubject & Readonly<{
  opId: string; target: ArtifactRef; policyChannelEvidenceRef: ArtifactRef; policyChannelEvidenceDigest: string;
}>;
export type McpServerApprovalWait = Readonly<{ schemaVersion: 1; kind: 'approval'; runId: string;
  createdFromRevision: number; createdAt: string; frontierRef: ArtifactRef; subject: McpServerApprovalSubject }>;
export type McpServerApprovalDecisionV1 = Readonly<Omit<ToolApprovalDecisionV1, 'subject'> & { subject: McpServerApprovalSubject }>;
export type McpServerPolicyDecisionItem = Readonly<{
  schemaVersion: 1; itemId: string; runId: string; kind: 'policy_decision'; subjectKind: 'mcp_server_launch';
  opId: string; principalId: string; decisionRef: ArtifactRef; policyChannelEvidenceRef: ArtifactRef;
  policyChannelEvidenceDigest: string; createdAt: string;
} & ({ decisionSource: 'direct_policy'; waitingSubjectRef?: never } |
  { decisionSource: 'interactive_approval'; waitingSubjectRef: ArtifactRef }) & (
  { decision: 'allow'; grantRef: ArtifactRef; denialOutcome?: never } |
  { decision: 'deny'; grantRef?: never; denialOutcome: { kind: 'tool_result_denied'; subjectKind: 'mcp_server_launch'; outcomeItemRef: ArtifactRef } })>;
export type McpServerLaunchFailureV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-server-launch-failure-v1'; runId: string; launchOpId: string; attempt: number;
  preparedJournalSeq: number; targetRef: ArtifactRef; requestRef: ArtifactRef; grantRef: ArtifactRef;
  dispatchId: string; sandboxLaunchSpecRef: ArtifactRef; nativeClosure: McpServerLaunchReceiptV1['nativeClosure'];
  stoppedAt: string; failureDigest: string;
} & ({ claimStatus?: never; claimedJournalSeq: number } |
  { claimStatus: 'not_claimed'; claimedJournalSeq?: never; instance: 'not_initialized'; closure: 'plan_quiescent';
    reason: 'transport_failure' | 'manifest_mismatch' | 'cancel' | 'deadline' | 'creator_lost_before_effect_claim'; stoppedItemId?: never; disposition?: never; owningCallClosureCause?: never }) &
({ instance: 'not_initialized'; instanceIdentityRef?: never; instanceIdentityDigest?: never } |
  { instance: 'setup_outcome_unavailable'; instanceIdentityRef?: never; instanceIdentityDigest?: never;
    reason: 'creator_lost_before_effect_claim'; closure: 'containment_dead';
    nativeClosure: Extract<McpServerLaunchReceiptV1['nativeClosure'], { kind: 'linux_successor_cleanup' }> } |
  { instance: 'initialized'; instanceIdentityRef: ArtifactRef; instanceIdentityDigest: string }) & (
  { closure: 'containment_dead'; processContainmentRef: ArtifactRef; containmentDeathEvidenceRef: ArtifactRef; noSpawnEvidenceRef?: never } |
  { closure: 'plan_quiescent'; noSpawnEvidenceRef: ArtifactRef; processContainmentRef?: never; containmentDeathEvidenceRef?: never }) & (
  { reason: 'owning_call_unknown'; stoppedItemId: string; disposition?: never; owningCallClosureCause?: never } |
  { reason: 'cancel' | 'deadline'; disposition: 'owning_call_not_dispatched'; stoppedItemId: string;
    owningCallClosureCause: Readonly<{ kind: 'stop_intent'; stopIntentRef: ArtifactRef }> | Readonly<{ kind: 'original_call_deadline'; deadlineMs: number }> } |
  { reason: 'creator_lost_before_effect_claim'; instance: 'setup_outcome_unavailable' | 'not_initialized';
    stoppedItemId?: never; disposition?: never; owningCallClosureCause?: never } |
  { reason: 'transport_failure' | 'manifest_mismatch' | 'cancel' | 'deadline'; instance: 'not_initialized'; stoppedItemId?: never; disposition?: never; owningCallClosureCause?: never })>;
export type McpServerFailedStoppedItem = Readonly<{
  schemaVersion: 1; kind: 'mcp_server_stopped'; itemId: string; runId: string;
  batchItemId: string; callId: string; callIndex: number; serverManifestRef: ArtifactRef; lifecycleSeq: number; launchOpId: string;
  instanceIdentityRef: ArtifactRef; instanceIdentityDigest: string; launchFailureRef: ArtifactRef; launchFailureDigest: string;
  containmentEvidenceRef: ArtifactRef; createdAt: string;
} & ({ disposition: 'owning_call_unknown'; cause: 'lease_release' } | { disposition: 'owning_call_not_dispatched'; cause: 'cancel' | 'deadline' })>;

const refFields = (data: Record<string, unknown>, names: readonly string[]) => { for (const name of names) controlWireRef(data[name]); };
const textFields = (data: Record<string, unknown>, names: readonly string[]) => { for (const name of names) controlWireText(data[name]); };
function bounded(value: unknown) { assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP server launch data'); }
function subject(value: unknown): McpServerLaunchSubject {
  const data = controlWireRecord(value, ['kind', 'registryRevisionRef', 'registryManifestDigest', 'lifecycleSeq',
    'originatingBatchItemId', 'originatingCallId', 'originatingCallIndex']);
  if (data.kind !== 'mcp_server_launch') throw new TypeError('foreign MCP server launch subject');
  refFields(data, ['registryRevisionRef', 'registryManifestDigest']); textFields(data, ['originatingBatchItemId', 'originatingCallId']);
  controlWireInteger(data.lifecycleSeq); controlWireInteger(data.originatingCallIndex);
  return immutableSnapshot(data) as McpServerLaunchSubject;
}
export function mcpServerLaunchSubject(target: McpServerLaunchTargetV1): McpServerLaunchSubject {
  return subject({ kind: 'mcp_server_launch', registryRevisionRef: target.registryRevisionRef,
    registryManifestDigest: target.registryManifestDigest, lifecycleSeq: target.lifecycleSeq,
    originatingBatchItemId: target.batchItemId, originatingCallId: target.callId, originatingCallIndex: target.callIndex });
}
export function decodeMcpServerLaunchTarget(value: unknown): McpServerLaunchTargetV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'registrationId', 'registryRevisionRef', 'registryManifestDigest',
    'lifecycleSeq', 'batchItemId', 'callId', 'callIndex', 'toolRequestRef', 'toolRequestDigest', 'executableIdentityRef', 'executableIdentityDigest',
    'argv', 'initializeDigest', 'capabilityDigest', 'probedToolsListDigest', 'maxLaunches', 'launchTimeoutMs', 'callTimeoutMs', 'targetDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-server-launch-target-v1') throw new TypeError('foreign MCP server launch target');
  textFields(data, ['runId', 'registrationId', 'batchItemId', 'callId']);
  refFields(data, ['registryRevisionRef', 'registryManifestDigest', 'toolRequestRef', 'toolRequestDigest', 'executableIdentityRef',
    'executableIdentityDigest', 'initializeDigest', 'capabilityDigest', 'probedToolsListDigest', 'targetDigest']);
  controlWireInteger(data.lifecycleSeq); controlWireInteger(data.callIndex); controlWireInteger(data.maxLaunches, 1, 3);
  controlWireInteger(data.launchTimeoutMs, 1000, 300000); controlWireInteger(data.callTimeoutMs, 1000, 3600000);
  if (!Array.isArray(data.argv) || data.argv.length > 128) throw new TypeError('MCP server argv exceeds its retained bound');
  for (const arg of data.argv) controlWireText(arg, 8192, 0);
  if (data.targetDigest !== digestOmitting(data, 'targetDigest'))
    throw new TypeError('MCP server launch target changes its original bounds or digest');
  return immutableSnapshot(data) as McpServerLaunchTargetV1;
}
export function decodeMcpServerLaunchRequest(value: unknown): McpServerLaunchRequestV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'opId', 'frontierRef', 'assemblyRef', 'registryRevisionRef',
    'registryManifestDigest', 'lifecycleSeq', 'batchItemId', 'callId', 'callIndex', 'toolRequestRef', 'toolRequestDigest', 'targetRef', 'targetDigest', 'requestDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-server-launch-request-v1') throw new TypeError('foreign MCP server launch request');
  textFields(data, ['runId', 'opId', 'batchItemId', 'callId']);
  refFields(data, ['frontierRef', 'assemblyRef', 'registryRevisionRef', 'registryManifestDigest', 'toolRequestRef', 'toolRequestDigest', 'targetRef', 'targetDigest', 'requestDigest']);
  controlWireInteger(data.lifecycleSeq); controlWireInteger(data.callIndex);
  if (data.opId !== mcpServerLaunchOperationId(data.runId as string, data.batchItemId as string, data.callIndex as number,
    data.callId as string, data.registryManifestDigest as string, data.lifecycleSeq as number) || data.requestDigest !== digestOmitting(data, 'requestDigest'))
    throw new TypeError('MCP launch request changes its original call or digest');
  return immutableSnapshot(data) as McpServerLaunchRequestV1;
}
export function decodeMcpServerLaunchPreparation(value: unknown): McpServerLaunchPreparationV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'principalId', 'launchOpId', 'attempt', 'batchItemId', 'callId', 'callIndex',
    'lifecycleSeq', 'registryRef', 'manifestDigest', 'toolRequestRef', 'toolRequestDigest', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'grantRef',
    'grantDigest', 'workerLaunchId', 'leaseEpoch', 'supervisorInstanceId', 'stateOwnerEpoch', 'originalSupervisor', 'controller', 'nonce', 'dispatchId', 'nativeRecipeRef',
    'plannedContainmentRef', 'plannedContainmentDigest', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'callDeadlineMs', 'launchDeadlineMs', 'createdAt', 'preparationDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-server-launch-preparation-v1') throw new TypeError('foreign MCP server launch prepared intent');
  textFields(data, ['runId', 'principalId', 'launchOpId', 'batchItemId', 'callId', 'workerLaunchId', 'supervisorInstanceId', 'dispatchId']);
  refFields(data, ['registryRef', 'manifestDigest', 'toolRequestRef', 'toolRequestDigest', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'grantRef', 'grantDigest',
    'nativeRecipeRef', 'plannedContainmentRef', 'plannedContainmentDigest', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'preparationDigest']);
  for (const name of ['attempt', 'callIndex', 'lifecycleSeq']) controlWireInteger(data[name]);
  for (const name of ['leaseEpoch', 'stateOwnerEpoch', 'callDeadlineMs', 'launchDeadlineMs']) controlWireInteger(data[name], 1);
  for (const name of ['originalSupervisor', 'controller']) {
    const process = controlWireRecord(data[name], ['pid', 'processStartToken']); controlWireInteger(process.pid, 1, 2147483647); controlWireText(process.processStartToken, 192);
  }
  if (typeof data.nonce !== 'string' || !/^[0-9a-f]{64}$/u.test(data.nonce) || (data.launchDeadlineMs as number) > (data.callDeadlineMs as number) ||
      parseCanonicalTime(data.createdAt as string) >= (data.launchDeadlineMs as number) ||
      data.launchOpId !== mcpServerLaunchOperationId(data.runId as string, data.batchItemId as string, data.callIndex as number,
        data.callId as string, data.manifestDigest as string, data.lifecycleSeq as number) || data.preparationDigest !== digestOmitting(data, 'preparationDigest'))
    throw new TypeError('MCP server prepared intent changes its original identity/nonce/deadline/digest');
  return immutableSnapshot(data) as McpServerLaunchPreparationV1;
}
export function decodeMcpServerPolicyChannelEvidence(value: unknown): McpServerPolicyChannelEvidenceV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'principalId', 'runId', 'policyRef', 'policyDigest', 'frontierRef', 'opId',
    'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'actionClass', 'decisionSource', 'matchedRuleIds', 'effectiveDisposition',
    'evaluatedAt', 'evidenceDigest', 'channel', 'namedAction', 'identityKey']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-policy-channel-evidence-v1' || data.actionClass !== 'mcp' || data.channel !== 'named-action' ||
      !['allow', 'ask', 'deny'].includes(data.effectiveDisposition as string) || !['rule', 'mode_fallthrough'].includes(data.decisionSource as string))
    throw new TypeError('foreign MCP server policy channel');
  textFields(data, ['principalId', 'runId', 'opId']); refFields(data, ['policyRef', 'policyDigest', 'frontierRef', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'evidenceDigest']);
  const named = subject(data.namedAction);
  if (data.identityKey !== `mcp_server_launch/${named.registryManifestDigest}/${named.lifecycleSeq}` || !Array.isArray(data.matchedRuleIds) ||
      data.matchedRuleIds.length !== (data.decisionSource === 'rule' ? 1 : 0)) throw new TypeError('MCP launch policy changes its exact named key');
  for (const id of data.matchedRuleIds) controlWireText(id);
  parseCanonicalTime(data.evaluatedAt as string);
  if (data.evidenceDigest !== digestOmitting(data, 'evidenceDigest')) throw new TypeError('MCP launch policy digest differs');
  return immutableSnapshot(data) as McpServerPolicyChannelEvidenceV1;
}
export function decodeMcpServerOperationGrant(value: unknown): McpServerOperationGrantV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'grantId', 'principalId', 'runId', 'policyRef', 'frontierRef', 'opId',
    'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'subject', 'provenance', 'maxDispatchedAttempts', 'maxLaunches', 'issuedAt', 'expiresAt', 'grantDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-operation-grant-v1') throw new TypeError('foreign MCP launch grant');
  textFields(data, ['grantId', 'principalId', 'runId', 'opId']); refFields(data, ['policyRef', 'frontierRef', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'grantDigest']);
  subject(data.subject); controlWireInteger(data.maxDispatchedAttempts, 1, 5); controlWireInteger(data.maxLaunches, 1, 3);
  const provenance = controlWireRecord(data.provenance, ['kind'], ['actionClass', 'channelEvidenceRef', 'channelEvidenceDigest', 'matchedRuleIds',
    'effectiveDisposition', 'decisionDigest', 'waitingSubjectRef', 'decisionRef', 'requestId']);
  if (provenance.kind === 'policy_snapshot') {
    controlWireRecord(provenance, ['kind', 'actionClass', 'channelEvidenceRef', 'channelEvidenceDigest', 'matchedRuleIds', 'effectiveDisposition', 'decisionDigest']);
    if (provenance.actionClass !== 'mcp' || provenance.effectiveDisposition !== 'allow' || !Array.isArray(provenance.matchedRuleIds) || provenance.matchedRuleIds.length > 1)
      throw new TypeError('MCP launch grant has no exact direct allow');
    for (const id of provenance.matchedRuleIds) controlWireText(id);
    controlWireRef(provenance.decisionDigest);
  } else if (provenance.kind === 'user_approval') {
    controlWireRecord(provenance, ['kind', 'waitingSubjectRef', 'decisionRef', 'requestId', 'channelEvidenceRef', 'channelEvidenceDigest']);
    refFields(provenance, ['waitingSubjectRef', 'decisionRef']); controlWireText(provenance.requestId);
  } else throw new TypeError('MCP launch grant cannot borrow another purpose provenance');
  refFields(provenance, ['channelEvidenceRef', 'channelEvidenceDigest']);
  if (parseCanonicalTime(data.expiresAt as string) <= parseCanonicalTime(data.issuedAt as string) || data.grantDigest !== digestOmitting(data, 'grantDigest'))
    throw new TypeError('MCP launch grant lifetime or digest differs');
  return immutableSnapshot(data) as McpServerOperationGrantV1;
}
export function decodeMcpServerApprovalWait(value: unknown): McpServerApprovalWait {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'kind', 'runId', 'createdFromRevision', 'createdAt', 'frontierRef', 'subject']);
  if (data.schemaVersion !== 1 || data.kind !== 'approval') throw new TypeError('foreign MCP launch approval wait');
  controlWireText(data.runId); controlWireInteger(data.createdFromRevision, 1); controlWireRef(data.frontierRef); parseCanonicalTime(data.createdAt as string);
  const selected = controlWireRecord(data.subject, ['kind', 'registryRevisionRef', 'registryManifestDigest', 'lifecycleSeq', 'originatingBatchItemId',
    'originatingCallId', 'originatingCallIndex', 'opId', 'target', 'policyChannelEvidenceRef', 'policyChannelEvidenceDigest']);
  const { opId, target, policyChannelEvidenceRef, policyChannelEvidenceDigest, ...core } = selected;
  const named = subject(core); controlWireText(opId); refFields(selected, ['target', 'policyChannelEvidenceRef', 'policyChannelEvidenceDigest']);
  if (opId !== mcpServerLaunchOperationId(data.runId as string, named.originatingBatchItemId, named.originatingCallIndex,
    named.originatingCallId, named.registryManifestDigest, named.lifecycleSeq)) throw new TypeError('MCP approval changes its owning launch');
  return immutableSnapshot(data) as McpServerApprovalWait;
}
export function decodeMcpServerApprovalDecision(value: unknown): McpServerApprovalDecisionV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'decisionId', 'principalId', 'channelIdentityRef', 'channelIdentityDigest',
    'runId', 'waitingSubjectRef', 'waitingSubjectDigest', 'frontierRef', 'subject', 'subjectDigest', 'requestId', 'requestDigest',
    'expectedRunRevision', 'decision', 'createdAt', 'decisionDigest'], ['requestedTtlMs', 'grantExpiresAt']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-approval-decision-v1' || !['allow', 'deny'].includes(data.decision as string))
    throw new TypeError('foreign MCP server approval decision');
  textFields(data, ['decisionId', 'principalId', 'runId', 'requestId']);
  refFields(data, ['channelIdentityRef', 'channelIdentityDigest', 'waitingSubjectRef', 'waitingSubjectDigest', 'frontierRef',
    'subjectDigest', 'requestDigest', 'decisionDigest']);
  controlWireInteger(data.expectedRunRevision, 2);
  if (data.requestedTtlMs !== undefined) controlWireInteger(data.requestedTtlMs, 1, 86400000);
  parseCanonicalTime(data.createdAt as string);
  if (data.decision === 'allow') {
    if (parseCanonicalTime(data.grantExpiresAt as string) <= parseCanonicalTime(data.createdAt as string)) throw new TypeError('MCP approval has no positive exact lifetime');
  } else if (data.grantExpiresAt !== undefined) throw new TypeError('MCP launch denial cannot carry execution expiry');
  // Reuse the same closed subject decoder without inventing a waiting fact.
  decodeMcpServerApprovalWait({ schemaVersion: 1, kind: 'approval', runId: data.runId,
    createdFromRevision: (data.expectedRunRevision as number) - 1, createdAt: data.createdAt, frontierRef: data.frontierRef, subject: data.subject });
  if (data.subjectDigest !== canonicalSha256(data.subject) || data.decisionDigest !== digestOmitting(data, 'decisionDigest'))
    throw new TypeError('MCP approval subject or decision digest differs');
  return immutableSnapshot(data) as McpServerApprovalDecisionV1;
}
export function decodeMcpServerPolicyDecisionItem(value: unknown): McpServerPolicyDecisionItem {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'itemId', 'runId', 'kind', 'subjectKind', 'opId', 'principalId', 'decisionRef',
    'policyChannelEvidenceRef', 'policyChannelEvidenceDigest', 'createdAt', 'decisionSource', 'decision'], ['waitingSubjectRef', 'grantRef', 'denialOutcome']);
  if (data.schemaVersion !== 1 || data.kind !== 'policy_decision' || data.subjectKind !== 'mcp_server_launch') throw new TypeError('foreign MCP server policy item');
  textFields(data, ['itemId', 'runId', 'opId', 'principalId']); refFields(data, ['decisionRef', 'policyChannelEvidenceRef', 'policyChannelEvidenceDigest']);
  parseCanonicalTime(data.createdAt as string);
  if (data.decisionSource === 'interactive_approval') controlWireRef(data.waitingSubjectRef);
  else if (data.decisionSource !== 'direct_policy' || data.waitingSubjectRef !== undefined) throw new TypeError('MCP policy item changes its decision source');
  if (data.decision === 'allow') {
    controlWireRef(data.grantRef); if (data.denialOutcome !== undefined) throw new TypeError('MCP allow cannot deny a call');
  } else if (data.decision === 'deny') {
    if (data.grantRef !== undefined) throw new TypeError('MCP denial cannot grant a launch');
    const denied = controlWireRecord(data.denialOutcome, ['kind', 'subjectKind', 'outcomeItemRef']);
    if (denied.kind !== 'tool_result_denied' || denied.subjectKind !== 'mcp_server_launch') throw new TypeError('MCP denial changes its owning call result');
    controlWireRef(denied.outcomeItemRef);
  } else throw new TypeError('MCP launch policy item has no closed disposition');
  return immutableSnapshot(data) as McpServerPolicyDecisionItem;
}
export function decodeMcpServerLaunchFailure(value: unknown): McpServerLaunchFailureV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'launchOpId', 'attempt', 'preparedJournalSeq',
    'targetRef', 'requestRef', 'grantRef', 'dispatchId', 'sandboxLaunchSpecRef', 'nativeClosure',
    'reason', 'stoppedAt', 'failureDigest', 'instance', 'closure'], ['claimedJournalSeq', 'claimStatus', 'instanceIdentityRef', 'instanceIdentityDigest', 'processContainmentRef', 'containmentDeathEvidenceRef', 'noSpawnEvidenceRef', 'stoppedItemId', 'disposition', 'owningCallClosureCause']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-server-launch-failure-v1' ||
      !['transport_failure', 'manifest_mismatch', 'cancel', 'deadline', 'owning_call_unknown', 'creator_lost_before_effect_claim'].includes(data.reason as string)) throw new TypeError('foreign MCP server launch failure');
  textFields(data, ['runId', 'launchOpId', 'dispatchId']);
  refFields(data, ['targetRef', 'requestRef', 'grantRef', 'sandboxLaunchSpecRef', 'failureDigest']);
  if (data.closure === 'containment_dead') {
    refFields(data, ['processContainmentRef', 'containmentDeathEvidenceRef']);
    if (data.noSpawnEvidenceRef !== undefined) throw new TypeError('MCP server death cannot borrow a no-spawn branch');
  } else if (data.closure === 'plan_quiescent') {
    controlWireRef(data.noSpawnEvidenceRef);
    if (data.processContainmentRef !== undefined || data.containmentDeathEvidenceRef !== undefined || data.instance !== 'not_initialized')
      throw new TypeError('MCP no-spawn closure cannot contain a created instance');
  } else throw new TypeError('MCP server failure has no closed original resource retirement branch');
  controlWireInteger(data.attempt); const prepared = controlWireInteger(data.preparedJournalSeq, 1);
  if (data.claimStatus === 'not_claimed') {
    if (data.claimedJournalSeq !== undefined || data.instance !== 'not_initialized' || data.closure !== 'plan_quiescent' || data.reason === 'owning_call_unknown')
      throw new TypeError('MCP unclaimed preparation requires its actual never-created local domain and no claim');
  } else if (data.claimStatus !== undefined || prepared >= controlWireInteger(data.claimedJournalSeq, 1))
    throw new TypeError('MCP server failure changes its original permanent claim');
  const native = controlWireRecord(data.nativeClosure, ['kind', 'lifecycleRawRef', 'lifecycleProjectionRef'], ['cleanupRawRef', 'cleanupProjectionRef']);
  refFields(native, ['lifecycleRawRef', 'lifecycleProjectionRef']);
  if (native.kind === 'linux_original_join') controlWireRecord(native, ['kind', 'lifecycleRawRef', 'lifecycleProjectionRef']);
  else if (native.kind === 'linux_successor_cleanup') {
    controlWireRecord(native, ['kind', 'lifecycleRawRef', 'lifecycleProjectionRef', 'cleanupRawRef', 'cleanupProjectionRef']);
    refFields(native, ['cleanupRawRef', 'cleanupProjectionRef']);
  } else throw new TypeError('MCP server failure has no complete closed native lifecycle root');
  if (data.instance === 'initialized') refFields(data, ['instanceIdentityRef', 'instanceIdentityDigest']);
  else if (!['not_initialized', 'setup_outcome_unavailable'].includes(data.instance as string) || data.instanceIdentityRef !== undefined || data.instanceIdentityDigest !== undefined)
    throw new TypeError('MCP server failure changes its initialized instance branch');
  if (data.instance === 'setup_outcome_unavailable' && (data.reason !== 'creator_lost_before_effect_claim' || data.closure !== 'containment_dead' ||
      data.claimStatus !== undefined || native.kind !== 'linux_successor_cleanup'))
    throw new TypeError('MCP unavailable setup outcome requires its original claimed server and separate current cleanup');
  if (data.reason === 'creator_lost_before_effect_claim' && (native.kind !== 'linux_successor_cleanup' || data.instance === 'initialized' ||
      data.stoppedItemId !== undefined || data.disposition !== undefined || data.owningCallClosureCause !== undefined))
    throw new TypeError('MCP lost creator closure cannot invent an initialized identity, effect outcome or original-owner join');
  if (data.reason === 'owning_call_unknown') {
    controlWireText(data.stoppedItemId);
    if (data.instance !== 'initialized' || data.closure !== 'containment_dead' || data.disposition !== undefined || data.owningCallClosureCause !== undefined)
      throw new TypeError('unknown owning call requires its actual initialized dead local instance');
  } else if (data.disposition === 'owning_call_not_dispatched') {
    controlWireText(data.stoppedItemId);
    if (!['cancel', 'deadline'].includes(data.reason as string) || data.instance !== 'initialized' || data.closure !== 'containment_dead')
      throw new TypeError('undispatched owning call requires its exact initialized dead local instance and Stop/expiry reason');
    const cause = controlWireRecord(data.owningCallClosureCause, ['kind'], ['stopIntentRef', 'deadlineMs']);
    if (cause.kind === 'stop_intent') { controlWireRecord(cause, ['kind', 'stopIntentRef']); controlWireRef(cause.stopIntentRef); }
    else if (cause.kind === 'original_call_deadline') { controlWireRecord(cause, ['kind', 'deadlineMs']); controlWireInteger(cause.deadlineMs, 1);
      if (data.reason !== 'deadline') throw new TypeError('original call expiry cannot become a cancellation'); }
    else throw new TypeError('foreign MCP undispatched owning-call closure cause');
  } else if (data.instance === 'initialized' || data.stoppedItemId !== undefined || data.disposition !== undefined || data.owningCallClosureCause !== undefined)
    throw new TypeError('MCP launch failure cannot borrow another owning-call stopped branch');
  parseCanonicalTime(data.stoppedAt as string);
  if (data.failureDigest !== digestOmitting(data, 'failureDigest')) throw new TypeError('MCP server failure changes its original digest');
  return immutableSnapshot(data) as McpServerLaunchFailureV1;
}
export function decodeMcpServerFailedStoppedItem(value: unknown): McpServerFailedStoppedItem {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'kind', 'disposition', 'itemId', 'runId', 'batchItemId', 'callId', 'callIndex',
    'serverManifestRef', 'lifecycleSeq', 'launchOpId', 'instanceIdentityRef', 'instanceIdentityDigest', 'launchFailureRef', 'launchFailureDigest', 'cause', 'containmentEvidenceRef', 'createdAt']);
  if (data.schemaVersion !== 1 || data.kind !== 'mcp_server_stopped' || (data.disposition === 'owning_call_unknown' ? data.cause !== 'lease_release'
    : data.disposition !== 'owning_call_not_dispatched' || !['cancel', 'deadline'].includes(data.cause as string)))
    throw new TypeError('foreign MCP local failed stopped audit');
  textFields(data, ['itemId', 'runId', 'batchItemId', 'callId', 'launchOpId']);
  refFields(data, ['serverManifestRef', 'instanceIdentityRef', 'instanceIdentityDigest', 'launchFailureRef', 'launchFailureDigest', 'containmentEvidenceRef']);
  controlWireInteger(data.callIndex); controlWireInteger(data.lifecycleSeq); parseCanonicalTime(data.createdAt as string);
  return immutableSnapshot(data) as McpServerFailedStoppedItem;
}
/** Data-only original whole-call counter. Replacement operation ids, attempts
 * and later grants never reset the frozen maxLaunchesPerCall ceiling. */
export function countMcpServerLaunchClaims(journal: readonly InvocationJournalEntry[], requests: ReadonlyMap<string, McpServerLaunchRequestV1>,
  call: Readonly<{ runId: string; batchItemId: string; callId: string; callIndex: number; registryRevisionRef: string; registryManifestDigest: string }>) {
  const prepared = new Map<string, { entry: InvocationJournalEntry; request: McpServerLaunchRequestV1 }>(), claims = new Set<string>();
  let previous = 0, total = 0;
  for (const entry of journal) {
    if (entry.runId !== call.runId || !Number.isSafeInteger(entry.seq) || entry.seq <= previous) throw new TypeError('MCP launch count requires its exact ordered original Run Journal');
    previous = entry.seq;
    if (entry.opKind !== 'mcp-server') continue;
    const key = JSON.stringify([entry.opId, entry.attempt]);
    if (entry.phase === 'prepared') {
      const request = requests.get(entry.requestRef);
      if (!request || prepared.has(key) || canonicalSha256(request) !== entry.requestRef || request.opId !== entry.opId || request.runId !== entry.runId)
        throw new TypeError('MCP launch count has no unique exact retained prepared request');
      prepared.set(key, { entry, request: decodeMcpServerLaunchRequest(request) });
    } else if (entry.phase === 'dispatch_claimed') {
      const original = prepared.get(key);
      if (!original || claims.has(key) || original.entry.requestRef !== entry.requestRef || original.entry.target !== entry.target || original.entry.grantRef !== entry.grantRef)
        throw new TypeError('MCP launch count changes or repeats an original permanent claim');
      claims.add(key); const request = original.request;
      if (request.batchItemId === call.batchItemId && request.callId === call.callId && request.callIndex === call.callIndex) {
        if (request.registryRevisionRef !== call.registryRevisionRef || request.registryManifestDigest !== call.registryManifestDigest)
          throw new TypeError('MCP launch replacement changes its frozen registry');
        total++;
      }
    }
  }
  return total;
}
