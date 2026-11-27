// Exact candidate source consent. This data is not the acquisition's native
// OperationGrant, and a policy-mode allow cannot replace its user decision.
import { canonicalSha256, canonicalJsonBytes } from './canonical.js';
import { assertControlWireJson, controlWireRecord, controlWireRef, controlWireText, controlWireInteger } from './control-wire-data.js';
import { decodeDependencyScriptConditions, type DependencyScriptConditionsV1 } from './dependency.js';
import { digestOmitting, identityHash, assertRequestId, parseCanonicalTime } from './identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { PolicyDisposition } from './tool-authorization.js';

export type DependencyScriptApprovalBinding = {
  runId: string; candidateItemId: string; candidateOrdinal: number; sourceCheckpointId: string;
  sourceRunSnapshotRef: string; workspaceStateRef: string; resultSourceRef: string; dependencyPlanRef: string;
  dependencyPlanDigest: string; lockfileDigest: string; scriptConditionsDigest: string;
};
export type DependencyScriptApprovalRequest = DependencyScriptApprovalBinding & {
  schemaVersion: 1; format: 'cliq-dependency-script-approval-request-v1'; opId: string;
  assemblyRef: string; frontierRef: string; targetRef: string; targetDigest: string; requestDigest: string;
};
export type DependencyScriptApprovalTarget = DependencyScriptApprovalBinding & {
  schemaVersion: 1; format: 'cliq-dependency-script-approval-target-v1'; workspaceIdentityRef: string; workspaceIdentityDigest: string;
  conditions: DependencyScriptConditionsV1;
  execution: { kind: 'supervisor_operation'; handlerId: 'dependency_install_scripts_approval'; supervisorEntryId: string;
    supervisorEntryVersion: string; supervisorExecutableDigest: string }; targetDigest: string;
};
export type DependencyScriptPolicyEvidence = {
  schemaVersion: 1; format: 'cliq-policy-channel-evidence-v1'; principalId: string; runId: string;
  policyRef: string; policyDigest: string; frontierRef: string; opId: string; requestRef: string; requestDigest: string;
  targetRef: string; targetDigest: string; actionClass: 'dependency_install_scripts'; channel: 'named-action';
  identityKey: string; decisionSource: 'rule' | 'mode_fallthrough'; matchedRuleIds: string[];
  effectiveDisposition: PolicyDisposition; evaluatedAt: string; evidenceDigest: string;
};
export type DependencyScriptApprovalSubject = DependencyScriptApprovalBinding & {
  kind: 'dependency_install_scripts'; reason: 'source_conditions_changed'; opId: string; target: string;
  policyChannelEvidenceRef: string; policyChannelEvidenceDigest: string;
};
export type DependencyScriptApprovalWait = {
  schemaVersion: 1; kind: 'approval'; runId: string; createdFromRevision: number; createdAt: string;
  frontierRef: string; subject: DependencyScriptApprovalSubject;
};
export type DependencyScriptApprovalDecision = {
  schemaVersion: 1; format: 'cliq-approval-decision-v1'; decisionId: string; principalId: string;
  channelIdentityRef: string; channelIdentityDigest: string; stateOwnerEpoch: number; supervisorInstanceId: string;
  inspectorIdentityRef: string; inspectorIdentityDigest: string; runId: string; waitingSubjectRef: string;
  waitingSubjectDigest: string; frontierRef: string; subject: DependencyScriptApprovalSubject; subjectDigest: string;
  requestId: string; requestDigest: string; expectedRunRevision: number; decision: 'allow' | 'deny';
  requestedTtlMs?: number; grantExpiresAt?: string; createdAt: string; decisionDigest: string;
};
/** Consent is registered in the existing continuation. A template is uniquely
 * reconstructed from this decision and its first response, avoiding a cycle
 * response -> context -> item -> template -> response. No dispatch grant here. */
export type DependencyScriptDecisionItem = {
  schemaVersion: 1; kind: 'policy_decision'; subjectKind: 'dependency_install_scripts'; itemId: string; runId: string;
  opId: string; principalId: string; decisionSource: 'interactive_approval'; waitingSubjectRef: string;
  decisionRef: string; policyChannelEvidenceRef: string; policyChannelEvidenceDigest: string;
  decision: 'allow' | 'deny'; createdAt: string;
};
const B = ['runId','candidateItemId','candidateOrdinal','sourceCheckpointId','sourceRunSnapshotRef','workspaceStateRef',
  'resultSourceRef','dependencyPlanRef','dependencyPlanDigest','lockfileDigest','scriptConditionsDigest'] as const;
const REFS = ['sourceRunSnapshotRef','workspaceStateRef','resultSourceRef','dependencyPlanRef','dependencyPlanDigest','lockfileDigest','scriptConditionsDigest'] as const;
const SUBJECT = [...B,'kind','reason','opId','target','policyChannelEvidenceRef','policyChannelEvidenceDigest'] as const;
export const dependencyScriptApprovalOpId = (b: DependencyScriptApprovalBinding) => identityHash('cliq-dependency-script-approval-op-v1',
  b.runId,b.candidateItemId,String(b.candidateOrdinal),b.dependencyPlanRef,b.resultSourceRef);
export const dependencyScriptWaitCheckpointId = (ref: string) => identityHash('cliq-dependency-script-wait-cp-v1', ref);
export const dependencyScriptDecisionCheckpointId = (ref: string) => identityHash('cliq-dependency-script-decision-cp-v1', ref);
export const dependencyScriptDecisionItemId = (runId: string, ref: string) => identityHash('cliq-dependency-script-decision-item-v1',runId,ref);
function data(value: unknown, keys: readonly string[], optional: readonly string[] = []) {
  assertControlWireJson(value); let nodes=0; const count=(v:unknown):void=>{if(++nodes>10000)throw new TypeError('dependency approval exceeds JSON node bound');
    if(v && typeof v==='object')for(const x of Object.values(v))count(x);}; count(value);
  if(canonicalJsonBytes(value).length>1048576)throw new TypeError('dependency approval exceeds JSON byte bound');
  return controlWireRecord(value,keys,optional);
}
function refs(v: Record<string,unknown>, keys: readonly string[]) { for(const k of keys)controlWireRef(v[k]); }
function texts(v:Record<string,unknown>, keys: readonly string[]) { for(const k of keys)controlWireText(v[k]); }
function time(v:unknown) { return parseCanonicalTime(controlWireText(v,24)); }
function binding(v:Record<string,unknown>) { refs(v,REFS);texts(v,['runId','candidateItemId','sourceCheckpointId']); controlWireInteger(v.candidateOrdinal); }
function hash(v:Record<string,unknown>,key:string) {controlWireRef(v[key]);if(v[key]!==digestOmitting(v,key))throw new TypeError('dependency approval digest differs');}
function subject(value:unknown):DependencyScriptApprovalSubject {
  const v=data(value,SUBJECT);binding(v);texts(v,['opId']);refs(v,['target','policyChannelEvidenceRef','policyChannelEvidenceDigest']);
  if(v.kind!=='dependency_install_scripts'||v.reason!=='source_conditions_changed'||v.opId!==dependencyScriptApprovalOpId(v as DependencyScriptApprovalSubject))throw new TypeError('foreign script approval subject');
  return immutableSnapshot(v) as DependencyScriptApprovalSubject;
}
export function decodeDependencyScriptApprovalRequest(value:unknown):DependencyScriptApprovalRequest {
  const v=data(value,[...B,'schemaVersion','format','opId','assemblyRef','frontierRef','targetRef','targetDigest','requestDigest']);binding(v);
  texts(v,['opId']);refs(v,['assemblyRef','frontierRef','targetRef','targetDigest']);hash(v,'requestDigest');
  if(v.schemaVersion!==1||v.format!=='cliq-dependency-script-approval-request-v1'||v.opId!==dependencyScriptApprovalOpId(v as DependencyScriptApprovalRequest))throw new TypeError('foreign script approval request');
  return immutableSnapshot(v) as DependencyScriptApprovalRequest;
}
export function decodeDependencyScriptApprovalTarget(value:unknown):DependencyScriptApprovalTarget {
  const v=data(value,[...B,'schemaVersion','format','workspaceIdentityRef','workspaceIdentityDigest','conditions','execution','targetDigest']);binding(v);
  refs(v,['workspaceIdentityRef','workspaceIdentityDigest']);const c=decodeDependencyScriptConditions(v.conditions);hash(v,'targetDigest');
  const e=data(v.execution,['kind','handlerId','supervisorEntryId','supervisorEntryVersion','supervisorExecutableDigest']);texts(e,['supervisorEntryId','supervisorEntryVersion']);refs(e,['supervisorExecutableDigest']);
  if(v.schemaVersion!==1||v.format!=='cliq-dependency-script-approval-target-v1'||canonicalSha256(c)!==v.scriptConditionsDigest||c.lockfileDigest!==v.lockfileDigest||
    c.source.sourceManifestRef!==v.resultSourceRef||e.kind!=='supervisor_operation'||e.handlerId!=='dependency_install_scripts_approval')throw new TypeError('foreign script consent target');
  return immutableSnapshot(v) as DependencyScriptApprovalTarget;
}
export function decodeDependencyScriptPolicyEvidence(value:unknown):DependencyScriptPolicyEvidence {
  const v=data(value,['schemaVersion','format','principalId','runId','policyRef','policyDigest','frontierRef','opId','requestRef','requestDigest','targetRef','targetDigest',
    'actionClass','channel','identityKey','decisionSource','matchedRuleIds','effectiveDisposition','evaluatedAt','evidenceDigest']);
  refs(v,['policyRef','policyDigest','frontierRef','requestRef','requestDigest','targetRef','targetDigest']);texts(v,['principalId','runId','opId','identityKey']);time(v.evaluatedAt);hash(v,'evidenceDigest');
  if(v.schemaVersion!==1||v.format!=='cliq-policy-channel-evidence-v1'||v.actionClass!=='dependency_install_scripts'||v.channel!=='named-action'||
    !['rule','mode_fallthrough'].includes(String(v.decisionSource))||!['allow','ask','deny'].includes(String(v.effectiveDisposition))||!Array.isArray(v.matchedRuleIds)||
    v.matchedRuleIds.length>256||v.matchedRuleIds.some(x=>typeof x!=='string')||new Set(v.matchedRuleIds).size!==v.matchedRuleIds.length)throw new TypeError('foreign script policy evidence');
  for(const x of v.matchedRuleIds)controlWireText(x);
  return immutableSnapshot(v) as DependencyScriptPolicyEvidence;
}
export function decodeDependencyScriptApprovalWait(value:unknown):DependencyScriptApprovalWait {
  const v=data(value,['schemaVersion','kind','runId','createdFromRevision','createdAt','frontierRef','subject']);texts(v,['runId']);controlWireInteger(v.createdFromRevision,1);time(v.createdAt);refs(v,['frontierRef']);const s=subject(v.subject);
  if(v.schemaVersion!==1||v.kind!=='approval'||s.runId!==v.runId)throw new TypeError('foreign dependency wait');return immutableSnapshot(v) as DependencyScriptApprovalWait;
}
export function decodeDependencyScriptApprovalDecision(value:unknown):DependencyScriptApprovalDecision {
  const v=data(value,['schemaVersion','format','decisionId','principalId','channelIdentityRef','channelIdentityDigest','stateOwnerEpoch','supervisorInstanceId','inspectorIdentityRef','inspectorIdentityDigest',
    'runId','waitingSubjectRef','waitingSubjectDigest','frontierRef','subject','subjectDigest','requestId','requestDigest','expectedRunRevision','decision','createdAt','decisionDigest'],['requestedTtlMs','grantExpiresAt']);
  refs(v,['channelIdentityRef','channelIdentityDigest','inspectorIdentityRef','inspectorIdentityDigest','waitingSubjectRef','waitingSubjectDigest','frontierRef','subjectDigest','requestDigest']);texts(v,['decisionId','principalId','supervisorInstanceId','runId']);
  controlWireInteger(v.stateOwnerEpoch,1);controlWireInteger(v.expectedRunRevision,1);assertRequestId(controlWireText(v.requestId));time(v.createdAt);hash(v,'decisionDigest');const s=subject(v.subject);
  if(v.requestedTtlMs!==undefined)controlWireInteger(v.requestedTtlMs,1,3600000);
  if(v.schemaVersion!==1||v.format!=='cliq-approval-decision-v1'||s.runId!==v.runId||canonicalSha256(s)!==v.subjectDigest||
    v.waitingSubjectRef!==v.waitingSubjectDigest||!['allow','deny'].includes(String(v.decision))||
    (v.decision==='allow')!==Object.hasOwn(v,'grantExpiresAt'))throw new TypeError('foreign dependency decision');
  if(v.grantExpiresAt!==undefined&&time(v.grantExpiresAt)<=time(v.createdAt))throw new TypeError('expired dependency decision');
  return immutableSnapshot(v) as DependencyScriptApprovalDecision;
}
export function decodeDependencyScriptDecisionItem(value:unknown):DependencyScriptDecisionItem {
  const v=data(value,['schemaVersion','kind','subjectKind','itemId','runId','opId','principalId','decisionSource','waitingSubjectRef','decisionRef','policyChannelEvidenceRef','policyChannelEvidenceDigest','decision','createdAt']);
  texts(v,['itemId','runId','opId','principalId']);refs(v,['waitingSubjectRef','decisionRef','policyChannelEvidenceRef','policyChannelEvidenceDigest']);time(v.createdAt);
  if(v.schemaVersion!==1||v.kind!=='policy_decision'||v.subjectKind!=='dependency_install_scripts'||v.decisionSource!=='interactive_approval'||
    !['allow','deny'].includes(String(v.decision))||v.itemId!==dependencyScriptDecisionItemId(v.runId as string,v.decisionRef as string))throw new TypeError('foreign dependency consent item');
  return immutableSnapshot(v) as DependencyScriptDecisionItem;
}
