import { canonicalSha256 } from './canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { assertRequestId, digestOmitting, identityHash, parseCanonicalTime } from './identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { PolicyDisposition } from './tool-authorization.js';

/** Every identity comes from the exact owned merge call and its original
 * immutable parent source cut, never from a model-selected merge target. */
export type ChildMergeBindingV1 = {
  runId: string; mergeBatchItemId: string; callId: string; callIndex: number;
  childRunId: string; childResultItemId: string; patchManifestRef: string;
  parentRunSnapshotRef: string; sourceCheckpointId: string; workspaceStateRef: string;
  sourceBaseRef: string; sourceDesiredRef: string; capturedWorkspaceRef: string;
};
export type ChildMergeRequestV1 = ChildMergeBindingV1 & {
  schemaVersion: 1; format: 'cliq-child-merge-request-v1'; opId: string;
  assemblyRef: string; frontierRef: string; targetRef: string; targetDigest: string; requestDigest: string;
};
export type ChildMergeTargetV1 = ChildMergeBindingV1 & {
  schemaVersion: 1; format: 'cliq-child-merge-target-v1'; workspaceIdentityRef: string; workspaceIdentityDigest: string;
  changedPathsDigest: string; execution: { kind: 'supervisor_operation'; handlerId: 'child_merge';
    supervisorEntryId: string; supervisorEntryVersion: string; supervisorExecutableDigest: string }; targetDigest: string;
};
export type ChildMergePolicyEvidenceV1 = {
  schemaVersion: 1; format: 'cliq-policy-channel-evidence-v1'; principalId: string; runId: string;
  policyRef: string; policyDigest: string; frontierRef: string; opId: string; requestRef: string; requestDigest: string;
  targetRef: string; targetDigest: string; actionClass: 'write'; channel: 'fs-write';
  canonicalRootRelativePaths: string[];
  pathDecisions: Array<{ path: string; decisionSource: 'rule' | 'mode_fallthrough'; matchedRuleIds: string[]; effectiveDisposition: PolicyDisposition }>;
  matchedRuleIds: string[]; effectiveDisposition: PolicyDisposition; evaluatedAt: string; evidenceDigest: string;
};
export type ChildMergeGrantSubjectV1 = ChildMergeBindingV1 & { kind: 'child_merge'; changedPathsDigest: string };
export type ChildMergeGrantV1 = {
  schemaVersion: 1; format: 'cliq-operation-grant-v1'; grantId: string; principalId: string; runId: string;
  policyRef: string; frontierRef: string; opId: string; requestRef: string; requestDigest: string;
  targetRef: string; targetDigest: string; subject: ChildMergeGrantSubjectV1;
  provenance: { kind: 'policy_snapshot'; actionClass: 'write'; channelEvidenceRef: string; channelEvidenceDigest: string;
    matchedRuleIds: string[]; effectiveDisposition: 'allow'; decisionDigest: string }
    | { kind: 'user_approval'; waitingSubjectRef: string; decisionRef: string; requestId: string;
        channelEvidenceRef: string; channelEvidenceDigest: string };
  /** Exactly one atomic local Journal triplet; this grant has no native/broker consumer. */
  maxDispatchedAttempts: 1; issuedAt: string; expiresAt: string; grantDigest: string;
};
export type ChildMergeApprovalSubjectV1 = ChildMergeGrantSubjectV1 & {
  opId: string; target: string; policyChannelEvidenceRef: string; policyChannelEvidenceDigest: string;
};
export type ChildMergeApprovalWait = {
  schemaVersion: 1; kind: 'approval'; runId: string; createdFromRevision: number; createdAt: string;
  frontierRef: string; subject: ChildMergeApprovalSubjectV1;
};
export type ChildMergeApprovalDecisionV1 = {
  schemaVersion: 1; format: 'cliq-approval-decision-v1'; decisionId: string;
  principalId: string; channelIdentityRef: string; channelIdentityDigest: string;
  stateOwnerEpoch: number; supervisorInstanceId: string; inspectorIdentityRef: string; inspectorIdentityDigest: string;
  runId: string; waitingSubjectRef: string; waitingSubjectDigest: string; frontierRef: string;
  subject: ChildMergeApprovalSubjectV1; subjectDigest: string; requestId: string; requestDigest: string;
  expectedRunRevision: number; decision: 'allow' | 'deny'; requestedTtlMs?: number; grantExpiresAt?: string;
  createdAt: string; decisionDigest: string;
};
export type ChildMergePolicyDecisionItem = {
  schemaVersion: 1; kind: 'policy_decision'; subjectKind: 'child_merge'; itemId: string; runId: string;
  opId: string; principalId: string; decisionRef: string; policyChannelEvidenceRef: string; policyChannelEvidenceDigest: string;
  createdAt: string;
} & ({ decisionSource: 'direct_policy'; waitingSubjectRef?: never } | { decisionSource: 'interactive_approval'; waitingSubjectRef: string }) &
  ({ decision: 'allow'; grantRef: string } | { decision: 'deny'; grantRef?: never });

export const childMergeOperationId = (source: Pick<ChildMergeBindingV1,
  'runId' | 'mergeBatchItemId' | 'callIndex' | 'callId' | 'patchManifestRef' | 'sourceCheckpointId' | 'workspaceStateRef'>) =>
  identityHash('cliq-child-merge-op-v1', source.runId, source.mergeBatchItemId, String(source.callIndex), source.callId,
    source.patchManifestRef, source.sourceCheckpointId, source.workspaceStateRef);
export const childMergeIdempotencyKey = (opId: string, requestDigest: string) => identityHash('cliq-child-merge-key-v1', opId, requestDigest);

export const CHILD_MERGE_BINDING_KEYS = ['runId', 'mergeBatchItemId', 'callId', 'callIndex', 'childRunId', 'childResultItemId',
  'patchManifestRef', 'parentRunSnapshotRef', 'sourceCheckpointId', 'workspaceStateRef', 'sourceBaseRef', 'sourceDesiredRef', 'capturedWorkspaceRef'] as const;
const BINDING_REFS = ['patchManifestRef', 'parentRunSnapshotRef', 'workspaceStateRef', 'sourceBaseRef', 'sourceDesiredRef', 'capturedWorkspaceRef'] as const;
const SUBJECT_KEYS = [...CHILD_MERGE_BINDING_KEYS, 'kind', 'changedPathsDigest'] as const;
const WAIT_SUBJECT_KEYS = [...SUBJECT_KEYS, 'opId', 'target', 'policyChannelEvidenceRef', 'policyChannelEvidenceDigest'] as const;
function data(value: unknown, keys: readonly string[], optional: readonly string[] = []) {
  assertControlWireJson(value); return controlWireRecord(value, keys, optional);
}
function refs(record: Record<string, unknown>, keys: readonly string[]) { for (const key of keys) controlWireRef(record[key]); }
function texts(record: Record<string, unknown>, keys: readonly string[]) { for (const key of keys) controlWireText(record[key]); }
function time(value: unknown) { return parseCanonicalTime(controlWireText(value, 24)); }
function selfDigest(record: Record<string, unknown>, key: string) {
  controlWireRef(record[key]); if (record[key] !== digestOmitting(record, key)) throw new TypeError('child merge digest does not rehash');
}
function binding(record: Record<string, unknown>) {
  refs(record, BINDING_REFS); texts(record, ['runId', 'mergeBatchItemId', 'callId', 'childRunId', 'childResultItemId', 'sourceCheckpointId']);
  controlWireInteger(record.callIndex);
  if (record.runId === record.childRunId) throw new TypeError('child merge cannot select its own Run as a child');
}
function strings(value: unknown, maximum = 100_000): string[] {
  if (!Array.isArray(value) || value.length > maximum) throw new TypeError('child merge list exceeds its bound');
  for (const item of value) controlWireText(item); return value as string[];
}
function disposition(value: unknown): asserts value is PolicyDisposition {
  if (!['allow', 'ask', 'deny'].includes(String(value))) throw new TypeError('invalid child merge policy disposition');
}
function path(value: unknown): string {
  const result = controlWireText(value, 4096);
  if (result.includes('\\') || result.split('/').some(part => !part || part === '.' || part === '..' ||
    part.toLowerCase() === '.git' || Buffer.byteLength(part) > 255)) throw new TypeError('child merge path is not canonical');
  return result;
}
export function decodeChildMergeRequest(value: unknown): Readonly<ChildMergeRequestV1> {
  const record = data(value, [...CHILD_MERGE_BINDING_KEYS, 'schemaVersion', 'format', 'opId', 'assemblyRef', 'frontierRef', 'targetRef', 'targetDigest', 'requestDigest']);
  if (record.schemaVersion !== 1 || record.format !== 'cliq-child-merge-request-v1') throw new TypeError('invalid child merge request schema');
  binding(record); texts(record, ['opId']); refs(record, ['assemblyRef', 'frontierRef', 'targetRef', 'targetDigest']); selfDigest(record, 'requestDigest');
  if (record.opId !== childMergeOperationId(record as ChildMergeBindingV1)) throw new TypeError('child merge request has a different stable local identity');
  return immutableSnapshot(record) as ChildMergeRequestV1;
}
export function decodeChildMergeTarget(value: unknown): Readonly<ChildMergeTargetV1> {
  const record = data(value, [...CHILD_MERGE_BINDING_KEYS, 'schemaVersion', 'format', 'workspaceIdentityRef', 'workspaceIdentityDigest', 'changedPathsDigest', 'execution', 'targetDigest']);
  if (record.schemaVersion !== 1 || record.format !== 'cliq-child-merge-target-v1') throw new TypeError('invalid child merge target schema');
  binding(record); refs(record, ['workspaceIdentityRef', 'workspaceIdentityDigest', 'changedPathsDigest']);
  const execution = data(record.execution, ['kind', 'handlerId', 'supervisorEntryId', 'supervisorEntryVersion', 'supervisorExecutableDigest']);
  if (execution.kind !== 'supervisor_operation' || execution.handlerId !== 'child_merge') throw new TypeError('child merge requires its distinct Supervisor handler');
  texts(execution, ['supervisorEntryId', 'supervisorEntryVersion']); refs(execution, ['supervisorExecutableDigest']); selfDigest(record, 'targetDigest');
  return immutableSnapshot(record) as ChildMergeTargetV1;
}
export function decodeChildMergePolicyEvidence(value: unknown): Readonly<ChildMergePolicyEvidenceV1> {
  const record = data(value, ['schemaVersion', 'format', 'principalId', 'runId', 'policyRef', 'policyDigest', 'frontierRef', 'opId',
    'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'actionClass', 'channel', 'canonicalRootRelativePaths', 'pathDecisions',
    'matchedRuleIds', 'effectiveDisposition', 'evaluatedAt', 'evidenceDigest']);
  if (record.schemaVersion !== 1 || record.format !== 'cliq-policy-channel-evidence-v1' || record.actionClass !== 'write' || record.channel !== 'fs-write')
    throw new TypeError('child merge policy evidence uses a different channel');
  texts(record, ['principalId', 'runId', 'opId']); refs(record, ['policyRef', 'policyDigest', 'frontierRef', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest']);
  if (!Array.isArray(record.canonicalRootRelativePaths) || record.canonicalRootRelativePaths.length > 100_000 ||
      !Array.isArray(record.pathDecisions) || record.pathDecisions.length !== record.canonicalRootRelativePaths.length)
    throw new TypeError('child merge policy evidence does not cover its exact path set');
  let previous: string | undefined;
  const matched = new Set<string>();
  for (const [index, original] of record.canonicalRootRelativePaths.entries()) {
    const current = path(original);
    if (previous !== undefined && Buffer.compare(Buffer.from(previous), Buffer.from(current)) >= 0) throw new TypeError('child merge paths are not unique and byte-sorted');
    previous = current;
    const row = data(record.pathDecisions[index], ['path', 'decisionSource', 'matchedRuleIds', 'effectiveDisposition']);
    if (row.path !== current || !['rule', 'mode_fallthrough'].includes(String(row.decisionSource))) throw new TypeError('child merge path decision belongs to another path');
    const rules = strings(row.matchedRuleIds, 1);
    if (rules.length !== (row.decisionSource === 'rule' ? 1 : 0)) throw new TypeError('child merge path decision has inconsistent rule provenance');
    for (const id of rules) matched.add(id); disposition(row.effectiveDisposition);
  }
  const expectedRules = [...matched].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const rules = strings(record.matchedRuleIds, 256);
  if (rules.length !== expectedRules.length || rules.some((id, i) => id !== expectedRules[i])) throw new TypeError('child merge aggregate rule provenance differs');
  disposition(record.effectiveDisposition); time(record.evaluatedAt); selfDigest(record, 'evidenceDigest');
  if (record.pathDecisions.length) {
    const rank = { allow: 0, ask: 1, deny: 2 };
    let expected: PolicyDisposition = 'allow';
    for (const row of record.pathDecisions as ChildMergePolicyEvidenceV1['pathDecisions'])
      if (rank[row.effectiveDisposition] > rank[expected]) expected = row.effectiveDisposition;
    if (record.effectiveDisposition !== expected) throw new TypeError('child merge aggregate disposition drops a path refusal');
  }
  return immutableSnapshot(record) as ChildMergePolicyEvidenceV1;
}
function subject(value: unknown, wait = false) {
  const record = data(value, wait ? WAIT_SUBJECT_KEYS : SUBJECT_KEYS); binding(record);
  if (record.kind !== 'child_merge') throw new TypeError('merge authority has a different subject');
  refs(record, ['changedPathsDigest']);
  if (wait) { texts(record, ['opId']); refs(record, ['target', 'policyChannelEvidenceRef', 'policyChannelEvidenceDigest']); }
  return record;
}
export function decodeChildMergeGrant(value: unknown): Readonly<ChildMergeGrantV1> {
  const record = data(value, ['schemaVersion', 'format', 'grantId', 'principalId', 'runId', 'policyRef', 'frontierRef', 'opId', 'requestRef', 'requestDigest',
    'targetRef', 'targetDigest', 'subject', 'provenance', 'maxDispatchedAttempts', 'issuedAt', 'expiresAt', 'grantDigest']);
  if (record.schemaVersion !== 1 || record.format !== 'cliq-operation-grant-v1' || record.maxDispatchedAttempts !== 1) throw new TypeError('invalid child merge local grant');
  texts(record, ['grantId', 'principalId', 'runId', 'opId']); refs(record, ['policyRef', 'frontierRef', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest']);
  const selected = subject(record.subject); if (selected.runId !== record.runId) throw new TypeError('child merge grant belongs to another Run');
  const source = record.provenance as Record<string, unknown>;
  if (source?.kind === 'policy_snapshot') {
    data(source, ['kind', 'actionClass', 'channelEvidenceRef', 'channelEvidenceDigest', 'matchedRuleIds', 'effectiveDisposition', 'decisionDigest']);
    if (source.actionClass !== 'write' || source.effectiveDisposition !== 'allow') throw new TypeError('child merge policy grant is not an allow');
    refs(source, ['channelEvidenceRef', 'channelEvidenceDigest', 'decisionDigest']); strings(source.matchedRuleIds, 256);
  } else {
    const approved = data(source, ['kind', 'waitingSubjectRef', 'decisionRef', 'requestId', 'channelEvidenceRef', 'channelEvidenceDigest']);
    if (approved.kind !== 'user_approval') throw new TypeError('child merge cannot inherit another grant');
    refs(approved, ['waitingSubjectRef', 'decisionRef', 'channelEvidenceRef', 'channelEvidenceDigest']); texts(approved, ['requestId']); assertRequestId(approved.requestId as string);
  }
  if (time(record.issuedAt) >= time(record.expiresAt)) throw new TypeError('child merge grant has no original lifetime');
  selfDigest(record, 'grantDigest');
  if (record.grantId !== identityHash('cliq-operation-grant-v1', record.runId, record.opId, record.requestDigest, record.subject, record.issuedAt))
    throw new TypeError('child merge grant has a different stable identity');
  return immutableSnapshot(record) as ChildMergeGrantV1;
}
export function decodeChildMergeApprovalWait(value: unknown): Readonly<ChildMergeApprovalWait> {
  const record = data(value, ['schemaVersion', 'kind', 'runId', 'createdFromRevision', 'createdAt', 'frontierRef', 'subject']);
  if (record.schemaVersion !== 1 || record.kind !== 'approval') throw new TypeError('invalid child merge approval wait');
  texts(record, ['runId']); controlWireInteger(record.createdFromRevision, 1); time(record.createdAt); refs(record, ['frontierRef']);
  if (subject(record.subject, true).runId !== record.runId) throw new TypeError('child merge wait belongs to another Run');
  return immutableSnapshot(record) as ChildMergeApprovalWait;
}
export function decodeChildMergeApprovalDecision(value: unknown): Readonly<ChildMergeApprovalDecisionV1> {
  const record = data(value, ['schemaVersion', 'format', 'decisionId', 'principalId', 'channelIdentityRef', 'channelIdentityDigest', 'stateOwnerEpoch',
    'supervisorInstanceId', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'runId', 'waitingSubjectRef', 'waitingSubjectDigest', 'frontierRef', 'subject',
    'subjectDigest', 'requestId', 'requestDigest', 'expectedRunRevision', 'decision', 'createdAt', 'decisionDigest'], ['requestedTtlMs', 'grantExpiresAt']);
  if (record.schemaVersion !== 1 || record.format !== 'cliq-approval-decision-v1' || !['allow', 'deny'].includes(String(record.decision)))
    throw new TypeError('invalid child merge approval decision');
  texts(record, ['decisionId', 'principalId', 'supervisorInstanceId', 'runId', 'requestId']);
  refs(record, ['channelIdentityRef', 'channelIdentityDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'waitingSubjectRef', 'waitingSubjectDigest', 'frontierRef', 'subjectDigest', 'requestDigest']);
  controlWireInteger(record.stateOwnerEpoch, 1); controlWireInteger(record.expectedRunRevision, 1);
  if (record.requestedTtlMs !== undefined && controlWireInteger(record.requestedTtlMs, 1) > 86_400_000) throw new TypeError('child merge approval TTL exceeds its original contract');
  const selected = subject(record.subject, true);
  if (selected.runId !== record.runId || canonicalSha256(selected) !== record.subjectDigest || record.waitingSubjectRef !== record.waitingSubjectDigest) throw new TypeError('child merge approval belongs to another Run');
  // Subject ref/digest linkage is checked independently by the retained reader.
  time(record.createdAt); assertRequestId(record.requestId as string);
  if (record.decision === 'allow') { if (time(record.grantExpiresAt) <= time(record.createdAt)) throw new TypeError('child merge approval has no lifetime'); }
  else if (Object.hasOwn(record, 'grantExpiresAt')) throw new TypeError('denied child merge cannot contain an expiry');
  selfDigest(record, 'decisionDigest');
  if (record.decisionId !== identityHash(record.principalId, record.runId, record.waitingSubjectRef, record.requestId, record.requestDigest))
    throw new TypeError('child merge approval has a different stable identity');
  return immutableSnapshot(record) as ChildMergeApprovalDecisionV1;
}

export function decodeChildMergePolicyDecisionItem(value: unknown): Readonly<ChildMergePolicyDecisionItem> {
  const record = data(value, ['schemaVersion', 'kind', 'subjectKind', 'itemId', 'runId', 'opId', 'principalId', 'decisionRef',
    'policyChannelEvidenceRef', 'policyChannelEvidenceDigest', 'createdAt', 'decisionSource', 'decision'], ['waitingSubjectRef', 'grantRef']);
  if (record.schemaVersion !== 1 || record.kind !== 'policy_decision' || record.subjectKind !== 'child_merge' ||
      !['allow', 'deny'].includes(String(record.decision)) || !['direct_policy', 'interactive_approval'].includes(String(record.decisionSource)))
    throw new TypeError('invalid child merge policy decision item');
  texts(record, ['itemId', 'runId', 'opId', 'principalId']); refs(record, ['decisionRef', 'policyChannelEvidenceRef', 'policyChannelEvidenceDigest']);
  if (record.decisionSource === 'interactive_approval') refs(record, ['waitingSubjectRef']);
  else if (Object.hasOwn(record, 'waitingSubjectRef')) throw new TypeError('direct merge policy cannot impersonate approval');
  if (record.decision === 'allow') refs(record, ['grantRef']);
  else if (Object.hasOwn(record, 'grantRef')) throw new TypeError('denied child merge cannot carry a grant');
  time(record.createdAt); return immutableSnapshot(record) as ChildMergePolicyDecisionItem;
}
