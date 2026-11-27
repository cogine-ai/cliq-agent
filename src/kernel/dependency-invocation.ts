import { canonicalJsonBytes } from './canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { decodeDependencyScriptConditions, type DependencyScriptConditionsV1 } from './dependency.js';
import { digestOmitting, parseCanonicalTime } from './identity.js';
import type { ArtifactRef } from './types.js';

/** Closed data for one whole acquisition. HTTP retries are children of this
 * operation, never new Journal claims or new lifecycle-script permission. */
export type DependencyRequestV1 = {
  schemaVersion: 1; format: 'cliq-dependency-request-v1'; runId: string; opId: string;
  frontierRef: ArtifactRef; assemblyRef: ArtifactRef; candidateItemId: string;
  resultSourceRef: ArtifactRef; dependencyPlanRef: ArtifactRef; dependencyPlanDigest: string;
  targetRef: ArtifactRef; targetDigest: string; requestDigest: string;
};
export type DependencyTargetV1 = {
  schemaVersion: 1; format: 'cliq-dependency-target-v1'; runId: string; candidateItemId: string;
  workspaceIdentityRef: ArtifactRef; workspaceIdentityDigest: string; resultSourceRef: ArtifactRef; sourceDigest: string;
  dependencyPlanRef: ArtifactRef; dependencyPlanDigest: string; scriptConditions: DependencyScriptConditionsV1;
  allowInstallScripts: boolean; scriptAuthorizationTemplateRef?: ArtifactRef;
  targetDigest: string;
};
export type DependencyOperationGrantV1 = {
  schemaVersion: 1; format: 'cliq-operation-grant-v1'; grantId: string; principalId: string; runId: string;
  policyRef: ArtifactRef; frontierRef: ArtifactRef; opId: string;
  requestRef: ArtifactRef; requestDigest: string; targetRef: ArtifactRef; targetDigest: string;
  subject: { kind: 'dependency_acquisition'; dependencyPlanRef: ArtifactRef; lockfileDigest: string;
    resultSourceRef: ArtifactRef; installScripts: boolean };
  provenance: { kind: 'dependency_policy'; dependencyPolicyRef: ArtifactRef; dependencyPolicyDigest: string } |
    { kind: 'dependency_install_scripts_template'; dependencyPolicyRef: ArtifactRef; templateRef: ArtifactRef; candidateOrdinal: number };
  maxDispatchedAttempts: 1 | 2; issuedAt: string; expiresAt: string; grantDigest: string;
};

function bounded(value: unknown): void {
  assertControlWireJson(value);
  let nodes = 0;
  const count = (item: unknown) => {
    if (++nodes > 10_000) throw new TypeError('dependency invocation exceeds its original JSON node bound');
    if (item && typeof item === 'object') for (const child of Object.values(item)) count(child);
  };
  count(value);
  if (canonicalJsonBytes(value).length > 1_048_576) throw new TypeError('dependency invocation exceeds its original JSON byte bound');
}
function header(value: unknown, fields: string[], format: string, optional: string[] = []): Record<string, unknown> {
  bounded(value); const data = controlWireRecord(value, ['schemaVersion', 'format', ...fields], optional);
  if (data.schemaVersion !== 1 || data.format !== format) throw new TypeError('dependency invocation has another purpose');
  return data;
}
function refs(data: Record<string, unknown>, keys: string[]): void { for (const key of keys) controlWireRef(data[key]); }
function texts(data: Record<string, unknown>, keys: string[]): void { for (const key of keys) controlWireText(data[key]); }
function hash(data: Record<string, unknown>, field: string): void {
  controlWireRef(data[field]);
  if (data[field] !== digestOmitting(data, field)) throw new TypeError('dependency invocation digest differs');
}
function scripts(data: Record<string, unknown>): void {
  if (typeof data.allowInstallScripts !== 'boolean' || data.allowInstallScripts !== Object.hasOwn(data, 'scriptAuthorizationTemplateRef'))
    throw new TypeError('dependency scripts require their exact explicit template or no template');
  if (data.allowInstallScripts) controlWireRef(data.scriptAuthorizationTemplateRef);
}
export function decodeDependencyRequest(value: unknown): DependencyRequestV1 {
  const data = header(value, ['runId', 'opId', 'frontierRef', 'assemblyRef', 'candidateItemId', 'resultSourceRef',
    'dependencyPlanRef', 'dependencyPlanDigest', 'targetRef', 'targetDigest', 'requestDigest'], 'cliq-dependency-request-v1');
  texts(data, ['runId', 'opId', 'candidateItemId']);
  refs(data, ['frontierRef', 'assemblyRef', 'resultSourceRef', 'dependencyPlanRef', 'dependencyPlanDigest', 'targetRef', 'targetDigest']);
  hash(data, 'requestDigest'); return data as DependencyRequestV1;
}
export function decodeDependencyTarget(value: unknown): DependencyTargetV1 {
  const data = header(value, ['runId', 'candidateItemId', 'workspaceIdentityRef', 'workspaceIdentityDigest', 'resultSourceRef',
    'sourceDigest', 'dependencyPlanRef', 'dependencyPlanDigest', 'scriptConditions', 'allowInstallScripts', 'targetDigest'],
  'cliq-dependency-target-v1', ['scriptAuthorizationTemplateRef']);
  texts(data, ['runId', 'candidateItemId']); refs(data, ['workspaceIdentityRef', 'workspaceIdentityDigest', 'resultSourceRef',
    'sourceDigest', 'dependencyPlanRef', 'dependencyPlanDigest']);
  const conditions = decodeDependencyScriptConditions(data.scriptConditions); scripts(data);
  if (conditions.source.sourceManifestRef !== data.resultSourceRef || conditions.source.sourceManifestDigest !== data.sourceDigest ||
      conditions.source.sourceRole !== 'result') throw new TypeError('dependency target substitutes its actual candidate source');
  hash(data, 'targetDigest'); return data as DependencyTargetV1;
}
export function decodeDependencyOperationGrant(value: unknown): DependencyOperationGrantV1 {
  const data = header(value, ['grantId', 'principalId', 'runId', 'policyRef', 'frontierRef', 'opId', 'requestRef', 'requestDigest',
    'targetRef', 'targetDigest', 'subject', 'provenance', 'maxDispatchedAttempts', 'issuedAt', 'expiresAt', 'grantDigest'], 'cliq-operation-grant-v1');
  texts(data, ['grantId', 'principalId', 'runId', 'opId']); refs(data, ['policyRef', 'frontierRef', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest']);
  const subject = controlWireRecord(data.subject, ['kind', 'dependencyPlanRef', 'lockfileDigest', 'resultSourceRef', 'installScripts']);
  if (subject.kind !== 'dependency_acquisition' || typeof subject.installScripts !== 'boolean' ||
      data.maxDispatchedAttempts !== (subject.installScripts ? 1 : 2)) throw new TypeError('dependency grant has another subject or dispatch count');
  refs(subject, ['resultSourceRef', 'dependencyPlanRef', 'lockfileDigest']);
  if (subject.installScripts) {
    const provenance = controlWireRecord(data.provenance, ['kind', 'dependencyPolicyRef', 'templateRef', 'candidateOrdinal']);
    if (provenance.kind !== 'dependency_install_scripts_template') throw new TypeError('dependency scripts require their explicit exact template');
    refs(provenance, ['dependencyPolicyRef', 'templateRef']); controlWireInteger(provenance.candidateOrdinal);
  } else {
    const provenance = controlWireRecord(data.provenance, ['kind', 'dependencyPolicyRef', 'dependencyPolicyDigest']);
    if (provenance.kind !== 'dependency_policy') throw new TypeError('dependency grant cannot borrow another permission purpose');
    refs(provenance, ['dependencyPolicyRef', 'dependencyPolicyDigest']);
  }
  const issuedAt = controlWireText(data.issuedAt), expiresAt = controlWireText(data.expiresAt);
  if (parseCanonicalTime(issuedAt) >= parseCanonicalTime(expiresAt)) throw new TypeError('dependency grant is not within its original lifetime');
  hash(data, 'grantDigest'); return data as DependencyOperationGrantV1;
}
