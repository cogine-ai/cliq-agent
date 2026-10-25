import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeAuthorizationCreateRequest as decodeAnyCreateRequest, decodeVerifierIdentityCreateRequest as decodeCreateRequest, decodeAuthorizationRevokeRequest,
  UnsupportedExecutionIdentityRequestError } from '../kernel/control-wire.js';
export { decodeAuthorizationRevokeRequest } from '../kernel/control-wire.js';
import type { AuthorizationConsumptionReceiptV1, AuthorizationGrantBaseV1, AuthorizationGrantSummaryV1,
  AuthorizationGrantV1, AuthorizationRevokeRequest, VerifierIdentityCreateRequest } from '../kernel/authorization.js';
import type { AuthorizationCreateRequest, SourceGitInspectionTargetV1 } from '../kernel/authorization.js';
import { decodeSandboxResourceOptions } from '../kernel/control-submit.js';
import { assertArtifactRef, assertRequestId, digestOmitting, identityHash, normalizeAbsolutePath, normalizeBoundedText, parseCanonicalTime } from '../kernel/identity.js';
import { KernelStorageError } from './errors.js';
import { types } from 'node:util';
import { normalizeSourceReadScopePath } from '../kernel/source-read-scope.js';

/** Fixed refusal classification; neither a string nor an artifact supplies authority. */
export class VerifierAuthorizationError extends KernelStorageError {
  constructor(readonly refusalCode: 'AUTHORIZATION_REQUIRED' | 'UNSUPPORTED_EXECUTION_IDENTITY') {
    super('STATE_TRANSITION_INVALID', 'verifier identity authority is unavailable'); this.name = 'VerifierAuthorizationError';
  }
}
const plain = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' &&
  !types.isProxy(value) && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
  Reflect.ownKeys(value).every(key => typeof key === 'string' && (() => {
    const property = Object.getOwnPropertyDescriptor(value, key)!;
    return property.enumerable && Object.hasOwn(property, 'value');
  })());
function exact(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!plain(value) || Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field)))
    throw new TypeError('authorization has unknown or missing fields');
  return value;
}
function text(value: unknown): string {
  if (typeof value !== 'string' || normalizeBoundedText(value, 1, 128) !== value) throw new TypeError('authorization text is not canonical');
  return value;
}
function ref(value: unknown): string { if (typeof value !== 'string') throw new TypeError('authorization digest must be text'); assertArtifactRef(value); return value; }
export const authorizationGrantId = (principalId: string, requestId: string, requestDigest: string) =>
  identityHash('cliq-authorization-grant-v1', principalId, requestId, requestDigest);
export function authorizationGrantCore(grant: AuthorizationGrantV1): Omit<AuthorizationGrantBaseV1, 'rowVersion' | 'grantCoreDigest'> {
  const { schemaVersion, grantId, ownerPrincipalId, channelIdentityRef, channelIdentityDigest, sourceRequestId,
    sourceRequestDigest, target, targetDigest, maxUses, createdAt, expiresAt } = grant;
  return { schemaVersion, grantId, ownerPrincipalId, channelIdentityRef, channelIdentityDigest, sourceRequestId,
    sourceRequestDigest, target, targetDigest, maxUses, createdAt, expiresAt };
}
export function authorizationSummary(grant: AuthorizationGrantV1): AuthorizationGrantSummaryV1 {
  return { schemaVersion: 1, grantId: grant.grantId, state: grant.state, targetKind: grant.target.kind,
    purpose: grant.target.kind === 'source_git_inspection' ? 'source_inspection' : grant.target.kind === 'read_scope' ? 'source' : 'verifier', targetDigest: grant.targetDigest, useCount: grant.useCount, rowVersion: grant.rowVersion,
    createdAt: grant.createdAt, expiresAt: grant.expiresAt,
    ...(grant.state === 'consumed' ? { consumedAt: grant.consumedAt } : {}),
    ...(grant.state === 'revoked' ? { revokedAt: grant.revokedAt } : {}) };
}
export function decodeSourceGitInspectionTarget(value: unknown): SourceGitInspectionTargetV1 {
  const data = exact(value, ['kind', 'purpose', 'sessionId', 'workspaceIdentityRef', 'workspaceIdentityDigest',
    'repositoryIdentityRef', 'repositoryIdentityDigest', 'scope', 'recipe', 'retention', 'resourceCeiling', 'inspector']);
  if (data.kind !== 'source_git_inspection' || data.purpose !== 'source_inspection' ||
      data.scope !== 'in_root_git_metadata_and_objects' || data.recipe !== 'cliq-source-git-inspection-v1' ||
      data.retention !== 'ephemeral_raw_reachable_only') throw new TypeError('source inspection authorization has a foreign scope or retention');
  text(data.sessionId);
  for (const key of ['workspaceIdentityRef', 'workspaceIdentityDigest', 'repositoryIdentityRef', 'repositoryIdentityDigest']) ref(data[key]);
  const resources = decodeSandboxResourceOptions(data.resourceCeiling);
  exact(data.resourceCeiling, Object.keys(resources));
  const inspector = exact(data.inspector, ['runtimeBundleRef', 'runtimeBundleManifestDigest', 'entryId', 'entryVersion', 'entryDigest']);
  for (const key of ['runtimeBundleRef', 'runtimeBundleManifestDigest', 'entryDigest']) ref(inspector[key]);
  if (inspector.entryId !== 'source_git_inspector' || inspector.entryVersion !== '1') throw new TypeError('source inspector is not the fixed signed recipe');
  return data as SourceGitInspectionTargetV1;
}
export function decodeAuthorizationGrant(value: unknown): AuthorizationGrantV1 {
  if (!plain(value)) throw new TypeError('authorization grant is not a record');
  const state = value.state;
  exact(value, ['schemaVersion', 'grantId', 'ownerPrincipalId', 'channelIdentityRef', 'channelIdentityDigest',
    'sourceRequestId', 'sourceRequestDigest', 'target', 'targetDigest', 'maxUses', 'rowVersion', 'createdAt', 'expiresAt',
    'grantCoreDigest', 'state', 'useCount', 'rowDigest', ...(state === 'consumed' ? ['consumptionReceiptRef', 'consumedAt'] :
      state === 'revoked' ? ['revokedByRequestId', 'revokedAt'] : [])]);
  if (!plain(value.target)) throw new TypeError('unsupported retained authorization purpose');
  let target: AuthorizationGrantV1['target'];
  if (value.target.kind === 'source_git_inspection') target = decodeSourceGitInspectionTarget(value.target);
  else if (value.target.kind === 'read_scope') {
    const scope = exact(value.target, ['kind', 'purpose', 'workspaceIdentityDigest', 'canonicalRootRelativePath', 'scope',
      ...(Object.hasOwn(value.target, 'expectedDigest') ? ['expectedDigest'] : [])]);
    if (scope.purpose !== 'source') throw new TypeError('unsupported retained source read purpose');
    ref(scope.workspaceIdentityDigest); normalizeSourceReadScopePath(scope.canonicalRootRelativePath, scope.scope);
    if (Object.hasOwn(scope, 'expectedDigest')) ref(scope.expectedDigest);
    target = scope as AuthorizationGrantV1['target'];
  }
  else {
    const verifier = exact(value.target, ['kind', 'purpose', 'identity']);
    if (verifier.kind !== 'execution_identity_read' || verifier.purpose !== 'verifier') throw new TypeError('unsupported retained authorization purpose');
    const identity = exact(verifier.identity, ['kind', 'guestToolchainManifestRef', 'manifestDigest', 'toolId', 'executionPath', 'executableDigest']);
    if (identity.kind !== 'guest_toolchain') throw new TypeError('unsupported retained verifier identity');
    for (const member of ['guestToolchainManifestRef', 'manifestDigest', 'executableDigest']) ref(identity[member]);
    text(identity.toolId);
    if (typeof identity.executionPath !== 'string' || normalizeAbsolutePath(identity.executionPath) !== identity.executionPath)
      throw new TypeError('verifier execution path is not canonical');
    target = verifier as AuthorizationGrantV1['target'];
  }
  for (const member of ['grantId', 'ownerPrincipalId']) text(value[member]);
  if (typeof value.sourceRequestId !== 'string') throw new TypeError('authorization source request id is invalid');
  assertRequestId(value.sourceRequestId);
  for (const member of ['channelIdentityRef', 'channelIdentityDigest', 'sourceRequestDigest', 'targetDigest', 'grantCoreDigest', 'rowDigest']) ref(value[member]);
  const start = parseCanonicalTime(value.createdAt as string), expiry = parseCanonicalTime(value.expiresAt as string);
  if (value.schemaVersion !== 1 || value.maxUses !== 1 || !['active', 'consumed', 'revoked'].includes(state as string) ||
      value.rowVersion !== (state === 'active' ? 1 : 2) || value.useCount !== (state === 'consumed' ? 1 : 0) ||
      expiry <= start || expiry - start > 86_400_000 || value.targetDigest !== canonicalSha256(target)) throw new TypeError('authorization grant has an invalid closed lifecycle');
  if (state === 'consumed') { ref(value.consumptionReceiptRef); if (parseCanonicalTime(value.consumedAt as string) < start ||
      (value.consumedAt as string) >= (value.expiresAt as string)) throw new TypeError('authorization consumption is outside its lifetime'); }
  if (state === 'revoked') { assertRequestId(value.revokedByRequestId as string); if (parseCanonicalTime(value.revokedAt as string) < start) throw new TypeError('authorization revocation precedes creation'); }
  const grant = value as AuthorizationGrantV1;
  if (grant.grantId !== authorizationGrantId(grant.ownerPrincipalId, grant.sourceRequestId, grant.sourceRequestDigest) ||
      grant.grantCoreDigest !== canonicalSha256(authorizationGrantCore(grant)) || grant.rowDigest !== digestOmitting(grant, 'rowDigest'))
    throw new TypeError('authorization grant identity or digest does not rehash');
  return grant;
}
export function decodeAuthorizationConsumptionReceipt(value: unknown): AuthorizationConsumptionReceiptV1 {
  const data = exact(value, ['schemaVersion', 'grantId', 'ownerPrincipalId', 'targetDigest', 'consumer', 'consumedAt', 'receiptDigest']);
  if (!plain(data.consumer)) throw new TypeError('unsupported authorization consumer');
  const source = data.consumer.kind === 'source_inspection';
  const consumer = exact(data.consumer, ['kind', source ? 'inspectionId' : 'runId', 'admissionIntentDigest']);
  if (data.schemaVersion !== 1 || consumer.kind !== (source ? 'source_inspection' : 'run_admission')) throw new TypeError('unsupported authorization consumer');
  text(data.grantId); text(data.ownerPrincipalId); text(consumer[source ? 'inspectionId' : 'runId']); ref(data.targetDigest); ref(consumer.admissionIntentDigest); ref(data.receiptDigest);
  parseCanonicalTime(data.consumedAt as string);
  if (data.receiptDigest !== digestOmitting(data, 'receiptDigest')) throw new TypeError('authorization receipt digest does not rehash');
  return data as AuthorizationConsumptionReceiptV1;
}
export function decodeVerifierIdentityCreateRequest(value: unknown): VerifierIdentityCreateRequest {
  try { return decodeCreateRequest(value); }
  catch (error) {
    if (error instanceof UnsupportedExecutionIdentityRequestError) throw new VerifierAuthorizationError('UNSUPPORTED_EXECUTION_IDENTITY');
    throw error;
  }
}
export function decodeAuthorizationCreateRequest(value: unknown): AuthorizationCreateRequest {
  try { return decodeAnyCreateRequest(value); }
  catch (error) {
    if (error instanceof UnsupportedExecutionIdentityRequestError) throw new VerifierAuthorizationError('UNSUPPORTED_EXECUTION_IDENTITY');
    throw error;
  }
}
