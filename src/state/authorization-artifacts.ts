import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeVerifierIdentityCreateRequest as decodeCreateRequest, decodeAuthorizationRevokeRequest,
  UnsupportedExecutionIdentityRequestError } from '../kernel/control-wire.js';
export { decodeAuthorizationRevokeRequest } from '../kernel/control-wire.js';
import type { AuthorizationConsumptionReceiptV1, AuthorizationGrantBaseV1, AuthorizationGrantSummaryV1,
  AuthorizationGrantV1, AuthorizationRevokeRequest, VerifierIdentityCreateRequest } from '../kernel/authorization.js';
import { assertArtifactRef, assertRequestId, digestOmitting, identityHash, normalizeAbsolutePath, normalizeBoundedText, parseCanonicalTime } from '../kernel/identity.js';
import { KernelStorageError } from './errors.js';

/** Fixed refusal classification; neither a string nor an artifact supplies authority. */
export class VerifierAuthorizationError extends KernelStorageError {
  constructor(readonly refusalCode: 'AUTHORIZATION_REQUIRED' | 'UNSUPPORTED_EXECUTION_IDENTITY') {
    super('STATE_TRANSITION_INVALID', 'verifier identity authority is unavailable'); this.name = 'VerifierAuthorizationError';
  }
}
const plain = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' &&
  !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
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
    purpose: 'verifier', targetDigest: grant.targetDigest, useCount: grant.useCount, rowVersion: grant.rowVersion,
    createdAt: grant.createdAt, expiresAt: grant.expiresAt,
    ...(grant.state === 'consumed' ? { consumedAt: grant.consumedAt } : {}),
    ...(grant.state === 'revoked' ? { revokedAt: grant.revokedAt } : {}) };
}
export function decodeAuthorizationGrant(value: unknown): AuthorizationGrantV1 {
  if (!plain(value)) throw new TypeError('authorization grant is not a record');
  const state = value.state;
  exact(value, ['schemaVersion', 'grantId', 'ownerPrincipalId', 'channelIdentityRef', 'channelIdentityDigest',
    'sourceRequestId', 'sourceRequestDigest', 'target', 'targetDigest', 'maxUses', 'rowVersion', 'createdAt', 'expiresAt',
    'grantCoreDigest', 'state', 'useCount', 'rowDigest', ...(state === 'consumed' ? ['consumptionReceiptRef', 'consumedAt'] :
      state === 'revoked' ? ['revokedByRequestId', 'revokedAt'] : [])]);
  const target = exact(value.target, ['kind', 'purpose', 'identity']);
  if (target.kind !== 'execution_identity_read' || target.purpose !== 'verifier') throw new TypeError('unsupported retained authorization purpose');
  const identity = exact(target.identity, ['kind', 'guestToolchainManifestRef', 'manifestDigest', 'toolId', 'executionPath', 'executableDigest']);
  if (identity.kind !== 'guest_toolchain') throw new TypeError('unsupported retained verifier identity');
  for (const member of ['guestToolchainManifestRef', 'manifestDigest', 'executableDigest']) ref(identity[member]);
  text(identity.toolId);
  if (typeof identity.executionPath !== 'string' || normalizeAbsolutePath(identity.executionPath) !== identity.executionPath)
    throw new TypeError('verifier execution path is not canonical');
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
  const consumer = exact(data.consumer, ['kind', 'runId', 'admissionIntentDigest']);
  if (data.schemaVersion !== 1 || consumer.kind !== 'run_admission') throw new TypeError('unsupported authorization consumer');
  text(data.grantId); text(data.ownerPrincipalId); text(consumer.runId); ref(data.targetDigest); ref(consumer.admissionIntentDigest); ref(data.receiptDigest);
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
