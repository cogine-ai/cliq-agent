import { domainToASCII } from 'node:url';
import { canonicalSha256, normalizeCanonicalText } from './canonical.js';
import { assertArtifactRef, assertRequestId, digestOmitting, identityHash, parseCanonicalTime } from './identity.js';
import type { ArtifactRef } from './types.js';

export type CredentialPurpose = 'model_endpoint' | 'dependency_registry' | 'mcp_streamable_http';

export type EndpointRegistrationV1 = {
  schemaVersion: 1; format: 'cliq-endpoint-registration-v1'; endpointRegistrationId: string;
  registrationKind: 'bundled_default' | 'user'; ownerPrincipalId: string; purposes: CredentialPurpose[];
  target: { scheme: 'https'; hostAscii: string; port: number; basePath: string; redirectPolicy: 'reject_all' };
  tls: { serverNameAscii: string; minimumVersion: 'TLSv1.3'; trustStoreRuntimeBundleRef: ArtifactRef;
    trustStoreRuntimeBundleManifestDigest: string; trustStoreEntryId: 'default_https_trust_store';
    trustStoreRef: ArtifactRef; trustStoreDigest: string; spkiSha256Pins: string[] };
  endpointIdentityDigest: string; tlsPolicyDigest: string; createdAt: string; registrationDigest: string;
};

type EndpointAuthorityRecordBaseV1 = {
  schemaVersion: 1; endpointRegistrationId: string; authorityRevision: number; ownerPrincipalId: string;
  sourceRequestId: string; sourceRequestDigest: string; registration: EndpointRegistrationV1;
  expectedRegistrationArtifactRef: ArtifactRef; createdAt: string;
};
export type EndpointAuthorityRecordV1 = EndpointAuthorityRecordBaseV1 & (
  | { state: 'active'; revokedAt?: never; revokedByRequestId?: never; revokedByRequestDigest?: never; recordDigest: string }
  | { state: 'revoked'; revokedAt: string; revokedByRequestId: string; revokedByRequestDigest: string; recordDigest: string }
);
export type EndpointAuthorityCommandCoreV1 =
  | { schemaVersion: 1; kind: 'register'; ownerPrincipalId: string; registration: EndpointRegistrationV1;
      expectedRegistrationArtifactRef: ArtifactRef; commandDigest: string }
  | { schemaVersion: 1; kind: 'revoke'; ownerPrincipalId: string; endpointRegistrationId: string;
      expectedAuthorityRevision: number; commandDigest: string };
export type EndpointAuthorityOperationV1 = {
  schemaVersion: 1; operationId: string; requestId: string; requestDigest: string;
  channelIdentityRef: ArtifactRef; channelIdentityDigest: string; commandCore: EndpointAuthorityCommandCoreV1;
  ownerPrincipalId: string; kind: 'register' | 'revoke'; endpointRegistrationId: string;
  disposition: 'registered' | 'already_registered' | 'revoked' | 'already_revoked';
  committedAuthorityRevision: number; resultRecordDigest: string; committedAt: string; operationDigest: string;
};

export type CredentialExternalSubjectV1 = {
  schemaVersion: 1; format: 'cliq-credential-external-subject-v1'; endpointIdentityDigest: string;
  subject:
    | { kind: 'provider_verified'; providerNamespace: string; accountSubjectDigest: string; scopes: string[]; audiences: string[] }
    | { kind: 'opaque_generation'; opaqueSubjectId: string; scopes: ['endpoint_exact_only']; audiences: [] };
  observedAt: string; subjectDigest: string;
};
export type EndpointCredentialGrantBinding = {
  schemaVersion: 1; credentialGrantId: string; authorityRevision: number; credentialServiceRevision: number;
  ownerPrincipalId: string; credentialHandleIdentityDigest: string; secretGeneration: number;
  externalSubject: CredentialExternalSubjectV1; externalSubjectDigest: string; purpose: CredentialPurpose;
  endpointRegistrationRef: ArtifactRef; endpointIdentityDigest: string; tlsPolicyDigest: string;
  createdAt: string; expiresAt?: string; bindingDigest: string;
};
type CredentialAuthorityRecordBaseV1 = {
  schemaVersion: 1; credentialGrantId: string; authorityRevision: number; credentialServiceRevision: number;
  ownerPrincipalId: string; purpose: CredentialPurpose; endpointRegistrationRef: ArtifactRef;
  endpointIdentityDigest: string; tlsPolicyDigest: string; credentialHandleIdentityDigest: string;
  secretGeneration: number; externalSubject: CredentialExternalSubjectV1; externalSubjectDigest: string;
  platformItem:
    | { kind: 'macos_keychain'; service: 'ai.cogine.cliq.credentials.v1'; accountId: string }
    | { kind: 'linux_secret_service'; schema: 'org.freedesktop.Secret.Generic'; collection: 'default'; itemId: string };
  createdAt: string; expiresAt?: string;
};
export type CredentialAuthorityRecordV1 = CredentialAuthorityRecordBaseV1 & (
  | { state: 'active'; revokedAt?: never; revokedByRequestId?: never; revokedByRequestDigest?: never; recordDigest: string }
  | { state: 'revoked'; revokedAt: string; revokedByRequestId: string; revokedByRequestDigest: string; recordDigest: string }
);

export type CredentialAuthorityCommandCoreV1 = {
  schemaVersion: 1; ownerPrincipalId: string; kind: 'enroll' | 'rotate'; credentialGrantId: string;
  purpose: CredentialPurpose; endpointRegistrationRef: ArtifactRef; endpointIdentityDigest: string; tlsPolicyDigest: string;
  expiresAt?: string; secretSubmissionId: string; externalSubject: CredentialExternalSubjectV1;
  externalSubjectDigest: string; credentialTargetDigest: string; commandDigest: string;
};
type CredentialAuthorityOperationBaseV1 = {
  schemaVersion: 1; operationId: string; requestId: string; requestDigest: string;
  channelIdentityRef: ArtifactRef; channelIdentityDigest: string; commandCore: CredentialAuthorityCommandCoreV1;
  attempt: 1 | 2 | 3; ownerPrincipalId: string; kind: 'enroll' | 'rotate'; credentialGrantId: string;
  credentialTargetDigest: string; intendedAuthorityRevision: number; intendedSecretGeneration: number;
  intendedExternalSubjectDigest: string; platformItem: CredentialAuthorityRecordBaseV1['platformItem'];
  createdAt: string; operationDigest: string;
};
export type CredentialAuthorityOperationV1 = CredentialAuthorityOperationBaseV1 & (
  | { phase: 'prepared' | 'secret_stored'; committedAuthorityRevision?: never; abortReason?: never; finishedAt?: never }
  | { phase: 'committed'; committedAuthorityRevision: number; abortReason?: never; finishedAt: string }
  | { phase: 'aborted'; committedAuthorityRevision?: never; abortReason: 'recovered_orphan' | 'platform_store_failed' | 'request_conflict'; finishedAt: string }
);

export type CredentialAuthorityRevokeCommandCoreV1 = {
  schemaVersion: 1; kind: 'revoke'; ownerPrincipalId: string; credentialGrantId: string;
  expectedAuthorityRevision: number; credentialTargetDigest: string; commandDigest: string;
};
type CredentialAuthorityRevokeOperationBaseV1 = {
  schemaVersion: 1; operationId: string; requestId: string; requestDigest: string;
  channelIdentityRef: ArtifactRef; channelIdentityDigest: string; commandCore: CredentialAuthorityRevokeCommandCoreV1;
  ownerPrincipalId: string; credentialGrantId: string; credentialTargetDigest: string; disposition: 'revoked' | 'already_revoked';
  committedAuthorityRevision: number; revokedRecordDigest: string; platformItem: CredentialAuthorityRecordBaseV1['platformItem'];
  metadataCommittedAt: string; operationDigest: string;
};
export type CredentialAuthorityRevokeOperationV1 = CredentialAuthorityRevokeOperationBaseV1 & (
  | { cleanupPhase: 'metadata_committed'; cleanupEvidenceDigest?: never; cleanupErrorCode?: never; cleanupFinishedAt?: never }
  | { cleanupPhase: 'cleanup_complete'; cleanupEvidenceDigest: string; cleanupErrorCode?: never; cleanupFinishedAt: string }
  | { cleanupPhase: 'cleanup_failed'; cleanupEvidenceDigest: string;
      cleanupErrorCode: 'platform_store_unavailable' | 'delete_denied' | 'delete_failed'; cleanupFinishedAt: string }
);

function closed(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError('authority object must be a plain object');
  const object = value as Record<string, unknown>;
  if (required.some(key => !Object.hasOwn(object, key)) ||
      Reflect.ownKeys(object).some(key => typeof key !== 'string' || ![...required, ...optional].includes(key)))
    throw new TypeError('authority object has missing or unknown fields');
  if (required.includes('schemaVersion') && object.schemaVersion !== 1) throw new TypeError('authority schemaVersion must be 1');
  return object;
}

function selfDigest(value: Record<string, unknown>, field: string): void {
  if (digestOmitting(value, field) !== value[field]) throw new TypeError(`authority ${field} does not rehash`);
}

function text(value: unknown): string {
  if (typeof value !== 'string' || !value || normalizeCanonicalText(value) !== value)
    throw new TypeError('authority text must be nonempty canonical NFC');
  return value;
}
function digest(value: unknown): string {
  const result = text(value);
  try { assertArtifactRef(result); }
  catch { throw new TypeError('authority digest must be canonical SHA-256'); }
  return result;
}
function time(value: unknown): string {
  const result = text(value);
  try { parseCanonicalTime(result); }
  catch { throw new TypeError('authority time must be a canonical UTC millisecond'); }
  return result;
}
function request(value: unknown): string { const result = text(value); assertRequestId(result); return result; }
function integer(value: unknown, minimum = 1, maximum = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new TypeError('authority integer is outside its canonical range');
  return value;
}
function purpose(value: unknown): CredentialPurpose {
  if (value !== 'model_endpoint' && value !== 'dependency_registry' && value !== 'mcp_streamable_http')
    throw new TypeError('credential purpose is invalid');
  return value;
}
function sorted(value: unknown, validate: (entry: unknown) => string, allowEmpty = false): void {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) throw new TypeError('authority list is invalid');
  let previous: string | undefined;
  for (const entry of value) {
    const current = validate(entry);
    if (previous !== undefined && Buffer.compare(Buffer.from(previous), Buffer.from(current)) >= 0)
      throw new TypeError('authority list must be unique and byte-sorted');
    previous = current;
  }
}
function host(value: unknown): void {
  const result = text(value);
  if (result !== result.toLowerCase() || domainToASCII(result) !== result || result.length > 253 ||
      result.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label)))
    throw new TypeError('endpoint host must be normalized lower-case IDNA ASCII');
}
function basePath(value: unknown): void {
  const result = text(value);
  if (!result.startsWith('/') || /[?#\\]/u.test(result) || /%(?:2f|5c)/iu.test(result) ||
      new URL(result, 'https://endpoint.invalid').pathname !== result)
    throw new TypeError('endpoint base path is not normalized');
  for (const segment of result.split('/')) {
    let decoded: string;
    try { decoded = decodeURIComponent(segment); }
    catch { throw new TypeError('endpoint base path contains invalid escaping'); }
    if (decoded === '.' || decoded === '..' || normalizeCanonicalText(decoded) !== decoded)
      throw new TypeError('endpoint base path contains a forbidden segment');
  }
}

/** Shape and embedded hash domains only; never proof of registration or a signed trust store. */
export function decodeEndpointRegistration(value: unknown): EndpointRegistrationV1 {
  const object = closed(value, ['schemaVersion', 'format', 'endpointRegistrationId', 'registrationKind', 'ownerPrincipalId',
    'purposes', 'target', 'tls', 'endpointIdentityDigest', 'tlsPolicyDigest', 'createdAt', 'registrationDigest']);
  if (object.format !== 'cliq-endpoint-registration-v1') throw new TypeError('endpoint registration format is invalid');
  text(object.endpointRegistrationId); text(object.ownerPrincipalId); time(object.createdAt);
  if (object.registrationKind !== 'bundled_default' && object.registrationKind !== 'user') throw new TypeError('endpoint registration kind is invalid');
  sorted(object.purposes, purpose);
  const target = closed(object.target, ['scheme', 'hostAscii', 'port', 'basePath', 'redirectPolicy']);
  if (target.scheme !== 'https' || target.redirectPolicy !== 'reject_all') throw new TypeError('endpoint target policy is invalid');
  host(target.hostAscii); integer(target.port, 1, 65535); basePath(target.basePath);
  const tls = closed(object.tls, ['serverNameAscii', 'minimumVersion', 'trustStoreRuntimeBundleRef', 'trustStoreRuntimeBundleManifestDigest',
    'trustStoreEntryId', 'trustStoreRef', 'trustStoreDigest', 'spkiSha256Pins']);
  if (tls.minimumVersion !== 'TLSv1.3' || tls.trustStoreEntryId !== 'default_https_trust_store') throw new TypeError('endpoint TLS policy is invalid');
  host(tls.serverNameAscii);
  for (const field of ['trustStoreRuntimeBundleRef', 'trustStoreRuntimeBundleManifestDigest', 'trustStoreRef', 'trustStoreDigest']) digest(tls[field]);
  if (tls.trustStoreRef !== tls.trustStoreDigest) throw new TypeError('endpoint trust-store content ref and digest differ');
  sorted(tls.spkiSha256Pins, digest);
  if (canonicalSha256(object.tls) !== object.tlsPolicyDigest) throw new TypeError('endpoint TLS policy digest does not rehash');
  if (canonicalSha256({ target: object.target, tlsPolicyDigest: object.tlsPolicyDigest }) !== object.endpointIdentityDigest)
    throw new TypeError('endpoint identity digest does not rehash');
  selfDigest(object, 'registrationDigest');
  return object as EndpointRegistrationV1;
}

function revocation(object: Record<string, unknown>): void {
  const keys = ['revokedAt', 'revokedByRequestId', 'revokedByRequestDigest'];
  if (object.state === 'active') {
    if (keys.some(key => Object.hasOwn(object, key))) throw new TypeError('active authority cannot contain revocation fields');
  } else if (object.state === 'revoked') {
    time(object.revokedAt); request(object.revokedByRequestId); digest(object.revokedByRequestDigest);
  } else throw new TypeError('authority record state is invalid');
}

export function decodeEndpointAuthorityRecord(value: unknown): EndpointAuthorityRecordV1 {
  const object = closed(value, ['schemaVersion', 'endpointRegistrationId', 'authorityRevision', 'ownerPrincipalId',
    'sourceRequestId', 'sourceRequestDigest', 'registration', 'expectedRegistrationArtifactRef', 'createdAt', 'state', 'recordDigest'],
  ['revokedAt', 'revokedByRequestId', 'revokedByRequestDigest']);
  const registration = decodeEndpointRegistration(object.registration);
  if (object.endpointRegistrationId !== registration.endpointRegistrationId || object.ownerPrincipalId !== registration.ownerPrincipalId ||
      object.expectedRegistrationArtifactRef !== canonicalSha256(registration)) throw new TypeError('endpoint record does not bind its inline registration');
  integer(object.authorityRevision); request(object.sourceRequestId); digest(object.sourceRequestDigest); time(object.createdAt);
  revocation(object); selfDigest(object, 'recordDigest');
  return object as EndpointAuthorityRecordV1;
}

export function decodeEndpointAuthorityCommandCore(value: unknown): EndpointAuthorityCommandCoreV1 {
  const common = ['schemaVersion', 'kind', 'ownerPrincipalId', 'commandDigest'];
  const object = closed(value, common, ['registration', 'expectedRegistrationArtifactRef', 'endpointRegistrationId', 'expectedAuthorityRevision']);
  text(object.ownerPrincipalId);
  if (object.kind === 'register') {
    closed(object, [...common, 'registration', 'expectedRegistrationArtifactRef']);
    const registration = decodeEndpointRegistration(object.registration);
    if (object.ownerPrincipalId !== registration.ownerPrincipalId || object.expectedRegistrationArtifactRef !== canonicalSha256(registration))
      throw new TypeError('endpoint command does not bind its inline registration');
  } else if (object.kind === 'revoke') {
    closed(object, [...common, 'endpointRegistrationId', 'expectedAuthorityRevision']);
    text(object.endpointRegistrationId); integer(object.expectedAuthorityRevision);
  } else throw new TypeError('endpoint command kind is invalid');
  selfDigest(object, 'commandDigest');
  return object as EndpointAuthorityCommandCoreV1;
}

/** Decoding retained provenance does not authenticate the current caller or resolve a result row. */
export function decodeEndpointAuthorityOperation(value: unknown): EndpointAuthorityOperationV1 {
  const object = closed(value, ['schemaVersion', 'operationId', 'requestId', 'requestDigest', 'channelIdentityRef', 'channelIdentityDigest',
    'commandCore', 'ownerPrincipalId', 'kind', 'endpointRegistrationId', 'disposition', 'committedAuthorityRevision',
    'resultRecordDigest', 'committedAt', 'operationDigest']);
  const core = decodeEndpointAuthorityCommandCore(object.commandCore);
  const endpointId = core.kind === 'register' ? core.registration.endpointRegistrationId : core.endpointRegistrationId;
  request(object.requestId); digest(object.channelIdentityRef); digest(object.channelIdentityDigest);
  if (object.ownerPrincipalId !== core.ownerPrincipalId || object.kind !== core.kind || object.endpointRegistrationId !== endpointId ||
      object.requestDigest !== core.commandDigest || object.operationId !== identityHash(core.ownerPrincipalId, object.requestId, core.commandDigest))
    throw new TypeError('endpoint operation does not repeat its command identity');
  if (core.kind === 'register'
    ? object.disposition !== 'registered' && object.disposition !== 'already_registered'
    : object.disposition !== 'revoked' && object.disposition !== 'already_revoked')
    throw new TypeError('endpoint operation disposition is invalid');
  integer(object.committedAuthorityRevision); digest(object.resultRecordDigest); time(object.committedAt); selfDigest(object, 'operationDigest');
  return object as EndpointAuthorityOperationV1;
}

export function decodeCredentialExternalSubject(value: unknown): CredentialExternalSubjectV1 {
  const object = closed(value, ['schemaVersion', 'format', 'endpointIdentityDigest', 'subject', 'observedAt', 'subjectDigest']);
  if (object.format !== 'cliq-credential-external-subject-v1') throw new TypeError('credential subject format is invalid');
  digest(object.endpointIdentityDigest); time(object.observedAt);
  const subject = closed(object.subject, ['kind', 'scopes', 'audiences'], ['providerNamespace', 'accountSubjectDigest', 'opaqueSubjectId']);
  if (subject.kind === 'provider_verified') {
    closed(subject, ['kind', 'providerNamespace', 'accountSubjectDigest', 'scopes', 'audiences']);
    text(subject.providerNamespace); digest(subject.accountSubjectDigest);
    sorted(subject.scopes, text, true); sorted(subject.audiences, text, true);
  } else if (subject.kind === 'opaque_generation') {
    closed(subject, ['kind', 'opaqueSubjectId', 'scopes', 'audiences']);
    // The RFC leaves the 256-bit identifier encoding to its actual producer.
    text(subject.opaqueSubjectId);
    if (!Array.isArray(subject.scopes) || subject.scopes.length !== 1 || subject.scopes[0] !== 'endpoint_exact_only' ||
        !Array.isArray(subject.audiences) || subject.audiences.length !== 0) throw new TypeError('opaque credential subject scope is invalid');
  } else throw new TypeError('credential subject kind is invalid');
  selfDigest(object, 'subjectDigest');
  return object as CredentialExternalSubjectV1;
}

const credentialTargetFields = ['credentialGrantId', 'ownerPrincipalId', 'purpose', 'endpointRegistrationRef', 'endpointIdentityDigest', 'tlsPolicyDigest'];
const credentialSubjectFields = ['externalSubject', 'externalSubjectDigest'];

function credentialTarget(object: Record<string, unknown>): void {
  text(object.credentialGrantId); text(object.ownerPrincipalId); purpose(object.purpose);
  digest(object.endpointRegistrationRef); digest(object.endpointIdentityDigest); digest(object.tlsPolicyDigest);
  if (Object.hasOwn(object, 'expiresAt')) time(object.expiresAt);
  const subject = decodeCredentialExternalSubject(object.externalSubject);
  if (subject.endpointIdentityDigest !== object.endpointIdentityDigest || subject.subjectDigest !== object.externalSubjectDigest)
    throw new TypeError('credential target does not bind its inline external subject');
}

function credentialHandle(object: Record<string, unknown>): void {
  integer(object.authorityRevision); integer(object.credentialServiceRevision); integer(object.secretGeneration);
  const expected = canonicalSha256({ ownerPrincipalId: object.ownerPrincipalId, credentialGrantId: object.credentialGrantId,
    credentialServiceRevision: object.credentialServiceRevision, purpose: object.purpose,
    endpointRegistrationRef: object.endpointRegistrationRef, endpointIdentityDigest: object.endpointIdentityDigest, tlsPolicyDigest: object.tlsPolicyDigest });
  if (object.credentialHandleIdentityDigest !== expected) throw new TypeError('credential handle identity digest does not rehash');
}

function platformItem(value: unknown): void {
  const object = closed(value, ['kind'], ['service', 'accountId', 'schema', 'collection', 'itemId']);
  if (object.kind === 'macos_keychain') {
    closed(object, ['kind', 'service', 'accountId']);
    if (object.service !== 'ai.cogine.cliq.credentials.v1') throw new TypeError('Keychain credential service is invalid');
    text(object.accountId);
  } else if (object.kind === 'linux_secret_service') {
    closed(object, ['kind', 'schema', 'collection', 'itemId']);
    if (object.schema !== 'org.freedesktop.Secret.Generic' || object.collection !== 'default') throw new TypeError('Secret Service credential target is invalid');
    text(object.itemId);
  } else throw new TypeError('credential platform item kind is invalid');
}

/** An immutable binding is a model, not latest-revision validation or a redemption capability. */
export function decodeEndpointCredentialGrantBinding(value: unknown): EndpointCredentialGrantBinding {
  const object = closed(value, ['schemaVersion', ...credentialTargetFields, ...credentialSubjectFields,
    'authorityRevision', 'credentialServiceRevision', 'credentialHandleIdentityDigest', 'secretGeneration', 'createdAt', 'bindingDigest'], ['expiresAt']);
  credentialTarget(object); credentialHandle(object); time(object.createdAt); selfDigest(object, 'bindingDigest');
  return object as EndpointCredentialGrantBinding;
}

export function decodeCredentialAuthorityRecord(value: unknown): CredentialAuthorityRecordV1 {
  const object = closed(value, ['schemaVersion', ...credentialTargetFields, ...credentialSubjectFields, 'authorityRevision',
    'credentialServiceRevision', 'credentialHandleIdentityDigest', 'secretGeneration', 'platformItem', 'createdAt', 'state', 'recordDigest'],
  ['expiresAt', 'revokedAt', 'revokedByRequestId', 'revokedByRequestDigest']);
  credentialTarget(object); credentialHandle(object); platformItem(object.platformItem); time(object.createdAt);
  revocation(object); selfDigest(object, 'recordDigest');
  return object as CredentialAuthorityRecordV1;
}

export function decodeCredentialAuthorityCommandCore(value: unknown): CredentialAuthorityCommandCoreV1 {
  const object = closed(value, ['schemaVersion', ...credentialTargetFields, ...credentialSubjectFields,
    'kind', 'secretSubmissionId', 'credentialTargetDigest', 'commandDigest'], ['expiresAt']);
  if (object.kind !== 'enroll' && object.kind !== 'rotate') throw new TypeError('credential command kind is invalid');
  credentialTarget(object); text(object.secretSubmissionId);
  const target = { credentialGrantId: object.credentialGrantId, ownerPrincipalId: object.ownerPrincipalId, purpose: object.purpose,
    endpointRegistrationRef: object.endpointRegistrationRef, endpointIdentityDigest: object.endpointIdentityDigest,
    tlsPolicyDigest: object.tlsPolicyDigest, ...(Object.hasOwn(object, 'expiresAt') ? { expiresAt: object.expiresAt } : {}),
    externalSubjectDigest: object.externalSubjectDigest };
  if (object.credentialTargetDigest !== canonicalSha256(target)) throw new TypeError('credential target digest does not rehash');
  selfDigest(object, 'commandDigest');
  return object as CredentialAuthorityCommandCoreV1;
}

/** History continuity, the current active endpoint and actual secret-store observations are metadata-owner duties. */
export function decodeCredentialAuthorityOperation(value: unknown): CredentialAuthorityOperationV1 {
  const common = ['schemaVersion', 'operationId', 'requestId', 'requestDigest', 'channelIdentityRef', 'channelIdentityDigest',
    'commandCore', 'attempt', 'ownerPrincipalId', 'kind', 'credentialGrantId', 'credentialTargetDigest', 'intendedAuthorityRevision',
    'intendedSecretGeneration', 'intendedExternalSubjectDigest', 'platformItem', 'createdAt', 'operationDigest', 'phase'];
  const object = closed(value, common, ['committedAuthorityRevision', 'abortReason', 'finishedAt']);
  const core = decodeCredentialAuthorityCommandCore(object.commandCore);
  const attempt = integer(object.attempt, 1, 3);
  request(object.requestId); digest(object.channelIdentityRef); digest(object.channelIdentityDigest); platformItem(object.platformItem); time(object.createdAt);
  if (object.ownerPrincipalId !== core.ownerPrincipalId || object.kind !== core.kind || object.credentialGrantId !== core.credentialGrantId ||
      object.credentialTargetDigest !== core.credentialTargetDigest || object.intendedExternalSubjectDigest !== core.externalSubjectDigest ||
      object.requestDigest !== core.commandDigest || object.operationId !== identityHash(core.ownerPrincipalId, object.requestId, core.commandDigest, attempt))
    throw new TypeError('credential operation does not repeat its command identity');
  const revision = integer(object.intendedAuthorityRevision), generation = integer(object.intendedSecretGeneration);
  if (core.kind === 'enroll' ? revision !== 1 || generation !== 1 : revision < 2 || generation < 2)
    throw new TypeError('credential operation intended revision or generation is invalid');
  if (object.phase === 'prepared' || object.phase === 'secret_stored') closed(object, common);
  else if (object.phase === 'committed') {
    closed(object, [...common, 'committedAuthorityRevision', 'finishedAt']);
    if (integer(object.committedAuthorityRevision) !== revision) throw new TypeError('credential committed revision does not match its intent');
    time(object.finishedAt);
  } else if (object.phase === 'aborted') {
    closed(object, [...common, 'abortReason', 'finishedAt']);
    if (object.abortReason !== 'recovered_orphan' && object.abortReason !== 'platform_store_failed' && object.abortReason !== 'request_conflict')
      throw new TypeError('credential abort reason is invalid');
    time(object.finishedAt);
  } else throw new TypeError('credential operation phase is invalid');
  selfDigest(object, 'operationDigest');
  return object as CredentialAuthorityOperationV1;
}

export function decodeCredentialAuthorityRevokeCommandCore(value: unknown): CredentialAuthorityRevokeCommandCoreV1 {
  const object = closed(value, ['schemaVersion', 'kind', 'ownerPrincipalId', 'credentialGrantId', 'expectedAuthorityRevision',
    'credentialTargetDigest', 'commandDigest']);
  if (object.kind !== 'revoke') throw new TypeError('credential revoke command kind is invalid');
  text(object.ownerPrincipalId); text(object.credentialGrantId); integer(object.expectedAuthorityRevision); digest(object.credentialTargetDigest);
  selfDigest(object, 'commandDigest');
  return object as CredentialAuthorityRevokeCommandCoreV1;
}

/** Cleanup is retained provenance of one revocation, not a new enrollment attempt or proof of deletion. */
export function decodeCredentialAuthorityRevokeOperation(value: unknown): CredentialAuthorityRevokeOperationV1 {
  const common = ['schemaVersion', 'operationId', 'requestId', 'requestDigest', 'channelIdentityRef', 'channelIdentityDigest',
    'commandCore', 'ownerPrincipalId', 'credentialGrantId', 'credentialTargetDigest', 'disposition', 'committedAuthorityRevision',
    'revokedRecordDigest', 'platformItem', 'metadataCommittedAt', 'operationDigest', 'cleanupPhase'];
  const object = closed(value, common, ['cleanupEvidenceDigest', 'cleanupErrorCode', 'cleanupFinishedAt']);
  const core = decodeCredentialAuthorityRevokeCommandCore(object.commandCore);
  request(object.requestId); digest(object.channelIdentityRef); digest(object.channelIdentityDigest);
  if (object.ownerPrincipalId !== core.ownerPrincipalId || object.credentialGrantId !== core.credentialGrantId ||
      object.credentialTargetDigest !== core.credentialTargetDigest || object.requestDigest !== core.commandDigest ||
      object.operationId !== identityHash(core.ownerPrincipalId, object.requestId, core.commandDigest))
    throw new TypeError('credential revoke operation does not repeat its command identity');
  if (object.disposition !== 'revoked' && object.disposition !== 'already_revoked') throw new TypeError('credential revoke disposition is invalid');
  integer(object.committedAuthorityRevision); digest(object.revokedRecordDigest); platformItem(object.platformItem); time(object.metadataCommittedAt);
  if (object.cleanupPhase === 'metadata_committed') closed(object, common);
  else if (object.cleanupPhase === 'cleanup_complete') {
    closed(object, [...common, 'cleanupEvidenceDigest', 'cleanupFinishedAt']);
    digest(object.cleanupEvidenceDigest); time(object.cleanupFinishedAt);
  } else if (object.cleanupPhase === 'cleanup_failed') {
    closed(object, [...common, 'cleanupEvidenceDigest', 'cleanupErrorCode', 'cleanupFinishedAt']);
    digest(object.cleanupEvidenceDigest); time(object.cleanupFinishedAt);
    if (object.cleanupErrorCode !== 'platform_store_unavailable' && object.cleanupErrorCode !== 'delete_denied' && object.cleanupErrorCode !== 'delete_failed')
      throw new TypeError('credential cleanup error code is invalid');
  } else throw new TypeError('credential cleanup phase is invalid');
  selfDigest(object, 'operationDigest');
  return object as CredentialAuthorityRevokeOperationV1;
}
