import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalSha256 } from './canonical.js';
import { digestOmitting, identityHash } from './identity.js';
import { decodeEndpointRegistration, decodeEndpointAuthorityRecord, decodeEndpointAuthorityCommandCore,
  decodeEndpointAuthorityOperation, type EndpointRegistrationV1, type EndpointAuthorityRecordV1,
  type EndpointAuthorityCommandCoreV1, type EndpointAuthorityOperationV1,
  decodeCredentialExternalSubject, decodeEndpointCredentialGrantBinding, decodeCredentialAuthorityRecord,
  type CredentialExternalSubjectV1, type EndpointCredentialGrantBinding, type CredentialAuthorityRecordV1,
  decodeCredentialAuthorityCommandCore, decodeCredentialAuthorityOperation,
  type CredentialAuthorityCommandCoreV1, type CredentialAuthorityOperationV1,
  decodeCredentialAuthorityRevokeCommandCore, decodeCredentialAuthorityRevokeOperation,
  type CredentialAuthorityRevokeCommandCoreV1, type CredentialAuthorityRevokeOperationV1 } from './credential-authority.js';

const now = '2026-10-11T00:00:00.000Z';
const ref = (digit: string) => digit.repeat(64);
const requestId = '019a0011-0000-7000-8000-000000000001';

function signed<T extends Record<string, unknown>>(value: T, field: keyof T & string): T {
  return { ...value, [field]: digestOmitting(value, field) };
}

function endpoint(): EndpointRegistrationV1 {
  const value: EndpointRegistrationV1 = {
    schemaVersion: 1, format: 'cliq-endpoint-registration-v1', endpointRegistrationId: 'example',
    registrationKind: 'user', ownerPrincipalId: 'principal', purposes: ['model_endpoint'],
    target: { scheme: 'https', hostAscii: 'example.com', port: 443, basePath: '/v1', redirectPolicy: 'reject_all' },
    tls: { serverNameAscii: 'example.com', minimumVersion: 'TLSv1.3', trustStoreRuntimeBundleRef: ref('1'),
      trustStoreRuntimeBundleManifestDigest: ref('2'), trustStoreEntryId: 'default_https_trust_store',
      trustStoreRef: ref('3'), trustStoreDigest: ref('3'), spkiSha256Pins: [ref('4')] },
    endpointIdentityDigest: '', tlsPolicyDigest: '', createdAt: now, registrationDigest: ''
  };
  value.tlsPolicyDigest = canonicalSha256(value.tls);
  value.endpointIdentityDigest = canonicalSha256({ target: value.target, tlsPolicyDigest: value.tlsPolicyDigest });
  value.registrationDigest = digestOmitting(value, 'registrationDigest');
  return value;
}

test('endpoint registration decodes the canonical HTTPS target and all three digest domains', () => {
  const value = endpoint();
  assert.deepEqual(decodeEndpointRegistration(value), value);
  assert.throws(() => decodeEndpointRegistration({ ...value, registrationDigest: ref('f') }), /digest/i);
  const wrongTls = { ...value, tlsPolicyDigest: ref('f') };
  wrongTls.registrationDigest = digestOmitting(wrongTls, 'registrationDigest');
  assert.throws(() => decodeEndpointRegistration(wrongTls), /TLS.*digest/i);
  const wrongIdentity = { ...value, endpointIdentityDigest: ref('f') };
  wrongIdentity.registrationDigest = digestOmitting(wrongIdentity, 'registrationDigest');
  assert.throws(() => decodeEndpointRegistration(wrongIdentity), /identity.*digest/i);
});

function rehashEndpoint(value: unknown): Record<string, unknown> {
  const object = value as Record<string, unknown>;
  object.tlsPolicyDigest = canonicalSha256(object.tls);
  object.endpointIdentityDigest = canonicalSha256({ target: object.target, tlsPolicyDigest: object.tlsPolicyDigest });
  object.registrationDigest = digestOmitting(object, 'registrationDigest');
  return object;
}

test('even self-consistent endpoint hashes cannot admit secrets, unknown members or noncanonical targets', () => {
  const changes: Array<readonly [string, (value: EndpointRegistrationV1) => unknown]> = [
    ['secret', value => ({ ...value, secret: 'not-authority' })],
    ['target secret', value => ({ ...value, target: { ...value.target, password: 'not-authority' } })],
    ['TLS secret', value => ({ ...value, tls: { ...value.tls, privateKey: 'not-authority' } })],
    ['missing owner', ({ ownerPrincipalId: _owner, ...value }) => value],
    ['schema', value => ({ ...value, schemaVersion: 2 })],
    ['kind', value => ({ ...value, registrationKind: 'ambient' })],
    ['empty purposes', value => ({ ...value, purposes: [] })],
    ['unknown purpose', value => ({ ...value, purposes: ['shell_network'] })],
    ['duplicate purposes', value => ({ ...value, purposes: ['model_endpoint', 'model_endpoint'] })],
    ['unsorted purposes', value => ({ ...value, purposes: ['model_endpoint', 'dependency_registry'] })],
    ['non-NFC id', value => ({ ...value, endpointRegistrationId: 'e\u0301' })],
    ['alternate time', value => ({ ...value, createdAt: '2026-10-11T00:00:00Z' })],
    ['HTTP', value => ({ ...value, target: { ...value.target, scheme: 'http' } })],
    ['redirect', value => ({ ...value, target: { ...value.target, redirectPolicy: 'same_origin' } })],
    ...['EXAMPLE.com', 'example.com.', 'éxample.com', 'user@example.com', 'example.com/path'].map(hostAscii =>
      [`host ${hostAscii}`, (value: EndpointRegistrationV1) => ({ ...value, target: { ...value.target, hostAscii } })] as const),
    ...[0, 65536, 443.5].map(port =>
      [`port ${port}`, (value: EndpointRegistrationV1) => ({ ...value, target: { ...value.target, port } })] as const),
    ...['relative', '/a/../b', '/%2e/b', '/a%2Fb', '/a%5cb', '/a?b', '/a#b', '/a\\b', '/%zz'].map(basePath =>
      [`path ${basePath}`, (value: EndpointRegistrationV1) => ({ ...value, target: { ...value.target, basePath } })] as const),
    ['TLS version', value => ({ ...value, tls: { ...value.tls, minimumVersion: 'TLSv1.2' } })],
    ['server name', value => ({ ...value, tls: { ...value.tls, serverNameAscii: 'EXAMPLE.com' } })],
    ['trust entry', value => ({ ...value, tls: { ...value.tls, trustStoreEntryId: 'system' } })],
    ['trust ref', value => ({ ...value, tls: { ...value.tls, trustStoreRef: 'sha256:' + ref('3') } })],
    ['trust content pair', value => ({ ...value, tls: { ...value.tls, trustStoreDigest: ref('4') } })],
    ['empty pins', value => ({ ...value, tls: { ...value.tls, spkiSha256Pins: [] } })],
    ['duplicate pins', value => ({ ...value, tls: { ...value.tls, spkiSha256Pins: [ref('4'), ref('4')] } })],
    ['unsorted pins', value => ({ ...value, tls: { ...value.tls, spkiSha256Pins: [ref('5'), ref('4')] } })],
    ['uppercase pin', value => ({ ...value, tls: { ...value.tls, spkiSha256Pins: [ref('A')] } })]
  ];
  for (const [label, change] of changes) assert.throws(() => decodeEndpointRegistration(rehashEndpoint(change(endpoint()))), TypeError, label);
});

function endpointRecord(): EndpointAuthorityRecordV1 {
  const registration = endpoint();
  return signed({ schemaVersion: 1, endpointRegistrationId: 'example', authorityRevision: 1, ownerPrincipalId: 'principal',
    sourceRequestId: requestId, sourceRequestDigest: ref('5'), registration,
    expectedRegistrationArtifactRef: canonicalSha256(registration), createdAt: now, state: 'active', recordDigest: ''
  } satisfies EndpointAuthorityRecordV1, 'recordDigest');
}

test('endpoint records bind the inline registration and exact canonical artifact ref without accepting revocation fields on active rows', () => {
  const active = endpointRecord();
  assert.deepEqual(decodeEndpointAuthorityRecord(active), active);
  const revoked = signed({ ...active, state: 'revoked', authorityRevision: 2, revokedAt: now,
    revokedByRequestId: requestId, revokedByRequestDigest: ref('6') }, 'recordDigest');
  assert.deepEqual(decodeEndpointAuthorityRecord(revoked), revoked);
  for (const change of [{ ownerPrincipalId: 'other' }, { endpointRegistrationId: 'other' },
    { expectedRegistrationArtifactRef: ref('f') }, { authorityRevision: 0 }, { sourceRequestId: 'not-uuid' },
    { state: 'unknown' }, { secret: 'not-authority' }, { revokedByRequestDigest: ref('6') }, { recordDigest: ref('f') }]) {
    const changed = { ...active, ...change };
    assert.throws(() => decodeEndpointAuthorityRecord('recordDigest' in change ? changed : signed(changed, 'recordDigest')), TypeError);
  }
  const { revokedByRequestDigest: _digest, ...incomplete } = revoked;
  assert.throws(() => decodeEndpointAuthorityRecord(signed(incomplete, 'recordDigest')), TypeError);
});

function endpointCommand(): EndpointAuthorityCommandCoreV1 {
  const registration = endpoint();
  return signed({ schemaVersion: 1, kind: 'register', ownerPrincipalId: 'principal', registration,
    expectedRegistrationArtifactRef: canonicalSha256(registration), commandDigest: ''
  } satisfies EndpointAuthorityCommandCoreV1, 'commandDigest');
}

function endpointOperation(): EndpointAuthorityOperationV1 {
  const commandCore = endpointCommand();
  return signed({ schemaVersion: 1, operationId: identityHash('principal', requestId, commandCore.commandDigest),
    requestId, requestDigest: commandCore.commandDigest, channelIdentityRef: ref('a'), channelIdentityDigest: ref('b'),
    commandCore, ownerPrincipalId: 'principal', kind: 'register', endpointRegistrationId: 'example', disposition: 'registered',
    committedAuthorityRevision: 1, resultRecordDigest: endpointRecord().recordDigest, committedAt: now, operationDigest: ''
  } satisfies EndpointAuthorityOperationV1, 'operationDigest');
}

test('endpoint commands and operations retain separate request, provenance and self-digest domains', () => {
  const operation = endpointOperation();
  assert.deepEqual(decodeEndpointAuthorityCommandCore(operation.commandCore), operation.commandCore);
  assert.deepEqual(decodeEndpointAuthorityOperation(operation), operation);
  const laterChannel = signed({ ...operation, channelIdentityRef: ref('c'), channelIdentityDigest: ref('d') }, 'operationDigest');
  assert.deepEqual(decodeEndpointAuthorityOperation(laterChannel), laterChannel);
  assert.equal(laterChannel.requestDigest, operation.requestDigest);
  const revoke = signed({ schemaVersion: 1, kind: 'revoke', ownerPrincipalId: 'principal', endpointRegistrationId: 'example',
    expectedAuthorityRevision: 1, commandDigest: '' } satisfies EndpointAuthorityCommandCoreV1, 'commandDigest');
  const revoked = signed({ ...operation, commandCore: revoke, requestDigest: revoke.commandDigest,
    operationId: identityHash('principal', requestId, revoke.commandDigest), kind: 'revoke', disposition: 'revoked',
    committedAuthorityRevision: 2 }, 'operationDigest');
  assert.deepEqual(decodeEndpointAuthorityCommandCore(revoke), revoke);
  assert.deepEqual(decodeEndpointAuthorityOperation(revoked), revoked);
  for (const change of [{ ownerPrincipalId: 'other' }, { endpointRegistrationId: 'other' }, { kind: 'revoke' },
    { disposition: 'revoked' }, { requestDigest: ref('f') }, { operationId: 'wrong' }, { channelIdentityRef: 'path' },
    { requestId: 'not-uuid' }, { committedAuthorityRevision: 0 }, { secret: 'not-authority' }])
    assert.throws(() => decodeEndpointAuthorityOperation(signed({ ...operation, ...change }, 'operationDigest')), TypeError);
  assert.throws(() => decodeEndpointAuthorityCommandCore(signed({ ...revoke, registration: endpoint() }, 'commandDigest')), TypeError);
  assert.throws(() => decodeEndpointAuthorityOperation({ ...operation, operationDigest: ref('f') }), TypeError);
});

test('endpoint operation dispositions are closed string literals, not coerced values', () => {
  const operation = endpointOperation();
  assert.deepEqual(decodeEndpointAuthorityOperation(signed({ ...operation, disposition: 'already_registered' }, 'operationDigest')),
    signed({ ...operation, disposition: 'already_registered' }, 'operationDigest'));
  for (const disposition of [['registered'], ['already_registered']])
    assert.throws(() => decodeEndpointAuthorityOperation(signed({ ...operation, disposition }, 'operationDigest')), TypeError);
  const commandCore = signed({ schemaVersion: 1, kind: 'revoke', ownerPrincipalId: 'principal', endpointRegistrationId: 'example',
    expectedAuthorityRevision: 1, commandDigest: '' } satisfies EndpointAuthorityCommandCoreV1, 'commandDigest');
  const revoked = signed({ ...operation, commandCore, kind: 'revoke', disposition: 'already_revoked',
    requestDigest: commandCore.commandDigest, operationId: identityHash('principal', requestId, commandCore.commandDigest) }, 'operationDigest');
  assert.deepEqual(decodeEndpointAuthorityOperation(revoked), revoked);
  for (const disposition of [['revoked'], ['already_revoked']])
    assert.throws(() => decodeEndpointAuthorityOperation(signed({ ...revoked, disposition }, 'operationDigest')), TypeError);
});

// Offline canonical models only: these do not mint a registered or redeemable grant.
function subject(): CredentialExternalSubjectV1 {
  return signed({ schemaVersion: 1, format: 'cliq-credential-external-subject-v1', endpointIdentityDigest: endpoint().endpointIdentityDigest,
    subject: { kind: 'provider_verified', providerNamespace: 'example', accountSubjectDigest: ref('7'),
      scopes: ['read', 'write'], audiences: ['api'] }, observedAt: now, subjectDigest: ''
  } satisfies CredentialExternalSubjectV1, 'subjectDigest');
}

function binding(): EndpointCredentialGrantBinding {
  const registration = endpoint(), externalSubject = subject();
  const value: EndpointCredentialGrantBinding = {
    schemaVersion: 1, credentialGrantId: 'grant', authorityRevision: 1, credentialServiceRevision: 1,
    ownerPrincipalId: 'principal', credentialHandleIdentityDigest: '', secretGeneration: 1,
    externalSubject, externalSubjectDigest: externalSubject.subjectDigest, purpose: 'model_endpoint',
    endpointRegistrationRef: canonicalSha256(registration), endpointIdentityDigest: registration.endpointIdentityDigest,
    tlsPolicyDigest: registration.tlsPolicyDigest, createdAt: now, expiresAt: '2026-10-12T00:00:00.000Z', bindingDigest: ''
  };
  value.credentialHandleIdentityDigest = canonicalSha256({ ownerPrincipalId: value.ownerPrincipalId, credentialGrantId: value.credentialGrantId,
    credentialServiceRevision: value.credentialServiceRevision, purpose: value.purpose, endpointRegistrationRef: value.endpointRegistrationRef,
    endpointIdentityDigest: value.endpointIdentityDigest, tlsPolicyDigest: value.tlsPolicyDigest });
  return signed(value, 'bindingDigest');
}

function credentialRecord(): CredentialAuthorityRecordV1 {
  const { bindingDigest: _digest, ...base } = binding();
  return signed({ ...base, state: 'active', platformItem: { kind: 'linux_secret_service', schema: 'org.freedesktop.Secret.Generic',
    collection: 'default', itemId: '/org/freedesktop/secrets/collection/default/item/1' }, recordDigest: ''
  } satisfies CredentialAuthorityRecordV1, 'recordDigest');
}

test('credential subjects close each provider or opaque branch and bind the exact semantic digest', () => {
  const verified = subject();
  assert.deepEqual(decodeCredentialExternalSubject(verified), verified);
  const opaque = signed({ ...verified, subject: { kind: 'opaque_generation', opaqueSubjectId: 'A'.repeat(43),
    scopes: ['endpoint_exact_only'], audiences: [] } }, 'subjectDigest');
  assert.deepEqual(decodeCredentialExternalSubject(opaque), opaque);
  for (const changed of [
    { ...verified, subject: { ...verified.subject, secret: 'not-authority' } },
    { ...verified, subject: { ...verified.subject, scopes: ['write', 'read'] } },
    { ...verified, subject: { ...verified.subject, scopes: ['read', 'read'] } },
    { ...verified, subject: { ...verified.subject, accountSubjectDigest: 'account-name' } },
    { ...opaque, subject: { ...opaque.subject, scopes: ['read'] } },
    { ...opaque, subject: { ...opaque.subject, audiences: ['api'] } },
    { ...opaque, subject: { ...opaque.subject, providerNamespace: 'example' } },
    { ...opaque, subject: { ...opaque.subject, opaqueSubjectId: '' } },
    { ...opaque, subject: { ...opaque.subject, opaqueSubjectId: 'e\u0301' } },
    { ...verified, observedAt: '2026-10-11T00:00:00Z' }
  ]) assert.throws(() => decodeCredentialExternalSubject(signed(changed, 'subjectDigest')), TypeError);
  assert.throws(() => decodeCredentialExternalSubject({ ...verified, subjectDigest: ref('f') }), TypeError);
});

test('bindings and credential records validate their embedded target, subject and fixed platform-item models without granting authority', () => {
  const grant = binding(), active = credentialRecord();
  assert.deepEqual(decodeEndpointCredentialGrantBinding(grant), grant);
  assert.deepEqual(decodeCredentialAuthorityRecord(active), active);
  const mac = signed({ ...active, platformItem: { kind: 'macos_keychain', service: 'ai.cogine.cliq.credentials.v1', accountId: 'item-1' } }, 'recordDigest');
  assert.deepEqual(decodeCredentialAuthorityRecord(mac), mac);
  const revoked = signed({ ...active, state: 'revoked', authorityRevision: 2, revokedAt: now,
    revokedByRequestId: requestId, revokedByRequestDigest: ref('6') }, 'recordDigest');
  assert.deepEqual(decodeCredentialAuthorityRecord(revoked), revoked);
  for (const change of [{ authorityRevision: 0 }, { secretGeneration: 1.5 }, { credentialServiceRevision: 0 },
    { externalSubjectDigest: ref('f') }, { endpointIdentityDigest: ref('f') }, { credentialHandleIdentityDigest: ref('f') },
    { purpose: 'generic_network' }, { expiresAt: null }, { secret: 'not-authority' }]) {
    assert.throws(() => decodeEndpointCredentialGrantBinding(signed({ ...grant, ...change }, 'bindingDigest')), TypeError);
    assert.throws(() => decodeCredentialAuthorityRecord(signed({ ...active, ...change }, 'recordDigest')), TypeError);
  }
  for (const platformItem of [{ kind: 'file', path: '/tmp/secret' }, { ...active.platformItem, collection: 'other' },
    { ...active.platformItem, secret: 'not-authority' }, { ...mac.platformItem, service: 'other' }, { ...mac.platformItem, itemId: 'cross-branch' }])
    assert.throws(() => decodeCredentialAuthorityRecord(signed({ ...active, platformItem }, 'recordDigest')), TypeError);
  assert.throws(() => decodeCredentialAuthorityRecord(signed({ ...active, revokedAt: now }, 'recordDigest')), TypeError);
  assert.throws(() => decodeCredentialAuthorityRecord({ ...active, recordDigest: ref('f') }), TypeError);
  assert.throws(() => decodeEndpointCredentialGrantBinding({ ...grant, bindingDigest: ref('f') }), TypeError);
});

function credentialCommand(): CredentialAuthorityCommandCoreV1 {
  const value = binding();
  const core: CredentialAuthorityCommandCoreV1 = { schemaVersion: 1, ownerPrincipalId: value.ownerPrincipalId, kind: 'enroll',
    credentialGrantId: value.credentialGrantId, purpose: value.purpose, endpointRegistrationRef: value.endpointRegistrationRef,
    endpointIdentityDigest: value.endpointIdentityDigest, tlsPolicyDigest: value.tlsPolicyDigest, expiresAt: value.expiresAt,
    secretSubmissionId: 'submission-1', externalSubject: value.externalSubject, externalSubjectDigest: value.externalSubjectDigest,
    credentialTargetDigest: '', commandDigest: '' };
  return rehashCredentialCommand(core) as CredentialAuthorityCommandCoreV1;
}

function rehashCredentialCommand(value: Record<string, unknown>): Record<string, unknown> {
  const target = { credentialGrantId: value.credentialGrantId, ownerPrincipalId: value.ownerPrincipalId, purpose: value.purpose,
    endpointRegistrationRef: value.endpointRegistrationRef, endpointIdentityDigest: value.endpointIdentityDigest,
    tlsPolicyDigest: value.tlsPolicyDigest, ...(Object.hasOwn(value, 'expiresAt') ? { expiresAt: value.expiresAt } : {}),
    externalSubjectDigest: value.externalSubjectDigest };
  const result: Record<string, unknown> = { ...value, credentialTargetDigest: canonicalSha256(target) };
  return signed(result, 'commandDigest');
}

function credentialOperation(): CredentialAuthorityOperationV1 {
  const commandCore = credentialCommand();
  return signed({ schemaVersion: 1, operationId: identityHash('principal', requestId, commandCore.commandDigest, 1), requestId,
    requestDigest: commandCore.commandDigest, channelIdentityRef: ref('a'), channelIdentityDigest: ref('b'), commandCore, attempt: 1,
    ownerPrincipalId: 'principal', kind: 'enroll', credentialGrantId: 'grant', credentialTargetDigest: commandCore.credentialTargetDigest,
    intendedAuthorityRevision: 1, intendedSecretGeneration: 1, intendedExternalSubjectDigest: commandCore.externalSubjectDigest,
    platformItem: credentialRecord().platformItem, createdAt: now, operationDigest: '', phase: 'prepared'
  } satisfies CredentialAuthorityOperationV1, 'operationDigest');
}

test('credential command target hashes include optional expiry and exclude submission/provenance without admitting raw secrets', () => {
  const core = credentialCommand();
  assert.deepEqual(decodeCredentialAuthorityCommandCore(core), core);
  const { expiresAt: _expiry, ...nonexpiring } = core;
  const noExpiry = rehashCredentialCommand(nonexpiring);
  assert.deepEqual(decodeCredentialAuthorityCommandCore(noExpiry), noExpiry);
  const newSubmission = signed({ ...core, secretSubmissionId: 'submission-2' }, 'commandDigest');
  assert.deepEqual(decodeCredentialAuthorityCommandCore(newSubmission), newSubmission);
  assert.equal(newSubmission.credentialTargetDigest, core.credentialTargetDigest);
  assert.notEqual(newSubmission.commandDigest, core.commandDigest);
  for (const change of [{ secret: 'not-authority' }, { kind: 'revoke' }, { secretSubmissionId: '' },
    { externalSubjectDigest: ref('f') }, { expiresAt: null }])
    assert.throws(() => decodeCredentialAuthorityCommandCore(rehashCredentialCommand({ ...core, ...change })), TypeError);
  assert.throws(() => decodeCredentialAuthorityCommandCore(signed({ ...core, credentialTargetDigest: ref('f') }, 'commandDigest')), TypeError);
  assert.throws(() => decodeCredentialAuthorityCommandCore({ ...core, commandDigest: ref('f') }), TypeError);
});

test('enrollment and rotation operations close each phase and repeat their complete command identity', () => {
  const prepared = credentialOperation();
  const stored = signed({ ...prepared, phase: 'secret_stored' }, 'operationDigest');
  const committed = signed({ ...prepared, phase: 'committed', committedAuthorityRevision: 1, finishedAt: now }, 'operationDigest');
  const aborted = signed({ ...prepared, phase: 'aborted', abortReason: 'recovered_orphan', finishedAt: now }, 'operationDigest');
  for (const value of [prepared, stored, committed, aborted]) assert.deepEqual(decodeCredentialAuthorityOperation(value), value);
  const commandCore = signed({ ...prepared.commandCore, kind: 'rotate' }, 'commandDigest');
  const rotating = signed({ ...prepared, commandCore, kind: 'rotate', requestDigest: commandCore.commandDigest,
    operationId: identityHash('principal', requestId, commandCore.commandDigest, 1), intendedAuthorityRevision: 2, intendedSecretGeneration: 2 }, 'operationDigest');
  assert.deepEqual(decodeCredentialAuthorityOperation(rotating), rotating);
  for (const change of [{ ownerPrincipalId: 'other' }, { credentialGrantId: 'other' }, { kind: 'rotate' }, { requestId: 'not-uuid' },
    { attempt: 0 }, { attempt: 4 }, { attempt: 1.5 }, { requestDigest: ref('f') }, { operationId: 'wrong' },
    { credentialTargetDigest: ref('f') }, { intendedExternalSubjectDigest: ref('f') }, { intendedAuthorityRevision: 2 },
    { intendedSecretGeneration: 2 }, { phase: 'unknown' }, { committedAuthorityRevision: 1 }, { abortReason: 'recovered_orphan' },
    { finishedAt: now }, { secret: 'not-authority' }])
    assert.throws(() => decodeCredentialAuthorityOperation(signed({ ...prepared, ...change }, 'operationDigest')), TypeError);
  assert.throws(() => decodeCredentialAuthorityOperation(signed({ ...committed, committedAuthorityRevision: 2 }, 'operationDigest')), TypeError);
  assert.throws(() => decodeCredentialAuthorityOperation(signed({ ...committed, abortReason: 'recovered_orphan' }, 'operationDigest')), TypeError);
  assert.throws(() => decodeCredentialAuthorityOperation(signed({ ...aborted, abortReason: 'unknown' }, 'operationDigest')), TypeError);
  assert.throws(() => decodeCredentialAuthorityOperation(signed({ ...aborted, committedAuthorityRevision: 1 }, 'operationDigest')), TypeError);
  const { finishedAt: _finish, ...incomplete } = committed;
  assert.throws(() => decodeCredentialAuthorityOperation(signed(incomplete, 'operationDigest')), TypeError);
  const laterChannel = signed({ ...prepared, channelIdentityRef: ref('c'), channelIdentityDigest: ref('d') }, 'operationDigest');
  assert.deepEqual(decodeCredentialAuthorityOperation(laterChannel), laterChannel);
  assert.equal(laterChannel.operationId, prepared.operationId);
  assert.equal(laterChannel.requestDigest, prepared.requestDigest);
  assert.throws(() => decodeCredentialAuthorityOperation({ ...prepared, operationDigest: ref('f') }), TypeError);
});

function credentialRevokeCommand(): CredentialAuthorityRevokeCommandCoreV1 {
  return signed({ schemaVersion: 1, kind: 'revoke', ownerPrincipalId: 'principal', credentialGrantId: 'grant',
    expectedAuthorityRevision: 1, credentialTargetDigest: credentialCommand().credentialTargetDigest, commandDigest: ''
  } satisfies CredentialAuthorityRevokeCommandCoreV1, 'commandDigest');
}

function credentialRevokeOperation(): CredentialAuthorityRevokeOperationV1 {
  const commandCore = credentialRevokeCommand();
  return signed({ schemaVersion: 1, operationId: identityHash('principal', requestId, commandCore.commandDigest), requestId,
    requestDigest: commandCore.commandDigest, channelIdentityRef: ref('a'), channelIdentityDigest: ref('b'), commandCore,
    ownerPrincipalId: 'principal', credentialGrantId: 'grant', credentialTargetDigest: commandCore.credentialTargetDigest,
    disposition: 'revoked', committedAuthorityRevision: 2, revokedRecordDigest: ref('c'), platformItem: credentialRecord().platformItem,
    metadataCommittedAt: now, operationDigest: '', cleanupPhase: 'metadata_committed'
  } satisfies CredentialAuthorityRevokeOperationV1, 'operationDigest');
}

test('credential revocation retains one three-part operation identity across exact cleanup phases', () => {
  const operation = credentialRevokeOperation();
  assert.deepEqual(decodeCredentialAuthorityRevokeCommandCore(operation.commandCore), operation.commandCore);
  const complete = signed({ ...operation, cleanupPhase: 'cleanup_complete', cleanupEvidenceDigest: ref('d'), cleanupFinishedAt: now }, 'operationDigest');
  const failed = signed({ ...operation, cleanupPhase: 'cleanup_failed', cleanupEvidenceDigest: ref('d'),
    cleanupErrorCode: 'delete_failed', cleanupFinishedAt: now }, 'operationDigest');
  const already = signed({ ...operation, disposition: 'already_revoked' }, 'operationDigest');
  for (const value of [operation, complete, failed, already]) assert.deepEqual(decodeCredentialAuthorityRevokeOperation(value), value);
  for (const cleanupErrorCode of ['platform_store_unavailable', 'delete_denied', 'delete_failed'])
    assert.deepEqual(decodeCredentialAuthorityRevokeOperation(signed({ ...failed, cleanupErrorCode }, 'operationDigest')),
      signed({ ...failed, cleanupErrorCode }, 'operationDigest'));
  assert.equal(complete.operationId, operation.operationId);
  assert.equal(failed.operationId, operation.operationId);
  const laterChannel = signed({ ...operation, channelIdentityRef: ref('e'), channelIdentityDigest: ref('f') }, 'operationDigest');
  assert.deepEqual(decodeCredentialAuthorityRevokeOperation(laterChannel), laterChannel);
  assert.equal(laterChannel.operationId, operation.operationId);
  assert.equal(laterChannel.requestDigest, operation.requestDigest);
  for (const change of [{ kind: 'enroll' }, { expectedAuthorityRevision: 0 }, { credentialTargetDigest: 'not-digest' },
    { secret: 'not-authority' }, { attempt: 1 }])
    assert.throws(() => decodeCredentialAuthorityRevokeCommandCore(signed({ ...operation.commandCore, ...change }, 'commandDigest')), TypeError);
  assert.throws(() => decodeCredentialAuthorityRevokeCommandCore({ ...operation.commandCore, commandDigest: ref('f') }), TypeError);
  for (const change of [{ ownerPrincipalId: 'other' }, { credentialGrantId: 'other' }, { credentialTargetDigest: ref('f') },
    { requestId: 'not-uuid' }, { requestDigest: ref('f') }, { operationId: 'wrong' }, { channelIdentityRef: 'path' },
    { attempt: 1 }, { operationId: identityHash('principal', requestId, operation.commandCore.commandDigest, 1) },
    { disposition: 'registered' }, { disposition: ['revoked'] }, { committedAuthorityRevision: 0 }, { revokedRecordDigest: 'not-digest' },
    { cleanupPhase: 'unknown' }, { cleanupEvidenceDigest: ref('d') }, { cleanupErrorCode: 'delete_failed' }, { cleanupFinishedAt: now },
    { secret: 'not-authority' }])
    assert.throws(() => decodeCredentialAuthorityRevokeOperation(signed({ ...operation, ...change }, 'operationDigest')), TypeError);
  for (const change of [{ cleanupErrorCode: 'delete_failed' }, { cleanupEvidenceDigest: 'not-digest' }, { cleanupFinishedAt: 'not-time' }])
    assert.throws(() => decodeCredentialAuthorityRevokeOperation(signed({ ...complete, ...change }, 'operationDigest')), TypeError);
  assert.throws(() => decodeCredentialAuthorityRevokeOperation(signed({ ...failed, cleanupErrorCode: 'unknown' }, 'operationDigest')), TypeError);
  const { cleanupEvidenceDigest: _evidence, ...incomplete } = failed;
  assert.throws(() => decodeCredentialAuthorityRevokeOperation(signed(incomplete, 'operationDigest')), TypeError);
  const { cleanupFinishedAt: _finished, ...unfinished } = complete;
  assert.throws(() => decodeCredentialAuthorityRevokeOperation(signed(unfinished, 'operationDigest')), TypeError);
  assert.throws(() => decodeCredentialAuthorityRevokeOperation({ ...operation, operationDigest: ref('f') }), TypeError);
});

test('malformed authority fields are rejected without echoing their input in errors', () => {
  const marker = 'accidentally-submitted-secret';
  for (const change of [{ channelIdentityRef: marker }, { metadataCommittedAt: marker }]) {
    assert.throws(() => decodeCredentialAuthorityRevokeOperation(signed({ ...credentialRevokeOperation(), ...change }, 'operationDigest')),
      (error: unknown) => error instanceof TypeError && !error.message.includes(marker));
  }
});

test('credential subject and revocation request domains match independently worked JCS vectors', () => {
  // These literals hash manually byte-sorted RFC objects with node:crypto,
  // without canonicalSha256/digestOmitting/identityHash as the expected oracle.
  const externalSubject: CredentialExternalSubjectV1 = {
    schemaVersion: 1, format: 'cliq-credential-external-subject-v1', endpointIdentityDigest: ref('e'),
    subject: { kind: 'opaque_generation', opaqueSubjectId: 'opaque-test-generation', scopes: ['endpoint_exact_only'], audiences: [] },
    observedAt: now, subjectDigest: '1965df14b0d297dd1421a03ce7385d51a4047666588a463e731572a0dd5345f1'
  };
  assert.deepEqual(decodeCredentialExternalSubject(externalSubject), externalSubject);
  const commandCore: CredentialAuthorityRevokeCommandCoreV1 = {
    schemaVersion: 1, kind: 'revoke', ownerPrincipalId: 'principal', credentialGrantId: 'grant',
    expectedAuthorityRevision: 1, credentialTargetDigest: ref('8'),
    commandDigest: 'ea1785ae8d2f01bfbcdec203778b39242255ae3d57a23b979b789e8c87385fe3'
  };
  assert.deepEqual(decodeCredentialAuthorityRevokeCommandCore(commandCore), commandCore);
  const operation = signed({ ...credentialRevokeOperation(), commandCore,
    requestDigest: commandCore.commandDigest, credentialTargetDigest: commandCore.credentialTargetDigest,
    operationId: 'QiG8L4FL9eLM4PmTNkedUxUqW6Ok9jSHXfykhd-exmA' }, 'operationDigest');
  assert.deepEqual(decodeCredentialAuthorityRevokeOperation(operation), operation);
});
