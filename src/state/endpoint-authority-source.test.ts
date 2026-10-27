import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { EndpointAuthorityCommandCoreV1, EndpointAuthorityOperationV1, EndpointAuthorityRecordV1, EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { LocalControlChannelIdentityV1, LocalPrincipalIdentityV1, PlatformProcessIdentityV1, StateRootIdentityV1 } from '../kernel/types.js';
import { validateRetainedEndpointResult, verifyRetainedEndpointAuthoritySource } from './endpoint-authority-source.js';

const ref = canonicalSha256;
const now = '2026-10-27T00:00:00.000Z', requestId = '019a0011-0000-7000-8000-000000000001';
const signed = <T extends object>(value: T, field: keyof T & string): T => ({ ...value, [field]: digestOmitting(value as Record<string, unknown>, field) });
function data() {
  const root = signed<StateRootIdentityV1>({ schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux',
    canonicalAbsolutePath: '/tmp/owned-data-fixture', ownerUid: 1000, deviceId: '1', directoryFileId: '2', mode: 448,
    openedNoFollow: true, layoutVersion: 1, identityDigest: '' }, 'identityDigest');
  const principalId = identityHash('cliq-local-principal-v1', root.identityDigest, root.platform, root.ownerUid);
  const principal = signed<LocalPrincipalIdentityV1>({ schemaVersion: 1, format: 'cliq-local-principal-identity-v1',
    stateRootIdentityRef: ref(root), stateRootIdentityDigest: root.identityDigest, platform: 'linux', effectiveUid: 1000,
    principalId, identityDigest: '' }, 'identityDigest');
  const process = signed<PlatformProcessIdentityV1>({ schemaVersion: 1, format: 'cliq-platform-process-identity-v1', platform: 'linux',
    pid: 7, processStartToken: 'linux-proc-start-ticks:42', ownerUid: 1000, executableImageDigest: ref('original image'),
    observedAt: now, identityDigest: '' }, 'identityDigest');
  const channel = signed<LocalControlChannelIdentityV1>({ schemaVersion: 1, format: 'cliq-local-control-channel-identity-v1',
    principalIdentityRef: ref(principal), principalIdentityDigest: principal.identityDigest, principalId, client: 'cli',
    transport: { kind: 'in_process', processIdentityRef: ref(process), processIdentityDigest: process.identityDigest },
    openedAt: now, channelNonceDigest: ref('channel nonce'), channelIdentityDigest: '' }, 'channelIdentityDigest');
  const registration: EndpointRegistrationV1 = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1', endpointRegistrationId: 'public',
    registrationKind: 'user', ownerPrincipalId: principalId, purposes: ['dependency_registry'],
    target: { scheme: 'https', hostAscii: 'registry.example', port: 443, basePath: '/', redirectPolicy: 'reject_all' },
    tls: { serverNameAscii: 'registry.example', minimumVersion: 'TLSv1.3', trustStoreRuntimeBundleRef: ref('bundle'),
      trustStoreRuntimeBundleManifestDigest: ref('bundle meaning'), trustStoreEntryId: 'default_https_trust_store',
      trustStoreRef: ref('CA bytes'), trustStoreDigest: ref('CA bytes'), spkiSha256Pins: [ref('SPKI')] },
    endpointIdentityDigest: '', tlsPolicyDigest: '', createdAt: now, registrationDigest: '' };
  registration.tlsPolicyDigest = ref(registration.tls); registration.endpointIdentityDigest = ref({ target: registration.target, tlsPolicyDigest: registration.tlsPolicyDigest });
  registration.registrationDigest = digestOmitting(registration, 'registrationDigest');
  const commandCore = signed<EndpointAuthorityCommandCoreV1>({ schemaVersion: 1, kind: 'register', ownerPrincipalId: principalId,
    registration, expectedRegistrationArtifactRef: ref(registration), commandDigest: '' }, 'commandDigest');
  const record = signed<EndpointAuthorityRecordV1>({ schemaVersion: 1, endpointRegistrationId: 'public', authorityRevision: 1,
    ownerPrincipalId: principalId, sourceRequestId: requestId, sourceRequestDigest: commandCore.commandDigest, registration,
    expectedRegistrationArtifactRef: ref(registration), createdAt: now, state: 'active', recordDigest: '' }, 'recordDigest');
  const operation = signed<EndpointAuthorityOperationV1>({ schemaVersion: 1, operationId: identityHash(principalId, requestId, commandCore.commandDigest),
    requestId, requestDigest: commandCore.commandDigest, channelIdentityRef: ref(channel), channelIdentityDigest: channel.channelIdentityDigest,
    commandCore, ownerPrincipalId: principalId, kind: 'register', endpointRegistrationId: 'public', disposition: 'registered',
    committedAuthorityRevision: 1, resultRecordDigest: record.recordDigest, committedAt: now, operationDigest: '' }, 'operationDigest');
  return { source: { operation, channel, principal, root, process }, record,
    expected: { principalId, stateRoot: root, executableImageDigest: process.executableImageDigest } };
}

test('shared endpoint source composition binds exact original object bytes and explicit original image', () => {
  const f = data(); assert.doesNotThrow(() => verifyRetainedEndpointAuthoritySource(f.source, f.expected));
  assert.doesNotThrow(() => validateRetainedEndpointResult(f.source.operation, [f.record]));
  for (const expected of [{ ...f.expected, principalId: 'foreign' }, { ...f.expected, executableImageDigest: ref('today is not original') },
    { ...f.expected, stateRoot: { ...f.source.root, canonicalAbsolutePath: '/tmp/other' } }])
    assert.throws(() => verifyRetainedEndpointAuthoritySource(f.source, expected));
  const changedChannel = signed({ ...f.source.channel, channelNonceDigest: ref('different valid channel') }, 'channelIdentityDigest');
  assert.throws(() => verifyRetainedEndpointAuthoritySource({ ...f.source, channel: changedChannel }, f.expected));
  const changedRecord = signed({ ...f.record, sourceRequestId: '019a0011-0000-7000-8000-000000000002' }, 'recordDigest');
  assert.throws(() => validateRetainedEndpointResult(f.source.operation, [changedRecord]));
  let read = 0; const fake = { get operation() { read++; throw new Error('getter'); } };
  assert.throws(() => verifyRetainedEndpointAuthoritySource(fake as unknown as typeof f.source, f.expected)); assert.equal(read, 0);
});
