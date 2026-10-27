// One pure composition for the existing locked reader and its retained CAS
// projection. It supplies neither registration nor physical scope authority.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson } from '../kernel/control-wire-data.js';
import { decodeEndpointAuthorityOperation, decodeEndpointAuthorityRecord, type EndpointAuthorityOperationV1,
  type EndpointAuthorityRecordV1 } from '../kernel/credential-authority.js';
import { assertArtifactRef, parseCanonicalTime } from '../kernel/identity.js';
import type { LocalControlChannelIdentityV1, LocalPrincipalIdentityV1, PlatformProcessIdentityV1, StateRootIdentityV1 } from '../kernel/types.js';
import { decodeControlChannel, decodeLocalPrincipalIdentity, decodePlatformProcessIdentity, decodeStateRootIdentity } from './decoders.js';
import { KernelStorageError } from './errors.js';

export function verifyRetainedEndpointAuthoritySource(source: {
  operation: EndpointAuthorityOperationV1; channel: LocalControlChannelIdentityV1; principal: LocalPrincipalIdentityV1;
  root: StateRootIdentityV1; process: PlatformProcessIdentityV1;
}, expected: { principalId: string; stateRoot: StateRootIdentityV1; executableImageDigest: string }): void {
  assertControlWireJson(source); assertControlWireJson(expected); assertArtifactRef(expected.executableImageDigest);
  const operation = decodeEndpointAuthorityOperation(source.operation), channel = decodeControlChannel(source.channel);
  const principal = decodeLocalPrincipalIdentity(source.principal), root = decodeStateRootIdentity(source.root);
  const processIdentity = decodePlatformProcessIdentity(source.process);
  if (channel.transport.kind !== 'in_process' || operation.ownerPrincipalId !== expected.principalId ||
      canonicalSha256(channel) !== operation.channelIdentityRef || canonicalSha256(principal) !== channel.principalIdentityRef ||
      canonicalSha256(root) !== principal.stateRootIdentityRef || canonicalSha256(processIdentity) !== channel.transport.processIdentityRef ||
      channel.channelIdentityDigest !== operation.channelIdentityDigest || channel.principalId !== expected.principalId || channel.client !== 'cli' ||
      principal.identityDigest !== channel.principalIdentityDigest || principal.principalId !== expected.principalId ||
      principal.stateRootIdentityDigest !== root.identityDigest || canonicalSha256(root) !== canonicalSha256(expected.stateRoot) ||
      principal.platform !== root.platform || principal.effectiveUid !== root.ownerUid || processIdentity.platform !== root.platform ||
      processIdentity.ownerUid !== root.ownerUid || processIdentity.identityDigest !== channel.transport.processIdentityDigest ||
      processIdentity.executableImageDigest !== expected.executableImageDigest || processIdentity.observedAt !== channel.openedAt ||
      parseCanonicalTime(operation.committedAt) < parseCanonicalTime(channel.openedAt))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'endpoint channel closure differs');
}

export function validateRetainedEndpointResult(operation: EndpointAuthorityOperationV1, history: readonly EndpointAuthorityRecordV1[]): void {
  assertControlWireJson(operation); assertControlWireJson(history);
  operation = decodeEndpointAuthorityOperation(operation);
  if (history.length > 2) throw new KernelStorageError('RECOVERY_REQUIRED', 'endpoint history contains extra revisions');
  const record = history[operation.committedAuthorityRevision - 1];
  if (record) decodeEndpointAuthorityRecord(record);
  const core = operation.commandCore;
  if (!record || record.recordDigest !== operation.resultRecordDigest || record.ownerPrincipalId !== operation.ownerPrincipalId ||
      record.endpointRegistrationId !== operation.endpointRegistrationId ||
      parseCanonicalTime(operation.committedAt) < parseCanonicalTime(record.state === 'revoked' ? record.revokedAt : record.createdAt))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'endpoint operation historical result differs');
  if (core.kind === 'register') {
    if (record.state !== 'active' || record.expectedRegistrationArtifactRef !== core.expectedRegistrationArtifactRef ||
        !canonicalJsonBytes(record.registration).equals(canonicalJsonBytes(core.registration)) ||
        (operation.disposition === 'registered' && (record.sourceRequestId !== operation.requestId || record.sourceRequestDigest !== operation.requestDigest ||
          record.createdAt !== operation.committedAt))) throw new KernelStorageError('RECOVERY_REQUIRED', 'endpoint registration result differs');
  } else if (record.state !== 'revoked' || (operation.disposition === 'revoked' &&
      (core.expectedAuthorityRevision !== 1 || record.revokedByRequestId !== operation.requestId || record.revokedByRequestDigest !== operation.requestDigest ||
        record.revokedAt !== operation.committedAt))) throw new KernelStorageError('RECOVERY_REQUIRED', 'endpoint revocation result differs');
}
