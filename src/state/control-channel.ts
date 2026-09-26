import type { LocalControlChannelIdentityV1 } from '../kernel/types.js';
import { consumeAuthenticatedUdsRequest } from '../control/request-authority.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import {
  decodeControlChannel,
  decodeLocalPrincipalIdentity,
  decodeLocalSocketPeerObservation,
  decodePlatformProcessIdentity,
  decodeStateLockIdentity,
  decodeStateRootIdentity
} from './decoders.js';
import { KernelStorageError } from './errors.js';
import { readLatestStateOwner, type StateOwnerContext } from './state-owner.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readCanonicalArtifact } from './agent-context.js';

/** Rewalk a historical channel against this database's retained StateRoot, without authenticating new input. */
export async function readHistoricalControlChannel(driver: SqliteDriver, artifacts: ArtifactCatalog,
  input: { channelIdentityRef: string; channelIdentityDigest: string; principalId: string }) {
  const owner = readLatestStateOwner(driver);
  if (!owner) throw new TypeError('control history has no retained state owner');
  const lock = decodeStateLockIdentity(await readCanonicalArtifact(artifacts, owner.stateLockIdentityRef));
  if (lock.identityDigest !== owner.stateLockIdentityDigest) throw new TypeError('control history state-owner lock mismatch');
  return readRetainedControlChannelClosure(artifacts, {
    stateRootIdentityRef: lock.stateRootIdentityRef, stateRootIdentityDigest: lock.stateRootIdentityDigest,
    filesystem: { root: { ownerUid: lock.ownerUid } }
  }, input);
}

export async function validateControlChannelClosure(
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: {
    channelIdentityRef: string;
    channelIdentityDigest: string;
    principalId: string;
  }
): Promise<{ channel: LocalControlChannelIdentityV1; metadata: PublishedArtifact[] }> {
  const closure = await readRetainedControlChannelClosure(artifacts, owner, input);
  const channel = closure.channel;
  if (channel.transport.kind === 'uds_peer') {
    consumeAuthenticatedUdsRequest({
      ownerEpoch: owner.ownerEpoch,
      principalId: input.principalId,
      channelIdentityRef: input.channelIdentityRef,
      channelIdentityDigest: input.channelIdentityDigest
    });
    return closure;
  }
  const [processIdentity, ownerProcessIdentity] = await Promise.all([
    artifacts.readCanonical(channel.transport.processIdentityRef).then(decodePlatformProcessIdentity),
    artifacts.readCanonical(owner.processIdentityRef).then(decodePlatformProcessIdentity)
  ]);
  if (ownerProcessIdentity.identityDigest !== owner.processIdentityDigest ||
      processIdentity.ownerUid !== ownerProcessIdentity.ownerUid ||
      processIdentity.platform !== ownerProcessIdentity.platform || processIdentity.pid !== ownerProcessIdentity.pid ||
      processIdentity.pid !== process.pid || processIdentity.processStartToken !== ownerProcessIdentity.processStartToken ||
      processIdentity.executableImageDigest !== ownerProcessIdentity.executableImageDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel process identity does not match the current owner');
  }
  return closure;
}

/** Historical audit only. A control-row owner must also bind these bytes; this never authenticates a new request. */
export async function readRetainedControlChannelClosure(
  artifacts: ArtifactCatalog,
  owner: Pick<StateOwnerContext, 'stateRootIdentityRef' | 'stateRootIdentityDigest'> & {
    filesystem: { root: Pick<StateOwnerContext['filesystem']['root'], 'ownerUid'> };
  },
  input: { channelIdentityRef: string; channelIdentityDigest: string; principalId: string }
): Promise<{ channel: LocalControlChannelIdentityV1; metadata: PublishedArtifact[] }> {
  const channel = decodeControlChannel(await artifacts.readCanonical(input.channelIdentityRef));
  if (
    channel.channelIdentityDigest !== input.channelIdentityDigest ||
    channel.principalId !== input.principalId
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel identity does not match the caller');
  }
  const principal = decodeLocalPrincipalIdentity(
    await artifacts.readCanonical(channel.principalIdentityRef)
  );
  if (
    principal.identityDigest !== channel.principalIdentityDigest ||
    principal.principalId !== input.principalId ||
    principal.stateRootIdentityRef !== owner.stateRootIdentityRef ||
    principal.stateRootIdentityDigest !== owner.stateRootIdentityDigest ||
    principal.effectiveUid !== owner.filesystem.root.ownerUid
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel principal identity is not current');
  }
  const metadata = await Promise.all([
    artifacts.describe(input.channelIdentityRef, 'application/json', 'cliq-local-control-channel-identity-v1'),
    artifacts.describe(channel.principalIdentityRef, 'application/json', 'cliq-local-principal-identity-v1')
  ]);
  if (channel.transport.kind === 'in_process') {
    const processIdentity = decodePlatformProcessIdentity(await artifacts.readCanonical(channel.transport.processIdentityRef));
    if (
      processIdentity.identityDigest !== channel.transport.processIdentityDigest ||
      processIdentity.ownerUid !== owner.filesystem.root.ownerUid ||
      processIdentity.platform !== principal.platform ||
      processIdentity.observedAt !== channel.openedAt
    ) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel process identity does not match');
    }
    metadata.push(
      await artifacts.describe(
        channel.transport.processIdentityRef,
        'application/json',
        'cliq-platform-process-identity-v1'
      )
    );
  } else {
    const observation = decodeLocalSocketPeerObservation(
      await artifacts.readCanonical(channel.transport.peerObservationRef)
    );
    const root = decodeStateRootIdentity(await artifacts.readCanonical(owner.stateRootIdentityRef));
    if (
      root.identityDigest !== owner.stateRootIdentityDigest ||
      observation.observationDigest !== channel.transport.peerObservationDigest ||
      observation.stateRootIdentityRef !== owner.stateRootIdentityRef ||
      observation.stateRootIdentityDigest !== owner.stateRootIdentityDigest ||
      observation.platform !== principal.platform ||
      observation.endpoint.ownerUid !== owner.filesystem.root.ownerUid ||
      observation.peerUid !== owner.filesystem.root.ownerUid ||
      observation.observedAt > channel.openedAt
    ) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'UDS peer observation does not close over the retained principal and StateRoot');
    }
    metadata.push(await artifacts.describe(
      channel.transport.peerObservationRef,
      'application/json',
      'cliq-local-socket-peer-observation-v2'
    ));
  }
  return { channel, metadata };
}
