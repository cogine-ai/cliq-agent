import type { LocalControlChannelIdentityV1 } from '../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import {
  decodeControlChannel,
  decodeLocalPrincipalIdentity,
  decodePlatformProcessIdentity
} from './decoders.js';
import { KernelStorageError } from './errors.js';
import type { StateOwnerContext } from './state-owner.js';

export async function validateControlChannelClosure(
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: {
    channelIdentityRef: string;
    channelIdentityDigest: string;
    principalId: string;
  }
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
    principal.effectiveUid !== owner.filesystem.ownerUid
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel principal identity is not current');
  }
  const metadata = await Promise.all([
    artifacts.describe(input.channelIdentityRef, 'application/json', 'cliq-local-control-channel-identity-v1'),
    artifacts.describe(channel.principalIdentityRef, 'application/json', 'cliq-local-principal-identity-v1')
  ]);
  if (channel.transport.kind === 'in_process') {
    const [processIdentity, ownerProcessIdentity] = await Promise.all([
      artifacts
        .readCanonical(channel.transport.processIdentityRef)
        .then(decodePlatformProcessIdentity),
      artifacts.readCanonical(owner.processIdentityRef).then(decodePlatformProcessIdentity)
    ]);
    if (
      processIdentity.identityDigest !== channel.transport.processIdentityDigest ||
      ownerProcessIdentity.identityDigest !== owner.processIdentityDigest ||
      processIdentity.platform !== ownerProcessIdentity.platform ||
      processIdentity.pid !== ownerProcessIdentity.pid ||
      processIdentity.pid !== process.pid ||
      processIdentity.processStartToken !== ownerProcessIdentity.processStartToken ||
      processIdentity.ownerUid !== ownerProcessIdentity.ownerUid ||
      processIdentity.ownerUid !== owner.filesystem.ownerUid ||
      processIdentity.executableImageDigest !== ownerProcessIdentity.executableImageDigest ||
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
    throw new KernelStorageError(
      'ARTIFACT_MISMATCH',
      'UDS control channels require a closed peer-observation decoder and native credential capture'
    );
  }
  return { channel, metadata };
}
