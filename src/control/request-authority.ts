import { AsyncLocalStorage } from 'node:async_hooks';

import { KernelStorageError } from '../state/errors.js';

type AuthenticatedRequest = {
  readonly ownerEpoch: number;
  readonly principalId: string;
  readonly channelIdentityRef: string;
  readonly channelIdentityDigest: string;
  used: boolean;
};

const current = new AsyncLocalStorage<AuthenticatedRequest>();

/** The Supervisor invokes this only at the post-framing, live-identity cut. */
export function runAuthenticatedControlRequest<T>(identity: {
  ownerEpoch: number;
  principalId: string;
  channelIdentityRef: string;
  channelIdentityDigest: string;
}, dispatch: () => Promise<T>): Promise<T> {
  const request: AuthenticatedRequest = { ...identity, used: false };
  return current.run(request, dispatch);
}

/** Retained channel artifacts never reconstruct this one-use runtime authority. */
export function consumeAuthenticatedUdsRequest(identity: {
  ownerEpoch: number;
  principalId: string;
  channelIdentityRef: string;
  channelIdentityDigest: string;
}): void {
  const request = current.getStore();
  if (!request || request.used || request.ownerEpoch !== identity.ownerEpoch ||
      request.principalId !== identity.principalId ||
      request.channelIdentityRef !== identity.channelIdentityRef ||
      request.channelIdentityDigest !== identity.channelIdentityDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'UDS control request lacks a current one-use authenticated connection');
  }
  request.used = true;
}
