import type { InstalledControlFeature, InstalledControlRequestV1, InstalledControlResponseFor } from '../control/v1.js';

/** Public copied client data only. This module intentionally imports no file,
 * installation, peer, credential or execution implementation. */
export type ClientStateRootIdentity = Readonly<{ deviceId: string; fileId: string; ownerUid: number }>;
export type PendingClientMutation = Extract<InstalledControlRequestV1, { requestId: string; requestDigest: string }>;
export type PendingRequestMetadata = Readonly<{
  schemaVersion: 1; protocolVersion: 1; method: PendingClientMutation['method']; requestId: string; requestDigest: string;
  stateRoot: ClientStateRootIdentity; sourceBundleDigest: string; controlSourceDigest: string;
}>;
export type PendingRequestRecord = Readonly<{
  metadata: PendingRequestMetadata; request: PendingClientMutation; bytes: Buffer;
  response?: InstalledControlResponseFor<PendingClientMutation['method']>;
}>;
export type PendingRequestSummary = Readonly<{
  metadata: PendingRequestMetadata; state: 'unresolved' | 'known'; knownRunId?: string; knownSessionId?: string;
}>;
/** Disk reads are historical client data. Explicit replay always requires a
 * real authenticated wire response and never promotes these cached bytes. */
export type ClientRequests = Readonly<{
  list(): Promise<readonly PendingRequestSummary[]>;
  load(requestId: string): Promise<PendingRequestRecord>;
  replay(requestId: string, expected?: PendingClientMutation): Promise<InstalledControlResponseFor<InstalledControlFeature>>;
  acknowledge(requestId: string): Promise<void>;
}>;
