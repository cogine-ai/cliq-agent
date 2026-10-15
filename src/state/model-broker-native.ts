// Private installed ABI. Only the held, signed provider-adapter image creates
// these handles; a structural value is not a release or retirement proof.
import type { SecretServiceObservation, SecretServiceSelector } from './credential-platform.js';
import { KernelStorageError } from './errors.js';

/** Fixed diagnosis from the actual installed native adapter, never authority,
 * a transport outcome proof, remote text, or permission to refund/retry. */
export class InstalledModelBrokerRefusalError extends KernelStorageError {
  readonly reason = 'broker_response_refused' as const;
  constructor() { super('RECOVERY_REQUIRED', 'installed model broker refused the response'); }
}

export const MODEL_BROKER_ENTRY_ID = 'openai-compatible-broker-v1';
export const MODEL_BROKER_RELATIVE_PATH = 'native/linux-x64/linux-model-broker.node';
export type ModelBrokerBinding = Readonly<{
  runId: string; opId: string; attempt: number; dispatchId: string; dispatchJournalSeq: number;
  requestRef: string; requestDigest: string; targetRef: string; targetDigest: string; grantRef: string;
  supervisorInstanceId: string; stateOwnerEpoch: number; leaseEpoch: number; brokerFenceTokenDigest: string;
}>;
export type ModelBrokerClosed = Readonly<{
  kind: 'broker_transport_closed'; brokerFenceTokenDigest: string; bodyBytesDigest: string;
  networkStarted: boolean; requestStarted: boolean; tokenRevoked: true; matchingActiveReleaseCount: 0;
}>;
export type NativeModelTransport = Readonly<{
  brokerFenceTokenDigest: string;
  /** The real owner is closeable before preparation I/O settles. A refusal or
   * cancellation rejects only after its native resource retirement joins. */
  ready: Promise<void>;
  connect(binding: ModelBrokerBinding): Promise<void>;
  releaseBody(binding: ModelBrokerBinding): Promise<Readonly<{
    kind: 'complete' | 'prefix_over_limit'; status: number;
    mediaType: 'application/json' | 'text/event-stream' | 'application/x-ndjson' | 'unknown'; bodyBytes: Buffer;
  }>>;
  close(): Promise<ModelBrokerClosed>;
}>;
export type NativeModelBrokerBinding = Readonly<{
  interfaceVersion: 2;
  prepareModelTransport(input: Readonly<{
    provider: 'openai-compatible'; selector: SecretServiceSelector; expectedObservation: SecretServiceObservation;
    target: Readonly<{ hostAscii: string; port: number; basePath: string; serverNameAscii: string; spkiSha256Pins: readonly string[] }>;
    trustStoreBytes: Buffer; trustStoreDigest: string; requestPath: '/chat/completions';
    bodyBytes: Buffer; bodyBytesDigest: string;
  }>): NativeModelTransport;
}>;
