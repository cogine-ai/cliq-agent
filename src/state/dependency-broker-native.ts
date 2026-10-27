// Purpose-specific installed ABI only. Structural types are never an installed
// selection, a release grant or a physical observation brand.
export const DEPENDENCY_BROKER_ENTRY_ID = 'dependency_registry_broker';
export const DEPENDENCY_BROKER_RELATIVE_PATH = 'native/linux-x64/linux-dependency-broker.node';
export type DependencyBrokerBinding = Readonly<{
  runId: string; opId: string; attempt: number; dispatchId: string; dispatchJournalSeq: number;
  requestRef: string; requestDigest: string; targetRef: string; targetDigest: string; grantRef: string;
  supervisorInstanceId: string; stateOwnerEpoch: number; leaseEpoch: number; brokerFenceTokenDigest: string;
}>;
export type NativeDependencyPackageReader = Readonly<{ readChunk(): Buffer; assertComplete(): void; close(): void }>;
export type NativeDependencyPackage = Readonly<{ byteCount: number; sha256: string;
  openReader(): NativeDependencyPackageReader; close(): void }>;
export type NativeDependencyGetOutcome = Readonly<{ kind: 'complete'; status: 200; receivedBytes: number; eof: true;
  packageIndex: number; attempt: 1 | 2 | 3; package: NativeDependencyPackage }> |
  Readonly<{ kind: 'integrity_mismatch' | 'http_error'; status: number; receivedBytes: number; eof: boolean; packageIndex: number; attempt: 1 | 2 | 3 }>;
export type DependencyBrokerCode = 'cancelled_or_expired' | 'clock_unavailable' | 'close_refused' | 'descriptor_endpoint_refused' |
  'descriptor_page_refused' | 'descriptor_sequence_refused' | 'descriptor_storage_refused' | 'dispatch_fence_refused' | 'integrity_refused' |
  'invocation_binding_refused' | 'operation_refused' | 'package_attempt_refused' | 'package_budget_refused' | 'package_metadata_refused' |
  'package_metadata_storage_unavailable' | 'package_reader_incomplete' | 'package_reader_refused' | 'package_readers_not_joined' |
  'package_release_refused' | 'package_storage_unavailable' | 'process_ack_refused' | 'process_release_refused' | 'request_refused' |
  'resource_retirement' | 'response_refused' | 'settlement_fence_refused' | 'tls_refused' | 'transport_interrupted' | 'worker_unavailable';
export type NativeDependencyFailureObservation = Readonly<{ brokerCode: DependencyBrokerCode; packageIndex: number; attempt: number;
  receivedBytes: number; eof: boolean; networkStarted: boolean; requestStarted: boolean; ioJoined: boolean; retryableTransport: boolean }>;
export type NativeDependencySettlementFence = Readonly<{ kind: 'dependency_settlement_fence'; brokerFenceTokenDigest: string;
  networkStarted: boolean; requestStarted: boolean; processClaimed: boolean; processJoined: boolean; processResultAvailable: boolean;
  assertCurrent(): void; close(): void }>;
export type NativeDependencyClosed = Readonly<{ kind: 'dependency_transport_closed'; brokerFenceTokenDigest: string; tokenRevoked: true;
  networkStarted: boolean; requestStarted: boolean; connectionCount: number; requestCount: number; transferredBytes: number;
  processClaimed: boolean; processJoined: boolean; processResultAcknowledged: boolean; processResultCustodyRetired: boolean;
  processResultCustodyOrigin: 'none' | 'acknowledged' | 'controller_joined'; dispatchFenceRetained: boolean; settlementFenceBorrowed: boolean }>;
export type NativeDependencyTransport = Readonly<{
  brokerFenceTokenDigest: string; ready: Promise<void>;
  registerPackagePage(pageBytes: Buffer): void; sealPackagePlan(): void;
  sealPackageInputs(bindingBytes: Buffer): Promise<void>;
  retainDispatchFence(): void; bindInvocation(bindingBytes: Buffer): void;
  connect(bindingBytes: Buffer, packageIndex: number, attempt: 1 | 2 | 3): Promise<void>;
  releaseGet(bindingBytes: Buffer, packageIndex: number, attempt: 1 | 2 | 3): Promise<NativeDependencyGetOutcome>;
  observeFailure(error: unknown): NativeDependencyFailureObservation;
  releaseProcess(bindingBytes: Buffer): void;
  acquireSettlementFence(bindingBytes: Buffer): NativeDependencySettlementFence;
  beginAcknowledgeProcessResult(bindingBytes: Buffer): void; pollProcessResultAcknowledged(): boolean;
  releaseDispatchFence(): void; close(): Promise<NativeDependencyClosed>;
}>;
export type NativeDependencyBrokerBinding = Readonly<{
  interfaceVersion: 1; maximumOwnerDataBytes: 67_108_864; descriptorPageStorageBytes: number; fixedOwnerStorageBytes: number;
  prepareDependencyTransport(configurationBytes: Buffer, trustStoreBytes: Buffer): NativeDependencyTransport;
}>;
