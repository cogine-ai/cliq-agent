// Private selected-image ABI. These opaque native objects are never control
// data, CAS artifacts, caller evidence or structural release/death proofs.
import type { SecretServiceObservation, SecretServiceSelector } from './credential-platform.js';
import { KernelStorageError } from './errors.js';
export const MCP_HTTP_BROKER_ENTRY_ID = 'mcp-streamable-http-broker-v1';
export const MCP_HTTP_BROKER_RELATIVE_PATH = 'native/linux-x64/linux-mcp-http-broker.node';
export const MCP_ADMIN_HELPER_ENTRY_ID = 'mcp-http-admin-probe-v1';
export const MCP_ADMIN_HELPER_RELATIVE_PATH = 'helpers/mcp-http-admin-probe.mjs';
export class InstalledMcpBrokerRefusalError extends KernelStorageError {
  readonly reason = 'broker_response_refused' as const;
  constructor() {
    super('RECOVERY_REQUIRED', 'installed MCP broker refused the response');
  }
}
export type McpHttpPhase = 'initialize' | 'initialized' | 'tools_list' | 'tools_call';
export type AdminMcpHttpPhase = Exclude<McpHttpPhase, 'tools_call'>;
export type RunMcpHttpBinding = Readonly<{
  runId: string;
  opId: string;
  attempt: number;
  dispatchId: string;
  dispatchJournalSeq: number;
  requestRef: string;
  requestDigest: string;
  targetRef: string;
  targetDigest: string;
  grantRef: string;
  grantDigest: string;
  registryRef: string;
  manifestDigest: string;
  toolContractDigest: string;
  batchItemId: string;
  callId: string;
  callIndex: number;
  supervisorInstanceId: string;
  stateOwnerEpoch: number;
  workerLaunchId: string;
  leaseEpoch: number;
  brokerFenceTokenDigest: string;
  deadlineMs: number;
}>;
export type AdminMcpHttpBinding = Readonly<{
  adminOperationId: string;
  attempt: number;
  principalId: string;
  method: 'mcp.register' | 'mcp.refresh';
  controlRequestDigest: string;
  targetRef: string;
  targetDigest: string;
  probePayloadCoreRef: string;
  probePayloadCoreDigest: string;
  probeRequestDigest: string;
  dispatchId: string;
  supervisorInstanceId: string;
  stateOwnerEpoch: number;
  processContainmentRef: string;
  plannedContainmentRef: string;
  plannedContainmentDigest: string;
  sandboxLaunchSpecRef: string;
  sandboxLaunchSpecDigest: string;
  deadlineMs: number;
}>;
export type FrozenMcpHttpInput = Readonly<{
  authentication: Readonly<{
    kind: 'public';
  }> | Readonly<{
    kind: 'bearer';
    selector: SecretServiceSelector;
    expectedObservation: SecretServiceObservation;
  }>;
  target: Readonly<{
    hostAscii: string;
    port: number;
    path: string;
    serverNameAscii: string;
    spkiSha256Pins: readonly string[];
  }>;
  trustStoreBytes: Buffer;
  trustStoreDigest: string;
  maximumResponseBytes: number;
  remainingDeadlineMs: number;
  recipe: readonly Readonly<{
    phase: McpHttpPhase;
    bodyBytes: Buffer;
    bodyBytesDigest: string;
  }>[];
}>;
declare const nativeReceipt: unique symbol;
declare const nativeBytes: unique symbol;
declare const nativeJoin: unique symbol;
declare const nativePeer: unique symbol;
declare const nativeAdminScript: unique symbol;
export type NativeMcpAdminProbeImage = Readonly<{
  readonly [nativeAdminScript]: true;
  identity: Readonly<{
    sha256: string;
    byteCount: number;
  }>;
  close(): void;
}>;
export type NativeMcpReceipt = Readonly<{
  readonly [nativeReceipt]: true;
}>;
export type NativeMcpProtocolPeer = Readonly<{
  readonly [nativePeer]: true;
}>;
export type NativeMcpScreenedBytes = Readonly<{
  readonly [nativeBytes]: true;
  copy(): Buffer;
}>;
export type NativeMcpResponseJoin = Readonly<{
  readonly [nativeJoin]: true;
}>;
export type NativeMcpMessage = Readonly<{
  kind: 'stage_requested';
  phase: AdminMcpHttpPhase;
}> | Readonly<{
  kind: 'stage_completed';
  phase: 'initialized';
}> | Readonly<{
  kind: 'notification' | 'ping' | 'response';
  phase: McpHttpPhase;
  ordinal: number;
  messageBytes: Buffer;
  messageDigest: string;
  receipt: NativeMcpReceipt;
}>;
export type NativeMcpRawResponse = Readonly<{
  mediaType: 'application/json' | 'text/event-stream';
  termination: 'http_eof' | 'sse_response_event';
  rawFinitePrefixBytes: number;
  rawFinitePrefixDigest: string;
  responseEventEndOffset?: number;
  receivedTailBytes: number;
  screenedRawCapture: NativeMcpScreenedBytes;
  actualResponseJoin: NativeMcpResponseJoin;
}>;
/** Original screened matching event custody after a specific full-prefix
 * NoEcho refusal. These metadata never expose or claim to replay unsafe tail. */
export type NativeMcpUnusableResponse = Readonly<{
  kind: 'mcp_known_response_unusable';
  mediaType: 'text/event-stream';
  termination: 'sse_response_event';
  rawFinitePrefixBytes: number;
  rawFinitePrefixDigest: string;
  responseEventEndOffset: number;
  receivedTailBytes: number;
  reason: 'full_capture_no_echo_refused';
  actualResponseJoin: NativeMcpResponseJoin;
}>;
type Joined = Readonly<{
  kind: 'mcp_http_owner_joined';
  networkStarted: boolean;
  requestStarted: boolean;
  setupReleased: boolean;
  effectReleased: boolean;
  completedStages: readonly McpHttpPhase[];
  tokenRevoked: true;
  matchingActiveReleaseCount: 0;
  networkJoined: true;
  tasksJoined: true;
}>;
export type NativeMcpRunJoined = Joined & Readonly<{
  purpose: 'run';
  brokerFenceTokenDigest: string;
}>;
export type NativeMcpAdminJoined = Joined & Readonly<{
  purpose: 'admin';
  adminPeerJoined: true;
}>;
export type NativeMcpNoReleaseFence = Readonly<{
  assertHeld(): void;
  close(): void;
}>;
type ProtocolOwner<B, P extends McpHttpPhase, J> = Readonly<{
  ready: Promise<void>;
  bind(binding: B): void;
  connectStage(binding: B, phase: P): Promise<void>;
  releaseStage(binding: B, phase: P): void;
  nextMessage(): Promise<NativeMcpMessage>;
  connectPing(binding: B, receipt: NativeMcpReceipt): Promise<void>;
  releasePing(binding: B, receipt: NativeMcpReceipt): void;
  finishResponse(receipt: NativeMcpReceipt): Promise<NativeMcpRawResponse>;
  readUnusableResponse(receipt: NativeMcpReceipt): NativeMcpUnusableResponse;
  close(): Promise<J>;
  assertBinding(binding: B): void;
  assertJoined(observation: J, binding: B): void;
  assertRawResponse(receipt: NativeMcpReceipt, response: NativeMcpRawResponse): void;
  assertUnusableResponse(receipt: NativeMcpReceipt, response: NativeMcpUnusableResponse): void;
}>;
export type NativeMcpRunHttpOwner = ProtocolOwner<RunMcpHttpBinding, McpHttpPhase, NativeMcpRunJoined> & Readonly<{
  brokerFenceTokenDigest: string;
  retainDispatchFence(): void;
  acquireNoReleaseFence(binding: RunMcpHttpBinding): NativeMcpNoReleaseFence;
  releaseDispatchFence(): void;
}>;
export type NativeMcpAdminHttpOwner = ProtocolOwner<AdminMcpHttpBinding, AdminMcpHttpPhase, NativeMcpAdminJoined> & Readonly<{
  retainDomain(): void;
  attachProtocolPeer(peer: NativeMcpProtocolPeer): void;
  releaseDomain(): void;
}>;
export type NativeMcpHttpBrokerBinding = Readonly<{
  interfaceVersion: 1;
  prepareAdminHttp(input: FrozenMcpHttpInput): NativeMcpAdminHttpOwner;
  prepareRunHttp(input: FrozenMcpHttpInput): NativeMcpRunHttpOwner;
}>;
