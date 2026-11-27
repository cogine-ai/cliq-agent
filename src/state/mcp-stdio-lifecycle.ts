// Closed native historical projections only. Reading data never supplies
// a current process, scope, cleanup permission or remote-effect conclusion.
import type { AdminMcpInputBinding } from './native-owner.js';
export type McpStdioDirectoryIdentity = Readonly<{ deviceId: string; fileId: string; ownerUid: number }>;
export type McpStdioProcessIdentity = Readonly<{ pid: number; processStartToken: string }>;
export type AdminMcpStdioInputBinding = AdminMcpInputBinding & Readonly<{
  originalSupervisorPid: number;
  originalSupervisorStartToken: string;
}>;
export type RunMcpStdioInputBinding = Readonly<{
  runId: string; principalId: string; launchOpId: string; batchItemId: string; callId: string; workerLaunchId: string;
  supervisorInstanceId: string; nonce: string; registryRef: string; manifestDigest: string; toolRequestRef: string; toolRequestDigest: string;
  requestRef: string; requestDigest: string; targetRef: string; targetDigest: string; grantRef: string; grantDigest: string;
  plannedContainmentRef: string; plannedContainmentDigest: string; sandboxLaunchSpecRef: string; sandboxLaunchSpecDigest: string;
  attempt: number; lifecycleSeq: number; callIndex: number; leaseEpoch: number; stateOwnerEpoch: number; callDeadlineMs: number; launchDeadlineMs: number;
  originalSupervisorPid: number; originalSupervisorStartToken: string;
}>;
export type McpStdioInputBinding = (AdminMcpStdioInputBinding & Readonly<{ kind: 'admin' }>) |
  (RunMcpStdioInputBinding & Readonly<{ kind: 'run' }>);
export type McpStdioScopeObservation = Readonly<{
  pid: number; processStartToken: string; namespaceInitStartToken: string; namespaceInitPid: number;
  cgroupId: string; pidNamespaceId: string; cgroupPopulated: number; namespaceInitDeadAndReaped: number;
  remainingTrackedDescendants: number; observedAtMs: number;
}>;
export type McpStdioNativeLifecycle = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-stdio-native-lifecycle-v1'; binding: McpStdioInputBinding;
  originalSupervisor: McpStdioProcessIdentity;
  stateRootIdentity: McpStdioDirectoryIdentity; runtimeIdentity: McpStdioDirectoryIdentity;
  privateParentIdentity: McpStdioDirectoryIdentity; birthIdentity: McpStdioDirectoryIdentity;
  controller: McpStdioProcessIdentity;
  images: Readonly<{ server: Readonly<{ digest: string; byteCount: number }>; client: Readonly<{ digest: string; byteCount: number }>;
    isolation: Readonly<{ digest: string; byteCount: number }>; recipe: Readonly<{ digest: string; byteCount: number }> }>;
  reservation: Readonly<{ cgroupName: string; cgroupDevice: string; cgroupInode: string }>;
  containment: McpStdioScopeObservation | null;
  retirement: McpStdioScopeObservation | null;
  joined: Readonly<{ deathJoined: boolean; outputCustodyRetired: boolean; protocolCompleted: boolean; execReleased: boolean; effectReleased: boolean;
    responseRefused: boolean; ownerDrained: boolean; spawnAttempted: boolean }>;
  progressKind: number; progressDigest: string;
}>;
export type McpStdioNativeCleanup = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-stdio-native-cleanup-v1'; originalBinding: McpStdioInputBinding;
  originalBirthDigest: string; originalController: McpStdioProcessIdentity;
  originalReservation: Readonly<{ cgroupName: string; cgroupDevice: string; cgroupInode: string }>;
  currentChecker: Readonly<{ supervisorInstanceId: string; stateOwnerEpoch: number; supervisorPid: number; supervisorStartToken: string;
    controllerPid: number; controllerStartToken: string }>;
  retirement: McpStdioScopeObservation;
  observedAtMs: number; priorSupervisorDead: true; priorControllerDead: true; outputCustodyRetired: true; remainingDescendants: 0;
}>;

export type RecoveryMcpStdioInputBinding = import('./mcp-stdio-broker-native.js').McpStdioRecoveryBinding & Readonly<{
  originalSupervisorPid: number; originalSupervisorStartToken: string;
}>;
export type McpStdioRecoveryNativeLifecycle = Omit<McpStdioNativeLifecycle, 'format' | 'binding' | 'joined'> & Readonly<{
  format: 'cliq-mcp-stdio-recovery-native-lifecycle-v1';
  binding: RecoveryMcpStdioInputBinding & Readonly<{ kind: 'recovery' }>;
  joined: Omit<McpStdioNativeLifecycle['joined'], 'effectReleased'> & Readonly<{ statusReleased: boolean }>;
}>;
export type McpStdioRecoveryNativeCleanup = Omit<McpStdioNativeCleanup, 'format' | 'originalBinding'> & Readonly<{
  format: 'cliq-mcp-stdio-recovery-native-cleanup-v1';
  originalBinding: RecoveryMcpStdioInputBinding & Readonly<{ kind: 'recovery' }>;
}>;

