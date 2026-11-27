// Independent current read-only observation of one original, already fully
// closed Admin scope. It is never execution, cleanup or a replacement kind9.
import type { AdminMcpInputBinding } from '../state/native-owner.js';
type Identity = Readonly<{ deviceId: string; fileId: string; ownerUid: number }>;
type Process = Readonly<{ pid: number; processStartToken: string }>;
export type McpAdminOriginalRetirement = Readonly<{
  schemaVersion: 1;
  format: 'cliq-mcp-admin-original-retirement-v1';
  transport: 'streamable_http' | 'stdio';
  originalBinding: AdminMcpInputBinding;
  originalLifecycleRef: string;
  originalLifecycleByteCount: number;
  currentObserver: Readonly<{
    supervisorInstanceId: string; stateOwnerEpoch: number;
    supervisorPid: number; supervisorStartToken: string;
  }>;
  stateRootIdentity: Identity;
  runtimeIdentity: Identity;
  privateParentIdentity: Identity;
  birthIdentity: Identity;
  controllerRootIdentity: Identity;
  originalController: Process;
  originalReservation: Readonly<{ cgroupName: string; deviceId: string; fileId: string }>;
  observedAtMs: number;
  originalControllerDead: true;
  originalProcessesDead: true;
  originalReservationAbsent: true;
  originalControllerLeafAbsent: true;
  originalInputClosed: true;
}>;
declare const originalRetirement: unique symbol;
export type NativeMcpAdminOriginalRetirement = Readonly<{
  readonly [originalRetirement]: true;
  copyData(): Buffer;
}>;
