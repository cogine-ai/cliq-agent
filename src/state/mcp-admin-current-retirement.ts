// Data audit of an independent current observation. The actual native scope
// creates and asserts its opaque observation; these readers cannot do so.
import { sha256Bytes, parseCanonicalTime } from '../kernel/identity.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { AdminProbeClosureEvidenceV1 } from '../kernel/mcp.js';
import type { McpAdminOriginalRetirement, NativeMcpAdminOriginalRetirement } from '../sandbox/mcp-admin-retirement.js';
import { requireEqual } from '../policy/runtime-authority.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';
import { KernelStorageError } from './errors.js';
import { decodeMcpAdminOriginalRetirementData, type AdminMcpNativeLifecycle } from './native-owner.js';
import type { McpStdioNativeLifecycle } from './mcp-stdio-lifecycle.js';

type Lifecycle = AdminMcpNativeLifecycle | McpStdioNativeLifecycle;
export type McpAdminRetirementScope = Readonly<{
  reobserveRetirement(): NativeMcpAdminOriginalRetirement;
  assertRetirementObservation(proof: NativeMcpAdminOriginalRetirement): void;
}>;
export type McpAdminRetirementObserver = Readonly<{ supervisorInstanceId: string; stateOwnerEpoch: number;
  pid: number; processStartToken: string; acquiredAt: string; releasedAt?: string;
  stateRootIdentity: Readonly<{ deviceId: string; fileId: string; ownerUid: number }> }>;
function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP current retirement does not observe its complete original closed owner/domain'); }
/** Closed, already-decoded data only; successful audit grants no authority. */
export function assertMcpAdminCurrentRetirementData(current: McpAdminOriginalRetirement, lifecycle: Lifecycle,
  originalBytes: Uint8Array, observer: McpAdminRetirementObserver) {
  if (!lifecycle.retirement || !lifecycle.containment || !lifecycle.joined.deathJoined || !lifecycle.joined.outputCustodyRetired ||
      current.originalLifecycleRef !== sha256Bytes(originalBytes) || current.originalLifecycleByteCount !== originalBytes.byteLength ||
      current.transport !== (lifecycle.format === 'cliq-mcp-admin-native-lifecycle-v1' ? 'streamable_http' : 'stdio') ||
      current.currentObserver.supervisorInstanceId !== observer.supervisorInstanceId || current.currentObserver.stateOwnerEpoch !== observer.stateOwnerEpoch ||
      current.currentObserver.supervisorPid !== observer.pid || current.currentObserver.supervisorStartToken !== observer.processStartToken ||
      lifecycle.originalSupervisor.pid !== observer.pid || lifecycle.originalSupervisor.processStartToken !== observer.processStartToken ||
      current.observedAtMs < lifecycle.retirement.observedAtMs || current.observedAtMs < parseCanonicalTime(observer.acquiredAt) ||
      observer.releasedAt !== undefined && current.observedAtMs > parseCanonicalTime(observer.releasedAt) ||
      !current.originalControllerDead || !current.originalProcessesDead || !current.originalReservationAbsent ||
      !current.originalControllerLeafAbsent || !current.originalInputClosed) invalid();
  const binding = lifecycle.binding;
  if ('kind' in binding) {
    if (binding.kind !== 'admin' || binding.originalSupervisorPid !== observer.pid || binding.originalSupervisorStartToken !== observer.processStartToken) invalid();
    const { kind: _kind, originalSupervisorPid: _pid, originalSupervisorStartToken: _start, ...original } = binding;
    requireEqual(current.originalBinding, original, 'MCP current same-owner original stdio input');
  } else requireEqual(current.originalBinding, binding, 'MCP current same-owner original HTTP input');
  requireEqual(current.originalController, lifecycle.controller, 'MCP current same-owner original controller');
  requireEqual(current.originalReservation, { cgroupName: lifecycle.reservation.cgroupName,
    deviceId: lifecycle.reservation.cgroupDevice, fileId: lifecycle.reservation.cgroupInode }, 'MCP current same-owner original cgroup reservation');
  const directory = (value: Readonly<{ deviceId: string; fileId: string; ownerUid: number }>) =>
    ({ deviceId: value.deviceId, fileId: value.fileId, ownerUid: value.ownerUid });
  requireEqual(current.stateRootIdentity, directory(observer.stateRootIdentity), 'MCP current same-owner StateRoot history');
  for (const key of ['stateRootIdentity', 'runtimeIdentity', 'privateParentIdentity', 'birthIdentity'] as const)
    requireEqual(current[key], directory(lifecycle[key]), 'MCP current same-owner original physical directory');
  return current;
}
export async function readMcpAdminCurrentRetirementData(artifacts: ArtifactCatalog, closure: AdminProbeClosureEvidenceV1,
  originalBytes: Buffer, lifecycle: Lifecycle, observer: McpAdminRetirementObserver) {
  if (!closure.nativeCurrentRetirement) return undefined;
  const root = closure.nativeCurrentRetirement;
  const raw = await artifacts.readBoundedBytes(root.rawRef, 65_536);
  if (sha256Bytes(raw) !== root.rawRef) invalid();
  const current = decodeMcpAdminOriginalRetirementData(raw, originalBytes), projection = await readCanonicalArtifact(artifacts, root.projectionRef);
  if (canonicalSha256(projection) !== root.projectionRef) invalid();
  requireEqual(current, projection, 'MCP current original-owner full native byte projection');
  return assertMcpAdminCurrentRetirementData(current, lifecycle, originalBytes, observer);
}
export async function publishMcpAdminCurrentRetirement(artifacts: ArtifactCatalog, scope: McpAdminRetirementScope,
  originalBytes: Buffer, lifecycle: Lifecycle, observer: McpAdminRetirementObserver) {
  const proof = scope.reobserveRetirement(); scope.assertRetirementObservation(proof);
  const raw = proof.copyData(), current = decodeMcpAdminOriginalRetirementData(raw, originalBytes);
  assertMcpAdminCurrentRetirementData(current, lifecycle, originalBytes, observer);
  const rawArtifact = await artifacts.publishBytes(raw, 'application/octet-stream', 'cliq-mcp-admin-original-retirement-bytes-v1');
  const projection = await artifacts.publishCanonical(current, current.format);
  return { proof, current, metadata: [rawArtifact, projection],
    edge: { kind: 'original_same_owner' as const, rawRef: rawArtifact.ref, projectionRef: projection.ref },
    assertCurrent() { scope.assertRetirementObservation(proof); } };
}
