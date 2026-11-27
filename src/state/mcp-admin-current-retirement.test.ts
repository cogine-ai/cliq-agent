// Pure inert historical data. No fixture below is a native receipt, physical
// observation, loaded addon, StateOwner, SQLite row or death proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { decodeAdminProbeClosureEvidence } from '../kernel/mcp.js';
import type { McpAdminOriginalRetirement } from '../sandbox/mcp-admin-retirement.js';
import type { AdminMcpNativeLifecycle } from './native-owner.js';
import { assertMcpAdminCurrentRetirementData } from './mcp-admin-current-retirement.js';

const at = '2026-11-03T00:00:00.000Z', later = '2026-11-03T00:01:00.000Z', hash = canonicalSha256;
function fixture() {
  const originalBytes = Buffer.from('inert original byte identity; not a native capture');
  const directory = { deviceId: '1', fileId: '2', ownerUid: 1000 }, process = { pid: 100, processStartToken: 'inert-process-start' };
  const binding = { adminOperationId: 'admin', attempt: 1, principalId: 'principal', nonce: 'a'.repeat(64),
    targetRef: hash('target'), targetDigest: hash('target-digest'), probePayloadCoreRef: hash('core'), probePayloadCoreDigest: hash('core-digest'),
    plannedContainmentRef: hash('plan'), plannedContainmentDigest: hash('plan-digest'), sandboxLaunchSpecRef: hash('spec'), sandboxLaunchSpecDigest: hash('spec-digest') };
  const observation = { pid: 101, processStartToken: 'inert-server-start', namespaceInitStartToken: 'inert-init-start', namespaceInitPid: 102,
    cgroupId: '3', pidNamespaceId: '4', cgroupPopulated: 1, namespaceInitDeadAndReaped: 0, remainingTrackedDescendants: 1, observedAtMs: Date.parse(at) };
  const lifecycle: AdminMcpNativeLifecycle = { schemaVersion: 1, format: 'cliq-mcp-admin-native-lifecycle-v1', binding,
    birthIdentity: directory, privateParentIdentity: directory, originalSupervisor: process, stateRootIdentity: directory, runtimeIdentity: directory,
    controller: { pid: 103, processStartToken: 'inert-controller-start' }, reservation: { cgroupName: 'inert-cgroup', cgroupDevice: '5', cgroupInode: '3' },
    containment: observation, retirement: { ...observation, cgroupPopulated: 0, namespaceInitDeadAndReaped: 1, remainingTrackedDescendants: 0 },
    joined: { deathJoined: true, outputCustodyRetired: true, protocolCompleted: true }, progressKind: 9, progressDigest: hash('inert-progress') };
  const current: McpAdminOriginalRetirement = { schemaVersion: 1, format: 'cliq-mcp-admin-original-retirement-v1', transport: 'streamable_http',
    originalBinding: binding, originalLifecycleRef: sha256Bytes(originalBytes), originalLifecycleByteCount: originalBytes.length,
    currentObserver: { supervisorInstanceId: 'supervisor', stateOwnerEpoch: 2, supervisorPid: process.pid, supervisorStartToken: process.processStartToken },
    stateRootIdentity: directory, runtimeIdentity: directory, privateParentIdentity: directory, birthIdentity: directory, controllerRootIdentity: directory,
    originalController: lifecycle.controller, originalReservation: { cgroupName: 'inert-cgroup', deviceId: '5', fileId: '3' }, observedAtMs: Date.parse(later),
    originalControllerDead: true, originalProcessesDead: true, originalReservationAbsent: true, originalControllerLeafAbsent: true, originalInputClosed: true };
  const observer = { supervisorInstanceId: 'supervisor', stateOwnerEpoch: 2, ...process, acquiredAt: at, stateRootIdentity: directory };
  return { originalBytes, lifecycle, current, observer };
}
test('current observation keeps the original retirement time and byte identity unchanged', () => {
  const data = fixture(), before = hash({ lifecycle: data.lifecycle, current: data.current, observer: data.observer }), bytesBefore = sha256Bytes(data.originalBytes);
  assert.equal(assertMcpAdminCurrentRetirementData(data.current, data.lifecycle, data.originalBytes, data.observer), data.current);
  assert.equal(data.lifecycle.retirement?.observedAtMs, Date.parse(at));
  assert.equal(hash({ lifecycle: data.lifecycle, current: data.current, observer: data.observer }), before); assert.equal(sha256Bytes(data.originalBytes), bytesBefore);
  assert.notEqual(data.current.observedAtMs, data.lifecycle.retirement?.observedAtMs);
});
test('a current data audit rejects rebinding original owner, bytes, reservation or captured directories', () => {
  const data = fixture(), { current, lifecycle, originalBytes, observer } = data;
  for (const changed of [
    { ...current, originalLifecycleRef: hash('foreign bytes') }, { ...current, originalLifecycleByteCount: originalBytes.length + 1 },
    { ...current, transport: 'stdio' as const }, { ...current, originalBinding: { ...current.originalBinding, nonce: 'b'.repeat(64) } },
    { ...current, originalController: { ...current.originalController, pid: 104 } },
    { ...current, originalReservation: { ...current.originalReservation, fileId: 'other' } },
    { ...current, birthIdentity: { ...current.birthIdentity, fileId: 'other' } },
    { ...current, currentObserver: { ...current.currentObserver, stateOwnerEpoch: 3 } },
    { ...current, currentObserver: { ...current.currentObserver, supervisorStartToken: 'later-process' } },
    { ...current, observedAtMs: Date.parse(at) - 1 }
  ]) assert.throws(() => assertMcpAdminCurrentRetirementData(changed, lifecycle, originalBytes, observer));
  assert.throws(() => assertMcpAdminCurrentRetirementData(current, { ...lifecycle, containment: null }, originalBytes, observer));
  assert.throws(() => assertMcpAdminCurrentRetirementData(current, lifecycle, Buffer.from('other original bytes'), observer));
  assert.throws(() => assertMcpAdminCurrentRetirementData(current, lifecycle, originalBytes, { ...observer, releasedAt: at }));
});
test('the closure current branch is closed and cannot attach to unclaimed, no-spawn or successor cleanup data', () => {
  const core = { schemaVersion: 1, format: 'cliq-admin-probe-closure-evidence-v1', adminOperationId: 'admin', attempt: 1,
    targetRef: hash('target'), targetDigest: hash('target-digest'), plannedContainmentRef: hash('plan'), plannedContainmentDigest: hash('plan-digest'),
    sandboxLaunchSpecRef: hash('spec'), sandboxLaunchSpecDigest: hash('spec-digest'), inspectorIdentityRef: hash('inspector'), inspectorIdentityDigest: hash('inspector-digest'),
    observedAt: at, closureKind: 'containment_dead', processContainmentRef: hash('containment'), dispatchId: 'dispatch', probeRequestDigest: hash('dispatch-digest'),
    deathEvidenceRef: hash('death'), deathEvidenceDigest: hash('death-digest'), nativeLifecycleRef: hash('raw'), nativeLifecycleDigest: hash('raw'),
    nativeLifecycleProjectionRef: hash('projection'), nativeLifecycleProjectionDigest: hash('projection'),
    nativeCurrentRetirement: { kind: 'original_same_owner', rawRef: hash('current-raw'), projectionRef: hash('current-projection') } };
  const seal = (value: Record<string, unknown>) => ({ ...value, evidenceDigest: hash(value) });
  assert.deepEqual(decodeAdminProbeClosureEvidence(seal(core)).nativeCurrentRetirement, core.nativeCurrentRetirement);
  for (const changed of [
    { ...core, nativeCurrentRetirement: { ...core.nativeCurrentRetirement, observedAt: later } },
    { ...core, nativeCurrentRetirement: { ...core.nativeCurrentRetirement, projectionRef: undefined } },
    { ...core, nativeCurrentRetirement: { ...core.nativeCurrentRetirement, kind: 'successor' } },
    { ...core, nativeCleanupRef: hash('cleanup'), nativeCleanupDigest: hash('cleanup') },
    { ...core, nativeLifecycleRef: undefined, nativeLifecycleDigest: undefined },
    { ...core, dispatchId: undefined, probeRequestDigest: undefined },
    { ...core, closureKind: 'no_spawn', noSpawnEvidenceRef: hash('no-spawn'), noSpawnEvidenceDigest: hash('no-spawn') }
  ]) assert.throws(() => decodeAdminProbeClosureEvidence(seal(changed)));
});
