import assert from 'node:assert/strict';
import test from 'node:test';

import { parseExecutionProbeReceipt } from './probe-protocol.js';

const observations = {
  generationWrite: true,
  workspaceReadDenied: true,
  workspaceWriteDenied: true,
  stateReadDenied: true,
  stateWriteDenied: true,
  homeReadDenied: true,
  directNetworkDenied: true,
  daemonContained: true,
  descendantsEnumerated: true,
  forcedTerminationEmpty: true,
  helperIdentityObserved: true,
  guestImageDigestVerified: true,
  authenticatedGuestBoot: true,
  noWritableHostShare: true,
  vmStopped: true,
  workerIdentityVerified: true
} as const;

const receipt = {
  schemaVersion: 1,
  protocolVersion: 'cliq-execution-backend-probe-v1',
  backend: 'macos_vm',
  challenge: 'a'.repeat(64),
  helperDigest: '1'.repeat(64),
  kernelDigest: '2'.repeat(64),
  initramfsDigest: '3'.repeat(64),
  workerDigest: '4'.repeat(64),
  observations
} as const;

test('execution probe receipt accepts only a complete positive observation set', () => {
  const parsed = parseExecutionProbeReceipt(JSON.stringify(receipt));

  assert.equal(parsed.backend, 'macos_vm');
  assert.deepEqual(parsed.observations, observations);
  assert.equal(Object.isFrozen(parsed.observations), true);
});

test('execution probe receipt rejects false observations and shape extensions', () => {
  assert.throws(
    () =>
      parseExecutionProbeReceipt(
        JSON.stringify({
          ...receipt,
          observations: { ...observations, directNetworkDenied: false }
        })
      ),
    /directNetworkDenied/i
  );
  assert.throws(
    () => parseExecutionProbeReceipt(JSON.stringify({ ...receipt, pid: 123 })),
    /unknown member/i
  );
  assert.throws(() => parseExecutionProbeReceipt('{'), /valid JSON/i);
});

test('Linux execution receipt requires every namespace and cgroup observation', () => {
  const linuxReceipt = {
    schemaVersion: 1,
    protocolVersion: 'cliq-execution-backend-probe-v1',
    backend: 'linux_namespace',
    challenge: 'a'.repeat(64),
    helperDigest: '1'.repeat(64),
    bubblewrapDigest: '2'.repeat(64),
    observations: {
      generationWrite: true,
      workspaceReadDenied: true,
      workspaceWriteDenied: true,
      stateReadDenied: true,
      stateWriteDenied: true,
      homeReadDenied: true,
      directNetworkDenied: true,
      daemonContained: true,
      descendantsEnumerated: true,
      forcedTerminationEmpty: true,
      helperIdentityObserved: true,
      workerIdentityVerified: true,
      userNamespace: true,
      mountNamespace: true,
      networkNamespace: true,
      pidNamespace: true,
      cgroupV2: true,
      cgroupOwned: true,
      cgroupFreeze: true,
      cgroupKill: true,
      cgroupEmpty: true,
      resourceLimits: true,
      subreaper: true,
      noNewPrivileges: true
    }
  } as const;

  const parsed = parseExecutionProbeReceipt(JSON.stringify(linuxReceipt));
  assert.equal(parsed.backend, 'linux_namespace');
  assert.equal(parsed.observations.cgroupKill, true);

  assert.throws(
    () =>
      parseExecutionProbeReceipt(
        JSON.stringify({
          ...linuxReceipt,
          observations: { ...linuxReceipt.observations, cgroupEmpty: false }
        })
      ),
    /cgroupEmpty/i
  );
});
