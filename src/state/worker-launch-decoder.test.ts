import assert from 'node:assert/strict';
import { test } from 'node:test';

import { identityHash } from '../kernel/identity.js';
import { decodeWorkerLaunch } from './invariants.js';

function logicalPreparation() {
  const runId = 'preparing-run', sourceCheckpointId = 'preparing-checkpoint';
  const sourceWorkspaceStateRef = '1'.repeat(64), generationCreationNonceDigest = '2'.repeat(64);
  // Pure schema data: no StateOwner, native resource or dispatch authority is created.
  return {
    schemaVersion: 1,
    launchId: 'preparing-launch',
    runId,
    plannedRunRevision: 1,
    supervisorInstanceId: 'preparing-supervisor',
    spawnNonceDigest: '3'.repeat(64),
    activationNonceDigest: '4'.repeat(64),
    phase: 'preparing',
    preparation: {
      stateOwnerEpoch: 1,
      sourceCheckpointId,
      sourceWorkspaceStateRef,
      generationCreationNonceDigest,
      generationId: identityHash(runId, sourceCheckpointId, sourceWorkspaceStateRef, generationCreationNonceDigest)
    },
    createdAt: '2026-10-16T00:00:00.000Z',
    activationDeadlineAt: '2026-10-16T00:02:00.000Z'
  };
}

test('preparing WorkerLaunch retains logical intent without execution fields', () => {
  const preparing = logicalPreparation();

  assert.deepEqual(decodeWorkerLaunch(preparing), preparing);

  const forbidden: Record<string, unknown> = {
    workspaceGenerationRef: '5'.repeat(64),
    containmentPlanRef: '6'.repeat(64),
    sandboxLaunchSpecRef: '7'.repeat(64),
    workerIdentityDigest: '8'.repeat(64),
    processContainmentRef: '9'.repeat(64),
    leaseEpoch: 1,
    leaseVersion: 0,
    leaseExpiresAt: '2026-10-16T00:00:30.000Z',
    generationWriteState: 'preactivated_readonly',
    quiesceId: 'preparing-quiesce',
    activatedAt: '2026-10-16T00:00:00.000Z',
    operationGrantRef: 'a'.repeat(64),
    brokerFenceTokenDigest: 'b'.repeat(64),
    retiredAt: '2026-10-16T00:00:00.000Z',
    retirementEvidenceRef: 'c'.repeat(64),
    retirementKind: 'preparation'
  };
  for (const [field, value] of Object.entries(forbidden)) {
    assert.throws(() => decodeWorkerLaunch({ ...preparing, [field]: value }),
      { code: 'STATE_TRANSITION_INVALID' }, `preparing forbids ${field}`);
  }
});

test('preparing WorkerLaunch records a complete generation birth without becoming executable', () => {
  const preparing = logicalPreparation();
  const generation = { generationRef: '5'.repeat(64), generationIdentityDigest: '6'.repeat(64) };
  const born = { ...preparing, preparation: { ...preparing.preparation, generation } };
  assert.deepEqual(decodeWorkerLaunch(born), born);
  for (const invalid of [{ generationRef: generation.generationRef },
    { generationIdentityDigest: generation.generationIdentityDigest },
    { ...generation, generationRef: 'not-an-artifact' },
    { ...generation, generationIdentityDigest: 'not-a-digest' },
    { ...generation, readonly: true }]) {
    assert.throws(() => decodeWorkerLaunch({ ...born, preparation: { ...born.preparation, generation: invalid } }),
      { code: 'STATE_TRANSITION_INVALID' });
  }
});

test('preparing WorkerLaunch keeps controller and reservation birth facts closed and complete', () => {
  const preparing = logicalPreparation();
  const controller = { birthIdentityRef: '7'.repeat(64), birthIdentityDigest: '8'.repeat(64) };
  const reservation = { deviceId: '10', fileId: '20', ownerUid: 1000 };
  const born = { ...preparing, preparation: { ...preparing.preparation, controller, reservation } };
  assert.deepEqual(decodeWorkerLaunch(born), born);
  for (const invalid of [{ birthIdentityRef: controller.birthIdentityRef },
    { birthIdentityDigest: controller.birthIdentityDigest },
    { ...controller, birthIdentityDigest: 'invalid' }, { ...controller, joined: true }]) {
    assert.throws(() => decodeWorkerLaunch({ ...born, preparation: { ...born.preparation, controller: invalid } }),
      { code: 'STATE_TRANSITION_INVALID' });
  }
  for (const invalid of [{ deviceId: reservation.deviceId, fileId: reservation.fileId },
    { fileId: reservation.fileId, ownerUid: reservation.ownerUid },
    { deviceId: reservation.deviceId, ownerUid: reservation.ownerUid },
    { ...reservation, ownerUid: -1 }, { ...reservation, noSpawn: true }]) {
    assert.throws(() => decodeWorkerLaunch({ ...born, preparation: { ...born.preparation, reservation: invalid } }),
      { code: 'STATE_TRANSITION_INVALID' });
  }
});

test('a bound WorkerLaunch retains complete preparation provenance without substituting its generation', () => {
  const preparing = logicalPreparation(), generationRef = '5'.repeat(64);
  const preparation = { ...preparing.preparation,
    generation: { generationRef, generationIdentityDigest: '6'.repeat(64) },
    controller: { birthIdentityRef: '7'.repeat(64), birthIdentityDigest: '8'.repeat(64) },
    reservation: { deviceId: '10', fileId: '20', ownerUid: 1000 } };
  const bound = { ...preparing, phase: 'reserved', preparation, workspaceGenerationRef: generationRef,
    containmentPlanRef: '9'.repeat(64), sandboxLaunchSpecRef: 'a'.repeat(64),
    leaseVersion: 0, generationWriteState: 'preactivated_readonly' };
  assert.deepEqual(decodeWorkerLaunch(bound), bound);
  for (const field of ['generation', 'controller', 'reservation'] as const) {
    const incomplete: Record<string, unknown> = { ...preparation };
    delete incomplete[field];
    assert.throws(() => decodeWorkerLaunch({ ...bound, preparation: incomplete }), { code: 'STATE_TRANSITION_INVALID' });
  }
  assert.throws(() => decodeWorkerLaunch({ ...bound, workspaceGenerationRef: 'b'.repeat(64) }),
    { code: 'STATE_TRANSITION_INVALID' });
  // Historical bound records are not backfilled with invented birth facts.
  const { preparation: unused, ...historical } = bound;
  assert.deepEqual(decodeWorkerLaunch(historical), historical);
});

test('retired preparation is a separate closed shape, not a sealed or never-spawned worker', () => {
  const preparing = logicalPreparation();
  // This is schema data only; its ref must still resolve genuine physical
  // retirement in the owning state transition and historical closure.
  const retired = { ...preparing, phase: 'retired', retirementKind: 'preparation',
    retiredAt: '2026-10-16T00:03:00.000Z', retirementEvidenceRef: 'c'.repeat(64) };
  assert.deepEqual(decodeWorkerLaunch(retired), retired);
  for (const extra of [{ generationWriteState: 'sealed' }, { leaseVersion: 0 },
    { workspaceGenerationRef: '5'.repeat(64) }, { processContainmentRef: '6'.repeat(64) },
    { containmentPlanRef: '7'.repeat(64) }, { sandboxLaunchSpecRef: '8'.repeat(64) },
    { retirementKind: 'preactivation_failed' }, { retirementEvidenceRef: 'invalid' },
    { retiredAt: '2026-10-15T23:59:59.999Z' }, { activationDeadlineAt: '2026-10-16T00:03:00.000Z' }]) {
    assert.throws(() => decodeWorkerLaunch({ ...retired, ...extra }), { code: 'STATE_TRANSITION_INVALID' });
  }
});
