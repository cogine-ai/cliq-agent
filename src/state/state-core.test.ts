import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_DATABASE_FILENAME } from '../config.js';
import {
  addCanonicalDuration,
  digestOmitting,
  identityHash
} from '../kernel/identity.js';
import type {
  LocalControlChannelIdentityV1,
  PlatformProcessIdentityV1
} from '../kernel/types.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { applyKernelSchema } from './schema.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel, type StateStore } from './store.js';

import { admissionKey, createActiveFixture, digest, disposeFixture, makePrivateDir, uuidv7 } from './testing/fixtures.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

test('WP01 state core persists activation, permanent dispatch claim, settlement, and recovery closure', async () => {
  const fixture = await createAgentFixture('lifecycle', undefined, { mode: 'default' });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }]);
    const before = fixture.store.getRun(fixture.runId);
    const prepared = await prepareTool(fixture);
    assert.equal(prepared.entry.phase, 'prepared');
    assert.equal(prepared.entry.attempt, 0);
    assert.equal(prepared.run.revision, before.revision + 1);
    const claimed = await claimTool(fixture, prepared);
    assert.equal(claimed.entry.phase, 'dispatch_claimed');
    assert.equal(claimed.entry.stateOwnerEpoch, fixture.store.ownerEpoch);
    const resultRef = await observation(fixture, claimed, { contents: 'read result' });
    const completed = await fixture.agent.completeTool({
      opId: prepared.entry.opId,
      attempt: 0,
      expectedRunRevision: prepared.run.revision,
      observationRef: resultRef
    });
    assert.equal(completed.entry.phase, 'completed');
    assert.equal(completed.run.budgetReserved.toolCalls, 0);
    assert.equal(completed.run.budgetConsumed.toolCalls, 1);
    assert.deepEqual(completed.settlement.released, {
      modelTokens: 0,
      costMicros: 0,
      toolCalls: 1,
      repairAttempts: 0
    });

    const metadataReader = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const registered = new Map(
        metadataReader
          .prepare(
            `SELECT ref, schema_kind FROM artifacts
             WHERE ref IN (?, ?, ?, ?)`
          )
          .all<{ ref: string; schema_kind: string }>(
            fixture.channelIdentityRef,
            prepared.entry.requestRef,
            resultRef,
            completed.entry.budgetSettlementRef!
          )
          .map((row) => [row.ref, row.schema_kind])
      );
      assert.equal(registered.get(fixture.channelIdentityRef), 'cliq-local-control-channel-identity-v1');
      assert.equal(registered.get(prepared.entry.requestRef), 'cliq-tool-request-v1');
      assert.equal(registered.get(resultRef), 'cliq-tool-observation-v1');
      assert.equal(registered.get(completed.entry.budgetSettlementRef!), 'cliq-budget-settlement-v1');
    } finally {
      metadataReader.close();
    }

    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(closure.journal.filter(entry => entry.opId === prepared.entry.opId).map((entry) => entry.phase), [
      'prepared',
      'dispatch_claimed',
      'completed'
    ]);
    assert.equal(closure.workerLaunches.length, 1);
    assert.equal(closure.workerLaunches[0]?.phase, 'activated');
    assert.equal(closure.workspaceGenerations.length, 1);
    assert.equal(closure.workspaceGenerations[0]?.phase, 'active');
    assert.equal(closure.run.activeWorkerLaunchId, fixture.launchId);

    const checkpointId = identityHash('cliq-checkpoint-test-v1', fixture.runId, 'sealed');
    // Canonical retained proofs exercise persistence only; no native execution is asserted here.
    const proof = await quiescedToolCheckpoint(fixture, checkpointId);
    const checkpointing = await fixture.store.readRecoveryClosure(fixture.runId);
    const sealed = await fixture.store.sealWorkerGeneration({
      launchId: fixture.launchId,
      expectedRunRevision: completed.run.revision,
      expectedGenerationRowVersion: checkpointing.workspaceGenerations[0]!.rowVersion,
      quiesceId: 'tool-test-quiesce',
      checkpointId,
      contextManifestRef: closure.latestCheckpoint.contextManifestRef,
      workspaceStateRef: closure.latestCheckpoint.workspaceStateRef,
      snapshotEvidenceRef: proof.checkpoint.snapshotEvidenceRef,
      snapshotEvidenceDigest: proof.snapshot.evidenceDigest,
      retirementEvidenceRef: proof.checkpoint.retirementEvidenceRef,
      checkpointReason: 'auto'
    });
    assert.equal(sealed.run.status, 'queued');
    assert.equal(sealed.run.activeWorkerLaunchId, undefined);
    assert.equal(sealed.launch.phase, 'retired');
    assert.equal(sealed.generation.phase, 'sealed');
    const sealedClosure = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(sealedClosure.latestCheckpoint.id, checkpointId);
    assert.deepEqual(sealedClosure.workerLaunches, []);
    assert.equal(sealedClosure.workspaceGenerations[0]?.phase, 'sealed');
  } finally {
    await disposeFixture(fixture);
  }
});

test('initial worker lease cannot extend past the Run deadline', async () => {
  await assert.rejects(
    createActiveFixture('initial-lease-deadline', {
      runWallTimeMs: 59_000,
      leaseDurationMs: 60_000
    }),
    (error) => error instanceof KernelStorageError && error.code === 'INVALID_REQUEST'
  );
});

test('dispatch claim is singleflight and cannot be appended twice', async () => {
  const fixture = await createAgentFixture('singleflight', undefined, { mode: 'default' });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }]);
    const prepared = await prepareTool(fixture);
    const claimInput = {
      expectedRunRevision: prepared.run.revision,
      leaseEpoch: fixture.leaseEpoch,
      opId: prepared.entry.opId,
      attempt: 0,
      dispatchId: 'singleflight-dispatch'
    };
    await fixture.agent.claimTool(claimInput);
    await assert.rejects(
      fixture.agent.claimTool({ ...claimInput, dispatchId: 'losing-dispatch' }),
      (error) => error instanceof KernelStorageError && error.code === 'STATE_TRANSITION_INVALID'
    );
  } finally {
    await disposeFixture(fixture);
  }
});

test('pre-dispatch failure settles prepared attempt and releases reservation', async () => {
  const fixture = await createActiveFixture('predispatch-fail');
  try {
    const request = await fixture.store.artifacts.publishCanonical(
      { schemaVersion: 1, format: 'cliq-tool-request-test-v1' },
      'cliq-tool-request-v1'
    );
    const error = await fixture.store.artifacts.publishCanonical(
      { schemaVersion: 1, format: 'cliq-invocation-error-test-v1', message: 'prep failed' },
      'cliq-invocation-error-v1'
    );
    const prepared = await fixture.store.prepareInvocation({
      runId: fixture.runId,
      expectedRunRevision: fixture.runRevision,
      leaseEpoch: fixture.leaseEpoch,
      opId: 'predispatch-op',
      opKind: 'tool',
      target: 'test.fail',
      requestRef: request.ref,
      replayClass: 'retry',
      reservation: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }
    });
    assert.equal(prepared.run.budgetReserved.toolCalls, 1);
    const failed = await fixture.store.failInvocationBeforeDispatch({
      runId: fixture.runId,
      opId: prepared.entry.opId,
      attempt: 0,
      expectedRunRevision: prepared.run.revision,
      errorRef: error.ref
    });
    assert.equal(failed.entry.phase, 'failed');
    assert.equal(failed.run.budgetReserved.toolCalls, 0);
    assert.equal(failed.run.budgetConsumed.toolCalls, 0);
    assert.deepEqual(failed.settlement.released, prepared.entry.budgetDelta);

    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(closure.journal.map((entry) => entry.phase), ['prepared', 'failed']);
  } finally {
    await disposeFixture(fixture);
  }
});

test('pre-dispatch failure rejects an attempt that already has a dispatch claim', async () => {
  const fixture = await createActiveFixture('predispatch-claim-reject');
  try {
    const request = await fixture.store.artifacts.publishCanonical({ request: true }, 'cliq-tool-request-v1');
    const error = await fixture.store.artifacts.publishCanonical(
      { schemaVersion: 1, message: 'too late' },
      'cliq-invocation-error-v1'
    );
    const prepared = await fixture.store.prepareInvocation({
      runId: fixture.runId,
      expectedRunRevision: fixture.runRevision,
      leaseEpoch: fixture.leaseEpoch,
      opId: 'predispatch-claimed-op',
      opKind: 'tool',
      target: 'test.fail',
      requestRef: request.ref,
      replayClass: 'retry',
      reservation: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }
    });
    await fixture.store.claimInvocationDispatch({
      runId: fixture.runId,
      expectedRunRevision: prepared.run.revision,
      leaseEpoch: fixture.leaseEpoch,
      opId: prepared.entry.opId,
      attempt: 0,
      dispatchId: 'predispatch-claim',
      brokerFenceTokenDigest: digest('predispatch-claim:fence')
    });
    await assert.rejects(
      fixture.store.failInvocationBeforeDispatch({
        runId: fixture.runId,
        opId: prepared.entry.opId,
        attempt: 0,
        expectedRunRevision: prepared.run.revision,
        errorRef: error.ref
      }),
      (error) => error instanceof KernelStorageError && error.code === 'STATE_TRANSITION_INVALID'
    );
  } finally {
    await disposeFixture(fixture);
  }
});

test('claimed failure without release settles with post-claim evidence', async () => {
  const fixture = await createActiveFixture('claimed-fail');
  try {
    const request = await fixture.store.artifacts.publishCanonical({ request: true }, 'cliq-tool-request-v1');
    const prepared = await fixture.store.prepareInvocation({
      runId: fixture.runId,
      expectedRunRevision: fixture.runRevision,
      leaseEpoch: fixture.leaseEpoch,
      opId: 'claimed-fail-op',
      opKind: 'tool',
      target: 'test.crash',
      requestRef: request.ref,
      replayClass: 'retry',
      reservation: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }
    });
    await fixture.store.claimInvocationDispatch({
      runId: fixture.runId,
      expectedRunRevision: prepared.run.revision,
      leaseEpoch: fixture.leaseEpoch,
      opId: prepared.entry.opId,
      attempt: 0,
      dispatchId: 'claimed-fail-dispatch',
      brokerFenceTokenDigest: digest('claimed-fail:fence')
    });
    const error = await fixture.store.artifacts.publishCanonical(
      { schemaVersion: 1, message: 'worker crashed' },
      'cliq-invocation-error-v1'
    );
    const evidencePayload = {
      schemaVersion: 1,
      format: 'cliq-post-claim-no-release-evidence-test-v1',
      reason: 'no release observed',
      evidenceDigest: ''
    };
    evidencePayload.evidenceDigest = digestOmitting(evidencePayload, 'evidenceDigest');
    const evidence = await fixture.store.artifacts.publishCanonical(
      evidencePayload,
      'cliq-post-claim-no-release-evidence-v1'
    );
    const failed = await fixture.store.failClaimedInvocationWithoutRelease({
      runId: fixture.runId,
      opId: prepared.entry.opId,
      attempt: 0,
      expectedRunRevision: prepared.run.revision,
      errorRef: error.ref,
      evidenceRef: evidence.ref,
      evidenceDigest: evidencePayload.evidenceDigest
    });
    assert.equal(failed.entry.phase, 'failed');
    assert.equal(failed.entry.evidenceRef, evidence.ref);
    assert.equal(failed.run.budgetReserved.toolCalls, 0);
    assert.equal(failed.run.budgetConsumed.toolCalls, 0);

    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(closure.journal.map((entry) => entry.phase), [
      'prepared',
      'dispatch_claimed',
      'failed'
    ]);
  } finally {
    await disposeFixture(fixture);
  }
});

test('manual unknown invocation can be abandoned after ambiguity evidence', async () => {
  const fixture = await createActiveFixture('manual-abandon');
  try {
    const request = await fixture.store.artifacts.publishCanonical({ request: true }, 'cliq-tool-request-v1');
    const prepared = await fixture.store.prepareInvocation({
      runId: fixture.runId,
      expectedRunRevision: fixture.runRevision,
      leaseEpoch: fixture.leaseEpoch,
      opId: 'manual-unknown-op',
      opKind: 'tool',
      target: 'test.ambiguous',
      requestRef: request.ref,
      replayClass: 'manual',
      reservation: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }
    });
    await fixture.store.claimInvocationDispatch({
      runId: fixture.runId,
      expectedRunRevision: prepared.run.revision,
      leaseEpoch: fixture.leaseEpoch,
      opId: prepared.entry.opId,
      attempt: 0,
      dispatchId: 'manual-unknown-dispatch',
      brokerFenceTokenDigest: digest('manual-unknown:fence')
    });
    const ambiguityPayload = {
      schemaVersion: 1,
      format: 'cliq-invocation-ambiguity-evidence-test-v1',
      reason: 'outcome unknown',
      evidenceDigest: ''
    };
    ambiguityPayload.evidenceDigest = digestOmitting(ambiguityPayload, 'evidenceDigest');
    const ambiguity = await fixture.store.artifacts.publishCanonical(
      ambiguityPayload,
      'cliq-invocation-ambiguity-evidence-v1'
    );
    const unknown = await fixture.store.markInvocationUnknown({
      runId: fixture.runId,
      opId: prepared.entry.opId,
      attempt: 0,
      expectedRunRevision: prepared.run.revision,
      evidenceRef: ambiguity.ref,
      evidenceDigest: ambiguityPayload.evidenceDigest
    });
    assert.equal(unknown.entry.phase, 'unknown');
    assert.equal(unknown.run.budgetConsumed.toolCalls, 1);
    assert.equal(unknown.run.budgetReserved.toolCalls, 0);

    const attestation = await fixture.store.artifacts.publishCanonical(
      { schemaVersion: 1, format: 'cliq-manual-abandon-attestation-test-v1', opId: prepared.entry.opId },
      'cliq-manual-abandon-attestation-v1'
    );
    const abandoned = await fixture.store.abandonUnknownInvocation({
      runId: fixture.runId,
      opId: prepared.entry.opId,
      attempt: 0,
      attestationRef: attestation.ref
    });
    assert.equal(abandoned.phase, 'abandoned');
    assert.equal(abandoned.attestationRef, attestation.ref);
    assert.equal(abandoned.budgetSettlementRef, unknown.entry.budgetSettlementRef);

    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(closure.journal.map((entry) => entry.phase), [
      'prepared',
      'dispatch_claimed',
      'unknown',
      'abandoned'
    ]);
  } finally {
    await disposeFixture(fixture);
  }
});

test('recovery requires every terminal Journal artifact to remain in CAS', async () => {
  const fixture = await createAgentFixture('recovery-terminal-cas', undefined, { mode: 'default' });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }]);
    const prepared = await prepareTool(fixture);
    const claimed = await claimTool(fixture, prepared);
    const resultRef = await observation(fixture, claimed, { contents: 'read result' });
    await fixture.agent.completeTool({
      opId: prepared.entry.opId,
      attempt: 0,
      expectedRunRevision: prepared.run.revision,
      observationRef: resultRef
    });

    await rm(path.join(fixture.stateRoot, 'cas', resultRef));
    await assert.rejects(
      fixture.store.readRecoveryClosure(fixture.runId),
      (error) => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED'
    );
  } finally {
    await disposeFixture(fixture);
  }
});

test('budget reservation and revoked generation fence dispatch and heartbeat', async () => {
  const fixture = await createAgentFixture('fencing', { toolCalls: 1 }, { mode: 'default' });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }, { name: 'read', input: { path: 'b' } }]);
    const first = await prepareTool(fixture), claimed = await claimTool(fixture, first);
    await fixture.agent.completeTool({ opId: first.entry.opId, attempt: first.entry.attempt,
      expectedRunRevision: first.run.revision, observationRef: await observation(fixture, claimed, { contents: 'read result' }) });
    await assert.rejects(
      fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
        leaseEpoch: fixture.leaseEpoch }),
      (error) => error instanceof KernelStorageError && error.code === 'BUDGET_EXHAUSTED'
    );
    const revoked = fixture.store.beginGenerationRevocation({
      launchId: fixture.launchId,
      expectedLeaseVersion: fixture.leaseVersion,
      expectedGenerationRowVersion: fixture.generationRowVersion,
      quiesceId: 'fencing-quiesce'
    });
    assert.equal(revoked.generation.phase, 'revoking');
    assert.throws(
      () => fixture.store.renewWorkerLease({
        launchId: fixture.launchId,
        expectedLeaseVersion: fixture.leaseVersion,
        runId: fixture.runId,
        leaseEpoch: fixture.leaseEpoch,
        workerIdentityDigest: fixture.workerIdentityDigest,
        newLeaseExpiresAt: addCanonicalDuration(sampleCanonicalNow(), 30_000)
      }),
      (error) => error instanceof KernelStorageError && error.code === 'LEASE_FENCED'
    );
  } finally {
    await disposeFixture(fixture);
  }
});

test('an expired worker lease cannot be revived by heartbeat', async () => {
  const fixture = await createActiveFixture('expired-heartbeat');
  try {
    const inspector = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const row = inspector
        .prepare('SELECT row_json FROM worker_launches WHERE launch_id = ?')
        .get<{ row_json: string }>(fixture.launchId);
      const launch = JSON.parse(row!.row_json) as { activatedAt: string; leaseExpiresAt: string };
      launch.leaseExpiresAt = addCanonicalDuration(launch.activatedAt, 1);
      inspector
        .prepare('UPDATE worker_launches SET row_json = ? WHERE launch_id = ?')
        .run(JSON.stringify(launch), fixture.launchId);
    } finally {
      inspector.close();
    }
    await new Promise((resolve) => setTimeout(resolve, 2));
    assert.throws(
      () => fixture.store.renewWorkerLease({
        launchId: fixture.launchId,
        expectedLeaseVersion: fixture.leaseVersion,
        runId: fixture.runId,
        leaseEpoch: fixture.leaseEpoch,
        workerIdentityDigest: fixture.workerIdentityDigest,
        newLeaseExpiresAt: addCanonicalDuration(sampleCanonicalNow(), 30_000)
      }),
      (error) => error instanceof KernelStorageError && error.code === 'LEASE_FENCED'
    );
  } finally {
    await disposeFixture(fixture);
  }
});

test('control channel decoding rejects extension fields even when its digest rehashes', async () => {
  const stateRoot = await makePrivateDir('.cliq-m2-channel-closed-state-');
  const workspace = await makePrivateDir('.cliq-m2-channel-closed-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const channel = await publishInProcessChannel(store);
    const extended = await store.artifacts.readCanonical<Record<string, unknown>>(
      channel.channelIdentityRef
    );
    extended.extension = 'not-allowed';
    extended.channelIdentityDigest = digestOmitting(extended, 'channelIdentityDigest');
    const extendedArtifact = await store.artifacts.publishCanonical(
      extended,
      'cliq-local-control-channel-identity-v1'
    );
    await assert.rejects(
      store.createSession({
        principalId: channel.principalId,
        requestId: uuidv7(),
        admissionKey: admissionKey('closed-channel'),
        workspacePath: workspace,
        channelIdentityRef: extendedArtifact.ref,
        channelIdentityDigest: String(extended.channelIdentityDigest)
      }),
      (error) => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH'
    );
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('control channel rejects forged process identity and opaque UDS peer evidence', async () => {
  const stateRoot = await makePrivateDir('.cliq-m2-channel-binding-state-');
  const workspace = await makePrivateDir('.cliq-m2-channel-binding-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const { principalId, ...published } = await publishInProcessChannel(store);
    const channel = await store.artifacts.readCanonical<LocalControlChannelIdentityV1>(
      published.channelIdentityRef
    );
    assert.equal(channel.transport.kind, 'in_process');
    if (channel.transport.kind !== 'in_process') throw new Error('expected in-process channel');
    const processIdentity = await store.artifacts.readCanonical<PlatformProcessIdentityV1>(
      channel.transport.processIdentityRef
    );
    const forgedProcess: PlatformProcessIdentityV1 = {
      ...processIdentity,
      processStartToken: `${processIdentity.processStartToken}:forged`,
      executableImageDigest: digest('forged-executable'),
      identityDigest: ''
    };
    forgedProcess.identityDigest = digestOmitting(forgedProcess, 'identityDigest');
    const forgedProcessArtifact = await store.artifacts.publishCanonical(
      forgedProcess,
      forgedProcess.format
    );
    const forgedChannel: LocalControlChannelIdentityV1 = {
      ...channel,
      transport: {
        kind: 'in_process',
        processIdentityRef: forgedProcessArtifact.ref,
        processIdentityDigest: forgedProcess.identityDigest
      },
      channelNonceDigest: digest('forged-process-channel'),
      channelIdentityDigest: ''
    };
    forgedChannel.channelIdentityDigest = digestOmitting(forgedChannel, 'channelIdentityDigest');
    const forgedChannelArtifact = await store.artifacts.publishCanonical(
      forgedChannel,
      forgedChannel.format
    );
    await assert.rejects(
      store.createSession({
        principalId,
        requestId: uuidv7(),
        admissionKey: admissionKey('forged-process-channel'),
        workspacePath: workspace,
        channelIdentityRef: forgedChannelArtifact.ref,
        channelIdentityDigest: forgedChannel.channelIdentityDigest
      }),
      (error) => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH'
    );

    const peerObservation = await store.artifacts.publishCanonical(
      { schemaVersion: 1, format: 'cliq-local-socket-peer-observation-test-v1' },
      'cliq-local-socket-peer-observation-v1'
    );
    const udsChannel: LocalControlChannelIdentityV1 = {
      ...channel,
      transport: {
        kind: 'uds_peer',
        peerObservationRef: peerObservation.ref,
        peerObservationDigest: peerObservation.ref
      },
      channelNonceDigest: digest('opaque-uds-channel'),
      channelIdentityDigest: ''
    };
    udsChannel.channelIdentityDigest = digestOmitting(udsChannel, 'channelIdentityDigest');
    const udsChannelArtifact = await store.artifacts.publishCanonical(
      udsChannel,
      udsChannel.format
    );
    await assert.rejects(
      store.createSession({
        principalId,
        requestId: uuidv7(),
        admissionKey: admissionKey('opaque-uds-channel'),
        workspacePath: workspace,
        channelIdentityRef: udsChannelArtifact.ref,
        channelIdentityDigest: udsChannel.channelIdentityDigest
      }),
      (error) => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH'
    );
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('recovery closed-decodes row_json instead of trusting redundant columns', async () => {
  const fixture = await createActiveFixture('corruption');
  try {
    const inspector = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      inspector
        .prepare(`UPDATE worker_launches SET row_json = '{}' WHERE launch_id = ?`)
        .run(fixture.launchId);
    } finally {
      inspector.close();
    }
    await assert.rejects(
      fixture.store.readRecoveryClosure(fixture.runId),
      (error) => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED'
    );
  } finally {
    await disposeFixture(fixture);
  }
});

test('fresh genesis refuses residual rows in every authority table', async () => {
  const stateRoot = await makePrivateDir('.cliq-m2-genesis-db-residue-');
  await mkdir(path.join(stateRoot, 'runtime'), { mode: 0o700 });
  await writeFile(path.join(stateRoot, 'runtime', 'state-owner.lock'), '', { mode: 0o600 });
  const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    applyKernelSchema(driver);
    driver
      .prepare(
        `INSERT INTO authorization_grants (grant_id, owner_principal_id, state, row_json)
         VALUES (?, ?, ?, ?)`
      )
      .run('residual-grant', 'residual-principal', 'active', '{}');
  } finally {
    driver.close();
  }
  try {
    await assert.rejects(
      openStateStore(stateRoot),
      (error) =>
        error instanceof KernelStorageError &&
        error.code === 'RECOVERY_REQUIRED' &&
        error.message.includes('authorization_grants')
    );
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('fresh genesis refuses a pre-existing CAS namespace', async () => {
  const stateRoot = await makePrivateDir('.cliq-m2-genesis-cas-residue-');
  const casRoot = path.join(stateRoot, 'cas');
  await mkdir(casRoot, { mode: 0o700 });
  await writeFile(path.join(casRoot, digest('residual-cas-object')), 'residual', { mode: 0o400 });
  try {
    await assert.rejects(
      openStateStore(stateRoot),
      (error) =>
        error instanceof KernelStorageError &&
        error.code === 'RECOVERY_REQUIRED' &&
        error.message.includes('CAS namespace')
    );
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('a live StateOwner cannot be silently reused by a second store', async () => {
  const stateRoot = await makePrivateDir('.cliq-m2-owner-singleton-');
  const first = await openStateStore(stateRoot);
  try {
    await assert.rejects(
      openStateStore(stateRoot),
      (error) => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED'
    );
  } finally {
    await first.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('concurrent close joins one graceful StateOwner release', async () => {
  const stateRoot = await makePrivateDir('.cliq-m2-owner-close-');
  const store = await openStateStore(stateRoot);
  try {
    await Promise.all([store.close(), store.close()]);
    const reopened = await openStateStore(stateRoot);
    assert.equal(reopened.ownerEpoch, 2);
    await reopened.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('graceful reacquisition preserves clock regression under the successor owner', async () => {
  const stateRoot = await makePrivateDir('.cliq-m2-owner-clock-regression-');
  const originalNow = Date.now;
  const first = await openStateStore(stateRoot);
  let second: StateStore | undefined;
  try {
    const firstFence = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    let highWater: string;
    try {
      highWater = firstFence
        .prepare('SELECT last_accepted_at FROM canonical_time_fence WHERE id = 1')
        .get<{ last_accepted_at: string }>()!.last_accepted_at;
    } finally {
      firstFence.close();
    }
    Date.now = () => Date.parse(highWater) - 1_000;
    await first.close();
    second = await openStateStore(stateRoot);
    assert.equal(second.ownerEpoch, 2);

    const secondFence = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const row = secondFence
        .prepare(
          `SELECT state_owner_epoch, last_accepted_at, observed_wall_clock_at, state
           FROM canonical_time_fence WHERE id = 1`
        )
        .get<{
          state_owner_epoch: unknown;
          last_accepted_at: string;
          observed_wall_clock_at: string;
          state: string;
        }>();
      assert.equal(Number(row?.state_owner_epoch), 2);
      assert.equal(row?.state, 'clock_regressed');
      assert.equal(row?.last_accepted_at, highWater);
      assert.ok(Date.parse(row!.observed_wall_clock_at) < Date.parse(highWater));
    } finally {
      secondFence.close();
    }

    Date.now = originalNow;
    assert.equal(second.recoverCanonicalTime(), 'healthy');
  } finally {
    Date.now = originalNow;
    await first.close().catch(() => undefined);
    await second?.close().catch(() => undefined);
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('open rejects and does not repair changed runtime or lock permissions', async () => {
  const stateRoot = await makePrivateDir('.cliq-m2-owner-permissions-');
  const runtimePath = path.join(stateRoot, 'runtime');
  const lockPath = path.join(runtimePath, 'state-owner.lock');
  const displacedRuntimePath = path.join(stateRoot, 'runtime.displaced');
  const first = await openStateStore(stateRoot);
  await first.close();
  try {
    await chmod(runtimePath, 0o755);
    await assert.rejects(
      openStateStore(stateRoot),
      (error) => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED'
    );
    assert.equal((await lstat(runtimePath)).mode & 0o7777, 0o755);
    await chmod(runtimePath, 0o700);

    await rename(runtimePath, displacedRuntimePath);
    await assert.rejects(
      openStateStore(stateRoot),
      (error) => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED'
    );
    await assert.rejects(lstat(runtimePath), (error: NodeJS.ErrnoException) => error.code === 'ENOENT');
    await rename(displacedRuntimePath, runtimePath);

    await chmod(lockPath, 0o644);
    await assert.rejects(
      openStateStore(stateRoot),
      (error) => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED'
    );
    assert.equal((await lstat(lockPath)).mode & 0o7777, 0o644);
    await chmod(lockPath, 0o600);

    const reopened = await openStateStore(stateRoot);
    assert.equal(reopened.ownerEpoch, 2);
    await reopened.close();
  } finally {
    await rename(displacedRuntimePath, runtimePath).catch(() => undefined);
    await chmod(runtimePath, 0o700).catch(() => undefined);
    await chmod(lockPath, 0o600).catch(() => undefined);
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('ordinary writes fail closed if the StateOwner lock inode is replaced', async () => {
  const stateRoot = await makePrivateDir('.cliq-m2-owner-lock-swap-');
  const workspace = await makePrivateDir('.cliq-m2-owner-lock-ws-');
  const store = await openStateStore(stateRoot);
  const lockPath = path.join(stateRoot, 'runtime', 'state-owner.lock');
  const displacedPath = path.join(stateRoot, 'runtime', 'state-owner.displaced');
  try {
    const channel = await publishInProcessChannel(store);
    await rename(lockPath, displacedPath);
    await writeFile(lockPath, '', { mode: 0o600 });
    await assert.rejects(
      store.createSession({
        requestId: uuidv7(),
        admissionKey: admissionKey('lock-swap'),
        workspacePath: workspace,
        ...channel
      }),
      (error) => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED'
    );
    await rm(lockPath);
    await rename(displacedPath, lockPath);
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});
