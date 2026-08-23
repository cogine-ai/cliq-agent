import assert from 'node:assert/strict';
import { randomFillSync } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_DATABASE_FILENAME } from '../config.js';
import {
  addCanonicalDuration,
  digestOmitting,
  identityHash,
  sha256Bytes
} from '../kernel/identity.js';
import type {
  FrozenIgnoreRulesV1,
  LocalControlChannelIdentityV1,
  PlatformProcessIdentityV1,
  SourceManifest,
  SourceProjectionSpec,
  VerifierSpec,
  WorkerIdentity,
  WorkspaceEntryManifest,
  WorkspaceGenerationIdentityV1,
  WorkspaceGenerationSnapshotEvidenceV1,
  WorkspaceIdentityV1,
  WorkspaceStateManifest
} from '../kernel/types.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { applyKernelSchema } from './schema.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel, type StateStore } from './store.js';

function uuidv7(): string {
  const bytes = Buffer.alloc(16);
  const unixMs = Date.now();
  bytes.writeUInt32BE(Math.floor(unixMs / 0x1_0000), 0);
  bytes.writeUInt16BE(unixMs & 0xffff, 4);
  randomFillSync(bytes, 6);
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function admissionKey(label: string): string {
  return Buffer.from(label.padEnd(16, '0')).toString('base64url');
}

function digest(label: string): string {
  return sha256Bytes(Buffer.from(label, 'utf8'));
}

async function makePrivateDir(prefix: string): Promise<string> {
  const directory = await mkdtemp(path.join(process.cwd(), prefix));
  await chmod(directory, 0o700);
  return directory;
}

async function publishEmptySourceGraph(store: StateStore, workspaceIdentityDigest: string) {
  const rules: FrozenIgnoreRulesV1 = {
    schemaVersion: 1,
    format: 'cliq-frozen-ignore-rules-v1',
    matcherVersion: 'cliq-git-wildmatch-v1',
    sources: [],
    rules: [],
    rulesDigest: ''
  };
  rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
  const rulesArtifact = await store.artifacts.publishCanonical(rules, rules.format);
  const projection: SourceProjectionSpec = {
    schemaVersion: 1,
    matcherVersion: 'cliq-exact-path-v1',
    frozenIgnoreRulesRef: rulesArtifact.ref,
    frozenIgnoreRulesDigest: rules.rulesDigest,
    explicitIncludes: [],
    explicitExcludes: [],
    maxChangedPaths: 10_000,
    maxChangedBytes: 512 * 1024 * 1024,
    projectionDigest: ''
  };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  const projectionArtifact = await store.artifacts.publishCanonical(projection, 'cliq-source-projection-v1');
  const entries: WorkspaceEntryManifest = {
    schemaVersion: 1,
    format: 'cliq-workspace-entries-v1',
    entries: [],
    entryCount: 0,
    byteCount: 0,
    treeDigest: ''
  };
  entries.treeDigest = digestOmitting(entries, 'treeDigest');
  const entriesArtifact = await store.artifacts.publishCanonical(entries, entries.format);
  const source: SourceManifest = {
    schemaVersion: 1,
    format: 'cliq-source-manifest-v1',
    role: 'base',
    workspaceIdentityDigest,
    entriesRef: entriesArtifact.ref,
    sourceProjectionRef: projectionArtifact.ref,
    sourceProjectionDigest: projection.projectionDigest,
    frozenIgnoreRulesRef: rulesArtifact.ref,
    frozenIgnoreRulesDigest: rules.rulesDigest,
    treeDigest: entries.treeDigest,
    manifestDigest: ''
  };
  source.manifestDigest = digestOmitting(source, 'manifestDigest');
  const sourceArtifact = await store.artifacts.publishCanonical(source, source.format);
  const verifier: VerifierSpec = {
    schemaVersion: 1,
    format: 'cliq-verifier-spec-v1',
    verifiers: [],
    specDigest: ''
  };
  verifier.specDigest = digestOmitting(verifier, 'specDigest');
  const verifierArtifact = await store.artifacts.publishCanonical(verifier, verifier.format);
  const [assembly, policy, sandbox] = await Promise.all([
    store.artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-m2-assembly-fixture-v1' }, 'cliq-run-assembly-v1'),
    store.artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-m2-policy-fixture-v1' }, 'cliq-run-policy-v1'),
    store.artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-m2-sandbox-fixture-v1' }, 'cliq-sandbox-profile-v1')
  ]);
  return {
    sourceProjectionRef: projectionArtifact.ref,
    frozenIgnoreRulesRef: rulesArtifact.ref,
    baseWorkspaceManifestRef: sourceArtifact.ref,
    verifierSpecRef: verifierArtifact.ref,
    assemblyRef: assembly.ref,
    policyRef: policy.ref,
    sandboxProfileRef: sandbox.ref,
    treeDigest: entries.treeDigest
  };
}

type ActiveFixture = {
  stateRoot: string;
  workspace: string;
  store: StateStore;
  channelIdentityRef: string;
  runId: string;
  runRevision: number;
  generationId: string;
  generationRef: string;
  generationRowVersion: number;
  launchId: string;
  leaseVersion: number;
  leaseEpoch: number;
  workerIdentityDigest: string;
};

type ActiveFixtureOptions = {
  runWallTimeMs?: number;
  leaseDurationMs?: number;
};

async function createActiveFixture(
  label: string,
  options: ActiveFixtureOptions = {}
): Promise<ActiveFixture> {
  const stateRoot = await makePrivateDir(`.cliq-m2-${label}-state-`);
  const workspace = await makePrivateDir(`.cliq-m2-${label}-ws-`);
  const store = await openStateStore(stateRoot);
  const principalId = 'cliq-m2-principal';
  const channel = await publishInProcessChannel(store, principalId);
  const session = await store.createSession({
    principalId,
    requestId: uuidv7(),
    admissionKey: admissionKey(`${label}-session`),
    workspacePath: workspace,
    ...channel
  });
  const workspaceIdentity = (await store.artifacts.readCanonical(
    session.session.workspaceIdentityRef
  )) as WorkspaceIdentityV1;
  const source = await publishEmptySourceGraph(store, workspaceIdentity.identityDigest);
  const admitted = await store.admitRun({
    principalId,
    requestId: uuidv7(),
    admissionKey: admissionKey(`${label}-run`),
    sessionId: session.session.id,
    expectedContextRevision: 1,
    workspacePath: workspace,
    objective: `exercise ${label}`,
    allowUnverified: true,
    budgets: options.runWallTimeMs === undefined
      ? undefined
      : { wallTimeMs: options.runWallTimeMs },
    ...channel,
    ...source
  });
  const initial = await store.readRecoveryClosure(admitted.run.id);
  const workspaceState = (await store.artifacts.readCanonical(
    initial.latestCheckpoint.workspaceStateRef
  )) as WorkspaceStateManifest;
  const stateRootFixture = await store.artifacts.publishCanonical(
    { schemaVersion: 1, format: 'cliq-state-root-test-fixture-v1', stateRoot },
    'cliq-state-root-test-fixture-v1'
  );
  const generationId = identityHash('cliq-workspace-generation-test-v1', admitted.run.id, label);
  const identity: WorkspaceGenerationIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-workspace-generation-identity-v1',
    generationId,
    runId: admitted.run.id,
    workspaceIdentityDigest: workspaceIdentity.identityDigest,
    sourceCheckpointId: initial.latestCheckpoint.id,
    sourceWorkspaceStateRef: initial.latestCheckpoint.workspaceStateRef,
    sourceWorkspaceStateDigest: workspaceState.stateDigest,
    sourceTreeDigest: source.treeDigest,
    creationNonceDigest: digest(`${label}:generation-nonce`),
    locator: process.platform === 'linux'
      ? {
          kind: 'linux_directory',
          stateRootIdentityRef: stateRootFixture.ref,
          stateRootIdentityDigest: stateRootFixture.ref,
          canonicalRootRelativePath: `generations/${generationId}`,
          deviceId: '1',
          directoryFileId: '2',
          ownerUid: process.geteuid!(),
          mode: 448,
          linkCount: 1
        }
      : {
          kind: 'macos_vm_volume',
          stateRootIdentityRef: stateRootFixture.ref,
          stateRootIdentityDigest: stateRootFixture.ref,
          backingStoreCanonicalRootRelativePath: `generations/${generationId}.img`,
          backingStoreDeviceId: '1',
          backingStoreFileId: '2',
          backingStoreOwnerUid: process.geteuid!(),
          backingStoreMode: 384,
          backingStoreLinkCount: 1,
          vmVolumeReservationId: `${label}-reservation`,
          guestVolumeId: `${label}-volume`
        },
    createdAt: sampleCanonicalNow(),
    identityDigest: ''
  };
  identity.identityDigest = digestOmitting(identity, 'identityDigest');
  const generationArtifact = await store.artifacts.publishCanonical(identity, identity.format);
  const materializing = await store.registerWorkspaceGeneration({
    runId: admitted.run.id,
    generationRef: generationArtifact.ref,
    generationIdentityDigest: identity.identityDigest
  });
  const snapshot: WorkspaceGenerationSnapshotEvidenceV1 = {
    schemaVersion: 1,
    format: 'cliq-workspace-generation-snapshot-evidence-v1',
    purpose: 'materialized_from_checkpoint',
    runId: admitted.run.id,
    generationRef: generationArtifact.ref,
    generationIdentityDigest: identity.identityDigest,
    checkpointId: initial.latestCheckpoint.id,
    workspaceStateRef: initial.latestCheckpoint.workspaceStateRef,
    workspaceStateDigest: workspaceState.stateDigest,
    entriesRef: workspaceState.entriesRef,
    treeDigest: source.treeDigest,
    descriptorRewalkComplete: true,
    fileFsyncComplete: true,
    directoryFsyncComplete: true,
    observedAt: sampleCanonicalNow(),
    evidenceDigest: ''
  };
  snapshot.evidenceDigest = digestOmitting(snapshot, 'evidenceDigest');
  const snapshotArtifact = await store.artifacts.publishCanonical(snapshot, snapshot.format);
  const preactivatedGeneration = await store.recordWorkspaceGenerationPreactivated({
    generationId,
    expectedRowVersion: materializing.rowVersion,
    snapshotEvidenceRef: snapshotArtifact.ref,
    snapshotEvidenceDigest: snapshot.evidenceDigest
  });
  const [plan, launchSpec, containment] = await Promise.all([
    store.artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-containment-plan-test-v1', generationId }, 'cliq-process-containment-plan-v1'),
    store.artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-worker-launch-spec-test-v1', generationId }, 'cliq-sandbox-launch-spec-v1'),
    store.artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-containment-test-v1', generationId }, 'cliq-process-containment-v1')
  ]);
  const launchId = identityHash('cliq-worker-launch-test-v1', admitted.run.id, label);
  const reserved = await store.reserveWorkerLaunch({
    launchId,
    runId: admitted.run.id,
    expectedRunRevision: admitted.run.revision,
    spawnNonceDigest: digest(`${label}:spawn`),
    activationNonceDigest: digest(`${label}:activate`),
    workspaceGenerationRef: generationArtifact.ref,
    containmentPlanRef: plan.ref,
    sandboxLaunchSpecRef: launchSpec.ref
  });
  const workerIdentity: WorkerIdentity = {
    schemaVersion: 1,
    executableRealpath: '/cliq/test-worker',
    executableDigest: digest(`${label}:worker-executable`),
    pid: process.pid,
    processStartToken: `${process.pid}:test`,
    spawnNonceDigest: reserved.spawnNonceDigest,
    activationNonceDigest: reserved.activationNonceDigest,
    intendedLeaseEpoch: 1,
    launchId,
    supervisorInstanceId: reserved.supervisorInstanceId,
    processContainmentRef: containment.ref
  };
  const workerArtifact = await store.artifacts.publishCanonical(workerIdentity, 'cliq-worker-identity-v1');
  await store.recordWorkerPreactivated({
    launchId,
    workerIdentityDigest: workerArtifact.ref,
    processContainmentRef: containment.ref
  });
  let activated: ReturnType<StateStore['activateWorkerLease']>;
  try {
    activated = store.activateWorkerLease({
      launchId,
      expectedRunRevision: admitted.run.revision,
      expectedGenerationRowVersion: preactivatedGeneration.rowVersion,
      leaseDurationMs: options.leaseDurationMs ?? 60_000
    });
  } catch (error) {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
    throw error;
  }
  return {
    stateRoot,
    workspace,
    store,
    channelIdentityRef: channel.channelIdentityRef,
    runId: admitted.run.id,
    runRevision: activated.run.revision,
    generationId,
    generationRef: generationArtifact.ref,
    generationRowVersion: activated.generation.rowVersion,
    launchId,
    leaseVersion: activated.launch.leaseVersion,
    leaseEpoch: activated.run.leaseEpoch,
    workerIdentityDigest: workerArtifact.ref
  };
}

async function disposeFixture(fixture: ActiveFixture): Promise<void> {
  await fixture.store.close();
  await rm(fixture.stateRoot, { recursive: true, force: true });
  await rm(fixture.workspace, { recursive: true, force: true });
}

test('WP01 state core persists activation, permanent dispatch claim, settlement, and recovery closure', async () => {
  const fixture = await createActiveFixture('lifecycle');
  try {
    const request = await fixture.store.artifacts.publishCanonical(
      { schemaVersion: 1, format: 'cliq-tool-request-test-v1' },
      'cliq-tool-request-v1'
    );
    const prepared = await fixture.store.prepareInvocation({
      runId: fixture.runId,
      expectedRunRevision: fixture.runRevision,
      leaseEpoch: fixture.leaseEpoch,
      opId: 'tool-op-1',
      opKind: 'tool',
      target: 'test.read',
      requestRef: request.ref,
      replayClass: 'retry',
      idempotencyKey: 'tool-op-1-attempt-0',
      reservation: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }
    });
    assert.equal(prepared.entry.phase, 'prepared');
    assert.equal(prepared.entry.attempt, 0);
    assert.equal(prepared.run.revision, fixture.runRevision + 1);
    const claimed = await fixture.store.claimInvocationDispatch({
      runId: fixture.runId,
      expectedRunRevision: prepared.run.revision,
      leaseEpoch: fixture.leaseEpoch,
      opId: prepared.entry.opId,
      attempt: 0,
      dispatchId: 'dispatch-tool-op-1',
      brokerFenceTokenDigest: digest('dispatch-tool-op-1:fence')
    });
    assert.equal(claimed.phase, 'dispatch_claimed');
    assert.equal(claimed.stateOwnerEpoch, fixture.store.ownerEpoch);
    const resultArtifact = await fixture.store.artifacts.publishCanonical(
      { schemaVersion: 1, format: 'cliq-tool-result-test-v1', ok: true },
      'cliq-tool-result-v1'
    );
    const completed = await fixture.store.completeInvocation({
      runId: fixture.runId,
      opId: prepared.entry.opId,
      attempt: 0,
      expectedRunRevision: prepared.run.revision,
      resultRef: resultArtifact.ref,
      consumed: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }
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
            request.ref,
            resultArtifact.ref,
            completed.entry.budgetSettlementRef!
          )
          .map((row) => [row.ref, row.schema_kind])
      );
      assert.equal(registered.get(fixture.channelIdentityRef), 'cliq-local-control-channel-identity-v1');
      assert.equal(registered.get(request.ref), 'cliq-invocation-request-v1');
      assert.equal(registered.get(resultArtifact.ref), 'cliq-invocation-result-v1');
      assert.equal(registered.get(completed.entry.budgetSettlementRef!), 'cliq-budget-settlement-v1');
    } finally {
      metadataReader.close();
    }

    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(closure.journal.map((entry) => entry.phase), [
      'prepared',
      'dispatch_claimed',
      'completed'
    ]);
    assert.equal(closure.workerLaunches.length, 1);
    assert.equal(closure.workerLaunches[0]?.phase, 'activated');
    assert.equal(closure.workspaceGenerations.length, 1);
    assert.equal(closure.workspaceGenerations[0]?.phase, 'active');
    assert.equal(closure.run.activeWorkerLaunchId, fixture.launchId);

    const revoking = fixture.store.beginGenerationRevocation({
      launchId: fixture.launchId,
      expectedLeaseVersion: fixture.leaseVersion,
      expectedGenerationRowVersion: closure.workspaceGenerations[0]!.rowVersion,
      quiesceId: 'lifecycle-quiesce'
    });
    const checkpointing = fixture.store.beginGenerationCheckpoint({
      launchId: fixture.launchId,
      expectedLeaseVersion: fixture.leaseVersion,
      expectedGenerationRowVersion: revoking.generation.rowVersion,
      quiesceId: 'lifecycle-quiesce'
    });
    const workspaceState = (await fixture.store.artifacts.readCanonical(
      closure.latestCheckpoint.workspaceStateRef
    )) as WorkspaceStateManifest;
    const entries = (await fixture.store.artifacts.readCanonical(
      workspaceState.entriesRef
    )) as WorkspaceEntryManifest;
    const checkpointId = identityHash('cliq-checkpoint-test-v1', fixture.runId, 'sealed');
    const sealedSnapshot: WorkspaceGenerationSnapshotEvidenceV1 = {
      schemaVersion: 1,
      format: 'cliq-workspace-generation-snapshot-evidence-v1',
      purpose: 'sealed_to_checkpoint',
      runId: fixture.runId,
      generationRef: fixture.generationRef,
      generationIdentityDigest: closure.workspaceGenerations[0]!.generationIdentityDigest,
      checkpointId,
      workspaceStateRef: closure.latestCheckpoint.workspaceStateRef,
      workspaceStateDigest: workspaceState.stateDigest,
      entriesRef: workspaceState.entriesRef,
      treeDigest: entries.treeDigest,
      descriptorRewalkComplete: true,
      fileFsyncComplete: true,
      directoryFsyncComplete: true,
      observedAt: sampleCanonicalNow(),
      evidenceDigest: ''
    };
    sealedSnapshot.evidenceDigest = digestOmitting(sealedSnapshot, 'evidenceDigest');
    const sealedSnapshotArtifact = await fixture.store.artifacts.publishCanonical(
      sealedSnapshot,
      sealedSnapshot.format
    );
    const retirement = await fixture.store.artifacts.publishCanonical(
      { schemaVersion: 1, format: 'cliq-worker-retirement-test-v1', launchId: fixture.launchId },
      'cliq-worker-retirement-evidence-v1'
    );
    const sealed = await fixture.store.sealWorkerGeneration({
      launchId: fixture.launchId,
      expectedRunRevision: completed.run.revision,
      expectedGenerationRowVersion: checkpointing.generation.rowVersion,
      quiesceId: 'lifecycle-quiesce',
      checkpointId,
      contextManifestRef: closure.latestCheckpoint.contextManifestRef,
      workspaceStateRef: closure.latestCheckpoint.workspaceStateRef,
      snapshotEvidenceRef: sealedSnapshotArtifact.ref,
      snapshotEvidenceDigest: sealedSnapshot.evidenceDigest,
      retirementEvidenceRef: retirement.ref,
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
  const fixture = await createActiveFixture('singleflight');
  try {
    const request = await fixture.store.artifacts.publishCanonical({ request: true }, 'cliq-tool-request-v1');
    const prepared = await fixture.store.prepareInvocation({
      runId: fixture.runId,
      expectedRunRevision: fixture.runRevision,
      leaseEpoch: fixture.leaseEpoch,
      opId: 'singleflight-op',
      opKind: 'tool',
      target: 'test.effect',
      requestRef: request.ref,
      replayClass: 'manual',
      reservation: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }
    });
    const claimInput = {
      runId: fixture.runId,
      expectedRunRevision: prepared.run.revision,
      leaseEpoch: fixture.leaseEpoch,
      opId: prepared.entry.opId,
      attempt: 0,
      dispatchId: 'singleflight-dispatch',
      brokerFenceTokenDigest: digest('singleflight:fence')
    };
    await fixture.store.claimInvocationDispatch(claimInput);
    await assert.rejects(
      fixture.store.claimInvocationDispatch({ ...claimInput, dispatchId: 'losing-dispatch' }),
      (error) => error instanceof KernelStorageError && error.code === 'STATE_TRANSITION_INVALID'
    );
  } finally {
    await disposeFixture(fixture);
  }
});

test('recovery requires every terminal Journal artifact to remain in CAS', async () => {
  const fixture = await createActiveFixture('recovery-terminal-cas');
  try {
    const request = await fixture.store.artifacts.publishCanonical(
      { schemaVersion: 1, format: 'cliq-tool-request-test-v1' },
      'cliq-tool-request-v1'
    );
    const prepared = await fixture.store.prepareInvocation({
      runId: fixture.runId,
      expectedRunRevision: fixture.runRevision,
      leaseEpoch: fixture.leaseEpoch,
      opId: 'missing-result-op',
      opKind: 'tool',
      target: 'test.read',
      requestRef: request.ref,
      replayClass: 'retry',
      idempotencyKey: 'missing-result-op-attempt-0',
      reservation: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }
    });
    await fixture.store.claimInvocationDispatch({
      runId: fixture.runId,
      expectedRunRevision: prepared.run.revision,
      leaseEpoch: fixture.leaseEpoch,
      opId: prepared.entry.opId,
      attempt: 0,
      dispatchId: 'missing-result-dispatch',
      brokerFenceTokenDigest: digest('missing-result:fence')
    });
    const result = await fixture.store.artifacts.publishCanonical(
      { schemaVersion: 1, format: 'cliq-tool-result-test-v1', ok: true },
      'cliq-tool-result-v1'
    );
    await fixture.store.completeInvocation({
      runId: fixture.runId,
      opId: prepared.entry.opId,
      attempt: 0,
      expectedRunRevision: prepared.run.revision,
      resultRef: result.ref,
      consumed: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }
    });

    await rm(path.join(fixture.stateRoot, 'cas', result.ref));
    await assert.rejects(
      fixture.store.readRecoveryClosure(fixture.runId),
      (error) => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED'
    );
  } finally {
    await disposeFixture(fixture);
  }
});

test('budget reservation and revoked generation fence dispatch and heartbeat', async () => {
  const fixture = await createActiveFixture('fencing');
  try {
    const request = await fixture.store.artifacts.publishCanonical({ request: true }, 'cliq-model-request-v1');
    await assert.rejects(
      fixture.store.prepareInvocation({
        runId: fixture.runId,
        expectedRunRevision: fixture.runRevision,
        leaseEpoch: fixture.leaseEpoch,
        opId: 'over-budget',
        opKind: 'model',
        target: 'test.model',
        requestRef: request.ref,
        replayClass: 'retry',
        reservation: {
          modelTokens: 2_000_001,
          costMicros: 0,
          toolCalls: 0,
          repairAttempts: 0
        }
      }),
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
    const channel = await publishInProcessChannel(store, 'cliq-m2-principal');
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
        principalId: 'cliq-m2-principal',
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
    const principalId = 'cliq-m2-principal';
    const published = await publishInProcessChannel(store, principalId);
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
      (error) => error instanceof KernelStorageError && error.code === 'INVALID_REQUEST'
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
    const channel = await publishInProcessChannel(store, 'cliq-m2-principal');
    await rename(lockPath, displacedPath);
    await writeFile(lockPath, '', { mode: 0o600 });
    await assert.rejects(
      store.createSession({
        principalId: 'cliq-m2-principal',
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
