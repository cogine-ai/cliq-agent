import { randomFillSync } from 'node:crypto';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { digestOmitting, identityHash, sha256Bytes } from '../../kernel/identity.js';
import type {
  FrozenIgnoreRulesV1, RunSpec, SourceManifest, SourceProjectionSpec, VerifierSpec,
  WorkerIdentity, WorkspaceEntryManifest, WorkspaceGenerationIdentityV1,
  WorkspaceGenerationSnapshotEvidenceV1, WorkspaceIdentityV1, WorkspaceStateManifest
} from '../../kernel/types.js';
import { sampleCanonicalNow } from '../canonical-time.js';
import { openStateStore, publishInProcessChannel, type StateStore, type StateStoreRuntimeAuthority } from '../store.js';

export function uuidv7(): string {
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

export function admissionKey(label: string): string {
  return Buffer.from(label.padEnd(16, '0')).toString('base64url');
}

export function digest(label: string): string {
  return sha256Bytes(Buffer.from(label, 'utf8'));
}

export async function makePrivateDir(prefix: string): Promise<string> {
  const directory = await mkdtemp(path.join(process.cwd(), prefix));
  await chmod(directory, 0o700);
  return directory;
}

/** M2-only placeholder closure for reducer/control integration tests; never public admission. */
export async function publishEmptySourceGraph(store: StateStore, workspaceIdentityDigest: string) {
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

export type ActiveFixture = {
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

export type ActiveFixtureOptions = {
  runtimeAuthority?: StateStoreRuntimeAuthority;
  runWallTimeMs?: number;
  leaseDurationMs?: number;
  assembly?: (store: StateStore) => Promise<string>;
  policy?: (store: StateStore, identity: WorkspaceIdentityV1) => Promise<string>;
  budgets?: Partial<RunSpec['budgets']>;
  credentialGrantRefs?: string[];
};

export async function createActiveFixture(
  label: string,
  options: ActiveFixtureOptions = {}
): Promise<ActiveFixture> {
  const stateRoot = await makePrivateDir(`.cliq-m2-${label}-state-`);
  const workspace = await makePrivateDir(`.cliq-m2-${label}-ws-`);
  const store = await openStateStore(stateRoot, options.runtimeAuthority);
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
  if (options.assembly) source.assemblyRef = await options.assembly(store);
  if (options.policy) source.policyRef = await options.policy(store, workspaceIdentity);
  const admitted = await store.admitRun({
    principalId,
    requestId: uuidv7(),
    admissionKey: admissionKey(`${label}-run`),
    sessionId: session.session.id,
    expectedContextRevision: 1,
    workspacePath: workspace,
    objective: `exercise ${label}`,
    allowUnverified: true,
    credentialGrantRefs: options.credentialGrantRefs,
    budgets: {
      ...options.budgets,
      ...(options.runWallTimeMs === undefined ? {} : { wallTimeMs: options.runWallTimeMs })
    },
    ...channel,
    ...source
  });
  try {
    return { stateRoot, workspace, store, channelIdentityRef: channel.channelIdentityRef,
      ...await activateFixtureWorker({ store, stateRoot, runId: admitted.run.id }, label, options.leaseDurationMs) };
  } catch (error) {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
    throw error;
  }
}

/** A fresh offline generation/worker from the current ready checkpoint, including after a control wait or restart. */
export async function activateFixtureWorker(
  fixture: Pick<ActiveFixture, 'store' | 'stateRoot' | 'runId'>, label: string, leaseDurationMs = 60_000
) {
  const { store, stateRoot, runId } = fixture;
  const run = store.getRun(runId);
  const initial = await store.readRecoveryClosure(runId);
  const workspaceIdentity = await store.artifacts.readCanonical<WorkspaceIdentityV1>(store.getSession(run.sessionId).workspaceIdentityRef);
  const workspaceState = (await store.artifacts.readCanonical(
    initial.latestCheckpoint.workspaceStateRef
  )) as WorkspaceStateManifest;
  const entries = await store.artifacts.readCanonical<WorkspaceEntryManifest>(workspaceState.entriesRef);
  const stateRootFixture = await store.artifacts.publishCanonical(
    { schemaVersion: 1, format: 'cliq-state-root-test-fixture-v1', stateRoot },
    'cliq-state-root-test-fixture-v1'
  );
  const generationId = identityHash('cliq-workspace-generation-test-v1', runId, label);
  const identity: WorkspaceGenerationIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-workspace-generation-identity-v1',
    generationId,
    runId: runId,
    workspaceIdentityDigest: workspaceIdentity.identityDigest,
    sourceCheckpointId: initial.latestCheckpoint.id,
    sourceWorkspaceStateRef: initial.latestCheckpoint.workspaceStateRef,
    sourceWorkspaceStateDigest: workspaceState.stateDigest,
    sourceTreeDigest: entries.treeDigest,
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
          mode: 448
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
    runId: runId,
    generationRef: generationArtifact.ref,
    generationIdentityDigest: identity.identityDigest
  });
  const snapshot: WorkspaceGenerationSnapshotEvidenceV1 = {
    schemaVersion: 1,
    format: 'cliq-workspace-generation-snapshot-evidence-v1',
    purpose: 'materialized_from_checkpoint',
    runId: runId,
    generationRef: generationArtifact.ref,
    generationIdentityDigest: identity.identityDigest,
    checkpointId: initial.latestCheckpoint.id,
    workspaceStateRef: initial.latestCheckpoint.workspaceStateRef,
    workspaceStateDigest: workspaceState.stateDigest,
    entriesRef: workspaceState.entriesRef,
    treeDigest: entries.treeDigest,
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
  const [plan, launchSpec] = await Promise.all([
    store.artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-containment-plan-test-v1', generationId }, 'cliq-process-containment-plan-v1'),
    store.artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-worker-launch-spec-test-v1', generationId,
      launchSpecDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-worker-launch-spec-test-v1', generationId }) }, 'cliq-sandbox-launch-spec-v1')
  ]);
  const launchId = identityHash('cliq-worker-launch-test-v1', runId, label);
  const reserved = await store.reserveWorkerLaunch({
    launchId,
    runId: runId,
    expectedRunRevision: run.revision,
    spawnNonceDigest: digest(`${label}:spawn`),
    activationNonceDigest: digest(`${label}:activate`),
    workspaceGenerationRef: generationArtifact.ref,
    containmentPlanRef: plan.ref,
    sandboxLaunchSpecRef: launchSpec.ref
  });
  // Offline containment identity only. This fixture never launches or claims to qualify a backend.
  const containment = await store.artifacts.publishCanonical({ schemaVersion: 1, planRef: plan.ref,
    sandboxLaunchSpecRef: launchSpec.ref,
    sandboxLaunchSpecDigest: (await store.artifacts.readCanonical<{ launchSpecDigest: string }>(launchSpec.ref)).launchSpecDigest,
    owner: { kind: 'worker_activation', runId: runId, intendedLeaseEpoch: run.leaseEpoch + 1, workerLaunchId: launchId },
    filesystemBinding: { kind: 'run-generation', generationRef: generationArtifact.ref }, launchNonceDigest: reserved.spawnNonceDigest,
    backend: { kind: 'linux', pidNamespaceReservationId: `${label}-namespace`, pidNamespaceId: 'pid:[test]',
      cgroupPath: '/cliq/test', cgroupId: `${label}-cgroup`, namespaceInitStartToken: 'test-init', subreaperStartToken: 'test-subreaper' },
    createdAt: sampleCanonicalNow()
  }, 'cliq-process-containment-v1');
  const workerIdentity: WorkerIdentity = {
    schemaVersion: 1,
    executableRealpath: '/cliq/test-worker',
    executableDigest: digest(`${label}:worker-executable`),
    pid: process.pid,
    processStartToken: `${process.pid}:test`,
    spawnNonceDigest: reserved.spawnNonceDigest,
    activationNonceDigest: reserved.activationNonceDigest,
    intendedLeaseEpoch: run.leaseEpoch + 1,
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
  const activated = store.activateWorkerLease({ launchId, expectedRunRevision: run.revision,
    expectedGenerationRowVersion: preactivatedGeneration.rowVersion, leaseDurationMs });
  return { runId, runRevision: activated.run.revision, generationId, generationRef: generationArtifact.ref,
    generationRowVersion: activated.generation.rowVersion, launchId, leaseVersion: activated.launch.leaseVersion,
    leaseEpoch: activated.run.leaseEpoch, workerIdentityDigest: workerArtifact.ref };
}

export async function disposeFixture(fixture: ActiveFixture): Promise<void> {
  await fixture.store.close();
  await rm(fixture.stateRoot, { recursive: true, force: true });
  await rm(fixture.workspace, { recursive: true, force: true });
}
