import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { ProcessContainment, SourceManifest, WorkerIdentity, WorkspaceEntryManifest, WorkspaceGenerationIdentityV1 } from '../kernel/types.js';
import { publishInProcessChannel } from './store.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { readActiveStateOwner } from './state-owner.js';
import { assertBuiltinEditLaunchClosure, assertWorkerLaunchClosure, readBuiltinEditLaunchClosure, readRetainedWorkerLaunchClosure, readWorkerLaunchClosure } from './execution-closure.js';
import type { ToolOperationGrantV1 } from '../kernel/tool-authorization.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import { createQueuedFixture, prepareFixtureGeneration, disposeFixture, digest, uuidv7, admissionKey } from './testing/fixtures.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { batch, prepareTool } from './testing/tool-calls.js';
import { publishFixtureEditLaunch, publishFixtureWorkerLaunch } from './testing/worker-launch.js';

function retainedOwner(stateRoot: string) {
  const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
  try { return readActiveStateOwner(driver)!; } finally { driver.close(); }
}

test('worker reservation rejects a canonical launch closed over another Run without changing authority', async () => {
  const fixture = await createQueuedFixture('closed-launch');
  try {
    const { store, runId } = fixture;
    const { generationArtifact } = await prepareFixtureGeneration(fixture, 'closed-launch');
    const initial = await store.readRecoveryClosure(runId);
    const launch = await publishFixtureWorkerLaunch(fixture, generationArtifact.ref, 'closed-launch');
    const plan = structuredClone(launch.plan); const spec = structuredClone(launch.spec);
    if (plan.owner.kind !== 'worker_activation') throw new Error('fixture must bind a worker activation');
    plan.owner.runId = 'a-different-run'; spec.owner.runId = 'a-different-run';
    plan.planDigest = digestOmitting(plan, 'planDigest');
    const planArtifact = await store.artifacts.publishCanonical(plan, plan.format);
    spec.containmentPlanRef = planArtifact.ref; spec.containmentPlanDigest = plan.planDigest;
    spec.launchSpecDigest = digestOmitting(spec, 'launchSpecDigest');
    const specArtifact = await store.artifacts.publishCanonical(spec, spec.format);
    await assert.rejects(store.reserveWorkerLaunch({ ...launch.input, containmentPlanRef: planArtifact.ref, sandboxLaunchSpecRef: specArtifact.ref }),
      { code: 'ARTIFACT_MISMATCH' });
    const unchanged = await store.readRecoveryClosure(runId);
    assert.deepEqual(unchanged.run, initial.run);
    assert.deepEqual(unchanged.workerLaunches, []);
    const reserved = await store.reserveWorkerLaunch(launch.input);
    assert.equal(reserved.phase, 'reserved');
    assert.equal(reserved.runId, runId);
    const execution = await readWorkerLaunchClosure(store.artifacts, retainedOwner(fixture.stateRoot), { ...launch.input, run: store.getRun(runId) });
    assert.throws(() => assertWorkerLaunchClosure(structuredClone(execution)), { code: 'ARTIFACT_MISMATCH' });
    assert.doesNotThrow(() => assertWorkerLaunchClosure(execution));
  } finally { await disposeFixture(fixture); }
});

test('worker reservation commits the immutable launch input validated before asynchronous artifact reads', async t => {
  const fixture = await createQueuedFixture('reservation-input-snapshot');
  try {
    const { generationArtifact } = await prepareFixtureGeneration(fixture, 'reservation-input-snapshot');
    const launch = await publishFixtureWorkerLaunch(fixture, generationArtifact.ref, 'reservation-input-snapshot');
    const unrelated = await fixture.store.artifacts.publishCanonical({ notALaunch: true }, 'cliq-test-unrelated-v1');
    const input = { ...launch.input };
    let reached!: () => void, release!: () => void;
    const described = new Promise<void>(resolve => { reached = resolve; });
    const barrier = new Promise<void>(resolve => { release = resolve; });
    const describe = fixture.store.artifacts.describe.bind(fixture.store.artifacts);
    t.mock.method(fixture.store.artifacts, 'describe', async (...args: Parameters<typeof describe>) => {
      const metadata = await describe(...args);
      if (args[0] === launch.input.sandboxLaunchSpecRef) { reached(); await barrier; }
      return metadata;
    });
    const pending = fixture.store.reserveWorkerLaunch(input);
    await described;
    input.sandboxLaunchSpecRef = unrelated.ref;
    input.spawnNonceDigest = unrelated.ref;
    input.activationNonceDigest = unrelated.ref;
    release();
    const reserved = await pending;
    assert.equal(reserved.sandboxLaunchSpecRef, launch.input.sandboxLaunchSpecRef);
    assert.equal(reserved.spawnNonceDigest, launch.input.spawnNonceDigest);
    assert.equal(reserved.activationNonceDigest, launch.input.activationNonceDigest);
  } finally { await disposeFixture(fixture); }
});

test('retained worker recovery reads its actual epoch and immutable source checkpoint after continuation advances', async () => {
  const fixture = await createAgentFixture('retained-worker-closure', undefined, { mode: 'plan' });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }]);
    await fixture.store.beginWorkerRecovery({ runId: fixture.runId, expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    const launch = cut.workerLaunches[0]!, generation = cut.workspaceGenerations[0]!;
    assert.notEqual(generation.sourceCheckpointId, cut.run.latestCheckpointId);
    const input = { run: cut.run, launch, generation };
    const execution = await readRetainedWorkerLaunchClosure(fixture.store.artifacts, retainedOwner(fixture.stateRoot), input);
    assertWorkerLaunchClosure(execution);
    assert.equal(execution.spec.owner.intendedLeaseEpoch, cut.run.leaseEpoch);
    assert.equal(execution.generation.sourceCheckpointId, generation.sourceCheckpointId);
    await assert.rejects(readRetainedWorkerLaunchClosure(fixture.store.artifacts, retainedOwner(fixture.stateRoot), {
      ...input, generation: { ...generation, sourceCheckpointId: cut.run.latestCheckpointId }
    }), { code: 'ARTIFACT_MISMATCH' });
  } finally { await disposeFixture(fixture); }
});

test('generation registration rejects rehashed identities with a wrong equation or platform-relative locator', async () => {
  const fixture = await createQueuedFixture('generation-equation');
  try {
    const prepared = await prepareFixtureGeneration(fixture, 'generation-equation');
    const identity = await fixture.store.artifacts.readCanonical<WorkspaceGenerationIdentityV1>(prepared.generationArtifact.ref);
    if (identity.locator.kind !== 'linux_directory') throw new Error('fixture must retain a Linux identity');
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const wrongEquation: WorkspaceGenerationIdentityV1 = { ...identity, generationId: 'wrong-generation-equation',
      locator: { ...identity.locator, canonicalRootRelativePath: `runs/${fixture.runId}/generations/wrong-generation-equation` } };
    const macNonce = digest('mac-generation-nonce');
    const macId = identityHash(identity.runId, identity.sourceCheckpointId, identity.sourceWorkspaceStateRef, macNonce);
    const wrongMacPath: WorkspaceGenerationIdentityV1 = { ...identity, generationId: macId, creationNonceDigest: macNonce,
      locator: { kind: 'macos_vm_volume', stateRootIdentityRef: identity.locator.stateRootIdentityRef, stateRootIdentityDigest: identity.locator.stateRootIdentityDigest,
        backingStoreCanonicalRootRelativePath: `runs/${fixture.runId}/generations/${macId}`, backingStoreDeviceId: '1', backingStoreFileId: '2',
        backingStoreOwnerUid: process.geteuid!(), backingStoreMode: 384, backingStoreLinkCount: 1,
        vmVolumeReservationId: 'development-reservation', guestVolumeId: 'development-volume' } };
    for (const wrong of [wrongEquation, wrongMacPath]) {
      wrong.identityDigest = digestOmitting(wrong, 'identityDigest');
      const artifact = await fixture.store.artifacts.publishCanonical(wrong, wrong.format);
      await assert.rejects(fixture.store.registerWorkspaceGeneration({ runId: fixture.runId,
        generationRef: artifact.ref, generationIdentityDigest: wrong.identityDigest }), { code: 'ARTIFACT_MISMATCH' });
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    }
  } finally { await disposeFixture(fixture); }
});

test('worker preactivation rejects a retained executable identity outside its signed launch contract', async () => {
  const fixture = await createQueuedFixture('preactivation-closure');
  try {
    const prepared = await prepareFixtureGeneration(fixture, 'preactivation-closure');
    const launch = await publishFixtureWorkerLaunch(fixture, prepared.generationArtifact.ref, 'preactivation-closure');
    const reservation = await fixture.store.reserveWorkerLaunch(launch.input);
    if (launch.plan.backend.kind !== 'linux' || launch.spec.executable.kind !== 'runtime_bundle') throw new Error('fixture must be a Linux retained launch');
    const containment: ProcessContainment = { schemaVersion: 1, planRef: launch.input.containmentPlanRef,
      sandboxLaunchSpecRef: launch.input.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: launch.spec.launchSpecDigest,
      owner: launch.plan.owner, filesystemBinding: launch.plan.filesystemBinding, launchNonceDigest: launch.plan.launchNonceDigest,
      backend: { kind: 'linux', cgroupPath: launch.plan.backend.cgroupPath, cgroupId: 'development-cgroup',
        pidNamespaceReservationId: launch.plan.backend.pidNamespaceReservationId, pidNamespaceId: 'pid:[development]',
        namespaceInitStartToken: 'development-init', subreaperStartToken: launch.plan.backend.subreaperStartToken }, createdAt: launch.spec.createdAt };
    const containmentArtifact = await fixture.store.artifacts.publishCanonical(containment, 'cliq-process-containment-v1');
    const identity: WorkerIdentity = { schemaVersion: 1, executableRealpath: launch.spec.executable.executionPath,
      executableDigest: digest('not-the-signed-worker'), pid: process.pid, processStartToken: 'development-process-start',
      spawnNonceDigest: reservation.spawnNonceDigest, activationNonceDigest: reservation.activationNonceDigest,
      intendedLeaseEpoch: launch.spec.owner.intendedLeaseEpoch, launchId: reservation.launchId,
      supervisorInstanceId: reservation.supervisorInstanceId, processContainmentRef: containmentArtifact.ref };
    const wrong = await fixture.store.artifacts.publishCanonical(identity, 'cliq-worker-identity-v1');
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.store.recordWorkerPreactivated({ launchId: reservation.launchId,
      workerIdentityDigest: wrong.ref, processContainmentRef: containmentArtifact.ref }), { code: 'ARTIFACT_MISMATCH' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    identity.executableDigest = launch.spec.executable.executableDigest;
    const right = await fixture.store.artifacts.publishCanonical(identity, 'cliq-worker-identity-v1');
    await fixture.store.recordWorkerPreactivated({ launchId: reservation.launchId, workerIdentityDigest: right.ref, processContainmentRef: containmentArtifact.ref });
    const activated = fixture.store.activateWorkerLease({ launchId: reservation.launchId, expectedRunRevision: reservation.plannedRunRevision,
      expectedGenerationRowVersion: prepared.preactivatedGeneration.rowVersion, leaseDurationMs: 60000 });
    assert.equal(activated.run.status, 'running');
    assert.equal(activated.launch.workerIdentityDigest, right.ref);
  } finally { await disposeFixture(fixture); }
});

test('worker reservation rejects nonadjacent overlapping canonical mount targets', async () => {
  const fixture = await createQueuedFixture('mount-overlap');
  try {
    const { generationArtifact } = await prepareFixtureGeneration(fixture, 'mount-overlap');
    const launch = await publishFixtureWorkerLaunch(fixture, generationArtifact.ref, 'mount-overlap');
    const wrong = structuredClone(launch.spec);
    wrong.mounts.splice(1, 0,
      { kind: 'private_ephemeral', privateRootId: 'sibling-root', targetPath: '/home/cliq-other', access: 'read_write', purpose: 'dependency' },
      { kind: 'private_ephemeral', privateRootId: 'nested-root', targetPath: '/home/cliq/dependency', access: 'read_write', purpose: 'dependency' });
    wrong.mountsDigest = canonicalSha256(wrong.mounts); wrong.launchSpecDigest = digestOmitting(wrong, 'launchSpecDigest');
    const artifact = await fixture.store.artifacts.publishCanonical(wrong, wrong.format);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.store.reserveWorkerLaunch({ ...launch.input, sandboxLaunchSpecRef: artifact.ref }), { code: 'ARTIFACT_MISMATCH' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    assert.equal((await fixture.store.reserveWorkerLaunch(launch.input)).phase, 'reserved');
  } finally { await disposeFixture(fixture); }
});

test('typed edit permanent claim closes its canonical launch over the exact dispatch and parent activation', async () => {
  const fixture = await createAgentFixture('edit-launch-closure', undefined, { tools: ['edit'], mode: 'yolo' });
  try {
    await batch(fixture, [{ name: 'edit', input: { path: 'a', old_text: 'before', new_text: 'after' } }]);
    const prepared = await prepareTool(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const wrong = await publishFixtureEditLaunch(fixture, prepared, 'other-dispatch');
    const input = { expectedRunRevision: prepared.run.revision, leaseEpoch: fixture.leaseEpoch,
      opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'current-dispatch' };
    await assert.rejects(fixture.agent.claimTool({ ...input, sandboxLaunchSpecRef: wrong.sandboxLaunchSpecRef }), { code: 'ARTIFACT_MISMATCH' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    const right = await publishFixtureEditLaunch(fixture, prepared, input.dispatchId);
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    const execution = await readBuiltinEditLaunchClosure(fixture.store.artifacts, retainedOwner(fixture.stateRoot), {
      run: cut.run, launch: cut.workerLaunches[0]!, generation: cut.workspaceGenerations[0]!, prepared: prepared.entry,
      request: prepared.request, target: prepared.target,
      grant: await fixture.store.artifacts.readCanonical<ToolOperationGrantV1>(prepared.entry.grantRef!),
      call: await fixture.store.artifacts.readCanonical<ToolCallInputV1>(prepared.request.inputRef),
      dispatchId: input.dispatchId, sandboxLaunchSpecRef: right.sandboxLaunchSpecRef
    });
    assert.throws(() => assertBuiltinEditLaunchClosure(structuredClone(execution)), { code: 'ARTIFACT_MISMATCH' });
    assert.doesNotThrow(() => assertBuiltinEditLaunchClosure(execution));
    const claim = await fixture.agent.claimTool({ ...input, sandboxLaunchSpecRef: right.sandboxLaunchSpecRef });
    assert.equal(claim.entry.sandboxLaunchSpecRef, right.sandboxLaunchSpecRef);
    assert.equal(claim.entry.phase, 'dispatch_claimed');
  } finally { await disposeFixture(fixture); }
});

test('Run admission rejects a workspace tree digest that includes derived manifest counters', async () => {
  const fixture = await createQueuedFixture('tree-digest');
  try {
    const { store } = fixture;
    const closure = await store.readRecoveryClosure(fixture.runId);
    const base = await store.artifacts.readCanonical<SourceManifest>(closure.runSpec.baseWorkspaceManifestRef);
    const entries = await store.artifacts.readCanonical<WorkspaceEntryManifest>(base.entriesRef);
    // This was the old implementation's equation, not RFC 4116's tree identity.
    entries.treeDigest = digestOmitting(entries, 'treeDigest');
    const badEntries = await store.artifacts.publishCanonical(entries, entries.format);
    const badBase = { ...base, entriesRef: badEntries.ref, treeDigest: entries.treeDigest };
    badBase.manifestDigest = digestOmitting(badBase, 'manifestDigest');
    const badSource = await store.artifacts.publishCanonical(badBase, badBase.format);
    const channel = await publishInProcessChannel(store);
    const session = await store.createSession({ ...channel, requestId: uuidv7(), admissionKey: admissionKey('tree-digest-second-session'), workspacePath: fixture.workspace });
    const before = store.getSession(session.session.id);
    await assert.rejects(store.admitRun({ ...channel, requestId: uuidv7(), admissionKey: admissionKey('tree-digest-bad-run'),
      sessionId: before.id, expectedContextRevision: before.contextRevision, workspacePath: fixture.workspace, objective: 'reject invalid tree identity',
      allowUnverified: true, baseWorkspaceManifestRef: badSource.ref, sourceProjectionRef: closure.runSpec.sourceProjectionRef,
      frozenIgnoreRulesRef: base.frozenIgnoreRulesRef, assemblyRef: closure.runSpec.assemblyRef, policyRef: closure.runSpec.policyRef,
      sandboxProfileRef: closure.runSpec.sandboxProfileRef, verifierSpecRef: closure.runSpec.verifierSpecRef }), { code: 'ARTIFACT_MISMATCH' });
    assert.deepEqual(store.getSession(before.id), before);
  } finally { await disposeFixture(fixture); }
});
