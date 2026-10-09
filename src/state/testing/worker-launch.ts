import { canonicalSha256 } from '../../kernel/canonical.js';
import { digestOmitting, identityHash } from '../../kernel/identity.js';
import type { ProcessContainmentPlanV1, SandboxLaunchSpecV1, SandboxProfileV1, SandboxRuntimeBindingV1,
  SanitizedSandboxEnvironmentV1 } from '../../kernel/execution.js';
import type { RunAssemblyV1 } from '../../kernel/types.js';
import type { createAgentFixture } from './agent-fixtures.js';
import type { prepareTool } from './tool-calls.js';
import type { RuntimeBundleManifest } from '../../policy/runtime-authority.js';
import { STATE_OWNER_NATIVE_ENTRY_ID } from '../native-owner.js';
import { sampleCanonicalNow } from '../canonical-time.js';
import { digest, type ActiveFixture } from './fixtures.js';

/** Canonical retained metadata only, not evidence of a qualified installed sandbox or actual process. */
export function fixtureSandboxProfile(): SandboxProfileV1 {
  const profile: SandboxProfileV1 = { schemaVersion: 1, format: 'cliq-sandbox-profile-v1', backend: 'linux_namespace',
    allowedOwners: ['run_invocation', 'worker_activation'], filesystemPolicy: 'typed_launch_spec_only', hostFilesystemReachability: 'none',
    networkAtSpawn: 'none', networkAfterRelease: 'typed_broker_only', credentialReachability: 'typed_broker_only',
    stateRootReachability: 'none', inheritedHostEnvironment: false,
    resources: { maxProcesses: 256, memoryBytes: 4 * 1024 ** 3, cpuQuotaMicrosPerSecond: 400000, maxOpenFiles: 1024,
      maxSingleFileBytes: 2 * 1024 ** 3, maxGenerationBytes: 20 * 1024 ** 3, maxInvocationOutputBytes: 16 * 1024 ** 2,
      maxIpcFrameBytes: 16 * 1024 ** 2, maxQueuedIpcBytes: 64 * 1024 ** 2 }, profileDigest: '' };
  profile.profileDigest = digestOmitting(profile, 'profileDigest');
  return profile;
}

/** Canonical retained edit launch only: no spawn and no execution capability. */
export async function publishFixtureEditLaunch(fixture: Awaited<ReturnType<typeof createAgentFixture>>,
  prepared: Awaited<ReturnType<typeof prepareTool>>, dispatchId: string) {
  const { store } = fixture;
  const closure = await store.readRecoveryClosure(fixture.runId);
  const parent = closure.workerLaunches.find((launch) => launch.launchId === closure.run.activeWorkerLaunchId)!;
  const worker = await store.artifacts.readCanonical<Extract<SandboxLaunchSpecV1, { purpose: 'worker_activation' }>>(parent.sandboxLaunchSpecRef);
  const owner = { kind: 'run_invocation' as const, runId: fixture.runId, intendedLeaseEpoch: closure.run.leaseEpoch,
    workerLaunchId: parent.launchId, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId };
  const plan: ProcessContainmentPlanV1 = { schemaVersion: 1, format: 'cliq-process-containment-plan-v1', owner,
    filesystemBinding: { kind: 'run-generation', generationRef: parent.workspaceGenerationRef }, parentContainmentRef: parent.processContainmentRef!,
    launchNonceDigest: digest(`edit-${dispatchId}:nonce`), backend: { kind: 'linux', cgroupPath: `/cliq/development-fixture/${digest(dispatchId)}`,
      cgroupNameReservationDigest: digest(`edit-${dispatchId}:cgroup-reservation`), pidNamespaceReservationId: `edit-${dispatchId}-namespace`,
      subreaperStartToken: 'test-subreaper' }, createdAt: sampleCanonicalNow(), planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest');
  const planArtifact = await store.artifacts.publishCanonical(plan, plan.format);
  if (prepared.target.execution.kind !== 'builtin') throw new Error('retained fixture requires builtin edit');
  const spec: Extract<SandboxLaunchSpecV1, { owner: { kind: 'run_invocation' } }> = { ...worker, owner, purpose: 'tool',
    executable: { kind: 'runtime_bundle', runtimeBundleRef: worker.runtime.runtimeBundleRef, runtimeBundleManifestDigest: worker.runtime.runtimeBundleManifestDigest,
      executableId: prepared.target.execution.adapterId, role: 'tool_adapter', executionPath: '/cliq/runtime/edit', executableDigest: prepared.target.execution.adapterCodeDigest },
    processInvocation: { kind: 'run_request', purpose: 'tool', recipe: 'cliq-tool-launch-v1', requestRef: prepared.entry.requestRef,
      requestDigest: prepared.request.requestDigest, targetRef: prepared.entry.target, targetDigest: prepared.target.targetDigest,
      argvCwdSource: 'trusted_recipe_decode_of_request_and_target', stdio: { stdin: 'closed', stdout: 'captured', stderr: 'captured', extraFileDescriptors: 'authenticated_operation_channel_only' } },
    filesystem: { kind: 'run_generation', generationRef: parent.workspaceGenerationRef, access: 'read_write', sourceProjectionRef: closure.runSpec.sourceProjectionRef, independentGit: true },
    operationGrantRef: prepared.entry.grantRef!, requestRef: prepared.entry.requestRef, requestDigest: prepared.request.requestDigest,
    targetRef: prepared.entry.target, targetDigest: prepared.target.targetDigest, parentWorkerContainmentRef: parent.processContainmentRef!,
    containmentPlanRef: planArtifact.ref, containmentPlanDigest: plan.planDigest, createdAt: sampleCanonicalNow(), launchSpecDigest: '' };
  spec.launchSpecDigest = digestOmitting(spec, 'launchSpecDigest');
  const artifact = await store.artifacts.publishCanonical(spec, spec.format);
  return { spec, plan, sandboxLaunchSpecRef: artifact.ref };
}

export async function publishFixtureWorkerLaunch(
  fixture: Pick<ActiveFixture, 'store' | 'runId'>, generationRef: string, label: string
) {
  const { store, runId } = fixture;
  const closure = await store.readRecoveryClosure(runId);
  const assembly = await store.artifacts.readCanonical<RunAssemblyV1>(closure.runSpec.assemblyRef);
  const profile = await store.artifacts.readCanonical<SandboxProfileV1>(closure.runSpec.sandboxProfileRef);
  const bundle = await store.artifacts.readCanonical<RuntimeBundleManifest>(assembly.runtime.runtimeBundleRef);
  const launchId = identityHash('cliq-worker-launch-test-v1', runId, label);
  const spawnNonceDigest = digest(`${label}:spawn`);
  const owner = { kind: 'worker_activation' as const, runId, intendedLeaseEpoch: closure.run.leaseEpoch + 1, workerLaunchId: launchId };
  const plan: ProcessContainmentPlanV1 = { schemaVersion: 1, format: 'cliq-process-containment-plan-v1', owner,
    filesystemBinding: { kind: 'run-generation', generationRef }, launchNonceDigest: spawnNonceDigest,
    backend: { kind: 'linux', cgroupPath: '/cliq/development-fixture', cgroupNameReservationDigest: digest(`${label}:cgroup-reservation`),
      pidNamespaceReservationId: `${label}-namespace`, subreaperStartToken: 'test-subreaper' }, createdAt: sampleCanonicalNow(), planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest');
  const planArtifact = await store.artifacts.publishCanonical(plan, plan.format);
  const launcher = bundle.entries.find((entry) => entry.entryId === STATE_OWNER_NATIVE_ENTRY_ID)!;
  const runtime: SandboxRuntimeBindingV1 = { runtimeBundleRef: assembly.runtime.runtimeBundleRef,
    runtimeBundleManifestDigest: assembly.runtime.runtimeBundleManifestDigest, sandboxBackend: 'linux_namespace', toolchain: { kind: 'none' },
    launcher: { executableId: launcher.entryId, executableDigest: launcher.digest }, runtimeDigest: '' };
  runtime.runtimeDigest = digestOmitting(runtime, 'runtimeDigest');
  const environment: SanitizedSandboxEnvironmentV1 = { schemaVersion: 1, format: 'cliq-sanitized-sandbox-environment-v1',
    controlledPath: ['/cliq/runtime'], locale: { lang: 'C.UTF-8', lcAll: 'C.UTF-8' }, home: '/home/cliq', tmpdir: '/tmp', variables: [],
    inheritedHostEnvironment: false, secretMaterial: 'none', brokerAccessAtSpawn: 'none', networkMode: 'none', environmentDigest: '' };
  environment.environmentDigest = digestOmitting(environment, 'environmentDigest');
  const spec: Extract<SandboxLaunchSpecV1, { purpose: 'worker_activation' }> = { schemaVersion: 1, format: 'cliq-sandbox-launch-v1', owner,
    purpose: 'worker_activation', runtime, executable: { kind: 'runtime_bundle', runtimeBundleRef: runtime.runtimeBundleRef,
      runtimeBundleManifestDigest: runtime.runtimeBundleManifestDigest, executableId: assembly.runtime.workerExecutableId, role: 'worker',
      executionPath: `/cliq/runtime/${assembly.runtime.workerExecutableId}`, executableDigest: assembly.runtime.workerExecutableDigest },
    processInvocation: { kind: 'worker_entrypoint', purpose: 'worker_activation', recipe: 'cliq-worker-entrypoint-v1', runtimeSource: 'launch_runtime',
      executableSource: 'launch_executable', argvSource: 'fixed_empty', cwdSource: 'generation_root', stdio: { stdin: 'closed', stdout: 'captured',
        stderr: 'captured', extraFileDescriptors: 'authenticated_worker_channel_only' } }, environment,
    filesystem: { kind: 'run_generation', generationRef, access: 'preactivated_readonly', sourceProjectionRef: closure.runSpec.sourceProjectionRef, independentGit: true },
    mounts: [{ kind: 'private_ephemeral', privateRootId: `${label}-home`, targetPath: '/home/cliq', access: 'read_write', purpose: 'home' },
      { kind: 'private_ephemeral', privateRootId: `${label}-tmp`, targetPath: '/tmp', access: 'read_write', purpose: 'tmp' }],
    mountsDigest: '', sandboxProfileRef: closure.runSpec.sandboxProfileRef, sandboxProfileDigest: profile.profileDigest,
    resources: profile.resources, resourcesDigest: canonicalSha256(profile.resources), containmentPlanRef: planArtifact.ref,
    containmentPlanDigest: plan.planDigest, createdAt: sampleCanonicalNow(), launchSpecDigest: '' };
  spec.mountsDigest = canonicalSha256(spec.mounts); spec.launchSpecDigest = digestOmitting(spec, 'launchSpecDigest');
  const specArtifact = await store.artifacts.publishCanonical(spec, spec.format);
  return { plan, spec, input: { launchId, runId, expectedRunRevision: closure.run.revision, spawnNonceDigest,
    activationNonceDigest: digest(`${label}:activate`), workspaceGenerationRef: generationRef,
    containmentPlanRef: planArtifact.ref, sandboxLaunchSpecRef: specArtifact.ref } };
}
