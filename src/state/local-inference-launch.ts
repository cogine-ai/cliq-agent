import { setTimeout as delay } from 'node:timers/promises';
import path from 'node:path';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireRecord } from '../kernel/control-wire-data.js';
import type { ProcessContainment, ProcessContainmentPlanV1, SandboxLaunchSpecV1,
  SandboxRootImageV1, SanitizedSandboxEnvironmentV1, SandboxMountV1 } from '../kernel/execution.js';
import { addCanonicalDuration, digestOmitting, encodeCanonicalTime, identityHash, normalizeAbsolutePath,
  parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeLocalInferenceBoundary, decodeLocalInferenceLaunch, localStableServiceIdentity, localInferenceLaunchId,
  LOCAL_INFERENCE_ACTIVATION_MS, type LocalInferenceActivationCycleV1, type LocalInferenceServiceLaunchV1,
  type LocalModelRegistrationV1 } from '../kernel/local-inference.js';
import { decodeBoundLocalInferenceNativeInput, LOCAL_INFERENCE_NATIVE_INPUT_KIND,
  type LocalInferenceNativeInputData, type LocalInferenceNativeObservation } from '../kernel/local-inference-native-input.js';
import type { StateOwnerRecordV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { assertInstalledLocalInferenceController, type InstalledLocalInferenceController } from '../sandbox/linux-worker.js';
import { requireEqual, verifyRuntimeBundle, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { verifyLocalModelManifestAuthority } from '../policy/local-model-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { decodeStateRootIdentity } from './decoders.js';
import { decodeSandboxRootProfile } from './execution-closure.js';
import { loadInstalledModelBroker, type HeldInstalledRuntime } from './installed-runtime.js';
import { installedLocalInferenceProfile } from './local-inference-profile.js';
import { bindLocalInferenceRuntime, localInferenceRuntimeInputs, localInferenceRuntimeRoots } from './local-inference-runtime.js';
import { InstalledLocalModelNotListeningError, type NativeLocalHealthRequest } from './model-broker-native.js';
import { stateRootIdentityForLock, type HeldStateOwnerLock } from './native-owner.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';

type ServiceSpec = Extract<SandboxLaunchSpecV1, { purpose: 'local_inference_service' }>;
type LinuxPlan = ProcessContainmentPlanV1 & { backend: Extract<ProcessContainmentPlanV1['backend'], { kind: 'linux' }> };
type LinuxContainment = ProcessContainment & { backend: Extract<ProcessContainment['backend'], { kind: 'linux' }> };
type RecipeInput = Readonly<{
  registration: LocalModelRegistrationV1; bundle: RuntimeBundleManifest; cycle: LocalInferenceActivationCycleV1;
  attempt: 1 | 2; supervisorInstanceId: string; stateOwnerEpoch: number; ownerUid: number;
  cgroupParent: string; controllerStartToken: string; nativeNonce: string; activationNonce: string; createdAt: string;
}>;
function refuse(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }

async function localLaunchRecipe(artifacts: ArtifactCatalog, input: RecipeInput) {
  const { registration, bundle, cycle, attempt, createdAt, nativeNonce, activationNonce } = input;
  const service = registration.serviceSpec, profile = installedLocalInferenceProfile();
  verifyRuntimeBundle(bundle, artifacts.releaseTrustRoots());
  if (registration.state !== 'active' ||
      canonicalSha256(bundle) !== service.runtimeBundleRef || bundle.manifestDigest !== service.runtimeBundleManifestDigest ||
      service.backend !== 'linux_namespace' || service.endpoint.host !== '127.0.0.1' ||
      registration.registrationDigest !== cycle.localModelRegistrationDigest || canonicalSha256(registration) !== cycle.localModelRegistrationRef ||
      registration.expectedServiceSpecRef !== cycle.serviceSpecRef || service.serviceSpecDigest !== cycle.serviceSpecDigest ||
      service.serviceId !== cycle.serviceId || service.ownerPrincipalId !== cycle.ownerPrincipalId ||
      !/^[0-9a-f]{64}$/u.test(nativeNonce) || !/^[0-9a-f]{64}$/u.test(activationNonce) ||
      normalizeAbsolutePath(input.cgroupParent) !== input.cgroupParent)
    refuse('local inference recipe differs from the original service, cycle or signed installation');
  if (canonicalSha256(profile) !== service.sandboxProfileRef || profile.profileDigest !== service.sandboxProfileDigest)
    refuse('local inference recipe differs from its fixed sandbox profile');
  requireEqual(service.resources, profile.resources, 'local inference exact original resource limits');

  const profileRoot = localInferenceRuntimeRoots(bundle)[0];
  const rootEntry = bundle.entries.find(entry => entry.entryId === 'installed-empty-root');
  const launcher = bundle.entries.find(entry => entry.entryId === 'linux_worker_controller');
  if (!profileRoot || !rootEntry || rootEntry.role !== 'sandbox_root_profile' || rootEntry.executable ||
      !launcher || launcher.role !== 'platform_helper' || !launcher.executable)
    refuse('local inference signed root and launcher recipe are incomplete');
  const runtimeProfile = bindLocalInferenceRuntime(bundle, profileRoot.artifactRef, await readCanonicalArtifact(artifacts, profileRoot.artifactRef));
  const inputs = localInferenceRuntimeInputs(bundle, runtimeProfile, registration.objectClosure);
  const rootProfile = decodeSandboxRootProfile(await readCanonicalArtifact(artifacts, rootEntry.digest));
  const rootImageCore = { schemaVersion: 1 as const, format: 'cliq-sandbox-root-image-v1' as const,
    runtimeBundleRef: service.runtimeBundleRef, runtimeBundleManifestDigest: service.runtimeBundleManifestDigest,
    entryId: rootEntry.entryId, entryVersion: rootEntry.version, entryDigest: rootEntry.digest, protocol: rootProfile.protocol,
    filesystemKind: rootProfile.filesystemKind, fixedDirectories: rootProfile.fixedDirectories, ownerUid: input.ownerUid,
    persistent: false as const, networkConfiguration: 'none' as const };
  const rootImage: SandboxRootImageV1 = { ...rootImageCore, imageDigest: canonicalSha256(rootImageCore) };
  const rootImageRef = canonicalSha256(rootImage);
  const launchId = localInferenceLaunchId(cycle.activationCycleId, attempt);
  if (cycle.launchIds[attempt - 1] !== launchId)
    refuse('local inference cycle has another original launch');
  const owner: ServiceSpec['owner'] = { kind: 'local_inference_service', serviceId: service.serviceId, serviceLaunchId: launchId,
    ownerPrincipalId: service.ownerPrincipalId, serviceSpecRef: registration.expectedServiceSpecRef, supervisorInstanceId: input.supervisorInstanceId };
  const plan: LinuxPlan = { schemaVersion: 1, format: 'cliq-process-containment-plan-v1', owner,
    filesystemBinding: { kind: 'isolated-empty-root', rootImageRef, rootImageDigest: rootImage.imageDigest },
    launchNonceDigest: sha256Bytes(Buffer.from(nativeNonce)),
    backend: { kind: 'linux', cgroupPath: input.cgroupParent + '/cliq-local-' + nativeNonce,
      cgroupNameReservationDigest: canonicalSha256(['cliq-local-service-cgroup-v1', owner, nativeNonce]),
      pidNamespaceReservationId: 'linux-local-inference:' + nativeNonce, subreaperStartToken: input.controllerStartToken },
    createdAt, planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest');
  const runtimeCore = { runtimeBundleRef: service.runtimeBundleRef, runtimeBundleManifestDigest: service.runtimeBundleManifestDigest,
    sandboxBackend: 'linux_namespace' as const, toolchain: { kind: 'none' as const },
    launcher: { executableId: launcher.entryId, executableDigest: launcher.digest } };
  const variables = [
    ['OLLAMA_HOST', '127.0.0.1:' + service.endpoint.port],
    ['OLLAMA_MODELS', '/models/files'],
    ['OLLAMA_NOHISTORY', '1'],
    ['OLLAMA_NOPRUNE', '1'],
    ['OLLAMA_NO_CLOUD', '1'],
  ].map(([name, value]) => ({ name: name!, value: { kind: 'non_secret_literal' as const, value: value! } }));
  const environmentCore = { schemaVersion: 1 as const, format: 'cliq-sanitized-sandbox-environment-v1' as const,
    controlledPath: [], locale: { lang: 'C', lcAll: 'C' }, home: '/scratch/home', tmpdir: '/scratch/tmp', variables,
    inheritedHostEnvironment: false as const, secretMaterial: 'none' as const, brokerAccessAtSpawn: 'none' as const, networkMode: 'none' as const };
  const environment: SanitizedSandboxEnvironmentV1 = { ...environmentCore, environmentDigest: canonicalSha256(environmentCore) };
  const mounts: SandboxMountV1[] = [{ kind: 'cas_artifact', artifactRef: inputs.bootstrap.digest, artifactDigest: inputs.bootstrap.digest,
    targetPath: '/runtime/bin/cliq-local-inference', access: 'read_only', purpose: 'executable' }];
  for (const file of inputs.files) mounts.push({ kind: 'cas_artifact', artifactRef: file.artifactRef, artifactDigest: file.artifactRef,
    targetPath: file.guestPath, access: 'read_only', purpose: file.kind === 'model_manifest' || file.kind === 'model_tokenizer' ||
      file.kind === 'model_file' ? 'input' : 'runtime' });
  mounts.push({ kind: 'private_ephemeral', privateRootId: identityHash('cliq-local-service-scratch-v1', launchId, nativeNonce),
    targetPath: '/scratch', access: 'read_write', purpose: 'output' });
  const spec: ServiceSpec = { schemaVersion: 1, format: 'cliq-sandbox-launch-v1', owner, purpose: 'local_inference_service',
    runtime: { ...runtimeCore, runtimeDigest: canonicalSha256(runtimeCore) },
    executable: { kind: 'runtime_bundle', runtimeBundleRef: service.runtimeBundleRef, runtimeBundleManifestDigest: service.runtimeBundleManifestDigest,
      executableId: service.executableId, role: 'local_inference', executionPath: '/runtime/bin/cliq-local-inference', executableDigest: service.executableDigest },
    environment, filesystem: { kind: 'isolated_empty_root', rootImageRef, rootImageDigest: rootImage.imageDigest, persistentWritableMounts: false },
    mounts, mountsDigest: canonicalSha256(mounts), sandboxProfileRef: service.sandboxProfileRef, sandboxProfileDigest: service.sandboxProfileDigest,
    resources: service.resources, resourcesDigest: canonicalSha256(service.resources), containmentPlanRef: canonicalSha256(plan),
    containmentPlanDigest: plan.planDigest, serviceSpecRef: registration.expectedServiceSpecRef, serviceSpecDigest: service.serviceSpecDigest,
    processInvocation: { kind: 'local_inference_entrypoint', purpose: 'local_inference_service', recipe: 'cliq-local-inference-entrypoint-v1',
      runtimeSource: 'launch_runtime', executableSource: 'launch_executable', modelManifestSource: 'service_spec',
      argvSource: 'trusted_recipe_decode_of_service_spec', cwdSource: 'isolated_root',
      stdio: { stdin: 'closed', stdout: 'captured', stderr: 'captured', extraFileDescriptors: 'authenticated_operation_channel_only' } },
    createdAt, launchSpecDigest: '' };
  spec.launchSpecDigest = digestOmitting(spec, 'launchSpecDigest');
  const data: LocalInferenceNativeInputData = { ...inputs, resources: service.resources,
    binding: { ownerPrincipalId: service.ownerPrincipalId, serviceId: service.serviceId, serviceLaunchId: launchId,
      activationCycleId: cycle.activationCycleId, supervisorInstanceId: input.supervisorInstanceId, stateOwnerEpoch: input.stateOwnerEpoch,
      localModelRegistrationRef: cycle.localModelRegistrationRef, localModelRegistrationDigest: cycle.localModelRegistrationDigest,
      serviceSpecRef: cycle.serviceSpecRef, serviceSpecDigest: cycle.serviceSpecDigest, runtimeBundleRef: service.runtimeBundleRef,
      runtimeBundleManifestDigest: service.runtimeBundleManifestDigest, modelManifestRef: registration.expectedModelManifestRef,
      modelManifestDigest: registration.modelManifest.modelManifestDigest, objectClosureRef: registration.expectedObjectClosureRef,
      objectClosureDigest: registration.objectClosure.closureDigest, sandboxProfileRef: service.sandboxProfileRef, sandboxProfileDigest: service.sandboxProfileDigest,
      containmentPlanRef: spec.containmentPlanRef, containmentPlanDigest: plan.planDigest, sandboxLaunchSpecRef: canonicalSha256(spec),
      sandboxLaunchSpecDigest: spec.launchSpecDigest, nativeNonce, activationNonce, createdAtMs: parseCanonicalTime(createdAt),
      activationDeadlineAtMs: parseCanonicalTime(createdAt) + LOCAL_INFERENCE_ACTIVATION_MS, activationAttempt: attempt, port: service.endpoint.port },
  };
  return immutableSnapshot({ plan, spec, profile, rootImage, runtimeProfile, data });
}

export async function publishLocalInferenceLaunch(artifacts: ArtifactCatalog, input: Omit<RecipeInput,
  'ownerUid' | 'controllerStartToken' | 'cgroupParent'> & Readonly<{ controller: InstalledLocalInferenceController; lock: HeldStateOwnerLock }>) {
  assertInstalledLocalInferenceController(input.controller);
  if (input.cycle.phase !== 'starting_launch' || input.cycle.activationAttempt !== input.attempt)
    refuse('new local inference launch requires its original starting cycle attempt');
  const recipe = await localLaunchRecipe(artifacts, { ...input, ownerUid: stateRootIdentityForLock(input.lock).ownerUid,
    controllerStartToken: input.controller.processStartToken, cgroupParent: input.controller.cgroupParent });
  const metadata = await artifacts.publishCanonicalFour([
    { value: recipe.rootImage, schemaKind: recipe.rootImage.format }, { value: recipe.profile, schemaKind: recipe.profile.format },
    { value: recipe.plan, schemaKind: recipe.plan.format }, { value: recipe.spec, schemaKind: recipe.spec.format },
  ]);
  const bytes = input.controller.captureInput(recipe.data);
  const source = await artifacts.publishBytes(bytes, 'application/octet-stream', LOCAL_INFERENCE_NATIVE_INPUT_KIND);
  const binding = recipe.data.binding;
  const launch = decodeLocalInferenceLaunch({ schemaVersion: 1, phase: 'reserved', serviceId: binding.serviceId,
    launchId: binding.serviceLaunchId, ownerPrincipalId: binding.ownerPrincipalId, serviceSpecRef: binding.serviceSpecRef,
    serviceSpecDigest: binding.serviceSpecDigest, supervisorInstanceId: binding.supervisorInstanceId,
    activationCycleId: binding.activationCycleId, activationAttempt: input.attempt,
    activationNonceDigest: sha256Bytes(Buffer.from(input.activationNonce, 'hex')), containmentPlanRef: binding.containmentPlanRef,
    sandboxLaunchSpecRef: binding.sandboxLaunchSpecRef, nativeInputRef: source.ref, rowVersion: 1, leaseVersion: 0, createdAt: input.createdAt,
    activationDeadlineAt: encodeCanonicalTime(binding.activationDeadlineAtMs) });
  decodeBoundLocalInferenceNativeInput(bytes, launch, input.cycle, input.registration);
  return immutableSnapshot({ ...recipe, launch, metadata: [...metadata, source] });
}

/** Historical source closure only. A current recovery owner must separately
 * reopen the original native witness and prove actual death/no-service-spawn. */
export async function readRetainedLocalInferenceLaunch(artifacts: ArtifactCatalog, launch: LocalInferenceServiceLaunchV1,
  cycle: LocalInferenceActivationCycleV1, registration: LocalModelRegistrationV1, bundle: RuntimeBundleManifest) {
  const bytes = await artifacts.readBoundedBytes(launch.nativeInputRef, 140832);
  const original = decodeBoundLocalInferenceNativeInput(bytes, launch, cycle, registration);
  const root = decodeStateRootIdentity(await readCanonicalArtifact(artifacts, registration.objectClosure.stateRootIdentityRef));
  if (root.identityDigest !== registration.objectClosure.stateRootIdentityDigest ||
      original.origin.stateRoot.deviceId !== root.deviceId || original.origin.stateRoot.fileId !== root.directoryFileId ||
      original.origin.stateRoot.uid !== root.ownerUid) refuse('retained local inference native input belongs to another StateRoot');
  verifyLocalModelManifestAuthority({ bundle, releaseKeys: artifacts.releaseTrustRoots(),
    manifestBytes: canonicalJsonBytes(registration.modelManifest),
    signatureBytes: await artifacts.readBoundedBytes(registration.modelManifest.signatureRef, 64) });
  const plan = await readCanonicalArtifact<ProcessContainmentPlanV1>(artifacts, launch.containmentPlanRef);
  if (plan.backend.kind !== 'linux') refuse('retained local inference does not use the fixed original Linux recipe');
  const recipe = await localLaunchRecipe(artifacts, { registration, bundle, cycle, attempt: launch.activationAttempt,
    supervisorInstanceId: launch.supervisorInstanceId, stateOwnerEpoch: original.data.binding.stateOwnerEpoch, ownerUid: root.ownerUid,
    cgroupParent: path.posix.dirname(plan.backend.cgroupPath), controllerStartToken: original.origin.controller.processStartToken,
    nativeNonce: original.data.binding.nativeNonce, activationNonce: original.data.binding.activationNonce, createdAt: launch.createdAt });
  const spec = await readCanonicalArtifact(artifacts, launch.sandboxLaunchSpecRef);
  requireEqual(plan, recipe.plan, 'retained exact local inference containment plan');
  requireEqual(spec, recipe.spec, 'retained exact local inference launch spec');
  requireEqual(original.data, recipe.data, 'retained exact local inference native input data');
  requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(recipe.rootImage)), recipe.rootImage, 'retained exact local inference root image');
  requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(recipe.profile)), recipe.profile, 'retained exact local inference sandbox profile');
  return { ...recipe, original, bytes };
}

export function originalLocalContainment(recipe: Awaited<ReturnType<typeof publishLocalInferenceLaunch>>,
  observed: LocalInferenceNativeObservation): LinuxContainment {
  if (!observed.namespaceInit || !observed.bootstrap || !observed.monitor || !observed.populated || observed.allReaped ||
      observed.cgroupFileId === '0' || observed.pidNamespaceId === '0' || observed.preparedCount !== recipe.data.files.length)
    refuse('original local inference namespace is not blocked with its complete verified inputs');
  const { plan, spec, launch } = recipe;
  return immutableSnapshot({ schemaVersion: 1, owner: plan.owner, planRef: launch.containmentPlanRef,
    sandboxLaunchSpecRef: launch.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: spec.launchSpecDigest,
    filesystemBinding: plan.filesystemBinding, launchNonceDigest: plan.launchNonceDigest,
    backend: { kind: 'linux', pidNamespaceId: observed.pidNamespaceId, cgroupId: observed.cgroupFileId,
      namespaceInitStartToken: observed.namespaceInit.processStartToken,
      pidNamespaceReservationId: plan.backend.pidNamespaceReservationId, subreaperStartToken: plan.backend.subreaperStartToken,
      cgroupPath: plan.backend.cgroupPath }, createdAt: encodeCanonicalTime(observed.observedAtMs),
  });
}

export async function observeLocalInferenceContainment(controller: InstalledLocalInferenceController,
  launch: LocalInferenceServiceLaunchV1, containment: LinuxContainment, owner: StateOwnerRecordV1) {
  assertInstalledLocalInferenceController(controller);
  if (owner.supervisorInstanceId !== launch.supervisorInstanceId || controller.processStartToken !== containment.backend.subreaperStartToken)
    refuse('local inference boundary requires its original current Supervisor and controller');
  const native = await controller.observeActive(), at = encodeCanonicalTime(native.observedAtMs);
  const validThrough = addCanonicalDuration(at, 5000);
  const now = sampleCanonicalNow();
  if (at > now || now >= validThrough || !native.populated || native.allReaped || native.cgroupFileId !== containment.backend.cgroupId ||
      native.pidNamespaceId !== containment.backend.pidNamespaceId || native.namespaceInit?.processStartToken !== containment.backend.namespaceInitStartToken)
    refuse('current native local inference boundary differs from the original containment');
  return { at, validThrough };
}

/** The caller commits the returned artifact only at a fresh current-owner cut. */
export async function observeLocalInferenceBoundary(artifacts: ArtifactCatalog, controller: InstalledLocalInferenceController,
  registration: LocalModelRegistrationV1, launch: LocalInferenceServiceLaunchV1, containment: LinuxContainment, owner: StateOwnerRecordV1) {
  const { at, validThrough } = await observeLocalInferenceContainment(controller, launch, containment, owner);
  const inspector = supervisorInspectorIdentity(owner), service = registration.serviceSpec;
  const core = { schemaVersion: 1, format: 'cliq-local-inference-boundary-v1', ownerPrincipalId: service.ownerPrincipalId,
    serviceId: service.serviceId, serviceSpecRef: registration.expectedServiceSpecRef, serviceSpecDigest: service.serviceSpecDigest,
    serviceLaunchId: launch.launchId, runtimeBundleRef: service.runtimeBundleRef, runtimeBundleManifestDigest: service.runtimeBundleManifestDigest,
    executableId: service.executableId, executableDigest: service.executableDigest, modelManifestRef: registration.expectedModelManifestRef,
    modelManifestDigest: registration.modelManifest.modelManifestDigest, processContainmentRef: canonicalSha256(containment),
    containmentPlanRef: launch.containmentPlanRef, sandboxLaunchSpecRef: launch.sandboxLaunchSpecRef,
    sandboxLaunchSpecDigest: containment.sandboxLaunchSpecDigest, backend: service.backend, externalNetworkEgress: 'denied', loopbackOnly: true,
    stableServiceIdentityDigest: localStableServiceIdentity({ service, serviceSpecRef: registration.expectedServiceSpecRef }),
    inspectorSupervisorInstanceId: inspector.supervisorInstanceId, inspectorIdentityRef: canonicalSha256(inspector),
    inspectorIdentityDigest: inspector.identityDigest, observedAt: at, validThrough, evidenceDigest: '' };
  const boundary = decodeLocalInferenceBoundary({ ...core, evidenceDigest: digestOmitting(core, 'evidenceDigest') });
  const metadata = await artifacts.publishCanonicalPair([{ value: inspector, schemaKind: inspector.format },
    { value: boundary, schemaKind: boundary.format }]);
  return { boundary, boundaryRef: metadata[1].ref, metadata };
}

export async function probeLocalInferenceHealth(selected: HeldInstalledRuntime, controller: InstalledLocalInferenceController,
  registration: LocalModelRegistrationV1, engineVersion: string, activationDeadlineAt: string, signal: AbortSignal): Promise<void> {
  assertInstalledLocalInferenceController(controller); signal.throwIfAborted();
  const broker = await loadInstalledModelBroker(selected, signal), prepare = broker.prepareLocalHealthTransport;
  if (broker.localModelInterfaceVersion !== 1 || typeof prepare !== 'function') refuse('original local inference health broker is unavailable');
  const remaining = parseCanonicalTime(activationDeadlineAt) - Date.now();
  if (remaining <= 0) refuse('local inference activation deadline elapsed before health');
  const stop = AbortSignal.any([signal, AbortSignal.timeout(remaining)]);
  const exchange = async (request: Omit<Extract<NativeLocalHealthRequest, { requestKind: 'version' }>, 'peer'> |
    Omit<Extract<NativeLocalHealthRequest, { requestKind: 'model_show' }>, 'peer'>): Promise<unknown> => {
    stop.throwIfAborted();
    const owner = prepare({ ...request, peer: controller.retainHealthPeer() });
    const cancel = () => { void owner.close().catch(() => undefined); };
    stop.addEventListener('abort', cancel, { once: true });
    try {
      if (stop.aborted) cancel();
      const response = await owner.result;
      stop.throwIfAborted();
      if (response.kind !== 'complete' || response.status !== 200 || response.mediaType !== 'application/json')
        refuse('original local inference health response is not complete success JSON');
      const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(response.bodyBytes));
      assertControlWireJson(value); return value;
    } finally { stop.removeEventListener('abort', cancel); await owner.close(); }
  };
  for (;;) {
    try {
      const version = controlWireRecord(await exchange({ provider: 'ollama', requestKind: 'version' }), ['version']);
      if (version.version !== engineVersion) refuse('original local inference engine version does not match its signed recipe');
      break;
    } catch (error) {
      if (!(error instanceof InstalledLocalModelNotListeningError)) throw error;
      await delay(25, undefined, { signal: stop });
    }
  }
  const manifest = registration.modelManifest, bodyBytes = canonicalJsonBytes({ model: manifest.model, verbose: false });
  const result = await exchange({ provider: 'ollama', requestKind: 'model_show', bodyBytes, bodyBytesDigest: sha256Bytes(bodyBytes) });
  const model = result as { capabilities?: unknown; model_info?: Record<string, unknown> } | null;
  if (!model || !Array.isArray(model.capabilities) || !model.capabilities.includes('completion') ||
      !model.model_info || model.model_info['general.architecture'] !== manifest.architecture ||
      model.model_info[manifest.architecture + '.context_length'] !== manifest.claims.contextLimitTokens ||
      manifest.claims.nativeToolCalling && !model.capabilities.includes('tools'))
    refuse('original local inference health did not confirm the signed model capability');
}
