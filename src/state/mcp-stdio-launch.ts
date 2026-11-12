// Inert stdio plan/spec publication. Actual native held images/input and
// same-scope observations remain independently required before dispatch.
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, normalizeAbsolutePath, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import type { ProcessContainmentOwner, ProcessContainmentPlanV1, SandboxLaunchSpecV1, SandboxResourceSpec,
  SandboxRootImageV1, SandboxProfileV1, SandboxRuntimeBindingV1, SanitizedSandboxEnvironmentV1 } from '../kernel/execution.js';
import type { McpResolvedTransportV1 } from '../kernel/mcp.js';
import type { LinuxWorkerController } from '../sandbox/linux-worker.js';
import { assertLinuxWorkerController } from '../sandbox/linux-worker.js';
import { requireEqual, verifyRuntimeBundle, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { decodeSandboxProfile, decodeSandboxRootProfile } from './execution-closure.js';
import { stateRootIdentityForLock, type HeldStateOwnerLock } from './native-owner.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';

export type McpStdioAdminLaunchPurpose = Readonly<{ kind: 'admin'; owner: Extract<ProcessContainmentOwner, { kind: 'admin_probe' }>;
  targetRef: string; targetDigest: string; probePayloadCoreRef: string }>;
export type McpStdioRunLaunchPurpose = Readonly<{ kind: 'run'; owner: Extract<ProcessContainmentOwner, { kind: 'run_invocation' }>;
  requestRef: string; requestDigest: string; targetRef: string; targetDigest: string; grantRef: string; parentWorkerContainmentRef: string }>;
export type McpStdioRecoveryLaunchPurpose = Readonly<{ kind: 'recovery'; owner: Extract<ProcessContainmentOwner, { kind: 'reconciliation_probe' }>;
  requestRef: string; requestDigest: string; targetRef: string; targetDigest: string;
  adapter: Readonly<{ entryId: string; executableDigest: string }> }>;
type RecipeInput = Readonly<{
  purpose: McpStdioAdminLaunchPurpose | McpStdioRunLaunchPurpose | McpStdioRecoveryLaunchPurpose; bundle: RuntimeBundleManifest;
  originalController: Readonly<{ subreaperStartToken: string }>; cgroupParent: string; ownerUid: number;
  executable: Extract<McpResolvedTransportV1, { kind: 'stdio' }>['executable'];
  nonce: string; createdAt: string; resources: SandboxResourceSpec;
}>;
async function recipeData(artifacts: ArtifactCatalog, input: RecipeInput) {
  const { purpose, bundle, originalController: controller, executable, nonce, createdAt, resources } = input;
  verifyRuntimeBundle(bundle, artifacts.releaseTrustRoots()); parseCanonicalTime(createdAt);
  if (executable.kind !== 'runtime_bundle' || canonicalSha256(bundle) !== executable.runtimeBundleRef || executable.executionPath !== '/runtime/mcp-server' ||
      !/^[0-9a-f]{64}$/u.test(nonce) || normalizeAbsolutePath(input.cgroupParent) !== input.cgroupParent)
    throw new TypeError('MCP stdio launch lacks its exact signed server, nonce or contained controller root');
  const server = bundle.entries.filter(entry => entry.entryId === executable.executableId), roots = bundle.entries.filter(entry => entry.entryId === 'installed-empty-root');
  const launcher = bundle.entries.filter(entry => entry.entryId === 'linux_worker_controller');
  if (server.length !== 1 || server[0]!.role !== 'mcp_server' || !server[0]!.executable || server[0]!.digest !== executable.executableDigest ||
      roots.length !== 1 || roots[0]!.role !== 'sandbox_root_profile' || roots[0]!.executable ||
      launcher.length !== 1 || launcher[0]!.role !== 'platform_helper' || !launcher[0]!.executable)
    throw new TypeError('MCP stdio launch substitutes an execution role or fixed signed isolation recipe');
  let program = server[0]!;
  if (purpose.kind === 'recovery') {
    const adapter = purpose.adapter;
    const entries = bundle.entries.filter(entry => entry.entryId === adapter.entryId), selected = entries[0];
    if (entries.length !== 1 || !selected || selected.role !== 'mcp_recovery_adapter' || !selected.executable ||
        selected.digest !== adapter.executableDigest || selected.digest === program.digest || selected.digest === launcher[0]!.digest)
      throw new TypeError('MCP recovery requires its distinct signed status adapter, original server and containment helper');
    program = selected;
  }
  const rootProfile = decodeSandboxRootProfile(await readCanonicalArtifact(artifacts, roots[0]!.digest));
  const rootCore = { schemaVersion: 1 as const, format: 'cliq-sandbox-root-image-v1' as const, runtimeBundleRef: canonicalSha256(bundle),
    runtimeBundleManifestDigest: bundle.manifestDigest, entryId: roots[0]!.entryId, entryVersion: roots[0]!.version, entryDigest: roots[0]!.digest,
    protocol: rootProfile.protocol, filesystemKind: rootProfile.filesystemKind, fixedDirectories: rootProfile.fixedDirectories,
    ownerUid: input.ownerUid, persistent: false as const, networkConfiguration: 'none' as const };
  const rootImage: SandboxRootImageV1 = { ...rootCore, imageDigest: canonicalSha256(rootCore) };
  const image = { ref: canonicalSha256(rootImage) };
  const plan: ProcessContainmentPlanV1 = { schemaVersion: 1, format: 'cliq-process-containment-plan-v1', owner: purpose.owner,
    filesystemBinding: { kind: 'isolated-empty-root', rootImageRef: image.ref, rootImageDigest: rootImage.imageDigest },
    launchNonceDigest: sha256Bytes(Buffer.from(nonce)), backend: { kind: 'linux', cgroupPath: `${input.cgroupParent}/cliq-mcp-stdio-${purpose.kind}-${nonce}`,
      cgroupNameReservationDigest: canonicalSha256(['cliq-mcp-stdio-cgroup-v1', purpose.kind, purpose.owner, nonce]),
      pidNamespaceReservationId: `linux-mcp-stdio:${purpose.kind}:${nonce}`, subreaperStartToken: controller.subreaperStartToken }, createdAt, planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest'); const planArtifact = { ref: canonicalSha256(plan) };
  const profileCore = { schemaVersion: 1 as const, format: 'cliq-sandbox-profile-v1' as const, backend: 'linux_namespace' as const,
    allowedOwners: [purpose.owner.kind], filesystemPolicy: 'typed_launch_spec_only' as const, hostFilesystemReachability: 'none' as const,
    networkAtSpawn: 'none' as const, networkAfterRelease: 'typed_broker_only' as const, credentialReachability: 'typed_broker_only' as const,
    stateRootReachability: 'none' as const, inheritedHostEnvironment: false as const, resources };
  const profile: SandboxProfileV1 = { ...profileCore, profileDigest: canonicalSha256(profileCore) };
  decodeSandboxProfile(profile); const profileArtifact = { ref: canonicalSha256(profile) };
  const runtimeCore = { runtimeBundleRef: canonicalSha256(bundle), runtimeBundleManifestDigest: bundle.manifestDigest,
    sandboxBackend: 'linux_namespace' as const, toolchain: { kind: 'none' as const },
    launcher: { executableId: launcher[0]!.entryId, executableDigest: launcher[0]!.digest } };
  const runtime: SandboxRuntimeBindingV1 = { ...runtimeCore, runtimeDigest: canonicalSha256(runtimeCore) };
  const environmentCore = { schemaVersion: 1 as const, format: 'cliq-sanitized-sandbox-environment-v1' as const, controlledPath: ['/runtime'],
    locale: { lang: 'C', lcAll: 'C' }, home: '/scratch/home', tmpdir: '/scratch/tmp', variables: [], inheritedHostEnvironment: false as const,
    secretMaterial: 'none' as const, brokerAccessAtSpawn: 'none' as const, networkMode: 'none' as const };
  const environment: SanitizedSandboxEnvironmentV1 = { ...environmentCore, environmentDigest: canonicalSha256(environmentCore) };
  const mounts = [{ kind: 'cas_artifact' as const, artifactRef: program.digest, artifactDigest: program.digest,
    targetPath: '/runtime/mcp-server', access: 'read_only' as const, purpose: 'executable' as const },
  { kind: 'private_ephemeral' as const, privateRootId: identityHash('cliq-mcp-stdio-scratch-v1', purpose.kind, purpose.owner, nonce),
    targetPath: '/scratch', access: 'read_write' as const, purpose: 'output' as const }];
  const executableCore = { kind: 'runtime_bundle' as const, runtimeBundleRef: canonicalSha256(bundle), runtimeBundleManifestDigest: bundle.manifestDigest,
    executableId: program.entryId, executionPath: '/runtime/mcp-server', executableDigest: program.digest };
  const base = { schemaVersion: 1 as const, format: 'cliq-sandbox-launch-v1' as const, runtime,
    environment, filesystem: { kind: 'isolated_empty_root' as const, rootImageRef: image.ref, rootImageDigest: rootImage.imageDigest, persistentWritableMounts: false as const },
    mounts, mountsDigest: canonicalSha256(mounts), sandboxProfileRef: profileArtifact.ref, sandboxProfileDigest: profile.profileDigest,
    resources, resourcesDigest: canonicalSha256(resources), containmentPlanRef: planArtifact.ref, containmentPlanDigest: plan.planDigest, createdAt, launchSpecDigest: '' };
  const stdio = { stdin: 'mcp_framed' as const, stdout: 'mcp_framed' as const, stderr: 'captured' as const, extraFileDescriptors: 'none' as const };
  const spec: SandboxLaunchSpecV1 = purpose.kind === 'admin' ? { ...base, owner: purpose.owner, purpose: 'admin_mcp_stdio_probe',
    executable: { ...executableCore, role: 'mcp_server' },
    processInvocation: { kind: 'admin_probe', purpose: 'admin_mcp_stdio_probe', recipe: 'cliq-admin-mcp-stdio-probe-v1', targetRef: purpose.targetRef,
      targetDigest: purpose.targetDigest, probePayloadCoreRef: purpose.probePayloadCoreRef, argvCwdSource: 'trusted_recipe_decode_of_admin_target_and_probe_core', stdio },
    adminTargetRef: purpose.targetRef, adminTargetDigest: purpose.targetDigest, probePayloadCoreRef: purpose.probePayloadCoreRef }
    : purpose.kind === 'recovery' ? { ...base, owner: purpose.owner, purpose: 'mcp_recovery',
      executable: { ...executableCore, role: 'mcp_recovery_adapter' },
      processInvocation: { kind: 'reconciliation_probe', purpose: 'mcp_recovery', recipe: 'cliq-mcp-readonly-status-v1',
        requestRef: purpose.requestRef, requestDigest: purpose.requestDigest, targetRef: purpose.targetRef, targetDigest: purpose.targetDigest,
        argvCwdSource: 'trusted_recipe_decode_of_signed_status_target_and_original_probe', stdio },
      requestRef: purpose.requestRef, requestDigest: purpose.requestDigest, targetRef: purpose.targetRef, targetDigest: purpose.targetDigest }
    : { ...base, owner: purpose.owner, purpose: 'mcp_stdio', executable: { ...executableCore, role: 'mcp_server' },
      processInvocation: { kind: 'run_request', purpose: 'mcp_stdio', recipe: 'cliq-mcp-stdio-launch-v1',
      requestRef: purpose.requestRef, requestDigest: purpose.requestDigest, targetRef: purpose.targetRef, targetDigest: purpose.targetDigest,
      argvCwdSource: 'trusted_recipe_decode_of_request_and_target', stdio }, operationGrantRef: purpose.grantRef, requestRef: purpose.requestRef,
    requestDigest: purpose.requestDigest, targetRef: purpose.targetRef, targetDigest: purpose.targetDigest, parentWorkerContainmentRef: purpose.parentWorkerContainmentRef };
  spec.launchSpecDigest = digestOmitting(spec, 'launchSpecDigest'); const specArtifact = { ref: canonicalSha256(spec) };
  requireEqual(spec.resources, resources, 'MCP stdio exact original resource bounds');
  return { plan, planArtifact, spec, specArtifact, profile, profileArtifact, rootImage, rootImageArtifact: image,
    serverEntry: program, launcherEntry: launcher[0]! };
}
export async function publishMcpStdioLaunch(artifacts: ArtifactCatalog, input: Omit<RecipeInput, 'originalController' | 'ownerUid'> & Readonly<{
  controller: LinuxWorkerController; lock: HeldStateOwnerLock;
}>) {
  assertLinuxWorkerController(input.controller); input.lock.assertHeld();
  const data = await recipeData(artifacts, { ...input, originalController: { subreaperStartToken: input.controller.subreaperStartToken }, ownerUid: stateRootIdentityForLock(input.lock).ownerUid });
  const metadata = await artifacts.mapReads([data.rootImage, data.plan, data.profile, data.spec], value => artifacts.publishCanonical(value, value.format));
  return { ...data, rootImageArtifact: metadata[0]!, planArtifact: metadata[1]!, profileArtifact: metadata[2]!, specArtifact: metadata[3]!, metadata };
}
/** Exact closed audit recipe. Original controller fields are retained data;
 * this function performs no native observation, publication or execution. */
export async function readMcpStdioLaunchRecipeData(artifacts: ArtifactCatalog, input: RecipeInput & Readonly<{
  plan: ProcessContainmentPlanV1; spec: SandboxLaunchSpecV1;
}>) {
  const data = await recipeData(artifacts, input);
  requireEqual(input.plan, data.plan, 'MCP stdio complete exact original plan recipe');
  requireEqual(input.spec, data.spec, 'MCP stdio complete exact original spec recipe');
  requireEqual(await readCanonicalArtifact(artifacts, data.rootImageArtifact.ref), data.rootImage, 'MCP stdio original signed root image');
  requireEqual(await readCanonicalArtifact(artifacts, data.profileArtifact.ref), data.profile, 'MCP stdio original fixed sandbox profile');
  return data;
}
