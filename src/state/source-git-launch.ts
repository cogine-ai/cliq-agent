import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { ProcessContainmentPlanV1, SandboxLaunchSpecV1, SandboxRootImageV1,
  SandboxRuntimeBindingV1, SanitizedSandboxEnvironmentV1, SourceInspectionAttemptV1,
  SourceInspectionInputV2, SourceInspectionPlanV1, SourceInspectionTargetV2, SandboxRootProfileV1 } from '../kernel/execution.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { NativeSourceGitReservationObservation } from '../sandbox/linux-worker.js';
import { LINUX_WORKER_RECIPE } from '../sandbox/linux-worker.js';
import { verifyRuntimeBundle, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import type { ArtifactCatalog } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { decodeSandboxProfile, decodeSandboxRootProfile } from './execution-closure.js';
import { decodeGuestToolchainManifest, guestToolchainMembers, readRetainedVerifierToolchain, type RetainedVerifierToolchain } from './guest-toolchain.js';
import { decodeSourceGitInputIntent } from './source-git-input.js';
import type { SourceInspectionBootstrap } from './source-target.js';

type Capturing = Extract<SourceInspectionAttemptV1, { phase: 'capturing' }>;
type SourceSpec = Extract<SandboxLaunchSpecV1, { purpose: 'source_inspection' }>;
type BundleEntry = RuntimeBundleManifest['entries'][number];
function invalid(): never { throw new KernelStorageError('ARTIFACT_MISMATCH', 'source Git typed launch differs from its fixed capture intent'); }

function recipeEntries(bundle: RuntimeBundleManifest) {
  const roots = bundle.entries.filter(entry => entry.entryId === 'installed-empty-root');
  const root = roots[0], inspectors = bundle.entries.filter(entry => entry.entryId === 'source_git_inspector');
  const inspector = inspectors[0], launchers = bundle.entries.filter(entry => entry.entryId === LINUX_WORKER_RECIPE.launcherId);
  const launcher = launchers[0];
  if (roots.length !== 1 || !root || root.role !== 'sandbox_root_profile' || root.executable || root.version !== '1' ||
      root.byteCount < 1 || root.byteCount > 1_048_576 || inspectors.length !== 1 || !inspector ||
      inspector.role !== 'platform_helper' || inspector.version !== '1' || inspector.executable ||
      inspector.relativePath !== 'helpers/source-git-inspector.mjs' || inspector.byteCount < 1 || inspector.byteCount > 1_048_576 ||
      launchers.length !== 1 || !launcher || launcher.role !== 'platform_helper' || !launcher.executable) return invalid();
  return { root, inspector, launcher };
}

function sourceOwner(row: SourceInspectionAttemptV1) {
  return { kind: 'source_inspection' as const, inspectionId: row.inspectionId, attempt: 1 as const,
    principalId: row.principalId, targetRef: row.targetRef, supervisorInstanceId: row.supervisorInstanceId };
}
function sourceRootImage(row: SourceInspectionAttemptV1, target: SourceInspectionTargetV2, entry: BundleEntry,
  profile: SandboxRootProfileV1): SandboxRootImageV1 {
  const image: SandboxRootImageV1 = { schemaVersion: 1, format: 'cliq-sandbox-root-image-v1',
    runtimeBundleRef: target.runtimeBundleRef, runtimeBundleManifestDigest: target.runtimeBundleManifestDigest,
    entryId: entry.entryId, entryVersion: entry.version, entryDigest: entry.digest,
    protocol: profile.protocol, filesystemKind: profile.filesystemKind, fixedDirectories: profile.fixedDirectories,
    ownerUid: row.stagingIdentity.ownerUid, persistent: false, networkConfiguration: 'none', imageDigest: '' };
  image.imageDigest = digestOmitting(image, 'imageDigest'); return image;
}
function sourcePlan(row: SourceInspectionAttemptV1, reservation: Omit<NativeSourceGitReservationObservation, 'observedAtMs'>,
  rootRef: string, rootDigest: string, launchNonceDigest: string, createdAt: string): ProcessContainmentPlanV1 {
  const plan: ProcessContainmentPlanV1 = { schemaVersion: 1, format: 'cliq-process-containment-plan-v1', owner: sourceOwner(row),
    filesystemBinding: { kind: 'isolated-empty-root', rootImageRef: rootRef, rootImageDigest: rootDigest }, launchNonceDigest,
    backend: { kind: 'linux', cgroupPath: reservation.cgroupPath,
      cgroupNameReservationDigest: canonicalSha256(['cliq-source-cgroup-v1', row.inspectionId, row.stagingNonceDigest]),
      pidNamespaceReservationId: reservation.pidNamespaceReservationId, subreaperStartToken: reservation.subreaperStartToken,
      nativeReservation: { deviceId: reservation.deviceId, fileId: reservation.fileId, ownerUid: reservation.ownerUid } },
    createdAt, planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest'); return plan;
}
function sourceSpec(row: SourceInspectionAttemptV1, target: SourceInspectionTargetV2, intent: SourceInspectionInputV2,
  intentRef: string, root: SandboxRootImageV1, rootRef: string, toolchain: RetainedVerifierToolchain,
  inspector: BundleEntry, launcher: BundleEntry, plan: ProcessContainmentPlanV1, planRef: string, createdAt: string): SourceSpec {
  const runtime: SandboxRuntimeBindingV1 = { runtimeBundleRef: target.runtimeBundleRef,
    runtimeBundleManifestDigest: target.runtimeBundleManifestDigest, sandboxBackend: 'linux_namespace',
    toolchain: { kind: 'guest_toolchain', guestToolchainManifestRef: toolchain.manifestRef,
      guestToolchainManifestDigest: toolchain.manifest.manifestDigest, guestImageRef: toolchain.manifest.guestImageRef,
      guestImageDigest: toolchain.manifest.guestImageDigest },
    launcher: { executableId: launcher.entryId, executableDigest: launcher.digest }, runtimeDigest: '' };
  runtime.runtimeDigest = digestOmitting(runtime, 'runtimeDigest');
  const environment: SanitizedSandboxEnvironmentV1 = { schemaVersion: 1, format: 'cliq-sanitized-sandbox-environment-v1',
    controlledPath: ['/usr/bin'], locale: { lang: 'C', lcAll: 'C' }, home: '/scratch/home', tmpdir: '/scratch/tmp', variables: [],
    inheritedHostEnvironment: false, secretMaterial: 'none', brokerAccessAtSpawn: 'none', networkMode: 'none', environmentDigest: '' };
  environment.environmentDigest = digestOmitting(environment, 'environmentDigest');
  const spec: SourceSpec = { schemaVersion: 1, format: 'cliq-sandbox-launch-v1', owner: sourceOwner(row), purpose: 'source_inspection', runtime,
    executable: { kind: 'guest_toolchain', guestToolchainManifestRef: toolchain.manifestRef,
      guestToolchainManifestDigest: toolchain.manifest.manifestDigest, toolId: toolchain.manifest.node.logicalName,
      role: 'tool', executionPath: '/usr/bin/node', executableDigest: toolchain.manifest.node.digest },
    processInvocation: { kind: 'source_inspection', purpose: 'source_inspection', recipe: 'cliq-source-git-inspection-v1',
      targetRef: row.targetRef, targetDigest: row.targetDigest, inputRef: intentRef, inputDigest: intent.inputDigest,
      argvCwdSource: 'trusted_recipe_decode_of_frozen_source_input', stdio: { stdin: 'closed', stdout: 'captured', stderr: 'captured',
        extraFileDescriptors: 'authenticated_operation_channel_only' } }, environment,
    filesystem: { kind: 'isolated_empty_root', rootImageRef: rootRef, rootImageDigest: root.imageDigest, persistentWritableMounts: false },
    mounts: [{ kind: 'cas_artifact', artifactRef: inspector.digest, artifactDigest: inspector.digest,
      targetPath: '/runtime/cliq-source-git-inspector.mjs', access: 'read_only', purpose: 'runtime' },
    { kind: 'private_ephemeral', privateRootId: identityHash('cliq-source-scratch-v1', row.inspectionId, row.stagingNonceDigest),
      targetPath: '/scratch', access: 'read_write', purpose: 'output' },
    { kind: 'source_git_inspection_input', inputRef: intentRef, inputDigest: intent.inputDigest,
      targetPath: '/scratch/input', access: 'read_only', purpose: 'input' }], mountsDigest: '',
    sandboxProfileRef: target.sandboxProfileRef, sandboxProfileDigest: target.sandboxProfileDigest,
    resources: intent.resources, resourcesDigest: canonicalSha256(intent.resources), containmentPlanRef: planRef,
    containmentPlanDigest: plan.planDigest, createdAt, launchSpecDigest: '',
    sourceInspectionTargetRef: row.targetRef, sourceInspectionTargetDigest: row.targetDigest,
    sourceInspectionInputRef: intentRef, sourceInspectionInputDigest: intent.inputDigest };
  spec.mountsDigest = canonicalSha256(spec.mounts); spec.launchSpecDigest = digestOmitting(spec, 'launchSpecDigest'); return spec;
}

/** Publishes exact signed recipe data, not a native reservation or execution
 * capability. Only the original owning attempt may persist this plan and then
 * create/release its genuine blocked scope at the current SQL fences. */
export async function publishSourceGitLaunch(artifacts: ArtifactCatalog, input: SourceInspectionBootstrap & {
  row: Capturing; target: SourceInspectionTargetV2; input: SourceInspectionInputV2;
  reservation: NativeSourceGitReservationObservation; toolchain: RetainedVerifierToolchain;
}, launchNonceDigest: string, signal?: AbortSignal) {
  signal?.throwIfAborted(); assertArtifactRef(launchNonceDigest);
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const { row, target, reservation, bundle, releaseKeys } = input;
  const intent = decodeSourceGitInputIntent(input.input), profile = decodeSandboxProfile(input.sandboxProfile);
  verifyRuntimeBundle(bundle, releaseKeys);
  if (row.phase !== 'capturing' || row.cancelRequested || row.retirementHandoffRef || target.schemaVersion !== 2 ||
      row.targetRef !== canonicalSha256(target) || row.targetDigest !== digestOmitting(target, 'targetDigest') ||
      target.targetDigest !== row.targetDigest || intent.inspectionId !== row.inspectionId || intent.targetRef !== row.targetRef ||
      intent.targetDigest !== row.targetDigest || row.principalId !== target.principalId ||
      row.method !== target.method || row.admissionKey !== target.admissionKey || row.admissionIntentDigest !== target.admissionIntentDigest ||
      row.workspaceIdentityDigest !== target.workspaceIdentityDigest ||
      intent.inspectionGrantId !== target.inspectionGrantId || intent.inspectionReceiptRef !== target.inspectionReceiptRef ||
      intent.inspectionReceiptDigest !== target.inspectionReceiptDigest || target.runtimeBundleRef !== canonicalSha256(bundle) ||
      target.runtimeBundleManifestDigest !== bundle.manifestDigest || target.sandboxProfileRef !== canonicalSha256(profile) ||
      target.sandboxProfileDigest !== profile.profileDigest || profile.backend !== 'linux_namespace' ||
      !profile.allowedOwners.includes('source_inspection') || canonicalSha256(intent.resources) !== canonicalSha256(profile.resources) ||
      reservation.fileId !== reservation.cgroupId || reservation.ownerUid !== row.stagingIdentity.ownerUid ||
      reservation.pidNamespaceReservationId !== `source-pending:${row.stagingNonceDigest}` ||
      !Number.isSafeInteger(reservation.observedAtMs) || reservation.observedAtMs < Date.parse(row.createdAt)) return invalid();
  const { root: rootEntry, inspector, launcher } = recipeEntries(bundle);
  const rootBytes = await reads.readBoundedBytes(rootEntry.digest, rootEntry.byteCount);
  signal?.throwIfAborted();
  if (rootBytes.length !== rootEntry.byteCount || sha256Bytes(rootBytes) !== rootEntry.digest) return invalid();
  const rootProfile = decodeSandboxRootProfile(parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(rootBytes)));
  if (!canonicalJsonBytes(rootProfile).equals(rootBytes)) return invalid();
  // An earlier selection/reference is not the complete current signed image
  // walk needed by this independent launch acceptance point.
  const toolchain = await readRetainedVerifierToolchain(reads, { bundle, releaseKeys,
    guestToolchainManifestRef: input.toolchain.manifestRef, signal });
  signal?.throwIfAborted();
  if (canonicalSha256(toolchain.manifest) !== canonicalSha256(input.toolchain.manifest) ||
      toolchain.manifest.node.canonicalGuestPath !== '/usr/bin/node' || toolchain.manifest.git.canonicalGuestPath !== '/usr/bin/git') return invalid();
  const recipeMetadata = [];
  for (const entry of [inspector, launcher]) {
    let count = 0;
    for await (const chunk of reads.readChunks(entry.digest, entry.byteCount)) { signal?.throwIfAborted(); count += chunk.length; }
    if (count !== entry.byteCount) return invalid();
    recipeMetadata.push({ ref: entry.digest, byteLength: entry.byteCount,
      mediaType: 'application/octet-stream', schemaKind: 'cliq-source-git-recipe-member-v1' });
  }
  const rootImage = sourceRootImage(row, target, rootEntry, rootProfile);
  const [intentArtifact, rootArtifact] = await artifacts.publishCanonicalPair([
    { value: intent, schemaKind: intent.format }, { value: rootImage, schemaKind: rootImage.format }
  ]);
  signal?.throwIfAborted();
  const containmentPlan = sourcePlan(row, reservation, rootArtifact.ref, rootImage.imageDigest, launchNonceDigest, sampleCanonicalNow());
  const planArtifact = await artifacts.publishCanonical(containmentPlan, containmentPlan.format);
  signal?.throwIfAborted();
  const spec = sourceSpec(row, target, intent, intentArtifact.ref, rootImage, rootArtifact.ref, toolchain,
    inspector, launcher, containmentPlan, planArtifact.ref, sampleCanonicalNow());
  const specArtifact = await artifacts.publishCanonical(spec, spec.format);
  signal?.throwIfAborted();
  const plan: SourceInspectionPlanV1 = { launchNonceDigest, containmentPlanRef: planArtifact.ref,
    containmentPlanDigest: containmentPlan.planDigest, sandboxLaunchSpecRef: specArtifact.ref, sandboxLaunchSpecDigest: spec.launchSpecDigest,
    reservedBackendIdentity: { kind: 'linux', cgroupPath: reservation.cgroupPath, cgroupId: reservation.cgroupId,
      deviceId: reservation.deviceId, fileId: reservation.fileId, ownerUid: reservation.ownerUid,
      pidNamespaceReservationId: reservation.pidNamespaceReservationId, subreaperStartToken: reservation.subreaperStartToken } };
  return immutableSnapshot({ input: intent, inputRef: intentArtifact.ref, rootImage, containmentPlan, spec, plan,
    metadata: [...recipeMetadata, intentArtifact, rootArtifact, planArtifact, specArtifact] });
}

async function canonicalData<T>(artifacts: ArtifactCatalog, ref: string, maximum = 1_048_576): Promise<T> {
  const bytes = await artifacts.readBoundedBytes(ref, maximum);
  if (sha256Bytes(bytes) !== ref) return invalid();
  const value: unknown = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!canonicalJsonBytes(value).equals(bytes)) return invalid();
  return value as T;
}

/** Complete retained recipe data under the original trusted StateOwner's
 * runtime identity. This does not authenticate a new key, reconstruct a native
 * object, or authorize execution. Its outer reader checks that original owner
 * and inspector; current trust keys cannot replace the original signed root. */
export async function readRetainedSourceGitLaunch(artifacts: ArtifactCatalog, row: SourceInspectionAttemptV1,
  target: SourceInspectionTargetV2, input: SourceInspectionInputV2, observedAt: string): Promise<void> {
  const recorded = row.plan;
  if (!recorded || recorded.reservedBackendIdentity.kind !== 'linux' || !row.inputRef ||
      row.inputRef !== canonicalSha256(input) || row.inputDigest !== input.inputDigest ||
      row.targetRef !== canonicalSha256(target) || target.targetDigest !== row.targetDigest ||
      target.targetDigest !== digestOmitting(target, 'targetDigest') || target.principalId !== row.principalId ||
      target.workspaceIdentityDigest !== row.workspaceIdentityDigest || input.inspectionId !== row.inspectionId ||
      input.targetRef !== row.targetRef || input.targetDigest !== row.targetDigest ||
      input.inspectionGrantId !== target.inspectionGrantId || input.inspectionReceiptRef !== target.inspectionReceiptRef ||
      input.inspectionReceiptDigest !== target.inspectionReceiptDigest) return invalid();
  // Read both original objects, rather than accepting their strings from the
  // row or requiring that a later native reply happened to include them.
  const plan = await canonicalData<ProcessContainmentPlanV1>(artifacts, recorded.containmentPlanRef);
  const spec = await canonicalData<SourceSpec>(artifacts, recorded.sandboxLaunchSpecRef);
  const created = parseCanonicalTime(plan.createdAt), launched = parseCanonicalTime(spec.createdAt);
  if (plan.planDigest !== recorded.containmentPlanDigest || plan.planDigest !== digestOmitting(plan, 'planDigest') ||
      spec.launchSpecDigest !== recorded.sandboxLaunchSpecDigest || spec.launchSpecDigest !== digestOmitting(spec, 'launchSpecDigest') ||
      created < parseCanonicalTime(row.createdAt) || launched < created || launched >= parseCanonicalTime(row.deadlineAt) ||
      launched > parseCanonicalTime(observedAt)) return invalid();
  const bundle = await canonicalData<RuntimeBundleManifest>(artifacts, target.runtimeBundleRef);
  const { manifestDigest: _bundleDigest, signature: _bundleSignature, ...bundleCore } = bundle;
  if (bundle.manifestDigest !== target.runtimeBundleManifestDigest || canonicalSha256(bundleCore) !== bundle.manifestDigest)
    return invalid();
  const profile = decodeSandboxProfile(await canonicalData(artifacts, target.sandboxProfileRef));
  if (profile.profileDigest !== target.sandboxProfileDigest || profile.backend !== 'linux_namespace' ||
      !profile.allowedOwners.includes('source_inspection') || canonicalSha256(profile.resources) !== canonicalSha256(input.resources)) return invalid();
  const entries = recipeEntries(bundle), rootProfile = decodeSandboxRootProfile(await canonicalData(artifacts, entries.root.digest));
  const rootImage = sourceRootImage(row, target, entries.root, rootProfile), rootRef = canonicalSha256(rootImage);
  const actualRoot = await canonicalData<SandboxRootImageV1>(artifacts, rootRef);
  if (!canonicalJsonBytes(actualRoot).equals(canonicalJsonBytes(rootImage))) return invalid();
  if (spec.runtime?.toolchain?.kind !== 'guest_toolchain') return invalid();
  const manifestRef = spec.runtime.toolchain.guestToolchainManifestRef;
  const manifest = decodeGuestToolchainManifest(await canonicalData(artifacts, manifestRef));
  const members = guestToolchainMembers(bundle, manifestRef, manifest);
  if (manifest.node.canonicalGuestPath !== '/usr/bin/node' || manifest.git.canonicalGuestPath !== '/usr/bin/git' ||
      entries.root.byteCount !== canonicalJsonBytes(rootProfile).length) return invalid();
  // CAS exhausts and hashes every selected signed member. No executable is
  // started and no bytes are adopted from today's installation.
  for (const entry of [...members, entries.inspector, entries.launcher]) {
    let count = 0;
    for await (const chunk of artifacts.readChunks(entry.digest, entry.byteCount)) count += chunk.length;
    if (count !== entry.byteCount) return invalid();
  }
  const expectedPlan = sourcePlan(row, recorded.reservedBackendIdentity, rootRef, rootImage.imageDigest,
    recorded.launchNonceDigest, plan.createdAt);
  const expectedSpec = sourceSpec(row, target, input, row.inputRef, rootImage, rootRef,
    { manifestRef, manifest, abiFingerprint: manifest.manifestDigest }, entries.inspector, entries.launcher,
    expectedPlan, recorded.containmentPlanRef, spec.createdAt);
  if (!canonicalJsonBytes(plan).equals(canonicalJsonBytes(expectedPlan)) ||
      !canonicalJsonBytes(spec).equals(canonicalJsonBytes(expectedSpec))) return invalid();
}
