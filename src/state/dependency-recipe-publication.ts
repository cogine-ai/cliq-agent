import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { ProcessContainmentPlanV1, SandboxLaunchSpecV1, SandboxRuntimeBindingV1 } from '../kernel/execution.js';
import { NPM_DEPENDENCY_SANDBOX_ENVIRONMENT, npmDependencyMounts } from '../sandbox/dependency-recipe.js';
import { requireEqual } from '../policy/runtime-authority.js';
import type { ArtifactCatalog } from './artifacts.js';
import type { PreparedDependencyInvocation } from './dependency-preparation.js';
import { decodeDependencySandboxLaunchSpec } from './execution-closure.js';
import { sampleCanonicalNow } from './canonical-time.js';

type WorkerSpec = Extract<SandboxLaunchSpecV1, { purpose: 'worker_activation' }>;
type DependencySpec = Extract<SandboxLaunchSpecV1, { owner: { kind: 'run_invocation' } }> & { purpose: 'dependency' };

/** Publishes fixed recipe data only. The permanent Journal claim, genuine
 * owner and full launch reader remain necessary before any native CREATE. */
export async function publishDependencyRecipe(artifacts: ArtifactCatalog, worker: WorkerSpec,
  parentContainmentRef: string, parentCgroup: string, prepared: PreparedDependencyInvocation, dispatchId: string) {
  if (worker.filesystem.kind !== 'run_generation' || worker.owner.runId !== prepared.run.id ||
      worker.owner.intendedLeaseEpoch !== prepared.run.leaseEpoch || worker.containmentPlanRef === parentContainmentRef)
    throw new TypeError('dependency requires its actual original activated parent');
  const parent = await artifacts.readCanonical<ProcessContainmentPlanV1>(worker.containmentPlanRef);
  if (parent.backend.kind !== 'linux') throw new TypeError('dependency requires its original Linux parent');
  requireEqual(worker.resources, prepared.source.profile.resources, 'dependency unchanged original resource profile');
  const signed = prepared.source.signed, guest = signed.toolchain.manifest;
  const owner = { kind: 'run_invocation' as const, runId: prepared.run.id, intendedLeaseEpoch: prepared.run.leaseEpoch,
    workerLaunchId: worker.owner.workerLaunchId, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId };
  const cgroupNameReservationDigest = canonicalSha256(['cliq-dependency-cgroup-v1', dispatchId]);
  const plan: ProcessContainmentPlanV1 = { schemaVersion: 1, format: 'cliq-process-containment-plan-v1', owner,
    filesystemBinding: { kind: 'run-generation', generationRef: worker.filesystem.generationRef }, parentContainmentRef,
    launchNonceDigest: randomBytes(32).toString('hex'), backend: { kind: 'linux',
      cgroupPath: path.posix.join(parentCgroup, `cliq-${cgroupNameReservationDigest}`), cgroupNameReservationDigest,
      pidNamespaceReservationId: identityHash('cliq-dependency-namespace-v1', dispatchId), subreaperStartToken: parent.backend.subreaperStartToken },
    createdAt: sampleCanonicalNow(), planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest');
  const containmentPlanRef = (await artifacts.publishCanonical(plan, plan.format)).ref;
  const runtime: SandboxRuntimeBindingV1 = { ...worker.runtime, toolchain: { kind: 'guest_toolchain',
    guestToolchainManifestRef: signed.toolchain.manifestRef, guestToolchainManifestDigest: guest.manifestDigest,
    guestImageRef: guest.guestImageRef, guestImageDigest: guest.guestImageDigest }, runtimeDigest: '' };
  runtime.runtimeDigest = digestOmitting(runtime, 'runtimeDigest');
  const mounts = [...npmDependencyMounts(dispatchId, worker.filesystem.generationRef, signed.adapter.digest, signed.image.digest)];
  const spec: DependencySpec = { ...worker, owner, purpose: 'dependency', runtime,
    executable: { kind: 'guest_toolchain', guestToolchainManifestRef: signed.toolchain.manifestRef,
      guestToolchainManifestDigest: guest.manifestDigest, toolId: 'node', role: 'package_manager',
      executionPath: '/usr/bin/node', executableDigest: guest.node.digest },
    processInvocation: { kind: 'run_request', purpose: 'dependency', recipe: 'cliq-dependency-npm-v1',
      requestRef: prepared.entry.requestRef, requestDigest: prepared.request.requestDigest,
      targetRef: prepared.request.targetRef, targetDigest: prepared.target.targetDigest,
      argvCwdSource: 'trusted_recipe_decode_of_request_and_target', stdio: { stdin: 'closed', stdout: 'captured', stderr: 'captured',
        extraFileDescriptors: 'sealed_dependency_input_and_package_metadata_only' } },
    filesystem: { ...worker.filesystem, access: 'read_only' }, environment: NPM_DEPENDENCY_SANDBOX_ENVIRONMENT,
    mounts, mountsDigest: canonicalSha256(mounts), parentWorkerContainmentRef: parentContainmentRef,
    requestRef: prepared.entry.requestRef, requestDigest: prepared.request.requestDigest,
    targetRef: prepared.request.targetRef, targetDigest: prepared.target.targetDigest, operationGrantRef: prepared.entry.grantRef!,
    containmentPlanRef, containmentPlanDigest: plan.planDigest, createdAt: sampleCanonicalNow(), launchSpecDigest: '' };
  spec.launchSpecDigest = digestOmitting(spec, 'launchSpecDigest');
  decodeDependencySandboxLaunchSpec(spec);
  return (await artifacts.publishCanonical(spec, spec.format)).ref;
}
