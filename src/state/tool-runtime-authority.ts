// Full original signed tool data, not a reusable permission or native launch.
import type { RunAssemblyV1, ToolContractManifestV1, StateOwnerRecordV1 } from '../kernel/types.js';
import { requireEqual, verifyToolRuntimeAuthority, type RuntimeBundleManifest, type ReleaseTrustKey } from '../policy/runtime-authority.js';
import type { PolicyEngineProfileV1, RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import { decodeToolExecutionIdentity } from '../tools/execution-identity.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readRetainedVerifierToolchain } from './guest-toolchain.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import { LINUX_VERIFIER_RESOURCE_MINIMUMS } from '../sandbox/guest-toolchain.js';
import { BUILTIN_SCRIPT_RECIPE } from '../sandbox/builtin-tool-data.js';

/** Fixed recipe support only, never a grant or a replacement OS limit. The
 * original supplied profile remains unchanged when it cannot support Node. */
export function assertBuiltinScriptResources(imageByteCount: number, resources: SandboxResourceSpec): void {
  if (!Number.isSafeInteger(imageByteCount) || imageByteCount < 1 || imageByteCount > BUILTIN_SCRIPT_RECIPE.maximumFileBytes ||
      [resources.maxProcesses, resources.maxSingleFileBytes, resources.maxInvocationOutputBytes,
        resources.maxIpcFrameBytes, resources.maxQueuedIpcBytes].some(value => !Number.isSafeInteger(value)) ||
      resources.maxProcesses < LINUX_VERIFIER_RESOURCE_MINIMUMS.maxProcesses ||
      resources.maxSingleFileBytes < imageByteCount || resources.maxSingleFileBytes > BUILTIN_SCRIPT_RECIPE.maximumFileBytes ||
      resources.maxInvocationOutputBytes < 65536 || resources.maxInvocationOutputBytes > BUILTIN_SCRIPT_RECIPE.maximumOutputBytes ||
      resources.maxIpcFrameBytes !== DEFAULT_SANDBOX_RESOURCES.maxIpcFrameBytes ||
      resources.maxQueuedIpcBytes !== DEFAULT_SANDBOX_RESOURCES.maxQueuedIpcBytes)
    throw new TypeError('the original profile cannot support the fixed signed builtin recipe');
}

/** Every call exhausts the original script and signed image streams. This is
 * deliberately scoped to the caller's read cut and cancellation signal. */
export async function readToolRuntimeAuthority(artifacts: ArtifactCatalog, input: {
  assembly: RunAssemblyV1; bundle: RuntimeBundleManifest; policy: RunPolicySnapshotV1;
  profile: PolicyEngineProfileV1; tools: ToolContractManifestV1['entries']; releaseKeys: readonly ReleaseTrustKey[];
  resources: SandboxResourceSpec;
}, signal?: AbortSignal) {
  signal?.throwIfAborted();
  const scripts = input.tools.map(tool => decodeToolExecutionIdentity(tool.execution))
    .filter(execution => execution.kind === 'builtin_script');
  const guestToolchain = scripts.length ? await readRetainedVerifierToolchain(artifacts, {
    bundle: input.bundle, releaseKeys: input.releaseKeys,
    guestToolchainManifestRef: input.assembly.runtime.guestToolchainManifestRef, signal
  }) : undefined;
  verifyToolRuntimeAuthority({ ...input, ...(guestToolchain ? { guestToolchain } : {}) });
  if (guestToolchain) assertBuiltinScriptResources(guestToolchain.manifest.guestImageByteCount, input.resources);
  for (const digest of new Set(scripts.map(execution => execution.adapterCodeDigest))) {
    const entry = input.bundle.entries.find(entry => entry.digest === digest)!;
    for await (const _chunk of artifacts.readChunks(entry.digest, entry.byteCount)) signal?.throwIfAborted();
  }
  signal?.throwIfAborted();
  return guestToolchain;
}

/** The caller obtains owner from the genuine held StateOwner assertion. An
 * original signed control handler cannot execute in a different current image. */
export function assertSupervisorControlIdentity(owner: StateOwnerRecordV1, assembly: RunAssemblyV1,
  tools: ToolContractManifestV1['entries']): void {
  for (const tool of tools) {
    const execution = decodeToolExecutionIdentity(tool.execution);
    if (execution.kind !== 'supervisor_control') continue;
    requireEqual({ runtimeBundleRef: owner.runtimeBundleRef, manifestDigest: owner.runtimeBundleManifestDigest,
      entryId: owner.supervisorEntryId, version: owner.supervisorEntryVersion, digest: owner.supervisorExecutableDigest },
    { runtimeBundleRef: assembly.runtime.runtimeBundleRef, manifestDigest: assembly.runtime.runtimeBundleManifestDigest,
      entryId: execution.supervisorEntryId, version: execution.supervisorEntryVersion, digest: execution.supervisorExecutableDigest },
    'current signed Supervisor control handler');
  }
}
