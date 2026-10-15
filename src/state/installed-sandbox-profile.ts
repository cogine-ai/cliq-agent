import { digestOmitting } from '../kernel/identity.js';
import type { SandboxProfileV1, SandboxResourceSpec } from '../kernel/execution.js';
import { immutableSnapshot } from '../model/immutable.js';
import { decodeSandboxProfile } from './execution-closure.js';

// Resource defaults are data, not the signed empty-root filesystem recipe or
// a Workspace Trust / tool permission decision.
export const DEFAULT_SANDBOX_RESOURCES: Readonly<SandboxResourceSpec> = Object.freeze({
  maxProcesses: 256, memoryBytes: 4 * 1024 ** 3, cpuQuotaMicrosPerSecond: 400_000,
  maxOpenFiles: 1024, maxSingleFileBytes: 256 * 1024 ** 2, maxGenerationBytes: 20 * 1024 ** 3,
  maxInvocationOutputBytes: 16 * 1024 ** 2, maxIpcFrameBytes: 16 * 1024 ** 2, maxQueuedIpcBytes: 64 * 1024 ** 2,
});

/** Fixed installed recipe. Public input can select only already-normalized
 * bounded resources, never filesystem/network/credential/environment flags. */
export function installedSandboxProfile(resources: SandboxResourceSpec = DEFAULT_SANDBOX_RESOURCES): SandboxProfileV1 {
  const profile: SandboxProfileV1 = { schemaVersion: 1, format: 'cliq-sandbox-profile-v1', backend: 'linux_namespace',
    allowedOwners: ['run_invocation', 'source_inspection', 'worker_activation'], filesystemPolicy: 'typed_launch_spec_only',
    hostFilesystemReachability: 'none', networkAtSpawn: 'none', networkAfterRelease: 'typed_broker_only',
    credentialReachability: 'typed_broker_only', stateRootReachability: 'none', inheritedHostEnvironment: false,
    resources: { ...resources }, profileDigest: '' };
  profile.profileDigest = digestOmitting(profile, 'profileDigest');
  return immutableSnapshot(decodeSandboxProfile(profile));
}
