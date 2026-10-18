import { digestOmitting } from '../kernel/identity.js';
import type { SandboxProfileV1, SandboxResourceSpec } from '../kernel/execution.js';
import { immutableSnapshot } from '../model/immutable.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
export { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';

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
