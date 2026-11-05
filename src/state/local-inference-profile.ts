// Fixed data recipe. This profile describes a requested boundary; only the
// actual native service owner and inspector can prove it exists.
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import type { SandboxProfileV1 } from '../kernel/execution.js';
import { digestOmitting } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { decodeSandboxProfile } from './execution-closure.js';

export function installedLocalInferenceProfile(): SandboxProfileV1 {
  const profile: SandboxProfileV1 = { schemaVersion: 1, format: 'cliq-sandbox-profile-v1', backend: 'linux_namespace',
    allowedOwners: ['local_inference_service'], filesystemPolicy: 'typed_launch_spec_only', hostFilesystemReachability: 'none',
    networkAtSpawn: 'none', networkAfterRelease: 'typed_broker_only', credentialReachability: 'typed_broker_only',
    stateRootReachability: 'none', inheritedHostEnvironment: false, resources: { ...DEFAULT_SANDBOX_RESOURCES }, profileDigest: '' };
  profile.profileDigest = digestOmitting(profile, 'profileDigest');
  return immutableSnapshot(decodeSandboxProfile(profile));
}
