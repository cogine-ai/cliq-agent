import { assertArtifactRef, digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import type { RunAssemblyV1, SupervisorInspectorIdentityV1 } from '../kernel/types.js';
import { exactKeys, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodePlatformProcessIdentity, decodeStateLockIdentity } from './decoders.js';
import type { StateOwnerContext } from './state-owner.js';

/** Shared identity check, not proof of a live observation. Each consumer owns freshness and state-owner fencing. */
export async function readSupervisorInspector(artifacts: ArtifactCatalog, owner: Pick<StateOwnerContext,
  'supervisorInstanceId' | 'ownerEpoch' | 'processIdentityRef' | 'processIdentityDigest' | 'stateLockIdentityRef' | 'stateLockIdentityDigest'>,
assembly: RunAssemblyV1, input: { inspectorIdentityRef: string; inspectorIdentityDigest: string; observedAt: string }) {
  const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, input.inspectorIdentityRef);
  const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, assembly.runtime.runtimeBundleRef);
  const supervisor = bundle.entries.find((entry) => entry.role === 'supervisor');
  if (!exactKeys(inspector, ['schemaVersion', 'format', 'supervisorInstanceId', 'stateOwnerEpoch', 'runtimeBundleRef',
    'runtimeBundleManifestDigest', 'supervisorEntryId', 'supervisorEntryVersion', 'supervisorExecutableDigest',
    'processIdentityRef', 'processIdentityDigest', 'stateLockIdentityRef', 'stateLockIdentityDigest', 'instanceNonceDigest', 'activatedAt', 'identityDigest']) ||
      inspector.schemaVersion !== 1 || inspector.format !== 'cliq-supervisor-inspector-identity-v1' ||
      inspector.identityDigest !== input.inspectorIdentityDigest || digestOmitting(inspector, 'identityDigest') !== inspector.identityDigest ||
      inspector.supervisorInstanceId !== owner.supervisorInstanceId || inspector.stateOwnerEpoch !== owner.ownerEpoch ||
      inspector.runtimeBundleRef !== assembly.runtime.runtimeBundleRef || inspector.runtimeBundleManifestDigest !== assembly.runtime.runtimeBundleManifestDigest ||
      inspector.processIdentityRef !== owner.processIdentityRef || inspector.processIdentityDigest !== owner.processIdentityDigest ||
      inspector.stateLockIdentityRef !== owner.stateLockIdentityRef || inspector.stateLockIdentityDigest !== owner.stateLockIdentityDigest ||
      inspector.supervisorEntryId !== supervisor?.entryId || inspector.supervisorEntryVersion !== supervisor.version ||
      inspector.supervisorExecutableDigest !== supervisor.digest || !supervisor.executable || inspector.activatedAt > input.observedAt) {
    throw new TypeError('inspector does not match the trusted state owner and frozen runtime');
  }
  assertArtifactRef(inspector.instanceNonceDigest);
  parseCanonicalTime(inspector.activatedAt);
  parseCanonicalTime(input.observedAt);
  const process = decodePlatformProcessIdentity(await readCanonicalArtifact(artifacts, inspector.processIdentityRef));
  const lock = decodeStateLockIdentity(await readCanonicalArtifact(artifacts, inspector.stateLockIdentityRef));
  if (process.identityDigest !== inspector.processIdentityDigest || lock.identityDigest !== inspector.stateLockIdentityDigest) {
    throw new TypeError('inspector process or state-lock identity digest mismatch');
  }
  return inspector;
}
