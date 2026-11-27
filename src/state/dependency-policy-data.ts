import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeDependencyPolicy } from '../kernel/dependency.js';
import { decodeEndpointRegistration } from '../kernel/credential-authority.js';
import type { RunSpec } from '../kernel/types.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';

/** Frozen data only. The original admission/intent reader independently
 * verifies registration provenance; each live release reopens that authority. */
export async function readFrozenDependencyPolicy(artifacts: ArtifactCatalog, spec: RunSpec) {
  if (!spec.dependencyPolicyRef) throw new TypeError('dependency candidate has no frozen policy');
  const policy = decodeDependencyPolicy(await readCanonicalArtifact(artifacts, spec.dependencyPolicyRef));
  if (policy.mode !== 'locked_node' || policy.allowedAdapters.length !== 1 || policy.allowedAdapters[0] !== 'npm-ci-v1' ||
      policy.credentialGrantRefs.length) throw new TypeError('dependency candidate is outside the public npm profile');
  const endpoints = await artifacts.mapReads(policy.registryEndpoints, async target => {
    const endpoint = decodeEndpointRegistration(await readCanonicalArtifact(artifacts, target.endpointRegistrationRef));
    if (canonicalSha256(endpoint) !== target.endpointRegistrationRef || endpoint.endpointIdentityDigest !== target.endpointIdentityDigest ||
        endpoint.tlsPolicyDigest !== target.tlsPolicyDigest || !endpoint.purposes.includes('dependency_registry'))
      throw new TypeError('dependency policy substitutes its complete original registry tuple');
    return endpoint;
  });
  artifacts.assertReadActive(); return { policy, endpoints };
}
