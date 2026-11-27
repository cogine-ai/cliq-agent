import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireRecord } from '../kernel/control-wire-data.js';
import { decodeEndpointRegistration, type EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import { decodeDependencyAcquisitionPlan, type DependencyAcquisitionPlan, type DependencyPackageDescriptorV1 } from '../kernel/dependency.js';
import { dependencyDescriptorSequence } from '../kernel/dependency-descriptors.js';
import { assertDependencyCacheManifestCapacity } from '../kernel/dependency-cache-capacity.js';
import { assertArtifactRef } from '../kernel/identity.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { types } from 'node:util';

/** New-purpose data admission only. It neither loads a native module nor
 * proves endpoint registration/currentness or consumes a network permission. */
export function planDependencyTransport(input: {
  plan: DependencyAcquisitionPlan; packages: readonly DependencyPackageDescriptorV1[];
  endpoints: readonly EndpointRegistrationV1[]; sandboxLaunchSpecRef: string; resources: SandboxResourceSpec;
  runRemainingMs: number; storage: { maximumOwnerDataBytes: number; descriptorPageStorageBytes: number; fixedOwnerStorageBytes: number };
}) {
  // The descriptor sequence has its own original bounded page channel. Do
  // not pretend that its entire packages[] is one model/wire JSON object.
  if (types.isProxy(input)) throw new TypeError('dependency transport requires plain original data');
  controlWireRecord(input, ['plan', 'packages', 'endpoints', 'sandboxLaunchSpecRef', 'resources', 'runRemainingMs', 'storage']);
  assertControlWireJson({ resources: input.resources, runRemainingMs: input.runRemainingMs,
    storage: input.storage, sandboxLaunchSpecRef: input.sandboxLaunchSpecRef });
  controlWireRecord(input.storage, ['maximumOwnerDataBytes', 'descriptorPageStorageBytes', 'fixedOwnerStorageBytes']);
  assertControlWireJson(input.endpoints);
  const plan = decodeDependencyAcquisitionPlan(input.plan), sequence = dependencyDescriptorSequence(input.packages);
  const { storage } = input;
  if (storage.maximumOwnerDataBytes !== 67_108_864 || !Number.isSafeInteger(storage.descriptorPageStorageBytes) ||
      storage.descriptorPageStorageBytes < 1 || storage.descriptorPageStorageBytes > 1_048_576 ||
      !Number.isSafeInteger(storage.fixedOwnerStorageBytes) || storage.fixedOwnerStorageBytes < 1 ||
      storage.fixedOwnerStorageBytes > storage.maximumOwnerDataBytes || !Number.isSafeInteger(input.runRemainingMs) || input.runRemainingMs < 1)
    throw new TypeError('dependency transport has invalid original storage or deadline bounds');
  assertArtifactRef(input.sandboxLaunchSpecRef);
  if (sequence.packageCount !== plan.packageCount || sequence.packageDescriptorBytes !== plan.packageDescriptorBytes ||
      sequence.descriptorSequenceDigest !== plan.descriptorSequenceDigest || plan.credentialGrantRefs.length || input.endpoints.length !== plan.registryEndpoints.length)
    throw new TypeError('dependency transport substitutes its original whole descriptor plan');
  const endpoints = input.endpoints.map(decodeEndpointRegistration), byRef = new Map(endpoints.map(endpoint => [canonicalSha256(endpoint), endpoint]));
  if (byRef.size !== endpoints.length) throw new TypeError('dependency transport contains duplicate registry roots');
  const targets = plan.registryEndpoints.map(target => {
    const endpoint = byRef.get(target.endpointRegistrationRef);
    if (!endpoint || endpoint.endpointIdentityDigest !== target.endpointIdentityDigest || endpoint.tlsPolicyDigest !== target.tlsPolicyDigest ||
        !endpoint.purposes.includes('dependency_registry') || endpoint.tls.spkiSha256Pins.length > 64)
      throw new TypeError('dependency transport substitutes its complete original TLS target');
    return { endpointRegistrationRef: target.endpointRegistrationRef, ...endpoint.target,
      serverNameAscii: endpoint.tls.serverNameAscii, spkiSha256Pins: endpoint.tls.spkiSha256Pins, tlsPolicyDigest: endpoint.tlsPolicyDigest };
  }).map(({ scheme: _scheme, redirectPolicy: _redirect, ...target }) => target);
  const trustStoreDigest = endpoints[0]?.tls.trustStoreDigest;
  if (!trustStoreDigest || endpoints.some(endpoint => endpoint.tls.trustStoreDigest !== trustStoreDigest ||
      endpoint.tls.trustStoreRef !== trustStoreDigest || endpoint.tls.trustStoreRuntimeBundleRef !== endpoints[0]!.tls.trustStoreRuntimeBundleRef ||
      endpoint.tls.trustStoreRuntimeBundleManifestDigest !== endpoints[0]!.tls.trustStoreRuntimeBundleManifestDigest))
    throw new TypeError('dependency transport requires one exact signed current CA byte root');
  const maxPackageBytes = Math.min(input.resources.maxSingleFileBytes, input.resources.maxInvocationOutputBytes, 67_108_864);
  if (!Number.isSafeInteger(maxPackageBytes) || maxPackageBytes < 1) throw new TypeError('dependency package has no bounded original data capacity');
  assertDependencyCacheManifestCapacity(input.packages, maxPackageBytes, plan.maxDownloadBytes);
  const configuration = { schemaVersion: 1, transport: 'public_integrity_get_v1', planDigest: canonicalSha256(plan),
    sandboxLaunchSpecRef: input.sandboxLaunchSpecRef, packageCount: plan.packageCount, packageDescriptorBytes: plan.packageDescriptorBytes,
    descriptorSequenceDigest: plan.descriptorSequenceDigest, maxPackageBytes, maxTransferBytes: plan.maxDownloadBytes,
    runRemainingMs: input.runRemainingMs, targets, trustStoreDigest };
  const configurationBytes = canonicalJsonBytes(configuration), pages = sequence.pages.map(page => canonicalJsonBytes(page));
  if (configurationBytes.length > 1_048_576) throw new TypeError('dependency configuration exceeds the original wire bound');
  let ownerStorageBytes = storage.fixedOwnerStorageBytes;
  for (const page of pages) ownerStorageBytes += page.length + storage.descriptorPageStorageBytes;
  // This is a size bound, never a published future GET observation. The real
  // native owner independently computes this reserve before any network I/O.
  for (const descriptor of input.packages) ownerStorageBytes += 4 + canonicalJsonBytes({ ...descriptor,
    blobBytes: maxPackageBytes, blobSha256: 'f'.repeat(64) }).length;
  if (!Number.isSafeInteger(ownerStorageBytes) || ownerStorageBytes > storage.maximumOwnerDataBytes)
    throw new TypeError('dependency complete native descriptor and metadata storage exceeds its fixed owned bound');
  return Object.freeze({ configurationBytes, pages: Object.freeze(pages), ownerStorageBytes, maxPackageBytes, trustStoreDigest });
}
