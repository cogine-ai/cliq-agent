import { canonicalSha256 } from '../../kernel/canonical.js';
import type { RunAssemblyV1 } from '../../kernel/types.js';
import { immutableSnapshot } from '../../model/immutable.js';
import type { RunAssemblyToolAuthority, RunAssemblyValidationMaterial } from '../../model/run-assembly.js';
import { testFixture } from '../../model/testing/fixtures.js';

export type OfflineWorkerCampaignMaterialData = Omit<RunAssemblyValidationMaterial,
  'resolveVerifiedCapabilityClaims' | 'verifyLocalZeroCostAuthority' | 'resolvePriceTableAuthority' |
  'resolveVerifiedTools' | 'verifyReference' | 'verifyProviderAdapter' | 'verifyProviderEndpoint'>;

/** Reconstruct only the existing offline model prefix after IPC serialization.
 * This data verifier creates no native, credential, provider or execution authority. */
export function restoreOfflineWorkerCampaignMaterial(input: {
  materialData: OfflineWorkerCampaignMaterialData;
  assembly: Pick<RunAssemblyV1, 'provider' | 'tools'>;
  tools: RunAssemblyToolAuthority[];
}): RunAssemblyValidationMaterial {
  const captured = immutableSnapshot(input), { provider } = captured.assembly;
  return { ...testFixture().material, ...captured.materialData,
    verifyProviderEndpoint: candidate => candidate.provider === provider.name && candidate.model === provider.model &&
      canonicalSha256(candidate.endpoint) === canonicalSha256(provider.endpoint) &&
      canonicalSha256(candidate.credentialGrantRefs) === canonicalSha256(provider.credentialGrantRefs) &&
      canonicalSha256(candidate.capabilitySource) === canonicalSha256(captured.materialData.capabilityEvidence.value.source),
    resolveVerifiedTools: reference => canonicalSha256(reference) === canonicalSha256(captured.assembly.tools) ? captured.tools : null };
}
