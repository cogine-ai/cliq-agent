// Original frozen local selection only. Current model-store heads are for new
// admission and never participate in this retained Run/claim reader.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { decodeLocalModelRegistration, decodeLocalInferenceBoundary, localStableServiceIdentity } from '../kernel/local-inference.js';
import type { RunAssemblyV1 } from '../kernel/types.js';
import { negotiateModelCapabilities, type ModelCapabilityEvidenceV1 } from '../model/capabilities.js';
import { decodeLocalZeroCostProvenanceData, type LocalZeroCostProvenanceV1 } from '../model/pricing.js';
import { verifyLocalModelManifestAuthority } from '../policy/local-model-authority.js';
import { requireEqual, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeStateRootIdentity } from './decoders.js';

async function readSignature(artifacts: ArtifactCatalog, ref: string): Promise<Buffer> {
  const pieces: Buffer[] = []; let total = 0;
  for await (const piece of artifacts.readChunks(ref, 64)) { total += piece.byteLength; if (total > 64) throw new TypeError('local detached signature exceeds its exact bound'); pieces.push(Buffer.from(piece)); }
  const bytes = Buffer.concat(pieces);
  if (total !== 64 || sha256Bytes(bytes) !== ref) throw new TypeError('local detached signature differs from its original complete bytes');
  return bytes;
}

/** Static cryptographic/source history, not a live model mount or no-egress
 * proof. The real local service independently owns/verifies every original
 * model descriptor before launch and guards it through each actual request. */
export async function readRetainedLocalModelRegistration(artifacts: ArtifactCatalog, input: Readonly<{
  provenance: LocalZeroCostProvenanceV1; principalId: string; assembly: RunAssemblyV1;
}>) {
  const provenance = decodeLocalZeroCostProvenanceData(input.provenance);
  const registration = decodeLocalModelRegistration(await readCanonicalArtifact(artifacts, provenance.localModelRegistrationRef));
  if (registration.state !== 'active' || registration.registrationDigest !== provenance.localModelRegistrationDigest ||
      canonicalSha256(registration) !== provenance.localModelRegistrationRef || registration.ownerPrincipalId !== input.principalId ||
      provenance.ownerPrincipalId !== input.principalId || registration.provider !== provenance.provider || registration.model !== provenance.model ||
      registration.createdAt > provenance.createdAt || registration.expectedServiceSpecRef !== provenance.serviceSpecRef ||
      registration.serviceSpec.serviceSpecDigest !== provenance.serviceSpecDigest ||
      localStableServiceIdentity({ service: registration.serviceSpec, serviceSpecRef: registration.expectedServiceSpecRef }) !== provenance.stableServiceIdentityDigest)
    throw new TypeError('local frozen registration does not match its original provenance/principal/model/service');
  const service = registration.serviceSpec, manifest = registration.modelManifest, closure = registration.objectClosure;
  requireEqual(await readCanonicalArtifact(artifacts, registration.expectedServiceSpecRef), service, 'original local service object and inline selection');
  requireEqual(await readCanonicalArtifact(artifacts, registration.expectedModelManifestRef), manifest, 'original local model object and inline signed selection');
  requireEqual(await readCanonicalArtifact(artifacts, registration.expectedObjectClosureRef), closure, 'original local object closure and inline selection');
  const root = decodeStateRootIdentity(await readCanonicalArtifact(artifacts, closure.stateRootIdentityRef));
  if (canonicalSha256(root) !== closure.stateRootIdentityRef || root.identityDigest !== closure.stateRootIdentityDigest)
    throw new TypeError('original local object closure changed its original complete StateRoot identity');
  if (service.runtimeBundleRef !== input.assembly.runtime.runtimeBundleRef || service.runtimeBundleManifestDigest !== input.assembly.runtime.runtimeBundleManifestDigest ||
      input.assembly.provider.name !== 'ollama' || input.assembly.provider.model !== registration.model)
    throw new TypeError('local frozen service/runtime/model differ from the retained Run assembly');
  const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, service.runtimeBundleRef);
  if (canonicalSha256(bundle) !== service.runtimeBundleRef || bundle.manifestDigest !== service.runtimeBundleManifestDigest)
    throw new TypeError('local original runtime object differs from the complete service selection');
  const signed = verifyLocalModelManifestAuthority({ bundle, releaseKeys: artifacts.releaseTrustRoots(),
    manifestBytes: canonicalJsonBytes(manifest), signatureBytes: await readSignature(artifacts, manifest.signatureRef) });
  requireEqual(signed, manifest, 'original local signed manifest');
  const bootstrap = bundle.entries.filter(entry => entry.entryId === service.executableId);
  if (bootstrap.length !== 1 || bootstrap[0]!.version !== service.executableVersion || bootstrap[0]!.digest !== service.executableDigest)
    throw new TypeError('local service substitutes its original signed bootstrap entry');
  requireEqual(service.endpoint, provenance.endpoint, 'original local endpoint');
  const capability = await readCanonicalArtifact<ModelCapabilityEvidenceV1>(artifacts, provenance.capabilityEvidenceRef);
  if (capability.evidenceDigest !== provenance.capabilityDigest) throw new TypeError('local capability changed its original semantic digest');
  const source = { kind: 'managed_local' as const, localInferenceServiceSpecRef: registration.expectedServiceSpecRef,
    localInferenceServiceSpecDigest: service.serviceSpecDigest, localModelManifestRef: registration.expectedModelManifestRef,
    localModelManifestDigest: manifest.modelManifestDigest };
  const negotiated = negotiateModelCapabilities({ provider: 'ollama', model: registration.model,
    endpointIdentityDigest: provenance.endpointIdentityDigest, adapter: input.assembly.provider.adapter,
    streamingRequested: input.assembly.provider.negotiation.streaming,
    admittedAt: provenance.createdAt, deadlineAt: provenance.validThrough, evidence: { ref: provenance.capabilityEvidenceRef, value: capability },
    resolveVerifiedSourceClaims(candidate) { return canonicalSha256(candidate) === canonicalSha256(source) ? manifest.claims : null; } });
  if (!negotiated.ok) throw new TypeError('local capability lacks its original signed model claims and complete provenance validity');
  const selected = input.assembly.provider.negotiation;
  for (const key of ['mode', 'nativeToolCalling', 'streaming', 'trustedUsageEvidence', 'contextLimitTokens', 'maxOutputTokens'] as const)
    if (selected[key] !== negotiated.negotiation[key]) throw new TypeError('local capability differs from the frozen Run negotiation');
  const boundary = decodeLocalInferenceBoundary(await readCanonicalArtifact(artifacts, provenance.boundaryEvidenceRef));
  if (canonicalSha256(boundary) !== provenance.boundaryEvidenceRef || boundary.evidenceDigest !== provenance.boundaryEvidenceDigest ||
      boundary.stableServiceIdentityDigest !== provenance.stableServiceIdentityDigest || boundary.serviceSpecRef !== registration.expectedServiceSpecRef ||
      boundary.observedAt > provenance.createdAt || boundary.validThrough < provenance.validThrough)
    throw new TypeError('local original admission boundary differs from its complete stable source/lifetime');
  return { provenance, registration, service, manifest, closure, bundle, capability, boundary };
}
