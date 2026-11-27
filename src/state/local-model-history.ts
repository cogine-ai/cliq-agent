// Original frozen local selection only. Current model-store heads are for new
// admission and never participate in this retained Run/claim reader.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { addCanonicalDuration, sha256Bytes } from '../kernel/identity.js';
import { decodeLocalModelRegistration, decodeLocalInferenceBoundary, localStableServiceIdentity,
  type LocalInferenceBoundaryEvidenceV1 } from '../kernel/local-inference.js';
import type { RunAssemblyV1 } from '../kernel/types.js';
import { negotiateModelCapabilities, type ModelCapabilityEvidenceV1 } from '../model/capabilities.js';
import { decodeLocalZeroCostProvenanceData, type LocalZeroCostProvenanceV1 } from '../model/pricing.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { verifyLocalModelManifestAuthority } from '../policy/local-model-authority.js';
import { requireEqual, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeStateRootIdentity } from './decoders.js';
import type { ChildAdmissionData } from './child-admission.js';

async function readSignature(artifacts: ArtifactCatalog, ref: string): Promise<Buffer> {
  const pieces: Buffer[] = []; let total = 0;
  for await (const piece of artifacts.readChunks(ref, 64)) { total += piece.byteLength; if (total > 64) throw new TypeError('local detached signature exceeds its exact bound'); pieces.push(Buffer.from(piece)); }
  const bytes = Buffer.concat(pieces);
  if (total !== 64 || sha256Bytes(bytes) !== ref) throw new TypeError('local detached signature differs from its original complete bytes');
  return bytes;
}

/** Admission-time physical evidence remains historical for the Run lifetime.
 * Model dispatch separately requires a fresh observation of its live service. */
export function assertRetainedLocalAdmissionBoundary(boundary: LocalInferenceBoundaryEvidenceV1, provenance: LocalZeroCostProvenanceV1,
  serviceSpecRef: string, admittedAt: string): void {
  if (canonicalSha256(boundary) !== provenance.boundaryEvidenceRef || boundary.evidenceDigest !== provenance.boundaryEvidenceDigest ||
      boundary.stableServiceIdentityDigest !== provenance.stableServiceIdentityDigest || boundary.serviceSpecRef !== serviceSpecRef ||
      boundary.serviceSpecRef !== provenance.serviceSpecRef || boundary.serviceSpecDigest !== provenance.serviceSpecDigest ||
      provenance.createdAt !== admittedAt || boundary.validThrough !== addCanonicalDuration(boundary.observedAt, 5000) ||
      boundary.observedAt > admittedAt || admittedAt >= boundary.validThrough)
    throw new TypeError('local original admission boundary differs from its complete stable source or fresh admission cut');
}

/** Children narrow the original assembly and keep its exact model authority.
 * Their new creation time cannot replace the root's physical admission cut. */
export async function readInheritedLocalModelAdmissionAssembly(artifacts: ArtifactCatalog, assembly: RunAssemblyV1,
  child: ChildAdmissionData): Promise<RunAssemblyV1> {
  const { rootOrigin } = child;
  const original = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, rootOrigin.spec.assemblyRef));
  if (canonicalSha256(assembly) !== child.spec.assemblyRef || original.provider.endpoint.kind !== 'local_zero_cost' ||
      original.createdAt !== rootOrigin.run.createdAt || rootOrigin.run.deadlineAt < child.run.deadlineAt)
    throw new TypeError('child model authority has no complete original root admission');
  requireEqual(assembly.provider, original.provider, 'child exact original local model authority');
  return original;
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
  if (provenance.createdAt > input.assembly.createdAt) throw new TypeError('local provenance follows its retaining Run assembly');
  assertRetainedLocalAdmissionBoundary(boundary, provenance, registration.expectedServiceSpecRef, provenance.createdAt);
  return { provenance, registration, service, manifest, closure, bundle, capability, boundary };
}
