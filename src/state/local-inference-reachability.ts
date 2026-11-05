// Closed semantic edges, selected by a production parent. A kind label or
// hash-looking JSON property never selects a decoder or deletion permission.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { decodeLocalModelManifest, decodeLocalModelObjectClosure, decodeLocalModelRegistration, decodeLocalModelRegistryHead,
  decodeLocalInferenceServiceSpec, decodeLocalInferenceCycle, decodeLocalInferenceLaunch, decodeLocalInferenceFailure, decodeLocalInferenceBoundary,
  type LocalModelRegistrationV1, type LocalInferenceActivationCycleV1 } from '../kernel/local-inference.js';
import { decodeLocalZeroCostProvenanceData } from '../model/pricing.js';
import { verifyLocalModelManifestAuthority } from '../policy/local-model-authority.js';
import type { ReleaseTrustKey, RuntimeBundleManifest } from '../policy/runtime-authority.js';
import type { CoreRetentionArtifactPurpose } from '../kernel/retention-purpose.js';
import { assertLocalModelRetiredCopy } from './local-model-registry-data.js';

export const LOCAL_INFERENCE_RETENTION_PURPOSES = [
  'local_model_manifest', 'local_model_signature', 'local_model_object_closure', 'local_model_registration', 'local_model_registry_head',
  'local_inference_service_spec', 'local_inference_activation_cycle', 'local_inference_service_launch', 'local_inference_activation_failure',
  'local_inference_boundary', 'local_zero_cost_provenance'
] as const;
export type LocalInferenceRetentionPurpose = typeof LOCAL_INFERENCE_RETENTION_PURPOSES[number];
export type LocalInferenceRetentionEdge = Readonly<{ ref: string; purpose: LocalInferenceRetentionPurpose | CoreRetentionArtifactPurpose |
  'state_root_identity' | 'sandbox_profile' | 'model_capability_evidence' | 'run_submit_request' }>;
export type LocalInferenceRetentionContext = Readonly<{
  registration: LocalModelRegistrationV1;
  bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[]; signatureBytes: Buffer;
  cycle?: LocalInferenceActivationCycleV1;
  originalActiveRegistration?: LocalModelRegistrationV1 & { state: 'active' };
}>;
export class UnsupportedLocalInferenceReachability extends TypeError {
  constructor() { super('local inference retention requires its exact original model/cycle context'); }
}
function unsupported(): never { throw new UnsupportedLocalInferenceReachability(); }
/** Original signed source context is mandatory even for the same-looking
 * manifest reached through another parent. A caller cannot substitute today's
 * registry head for the exact original registration/closure/cycle. */
export function readLocalInferenceEdges(purpose: LocalInferenceRetentionPurpose, value: unknown,
  context?: LocalInferenceRetentionContext): readonly LocalInferenceRetentionEdge[] {
  if (!context) unsupported();
  const registration = decodeLocalModelRegistration(context.registration), manifest = registration.modelManifest, service = registration.serviceSpec;
  if (canonicalSha256(context.bundle) !== service.runtimeBundleRef ||
      context.bundle.manifestDigest !== service.runtimeBundleManifestDigest) unsupported();
  const signed = verifyLocalModelManifestAuthority({ bundle: context.bundle, releaseKeys: context.releaseKeys,
    manifestBytes: canonicalJsonBytes(manifest), signatureBytes: context.signatureBytes });
  if (canonicalSha256(signed) !== registration.expectedModelManifestRef) unsupported();
  const edge = (ref: string, purpose: LocalInferenceRetentionEdge['purpose']): LocalInferenceRetentionEdge => ({ ref, purpose });
  if (purpose === 'local_model_registration') {
    const record = decodeLocalModelRegistration(value);
    if (canonicalSha256(record) !== canonicalSha256(registration)) unsupported();
    if (record.state === 'retired') {
      if (!context.originalActiveRegistration) unsupported();
      const original = decodeLocalModelRegistration(context.originalActiveRegistration);
      if (original.state !== 'active') unsupported();
      assertLocalModelRetiredCopy(original, record, record.retiredAt);
    }
    return [edge(record.expectedServiceSpecRef, 'local_inference_service_spec'), edge(record.expectedModelManifestRef, 'local_model_manifest'),
      edge(record.expectedObjectClosureRef, 'local_model_object_closure')];
  }
  if (purpose === 'local_model_manifest') {
    const record = decodeLocalModelManifest(value);
    if (canonicalSha256(record) !== registration.expectedModelManifestRef) unsupported();
    return [edge(record.signatureRef, 'local_model_signature'), edge(record.tokenizerRef, 'opaque_blob'), ...record.files.map(file => edge(file.contentRef, 'opaque_blob'))];
  }
  if (purpose === 'local_model_signature') {
    if (!Buffer.isBuffer(value) || value.byteLength !== 64 || !value.equals(context.signatureBytes) || sha256Bytes(value) !== manifest.signatureRef) unsupported();
    return [];
  }
  if (purpose === 'local_model_object_closure') {
    const record = decodeLocalModelObjectClosure(value, manifest);
    if (canonicalSha256(record) !== registration.expectedObjectClosureRef) unsupported();
    return [edge(record.stateRootIdentityRef, 'state_root_identity'), ...record.objects.map(object => edge(object.artifactRef,
      object.kind === 'model_manifest' ? 'local_model_manifest' : object.kind === 'model_signature' ? 'local_model_signature' : 'opaque_blob'))];
  }
  if (purpose === 'local_model_registry_head') {
    const record = decodeLocalModelRegistryHead(value), result: LocalInferenceRetentionEdge[] = [];
    if (record.ownerPrincipalId !== registration.ownerPrincipalId || record.provider !== registration.provider || record.model !== registration.model) unsupported();
    if ('predecessorHeadRef' in record) result.push(edge(record.predecessorHeadRef, 'local_model_registry_head'));
    if ('activeRegistrationRef' in record) result.push(edge(record.activeRegistrationRef, 'local_model_registration'));
    if ('retiredRegistrationRef' in record) result.push(edge(record.retiredRegistrationRef, 'local_model_registration'));
    return result;
  }
  if (purpose === 'local_inference_service_spec') {
    const record = decodeLocalInferenceServiceSpec(value);
    if (canonicalSha256(record) !== registration.expectedServiceSpecRef) unsupported();
    return [edge(record.runtimeBundleRef, 'runtime_bundle'), edge(record.modelManifestRef, 'local_model_manifest'), edge(record.sandboxProfileRef, 'sandbox_profile')];
  }
  if (purpose === 'local_inference_activation_cycle') {
    const record = decodeLocalInferenceCycle(value);
    if (registration.state !== 'active' || record.localModelRegistrationRef !== canonicalSha256(registration) || record.localModelRegistrationDigest !== registration.registrationDigest ||
        record.serviceSpecRef !== registration.expectedServiceSpecRef || record.serviceSpecDigest !== service.serviceSpecDigest ||
        record.ownerPrincipalId !== registration.ownerPrincipalId || record.serviceId !== registration.serviceId) unsupported();
    const result = [edge(record.localModelRegistrationRef, 'local_model_registration'), edge(record.serviceSpecRef, 'local_inference_service_spec'),
      ...record.participants.map(participant => participant.kind === 'run_submission'
        ? edge(participant.runSubmitRequestRef, 'run_submit_request') : edge(participant.frontierRef, 'run_frontier'))];
    if (record.phase === 'active') result.push(edge(record.boundaryEvidenceRef, 'local_inference_boundary'));
    if (record.phase === 'failed') result.push(edge(record.failureDetailRef, 'local_inference_activation_failure'));
    return result;
  }
  if (purpose === 'local_inference_service_launch') {
    const record = decodeLocalInferenceLaunch(value), cycle = context.cycle && decodeLocalInferenceCycle(context.cycle);
    if (!cycle || record.activationCycleId !== cycle.activationCycleId || record.serviceSpecRef !== cycle.serviceSpecRef ||
        record.serviceSpecDigest !== cycle.serviceSpecDigest || record.serviceId !== cycle.serviceId || record.ownerPrincipalId !== cycle.ownerPrincipalId ||
        cycle.launchIds[record.activationAttempt - 1] !== record.launchId || cycle.localModelRegistrationRef !== canonicalSha256(registration) ||
        cycle.localModelRegistrationDigest !== registration.registrationDigest) unsupported();
    const result = [edge(record.serviceSpecRef, 'local_inference_service_spec'), edge(record.containmentPlanRef, 'process_containment_plan'),
      edge(record.sandboxLaunchSpecRef, 'sandbox_launch_spec')];
    if ('processContainmentRef' in record) result.push(edge(record.processContainmentRef, 'process_containment'));
    if ('boundaryEvidenceRef' in record && record.boundaryEvidenceRef) result.push(edge(record.boundaryEvidenceRef, 'local_inference_boundary'));
    if (record.phase === 'retired') result.push(edge(record.retirementEvidenceRef, record.retirementKind === 'no_spawn' ? 'process_containment_no_spawn' : 'process_containment_death'));
    return result;
  }
  if (purpose === 'local_inference_activation_failure') {
    const record = decodeLocalInferenceFailure(value), cycle = context.cycle && decodeLocalInferenceCycle(context.cycle);
    if (!cycle || cycle.phase !== 'failed' || record.activationCycleId !== cycle.activationCycleId || record.serviceId !== cycle.serviceId ||
        record.ownerPrincipalId !== cycle.ownerPrincipalId || record.serviceSpecRef !== cycle.serviceSpecRef || record.serviceSpecDigest !== cycle.serviceSpecDigest ||
        cycle.failureDetailRef !== canonicalSha256(record)) unsupported();
    // Failure evidenceRefs have branch-specific native meanings. Without the
    // owning completed lifecycle reader these edges cannot be guessed.
    unsupported();
  }
  if (purpose === 'local_inference_boundary') {
    const record = decodeLocalInferenceBoundary(value);
    if (record.serviceSpecRef !== registration.expectedServiceSpecRef || record.serviceSpecDigest !== service.serviceSpecDigest ||
        record.ownerPrincipalId !== registration.ownerPrincipalId || record.serviceId !== registration.serviceId) unsupported();
    return [edge(record.serviceSpecRef, 'local_inference_service_spec'), edge(record.runtimeBundleRef, 'runtime_bundle'),
      edge(record.modelManifestRef, 'local_model_manifest'), edge(record.processContainmentRef, 'process_containment'),
      edge(record.containmentPlanRef, 'process_containment_plan'), edge(record.sandboxLaunchSpecRef, 'sandbox_launch_spec'),
      edge(record.inspectorIdentityRef, 'supervisor_inspector')];
  }
  if (purpose === 'local_zero_cost_provenance') {
    const record = decodeLocalZeroCostProvenanceData(value);
    if (registration.state !== 'active' || record.localModelRegistrationRef !== canonicalSha256(registration) || record.localModelRegistrationDigest !== registration.registrationDigest ||
        record.serviceSpecRef !== registration.expectedServiceSpecRef || record.serviceSpecDigest !== service.serviceSpecDigest ||
        record.ownerPrincipalId !== registration.ownerPrincipalId || record.model !== registration.model) unsupported();
    return [edge(record.localModelRegistrationRef, 'local_model_registration'), edge(record.serviceSpecRef, 'local_inference_service_spec'),
      edge(record.boundaryEvidenceRef, 'local_inference_boundary'), edge(record.capabilityEvidenceRef, 'model_capability_evidence')];
  }
  return unsupported();
}
