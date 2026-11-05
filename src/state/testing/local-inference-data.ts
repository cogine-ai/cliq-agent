// Literal secret-free data only. No model, native holder, Store, process or
// release authority is created by these fixtures.
import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../../kernel/control-submit.js';
import { addCanonicalDuration, identityHash } from '../../kernel/identity.js';
import { localModelManifestDigest, localServiceSpecCoreDigest, localInferenceCycleId, localInferenceLaunchId,
  type LocalModelManifestV1, type LocalModelObjectClosureV1, type LocalInferenceServiceSpecV1,
  type LocalModelRegistrationV1, type LocalInferenceActivationCycleV1, type LocalInferenceServiceLaunchV1 } from '../../kernel/local-inference.js';

export const localRef = (value: unknown): string => canonicalSha256(value);
export const LOCAL_AT = '2026-11-01T00:00:00.000Z';
export function localManifestFixture(): LocalModelManifestV1 {
  const core = { schemaVersion: 1 as const, format: 'cliq-local-model-manifest-v1' as const,
    signerKeyId: 'local-model-test-publisher', signatureAlgorithm: 'ed25519' as const, signatureRef: localRef('signature-bytes'),
    provider: 'ollama' as const, model: 'literal-local-model', architecture: 'llama', tokenizerRef: localRef('tokenizer'), tokenizerDigest: localRef('tokenizer'),
    files: [{ canonicalRelativePath: 'blobs/model', contentRef: localRef('weight-bytes'), contentDigest: localRef('weight-bytes'), sizeBytes: 25 },
      { canonicalRelativePath: 'manifests/model.json', contentRef: localRef('engine-manifest'), contentDigest: localRef('engine-manifest'), sizeBytes: 13 }],
    claims: { nativeToolCalling: true, streaming: true, trustedUsageEvidence: true, contextLimitTokens: 32768, maxOutputTokens: 8192 } };
  return { ...core, modelManifestDigest: localModelManifestDigest(core) };
}
export function localClosureFixture(manifest = localManifestFixture()): LocalModelObjectClosureV1 {
  const objects: LocalModelObjectClosureV1['objects'] = [
    { kind: 'model_manifest', logicalPath: 'model-manifest.json', artifactRef: localRef(manifest), artifactDigest: localRef(manifest), sizeBytes: canonicalJsonBytes(manifest).length },
    { kind: 'model_signature', logicalPath: 'model-signature', artifactRef: manifest.signatureRef, artifactDigest: manifest.signatureRef, sizeBytes: 64 },
    { kind: 'tokenizer', logicalPath: 'tokenizer', artifactRef: manifest.tokenizerRef, artifactDigest: manifest.tokenizerDigest, sizeBytes: 11 },
    ...manifest.files.map(file => ({ kind: 'model_file' as const, logicalPath: file.canonicalRelativePath,
      artifactRef: file.contentRef, artifactDigest: file.contentDigest, sizeBytes: file.sizeBytes }))
  ];
  const core = { schemaVersion: 1 as const, format: 'cliq-local-model-object-closure-v1' as const,
    stateRootIdentityRef: localRef('root bytes'), stateRootIdentityDigest: localRef('root semantic'), objectStoreRootRelativePath: 'local-models/objects' as const,
    modelManifestRef: localRef(manifest), modelManifestDigest: manifest.modelManifestDigest, objects,
    objectCount: objects.length, totalBytes: objects.reduce((sum, entry) => sum + entry.sizeBytes, 0) };
  return { ...core, closureDigest: localRef(core) };
}
export function localServiceFixture(port = 49152, manifest = localManifestFixture()): LocalInferenceServiceSpecV1 {
  const core = { schemaVersion: 1 as const, format: 'cliq-local-inference-service-v1' as const, ownerPrincipalId: 'literal-principal',
    runtimeBundleRef: localRef('runtime'), runtimeBundleManifestDigest: localRef('runtime-semantic'), executableId: 'ollama_local_inference' as const,
    executableVersion: '1', executableDigest: localRef('bootstrap'), modelManifestRef: localRef(manifest), modelManifestDigest: manifest.modelManifestDigest,
    endpoint: { scheme: 'http' as const, host: '127.0.0.1' as const, port }, backend: 'linux_namespace' as const,
    sandboxProfileRef: localRef('profile'), sandboxProfileDigest: localRef('profile-semantic'), resources: DEFAULT_SANDBOX_RESOURCES };
  const serviceSpecCoreDigest = localServiceSpecCoreDigest(core), serviceId = identityHash(core.ownerPrincipalId, 'ollama', manifest.model, serviceSpecCoreDigest);
  const value = { ...core, serviceId, serviceSpecCoreDigest, createdAt: LOCAL_AT };
  return { ...value, serviceSpecDigest: localRef(value) };
}
export function localRegistrationFixture(port = 49152, revision = 1): LocalModelRegistrationV1 & { state: 'active' } {
  const modelManifest = localManifestFixture(), serviceSpec = localServiceFixture(port, modelManifest), objectClosure = localClosureFixture(modelManifest);
  const core = { schemaVersion: 1 as const, format: 'cliq-local-model-registration-v1' as const, ownerPrincipalId: serviceSpec.ownerPrincipalId,
    provider: 'ollama' as const, model: modelManifest.model, registryRevision: revision, serviceId: serviceSpec.serviceId,
    serviceSpec, expectedServiceSpecRef: localRef(serviceSpec), modelManifest, expectedModelManifestRef: localRef(modelManifest),
    objectClosure, expectedObjectClosureRef: localRef(objectClosure), createdAt: LOCAL_AT, state: 'active' as const };
  return { ...core, registrationDigest: localRef(core) };
}
export function localCycleFixture(): Extract<LocalInferenceActivationCycleV1, { phase: 'starting_launch' }> {
  const registration = localRegistrationFixture(), service = registration.serviceSpec, cycleOrdinal = 1;
  const activationCycleId = localInferenceCycleId({ ...service, cycleOrdinal });
  const currentLaunchId = localInferenceLaunchId(activationCycleId, 1);
  const core = { schemaVersion: 1 as const, activationCycleId, ownerPrincipalId: service.ownerPrincipalId,
    localModelRegistrationRef: localRef(registration), localModelRegistrationDigest: registration.registrationDigest,
    serviceId: service.serviceId, serviceSpecRef: localRef(service), serviceSpecDigest: service.serviceSpecDigest, cycleOrdinal,
    participants: [{ kind: 'run_submission' as const, requestId: '019a3c00-0000-7000-8000-000000000001', requestDigest: localRef('request'),
      runSubmitRequestRef: localRef('wire-request'), admissionKey: 'A'.repeat(43), admissionIntentDigest: localRef('admission'), joinedAt: LOCAL_AT }],
    rowVersion: 1, createdAt: LOCAL_AT, phase: 'starting_launch' as const, activationAttempt: 1 as const, launchIds: [currentLaunchId], currentLaunchId };
  return { ...core, cycleDigest: localRef(core) };
}
export function localLaunchFixture(): Extract<LocalInferenceServiceLaunchV1, { phase: 'reserved' }> {
  const cycle = localCycleFixture();
  return { schemaVersion: 1, serviceId: cycle.serviceId, launchId: cycle.currentLaunchId, ownerPrincipalId: cycle.ownerPrincipalId,
    serviceSpecRef: cycle.serviceSpecRef, serviceSpecDigest: cycle.serviceSpecDigest, supervisorInstanceId: 'literal-supervisor',
    activationCycleId: cycle.activationCycleId, activationAttempt: 1, activationNonceDigest: localRef('activation-nonce'),
    containmentPlanRef: localRef('plan'), sandboxLaunchSpecRef: localRef('sandbox-launch'), rowVersion: 1, leaseVersion: 0,
    createdAt: LOCAL_AT, activationDeadlineAt: addCanonicalDuration(LOCAL_AT, 120000), phase: 'reserved' };
}
