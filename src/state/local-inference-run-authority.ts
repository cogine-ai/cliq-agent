import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import { decodeLocalInferenceBoundary, decodeLocalInferenceServiceSpec, decodeLocalModelManifest,
  decodeLocalModelObjectClosure, decodeLocalModelRegistration, localStableServiceIdentity, type LocalModelRegistrationV1,
  type LocalInferenceBoundaryEvidenceV1 } from '../kernel/local-inference.js';
import type { RunAssemblyV1, SupervisorInspectorIdentityV1 } from '../kernel/types.js';
import type { ModelCapabilityEvidenceV1 } from '../model/capabilities.js';
import { decodeLocalZeroCostProvenanceData, type LocalZeroCostProvenanceV1 } from '../model/pricing.js';
import { requireEqual, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import type { InstalledRuntimeBorrow } from './installed-runtime.js';
import { readRetainedLocalInferenceLaunch } from './local-inference-launch.js';
import { readLocalInferenceCycle, readLocalInferenceLaunch } from './local-inference-rows.js';
import { assertRetainedLocalAdmissionBoundary } from './local-model-history.js';
import { readInstalledLocalInferenceObservation, type InstalledLocalInferenceObservation } from './local-inference-service.js';
import { MODEL_BROKER_ENTRY_ID, MODEL_BROKER_RELATIVE_PATH } from './model-broker-native.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { readSupervisorInspector } from './supervisor-inspector.js';

function mismatch(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }
function localAdapter(bundle: RuntimeBundleManifest) {
  const entry = bundle.entries.find(value => value.entryId === MODEL_BROKER_ENTRY_ID);
  if (!entry || entry.role !== 'provider_adapter' || !entry.executable || entry.version !== '1' || entry.relativePath !== MODEL_BROKER_RELATIVE_PATH)
    mismatch('managed model lacks the exact original signed provider broker');
  return { adapterId: entry.entryId, version: entry.version, codeDigest: entry.digest };
}
function localCapability(bundle: RuntimeBundleManifest, registration: LocalModelRegistrationV1,
  observedAt: string, validThrough: string): ModelCapabilityEvidenceV1 {
  const model = registration.modelManifest, service = registration.serviceSpec;
  const capability: ModelCapabilityEvidenceV1 = { schemaVersion: 1, format: 'cliq-model-capability-evidence-v1',
    provider: 'ollama', model: registration.model, endpointIdentityDigest: canonicalSha256(service.endpoint), adapter: localAdapter(bundle),
    source: { kind: 'managed_local', localInferenceServiceSpecRef: registration.expectedServiceSpecRef, localInferenceServiceSpecDigest: service.serviceSpecDigest,
      localModelManifestRef: registration.expectedModelManifestRef, localModelManifestDigest: model.modelManifestDigest },
    ...model.claims, observedAt, validThrough, evidenceDigest: '' };
  capability.evidenceDigest = digestOmitting(capability, 'evidenceDigest'); return capability;
}
function localProvenance(registration: LocalModelRegistrationV1, boundary: LocalInferenceBoundaryEvidenceV1,
  capability: ModelCapabilityEvidenceV1, admittedAt: string, deadlineAt: string): LocalZeroCostProvenanceV1 {
  const service = registration.serviceSpec;
  const source: LocalZeroCostProvenanceV1 = { schemaVersion: 1, format: 'cliq-local-zero-cost-v1', ownerPrincipalId: registration.ownerPrincipalId,
    provider: 'ollama', model: registration.model, localModelRegistrationRef: canonicalSha256(registration), localModelRegistrationDigest: registration.registrationDigest,
    serviceSpecRef: registration.expectedServiceSpecRef, serviceSpecDigest: service.serviceSpecDigest,
    stableServiceIdentityDigest: localStableServiceIdentity({ service, serviceSpecRef: registration.expectedServiceSpecRef }),
    endpoint: service.endpoint, endpointIdentityDigest: canonicalSha256(service.endpoint), boundaryEvidenceRef: canonicalSha256(boundary),
    boundaryEvidenceDigest: boundary.evidenceDigest, capabilityEvidenceRef: canonicalSha256(capability), capabilityDigest: capability.evidenceDigest,
    createdAt: admittedAt, validThrough: deadlineAt, provenanceDigest: '' };
  source.provenanceDigest = digestOmitting(source, 'provenanceDigest');
  return decodeLocalZeroCostProvenanceData(source);
}
function localProvider(registration: LocalModelRegistrationV1, capability: ModelCapabilityEvidenceV1, provenance: LocalZeroCostProvenanceV1):
  Pick<RunAssemblyV1['provider'], 'name' | 'model' | 'endpoint' | 'credentialGrantRefs' | 'adapter' | 'pricing'> {
  const ref = canonicalSha256(provenance);
  return { name: 'ollama', model: registration.model, endpoint: { kind: 'local_zero_cost', identityDigest: provenance.endpointIdentityDigest, localProvenanceRef: ref },
    credentialGrantRefs: [], adapter: capability.adapter, pricing: { kind: 'zero_cost', maxRunCostMicros: 0, provenanceRef: ref } };
}

export async function publishInstalledLocalRunModel(artifacts: ArtifactCatalog, installed: InstalledRuntimeBorrow, driver: SqliteDriver,
  owner: StateOwnerContext, observation: InstalledLocalInferenceObservation, principalId: string, model: string, admittedAt: string, deadlineAt: string) {
  const { registration, launch } = readInstalledLocalInferenceObservation(observation, driver, owner);
  const { boundary } = observation.boundary;
  if (registration.ownerPrincipalId !== principalId || registration.model !== model || registration.serviceSpec.runtimeBundleRef !== installed.bundleDigest ||
      boundary.serviceLaunchId !== launch.launchId || boundary.observedAt > admittedAt || admittedAt >= boundary.validThrough)
    mismatch('local Run model does not belong to its exact current service and principal');
  const capability = localCapability(installed.bundle, registration, boundary.observedAt, deadlineAt);
  const provenance = localProvenance(registration, boundary, capability, admittedAt, deadlineAt);
  const [capabilityArtifact, provenanceArtifact] = await artifacts.publishCanonicalPair([
    { value: capability, schemaKind: capability.format }, { value: provenance, schemaKind: provenance.format },
  ]);
  observation.assertCurrent();
  return { provider: localProvider(registration, capability, provenance), capability, capabilityArtifact, provenanceArtifact,
    claims: registration.modelManifest.claims };
}

/** Audit the frozen registration and current-row history named by the
 * admission proof. A current registry head is never consulted here. */
export async function readInstalledLocalRunModel(artifacts: ArtifactCatalog, installed: Pick<InstalledRuntimeBorrow, 'bundle' | 'bundleDigest'>, driver: SqliteDriver,
  assembly: RunAssemblyV1) {
  const endpoint = assembly.provider.endpoint;
  if (endpoint.kind !== 'local_zero_cost' || assembly.provider.name !== 'ollama' || assembly.provider.pricing.kind !== 'zero_cost' ||
      assembly.provider.credentialGrantRefs.length || assembly.provider.pricing.provenanceRef !== endpoint.localProvenanceRef)
    mismatch('installed local Run model has a credential, price or endpoint substitution');
  const provenance = decodeLocalZeroCostProvenanceData(await readCanonicalArtifact(artifacts, endpoint.localProvenanceRef));
  if (assembly.provider.negotiation.capabilityEvidenceRef !== provenance.capabilityEvidenceRef ||
      assembly.provider.negotiation.capabilityDigest !== provenance.capabilityDigest)
    mismatch('installed local Run capability and zero-cost provenance differ');
  const registration = decodeLocalModelRegistration(await readCanonicalArtifact(artifacts, provenance.localModelRegistrationRef));
  if (registration.state !== 'active' || registration.serviceSpec.runtimeBundleRef !== installed.bundleDigest ||
      registration.serviceSpec.runtimeBundleManifestDigest !== installed.bundle.manifestDigest)
    mismatch('installed local Run model lacks its exact original active signed registration');
  const service = registration.serviceSpec, manifest = registration.modelManifest;
  requireEqual(decodeLocalInferenceServiceSpec(await readCanonicalArtifact(artifacts, registration.expectedServiceSpecRef)), service, 'original local Run service');
  requireEqual(decodeLocalModelManifest(await readCanonicalArtifact(artifacts, registration.expectedModelManifestRef)), manifest, 'original local Run manifest');
  requireEqual(decodeLocalModelObjectClosure(await readCanonicalArtifact(artifacts, registration.expectedObjectClosureRef), manifest),
    registration.objectClosure, 'original local Run model object closure');
  const boundary = decodeLocalInferenceBoundary(await readCanonicalArtifact(artifacts, provenance.boundaryEvidenceRef));
  assertRetainedLocalAdmissionBoundary(boundary, provenance, registration.expectedServiceSpecRef, assembly.createdAt);
  const launch = readLocalInferenceLaunch(driver, boundary.serviceLaunchId);
  const cycle = launch && readLocalInferenceCycle(driver, launch.activationCycleId);
  if (!launch || !cycle || launch.phase === 'reserved' || launch.phase === 'preactivated' ||
      !('processContainmentRef' in launch) || !launch.boundaryEvidenceRef ||
      launch.processContainmentRef !== boundary.processContainmentRef || launch.containmentPlanRef !== boundary.containmentPlanRef ||
      launch.sandboxLaunchSpecRef !== boundary.sandboxLaunchSpecRef || launch.supervisorInstanceId !== boundary.inspectorSupervisorInstanceId ||
      boundary.observedAt < launch.createdAt)
    mismatch('local Run model audit boundary differs from its original verified service launch');
  const recipe = await readRetainedLocalInferenceLaunch(artifacts, launch, cycle, registration, installed.bundle);
  if (recipe.spec.launchSpecDigest !== boundary.sandboxLaunchSpecDigest) mismatch('original local Run launch recipe digest changed');
  const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, boundary.inspectorIdentityRef);
  const history = await readRetainedStateOwnerHistory(driver, artifacts, inspector.stateOwnerEpoch);
  const original = history.entries.at(-1);
  if (!original || original.owner.ownerEpoch !== recipe.original.data.binding.stateOwnerEpoch ||
      original.owner.state === 'terminal' && original.owner.releasedAt <= boundary.observedAt)
    mismatch('local Run audit inspector is outside its exact original StateOwner lifetime');
  await readSupervisorInspector(artifacts, original.owner, assembly, boundary);
  const capability = localCapability(installed.bundle, registration, boundary.observedAt, provenance.validThrough);
  requireEqual(await readCanonicalArtifact(artifacts, provenance.capabilityEvidenceRef), capability, 'original signed local model capabilities');
  parseCanonicalTime(provenance.validThrough);
  requireEqual(provenance, localProvenance(registration, boundary, capability, assembly.createdAt, provenance.validThrough),
    'original local Run zero-cost provenance');
  const provider = localProvider(registration, capability, provenance);
  const { negotiation: _negotiation, ...retained } = assembly.provider;
  requireEqual(retained, provider, 'original local Run provider, adapter and zero-cost bound');
  history.assertUnchanged(driver);
  return { registration, capability, provenance: { ref: endpoint.localProvenanceRef, value: provenance } };
}
