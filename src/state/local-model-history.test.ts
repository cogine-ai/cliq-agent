import assert from 'node:assert/strict';
import test from 'node:test';
import { addCanonicalDuration, digestOmitting } from '../kernel/identity.js';
import { decodeLocalInferenceBoundary, localStableServiceIdentity } from '../kernel/local-inference.js';
import type { LocalZeroCostProvenanceV1 } from '../model/pricing.js';
import { assertRetainedLocalAdmissionBoundary } from './local-model-history.js';
import { LOCAL_AT, localLaunchFixture, localRef, localRegistrationFixture } from './testing/local-inference-data.js';

test('historical local boundary covers admission while zero-cost provenance covers the Run', () => {
  const registration = localRegistrationFixture(), service = registration.serviceSpec;
  const serviceSpecRef = registration.expectedServiceSpecRef;
  const stableServiceIdentityDigest = localStableServiceIdentity({ service, serviceSpecRef });
  const launch = localLaunchFixture();
  const boundaryCore = {
    schemaVersion: 1, format: 'cliq-local-inference-boundary-v1', ownerPrincipalId: service.ownerPrincipalId,
    serviceId: service.serviceId, serviceSpecRef, serviceSpecDigest: service.serviceSpecDigest, serviceLaunchId: launch.launchId,
    runtimeBundleRef: service.runtimeBundleRef, runtimeBundleManifestDigest: service.runtimeBundleManifestDigest,
    executableId: service.executableId, executableDigest: service.executableDigest, modelManifestRef: service.modelManifestRef,
    modelManifestDigest: service.modelManifestDigest, processContainmentRef: localRef('containment'), containmentPlanRef: launch.containmentPlanRef,
    sandboxLaunchSpecRef: launch.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: localRef('launch digest'), backend: service.backend,
    externalNetworkEgress: 'denied', loopbackOnly: true, stableServiceIdentityDigest,
    inspectorSupervisorInstanceId: launch.supervisorInstanceId, inspectorIdentityRef: localRef('inspector'),
    inspectorIdentityDigest: localRef('inspector digest'), observedAt: LOCAL_AT, validThrough: addCanonicalDuration(LOCAL_AT, 5000), evidenceDigest: '',
  };
  const makeBoundary = (validThrough: string) => {
    const value = { ...boundaryCore, validThrough };
    return decodeLocalInferenceBoundary({ ...value, evidenceDigest: digestOmitting(value, 'evidenceDigest') });
  };
  const makeProvenance = (boundary: ReturnType<typeof makeBoundary>, createdAt: string): LocalZeroCostProvenanceV1 => {
    const value: LocalZeroCostProvenanceV1 = { schemaVersion: 1, format: 'cliq-local-zero-cost-v1', ownerPrincipalId: service.ownerPrincipalId,
      provider: 'ollama', model: registration.model, localModelRegistrationRef: localRef(registration),
      localModelRegistrationDigest: registration.registrationDigest, serviceSpecRef, serviceSpecDigest: service.serviceSpecDigest,
      stableServiceIdentityDigest, endpoint: service.endpoint, endpointIdentityDigest: localRef(service.endpoint),
      boundaryEvidenceRef: localRef(boundary), boundaryEvidenceDigest: boundary.evidenceDigest,
      capabilityEvidenceRef: localRef('capability'), capabilityDigest: localRef('capability digest'),
      createdAt, validThrough: addCanonicalDuration(LOCAL_AT, 300_000), provenanceDigest: '' };
    return { ...value, provenanceDigest: digestOmitting(value, 'provenanceDigest') };
  };
  const boundary = makeBoundary(boundaryCore.validThrough);
  const admittedAt = addCanonicalDuration(LOCAL_AT, 4999), provenance = makeProvenance(boundary, admittedAt);
  assert.doesNotThrow(() => assertRetainedLocalAdmissionBoundary(boundary, provenance, serviceSpecRef, admittedAt));
  for (const wrongTime of ['2026-10-31T23:59:59.999Z', boundary.validThrough])
    assert.throws(() => assertRetainedLocalAdmissionBoundary(boundary, makeProvenance(boundary, wrongTime), serviceSpecRef, wrongTime), TypeError);
  assert.throws(() => assertRetainedLocalAdmissionBoundary(boundary, provenance, serviceSpecRef, LOCAL_AT), TypeError);
  const extended = makeBoundary(addCanonicalDuration(LOCAL_AT, 300_000));
  assert.throws(() => assertRetainedLocalAdmissionBoundary(extended, makeProvenance(extended, admittedAt), serviceSpecRef, admittedAt), TypeError);
});
