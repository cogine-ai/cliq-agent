import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { addCanonicalDuration, identityHash } from './identity.js';
import { decodeLocalIdentity, decodeLocalModelPath, decodeLocalModelManifest, localModelManifestDigest,
  decodeLocalModelObjectClosure, decodeLocalInferenceServiceSpec, decodeLocalModelRegistration,
  decodeLocalInferenceCycle, decodeLocalInferenceLaunch, decodeLocalInferenceBoundary, localStableServiceIdentity,
  localInferenceCycleId, localInferenceLaunchId } from './local-inference.js';
import { LOCAL_AT, localRef, localManifestFixture, localClosureFixture, localServiceFixture,
  localRegistrationFixture, localCycleFixture, localLaunchFixture } from '../state/testing/local-inference-data.js';

test('managed model manifest and complete signature/tokenizer/weights closure retain exact domains and reject omissions', () => {
  const manifest = localManifestFixture(), closure = localClosureFixture(manifest);
  assert.deepEqual(decodeLocalModelManifest(manifest), manifest);
  assert.deepEqual(decodeLocalModelObjectClosure(closure, manifest), closure);
  assert.equal(Object.isFrozen(decodeLocalModelObjectClosure(closure, manifest).objects), true);
  const signChanged = { ...manifest, signatureRef: localRef('other detached signature') };
  assert.equal(localModelManifestDigest(signChanged), manifest.modelManifestDigest, 'signature ref is outside its own signed digest');
  assert.notEqual(canonicalSha256(signChanged), canonicalSha256(manifest), 'complete manifest bytes still include detached signature ref');
  for (const change of [
    { ...closure, objects: closure.objects.filter(entry => entry.kind !== 'model_signature'), objectCount: closure.objectCount - 1 },
    { ...closure, objects: [...closure.objects].reverse() },
    { ...closure, objects: [...closure.objects, closure.objects[2]], objectCount: closure.objectCount + 1 },
    { ...closure, totalBytes: closure.totalBytes + 1 },
    { ...closure, objectStoreRootRelativePath: '/caller/cache' },
    { ...closure, objects: closure.objects.map(entry => entry.kind === 'model_signature' ? { ...entry, sizeBytes: 63 } : entry) }
  ]) assert.throws(() => decodeLocalModelObjectClosure(change, manifest));
});

test('managed model closed claims and files reject unsafe identities even after semantic rehash', () => {
  const manifest = localManifestFixture();
  for (const change of [
    { ...manifest, provider: 'openai' }, { ...manifest, permission: true }, { ...manifest, tokenizerDigest: localRef('wrong-tokenizer') },
    { ...manifest, claims: { ...manifest.claims, contextLimitTokens: 32767 } },
    { ...manifest, claims: { ...manifest.claims, maxOutputTokens: 8193 } },
    { ...manifest, files: [...manifest.files].reverse() },
    { ...manifest, files: manifest.files.map(file => ({ ...file, canonicalRelativePath: '../outside' })) },
    { ...manifest, files: [...manifest.files, { ...manifest.files[0]!, canonicalRelativePath: 'zzz' }] }
  ]) assert.throws(() => decodeLocalModelManifest({ ...change, modelManifestDigest: localModelManifestDigest(change as typeof manifest) }));
  // The lexical neighbour is not necessarily the parent: '-' sorts before '/'.
  const prefix = { ...manifest, files: ['a', 'a-b', 'a/x'].map((path, index) => ({ canonicalRelativePath: path,
    contentRef: localRef(index), contentDigest: localRef(index), sizeBytes: 1 })) };
  assert.throws(() => decodeLocalModelManifest({ ...prefix, modelManifestDigest: localModelManifestDigest(prefix) }));
  for (const path of ['/host/path', 'a/../b', 'a//b', 'a\\b', '.', 'a/', 'a/./b']) assert.throws(() => decodeLocalModelPath(path));
});

test('service semantic identity includes endpoint/runtime/model/resources but excludes creation time and dynamic launch evidence', () => {
  const service = localServiceFixture(), registration = localRegistrationFixture();
  assert.deepEqual(decodeLocalInferenceServiceSpec(service), service); assert.deepEqual(decodeLocalModelRegistration(registration), registration);
  const different = localServiceFixture(49153);
  assert.notEqual(service.serviceSpecCoreDigest, different.serviceSpecCoreDigest); assert.notEqual(service.serviceId, different.serviceId);
  const { serviceSpecDigest: _digest, ...retimed } = { ...service, createdAt: addCanonicalDuration(LOCAL_AT, 1000) };
  assert.equal(decodeLocalInferenceServiceSpec({ ...retimed, serviceSpecDigest: canonicalSha256(retimed) }).serviceSpecCoreDigest, service.serviceSpecCoreDigest);
  for (const change of [{ ...registration, serviceId: different.serviceId }, { ...registration, expectedObjectClosureRef: localRef('other closure') },
    { ...registration, state: 'retired', retiredAt: '2026-10-31T23:59:59.999Z' }])
    assert.throws(() => decodeLocalModelRegistration(change));
  const stable = localStableServiceIdentity({ service, serviceSpecRef: canonicalSha256(service) });
  const core = { schemaVersion: 1 as const, format: 'cliq-local-inference-boundary-v1' as const,
    ownerPrincipalId: service.ownerPrincipalId, serviceId: service.serviceId, serviceSpecRef: canonicalSha256(service), serviceSpecDigest: service.serviceSpecDigest,
    serviceLaunchId: localLaunchFixture().launchId, runtimeBundleRef: service.runtimeBundleRef, runtimeBundleManifestDigest: service.runtimeBundleManifestDigest,
    executableId: service.executableId, executableDigest: service.executableDigest, modelManifestRef: service.modelManifestRef, modelManifestDigest: service.modelManifestDigest,
    processContainmentRef: localRef('containment'), containmentPlanRef: localRef('plan'), sandboxLaunchSpecRef: localRef('launch'), sandboxLaunchSpecDigest: localRef('launch-semantic'),
    backend: service.backend, externalNetworkEgress: 'denied' as const, loopbackOnly: true as const, stableServiceIdentityDigest: stable,
    inspectorSupervisorInstanceId: 'original-supervisor', inspectorIdentityRef: localRef('inspector'), inspectorIdentityDigest: localRef('inspector-semantic'),
    observedAt: LOCAL_AT, validThrough: addCanonicalDuration(LOCAL_AT, 60000) };
  const boundary = decodeLocalInferenceBoundary({ ...core, evidenceDigest: canonicalSha256(core) });
  const updated = { ...core, serviceLaunchId: identityHash('replacement'), inspectorSupervisorInstanceId: 'successor', observedAt: addCanonicalDuration(LOCAL_AT, 1000) };
  assert.equal(decodeLocalInferenceBoundary({ ...updated, evidenceDigest: canonicalSha256(updated) }).stableServiceIdentityDigest, boundary.stableServiceIdentityDigest);
  const dishonest = { ...core, externalNetworkEgress: 'allowed' };
  assert.throws(() => decodeLocalInferenceBoundary({ ...dishonest, evidenceDigest: canonicalSha256(dishonest) }));
});

test('activation rows retain exact object-H cycle identity, contiguous launches, participants and fixed activation deadline', () => {
  const cycle = localCycleFixture(), launch = localLaunchFixture();
  assert.deepEqual(decodeLocalInferenceCycle(cycle), cycle); assert.deepEqual(decodeLocalInferenceLaunch(launch), launch);
  assert.equal(cycle.activationCycleId, localInferenceCycleId(cycle));
  assert.notEqual(cycle.activationCycleId, identityHash(cycle.ownerPrincipalId, cycle.serviceId, cycle.serviceSpecDigest, cycle.cycleOrdinal), 'object-JCS identity must not drift into generic argument-array H');
  assert.equal(launch.launchId, localInferenceLaunchId(cycle.activationCycleId, 1));
  for (const change of [{ ...cycle, activationCycleId: identityHash('other cycle') }, { ...cycle, activationAttempt: 2 },
    { ...cycle, participants: [...cycle.participants, ...cycle.participants] },
    { ...cycle, phase: 'active', boundaryEvidenceRef: localRef('boundary'), finishedAt: '2026-10-31T00:00:00.000Z' },
    { ...cycle, phase: 'retry_wait', retryNotBeforeAt: addCanonicalDuration(LOCAL_AT, 1000) }]) {
    const { cycleDigest: _old, ...core } = change;
    assert.throws(() => decodeLocalInferenceCycle({ ...core, cycleDigest: canonicalSha256(core) }));
  }
  for (const change of [{ ...launch, activationDeadlineAt: addCanonicalDuration(LOCAL_AT, 120001) }, { ...launch, requestRef: localRef('run authority') },
    { ...launch, leaseVersion: 1 }, { ...launch, phase: 'retired', rowVersion: 2, retirementKind: 'no_spawn', processContainmentRef: localRef('invented'),
      retirementEvidenceRef: localRef('proof'), retiredAt: addCanonicalDuration(LOCAL_AT, 1000) }])
    assert.throws(() => decodeLocalInferenceLaunch(change));
});

test('managed identities are canonical 32-byte base64url values, never CAS digests or padded aliases', () => {
  const valid = identityHash('local-model-identity'); assert.equal(decodeLocalIdentity(valid), valid);
  for (const value of [localRef('not-id'), `${valid}=`, '', 'A'.repeat(42), `${'A'.repeat(42)}B`]) assert.throws(() => decodeLocalIdentity(value));
});
