import type { RetainedControlRootContext } from './control-channel.js';
// One original capture's immutable data graph. The source owner supplies its
// real row; this publisher neither reserves source nor creates permission.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { decodeEndpointAuthorityRecord, decodeEndpointAuthorityOperation, type EndpointAuthorityRecordV1,
  type EndpointAuthorityOperationV1 } from '../kernel/credential-authority.js';
import { assertControlWireJson } from '../kernel/control-wire-data.js';
import { decodeDependencyAcquisitionPlan, decodeDependencyPolicy, dependencyRegistryTargetsDigest,
  DEPENDENCY_LIMITS, type DependencyAcquisitionPlan, type DependencyPolicy, type DependencyScriptConditionsV1 } from '../kernel/dependency.js';
import { decodeDependencyScriptIntent, type DependencyScriptIntentV1, type DependencyRegistrySourceV1 } from '../kernel/dependency-script-intent.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { SourceInspectionAttemptV1 } from '../kernel/execution.js';
import { immutableSnapshot } from '../model/immutable.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { AuthorizationRuntime } from './authorization.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeControlChannel, decodeLocalPrincipalIdentity, decodePlatformProcessIdentity, decodeStateRootIdentity } from './decoders.js';
import { verifyRetainedEndpointAuthoritySource, validateRetainedEndpointResult } from './endpoint-authority-source.js';
import { verifyRetainedInstalledEndpointData } from './installed-credential-history.js';
import { readCandidateDependencyPlan } from './dependency-plan.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { KernelStorageError, joinResourceOperations } from './errors.js';
import { readSourceInspectionOriginalRequest, readSourceInspectionAttempt } from './source-inspection.js';
import { readSourceInspectionTargetData } from './source-target.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

type EndpointSource = { record: EndpointAuthorityRecordV1; originalRecord: EndpointAuthorityRecordV1; operation: EndpointAuthorityOperationV1;
  objects: readonly { artifactRef: string; bytes: Buffer }[] };
function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'dependency intent differs from its complete original source graph'); }
const same = (left: unknown, right: unknown) => canonicalJsonBytes(left).equals(canonicalJsonBytes(right));

export function decodeDependencyRegistrySource(value: unknown): DependencyRegistrySourceV1 {
  assertControlWireJson(value);
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const source = value as DependencyRegistrySourceV1;
  if (Object.keys(source).sort().join() !== 'format,objectRefs,operation,originalRecord,record,schemaVersion,sourceDigest' ||
      source.schemaVersion !== 1 || source.format !== 'cliq-dependency-registry-source-v1') invalid();
  decodeEndpointAuthorityRecord(source.record); decodeEndpointAuthorityRecord(source.originalRecord); decodeEndpointAuthorityOperation(source.operation);
  if (source.record.state !== 'active' || !same(source.record, source.originalRecord) || source.operation.kind !== 'register' ||
      source.operation.disposition !== 'registered' || !Array.isArray(source.objectRefs) || source.objectRefs.length !== 6 ||
      source.objectRefs.some((ref, index) => typeof ref !== 'string' || !/^[0-9a-f]{64}$/u.test(ref) || index > 0 && ref <= source.objectRefs[index - 1]!) ||
      source.sourceDigest !== digestOmitting(source, 'sourceDigest')) invalid();
  return immutableSnapshot(source);
}

export async function publishDependencyScriptIntent(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, input: { row: SourceInspectionAttemptV1; conditions: DependencyScriptConditionsV1; scriptlessPolicy: DependencyPolicy;
    scriptlessPlan: DependencyAcquisitionPlan; registrySources: readonly EndpointSource[] }, signal?: AbortSignal) {
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const { row, conditions, scriptlessPolicy: policy, scriptlessPlan: plan } = input;
  decodeDependencyPolicy(policy); decodeDependencyAcquisitionPlan(plan); assertActiveStateOwner(driver, owner);
  const key = { principalId: row.principalId, method: row.method, admissionKey: row.admissionKey, admissionIntentDigest: row.admissionIntentDigest };
  if (row.phase === 'retired' || row.method !== 'run.submit' || !same(readSourceInspectionAttempt(driver, key), row) ||
      input.registrySources.length < 1 || input.registrySources.length > 128 || policy.installScriptsPolicy !== 'deny' ||
      plan.allowInstallScripts || dependencyRegistryTargetsDigest(policy) !== conditions.execution.registryTargetsDigest) invalid();
  const index = readSourceInspectionOriginalRequest(driver, row.inspectionId);
  const { target, original } = await readSourceInspectionTargetData(reads, row, index);
  if (original.method !== 'run.submit' || original.dependency.mode !== 'locked' || !original.dependency.allowInstallScripts ||
      original.dependency.installScriptsGrantId !== undefined) invalid();
  // These copies are private before the first publication await. Equal refs
  // must also have equal complete bytes, even when many endpoints share a CA.
  const objects = new Map<string, Buffer>(), sourceData: DependencyRegistrySourceV1[] = [];
  for (const source of input.registrySources) {
    const refs: string[] = [];
    for (const object of source.objects) {
      if (!Buffer.isBuffer(object.bytes) || object.bytes.length < 1 || object.bytes.length > 16_777_216 || sha256Bytes(object.bytes) !== object.artifactRef) invalid();
      const previous = objects.get(object.artifactRef);
      if (previous && !previous.equals(object.bytes)) invalid();
      if (!previous) objects.set(object.artifactRef, Buffer.from(object.bytes));
      refs.push(object.artifactRef);
    }
    const data: DependencyRegistrySourceV1 = { schemaVersion: 1, format: 'cliq-dependency-registry-source-v1',
      record: source.record, originalRecord: source.originalRecord, operation: source.operation,
      objectRefs: refs.sort(), sourceDigest: '' }; data.sourceDigest = digestOmitting(data, 'sourceDigest');
    sourceData.push(decodeDependencyRegistrySource(data));
  }
  if (!same([...original.dependency.registryEndpointIds].sort(), sourceData.map(source => source.record.endpointRegistrationId).sort()) ||
      !same(sourceData.map(source => ({ endpointRegistrationRef: source.record.expectedRegistrationArtifactRef,
        endpointIdentityDigest: source.record.registration.endpointIdentityDigest, tlsPolicyDigest: source.record.registration.tlsPolicyDigest }))
        .sort((a, b) => Buffer.compare(Buffer.from(a.endpointRegistrationRef), Buffer.from(b.endpointRegistrationRef))), policy.registryEndpoints)) invalid();
  const metadata: PublishedArtifact[] = [], ordered = [...objects].sort(([a], [b]) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  for (let index = 0; index < ordered.length; index += 4) {
    signal?.throwIfAborted();
    const results = await joinResourceOperations(ordered.slice(index, index + 4).map(async ([ref, bytes]) => {
      const result = await reads.publishBytes(bytes, 'application/octet-stream', 'cliq-retained-endpoint-source-bytes-v1');
      if (result.ref !== ref || result.byteLength !== bytes.length || !(await reads.readBoundedBytes(ref, bytes.length)).equals(bytes)) invalid();
      return result;
    }));
    metadata.push(...results);
  }
  const registrySourceRefs: string[] = [];
  for (const source of sourceData) {
    const registration = source.originalRecord.registration;
    const registered = await reads.publishCanonical(registration, registration.format);
    if (registered.ref !== source.originalRecord.expectedRegistrationArtifactRef ||
        !same(await readCanonicalArtifact(reads, registered.ref), registration)) invalid();
    metadata.push(registered);
    const result = await reads.publishCanonical(source, source.format);
    if (!same(await readCanonicalArtifact(reads, result.ref), source)) invalid();
    metadata.push(result); registrySourceRefs.push(result.ref);
  }
  const [policyArtifact, planArtifact] = await reads.publishCanonicalPair([
    { value: policy, schemaKind: 'cliq-dependency-policy-v1' }, { value: plan, schemaKind: plan.format }]);
  metadata.push(policyArtifact, planArtifact);
  const intent: DependencyScriptIntentV1 = { schemaVersion: 1, format: 'cliq-dependency-script-intent-v1',
    inspectionId: row.inspectionId, principalId: row.principalId, targetRef: row.targetRef,
    originalRequestId: index.originalRequestId, originalRequestDigest: index.originalRequestDigest, admissionIntentDigest: row.admissionIntentDigest,
    workspaceIdentityRef: target.workspaceIdentityRef, workspaceIdentityDigest: row.workspaceIdentityDigest,
    sourceManifestRef: conditions.source.sourceManifestRef, sourceManifestDigest: conditions.source.sourceManifestDigest, conditions,
    scriptlessPolicyRef: policyArtifact.ref, scriptlessPlanRef: planArtifact.ref, registrySourceRefs: registrySourceRefs.sort(), intentDigest: '' };
  intent.intentDigest = digestOmitting(intent, 'intentDigest'); decodeDependencyScriptIntent(intent);
  const artifact = await reads.publishCanonical(intent, intent.format);
  if (!same(await readCanonicalArtifact(reads, artifact.ref), intent) || !same(await readCanonicalArtifact(reads, policyArtifact.ref), policy) ||
      !same(await readCanonicalArtifact(reads, planArtifact.ref), plan)) invalid();
  // Reopen the entire graph through the same retained consumer before the
  // physical staging-retirement observation starts its existing five seconds.
  await readDependencyScriptIntentData(driver, reads, owner, runtime, artifact.ref, row, signal);
  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  if (!same(readSourceInspectionAttempt(driver, key), row) || !same(readSourceInspectionOriginalRequest(driver, row.inspectionId), index)) invalid();
  return { artifact, intent: immutableSnapshot(intent), metadata: [...metadata, artifact] };
}

/** Data-only whole-graph read shared by the producer's post-publication audit
 * and the later authenticated consent/history path. No live registry is read. */
export async function readDependencyScriptIntentData(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: RetainedControlRootContext,
  runtime: AuthorizationRuntime, ref: string, row: SourceInspectionAttemptV1, signal?: AbortSignal) {
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  reads.assertReadActive();
  const intent = decodeDependencyScriptIntent(await readCanonicalArtifact(reads, ref));
  const index = readSourceInspectionOriginalRequest(driver, row.inspectionId);
  const { target, original } = await readSourceInspectionTargetData(reads, row, index);
  if (row.method !== 'run.submit' || original.method !== 'run.submit' || original.dependency.mode !== 'locked' ||
      !original.dependency.allowInstallScripts || original.dependency.installScriptsGrantId !== undefined ||
      intent.inspectionId !== row.inspectionId || intent.principalId !== row.principalId || intent.targetRef !== row.targetRef ||
      intent.originalRequestId !== index.originalRequestId || intent.originalRequestDigest !== index.originalRequestDigest ||
      intent.admissionIntentDigest !== row.admissionIntentDigest || intent.workspaceIdentityRef !== target.workspaceIdentityRef ||
      intent.workspaceIdentityDigest !== row.workspaceIdentityDigest ||
      row.phase === 'retired' && (row.outcome.kind !== 'captured' || row.outcome.sourceManifestRef !== intent.sourceManifestRef ||
        row.outcome.sourceManifestDigest !== intent.sourceManifestDigest || row.dependencyScriptIntentRef !== ref)) invalid();
  const root = decodeStateRootIdentity(await readCanonicalArtifact(reads, owner.stateRootIdentityRef));
  if (root.identityDigest !== owner.stateRootIdentityDigest) invalid();
  const cache = new Map<string, Buffer>();
  const bytes = async (objectRef: string) => {
    let value = cache.get(objectRef);
    if (!value) { value = await reads.readBoundedBytes(objectRef, 16_777_216); if (sha256Bytes(value) !== objectRef) invalid(); cache.set(objectRef, value); }
    return value;
  };
  const json = async (objectRef: string) => {
    const raw = await bytes(objectRef); if (raw.length > 1_048_576) invalid();
    const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw));
    if (!canonicalJsonBytes(value).equals(raw)) invalid(); return value;
  };
  const registry = [];
  for (const sourceRef of intent.registrySourceRefs) {
    signal?.throwIfAborted();
    const source = decodeDependencyRegistrySource(await readCanonicalArtifact(reads, sourceRef)), op = source.operation;
    const channel = decodeControlChannel(await json(op.channelIdentityRef));
    const principal = decodeLocalPrincipalIdentity(await json(channel.principalIdentityRef));
    const originalRoot = decodeStateRootIdentity(await json(principal.stateRootIdentityRef));
    if (channel.transport.kind !== 'in_process') invalid();
    const process = decodePlatformProcessIdentity(await json(channel.transport.processIdentityRef));
    const registration = source.originalRecord.registration, tls = registration.tls;
    const expectedRefs = [op.channelIdentityRef, channel.principalIdentityRef, principal.stateRootIdentityRef,
      channel.transport.processIdentityRef, tls.trustStoreRuntimeBundleRef, tls.trustStoreRef].sort();
    if (!same(source.objectRefs, expectedRefs) || source.record.ownerPrincipalId !== row.principalId ||
        source.originalRecord.authorityRevision !== 1 || registration.registrationKind !== 'user' ||
        !registration.purposes.includes('dependency_registry') || registration.createdAt > source.originalRecord.createdAt ||
        op.requestDigest !== source.originalRecord.sourceRequestDigest) invalid();
    const old = tls.trustStoreRuntimeBundleRef !== canonicalSha256(runtime.bundle);
    const schema = runtime.bundle.entries.find(entry => entry.entryId === 'kernel_schema');
    const conversion = runtime.bundle.entries.find(entry => entry.entryId === 'schema_conversion');
    const proved = verifyRetainedInstalledEndpointData({ currentBundle: runtime.bundle, releaseKeys: runtime.releaseKeys, registration,
      originalBundleBytes: await bytes(tls.trustStoreRuntimeBundleRef), originalTrustStoreBytes: await bytes(tls.trustStoreRef),
      ...(old && schema && conversion ? { currentSchemaBytes: await bytes(schema.digest), currentConversionBytes: await bytes(conversion.digest) } : {}) });
    verifyRetainedEndpointAuthoritySource({ operation: op, channel, principal, root: originalRoot, process },
      { principalId: row.principalId, stateRoot: root, executableImageDigest: proved.supervisorImageDigest });
    validateRetainedEndpointResult(op, [source.originalRecord]); registry.push(registration);
  }
  const policy = decodeDependencyPolicy(await readCanonicalArtifact(reads, intent.scriptlessPolicyRef));
  const plan = decodeDependencyAcquisitionPlan(await readCanonicalArtifact(reads, intent.scriptlessPlanRef));
  if (policy.mode !== 'locked_node' || !same(policy.allowedAdapters, ['npm-ci-v1']) || policy.credentialGrantRefs.length ||
      policy.installScriptsPolicy !== 'deny' || policy.installScriptsGrantRef !== undefined || plan.allowInstallScripts ||
      policy.maxPackages !== (original.dependency.maxPackages ?? DEPENDENCY_LIMITS.defaultPackages) ||
      policy.maxDownloadBytes !== (original.dependency.maxDownloadBytes ?? DEPENDENCY_LIMITS.defaultDownloadBytes) ||
      dependencyRegistryTargetsDigest(policy) !== intent.conditions.execution.registryTargetsDigest ||
      !same([...original.dependency.registryEndpointIds].sort(), registry.map(value => value.endpointRegistrationId).sort())) invalid();
  const selected = await readCandidateDependencyPlan(reads, { sourceRef: intent.sourceManifestRef, policy, registryEndpoints: registry,
    guestToolchainManifestRef: intent.conditions.execution.guestToolchainManifestRef, maxSingleFileBytes: original.sandboxResources.maxSingleFileBytes });
  if (!same(selected.plan, plan) || plan.lockfileDigest !== intent.conditions.lockfileDigest ||
      plan.packageManifest.contentDigest !== intent.conditions.packageManifestDigest) invalid();
  reads.assertReadActive();
  return immutableSnapshot({ intent, policy, plan, registrations: registry });
}
