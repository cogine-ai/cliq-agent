import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { ProcessContainment, SourceInspectionAttemptV1, SourceInspectionRetirementEvidenceV1,
  SourceInspectionTargetV2 } from '../kernel/execution.js';
import { parseCanonicalTime } from '../kernel/identity.js';
import { decodeSourceGitRetirementObservation } from '../sandbox/source-git-native.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { decodeSourceGitInspectionOutput } from '../workspace/source-git-output.js';
import { readPrivateGitData, privateGitSourceHead } from '../workspace/private-git-data.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeSourceManifest, decodeSourceProjection, decodeWorkspaceIdentity } from './decoders.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { readSourceGitInputIntent } from './source-git-input.js';
import { readRetainedSourceGitLaunch } from './source-git-launch.js';
import { readSourceInspectionRetirementHandoff } from './source-inspection-handoff.js';
import { readSourceInspectionOriginalRequest } from './source-inspection.js';
import { readSourceInspectionTargetData } from './source-target.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { joinResourceOperations } from './errors.js';

type Retired = Extract<SourceInspectionAttemptV1, { phase: 'retired' }>;
function invalid(): never { throw new TypeError('retained source Git retirement differs from its original complete closure'); }
function originalObservation(value: import('../kernel/execution.js').SourceInspectionNativeRetirementV1) {
  const { origin: _origin, observedAtMs: _observedAt, containment, ...identity } = value;
  if (!containment) return { ...identity, containment: null };
  const { observedAtMs: _deathTime, ...domain } = containment;
  return { ...identity, containment: domain };
}

async function intent(artifacts: ArtifactCatalog, row: Retired, target: SourceInspectionTargetV2) {
  if (!row.inputRef || !row.inputDigest) return invalid();
  const [input, workspace, profile] = await joinResourceOperations([
    readSourceGitInputIntent(artifacts, row.inputRef),
    readCanonicalArtifact(artifacts, target.workspaceIdentityRef).then(decodeWorkspaceIdentity),
    readCanonicalArtifact(artifacts, target.sandboxProfileRef).then(decodeSandboxProfile)
  ]);
  if (workspace.kind !== 'live' || !workspace.repositoryIdentityDigest || workspace.identityDigest !== row.workspaceIdentityDigest ||
      input.inspectionId !== row.inspectionId || input.targetRef !== row.targetRef || input.targetDigest !== row.targetDigest ||
      input.inputDigest !== row.inputDigest || input.repositoryIdentityDigest !== workspace.repositoryIdentityDigest ||
      input.inspectionGrantId !== target.inspectionGrantId || input.inspectionReceiptRef !== target.inspectionReceiptRef ||
      input.inspectionReceiptDigest !== target.inspectionReceiptDigest || canonicalSha256(input.resources) !== canonicalSha256(profile.resources)) return invalid();
  return input;
}

/** Retained data audit only. This never opens an old source, lends a native
 * token, resumes a process, or converts a missing birth into no-spawn. The
 * outer owner reader separately verifies inspector and actual owner-death. */
export async function readSourceGitRetirementClosure(driver: SqliteDriver, artifacts: ArtifactCatalog, row: Retired,
  evidence: SourceInspectionRetirementEvidenceV1,
  runtime: { runtimeBundleRef: string; runtimeBundleManifestDigest: string }): Promise<void> {
  const closure = evidence.processClosure;
  if (evidence.stagingObservation === 'registered_reserved_root_absent' &&
      (closure.kind !== 'source_native_retired' || evidence.captureOwnerClosure.kind !== 'owning_process_dead' || !row.retirementHandoffRef)) return invalid();
  if (closure.kind === 'not_planned') {
    if (!exactKeys(closure, ['kind']) || row.inputRef !== undefined || row.plan !== undefined || row.processContainmentRef !== undefined ||
        row.outcome.kind === 'captured' && row.outcome.privateGitStateRef !== undefined) return invalid();
    return;
  }
  const { target } = await readSourceInspectionTargetData(artifacts, row, readSourceInspectionOriginalRequest(driver, row.inspectionId));
  if (target.schemaVersion !== 2 || target.runtimeBundleRef !== runtime.runtimeBundleRef ||
      target.runtimeBundleManifestDigest !== runtime.runtimeBundleManifestDigest) return invalid();
  const input = await intent(artifacts, row, target);
  if (closure.kind === 'input_not_started') {
    if (!exactKeys(closure, ['kind', 'inputRef', 'inputDigest']) || closure.inputRef !== row.inputRef ||
        closure.inputDigest !== row.inputDigest || row.plan !== undefined || row.processContainmentRef !== undefined ||
        row.outcome.kind === 'captured') return invalid();
    if (evidence.captureOwnerClosure.kind !== 'local_resources_joined') {
      const joined = await readSourceInspectionRetirementHandoff(driver, artifacts, row, runtime);
      if (joined.handoff.captureOwnerClosure.kind !== 'local_resources_joined' ||
          canonicalSha256(joined.handoff.processClosure) !== canonicalSha256(closure)) return invalid();
    }
    return;
  }
  if (closure.kind !== 'source_native_retired' || !exactKeys(closure, ['kind', 'inputRef', 'inputDigest', 'nativeBirthIdentity', 'observation',
    ...(Object.hasOwn(closure, 'output') ? ['output'] : [])]) || closure.inputRef !== row.inputRef || closure.inputDigest !== row.inputDigest) return invalid();
  const birth = closure.nativeBirthIdentity;
  if (!exactKeys(birth, ['deviceId', 'fileId', 'ownerUid']) || !/^(0|[1-9][0-9]{0,19})$/u.test(birth.deviceId) ||
      !/^[1-9][0-9]{0,19}$/u.test(birth.fileId) || birth.ownerUid !== row.stagingIdentity.ownerUid) return invalid();
  const registeredAbsent = evidence.stagingObservation === 'registered_reserved_root_absent';
  if (registeredAbsent && (evidence.captureOwnerClosure.kind !== 'owning_process_dead' || !row.retirementHandoffRef)) return invalid();
  const origin = registeredAbsent ? 'original_birth_registered_absent_checker'
    : evidence.captureOwnerClosure.kind === 'local_resources_joined' ? 'original_owner_joined' : 'original_birth_current_checker';
  const observed = decodeSourceGitRetirementObservation(closure.observation, origin);
  if (registeredAbsent) {
    const joined = await readSourceInspectionRetirementHandoff(driver, artifacts, row, runtime), prior = joined.handoff.processClosure;
    if (prior.kind !== 'source_native_retired' || !joined.handoff.nativeLifecycleRef ||
        canonicalSha256(prior.nativeBirthIdentity) !== canonicalSha256(birth) ||
        canonicalSha256(originalObservation(prior.observation)) !== canonicalSha256(originalObservation(observed)) ||
        observed.observedAtMs < prior.observation.observedAtMs) return invalid();
  }
  if (observed.inspectionId !== row.inspectionId || observed.targetRef !== row.targetRef ||
      observed.stagingNonceDigest !== row.stagingNonceDigest || observed.inputIntentRef !== row.inputRef ||
      observed.observedAtMs < parseCanonicalTime(row.createdAt) || observed.observedAtMs > parseCanonicalTime(evidence.observedAt) ||
      observed.snapshotDigest !== undefined && (observed.byteCount > input.resources.maxGenerationBytes ||
        observed.entryCount > 100_000 || observed.shardCount > 16)) return invalid();
  if (row.plan) {
    await readRetainedSourceGitLaunch(artifacts, row, target, input, evidence.observedAt);
    const plan = row.plan, backend = plan.reservedBackendIdentity;
    if (backend.kind !== 'linux' || !observed.reserved || backend.deviceId !== observed.cgroupDeviceId ||
        backend.cgroupId !== observed.cgroupId || backend.fileId !== observed.cgroupId ||
        plan.launchNonceDigest !== observed.launchNonceDigest ||
        backend.pidNamespaceReservationId !== `source-pending:${row.stagingNonceDigest}` ||
        backend.subreaperStartToken !== `linux-subreaper:${observed.originalControllerPid}:${observed.originalControllerStartToken}` ||
        observed.containmentPlanRef !== null && (observed.containmentPlanRef !== plan.containmentPlanRef ||
          observed.sandboxLaunchRef !== plan.sandboxLaunchSpecRef || observed.sandboxLaunchDigest !== plan.sandboxLaunchSpecDigest)) return invalid();
    if (row.processContainmentRef) {
      const actual = await readCanonicalArtifact<ProcessContainment>(artifacts, row.processContainmentRef), death = observed.containment;
      if (!death || actual.backend.kind !== 'linux' || actual.planRef !== plan.containmentPlanRef ||
          actual.sandboxLaunchSpecRef !== plan.sandboxLaunchSpecRef || actual.sandboxLaunchSpecDigest !== plan.sandboxLaunchSpecDigest ||
          actual.owner.kind !== 'source_inspection' || actual.owner.inspectionId !== row.inspectionId ||
          actual.owner.supervisorInstanceId !== row.supervisorInstanceId || actual.owner.principalId !== row.principalId ||
          actual.owner.targetRef !== row.targetRef || actual.launchNonceDigest !== plan.launchNonceDigest ||
          actual.backend.cgroupId !== observed.cgroupId || actual.backend.cgroupPath !== backend.cgroupPath ||
          actual.backend.pidNamespaceReservationId !== backend.pidNamespaceReservationId ||
          actual.backend.pidNamespaceId !== death.pidNamespaceId || actual.backend.namespaceInitStartToken !== death.namespaceInitStartToken ||
          actual.backend.subreaperStartToken !== backend.subreaperStartToken) return invalid();
    }
  } else if (row.processContainmentRef || observed.containmentPlanRef !== null || observed.blocked) return invalid();
  if (closure.output !== undefined) {
    if (!exactKeys(closure.output, ['inspectionOutputRef', 'privateGitStateRef']) || origin !== 'original_owner_joined' ||
        !observed.continued || row.processContainmentRef === undefined) return invalid();
    const { inspectionOutputRef, privateGitStateRef } = closure.output;
    const output = decodeSourceGitInspectionOutput(await artifacts.readBoundedBytes(inspectionOutputRef,
      Math.min(input.resources.maxSingleFileBytes, input.resources.maxInvocationOutputBytes)), {
      repositoryIdentityDigest: input.repositoryIdentityDigest, resources: input.resources });
    const data = await readPrivateGitData(artifacts, privateGitStateRef, { repositoryIdentityDigest: input.repositoryIdentityDigest, resources: input.resources });
    if (canonicalSha256(data.manifest.head) !== canonicalSha256(output.head) || canonicalSha256(data.manifest.refs) !== canonicalSha256(output.refs) ||
        canonicalSha256(data.index.entries) !== canonicalSha256(output.index.entries) || data.index.indexTreeObjectId !== output.index.indexTreeObjectId ||
        data.index.canonicalIndexBytesRef !== output.index.sha256 || data.index.canonicalIndexByteCount !== output.index.byteCount ||
        !data.pack || data.pack.packBytesRef !== output.pack.sha256 || data.pack.packByteCount !== output.pack.byteCount ||
        data.pack.packIndexBytesRef !== output.pack.indexSha256 || data.pack.packIndexByteCount !== output.pack.indexByteCount ||
        data.pack.packTrailerObjectHash !== output.pack.trailerObjectHash || canonicalSha256(data.closure.reachableObjectIds) !== canonicalSha256(output.pack.objectIds) ||
        !canonicalJsonBytes(data.config).equals(canonicalJsonBytes(output.sanitizedConfig))) return invalid();
    if (row.outcome.kind === 'captured') {
      const source = decodeSourceManifest(await readCanonicalArtifact(artifacts, row.outcome.sourceManifestRef));
      const projection = decodeSourceProjection(await readCanonicalArtifact(artifacts, source.sourceProjectionRef));
      if (row.outcome.privateGitStateRef !== privateGitStateRef || !source.git || source.git.repositoryIdentityDigest !== input.repositoryIdentityDigest ||
          row.method === 'run.submit' && projection.classificationIndexRef !== source.git.indexRef ||
          source.git.indexRef !== data.manifest.indexRef || source.git.indexTreeObjectId !== data.index.indexTreeObjectId ||
          canonicalSha256(source.git.head) !== canonicalSha256(privateGitSourceHead(data))) return invalid();
    }
  } else if (row.outcome.kind === 'captured') return invalid();
}
