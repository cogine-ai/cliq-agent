import { canonicalSha256 } from '../kernel/canonical.js';
import type { NormalizedRunSubmitRequest } from '../kernel/control-submit.js';
import { decodeDependencyPolicy, DEPENDENCY_LIMITS } from '../kernel/dependency.js';
import { immutableSnapshot } from '../model/immutable.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeWorkspaceIdentity } from './decoders.js';
import { readInstalledDependencyEndpoints } from './dependency-endpoints.js';
import { readCandidateDependencyPlan } from './dependency-plan.js';
import { readDependencyScriptSourceConditions } from './dependency-script-source.js';
import { KernelStorageError } from './errors.js';
import { readDependencySignedAssets } from './dependency-execution-data.js';
import type { HeldInstalledRuntime } from './installed-runtime.js';
import { readSession, readSessionPrincipalId } from './rows.js';
import { readSourceInspectionTargetData, runSubmitIntentDigest, type SourceInspectionBootstrap } from './source-target.js';
import { readSourceInspectionAttempt, readSourceInspectionOriginalRequest } from './source-inspection.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

/** Reproduce only data while the original capture owner still owns the whole
 * graph. This does not consume consent or attest capture/retirement. The
 * original final transaction independently binds its native joined result.
 * There is deliberately no fabricated future template or script permission. */
export async function readDependencySubmissionConditions(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: SourceInspectionBootstrap & { selectedRuntime: HeldInstalledRuntime }, input: {
    request: NormalizedRunSubmitRequest; sourceManifestRef: string; workspaceEntriesRef: string; privateGitStateRef?: string;
  }, signal?: AbortSignal) {
  input = immutableSnapshot(input);
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  if (input.request.dependency.mode !== 'locked' || input.request.dependency.credentialGrantIds.length)
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'only the public single-root locked npm dependency profile is supported');
  reads.assertReadActive();
  const active = assertActiveStateOwner(driver, owner), session = readSession(driver, input.request.sessionId);
  const principalId = readSessionPrincipalId(driver, session.id);
  const attempt = readSourceInspectionAttempt(driver, { principalId, method: 'run.submit', admissionKey: input.request.admissionKey,
    admissionIntentDigest: runSubmitIntentDigest(principalId, input.request) });
  if (!attempt || attempt.method !== 'run.submit' || attempt.stateOwnerEpoch !== active.ownerEpoch ||
      attempt.supervisorInstanceId !== active.supervisorInstanceId)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'dependency submission has no original source capture owner');
  const original = await readSourceInspectionTargetData(reads, attempt, readSourceInspectionOriginalRequest(driver, attempt.inspectionId));
  if (original.original.method !== 'run.submit' || canonicalSha256(original.original) !== canonicalSha256(input.request))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'dependency submission substitutes its complete original normalized request');
  const request = original.original;
  if (request.dependency.mode !== 'locked' || request.dependency.credentialGrantIds.length)
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'dependency capture does not name the public locked profile');
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(reads, session.workspaceIdentityRef));
  if (session.contextRevision !== request.expectedContextRevision || workspace.kind !== 'live' || workspace.ownerPrincipalId !== principalId ||
      workspace.canonicalRootPath !== request.workspacePath || active.runtimeBundleRef !== canonicalSha256(runtime.bundle) ||
      active.runtimeBundleManifestDigest !== runtime.bundle.manifestDigest ||
      canonicalSha256(runtime.sandboxProfile.resources) !== canonicalSha256(request.sandboxResources))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'dependency submission differs from its original Session, selected runtime or profile');
  const signed = await readDependencySignedAssets(reads, { bundle: runtime.bundle, releaseKeys: runtime.releaseKeys,
    resources: request.sandboxResources, allowScripts: request.dependency.allowInstallScripts }, signal);
  const { toolchain } = signed;
  const registrySources = await readInstalledDependencyEndpoints(driver, reads, owner, runtime.selectedRuntime,
    { principalId, endpointIds: request.dependency.registryEndpointIds }, signal);
  const registryRecords = registrySources.map(source => source.record);
  const endpoints = registryRecords.map(record => ({ endpointRegistrationRef: record.expectedRegistrationArtifactRef,
    endpointIdentityDigest: record.registration.endpointIdentityDigest, tlsPolicyDigest: record.registration.tlsPolicyDigest }))
    .sort((a, b) => Buffer.compare(Buffer.from(a.endpointRegistrationRef), Buffer.from(b.endpointRegistrationRef)));
  const scriptlessPolicy = decodeDependencyPolicy({ schemaVersion: 1, mode: 'locked_node', allowedAdapters: ['npm-ci-v1'],
    registryEndpoints: endpoints, credentialGrantRefs: [], installScriptsPolicy: 'deny',
    maxPackages: request.dependency.maxPackages ?? DEPENDENCY_LIMITS.defaultPackages,
    maxDownloadBytes: request.dependency.maxDownloadBytes ?? DEPENDENCY_LIMITS.defaultDownloadBytes });
  const selected = await readCandidateDependencyPlan(reads, { sourceRef: input.sourceManifestRef, policy: scriptlessPolicy,
    guestToolchainManifestRef: toolchain.manifestRef, registryEndpoints: registryRecords.map(record => record.registration),
    maxSingleFileBytes: request.sandboxResources.maxSingleFileBytes });
  const conditions = await readDependencyScriptSourceConditions(reads, {
    sourceManifestRef: input.sourceManifestRef, workspaceEntriesRef: input.workspaceEntriesRef,
    ...(input.privateGitStateRef ? { privateGitStateRef: input.privateGitStateRef } : {}), workspaceIdentityDigest: workspace.identityDigest,
    resources: request.sandboxResources, packageManifestDigest: selected.plan.packageManifest.contentDigest,
    lockfileDigest: selected.plan.lockfileDigest, bindingGyp: selected.plan.bindingGyp.kind === 'absent' ? { kind: 'absent' }
      : { kind: 'present', contentDigest: selected.plan.bindingGyp.contentDigest },
    execution: { ...signed.execution, registryTargetsDigest: canonicalSha256({ registryEndpoints: endpoints, credentialGrantRefs: [] }) }
  });
  reads.assertReadActive(); signal?.throwIfAborted();
  if (canonicalSha256(assertActiveStateOwner(driver, owner)) !== canonicalSha256(active) ||
      canonicalSha256(readSession(driver, request.sessionId)) !== canonicalSha256(session) || readSessionPrincipalId(driver, session.id) !== principalId)
    throw new KernelStorageError('REVISION_CONFLICT', 'dependency capture data no longer belongs to its original owner and Session cut');
  return Object.freeze({ ...immutableSnapshot({ conditions, scriptlessPolicy, scriptlessPlan: selected.plan, data: selected.data, toolchain, registryRecords }),
    registrySources });
}
