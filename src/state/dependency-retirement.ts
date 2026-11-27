import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from '../kernel/control-wire-data.js';
import { decodeDependencyReadyItem, decodeDependencyFailureItem, type DependencyReadyItem, type DependencyFailureItem } from '../kernel/dependency.js';
import { decodeDependencyOperationGrant, decodeDependencyRequest, decodeDependencyTarget } from '../kernel/dependency-invocation.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { InvocationJournalEntry, RecoveryClosureV1, WorkspaceEntryManifest } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { isManagedNodeDependencyPath } from '../kernel/dependency-source.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readDependencyProcessCapture } from './dependency-capture.js';
import { readRetainedDependencyCandidate } from './dependency-candidate.js';
import { planDependencyInvocation } from './dependency-invocation-plan.js';
import { readDependencyPackageCache } from './dependency-plan.js';
import { readDependencyScriptsTemplateHistoryData } from './dependency-script-history.js';
import { decodeBudgetSettlement, decodeContextManifest, decodeWorkspaceEntries, decodeWorkspaceGenerationSnapshotEvidence, decodeWorkspaceState } from './decoders.js';
import { readRetiredGenerationSource } from './generation-retirement.js';
import { readCandidateSource } from './result-source.js';
import { readCheckpoint } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import { validateMatchingWorkerDeath, validateRetainedWorkerSeal } from './tool-checkpoint.js';
import { readStateOwner } from './state-owner.js';
import { readRetainedDependencyLaunchEnvironment } from './execution-closure.js';
import { npmDependencyMounts } from '../sandbox/dependency-recipe.js';
import { readInvocationAttempt } from './repositories/journal.js';
import { decodeDependencyPackageFetchObservation } from '../kernel/dependency-fetch.js';
import { decodeDependencyIntegrityEvidence, dependencyProtectedEntryChanges } from '../kernel/dependency-integrity.js';
import { readSupervisorInspector } from './supervisor-inspector.js';

export const dependencyReadyCheckpointId = (runId: string, opId: string, attempt: number) => identityHash('cliq-dependency-ready-checkpoint-v1', runId, opId, String(attempt));
export const dependencyFailureItemId = (runId: string, opId: string, attempt: number) => identityHash('cliq-dependency-failure-item-v1', runId, opId, String(attempt));
export const dependencyReadyItemId = (runId: string, opId: string, attempt: number) => identityHash('cliq-dependency-ready-item-v1', runId, opId, String(attempt));
/** Only a digest of the real complete sealed M entries. There is no invented
 * filtered SourceManifest, capture ref, native observation or new data root. */
export function dependencyManagedTreeDigest(input: WorkspaceEntryManifest, requireRoot: boolean): string {
  assertControlWireJson(input); const entries = decodeWorkspaceEntries(input);
  const managed = entries.entries.filter(entry => isManagedNodeDependencyPath(entry.path));
  if (requireRoot && (managed[0]?.path !== 'node_modules' || managed[0].kind !== 'directory')) throw new TypeError('dependency installed tree lacks its actual managed directory');
  return canonicalSha256({ schemaVersion: 1, format: 'cliq-node-managed-tree-v1', root: 'node_modules', entries: managed });
}
export const dependencyInstalledTreeDigest = (entries: WorkspaceEntryManifest) => dependencyManagedTreeDigest(entries, true);
/** Every unmanaged file and the original Git state stay equal. Generated
 * outputs outside node_modules are not a supported first-profile capability. */
export function assertDependencyUnmanagedEntries(before: WorkspaceEntryManifest, after: WorkspaceEntryManifest): void {
  before = decodeWorkspaceEntries(before); after = decodeWorkspaceEntries(after);
  requireEqual(after.entries.filter(entry => !isManagedNodeDependencyPath(entry.path)),
    before.entries.filter(entry => !isManagedNodeDependencyPath(entry.path)), 'dependency complete unmanaged workspace entries');
}
export type DependencyRetirementV1 = {
  schemaVersion: 1; format: 'cliq-dependency-retirement-v1'; runId: string; opId: string; attempt: number; dispatchId: string; leaseEpoch: number;
  dependencyPlanRef: string; packageCacheManifestRef: string; captureRef: string; captureDigest: string;
  checkpointId: string; workspaceStateRef: string; snapshotEvidenceRef: string; parentRetirementEvidenceRef: string;
  sourceAfterRef: string; sourceAfterDigest: string; installedTreeDigest: string; evidenceDigest: string;
  integrityEvidenceRef?: string; integrityEvidenceDigest?: string;
};
export function decodeDependencyRetirement(value: unknown): DependencyRetirementV1 {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dispatchId', 'leaseEpoch',
    'dependencyPlanRef', 'packageCacheManifestRef', 'captureRef', 'captureDigest', 'checkpointId', 'workspaceStateRef', 'snapshotEvidenceRef',
    'parentRetirementEvidenceRef', 'sourceAfterRef', 'sourceAfterDigest', 'installedTreeDigest', 'evidenceDigest'], ['integrityEvidenceRef', 'integrityEvidenceDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-dependency-retirement-v1') throw new TypeError('dependency retirement has another purpose');
  for (const key of ['runId', 'opId', 'dispatchId', 'checkpointId']) controlWireText(data[key], 256);
  controlWireInteger(data.attempt, 0, 1); controlWireInteger(data.leaseEpoch, 1);
  for (const key of ['dependencyPlanRef', 'packageCacheManifestRef', 'captureRef', 'captureDigest', 'workspaceStateRef', 'snapshotEvidenceRef',
    'parentRetirementEvidenceRef', 'sourceAfterRef', 'sourceAfterDigest', 'installedTreeDigest', 'evidenceDigest']) controlWireRef(data[key]);
  if (data.evidenceDigest !== digestOmitting(data, 'evidenceDigest')) throw new TypeError('dependency retirement complete digest differs');
  if (Object.hasOwn(data, 'integrityEvidenceRef') !== Object.hasOwn(data, 'integrityEvidenceDigest')) throw new TypeError('dependency retirement lost its exact integrity evidence pair');
  if (Object.hasOwn(data, 'integrityEvidenceRef')) { controlWireRef(data.integrityEvidenceRef); controlWireRef(data.integrityEvidenceDigest); }
  return data as DependencyRetirementV1;
}
type Cut = Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'items' | 'journal' | 'workspaceGenerations'>;

/** Complete acquired-ready history. It validates the original native result,
 * whole source, all cached bytes/SRI and the atomic parent seal. It grants no
 * live permission and does not use close, pathname or CAS existence as death. */
async function readDependencyProcessRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: Cut,
  supplied: Extract<DependencyReadyItem, { origin: 'acquired' }> | DependencyFailureItem) {
  assertControlWireJson(supplied);
  const item = immutableSnapshot(supplied.kind === 'dependency_ready' ? decodeDependencyReadyItem(supplied) : decodeDependencyFailureItem(supplied));
  if (item.kind === 'dependency_ready' && item.origin !== 'acquired') throw new TypeError('dependency result cannot borrow an inherited ready');
  const success = item.kind === 'dependency_ready', checkpointId = success ? item.readyCheckpointId : item.checkpointId;
  const opId = item.opId, attempt = item.attempt;
  if (item.runId !== cut.run.id || item.itemId !== (success ? dependencyReadyItemId(item.runId, opId, attempt) : dependencyFailureItemId(item.runId, opId, attempt)) ||
      checkpointId !== dependencyReadyCheckpointId(item.runId, opId, attempt)) throw new TypeError('dependency result has another original invocation');
  const rows = immutableSnapshot(readInvocationAttempt(driver, item.runId, item.opId, item.attempt)), [prepared, claim, terminal] = rows;
  if (rows.length !== 3 || prepared?.phase !== 'prepared' || prepared.opKind !== 'tool' || prepared.target !== 'builtin:dependency-acquire' ||
      claim?.phase !== 'dispatch_claimed' || (success ? terminal?.phase !== 'completed' || !terminal.resultRef || !terminal.receiptRef :
        terminal?.phase !== 'failed' || !terminal.errorRef || !terminal.evidenceRef || !terminal.evidenceDigest) || !terminal?.budgetSettlementRef ||
      !claim.evidenceRef || !claim.evidenceDigest || !claim.brokerFenceTokenDigest || claim.sandboxLaunchSpecRef !== undefined)
    throw new TypeError('dependency ready lacks its original unique completed Journal');
  const captureRef = (success ? terminal.resultRef : terminal.evidenceRef)!;
  const proofRef = (success ? terminal.receiptRef : terminal.errorRef)!;
  const proof = decodeDependencyRetirement(await readCanonicalArtifact(artifacts, proofRef));
  const packageCacheManifestRef = success ? item.packageCacheManifestRef : proof.packageCacheManifestRef;
  if (!success && item.receiptRef !== proofRef) throw new TypeError('dependency failure changed its exact original receipt');
  if (proof.runId !== item.runId || proof.opId !== item.opId || proof.attempt !== item.attempt || proof.dispatchId !== claim.dispatchId ||
      proof.leaseEpoch !== claim.leaseEpoch || proof.dependencyPlanRef !== item.planRef || proof.packageCacheManifestRef !== packageCacheManifestRef ||
      proof.captureRef !== captureRef || proof.checkpointId !== checkpointId || success && proof.installedTreeDigest !== item.installedTreeDigest)
    throw new TypeError('dependency ready substitutes its original result or atomic Checkpoint');
  const request = decodeDependencyRequest(await readCanonicalArtifact(artifacts, prepared.requestRef));
  const target = decodeDependencyTarget(await readCanonicalArtifact(artifacts, request.targetRef));
  const grant = decodeDependencyOperationGrant(await readCanonicalArtifact(artifacts, prepared.grantRef!));
  const cacheHeader = await readCanonicalArtifact<{ resultSourceRef: string }>(artifacts, packageCacheManifestRef);
  const evidence = (await import('../kernel/dependency-claim.js')).decodeDependencyClaimEvidence(await readCanonicalArtifact(artifacts, claim.evidenceRef));
  const source = await readRetainedDependencyCandidate(driver, artifacts, item.runId, { candidateItemId: request.candidateItemId,
    sourceCheckpointId: evidence.sourceCheckpointId, dependencyPlanRef: item.planRef, resultSourceRef: request.resultSourceRef,
    releaseKeys: artifacts.releaseTrustRoots() });
  requireEqual(source.run, cut.run, 'dependency actual complete recovery Run');
  requireEqual(source.spec, cut.runSpec, 'dependency actual immutable Run spec');
  requireEqual(source.journal.filter(row => row.opId === item.opId && row.attempt === item.attempt), rows, 'dependency actual original acquisition rows');
  if (cacheHeader.resultSourceRef !== source.candidate.resultSourceRef || request.dependencyPlanRef !== item.planRef || request.resultSourceRef !== source.candidate.resultSourceRef)
    throw new TypeError('dependency ready substitutes its original candidate');
  let history: Awaited<ReturnType<typeof readDependencyScriptsTemplateHistoryData>> | undefined;
  if (source.plan.allowInstallScripts) {
    if (!target.scriptAuthorizationTemplateRef) throw new TypeError('dependency lifecycle has no original exact consent');
    history = await readDependencyScriptsTemplateHistoryData(driver, artifacts, { bundle: source.bundle, releaseKeys: artifacts.releaseTrustRoots() },
      { runId: item.runId, templateRef: target.scriptAuthorizationTemplateRef });
  }
  const planned = planDependencyInvocation({ runId: source.run.id, principalId: source.principalId, policyRef: source.spec.policyRef,
    frontierRef: request.frontierRef, assemblyRef: source.spec.assemblyRef, workspaceIdentityRef: source.session.workspaceIdentityRef,
    workspaceIdentityDigest: source.workspaceIdentity.identityDigest, candidateItemId: source.candidate.itemId, candidateOrdinal: source.candidateOrdinal,
    resultSourceRef: request.resultSourceRef, sourceDigest: source.candidate.sourceDigest, dependencyPolicyRef: source.spec.dependencyPolicyRef!,
    policy: source.policy, dependencyPlanRef: item.planRef, plan: source.plan, conditions: source.conditions, deadlineAt: source.run.deadlineAt,
    ...(history ? { scripts: { template: history.template, templateRef: history.templateRef } } : {}) });
  requireEqual(request, planned.request, 'dependency original complete acquisition request');
  requireEqual(target, planned.target, 'dependency original whole source target');
  requireEqual(grant, planned.grant(grant.issuedAt, grant.expiresAt), 'dependency original policy or exact script consent');
  if (prepared.timestamp < grant.issuedAt || claim.timestamp < prepared.timestamp || claim.timestamp >= grant.expiresAt || item.createdAt < terminal.timestamp)
    throw new TypeError('dependency original dispatch is outside its real grant or completion');
  const captured = await readDependencyProcessCapture(driver, artifacts, { captureRef, prepared, claim,
    assembly: source.assembly, observedAt: item.createdAt });
  const originalOwner = claim.stateOwnerEpoch && readStateOwner(driver, claim.stateOwnerEpoch);
  if (!originalOwner || originalOwner.supervisorInstanceId !== claim.supervisorInstanceId) throw new TypeError('dependency recipe lost its original StateOwner');
  const environment = await readRetainedDependencyLaunchEnvironment(artifacts, originalOwner, cut.runSpec, captured.capture.sandboxLaunchSpecRef);
  requireEqual(environment.bundle, source.bundle, 'dependency original complete signed execution bundle');
  requireEqual(environment.assembly, source.assembly, 'dependency original assembly');
  const toolchain = source.signed.toolchain;
  requireEqual(captured.spec.executable, { kind: 'guest_toolchain', guestToolchainManifestRef: toolchain.manifestRef,
    guestToolchainManifestDigest: toolchain.manifest.manifestDigest, toolId: 'node', role: 'package_manager', executionPath: '/usr/bin/node',
    executableDigest: toolchain.manifest.node.digest }, 'dependency original signed Node interpreter');
  requireEqual(captured.spec.runtime.toolchain, { kind: 'guest_toolchain', guestToolchainManifestRef: toolchain.manifestRef,
    guestToolchainManifestDigest: toolchain.manifest.manifestDigest, guestImageRef: toolchain.manifest.guestImageRef,
    guestImageDigest: toolchain.manifest.guestImageDigest }, 'dependency original signed guest data');
  if (environment.spec.filesystem.kind !== 'run_generation') throw new TypeError('dependency original historical recipe has no generation');
  requireEqual(captured.spec.mounts, npmDependencyMounts(claim.dispatchId!, environment.spec.filesystem.generationRef,
    source.signed.adapter.digest, source.signed.image.digest), 'dependency original exact signed adapter, image and managed roots');
  if (captured.capture.captureDigest !== proof.captureDigest || !success && terminal.evidenceDigest !== proof.captureDigest ||
      success && (captured.capture.terminationReason !== 'exit' || captured.capture.exitCode !== 0))
    throw new TypeError('dependency readiness is not an original successful complete process result');
  const cache = await readDependencyPackageCache(artifacts, { manifestRef: packageCacheManifestRef, runId: item.runId,
    resultSourceRef: request.resultSourceRef, dependencyPlan: source.plan, packages: source.data.packages });
  for (const [index, entry] of cache.entries.entries()) {
    for (const attempt of entry.fetchAttempts) {
      const observation = decodeDependencyPackageFetchObservation(await readCanonicalArtifact(artifacts, attempt.observationDigest));
      if (observation.runId !== item.runId || observation.opId !== item.opId || observation.invocationAttempt !== item.attempt ||
          observation.dispatchId !== claim.dispatchId || observation.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest ||
          observation.packageIndex !== index || observation.attempt !== attempt.attempt || observation.receivedBytes !== attempt.receivedBytes ||
          observation.observedAt < claim.timestamp || observation.observedAt > terminal.timestamp ||
          attempt.outcome !== (observation.kind === 'complete' ? 'completed' : observation.kind) ||
          observation.kind === 'http_error' && observation.status !== attempt.httpStatus)
        throw new TypeError('dependency cache substitutes its original same-claim GET observations');
    }
  }
  const checkpoint = readCheckpoint(driver, checkpointId), snapshot = decodeWorkspaceGenerationSnapshotEvidence(await readCanonicalArtifact(artifacts, proof.snapshotEvidenceRef));
  const row = source.items.find(row => row.itemId === item.itemId), itemRef = canonicalSha256(item);
  if (!row || row.payloadRef !== itemRef || row.createdAt !== item.createdAt || checkpoint.runId !== item.runId || checkpoint.createdAt < item.createdAt ||
      checkpoint.runItemSeq !== row.itemSeq || checkpoint.journalSeq !== terminal.seq || checkpoint.workspaceStateRef !== proof.workspaceStateRef ||
      snapshot.purpose !== 'sealed_to_checkpoint' || snapshot.checkpointId !== checkpoint.id || snapshot.workspaceStateRef !== checkpoint.workspaceStateRef ||
      snapshot.observedAt < captured.death.observedAt || snapshot.observedAt > checkpoint.createdAt)
    throw new TypeError('dependency ready lacks its original atomic item, Journal and post-effect seal');
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  const contextItems = await artifacts.mapReads(source.items.slice(0, row.itemSeq), async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
    item: await readCanonicalArtifact<import('../kernel/types.js').ContinuationItem>(artifacts, row.payloadRef) }));
  validateContextItems(context, contextItems);
  if (context.throughItemSeq !== checkpoint.runItemSeq || context.runId !== item.runId || context.assemblyRef !== source.spec.assemblyRef ||
      context.admittedContextRef !== source.spec.admittedContextRef) throw new TypeError('dependency ready lost its original whole context prefix');
  const state = decodeWorkspaceState(await readCanonicalArtifact(artifacts, checkpoint.workspaceStateRef));
  const entries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, state.entriesRef));
  const before = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, source.workspace.entriesRef));
  const unmanaged = (value: WorkspaceEntryManifest) => value.entries.filter(entry => !isManagedNodeDependencyPath(entry.path));
  const after = await readCandidateSource(artifacts, source.spec, checkpoint.workspaceStateRef);
  const sourceUnchanged = canonicalSha256(unmanaged(before)) === canonicalSha256(unmanaged(entries)) &&
    state.privateGitStateRef === source.workspace.privateGitStateRef && after.sourceRef === request.resultSourceRef &&
    after.source.manifestDigest === source.candidate.sourceDigest;
  if (proof.sourceAfterRef !== after.sourceRef || proof.sourceAfterDigest !== after.source.manifestDigest ||
      dependencyManagedTreeDigest(entries, success) !== proof.installedTreeDigest)
    throw new TypeError('dependency result substitutes its actual complete post-effect source or managed tree');
  if (success ? !sourceUnchanged : item.failureKind !== (sourceUnchanged ? 'process_failed' : 'source_integrity') ||
      sourceUnchanged && captured.capture.terminationReason === 'exit' && captured.capture.exitCode === 0)
    throw new TypeError('dependency result does not reproduce its actual success or failure');
  const generations = await artifacts.mapReads(source.generations, async generation => generation.phase === 'retired'
    ? (await readRetiredGenerationSource(driver, artifacts, { run: cut.run, spec: cut.runSpec, assembly: source.assembly, generation })).source : generation);
  const generation = generations.find(generation => generation.phase === 'sealed' && generation.generationRef === snapshot.generationRef &&
    generation.snapshotEvidenceRef === proof.snapshotEvidenceRef);
  if (!generation || generation.phase !== 'sealed') throw new TypeError('dependency ready has no original sealed generation');
  const launch = source.workers.find(launch => launch.launchId === captured.spec.owner.workerLaunchId);
  if (!launch || launch.phase !== 'retired' || launch.generationWriteState !== 'sealed' || launch.workspaceGenerationRef !== generation.generationRef ||
      !launch.retirementEvidenceRef) throw new TypeError('dependency ready has no original complete parent retirement');
  const originalParentDeath = await readCanonicalArtifact(artifacts, proof.parentRetirementEvidenceRef);
  const currentParentDeath = await readCanonicalArtifact(artifacts, launch.retirementEvidenceRef!);
  validateMatchingWorkerDeath(originalParentDeath, currentParentDeath, 'dependency original parent continuous retirement');
  await validateRetainedWorkerSeal(driver, artifacts, { run: cut.run, spec: cut.runSpec, assembly: source.assembly, launch, generation });
  if (!success && item.failureKind === 'source_integrity') {
    if (!proof.integrityEvidenceRef || !proof.integrityEvidenceDigest) throw new TypeError('dependency drift lacks its original protected-workspace evidence');
    const integrity = decodeDependencyIntegrityEvidence(await readCanonicalArtifact(artifacts, proof.integrityEvidenceRef));
    const { observedAt, inspectorIdentityRef, inspectorIdentityDigest, evidenceDigest, ...bound } = integrity;
    requireEqual(bound, { schemaVersion: 1, format: 'cliq-dependency-integrity-evidence-v1', runId: cut.run.id,
      opId: item.opId, attempt: item.attempt, dependencyPlanRef: item.planRef, claimEvidenceRef: claim.evidenceRef,
      captureRef, workspaceGenerationRef: generation.generationRef, workspaceBeforeRef: source.checkpoint.workspaceStateRef,
      workspaceAfterRef: checkpoint.workspaceStateRef, sourceBeforeRef: request.resultSourceRef, sourceBeforeDigest: source.candidate.sourceDigest,
      sourceAfterRef: after.sourceRef, sourceAfterDigest: after.source.manifestDigest,
      observationSource: 'trusted_out_of_containment_rehash', changedEntryDigests: dependencyProtectedEntryChanges(before, entries),
      ...(source.workspace.privateGitStateRef ? { privateGitBeforeRef: source.workspace.privateGitStateRef } : {}),
      ...(state.privateGitStateRef ? { privateGitAfterRef: state.privateGitStateRef } : {}) }, 'dependency actual protected workspace drift');
    if (evidenceDigest !== proof.integrityEvidenceDigest || observedAt < captured.capture.endedAt || observedAt > terminal.timestamp)
      throw new TypeError('dependency integrity evidence is outside its original real completion');
    await readSupervisorInspector(artifacts, originalOwner, source.assembly, { inspectorIdentityRef, inspectorIdentityDigest, observedAt });
  } else if (proof.integrityEvidenceRef !== undefined || proof.integrityEvidenceDigest !== undefined)
    throw new TypeError('dependency process outcome cannot carry another integrity cause');
  const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, terminal.budgetSettlementRef));
  requireEqual(prepared.budgetDelta, { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, 'dependency one-operation reservation');
  requireEqual(claim.budgetDelta, { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, 'dependency claim has no second charge');
  requireEqual(terminal.budgetDelta, prepared.budgetDelta, 'dependency original single charge');
  if (settlement.runId !== item.runId || settlement.opId !== item.opId || settlement.attempt !== item.attempt || settlement.preparedJournalSeq !== prepared.seq ||
      settlement.terminalJournalSeq !== terminal.seq || settlement.terminalPhase !== (success ? 'completed' : 'failed')) throw new TypeError('dependency ready lost its exact unique settlement');
  history?.assertUnchanged(driver); source.assertUnchanged(driver); artifacts.assertReadActive();
  return Object.freeze({ item: immutableSnapshot(item), source, cache, captured, proof, checkpoint, snapshot, workspace: state, entries,
    assertUnchanged: source.assertUnchanged });
}

export async function readAcquiredDependencyReady(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: Cut,
  supplied: Extract<DependencyReadyItem, { origin: 'acquired' }>) {
  const result = await readDependencyProcessRetirement(driver, artifacts, cut, supplied);
  if (result.item.kind !== 'dependency_ready' || result.item.origin !== 'acquired') throw new TypeError('dependency result is not acquired readiness');
  return { ...result, item: result.item };
}
export async function readFailedDependencyResult(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: Cut, supplied: DependencyFailureItem) {
  if (supplied.failureKind === 'acquisition_failed')
    return (await import('./dependency-acquisition-history.js')).readFailedDependencyAcquisition(driver, artifacts, cut, supplied);
  const result = await readDependencyProcessRetirement(driver, artifacts, cut, supplied);
  if (result.item.kind !== 'dependency_failure') throw new TypeError('dependency result is not an original known failure');
  return { ...result, item: result.item };
}
