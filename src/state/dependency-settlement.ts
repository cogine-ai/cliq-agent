import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { digestOmitting } from '../kernel/identity.js';
import type { DependencyReadyItem, DependencyFailureItem } from '../kernel/dependency.js';
import type { Run } from '../kernel/types.js';
import type { ToolCheckpointProof } from '../kernel/tool-authorization.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { planContinuationCommit } from './continuation-commit.js';
import { decodeWorkspaceEntries, decodeWorkspaceState } from './decoders.js';
import { readRetainedDependencyCandidate } from './dependency-candidate.js';
import { assertDependencySettlementForInvocation, publishDependencyResultCapture, readDependencySettlementInput,
  type DependencyInvocationOwner } from './dependency-invocation-owner.js';
import { assertDependencyUnmanagedEntries, dependencyManagedTreeDigest, dependencyReadyCheckpointId, dependencyReadyItemId, dependencyFailureItemId,
  decodeDependencyRetirement, type DependencyRetirementV1 } from './dependency-retirement.js';
import { KernelStorageError } from './errors.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { prepareCandidateSource } from './result-source.js';
import { decodeDependencyIntegrityEvidence, dependencyProtectedEntryChanges } from '../kernel/dependency-integrity.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { readRun } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { prepareToolCheckpoint, type NativeWorkerRetirement } from './tool-checkpoint.js';
import { prepareDependencyInvocationSettlement, type SettlementContinuation } from './reducers/invocation.js';
import { assertDependencyAcquisitionFailure, publishDependencyAcquisitionFailure } from './dependency-invocation-owner.js';
import { decodeDependencyAcquisitionRetirement, type DependencyAcquisitionRetirementV1 } from '../kernel/dependency-acquisition.js';

const brand = Symbol('original received dependency settlement');
export type OwnedDependencySettlement = Readonly<{ readonly [brand]: true }>;
type Original = { driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext;
  input: { runId: string; opId: string; attempt: number };
  terminal: ({ phase: 'completed'; resultRef: string; receiptRef: string } |
    { phase: 'failed'; errorRef: string; evidenceRef: string; evidenceDigest: string; requireClaim: true }) &
    { consumed: { modelTokens: 0; costMicros: 0; toolCalls: 1; repairAttempts: 0 } };
  continuation: SettlementContinuation; validateSnapshot(connection: SqliteConnection, run: Run): void };
const originals = new WeakMap<object, Original>();
export function assertOwnedDependencySettlement(driver: SqliteDriver, owner: StateOwnerContext, token: unknown) {
  const original = token && typeof token === 'object' ? originals.get(token) : undefined;
  if (!original || original.driver !== driver || original.owner !== owner) throw new TypeError('dependency completion requires its genuine original owner');
  return original;
}
const stableRun = ({ revision: _revision, updatedAt: _time, stopIntentRef: _stop, cancelRequested: _cancel,
  parentCancellationRef: _parentCancel, ...run }: Run) => run;

/** One retained successful physical result and parent seal. The caller never
 * supplies output bytes, a success flag, arbitrary continuation or ready item.
 * A received completion must own this call before its first await. */
export async function prepareDependencyReceivedSettlement(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  invocation: DependencyInvocationOwner, postEffect: ToolCheckpointProof, reobserve?: NativeWorkerRetirement) {
  const capture = await publishDependencyResultCapture(driver, owner, invocation);
  const held = readDependencySettlementInput(driver, owner, invocation);
  const original = assertDependencySettlementForInvocation(driver, owner, invocation, driver);
  postEffect = immutableSnapshot(postEffect);
  let checked = await readRetainedDependencyCandidate(driver, artifacts, invocation.runId, {
    candidateItemId: held.request.candidateItemId, sourceCheckpointId: held.input.sourceCheckpointId,
    dependencyPlanRef: held.request.dependencyPlanRef, resultSourceRef: held.request.resultSourceRef, releaseKeys: held.keys });
  const initialRun = checked.run;
  const state = decodeWorkspaceState(await readCanonicalArtifact(artifacts, postEffect.workspaceStateRef));
  const entries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, state.entriesRef));
  const before = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, checked.workspace.entriesRef));
  const after = await (await prepareCandidateSource(artifacts, checked.spec, postEffect.workspaceStateRef)).publish();
  if (state.runId !== invocation.runId) throw new KernelStorageError('ARTIFACT_MISMATCH', 'dependency post-effect workspace belongs to another Run');
  const unmanaged = (value: typeof entries) => value.entries.filter(entry => entry.path !== 'node_modules' && !entry.path.startsWith('node_modules/'));
  const sourceUnchanged = canonicalSha256(unmanaged(before)) === canonicalSha256(unmanaged(entries)) &&
    state.privateGitStateRef === checked.workspace.privateGitStateRef && after.sourceRef === held.request.resultSourceRef &&
    after.source.manifestDigest === held.target.sourceDigest;
  const processSucceeded = capture.capture.terminationReason === 'exit' && capture.capture.exitCode === 0;
  const success = sourceUnchanged && processSucceeded;
  const failureKind = sourceUnchanged ? 'process_failed' as const : 'source_integrity' as const;
  let integrity: Awaited<ReturnType<ArtifactCatalog['publishCanonical']>> | undefined;
  if (!sourceUnchanged) {
    if (held.spec.filesystem.kind !== 'run_generation') throw new TypeError('dependency drift has no original physical generation');
    const inspector = supervisorInspectorIdentity(assertActiveStateOwner(driver, owner));
    const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
    const value = { schemaVersion: 1, format: 'cliq-dependency-integrity-evidence-v1', runId: invocation.runId, opId: invocation.opId,
      attempt: invocation.attempt, dependencyPlanRef: held.request.dependencyPlanRef, claimEvidenceRef: capture.capture.claimEvidenceRef,
      captureRef: capture.artifact.ref, workspaceGenerationRef: held.spec.filesystem.generationRef,
      workspaceBeforeRef: checked.checkpoint.workspaceStateRef, workspaceAfterRef: postEffect.workspaceStateRef,
      sourceBeforeRef: held.request.resultSourceRef, sourceBeforeDigest: held.target.sourceDigest,
      sourceAfterRef: after.sourceRef, sourceAfterDigest: after.source.manifestDigest,
      observationSource: 'trusted_out_of_containment_rehash', changedEntryDigests: dependencyProtectedEntryChanges(before, entries),
      ...(checked.workspace.privateGitStateRef ? { privateGitBeforeRef: checked.workspace.privateGitStateRef } : {}),
      ...(state.privateGitStateRef ? { privateGitAfterRef: state.privateGitStateRef } : {}),
      inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, observedAt: sampleCanonicalNow(), evidenceDigest: '' };
    value.evidenceDigest = digestOmitting(value, 'evidenceDigest'); decodeDependencyIntegrityEvidence(value);
    integrity = await artifacts.publishCanonical(value, value.format);
    after.metadata.push(inspectorArtifact);
  }
  const installedTreeDigest = dependencyManagedTreeDigest(entries, success);
  const checkpointId = dependencyReadyCheckpointId(invocation.runId, invocation.opId, invocation.attempt);
  const seal = await prepareToolCheckpoint(driver, artifacts, owner, { run: checked.run, spec: checked.spec, assembly: checked.assembly,
    checkpointId, observedAt: capture.capture.endedAt, postEffect }, reobserve);
  let graph: ReturnType<typeof planContinuationCommit> | undefined;
  const proof: DependencyRetirementV1 = { schemaVersion: 1, format: 'cliq-dependency-retirement-v1', runId: invocation.runId,
    opId: invocation.opId, attempt: invocation.attempt, dispatchId: original.claim.dispatchId!, leaseEpoch: original.claim.leaseEpoch,
    dependencyPlanRef: held.request.dependencyPlanRef, packageCacheManifestRef: original.cache.artifact.ref, captureRef: capture.artifact.ref,
    captureDigest: capture.capture.captureDigest, checkpointId, workspaceStateRef: postEffect.workspaceStateRef,
    snapshotEvidenceRef: postEffect.snapshotEvidenceRef, parentRetirementEvidenceRef: postEffect.retirementEvidenceRef,
    sourceAfterRef: after.sourceRef, sourceAfterDigest: after.source.manifestDigest, installedTreeDigest,
    ...(integrity ? { integrityEvidenceRef: integrity.ref,
      integrityEvidenceDigest: decodeDependencyIntegrityEvidence(await readCanonicalArtifact(artifacts, integrity.ref)).evidenceDigest } : {}), evidenceDigest: '' };
  proof.evidenceDigest = digestOmitting(proof, 'evidenceDigest'); decodeDependencyRetirement(proof);
  const proofPlan = planCanonicalArtifact(proof, proof.format);
  const receipt = await artifacts.publishBytes(proofPlan.bytes, proofPlan.mediaType, proofPlan.schemaKind);
  const consumed = { modelTokens: 0 as const, costMicros: 0 as const, toolCalls: 1 as const, repairAttempts: 0 as const };
  const terminal: Original['terminal'] = success
    ? { phase: 'completed', resultRef: capture.artifact.ref, receiptRef: receipt.ref, consumed }
    : { phase: 'failed', errorRef: receipt.ref, evidenceRef: capture.artifact.ref, evidenceDigest: capture.capture.captureDigest, requireClaim: true, consumed };
  const validateSnapshot = (connection: SqliteConnection, current: Run) => {
    assertActiveStateOwner(connection, owner); checked.assertUnchanged(connection);
    requireEqual(current, checked.run, 'dependency fully checked current completion cut');
    original.validateSnapshot(connection, current);
  };
  const continuation: SettlementContinuation = async ({ settlement }) => {
    if (!graph) {
      const item: DependencyReadyItem | DependencyFailureItem = success
        ? { schemaVersion: 1, kind: 'dependency_ready', itemId: dependencyReadyItemId(invocation.runId, invocation.opId, invocation.attempt),
            runId: invocation.runId, origin: 'acquired', opId: invocation.opId, attempt: invocation.attempt,
            planRef: held.request.dependencyPlanRef, packageCacheManifestRef: original.cache.artifact.ref, readyCheckpointId: checkpointId,
            installedTreeDigest, createdAt: settlement.settledAt }
        : { schemaVersion: 1, kind: 'dependency_failure', itemId: dependencyFailureItemId(invocation.runId, invocation.opId, invocation.attempt),
            runId: invocation.runId, opId: invocation.opId, attempt: invocation.attempt, planRef: held.request.dependencyPlanRef,
            receiptRef: receipt.ref, checkpointId, failureKind, createdAt: settlement.settledAt };
      const existingItems = await artifacts.mapReads(checked.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
        item: await readCanonicalArtifact<import('../kernel/types.js').ContinuationItem>(artifacts, row.payloadRef) }));
      graph = planContinuationCommit(artifacts, { context: checked.context, existingItems, items: [item], checkpointId,
        workspaceStateRef: postEffect.workspaceStateRef, frontier: { schemaVersion: 1, kind: 'verify', phase: success ? 'verifiers' : 'dependencies',
          candidateItemId: checked.candidate.itemId, resultSourceRef: held.request.resultSourceRef, verifierPlanRef: checked.verifierPlanRef,
          dependencyPlanRef: held.request.dependencyPlanRef, nextVerifierIndex: 0,
          afterPass: checked.spec.operation === 'delivery' ? 'delivery_approval' : 'finalize' }, artifacts: [proofPlan] });
    }
    const plan = await graph.publish(); await seal.refresh();
    return { get metadata() { return [...capture.metadata, ...original.cache.metadata, ...after.metadata, ...(integrity ? [integrity] : []), ...plan.metadata, ...seal.metadata]; },
      validate: validateSnapshot, commit(connection, run, entry, at) {
        if ((success ? entry.phase !== 'completed' || entry.resultRef !== capture.artifact.ref || entry.receiptRef !== receipt.ref :
            entry.phase !== 'failed' || entry.errorRef !== receipt.ref || entry.evidenceRef !== capture.artifact.ref || entry.evidenceDigest !== capture.capture.captureDigest) ||
            entry.timestamp < capture.capture.endedAt) throw new TypeError('dependency settlement changed its original result');
        seal.commit(connection, run, at); plan.commit(connection, run, entry.seq, at);
      } };
  };
  const token = Object.freeze({ [brand]: true as const });
  originals.set(token, { driver, artifacts, owner, input: { runId: invocation.runId, opId: invocation.opId, attempt: invocation.attempt },
    terminal, continuation, validateSnapshot });
  const settlement = prepareDependencyInvocationSettlement(driver, artifacts, owner, token);
  return { outcome: success ? 'ready' as const : 'failed' as const, async settle(expectedRunRevision: number) {
    const recovery = await readRecoveryClosure(driver, artifacts, invocation.runId);
    requireEqual(stableRun(recovery.run), stableRun(initialRun), 'dependency completion retains its original Run and frontier');
    if (recovery.run.revision !== expectedRunRevision || recovery.run.revision < initialRun.revision ||
        recovery.run.revision !== initialRun.revision && !recovery.run.stopIntentRef)
      throw new KernelStorageError('REVISION_CONFLICT', 'dependency completion requires its current fully authenticated Stop cut');
    checked = await readRetainedDependencyCandidate(driver, artifacts, invocation.runId, { candidateItemId: held.request.candidateItemId,
      sourceCheckpointId: held.input.sourceCheckpointId, dependencyPlanRef: held.request.dependencyPlanRef,
      resultSourceRef: held.request.resultSourceRef, releaseKeys: held.keys });
    requireEqual(checked.run, recovery.run, 'dependency unchanged complete Stop source cut');
    return settlement.settle(expectedRunRevision);
  } };
}

/** Original GET owner positively closed before any process peer existed.
 * This branch has no output result, output ACK or invented namespace death. */
export async function prepareDependencyAcquisitionFailureSettlement(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  invocation: DependencyInvocationOwner, postEffect: ToolCheckpointProof, reobserve?: NativeWorkerRetirement) {
  const publication = await publishDependencyAcquisitionFailure(driver, owner, invocation);
  const held = assertDependencyAcquisitionFailure(driver, owner, invocation, driver);
  let checked = await readRetainedDependencyCandidate(driver, artifacts, invocation.runId, { candidateItemId: held.request.candidateItemId,
    sourceCheckpointId: held.input.sourceCheckpointId, dependencyPlanRef: held.request.dependencyPlanRef,
    resultSourceRef: held.request.resultSourceRef, releaseKeys: held.keys });
  const initialRun = checked.run;
  postEffect = immutableSnapshot(postEffect);
  // A process was never acquired. The original parent still must actually
  // retire and prove the full M unchanged, including the managed subtree.
  if (postEffect.workspaceStateRef !== checked.checkpoint.workspaceStateRef)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'unexecuted dependency acquisition cannot adopt a workspace mutation');
  const checkpointId = dependencyReadyCheckpointId(invocation.runId, invocation.opId, invocation.attempt);
  const seal = await prepareToolCheckpoint(driver, artifacts, owner, { run: checked.run, spec: checked.spec, assembly: checked.assembly,
    checkpointId, observedAt: publication.evidence.observedAt, postEffect }, reobserve);
  const proof: DependencyAcquisitionRetirementV1 = { schemaVersion: 1, format: 'cliq-dependency-acquisition-retirement-v1',
    runId: invocation.runId, opId: invocation.opId, attempt: invocation.attempt, dependencyPlanRef: held.request.dependencyPlanRef,
    acquisitionClosureRef: publication.artifact.ref, acquisitionClosureDigest: publication.evidence.evidenceDigest, checkpointId,
    workspaceStateRef: postEffect.workspaceStateRef, snapshotEvidenceRef: postEffect.snapshotEvidenceRef,
    parentRetirementEvidenceRef: postEffect.retirementEvidenceRef, evidenceDigest: '' };
  proof.evidenceDigest = digestOmitting(proof, 'evidenceDigest'); decodeDependencyAcquisitionRetirement(proof);
  const proofPlan = planCanonicalArtifact(proof, proof.format);
  const receipt = await artifacts.publishBytes(proofPlan.bytes, proofPlan.mediaType, proofPlan.schemaKind);
  const terminal: Original['terminal'] = { phase: 'failed', errorRef: receipt.ref, evidenceRef: publication.artifact.ref,
    evidenceDigest: publication.evidence.evidenceDigest, requireClaim: true,
    consumed: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 } };
  const validateSnapshot = (connection: SqliteConnection, run: Run) => {
    checked.assertUnchanged(connection); requireEqual(run, checked.run, 'dependency original acquisition failure Run');
    held.validateSnapshot(connection, run);
  };
  let graph: ReturnType<typeof planContinuationCommit> | undefined;
  const continuation: SettlementContinuation = async ({ settlement }) => {
    if (!graph) {
      const item: DependencyFailureItem = { schemaVersion: 1, kind: 'dependency_failure', runId: invocation.runId,
        itemId: dependencyFailureItemId(invocation.runId, invocation.opId, invocation.attempt), opId: invocation.opId,
        attempt: invocation.attempt, planRef: held.request.dependencyPlanRef, receiptRef: receipt.ref, checkpointId,
        failureKind: 'acquisition_failed', createdAt: settlement.settledAt };
      const existingItems = await artifacts.mapReads(checked.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
        item: await readCanonicalArtifact<import('../kernel/types.js').ContinuationItem>(artifacts, row.payloadRef) }));
      graph = planContinuationCommit(artifacts, { context: checked.context, existingItems, items: [item], checkpointId,
        workspaceStateRef: postEffect.workspaceStateRef, frontier: { schemaVersion: 1, kind: 'verify', phase: 'dependencies',
          candidateItemId: checked.candidate.itemId, resultSourceRef: held.request.resultSourceRef, verifierPlanRef: checked.verifierPlanRef,
          dependencyPlanRef: held.request.dependencyPlanRef, nextVerifierIndex: 0,
          afterPass: checked.spec.operation === 'delivery' ? 'delivery_approval' : 'finalize' }, artifacts: [proofPlan] });
    }
    const plan = await graph.publish(); await seal.refresh();
    return { get metadata() { return [...publication.metadata, receipt, ...plan.metadata, ...seal.metadata]; }, validate: validateSnapshot,
      commit(connection, run, entry, at) {
        if (entry.phase !== 'failed' || entry.errorRef !== receipt.ref || entry.evidenceRef !== publication.artifact.ref ||
            entry.evidenceDigest !== publication.evidence.evidenceDigest || entry.timestamp < publication.evidence.observedAt)
          throw new TypeError('dependency acquisition settlement substitutes its original closed owner');
        seal.commit(connection, run, at); plan.commit(connection, run, entry.seq, at);
      } };
  };
  const token = Object.freeze({ [brand]: true as const });
  originals.set(token, { driver, artifacts, owner, input: { runId: invocation.runId, opId: invocation.opId, attempt: invocation.attempt },
    terminal, continuation, validateSnapshot });
  const settlement = prepareDependencyInvocationSettlement(driver, artifacts, owner, token);
  return { async settle(expectedRunRevision: number) {
    const recovery = await readRecoveryClosure(driver, artifacts, invocation.runId);
    requireEqual(stableRun(recovery.run), stableRun(initialRun), 'dependency acquisition retains its original source and frontier');
    if (recovery.run.revision !== expectedRunRevision || recovery.run.revision < initialRun.revision ||
        recovery.run.revision !== initialRun.revision && !recovery.run.stopIntentRef)
      throw new KernelStorageError('REVISION_CONFLICT', 'dependency acquisition requires its original authenticated Stop cut');
    checked = await readRetainedDependencyCandidate(driver, artifacts, invocation.runId, { candidateItemId: held.request.candidateItemId,
      sourceCheckpointId: held.input.sourceCheckpointId, dependencyPlanRef: held.request.dependencyPlanRef,
      resultSourceRef: held.request.resultSourceRef, releaseKeys: held.keys });
    requireEqual(checked.run, recovery.run, 'dependency acquisition unchanged complete Stop source cut');
    return settlement.settle(expectedRunRevision);
  } };
}
