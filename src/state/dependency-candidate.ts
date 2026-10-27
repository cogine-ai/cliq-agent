// Complete original candidate data shared with approval/history consumers.
// Neither reader runs recovery, authorizes a release nor opens a generation.
import { canonicalSha256 } from '../kernel/canonical.js';
import { runApplyIntentDigest } from '../kernel/control-apply.js';
import { assertArtifactRef, normalizeBoundedText, parseCanonicalTime } from '../kernel/identity.js';
import type { ContinuationItem, RunFrontier, RunItemReferenceV1, WorkspaceGenerationStateV1, WorkspaceGenerationSnapshotEvidenceV1, WorkerLaunch } from '../kernel/types.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readChildAdmission } from './child-admission.js';
import { decodeContextManifest, decodeRunSpec, decodeWorkspaceIdentity, decodeWorkspaceState } from './decoders.js';
import { readDependencySignedAssets } from './dependency-execution-data.js';
import { readCandidateDependencyPlan } from './dependency-plan.js';
import { readFrozenDependencyPolicy } from './dependency-policy-data.js';
import { readDependencyScriptSourceConditions } from './dependency-script-source.js';
import { validateDeliveryRecoveryData } from './delivery-recovery.js';
import { KernelStorageError } from './errors.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { readCandidateVerifierPlan } from './final-candidate-plan.js';
import { readRetainedFinalCandidateSource } from './final-candidate-recovery.js';
import { readRetiredGenerationSource } from './generation-retirement.js';
import { readRetainedJournalData } from './recovery-closure.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import { readDeliveryRunAdmission } from './reducers/delivery-admission.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { decodeFinalCandidateItem, decodeVerifierPlan } from './result-artifacts.js';
import { readCandidateSource } from './result-source.js';
import { checkpointFromRow, readCheckpoint, readControlRequest, readRun, readSession, readSessionPrincipalId } from './rows.js';
import { readRootRunAdmissionOrigin } from './run-admission-origin.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { readSourceInspectionAttempt } from './source-inspection.js';
import { validateRetainedWorkerSeal } from './tool-checkpoint.js';

type Options = { releaseKeys: readonly ReleaseTrustKey[]; signal?: AbortSignal };
type Locator = { candidateItemId: string; sourceCheckpointId: string; dependencyPlanRef: string; resultSourceRef: string };
function invalid(reason: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', `dependency candidate ${reason}`); }

const itemRows = (connection: SqliteConnection | SqliteDriver, runId: string) => connection.prepare(
  'SELECT item_id,item_seq,kind,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
  .all<{ item_id: string; item_seq: unknown; kind: string; payload_ref: string; created_at: string }>(runId)
  .map(row => ({ ...row, item_seq: Number(row.item_seq) }));
const checkpointRows = (connection: SqliteConnection | SqliteDriver, runId: string) => connection.prepare(
  'SELECT * FROM checkpoints WHERE run_id=? ORDER BY rowid').all(runId).map(checkpointFromRow);
function databaseCut(connection: SqliteConnection | SqliteDriver, runId: string) {
  const run = readRun(connection, runId), session = readSession(connection, run.sessionId), principalId = readSessionPrincipalId(connection, session.id);
  const principal = connection.prepare('SELECT principal_id FROM runs WHERE id=?').get<{ principal_id: string }>(runId);
  if (!principal || principal.principal_id !== principalId) invalid('has no original Session principal');
  const admission = connection.prepare(`SELECT principal_id,admission_method,admission_key,admission_intent_digest,
    admitted_request_digest,admission_request_id FROM runs WHERE id=?`).get(runId);
  return { run, session, principalId, admission, rows: itemRows(connection, runId), checkpoints: checkpointRows(connection, runId),
    journal: readInvocationJournal(connection, runId), generations: readWorkspaceGenerationsForRun(connection, runId),
    workers: readWorkerLaunchesForRun(connection, runId), allocations: readChildAllocationsForRun(connection, runId) };
}

/** Current selection first requires a genuinely retired, worker-free source
 * cut. The caller must use the existing retirement lifecycle and reread when
 * an original worker is still active; clearing a row pointer is insufficient. */
export async function readCurrentDependencyCandidate(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string, options: Options) {
  const reads = options.signal ? artifacts.withReadSignal(options.signal) : artifacts;
  const run = readRun(driver, runId);
  if (run.status !== 'queued' || run.nextStep !== 'verify' || !run.frontierRef || run.activeWorkerLaunchId ||
      run.cancelRequested || run.stopIntentRef || run.waitingReason || run.waitingOnRef)
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'dependency approval requires its original worker-free candidate cut');
  const frontier = await readCanonicalArtifact<RunFrontier>(reads, run.frontierRef);
  if (frontier.kind !== 'verify' || frontier.phase !== 'dependencies' || frontier.nextVerifierIndex !== 0 || !frontier.dependencyPlanRef ||
      !exactKeys(frontier, ['schemaVersion', 'kind', 'phase', 'candidateItemId', 'resultSourceRef', 'verifierPlanRef',
        'dependencyPlanRef', 'nextVerifierIndex', 'afterPass'])) invalid('has no exact original dependency frontier');
  const selected = await readRetainedDependencyCandidate(driver, reads, runId, { candidateItemId: frontier.candidateItemId,
    sourceCheckpointId: run.latestCheckpointId, dependencyPlanRef: frontier.dependencyPlanRef,
    resultSourceRef: frontier.resultSourceRef, ...options });
  requireEqual(selected.run, run, 'current dependency candidate Run');
  if (selected.workers.some(worker => worker.phase !== 'retired') ||
      selected.generations.some(generation => !['sealed', 'retired', 'quarantined'].includes(generation.phase)))
    invalid('retains an original nonretired worker or mutable generation');
  const pending = new Map<string, typeof selected.journal[number]>();
  for (const entry of selected.journal) pending.set(`${entry.opId}\0${entry.attempt}`, entry);
  if ([...pending.values()].some(entry => !['completed', 'failed'].includes(entry.phase)))
    invalid('cannot overtake an unresolved original Journal attempt');
  if (frontier.verifierPlanRef !== selected.verifierPlanRef || frontier.afterPass !==
      (selected.spec.operation === 'agent' ? 'finalize' : 'delivery_approval')) invalid('substitutes its original verifier continuation');
  selected.assertUnchanged(driver); reads.assertReadActive();
  return Object.freeze({ ...selected, frontier });
}

/** Immutable SQL locators come from the original waiting subject/claim, not
 * today's frontier. Original model/merge source, physical seal and all CAS
 * bytes are reread. The enclosing reader owns that locator's registration. */
export async function readRetainedDependencyCandidate(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string,
  input: Locator & Options) {
  if (normalizeBoundedText(input.candidateItemId, 1, 128) !== input.candidateItemId ||
      normalizeBoundedText(input.sourceCheckpointId, 1, 128) !== input.sourceCheckpointId) invalid('locator is malformed');
  assertArtifactRef(input.dependencyPlanRef); assertArtifactRef(input.resultSourceRef);
  const reads = input.signal ? artifacts.withReadSignal(input.signal) : artifacts; reads.assertReadActive();
  const cut = immutableSnapshot(driver.readSnapshot(connection => databaseCut(connection, runId)));
  const { run, journal, workers, generations, allocations, session, principalId } = cut;
  const spec = decodeRunSpec(await readCanonicalArtifact(reads, run.specRef));
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(reads, spec.assemblyRef));
  const profile = decodeSandboxProfile(await readCanonicalArtifact(reads, spec.sandboxProfileRef));
  const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(reads, assembly.runtime.runtimeBundleRef);
  if (bundle.manifestDigest !== assembly.runtime.runtimeBundleManifestDigest) invalid('runtime differs from the frozen signed assembly');
  const { policy, endpoints } = await readFrozenDependencyPolicy(reads, spec);
  const signed = await readDependencySignedAssets(reads, { bundle, releaseKeys: input.releaseKeys, resources: profile.resources,
    allowScripts: policy.installScriptsPolicy === 'exact_lockfile_grant' }, input.signal);
  if (assembly.runtime.guestToolchainManifestRef !== signed.toolchain.manifestRef ||
      assembly.runtime.guestToolchainManifestDigest !== signed.toolchain.manifest.manifestDigest) invalid('guest differs from the original assembly');
  const items: RunItemReferenceV1[] = [], decodedItems = new Map<string, ContinuationItem>();
  await reads.mapReads(cut.rows, async (row, index) => {
    const item = await readCanonicalArtifact<ContinuationItem>(reads, row.payload_ref);
    parseCanonicalTime(item.createdAt);
    // This is the complete retained cut, including later received tool/child
    // observations and Stop drain. Each owning history validates its purpose.
    // The exact candidate/producer/source Checkpoint below must precede the
    // deadline; every live release independently enforces fresh C < deadline.
    if (row.item_seq !== index + 1 || item.itemId !== row.item_id || item.kind !== row.kind || item.runId !== runId ||
        item.createdAt !== row.created_at || item.createdAt < run.createdAt || item.createdAt > run.updatedAt)
      invalid('item differs from its complete original SQL owner');
    decodedItems.set(row.item_id, item);
    items[index] = { schemaVersion: 1, itemId: row.item_id, itemSeq: row.item_seq, payloadRef: row.payload_ref,
      payloadDigest: row.payload_ref, createdAt: row.created_at };
  });
  await readRetainedJournalData(reads, journal);
  const row = items.find(item => item.itemId === input.candidateItemId);
  if (!row || decodedItems.get(row.itemId)?.kind !== 'final_candidate') invalid('has no registered original candidate item');
  const candidate = decodeFinalCandidateItem(decodedItems.get(row.itemId));
  if (candidate.resultSourceRef !== input.resultSourceRef) invalid('substitutes its exact result source');
  const candidateRows = items.filter(item => decodedItems.get(item.itemId)?.kind === 'final_candidate');
  const candidateOrdinal = candidateRows.indexOf(row);
  if (candidateOrdinal < 0 || candidateOrdinal > spec.budgets.repairAttempts) invalid('ordinal exceeds its original candidate budget');
  const generationProofs = await reads.mapReads(generations, async generation => generation.phase === 'retired'
    ? (await readRetiredGenerationSource(driver, reads, { run, spec, assembly, generation })).source : generation);
  let originAssert: (connection: SqliteConnection | SqliteDriver) => void;
  let originalCheckpoint;
  let candidateRetirement: { generation: WorkspaceGenerationStateV1; snapshot: WorkspaceGenerationSnapshotEvidenceV1; launch: WorkerLaunch } | undefined;
  if (spec.operation === 'agent') {
    const origin = run.parentRunId ? await readChildAdmission(driver, reads, runId, { signal: input.signal })
      : await readRootRunAdmissionOrigin(driver, reads, runId, { signal: input.signal });
    originAssert = origin.assertUnchanged;
    const original = await readRetainedFinalCandidateSource({ driver, artifacts: reads, run, spec, items, journal,
      checkpoints: cut.checkpoints, workspaceGenerations: generationProofs, decodedItems }, row);
    const matching = workers.filter(worker => worker.phase === 'retired' && worker.generationWriteState === 'sealed' &&
      worker.workspaceGenerationRef === original.generation.generationRef);
    if (matching.length !== 1) invalid('has no unique original retired sealed worker');
    await validateRetainedWorkerSeal(driver, reads, { run, spec, assembly, launch: matching[0]!, generation: original.generation });
    originalCheckpoint = original.checkpoint;
    candidateRetirement = { generation: original.generation, snapshot: original.snapshot, launch: matching[0]! };
  } else {
    const origin = await readDeliveryRunAdmission(driver, reads, runId, { signal: input.signal });
    const delivery = await validateDeliveryRecoveryData(driver, reads, { run, runSpec: spec, items, journal,
      checkpoints: cut.checkpoints, decodedItems }, origin);
    const merged = delivery.get(candidate.producingItemId);
    if (!merged || canonicalSha256(merged.candidate) !== row.payloadRef) invalid('lost its complete original Delivery merge');
    originalCheckpoint = merged.checkpoint;
    const sourceKey = { principalId, method: 'run.apply' as const, admissionKey: origin.request.admissionKey,
      admissionIntentDigest: runApplyIntentDigest(principalId, origin.request) };
    const originSql = (connection: SqliteConnection | SqliteDriver) => ({
      control: readControlRequest(connection, principalId, 'run.apply', origin.request.requestId),
      inspection: readSourceInspectionAttempt(connection, sourceKey), sourceRun: readRun(connection, origin.source.run.id),
      sourceSession: readSession(connection, origin.source.run.sessionId),
      sourcePrincipalId: readSessionPrincipalId(connection, origin.source.run.sessionId) });
    const retainedOrigin = originSql(driver);
    requireEqual(retainedOrigin.control, origin.original, 'dependency original Delivery response');
    requireEqual(retainedOrigin.inspection, origin.inspection, 'dependency original Delivery retired capture');
    requireEqual(retainedOrigin.sourceRun, origin.source.run, 'dependency original Delivery verified source Run');
    originAssert = connection => requireEqual(originSql(connection), retainedOrigin, 'dependency complete Delivery origin SQL cut');
  }
  const checkpoint = readCheckpoint(driver, input.sourceCheckpointId);
  if (checkpoint.runId !== runId || checkpoint.createdAt < originalCheckpoint.createdAt || checkpoint.createdAt >= run.deadlineAt ||
      checkpoint.workspaceStateRef !== originalCheckpoint.workspaceStateRef || checkpoint.runItemSeq < row.itemSeq ||
      checkpoint.journalSeq < originalCheckpoint.journalSeq || checkpoint.runItemSeq > items.length || checkpoint.journalSeq > journal.length)
    invalid('source Checkpoint is not its exact original restorable candidate');
  const context = decodeContextManifest(await readCanonicalArtifact(reads, checkpoint.contextManifestRef));
  if (context.runId !== runId || context.assemblyRef !== spec.assemblyRef || context.admittedContextRef !== spec.admittedContextRef ||
      context.throughItemSeq !== checkpoint.runItemSeq) invalid('source context is foreign');
  validateContextItems(context, items.slice(0, checkpoint.runItemSeq).map(item => ({ itemSeq: item.itemSeq,
    itemRef: item.payloadRef, item: decodedItems.get(item.itemId)! })));
  const workspace = decodeWorkspaceState(await readCanonicalArtifact(reads, checkpoint.workspaceStateRef));
  const projected = await readCandidateSource(reads, spec, checkpoint.workspaceStateRef, input.signal);
  if (projected.sourceRef !== input.resultSourceRef || projected.source.manifestDigest !== candidate.sourceDigest) invalid('source no longer reproduces its actual candidate');
  const selected = await readCandidateDependencyPlan(reads, { sourceRef: input.resultSourceRef, policy,
    guestToolchainManifestRef: signed.toolchain.manifestRef, registryEndpoints: endpoints, maxSingleFileBytes: profile.resources.maxSingleFileBytes });
  if (canonicalSha256(selected.plan) !== input.dependencyPlanRef) invalid('plan differs from its full original lock and registry inputs');
  requireEqual(await readCanonicalArtifact(reads, input.dependencyPlanRef), selected.plan, 'retained complete dependency plan');
  const verifierPlan = await readCandidateVerifierPlan(reads, spec, { runId, candidateItemId: candidate.itemId, resultSourceRef: input.resultSourceRef });
  const verifierPlanRef = canonicalSha256(verifierPlan);
  requireEqual(decodeVerifierPlan(await readCanonicalArtifact(reads, verifierPlanRef)), verifierPlan, 'retained dependency verifier plan');
  const workspaceIdentity = decodeWorkspaceIdentity(await readCanonicalArtifact(reads, session.workspaceIdentityRef));
  if (workspaceIdentity.ownerPrincipalId !== principalId) invalid('workspace has another original principal');
  const conditions = await readDependencyScriptSourceConditions(reads, { sourceManifestRef: input.resultSourceRef,
    workspaceEntriesRef: workspace.entriesRef, ...(workspace.privateGitStateRef ? { privateGitStateRef: workspace.privateGitStateRef } : {}),
    workspaceIdentityDigest: workspaceIdentity.identityDigest, resources: profile.resources,
    packageManifestDigest: selected.plan.packageManifest.contentDigest, lockfileDigest: selected.plan.lockfileDigest,
    bindingGyp: selected.plan.bindingGyp.kind === 'absent' ? { kind: 'absent' } : { kind: 'present', contentDigest: selected.plan.bindingGyp.contentDigest },
    execution: { ...signed.execution, registryTargetsDigest: canonicalSha256({ registryEndpoints: policy.registryEndpoints, credentialGrantRefs: policy.credentialGrantRefs }) } });
  function assertUnchanged(connection: SqliteConnection | SqliteDriver) {
    requireEqual(databaseCut(connection, runId), cut, 'dependency complete original SQL cut');
    requireEqual(readCheckpoint(connection, checkpoint.id), checkpoint, 'dependency original source Checkpoint');
    originAssert(connection);
  }
  assertUnchanged(driver); reads.assertReadActive();
  return Object.freeze({ ...immutableSnapshot({ run, spec, assembly, profile, bundle, principalId, session, workspaceIdentity, items, journal,
    workers, generations, allocations, candidate, candidateOrdinal, originalCheckpoint, candidateRetirement, checkpoint, context, workspace,
    policy, plan: selected.plan, dependencyPlanRef: input.dependencyPlanRef, data: selected.data, conditions, endpoints,
    signed, verifierPlan, verifierPlanRef }), assertUnchanged });
}
export type DependencyCandidateData = Awaited<ReturnType<typeof readRetainedDependencyCandidate>>;
