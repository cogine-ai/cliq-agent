import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeDependencyReadyItem, type DependencyReadyItem } from '../kernel/dependency.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { ContinuationItem, RunFrontier } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { readChildAdmission, type ChildAdmissionData } from './child-admission.js';
import { planContinuationCommit } from './continuation-commit.js';
import { decodeRunSpec, decodeWorkspaceEntries, decodeWorkspaceState } from './decoders.js';
import { readCurrentDependencyCandidate } from './dependency-candidate.js';
import { readDependencyHistory, type DependencyHistoryCut } from './dependency-history.js';
import { readAcquiredDependencyReady, dependencyInstalledTreeDigest } from './dependency-retirement.js';
import { readDerivedDependencyScriptSourceConditions, sameDependencyReadyInputs } from './dependency-script-source.js';
import { readDependencyPlanForProjectedSource } from './dependency-plan.js';
import { KernelStorageError } from './errors.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { planChildForkSource } from './result-source.js';
import { readCheckpoint, readRun } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
export const inheritedDependencyCheckpointId = (runId: string, candidateId: string, planRef: string) =>
  identityHash('cliq-inherited-dependency-checkpoint-v1', runId, candidateId, planRef);
export const inheritedDependencyItemId = (runId: string, candidateId: string, planRef: string) =>
  identityHash('cliq-inherited-dependency-item-v1', runId, candidateId, planRef);

async function actualCut(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string): Promise<DependencyHistoryCut> {
  const run = readRun(driver, runId), runSpec = decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef));
  const rows = driver.prepare('SELECT item_id,item_seq,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: bigint; payload_ref: string; created_at: string }>(runId);
  return { run, runSpec, items: rows.map(row => ({ schemaVersion: 1, itemId: row.item_id, itemSeq: Number(row.item_seq),
    payloadRef: row.payload_ref, payloadDigest: row.payload_ref, createdAt: row.created_at })), journal: readInvocationJournal(driver, runId),
    workspaceGenerations: readWorkspaceGenerationsForRun(driver, runId) };
}
async function fullManagedBytes(artifacts: ArtifactCatalog, stateRef: string) {
  const workspace = decodeWorkspaceState(await readCanonicalArtifact(artifacts, stateRef));
  const entries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, workspace.entriesRef));
  const treeDigest = dependencyInstalledTreeDigest(entries);
  for (const entry of entries.entries) if (entry.kind === 'file' && entry.path.startsWith('node_modules/')) {
    let count = 0;
    for await (const chunk of artifacts.readChunks(entry.blobRef, entry.size)) { artifacts.assertReadActive(); count += chunk.length; }
    if (count !== entry.size) invalid('inherited dependency did not read its complete managed data');
  }
  return { workspace, entries, treeDigest };
}

/** The selected original parent Checkpoint is read from SQLite, including
 * every retained ready receipt/native seal and every actual managed byte.
 * This reuses immutable output data and creates no child dispatch consent. */
export async function readParentDependencyReadyAtCheckpoint(driver: SqliteDriver, artifacts: ArtifactCatalog,
  input: { runId: string; checkpointId: string }) {
  const cut = await actualCut(driver, artifacts, input.runId), checkpoint = readCheckpoint(driver, input.checkpointId);
  if (!cut.runSpec.dependencyPolicyRef || checkpoint.runId !== cut.run.id || checkpoint.runItemSeq > cut.items.length)
    invalid('child dependency has no original parent ready Checkpoint');
  const history = await readDependencyHistory(driver, artifacts, cut);
  const eligible = [...history.values()].flatMap(progress => progress.ready ? [progress.ready] : [])
    .filter(item => cut.items.find(row => row.itemId === item.itemId)?.itemSeq! <= checkpoint.runItemSeq);
  const ready = eligible.at(-1);
  if (!ready) invalid('child dependency cannot acquire or execute instead of inheriting a true parent ready result');
  const checked = ready.origin === 'acquired' ? await readAcquiredDependencyReady(driver, artifacts, cut, ready)
    : await readInheritedDependencyReady(driver, artifacts, cut, ready);
  const material = await fullManagedBytes(artifacts, checkpoint.workspaceStateRef);
  if (material.treeDigest !== ready.installedTreeDigest) invalid('parent dependency tree drifted after its original sealed ready result');
  const projected = await planChildForkSource(artifacts, cut.runSpec, checkpoint.workspaceStateRef);
  // The original ready retains its original source/retirement. This fork is
  // explicitly derived data over the actual M; the child admission later
  // publishes its own complete base graph in its original sole transaction.
  const projectedEntries = projected.plans.find(plan => plan.ref === projected.source.entriesRef);
  const entries = decodeWorkspaceEntries(projectedEntries ? parseJsonStrict(Buffer.from(projectedEntries.bytes).toString('utf8'))
    : await readCanonicalArtifact(artifacts, projected.source.entriesRef));
  const source = checked.source;
  const selected = await readDependencyPlanForProjectedSource(artifacts, { source: projected.source, entries, policy: source.policy,
    guestToolchainManifestRef: source.signed.toolchain.manifestRef, registryEndpoints: source.endpoints,
    maxSingleFileBytes: source.profile.resources.maxSingleFileBytes });
  const conditions = await readDerivedDependencyScriptSourceConditions(artifacts, { source: projected.source, projected: entries,
    workspaceEntriesRef: material.workspace.entriesRef, ...(material.workspace.privateGitStateRef ? { privateGitStateRef: material.workspace.privateGitStateRef } : {}),
    workspaceIdentityDigest: source.workspaceIdentity.identityDigest, resources: source.profile.resources,
    packageManifestDigest: selected.plan.packageManifest.contentDigest, lockfileDigest: selected.plan.lockfileDigest,
    bindingGyp: selected.plan.bindingGyp.kind === 'absent' ? { kind: 'absent' } : { kind: 'present', contentDigest: selected.plan.bindingGyp.contentDigest },
    execution: source.conditions.execution });
  if (!sameDependencyReadyInputs(source.conditions, conditions, source.plan.allowInstallScripts) ||
      canonicalSha256(selected.plan) !== ready.planRef) invalid('parent ready no longer covers its complete actual dependency execution inputs');
  checked.assertUnchanged(driver); requireEqual(readCheckpoint(driver, checkpoint.id), checkpoint, 'parent exact original ready fork Checkpoint');
  return { ready, readyRef: canonicalSha256(ready), readyCheckpoint: checked.checkpoint, checkpoint, source,
    conditions, material, assertUnchanged() { checked.assertUnchanged(driver); requireEqual(readCheckpoint(driver, checkpoint.id), checkpoint, 'parent original dependency fork cut'); } };
}

export async function validateChildDependencyOrigin(driver: SqliteDriver, artifacts: ArtifactCatalog, child: ChildAdmissionData) {
  if (!child.spec.dependencyPolicyRef) return undefined;
  if (child.delegated.verifierMode !== 'inherit_parent' || child.spec.dependencyPolicyRef !== child.parentSpec.dependencyPolicyRef ||
      child.capabilityGrant.childDependencyPolicyRef !== child.spec.dependencyPolicyRef)
    invalid('child dependency is not the exact original parent data policy');
  const parent = await readParentDependencyReadyAtCheckpoint(driver, artifacts, { runId: child.parent.id, checkpointId: child.checkpoint.id });
  const initial = await fullManagedBytes(artifacts, child.request.childWorkspaceStateRef);
  if (initial.treeDigest !== parent.ready.installedTreeDigest || initial.workspace.entriesRef !== child.parentWorkspace.entriesRef)
    invalid('child independent original workspace substitutes its parent sealed dependency data');
  parent.assertUnchanged(); child.assertUnchanged(driver); return parent;
}

/** Full retained inherited origin, with the child's own real original
 * candidate worker retirement. No fake child GET/Journal/result is produced. */
export async function readInheritedDependencyReady(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: DependencyHistoryCut,
  supplied: Extract<DependencyReadyItem, { origin: 'inherited_parent_ready' }>) {
  const item = decodeDependencyReadyItem(supplied);
  if (item.origin !== 'inherited_parent_ready' || item.runId !== cut.run.id || item.parentRunId !== cut.run.parentRunId)
    invalid('inherited dependency has another original child/parent');
  const child = await readChildAdmission(driver, artifacts, cut.run.id), parent = await validateChildDependencyOrigin(driver, artifacts, child);
  if (!parent || item.parentReadyItemRef !== parent.readyRef || item.parentReadyCheckpointId !== parent.readyCheckpoint.id ||
      item.parentReadyWorkspaceStateRef !== parent.readyCheckpoint.workspaceStateRef || item.childAdmissionRequestRef !== child.receipt.requestRef)
    invalid('inherited dependency substitutes its original parent ready or local admission');
  const checkpoint = readCheckpoint(driver, item.readyCheckpointId), row = cut.items.find(row => row.itemId === item.itemId);
  if (!row || row.payloadRef !== canonicalSha256(item) || checkpoint.runId !== cut.run.id || checkpoint.runItemSeq !== row.itemSeq ||
      checkpoint.createdAt !== item.createdAt || row.createdAt !== item.createdAt || checkpoint.journalSeq > cut.journal.length)
    invalid('inherited dependency has no original same-transaction child item and ready Checkpoint');
  const snapshot = (await import('./decoders.js')).decodeWorkspaceGenerationSnapshotEvidence(await readCanonicalArtifact(artifacts, item.childPreparation.snapshotEvidenceRef));
  const original = readCheckpoint(driver, snapshot.checkpointId);
  if (snapshot.purpose !== 'sealed_to_checkpoint' || snapshot.workspaceStateRef !== checkpoint.workspaceStateRef || original.createdAt > item.createdAt ||
      original.workspaceStateRef !== checkpoint.workspaceStateRef || original.journalSeq !== checkpoint.journalSeq)
    invalid('child readiness has no real unchanged sealed candidate M');
  const candidateRow = cut.items.find(row => row.itemSeq === original.runItemSeq), candidate = candidateRow &&
    (await import('./result-artifacts.js')).decodeFinalCandidateItem(await readCanonicalArtifact(artifacts, candidateRow.payloadRef));
  if (!candidate || candidate.runId !== cut.run.id || item.itemId !== inheritedDependencyItemId(cut.run.id, candidate.itemId, item.planRef) ||
      item.readyCheckpointId !== inheritedDependencyCheckpointId(cut.run.id, candidate.itemId, item.planRef)) invalid('child readiness has another original candidate');
  const source = await (await import('./dependency-candidate.js')).readRetainedDependencyCandidate(driver, artifacts, cut.run.id,
    { candidateItemId: candidate.itemId, sourceCheckpointId: original.id, dependencyPlanRef: item.planRef,
      resultSourceRef: candidate.resultSourceRef, releaseKeys: artifacts.releaseTrustRoots() });
  const launch = source.workers.find(launch => launch.launchId === item.childPreparation.workerLaunchId);
  if (!launch || launch.phase !== 'retired' || launch.retirementEvidenceRef !== item.childPreparation.retirementEvidenceRef ||
      !source.candidateRetirement || source.candidateRetirement.snapshot.generationRef !== snapshot.generationRef ||
      source.candidateRetirement.generation.generationRef !== launch.workspaceGenerationRef ||
      source.candidateRetirement.generation.phase !== 'sealed' || source.candidateRetirement.generation.snapshotEvidenceRef !== item.childPreparation.snapshotEvidenceRef) invalid('child readiness lost its original retired worker');
  if (source.originalCheckpoint.id !== original.id || source.originalCheckpoint.workspaceStateRef !== checkpoint.workspaceStateRef ||
      !sameDependencyReadyInputs(parent.conditions, source.conditions, source.plan.allowInstallScripts) || item.planRef !== parent.ready.planRef)
    invalid('child candidate changed its original inherited dependency execution inputs');
  const material = await fullManagedBytes(artifacts, checkpoint.workspaceStateRef);
  if (material.treeDigest !== item.installedTreeDigest || item.installedTreeDigest !== parent.ready.installedTreeDigest)
    invalid('child ready material differs from the complete original parent data');
  source.assertUnchanged(driver); parent.assertUnchanged(); child.assertUnchanged(driver);
  return { item: { ...item, origin: 'inherited_parent_ready' as const }, source, checkpoint,
    assertUnchanged(connection = driver) { source.assertUnchanged(connection); parent.assertUnchanged(); child.assertUnchanged(connection); } };
}

/** Worker-free logical Checkpoint over M that the child's original candidate
 * worker has already physically sealed. Native birth/death refs remain those
 * of that real original CP, never relabelled as a new native observation. */
export async function commitInheritedCandidateReady(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runId: string, expectedRunRevision: number) {
  const source = await readCurrentDependencyCandidate(driver, artifacts, runId, { releaseKeys: artifacts.releaseTrustRoots() });
  if (!source.run.parentRunId || source.run.revision !== expectedRunRevision) invalid('child inherited readiness requires its exact worker-free candidate');
  const child = await readChildAdmission(driver, artifacts, runId), parent = await validateChildDependencyOrigin(driver, artifacts, child);
  if (!parent || source.dependencyPlanRef !== parent.ready.planRef || !sameDependencyReadyInputs(parent.conditions, source.conditions, source.plan.allowInstallScripts))
    invalid('child dependency drift requires a separately supported explicit acquisition');
  const material = await fullManagedBytes(artifacts, source.checkpoint.workspaceStateRef);
  if (material.treeDigest !== parent.ready.installedTreeDigest) invalid('child cannot relabel changed managed data as inherited');
  const actual = source.candidateRetirement;
  if (!actual || actual.generation.phase !== 'sealed' || !actual.launch.retirementEvidenceRef ||
      actual.snapshot.checkpointId !== source.originalCheckpoint.id) invalid('child readiness requires its one real original candidate worker seal');
  const at = sampleCanonicalNow(), checkpointId = inheritedDependencyCheckpointId(runId, source.candidate.itemId, source.dependencyPlanRef);
  const item: Extract<DependencyReadyItem, { origin: 'inherited_parent_ready' }> = { schemaVersion: 1, kind: 'dependency_ready',
    itemId: inheritedDependencyItemId(runId, source.candidate.itemId, source.dependencyPlanRef), runId, planRef: source.dependencyPlanRef,
    origin: 'inherited_parent_ready', parentRunId: child.parent.id, parentReadyItemRef: parent.readyRef,
    parentReadyCheckpointId: parent.readyCheckpoint.id, parentReadyWorkspaceStateRef: parent.readyCheckpoint.workspaceStateRef,
    childAdmissionRequestRef: child.receipt.requestRef, childPreparation: { workerLaunchId: actual.launch.launchId,
      snapshotEvidenceRef: actual.generation.snapshotEvidenceRef, retirementEvidenceRef: actual.launch.retirementEvidenceRef! },
    readyCheckpointId: checkpointId, installedTreeDigest: material.treeDigest, createdAt: at };
  decodeDependencyReadyItem(item);
  const existingItems = await artifacts.mapReads(source.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
    item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) }));
  const frontier: RunFrontier = { ...source.frontier, phase: 'verifiers' };
  const graph = await planContinuationCommit(artifacts, { context: source.context, existingItems, items: [item], frontier,
    checkpointId, workspaceStateRef: source.checkpoint.workspaceStateRef }).publish();
  let fence: TimeFenceAdvance | undefined;
  driver.transaction(connection => {
    assertActiveStateOwner(connection, owner); source.assertUnchanged(connection); child.assertUnchanged(connection); parent.assertUnchanged();
    const now = sampleCanonicalNow();
    if (now < at || now >= source.run.deadlineAt || source.run.stopIntentRef || source.run.cancelRequested) invalid('child ready cut lost its original time or Stop gate');
    fence = advanceTimeFence(connection, owner.ownerEpoch, now); if (fence !== 'healthy') return;
    for (const artifact of graph.metadata) insertArtifactMetadata(connection, artifact, now);
    graph.commit(connection, source.run, source.journal.length, at);
    connection.prepare('UPDATE runs SET revision=revision+1,updated_at=? WHERE id=? AND revision=?').run(now, runId, BigInt(expectedRunRevision));
    appendRunStateEvent(connection, readRun(connection, runId), now);
  });
  requireHealthyFence(fence); return readRun(driver, runId);
}
