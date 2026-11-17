import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeDependencyReadyItem, type DependencyReadyItem } from '../kernel/dependency.js';
import { identityHash } from '../kernel/identity.js';
import type { ContinuationItem, RunFrontier } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { planContinuationCommit } from './continuation-commit.js';
import { decodeWorkspaceEntries } from './decoders.js';
import type { DependencyCandidateData } from './dependency-candidate.js';
import { dependencyInstalledTreeDigest, readAcquiredDependencyReady } from './dependency-retirement.js';
import { sameDependencyReadyInputs } from './dependency-script-source.js';
import { KernelStorageError } from './errors.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import { readCheckpoint, readRun } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

type ReusedReady = Extract<DependencyReadyItem, { origin: 'reused_acquired' }>;
type AcquiredProof = Awaited<ReturnType<typeof readAcquiredDependencyReady>>;

export const reusedDependencyItemId = (runId: string, candidateId: string, planRef: string) =>
  identityHash('cliq-reused-dependency-item-v1', runId, candidateId, planRef);
const checkpointIdFor = (source: DependencyCandidateData) =>
  identityHash('cliq-reused-dependency-checkpoint-v1', source.run.id, source.candidate.itemId, source.dependencyPlanRef);

/** No dispatch or new native proof. The original candidate has already
 * physically sealed its bytes, including the unchanged managed tree. */
async function readReuseBasis(artifacts: ArtifactCatalog, source: DependencyCandidateData, acquired: AcquiredProof) {
  if (source.spec.operation !== 'agent' || source.run.parentRunId || source.candidateOrdinal === 0 || source.plan.allowInstallScripts ||
      !source.candidateRetirement || source.candidateRetirement.snapshot.checkpointId !== source.originalCheckpoint.id ||
      acquired.item.runId !== source.run.id || acquired.item.planRef !== source.dependencyPlanRef ||
      acquired.checkpoint.runItemSeq >= source.originalCheckpoint.runItemSeq ||
      !sameDependencyReadyInputs(acquired.source.conditions, source.conditions, false)) return undefined;
  const entries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, source.workspace.entriesRef));
  if (!entries.entries.some(entry => entry.kind === 'directory' && entry.path === 'node_modules')) return undefined;
  const digest = dependencyInstalledTreeDigest(entries);
  if (digest !== acquired.item.installedTreeDigest) return undefined;
  // Both previous acquisition and current candidate have verified their real
  // workspace seals, including each file's complete size, bytes and hash.
  return digest;
}

export async function readReusedDependencyReady(driver: SqliteDriver, artifacts: ArtifactCatalog, source: DependencyCandidateData,
  item: ReusedReady, acquired: AcquiredProof | undefined) {
  const checkpoint = readCheckpoint(driver, item.readyCheckpointId);
  const row = source.items.find(row => row.itemId === item.itemId);
  if (!acquired || item.acquiredReadyItemRef !== canonicalSha256(acquired.item) ||
      item.itemId !== reusedDependencyItemId(source.run.id, source.candidate.itemId, source.dependencyPlanRef) ||
      item.readyCheckpointId !== checkpointIdFor(source) || !row || row.payloadRef !== canonicalSha256(item) ||
      row.itemSeq !== source.originalCheckpoint.runItemSeq + 1 || row.itemSeq !== checkpoint.runItemSeq ||
      checkpoint.runId !== source.run.id || checkpoint.createdAt !== row.createdAt || row.createdAt !== item.createdAt ||
      item.createdAt < source.originalCheckpoint.createdAt || item.createdAt >= source.run.deadlineAt ||
      checkpoint.workspaceStateRef !== source.originalCheckpoint.workspaceStateRef || checkpoint.journalSeq !== source.originalCheckpoint.journalSeq ||
      item.installedTreeDigest !== await readReuseBasis(artifacts, source, acquired))
    throw new TypeError('dependency reuse differs from its original acquisition or sealed repair candidate');
  source.assertUnchanged(driver); acquired.assertUnchanged(driver);
  return { item, checkpoint };
}

export async function commitReusedDependencyReady(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  source: DependencyCandidateData & { frontier: Extract<RunFrontier, { kind: 'verify' }> }) {
  if (source.spec.operation !== 'agent' || source.run.parentRunId || source.candidateOrdinal === 0 || source.plan.allowInstallScripts ||
      source.checkpoint.id !== source.originalCheckpoint.id) return undefined;
  const originalItems = await artifacts.mapReads(source.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
    item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) }));
  const original = [...originalItems].reverse().find(({ item }) => item.kind === 'dependency_ready' && item.origin === 'acquired' &&
    item.planRef === source.dependencyPlanRef)?.item;
  if (original?.kind !== 'dependency_ready' || original.origin !== 'acquired') return undefined;
  const cut = { run: source.run, runSpec: source.spec, items: source.items, journal: source.journal, workspaceGenerations: source.generations };
  const acquired = await readAcquiredDependencyReady(driver, artifacts, cut, original);
  const installedTreeDigest = await readReuseBasis(artifacts, source, acquired);
  if (!installedTreeDigest) return undefined;
  const at = sampleCanonicalNow(), checkpointId = checkpointIdFor(source);
  const item: ReusedReady = { schemaVersion: 1, kind: 'dependency_ready', origin: 'reused_acquired',
    itemId: reusedDependencyItemId(source.run.id, source.candidate.itemId, source.dependencyPlanRef), runId: source.run.id,
    planRef: source.dependencyPlanRef, readyCheckpointId: checkpointId, installedTreeDigest, acquiredReadyItemRef: canonicalSha256(acquired.item), createdAt: at };
  decodeDependencyReadyItem(item);
  const graph = await planContinuationCommit(artifacts, { context: source.context, existingItems: originalItems, items: [item],
    frontier: { ...source.frontier, phase: 'verifiers' }, checkpointId, workspaceStateRef: source.checkpoint.workspaceStateRef }).publish();
  artifacts.assertReadActive();
  let fence: TimeFenceAdvance | undefined;
  driver.transaction(connection => {
    assertActiveStateOwner(connection, owner); source.assertUnchanged(connection); acquired.assertUnchanged(connection);
    const now = sampleCanonicalNow();
    if (now < at || now >= source.run.deadlineAt || source.run.stopIntentRef || source.run.cancelRequested)
      throw new KernelStorageError('LEASE_FENCED', 'dependency reuse lost its original Run time or Stop gate');
    fence = advanceTimeFence(connection, owner.ownerEpoch, now); if (fence !== 'healthy') return;
    for (const artifact of graph.metadata) insertArtifactMetadata(connection, artifact, now);
    graph.commit(connection, source.run, source.journal.length, at);
    connection.prepare('UPDATE runs SET revision=revision+1,updated_at=? WHERE id=? AND revision=?')
      .run(now, source.run.id, BigInt(source.run.revision));
    appendRunStateEvent(connection, readRun(connection, source.run.id), now);
  });
  requireHealthyFence(fence);
  const run = readRun(driver, source.run.id);
  requireEqual(run.latestCheckpointId, checkpointId, 'dependency reuse exact committed Checkpoint');
  return run;
}
