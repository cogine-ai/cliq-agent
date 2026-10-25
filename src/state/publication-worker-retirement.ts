import { canonicalSha256 } from '../kernel/canonical.js';
import type { RecoveryClosureV1, Run, WorkerDeathWait } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { readPublicationPrefix } from './delivery-publication-progress.js';
import { KernelStorageError } from './errors.js';
import { isZeroBudget } from './invariants.js';
import { readDeliveryPublicationClosure } from './recovery-closure.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { readCheckpoint, readRun, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readAgentStop } from './stop-recovery.js';
import { readWorkerRecoveryTerminalPlan, type WorkerRecoveryTerminalPlan } from './worker-recovery-terminal.js';

/** Existing conservative charge plus the full original publication graph,
 * not a flag based on opKind or a replacement worker-death observation. */
export async function readUnresolvedPublicationWorkerCut(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  if (cut.runSpec.operation !== 'delivery' || cut.run.nextStep !== 'delivery' || !isZeroBudget(cut.run.budgetReserved))
    invalid('publication UNKNOWN retirement requires its original Delivery worker and settled reservation');
  const prefix = await readPublicationPrefix(driver, artifacts, cut);
  const unresolved = [...prefix.entries.values()].filter(entry => entry.result?.item.outcome === 'unknown');
  if (!prefix.authorization?.grant || unresolved.length !== 1 || !unresolved[0]!.claim ||
      unresolved[0]!.pendingReceivedHandoff || unresolved[0]!.sequence === 'abort' &&
        (!cut.run.stopIntentRef || unresolved[0]!.grant.format !== 'cliq-publication-maintenance-authority-v1') ||
      [...prefix.entries.values()].some(entry => entry !== unresolved[0] && !entry.preparationClosure &&
        (!entry.result || entry.result.item.outcome === 'unknown')))
    invalid('publication UNKNOWN retirement requires its fully validated sole conservative claim');
  const entry = unresolved[0]!, latest = new Map<string, (typeof cut.journal)[number]>();
  for (const row of cut.journal) latest.set(`${row.opId}\0${row.attempt}`, row);
  const open = cut.journal.filter(row => row.phase === 'prepared' &&
    ['prepared', 'dispatch_claimed', 'unknown'].includes(latest.get(`${row.opId}\0${row.attempt}`)!.phase));
  if (open.length !== 1 || open[0]!.opKind !== 'publish' || open[0]!.opId !== entry.prepared.opId ||
      open[0]!.attempt !== entry.prepared.attempt || entry.claim!.leaseEpoch !== cut.run.leaseEpoch ||
      readChildAllocationsForRun(driver, cut.run.id).length ||
      driver.prepare('SELECT 1 FROM runs WHERE parent_run_id=? LIMIT 1').get(cut.run.id))
    invalid('publication UNKNOWN cannot quarantine another open invocation or child domain');
  const sideCut = (connection: SqliteConnection) => {
    const selected = sqlCut(connection, cut.run.id);
    return { source: sqlCut(connection, prefix.admission.source.run.id), session: selected.session,
      principalId: selected.principalId, admission: selected.admission, items: selected.items,
      children: selected.children, childRuns: selected.childRuns };
  };
  const retained = sideCut(driver);
  requireEqual(retained.source.run, prefix.admission.source.run, 'publication worker recovery original verified source');
  requireEqual(retained.source.session, sessionIdentity(prefix.admission.source.session), 'publication worker recovery original source Session identity');
  if (retained.principalId !== retained.source.principalId) invalid('publication worker recovery changed the source principal');
  const fingerprint = canonicalSha256(retained);
  return { prefix, entry, assertSourceCut(connection: SqliteConnection) {
    if (canonicalSha256(sideCut(connection)) !== fingerprint)
      throw new KernelStorageError('REVISION_CONFLICT', 'publication UNKNOWN recovery changed its original source, Session or audit items');
  } };
}

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
const sessionIdentity = (session: ReturnType<typeof readSession>) => ({ id: session.id,
  workspaceIdentityRef: session.workspaceIdentityRef, createdAt: session.createdAt,
  ...(session.parentSessionId === undefined ? {} : { parentSessionId: session.parentSessionId, forkedThroughItemSeq: session.forkedThroughItemSeq }) });
function sqlCut(connection: SqliteConnection, runId: string) {
  const run = readRun(connection, runId);
  return { run, checkpoint: readCheckpoint(connection, run.latestCheckpointId),
    session: sessionIdentity(readSession(connection, run.sessionId)), principalId: readSessionPrincipalId(connection, run.sessionId),
    admission: connection.prepare(`SELECT principal_id,admission_method,admission_key,admission_intent_digest,
      admitted_request_digest,admission_request_id FROM runs WHERE id=?`).get(runId),
    journal: readInvocationJournal(connection, runId), launches: readWorkerLaunchesForRun(connection, runId),
    generations: readWorkspaceGenerationsForRun(connection, runId),
    items: connection.prepare('SELECT item_id,session_id,run_id,item_seq,kind,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
      .all<{ item_id: string; session_id: string | null; run_id: string; item_seq: bigint; kind: string; payload_ref: string; created_at: string }>(runId)
      .map(row => ({ ...row, item_seq: Number(row.item_seq) })),
    children: readChildAllocationsForRun(connection, runId),
    childRuns: connection.prepare('SELECT id FROM runs WHERE parent_run_id=? ORDER BY id').all<{ id: string }>(runId) };
}

/** Only the original genuine worker-recovery producer may transfer a stopped
 * known publication to host maintenance. This is neither terminal success nor
 * a generic stopped-worker queued transition: no claim, charge, Checkpoint,
 * semantic frontier, StopIntent or Session is created/replaced here. The real
 * generation remains quarantined for the existing fresh retirement producer. */
export async function commitStoppedPublicationWorkerRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, token: WorkerRecoveryTerminalPlan, runId: string, signal?: AbortSignal): Promise<Run> {
  return commitPublicationWorkerRetirement(driver, artifacts, owner, token, runId, 'known', signal);
}

/** Same original true quarantine plan, preserving the unresolved publication
 * and its one pessimistic BudgetSet for later descriptor-only reconciliation. */
export async function commitUnresolvedPublicationWorkerRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, token: WorkerRecoveryTerminalPlan, runId: string, signal?: AbortSignal): Promise<Run> {
  return commitPublicationWorkerRetirement(driver, artifacts, owner, token, runId, 'unknown', signal);
}

async function commitPublicationWorkerRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, token: WorkerRecoveryTerminalPlan, runId: string, mode: 'known' | 'unknown', signal?: AbortSignal): Promise<Run> {
  // WeakMap/same-Store ownership must precede even property reads from a
  // supplied token. Retained rows or callbacks cannot fabricate this plan.
  const retirement = readWorkerRecoveryTerminalPlan(driver, owner, token, runId), original = retirement.cut;
  signal?.throwIfAborted();
  if (signal) artifacts = artifacts.withReadSignal(signal);
  if (original.runSpec.operation !== 'delivery' || original.run.nextStep !== 'delivery' || !original.run.stopIntentRef ||
      original.run.status !== 'waiting' || original.run.waitingReason !== 'reconciliation' || !original.run.waitingOnRef ||
      retirement.rollback || !isZeroBudget(original.run.budgetReserved))
    invalid('stopped publication retirement requires its exact original zero-reservation Delivery worker wait');
  const before = driver.readSnapshot(connection => sqlCut(connection, runId));
  requireEqual(before.run, original.run, 'publication retirement original worker-recovery Run');
  requireEqual(before.checkpoint, original.latestCheckpoint, 'publication retirement original ready M Checkpoint');
  requireEqual(before.journal, original.journal, 'publication retirement original settled Journal');
  requireEqual(before.generations, original.workspaceGenerations, 'publication retirement original fenced generations');
  requireEqual(before.launches.filter(launch => launch.phase !== 'retired'), original.workerLaunches,
    'publication retirement original bound worker');
  const { cut, prefix } = await readDeliveryPublicationClosure(driver, artifacts, runId);
  requireEqual(cut.run, original.run, 'publication retirement full original worker wait');
  requireEqual(cut.latestCheckpoint, original.latestCheckpoint, 'publication retirement unchanged source Checkpoint');
  const wait = await readCanonicalArtifact<WorkerDeathWait>(artifacts, cut.run.waitingOnRef!);
  if (wait.subject.kind !== 'worker_death' || wait.subject.workspaceGenerationRef !== retirement.generation.generationRef ||
      cut.run.activeWorkerLaunchId !== undefined || !prefix.authorization?.grant ||
      prefix.authorization.decision.decision !== 'allow' || !prefix.forward.some(entry => entry.claim) ||
      mode === 'known' && [...prefix.entries.values()].some(entry => entry.preparationClosure ? entry.sequence !== 'forward' :
        !entry.claim || !entry.result || entry.result.item.outcome === 'unknown') ||
      mode === 'known' && prefix.abortResults.some(entry => !entry.result || entry.result.item.outcome === 'unknown') ||
      !isZeroBudget(cut.run.budgetReserved) || before.children.length || before.childRuns.length)
    invalid('publication retirement waits for its complete known original forward and cleanup prefix');
  if (mode === 'unknown') {
    const selected = await readUnresolvedPublicationWorkerCut(driver, artifacts, cut);
    const launch = original.workerLaunches.find(value => value.workspaceGenerationRef === retirement.generation.generationRef);
    if (!launch || selected.entry.claim!.supervisorInstanceId !== launch.supervisorInstanceId ||
        selected.entry.claim!.leaseEpoch !== launch.leaseEpoch)
      invalid('publication UNKNOWN retirement lost its exact original productive M');
  }
  const stop = await readAgentStop(driver, artifacts, cut);
  if (canonicalSha256(stop) !== cut.run.stopIntentRef)
    invalid('publication retirement lost its exact winning StopIntent');
  const source = driver.readSnapshot(connection => sqlCut(connection, prefix.admission.source.run.id));
  requireEqual(source.run, prefix.admission.source.run, 'publication retirement full verified source');
  requireEqual(source.session, sessionIdentity(prefix.admission.source.session), 'publication retirement original source Session identity');
  if (source.principalId !== before.principalId || source.principalId !== prefix.authorization.grant.principalId)
    invalid('publication retirement changed its original source or publication principal');
  const fingerprint = canonicalSha256({ before, source });
  const assertCut = (connection: SqliteConnection) => {
    signal?.throwIfAborted();
    assertActiveStateOwner(connection, owner);
    if (canonicalSha256({ before: sqlCut(connection, runId), source: sqlCut(connection, source.run.id) }) !== fingerprint)
      throw new KernelStorageError('REVISION_CONFLICT', 'publication retirement original Stop, source or worker SQL cut changed');
  };
  let outcome: TimeFenceAdvance | undefined, result: Run | undefined;
  driver.transaction(connection => {
    assertCut(connection); retirement.reobserve(connection);
    const preparedAt = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, preparedAt);
    if (outcome !== 'healthy') return;
    for (const artifact of retirement.quarantineMetadata) { signal?.throwIfAborted(); insertArtifactMetadata(connection, artifact, preparedAt); }
    assertCut(connection); retirement.reobserve(connection);
    const committedAt = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, committedAt);
    if (outcome !== 'healthy') return;
    retirement.validateQuarantined(connection, committedAt); retirement.commitQuarantined(connection, committedAt);
    const updated = connection.prepare(`UPDATE runs SET status='queued',waiting_reason=NULL,waiting_on_ref=NULL,
      active_worker_launch_id=NULL,revision=revision+1,updated_at=? WHERE id=? AND revision=?`)
      .run(committedAt, runId, BigInt(cut.run.revision));
    if (updated.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'publication retirement lost its original Run revision');
    const { waitingReason: _reason, waitingOnRef: _wait, activeWorkerLaunchId: _worker, ...stopped } = cut.run;
    result = readRun(connection, runId);
    requireEqual(result, { ...stopped, status: 'queued', revision: cut.run.revision + 1, updatedAt: committedAt },
      'publication retirement preserves its exact Stop, Journal, budget, frontier and ready Checkpoint');
    appendRunStateEvent(connection, result, committedAt);
  });
  requireHealthyFence(outcome);
  if (!result) invalid('publication retirement did not commit its actual original resource closure');
  return immutableSnapshot(result);
}
