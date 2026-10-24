import { randomBytes } from 'node:crypto';
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeInstalledControlEnvelope, decodeInstalledControlRequest, type RunReconcileRequestV1 } from '../kernel/control-wire.js';
import { addCanonicalDuration, digestOmitting, identityHash, sha256Bytes } from '../kernel/identity.js';
import type { PublicationPathWait, ReconciliationProbeDispatchV1, ReconciliationProbeEvidenceV1,
  ReconciliationProbeCancellationClosureV1, ReconciliationProbeTimeoutClosureV1 } from '../kernel/reconciliation.js';
import type { RecoveryClosureV1, Run, SupervisorInspectorIdentityV1 } from '../kernel/types.js';
import { decodePublicationLateObservationItem, publicationLateObservationItemId, publicationLateObservationCheckpointId } from '../kernel/publication.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { assertCurrentControlFrame, validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { readPublicationPrefix, type RetainedPublicationOperation } from './delivery-publication-progress.js';
import { KernelStorageError, RunTerminalError, stateOperation } from './errors.js';
import { isZeroBudget } from './invariants.js';
import { decodePublicationInspectionTarget, decodePublicationPathWait } from './publication-reconciliation-artifacts.js';
import { readPublicationProbeTarget, readPublicationUserProbeSource, validatePublicationProbeWait } from './publication-reconciliation-history.js';
import { assertPublicationReconciliationTaskReceipt, type PublicationReconciliationTaskReceipt } from './publication-reconciliation-task.js';
import { readOwnedPublicationReconciliationProgress, type OwnedPublicationReconciliationProgress,
  readOwnedPublicationLateObservation, assertOwnedPublicationLateObservationSql, acceptOwnedPublicationLateObservationAudit,
  type OwnedPublicationLateObservation } from './publication-invocation.js';
import { projectPublicationProbeProgress } from './publication-reconciliation-progress.js';
import { projectPublicationLateObservation } from './publication-late-observation.js';
import { planContinuationCommit } from './continuation-commit.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { assertDeliveryPublicationReconciliationExecution, assertOwnedPublicationReconciliationTask,
  type DeliveryPublicationReconciliationTask } from './run-execution.js';
import { insertControlRequest, readCheckpoint, readControlRequest, readRun, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readStateOwnerDeath } from './state-owner-death.js';
import { WORKER_PROBE_BACKOFF_MS } from './worker-recovery.js';

type TaskInput = { runId: string; expectedRunRevision: number; execution: unknown; task: DeliveryPublicationReconciliationTask };
type Mutation = { request: RunReconcileRequestV1; identity: AuthenticatedControlIdentity };
type BeginInput = TaskInput & { mutation?: Mutation };
type Response = Extract<ReturnType<typeof decodeInstalledControlEnvelope>, { ok: true }> &
  { result: Extract<Extract<ReturnType<typeof decodeInstalledControlEnvelope>, { ok: true }>['result'], { method: 'run.reconcile' }> };
type ReadWait = NonNullable<Awaited<ReturnType<typeof readPublicationReconciliation>>>;
type OwnedProbe = { driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; execution: unknown;
  task: DeliveryPublicationReconciliationTask; selected: ReadWait; fingerprint: ReturnType<typeof sqlCut>;
  progressTransfer?: OwnedPublicationReconciliationProgress };
const probes = new WeakMap<object, OwnedProbe>();
type LateInput = { execution: unknown; lateObservation: OwnedPublicationLateObservation };
type LateSource = Awaited<ReturnType<typeof readOwnedPublicationLateObservation>>;
type LateWriter = { commit(input: { expectedRunRevision: number }): Promise<Run> };
type LateBinding = { driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; input: LateInput;
  source: LateSource; item: ReturnType<typeof decodePublicationLateObservationItem>;
  graph: ReturnType<typeof planContinuationCommit>; writer: LateWriter; committed?: Run; accepted: boolean; working?: Promise<Run> };
const lateWriters = new WeakMap<object, LateBinding>();
const fail = (message: string): never => { throw new KernelStorageError('RECOVERY_REQUIRED', message); };
function exactInput(value: unknown, keys: readonly string[]) {
  if (!value || typeof value !== 'object') throw new KernelStorageError('INVALID_REQUEST', 'publication probe requires closed input');
  const data = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(data).length !== keys.length || keys.some(key => !Object.hasOwn(data, key)) ||
      Object.values(data).some(field => !field.enumerable || !Object.hasOwn(field, 'value') || field.value === undefined))
    throw new KernelStorageError('INVALID_REQUEST', 'publication probe requires closed input');
}
function revision(run: Run, expected: number) {
  if (['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(run.status)) throw new RunTerminalError();
  if (!Number.isSafeInteger(expected) || expected < 1) throw new KernelStorageError('INVALID_REQUEST', 'publication probe requires a positive expected revision');
  if (run.revision !== expected) throw new KernelStorageError('REVISION_CONFLICT', 'publication reconciliation Run revision changed');
}
const sessionIdentity = (session: ReturnType<typeof readSession>) => ({ id: session.id,
  workspaceIdentityRef: session.workspaceIdentityRef, createdAt: session.createdAt,
  ...(session.parentSessionId === undefined ? {} : { parentSessionId: session.parentSessionId, forkedThroughItemSeq: session.forkedThroughItemSeq }) });
function sqlCut(connection: SqliteConnection, runId: string, sourceRunId: string) {
  const selected = (id: string) => {
    const run = readRun(connection, id);
    return { run, checkpoint: readCheckpoint(connection, run.latestCheckpointId), session: sessionIdentity(readSession(connection, run.sessionId)),
      principalId: readSessionPrincipalId(connection, run.sessionId), journal: readInvocationJournal(connection, id),
      launches: readWorkerLaunchesForRun(connection, id), generations: readWorkspaceGenerationsForRun(connection, id),
      children: readChildAllocationsForRun(connection, id),
      admission: connection.prepare('SELECT principal_id,admission_method,admission_key,admission_intent_digest,admitted_request_digest,admission_request_id FROM runs WHERE id=?').get(id),
      items: connection.prepare('SELECT item_id,payload_ref,kind,created_at,CAST(item_seq AS INTEGER) AS item_seq FROM items WHERE run_id=? ORDER BY item_seq')
        .all<{ item_id: string; payload_ref: string; kind: string; created_at: string; item_seq: bigint }>(id)
        .map(row => ({ ...row, item_seq: Number(row.item_seq) })) };
  };
  return { selected: selected(runId), source: selected(sourceRunId) };
}
function validatedSqlCut(driver: SqliteDriver, cut: RecoveryClosureV1,
  source: Awaited<ReturnType<typeof readPublicationPrefix>>['admission']['source']) {
  const initial = sqlCut(driver, cut.run.id, source.run.id);
  requireEqual(initial.selected.run, cut.run, 'publication reconciliation actual SQL cut');
  requireEqual(initial.selected.checkpoint, cut.latestCheckpoint, 'publication reconciliation actual source Checkpoint');
  requireEqual(initial.selected.journal, cut.journal, 'publication reconciliation actual whole Journal');
  requireEqual(initial.selected.generations, cut.workspaceGenerations, 'publication reconciliation actual generations');
  requireEqual(initial.selected.launches.filter(launch => launch.phase !== 'retired'), cut.workerLaunches, 'publication actual nonretired worker inventory');
  requireEqual(initial.selected.items.map(({ kind: _kind, ...row }) => row), cut.items.map(row => ({ item_id: row.itemId, payload_ref: row.payloadRef,
    created_at: row.createdAt, item_seq: row.itemSeq })), 'publication reconciliation actual audit items');
  requireEqual(initial.source.run, source.run, 'publication reconciliation verified source terminal Run');
  requireEqual(initial.source.session, sessionIdentity(source.session), 'publication reconciliation verified source Session identity');
  if (initial.selected.principalId !== initial.source.principalId) fail('publication reconciliation changed its original source principal');
  return initial;
}
function bindCut(driver: SqliteDriver, owner: StateOwnerContext, cut: RecoveryClosureV1,
  source: Awaited<ReturnType<typeof readPublicationPrefix>>['admission']['source']) {
  const initial = validatedSqlCut(driver, cut, source), sourceRunId = source.run.id;
  const fingerprint = canonicalSha256(initial);
  return (connection: SqliteConnection) => {
    assertActiveStateOwner(connection, owner);
    if (canonicalSha256(sqlCut(connection, cut.run.id, sourceRunId)) !== fingerprint)
      throw new KernelStorageError('REVISION_CONFLICT', 'publication reconciliation changed its original source, Session, Journal or resources');
  };
}
function unresolved(prefix: Awaited<ReturnType<typeof readPublicationPrefix>>): RetainedPublicationOperation {
  const entries = [...prefix.entries.values()].filter(entry => entry.result?.item.outcome === 'unknown');
  if (entries.length !== 1 || !entries[0]!.claim || entries[0]!.history.at(-1)!.phase !== 'unknown' || entries[0]!.pendingReceivedHandoff ||
      [...prefix.entries.values()].some(entry => entry !== entries[0] && !entry.preparationClosure &&
        (!entry.result || entry.result.item.outcome === 'unknown')))
    return fail('publication wait requires its one unresolved original claim and complete other prefix');
  return entries[0]!;
}
function requireRetired(cut: RecoveryClosureV1, entry: RetainedPublicationOperation, driver: SqliteDriver) {
  if (entry.sequence === 'abort' && (!cut.run.stopIntentRef || entry.grant.format !== 'cliq-publication-maintenance-authority-v1'))
    fail('publication maintenance inspection requires its fully validated original stopping authority');
  const original = readWorkerLaunchesForRun(driver, cut.run.id).filter(launch => launch.leaseEpoch === entry.claim!.leaseEpoch &&
    (entry.sequence === 'abort' || launch.supervisorInstanceId === entry.claim!.supervisorInstanceId) && launch.retirementKind !== 'preparation');
  if (cut.run.activeWorkerLaunchId || cut.workerLaunches.length || !isZeroBudget(cut.run.budgetReserved) ||
      cut.workspaceGenerations.some(generation => !['sealed', 'retired'].includes(generation.phase)) ||
      original.length !== 1 || original[0]!.phase !== 'retired' ||
      !cut.workspaceGenerations.some(generation => generation.generationRef === original[0]!.workspaceGenerationRef &&
        (generation.phase === 'retired' || entry.sequence === 'abort' && generation.phase === 'sealed')))
    fail('publication inspection cannot replace the original worker-death or actual M retirement lifecycle');
}

/** A fixed friend of the original native producer, not an input/callback for
 * attaching a caller-selected Checkpoint. The real TX has already succeeded;
 * this synchronous cache handoff must finish before any cancellation point.
 * It grants neither cleanup nor a known result, and performs no CAS/full-R read. */
export function updatePublicationReconciliationProgress(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, task: DeliveryPublicationReconciliationTask, token: OwnedPublicationReconciliationProgress): void {
  const delta = readOwnedPublicationReconciliationProgress(driver, artifacts, owner, execution, task, token);
  const owned = probes.get(task);
  if (!owned || owned.driver !== driver || owned.artifacts !== artifacts || owned.owner !== owner || owned.execution !== execution)
    return fail('publication progress cannot replace its original persisted owning probe cache');
  const actual = sqlCut(driver, owned.selected.run.id, owned.selected.prefix.admission.source.run.id);
  if (owned.progressTransfer === token) {
    requireEqual(actual, owned.fingerprint, 'publication progress replay exact original installed SQL cut');
    return;
  }
  if (owned.progressTransfer || !owned.selected.entry.claim || owned.selected.entry.progress)
    return fail('publication probe cannot attach a second or unrelated progress transition');
  const { entry, cut } = owned.selected;
  const projected = projectPublicationProbeProgress(cut, { prepared: entry.prepared, claim: entry.claim!,
    planRef: entry.planRef, operation: entry.operation }, delta);
  const expected: ReturnType<typeof sqlCut> = { ...owned.fingerprint, selected: { ...owned.fingerprint.selected,
    run: projected.run, checkpoint: projected.latestCheckpoint, items: [...owned.fingerprint.selected.items, {
      item_id: delta.item.itemId, payload_ref: delta.item.payloadRef, item_seq: delta.item.itemSeq,
      kind: 'publication_path_progress', created_at: delta.item.createdAt }] } };
  requireEqual(actual, expected, 'publication progress exact single original-producer item, Checkpoint and Run delta');
  // This is the original reader's cut plus a genuine, already-committed
  // producer delta. It is only the closure cache, never a new validation or
  // permission to resume effect/cleanup from structural retained data.
  owned.selected = { ...owned.selected, run: projected.run, cut: { ...cut, ...projected } };
  owned.fingerprint = actual; owned.progressTransfer = token;
}

/** Original-producer audit only. Its one excluded item never closes a nonce,
 * settles a claim or obtains permission from a structurally valid fact. */
export const preparePublicationLateObservation = stateOperation('RECOVERY_REQUIRED', async (driver: SqliteDriver,
  artifacts: ArtifactCatalog, owner: StateOwnerContext, input: LateInput): Promise<LateWriter> => {
  exactInput(input, ['execution', 'lateObservation']); input = Object.freeze({ ...input });
  const existing = lateWriters.get(input.lateObservation);
  if (existing) {
    if (existing.driver !== driver || existing.artifacts !== artifacts || existing.owner !== owner || existing.input.execution !== input.execution)
      return fail('late audit cannot transfer its original producer');
    assertOwnedPublicationReconciliationTask(driver, owner, input.execution, existing.source.task, artifacts);
    return existing.writer;
  }
  let source = await readOwnedPublicationLateObservation(driver, artifacts, owner, input.execution, input.lateObservation);
  const state = source.wait.probeState, entry = source.entry, claim = entry.claim;
  if (!claim || state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight' ||
      state.dispatch.subjectKind !== 'publication' || source.completedAt <= state.dispatch.probeDeadlineAt)
    return fail('late audit lost its actual expired task and original claim');
  const at = sampleCanonicalNow();
  if (at < source.cut.run.updatedAt || at < source.completedAt) return fail('late audit creation regressed its actual receive time');
  const item = decodePublicationLateObservationItem({ schemaVersion: 1, kind: 'publication_late_observation',
    itemId: publicationLateObservationItemId(source.cut.run.id, claim.opId, 0, state.dispatch.dispatchDigest, source.evidenceRef),
    runId: source.cut.run.id, deliveryPlanRef: entry.planRef, sequence: entry.sequence, operationIndex: entry.operation.index,
    operationId: entry.operation.operationId, opId: claim.opId, attempt: 0, dispatchId: claim.dispatchId!, claimJournalSeq: claim.seq,
    probeWaitingSubjectRef: source.cut.run.waitingOnRef!, probeDispatchDigest: state.dispatch.dispatchDigest,
    disposition: source.disposition, evidenceRef: source.evidenceRef, evidenceDigest: source.evidence.proofDigest, completedAt: source.completedAt,
    ...(source.retirement ? { retirement: source.retirement } : {}), createdAt: at });
  const graph = planContinuationCommit(artifacts, { ...source.continuation, items: [item],
    checkpointId: publicationLateObservationCheckpointId(item.runId, item.opId, 0, item.probeDispatchDigest, item.evidenceRef),
    workspaceStateRef: source.cut.latestCheckpoint.workspaceStateRef });
  if (graph.runUpdate.frontierRef !== source.cut.run.frontierRef || graph.runUpdate.nextStep !== source.cut.run.nextStep)
    return fail('late audit cannot change its original publication frontier');
  const accept = (binding: LateBinding) => {
    const owned = probes.get(binding.source.task);
    if (!owned || owned.driver !== driver || owned.artifacts !== artifacts || owned.owner !== owner || owned.execution !== input.execution)
      return fail('late audit lost its original owning nonce closure cache');
    const accepted = acceptOwnedPublicationLateObservationAudit(driver, artifacts, owner, input.execution, input.lateObservation, item);
    const before = source.cut;
    const projected = projectPublicationLateObservation(before, item, accepted.cut.latestCheckpoint, accepted.cut.run);
    const actual = sqlCut(driver, item.runId, owned.selected.prefix.admission.source.run.id);
    const expected = { ...owned.fingerprint, selected: { ...owned.fingerprint.selected, run: projected.run,
      checkpoint: projected.latestCheckpoint, items: [...owned.fingerprint.selected.items,
        { item_id: item.itemId, payload_ref: canonicalSha256(item), item_seq: projected.items.length, kind: item.kind, created_at: item.createdAt }] } };
    requireEqual(actual, expected, 'late audit only installs its genuine original-producer item, CP and revision');
    owned.selected = { ...owned.selected, run: projected.run, cut: { ...owned.selected.cut, ...projected } };
    owned.fingerprint = actual; binding.accepted = true;
  };
  let binding!: LateBinding;
  const writer: LateWriter = Object.freeze({ commit(request) {
    exactInput(request, ['expectedRunRevision']);
    if (!Number.isSafeInteger(request.expectedRunRevision) || request.expectedRunRevision < 1)
      return Promise.reject(new KernelStorageError('INVALID_REQUEST', 'late audit requires its exact Run revision'));
    if (binding.working) return binding.working;
    binding.working = (async () => {
      if (binding.committed) {
        if (!binding.accepted) accept(binding);
        assertOwnedPublicationReconciliationTask(driver, owner, input.execution, source.task, artifacts);
        return immutableSnapshot(binding.committed);
      }
      source = await readOwnedPublicationLateObservation(driver, artifacts, owner, input.execution, input.lateObservation);
      binding.source = source;
      revision(source.cut.run, request.expectedRunRevision);
      const published = await graph.publish();
      source = await readOwnedPublicationLateObservation(driver, artifacts, owner, input.execution, input.lateObservation);
      binding.source = source;
      revision(source.cut.run, request.expectedRunRevision);
      let outcome: TimeFenceAdvance | undefined, committed!: Run;
      driver.transaction(connection => {
        assertOwnedPublicationLateObservationSql(driver, artifacts, owner, input.execution, input.lateObservation, connection);
        const actualRun = readRun(connection, item.runId); requireEqual(actualRun, source.cut.run, 'late audit exact original Run cut');
        const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
        if (outcome !== 'healthy') return;
        if (now < item.createdAt) fail('late audit commit regressed its original fact');
        for (const metadata of [...source.metadata, ...published.metadata]) insertArtifactMetadata(connection, metadata, now);
        graph.commit(connection, actualRun, source.cut.journal.length, now);
        connection.prepare('UPDATE runs SET revision=revision+1,updated_at=? WHERE id=?').run(now, item.runId);
        committed = readRun(connection, item.runId); appendRunStateEvent(connection, committed, now);
      });
      requireHealthyFence(outcome); binding.committed = committed;
      // No await/cancellation point between actual SQL commit and the two
      // original-owner caches accepting precisely this fixed producer delta.
      accept(binding); return immutableSnapshot(committed);
    })().finally(() => { binding.working = undefined; });
    return binding.working;
  } });
  binding = { driver, artifacts, owner, input, source, item, graph, writer, accepted: false };
  lateWriters.set(input.lateObservation, binding); return writer;
});

/** Full retained inspection input, with no live/native/release authority. */
export async function readPublicationReconciliation(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string) {
  const cut = await readRecoveryClosure(driver, artifacts, runId);
  if (cut.runSpec.operation !== 'delivery' || cut.run.status !== 'waiting' || cut.run.waitingReason !== 'reconciliation' || !cut.run.waitingOnRef)
    return undefined;
  const raw = await readCanonicalArtifact<{ subject?: { kind?: string } }>(artifacts, cut.run.waitingOnRef);
  if (raw.subject?.kind !== 'publication_path') return undefined;
  const wait = decodePublicationPathWait(raw), prefix = await readPublicationPrefix(driver, artifacts, cut), entry = unresolved(prefix);
  requireRetired(cut, entry, driver);
  await validatePublicationProbeWait(driver, artifacts, cut, prefix.admission, entry, wait);
  const state = wait.probeState;
  const frozen = (state.phase === 'automatic_in_flight' || state.phase === 'user_in_flight') && state.dispatch.subjectKind === 'publication'
    ? decodePublicationInspectionTarget(await readCanonicalArtifact(artifacts, state.dispatch.inspectionTargetDigest)) : undefined;
  const { target, settlement, unknown } = await readPublicationProbeTarget(artifacts, cut, entry, frozen);
  validatedSqlCut(driver, cut, prefix.admission.source);
  return { cut, prefix, admission: prefix.admission, run: cut.run, wait, target, entry, settlement, unknown };
}

export const preparePublicationReconciliation = stateOperation('RECOVERY_REQUIRED', async (driver: SqliteDriver,
  artifacts: ArtifactCatalog, owner: StateOwnerContext, input: TaskInput) => {
  exactInput(input, ['runId', 'expectedRunRevision', 'execution', 'task']);
  input = Object.freeze({ ...input });
  const resources = assertDeliveryPublicationReconciliationExecution(driver, owner, input.execution, input.task, artifacts);
  if (resources.runId !== input.runId || resources.expectedRunRevision !== input.expectedRunRevision) fail('publication wait lost its original owning task cut');
  const reads = artifacts.withReadSignal(resources.signal), cut = await readRecoveryClosure(driver, reads, input.runId);
  revision(cut.run, input.expectedRunRevision);
  if (cut.runSpec.operation !== 'delivery' || cut.run.status !== 'queued' || cut.run.nextStep !== 'delivery' || !cut.run.frontierRef)
    fail('publication wait requires its queued actual Delivery frontier');
  const prefix = await readPublicationPrefix(driver, reads, cut), entry = unresolved(prefix);
  requireRetired(cut, entry, driver);
  const { target, settlement, unknown } = await readPublicationProbeTarget(reads, cut, entry), createdAt = sampleCanonicalNow();
  if (createdAt < cut.run.updatedAt) fail('publication wait creation precedes its original Run cut');
  const wait = decodePublicationPathWait({ schemaVersion: 1, kind: 'reconciliation', runId: cut.run.id,
    createdFromRevision: cut.run.revision, createdAt, frontierRef: cut.run.frontierRef, subject: target.subject,
    probeState: { phase: 'automatic_pending', automaticProbeCount: 0, userProbeCount: 0, nextProbeAt: createdAt } });
  const accept = bindCut(driver, owner, cut, prefix.admission.source), artifact = await artifacts.publishCanonical(wait, 'cliq-waiting-subject-v1');
  let outcome: TimeFenceAdvance | undefined, run!: Run;
  driver.transaction(connection => {
    resources.signal.throwIfAborted(); assertDeliveryPublicationReconciliationExecution(driver, owner, input.execution, input.task, artifacts, connection);
    accept(connection); const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (outcome !== 'healthy') return;
    if (now < createdAt) fail('publication wait commit has a regressed time');
    insertArtifactMetadata(connection, artifact, now);
    connection.prepare("UPDATE runs SET status='waiting',waiting_reason='reconciliation',waiting_on_ref=?,revision=revision+1,updated_at=? WHERE id=?")
      .run(artifact.ref, now, cut.run.id);
    run = readRun(connection, cut.run.id); appendRunStateEvent(connection, run, now);
  });
  requireHealthyFence(outcome);
  return { cut: { ...cut, run }, prefix, admission: prefix.admission, run: immutableSnapshot(run), wait, target, entry, settlement, unknown };
});

/** Public replay stays independent of the RunExecution pending gate, but
 * still crosses the actual fresh authenticated frame and full source reader. */
export const replayPublicationReconciliationProbe = stateOperation('RECOVERY_REQUIRED', async (driver: SqliteDriver,
  artifacts: ArtifactCatalog, owner: StateOwnerContext, input: Mutation) => {
  exactInput(input, ['request', 'identity']); assertCurrentControlFrame(owner, input.identity);
  assertActiveStateOwner(driver, owner);
  const request = decodeInstalledControlRequest(input.request);
  if (request.method !== 'run.reconcile') throw new KernelStorageError('INVALID_REQUEST', 'publication probe requires run.reconcile probe_now');
  await validateControlChannelClosure(artifacts, owner, input.identity);
  const row = readControlRequest(driver, input.identity.principalId, 'run.reconcile', request.requestId);
  if (!row) return undefined;
  if (row.requestDigest !== request.requestDigest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'publication probe requestId was reused');
  const selected = readRun(driver, request.runId);
  if (readSessionPrincipalId(driver, selected.sessionId) !== input.identity.principalId)
    throw new KernelStorageError('NOT_FOUND', 'publication Run is unavailable');
  const cut = await readRecoveryClosure(driver, artifacts, request.runId), prefix = await readPublicationPrefix(driver, artifacts, cut);
  const response = decodeInstalledControlEnvelope(await readCanonicalArtifact(artifacts, row.responseRef), 'run.reconcile');
  if (!response.ok || response.result.method !== 'run.reconcile' || !response.result.snapshot.run.waitingOnRef)
    return fail('publication probe replay lost its original durable response');
  const wait = decodePublicationPathWait(await readCanonicalArtifact(artifacts, response.result.snapshot.run.waitingOnRef));
  const entry = [...prefix.entries.values()].find(value => value.operation.operationId === wait.subject.pathOperationId && value.planRef === wait.subject.deliveryPlanRef);
  if (!entry) return fail('publication probe replay lost its original permanent claim');
  await validatePublicationProbeWait(driver, artifacts, cut, prefix.admission, entry, wait);
  await readPublicationUserProbeSource(driver, artifacts, cut, wait);
  validatedSqlCut(driver, cut, prefix.admission.source); assertActiveStateOwner(driver, owner);
  assertCurrentControlFrame(owner, input.identity);
  if (wait.probeState.phase !== 'user_in_flight' || wait.probeState.dispatch.subjectKind !== 'publication')
    return fail('publication enqueue replay lost its exact original persisted inspection target');
  const frozen = decodePublicationInspectionTarget(await readCanonicalArtifact(artifacts, wait.probeState.dispatch.inspectionTargetDigest));
  const { target } = await readPublicationProbeTarget(artifacts, cut, entry, frozen);
  return immutableSnapshot({ run: response.result.snapshot.run, wait, target, response: response as Response, replayed: true });
});

export const beginPublicationReconciliationProbe = stateOperation('RECOVERY_REQUIRED', async (driver: SqliteDriver,
  artifacts: ArtifactCatalog, owner: StateOwnerContext, input: BeginInput) => {
  let mutation = Object.getOwnPropertyDescriptor(input, 'mutation')?.value as Mutation | undefined;
  exactInput(input, ['runId', 'expectedRunRevision', 'execution', 'task', ...(mutation ? ['mutation'] : [])]);
  input = Object.freeze({ ...input });
  if (mutation) {
    exactInput(mutation, ['request', 'identity']);
    const request = decodeInstalledControlRequest(mutation.request);
    if (request.method !== 'run.reconcile') throw new KernelStorageError('INVALID_REQUEST', 'publication user probe requires probe_now');
    mutation = Object.freeze({ request, identity: mutation.identity });
  }
  const resources = assertDeliveryPublicationReconciliationExecution(driver, owner, input.execution, input.task, artifacts);
  if (resources.runId !== input.runId) fail('publication probe task changed its Run');
  const reads = artifacts.withReadSignal(resources.signal);
  let channel: Awaited<ReturnType<typeof validateControlChannelClosure>> | undefined;
  if (mutation) {
    const replay = await replayPublicationReconciliationProbe(driver, reads, owner, mutation); if (replay) return replay;
    channel = await validateControlChannelClosure(reads, owner, mutation.identity);
    const selected = readRun(driver, input.runId);
    if (readSessionPrincipalId(driver, selected.sessionId) !== mutation.identity.principalId)
      throw new KernelStorageError('NOT_FOUND', 'publication Run is unavailable');
  }
  revision(readRun(driver, input.runId), input.expectedRunRevision);
  const selected = await readPublicationReconciliation(driver, reads, input.runId);
  if (!selected) throw new KernelStorageError('INVALID_REQUEST', 'publication probe requires its current publication wait');
  const { cut, run, wait, target, prefix } = selected; revision(run, input.expectedRunRevision);
  const state = wait.probeState, at = sampleCanonicalNow();
  if (mutation) {
    const request = mutation.request;
    if (request.method !== 'run.reconcile' || request.runId !== run.id || request.expectedRevision !== input.expectedRunRevision ||
        request.waitingOnRef !== run.waitingOnRef || request.resolution.kind !== 'probe_now' || state.phase !== 'automatic_exhausted' ||
        !Number.isSafeInteger(state.userProbeCount + 1))
      throw new KernelStorageError('INVALID_REQUEST', 'probe_now requires the exact exhausted publication wait');
  } else if (state.phase !== 'automatic_pending' || at < state.nextProbeAt)
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'publication automatic probe is not due or already in flight');
  const automatic = state.phase === 'automatic_pending', ordinal = automatic ? state.automaticProbeCount + 1 :
    state.phase === 'automatic_exhausted' ? state.userProbeCount + 1 : 0;
  const nonce = sha256Bytes(randomBytes(32)), kind = automatic ? 'automatic' : 'user_requested';
  const targetArtifact = await artifacts.publishCanonical(target, target.format);
  const dispatch: ReconciliationProbeDispatchV1 = { schemaVersion: 1, format: 'cliq-reconciliation-probe-dispatch-v1',
    runId: run.id, reconciliationSubjectDigest: canonicalSha256(wait.subject), probeKind: kind, probeOrdinal: ordinal,
    probeNonceDigest: nonce, probeStartedAt: at, probeDeadlineAt: addCanonicalDuration(at, 30_000),
    owningSupervisorInstanceId: owner.supervisorInstanceId, dispatchDigest: '', subjectKind: 'publication',
    inspectorTaskId: identityHash(run.id, canonicalSha256(wait.subject), kind, ordinal, nonce), inspectionTargetDigest: targetArtifact.ref,
    previousWaitingSubjectRef: run.waitingOnRef!, ...(mutation ? { controlRequestId: mutation.request.requestId,
      controlRequestDigest: mutation.request.requestDigest } : {}) };
  dispatch.dispatchDigest = digestOmitting(dispatch, 'dispatchDigest');
  const nextWait = decodePublicationPathWait({ ...wait, probeState: automatic
    ? { phase: 'automatic_in_flight', automaticProbeCount: ordinal, userProbeCount: 0, dispatch }
    : { phase: 'user_in_flight', automaticProbeCount: 8, userProbeCount: ordinal, dispatch } });
  const metadata = [targetArtifact, await artifacts.publishCanonical(dispatch, dispatch.format),
    await artifacts.publishCanonical(nextWait, 'cliq-waiting-subject-v1'), ...(channel?.metadata ?? [])];
  const nextRun: Run = { ...run, waitingOnRef: canonicalSha256(nextWait), revision: run.revision + 1, updatedAt: at };
  let response: Response | undefined, responseArtifact: PublishedArtifact | undefined;
  if (mutation) {
    const { requestDigest: _digest, ...core } = mutation.request;
    const coreArtifact = await artifacts.publishCanonical(core, 'cliq-run-reconcile-request-core-v1');
    if (coreArtifact.ref !== mutation.request.requestDigest) fail('publication probe changed its original public request bytes');
    response = { protocolVersion: 1, ok: true, result: { method: 'run.reconcile', snapshot: { schemaVersion: 1, operation: 'delivery',
      run: nextRun, latestRunItemSeq: cut.items.length }, resolution: { kind: 'probe_enqueued', dispatchDigest: dispatch.dispatchDigest, userProbeCount: ordinal } } };
    responseArtifact = await artifacts.publishCanonical(response, 'cliq-control-response-v1'); metadata.push(coreArtifact, responseArtifact);
  }
  const accept = bindCut(driver, owner, cut, prefix.admission.source);
  let outcome: TimeFenceAdvance | undefined, committed = false;
  driver.transaction(connection => {
    if (mutation) {
      assertCurrentControlFrame(owner, mutation.identity);
      if (readControlRequest(connection, mutation.identity.principalId, 'run.reconcile', mutation.request.requestId)) return;
    }
    resources.signal.throwIfAborted(); assertDeliveryPublicationReconciliationExecution(driver, owner, input.execution, input.task, artifacts, connection);
    accept(connection); const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (outcome !== 'healthy') return;
    if (now < at || now >= dispatch.probeDeadlineAt) fail('publication probe expired or regressed before dispatch commit');
    for (const artifact of metadata) insertArtifactMetadata(connection, artifact, at);
    connection.prepare('UPDATE runs SET waiting_on_ref=?,revision=revision+1,updated_at=? WHERE id=?').run(nextRun.waitingOnRef!, at, run.id);
    requireEqual(readRun(connection, run.id), nextRun, 'publication committed dispatch Run'); appendRunStateEvent(connection, nextRun, at);
    if (mutation) insertControlRequest(connection, { principalId: mutation.identity.principalId, method: 'run.reconcile',
      requestId: mutation.request.requestId, requestDigest: mutation.request.requestDigest, channelIdentityRef: mutation.identity.channelIdentityRef,
      channelIdentityDigest: mutation.identity.channelIdentityDigest, responseRef: responseArtifact!.ref, committedAt: at });
    committed = true;
  });
  requireHealthyFence(outcome);
  if (!committed && mutation) {
    const replay = await replayPublicationReconciliationProbe(driver, reads, owner, mutation); if (replay) return replay;
  }
  if (!committed) throw new KernelStorageError('REVISION_CONFLICT', 'publication probe enqueue changed before commit');
  probes.set(input.task, { driver, artifacts, owner, execution: input.execution, task: input.task,
    selected: { ...selected, cut: { ...cut, run: nextRun }, run: nextRun, wait: nextWait },
    fingerprint: sqlCut(driver, run.id, prefix.admission.source.run.id) });
  return immutableSnapshot({ run: nextRun, wait: nextWait, target, ...(response ? { response } : {}), replayed: false });
});

type CloseInput = TaskInput & { closure: { kind: 'shutdown'; receipt: PublicationReconciliationTaskReceipt } |
  { kind: 'deadline'; receipt?: PublicationReconciliationTaskReceipt } };
function inspectorFor(owner: ReturnType<typeof assertActiveStateOwner>): SupervisorInspectorIdentityV1 {
  const value: SupervisorInspectorIdentityV1 = { schemaVersion: 1, format: 'cliq-supervisor-inspector-identity-v1',
    supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: owner.ownerEpoch, runtimeBundleRef: owner.runtimeBundleRef,
    runtimeBundleManifestDigest: owner.runtimeBundleManifestDigest, supervisorEntryId: owner.supervisorEntryId,
    supervisorEntryVersion: owner.supervisorEntryVersion, supervisorExecutableDigest: owner.supervisorExecutableDigest,
    processIdentityRef: owner.processIdentityRef, processIdentityDigest: owner.processIdentityDigest,
    stateLockIdentityRef: owner.stateLockIdentityRef, stateLockIdentityDigest: owner.stateLockIdentityDigest,
    instanceNonceDigest: owner.instanceNonceDigest, activatedAt: owner.acquiredAt, identityDigest: '' };
  value.identityDigest = digestOmitting(value, 'identityDigest'); return value;
}

/** Only an actual joined original probe (or a later actual owner-death
 * timeout) closes a nonce. Shutdown does not need to wait for its deadline,
 * and never returns a path outcome or permission to repeat a syscall. */
export const closePublicationReconciliationProbe = stateOperation('RECOVERY_REQUIRED', async (driver: SqliteDriver,
  artifacts: ArtifactCatalog, owner: StateOwnerContext, input: CloseInput): Promise<Run> => {
  exactInput(input, ['runId', 'expectedRunRevision', 'execution', 'task', 'closure']);
  input = Object.freeze({ ...input });
  assertOwnedPublicationReconciliationTask(driver, owner, input.execution, input.task, artifacts);
  const kind = Object.getOwnPropertyDescriptor(input.closure, 'kind')?.value;
  exactInput(input.closure, ['kind', ...(Object.hasOwn(input.closure, 'receipt') ? ['receipt'] : [])]);
  if (kind !== 'shutdown' && kind !== 'deadline' || kind === 'shutdown' && !Object.hasOwn(input.closure, 'receipt'))
    throw new KernelStorageError('INVALID_REQUEST', 'publication probe closure requires its fixed shutdown or deadline branch');
  let owned = probes.get(input.task);
  if (owned && (owned.driver !== driver || owned.artifacts !== artifacts || owned.owner !== owner || owned.execution !== input.execution))
    fail('publication probe closure cannot transfer its original owning work');
  if (!owned) {
    if (kind === 'shutdown') fail('shutdown cannot adopt a task or nonce from another owner');
    const resources = assertDeliveryPublicationReconciliationExecution(driver, owner, input.execution, input.task, artifacts);
    const selected = await readPublicationReconciliation(driver, artifacts.withReadSignal(resources.signal), input.runId);
    if (!selected) return fail('publication deadline has no actual persisted wait');
    owned = { driver, artifacts, owner, execution: input.execution, task: input.task, selected,
      fingerprint: sqlCut(driver, selected.run.id, selected.prefix.admission.source.run.id) };
  }
  if (!owned) return fail('publication probe has no actual original owning task');
  const { selected } = owned, state = selected.wait.probeState;
  if (state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight') return fail('publication closure has no original in-flight task');
  const dispatch = state.dispatch;
  if (dispatch.subjectKind !== 'publication') return fail('publication task closure substituted its subject');
  const actual = sqlCut(driver, selected.run.id, selected.prefix.admission.source.run.id), run = actual.selected.run;
  revision(run, input.expectedRunRevision);
  const stable = ({ revision: _revision, updatedAt: _time, cancelRequested: _cancel, stopIntentRef: _stop, ...value }: Run) => value;
  requireEqual(stable(run), stable(selected.run), 'publication probe exact original wait while closing');
  requireEqual({ ...actual, selected: { ...actual.selected, run: selected.run } }, owned.fingerprint,
    'publication probe original source, resources, Journal and subject while closing');
  if (run.revision < selected.run.revision || selected.run.cancelRequested && !run.cancelRequested || run.updatedAt < selected.run.updatedAt)
    fail('publication probe closure regressed its monotonic Stop cut');
  if (canonicalSha256(run) !== canonicalSha256(selected.run)) {
    if (!run.stopIntentRef) fail('publication probe changed outside a monotonic Stop');
    const { readAgentStop, readRetainedAgentStop } = await import('./stop-recovery.js');
    const currentCut = { ...selected.cut, run };
    await readAgentStop(driver, artifacts, currentCut);
    if (selected.run.stopIntentRef) await readRetainedAgentStop(driver, artifacts, currentCut, selected.run.stopIntentRef);
  }
  const inspectingOwner = assertActiveStateOwner(driver, owner), closedAt = sampleCanonicalNow();
  if (kind === 'deadline' && closedAt < dispatch.probeDeadlineAt) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'publication probe deadline has not elapsed');
  let taskClosure: Extract<ReconciliationProbeTimeoutClosureV1, { subjectKind: 'publication' }>['taskClosure'];
  if (dispatch.owningSupervisorInstanceId === owner.supervisorInstanceId) {
    assertPublicationReconciliationTaskReceipt(input.closure.receipt,
      { driver, artifacts, owner, execution: input.execution, task: input.task, run, wait: selected.wait }, closedAt);
    taskClosure = { closureKind: 'cancelled_and_joined', inspectorTaskCancelledAndJoined: true };
  } else {
    if (kind === 'shutdown' || input.closure.receipt !== undefined) fail('only an original actual task may close during shutdown');
    const death = await readStateOwnerDeath(artifacts, driver, { supervisorInstanceId: dispatch.owningSupervisorInstanceId, ownedAt: dispatch.probeStartedAt });
    if (inspectingOwner.ownerEpoch < death.successorOwner.ownerEpoch || closedAt < death.successorOwner.acquiredAt)
      fail('publication timeout has no actual predecessor owner death');
    taskClosure = { closureKind: 'owner_process_dead', ownerDeathAcquisitionEvidenceRef: death.acquisitionEvidenceRef,
      ownerDeathAcquisitionEvidenceDigest: death.acquisitionEvidenceDigest };
  }
  const inspector = inspectorFor(inspectingOwner), inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const common = { schemaVersion: 1 as const, runId: run.id, waitingSubjectRef: run.waitingOnRef!, probeKind: dispatch.probeKind,
    probeOrdinal: dispatch.probeOrdinal, probeNonceDigest: dispatch.probeNonceDigest, probeDispatchDigest: dispatch.dispatchDigest,
    probeDeadlineAt: dispatch.probeDeadlineAt, inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
    closedAt, closureDigest: '', subjectKind: 'publication' as const, deliveryPlanRef: selected.wait.subject.deliveryPlanRef,
    pathOperationId: selected.wait.subject.pathOperationId, attempt: selected.wait.subject.attempt, inspectorTaskId: dispatch.inspectorTaskId };
  const closure: Extract<ReconciliationProbeCancellationClosureV1, { subjectKind: 'publication' }> |
    Extract<ReconciliationProbeTimeoutClosureV1, { subjectKind: 'publication' }> = kind === 'shutdown'
    ? { ...common, format: 'cliq-reconciliation-probe-cancellation-closure-v1', reason: 'owning_supervisor_shutdown',
      taskClosure: taskClosure as Extract<typeof taskClosure, { closureKind: 'cancelled_and_joined' }> }
    : { ...common, format: 'cliq-reconciliation-probe-timeout-closure-v1', taskClosure };
  closure.closureDigest = digestOmitting(closure, 'closureDigest');
  const closureArtifact = await artifacts.publishCanonical(closure, closure.format);
  const wrapper: ReconciliationProbeEvidenceV1 = { schemaVersion: 1, format: 'cliq-reconciliation-probe-evidence-v1', runId: run.id,
    waitingSubjectRef: run.waitingOnRef!, waitingSubjectDigest: run.waitingOnRef!, probeKind: dispatch.probeKind, probeOrdinal: dispatch.probeOrdinal,
    probeNonceDigest: dispatch.probeNonceDigest, probeDispatchDigest: dispatch.dispatchDigest, probeStartedAt: dispatch.probeStartedAt,
    probeDeadlineAt: dispatch.probeDeadlineAt, inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
    observedAt: closedAt, evidenceDigest: '', ...(kind === 'shutdown' ? { outcome: 'probe_cancelled' as const,
      cancellationReason: 'owning_supervisor_shutdown' as const, cancellationClosureRef: closureArtifact.ref, cancellationClosureDigest: closure.closureDigest }
      : { outcome: 'probe_timeout' as const, timeoutReason: 'no_authoritative_observation_before_deadline' as const,
        timeoutClosureRef: closureArtifact.ref, timeoutClosureDigest: closure.closureDigest }) };
  wrapper.evidenceDigest = digestOmitting(wrapper, 'evidenceDigest');
  const wrapperArtifact = await artifacts.publishCanonical(wrapper, wrapper.format);
  const evidence = { lastProbeEvidenceRef: wrapperArtifact.ref, lastProbeEvidenceDigest: wrapper.evidenceDigest };
  const nextWait = decodePublicationPathWait({ ...selected.wait, probeState: state.phase === 'user_in_flight' || state.automaticProbeCount === 8
    ? { phase: 'automatic_exhausted', automaticProbeCount: 8, userProbeCount: state.userProbeCount, ...evidence }
    : { phase: 'automatic_pending', automaticProbeCount: state.automaticProbeCount, userProbeCount: 0,
      nextProbeAt: addCanonicalDuration(closedAt, WORKER_PROBE_BACKOFF_MS[state.automaticProbeCount - 1]!), ...evidence } });
  const waitArtifact = await artifacts.publishCanonical(nextWait, 'cliq-waiting-subject-v1'), fingerprint = canonicalSha256(actual);
  let outcome: TimeFenceAdvance | undefined, updated!: Run;
  driver.transaction(connection => {
    assertOwnedPublicationReconciliationTask(driver, owner, input.execution, input.task, artifacts); assertActiveStateOwner(connection, owner);
    if (canonicalSha256(sqlCut(connection, run.id, selected.prefix.admission.source.run.id)) !== fingerprint)
      throw new KernelStorageError('REVISION_CONFLICT', 'publication probe closure lost its exact actual task and Stop cut');
    const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (outcome !== 'healthy') return;
    if (now < closedAt) fail('publication probe closure commit regressed its actual join time');
    for (const artifact of [inspectorArtifact, closureArtifact, wrapperArtifact, waitArtifact]) insertArtifactMetadata(connection, artifact, now);
    connection.prepare('UPDATE runs SET waiting_on_ref=?,revision=revision+1,updated_at=? WHERE id=?').run(waitArtifact.ref, now, run.id);
    updated = readRun(connection, run.id); appendRunStateEvent(connection, updated, now);
  });
  requireHealthyFence(outcome); probes.delete(input.task); return immutableSnapshot(updated);
});
