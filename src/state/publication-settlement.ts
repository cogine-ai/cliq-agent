import { canonicalSha256 } from '../kernel/canonical.js';
import { decodePublicationPathResultItem, type PublicationPathResultItem } from '../kernel/publication.js';
import type { BudgetSettlementV1, ContinuationItem, InvocationJournalEntry, RecoveryClosureV1, Run, RunFrontier } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { selectAgentStop, type AgentStopIntent } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { addCanonicalDuration } from '../kernel/identity.js';
import { planContinuationCommit } from './continuation-commit.js';
import { decodeBudgetSettlement, decodeContextManifest } from './decoders.js';
import { assertPublicationReadCut, publicationResultCheckpointId, publicationResultItemId, readPublicationPrefix } from './delivery-publication-progress.js';
import { readDeliveryTerminalProjection } from './delivery-publication-recovery.js';
import { KernelStorageError } from './errors.js';
import { assertOwnedPublicationArtifacts, readOwnedPublicationCompletion, readOwnedPublicationPreparationClosure,
  type OwnedPublicationInitialAmbiguity, type OwnedPublicationReconciliationResult, type PublicationInvocationOwner } from './publication-invocation.js';
import { closeOwnedPublicationFinalization, commitOwnedPublicationFinalization, isOwnedPublicationSessionConflict,
  prepareOwnedPublicationFinalization, readOwnedPublicationFinalizationMetadata, validateOwnedPublicationFinalization,
  readOwnedPublicationReceivedResult, type OwnedPublicationFinalization, type OwnedPublicationReceivedResult } from './publication-finalization.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { appendRunStateEvent, preparePublicationInvocationSettlement, preparePublicationReconciliationInvocationSettlement,
  requireHealthyFence, type SettlementContinuation } from './reducers/invocation.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { readCheckpoint, readRun, readSession, ZERO_BUDGET } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readAgentStop } from './stop-recovery.js';
import { decodeRunResult } from './result-artifacts.js';
import { decodePublicationPathWait } from './publication-reconciliation-artifacts.js';
import { WORKER_PROBE_BACKOFF_MS } from './worker-recovery.js';

type Completion = ReturnType<typeof readOwnedPublicationCompletion>;
type Prefix = Awaited<ReturnType<typeof readPublicationPrefix>>;
type Selection = { cut: RecoveryClosureV1; prefix: Prefix; assertCut(connection: SqliteConnection): void; stop?: AgentStopIntent };
type Result = { run: Run; entry: InvocationJournalEntry; settlement: BudgetSettlementV1 };
type Input = { execution: unknown; publicationOwner: PublicationInvocationOwner };
type ReceivedCompletion = ReturnType<typeof readOwnedPublicationReceivedResult>['completion'];
type ReceivedInput = { execution: unknown; receivedResult: OwnedPublicationReceivedResult };
const CHARGE = Object.freeze({ ...ZERO_BUDGET, toolCalls: 1 });

function retirement(completion: Completion) {
  if (completion.disposition === 'unknown') return undefined;
  if (!completion.arenaRetirementRef || completion.slotObservationRefs.length < 1 || completion.slotObservationRefs.length > 2)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'known publication lost its actual original retired arena or private-slot observations');
  return { slotObservationRefs: [...completion.slotObservationRefs], arenaRetirementRef: completion.arenaRetirementRef };
}
function terminal(completion: Completion) {
  retirement(completion);
  const evidence = { evidenceRef: completion.evidenceRef, evidenceDigest: completion.evidence.proofDigest };
  const consumed = completion.birth.sequence === 'forward' ? CHARGE : ZERO_BUDGET;
  if (completion.disposition === 'received') {
    if (completion.evidence.kind !== 'terminal_receipt' || completion.receiptRef !== completion.evidenceRef || !completion.progressCommitted)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'publication completion lost its actual receipt or durable progress');
    return { phase: 'completed' as const, receiptRef: completion.receiptRef, ...evidence, consumed };
  }
  if (completion.disposition === 'unknown') {
    if (completion.evidence.kind !== 'path_ambiguity' || completion.receiptRef !== undefined)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'publication ambiguity cannot supply a completed receipt');
    return { phase: 'unknown' as const, ...evidence };
  }
  if (completion.disposition === 'retained_planned_descendant') {
    if (completion.birth.sequence !== 'abort' || completion.evidence.kind !== 'planned_descendant' ||
        completion.receiptRef !== undefined || completion.progressCommitted)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'retained maintenance descendants have no genuine original observation');
    return { phase: 'failed' as const, errorRef: completion.evidenceRef, ...evidence, consumed, requireClaim: true };
  }
  if (completion.evidence.kind !== 'path_observation' || completion.receiptRef !== undefined || completion.progressCommitted)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'unreleased publication has no exact original observation');
  // The real observation is the retained failed outcome, not a fabricated
  // provider/tool-error payload. Its once-reserved forward envelope is charged.
  return { phase: 'failed' as const, errorRef: completion.evidenceRef, ...evidence, consumed, requireClaim: true };
}
type Binding = {
  kind: 'path';
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; execution: unknown; publicationOwner: PublicationInvocationOwner;
  completion: Completion; terminal: ReturnType<typeof terminal>; input: { runId: string; opId: string; attempt: number };
  selection?: Selection; observedStop?: AgentStopIntent; item?: PublicationPathResultItem;
  graphs: Map<string, ReturnType<typeof planContinuationCommit>>; settling?: Promise<Result>;
  reducer: ReturnType<typeof preparePublicationInvocationSettlement>;
  continuation: SettlementContinuation; validateSnapshot(connection: SqliteConnection, run: Run): void;
  facade: Readonly<{ settle(input: { expectedRunRevision: number }): Promise<Result> }>;
};
type ReceivedBinding = {
  kind: 'received'; driver: SqliteDriver; artifacts: ArtifactCatalog; reads: ArtifactCatalog; owner: StateOwnerContext;
  execution: unknown; receivedResult: OwnedPublicationReceivedResult; completion: ReceivedCompletion;
  input: { runId: string; opId: string; attempt: number };
  terminal: { phase: 'completed'; receiptRef: string; evidenceRef: string; evidenceDigest: string; consumed: typeof CHARGE };
  selection?: Selection; observedStop?: AgentStopIntent; finalization?: OwnedPublicationFinalization;
  graphs: Map<string, ReturnType<typeof planContinuationCommit>>; settling?: Promise<Result>;
  reducer: ReturnType<typeof preparePublicationInvocationSettlement>;
  resolvedUnknown?: { unknown: InvocationJournalEntry; settlement: BudgetSettlementV1 }; resolution?: Resolution; resolutionCreatedAt?: string;
  continuation: SettlementContinuation; validateSnapshot(connection: SqliteConnection, run: Run): void;
  facade: Binding['facade'];
};
type Resolution = {
  input: { runId: string; opId: string; attempt: number }; artifacts: ArtifactCatalog;
  prepared: InvocationJournalEntry; claim: InvocationJournalEntry; unknown: InvocationJournalEntry;
  settlement: BudgetSettlementV1; journalSeq: number; observedAt: string; metadata: PublishedArtifact[];
  terminal: { phase: 'completed'; receiptRef: string; evidenceRef: string; evidenceDigest: string } |
    { phase: 'failed'; errorRef: string; evidenceRef: string; evidenceDigest: string };
  continuation: SettlementContinuation; validateSnapshot(connection: SqliteConnection, run: Run): void;
};
type RecoveryMaterial = Awaited<ReturnType<typeof import('./publication-invocation.js')['readOwnedPublicationReconciliationResult']>>;
type RecoveryBinding = {
  kind: 'reconciliation'; driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; execution: unknown;
  recoveryResult: OwnedPublicationReconciliationResult; current: RecoveryMaterial;
  input: Resolution['input']; settlement: BudgetSettlementV1; resolution?: Resolution;
  sql(connection: SqliteConnection): void; continuation: SettlementContinuation;
  reducer: ReturnType<typeof preparePublicationReconciliationInvocationSettlement>;
  facade: Binding['facade']; settling?: Promise<Result>; committed?: Result; createdAt?: string;
};
type InitialMaterial = Awaited<ReturnType<typeof import('./publication-invocation.js')['readOwnedPublicationInitialAmbiguity']>>;
type InitialBinding = {
  kind: 'initial_ambiguity'; driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; execution?: never;
  initialAmbiguity: OwnedPublicationInitialAmbiguity; current: InitialMaterial; input: Resolution['input'];
  terminal: { phase: 'unknown'; evidenceRef: string; evidenceDigest: string };
  continuation: SettlementContinuation; validateSnapshot(connection: SqliteConnection, run: Run): void;
  reducer: ReturnType<typeof preparePublicationInvocationSettlement>; facade: Binding['facade']; settling?: Promise<Result>; committed?: Result;
};
type PreparationCompletion = ReturnType<typeof readOwnedPublicationPreparationClosure>;
type PreparationBinding = {
  kind: 'preparation'; driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; execution: unknown;
  publicationOwner: PublicationInvocationOwner; completion: PreparationCompletion;
  input: { runId: string; opId: string; attempt: number };
  terminal: { phase: 'failed'; errorRef: string; consumed: typeof ZERO_BUDGET; requireClaim: false };
  continuation: SettlementContinuation; validateSnapshot(connection: SqliteConnection, run: Run): void;
  reducer: ReturnType<typeof preparePublicationInvocationSettlement>; selection?: Selection; observedStop?: AgentStopIntent;
  settling?: Promise<Result>; settledFromRevision?: number; facade: Binding['facade'];
};
const bindings = new WeakMap<object, Binding | PreparationBinding | ReceivedBinding | RecoveryBinding | InitialBinding>();
function invalid(message: string): never { throw new KernelStorageError('STATE_TRANSITION_INVALID', message); }
function closed(value: unknown, keys: readonly string[], message: string) {
  if (!value || typeof value !== 'object') throw new TypeError(message);
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !Object.hasOwn(fields, key)) ||
      Object.values(fields).some(field => !field.enumerable || !Object.hasOwn(field, 'value') || field.value === undefined)) throw new TypeError(message);
}
function original(binding: Binding) {
  const completion = readOwnedPublicationCompletion(binding.driver, binding.owner, binding.execution, binding.publicationOwner);
  if (completion.disposition !== binding.completion.disposition || completion.evidenceRef !== binding.completion.evidenceRef ||
      completion.planRef !== binding.completion.planRef || completion.prepared.opId !== binding.input.opId ||
      completion.claim.dispatchId !== binding.completion.claim.dispatchId)
    invalid('publication settlement cannot reinterpret a different original native completion');
  requireEqual(completion.evidence, binding.completion.evidence, 'publication same original physical evidence');
  if (completion.disposition !== 'unknown') requireEqual(retirement(completion), retirement(binding.completion),
    'publication exact original retired arena and slot observations');
  requireEqual(terminal(completion), binding.terminal, 'publication exact original terminal outcome');
  return completion;
}
function sqlCut(connection: SqliteConnection, binding: Pick<Binding, 'input'>, sourceRunId: string) {
  const run = readRun(connection, binding.input.runId), source = readRun(connection, sourceRunId);
  const session = readSession(connection, run.sessionId), sourceSession = readSession(connection, source.sessionId);
  return { run, checkpoint: readCheckpoint(connection, run.latestCheckpointId), journal: readInvocationJournal(connection, run.id),
    launches: readWorkerLaunchesForRun(connection, run.id), generations: readWorkspaceGenerationsForRun(connection, run.id),
    items: connection.prepare('SELECT item_id,item_seq,kind,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
      .all<{ item_id: string; item_seq: bigint; kind: string; payload_ref: string; created_at: string }>(run.id)
      .map(row => ({ ...row, item_seq: Number(row.item_seq) })), source,
    session: { id: session.id, workspaceIdentityRef: session.workspaceIdentityRef, createdAt: session.createdAt },
    sourceSession: { id: sourceSession.id, workspaceIdentityRef: sourceSession.workspaceIdentityRef, createdAt: sourceSession.createdAt },
    children: !!connection.prepare('SELECT 1 FROM child_allocations WHERE parent_run_id=? OR child_run_id=? LIMIT 1').get(run.id, run.id) ||
      !!connection.prepare('SELECT 1 FROM runs WHERE parent_run_id=? LIMIT 1').get(run.id) };
}
async function select(binding: Binding): Promise<Selection> {
  const completion = original(binding), { driver, artifacts } = binding;
  const cut = await readRecoveryClosure(driver, artifacts, binding.input.runId), prefix = await readPublicationPrefix(driver, artifacts, cut);
  const entry = prefix.entries.get(binding.input.opId), authorization = prefix.authorization;
  if (!entry?.claim || !entry.birth || !authorization || entry.sequence !== completion.birth.sequence ||
      entry.operation.operationId !== completion.operation.operationId || entry.planRef !== completion.planRef)
    invalid('publication settlement has no exact current original forward prefix');
  requireEqual(entry.prepared, completion.prepared, 'publication settlement original preparation');
  requireEqual(entry.claim, completion.claim, 'publication settlement original permanent claim');
  requireEqual(entry.birth, completion.birth, 'publication settlement original native arena birth');
  requireEqual(entry.plan, completion.plan, 'publication settlement complete original Plan');
  if (!entry.result) {
    if (cut.run.nextStep !== 'delivery' || !cut.run.frontierRef ||
        (entry.sequence === 'forward' ? cut.run.status !== 'running' || prefix.abortResults.length || prefix.forward.at(-1) !== entry :
          !['queued', 'running'].includes(cut.run.status) || !cut.run.stopIntentRef || prefix.abort.at(-1) !== entry))
      invalid('publication settlement is not its exact current unpublished result cut');
    const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, cut.run.frontierRef);
    requireEqual(frontier, { ...authorization.frontier, phase: entry.sequence === 'forward' ? 'publish' : 'abort_cleanup', nextPathOperationIndex: entry.operation.index },
      'publication settlement exact current unpublished result frontier');
  }
  const stop = cut.run.stopIntentRef ? await readAgentStop(driver, artifacts, cut) : undefined;
  if (binding.observedStop && (!stop || canonicalSha256(stop) !== canonicalSha256(binding.observedStop) && selectAgentStop(binding.observedStop, stop) !== stop))
    invalid('publication settlement lost its winning original StopIntent');
  if (stop) binding.observedStop = stop;
  await assertPublicationReadCut(driver, artifacts, cut);
  const fingerprint = canonicalSha256(sqlCut(driver, binding, prefix.admission.source.run.id));
  const assertCut = (connection: SqliteConnection) => {
    assertActiveStateOwner(connection, binding.owner);
    if (canonicalSha256(sqlCut(connection, binding, prefix.admission.source.run.id)) !== fingerprint)
      throw new KernelStorageError('REVISION_CONFLICT', 'publication result lost its original current Run, Stop or dispatch cut');
    original(binding);
  };
  return { cut, prefix, assertCut, ...(stop ? { stop } : {}) };
}

/** Private invocation friend. Only the actual adapter registered for this same
 * original native owner can provide its terminal data and SQL continuation. */
export function assertPublicationSettlementForInvocation(driver: SqliteDriver, owner: StateOwnerContext,
  publicationOwner: PublicationInvocationOwner | OwnedPublicationReceivedResult | OwnedPublicationInitialAmbiguity) {
  const binding = bindings.get(publicationOwner);
  if (!binding || binding.driver !== driver || binding.owner !== owner)
    throw new TypeError('publication settlement requires its exact original registered completion owner');
  if (binding.kind === 'reconciliation') throw new TypeError('publication recovery requires its exact original registered reconciliation owner');
  if (binding.kind === 'received' && binding.resolvedUnknown)
    throw new TypeError('publication UNKNOWN requires its exact original registered reconciliation owner');
  if (binding.kind === 'initial_ambiguity') {
    binding.validateSnapshot(driver, binding.current.cut.run);
    return { kind: binding.kind, input: binding.input, terminal: binding.terminal, continuation: binding.continuation,
      validateSnapshot: binding.validateSnapshot, artifacts: binding.artifacts, readArtifacts: binding.artifacts };
  }
  if (binding.kind === 'path') original(binding);
  else if (binding.kind === 'received') originalReceived(binding);
  else originalPreparation(binding);
  return { kind: binding.kind, input: binding.input, terminal: binding.terminal, continuation: binding.continuation, validateSnapshot: binding.validateSnapshot,
    artifacts: binding.artifacts, readArtifacts: binding.kind === 'received' ? binding.reads : binding.artifacts };
}

function validateInitialAmbiguity(material: InitialMaterial) {
  const { cut, entry, prepared, claim } = material;
  requireEqual(prepared, entry.prepared, 'publication initial ambiguity exact original preparation');
  requireEqual(claim, entry.claim, 'publication initial ambiguity exact original permanent claim');
  requireEqual(prepared.budgetDelta, entry.sequence === 'forward' ? CHARGE : ZERO_BUDGET,
    'publication initial ambiguity exact original reservation');
  if (entry.result || entry.pendingReceivedHandoff || entry.preparationClosure || entry.history.length !== 2 ||
      entry.history[0]!.phase !== 'prepared' || entry.history[1]!.phase !== 'dispatch_claimed' || claim.seq !== cut.journal.length ||
      material.evidence.kind !== 'path_ambiguity' || material.evidenceRef !== canonicalSha256(material.evidence))
    invalid('publication initial ambiguity has no exact original unsettled claim and conservative observation');
  if (material.kind === 'closed_maintenance') {
    if (entry.sequence !== 'abort' || entry.operation.kind !== 'abort_rmdir' ||
        entry.grant.format !== 'cliq-publication-maintenance-authority-v1' || !cut.run.stopIntentRef ||
        cut.run.status !== 'queued' || cut.run.waitingOnRef || cut.run.activeWorkerLaunchId || cut.workerLaunches.length ||
        cut.workspaceGenerations.some(row => !['sealed', 'retired'].includes(row.phase)))
      invalid('publication initial maintenance ambiguity cannot substitute a worker-death wait or productive claim');
    requireEqual(cut.run.budgetReserved, ZERO_BUDGET, 'publication initial maintenance has no productive reservation');
  } else if (material.kind !== 'worker_death' || !material.wait || cut.run.status !== 'waiting' ||
      cut.run.waitingReason !== 'reconciliation' || canonicalSha256(material.wait) !== cut.run.waitingOnRef ||
      material.wait.subject.kind !== 'worker_death')
    invalid('publication initial worker ambiguity lost its actual original worker-death wait');
}

/** Either the real worker-death producer or the distinct worker-free stopped
 * maintenance task owns this first pessimistic observation. Neither recreates
 * the old native path, and maintenance never manufactures worker-death data. */
export async function preparePublicationInitialAmbiguitySettlement(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, token: OwnedPublicationInitialAmbiguity): Promise<Binding['facade']> {
  const native = await import('./publication-invocation.js');
  const current = await native.readOwnedPublicationInitialAmbiguity(driver, artifacts, owner, token);
  validateInitialAmbiguity(current);
  const prior = bindings.get(token);
  if (prior) {
    if (prior.kind !== 'initial_ambiguity' || prior.driver !== driver || prior.artifacts !== artifacts || prior.owner !== owner)
      throw new TypeError('publication initial ambiguity cannot transfer its original native death owner');
    return prior.facade;
  }
  const binding: InitialBinding = { kind: 'initial_ambiguity', driver, artifacts, owner, initialAmbiguity: token, current,
    input: { runId: current.cut.run.id, opId: current.prepared.opId, attempt: current.prepared.attempt },
    terminal: { phase: 'unknown', evidenceRef: current.evidenceRef, evidenceDigest: current.evidence.proofDigest },
    reducer: preparePublicationInvocationSettlement(driver, artifacts, owner, token),
    validateSnapshot(connection, run) {
      requireEqual(run, binding.current.cut.run, 'publication initial ambiguity original owning cut');
      native.assertOwnedPublicationInitialAmbiguitySql(driver, artifacts, owner, token, connection);
    },
    async continuation({ run, prepared, settlement }) {
      const actual = binding.current;
      requireEqual(prepared, actual.prepared, 'publication initial conservative original preparation');
      requireEqual(run, actual.cut.run, 'publication initial conservative owning cut');
      if (settlement.terminalPhase !== 'unknown' || settlement.preparedJournalSeq !== prepared.seq ||
          settlement.settledAt < actual.evidence.observedAt) invalid('publication initial ambiguity changed its one conservative settlement');
      requireEqual(settlement.consumed, prepared.budgetDelta, 'publication initial ambiguity full original reservation charge');
      requireEqual(settlement.reserved, prepared.budgetDelta, 'publication initial ambiguity exact original reservation');
      requireEqual(settlement.released, prepared.budgetDelta, 'publication initial ambiguity exact original reservation release');
      const item = decodePublicationPathResultItem({ schemaVersion: 1, kind: 'publication_path_result',
        itemId: publicationResultItemId(run.id, prepared.opId, prepared.attempt, actual.evidenceRef), runId: run.id,
        deliveryPlanRef: actual.entry.planRef, sequence: actual.entry.sequence, operationIndex: actual.entry.operation.index,
        operationId: actual.entry.operation.operationId, opId: prepared.opId, attempt: prepared.attempt,
        outcome: 'unknown', evidenceRef: actual.evidenceRef, createdAt: settlement.settledAt });
      const graph = await planContinuationCommit(artifacts, { ...actual.continuation, items: [item],
        checkpointId: publicationResultCheckpointId(run.id, prepared.opId, prepared.attempt, actual.evidenceRef),
        workspaceStateRef: actual.cut.latestCheckpoint.workspaceStateRef }).publish();
      return { metadata: [...actual.metadata, ...graph.metadata], validate(connection, current, now) {
        binding.validateSnapshot(connection, current);
        if (now < item.createdAt || now < actual.evidence.observedAt) invalid('publication initial ambiguity precedes its actual observation');
      }, commit(connection, current, journal, now) {
        graph.commit(connection, current, journal.seq, now);
        // This CP adds only excluded audit data to the same W_M. The actual
        // worker wait/anchor/fenced cursor or worker-free maintenance frontier
        // is never replaced by a path wait here.
        const updated = readRun(connection, current.id);
        requireEqual({ ...updated, revision: current.revision, updatedAt: current.updatedAt,
          latestCheckpointId: current.latestCheckpointId }, { ...current, budgetReserved: settlement.budgetReservedAfter,
          budgetConsumed: settlement.budgetConsumedAfter }, 'initial ambiguity preserves its owning cut and exactly one conservative settlement');
      } };
    }, facade: Object.freeze({ settle(request: { expectedRunRevision: number }) {
      closed(request, ['expectedRunRevision'], 'initial ambiguity settlement requires its original expected revision');
      if (!Number.isSafeInteger(request.expectedRunRevision) || request.expectedRunRevision < 1) throw new TypeError('initial ambiguity expected revision is invalid');
      if (binding.settling) return Promise.reject(new KernelStorageError('STATE_TRANSITION_INVALID', 'initial ambiguity settlement is already in flight'));
      binding.settling = (async () => {
        if (binding.committed) return binding.committed;
        binding.current = await native.readOwnedPublicationInitialAmbiguity(driver, artifacts, owner, token);
        validateInitialAmbiguity(binding.current);
        if (binding.current.cut.run.revision !== request.expectedRunRevision)
          throw new KernelStorageError('REVISION_CONFLICT', 'publication initial ambiguity Run revision changed');
        return binding.committed = immutableSnapshot(await binding.reducer.settle(request.expectedRunRevision));
      })().finally(() => { binding.settling = undefined; });
      return binding.settling;
    } }) };
  bindings.set(token, binding); return binding.facade;
}

/** Fixed ZERO writer friend. The key was registered only after the genuine
 * received task/native result and its complete original UNKNOWN graph. */
export function assertPublicationReconciliationSettlementForInvocation(driver: SqliteDriver, owner: StateOwnerContext,
  key: OwnedPublicationReconciliationResult | OwnedPublicationReceivedResult): Resolution {
  const binding = bindings.get(key);
  if (!binding || binding.driver !== driver || binding.owner !== owner ||
      (binding.kind !== 'reconciliation' && binding.kind !== 'received'))
    throw new TypeError('publication resolution requires its exact original registered reconciliation owner');
  if (!binding.resolution || binding.kind === 'received' && !binding.resolvedUnknown)
    throw new TypeError('publication resolution requires its exact original registered reconciliation owner');
  if (binding.kind === 'reconciliation') { binding.sql(driver); return binding.resolution; }
  originalReceived(binding); return binding.resolution;
}

/** The actual descriptor-only inspection fixes every outcome/ref here. The
 * public generic invocation APIs cannot enter this same-claim ZERO writer. */
export async function preparePublicationReconciliationSettlement(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, input: { execution: unknown; recoveryResult: OwnedPublicationReconciliationResult }): Promise<Binding['facade']> {
  closed(input, ['execution', 'recoveryResult'], 'settlement requires one closed original publication inspection input');
  const native = await import('./publication-invocation.js');
  const material = await native.readOwnedPublicationReconciliationResult(driver, artifacts, owner, input.execution, input.recoveryResult);
  const prior = bindings.get(input.recoveryResult);
  if (prior) {
    if (prior.kind !== 'reconciliation' || prior.driver !== driver || prior.artifacts !== artifacts || prior.owner !== owner || prior.execution !== input.execution)
      throw new TypeError('publication inspection cannot transfer its original ZERO result owner');
    return prior.facade;
  }
  if (!material.unknown.budgetSettlementRef) invalid('publication inspection lost its actual original UNKNOWN settlement');
  // The genuine producer fully read this original immutable CAS object before
  // its first native I/O. Shutdown must not erase a received result by aborting
  // a redundant read of those same fixed bytes afterwards.
  const settlement = decodeBudgetSettlement(material.settlement);
  if (canonicalSha256(settlement) !== material.unknown.budgetSettlementRef || settlement.terminalPhase !== 'unknown' ||
      settlement.runId !== material.run.id || settlement.opId !== material.prepared.opId || settlement.attempt !== material.prepared.attempt ||
      settlement.preparedJournalSeq !== material.prepared.seq || settlement.terminalJournalSeq !== material.unknown.seq ||
      settlement.settledAt !== material.unknown.timestamp)
    invalid('publication inspection substituted its original immutable BudgetSet');
  requireEqual(settlement.reserved, material.prepared.budgetDelta, 'publication inspection original reservation');
  requireEqual(settlement.released, material.prepared.budgetDelta, 'publication inspection original reservation release');
  requireEqual(settlement.consumed, material.birth.sequence === 'forward' ? CHARGE : ZERO_BUDGET, 'publication original once-only conservative charge');
  requireEqual(material.unknown.budgetDelta, settlement.consumed, 'publication original UNKNOWN accounted delta');
  const binding: RecoveryBinding = { kind: 'reconciliation', driver, artifacts, owner, execution: input.execution,
    recoveryResult: input.recoveryResult, current: material, settlement,
    input: { runId: material.run.id, opId: material.prepared.opId, attempt: material.prepared.attempt },
    sql(connection) { native.assertOwnedPublicationReconciliationSql(driver, artifacts, owner, input.execution, input.recoveryResult, connection); },
    reducer: preparePublicationReconciliationInvocationSettlement(driver, artifacts, owner, input.recoveryResult),
    async continuation({ run, prepared, settlement: originalSettlement }) {
      const actual = binding.current;
      requireEqual(run, actual.cut.run, 'publication reconciliation same original selected Run');
      requireEqual(prepared, actual.prepared, 'publication reconciliation original preparation');
      requireEqual(originalSettlement, binding.settlement, 'publication reconciliation retains its original UNKNOWN BudgetSet');
      if (actual.disposition === 'unknown') invalid('an unresolved probe cannot append a terminal invocation or advance its frontier');
      if (actual.disposition === 'received' && actual.isLastForwardPath)
        invalid('reconciled last publication must first commit its genuine received-result handoff');
      const stop = actual.cut.run.stopIntentRef ? await readAgentStop(driver, artifacts, actual.cut) : undefined;
      const abortStop = actual.birth.sequence === 'forward' ? stop : undefined;
      binding.createdAt ??= sampleCanonicalNow();
      if (abortStop && abortStop.createdAt > binding.createdAt) binding.createdAt = abortStop.createdAt;
      const completed = actual.disposition === 'received';
      if (!actual.retirement)
        invalid('reconciled known result has not joined its complete original envelope');
      const item = decodePublicationPathResultItem({ schemaVersion: 1, kind: 'publication_path_result',
        itemId: publicationResultItemId(run.id, prepared.opId, prepared.attempt, actual.evidenceRef), runId: run.id,
        deliveryPlanRef: actual.planRef, sequence: actual.birth.sequence, operationIndex: actual.operation.index,
        operationId: actual.operation.operationId, opId: prepared.opId, attempt: prepared.attempt,
        outcome: completed ? 'completed' : actual.disposition === 'retained_planned_descendant' ? 'retained_planned_descendant' : 'failed',
        evidenceRef: actual.evidenceRef, ...(completed ? { receiptRef: actual.receiptRef } : {}),
        retirement: actual.retirement,
        reconciliationEvidenceRef: actual.wrapperRef, reconciliationEvidenceDigest: actual.wrapper.evidenceDigest,
        ...(abortStop ? { abortStopIntentRef: canonicalSha256(abortStop) } : {}), createdAt: binding.createdAt });
      const frontier: RunFrontier = { ...actual.prefix.authorization!.frontier,
        phase: actual.birth.sequence === 'abort' || abortStop ? 'abort_cleanup' : 'publish',
        nextPathOperationIndex: abortStop ? 0 : actual.operation.index +
          (completed || actual.disposition === 'retained_planned_descendant' ? 1 : 0) };
      const graph = await planContinuationCommit(artifacts, { ...actual.continuation, items: [item], frontier,
        checkpointId: publicationResultCheckpointId(run.id, prepared.opId, prepared.attempt, actual.evidenceRef),
        workspaceStateRef: actual.cut.latestCheckpoint.workspaceStateRef }).publish();
      return { metadata: graph.metadata, validate(connection, current, now) {
        requireEqual(current, actual.cut.run, 'reconciled original wait before settlement'); binding.sql(connection);
        if (now < item.createdAt || now < actual.evidence.observedAt) invalid('reconciled terminal precedes its actual observation or item');
      }, commit(connection, current, journal, now) {
        graph.commit(connection, current, journal.seq, now);
        connection.prepare("UPDATE runs SET status='queued',waiting_reason=NULL,waiting_on_ref=NULL WHERE id=?").run(current.id);
      } };
    }, facade: Object.freeze({ settle(request: { expectedRunRevision: number }) {
      closed(request, ['expectedRunRevision'], 'publication resolution requires one exact expected revision');
      if (!Number.isSafeInteger(request.expectedRunRevision) || request.expectedRunRevision < 1) throw new TypeError('publication resolution requires one exact expected revision');
      if (binding.settling) return Promise.reject(new KernelStorageError('STATE_TRANSITION_INVALID', 'original publication resolution is already in flight'));
      binding.settling = (async () => {
        if (binding.committed) {
          const run = readRun(driver, binding.input.runId);
          requireEqual(run, binding.committed.run, 'publication reconciliation exact original completed replay');
          if (![run.revision, run.revision - 1].includes(request.expectedRunRevision))
            throw new KernelStorageError('REVISION_CONFLICT', 'publication reconciliation replay revision changed');
          return binding.committed;
        }
        const actual = await native.readOwnedPublicationReconciliationResult(driver, artifacts, owner, input.execution, input.recoveryResult);
        binding.current = actual;
        if (actual.run.revision !== request.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'publication resolution Run revision changed');
        if (actual.disposition === 'unknown') {
          const state = actual.wait.probeState;
          if ((state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight') || actual.evidence.kind !== 'path_ambiguity' ||
              actual.wrapper.waitingSubjectRef !== actual.run.waitingOnRef || actual.wrapper.subjectEvidenceRef !== actual.evidenceRef)
            invalid('unresolved publication inspection lost its original actual nonce or path ambiguity');
          const evidence = { lastProbeEvidenceRef: actual.wrapperRef, lastProbeEvidenceDigest: actual.wrapper.evidenceDigest };
          const nextWait = decodePublicationPathWait({ ...actual.wait, probeState: state.phase === 'user_in_flight' || state.automaticProbeCount === 8
            ? { phase: 'automatic_exhausted', automaticProbeCount: 8, userProbeCount: state.userProbeCount, ...evidence }
            : { phase: 'automatic_pending', automaticProbeCount: state.automaticProbeCount, userProbeCount: 0,
              nextProbeAt: addCanonicalDuration(actual.wrapper.observedAt, WORKER_PROBE_BACKOFF_MS[state.automaticProbeCount - 1]!), ...evidence } });
          const artifact = await artifacts.publishCanonical(nextWait, 'cliq-waiting-subject-v1');
          let outcome: TimeFenceAdvance | undefined, run!: Run;
          driver.transaction(connection => {
            assertActiveStateOwner(connection, owner); binding.sql(connection);
            const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
            if (outcome !== 'healthy') return;
            if (now < actual.wrapper.observedAt) invalid('unresolved publication wait precedes its actual observation');
            for (const metadata of [...actual.metadata, artifact]) insertArtifactMetadata(connection, metadata, now);
            connection.prepare('UPDATE runs SET waiting_on_ref=?,revision=revision+1,updated_at=? WHERE id=? AND revision=? AND waiting_on_ref=?')
              .run(artifact.ref, now, actual.run.id, BigInt(actual.run.revision), actual.run.waitingOnRef!);
            run = readRun(connection, actual.run.id);
            const expected: Run = { ...actual.run, waitingOnRef: artifact.ref, revision: actual.run.revision + 1, updatedAt: now };
            requireEqual(run, expected, 'unresolved publication leaves Journal, budget, frontier and native claim unchanged');
            appendRunStateEvent(connection, run, now);
          });
          requireHealthyFence(outcome);
          return binding.committed = immutableSnapshot({ run, entry: actual.unknown, settlement: binding.settlement });
        }
        const completed = actual.disposition === 'received';
        binding.resolution = { input: binding.input, artifacts, prepared: actual.prepared, claim: actual.claim, unknown: actual.unknown,
          settlement: binding.settlement, journalSeq: actual.cut.journal.length + 1, observedAt: actual.evidence.observedAt,
          metadata: [...actual.metadata], terminal: completed ? { phase: 'completed', receiptRef: actual.receiptRef,
            evidenceRef: actual.evidenceRef, evidenceDigest: actual.evidence.proofDigest } : { phase: 'failed', errorRef: actual.evidenceRef,
              evidenceRef: actual.evidenceRef, evidenceDigest: actual.evidence.proofDigest },
          continuation: binding.continuation, validateSnapshot(connection, run) {
            requireEqual(run, actual.cut.run, 'publication exact original inspected cut'); binding.sql(connection);
          } };
        return binding.committed = immutableSnapshot(await binding.reducer.settle(request.expectedRunRevision));
      })().finally(() => { binding.settling = undefined; });
      return binding.settling;
    } }) };
  bindings.set(input.recoveryResult, binding); return binding.facade;
}

/** One original physical completion, one settlement and one retained result.
 * No caller can select evidence, receipts, grants, callbacks or a future cut. */
export async function preparePublicationSettlement(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: Input): Promise<Binding['facade']> {
  closed(input, ['execution', 'publicationOwner'], 'settlement requires one closed original publication input');
  assertOwnedPublicationArtifacts(driver, owner, input.execution, input.publicationOwner, artifacts);
  const completion = readOwnedPublicationCompletion(driver, owner, input.execution, input.publicationOwner);
  const prior = bindings.get(input.publicationOwner);
  if (prior) {
    if (prior.kind !== 'path' || prior.driver !== driver || prior.owner !== owner || prior.artifacts !== artifacts || prior.execution !== input.execution)
      throw new TypeError('publication settlement cannot transfer its original completion owner');
    original(prior); return prior.facade;
  }
  const binding: Binding = { kind: 'path', driver, artifacts, owner, execution: input.execution, publicationOwner: input.publicationOwner, completion,
    terminal: terminal(completion), input: { runId: completion.run.id, opId: completion.prepared.opId, attempt: completion.prepared.attempt },
    graphs: new Map(), reducer: preparePublicationInvocationSettlement(driver, artifacts, owner, input.publicationOwner),
    validateSnapshot(connection, run) {
      const selection = binding.selection;
      if (!selection) invalid('publication settlement lacks its complete retained current cut');
      requireEqual(run, selection.cut.run, 'publication settlement exact selected Run'); selection.assertCut(connection);
    },
    async continuation({ run, prepared, settlement }) {
      const selection = binding.selection;
      if (!selection) invalid('publication settlement lost its exact selected continuation');
      requireEqual(run, selection.cut.run, 'publication original selected settlement Run');
      requireEqual(prepared, binding.completion.prepared, 'publication original selected settlement preparation');
      if (settlement.terminalPhase !== binding.terminal.phase || settlement.preparedJournalSeq !== prepared.seq ||
          settlement.settledAt < completion.evidence.observedAt)
        invalid('publication changed its original once-only settlement');
      if (completion.disposition === 'received' && completion.isLastForwardPath && !selection.stop) {
        invalid('last received publication must first commit its genuine received-result handoff');
      }
      const outcome = completion.disposition === 'received' ? 'completed' : completion.disposition === 'unknown' ? 'unknown' :
        completion.disposition === 'retained_planned_descendant' ? 'retained_planned_descendant' : 'failed';
      const abortStop = completion.birth.sequence === 'forward' && selection.stop && completion.disposition !== 'unknown' ? selection.stop : undefined;
      // CAS/rolled-back SQL can precede a later winning Stop. Only this
      // uncommitted data edge changes; native effect, evidence, item identity
      // and the single original BudgetSettlement are never recreated.
      binding.item = decodePublicationPathResultItem({ schemaVersion: 1, kind: 'publication_path_result',
        itemId: publicationResultItemId(run.id, prepared.opId, prepared.attempt, completion.evidenceRef), runId: run.id,
        deliveryPlanRef: completion.planRef, sequence: completion.birth.sequence, operationIndex: completion.operation.index,
        operationId: completion.operation.operationId, opId: prepared.opId, attempt: prepared.attempt,
        outcome, evidenceRef: completion.evidenceRef, ...(outcome === 'completed' ? { receiptRef: completion.receiptRef } : {}),
        ...(outcome === 'unknown' ? {} : { retirement: retirement(completion) }),
        ...(abortStop ? { abortStopIntentRef: canonicalSha256(abortStop) } : {}),
        createdAt: abortStop && abortStop.createdAt > settlement.settledAt ? abortStop.createdAt : settlement.settledAt });
      const frontier: RunFrontier = { ...selection.prefix.authorization!.frontier,
        phase: completion.birth.sequence === 'abort' || abortStop ? 'abort_cleanup' : 'publish',
        nextPathOperationIndex: abortStop ? 0 : completion.operation.index +
          (completion.disposition === 'received' || completion.disposition === 'retained_planned_descendant' ? 1 : 0) };
      const key = canonicalSha256({ checkpoint: selection.cut.latestCheckpoint.id, frontier, item: binding.item });
      let graph = binding.graphs.get(key);
      if (!graph) {
        const context = decodeContextManifest(await readCanonicalArtifact(artifacts, selection.cut.latestCheckpoint.contextManifestRef));
        const existingItems = [];
        for (const row of selection.cut.items) existingItems.push({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
          item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) });
        graph = planContinuationCommit(artifacts, { context, existingItems, items: [binding.item], frontier,
          checkpointId: publicationResultCheckpointId(run.id, prepared.opId, prepared.attempt, completion.evidenceRef),
          workspaceStateRef: selection.cut.latestCheckpoint.workspaceStateRef });
        binding.graphs.set(key, graph);
      }
      const published = await graph.publish();
      return { metadata: [...completion.metadata, ...published.metadata],
        validate(connection, current, committedAt) {
          binding.validateSnapshot(connection, current);
          if (committedAt < completion.evidence.observedAt || committedAt < binding.item!.createdAt)
            throw new KernelStorageError('RECOVERY_REQUIRED', 'publication result precedes its actual original evidence');
        },
        commit(connection, current, entry, committedAt) { published.commit(connection, current, entry.seq, committedAt); } };
    },
    facade: Object.freeze({ settle(request: { expectedRunRevision: number }) {
      closed(request, ['expectedRunRevision'], 'publication settlement requires one exact expected revision');
      const expected = request.expectedRunRevision;
      if (!Number.isSafeInteger(expected) || expected < 1) throw new TypeError('publication settlement requires one exact expected revision');
      if (binding.settling) return Promise.reject(new KernelStorageError('STATE_TRANSITION_INVALID', 'original publication settlement is already in flight'));
      binding.settling = (async () => {
        const selection = await select(binding), retained = selection.prefix.entries.get(binding.input.opId)!;
        if (retained.result) {
          if (retained.result.item.evidenceRef !== completion.evidenceRef || retained.result.item.outcome !==
              (completion.disposition === 'received' ? 'completed' : completion.disposition === 'unknown' ? 'unknown' :
                completion.disposition === 'retained_planned_descendant' ? 'retained_planned_descendant' : 'failed'))
            invalid('settled publication ambiguity requires a new genuine same-claim completion, never a fabricated resolution');
          const entry = retained.history.find(row => row.evidenceRef === completion.evidenceRef && ['completed', 'failed', 'unknown'].includes(row.phase))!;
          let checkpoint = retained.checkpoint;
          if (!checkpoint && completion.disposition === 'received' && completion.isLastForwardPath &&
              selection.cut.run.status === 'succeeded' && selection.cut.run.resultRef) {
            // The last result has no standalone path Checkpoint. Its actual
            // publication/result graph committed atomically with the terminal
            // Run; derive that original CP only through the complete reader.
            const result = decodeRunResult(await readCanonicalArtifact(artifacts, selection.cut.run.resultRef));
            if (!result.deliveryTerminalProjectionEvidenceRef)
              invalid('last publication replay lost its actual terminal result projection');
            checkpoint = (await readDeliveryTerminalProjection(driver, artifacts, selection.cut,
              result.deliveryTerminalProjectionEvidenceRef)).checkpoint;
          }
          if (!entry?.budgetSettlementRef || !checkpoint || ![selection.cut.run.revision, checkpoint.basedOnRunRevision].includes(expected))
            throw new KernelStorageError('REVISION_CONFLICT', 'publication settlement replay changed its original retained result cut');
          return immutableSnapshot({ run: selection.cut.run, entry,
            settlement: decodeBudgetSettlement(await readCanonicalArtifact(artifacts, entry.budgetSettlementRef)) });
        }
        if (selection.cut.run.revision !== expected) throw new KernelStorageError('REVISION_CONFLICT', 'publication result Run revision changed');
        binding.selection = selection;
        return immutableSnapshot(await binding.reducer.settle(expected));
      })().finally(() => { binding.settling = undefined; });
      return binding.settling;
    } }) };
  // Complete the original retained read before exposing even this nonsemantic
  // adapter. No structural successful fixture can supply this selection.
  binding.selection = await select(binding);
  bindings.set(input.publicationOwner, binding);
  return binding.facade;
}

function originalReceived(binding: ReceivedBinding) {
  const actual = readOwnedPublicationReceivedResult(binding.driver, binding.artifacts, binding.owner, binding.execution, binding.receivedResult);
  requireEqual(actual.completion, binding.completion, 'publication same original durable received result');
  const handoff = actual.entry.receivedHandoff;
  if (!handoff || actual.entry.result && actual.entry.result.item.outcome !== 'unknown' || actual.entry.sequence !== 'forward' ||
      actual.entry.operation.index !== actual.completion.plan.forwardOperations.length - 1 ||
      handoff.item.receiptRef !== binding.completion.receiptRef ||
      handoff.item.receiptDigest !== binding.completion.evidence.proofDigest)
    invalid('received settlement lost its original last handoff and receipt');
  if (actual.entry.result?.item.outcome === 'unknown' && (!handoff.item.reconciliationEvidenceRef ||
      handoff.item.reconciliationEvidenceRef !== actual.completion.reconciliationEvidenceRef ||
      handoff.item.reconciliationEvidenceDigest !== actual.completion.reconciliationEvidenceDigest))
    invalid('received UNKNOWN resolution lost its full original probe and handoff association');
  actual.resources.signal.throwIfAborted(); return actual;
}

async function selectReceived(binding: ReceivedBinding): Promise<Selection> {
  const actual = originalReceived(binding), completion = actual.completion;
  const cut = await readRecoveryClosure(binding.driver, binding.reads, binding.input.runId);
  const prefix = await readPublicationPrefix(binding.driver, binding.reads, cut);
  const entry = prefix.entries.get(binding.input.opId), authorization = prefix.authorization;
  if (!entry?.claim || !entry.birth || !entry.receivedHandoff || !authorization || entry.sequence !== 'forward' ||
      entry.operation.operationId !== completion.operation.operationId || entry.planRef !== completion.planRef ||
      prefix.forward.at(-1) !== entry || prefix.forward.length !== completion.plan.forwardOperations.length)
    invalid('received settlement has no exact original last forward handoff');
  requireEqual(entry.prepared, completion.prepared, 'received settlement original preparation');
  requireEqual(entry.claim, completion.claim, 'received settlement original permanent claim');
  requireEqual(entry.birth, completion.birth, 'received settlement original native birth');
  requireEqual(entry.plan, completion.plan, 'received settlement complete original Plan');
  requireEqual(entry.receivedHandoff, actual.entry.receivedHandoff, 'received settlement original durable resource Checkpoint');
  if (entry.pendingReceivedHandoff) {
    if (cut.run.status !== 'queued' || cut.run.nextStep !== 'delivery' || !cut.run.frontierRef ||
        cut.run.activeWorkerLaunchId || cut.workerLaunches.length || prefix.abortResults.length)
      invalid('received settlement is not its worker-free pending last result cut');
    const frontier = await readCanonicalArtifact<RunFrontier>(binding.reads, cut.run.frontierRef);
    requireEqual(frontier, { ...authorization.frontier, phase: 'publish', nextPathOperationIndex: entry.operation.index },
      'received settlement original unadvanced publication frontier');
  }
  const stop = cut.run.stopIntentRef ? await readAgentStop(binding.driver, binding.reads, cut) : undefined;
  if (binding.observedStop && (!stop || canonicalSha256(stop) !== canonicalSha256(binding.observedStop) &&
      selectAgentStop(binding.observedStop, stop) !== stop)) invalid('received settlement lost its monotonic winning StopIntent');
  if (stop) binding.observedStop = stop;
  await assertPublicationReadCut(binding.driver, binding.reads, cut);
  const fingerprint = canonicalSha256(sqlCut(binding.driver, binding, prefix.admission.source.run.id));
  return { cut, prefix, ...(stop ? { stop } : {}), assertCut(connection) {
    assertActiveStateOwner(connection, binding.owner);
    if (canonicalSha256(sqlCut(connection, binding, prefix.admission.source.run.id)) !== fingerprint)
      throw new KernelStorageError('REVISION_CONFLICT', 'received publication result lost its exact Run, Stop, Session or handoff cut');
    originalReceived(binding);
  } };
}

/** A fixed read-only handoff consumer. The opaque task and complete durable
 * original claim/receipt/M-seal graph, never a reconstructed native handle,
 * own the sole later terminal accounting and continuation transaction. */
export async function preparePublicationReceivedSettlement(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: ReceivedInput): Promise<Binding['facade']> {
  closed(input, ['execution', 'receivedResult'], 'settlement requires one closed original received publication input');
  const actual = readOwnedPublicationReceivedResult(driver, artifacts, owner, input.execution, input.receivedResult);
  const prior = bindings.get(input.receivedResult);
  if (prior) {
    if (prior.kind !== 'received' || prior.driver !== driver || prior.owner !== owner || prior.artifacts !== artifacts || prior.execution !== input.execution)
      throw new TypeError('received publication settlement cannot transfer its original handoff');
    originalReceived(prior); return prior.facade;
  }
  const completion = actual.completion;
  const unknown = actual.entry.history.find(value => value.phase === 'unknown');
  let resolvedUnknown: ReceivedBinding['resolvedUnknown'];
  if (unknown) {
    if (!unknown.budgetSettlementRef || !completion.reconciliationEvidenceRef || !completion.reconciliationEvidenceDigest)
      invalid('received UNKNOWN result lacks its original once-only settlement and exact probe');
    const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts.withReadSignal(actual.resources.signal), unknown.budgetSettlementRef));
    const { assertPublicationUnknownSettlementAssociation } = await import('./publication-finalization.js');
    assertPublicationUnknownSettlementAssociation(completion.prepared, completion.claim, unknown, settlement);
    resolvedUnknown = { unknown, settlement };
  }
  const binding: ReceivedBinding = { kind: 'received', driver, artifacts, reads: artifacts.withReadSignal(actual.resources.signal),
    owner, execution: input.execution, receivedResult: input.receivedResult, completion,
    input: { runId: completion.run.id, opId: completion.prepared.opId, attempt: completion.prepared.attempt },
    terminal: { phase: 'completed', receiptRef: completion.receiptRef, evidenceRef: completion.evidenceRef,
      evidenceDigest: completion.evidence.proofDigest, consumed: CHARGE },
    graphs: new Map(), ...(resolvedUnknown ? { resolvedUnknown } : {}), reducer: resolvedUnknown
      ? preparePublicationReconciliationInvocationSettlement(driver, artifacts, owner, input.receivedResult)
      : preparePublicationInvocationSettlement(driver, artifacts, owner, input.receivedResult),
    validateSnapshot(connection, run) {
      if (binding.finalization) {
        validateOwnedPublicationFinalization(driver, owner, binding.finalization, connection, run); return;
      }
      if (!binding.selection) invalid('received settlement lacks its full current read-only cut');
      requireEqual(run, binding.selection.cut.run, 'received settlement exact current Run'); binding.selection.assertCut(connection);
    },
    async continuation({ run, prepared, settlement }) {
      const selection = binding.selection;
      if (!selection) invalid('received settlement lost its exact selected continuation');
      originalReceived(binding);
      requireEqual(run, selection.cut.run, 'received original selected settlement Run');
      requireEqual(prepared, completion.prepared, 'received original permanent preparation');
      if (binding.resolvedUnknown) requireEqual(settlement, binding.resolvedUnknown.settlement, 'received result original charged UNKNOWN BudgetSet');
      else if (settlement.terminalPhase !== 'completed' || settlement.preparedJournalSeq !== prepared.seq || settlement.settledAt < completion.evidence.observedAt)
        invalid('received publication changed its original once-only settlement');
      requireEqual(settlement.consumed, CHARGE, 'received publication original once-only charge');
      if (!selection.stop) {
        if (binding.finalization) invalid('received finalization already owns its actual read-only descriptors');
        const finalization = await prepareOwnedPublicationFinalization(driver, artifacts, owner, binding.execution, binding.receivedResult, settlement);
        binding.finalization = finalization;
        return { metadata: [...readOwnedPublicationFinalizationMetadata(driver, owner, finalization)],
          validate(connection, current, committedAt) { validateOwnedPublicationFinalization(driver, owner, finalization, connection, current, committedAt); },
          commit(connection, current, journal, committedAt) { commitOwnedPublicationFinalization(driver, owner, finalization, connection, current, journal, committedAt); } };
      }
      // Stop never erases the positively received result or repeats its seal,
      // native effect, dispatch or charge. Only its uncommitted abort edge is
      // rebuilt when a later monotonic Stop wins after CAS/SQL failure.
      const item = decodePublicationPathResultItem({ schemaVersion: 1, kind: 'publication_path_result',
        itemId: publicationResultItemId(run.id, prepared.opId, prepared.attempt, completion.evidenceRef), runId: run.id,
        deliveryPlanRef: completion.planRef, sequence: 'forward', operationIndex: completion.operation.index,
        operationId: completion.operation.operationId, opId: prepared.opId, attempt: prepared.attempt,
        outcome: 'completed', evidenceRef: completion.evidenceRef, receiptRef: completion.receiptRef,
        retirement: completion.retirement,
        abortStopIntentRef: canonicalSha256(selection.stop),
        ...(completion.reconciliationEvidenceRef ? { reconciliationEvidenceRef: completion.reconciliationEvidenceRef,
          reconciliationEvidenceDigest: completion.reconciliationEvidenceDigest } : {}),
        createdAt: binding.resolvedUnknown ? (binding.resolutionCreatedAt = [binding.resolutionCreatedAt ?? sampleCanonicalNow(), selection.stop.createdAt].sort().at(-1)!) :
          selection.stop.createdAt > settlement.settledAt ? selection.stop.createdAt : settlement.settledAt });
      const frontier: RunFrontier = { ...selection.prefix.authorization!.frontier, phase: 'abort_cleanup', nextPathOperationIndex: 0 };
      const key = canonicalSha256({ checkpoint: selection.cut.latestCheckpoint.id, frontier, item });
      let graph = binding.graphs.get(key);
      if (!graph) {
        const context = decodeContextManifest(await readCanonicalArtifact(binding.reads, selection.cut.latestCheckpoint.contextManifestRef)), existingItems = [];
        for (const row of selection.cut.items) existingItems.push({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
          item: await readCanonicalArtifact<ContinuationItem>(binding.reads, row.payloadRef) });
        graph = planContinuationCommit(artifacts, { context, existingItems, items: [item], frontier,
          checkpointId: publicationResultCheckpointId(run.id, prepared.opId, prepared.attempt, completion.evidenceRef),
          workspaceStateRef: selection.cut.latestCheckpoint.workspaceStateRef });
        binding.graphs.set(key, graph);
      }
      const published = await graph.publish();
      return { metadata: published.metadata,
        validate(connection, current, committedAt) {
          binding.validateSnapshot(connection, current);
          if (committedAt < completion.evidence.observedAt || committedAt < item.createdAt)
            throw new KernelStorageError('RECOVERY_REQUIRED', 'received publication result precedes its original receipt or Stop');
        },
        commit(connection, current, journal, committedAt) { published.commit(connection, current, journal.seq, committedAt); } };
    },
    facade: Object.freeze({ settle(request: { expectedRunRevision: number }) {
      closed(request, ['expectedRunRevision'], 'received settlement requires one exact expected revision');
      const expected = request.expectedRunRevision;
      if (!Number.isSafeInteger(expected) || expected < 1) throw new TypeError('received settlement requires one exact expected revision');
      if (binding.settling) return Promise.reject(new KernelStorageError('STATE_TRANSITION_INVALID', 'original received settlement is already in flight'));
      binding.settling = (async () => {
        for (let retry = 0; ; retry++) try {
          const selection = await selectReceived(binding), retained = selection.prefix.entries.get(binding.input.opId)!;
          if (retained.result && retained.result.item.outcome !== 'unknown') {
            if (retained.result.item.outcome !== 'completed' || retained.result.item.evidenceRef !== completion.evidenceRef)
              invalid('received settlement cannot replace its original known receipt');
            const entry = retained.history.find(row => row.phase === 'completed' && row.evidenceRef === completion.evidenceRef);
            let checkpoint = retained.checkpoint;
            if (!checkpoint && selection.cut.run.status === 'succeeded' && selection.cut.run.resultRef) {
              const result = decodeRunResult(await readCanonicalArtifact(binding.reads, selection.cut.run.resultRef));
              if (!result.deliveryTerminalProjectionEvidenceRef) invalid('received replay lost its actual terminal projection');
              checkpoint = (await readDeliveryTerminalProjection(driver, binding.reads, selection.cut, result.deliveryTerminalProjectionEvidenceRef)).checkpoint;
            }
            if (!entry?.budgetSettlementRef || !checkpoint || ![selection.cut.run.revision, checkpoint.basedOnRunRevision].includes(expected))
              throw new KernelStorageError('REVISION_CONFLICT', 'received settlement replay changed its original terminal cut');
            return immutableSnapshot({ run: selection.cut.run, entry,
              settlement: decodeBudgetSettlement(await readCanonicalArtifact(binding.reads, entry.budgetSettlementRef)) });
          }
          if (selection.cut.run.revision !== expected) throw new KernelStorageError('REVISION_CONFLICT', 'received settlement Run revision changed');
          binding.selection = selection;
          if (binding.resolvedUnknown) binding.resolution = { input: binding.input, artifacts, prepared: completion.prepared,
            claim: completion.claim, unknown: binding.resolvedUnknown.unknown, settlement: binding.resolvedUnknown.settlement,
            journalSeq: selection.cut.journal.length + 1, observedAt: completion.evidence.observedAt, metadata: [],
            terminal: { phase: 'completed', receiptRef: completion.receiptRef, evidenceRef: completion.evidenceRef,
              evidenceDigest: completion.evidence.proofDigest }, continuation: binding.continuation, validateSnapshot: binding.validateSnapshot };
          return immutableSnapshot(await binding.reducer.settle(expected));
        } catch (error) {
          if (retry >= 7 || !isOwnedPublicationSessionConflict(driver, owner, binding.receivedResult, error)) throw error;
          // Only this exact finalizer's Session CAS mismatch permits a new
          // read-only projection plan; the fixed original BudgetSet remains.
        } finally {
          const finalization = binding.finalization; binding.finalization = undefined;
          if (finalization) closeOwnedPublicationFinalization(driver, owner, finalization);
        }
      })().finally(() => { binding.settling = undefined; });
      return binding.settling;
    } }) };
  binding.selection = await selectReceived(binding);
  bindings.set(input.receivedResult, binding); return binding.facade;
}

function originalPreparation(binding: PreparationBinding) {
  const actual = readOwnedPublicationPreparationClosure(binding.driver, binding.owner, binding.execution, binding.publicationOwner);
  requireEqual(actual.closure, binding.completion.closure, 'publication same original preparation retirement closure');
  requireEqual(actual.prepared, binding.completion.prepared, 'publication same original undispatched preparation');
  if (actual.closureRef !== binding.completion.closureRef || actual.planRef !== binding.completion.planRef)
    invalid('publication cannot replace its original preparation retirement');
  return actual;
}
async function selectPreparation(binding: PreparationBinding): Promise<Selection> {
  const actual = originalPreparation(binding), { driver, artifacts } = binding;
  const cut = await readRecoveryClosure(driver, artifacts, binding.input.runId), prefix = await readPublicationPrefix(driver, artifacts, cut);
  const entry = prefix.entries.get(binding.input.opId);
  if (!entry || entry.claim || entry.planRef !== actual.planRef || entry.operation.operationId !== actual.operation.operationId ||
      entry.sequence !== actual.sequence || entry.history.length > 2 || entry.history.some(row => !['prepared', 'failed'].includes(row.phase)))
    invalid('publication preparation settlement lost its exact original unclaimed prefix');
  requireEqual(entry.prepared, actual.prepared, 'publication original preparation before zero settlement');
  if (entry.history.length === 2 && entry.history[1]!.errorRef !== actual.closureRef)
    invalid('publication preparation cannot replace another original failure');
  const stop = cut.run.stopIntentRef ? await readAgentStop(driver, artifacts, cut) : undefined;
  if (binding.observedStop && (!stop || selectAgentStop(binding.observedStop, stop) !== stop &&
      canonicalSha256(binding.observedStop) !== canonicalSha256(stop)))
    invalid('publication preparation retirement lost its monotonic StopIntent');
  if (stop) binding.observedStop = stop;
  await assertPublicationReadCut(driver, artifacts, cut);
  const fingerprint = canonicalSha256(sqlCut(driver, binding, prefix.admission.source.run.id));
  return { cut, prefix, ...(stop ? { stop } : {}), assertCut(connection) {
    assertActiveStateOwner(connection, binding.owner);
    if (canonicalSha256(sqlCut(connection, binding, prefix.admission.source.run.id)) !== fingerprint)
      throw new KernelStorageError('REVISION_CONFLICT', 'publication preparation retirement cut changed');
    originalPreparation(binding);
  } };
}

/** Fixed same-owner adapter, not a public pre-dispatch refund or supplied
 * error/evidence seam. It can settle only the original joined preparation. */
export async function preparePublicationPreparationSettlement(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: Input): Promise<Binding['facade']> {
  closed(input, ['execution', 'publicationOwner'], 'preparation settlement requires one closed original publication input');
  assertOwnedPublicationArtifacts(driver, owner, input.execution, input.publicationOwner, artifacts);
  const completion = readOwnedPublicationPreparationClosure(driver, owner, input.execution, input.publicationOwner);
  const prior = bindings.get(input.publicationOwner);
  if (prior) {
    if (prior.kind !== 'preparation' || prior.driver !== driver || prior.owner !== owner || prior.execution !== input.execution || prior.artifacts !== artifacts)
      throw new TypeError('preparation settlement cannot transfer its original owner');
    originalPreparation(prior); return prior.facade;
  }
  const binding: PreparationBinding = { kind: 'preparation', driver, artifacts, owner, execution: input.execution, publicationOwner: input.publicationOwner,
    completion, input: { runId: completion.prepared.runId, opId: completion.prepared.opId, attempt: 0 },
    terminal: { phase: 'failed', errorRef: completion.closureRef, consumed: ZERO_BUDGET, requireClaim: false },
    reducer: preparePublicationInvocationSettlement(driver, artifacts, owner, input.publicationOwner),
    validateSnapshot(connection, run) {
      if (!binding.selection) invalid('publication preparation retirement lost its actual SQL cut');
      requireEqual(run, binding.selection.cut.run, 'publication preparation retirement exact Run'); binding.selection.assertCut(connection);
    },
    async continuation({ run, prepared, settlement }) {
      originalPreparation(binding);
      requireEqual(prepared, completion.prepared, 'publication preparation original zero-settlement preparation');
      if (settlement.terminalPhase !== 'failed' || settlement.settledAt < completion.closure.observedAt)
        invalid('publication preparation settlement predates its actual joined retirement');
      requireEqual(settlement.consumed, ZERO_BUDGET, 'publication preparation consumes no productive budget');
      return { metadata: completion.metadata, validate(connection, current, committedAt) {
        binding.validateSnapshot(connection, current);
        if (committedAt < completion.closure.observedAt || current.id !== run.id)
          invalid('publication preparation retirement has a noncausal SQL commit');
      } };
    },
    facade: Object.freeze({ settle(request: { expectedRunRevision: number }) {
      closed(request, ['expectedRunRevision'], 'preparation settlement requires one exact expected revision');
      const expected = request.expectedRunRevision;
      if (!Number.isSafeInteger(expected) || expected < 1) throw new TypeError('preparation settlement requires one exact expected revision');
      if (binding.settling) return Promise.reject(new KernelStorageError('STATE_TRANSITION_INVALID', 'original preparation settlement is already in flight'));
      binding.settling = (async () => {
        const selection = await selectPreparation(binding), entry = selection.prefix.entries.get(binding.input.opId)!;
        if (entry.preparationClosure) {
          if (entry.preparationClosure.closureRef !== completion.closureRef ||
              expected !== selection.cut.run.revision && expected !== binding.settledFromRevision)
            throw new KernelStorageError('REVISION_CONFLICT', 'preparation settlement replay changed its original closed cut');
          const terminal = entry.preparationClosure.terminal;
          return immutableSnapshot({ run: selection.cut.run, entry: terminal,
            settlement: decodeBudgetSettlement(await readCanonicalArtifact(artifacts, terminal.budgetSettlementRef!)) });
        }
        if (selection.cut.run.revision !== expected) throw new KernelStorageError('REVISION_CONFLICT', 'preparation retirement Run revision changed');
        binding.selection = selection;
        const result = await binding.reducer.settle(expected); binding.settledFromRevision = expected; return immutableSnapshot(result);
      })().finally(() => { binding.settling = undefined; });
      return binding.settling;
    } }) };
  binding.selection = await selectPreparation(binding);
  bindings.set(input.publicationOwner, binding); return binding.facade;
}
