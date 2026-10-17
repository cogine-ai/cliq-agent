import { digestOmitting, modelOperationId, parseCanonicalTime } from '../../kernel/identity.js';
import { planCanonicalArtifact, type PlannedArtifact } from '../../kernel/artifact-plan.js';
import type {
  BudgetSettlementV1,
  BudgetUsage,
  InvocationJournalEntry,
  ReplayClass,
  Run,
  RunAssemblyV1,
  RunFrontier,
  RunContextCompactionPlan,
  RunEvent,
  BoundWorkerLaunch,
  WorkspaceGenerationStateV1
} from '../../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from '../artifacts.js';
import { insertArtifactMetadata } from '../artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import { KernelStorageError, stateOperation } from '../errors.js';
import {
  addBudget,
  assertBudgetWithin,
  decodeBudgetUsage,
  isZeroBudget,
  subtractBudget
} from '../invariants.js';
import {
  appendInvocationJournalEntry,
  nextJournalSequence,
  readHighestPreparedAttempt,
  readInvocationAttempt,
  readOperationJournal
} from '../repositories/journal.js';
import { readRequiredWorkerLaunch } from '../repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef } from '../repositories/workspace-generations.js';
import { insertRunEvent, readCheckpoint, readRun } from '../rows.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';
import { decodeBudgetSettlement, decodeContextManifest, decodeRunSpec } from '../decoders.js';
import { readCanonicalArtifact } from '../agent-context.js';
import type { ModelRequestV1, NormalPromptProjectionV1, ModelVisiblePromptV1 } from '../../model/request.js';
import { assertSameModelOperation, modelRetryState } from '../../runtime/model-retry.js';
import { decodeRetainedRunAssembly } from '../../model/run-assembly.js';
import { assertModelGrantDispatch, readModelGrantClosure } from '../model-grant.js';
import { prepareInstalledBrokerAmbiguity } from '../broker-ambiguity.js';
import { MODEL_BROKER_ENTRY_ID } from '../model-broker-native.js';
import { readWorkerRecoveryTerminalPlan, type WorkerRecoveryTerminalPlan } from '../worker-recovery-terminal.js';

const ZERO_BUDGET: BudgetUsage = {
  modelTokens: 0,
  costMicros: 0,
  toolCalls: 0,
  repairAttempts: 0
};
const SETTLEMENT_RETRY_LIMIT = 8;

class ReducerSnapshotChanged extends Error {}

export function requireHealthyFence(outcome: TimeFenceAdvance | undefined): void {
  if (outcome === 'clock_regressed' || outcome === 'still_regressed') {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical clock is not healthy');
  }
}

function nextRunEventSequence(connection: SqliteConnection, runId: string): number {
  const row = connection
    .prepare('SELECT COALESCE(max(event_seq), 0) + 1 AS event_seq FROM run_events WHERE run_id = ?')
    .get<{ event_seq: unknown }>(runId);
  const value = Number(row?.event_seq);
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'Run event sequence overflowed');
  }
  return value;
}

function latestRunItemSequence(connection: SqliteConnection, runId: string): number {
  const row = connection
    .prepare('SELECT COALESCE(max(item_seq), 0) AS item_seq FROM items WHERE run_id = ?')
    .get<{ item_seq: unknown }>(runId);
  return Number(row?.item_seq ?? 0);
}

export function appendRunStateEvent(connection: SqliteConnection, run: Run, occurredAt: string): void {
  const event: Extract<RunEvent, { kind: 'state_changed' }> = {
    schemaVersion: 1,
    kind: 'state_changed',
    runId: run.id,
    eventSeq: nextRunEventSequence(connection, run.id),
    runRevision: run.revision,
    status: run.status,
    nextStep: run.nextStep,
    latestRunItemSeq: latestRunItemSequence(connection, run.id),
    occurredAt
  };
  if (run.frontierRef !== undefined) event.frontierRef = run.frontierRef;
  if (run.waitingReason !== undefined) event.waitingReason = run.waitingReason;
  if (run.waitingOnRef !== undefined) event.waitingOnRef = run.waitingOnRef;
  if (run.resultRef !== undefined) event.resultRef = run.resultRef;
  if (run.terminalReason !== undefined) event.terminalReason = run.terminalReason;
  if (run.terminalDetailRef !== undefined) event.terminalDetailRef = run.terminalDetailRef;
  insertRunEvent(connection, event);
}

function findGenerationByRef(connection: SqliteConnection, generationRef: string): WorkspaceGenerationStateV1 {
  return readRequiredWorkspaceGenerationByRef(connection, generationRef);
}

type LiveDispatchState = {
  run: Run;
  launch: BoundWorkerLaunch;
  generation: WorkspaceGenerationStateV1;
};

export function assertLiveDispatchState(
  connection: SqliteConnection,
  owner: StateOwnerContext,
  runId: string,
  expectedRunRevision: number,
  expectedLeaseEpoch: number,
  now: string
): LiveDispatchState {
  const run = readRun(connection, runId);
  if (run.revision !== expectedRunRevision) {
    throw new KernelStorageError('REVISION_CONFLICT', 'Run revision changed before invocation transition');
  }
  if (
    run.status !== 'running' ||
    run.activeWorkerLaunchId === undefined ||
    run.leaseEpoch !== expectedLeaseEpoch ||
    run.cancelRequested ||
    run.stopIntentRef !== undefined
  ) {
    throw new KernelStorageError('LEASE_FENCED', 'Run does not have a live dispatch lease');
  }
  if (parseCanonicalTime(now) >= parseCanonicalTime(run.deadlineAt)) {
    throw new KernelStorageError('LEASE_FENCED', 'Run deadline has elapsed');
  }
  const launch = readRequiredWorkerLaunch(connection, run.activeWorkerLaunchId);
  if (
    launch.phase !== 'activated' ||
    launch.runId !== run.id ||
    launch.supervisorInstanceId !== owner.supervisorInstanceId ||
    launch.leaseEpoch !== run.leaseEpoch ||
    launch.generationWriteState !== 'active' ||
    launch.leaseExpiresAt === undefined ||
    parseCanonicalTime(now) >= parseCanonicalTime(launch.leaseExpiresAt)
  ) {
    throw new KernelStorageError('LEASE_FENCED', 'WorkerLaunch is stale, expired, or not writable');
  }
  const generation = findGenerationByRef(connection, launch.workspaceGenerationRef);
  if (
    generation.phase !== 'active' ||
    generation.runId !== run.id ||
    generation.activeWorkerLaunchId !== launch.launchId ||
    generation.leaseEpoch !== run.leaseEpoch
  ) {
    throw new KernelStorageError('LEASE_FENCED', 'workspace generation write gate is not active');
  }
  return { run, launch, generation };
}

function previousAttemptAllowsRetry(entries: InvocationJournalEntry[]): boolean {
  const last = entries.at(-1);
  if (last === undefined) return false;
  if (last.phase === 'failed') return last.budgetSettlementRef !== undefined;
  if (last.phase === 'unknown') {
    return last.budgetSettlementRef !== undefined &&
      (last.replayClass === 'retry' || last.replayClass === 'workspace-rollback-retry');
  }
  return false;
}

export type PrepareInvocationInput = {
  runId: string;
  expectedRunRevision: number;
  leaseEpoch: number;
  opId: string;
  opKind: InvocationJournalEntry['opKind'];
  target: string;
  requestRef: string;
  replayClass: ReplayClass;
  idempotencyKey?: string;
  grantRef?: string;
  reservation: BudgetUsage;
};

export async function prepareInvocation(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: PrepareInvocationInput
): Promise<{ entry: InvocationJournalEntry; run: Run }> {
  if (input.opKind === 'model') {
    throw new KernelStorageError('INVALID_REQUEST', 'model invocations require the typed model admission path');
  }
  const run = readRun(driver, input.runId);
  const spec = decodeRunSpec(await artifacts.readCanonical(run.specRef));
  const assembly = await artifacts.readCanonical<{ format?: string }>(spec.assemblyRef);
  if (assembly.format === 'cliq-run-assembly-v1') {
    throw new KernelStorageError('INVALID_REQUEST', 'typed agent Runs require frontier-specific invocation admission');
  }
  return prepareValidatedInvocation(driver, artifacts, owner, input);
}

/** State reducer implementation detail, never a caller-controlled StateStore option. */
export async function prepareValidatedInvocation(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: PrepareInvocationInput,
  typed?: {
    metadata: PublishedArtifact[];
    validate: (connection: SqliteConnection, run: Run, attempt: number, now: string) => void;
    commit?: (connection: SqliteConnection, run: Run, entry: InvocationJournalEntry) => void;
  }
): Promise<{ entry: InvocationJournalEntry; run: Run }> {
  decodeBudgetUsage(input.reservation, 'invocation reservation');
  if (isZeroBudget(input.reservation)) {
    throw new KernelStorageError('INVALID_REQUEST', 'ordinary invocation reservation must be nonzero');
  }
  await artifacts.readBytes(input.requestRef);
  if (input.grantRef !== undefined) await artifacts.readBytes(input.grantRef);
  const invocationMetadata = typed?.metadata ?? await Promise.all([
    artifacts.describe(input.requestRef, 'application/json', 'cliq-invocation-request-v1'),
    ...(input.grantRef === undefined
      ? []
      : [artifacts.describe(input.grantRef, 'application/json', 'cliq-operation-grant-v1')])
  ]);
  const initialRun = readRun(driver, input.runId);
  const runSpec = decodeRunSpec(await artifacts.readCanonical(initialRun.specRef));
  const ceilings: BudgetUsage = {
    modelTokens: runSpec.budgets.modelTokens,
    costMicros: runSpec.budgets.costMicros,
    toolCalls: runSpec.budgets.toolCalls,
    repairAttempts: runSpec.budgets.repairAttempts
  };

  let result!: { entry: InvocationJournalEntry; run: Run };
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (fenceOutcome !== 'healthy') return;
    const { run } = assertLiveDispatchState(
      connection,
      owner,
      input.runId,
      input.expectedRunRevision,
      input.leaseEpoch,
      now
    );
    const highest = readHighestPreparedAttempt(connection, input.runId, input.opId);
    const attempt = highest === undefined ? 0 : highest.attempt + 1;
    typed?.validate(connection, run, attempt, now);
    if (highest !== undefined) {
      const previous = readInvocationAttempt(connection, input.runId, input.opId, highest.attempt);
      if (!previousAttemptAllowsRetry(previous)) {
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'prior invocation attempt is not retryable and settled');
      }
    }
    assertBudgetWithin(run.budgetConsumed, run.budgetReserved, input.reservation, ceilings);
    const nextReserved = addBudget(run.budgetReserved, input.reservation, 'Run budget reservation');
    const entry: InvocationJournalEntry = {
      seq: nextJournalSequence(connection, input.runId),
      runId: input.runId,
      opId: input.opId,
      opKind: input.opKind,
      attempt,
      leaseEpoch: input.leaseEpoch,
      phase: 'prepared',
      target: input.target,
      requestRef: input.requestRef,
      replayClass: input.replayClass,
      budgetDelta: input.reservation,
      timestamp: now
    };
    if (input.idempotencyKey !== undefined) entry.idempotencyKey = input.idempotencyKey;
    if (input.grantRef !== undefined) entry.grantRef = input.grantRef;
    for (const artifact of invocationMetadata) insertArtifactMetadata(connection, artifact, now);
    appendInvocationJournalEntry(connection, entry);
    const update = connection
      .prepare(
        `UPDATE runs SET budget_reserved_json = ?, revision = revision + 1, updated_at = ?
         WHERE id = ? AND revision = ? AND budget_reserved_json = ?`
      )
      .run(
        JSON.stringify(nextReserved),
        now,
        run.id,
        BigInt(run.revision),
        JSON.stringify(run.budgetReserved)
      );
    if (update.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'Run reservation CAS failed');
    typed?.commit?.(connection, run, entry);
    const updatedRun = readRun(connection, run.id);
    appendRunStateEvent(connection, updatedRun, now);
    result = { entry, run: updatedRun };
  });
  requireHealthyFence(fenceOutcome);
  return result;
}

export type ClaimInvocationDispatchInput = {
  runId: string;
  expectedRunRevision: number;
  leaseEpoch: number;
  opId: string;
  attempt: number;
  dispatchId: string;
  sandboxLaunchSpecRef?: string;
  brokerFenceTokenDigest?: string;
};

/** Verify retained retry requests and their first settlement clock before any preparation or claim. */
export async function readModelRetryHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string, opId: string) {
  const history = readOperationJournal(driver, runId, opId);
  let originalRequest: ModelRequestV1 | undefined;
  const settled = new Set<number>();
  for (const entry of history) {
    if (entry.phase === 'prepared') {
      const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, entry.requestRef);
      if (originalRequest !== undefined) assertSameModelOperation(originalRequest, request);
      else originalRequest = request;
    }
    if (!entry.budgetSettlementRef || settled.has(entry.attempt)) continue;
    const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, entry.budgetSettlementRef));
    if (settlement.runId !== runId || settlement.opId !== opId || settlement.attempt !== entry.attempt ||
        settlement.terminalJournalSeq !== entry.seq || settlement.terminalPhase !== entry.phase || settlement.settledAt !== entry.timestamp) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'model retry clock differs from its retained first settlement');
    }
    settled.add(entry.attempt);
  }
  return history;
}

export const readModelClaimCut = stateOperation('RECOVERY_REQUIRED', async (
  driver: SqliteDriver, artifacts: ArtifactCatalog, prepared: InvocationJournalEntry
) => {
  const run = readRun(driver, prepared.runId);
  if (run.nextStep !== 'agent' || !run.frontierRef) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'model claim requires the current agent frontier');
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef);
  const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, prepared.requestRef);
  const spec = decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef));
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, spec.assemblyRef));
  const checkpoint = readCheckpoint(driver, run.latestCheckpointId);
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  if (frontier.kind !== 'agent' || !['model_turn', 'context_compaction'].includes(frontier.phase) ||
      (frontier.phase === 'context_compaction') !== (frontier.compactionPlanRef !== undefined) ||
      prepared.opId !== modelOperationId(run.id, frontier) ||
      request.schemaVersion !== 1 || request.format !== 'cliq-model-request-v1' ||
      request.requestDigest !== digestOmitting(request, 'requestDigest') || request.runId !== run.id ||
      request.opId !== prepared.opId || request.attempt !== prepared.attempt || request.model !== assembly.provider.model || request.assemblyRef !== context.assemblyRef ||
      spec.operation !== 'agent' || request.assemblyRef !== spec.assemblyRef || context.admittedContextRef !== spec.admittedContextRef ||
      request.kind !== (frontier.phase === 'model_turn' ? 'normal' : 'context_compaction') || request.compactionPlanRef !== frontier.compactionPlanRef ||
      context.runId !== run.id || checkpoint.runId !== run.id || context.throughItemSeq !== checkpoint.runItemSeq ||
      frontier.contextItemSeq !== checkpoint.runItemSeq || latestRunItemSequence(driver, run.id) !== checkpoint.runItemSeq) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'prepared model claim differs from its current frontier and ready context');
  }
  if ((await artifacts.readBytes(request.bodyBytesRef)).byteLength !== request.bodyByteCount) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'model claim native body byte count mismatch');
  }
  const projection = await readCanonicalArtifact<NormalPromptProjectionV1 | ModelVisiblePromptV1>(artifacts, request.promptProjectionRef);
  if (request.kind === 'normal') {
    if (!('frontierDigest' in projection) || projection.runId !== run.id || projection.runSpecRef !== run.specRef ||
        projection.frontierDigest !== run.frontierRef || projection.contextManifestRef !== checkpoint.contextManifestRef ||
        projection.projectionDigest !== request.promptProjectionDigest || digestOmitting(projection, 'projectionDigest') !== projection.projectionDigest) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'model claim projection differs from the current context');
    }
  } else {
    const plan = await readCanonicalArtifact<RunContextCompactionPlan>(artifacts, request.compactionPlanRef!);
    if (plan.runId !== run.id || plan.sourceContextManifestRef !== checkpoint.contextManifestRef ||
        projection.format !== 'cliq-compaction-prompt-v1' || request.promptProjectionDigest !== request.promptProjectionRef) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'model claim compaction plan differs from the current context');
    }
  }
  const history = await readModelRetryHistory(driver, artifacts, run.id, prepared.opId);
  modelRetryState(assembly.retry.model, history, sampleCanonicalNow());
  if (!prepared.grantRef) throw new KernelStorageError('RECOVERY_REQUIRED', 'prepared model claim has no operation grant');
  const authority = await readModelGrantClosure(driver, artifacts, { run, spec, assembly, frontier,
    frontierRef: run.frontierRef, request, requestRef: prepared.requestRef, grantRef: prepared.grantRef });
  if (prepared.target !== authority.targetRef || prepared.timestamp < authority.grant.issuedAt) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'prepared model claim target or time differs from its operation grant');
  }
  return { run, checkpoint, prepared, request, spec, assembly, frontier, authority, retryPolicy: assembly.retry.model };
});

export async function claimInvocationDispatch(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: ClaimInvocationDispatchInput
): Promise<InvocationJournalEntry> {
  input = { ...input };
  const prepared = readHighestPreparedAttempt(driver, input.runId, input.opId);
  if (prepared && (prepared.opKind === 'tool' || prepared.opKind === 'mcp')) {
    const run = readRun(driver, input.runId);
    const spec = decodeRunSpec(await artifacts.readCanonical(run.specRef));
    const assembly = await artifacts.readCanonical<{ format?: string }>(spec.assemblyRef);
    if (assembly.format === 'cliq-run-assembly-v1') {
      throw new KernelStorageError('INVALID_REQUEST', 'typed tool claims require current canonical policy/grant validation');
    }
  }
  return claimValidatedInvocation(driver, artifacts, owner, input);
}

/** Internal claim seam. Only the typed reducer supplies its independently reproduced authority check. */
export async function claimValidatedInvocation(
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: ClaimInvocationDispatchInput,
  validate?: (connection: SqliteConnection, run: Run, prepared: InvocationJournalEntry, now: string) => void
): Promise<InvocationJournalEntry> {
  input = { ...input };
  const preparedSnapshot = readHighestPreparedAttempt(driver, input.runId, input.opId);
  const modelCut = preparedSnapshot?.opKind === 'model' ? await readModelClaimCut(driver, artifacts, preparedSnapshot) : undefined;
  if (input.sandboxLaunchSpecRef !== undefined) await artifacts.readBytes(input.sandboxLaunchSpecRef);
  const launchSpecMetadata = input.sandboxLaunchSpecRef === undefined
    ? undefined
    : await artifacts.describe(
        input.sandboxLaunchSpecRef,
        'application/json',
        'cliq-sandbox-launch-spec-v1'
      );
  if (input.sandboxLaunchSpecRef !== undefined && input.brokerFenceTokenDigest !== undefined) {
    throw new KernelStorageError('INVALID_REQUEST', 'dispatch cannot use both process containment and broker fence token');
  }

  let claimed!: InvocationJournalEntry;
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (fenceOutcome !== 'healthy') return;
    const { run } = assertLiveDispatchState(
      connection,
      owner,
      input.runId,
      input.expectedRunRevision,
      input.leaseEpoch,
      now
    );
    const highest = readHighestPreparedAttempt(connection, input.runId, input.opId);
    if (highest === undefined || highest.attempt !== input.attempt || highest.leaseEpoch !== input.leaseEpoch) {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'dispatch claim is not for the highest prepared attempt');
    }
    if (highest.opKind === 'model' && (!modelCut || highest.requestRef !== modelCut.prepared.requestRef ||
        highest.grantRef !== modelCut.prepared.grantRef || highest.target !== modelCut.prepared.target ||
        run.nextStep !== 'agent' || run.frontierRef !== modelCut.run.frontierRef || run.latestCheckpointId !== modelCut.run.latestCheckpointId ||
        readCheckpoint(connection, run.latestCheckpointId).contextManifestRef !== modelCut.checkpoint.contextManifestRef ||
        latestRunItemSequence(connection, run.id) !== modelCut.checkpoint.runItemSeq)) {
      throw new KernelStorageError('REVISION_CONFLICT', 'model claim no longer matches its validated state cut');
    }
    const attemptEntries = readInvocationAttempt(connection, input.runId, input.opId, input.attempt);
    if (attemptEntries.length !== 1 || attemptEntries[0]?.phase !== 'prepared') {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'invocation attempt is already claimed or settled');
    }
    if (modelCut) assertModelGrantDispatch(modelCut.authority.grant, { run, prepared: highest,
      history: readOperationJournal(connection, run.id, highest.opId), now });
    validate?.(connection, run, highest, now);
    claimed = {
      ...highest,
      seq: nextJournalSequence(connection, input.runId),
      phase: 'dispatch_claimed',
      dispatchId: input.dispatchId,
      supervisorInstanceId: owner.supervisorInstanceId,
      stateOwnerEpoch: owner.ownerEpoch,
      budgetDelta: ZERO_BUDGET,
      timestamp: now
    };
    if (input.sandboxLaunchSpecRef !== undefined) claimed.sandboxLaunchSpecRef = input.sandboxLaunchSpecRef;
    if (input.brokerFenceTokenDigest !== undefined) {
      claimed.brokerFenceTokenDigest = input.brokerFenceTokenDigest;
    }
    if (modelCut) modelRetryState(modelCut.retryPolicy, [...readOperationJournal(connection, run.id, highest.opId), claimed], now);
    if (launchSpecMetadata !== undefined) insertArtifactMetadata(connection, launchSpecMetadata, now);
    appendInvocationJournalEntry(connection, claimed);
  });
  requireHealthyFence(fenceOutcome);
  return claimed;
}

type InitialSettlementKind =
  | { phase: 'completed'; resultRef?: string; receiptRef?: string; consumed: BudgetUsage }
  | { phase: 'failed'; errorRef: string; evidenceRef?: string; evidenceDigest?: string; consumed: BudgetUsage; requireClaim: boolean }
  | { phase: 'unknown'; evidenceRef: string; evidenceDigest: string };

export type SettleInvocationInput = {
  runId: string;
  opId: string;
  attempt: number;
  expectedRunRevision: number;
};

/** Builds CAS artifacts before, and applies their validated rows inside, the settlement transaction. */
export type SettlementContinuation = (input: {
  run: Run;
  prepared: InvocationJournalEntry;
  settlement: BudgetSettlementV1;
}) => Promise<{
  metadata: PublishedArtifact[];
  unknownEvidence?: { evidenceRef: string; evidenceDigest: string };
  validate?: (connection: SqliteConnection, run: Run, committedAt: string) => void;
  commit?: (connection: SqliteConnection, run: Run, entry: InvocationJournalEntry, committedAt: string) => void;
}>;

export async function settleValidatedInvocation(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: SettleInvocationInput,
  terminal: InitialSettlementKind,
  continuation?: SettlementContinuation
): Promise<{ entry: InvocationJournalEntry; settlement: BudgetSettlementV1; run: Run }> {
  return settleInitialInvocation(driver, artifacts, owner, input, terminal, continuation);
}

type RetainedSettlement = {
  validateSnapshot(connection: SqliteConnection, run: Run): void;
  settlement?: BudgetSettlementV1;
  plan?: PlannedArtifact;
  artifact?: PublishedArtifact;
  continuation?: Awaited<ReturnType<SettlementContinuation>>;
  rebind?: { error: KernelStorageError; revision: number };
};

/** Internal owner of one already validated completion, not a StateStore
 * admission or a transferable execution/retirement capability. */
export function prepareValidatedInvocationSettlement(
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: SettleInvocationInput, terminal: InitialSettlementKind, continuation: SettlementContinuation,
  validateSnapshot: RetainedSettlement['validateSnapshot']
) {
  const retained: RetainedSettlement = { validateSnapshot };
  return { settle(expectedRunRevision: number) {
    return settleInitialInvocation(driver, artifacts, owner, { ...input, expectedRunRevision }, terminal, continuation, retained);
  }, hasRevisionConflict(error: unknown, expectedRunRevision: number) {
    return retained.rebind?.error === error && retained.rebind?.revision === expectedRunRevision;
  }, acceptRevisionConflict(error: unknown, expectedRunRevision: number) {
    const permit = retained.rebind;
    if (!permit || permit.error !== error || permit.revision !== expectedRunRevision) return false;
    const current = readRun(driver, input.runId);
    if (current.revision !== expectedRunRevision) return false;
    retained.validateSnapshot(driver, current);
    retained.rebind = undefined;
    return true;
  } };
}

async function settleInitialInvocation(
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: SettleInvocationInput, terminal: InitialSettlementKind, continuation?: SettlementContinuation,
  retained?: RetainedSettlement
): Promise<{ entry: InvocationJournalEntry; settlement: BudgetSettlementV1; run: Run }> {
  const artifactRefs = terminal.phase === 'completed'
    ? [terminal.resultRef, terminal.receiptRef]
    : terminal.phase === 'failed'
      ? [terminal.errorRef, terminal.evidenceRef]
      : [terminal.evidenceRef];
  await Promise.all(artifactRefs.filter((ref): ref is string => ref !== undefined).map((ref) => artifacts.readBytes(ref)));
  const terminalMetadata = continuation === undefined ? await Promise.all(
    artifactRefs
      .filter((ref): ref is string => ref !== undefined)
      .map((ref, index) => artifacts.describe(
        ref,
        'application/json',
        terminal.phase === 'completed'
          ? index === 0 && terminal.resultRef !== undefined
            ? 'cliq-invocation-result-v1'
            : 'cliq-invocation-receipt-v1'
          : terminal.phase === 'failed'
            ? index === 0
              ? 'cliq-invocation-error-v1'
              : 'cliq-post-claim-no-release-evidence-v1'
            : 'cliq-invocation-ambiguity-evidence-v1'
      ))
  ) : [];

  for (let retry = 0; retry < SETTLEMENT_RETRY_LIMIT; retry += 1) {
    const snapshotRun = readRun(driver, input.runId);
    if (snapshotRun.revision !== input.expectedRunRevision) {
      const error = new KernelStorageError('REVISION_CONFLICT', 'Run revision changed before invocation settlement');
      if (retained && snapshotRun.revision > input.expectedRunRevision && snapshotRun.stopIntentRef) {
        // Pending cause only. The owning reducer must asynchronously verify
        // the exact new StopIntent before acceptRevisionConflict can grant it.
        retained.rebind = { error, revision: snapshotRun.revision };
      }
      throw error;
    }
    retained?.validateSnapshot(driver, snapshotRun);
    const entries = readInvocationAttempt(driver, input.runId, input.opId, input.attempt);
    const prepared = entries.find((entry) => entry.phase === 'prepared');
    const claim = entries.find((entry) => entry.phase === 'dispatch_claimed');
    if (prepared === undefined) throw new KernelStorageError('NOT_FOUND', 'prepared invocation attempt is missing');
    if (continuation === undefined && (prepared.opKind === 'tool' || prepared.opKind === 'mcp')) {
      const spec = decodeRunSpec(await artifacts.readCanonical(snapshotRun.specRef));
      const assembly = await artifacts.readCanonical<{ format?: string }>(spec.assemblyRef);
      if (assembly.format === 'cliq-run-assembly-v1' && terminal.phase !== 'unknown') {
        throw new KernelStorageError('INVALID_REQUEST', 'typed tool settlement requires its ordered continuation and checkpoint');
      }
    }
    if (prepared.opKind === 'model' && terminal.phase === 'completed' && continuation === undefined) {
      throw new KernelStorageError('INVALID_REQUEST', 'model completion requires its typed continuation');
    }
    if (prepared.opKind === 'model' && terminal.phase === 'failed' && terminal.requireClaim && continuation === undefined) {
      throw new KernelStorageError('INVALID_REQUEST', 'claimed model refunds require validated broker no-release evidence');
    }
    if (entries.some((entry) => ['completed', 'failed', 'unknown', 'abandoned'].includes(entry.phase))) {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'invocation attempt is already settled');
    }
    if ((terminal.phase !== 'failed' || terminal.requireClaim) && claim === undefined) {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'invocation settlement requires a permanent dispatch claim');
    }
    if (terminal.phase === 'failed' && !terminal.requireClaim && claim !== undefined) {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'pre-dispatch failure cannot follow a claim');
    }
    const consumed = terminal.phase === 'unknown' || (prepared.opKind === 'model' && terminal.phase === 'completed')
      ? prepared.budgetDelta
      : decodeBudgetUsage(terminal.consumed, 'invocation consumed budget');
    const released = prepared.budgetDelta;
    const reservedAfter = subtractBudget(snapshotRun.budgetReserved, prepared.budgetDelta, 'Run reserved settlement');
    const consumedAfter = addBudget(snapshotRun.budgetConsumed, consumed, 'Run consumed settlement');
    const settlement = retained?.settlement ?? (() => {
      const fence = readTimeFence(driver);
      if (fence === undefined) throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence is missing');
      const sampled = sampleCanonicalNow();
      const settledAt = sampled >= fence.lastAcceptedAt ? sampled : fence.lastAcceptedAt;
      const terminalSequence = entries.length === 0
        ? 0
        : Number(
            driver
              .prepare('SELECT COALESCE(max(seq), 0) + 1 AS seq FROM run_journal WHERE run_id = ?')
              .get<{ seq: unknown }>(input.runId)?.seq
          );
      const settlement: BudgetSettlementV1 = {
        schemaVersion: 1,
        format: 'cliq-budget-settlement-v1',
        runId: input.runId,
        opId: input.opId,
        attempt: input.attempt,
        preparedJournalSeq: prepared.seq,
        terminalJournalSeq: terminalSequence,
        terminalPhase: terminal.phase,
        reserved: prepared.budgetDelta,
        consumed,
        released,
        budgetConsumedBefore: snapshotRun.budgetConsumed,
        budgetConsumedAfter: consumedAfter,
        budgetReservedBefore: snapshotRun.budgetReserved,
        budgetReservedAfter: reservedAfter,
        settledAt,
        settlementDigest: ''
      };
      settlement.settlementDigest = digestOmitting(settlement, 'settlementDigest');
      return settlement;
    })();
    if (retained) retained.settlement = settlement;
    const settlementPlan = retained?.plan ?? planCanonicalArtifact(settlement, 'cliq-budget-settlement-v1');
    if (retained) retained.plan = settlementPlan;
    const settlementArtifact = retained?.artifact ?? await artifacts.publishBytes(settlementPlan.bytes, settlementPlan.mediaType, settlementPlan.schemaKind);
    if (retained) retained.artifact = settlementArtifact;
    const continuationPlan = retained?.continuation ?? await continuation?.({ run: snapshotRun, prepared, settlement });
    if (retained) retained.continuation = continuationPlan;
    if (continuationPlan?.unknownEvidence && terminal.phase !== 'unknown') {
      throw new KernelStorageError('INVALID_REQUEST', 'only a protected unknown settlement can restage its evidence');
    }
    const selectedTerminal = terminal.phase === 'unknown' && continuationPlan?.unknownEvidence
      ? { ...terminal, ...continuationPlan.unknownEvidence } : terminal;
    try {
      return commitInitialSettlement(
        driver,
        owner,
        input,
        selectedTerminal,
        prepared,
        claim,
        snapshotRun,
        settlement,
        settlementArtifact,
        [...terminalMetadata, ...(continuationPlan?.metadata ?? [])],
        continuationPlan?.commit,
        (connection, run, committedAt) => {
          retained?.validateSnapshot(connection, run);
          continuationPlan?.validate?.(connection, run, committedAt);
        }
      );
    } catch (error) {
      if (error instanceof ReducerSnapshotChanged) {
        const changed = new KernelStorageError('REVISION_CONFLICT', 'prepared continuation cut changed before settlement');
        if (retained) {
          const current = readRun(driver, input.runId);
          // This private exception escaped transaction() only after its
          // successful rollback. The changed StopIntent is not SQL failure
          // permission and never rebuilds the original completion plan.
          if (current.revision > input.expectedRunRevision && current.stopIntentRef) retained.rebind = { error: changed, revision: current.revision };
        }
        if (continuationPlan || retained) throw changed;
        continue;
      }
      throw error;
    }
  }
  throw new KernelStorageError('REVISION_CONFLICT', 'invocation settlement could not obtain a stable state cut');
}

function commitInitialSettlement(
  driver: SqliteDriver,
  owner: StateOwnerContext,
  input: SettleInvocationInput,
  terminal: InitialSettlementKind,
  preparedSnapshot: InvocationJournalEntry,
  claimSnapshot: InvocationJournalEntry | undefined,
  runSnapshot: Run,
  settlement: BudgetSettlementV1,
  settlementArtifact: PublishedArtifact,
  terminalMetadata: PublishedArtifact[],
  commitContinuation?: (connection: SqliteConnection, run: Run, entry: InvocationJournalEntry, committedAt: string) => void,
  validateTerminal?: (connection: SqliteConnection, run: Run, committedAt: string) => void
): { entry: InvocationJournalEntry; settlement: BudgetSettlementV1; run: Run } {
  let result!: { entry: InvocationJournalEntry; settlement: BudgetSettlementV1; run: Run };
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const committedAt = sampleCanonicalNow();
    const run = readRun(connection, input.runId);
    if (
      run.revision !== runSnapshot.revision ||
      JSON.stringify(run.budgetReserved) !== JSON.stringify(runSnapshot.budgetReserved) ||
      JSON.stringify(run.budgetConsumed) !== JSON.stringify(runSnapshot.budgetConsumed)
    ) throw new ReducerSnapshotChanged();
    // Journal-only evidence may settle, but only the recovery reducer may advance
    // a frontier retained by its exact reconciliation wait.
    if (commitContinuation && run.waitingReason === 'reconciliation') {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'invocation continuation awaits worker recovery');
    }
    const entries = readInvocationAttempt(connection, input.runId, input.opId, input.attempt);
    const prepared = entries.find((entry) => entry.phase === 'prepared');
    const claim = entries.find((entry) => entry.phase === 'dispatch_claimed');
    if (
      JSON.stringify(prepared) !== JSON.stringify(preparedSnapshot) ||
      JSON.stringify(claim) !== JSON.stringify(claimSnapshot) ||
      entries.some((entry) => ['completed', 'failed', 'unknown', 'abandoned'].includes(entry.phase)) ||
      nextJournalSequence(connection, input.runId) !== settlement.terminalJournalSeq
    ) throw new ReducerSnapshotChanged();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, committedAt);
    if (fenceOutcome !== 'healthy') return;
    if (committedAt < settlement.settledAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'transaction clock precedes its staged settlement');
    validateTerminal?.(connection, run, committedAt);
    insertArtifactMetadata(connection, settlementArtifact, committedAt);
    for (const artifact of terminalMetadata) {
      insertArtifactMetadata(connection, artifact, committedAt);
    }
    const source = claim ?? prepared!;
    const entry: InvocationJournalEntry = {
      ...source,
      seq: settlement.terminalJournalSeq,
      phase: terminal.phase,
      budgetDelta: settlement.consumed,
      budgetSettlementRef: settlementArtifact.ref,
      timestamp: settlement.settledAt
    };
    if (terminal.phase === 'completed') {
      if (terminal.resultRef !== undefined) entry.resultRef = terminal.resultRef;
      if (terminal.receiptRef !== undefined) entry.receiptRef = terminal.receiptRef;
    } else if (terminal.phase === 'failed') {
      entry.errorRef = terminal.errorRef;
      if (terminal.evidenceRef !== undefined) {
        entry.evidenceRef = terminal.evidenceRef;
        entry.evidenceDigest = terminal.evidenceDigest;
      }
    } else {
      entry.evidenceRef = terminal.evidenceRef;
      entry.evidenceDigest = terminal.evidenceDigest;
    }
    appendInvocationJournalEntry(connection, entry);
    const update = connection
      .prepare(
        `UPDATE runs SET budget_reserved_json = ?, budget_consumed_json = ?,
           revision = revision + 1, updated_at = ?
         WHERE id = ? AND revision = ? AND budget_reserved_json = ? AND budget_consumed_json = ?`
      )
      .run(
        JSON.stringify(settlement.budgetReservedAfter),
        JSON.stringify(settlement.budgetConsumedAfter),
        committedAt,
        run.id,
        BigInt(run.revision),
        JSON.stringify(run.budgetReserved),
        JSON.stringify(run.budgetConsumed)
      );
    if (update.changes !== 1n) throw new ReducerSnapshotChanged();
    commitContinuation?.(connection, run, entry, committedAt);
    const updatedRun = readRun(connection, run.id);
    appendRunStateEvent(connection, updatedRun, committedAt);
    result = { entry, settlement, run: updatedRun };
  });
  requireHealthyFence(fenceOutcome);
  return result;
}

export function completeInvocation(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: SettleInvocationInput & { resultRef?: string; receiptRef?: string; consumed: BudgetUsage }
): Promise<{ entry: InvocationJournalEntry; settlement: BudgetSettlementV1; run: Run }> {
  if (input.resultRef === undefined && input.receiptRef === undefined) {
    throw new KernelStorageError('INVALID_REQUEST', 'completed invocation requires a result or receipt');
  }
  return settleValidatedInvocation(driver, artifacts, owner, input, {
    phase: 'completed',
    resultRef: input.resultRef,
    receiptRef: input.receiptRef,
    consumed: input.consumed
  });
}

export function failInvocationBeforeDispatch(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: SettleInvocationInput & { errorRef: string }
): Promise<{ entry: InvocationJournalEntry; settlement: BudgetSettlementV1; run: Run }> {
  return settleValidatedInvocation(driver, artifacts, owner, input, {
    phase: 'failed',
    errorRef: input.errorRef,
    consumed: ZERO_BUDGET,
    requireClaim: false
  });
}

export function failClaimedInvocationWithoutRelease(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: SettleInvocationInput & { errorRef: string; evidenceRef: string; evidenceDigest: string }
): Promise<{ entry: InvocationJournalEntry; settlement: BudgetSettlementV1; run: Run }> {
  return settleValidatedInvocation(driver, artifacts, owner, input, {
    phase: 'failed',
    errorRef: input.errorRef,
    evidenceRef: input.evidenceRef,
    evidenceDigest: input.evidenceDigest,
    consumed: ZERO_BUDGET,
    requireClaim: true
  });
}

export async function markInvocationUnknown(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: SettleInvocationInput & { evidenceRef: string; evidenceDigest: string }
): Promise<{ entry: InvocationJournalEntry; settlement: BudgetSettlementV1; run: Run }> {
  const run = readRun(driver, input.runId);
  const spec = decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef));
  const assembly = await readCanonicalArtifact<Partial<RunAssemblyV1>>(artifacts, spec.assemblyRef);
  const prepared = readInvocationAttempt(driver, input.runId, input.opId, input.attempt).find(entry => entry.phase === 'prepared');
  if (prepared?.opKind === 'model' && assembly.format === 'cliq-run-assembly-v1' && assembly.provider?.adapter?.adapterId === MODEL_BROKER_ENTRY_ID) {
    return markInstalledBrokerAmbiguity(driver, artifacts, owner, input);
  }
  return settleValidatedInvocation(driver, artifacts, owner, input, {
    phase: 'unknown',
    evidenceRef: input.evidenceRef,
    evidenceDigest: input.evidenceDigest
  });
}

/** Private installed failed-release producer only. The protected continuation
 * fixes observation time to the actual unknown Journal settlement, then checks
 * its exact current claim inside that same SQL transaction before insertion. */
export function markInstalledBrokerAmbiguity(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: SettleInvocationInput & { evidenceRef: string; evidenceDigest: string }
): Promise<{ entry: InvocationJournalEntry; settlement: BudgetSettlementV1; run: Run }> {
  return settleValidatedInvocation(driver, artifacts, owner, input,
    { phase: 'unknown', evidenceRef: input.evidenceRef, evidenceDigest: input.evidenceDigest },
    async ({ run, prepared, settlement }) => {
      const claim = readInvocationAttempt(driver, input.runId, input.opId, input.attempt).find(entry => entry.phase === 'dispatch_claimed');
      const plan = await prepareInstalledBrokerAmbiguity(driver, artifacts, owner, { run, prepared, claim,
        evidenceRef: input.evidenceRef, evidenceDigest: input.evidenceDigest, settledAt: settlement.settledAt });
      if (!plan) throw new KernelStorageError('INVALID_REQUEST', 'installed broker ambiguity requires its fixed admitted model recipe');
      return plan;
    });
}

export async function abandonUnknownInvocation(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: {
    runId: string;
    opId: string;
    attempt: number;
    attestationRef: string;
  }
): Promise<InvocationJournalEntry> {
  await artifacts.readBytes(input.attestationRef);
  const attestationMetadata = await artifacts.describe(
    input.attestationRef,
    'application/json',
    'cliq-manual-abandon-attestation-v1'
  );
  let abandoned!: InvocationJournalEntry;
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (fenceOutcome !== 'healthy') return;
    const entries = readInvocationAttempt(connection, input.runId, input.opId, input.attempt);
    const unknown = entries.find((entry) => entry.phase === 'unknown');
    const claim = entries.find((entry) => entry.phase === 'dispatch_claimed');
    if (
      unknown === undefined ||
      claim === undefined ||
      unknown.replayClass !== 'manual' ||
      unknown.budgetSettlementRef === undefined ||
      entries.some((entry) => entry.phase === 'abandoned')
    ) {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'only one manual unknown invocation may be abandoned');
    }
    abandoned = {
      ...claim,
      seq: nextJournalSequence(connection, input.runId),
      phase: 'abandoned',
      attestationRef: input.attestationRef,
      budgetDelta: ZERO_BUDGET,
      budgetSettlementRef: unknown.budgetSettlementRef,
      timestamp: now
    };
    insertArtifactMetadata(connection, attestationMetadata, now);
    appendInvocationJournalEntry(connection, abandoned);
  });
  requireHealthyFence(fenceOutcome);
  return abandoned;
}

/** Sole terminal transaction only. Positive original private-domain rollback
 * resolves the unknown without replacing its pessimistic BudgetSettlement. */
export function resolvePrivateRollbackInvocation(connection: SqliteConnection, driver: SqliteDriver,
  owner: StateOwnerContext, token: WorkerRecoveryTerminalPlan, runId: string, now: string): InvocationJournalEntry {
  const plan = readWorkerRecoveryTerminalPlan(driver, owner, token, runId), rollback = plan.rollback;
  assertActiveStateOwner(connection, owner);
  if (!rollback) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'private rollback has no original unknown producer');
  const entries = readInvocationAttempt(connection, runId, rollback.prepared.opId, rollback.prepared.attempt);
  const generation = readRequiredWorkspaceGenerationByRef(connection, plan.generation.generationRef);
  const current = readRun(connection, runId);
  if (current.revision !== plan.cut.run.revision || current.waitingOnRef !== plan.cut.run.waitingOnRef ||
      generation.phase !== 'retired' || generation.retirementEvidenceRef !== rollback.evidence.retirementEvidenceRef ||
      readHighestPreparedAttempt(connection, runId, rollback.prepared.opId)?.attempt !== rollback.prepared.attempt ||
      entries.length !== 3 || entries[0]?.seq !== rollback.prepared.seq || entries[1]?.seq !== rollback.claim.seq ||
      entries[2]?.phase !== 'unknown' || entries[2].seq !== rollback.unknown.seq ||
      entries[2].budgetSettlementRef !== rollback.unknown.budgetSettlementRef ||
      nextJournalSequence(connection, runId) !== plan.cut.journal.length + 1 || now < rollback.evidence.observedAt)
    throw new KernelStorageError('REVISION_CONFLICT', 'private rollback original claim, retirement or immutable settlement changed');
  const failed: InvocationJournalEntry = { ...rollback.claim, seq: nextJournalSequence(connection, runId), phase: 'failed',
    budgetDelta: ZERO_BUDGET, budgetSettlementRef: rollback.unknown.budgetSettlementRef, errorRef: rollback.artifact.ref,
    evidenceRef: rollback.artifact.ref, evidenceDigest: rollback.evidence.evidenceDigest, timestamp: now };
  appendInvocationJournalEntry(connection, failed);
  return failed;
}
