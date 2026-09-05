import { digestOmitting, parseCanonicalTime } from '../../kernel/identity.js';
import type {
  BudgetSettlementV1,
  BudgetUsage,
  InvocationJournalEntry,
  ReplayClass,
  Run,
  RunEvent,
  WorkerLaunch,
  WorkspaceGenerationStateV1
} from '../../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from '../artifacts.js';
import { insertArtifactMetadata } from '../artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import { KernelStorageError } from '../errors.js';
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
  readInvocationAttempt
} from '../repositories/journal.js';
import { readRequiredWorkerLaunch } from '../repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef } from '../repositories/workspace-generations.js';
import { insertRunEvent, readRun } from '../rows.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';
import { decodeBudgetSettlement, decodeRunSpec } from '../decoders.js';

const ZERO_BUDGET: BudgetUsage = {
  modelTokens: 0,
  costMicros: 0,
  toolCalls: 0,
  repairAttempts: 0
};
const SETTLEMENT_RETRY_LIMIT = 8;

class ReducerSnapshotChanged extends Error {}

function requireHealthyFence(outcome: TimeFenceAdvance | undefined): void {
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

function appendRunStateEvent(connection: SqliteConnection, run: Run, occurredAt: string): void {
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
  insertRunEvent(connection, event);
}

function findGenerationByRef(connection: SqliteConnection, generationRef: string): WorkspaceGenerationStateV1 {
  return readRequiredWorkspaceGenerationByRef(connection, generationRef);
}

type LiveDispatchState = {
  run: Run;
  launch: WorkerLaunch;
  generation: WorkspaceGenerationStateV1;
};

function assertLiveDispatchState(
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
  decodeBudgetUsage(input.reservation, 'invocation reservation');
  if (isZeroBudget(input.reservation)) {
    throw new KernelStorageError('INVALID_REQUEST', 'ordinary invocation reservation must be nonzero');
  }
  await artifacts.readBytes(input.requestRef);
  if (input.grantRef !== undefined) await artifacts.readBytes(input.grantRef);
  const invocationMetadata = await Promise.all([
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

export async function claimInvocationDispatch(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: ClaimInvocationDispatchInput
): Promise<InvocationJournalEntry> {
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
    assertLiveDispatchState(
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
    const attemptEntries = readInvocationAttempt(connection, input.runId, input.opId, input.attempt);
    if (attemptEntries.length !== 1 || attemptEntries[0]?.phase !== 'prepared') {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'invocation attempt is already claimed or settled');
    }
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

async function settleInitialAttempt(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: SettleInvocationInput,
  terminal: InitialSettlementKind
): Promise<{ entry: InvocationJournalEntry; settlement: BudgetSettlementV1; run: Run }> {
  const artifactRefs = terminal.phase === 'completed'
    ? [terminal.resultRef, terminal.receiptRef]
    : terminal.phase === 'failed'
      ? [terminal.errorRef, terminal.evidenceRef]
      : [terminal.evidenceRef];
  await Promise.all(artifactRefs.filter((ref): ref is string => ref !== undefined).map((ref) => artifacts.readBytes(ref)));
  const terminalMetadata = await Promise.all(
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
  );

  for (let retry = 0; retry < SETTLEMENT_RETRY_LIMIT; retry += 1) {
    const snapshotRun = readRun(driver, input.runId);
    if (snapshotRun.revision !== input.expectedRunRevision) {
      throw new KernelStorageError('REVISION_CONFLICT', 'Run revision changed before invocation settlement');
    }
    const entries = readInvocationAttempt(driver, input.runId, input.opId, input.attempt);
    const prepared = entries.find((entry) => entry.phase === 'prepared');
    const claim = entries.find((entry) => entry.phase === 'dispatch_claimed');
    if (prepared === undefined) throw new KernelStorageError('NOT_FOUND', 'prepared invocation attempt is missing');
    if (entries.some((entry) => ['completed', 'failed', 'unknown', 'abandoned'].includes(entry.phase))) {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'invocation attempt is already settled');
    }
    if ((terminal.phase !== 'failed' || terminal.requireClaim) && claim === undefined) {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'invocation settlement requires a permanent dispatch claim');
    }
    if (terminal.phase === 'failed' && !terminal.requireClaim && claim !== undefined) {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'pre-dispatch failure cannot follow a claim');
    }
    const consumed = terminal.phase === 'unknown'
      ? prepared.budgetDelta
      : decodeBudgetUsage(terminal.consumed, 'invocation consumed budget');
    const released = prepared.budgetDelta;
    const reservedAfter = subtractBudget(snapshotRun.budgetReserved, prepared.budgetDelta, 'Run reserved settlement');
    const consumedAfter = addBudget(snapshotRun.budgetConsumed, consumed, 'Run consumed settlement');
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
    decodeBudgetSettlement(settlement);
    const settlementArtifact = await artifacts.publishCanonical(settlement, 'cliq-budget-settlement-v1');
    try {
      return commitInitialSettlement(
        driver,
        owner,
        input,
        terminal,
        prepared,
        claim,
        snapshotRun,
        settlement,
        settlementArtifact,
        terminalMetadata
      );
    } catch (error) {
      if (error instanceof ReducerSnapshotChanged) continue;
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
  terminalMetadata: PublishedArtifact[]
): { entry: InvocationJournalEntry; settlement: BudgetSettlementV1; run: Run } {
  let result!: { entry: InvocationJournalEntry; settlement: BudgetSettlementV1; run: Run };
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const currentFence = readTimeFence(connection);
    if (currentFence === undefined || settlement.settledAt < currentFence.lastAcceptedAt) {
      throw new ReducerSnapshotChanged();
    }
    const run = readRun(connection, input.runId);
    if (
      run.revision !== runSnapshot.revision ||
      JSON.stringify(run.budgetReserved) !== JSON.stringify(runSnapshot.budgetReserved) ||
      JSON.stringify(run.budgetConsumed) !== JSON.stringify(runSnapshot.budgetConsumed)
    ) throw new ReducerSnapshotChanged();
    const entries = readInvocationAttempt(connection, input.runId, input.opId, input.attempt);
    const prepared = entries.find((entry) => entry.phase === 'prepared');
    const claim = entries.find((entry) => entry.phase === 'dispatch_claimed');
    if (
      JSON.stringify(prepared) !== JSON.stringify(preparedSnapshot) ||
      JSON.stringify(claim) !== JSON.stringify(claimSnapshot) ||
      entries.some((entry) => ['completed', 'failed', 'unknown', 'abandoned'].includes(entry.phase)) ||
      nextJournalSequence(connection, input.runId) !== settlement.terminalJournalSeq
    ) throw new ReducerSnapshotChanged();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, settlement.settledAt);
    if (fenceOutcome !== 'healthy') return;
    insertArtifactMetadata(connection, settlementArtifact, settlement.settledAt);
    for (const artifact of terminalMetadata) {
      insertArtifactMetadata(connection, artifact, settlement.settledAt);
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
        settlement.settledAt,
        run.id,
        BigInt(run.revision),
        JSON.stringify(run.budgetReserved),
        JSON.stringify(run.budgetConsumed)
      );
    if (update.changes !== 1n) throw new ReducerSnapshotChanged();
    const updatedRun = readRun(connection, run.id);
    appendRunStateEvent(connection, updatedRun, settlement.settledAt);
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
  return settleInitialAttempt(driver, artifacts, owner, input, {
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
  return settleInitialAttempt(driver, artifacts, owner, input, {
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
  return settleInitialAttempt(driver, artifacts, owner, input, {
    phase: 'failed',
    errorRef: input.errorRef,
    evidenceRef: input.evidenceRef,
    evidenceDigest: input.evidenceDigest,
    consumed: ZERO_BUDGET,
    requireClaim: true
  });
}

export function markInvocationUnknown(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: SettleInvocationInput & { evidenceRef: string; evidenceDigest: string }
): Promise<{ entry: InvocationJournalEntry; settlement: BudgetSettlementV1; run: Run }> {
  return settleInitialAttempt(driver, artifacts, owner, input, {
    phase: 'unknown',
    evidenceRef: input.evidenceRef,
    evidenceDigest: input.evidenceDigest
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
