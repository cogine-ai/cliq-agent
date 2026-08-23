import { assertArtifactRef, parseCanonicalTime } from '../kernel/identity.js';
import type {
  BudgetUsage,
  InvocationJournalEntry,
  RecoveryClosureV1,
  RunItemReferenceV1,
  WorkerLaunch,
  WorkspaceGenerationStateV1
} from '../kernel/types.js';
import type { ArtifactCatalog } from './artifacts.js';
import {
  decodeBudgetSettlement,
  decodeContextManifest,
  decodeRunSpec,
  decodeWorkerIdentity,
  decodeWorkspaceEntries,
  decodeWorkspaceGenerationIdentity,
  decodeWorkspaceGenerationSnapshotEvidence,
  decodeWorkspaceState
} from './decoders.js';
import { KernelStorageError } from './errors.js';
import { addBudget, decodeBudgetUsage, isZeroBudget } from './invariants.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { readCheckpoint, readRun } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';

const ZERO_BUDGET: BudgetUsage = {
  modelTokens: 0,
  costMicros: 0,
  toolCalls: 0,
  repairAttempts: 0
};

function recoveryFailure(message: string): never {
  throw new KernelStorageError('RECOVERY_REQUIRED', message);
}

function requireRecoveryArtifactRef(value: string, label: string): void {
  try {
    assertArtifactRef(value);
  } catch {
    recoveryFailure(`${label} is not a canonical ArtifactRef`);
  }
}

function requireRecoveryTime(value: string, label: string): number {
  try {
    return parseCanonicalTime(value);
  } catch {
    recoveryFailure(`${label} is not a canonical UTC millisecond`);
  }
}

function readRunItems(
  connection: SqliteConnection | SqliteDriver,
  runId: string
): RunItemReferenceV1[] {
  const rows = connection
    .prepare(
      `SELECT item_id, item_seq, payload_ref, created_at
       FROM items WHERE run_id = ? ORDER BY item_seq`
    )
    .all<{ item_id: string; item_seq: unknown; payload_ref: string; created_at: string }>(runId);
  return rows.map((row, index) => {
    const itemSeq = Number(row.item_seq);
    if (itemSeq !== index + 1) recoveryFailure('Run item sequence is not contiguous');
    try {
      assertArtifactRef(row.payload_ref);
    } catch {
      recoveryFailure('Run item payload is not a canonical ArtifactRef');
    }
    requireRecoveryTime(row.created_at, 'Run item createdAt');
    return {
      schemaVersion: 1,
      itemId: row.item_id,
      itemSeq,
      payloadRef: row.payload_ref,
      payloadDigest: row.payload_ref,
      createdAt: row.created_at
    };
  });
}

function assertRepeatedAttemptFields(
  prepared: InvocationJournalEntry,
  later: InvocationJournalEntry
): void {
  for (const field of [
    'runId',
    'opId',
    'opKind',
    'attempt',
    'leaseEpoch',
    'target',
    'requestRef',
    'replayClass',
    'idempotencyKey',
    'grantRef'
  ] as const) {
    if (prepared[field] !== later[field]) recoveryFailure(`Journal ${field} changed within an attempt`);
  }
}

function assertRepeatedClaimFields(
  claim: InvocationJournalEntry,
  later: InvocationJournalEntry
): void {
  for (const field of [
    'sandboxLaunchSpecRef',
    'dispatchId',
    'supervisorInstanceId',
    'stateOwnerEpoch',
    'brokerFenceTokenDigest'
  ] as const) {
    if (claim[field] !== later[field]) recoveryFailure(`Journal claim ${field} changed after dispatch`);
  }
}

type AttemptGroup = {
  prepared: InvocationJournalEntry;
  entries: InvocationJournalEntry[];
};

function validateJournalGraph(journal: InvocationJournalEntry[]): Map<string, AttemptGroup> {
  const groups = new Map<string, AttemptGroup>();
  const highestAttempt = new Map<string, number>();
  for (let index = 0; index < journal.length; index += 1) {
    const entry = journal[index]!;
    if (entry.seq !== index + 1) recoveryFailure('Run Journal sequence is not contiguous');
    const key = `${entry.opId}\0${entry.attempt}`;
    let group = groups.get(key);
    if (entry.phase === 'prepared') {
      if (group !== undefined) recoveryFailure('Run Journal attempt contains duplicate prepared rows');
      const expectedAttempt = (highestAttempt.get(entry.opId) ?? -1) + 1;
      if (entry.attempt !== expectedAttempt) recoveryFailure('Run Journal attempts are not contiguous from zero');
      highestAttempt.set(entry.opId, entry.attempt);
      group = { prepared: entry, entries: [] };
      groups.set(key, group);
    } else if (group === undefined) {
      recoveryFailure('Run Journal phase precedes its prepared row');
    }
    group.entries.push(entry);
    assertRepeatedAttemptFields(group.prepared, entry);
  }

  for (const group of groups.values()) {
    const phases = group.entries.map((entry) => entry.phase);
    if (phases[0] !== 'prepared') recoveryFailure('Run Journal attempt does not begin prepared');
    const claim = group.entries.find((entry) => entry.phase === 'dispatch_claimed');
    if (claim !== undefined) {
      if (phases[1] !== 'dispatch_claimed') recoveryFailure('Run Journal claim is not immediately after prepared');
      for (const entry of group.entries.slice(2)) assertRepeatedClaimFields(claim, entry);
    }
    const legal = claim === undefined
      ? phases.length === 1 || (phases.length === 2 && phases[1] === 'failed')
      : phases.length === 2 ||
        (phases.length === 3 && ['completed', 'failed', 'unknown'].includes(phases[2]!)) ||
        (phases.length === 4 && phases[2] === 'unknown' && ['completed', 'failed', 'abandoned'].includes(phases[3]!));
    if (!legal) recoveryFailure(`Run Journal phase graph is invalid: ${phases.join(' -> ')}`);
  }
  return groups;
}

async function validateJournalArtifactsAndBudgets(
  artifacts: ArtifactCatalog,
  groups: Map<string, AttemptGroup>
): Promise<{ reserved: BudgetUsage; consumed: BudgetUsage }> {
  let reserved = { ...ZERO_BUDGET };
  let consumed = { ...ZERO_BUDGET };
  for (const group of groups.values()) {
    await artifacts.readBytes(group.prepared.requestRef);
    const firstTerminal = group.entries.find((entry) =>
      entry.phase === 'completed' || entry.phase === 'failed' || entry.phase === 'unknown'
    );
    if (firstTerminal === undefined) {
      reserved = addBudget(reserved, group.prepared.budgetDelta, 'recovery reserved budget');
      continue;
    }
    if (firstTerminal.budgetSettlementRef === undefined) {
      recoveryFailure('settled Journal attempt is missing BudgetSettlement');
    }
    const settlement = decodeBudgetSettlement(
      await artifacts.readCanonical(firstTerminal.budgetSettlementRef)
    );
    const settlementMismatches = [
      settlement.runId !== group.prepared.runId ? 'runId' : undefined,
      settlement.opId !== group.prepared.opId ? 'opId' : undefined,
      settlement.attempt !== group.prepared.attempt ? 'attempt' : undefined,
      settlement.preparedJournalSeq !== group.prepared.seq ? 'preparedJournalSeq' : undefined,
      settlement.terminalJournalSeq !== firstTerminal.seq ? 'terminalJournalSeq' : undefined,
      settlement.terminalPhase !== firstTerminal.phase ? 'terminalPhase' : undefined,
      !budgetEqual(settlement.reserved, group.prepared.budgetDelta) ? 'reserved' : undefined,
      !budgetEqual(settlement.consumed, firstTerminal.budgetDelta) ? 'consumed' : undefined
    ].filter((field): field is string => field !== undefined);
    if (settlementMismatches.length > 0) {
      recoveryFailure(`BudgetSettlement does not match its Journal attempt: ${settlementMismatches.join(', ')}`);
    }
    for (const later of group.entries.slice(group.entries.indexOf(firstTerminal) + 1)) {
      if (later.budgetSettlementRef !== firstTerminal.budgetSettlementRef) {
        recoveryFailure('post-unknown Journal resolution changed its BudgetSettlement');
      }
    }
    consumed = addBudget(consumed, settlement.consumed, 'recovery consumed budget');
  }
  return { reserved, consumed };
}

function budgetLessThanOrEqual(left: BudgetUsage, right: BudgetUsage): boolean {
  return (
    left.modelTokens <= right.modelTokens &&
    left.costMicros <= right.costMicros &&
    left.toolCalls <= right.toolCalls &&
    left.repairAttempts <= right.repairAttempts
  );
}

function budgetEqual(left: BudgetUsage, right: BudgetUsage): boolean {
  return budgetLessThanOrEqual(left, right) && budgetLessThanOrEqual(right, left);
}

async function validateGenerationArtifacts(
  artifacts: ArtifactCatalog,
  generations: WorkspaceGenerationStateV1[]
): Promise<void> {
  for (const generation of generations) {
    const identity = decodeWorkspaceGenerationIdentity(
      await artifacts.readCanonical(generation.generationRef)
    );
    if (
      identity.generationId !== generation.generationId ||
      identity.runId !== generation.runId ||
      identity.identityDigest !== generation.generationIdentityDigest ||
      identity.sourceCheckpointId !== generation.sourceCheckpointId ||
      identity.sourceWorkspaceStateRef !== generation.sourceWorkspaceStateRef ||
      identity.sourceWorkspaceStateDigest !== generation.sourceWorkspaceStateDigest
    ) recoveryFailure('workspace generation state does not match its immutable identity');
    if (generation.snapshotEvidenceRef !== undefined) {
      const evidence = decodeWorkspaceGenerationSnapshotEvidence(
        await artifacts.readCanonical(generation.snapshotEvidenceRef)
      );
      const evidenceWorkspaceState = decodeWorkspaceState(
        await artifacts.readCanonical(evidence.workspaceStateRef)
      );
      const evidenceEntries = decodeWorkspaceEntries(
        await artifacts.readCanonical(evidenceWorkspaceState.entriesRef)
      );
      if (
        evidence.evidenceDigest !== generation.snapshotEvidenceDigest ||
        evidence.generationRef !== generation.generationRef ||
        evidence.generationIdentityDigest !== generation.generationIdentityDigest ||
        evidence.runId !== generation.runId ||
        evidenceWorkspaceState.stateDigest !== evidence.workspaceStateDigest ||
        evidenceWorkspaceState.entriesRef !== evidence.entriesRef ||
        evidenceWorkspaceState.privateGitStateRef !== evidence.privateGitStateRef ||
        evidenceEntries.treeDigest !== evidence.treeDigest ||
        evidence.treeDigest !== generation.lastVerifiedTreeDigest ||
        (generation.phase === 'sealed'
          ? evidence.purpose !== 'sealed_to_checkpoint'
          : evidence.purpose !== 'materialized_from_checkpoint' ||
            evidence.checkpointId !== generation.sourceCheckpointId ||
            evidence.workspaceStateRef !== generation.sourceWorkspaceStateRef ||
            evidence.workspaceStateDigest !== generation.sourceWorkspaceStateDigest)
      ) recoveryFailure('workspace generation snapshot evidence does not match its row');
    }
  }
}

async function validateLaunchGraph(
  artifacts: ArtifactCatalog,
  run: RecoveryClosureV1['run'],
  launches: WorkerLaunch[],
  generations: WorkspaceGenerationStateV1[]
): Promise<void> {
  const byRef = new Map(generations.map((generation) => [generation.generationRef, generation]));
  for (const launch of launches) {
    const generation = byRef.get(launch.workspaceGenerationRef);
    if (generation === undefined || generation.runId !== launch.runId) {
      recoveryFailure('unretired WorkerLaunch has no matching unretired workspace generation');
    }
    if (launch.workerIdentityDigest !== undefined) {
      const identity = decodeWorkerIdentity(await artifacts.readCanonical(launch.workerIdentityDigest));
      if (
        identity.launchId !== launch.launchId ||
        identity.supervisorInstanceId !== launch.supervisorInstanceId ||
        identity.spawnNonceDigest !== launch.spawnNonceDigest ||
        identity.activationNonceDigest !== launch.activationNonceDigest ||
        identity.processContainmentRef !== launch.processContainmentRef
      ) recoveryFailure('WorkerIdentity does not match WorkerLaunch');
    }
    if (launch.phase === 'activated') {
      if (
        !['active', 'revoking', 'checkpointing'].includes(generation.phase) ||
        !('activeWorkerLaunchId' in generation) ||
        generation.activeWorkerLaunchId !== launch.launchId ||
        generation.leaseEpoch !== launch.leaseEpoch ||
        generation.phase !== launch.generationWriteState
      ) recoveryFailure('activated WorkerLaunch and workspace generation write gate disagree');
    }
    if (launch.phase === 'reconciling' && generation.phase !== 'fenced_reconciling') {
      recoveryFailure('reconciling WorkerLaunch is not paired with a fenced generation');
    }
  }

  if (run.status === 'running') {
    if (run.activeWorkerLaunchId === undefined) recoveryFailure('running Run has no active WorkerLaunch pointer');
    const active = launches.find((launch) => launch.launchId === run.activeWorkerLaunchId);
    if (active?.phase !== 'activated' || active.leaseEpoch !== run.leaseEpoch) {
      recoveryFailure('running Run pointer does not match an activated WorkerLaunch');
    }
  } else if (run.activeWorkerLaunchId !== undefined) {
    recoveryFailure('non-running Run retains an active WorkerLaunch pointer');
  }
}

export async function readRecoveryClosure(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  runId: string
): Promise<RecoveryClosureV1> {
  const databaseCut = driver.transaction((connection) => {
    const run = readRun(connection, runId);
    if (run.revision < 1 || run.latestCheckpointId.length === 0) {
      recoveryFailure('Run is missing its initial ready Checkpoint');
    }
    const latestCheckpoint = readCheckpoint(connection, run.latestCheckpointId);
    return {
      run,
      latestCheckpoint,
      items: readRunItems(connection, run.id),
      journal: readInvocationJournal(connection, run.id),
      workerLaunches: readWorkerLaunchesForRun(connection, run.id, true),
      workspaceGenerations: readWorkspaceGenerationsForRun(connection, run.id, true),
      childAllocations: readChildAllocationsForRun(connection, run.id)
    };
  });
  const {
    run,
    latestCheckpoint,
    items,
    journal,
    workerLaunches,
    workspaceGenerations,
    childAllocations
  } = databaseCut;
  requireRecoveryArtifactRef(run.specRef, 'Run.specRef');
  for (const [label, ref] of [
    ['Run.frontierRef', run.frontierRef],
    ['Run.waitingOnRef', run.waitingOnRef],
    ['Run.resultRef', run.resultRef],
    ['Run.terminalDetailRef', run.terminalDetailRef],
    ['Run.stopIntentRef', run.stopIntentRef]
  ] as const) {
    if (ref !== undefined) requireRecoveryArtifactRef(ref, label);
  }
  try {
    decodeBudgetUsage(run.budgetReserved, 'Run.budgetReserved');
    decodeBudgetUsage(run.budgetConsumed, 'Run.budgetConsumed');
  } catch (error) {
    recoveryFailure(`Run budget state is invalid: ${(error as Error).message}`);
  }
  const createdAt = requireRecoveryTime(run.createdAt, 'Run.createdAt');
  const deadlineAt = requireRecoveryTime(run.deadlineAt, 'Run.deadlineAt');
  requireRecoveryTime(run.updatedAt, 'Run.updatedAt');
  if (deadlineAt <= createdAt) recoveryFailure('Run deadline is not after creation');
  if (!['agent', 'tool', 'verify', 'finalize', 'delivery', null].includes(run.nextStep)) {
    recoveryFailure('Run.nextStep is not closed');
  }
  if (
    run.waitingReason !== undefined &&
    !['approval', 'input', 'child', 'reconciliation'].includes(run.waitingReason)
  ) {
    recoveryFailure('Run.waitingReason is not closed');
  }
  requireRecoveryArtifactRef(latestCheckpoint.contextManifestRef, 'Checkpoint.contextManifestRef');
  requireRecoveryArtifactRef(latestCheckpoint.workspaceStateRef, 'Checkpoint.workspaceStateRef');
  requireRecoveryTime(latestCheckpoint.createdAt, 'Checkpoint.createdAt');
  if (latestCheckpoint.runId !== run.id || latestCheckpoint.basedOnRunRevision >= run.revision) {
    recoveryFailure('latest Checkpoint is not a prior cut of the Run');
  }
  if (run.revision === 1 && latestCheckpoint.basedOnRunRevision !== 0) {
    recoveryFailure('initial Checkpoint must be based on virtual revision 0');
  }

  const runSpec = decodeRunSpec(await artifacts.readCanonical(run.specRef));
  assertArtifactRef(runSpec.objectiveRef);
  const context = decodeContextManifest(await artifacts.readCanonical(latestCheckpoint.contextManifestRef));
  if (context.runId !== run.id || context.throughItemSeq !== latestCheckpoint.runItemSeq) {
    recoveryFailure('Checkpoint ContextManifest does not match its Run cut');
  }
  const workspaceState = decodeWorkspaceState(
    await artifacts.readCanonical(latestCheckpoint.workspaceStateRef)
  );
  if (
    workspaceState.runId !== run.id ||
    workspaceState.baseWorkspaceManifestRef !== runSpec.baseWorkspaceManifestRef
  ) recoveryFailure('workspace state is not bound to the admitted RunSpec');

  if (latestCheckpoint.runItemSeq > items.length) recoveryFailure('Checkpoint item cursor exceeds recovery items');
  if (latestCheckpoint.journalSeq > journal.length) recoveryFailure('Checkpoint Journal cursor exceeds recovery Journal');
  await Promise.all(items.map((item) => artifacts.readBytes(item.payloadRef)));
  const groups = validateJournalGraph(journal);
  const journalBudgets = await validateJournalArtifactsAndBudgets(artifacts, groups);
  if (
    !budgetLessThanOrEqual(journalBudgets.reserved, run.budgetReserved) ||
    !budgetLessThanOrEqual(journalBudgets.consumed, run.budgetConsumed)
  ) recoveryFailure('Run budget counters are below their durable Journal facts');
  if (childAllocations.length === 0) {
    if (
      !budgetEqual(journalBudgets.reserved, run.budgetReserved) ||
      !budgetEqual(journalBudgets.consumed, run.budgetConsumed)
    ) recoveryFailure('Run budget counters do not equal the Journal closure');
  }
  if (run.status !== 'running' && !isZeroBudget(run.budgetReserved) && journal.length === 0) {
    recoveryFailure('lease-free Run has an unexplained budget reservation');
  }
  await validateGenerationArtifacts(artifacts, workspaceGenerations);
  await validateLaunchGraph(artifacts, run, workerLaunches, workspaceGenerations);

  return {
    runSpec,
    run,
    latestCheckpoint,
    items,
    journal,
    workerLaunches,
    workspaceGenerations,
    childAllocations
  };
}
