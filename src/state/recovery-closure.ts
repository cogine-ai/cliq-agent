import { observeInstalledPublicationWork } from './installed-run-diagnostics.js';
import { readChildAdmission } from './child-admission.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, parseCanonicalTime } from '../kernel/identity.js';
import type {
  BudgetUsage,
  ChildAllocationV1,
  ContextManifest,
  InvocationJournalEntry,
  RecoveryClosureV1,
  RunAssemblyV1,
  RunItemReferenceV1,
  RunSpec,
  SourceManifest,
  FrozenIgnoreRulesV1,
  WorkerLaunch,
  WorkspaceEntryManifest,
  WorkspaceGenerationStateV1,
  WorkspaceStateManifest
} from '../kernel/types.js';
import type { ArtifactCatalog } from './artifacts.js';
import { validateAgentRecovery, validateAgentRecoveryInDeliveryEpoch } from './agent-recovery.js';
import { createDeliveryReadData } from './delivery-read-data.js';
import { validateStopRecovery, validateStopRecoveryInDeliveryEpoch } from './stop-recovery.js';
import {
  decodeAdmittedContext,
  decodeBudgetSettlement,
  decodeContextManifest,
  decodeFrozenIgnoreRules,
  decodeRunObjective,
  decodeRunSpec,
  decodeSourceManifest,
  decodeSourceProjection,
  decodeVerifierSpec,
  decodeWorkerIdentity,
  decodeWorkspaceEntries,
  decodeWorkspaceGenerationIdentity,
  decodeWorkspaceGenerationSnapshotEvidence,
  decodeWorkspaceState
} from './decoders.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { validateWorkerRecoveryWait } from './worker-recovery.js';
import { addBudget, childAllocationBudgetFacts, decodeBudgetUsage, isZeroBudget } from './invariants.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { checkpointFromRow, readCheckpoint, readRun, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { validateRetainedWorkerSeal } from './tool-checkpoint.js';
import { readRetiredGenerationSource } from './generation-retirement.js';
import { validateInstalledBrokerAmbiguityHistory } from './broker-ambiguity.js';
import { validateInstalledModelNoReleaseHistory } from './broker-no-release.js';
import { assertWorkerPreparationCleanupContext, validateWorkerPreparationHistory, type WorkerPreparationCleanupContext } from './worker-preparation.js';
import { validateRunResultRecovery, validateRunResultRecoveryInDeliveryEpoch } from './run-result-recovery.js';
import { assertDeliveryModelFreeCut } from './run-model-free.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { readFrozenIgnoreRules } from '../workspace/frozen-ignore.js';
import { loadFrozenPrivateGit } from '../workspace/run-workspace/private-git.js';
import { readSourceProjectionData } from './source-projection-data.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { checkSourceManifest } from './source-validation.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { readAssemblySkills } from './skill-data.js';

type FrozenSourceContext = Readonly<{ baseRef: string; source: SourceManifest; rules: FrozenIgnoreRulesV1; resources?: SandboxResourceSpec }>;

const ZERO_BUDGET: BudgetUsage = {
  modelTokens: 0,
  costMicros: 0,
  toolCalls: 0,
  repairAttempts: 0
};

function recoveryFailure(message: string, cause?: unknown): never {
  if (cause instanceof ResourceRetirementError) throw cause;
  throw new KernelStorageError('RECOVERY_REQUIRED', message, { cause });
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

async function requireRecoveryArtifacts(
  artifacts: ArtifactCatalog,
  refs: ReadonlyArray<readonly [label: string, ref: string | undefined]>
): Promise<void> {
  const unique = new Map<string, string>();
  for (const [label, ref] of refs) {
    if (ref === undefined) continue;
    requireRecoveryArtifactRef(ref, label);
    if (!unique.has(ref)) unique.set(ref, label);
  }
  await artifacts.mapReads(
    [...unique], async ([ref, label]) => {
      try {
        await artifacts.verifyBytes(ref);
      } catch (error) {
        recoveryFailure(`${label} is not readable from CAS: ${(error as Error).message}`, error);
      }
    }
  );
}

async function validateWorkspaceStateArtifacts(
  artifacts: ArtifactCatalog,
  workspaceStateRef: string,
  label: string,
  frozen: FrozenSourceContext
): Promise<{ state: WorkspaceStateManifest; entries: WorkspaceEntryManifest }> {
  await requireRecoveryArtifacts(artifacts, [[label, workspaceStateRef]]);
  const state = decodeWorkspaceState(await artifacts.readCanonical(workspaceStateRef));
  if (state.baseWorkspaceManifestRef !== frozen.baseRef || state.sourceProjectionDigest !== frozen.source.sourceProjectionDigest)
    recoveryFailure('workspace state substitutes its original admitted base or projection');
  await requireRecoveryArtifacts(artifacts, [
    [`${label}.baseWorkspaceManifestRef`, state.baseWorkspaceManifestRef],
    [`${label}.entriesRef`, state.entriesRef],
    [`${label}.privateGitStateRef`, state.privateGitStateRef]
  ]);
  const entries = decodeWorkspaceEntries(await artifacts.readCanonical(state.entriesRef));
  await loadFrozenPrivateGit(artifacts, frozen.source, state, frozen.rules, undefined, frozen.resources);
  await requireRecoveryArtifacts(
    artifacts,
    entries.entries
      .filter((entry) => entry.kind === 'file')
      .map((entry, index) => [`${label}.entries[${index}].blobRef`, entry.blobRef] as const)
  );
  return { state, entries };
}

async function validateRunSpecArtifacts(
  artifacts: ArtifactCatalog,
  runSpec: RunSpec
): Promise<FrozenSourceContext> {
  await requireRecoveryArtifacts(artifacts, [
    ['RunSpec.objectiveRef', runSpec.objectiveRef],
    ['RunSpec.admittedContextRef', runSpec.admittedContextRef],
    ['RunSpec.baseWorkspaceManifestRef', runSpec.baseWorkspaceManifestRef],
    ['RunSpec.sourceProjectionRef', runSpec.sourceProjectionRef],
    ['RunSpec.assemblyRef', runSpec.assemblyRef],
    ['RunSpec.policyRef', runSpec.policyRef],
    ['RunSpec.sandboxProfileRef', runSpec.sandboxProfileRef],
    ['RunSpec.verifierSpecRef', runSpec.verifierSpecRef],
    ['RunSpec.dependencyPolicyRef', runSpec.dependencyPolicyRef],
    ['RunSpec.unverifiedConsentRef', runSpec.unverifiedConsentRef],
    ...runSpec.credentialGrantRefs.map((ref, index) =>
      [`RunSpec.credentialGrantRefs[${index}]`, ref] as const
    )
  ]);

  decodeRunObjective(await artifacts.readCanonical(runSpec.objectiveRef));
  decodeVerifierSpec(await artifacts.readCanonical(runSpec.verifierSpecRef));
  const admitted = decodeAdmittedContext(
    await artifacts.readCanonical(runSpec.admittedContextRef)
  );
  await requireRecoveryArtifacts(artifacts, [
    ['AdmittedContext.sessionProjectionRef', admitted.sessionProjectionRef],
    ...admitted.parentContextRefs.map((ref, index) =>
      [`AdmittedContext.parentContextRefs[${index}]`, ref] as const
    ),
    ...admitted.additionalArtifactRefs.map((ref, index) =>
      [`AdmittedContext.additionalArtifactRefs[${index}]`, ref] as const
    )
  ]);

  const source = decodeSourceManifest(
    await artifacts.readCanonical(runSpec.baseWorkspaceManifestRef)
  );
  checkSourceManifest(source);
  const projection = decodeSourceProjection(
    await artifacts.readCanonical(runSpec.sourceProjectionRef)
  );
  if (!source.git && projection.classificationIndexRef !== undefined) recoveryFailure('non-Git Run has a Git classification index');
  await requireRecoveryArtifacts(artifacts, [
    ['SourceManifest.entriesRef', source.entriesRef],
    ['SourceManifest.sourceProjectionRef', source.sourceProjectionRef],
    ['SourceManifest.frozenIgnoreRulesRef', source.frozenIgnoreRulesRef],
    ['SourceManifest.git.indexRef', source.git?.indexRef],
    ['SourceProjection.classificationIndexRef', projection.classificationIndexRef],
    ...projection.explicitIncludes.map((include, index) =>
      [`SourceProjection.explicitIncludes[${index}].authorizationRef`, include.authorizationRef] as const
    )
  ]);
  const resources = source.git || projection.explicitIncludes.length
    ? decodeSandboxProfile(await artifacts.readCanonical(runSpec.sandboxProfileRef)).resources : undefined;
  const classification = resources ? await readSourceProjectionData(artifacts, source, projection, resources) : undefined;
  const rules = classification?.rules ?? await readFrozenIgnoreRules(artifacts, source.frozenIgnoreRulesRef);
  await requireRecoveryArtifacts(
    artifacts,
    rules.sources.map((ruleSource, index) =>
      [`FrozenIgnoreRules.sources[${index}].contentRef`, ruleSource.contentRef] as const
    )
  );
  if (
    source.sourceProjectionRef !== runSpec.sourceProjectionRef ||
    source.frozenIgnoreRulesRef !== projection.frozenIgnoreRulesRef ||
    source.frozenIgnoreRulesDigest !== projection.frozenIgnoreRulesDigest ||
    source.frozenIgnoreRulesDigest !== rules.rulesDigest
  ) recoveryFailure('RunSpec source manifest, projection, and frozen ignore rules disagree');
  const sourceEntries = decodeWorkspaceEntries(await artifacts.readCanonical(source.entriesRef));
  if (sourceEntries.treeDigest !== source.treeDigest) {
    recoveryFailure('SourceManifest entries do not match its tree digest');
  }
  await requireRecoveryArtifacts(
    artifacts,
    sourceEntries.entries
      .filter((entry) => entry.kind === 'file')
      .map((entry, index) => [`SourceManifest.entries[${index}].blobRef`, entry.blobRef] as const)
  );
  return { baseRef: runSpec.baseWorkspaceManifestRef, source, rules, ...(resources ? { resources } : {}) };
}

async function validateContextArtifacts(
  artifacts: ArtifactCatalog,
  context: ContextManifest,
  runSpec: RunSpec
): Promise<void> {
  if (
    context.admittedContextRef !== runSpec.admittedContextRef ||
    context.assemblyRef !== runSpec.assemblyRef
  ) recoveryFailure('Checkpoint ContextManifest does not match its admitted RunSpec');
  const refs: Array<readonly [string, string | undefined]> = [
    ['ContextManifest.admittedContextRef', context.admittedContextRef],
    ['ContextManifest.assemblyRef', context.assemblyRef]
  ];
  for (const [segmentIndex, segment] of context.segments.entries()) {
    if (segment.kind === 'raw') {
      for (const [itemIndex, item] of segment.items.entries()) {
        refs.push([
          `ContextManifest.segments[${segmentIndex}].items[${itemIndex}].itemRef`,
          item.itemRef
        ]);
      }
    } else if (segment.kind === 'summary') {
      refs.push([`ContextManifest.segments[${segmentIndex}].summaryRef`, segment.summaryRef]);
      for (const [itemIndex, ref] of segment.preservedItemRefs.entries()) {
        refs.push([
          `ContextManifest.segments[${segmentIndex}].preservedItemRefs[${itemIndex}]`,
          ref
        ]);
      }
    }
  }
  await requireRecoveryArtifacts(artifacts, refs);
}

async function validateChildAllocationArtifacts(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  allocations: ChildAllocationV1[], run: RecoveryClosureV1['run']
): Promise<void> {
  const children = driver.prepare('SELECT id FROM runs WHERE parent_run_id=? ORDER BY id').all<{ id: string }>(run.id).map(row => row.id);
  const outgoing = allocations.filter(row => row.parentRunId === run.id).map(row => row.childRunId).sort();
  if (canonicalSha256(children) !== canonicalSha256(outgoing)) recoveryFailure('direct child Runs and allocation ownership are not all-and-only');
  const incoming = allocations.filter(row => row.childRunId === run.id);
  if (run.parentRunId ? incoming.length !== 1 || incoming[0]!.parentRunId !== run.parentRunId : incoming.length !== 0)
    recoveryFailure('Run parent identity has no exact unique original incoming allocation');
  const refs: Array<readonly [string, string | undefined]> = [];
  for (const [index, allocation] of allocations.entries()) {
    const original = await readChildAdmission(driver, artifacts, allocation.childRunId);
    if (canonicalSha256(original.allocation) !== canonicalSha256(allocation)) recoveryFailure('child allocation source differs from the original consistent cut');
    refs.push(
      [`ChildAllocation[${index}].delegateOperationGrantRef`, allocation.delegateOperationGrantRef],
      [`ChildAllocation[${index}].capabilityGrantRef`, allocation.capabilityGrantRef]
    );
    if (allocation.state !== 'reserved') {
      refs.push([
        `ChildAllocation[${index}].terminal.modelContentRef`,
        allocation.terminal.modelContentRef
      ]);
      if ('resultRef' in allocation.terminal) {
        refs.push(
          [`ChildAllocation[${index}].terminal.resultRef`, allocation.terminal.resultRef],
          [`ChildAllocation[${index}].terminal.patchManifestRef`, allocation.terminal.patchManifestRef]
        );
      } else {
        refs.push([
          `ChildAllocation[${index}].terminal.terminalDetailRef`,
          allocation.terminal.terminalDetailRef
        ]);
      }
    }
  }
  await requireRecoveryArtifacts(artifacts, refs);
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
    if (group.prepared.opKind === 'child_admission' || group.prepared.opKind === 'child_merge' || group.prepared.opKind === 'child_await' || group.prepared.opKind === 'skill_resource') {
      if (phases.join(',') !== 'prepared,dispatch_claimed,completed' || group.entries.some(entry =>
          entry.localCommittedAt !== group.prepared.localCommittedAt || entry.timestamp !== group.prepared.timestamp))
        recoveryFailure('local child Journal must be one complete original atomic triplet');
    }
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
    await requireRecoveryArtifacts(
      artifacts,
      group.entries.flatMap((entry, index) => [
        [`Journal[${entry.seq}:${index}].requestRef`, entry.requestRef] as const,
        [`Journal[${entry.seq}:${index}].grantRef`, entry.grantRef] as const,
        [`Journal[${entry.seq}:${index}].sandboxLaunchSpecRef`, entry.sandboxLaunchSpecRef] as const,
        [`Journal[${entry.seq}:${index}].resultRef`, entry.resultRef] as const,
        [`Journal[${entry.seq}:${index}].receiptRef`, entry.receiptRef] as const,
        [`Journal[${entry.seq}:${index}].errorRef`, entry.errorRef] as const,
        [`Journal[${entry.seq}:${index}].evidenceRef`, entry.evidenceRef] as const,
        [`Journal[${entry.seq}:${index}].attestationRef`, entry.attestationRef] as const,
        [`Journal[${entry.seq}:${index}].budgetSettlementRef`, entry.budgetSettlementRef] as const
      ])
    );
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
      settlement.settledAt !== firstTerminal.timestamp ? 'settledAt' : undefined,
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

/** Complete original Journal data checks without entering Run recovery or
 * authorization readers. This confers no claim, retry or native authority. */
export function readRetainedJournalData(artifacts: ArtifactCatalog, journal: InvocationJournalEntry[]) {
  return validateJournalArtifactsAndBudgets(artifacts, validateJournalGraph(journal));
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
  generations: WorkspaceGenerationStateV1[],
  frozen: FrozenSourceContext
): Promise<void> {
  for (const generation of generations) {
    await requireRecoveryArtifacts(artifacts, [
      ['WorkspaceGeneration.generationRef', generation.generationRef],
      ['WorkspaceGeneration.sourceWorkspaceStateRef', generation.sourceWorkspaceStateRef],
      ['WorkspaceGeneration.snapshotEvidenceRef', generation.snapshotEvidenceRef],
      ['WorkspaceGeneration.waitingSubjectRef', generation.waitingSubjectRef],
      ['WorkspaceGeneration.quarantineEvidenceRef', generation.quarantineEvidenceRef],
      ['WorkspaceGeneration.retirementEvidenceRef', generation.retirementEvidenceRef]
    ]);
    const identity = decodeWorkspaceGenerationIdentity(
      await artifacts.readCanonical(generation.generationRef)
    );
    await requireRecoveryArtifacts(artifacts, [
      ['WorkspaceGenerationIdentity.locator.stateRootIdentityRef', identity.locator.stateRootIdentityRef]
    ]);
    const sourceWorkspace = await validateWorkspaceStateArtifacts(
      artifacts,
      identity.sourceWorkspaceStateRef,
      'WorkspaceGenerationIdentity.sourceWorkspaceStateRef', frozen
    );
    if (
      identity.generationId !== generation.generationId ||
      identity.runId !== generation.runId ||
      identity.identityDigest !== generation.generationIdentityDigest ||
      identity.sourceCheckpointId !== generation.sourceCheckpointId ||
      identity.sourceWorkspaceStateRef !== generation.sourceWorkspaceStateRef ||
      identity.sourceWorkspaceStateDigest !== generation.sourceWorkspaceStateDigest ||
      sourceWorkspace.state.stateDigest !== identity.sourceWorkspaceStateDigest ||
      sourceWorkspace.entries.treeDigest !== identity.sourceTreeDigest
    ) recoveryFailure('workspace generation state does not match its immutable identity');
    if (generation.snapshotEvidenceRef !== undefined) {
      const evidence = decodeWorkspaceGenerationSnapshotEvidence(
        await artifacts.readCanonical(generation.snapshotEvidenceRef)
      );
      const evidenceWorkspace = await validateWorkspaceStateArtifacts(
        artifacts,
        evidence.workspaceStateRef,
        'WorkspaceGenerationSnapshotEvidence.workspaceStateRef', frozen
      );
      if (
        evidence.evidenceDigest !== generation.snapshotEvidenceDigest ||
        evidence.generationRef !== generation.generationRef ||
        evidence.generationIdentityDigest !== generation.generationIdentityDigest ||
        evidence.runId !== generation.runId ||
        evidenceWorkspace.state.stateDigest !== evidence.workspaceStateDigest ||
        evidenceWorkspace.state.entriesRef !== evidence.entriesRef ||
        evidenceWorkspace.state.privateGitStateRef !== evidence.privateGitStateRef ||
        evidenceWorkspace.entries.treeDigest !== evidence.treeDigest ||
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
    // Its owning history validator checked the logical intent, actual recorded
    // births and original live owner. No execution fields exist in this branch.
    if (launch.phase === 'preparing') continue;
    if (launch.retirementKind === 'preparation') recoveryFailure('retired preparation is not an unretired launch');
    await requireRecoveryArtifacts(artifacts, [
      ['WorkerLaunch.workspaceGenerationRef', launch.workspaceGenerationRef],
      ['WorkerLaunch.containmentPlanRef', launch.containmentPlanRef],
      ['WorkerLaunch.sandboxLaunchSpecRef', launch.sandboxLaunchSpecRef],
      ['WorkerLaunch.workerIdentityDigest', launch.workerIdentityDigest],
      ['WorkerLaunch.processContainmentRef', launch.processContainmentRef],
      ['WorkerLaunch.retirementEvidenceRef', launch.retirementEvidenceRef]
    ]);
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
        identity.processContainmentRef !== launch.processContainmentRef ||
        (launch.leaseEpoch !== undefined && identity.intendedLeaseEpoch !== launch.leaseEpoch)
      ) recoveryFailure('WorkerIdentity does not match WorkerLaunch');
    }
    if (launch.phase === 'activated') {
      if (
        !['active', 'revoking', 'checkpointing'].includes(generation.phase) ||
        !('activeWorkerLaunchId' in generation) ||
        generation.activeWorkerLaunchId !== launch.launchId ||
        generation.leaseEpoch !== launch.leaseEpoch ||
        generation.phase !== launch.generationWriteState ||
        generation.quiesceId !== launch.quiesceId
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
  if (run.status === 'waiting' && (run.waitingReason === 'approval' || run.waitingReason === 'input' || run.waitingReason === 'child') && launches.some((launch) => launch.phase !== 'retired')) {
    recoveryFailure('control wait retains an unretired WorkerLaunch');
  }
}

/** Fixed, inert progress only: no refs, timing, authority or retry decisions. */
export type RecoveryClosurePhase = 'cut' | 'preparation' | 'spec' | 'context' | 'journal' | 'generations' | 'history' |
  `history_${import('./agent-recovery.js').AgentRecoveryPhase}` | 'history_broker' | 'seals' | 'terminal';

type PublicationPrefix = Awaited<ReturnType<typeof import('./delivery-publication-progress.js')['readPublicationPrefix']>>;

export async function readRecoveryClosure(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  runId: string,
  onPhase?: (phase: RecoveryClosurePhase) => void
): Promise<RecoveryClosureV1> {
  return (await readRecoveryProjection(driver, artifacts, runId, onPhase)).cut;
}

/** One exact dead preparation may be inspected by its genuine successor.
 * This does not resume the original producer or grant execution/retirement. */
export async function readPreparingCleanupClosure(driver: SqliteDriver, artifacts: ArtifactCatalog,
  runId: string, context: WorkerPreparationCleanupContext): Promise<RecoveryClosureV1> {
  assertWorkerPreparationCleanupContext(driver, context, runId);
  const result = await readRecoveryProjection(driver, artifacts, runId, undefined, context);
  assertWorkerPreparationCleanupContext(driver, context, runId);
  return result.cut;
}

/** One complete fresh recovery traversal and its publication projection.
 * Returned data grants no task, dispatch, settlement or terminal authority. */
export async function readDeliveryPublicationClosure(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  runId: string,
  onPhase?: (phase: RecoveryClosurePhase) => void
): Promise<{ cut: RecoveryClosureV1; prefix: PublicationPrefix }> {
  return observeInstalledPublicationWork(runId, 'publication_recovery', async () => {
    const result = await readRecoveryProjection(driver, artifacts, runId, onPhase);
    if (result.cut.runSpec.operation !== 'delivery' || !result.prefix)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'publication closure requires a delivery Run');
    return { cut: result.cut, prefix: result.prefix };
  });
}

async function readRecoveryProjection(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  runId: string,
  onPhase?: (phase: RecoveryClosurePhase) => void,
  preparationCleanup?: WorkerPreparationCleanupContext
): Promise<{ cut: RecoveryClosureV1; prefix?: PublicationPrefix }> {
  const phase = (value: RecoveryClosurePhase) => { try { onPhase?.(value); } catch { /* Diagnosis cannot decide recovery. */ } };
  phase('cut');
  const databaseCut = driver.transaction((connection) => {
    const run = readRun(connection, runId);
    const principalId = connection.prepare('SELECT principal_id FROM runs WHERE id = ?').get<{ principal_id: string }>(run.id)?.principal_id;
    const session = readSession(connection, run.sessionId);
    if (!principalId || principalId !== readSessionPrincipalId(connection, session.id)) {
      recoveryFailure('Run does not share its original Session principal');
    }
    if (run.revision < 1 || run.latestCheckpointId.length === 0) {
      recoveryFailure('Run is missing its initial ready Checkpoint');
    }
    const latestCheckpoint = readCheckpoint(connection, run.latestCheckpointId);
    const checkpoints = connection.prepare('SELECT * FROM checkpoints WHERE run_id = ? ORDER BY rowid')
      .all(run.id).map(checkpointFromRow);
    const allWorkerLaunches = readWorkerLaunchesForRun(connection, run.id);
    return {
      run,
      principalId,
      workspaceIdentityRef: session.workspaceIdentityRef,
      latestCheckpoint,
      checkpoints,
      items: readRunItems(connection, run.id),
      journal: readInvocationJournal(connection, run.id),
      workerLaunches: allWorkerLaunches.filter(launch => launch.phase !== 'retired'),
      allWorkerLaunches,
      workspaceGenerations: readWorkspaceGenerationsForRun(connection, run.id),
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
  phase('preparation');
  try {
    await validateWorkerPreparationHistory(driver, artifacts, { run, launches: databaseCut.allWorkerLaunches,
      generations: workspaceGenerations }, preparationCleanup);
  } catch (error) { recoveryFailure(`worker preparation history is invalid: ${(error as Error).message}`, error); }
  phase('spec');
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
  await requireRecoveryArtifacts(artifacts, [
    ['Run.specRef', run.specRef],
    ['Run.frontierRef', run.frontierRef],
    ['Run.waitingOnRef', run.waitingOnRef],
    ['Run.resultRef', run.resultRef],
    ['Run.terminalDetailRef', run.terminalDetailRef],
    ['Run.stopIntentRef', run.stopIntentRef]
  ]);
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
  await requireRecoveryArtifacts(artifacts, [
    ['Checkpoint.contextManifestRef', latestCheckpoint.contextManifestRef],
    ['Checkpoint.workspaceStateRef', latestCheckpoint.workspaceStateRef]
  ]);
  requireRecoveryTime(latestCheckpoint.createdAt, 'Checkpoint.createdAt');
  if (latestCheckpoint.runId !== run.id || latestCheckpoint.basedOnRunRevision >= run.revision) {
    recoveryFailure('latest Checkpoint is not a prior cut of the Run');
  }
  if (run.revision === 1 && latestCheckpoint.basedOnRunRevision !== 0) {
    recoveryFailure('initial Checkpoint must be based on virtual revision 0');
  }

  const runSpec = decodeRunSpec(await artifacts.readCanonical(run.specRef));
  if (runSpec.operation === 'delivery') assertDeliveryModelFreeCut({ run, runSpec, journal, childAllocations });
  const frozenSource = await validateRunSpecArtifacts(artifacts, runSpec);
  const assemblyData = await artifacts.readCanonical<RunAssemblyV1>(runSpec.assemblyRef);
  if (assemblyData?.format === 'cliq-run-assembly-v1' && assemblyData.instructions?.skills?.length) {
    try {
      await readAssemblySkills(artifacts, decodeRetainedRunAssembly(assemblyData), {
        workspaceIdentityRef: databaseCut.workspaceIdentityRef, ownerPrincipalId: databaseCut.principalId
      });
    } catch (error) { recoveryFailure('Run skill closure is not its complete original immutable source', error); }
  }
  phase('context');
  const context = decodeContextManifest(await artifacts.readCanonical(latestCheckpoint.contextManifestRef));
  if (context.runId !== run.id || context.throughItemSeq !== latestCheckpoint.runItemSeq) {
    recoveryFailure('Checkpoint ContextManifest does not match its Run cut');
  }
  await validateContextArtifacts(artifacts, context, runSpec);
  const latestWorkspace = await validateWorkspaceStateArtifacts(
    artifacts,
    latestCheckpoint.workspaceStateRef,
    'Checkpoint.workspaceStateRef', frozenSource
  );
  if (
    latestWorkspace.state.runId !== run.id ||
    latestWorkspace.state.baseWorkspaceManifestRef !== runSpec.baseWorkspaceManifestRef
  ) recoveryFailure('workspace state is not bound to the admitted RunSpec');

  phase('journal');
  if (latestCheckpoint.runItemSeq > items.length) recoveryFailure('Checkpoint item cursor exceeds recovery items');
  if (latestCheckpoint.journalSeq > journal.length) recoveryFailure('Checkpoint Journal cursor exceeds recovery Journal');
  await requireRecoveryArtifacts(
    artifacts,
    items.map((item, index) => [`Run.items[${index}].payloadRef`, item.payloadRef] as const)
  );
  const groups = validateJournalGraph(journal);
  const journalBudgets = await validateJournalArtifactsAndBudgets(artifacts, groups);
  phase('generations');
  const generationProofs: WorkspaceGenerationStateV1[] = [];
  if (workspaceGenerations.some(generation => generation.phase === 'retired')) {
    try {
      const assembly = await artifacts.readCanonical<RunAssemblyV1>(runSpec.assemblyRef);
      if (assembly.format !== 'cliq-run-assembly-v1') throw new TypeError('generation retirement requires its typed historical runtime');
      for (const generation of workspaceGenerations) generationProofs.push(generation.phase === 'retired'
        ? (await readRetiredGenerationSource(driver, artifacts, { run, spec: runSpec, assembly, generation })).source : generation);
    } catch (error) { recoveryFailure(`generation retirement history is invalid: ${(error as Error).message}`, error); }
  } else generationProofs.push(...workspaceGenerations);
  await validateGenerationArtifacts(artifacts, generationProofs, frozenSource);
  const closure: RecoveryClosureV1 = { runSpec, run, latestCheckpoint, items, journal, workerLaunches, workspaceGenerations, childAllocations };
  const delivery = runSpec.operation === 'delivery' ? createDeliveryReadData(driver, artifacts, closure) : undefined;
  phase('history');
  if (journal.some((entry) => entry.opKind === 'model' || entry.opKind === 'verifier') || run.repairCount !== 0 ||
      runSpec.operation === 'agent' && items.length > 0 || runSpec.operation === 'delivery') {
    try {
      const input = { driver, artifacts, run, spec: runSpec, items, journal,
        principalId: databaseCut.principalId, workspaceIdentityRef: databaseCut.workspaceIdentityRef,
        checkpoints: databaseCut.checkpoints, workspaceGenerations: generationProofs,
        context: decodeContextManifest(await artifacts.readCanonical(latestCheckpoint.contextManifestRef)) };
      const history = delivery
        ? await validateAgentRecoveryInDeliveryEpoch(input, delivery, value => phase(`history_${value}`))
        : await validateAgentRecovery(input, value => phase(`history_${value}`));
      journalBudgets.consumed = addBudget(journalBudgets.consumed,
        { ...ZERO_BUDGET, repairAttempts: history.repairAttempts }, 'recovery authorized repair budget');
      const assembly = await artifacts.readCanonical<RunAssemblyV1>(runSpec.assemblyRef);
      if (assembly.format === 'cliq-run-assembly-v1') {
        phase('history_broker');
        await validateInstalledBrokerAmbiguityHistory({ driver, artifacts,
          run, spec: runSpec, assembly, journal, childAllocations, principalId: databaseCut.principalId });
      }
    } catch (error) {
      recoveryFailure(`typed agent recovery closure is invalid: ${(error as Error).message}`, error);
    }
  }
  const childBudgets = childAllocationBudgetFacts(run.id, childAllocations);
  if (!budgetEqual(addBudget(journalBudgets.reserved, childBudgets.reserved), run.budgetReserved) ||
      !budgetEqual(addBudget(journalBudgets.consumed, childBudgets.consumed), run.budgetConsumed))
    recoveryFailure('Run budget counters do not equal their complete own-Journal and direct inclusive child closure');
  if (run.status !== 'running' && !isZeroBudget(run.budgetReserved) && journal.length === 0) {
    recoveryFailure('lease-free Run has an unexplained budget reservation');
  }
  phase('seals');
  const sealedGenerations = generationProofs.filter(generation => generation.phase === 'sealed');
  const sealedLaunches = databaseCut.allWorkerLaunches.filter(launch => launch.phase === 'retired' && launch.generationWriteState === 'sealed');
  if (sealedGenerations.length || sealedLaunches.length) {
    const assembly = await artifacts.readCanonical<RunAssemblyV1>(runSpec.assemblyRef);
    if (assembly.format === 'cliq-run-assembly-v1') {
      try {
        for (const generation of sealedGenerations) {
          const matches = sealedLaunches.filter(launch => launch.workspaceGenerationRef === generation.generationRef);
          if (matches.length !== 1 || !matches[0]!.activatedAt) throw new TypeError('sealed generation has no unique retired activated worker');
          await validateRetainedWorkerSeal(driver, artifacts, { run, spec: runSpec, assembly, launch: matches[0]!, generation });
        }
        if (sealedLaunches.some(launch => !sealedGenerations.some(generation => generation.generationRef === launch.workspaceGenerationRef))) {
          throw new TypeError('retired sealed worker has no matching sealed generation');
        }
      } catch (error) {
        recoveryFailure(`worker seal history is invalid: ${(error as Error).message}`, error);
      }
    }
  }
  await validateLaunchGraph(artifacts, run, workerLaunches, workspaceGenerations);
  try { await validateWorkerRecoveryWait(artifacts, { ...databaseCut, workspaceGenerations: generationProofs }, driver); }
  catch (error) { recoveryFailure(`worker recovery closure is invalid: ${(error as Error).message}`, error); }
  await validateChildAllocationArtifacts(driver, artifacts, childAllocations, run);

  phase('terminal');
  let publicationPrefix: PublicationPrefix | undefined;
  try {
    if (runSpec.operation === 'delivery') {
      // Use the complete actual cut, not a filled-in verifier/agent subset.
      // Reverse coverage requires the unique policy + delivery decision and
      // their original wait/control/Checkpoint graph even if a later stop
      // outranks the decision. No pure decoder result grants publication.
      publicationPrefix = await delivery!.prefix();
    }
    await validateInstalledModelNoReleaseHistory(driver, artifacts, closure);
    if (delivery) await validateStopRecoveryInDeliveryEpoch(driver, artifacts, closure, delivery);
    else await validateStopRecovery(driver, artifacts, closure);
    if (delivery) await validateRunResultRecoveryInDeliveryEpoch(driver, artifacts, closure, delivery);
    else await validateRunResultRecovery(driver, artifacts, closure);
    if (delivery) await delivery.prefix();
  }
  catch (error) { recoveryFailure(`stop recovery closure is invalid: ${(error as Error).message}`, error); }
  return { cut: closure, ...(publicationPrefix ? { prefix: publicationPrefix } : {}) };
}
