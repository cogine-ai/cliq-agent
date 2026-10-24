import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { decodeDeliveryCaptureTopology, decodeDeliveryTerminalProjectionEvidence, decodePublicationPathProgressItem, decodePublicationPathResultItem, decodePublicationProof,
  publicationDirectoryIdentityDigest, publicationLocationKey, type DeliveryTerminalProjectionEvidence,
  type DeliveryCaptureTopologyV1, type PublicationPathObservationV1, type PublicationPathState, type PublicationProofV1,
  type PublicationReconciliationAssociation, type PublicationPathRetirementV1, type PublicationTransientEnvelopeRetirementV1 } from '../kernel/publication.js';
import type { BudgetSettlementV1, ContinuationItem, InvocationJournalEntry, RecoveryClosureV1, Run, RunFrontier, WorkspaceEntry } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { captureFrozenSourceProjection, MAX_SOURCE_PROJECTION_ENTRIES } from '../workspace/source-projection.js';
import { readCanonicalArtifact, readText } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { planContinuationCommit } from './continuation-commit.js';
import { decodeBudgetSettlement, decodeContextManifest, decodeSourceManifest, decodeWorkspaceEntries } from './decoders.js';
import { deliveryPublicationCheckpointId, deliveryPublicationTerminalCheckpointId, publicationEnvelopeLocations, publicationReceivedHandoffItemId, publicationResultItemId, readOwnedPublicationProof,
  readPublicationPrefix, readPublicationPathRetirement } from './delivery-publication-progress.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath, type HeldWorkspaceCursor, type HeldWorkspaceEntry,
  type HeldWorkspaceRoot } from './native-owner.js';
import { assertOwnedPublicationArtifacts, readOwnedPublicationCompletion, type PublicationInvocationOwner } from './publication-invocation.js';
import type { OwnedPublicationReconciliationResult } from './publication-invocation.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { readCheckpoint, readRun, readSession, readSessionPrincipalId, ZERO_BUDGET } from './rows.js';
import { assertDeliveryPublicationMaintenanceExecution, assertDeliveryPublicationReceivedExecution, readOwnedPublicationExecutionResources,
  type DeliveryPublicationMaintenanceTask, type DeliveryPublicationReceivedTask } from './run-execution.js';
import { loadRunResult, readOwnedPublicationResultPlan, type OwnedPublicationResultPlan } from './run-result.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { prepareToolCheckpoint } from './tool-checkpoint.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import { readSupervisorInspector, supervisorInspectorIdentity } from './supervisor-inspector.js';

const brand: unique symbol = Symbol('OwnedPublicationFinalization');
export type OwnedPublicationFinalization = Readonly<{ readonly [brand]: true }>;
type Completion = ReturnType<typeof readOwnedPublicationCompletion>;
type Prefix = Awaited<ReturnType<typeof readPublicationPrefix>>;
type Resources = Awaited<ReturnType<typeof readOwnedPublicationExecutionResources>>;
type Gate = Awaited<ReturnType<typeof openPublicationProjectionGate>>;
type Receipt = Extract<PublicationProofV1, { kind: 'terminal_receipt' }>;
type Binding = {
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; execution: unknown;
  receivedResult: OwnedPublicationReceivedResult; completion: ReceivedMaterial; settlement: BudgetSettlementV1;
  resolvedUnknown?: InvocationJournalEntry;
  cut: RecoveryClosureV1; prefix: Prefix; resources: ReceivedBinding['resources']; gate: Gate;
  graph: Awaited<ReturnType<ReturnType<typeof planContinuationCommit>['publish']>>;
  item: ReturnType<typeof decodePublicationPathResultItem>; evidence: DeliveryTerminalProjectionEvidence; evidenceRef: string;
  summaryDigest: string; metadata: PublishedArtifact[]; result?: OwnedPublicationResultPlan;
  sql: ReturnType<typeof sqlCut>; sqlDigest: string; closed: boolean; retirementFailure?: ResourceRetirementError;
  installed?: { sql: ReturnType<typeof sqlCut>; journal: InvocationJournalEntry; committedAt: string };
};
const finalizations = new WeakMap<object, Binding>();
const resourceFailures = new WeakMap<object, ResourceRetirementError>();
const seals = new WeakMap<Resources['retire'], { driver: SqliteDriver; owner: StateOwnerContext; execution: unknown;
  runId: string; planRef: string; retired: Awaited<ReturnType<Resources['retire']>>; seal: Awaited<ReturnType<typeof prepareToolCheckpoint>> }>();
const sessionConflicts = new WeakMap<object, { driver: SqliteDriver; owner: StateOwnerContext; receivedResult: OwnedPublicationReceivedResult }>();
type HandoffItem = Extract<ContinuationItem, { kind: 'publication_path_progress'; state: 'received_handoff' }>;
type HandoffBinding = {
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; execution: unknown; publicationOwner: PublicationInvocationOwner;
  prepared: Awaited<ReturnType<typeof prepareOwnedPublicationGenerationSeal>>; completion: Completion;
  item: HandoffItem; graph: ReturnType<typeof planContinuationCommit>; committed: boolean; pending?: Promise<Run>;
};
const handoffs = new WeakMap<object, HandoffBinding>();
type ReconciledMaterial = Extract<Awaited<ReturnType<typeof import('./publication-invocation.js')['readOwnedPublicationReconciliationResult']>>,
  { disposition: 'received' }>;
type ReconciledHandoffBinding = {
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; execution: unknown;
  material: ReconciledMaterial; item: HandoffItem; graph: ReturnType<typeof planContinuationCommit>;
  committed: boolean; pending?: Promise<Run>;
};
const reconciledHandoffs = new WeakMap<object, ReconciledHandoffBinding>();
const receivedBrand: unique symbol = Symbol('OwnedPublicationReceivedResult');
export type OwnedPublicationReceivedResult = Readonly<{ readonly [receivedBrand]: true }>;
type ReceivedBinding = {
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; execution: unknown;
  task: DeliveryPublicationReceivedTask; resources: ReturnType<typeof assertDeliveryPublicationReceivedExecution>;
  cut: RecoveryClosureV1; prefix: Prefix; entry: NonNullable<ReturnType<Prefix['entries']['get']>>;
  receipt: Receipt; exposed?: { cut: RecoveryClosureV1; entry: ReceivedEntryData; completion: ReceivedMaterial };
};
const receivedResults = new WeakMap<object, ReceivedBinding>();
type ReceivedEntryData = Pick<ReceivedBinding['entry'], 'sequence' | 'operation' | 'planRef' | 'prepared' | 'claim' | 'birth' |
  'progress' | 'receivedHandoff' | 'result' | 'history'>;
type ReceivedMaterial = {
  run: Run; prepared: InvocationJournalEntry; claim: InvocationJournalEntry;
  plan: ReceivedBinding['entry']['plan']; planRef: string; operation: ReceivedBinding['entry']['operation'];
  birth: NonNullable<ReceivedBinding['entry']['birth']>; evidence: Receipt; evidenceRef: string; receiptRef: string;
  retirement: PublicationPathRetirementV1;
} & PublicationReconciliationAssociation;
const compare = (left: string, right: string) => Buffer.compare(Buffer.from(left), Buffer.from(right));
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }

/** Pure last-forward accounting association only (one tool-call charge, not
 * the zero-budget abort branch). The production caller first reads the
 * complete owning prefix and the original CAS object; this cannot mint a
 * claim, result, settlement, refund or new terminal permission. */
export function assertPublicationUnknownSettlementAssociation(prepared: InvocationJournalEntry, claim: InvocationJournalEntry,
  unknown: InvocationJournalEntry, input: BudgetSettlementV1): void {
  const settlement = decodeBudgetSettlement(input);
  if (prepared.opKind !== 'publish' || prepared.phase !== 'prepared' || claim.phase !== 'dispatch_claimed' || unknown.phase !== 'unknown' ||
      prepared.attempt !== 0 || prepared.seq >= claim.seq || claim.seq >= unknown.seq || !claim.dispatchId ||
      !unknown.budgetSettlementRef || canonicalSha256(settlement) !== unknown.budgetSettlementRef ||
      settlement.runId !== prepared.runId || settlement.opId !== prepared.opId || settlement.attempt !== prepared.attempt ||
      settlement.preparedJournalSeq !== prepared.seq || settlement.terminalJournalSeq !== unknown.seq ||
      settlement.terminalPhase !== 'unknown' || settlement.settledAt !== unknown.timestamp)
    invalid('publication reconciliation substituted its original UNKNOWN settlement');
  for (const field of ['runId', 'opId', 'opKind', 'attempt', 'leaseEpoch', 'target', 'requestRef', 'grantRef', 'replayClass'] as const)
    if (prepared[field] !== claim[field] || claim[field] !== unknown[field])
      invalid('publication reconciliation changed its original permanent producer');
  for (const field of ['dispatchId', 'supervisorInstanceId', 'stateOwnerEpoch'] as const)
    if (claim[field] !== unknown[field]) invalid('publication reconciliation changed its original permanent claim');
  requireEqual(settlement.reserved, prepared.budgetDelta, 'publication original UNKNOWN reservation');
  requireEqual(settlement.released, prepared.budgetDelta, 'publication original UNKNOWN released reservation');
  requireEqual(settlement.consumed, { ...ZERO_BUDGET, toolCalls: 1 }, 'publication original full UNKNOWN charge');
  requireEqual(unknown.budgetDelta, settlement.consumed, 'publication original UNKNOWN accounted Journal delta');
}

/** Actual original producer only. This roots its known result and real M seal,
 * never a Journal terminal, PathResult, charge, release or advanced frontier. */
export async function handoffOwnedPublicationResult(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, publicationOwner: PublicationInvocationOwner): Promise<Run> {
  assertOwnedPublicationArtifacts(driver, owner, execution, publicationOwner, artifacts);
  assertActiveStateOwner(driver, owner);
  let held = handoffs.get(publicationOwner);
  if (held && (held.driver !== driver || held.artifacts !== artifacts || held.owner !== owner || held.execution !== execution))
    throw new TypeError('received handoff cannot transfer its original producer');
  if (held?.committed) return readRun(driver, held.item.runId);
  if (held?.pending) return held.pending;
  if (!held) {
    const completion = readOwnedPublicationCompletion(driver, owner, execution, publicationOwner, driver);
    if (completion.disposition !== 'received' || !completion.isLastForwardPath || !completion.progressCommitted || !completion.birth ||
        completion.evidence.kind !== 'terminal_receipt' || completion.receiptRef !== completion.evidenceRef || !completion.arenaRetirementRef)
      invalid('received handoff requires its genuine last receipt and complete original retirement');
    const prepared = await prepareOwnedPublicationGenerationSeal(driver, artifacts, owner, execution, publicationOwner);
    const { cut, prefix, retired } = prepared, entry = prefix.forward.at(-1);
    if (!entry?.claim || entry.result || entry.receivedHandoff || !entry.progress || entry.prepared.opId !== completion.prepared.opId ||
        prefix.forward.length !== completion.plan.forwardOperations.length || prefix.abortResults.length ||
        prefix.forward.slice(0, -1).some(value => value.result?.item.outcome !== 'completed') ||
        cut.run.status !== 'running' || cut.run.nextStep !== 'delivery' || !cut.run.activeWorkerLaunchId)
      invalid('received handoff is not its exact original pending last forward prefix');
    requireEqual(entry.claim, completion.claim, 'received handoff original permanent claim');
    requireEqual(entry.birth, completion.birth, 'received handoff original native birth');
    const item = decodePublicationPathProgressItem({ schemaVersion: 1, kind: 'publication_path_progress',
      itemId: publicationReceivedHandoffItemId(cut.run.id, completion.prepared.opId), runId: cut.run.id,
      deliveryPlanRef: completion.planRef, operationIndex: completion.operation.index, operationId: completion.operation.operationId,
      opId: completion.prepared.opId, attempt: 0, state: 'received_handoff', sequence: 'forward', dispatchId: completion.claim.dispatchId,
      claimJournalSeq: completion.claim.seq, receiptRef: completion.receiptRef, receiptDigest: completion.evidence.proofDigest,
      retirement: { slotObservationRefs: [...completion.slotObservationRefs], arenaRetirementRef: completion.arenaRetirementRef },
      generationResources: { kind: 'sealed', workerLaunchId: cut.run.activeWorkerLaunchId, generationRef: retired.snapshot.generationRef,
        snapshotEvidenceRef: retired.postEffect.snapshotEvidenceRef }, createdAt: sampleCanonicalNow() });
    if (item.state !== 'received_handoff') invalid('received handoff selected a cleanup progress branch');
    const context = decodeContextManifest(await readCanonicalArtifact(artifacts, cut.latestCheckpoint.contextManifestRef)), existingItems = [];
    for (const row of cut.items) existingItems.push({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
      item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) });
    const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, cut.run.frontierRef!);
    const graph = planContinuationCommit(artifacts, { context, existingItems, items: [item], frontier,
      checkpointId: deliveryPublicationCheckpointId(cut.run.id, completion.planRef), workspaceStateRef: cut.latestCheckpoint.workspaceStateRef });
    held = { driver, artifacts, owner, execution, publicationOwner, completion, prepared, item, graph, committed: false };
    handoffs.set(publicationOwner, held);
  }
  const binding = held;
  const work = (async () => {
    const graph = await binding.graph.publish();
    for (let attempt = 0; attempt < 8; attempt++) {
      const cut = await readRecoveryClosure(driver, artifacts, binding.item.runId), prefix = await readPublicationPrefix(driver, artifacts, cut);
      const entry = prefix.entries.get(binding.item.opId);
      if (entry?.receivedHandoff) {
        requireEqual(entry.receivedHandoff.item, binding.item, 'same original received handoff after committed SQL');
        binding.committed = true; return cut.run;
      }
      if (!entry?.claim || entry.result || cut.run.status !== 'running' || cut.run.nextStep !== 'delivery' ||
          binding.item.generationResources.kind !== 'sealed' ||
          cut.run.activeWorkerLaunchId !== binding.item.generationResources.workerLaunchId ||
          cut.latestCheckpoint.id !== binding.prepared.cut.latestCheckpoint.id)
        invalid('received handoff lost its original pending worker or continuation');
      requireEqual(entry.claim, binding.completion.claim, 'received handoff current original claim');
      requireEqual(cut.latestCheckpoint, binding.prepared.cut.latestCheckpoint, 'received handoff original accounted M Checkpoint');
      const snapshot = canonicalSha256(sqlCut(driver, cut.run.id, prefix.admission.source.run.id));
      await binding.prepared.seal.refresh();
      let outcome: TimeFenceAdvance | undefined, updated: Run | undefined;
      try {
        driver.transaction(connection => {
          assertActiveStateOwner(connection, owner);
          if (canonicalSha256(sqlCut(connection, cut.run.id, prefix.admission.source.run.id)) !== snapshot)
            throw new KernelStorageError('REVISION_CONFLICT', 'received handoff current Stop or owning SQL cut changed');
          const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
          if (outcome !== 'healthy') return;
          if (now < binding.item.createdAt || now < cut.run.updatedAt)
            invalid('received handoff has a noncausal commit time');
          const actual = readOwnedPublicationCompletion(driver, owner, execution, publicationOwner, connection);
          if (actual.disposition !== 'received' || actual.evidenceRef !== binding.item.receiptRef)
            invalid('received handoff lost its genuine original joined producer before commit');
          requireEqual(actual.evidence, binding.completion.evidence, 'received handoff original actual receipt at SQL cut');
          requireEqual({ slotObservationRefs: actual.slotObservationRefs, arenaRetirementRef: actual.arenaRetirementRef }, binding.item.retirement,
            'received handoff original actual descriptor retirement at SQL cut');
          for (const artifact of [...binding.completion.metadata, ...binding.prepared.seal.metadata, ...graph.metadata])
            insertArtifactMetadata(connection, artifact, now);
          binding.prepared.seal.commit(connection, cut.run, now);
          graph.commit(connection, cut.run, binding.item.claimJournalSeq, now);
          connection.prepare('UPDATE runs SET revision=revision+1, updated_at=? WHERE id=? AND revision=?')
            .run(now, cut.run.id, BigInt(cut.run.revision));
          updated = readRun(connection, cut.run.id);
          appendRunStateEvent(connection, updated, now);
        });
      } catch (error) {
        if (error instanceof KernelStorageError && error.code === 'REVISION_CONFLICT') continue;
        throw error;
      }
      requireHealthyFence(outcome);
      if (!updated) invalid('received handoff did not commit under its original time fence');
      binding.committed = true; return updated;
    }
    throw new KernelStorageError('REVISION_CONFLICT', 'received handoff current Stop cut kept changing');
  })();
  binding.pending = work;
  try { return await work; } finally { if (binding.pending === work) binding.pending = undefined; }
}

/** The genuine inspection result retains its fully validated pre-I/O graph.
 * This authority-reducing write does not re-read an unbounded history after
 * learning a real result, cancel that result, reseal M, or settle its charge. */
export async function handoffOwnedReconciledPublicationResult(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, result: OwnedPublicationReconciliationResult): Promise<Run> {
  const { readOwnedPublicationReconciliationResult, assertOwnedPublicationReconciliationSql } = await import('./publication-invocation.js');
  // The native producer's WeakMap is checked before reading supplied data,
  // SQLite, CAS, or a property of the caller's purported token.
  const actual = await readOwnedPublicationReconciliationResult(driver, artifacts, owner, execution, result);
  if (actual.disposition !== 'received' || !actual.isLastForwardPath)
    invalid('received reconciliation handoff requires its genuine last completed inspection');
  let held = reconciledHandoffs.get(result);
  if (held && (held.driver !== driver || held.artifacts !== artifacts || held.owner !== owner || held.execution !== execution))
    throw new TypeError('reconciled handoff cannot transfer its actual original result');
  if (held?.committed) return readRun(driver, held.item.runId);
  if (held?.pending) return held.pending;
  if (!held) {
    const { cut, prefix, continuation, generationResources } = actual, entry = prefix.forward.at(-1);
    requireEqual(cut.run, actual.run, 'reconciled handoff original fully verified Run');
    if (!entry?.claim || !entry.birth || !entry.progress || !entry.result || entry.result.item.outcome !== 'unknown' || entry.receivedHandoff ||
        entry.prepared.opId !== actual.prepared.opId || prefix.forward.length !== actual.plan.forwardOperations.length || prefix.abortResults.length ||
        prefix.forward.slice(0, -1).some(value => value.result?.item.outcome !== 'completed') ||
        cut.run.status !== 'waiting' || cut.run.waitingReason !== 'reconciliation' || !cut.run.waitingOnRef || cut.run.nextStep !== 'delivery' ||
        cut.run.activeWorkerLaunchId || cut.workerLaunches.length ||
        cut.workspaceGenerations.some(value => value.phase !== 'retired' && value.phase !== 'sealed') ||
        actual.unknown.seq !== cut.journal.length || actual.unknown.phase !== 'unknown' ||
        actual.wrapper.outcome !== 'subject_observation' || actual.wrapper.subjectEvidenceKind !== 'publication' ||
        actual.wrapper.waitingSubjectRef !== cut.run.waitingOnRef || actual.wrapper.subjectEvidenceRef !== actual.receiptRef ||
        actual.wrapper.subjectEvidenceDigest !== actual.receipt.proofDigest || actual.wrapper.observedAt !== actual.receipt.observedAt ||
        canonicalSha256(actual.wrapper) !== actual.wrapperRef || canonicalSha256(actual.receipt) !== actual.receiptRef ||
        generationResources?.kind !== 'genuinely_retired_from_verified_checkpoint' ||
        !cut.workspaceGenerations.some(value => value.generationRef === generationResources.generationRef && value.phase === 'retired'))
      invalid('reconciled handoff lost its exact UNKNOWN, inspection or genuinely retired verified M');
    // The genuine producer validated this exact claimed M's full retirement
    // graph before inspection. Earlier verifier generations may legitimately
    // remain sealed; they are not this original publication generation.
    requireEqual(entry.prepared, actual.prepared, 'reconciled handoff original preparation');
    requireEqual(entry.claim, actual.claim, 'reconciled handoff original permanent claim');
    requireEqual(entry.birth, actual.birth, 'reconciled handoff original arena birth');
    requireEqual(entry.history, [actual.prepared, actual.claim, actual.unknown], 'reconciled handoff exact original UNKNOWN history');
    if (canonicalSha256(continuation.context) !== cut.latestCheckpoint.contextManifestRef ||
        canonicalSha256(continuation.frontier) !== cut.run.frontierRef || continuation.existingItems.length !== cut.items.length)
      invalid('reconciled handoff changed its fully read original continuation');
    for (let index = 0; index < cut.items.length; index++) {
      const row = cut.items[index]!, value = continuation.existingItems[index]!;
      if (row.itemSeq !== value.itemSeq || row.payloadRef !== value.itemRef || canonicalSha256(value.item) !== row.payloadRef)
        invalid('reconciled handoff substituted its complete original continuation item');
    }
    const item = decodePublicationPathProgressItem({ schemaVersion: 1, kind: 'publication_path_progress',
      itemId: publicationReceivedHandoffItemId(cut.run.id, actual.prepared.opId), runId: cut.run.id,
      deliveryPlanRef: actual.planRef, operationIndex: actual.operation.index, operationId: actual.operation.operationId,
      opId: actual.prepared.opId, attempt: 0, state: 'received_handoff', sequence: 'forward', dispatchId: actual.claim.dispatchId,
      claimJournalSeq: actual.claim.seq, receiptRef: actual.receiptRef, receiptDigest: actual.receipt.proofDigest,
      retirement: actual.retirement,
      generationResources, reconciliationEvidenceRef: actual.wrapperRef, reconciliationEvidenceDigest: actual.wrapper.evidenceDigest,
      createdAt: sampleCanonicalNow() });
    if (item.state !== 'received_handoff' || item.createdAt < actual.wrapper.observedAt)
      invalid('reconciled handoff predates its actual joined inspection');
    const graph = planContinuationCommit(artifacts, { ...continuation, existingItems: [...continuation.existingItems], items: [item],
      checkpointId: deliveryPublicationCheckpointId(cut.run.id, actual.planRef), workspaceStateRef: cut.latestCheckpoint.workspaceStateRef });
    held = { driver, artifacts, owner, execution, material: actual, item, graph, committed: false };
    reconciledHandoffs.set(result, held);
  }
  const binding = held;
  const work = (async () => {
    const graph = await binding.graph.publish();
    const current = await readOwnedPublicationReconciliationResult(driver, artifacts, owner, execution, result);
    if (current.disposition !== 'received') invalid('reconciled handoff lost its actual fixed received result');
    for (const field of ['prepared', 'claim', 'unknown', 'plan', 'planRef', 'operation', 'birth', 'receipt', 'receiptRef', 'wrapper',
      'wrapperRef', 'retirement', 'generationResources', 'continuation'] as const)
      requireEqual(current[field], binding.material[field], 'reconciled handoff original fixed known result');
    const cut = current.cut;
    let outcome: TimeFenceAdvance | undefined, updated: Run | undefined;
    driver.transaction(connection => {
      assertActiveStateOwner(connection, owner);
      assertOwnedPublicationReconciliationSql(driver, artifacts, owner, execution, result, connection);
      const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
      if (outcome !== 'healthy') return;
      if (now < binding.item.createdAt || now < cut.run.updatedAt || !cut.run.waitingOnRef ||
          cut.journal.length !== current.unknown.seq)
        invalid('reconciled handoff has a noncausal or substituted original wait cut');
      for (const artifact of [...current.metadata, ...graph.metadata]) insertArtifactMetadata(connection, artifact, now);
      assertOwnedPublicationReconciliationSql(driver, artifacts, owner, execution, result, connection);
      graph.commit(connection, cut.run, current.unknown.seq, now);
      const changed = connection.prepare(`UPDATE runs SET status='queued',waiting_reason=NULL,waiting_on_ref=NULL,
        revision=revision+1,updated_at=? WHERE id=? AND revision=? AND waiting_on_ref=?`)
        .run(now, cut.run.id, BigInt(cut.run.revision), cut.run.waitingOnRef);
      if (changed.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'reconciled handoff lost its original wait');
      const { waitingReason: _reason, waitingOnRef: _wait, ...unwaiting } = cut.run;
      updated = readRun(connection, cut.run.id);
      requireEqual(updated, { ...unwaiting, status: 'queued', latestCheckpointId: deliveryPublicationCheckpointId(cut.run.id, current.planRef),
        frontierRef: graph.runUpdate.frontierRef, nextStep: 'delivery', revision: cut.run.revision + 1, updatedAt: now },
      'reconciled handoff retains its exact original Journal, budget, Stop and publication frontier');
      appendRunStateEvent(connection, updated, now);
    });
    requireHealthyFence(outcome);
    if (!updated) invalid('reconciled handoff did not commit its original resource closure');
    binding.committed = true; return updated;
  })();
  binding.pending = work;
  try { return await work; } finally { if (binding.pending === work) binding.pending = undefined; }
}

/** No native owner is reconstructed. Only this execution's genuine read-only
 * task can consume the complete handoff and actual original M resource graph. */
export async function prepareOwnedPublicationReceivedResult(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, task: DeliveryPublicationReceivedTask): Promise<OwnedPublicationReceivedResult> {
  const resources = assertDeliveryPublicationReceivedExecution(driver, owner, execution, task, artifacts);
  const reads = artifacts.withReadSignal(resources.signal), cut = await readRecoveryClosure(driver, reads, resources.runId);
  const prefix = await readPublicationPrefix(driver, reads, cut), entry = prefix.forward.at(-1);
  if (cut.run.revision !== resources.expectedRunRevision || cut.run.status !== 'queued' || cut.run.nextStep !== 'delivery' ||
      cut.run.activeWorkerLaunchId || cut.workerLaunches.length || !entry?.receivedHandoff || !entry.pendingReceivedHandoff || !entry.claim || !entry.birth ||
      entry.operation.index !== entry.plan.forwardOperations.length - 1 || prefix.abortResults.length ||
      prefix.forward.slice(0, -1).some(value => value.result?.item.outcome !== 'completed'))
    invalid('received publication task requires its complete original pending handoff and retired M');
  const receipt = await readOwnedPublicationProof(driver, reads, prefix.admission, entry.planRef, entry.receivedHandoff.item.receiptRef, entry.claim);
  if (receipt.kind !== 'terminal_receipt' || receipt.proofDigest !== entry.receivedHandoff.item.receiptDigest)
    invalid('received publication task lost its exact original receipt');
  resources.signal.throwIfAborted(); assertActiveStateOwner(driver, owner);
  const token = Object.freeze({ [receivedBrand]: true as const });
  receivedResults.set(token, { driver, artifacts, owner, execution, task, resources, cut, prefix, entry, receipt });
  return token;
}

function originalReceived(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, token: OwnedPublicationReceivedResult, connection: SqliteConnection = driver) {
  const value = token !== null && typeof token === 'object' ? receivedResults.get(token) : undefined;
  if (!value || value.driver !== driver || value.artifacts !== artifacts || value.owner !== owner || value.execution !== execution)
    throw new TypeError('a genuine same-execution received publication result is required');
  const resources = assertDeliveryPublicationReceivedExecution(driver, owner, execution, value.task, artifacts, connection);
  if (resources.workspaceRoot !== value.resources.workspaceRoot || resources.controlledHome !== value.resources.controlledHome)
    invalid('received publication result lost its actual original read-only roots');
  resources.signal.throwIfAborted();
  return { value, resources };
}
function receivedMaterial(value: ReceivedBinding): ReceivedMaterial {
  const { entry } = value, item = entry.receivedHandoff!.item;
  const material = { run: value.cut.run, prepared: entry.prepared, claim: entry.claim!,
    plan: entry.plan, planRef: entry.planRef, operation: entry.operation, birth: entry.birth!,
    evidence: value.receipt, evidenceRef: item.receiptRef, receiptRef: item.receiptRef,
    retirement: item.retirement };
  if (!item.reconciliationEvidenceRef) return material;
  if (!item.reconciliationEvidenceDigest) invalid('received publication result lost its complete reconciliation association');
  return { ...material, reconciliationEvidenceRef: item.reconciliationEvidenceRef,
    reconciliationEvidenceDigest: item.reconciliationEvidenceDigest };
}
/** Read-only same-execution friend. Its data cannot arm, commit, reconcile or
 * clean an operation; the durable original claim is never reconstructed. */
export function readOwnedPublicationReceivedResult(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, token: OwnedPublicationReceivedResult, connection: SqliteConnection = driver) {
  const { value, resources } = originalReceived(driver, artifacts, owner, execution, token, connection);
  // The friend exposes copied readonly data, never the WeakMap's mutable
  // retained graph. The full source/prefix graph remains private; an adapter
  // still obtains its own complete fresh selection rather than copying it.
  const { sequence, operation, planRef, prepared, claim, birth, progress, receivedHandoff, result, history } = value.entry;
  value.exposed ??= immutableSnapshot({ cut: value.cut,
    entry: { sequence, operation, planRef, prepared, claim, birth, progress, receivedHandoff, result, history }, completion: receivedMaterial(value) });
  resources.signal.throwIfAborted();
  return { ...value.exposed, resources };
}

/** Same genuine execution's original M retirement, shared by forward success
 * and stopped publication. Only the native-owning factory supplies the cache
 * key; a caller callback or a retained CAS snapshot cannot mint this seal. */
export async function prepareOwnedPublicationGenerationSeal(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, publicationOwner: PublicationInvocationOwner, task?: DeliveryPublicationMaintenanceTask) {
  assertOwnedPublicationArtifacts(driver, owner, execution, publicationOwner, artifacts);
  const completion = readOwnedPublicationCompletion(driver, owner, execution, publicationOwner, driver);
  const before = readRun(driver, completion.run.id);
  if (!before.stopIntentRef && (completion.disposition !== 'received' || !completion.isLastForwardPath))
    invalid('publication M seal requires its genuine last completion or stopped original owner');
  const selectedResources = task === undefined ? await readOwnedPublicationExecutionResources(driver, owner, execution, publicationOwner)
    : assertDeliveryPublicationMaintenanceExecution(driver, owner, execution, task, artifacts);
  if (!selectedResources.retire || !selectedResources.publicationOwners.includes(publicationOwner))
    invalid('publication M seal lost its actual original stopped worker resources');
  const resources = { ...selectedResources, retire: selectedResources.retire };
  const retained = seals.get(resources.retire);
  if (retained && (retained.driver !== driver || retained.owner !== owner || retained.execution !== execution ||
      retained.runId !== completion.run.id || retained.planRef !== completion.planRef))
    throw new TypeError('publication cannot transfer its original M seal owner');
  const retired = retained?.retired ?? await resources.retire();
  const reads = artifacts.withReadSignal(resources.signal), cut = await readRecoveryClosure(driver, reads, completion.run.id);
  const prefix = await readPublicationPrefix(driver, reads, cut), authorization = prefix.authorization;
  if (!authorization || authorization.context.planRef !== completion.planRef ||
      retired.snapshot.checkpointId !== deliveryPublicationCheckpointId(cut.run.id, completion.planRef) ||
      retired.postEffect.workspaceStateRef !== cut.latestCheckpoint.workspaceStateRef ||
      retired.snapshot.workspaceStateRef !== authorization.verified.checkpoint.workspaceStateRef)
    invalid('publication changed its actual private M instead of sealing the original verified workspace');
  // Host abort maintenance can occur after the original M is already dead.
  // Bind its seal to that genuine retirement's quiescence, not a later host
  // receipt that would require the same dead worker to die a second time.
  if (cut.run.stopIntentRef && !retired.snapshot.quiescenceEvidenceRef) invalid('publication M retirement lost its original quiescence');
  const observedAt = cut.run.stopIntentRef
    ? (await readCanonicalArtifact<{ observedAt: string }>(reads, retired.snapshot.quiescenceEvidenceRef!)).observedAt
    : completion.evidence.observedAt;
  const seal = retained?.seal ?? await prepareToolCheckpoint(driver, reads, owner, { run: cut.run, spec: cut.runSpec,
    assembly: prefix.admission.source.assembly, checkpointId: deliveryPublicationCheckpointId(cut.run.id, completion.planRef),
    observedAt, postEffect: retired.postEffect }, resources.reobserveRetirement);
  if (!retained) seals.set(resources.retire, { driver, owner, execution, runId: cut.run.id, planRef: completion.planRef, retired, seal });
  return { resources, retired, seal, cut, prefix };
}

function original(driver: SqliteDriver, owner: StateOwnerContext, token: unknown, connection: SqliteConnection = driver): Binding {
  const value = token !== null && typeof token === 'object' ? finalizations.get(token) : undefined;
  if (!value || value.driver !== driver || value.owner !== owner)
    throw new TypeError('a genuine original publication finalization is required');
  if (value.retirementFailure) throw value.retirementFailure;
  if (value.closed) invalid('publication projection descriptors are already joined');
  originalReceived(driver, value.artifacts, owner, value.execution, value.receivedResult, connection);
  return value;
}
function sqlCut(connection: SqliteConnection, runId: string, sourceRunId: string) {
  const run = readRun(connection, runId), source = readRun(connection, sourceRunId);
  const sessionIdentity = (id: string) => { const session = readSession(connection, id); return { id: session.id,
    workspaceIdentityRef: session.workspaceIdentityRef, createdAt: session.createdAt,
    ...(session.parentSessionId === undefined ? {} : { parentSessionId: session.parentSessionId, forkedThroughItemSeq: session.forkedThroughItemSeq }) }; };
  return { run, source, session: sessionIdentity(run.sessionId), sourceSession: sessionIdentity(source.sessionId),
    principalId: readSessionPrincipalId(connection, run.sessionId), sourcePrincipalId: readSessionPrincipalId(connection, source.sessionId),
    checkpoint: readCheckpoint(connection, run.latestCheckpointId), journal: readInvocationJournal(connection, runId),
    items: connection.prepare('SELECT item_id,item_seq,kind,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
      .all<{ item_id: string; item_seq: bigint; kind: string; payload_ref: string; created_at: string }>(runId)
      .map(row => ({ ...row, item_seq: Number(row.item_seq) })),
    launches: readWorkerLaunchesForRun(connection, runId), generations: readWorkspaceGenerationsForRun(connection, runId),
    children: !!connection.prepare('SELECT 1 FROM child_allocations WHERE parent_run_id=? OR child_run_id=? LIMIT 1').get(runId, runId) ||
      !!connection.prepare('SELECT 1 FROM runs WHERE parent_run_id=? LIMIT 1').get(runId) };
}
// Actual rows only, not a future cut or permission. The two genuine terminal
// producers retain and compare this single complete field list.
export { sqlCut as readDeliveryTerminalSqlCut };
function closeGate(value: Binding) {
  if (value.closed) return;
  try { value.gate.close(); value.closed = true; }
  catch (cause) {
    const failure = cause instanceof ResourceRetirementError ? cause : new ResourceRetirementError('publication projection did not join', cause);
    resourceFailures.set(value.receivedResult, failure); throw value.retirementFailure = failure;
  }
}

type Node = { path: string; children: Map<string, Node>; parent?: Node; entry?: HeldWorkspaceEntry; cursor?: HeldWorkspaceCursor; childCount?: number };
/** Read-only FD lifetime, not execution/cleanup authority. The full frozen
 * capture still reads every projected byte, including newly born paths. */
export async function openPublicationProjectionGate(root: HeldWorkspaceRoot, entries: readonly WorkspaceEntry[], paths: readonly string[], signal: AbortSignal,
  maxEntries = MAX_SOURCE_PROJECTION_ENTRIES) {
  assertHeldWorkspaceRoot(root);
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > MAX_SOURCE_PROJECTION_ENTRIES)
    throw new TypeError('publication metadata entry limit is outside the fixed source capture bound');
  const tree: Node = { path: '', children: new Map() }, held: Array<{ close(): void }> = [];
  const allEntries: HeldWorkspaceEntry[] = [], cursors: HeldWorkspaceCursor[] = [];
  let closed = false, retirementFailure: ResourceRetirementError | undefined;
  function select(path: string) {
    let node = tree;
    for (const part of path.split('/')) {
      let next = node.children.get(part);
      if (!next) { next = { path: node.path ? `${node.path}/${part}` : part, parent: node, children: new Map() }; node.children.set(part, next); }
      node = next;
    }
    return node;
  }
  for (const entry of entries) select(entry.path);
  for (const path of paths) select(path);
  function close(operationError?: unknown) {
    if (retirementFailure) throw retirementFailure;
    if (closed) return;
    const failures: unknown[] = [];
    for (const resource of held.splice(0).reverse()) try { resource.close(); } catch (error) { failures.push(error); }
    if (failures.length) throw retirementFailure = new ResourceRetirementError('publication projection descriptors did not join',
      new AggregateError(operationError === undefined ? failures : [operationError, ...failures]));
    closed = true;
  }
  async function walk() {
    const stack: Node[] = [];
    function descend(node: Node, cursor: HeldWorkspaceCursor) {
      node.cursor = cursor; cursors.push(cursor); held.push(cursor); node.childCount = 0; stack.push(node);
    }
    descend(tree, root.openSnapshot());
    let inventoryCount = 0;
    while (stack.length) {
      signal.throwIfAborted();
      const node = stack[stack.length - 1]!, cursor = node.cursor!;
      const entry = cursor.next();
      if (!entry) { cursor.assertComplete(); stack.pop(); continue; }
      node.childCount!++;
      if (++inventoryCount > maxEntries) {
        try { entry.close(); } catch (cause) { throw new ResourceRetirementError('over-limit publication metadata did not join', cause); }
        invalid('publication metadata inventory exceeds the entry limit');
      }
      const child = node.children.get(entry.path.split('/').at(-1)!);
      if (!child) { try { entry.close(); } catch (cause) { throw new ResourceRetirementError('unselected publication metadata did not join', cause); } }
      else {
        child.entry = entry; allEntries.push(entry); held.push(entry);
        if (entry.path !== child.path) invalid('publication cursor changed its original root-relative path');
        if (entry.kind === 'directory') descend(child, entry.openDirectory());
      }
      if ((inventoryCount & 127) === 0) await new Promise<void>(resolve => setImmediate(resolve));
    }
  }
  try { await walk(); }
  catch (error) { close(error); throw error; }
  const desired = new Map(entries.map(entry => [entry.path, entry]));
  const assertHeld = () => {
    if (retirementFailure) throw retirementFailure;
    if (closed) invalid('publication projection descriptors are already joined');
    signal.throwIfAborted(); assertHeldWorkspaceRoot(root);
    for (const entry of allEntries) entry.assertHeld();
    for (const cursor of cursors) cursor.assertComplete();
  };
  function state(node: Node, workspaceIdentityDigest: string): PublicationPathState {
    const entry = node.entry;
    if (!entry) return { kind: 'absent' };
    const expected = desired.get(node.path);
    if (entry.kind === 'file') {
      if (expected?.kind !== 'file' || expected.size !== entry.byteCount || (entry.mode & 0o111 ? 0o755 : 0o644) !== expected.mode)
        invalid('publication actual file is outside its complete desired source');
      return { kind: 'file', mode: entry.mode, digest: expected.blobRef };
    }
    if (entry.kind === 'symlink') {
      const target = entry.readSymlink();
      if (expected?.kind !== 'symlink' || expected.target !== target || expected.targetDigest !== sha256Bytes(Buffer.from(target)))
        invalid('publication actual symlink is outside its complete desired source');
      return { kind: 'symlink', target, digest: expected.targetDigest };
    }
    if (entry.kind !== 'directory' || node.childCount === undefined) invalid('publication observed an unsupported actual destination');
    return { kind: 'directory', mode: entry.mode, empty: node.childCount === 0,
      identityDigest: publicationDirectoryIdentityDigest(workspaceIdentityDigest, { ...entry.identity, mode: entry.mode }) };
  }
  function observe(path: string, workspaceIdentityDigest: string): { observation: PublicationPathObservationV1; ancestorPath?: string } {
    if (retirementFailure) throw retirementFailure;
    if (closed) invalid('publication projection descriptors are already joined');
    let node = tree;
    for (const part of path.split('/')) {
      const child = node.children.get(part); if (!child) invalid('publication path was not part of its complete projection gate');
      if (node !== tree && node.entry?.kind !== 'directory') break;
      node = child;
    }
    const observed = state(node, workspaceIdentityDigest);
    const parent = node.parent!;
    const identity = parent === tree ? root.identity : parent.entry!.identity;
    const linkCount = parent === tree ? root.linkCount : parent.entry!.linkCount;
    const observation: PublicationPathObservationV1 = { location: { kind: 'workspace', path: node.path }, state: observed,
      parentDeviceId: identity.deviceId, parentFileId: identity.fileId, parentLinkCount: linkCount,
      ...(node.entry ? { entryDeviceId: node.entry.identity.deviceId, entryFileId: node.entry.identity.fileId, entryLinkCount: node.entry.linkCount } : {}) };
    return { observation, ...(node.path !== path ? { ancestorPath: node.path } : {}) };
  }
  function assertOriginalObservations(topology: DeliveryCaptureTopologyV1, observations: ReadonlyMap<string, PublicationPathObservationV1>, workspaceIdentityDigest: string) {
    assertHeld();
    const physical = (value: HeldWorkspaceRoot | HeldWorkspaceEntry) => ({ ...value.identity, mode: value.mode });
    const raw = (value: DeliveryCaptureTopologyV1['rootIdentity']) => ({ deviceId: value.deviceId, fileId: value.fileId,
      ownerUid: value.ownerUid, mode: value.mode });
    requireEqual(physical(root), raw(topology.rootIdentity), 'publication terminal original root identity and raw mode');
    const directories = new Map(topology.directories.map(value => [value.path, value]));
    for (const entry of allEntries) {
      if (entry.kind !== 'directory') continue;
      const after = observations.get(entry.path);
      if (after?.state.kind === 'directory') {
        // Later legitimate child operations change directory emptiness/link
        // count, never the inode/raw identity committed by its native receipt.
        if (entry.identity.deviceId !== after.entryDeviceId || entry.identity.fileId !== after.entryFileId ||
            entry.mode !== after.state.mode || publicationDirectoryIdentityDigest(workspaceIdentityDigest, physical(entry)) !== after.state.identityDigest)
          invalid('publication terminal directory differs from its original completed native result');
      } else {
        const captured = directories.get(entry.path);
        if (!captured) invalid('publication terminal directory has no original captured or native-created identity');
        requireEqual(physical(entry), raw(captured), 'publication terminal original captured directory identity');
      }
    }
    for (const [path, after] of observations) {
      const actual = observe(path, workspaceIdentityDigest);
      const state = actual.ancestorPath ? { kind: 'absent' as const } : actual.observation.state;
      if (state.kind !== after.state.kind) invalid('publication terminal path no longer has its original completed type');
      if (state.kind === 'absent') continue;
      if (actual.ancestorPath || actual.observation.entryDeviceId !== after.entryDeviceId ||
          actual.observation.entryFileId !== after.entryFileId)
        invalid('publication terminal path substituted its original completed inode');
      if (state.kind !== 'directory') {
        requireEqual(state, after.state, 'publication terminal original completed leaf state');
        if (actual.observation.entryLinkCount !== after.entryLinkCount)
          invalid('publication terminal leaf link count differs from its original native result');
      }
    }
  }
  function assertOriginalIdentities(topology: DeliveryCaptureTopologyV1, receipts: ReadonlyMap<string, Receipt>, workspaceIdentityDigest: string) {
    assertOriginalObservations(topology, new Map([...receipts].map(([path, receipt]) => [path, receipt.after])), workspaceIdentityDigest);
  }
  return { assertHeld, assertOriginalIdentities, assertOriginalObservations, observe, close };
}

async function originalTransients(driver: SqliteDriver, reads: ArtifactCatalog, prefix: Prefix, completion: ReceivedMaterial) {
  const slots: Array<{ key: string; location: ReturnType<typeof publicationEnvelopeLocations>[number]; ref: string }> = [];
  const arenaRetirements: Array<{ arenaId: string; ref: string }> = [];
  const envelopeRetirements: PublicationTransientEnvelopeRetirementV1[] = [];
  const transientLocations: ReturnType<typeof publicationEnvelopeLocations> = [];
  const receipts = new Map<string, Receipt>();
  let latestObservedAt = completion.evidence.observedAt;
  for (const entry of prefix.forward) {
    const retained = entry.result?.item.outcome === 'unknown' ? entry.receivedHandoff?.item : entry.result?.item ?? entry.receivedHandoff?.item;
    if (!entry.claim || !entry.birth || !retained || !('retirement' in retained) || !retained.retirement ||
        !('receiptRef' in retained) || !retained.receiptRef)
      invalid('publication complete path lost its durable original receipt and physical retirement');
    const receipt = await readOwnedPublicationProof(driver, reads, prefix.admission, completion.planRef, retained.receiptRef, entry.claim);
    if (receipt.kind !== 'terminal_receipt' || receipt.after.location.kind !== 'workspace' || receipt.after.location.path !== entry.operation.path)
      invalid('publication complete original path lost its exact native terminal receipt');
    receipts.set(entry.operation.path, receipt);
    if (receipt.observedAt > latestObservedAt) latestObservedAt = receipt.observedAt;
    const graph = await readPublicationPathRetirement(driver, reads, prefix.admission, entry, retained.retirement,
      retained.createdAt, retained.createdAt);
    if (graph.latestObservedAt > latestObservedAt) latestObservedAt = graph.latestObservedAt;
    envelopeRetirements.push({ arenaId: entry.birth.arenaId, retirement: retained.retirement });
    transientLocations.push(...publicationEnvelopeLocations(entry));
    if (graph.kind === 'current_namespace') {
      if (receipt.namespaceRetirementEvidenceRef !== graph.namespaceEvidence.ref)
        invalid('publication current namespace receipt substituted its original retirement');
      requireEqual(receipt.after, graph.destinationEvidence.proof.observation, 'publication fresh original-inode destination');
    } else {
      for (const { ref, proof } of graph.slotObservations) {
        const location = proof.observation.location;
        slots.push({ key: publicationLocationKey(location), location, ref });
      }
      arenaRetirements.push({ arenaId: entry.birth.arenaId, ref: graph.arenaRetirement.ref });
    }
  }
  slots.sort((a, b) => compare(a.key, b.key)); arenaRetirements.sort((a, b) => compare(a.arenaId, b.arenaId));
  envelopeRetirements.sort((a, b) => compare(a.arenaId, b.arenaId));
  transientLocations.sort((a, b) => compare(publicationLocationKey(a), publicationLocationKey(b)));
  return { slots, arenaRetirements, envelopeRetirements, transientLocations, receipts, latestObservedAt };
}

/** Same original owner, same fixed once-only settlement. No supplied proof,
 * desired refs, native callback or structural future RecoveryClosure is accepted. */
export async function prepareOwnedPublicationFinalization(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, receivedResult: OwnedPublicationReceivedResult, settlementInput: BudgetSettlementV1): Promise<OwnedPublicationFinalization> {
  const { value: received, resources } = originalReceived(driver, artifacts, owner, execution, receivedResult);
  const { cut, prefix } = received, completion = receivedMaterial(received);
  const failed = resourceFailures.get(receivedResult); if (failed) throw failed;
  const settlement = decodeBudgetSettlement(settlementInput);
  const reads = artifacts.withReadSignal(resources.signal);
  const current = prefix.entries.get(completion.prepared.opId), authorization = prefix.authorization;
  if (cut.run.stopIntentRef || cut.run.cancelRequested)
    throw new KernelStorageError('REVISION_CONFLICT', 'a genuine StopIntent won before publication finalization');
  if (!authorization || !current?.claim || !current.pendingReceivedHandoff || prefix.forward.at(-1) !== current || prefix.abort.length ||
      !current.receivedHandoff || cut.run.status !== 'queued' || cut.run.activeWorkerLaunchId ||
      cut.run.nextStep !== 'delivery' || cut.run.stopIntentRef || cut.run.cancelRequested ||
      prefix.forward.length !== completion.plan.forwardOperations.length ||
      prefix.forward.slice(0, -1).some(entry => entry.result?.item.outcome !== 'completed'))
    invalid('publication finalization requires its complete unstopped original forward prefix');
  requireEqual(current.prepared, completion.prepared, 'final publication original preparation');
  requireEqual(current.claim, completion.claim, 'final publication original permanent claim');
  requireEqual(current.birth, completion.birth, 'final publication original native birth');
  requireEqual(current.plan, completion.plan, 'final publication original complete Plan');
  const unknownRows = current.history.filter(entry => entry.phase === 'unknown'), resolvedUnknown = unknownRows[0];
  if (unknownRows.length > 1 || Boolean(resolvedUnknown) !== Boolean(completion.reconciliationEvidenceRef))
    invalid('publication finalization lost its exact original reconciliation accounting branch');
  if (resolvedUnknown) {
    if (current.history.length !== 3 || current.history[0]?.seq !== current.prepared.seq || current.history[1]?.seq !== current.claim.seq ||
        current.history[2]?.seq !== resolvedUnknown.seq || !resolvedUnknown.budgetSettlementRef)
      invalid('publication finalization has no original unresolved UNKNOWN accounting cut');
    const originalSettlement = decodeBudgetSettlement(await readCanonicalArtifact(reads, resolvedUnknown.budgetSettlementRef));
    requireEqual(settlement, originalSettlement, 'publication retained original UNKNOWN settlement bytes');
    assertPublicationUnknownSettlementAssociation(current.prepared, current.claim, resolvedUnknown, settlement);
  } else {
    if (settlement.runId !== completion.run.id || settlement.opId !== completion.prepared.opId || settlement.attempt !== 0 ||
        settlement.preparedJournalSeq !== completion.prepared.seq || settlement.terminalPhase !== 'completed' ||
        settlement.settledAt < completion.evidence.observedAt || settlement.terminalJournalSeq !== cut.journal.length + 1 ||
        canonicalSha256(cut.run.budgetReserved) !== canonicalSha256(settlement.budgetReservedBefore) ||
        canonicalSha256(cut.run.budgetConsumed) !== canonicalSha256(settlement.budgetConsumedBefore))
      invalid('publication finalization substituted its original settlement');
    requireEqual(settlement.consumed, { ...ZERO_BUDGET, toolCalls: 1 }, 'publication original once-only final charge');
    requireEqual(settlement.reserved, completion.prepared.budgetDelta, 'publication original reserved budget');
    requireEqual(settlement.released, completion.prepared.budgetDelta, 'publication original released reservation');
  }
  const resultCreatedAt = resolvedUnknown ? sampleCanonicalNow() : settlement.settledAt;
  if (resultCreatedAt < completion.evidence.observedAt || resultCreatedAt < current.receivedHandoff.item.createdAt)
    invalid('publication known-result item predates its real receipt or durable handoff');
  const originalSql = sqlCut(driver, cut.run.id, prefix.admission.source.run.id), sqlDigest = canonicalSha256(originalSql);
  const checkpointId = deliveryPublicationTerminalCheckpointId(cut.run.id, completion.planRef);
  if (cut.latestCheckpoint.id !== deliveryPublicationCheckpointId(cut.run.id, completion.planRef) ||
      cut.latestCheckpoint.workspaceStateRef !== authorization.verified.checkpoint.workspaceStateRef)
    invalid('publication lost its original already-sealed M resource Checkpoint');
  const desired = decodeSourceManifest(await readCanonicalArtifact(reads, completion.plan.desiredSourceRef));
  const entries = decodeWorkspaceEntries(await readCanonicalArtifact(reads, desired.entriesRef));
  // Expensive retained graph reads precede the fresh physical observation.
  // They still run in full; their immutable facts are not a metadata cache.
  const { slots, arenaRetirements, envelopeRetirements, transientLocations, receipts, latestObservedAt } = await originalTransients(driver, reads, prefix, completion);
  const topology = decodeDeliveryCaptureTopology(await readCanonicalArtifact(reads, completion.plan.captureTopologyRef));
  const context = decodeContextManifest(await readCanonicalArtifact(reads, cut.latestCheckpoint.contextManifestRef));
  const existingItems = [];
  for (const row of cut.items) existingItems.push({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
    item: await readCanonicalArtifact<ContinuationItem>(reads, row.payloadRef) });
  const summary = await readText(reads, authorization.verified.candidate.summaryRef);
  const stateOwner = assertActiveStateOwner(driver, owner), inspector = supervisorInspectorIdentity(stateOwner);
  const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  // Full immutable inspector/runtime closure before the fresh physical cut;
  // no hash is omitted and the original active owner is asserted again below.
  await readSupervisorInspector(reads, stateOwner, prefix.admission.source.assembly,
    { inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, observedAt: sampleCanonicalNow() });
  const gate = await openPublicationProjectionGate(resources.workspaceRoot, entries.entries, completion.plan.forwardOperations.map(value => value.path), resources.signal);
  let binding: Binding | undefined;
  try {
    requireEqual(resources.workspaceRoot.identity, authorization.workspace.rootIdentity, 'publication actual original root');
    if (heldWorkspaceRootPath(resources.workspaceRoot) !== authorization.workspace.canonicalRootPath)
      invalid('publication terminal capture changed its original workspace path');
    gate.assertOriginalIdentities(topology, receipts, completion.birth!.workspaceIdentityDigest);
    const profile = decodeSandboxProfile(await readCanonicalArtifact(reads, cut.runSpec.sandboxProfileRef));
    const captured = await captureFrozenSourceProjection({ workspaceRoot: resources.workspaceRoot, controlledHome: resources.controlledHome,
      stateOwnerLock: owner.filesystem, workspaceIdentityDigest: authorization.context.workspaceIdentityDigest, artifacts: reads,
      sourceProjectionRef: cut.runSpec.sourceProjectionRef, sourceProjectionDigest: desired.sourceProjectionDigest,
      maxEntries: MAX_SOURCE_PROJECTION_ENTRIES, maxBytes: profile.resources.maxGenerationBytes, maxSingleFileBytes: profile.resources.maxSingleFileBytes,
      signal: resources.signal });
    if (captured.resultWorkspaceManifestRef !== completion.plan.desiredSourceRef)
      invalid('publication fresh complete root projection differs from the verified desired source');
    gate.assertHeld();
    const metadata: PublishedArtifact[] = [inspectorArtifact, ...captured.metadata];
    const item = decodePublicationPathResultItem({ schemaVersion: 1, kind: 'publication_path_result',
      itemId: publicationResultItemId(cut.run.id, completion.prepared.opId, 0, completion.evidenceRef), runId: cut.run.id,
      deliveryPlanRef: completion.planRef, sequence: 'forward', operationIndex: completion.operation.index,
      operationId: completion.operation.operationId, opId: completion.prepared.opId, attempt: 0, outcome: 'completed',
      evidenceRef: completion.evidenceRef, receiptRef: completion.receiptRef,
      retirement: completion.retirement,
      ...(completion.reconciliationEvidenceRef ? { reconciliationEvidenceRef: completion.reconciliationEvidenceRef,
        reconciliationEvidenceDigest: completion.reconciliationEvidenceDigest } : {}), createdAt: resultCreatedAt });
    const itemRef = canonicalSha256(item), observedAt = sampleCanonicalNow();
    if (observedAt < latestObservedAt || observedAt < resultCreatedAt || observedAt < cut.latestCheckpoint.createdAt)
      invalid('publication terminal observation predates its actual original completion or M snapshot');
    const birth = completion.birth!;
    requireEqual(assertActiveStateOwner(driver, owner), stateOwner, 'publication current actual inspector at fresh physical cut');
    type Fields<T = PublicationProofV1> = T extends PublicationProofV1 ? Omit<T, 'schemaVersion' | 'format' | 'deliveryRunId' | 'deliveryPlanRef' |
      'workspaceIdentityRef' | 'workspaceIdentityDigest' | 'inspectorIdentityRef' | 'inspectorIdentityDigest' | 'proofDigest' | 'observedAt'> : never;
    const publish = async (fields: Fields) => {
      resources.signal.throwIfAborted(); assertHeldWorkspaceRoot(resources.workspaceRoot);
      const value = { schemaVersion: 1, format: 'cliq-publication-proof-v1', deliveryRunId: cut.run.id, deliveryPlanRef: completion.planRef,
        workspaceIdentityRef: birth.workspaceIdentityRef, workspaceIdentityDigest: birth.workspaceIdentityDigest,
        inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
        ...fields, observedAt, proofDigest: '' };
      value.proofDigest = digestOmitting(value, 'proofDigest'); decodePublicationProof(value);
      const artifact = await artifacts.publishCanonical(value, value.format); metadata.push(artifact); return artifact.ref;
    };
    const observedPathStates: DeliveryTerminalProjectionEvidence['observedPathStates'] = [];
    for (const path of completion.plan.forwardOperations.map(value => value.path).sort(compare)) {
      const actual = gate.observe(path, birth.workspaceIdentityDigest);
      const actualRef = await publish({ kind: 'path_observation', observation: actual.observation });
      const evidenceRef = actual.ancestorPath ? await publish({ kind: 'ancestor_projection_absence', path,
        ancestorPath: actual.ancestorPath, ancestorObservationRef: actualRef }) : actualRef;
      observedPathStates.push({ path, state: actual.ancestorPath ? { kind: 'absent' } : actual.observation.state, evidenceRef });
    }
    const forwardResultItemRefs = [...prefix.forward.slice(0, -1).map(entry => entry.result!.row.payloadRef), itemRef];
    const transientAbsenceEvidenceRef = await publish(envelopeRetirements.some(value => 'kind' in value.retirement)
      ? { kind: 'transient_absence', transientLocations, envelopeRetirements }
      : { kind: 'transient_absence', transientLocations, observationRefs: slots.map(value => value.ref),
        arenaRetirementRefs: arenaRetirements.map(value => value.ref) });
    const projectionClosureEvidenceRef = await publish({ kind: 'projection_closure', selectedBranch: 'forward_finalize',
      observedSourceRef: captured.resultWorkspaceManifestRef, observedPathEvidenceRefs: observedPathStates.map(value => value.evidenceRef),
      forwardResultItemRefs, unstartedForwardOperationIds: [], abortResultItemRefs: [] });
    const gitIndexUnchangedEvidenceRef = await publish({ kind: 'git_index_unchanged', repositoryKind: 'non_git' });
    const evidenceCore = { schemaVersion: 1 as const, deliveryRunId: cut.run.id,
      deliveryPlanRef: completion.planRef, selectedBranch: 'forward_finalize', observedSourceRef: captured.resultWorkspaceManifestRef,
      observedPathStates, forwardResultItemRefs, unstartedForwardOperationIds: [], abortResultItemRefs: [], transientAbsenceEvidenceRef,
      projectionClosureEvidenceRef, gitIndexUnchangedEvidenceRef, observedAt };
    const evidence = decodeDeliveryTerminalProjectionEvidence({ ...evidenceCore, evidenceDigest: canonicalSha256(evidenceCore) });
    const projection = await artifacts.publishCanonical(evidence, 'cliq-delivery-terminal-projection-evidence-v1'); metadata.push(projection);
    const frontier: RunFrontier = { schemaVersion: 1, kind: 'finalize', operation: 'delivery',
      candidateItemId: authorization.verified.candidate.itemId, resultSourceRef: authorization.verified.candidate.resultSourceRef,
      verificationClosureRef: authorization.frontier.verificationClosureRef, deliveryTerminalProjectionEvidenceRef: projection.ref };
    const graph = await planContinuationCommit(artifacts, { context, existingItems, items: [item], frontier,
      checkpointId, workspaceStateRef: cut.latestCheckpoint.workspaceStateRef }).publish();
    const token = Object.freeze({ [brand]: true as const });
    binding = { driver, artifacts, owner, execution, receivedResult, completion, settlement: immutableSnapshot(settlement), resolvedUnknown, cut, prefix,
      resources, gate, graph, item, evidence, evidenceRef: projection.ref, summaryDigest: summary.textDigest,
      metadata: [...metadata, ...graph.metadata], sql: originalSql, sqlDigest, closed: false };
    finalizations.set(token, binding);
    const result = loadRunResult(driver, artifacts, owner, { run: cut.run, spec: cut.runSpec,
      principalId: readSessionPrincipalId(driver, cut.run.sessionId) });
    binding.result = await result.prepareOwnedPublicationResult(execution, token);
    binding.metadata.push(...readOwnedPublicationResultPlan(driver, owner, binding.result).metadata);
    validateOwnedPublicationFinalization(driver, owner, token, driver, cut.run);
    return token;
  } catch (error) {
    if (binding) closeGate(binding);
    else try { gate.close(); } catch (cause) {
      const failed = cause instanceof ResourceRetirementError ? cause : new ResourceRetirementError('publication projection did not join', cause);
      resourceFailures.set(receivedResult, failed); throw failed;
    }
    throw error;
  }
}

/** Friend for the sole result writer, not a transferable result/candidate input. */
export function readOwnedPublicationTerminalMaterial(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, execution: unknown,
  token: OwnedPublicationFinalization) {
  const value = original(driver, owner, token);
  if (value.execution !== execution || value.artifacts !== artifacts) throw new TypeError('publication result changed its original owner or ArtifactCatalog');
  const verified = value.prefix.authorization!.verified;
  const verificationReceiptRefs = verified.closure.verification.kind === 'inherited_verified'
    ? [...verified.admission.source.result.verificationReceiptRefs]
    : verified.closure.verification.entries.flatMap(entry => 'receiptRef' in entry.disposition ? [entry.disposition.receiptRef] : []);
  return { run: value.cut.run, spec: value.cut.runSpec, principalId: readSessionPrincipalId(driver, value.cut.run.sessionId),
    candidate: verified.candidate, closure: verified.closure, verificationReceiptRefs, summaryDigest: value.summaryDigest,
    projection: value.evidence, signal: value.resources.signal, frontier: { schemaVersion: 1, kind: 'finalize', operation: 'delivery',
      candidateItemId: verified.candidate.itemId, resultSourceRef: verified.candidate.resultSourceRef,
      verificationClosureRef: value.prefix.authorization!.frontier.verificationClosureRef,
      deliveryTerminalProjectionEvidenceRef: value.evidenceRef } as const };
}

export function readOwnedPublicationFinalizationMetadata(driver: SqliteDriver, owner: StateOwnerContext, token: OwnedPublicationFinalization): readonly PublishedArtifact[] {
  return Object.freeze([...original(driver, owner, token).metadata]);
}
export function validateOwnedPublicationFinalization(driver: SqliteDriver, owner: StateOwnerContext, token: OwnedPublicationFinalization,
  connection: SqliteConnection, run: Run, committedAt?: string): void {
  const value = original(driver, owner, token, connection);
  assertActiveStateOwner(connection, owner); requireEqual(run, value.cut.run, 'publication finalization original Run');
  if (canonicalSha256(sqlCut(connection, run.id, value.prefix.admission.source.run.id)) !== value.sqlDigest)
    throw new KernelStorageError('REVISION_CONFLICT', 'publication finalization original Run, Stop, source or owned SQL cut changed');
  value.gate.assertHeld();
  if (value.result && !readOwnedPublicationResultPlan(driver, owner, value.result).sessionMatches(connection)) {
    const error = new KernelStorageError('REVISION_CONFLICT', 'publication result Session changed before its original atomic commit');
    sessionConflicts.set(error, { driver, owner, receivedResult: value.receivedResult });
    throw error;
  }
  if (committedAt && (committedAt < value.evidence.observedAt || committedAt >= run.deadlineAt ||
      parseCanonicalTime(committedAt) - parseCanonicalTime(value.evidence.observedAt) > 5000))
    invalid('publication terminal projection is outside its unchanged freshness or Run lifetime');
}

/** Only the registered invocation adapter calls this after appending its exact
 * original terminal Journal row in the same transaction. */
export function commitOwnedPublicationFinalization(driver: SqliteDriver, owner: StateOwnerContext, token: OwnedPublicationFinalization,
  connection: SqliteConnection, run: Run, journal: InvocationJournalEntry, committedAt: string): Run {
  const value = original(driver, owner, token, connection), { settlement, completion, cut, resolvedUnknown } = value;
  assertActiveStateOwner(connection, owner); requireEqual(run, cut.run, 'publication original preappend Run');
  requireEqual(readInvocationJournal(connection, run.id), [...cut.journal, journal], 'publication exact original Journal plus actual settlement row');
  const terminalSequence = resolvedUnknown ? cut.journal.length + 1 : settlement.terminalJournalSeq;
  const timestamp = resolvedUnknown ? committedAt : settlement.settledAt;
  if (journal.seq !== terminalSequence || journal.phase !== 'completed' || journal.receiptRef !== completion.receiptRef ||
      journal.evidenceRef !== completion.evidenceRef || journal.evidenceDigest !== completion.evidence.proofDigest ||
      journal.timestamp !== timestamp || timestamp < value.item.createdAt || journal.opId !== completion.prepared.opId || journal.attempt !== 0 ||
      journal.dispatchId !== completion.claim.dispatchId || journal.stateOwnerEpoch !== completion.claim.stateOwnerEpoch ||
      !journal.budgetSettlementRef || committedAt < value.evidence.observedAt || committedAt >= cut.run.deadlineAt ||
      parseCanonicalTime(committedAt) - parseCanonicalTime(value.evidence.observedAt) > 5000)
    invalid('publication terminal Journal differs from its original once-only native completion');
  requireEqual(journal, { ...completion.claim, seq: terminalSequence, phase: 'completed', budgetDelta: resolvedUnknown ? ZERO_BUDGET : settlement.consumed,
    budgetSettlementRef: canonicalSha256(settlement), timestamp, receiptRef: completion.receiptRef,
    evidenceRef: completion.evidenceRef, evidenceDigest: completion.evidence.proofDigest }, 'publication exact full original terminal Journal');
  value.gate.assertHeld();
  const settledRun = { ...cut.run, revision: cut.run.revision + 1,
    budgetReserved: resolvedUnknown ? cut.run.budgetReserved : settlement.budgetReservedAfter,
    budgetConsumed: resolvedUnknown ? cut.run.budgetConsumed : settlement.budgetConsumedAfter, updatedAt: committedAt };
  requireEqual(sqlCut(connection, run.id, value.prefix.admission.source.run.id), { ...value.sql, run: settledRun,
    journal: [...cut.journal, journal] }, 'publication full original SQL plus its sole actual settlement');
  value.graph.commit(connection, run, journal.seq, committedAt);
  const checkpoint = { id: deliveryPublicationTerminalCheckpointId(run.id, completion.planRef), schemaVersion: 1 as const, runId: run.id,
    basedOnRunRevision: cut.run.revision, runItemSeq: cut.items.length + 1, contextManifestRef: value.graph.metadata.find(artifact =>
      artifact.schemaKind === 'cliq-context-manifest-v1')!.ref, journalSeq: journal.seq, workspaceStateRef: cut.latestCheckpoint.workspaceStateRef,
    createdAt: committedAt, reason: 'auto' as const };
  const { activeWorkerLaunchId: _active, ...unpointed } = settledRun;
  const expected = { ...value.sql, run: { ...unpointed, status: 'queued' as const,
    latestCheckpointId: checkpoint.id, nextStep: 'finalize' as const, frontierRef: value.graph.runUpdate.frontierRef },
    checkpoint, journal: [...cut.journal, journal], items: [...value.sql.items, { item_id: value.item.itemId,
      item_seq: cut.items.length + 1, kind: value.item.kind, payload_ref: canonicalSha256(value.item), created_at: value.item.createdAt }] };
  const installedSql = sqlCut(connection, run.id, value.prefix.admission.source.run.id);
  requireEqual(installedSql, expected, 'publication exact actual seal, last item, context and finalize SQL graph');
  value.installed = { sql: installedSql, journal, committedAt };
  if (!value.result) invalid('publication terminal result preparation is incomplete');
  const result = readOwnedPublicationResultPlan(driver, owner, value.result).commit(connection, committedAt);
  closeGate(value);
  return result;
}

/** Synchronous SQL friend after the actual pubCP/finalize installation. No
 * future RecoveryClosure, async CAS read or caller callback is accepted. */
export function assertOwnedPublicationTerminalSql(driver: SqliteDriver, owner: StateOwnerContext, token: OwnedPublicationFinalization,
  connection: SqliteConnection, committedAt: string): void {
  const value = original(driver, owner, token, connection), installed = value.installed;
  if (!installed || installed.committedAt !== committedAt) invalid('publication result has no actual same-transaction finalize installation');
  requireEqual(sqlCut(connection, value.cut.run.id, value.prefix.admission.source.run.id), installed.sql,
    'publication complete actual installed finalize SQL cut');
  requireEqual(readInvocationJournal(connection, value.cut.run.id), [...value.cut.journal, installed.journal], 'publication actual complete settled Journal');
  const { run, checkpoint } = installed.sql;
  if (run.status !== 'queued' || run.nextStep !== 'finalize' || run.activeWorkerLaunchId ||
      run.stopIntentRef || run.cancelRequested || run.revision !== value.cut.run.revision + 1 ||
      checkpoint.id !== deliveryPublicationTerminalCheckpointId(run.id, value.completion.planRef) ||
      checkpoint.basedOnRunRevision !== value.cut.run.revision || checkpoint.createdAt !== committedAt ||
      checkpoint.runItemSeq !== value.cut.items.length + 1 || checkpoint.journalSeq !== installed.journal.seq ||
      checkpoint.workspaceStateRef !== value.cut.latestCheckpoint.workspaceStateRef || checkpoint.contextManifestRef !== value.graph.metadata.find(artifact =>
        artifact.schemaKind === 'cliq-context-manifest-v1')?.ref)
    invalid('publication result lost its exact actual same-transaction Checkpoint');
  value.gate.assertHeld();
  const actualNow = sampleCanonicalNow();
  if (actualNow < committedAt || actualNow >= value.cut.run.deadlineAt ||
      parseCanonicalTime(actualNow) - parseCanonicalTime(value.evidence.observedAt) > 5000)
    invalid('publication actual root projection aged before its sole terminal writer');
}

/** Read-only metadata descriptors must join on every failed SQL attempt. This
 * never closes the execution-owned roots or fabricates arena/worker retirement. */
export function closeOwnedPublicationFinalization(driver: SqliteDriver, owner: StateOwnerContext, token: OwnedPublicationFinalization): void {
  const value = token !== null && typeof token === 'object' ? finalizations.get(token) : undefined;
  if (!value || value.driver !== driver || value.owner !== owner) throw new TypeError('a genuine original publication finalization is required');
  if (value.retirementFailure) throw value.retirementFailure;
  closeGate(value);
}
/** Only an exact Session mismatch raised before writes by this original owned
 * plan may trigger bounded re-preparation of its immutable Session bytes. */
export function isOwnedPublicationSessionConflict(driver: SqliteDriver, owner: StateOwnerContext,
  receivedResult: OwnedPublicationReceivedResult, error: unknown): boolean {
  const conflict = error !== null && typeof error === 'object' ? sessionConflicts.get(error) : undefined;
  return conflict?.driver === driver && conflict.owner === owner && conflict.receivedResult === receivedResult;
}
