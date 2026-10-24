import { randomBytes } from 'node:crypto';
import { setImmediate as yieldToLoop } from 'node:timers/promises';
import { planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { decodeDeliveryCaptureTopology, decodePublicationActualPreimage, decodePublicationLateObservationItem, decodePublicationPathProgressItem, decodePublicationPreparationClosure, decodePublicationProof,
  publicationArenaId, publicationDirectoryIdentityDigest, type PublicationAbortOperation, type PublicationActualPreimageV1, type PublicationArenaBirthV1,
  type PublicationLocationV1, type PublicationOperation, type PublicationPathObservationV1, type PublicationPathProgressItem,
  type PublicationPathResultItem, type PublicationPreparationClosureV1, type PublicationProofV1,
  type PublicationPathRetirementV1, type PublicationLateObservationItem, publicationLateObservationCheckpointId,
  publicationLateObservationItemId } from '../kernel/publication.js';
import type { ContinuationItem, InvocationJournalEntry, RecoveryClosureV1, Run, RunFrontier, WorkspaceEntryManifest } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { derivePublicationGrant, derivePublicationMaintenance } from './delivery-policy.js';
import { assertPublicationReadCut, publicationEnvelopeLocations, publicationProgressCheckpointId, publicationProgressItemId,
  publicationResultCheckpointId, publicationResultItemId,
  readOwnedPublicationProof, readPublicationPrefix } from './delivery-publication-progress.js';
import { decodeContextManifest, decodeSourceManifest, decodeStateLockIdentity, decodeWorkspaceEntries } from './decoders.js';
import { joinResourceOperations, KernelStorageError, ResourceRetirementError } from './errors.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath, openHeldPublicationOperation, readHeldPublicationBirth,
  readRetiredPublicationArena, openHeldPublicationNamespaceObserver, retireHeldPublicationNamespace, readRetiredPublicationNamespace,
  readJoinedPublicationRetirementSpans, noteNormalPublicationRetirement,
  stateRootIdentityForLock,
  type HeldPublicationNamespaceObserver, type HeldPublicationOperation, type HeldWorkspaceRoot, type NativePublicationObservation, type NativePublicationOperationInput } from './native-owner.js';
import { assertPublicationPreflight, preparePublicationPreflight, type PublicationPreflight } from './publication-preflight.js';
import { noteJoinedPublicationRetirement, publicationRetirementDiagnosticKey } from './publication-retirement-diagnostics.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { appendRunStateEvent, assertLiveDispatchState, claimValidatedInvocation, prepareValidatedInvocation, requireHealthyFence, type ClaimInvocationDispatchInput } from './reducers/invocation.js';
import { appendInvocationJournalEntry, nextJournalSequence, readInvocationAttempt, readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { readCheckpoint, readRun, readSession, readSessionPrincipalId, ZERO_BUDGET } from './rows.js';
import { assertDeliveryPublicationExecution, assertDeliveryPublicationMaintenanceExecution, type DeliveryPublicationMaintenanceTask,
  type DeliveryPublicationTask, type RunExecutionWorkerIdentity, type RunPublicationPhase } from './run-execution.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readStateOwner, type StateOwnerContext } from './state-owner.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import { insertArtifactMetadata } from './artifacts.js';
import { planContinuationCommit } from './continuation-commit.js';
import { isJoinedCasPublicationFailure } from './cas.js';
import { assertSqliteConnectionOwnedBy, isRolledBackSqliteTransactionFailure } from './sqlite-driver.js';
import { readAgentStop, readRetainedAgentStop } from './stop-recovery.js';
import { preserveActualEmptyPublicationDirectory } from './publication-actual-preimage.js';
import { selectAgentStop, type AgentStopIntent } from '../runtime/stop.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { observePublicationMaintenancePath } from './publication-maintenance-observation.js';
import type { PublicationRecoveryOriginV1 } from '../kernel/reconciliation.js';
import type { PublicationGenerationResourcesV1 } from '../kernel/publication.js';
import type { ContextManifest, ReconciliationProbeEvidenceV1, Session, SupervisorInspectorIdentityV1 } from '../kernel/types.js';
import { contextSourceDigest, validateContextItems, type ContextItem } from '../runtime/context-compaction.js';
import { assertDeliveryPublicationReconciliationExecution, assertOwnedPublicationReconciliationTask,
  type DeliveryPublicationReconciliationTask } from './run-execution.js';
import { decodePublicationRecoveryOrigin } from './publication-reconciliation-artifacts.js';
import { readPublicationRecoveryOrigin } from './publication-reconciliation-history.js';
import { readPublicationReconciliation, updatePublicationReconciliationProgress } from './publication-reconciliation.js';
import { readStateOwnerDeath } from './state-owner-death.js';
import { readRetainedStateOwnerHistory, type RetainedStateOwnerHistory } from './state-owner-history.js';
import { readPublicationGenerationResources, type RetainedPublicationOperation } from './delivery-publication-progress.js';
import { readRetiredGenerationSource } from './generation-retirement.js';
import { assertNativeContainmentDeath, type NativeContainmentDeathObservation } from '../sandbox/linux-worker.js';
import { readWorkerRecoveryAnchor } from './worker-recovery.js';
import type { WorkerDeathWait } from '../kernel/types.js';
import { validateRetainedWorkerSeal } from './tool-checkpoint.js';
import { validateRetainedWorkerQuarantines } from './worker-recovery.js';

const ownerBrand: unique symbol = Symbol('PublicationInvocationOwner');
/** An original owned preparation/dispatch, not a transferable native permit. */
export type PublicationInvocationOwner = Readonly<{
  readonly [ownerBrand]: true; run: Run; opId: string; attempt: 0;
  /** Irreversible semantic revocation, independent of final descriptor join. */
  revoke(): void;
  /** Joins descriptors only; this never asserts cleanup or arena retirement. */
  close(): void;
}>;
type Prefix = Awaited<ReturnType<typeof readPublicationPrefix>>;
type Authorization = NonNullable<Prefix['authorization']>;
type Binding = {
  driver: SqliteDriver; artifacts: ArtifactCatalog; reads: ArtifactCatalog; owner: StateOwnerContext; execution: unknown;
  root: HeldWorkspaceRoot; signal?: AbortSignal;
  run: Run; prepared: InvocationJournalEntry; authorization: Authorization;
  prefix: Prefix; cut: RecoveryClosureV1; assertCut(connection: SqliteConnection): void;
  dispatchId: string; nativeInput: NativePublicationOperationInput;
  nativeOpenState: 'not_attempted' | 'returned' | 'unknown';
  preflight?: PublicationPreflight; native?: HeldPublicationOperation; birth?: PublicationArenaBirthV1;
  metadata?: PublishedArtifact[]; birthPlans?: PlannedArtifact[]; birthRef?: string; claim?: InvocationJournalEntry; armed: boolean;
  revoked: boolean; closed: boolean; retirementFailure?: ResourceRetirementError; pending?: Promise<{ run: Run; claim: InvocationJournalEntry }>;
  advancing?: Promise<PublicationPathDisposition>; disposition?: PublicationPathDisposition;
  publications?: Map<string, { plan: PlannedArtifact; artifact?: PublishedArtifact }>;
  payloadMetadata?: PublishedArtifact[]; observations?: Map<string, Extract<PublicationProofV1, { kind: 'path_observation' }>>;
  commitAttempted?: boolean; originalVerified?: boolean; stageStarted?: boolean; stageFinished?: boolean;
  committed?: boolean; cleaned?: boolean; arenaRetired?: boolean; physicalFailure?: unknown; failure?: unknown;
  before?: PublicationPathObservationV1; beforeRef?: string; preservedRef?: string; destinationRef?: string;
  progress?: { item: Extract<PublicationPathProgressItem, { state: 'desired_committed_cleanup_pending' }>;
    graph: ReturnType<typeof planContinuationCommit>; metadata?: PublishedArtifact[] };
  progressCommitted?: boolean; afterProgressRun?: Run; observedStop?: AgentStopIntent;
  slotObservationRefs?: string[]; arenaRetirementRef?: string;
  completion?: { evidence: PublicationProofV1; evidenceRef: string; receiptRef?: string; metadata: PublishedArtifact[] };
  unknownProof?: Extract<PublicationProofV1, { kind: 'path_ambiguity' }>; receiptProof?: Extract<PublicationProofV1, { kind: 'terminal_receipt' }>;
  ambiguity?: Extract<PublicationProofV1, { kind: 'path_ambiguity' }>['failure']; actualPreimageRef?: string;
  finalObservations?: PublicationPathObservationV1[]; finalDestination?: PublicationPathObservationV1;
  arenaRetirementProof?: Extract<PublicationProofV1, { kind: 'arena_retirement' }>;
  preparedSnapshot?: ReturnType<typeof sqlCut>;
  preparationRetiring?: Promise<Run>;
  preparationClosure?: PublicationPreparationClosureV1; preparationClosureRef?: string;
  preparationDiscardAttempted?: boolean; preparationDiscarded?: boolean;
} & ({ mode: 'forward'; task: DeliveryPublicationTask; worker: RunExecutionWorkerIdentity; operation: PublicationOperation } |
  { mode: 'abort'; task: DeliveryPublicationMaintenanceTask; worker?: never; operation: PublicationAbortOperation;
    creatorReceiptRef: string; stopIntentRef: string });
export type PublicationPathDisposition = Readonly<{ disposition: 'received' | 'unknown' | 'stopped_before_effect' | 'retained_planned_descendant' }>;
const owners = new WeakMap<object, Binding>();
type ReconciledPublicationRetirement = {
  disposition: 'received' | 'stopped_before_effect'; planRef: string; operation: Binding['operation'];
  prepared: InvocationJournalEntry; claim: InvocationJournalEntry; birth: PublicationArenaBirthV1; unknownEvidenceRef: string;
  evidence: PublicationProofV1; evidenceRef: string;
  wrapper: Extract<ReconciliationProbeEvidenceV1, { outcome: 'subject_observation' }>; wrapperRef: string;
  retirement: { slotObservationRefs: string[]; arenaRetirementRef: string }; metadata: PublishedArtifact[];
};
// Original-owner physical facts only. Neither the expired inspection task nor
// its native cleanup capability is retained or transferred by this archive.
const reconciledRetirements = new WeakMap<Binding, {
  data: ReconciledPublicationRetirement; actual: ReturnType<typeof readRetiredPublicationArena>;
}>();
function invalid(message: string): never { throw new KernelStorageError('STATE_TRANSITION_INVALID', message); }

// Shared only by the two genuine producers in this module. These fields are
// physical facts and immutable publication plans, never a semantic release.
type PhysicalBinding = Pick<Binding, 'artifacts' | 'owner' | 'run' | 'mode' | 'operation' | 'nativeInput' | 'native' | 'birth' |
  'prepared' | 'claim' | 'closed' | 'retirementFailure' | 'physicalFailure' | 'publications' | 'metadata' | 'payloadMetadata' |
  'observations' | 'beforeRef' | 'preservedRef' | 'finalObservations' | 'finalDestination' | 'slotObservationRefs' | 'arenaRetired' |
  'arenaRetirementRef' | 'arenaRetirementProof' | 'progress'> & {
    proofInspector?: Pick<SupervisorInspectorIdentityV1, 'identityDigest'> & { ref: string };
    recoveryOrigin?: { ref: string; digest: string };
    namespaceDestinationProof?: Extract<PublicationProofV1, { kind: 'path_observation' }>;
    namespaceProof?: Extract<PublicationProofV1, { kind: 'arena_namespace_absence' }>; namespaceEvidenceRef?: string;
    /** Private genuine probe gate; never supplied through a public API. */
    inspectionGate?: () => void;
  };

function binding(driver: SqliteDriver, owner: StateOwnerContext, value: unknown): Binding {
  const held = value !== null && typeof value === 'object' ? owners.get(value) : undefined;
  if (!held || held.driver !== driver || held.owner !== owner) throw new TypeError('publication requires its exact original invocation owner');
  if (held.retirementFailure) throw held.retirementFailure;
  return held;
}
/** Internal inert binding check. A genuine completion cannot be paired with
 * a different catalog to supply caller-selected artifacts during finalization. */
export function assertOwnedPublicationArtifacts(driver: SqliteDriver, owner: StateOwnerContext, execution: unknown,
  token: PublicationInvocationOwner, artifacts: ArtifactCatalog): void {
  const held = binding(driver, owner, token);
  if (held.execution !== execution || held.artifacts !== artifacts)
    throw new TypeError('publication requires its exact original execution and artifact catalog');
}
function assertCurrent(held: Binding, connection: SqliteConnection = held.driver) {
  if (held.retirementFailure) throw held.retirementFailure;
  if (held.closed || held.revoked) throw new KernelStorageError('LEASE_FENCED', 'original publication owner is closed or revoked');
  held.signal?.throwIfAborted();
  if (held.mode === 'forward') assertDeliveryPublicationExecution(held.driver, held.owner, held.execution, held.worker, held.task, connection);
  else {
    const resources = assertDeliveryPublicationMaintenanceExecution(held.driver, held.owner, held.execution, held.task, held.artifacts, connection);
    if (resources.workspaceRoot !== held.root || resources.runId !== held.run.id) throw new TypeError('maintenance changed its genuine original root');
  }
  assertHeldWorkspaceRoot(held.root); assertActiveStateOwner(connection, held.owner);
}
function sessionIdentity(connection: SqliteConnection, id: string) {
  return immutableSessionIdentity(readSession(connection, id));
}
function immutableSessionIdentity(session: Session) {
  return { id: session.id, workspaceIdentityRef: session.workspaceIdentityRef, createdAt: session.createdAt,
    ...(session.parentSessionId === undefined ? {} : { parentSessionId: session.parentSessionId, forkedThroughItemSeq: session.forkedThroughItemSeq }) };
}
function sqlCut(connection: SqliteConnection, runId: string, sourceRunId: string) {
  const run = readRun(connection, runId), source = readRun(connection, sourceRunId);
  return { run, checkpoint: readCheckpoint(connection, run.latestCheckpointId), journal: readInvocationJournal(connection, runId),
    items: connection.prepare('SELECT item_id,kind,payload_ref,item_seq,created_at FROM items WHERE run_id=? ORDER BY item_seq')
      .all<{ item_id: string; kind: string; payload_ref: string; item_seq: bigint; created_at: string }>(runId)
      .map(row => ({ ...row, item_seq: Number(row.item_seq) })),
    launches: readWorkerLaunchesForRun(connection, runId), generations: readWorkspaceGenerationsForRun(connection, runId),
    session: sessionIdentity(connection, run.sessionId), principalId: readSessionPrincipalId(connection, run.sessionId),
    source, sourceSession: sessionIdentity(connection, source.sessionId),
    children: !!connection.prepare('SELECT 1 FROM child_allocations WHERE parent_run_id=? OR child_run_id=? LIMIT 1').get(runId, runId) ||
      !!connection.prepare('SELECT 1 FROM runs WHERE parent_run_id=? LIMIT 1').get(runId) };
}
function closedInput(value: unknown): asserts value is Parameters<typeof preparePublicationInvocation>[3] {
  if (value === null || typeof value !== 'object') throw new TypeError('publication preparation requires one closed owning input');
  const fields = Object.getOwnPropertyDescriptors(value), keys = ['execution', 'worker', 'workspaceRoot', 'expectedRunRevision', 'task'];
  if (Object.hasOwn(fields, 'signal')) keys.push('signal');
  if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !Object.hasOwn(fields, key)) ||
      Object.values(fields).some(field => !field.enumerable || !Object.hasOwn(field, 'value') || field.value === undefined))
    throw new TypeError('publication preparation requires one closed owning input');
}

async function physicalInput(driver: SqliteDriver, artifacts: ArtifactCatalog, prefix: Prefix, operation: PublicationOperation, arenaId: string): Promise<NativePublicationOperationInput> {
  const authorization = prefix.authorization!;
  const plan = authorization.context.plan;
  const topology = decodeDeliveryCaptureTopology(await readCanonicalArtifact(artifacts, plan.captureTopologyRef));
  const physical = new Map(topology.directories.map(entry => [entry.path, entry]));
  const parents: NativePublicationOperationInput['parents'][number][] = [];
  const segments = operation.path.split('/');
  for (let index = 0; index < segments.length; index++) {
    const path = segments.slice(0, index).join('/');
    const creator = prefix.forward.find(entry => entry.operation.kind !== 'abort_rmdir' && entry.operation.path === path &&
      entry.operation.desired.kind === 'directory' && entry.operation.expected.kind !== 'directory');
    if (!creator) {
      const identity = path ? physical.get(path) : topology.rootIdentity;
      if (!identity) invalid('publication ancestor is absent from its complete captured topology');
      parents.push({ deviceId: identity.deviceId, fileId: identity.fileId, ownerUid: identity.ownerUid, mode: identity.mode });
    } else {
      if (creator.result?.item.outcome !== 'completed') invalid('publication planned ancestor has no completed original creator');
      const proof = await readOwnedPublicationProof(driver, artifacts, prefix.admission, creator.planRef, creator.result.item.receiptRef, creator.claim);
      if (proof.kind !== 'terminal_receipt' || proof.after.state.kind !== 'directory' || proof.after.entryDeviceId === undefined || proof.after.entryFileId === undefined)
        invalid('publication planned ancestor has no actual original directory birth');
      parents.push({ deviceId: proof.after.entryDeviceId, fileId: proof.after.entryFileId, ownerUid: topology.rootIdentity.ownerUid, mode: proof.after.state.mode });
    }
  }
  const parent = parents.at(-1)!;
  if (operation.parent.kind === 'existing_directory' && publicationDirectoryIdentityDigest(authorization.context.workspaceIdentityDigest, parent) !== operation.parent.expectedIdentityDigest)
    invalid('publication direct parent differs from its approved original identity');
  const sourceEntries = async (ref: string) => {
    const source = decodeSourceManifest(await readCanonicalArtifact(artifacts, ref));
    return decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, source.entriesRef));
  };
  const before = await sourceEntries(plan.capturedWorkspaceRef), after = await sourceEntries(plan.desiredSourceRef);
  const file = <Mode extends number>(state: { mode: Mode; digest: string }, entries: typeof before) => {
    const entry = entries.entries.find(value => value.path === operation.path);
    if (!entry || entry.kind !== 'file' || entry.blobRef !== state.digest) return invalid('publication file has no exact complete source bytes');
    return { kind: 'file' as const, mode: state.mode, digest: state.digest, byteCount: entry.size };
  };
  const expected = (state: Exclude<PublicationOperation['expected'], { kind: 'absent' }>): Extract<NativePublicationOperationInput, { kind: 'replace' }>['expected'] => {
    if (state.kind === 'file') return file(state, before);
    if (state.kind === 'symlink') return state;
    const identity = physical.get(operation.path);
    if (!identity || identity.identityDigest !== state.identityDigest) return invalid('publication old directory differs from its captured physical identity');
    return { kind: 'directory', mode: state.mode, identity: { deviceId: identity.deviceId, fileId: identity.fileId, ownerUid: identity.ownerUid } };
  };
  const desiredFile = (state: Extract<PublicationOperation['desired'], { kind: 'file' }>):
    Extract<Extract<NativePublicationOperationInput, { kind: 'replace' }>['desired'], { kind: 'file' }> => {
    const mode = state.mode;
    if (mode !== 0o644 && mode !== 0o755) return invalid('publication desired file mode is not canonical');
    return { ...file(state, after), mode };
  };
  const desired = (state: Exclude<PublicationOperation['desired'], { kind: 'absent' }>) => state.kind === 'file' ? desiredFile(state) : state;
  const common = { arenaId, path: operation.path, parents };
  if (operation.kind === 'mkdir') return { ...common, kind: 'mkdir' as const, expected: operation.expected, desired: operation.desired };
  if (operation.kind === 'create') return { ...common, kind: 'create' as const, expected: operation.expected,
    desired: operation.desired.kind === 'file' ? desiredFile(operation.desired) : operation.desired, stagingName: operation.stagingName };
  if (operation.kind === 'delete') return { ...common, kind: 'delete' as const, expected: expected(operation.expected), desired: operation.desired, quarantineName: operation.quarantineName };
  return { ...common, kind: 'replace' as const, expected: expected(operation.expected), desired: desired(operation.desired),
    stagingName: operation.stagingName, quarantineName: operation.quarantineName };
}
type PublicationPreparationPhase = Extract<RunPublicationPhase, `publication_prepare_${string}`>;
/** Sole forward preparation. Handles and task brands are checked before any
 * SQLite/CAS/native I/O; no caller chooses a request, grant, dispatch or proof.
 * Fixed observation is separate from the closed authority input. */
export async function preparePublicationInvocation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { execution: unknown; task: DeliveryPublicationTask; worker: RunExecutionWorkerIdentity; workspaceRoot: HeldWorkspaceRoot;
    expectedRunRevision: number; signal?: AbortSignal },
  onPreparationPhase?: (phase: PublicationPreparationPhase) => void): Promise<PublicationInvocationOwner> {
  const preparationPhase = (phase: PublicationPreparationPhase) => { try { onPreparationPhase?.(phase); } catch { /* Diagnosis cannot decide preparation. */ } };
  closedInput(input);
  assertDeliveryPublicationExecution(driver, owner, input.execution, input.worker, input.task);
  assertHeldWorkspaceRoot(input.workspaceRoot);
  if (!Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1) throw new TypeError('publication requires one expected revision');
  input.signal?.throwIfAborted();
  const worker = immutableSnapshot(input.worker), root = input.workspaceRoot;
  input = Object.freeze({ ...input, worker });
  const reads = input.signal ? artifacts.withReadSignal(input.signal) : artifacts;
  preparationPhase('publication_prepare_read');
  const cut = await readRecoveryClosure(driver, reads, worker.runId), prefix = await readPublicationPrefix(driver, reads, cut);
  const authorization = prefix.authorization;
  if (!authorization?.grant || !authorization.grantRef || authorization.decision.decision !== 'allow' || authorization.workspace.kind !== 'live')
    invalid('publication requires the complete original delivery allow');
  if (cut.run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'publication preparation Run revision changed');
  if (cut.run.nextStep !== 'delivery' || !cut.run.frontierRef || cut.run.stopIntentRef || cut.run.cancelRequested || prefix.abort.length ||
      prefix.forward.some(entry => entry.result?.item.outcome !== 'completed')) invalid('publication requires its exact completed forward prefix');
  const index = prefix.forward.length, operation = authorization.context.plan.forwardOperations[index];
  if (!operation) invalid('publication has no remaining productive path');
  const frontier: RunFrontier = { ...authorization.frontier, phase: 'publish', nextPathOperationIndex: index };
  requireEqual(await readCanonicalArtifact(reads, cut.run.frontierRef), frontier, 'publication exact current forward frontier');
  if (heldWorkspaceRootPath(root) !== authorization.workspace.canonicalRootPath) invalid('publication root differs from its original approved workspace');
  requireEqual(root.identity, authorization.workspace.rootIdentity, 'publication original root identity');
  const issuedAt = sampleCanonicalNow();
  preparationPhase('publication_prepare_grant');
  const derived = derivePublicationGrant({ context: { ...authorization.context, frontierRef: cut.run.frontierRef },
    parent: authorization.grant, parentRef: authorization.grantRef, decision: authorization.decision, sequence: 'forward', operationIndex: index, issuedAt });
  const snapshot = sqlCut(driver, cut.run.id, authorization.verified.admission.source.run.id), fingerprint = canonicalSha256(snapshot);
  preparationPhase('publication_prepare_cut');
  await assertPublicationReadCut(driver, reads, cut);
  const assertCut = (connection: SqliteConnection) => {
    assertSqliteConnectionOwnedBy(driver, connection);
    assertActiveStateOwner(connection, owner);
    if (canonicalSha256(sqlCut(connection, cut.run.id, authorization.verified.admission.source.run.id)) !== fingerprint)
      throw new KernelStorageError('REVISION_CONFLICT', 'publication original source, Run, worker or prefix cut changed');
    assertDeliveryPublicationExecution(driver, owner, input.execution, worker, input.task, connection); root.assertHeld(); input.signal?.throwIfAborted();
  };
  const metadata = await joinResourceOperations([artifacts.publishCanonical(derived.request, derived.request.format), artifacts.publishCanonical(derived.target, derived.target.format),
    artifacts.publishCanonical(derived.grant, derived.grant.format)]);
  const dispatchId = sha256Bytes(randomBytes(32));
  preparationPhase('publication_prepare_physical');
  const nativeInput = await physicalInput(driver, reads, prefix, operation, publicationArenaId(cut.run.id, operation.operationId, derived.request.opId, 0, dispatchId));
  preparationPhase('publication_prepare_admit');
  const prepared = await prepareValidatedInvocation(driver, reads, owner, { runId: cut.run.id, expectedRunRevision: cut.run.revision,
    leaseEpoch: worker.leaseEpoch, opId: derived.request.opId, opKind: 'publish', target: derived.request.targetRef,
    requestRef: canonicalSha256(derived.request), grantRef: canonicalSha256(derived.grant), replayClass: 'reconcile', reservation: { ...ZERO_BUDGET, toolCalls: 1 } },
  { metadata, validate(connection, run, attempt, now) {
    assertCut(connection); requireEqual(run, cut.run, 'publication preparation exact Run');
    if (attempt !== 0 || now < issuedAt || now >= derived.grant.expiresAt) throw new KernelStorageError('LEASE_FENCED', 'publication child grant is no longer fresh');
  } });
  const preparedFingerprint = canonicalSha256(sqlCut(driver, cut.run.id, authorization.verified.admission.source.run.id));
  const assertPreparedCut = (connection: SqliteConnection) => {
    assertActiveStateOwner(connection, owner);
    if (canonicalSha256(sqlCut(connection, cut.run.id, authorization.verified.admission.source.run.id)) !== preparedFingerprint)
      throw new KernelStorageError('REVISION_CONFLICT', 'publication original prepared cut changed');
  };
  const held: Binding = { mode: 'forward', driver, artifacts, reads, owner, execution: input.execution, task: input.task, worker, root, signal: input.signal,
    run: immutableSnapshot(prepared.run), prepared: immutableSnapshot(prepared.entry), authorization, operation, prefix, cut,
    assertCut: assertPreparedCut, dispatchId, nativeInput, nativeOpenState: 'not_attempted', armed: false, revoked: false, closed: false };
  return retainOwner(held);
}

type MaintenanceInput = { execution: unknown; task: DeliveryPublicationMaintenanceTask; workspaceRoot: HeldWorkspaceRoot;
  expectedRunRevision: number; signal?: AbortSignal };
function closedMaintenanceInput(value: unknown): asserts value is MaintenanceInput {
  if (!value || typeof value !== 'object') throw new TypeError('maintenance requires one closed original task input');
  const fields = Object.getOwnPropertyDescriptors(value), keys = ['execution', 'task', 'workspaceRoot', 'expectedRunRevision'];
  if (Object.hasOwn(fields, 'signal')) keys.push('signal');
  if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !Object.hasOwn(fields, key)) ||
      Object.values(fields).some(field => !field.enumerable || !Object.hasOwn(field, 'value') || field.value === undefined))
    throw new TypeError('maintenance requires one closed original task input');
}
async function completedDescendants(driver: SqliteDriver, artifacts: ArtifactCatalog, prefix: Prefix, path: string) {
  const result = [];
  for (const entry of prefix.forward) {
    if (!entry.operation.path.startsWith(`${path}/`) || entry.result?.item.outcome !== 'completed') continue;
    if (prefix.abortResults.some(abort => abort.operation.path === entry.operation.path && abort.result?.item.outcome === 'completed')) continue;
    const receipt = await readOwnedPublicationProof(driver, artifacts, prefix.admission, entry.planRef, entry.result.item.receiptRef, entry.claim);
    if (receipt.kind !== 'terminal_receipt') invalid('maintenance descendant has no actual completed receipt');
    if (receipt.after.state.kind !== 'absent') result.push({ operationId: entry.operation.operationId, observation: receipt.after });
  }
  return result.sort((left, right) => Buffer.compare(Buffer.from(left.observation.location.kind === 'workspace' ? left.observation.location.path : ''),
    Buffer.from(right.observation.location.kind === 'workspace' ? right.observation.location.path : '')));
}
/** A stopping task may create only the distinct zero-budget maintenance
 * envelope. It cannot borrow a productive worker, extend a grant or adopt an
 * arena by its pathname. No directory is opened for mutation until claim. */
export async function preparePublicationMaintenance(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: MaintenanceInput): Promise<{ kind: 'not_created'; run: Run } | { kind: 'path'; publicationOwner: PublicationInvocationOwner }> {
  closedMaintenanceInput(input);
  const resources = assertDeliveryPublicationMaintenanceExecution(driver, owner, input.execution, input.task, artifacts);
  if (input.workspaceRoot !== resources.workspaceRoot || input.signal !== undefined && input.signal !== resources.signal)
    throw new TypeError('maintenance requires its genuine original root and read lifetime');
  if (!Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision !== resources.expectedRunRevision)
    throw new TypeError('maintenance requires its genuine original expected revision');
  input = Object.freeze({ ...input });
  const root = resources.workspaceRoot, signal = resources.signal, reads = artifacts.withReadSignal(signal);
  signal.throwIfAborted(); assertHeldWorkspaceRoot(root);
  const cut = await readRecoveryClosure(driver, reads, resources.runId), prefix = await readPublicationPrefix(driver, reads, cut);
  const authorization = prefix.authorization;
  if (!authorization?.grant || !authorization.grantRef || authorization.decision.decision !== 'allow' || authorization.workspace.kind !== 'live')
    invalid('maintenance requires its complete original approved Plan');
  if (cut.run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'maintenance original Run revision changed');
  if (cut.run.nextStep !== 'delivery' || !['queued', 'running'].includes(cut.run.status) || !cut.run.frontierRef || !cut.run.stopIntentRef ||
      prefix.forward.some(entry => !entry.result || entry.result.item.outcome === 'unknown') ||
      prefix.abortResults.some(entry => !entry.result || entry.result.item.outcome === 'unknown') ||
      canonicalSha256(cut.run.budgetReserved) !== canonicalSha256(ZERO_BUDGET))
    invalid('maintenance requires its stopped, fully settled original prefix and zero reservation');
  const stop = await readAgentStop(driver, reads, cut);
  requireEqual(root.identity, authorization.workspace.rootIdentity, 'maintenance original root identity');
  if (heldWorkspaceRootPath(root) !== authorization.workspace.canonicalRootPath) invalid('maintenance changed its original approved root');
  const index = prefix.abortResults.length, operation = authorization.context.plan.abortOperations[index];
  if (!operation) invalid('maintenance has no remaining original abort operation');
  const frontier: RunFrontier = { ...authorization.frontier, phase: 'abort_cleanup', nextPathOperationIndex: index };
  const actualFrontier = await readCanonicalArtifact<RunFrontier>(reads, cut.run.frontierRef);
  if (index || actualFrontier.kind === 'delivery' && actualFrontier.phase === 'abort_cleanup')
    requireEqual(actualFrontier, frontier, 'maintenance current exact abort frontier');
  else requireEqual(actualFrontier, { ...authorization.frontier, phase: 'publish', nextPathOperationIndex: prefix.forward.length },
    'maintenance original settled forward-to-abort cut');
  const fingerprint = canonicalSha256(sqlCut(driver, cut.run.id, prefix.admission.source.run.id));
  const assertCut = (connection: SqliteConnection) => {
    assertSqliteConnectionOwnedBy(driver, connection);
    assertActiveStateOwner(connection, owner);
    const actual = assertDeliveryPublicationMaintenanceExecution(driver, owner, input.execution, input.task, artifacts, connection);
    if (actual.workspaceRoot !== root || actual.runId !== cut.run.id) throw new TypeError('maintenance changed its owning task');
    signal.throwIfAborted(); root.assertHeld();
    if (canonicalSha256(sqlCut(connection, cut.run.id, prefix.admission.source.run.id)) !== fingerprint)
      throw new KernelStorageError('REVISION_CONFLICT', 'maintenance original source, Stop, Session or publication cut changed');
  };
  const profile = decodeSandboxProfile(await readCanonicalArtifact(reads, cut.runSpec.sandboxProfileRef));
  const observed = await observePublicationMaintenancePath(root, { path: operation.path,
    workspaceIdentityDigest: authorization.context.workspaceIdentityDigest,
    completedDescendants: await completedDescendants(driver, reads, prefix, operation.path),
    maxSingleFileBytes: profile.resources.maxSingleFileBytes, maxBytes: profile.resources.maxGenerationBytes, signal });
  const creator = prefix.forward.find(entry => entry.operation.operationId === operation.createdByOperationId);
  if (creator?.result?.item.outcome !== 'completed') {
    if (creator?.claim) {
      const originals = resources.publicationOwners.filter(token => token.opId === creator.prepared.opId);
      if (originals.length > 1 || creator.result?.item.outcome !== 'failed' || !creator.result.item.retirement)
        invalid('maintenance cannot replace an unresolved original claimed directory creator');
      const retained = await readOwnedPublicationProof(driver, reads, prefix.admission, creator.planRef,
        creator.result.item.evidenceRef, creator.claim);
      if (retained.kind !== 'path_observation' || retained.observation.location.kind !== 'workspace' ||
          retained.observation.location.path !== operation.path || creator.progress)
        invalid('maintenance creator has no original stopped-before-effect observation');
      if (originals.length) {
        const actual = readOwnedPublicationCompletion(driver, owner, input.execution, originals[0]!);
        if (actual.disposition !== 'stopped_before_effect' || actual.birth.sequence !== 'forward' ||
            actual.operation.operationId !== operation.createdByOperationId || actual.evidence.kind !== 'path_observation' ||
            actual.evidenceRef !== creator.result.item.evidenceRef || actual.receiptRef !== undefined || actual.progressCommitted)
          invalid('maintenance lost its genuine stopped creator and original no-effect observation');
        requireEqual(actual.prepared, creator.prepared, 'maintenance original stopped directory creator preparation');
        requireEqual(actual.claim, creator.claim, 'maintenance original stopped directory creator claim');
        requireEqual({ slotObservationRefs: actual.slotObservationRefs, arenaRetirementRef: actual.arenaRetirementRef },
          creator.result.item.retirement, 'maintenance original durable stopped creator retirement');
      }
      // The full prefix has verified this original claim's durable slot and
      // arena-retirement graph. A successor reads that historical fact only:
      // it does not reconstruct the old owner, open an old arena or clean it.
    } else if (creator?.history.some(entry => entry.phase === 'completed'))
      invalid('maintenance cannot replace a completed original directory creator');
    // A file/symlink-to-directory conversion that never happened still has
    // its captured A leaf. Preserve its real observation, never call it absent
    // or acquire cleanup authority over it. A blocking unchanged A leaf also
    // proves only no-follow projection absence for planned descendants.
    const location = observed.observation.location;
    const original = location.kind === 'workspace'
      ? authorization.context.plan.forwardOperations.find(value => value.path === location.path) : undefined;
    const unchangedLeaf = original?.desired.kind === 'directory' &&
      (original.expected.kind === 'file' || original.expected.kind === 'symlink') &&
      canonicalSha256(original.expected) === canonicalSha256(observed.observation.state) &&
      (original.expected.kind !== 'file' || observed.observation.entryLinkCount === 1);
    if (observed.classification !== 'absent' && !unchangedLeaf)
      invalid('maintenance cannot call a changed, present directory or unexpected original leaf not-created');
    const active = assertActiveStateOwner(driver, owner), inspector = supervisorInspectorIdentity(active);
    const observedAt = sampleCanonicalNow(), base = { schemaVersion: 1 as const, format: 'cliq-publication-proof-v1' as const,
      deliveryRunId: cut.run.id, deliveryPlanRef: authorization.context.planRef,
      workspaceIdentityRef: authorization.context.workspaceIdentityRef, workspaceIdentityDigest: authorization.context.workspaceIdentityDigest,
      inspectorIdentityRef: canonicalSha256(inspector), inspectorIdentityDigest: inspector.identityDigest, observedAt, proofDigest: '' };
    const observedProof = { ...base, kind: 'path_observation' as const, observation: observed.observation };
    observedProof.proofDigest = digestOmitting(observedProof, 'proofDigest'); decodePublicationProof(observedProof);
    const evidence = observed.ancestorPath === undefined ? observedProof : { ...base, kind: 'ancestor_projection_absence' as const,
      path: operation.path, ancestorPath: observed.ancestorPath, ancestorObservationRef: canonicalSha256(observedProof) };
    evidence.proofDigest = digestOmitting(evidence, 'proofDigest'); decodePublicationProof(evidence);
    const evidenceRef = canonicalSha256(evidence), opId = identityHash('cliq-publication-abort-observation-v1', cut.run.id, operation.operationId);
    const item: PublicationPathResultItem = { schemaVersion: 1, kind: 'publication_path_result',
      itemId: publicationResultItemId(cut.run.id, opId, 0, evidenceRef), runId: cut.run.id, deliveryPlanRef: authorization.context.planRef,
      sequence: 'abort', operationIndex: index, operationId: operation.operationId, opId, attempt: 0, outcome: 'not_created', evidenceRef, createdAt: observedAt };
    const context = decodeContextManifest(await readCanonicalArtifact(reads, cut.latestCheckpoint.contextManifestRef)), existingItems = [];
    for (const row of cut.items) existingItems.push({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
      item: await readCanonicalArtifact<ContinuationItem>(reads, row.payloadRef) });
    const graph = planContinuationCommit(artifacts, { context, existingItems, items: [item], frontier,
      checkpointId: publicationResultCheckpointId(cut.run.id, opId, 0, evidenceRef), workspaceStateRef: cut.latestCheckpoint.workspaceStateRef,
      artifacts: [planCanonicalArtifact(inspector, inspector.format), planCanonicalArtifact(observedProof, observedProof.format),
        ...(observed.ancestorPath === undefined ? [] : [planCanonicalArtifact(evidence, evidence.format)])] });
    const published = await graph.publish(); await assertPublicationReadCut(driver, reads, cut); assertCut(driver);
    let outcome: TimeFenceAdvance | undefined, run: Run | undefined;
    driver.transaction(connection => {
      assertCut(connection); const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
      if (outcome !== 'healthy') return;
      if (now < observedAt || now < cut.run.updatedAt) invalid('maintenance absence has a noncausal commit time');
      for (const artifact of published.metadata) insertArtifactMetadata(connection, artifact, now);
      published.commit(connection, cut.run, cut.journal.length, now);
      connection.prepare('UPDATE runs SET revision=revision+1,updated_at=? WHERE id=? AND revision=?')
        .run(now, cut.run.id, BigInt(cut.run.revision));
      run = readRun(connection, cut.run.id); appendRunStateEvent(connection, run, now);
    });
    requireHealthyFence(outcome);
    if (!run) invalid('maintenance absence did not commit');
    return { kind: 'not_created', run: immutableSnapshot(run) };
  }
  if (!creator.claim || creator.operation.kind === 'abort_rmdir') invalid('maintenance lost its exact original creator claim');
  const receipt = await readOwnedPublicationProof(driver, reads, prefix.admission, creator.planRef, creator.result.item.receiptRef, creator.claim);
  if (receipt.kind !== 'terminal_receipt' || receipt.after.state.kind !== 'directory' || receipt.after.entryDeviceId === undefined ||
      receipt.after.entryFileId === undefined || receipt.after.location.kind !== 'workspace' || receipt.after.location.path !== operation.path)
    invalid('maintenance creator has no actual directory birth');
  if (observed.classification !== 'empty_directory' && observed.classification !== 'planned_descendants')
    invalid('maintenance refuses unexpected or unavailable creator contents');
  const expected = receipt.after;
  if (expected.state.kind !== 'directory') invalid('maintenance creator is not an actual directory');
  if (observed.observation.state.kind !== 'directory' || observed.observation.entryDeviceId !== expected.entryDeviceId ||
      observed.observation.entryFileId !== expected.entryFileId || observed.observation.state.mode !== expected.state.mode ||
      observed.observation.state.identityDigest !== expected.state.identityDigest)
    invalid('maintenance refuses a foreign directory at its original creator path');
  const issuedAt = sampleCanonicalNow(), frontierPlan = planCanonicalArtifact(frontier, 'cliq-run-frontier-v1');
  const derived = derivePublicationMaintenance({ context: { ...authorization.context, frontierRef: frontierPlan.ref },
    parent: authorization.grant, parentRef: authorization.grantRef, decision: authorization.decision, operationIndex: index, issuedAt,
    stopIntentRef: cut.run.stopIntentRef, creatorReceiptRef: creator.result.item.receiptRef });
  const metadata = await joinResourceOperations([artifacts.publishCanonical(derived.request, derived.request.format),
    artifacts.publishCanonical(derived.target, derived.target.format), artifacts.publishCanonical(derived.grant, derived.grant.format),
    artifacts.publishBytes(frontierPlan.bytes, frontierPlan.mediaType, frontierPlan.schemaKind)]);
  const dispatchId = sha256Bytes(randomBytes(32));
  const creatorInput = await physicalInput(driver, reads, prefix, creator.operation,
    publicationArenaId(cut.run.id, operation.operationId, derived.request.opId, 0, dispatchId));
  const topology = decodeDeliveryCaptureTopology(await readCanonicalArtifact(reads, authorization.context.plan.captureTopologyRef));
  const nativeInput: NativePublicationOperationInput = { arenaId: creatorInput.arenaId, path: operation.path, parents: creatorInput.parents,
    kind: 'abort_rmdir', expected: { kind: 'directory', mode: expected.state.mode,
      identity: { deviceId: expected.entryDeviceId!, fileId: expected.entryFileId!, ownerUid: topology.rootIdentity.ownerUid } },
    desired: { kind: 'absent' }, quarantineName: operation.quarantineName };
  await assertPublicationReadCut(driver, reads, cut); assertCut(driver);
  let outcome: TimeFenceAdvance | undefined, prepared: InvocationJournalEntry | undefined, preparedRun: Run | undefined;
  driver.transaction(connection => {
    assertCut(connection); const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (outcome !== 'healthy') return;
    if (now < issuedAt || now < cut.run.updatedAt || now < stop.createdAt) invalid('maintenance preparation has a noncausal time');
    if (readInvocationAttempt(connection, cut.run.id, derived.request.opId, 0).length) invalid('maintenance cannot replace its original envelope');
    const entry: InvocationJournalEntry = { runId: cut.run.id, seq: nextJournalSequence(connection, cut.run.id), opId: derived.request.opId,
      opKind: 'publish', attempt: 0, phase: 'prepared', target: derived.request.targetRef, requestRef: canonicalSha256(derived.request),
      grantRef: canonicalSha256(derived.grant), replayClass: 'reconcile', leaseEpoch: cut.run.leaseEpoch, budgetDelta: ZERO_BUDGET, timestamp: now };
    for (const artifact of metadata) insertArtifactMetadata(connection, artifact, now);
    appendInvocationJournalEntry(connection, entry); prepared = entry;
    connection.prepare('UPDATE runs SET frontier_ref=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?')
      .run(frontierPlan.ref, now, cut.run.id, BigInt(cut.run.revision));
    preparedRun = readRun(connection, cut.run.id); appendRunStateEvent(connection, preparedRun, now);
  });
  requireHealthyFence(outcome);
  if (!prepared || !preparedRun) invalid('maintenance preparation did not commit');
  const preparedFingerprint = canonicalSha256(sqlCut(driver, cut.run.id, prefix.admission.source.run.id));
  const assertPreparedCut = (connection: SqliteConnection) => {
    assertActiveStateOwner(connection, owner);
    if (canonicalSha256(sqlCut(connection, cut.run.id, prefix.admission.source.run.id)) !== preparedFingerprint)
      throw new KernelStorageError('REVISION_CONFLICT', 'maintenance original prepared cut changed');
  };
  const held: Binding = { mode: 'abort', driver, artifacts, reads, owner, execution: input.execution, task: input.task, root, signal,
    run: immutableSnapshot(preparedRun), prepared: immutableSnapshot(prepared), authorization, operation, prefix, cut,
    assertCut: assertPreparedCut, dispatchId, nativeInput, nativeOpenState: 'not_attempted', armed: false, revoked: false, closed: false,
    creatorReceiptRef: creator.result.item.receiptRef, stopIntentRef: cut.run.stopIntentRef, observedStop: stop,
    preparedSnapshot: sqlCut(driver, cut.run.id, prefix.admission.source.run.id) };
  return { kind: 'path', publicationOwner: retainOwner(held) };
}

function claimMaintenance(held: Binding, token: PublicationInvocationOwner): InvocationJournalEntry {
  if (held.mode !== 'abort') throw new TypeError('maintenance cannot release a productive publication');
  const input = { runId: held.run.id, expectedRunRevision: held.run.revision, leaseEpoch: held.run.leaseEpoch,
    opId: held.prepared.opId, attempt: 0, dispatchId: held.dispatchId };
  const original = assertPublicationClaimForInvocation(held.driver, held.owner, token, input);
  let outcome: TimeFenceAdvance | undefined, claim: InvocationJournalEntry | undefined;
  held.driver.transaction(connection => {
    const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, held.owner.ownerEpoch, now);
    if (outcome !== 'healthy') return;
    const run = readRun(connection, held.run.id); original.validate(connection, run, held.prepared, now);
    if (!run.stopIntentRef || run.nextStep !== 'delivery' || !['queued', 'running'].includes(run.status)) invalid('maintenance lost its durable stopping cut');
    for (const artifact of original.metadata) insertArtifactMetadata(connection, artifact, now);
    claim = { ...held.prepared, seq: nextJournalSequence(connection, run.id), phase: 'dispatch_claimed', dispatchId: held.dispatchId,
      supervisorInstanceId: held.owner.supervisorInstanceId, stateOwnerEpoch: held.owner.ownerEpoch,
      evidenceRef: original.evidenceRef, evidenceDigest: original.evidenceDigest, budgetDelta: ZERO_BUDGET, timestamp: now };
    appendInvocationJournalEntry(connection, claim);
  });
  requireHealthyFence(outcome);
  if (!claim) invalid('maintenance claim did not commit');
  return claim;
}
function retainOwner(held: Binding): PublicationInvocationOwner {
  const token: PublicationInvocationOwner = Object.freeze({ [ownerBrand]: true as const, run: held.run, opId: held.prepared.opId, attempt: 0 as const,
    revoke() { if (this !== token) throw new TypeError('invalid publication owner receiver'); if (held.retirementFailure) throw held.retirementFailure;
      held.revoked = true; if (!held.closed && held.native) physical(held, () => held.native!.revoke()); },
    close() { if (this !== token) throw new TypeError('invalid publication owner receiver'); if (held.retirementFailure) throw held.retirementFailure;
      if (held.closed) return;
      const failures: unknown[] = [];
      for (const resource of [held.native, held.preflight]) try { resource?.close(); } catch (error) { failures.push(error); }
      if (failures.length) throw held.retirementFailure = new ResourceRetirementError('original publication descriptors did not join', new AggregateError(failures));
      held.closed = true;
    } });
  owners.set(token, held); return token;
}

async function retainBirth(held: Binding, reads: ArtifactCatalog) {
  if (!held.native || held.nativeOpenState !== 'returned') invalid('publication has no original returned native birth');
  if (!held.birth) {
    const active = assertActiveStateOwner(held.driver, held.owner);
    const lock = decodeStateLockIdentity(await readCanonicalArtifact(reads, active.stateLockIdentityRef));
    const actual = readHeldPublicationBirth(held.owner.filesystem, held.native), observedAt = sampleCanonicalNow();
    const inspector = supervisorInspectorIdentity(active), inspectorPlan = planCanonicalArtifact(inspector, inspector.format);
    const value: PublicationArenaBirthV1 = { schemaVersion: 1, format: 'cliq-publication-arena-birth-v1', deliveryRunId: held.run.id,
      deliveryPlanRef: held.authorization.context.planRef, workspaceIdentityRef: held.authorization.context.workspaceIdentityRef,
      workspaceIdentityDigest: held.authorization.context.workspaceIdentityDigest, stateRootIdentityRef: lock.stateRootIdentityRef,
      stateRootIdentityDigest: lock.stateRootIdentityDigest, inspectorIdentityRef: inspectorPlan.ref, inspectorIdentityDigest: inspector.identityDigest,
      sequence: held.mode, operationIndex: held.operation.index, operationId: held.operation.operationId, opId: held.prepared.opId, attempt: 0,
      dispatchId: held.dispatchId, ...actual, observedAt, birthDigest: '' };
    value.birthDigest = digestOmitting(value, 'birthDigest');
    const birthPlan = planCanonicalArtifact(value, value.format);
    held.birth = value; held.birthPlans = [inspectorPlan, birthPlan]; held.birthRef = birthPlan.ref; held.metadata = [];
  }
  for (let index = held.metadata!.length; index < held.birthPlans!.length; index++) {
    const plan = held.birthPlans![index]!;
    held.metadata!.push(await held.artifacts.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind));
  }
}

/** Private generic-reducer friend. A structural attachment or plain metadata
 * cannot supply the birth edge; the issuer owns the actual unarmed operation. */
export function assertPublicationClaimForInvocation(driver: SqliteDriver, owner: StateOwnerContext, token: unknown, input: ClaimInvocationDispatchInput) {
  const held = binding(driver, owner, token); assertCurrent(held);
  if (!held.native || !held.birth || !held.birthRef || held.metadata?.length !== 2 || held.birthPlans?.length !== 2 || held.claim || input.runId !== held.run.id ||
      input.expectedRunRevision !== held.run.revision || input.leaseEpoch !== held.run.leaseEpoch || input.opId !== held.prepared.opId ||
      input.attempt !== 0 || input.dispatchId !== held.dispatchId || input.sandboxLaunchSpecRef !== undefined || input.brokerFenceTokenDigest !== undefined)
    throw new TypeError('publication claim requires its exact original unarmed native birth');
  return { metadata: immutableSnapshot(held.metadata), evidenceRef: held.birthRef, evidenceDigest: held.birth.birthDigest,
    validate(connection: SqliteConnection, run: Run, prepared: InvocationJournalEntry, now: string) {
      assertCurrent(held, connection); held.assertCut(connection); held.preflight && assertPublicationPreflight(driver, owner, held.preflight, connection);
      requireEqual(run, held.run, 'publication original prepared Run'); requireEqual(prepared, held.prepared, 'publication original prepared invocation');
      requireEqual(readInvocationAttempt(connection, run.id, prepared.opId, 0), [held.prepared], 'publication unique original preparation');
      requireEqual(readHeldPublicationBirth(owner.filesystem, held.native!), { arenaId: held.birth!.arenaId, arenaIdentity: held.birth!.arenaIdentity,
        parentIdentity: held.birth!.parentIdentity }, 'publication original held birth');
      if (now < held.birth!.observedAt || parseCanonicalTime(now) - parseCanonicalTime(held.birth!.observedAt) > 5000 ||
          held.mode === 'forward' && now >= held.authorization.grant!.expiresAt)
        throw new KernelStorageError('LEASE_FENCED', 'publication original native birth is stale');
    } };
}

/** Claim once, then release only that original native operation. A failed CAS
 * or SQL attempt keeps its same birth/dispatch and never opens another arena. */
export function claimPublicationInvocation(driver: SqliteDriver, owner: StateOwnerContext, token: PublicationInvocationOwner): Promise<{ run: Run; claim: InvocationJournalEntry }> {
  const held = binding(driver, owner, token);
  if (held.pending) return held.pending;
  held.pending = (async () => {
    assertCurrent(held);
    if (held.claim) {
      if (!held.armed) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication original claim did not release its native operation');
      return { run: readRun(driver, held.run.id), claim: immutableSnapshot(held.claim) };
    }
    const cut = await readRecoveryClosure(driver, held.reads, held.run.id), prefix = await readPublicationPrefix(driver, held.reads, cut);
    if (held.mode === 'abort' && canonicalSha256(cut.run) !== canonicalSha256(held.run)) {
      const previous = held.preparedSnapshot!;
      const current = sqlCut(driver, cut.run.id, prefix.admission.source.run.id);
      const stable = (snapshot: ReturnType<typeof sqlCut>) => {
        const { revision: _revision, updatedAt: _updatedAt, cancelRequested: _cancel, stopIntentRef: _stop, ...run } = snapshot.run;
        return { ...snapshot, run };
      };
      requireEqual(stable(current), stable(previous), 'maintenance original prepared cut except its validated monotonic Stop');
      if (!cut.run.stopIntentRef || cut.run.revision <= held.run.revision || cut.run.updatedAt < held.run.updatedAt ||
          held.run.cancelRequested && !cut.run.cancelRequested || cut.run.stopIntentRef === held.run.stopIntentRef &&
            cut.run.cancelRequested === held.run.cancelRequested)
        invalid('maintenance cannot rebind an unrelated prepared revision');
      await readRetainedAgentStop(driver, held.reads, cut, held.stopIntentRef);
      const stop = await readAgentStop(driver, held.reads, cut);
      await assertPublicationReadCut(driver, held.reads, cut); assertCurrent(held);
      held.run = immutableSnapshot(cut.run); held.observedStop = stop; held.preparedSnapshot = current;
      const fingerprint = canonicalSha256(current);
      held.assertCut = connection => {
        assertActiveStateOwner(connection, owner);
        if (canonicalSha256(sqlCut(connection, held.run.id, prefix.admission.source.run.id)) !== fingerprint)
          throw new KernelStorageError('REVISION_CONFLICT', 'maintenance upgraded Stop cut changed');
      };
    }
    assertCurrent(held); requireEqual(cut.run, held.run, 'publication claim original prepared Run');
    const selected = prefix.entries.get(held.prepared.opId);
    if (!selected || selected.claim || selected.sequence !== held.mode || selected.operation.operationId !== held.operation.operationId)
      invalid('publication claim lost its exact original prepared prefix');
    requireEqual(selected.history, [held.prepared], 'publication original unclaimed preparation');
    if (held.mode === 'forward' && held.operation.index === 0) held.preflight ??= await preparePublicationPreflight(driver, held.reads, owner,
      { runId: held.run.id, expectedRunRevision: held.run.revision, execution: held.execution, task: held.task, worker: held.worker, workspaceRoot: held.root,
        ...(held.signal ? { signal: held.signal } : {}) });
    await assertPublicationReadCut(driver, held.reads, cut); held.assertCut(driver); assertCurrent(held);
    if (held.nativeOpenState === 'unknown') throw new KernelStorageError('RECOVERY_REQUIRED', 'publication factory birth did not return its original handle');
    if (held.nativeOpenState === 'not_attempted') {
      // A throwing factory may have created only part of its physical birth.
      // Never retry/adopt it by derived name or claim that no birth occurred.
      held.nativeOpenState = 'unknown';
      held.native = openHeldPublicationOperation(owner.filesystem, held.root, held.nativeInput);
      held.nativeOpenState = 'returned';
    }
    // The original graph is fixed before the first write. Even an after-write
    // CAS error can only retry these same bytes, never refresh/recreate birth.
    await retainBirth(held, held.reads); assertCurrent(held);
    if (!held.native) invalid('publication original native factory did not return its handle');
    held.claim = held.mode === 'forward'
      ? await claimValidatedInvocation(driver, held.artifacts, owner, { runId: held.run.id, expectedRunRevision: held.run.revision,
        leaseEpoch: held.worker.leaseEpoch, opId: held.prepared.opId, attempt: 0, dispatchId: held.dispatchId }, undefined, token)
      : claimMaintenance(held, token);
    try { held.preflight?.close(); held.preflight = undefined; }
    catch (cause) {
      held.revoked = true;
      try { held.native.revoke(); } catch (failure) { cause = new AggregateError([cause, failure]); }
      throw held.retirementFailure = new ResourceRetirementError('original publication preflight descriptors did not join', cause);
    }
    assertCurrent(held);
    if (held.mode === 'forward') assertLiveDispatchState(driver, owner, held.run.id, held.run.revision, held.worker.leaseEpoch, sampleCanonicalNow());
    held.native.arm(); held.armed = true;
    return { run: readRun(driver, held.run.id), claim: immutableSnapshot(held.claim) };
  })().finally(() => { held.pending = undefined; });
  return held.pending;
}

/** Only the same actual execution can continue into physical progress. The
 * returned original descriptors are never reconstructed from retained refs. */
export function assertOwnedPublicationPath(driver: SqliteDriver, owner: StateOwnerContext, execution: unknown, token: unknown) {
  const held = claimedBinding(driver, owner, execution, token);
  // An already claimed result/cleanup is still owned after Stop or expiry.
  // This friend supplies original facts, never a fresh semantic release.
  assertActiveStateOwner(driver, owner);
  if (held.closed) physical(held, () => readRetiredPublicationArena(owner.filesystem, held.native));
  else physical(held, () => held.native.assertHeld());
  return Object.freeze({ operation: held.operation, plan: held.authorization.context.plan, planRef: held.authorization.context.planRef,
    root: held.root, native: held.native, run: held.run, authorization: held.authorization, worker: held.worker, task: held.task,
    execution: held.execution, armed: held.armed, prepared: held.prepared, claim: held.claim, birth: immutableSnapshot(held.birth), birthRef: held.birthRef });
}

/** Original issuer state only, not an arm permit. A committed-but-unarmed
 * claim can retire without re-entering the productive claim gate; SQL rows or
 * caller booleans cannot supply this native owner's phase. */
export function readOwnedPublicationDispatchState(driver: SqliteDriver, owner: StateOwnerContext, execution: unknown, token: unknown):
  Readonly<{ phase: 'prepared' } | { phase: 'claimed'; armed: boolean }> {
  const held = binding(driver, owner, token);
  if (held.execution !== execution) throw new TypeError('publication dispatch state requires its original execution');
  assertActiveStateOwner(driver, owner);
  if (!held.claim) return Object.freeze({ phase: 'prepared' });
  claimedBinding(driver, owner, execution, token);
  return Object.freeze({ phase: 'claimed', armed: held.armed });
}

function assertUnclaimedPreparation(held: Binding) {
  assertActiveStateOwner(held.driver, held.owner);
  const history = readInvocationAttempt(held.driver, held.run.id, held.prepared.opId, 0);
  requireEqual(history[0], held.prepared, 'publication original unclaimed preparation');
  if (held.claim || held.armed || held.commitAttempted || history.some(entry => entry.phase === 'dispatch_claimed') ||
      history.length !== 1 && !(history.length === 2 && history[1]!.phase === 'failed' && held.preparationClosureRef &&
        history[1]!.errorRef === held.preparationClosureRef))
    invalid('publication preparation retirement cannot replace a claim, effect or another terminal fact');
  if (held.nativeOpenState === 'unknown')
    throw new KernelStorageError('RECOVERY_REQUIRED', 'publication factory may have left an unreturned partial native birth');
}

/** Original producer facts only. This does not recreate a native owner or
 * permit any workspace operation after an undispatched preparation closed. */
export function readOwnedPublicationPreparationClosure(driver: SqliteDriver, owner: StateOwnerContext, execution: unknown,
  token: PublicationInvocationOwner) {
  const held = binding(driver, owner, token);
  if (held.execution !== execution) throw new TypeError('preparation closure requires its exact original execution');
  assertUnclaimedPreparation(held);
  if (!held.revoked || !held.closed || !held.preparationClosure || !held.preparationClosureRef)
    invalid('publication original preparation has not actually retired and joined');
  if (held.preparationClosure.retirement.kind === 'retired') {
    if (!held.native || held.nativeOpenState !== 'returned' || !held.arenaRetired)
      invalid('publication preparation lost its actual returned and retired native owner');
    const actual = physical(held, () => readRetiredPublicationArena(owner.filesystem, held.native!));
    requireEqual(actual.arenaIdentity, held.birth!.arenaIdentity, 'preparation original retired native arena');
    requireEqual(actual.parentIdentity, held.birth!.parentIdentity, 'preparation original retired private parent');
  } else if (held.nativeOpenState !== 'not_attempted' || held.native || held.birth)
    invalid('no-birth preparation cannot conceal a native factory attempt');
  return Object.freeze({ run: held.run, prepared: held.prepared, operation: held.operation, planRef: held.authorization.context.planRef,
    sequence: held.mode, closure: immutableSnapshot(held.preparationClosure), closureRef: held.preparationClosureRef, metadata: metadata(held) });
}

/** Revoke and join the original factory/claim task before proving a genuine
 * unclaimed preparation retired. CAS/SQL retries keep this same owner, birth,
 * closed graph and once-only zero-consumption settlement. */
export async function retirePublicationPreparation(driver: SqliteDriver, owner: StateOwnerContext, execution: unknown,
  token: PublicationInvocationOwner): Promise<Run> {
  const held = binding(driver, owner, token);
  if (held.execution !== execution) throw new TypeError('preparation retirement requires its exact original execution');
  // Synchronous revocation precedes the first await, including a pending
  // factory/claim. No returned native owner may arm after this fence.
  held.revoked = true;
  if (held.native && !held.closed) physical(held, () => held.native!.revoke());
  if (held.preparationRetiring) return held.preparationRetiring;
  held.preparationRetiring = (async () => {
    const pending = held.pending;
    if (pending) try { await pending; }
    catch (error) { if (error instanceof ResourceRetirementError) throw held.retirementFailure ??= error; }
    assertUnclaimedPreparation(held);
    try { held.preflight?.close(); held.preflight = undefined; }
    catch (cause) { throw held.retirementFailure = new ResourceRetirementError('publication preparation preflight did not join', cause); }
    if (!held.preparationClosure) {
      let retirement: PublicationPreparationClosureV1['retirement'];
      if (held.nativeOpenState === 'not_attempted') { held.closed = true; retirement = { kind: 'no_birth' }; }
      else {
        await retainBirth(held, held.artifacts);
        if (!held.preparationDiscardAttempted) {
          held.preparationDiscardAttempted = true;
          physical(held, () => held.native!.discardStage());
          held.preparationDiscarded = true;
        }
        if (!held.preparationDiscarded) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication preparation discard did not return its original outcome');
        // Preparation never reads or asserts destination content. Only its
        // exact original empty private arena is retired here. The helper also
        // resumes its fixed CAS plans after an actual retirement already won.
        await retireArena(held, false);
        retirement = { kind: 'retired', arenaBirthRef: held.birthRef!, slotObservationRefs: [...held.slotObservationRefs!],
          arenaRetirementRef: held.arenaRetirementRef! };
      }
      const active = assertActiveStateOwner(driver, owner), inspector = supervisorInspectorIdentity(active);
      const inspectorRef = (await publishFixed(held, inspector, inspector.format)).ref;
      const closure: PublicationPreparationClosureV1 = { schemaVersion: 1, format: 'cliq-publication-preparation-closure-v1',
        deliveryRunId: held.run.id, deliveryPlanRef: held.authorization.context.planRef, sequence: held.mode,
        operationIndex: held.operation.index, operationId: held.operation.operationId, opId: held.prepared.opId, attempt: 0,
        preparedJournalSeq: held.prepared.seq, requestRef: held.prepared.requestRef, targetRef: held.prepared.target,
        grantRef: held.prepared.grantRef!, dispatchId: held.dispatchId, stateOwnerEpoch: owner.ownerEpoch,
        supervisorInstanceId: owner.supervisorInstanceId, leaseEpoch: held.prepared.leaseEpoch,
        inspectorIdentityRef: inspectorRef, inspectorIdentityDigest: inspector.identityDigest,
        retirement, observedAt: sampleCanonicalNow(), closureDigest: '' };
      closure.closureDigest = digestOmitting(closure, 'closureDigest');
      held.preparationClosure = decodePublicationPreparationClosure(closure);
    }
    held.preparationClosureRef ??= (await publishFixed(held, held.preparationClosure, held.preparationClosure.format)).ref;
    readOwnedPublicationPreparationClosure(driver, owner, execution, token);
    const { preparePublicationPreparationSettlement } = await import('./publication-settlement.js');
    const settlement = await preparePublicationPreparationSettlement(driver, held.artifacts, owner, { execution, publicationOwner: token });
    return (await settlement.settle({ expectedRunRevision: readRun(driver, held.run.id).revision })).run;
  })().finally(() => { held.preparationRetiring = undefined; });
  return held.preparationRetiring;
}
function claimedBinding(driver: SqliteDriver, owner: StateOwnerContext, execution: unknown, token: unknown): Binding & {
  claim: InvocationJournalEntry; native: HeldPublicationOperation; birth: PublicationArenaBirthV1; birthRef: string;
} {
  const held = binding(driver, owner, token);
  if (held.execution !== execution || !held.claim || !held.native || !held.birth || !held.birthRef)
    throw new TypeError('publication progress requires its exact original claimed path owner');
  // The only assignment of this native reference is the genuine issuer above.
  // Reading a recorded negative fact does not invoke assertHeld, nor claim
  // that this original native owner can still observe, clean up or release.
  assertActiveStateOwner(driver, owner);
  const retained = readInvocationAttempt(driver, held.run.id, held.prepared.opId, 0);
  requireEqual(retained.slice(0, 2), [held.prepared, held.claim], 'publication exact original permanent claim');
  return held as Binding & { claim: InvocationJournalEntry; native: HeldPublicationOperation; birth: PublicationArenaBirthV1; birthRef: string };
}

function physical<T>(held: PhysicalBinding, action: () => T): T {
  held.inspectionGate?.();
  try { return action(); }
  catch (error) {
    if (error instanceof ResourceRetirementError) held.retirementFailure ??= error;
    held.physicalFailure = error; throw error;
  }
}
type ProofFields<Value = PublicationProofV1> = Value extends PublicationProofV1 ? Omit<Value, 'schemaVersion' | 'format' | 'deliveryRunId' | 'deliveryPlanRef' |
  'workspaceIdentityRef' | 'workspaceIdentityDigest' | 'inspectorIdentityRef' | 'inspectorIdentityDigest' | 'proofDigest'> : never;
function proof(held: PhysicalBinding, fields: ProofFields): PublicationProofV1 {
  const birth = held.birth!;
  if (held.recoveryOrigin && !['path_observation', 'terminal_receipt', 'path_ambiguity', 'arena_retirement', 'arena_namespace_absence'].includes(fields.kind))
    invalid('publication recovery origin cannot grant another proof kind');
  if (fields.kind === 'arena_namespace_absence' && (!held.recoveryOrigin ||
      fields.recoveryOriginRef !== held.recoveryOrigin.ref || fields.recoveryOriginDigest !== held.recoveryOrigin.digest))
    invalid('current namespace proof requires its genuine original-claim owner-death origin');
  const value = { schemaVersion: 1, format: 'cliq-publication-proof-v1', deliveryRunId: held.run.id,
    deliveryPlanRef: birth.deliveryPlanRef, workspaceIdentityRef: birth.workspaceIdentityRef, workspaceIdentityDigest: birth.workspaceIdentityDigest,
    inspectorIdentityRef: held.proofInspector?.ref ?? birth.inspectorIdentityRef,
    inspectorIdentityDigest: held.proofInspector?.identityDigest ?? birth.inspectorIdentityDigest,
    ...(held.recoveryOrigin ? { recoveryOriginRef: held.recoveryOrigin.ref, recoveryOriginDigest: held.recoveryOrigin.digest } : {}),
    ...fields, proofDigest: '' };
  value.proofDigest = digestOmitting(value, 'proofDigest'); return decodePublicationProof(value);
}
async function publishFixed(held: PhysicalBinding, value: unknown, format: string): Promise<PublishedArtifact> {
  const plan = planCanonicalArtifact(value, format), publications = held.publications ??= new Map();
  let selected = publications.get(plan.ref);
  if (!selected) { selected = { plan }; publications.set(plan.ref, selected); }
  selected.artifact ??= await held.artifacts.publishBytes(selected.plan.bytes, selected.plan.mediaType, selected.plan.schemaKind);
  return selected.artifact;
}
function metadata(held: PhysicalBinding): PublishedArtifact[] {
  return [...(held.metadata ?? []), ...(held.payloadMetadata ?? []), ...[...(held.publications?.values() ?? [])].map(value => {
    if (!value.artifact) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication has an unfinished original immutable graph');
    return value.artifact;
  }), ...(held.progress?.metadata ?? [])];
}
function observation(held: PhysicalBinding, location: PublicationLocationV1, native: NativePublicationObservation,
  parent: { identity: HeldWorkspaceRoot['identity']; linkCount: number }): PublicationPathObservationV1 {
  const base = { location, parentDeviceId: parent.identity.deviceId, parentFileId: parent.identity.fileId, parentLinkCount: parent.linkCount };
  if (native.kind === 'absent') return { ...base, state: { kind: 'absent' } };
  if (native.kind === 'unsupported') invalid('publication observed an unsupported actual entry');
  const state = native.kind === 'file' ? (() => {
    if (!native.digest || native.linkCount !== 1) return invalid('publication actual file has no complete single-link digest');
    return { kind: 'file' as const, mode: native.mode, digest: native.digest };
  })() : native.kind === 'directory' ? (() => {
    if (native.empty === undefined) return invalid('publication actual directory has no complete empty observation');
    return { kind: 'directory' as const, mode: native.mode, empty: native.empty,
      identityDigest: publicationDirectoryIdentityDigest(held.birth!.workspaceIdentityDigest, { ...native.identity, mode: native.mode }) };
  })() : (() => {
    if (!native.digest || native.target === undefined) return invalid('publication actual symlink has no complete target');
    return { kind: 'symlink' as const, target: native.target, digest: native.digest };
  })();
  return { ...base, state, entryDeviceId: native.identity.deviceId, entryFileId: native.identity.fileId, entryLinkCount: native.linkCount };
}
async function publishObservation(held: PhysicalBinding, key: string, value: PublicationPathObservationV1): Promise<string> {
  const observations = held.observations ??= new Map(); let item = observations.get(key);
  if (!item) {
    const candidate = proof(held, { kind: 'path_observation', observation: value, observedAt: sampleCanonicalNow() });
    if (candidate.kind !== 'path_observation') throw new TypeError('publication original observation kind differs');
    item = candidate; observations.set(key, item);
  } else requireEqual(item.observation, value, 'publication original fixed descriptor observation');
  return (await publishFixed(held, item, item.format)).ref;
}
async function completionCut(held: Binding): Promise<RecoveryClosureV1> {
  assertActiveStateOwner(held.driver, held.owner);
  const cut = await readRecoveryClosure(held.driver, held.artifacts, held.run.id);
  const baseline = held.afterProgressRun ?? held.run;
  const stable = (run: Run) => {
    const { revision: _revision, updatedAt: _updatedAt, cancelRequested: _cancel, stopIntentRef: _stop, ...rest } = run;
    return rest;
  };
  requireEqual(stable(cut.run), stable(baseline), 'publication completion original non-stop Run cut');
  const expectedJournal = [...held.cut.journal, held.prepared, held.claim!];
  requireEqual(cut.journal, expectedJournal, 'publication completion unique original dispatch prefix');
  if (cut.run.revision !== baseline.revision && !cut.run.stopIntentRef)
    throw new KernelStorageError('REVISION_CONFLICT', 'publication completion revision changed without its actual StopIntent');
  if (held.observedStop && !cut.run.stopIntentRef) invalid('publication completion lost its monotonic original StopIntent');
  if (cut.run.stopIntentRef) {
    const current = await readAgentStop(held.driver, held.artifacts, cut);
    if (held.observedStop && canonicalSha256(current) !== canonicalSha256(held.observedStop) && selectAgentStop(held.observedStop, current) !== current)
      invalid('publication completion replaced its winning original StopIntent');
    held.observedStop = current;
  }
  await assertPublicationReadCut(held.driver, held.artifacts, cut); return cut;
}
function canRelease(held: Binding): boolean {
  if (!held.armed || held.revoked || held.closed || held.signal?.aborted) return false;
  const run = readRun(held.driver, held.run.id);
  if (held.mode === 'forward') {
    if (run.stopIntentRef || run.cancelRequested || sampleCanonicalNow() >= run.deadlineAt) return false;
  } else {
    if (!run.stopIntentRef || run.nextStep !== 'delivery' || !['queued', 'running'].includes(run.status) ||
        run.frontierRef !== held.run.frontierRef || run.leaseEpoch !== held.run.leaseEpoch)
      invalid('maintenance lost its exact original stopped frontier and epoch');
    if (run.stopIntentRef !== canonicalSha256(held.observedStop))
      throw new KernelStorageError('REVISION_CONFLICT', 'maintenance must read the complete upgraded Stop before release');
  }
  assertCurrent(held); return true;
}
async function readOriginal(held: Binding) {
  if (held.originalVerified || held.nativeInput.expected.kind === 'absent') return;
  for (;;) {
    if (!canRelease(held)) return;
    if (physical(held, () => held.native!.readOriginalChunk()) === null) { held.originalVerified = true; return; }
    await yieldToLoop();
  }
}
async function stage(held: Binding) {
  if (held.stageFinished) return;
  if (!held.stageStarted) { physical(held, () => held.native!.stage()); held.stageStarted = true; }
  if (held.nativeInput.desired.kind === 'file') {
    const desired = held.nativeInput.desired;
    for await (const bytes of held.artifacts.readChunks(desired.digest, desired.byteCount)) {
      if (!canRelease(held)) return;
      physical(held, () => held.native!.writeChunk(bytes));
    }
  }
  for (;;) {
    if (!canRelease(held)) return;
    if (physical(held, () => held.native!.finishStage())) { held.stageFinished = true; return; }
    await yieldToLoop();
  }
}
function emptyEntries(): WorkspaceEntryManifest {
  const value: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: [], entryCount: 0, byteCount: 0, treeDigest: '' };
  value.treeDigest = canonicalSha256({ schemaVersion: 1, format: value.format, entries: value.entries }); return value;
}
async function preservePreimage(held: PhysicalBinding) {
  if (held.preservedRef || held.nativeInput.expected.kind === 'absent') return;
  physical(held, () => held.native!.restartRead('preimage'));
  const expected = held.nativeInput.expected;
  if (expected.kind !== 'directory') {
    const limit = expected.kind === 'file' ? expected.byteCount : Buffer.byteLength(expected.target);
    const stream = async function* () {
      for (;;) { const bytes = physical(held, () => held.native!.readPreimageChunk()); if (bytes === null) return;
        yield bytes; await yieldToLoop(); }
    };
    const payload = await held.artifacts.publishChunks(stream(), 'application/octet-stream', 'cliq-publication-preimage-bytes-v1', limit);
    if (payload.ref !== expected.digest || payload.byteLength !== limit) invalid('publication preserved preimage differs from its actual original bytes');
    // The registered payload is a fully exhausted native stream; labels never
    // replace the original inode/full hash gate in finishCleanup.
    (held.payloadMetadata ??= []).push(payload);
    held.preservedRef = payload.ref; return;
  }
  if (physical(held, () => held.native!.readPreimageChunk()) !== null) invalid('publication old directory was not empty');
  const actual = physical(held, () => held.native!.observe());
  if (!actual.quarantine || !('quarantineName' in held.operation)) invalid('publication empty directory lost its actual quarantine');
  const location = { kind: 'publication_arena' as const, arenaId: held.birth!.arenaId, component: held.operation.quarantineName };
  const quarantined = observation(held, location, actual.quarantine, { identity: actual.arena.identity, linkCount: actual.arena.linkCount });
  const quarantineRef = await publishObservation(held, 'quarantine', quarantined), entries = emptyEntries();
  const entriesRef = (await publishFixed(held, entries, entries.format)).ref;
  const directory = { schemaVersion: 1, format: 'cliq-publication-directory-preimage-v1', deliveryRunId: held.run.id,
    deliveryPlanRef: held.birth!.deliveryPlanRef, operationId: held.operation.operationId, opId: held.prepared.opId, attempt: 0,
    beforeObservationRef: held.beforeRef!, quarantineObservationRef: quarantineRef, entriesRef, preimageDigest: '' };
  directory.preimageDigest = digestOmitting(directory, 'preimageDigest');
  held.preservedRef = (await publishFixed(held, directory, directory.format)).ref;
}
async function persistProgress(held: Binding) {
  if (held.progressCommitted) return;
  const cut = await completionCut(held);
  if (!held.progress) {
    if (held.nativeInput.desired.kind !== 'absent') {
      for (;;) { if (physical(held, () => held.native!.readDestinationChunk()) === null) break; await yieldToLoop(); }
    }
    const actual = physical(held, () => held.native!.observe());
    const destination = observation(held, { kind: 'workspace', path: held.operation.path }, actual.destination, actual.parent);
    held.destinationRef ??= await publishObservation(held, 'destination', destination);
    let transientObservationRef: string | undefined;
    if (actual.quarantine && actual.quarantine.kind !== 'absent' && 'quarantineName' in held.operation)
      transientObservationRef = await publishObservation(held, 'quarantine', observation(held, { kind: 'publication_arena', arenaId: held.birth!.arenaId,
        component: held.operation.quarantineName }, actual.quarantine, { identity: actual.arena.identity, linkCount: actual.arena.linkCount }));
    const item: Extract<PublicationPathProgressItem, { state: 'desired_committed_cleanup_pending' }> = { schemaVersion: 1, kind: 'publication_path_progress',
      itemId: publicationProgressItemId(held.run.id, held.prepared.opId, 0), runId: held.run.id, deliveryPlanRef: held.birth!.deliveryPlanRef,
      operationIndex: held.operation.index, operationId: held.operation.operationId, opId: held.prepared.opId, attempt: 0,
      state: 'desired_committed_cleanup_pending', beforeObservationRef: held.beforeRef!, destinationEvidenceRef: held.destinationRef,
      ...(held.preservedRef ? { preservedPreimageRef: held.preservedRef } : {}), ...(transientObservationRef ? { transientObservationRef } : {}), createdAt: sampleCanonicalNow() };
    decodePublicationPathProgressItem(item);
    const context = decodeContextManifest(await readCanonicalArtifact(held.artifacts, cut.latestCheckpoint.contextManifestRef));
    const existingItems = [];
    for (const row of cut.items) existingItems.push({ itemSeq: row.itemSeq, itemRef: row.payloadRef, item: await readCanonicalArtifact<ContinuationItem>(held.artifacts, row.payloadRef) });
    const frontier = await readCanonicalArtifact<RunFrontier>(held.artifacts, cut.run.frontierRef!);
    held.progress = { item, graph: planContinuationCommit(held.artifacts, { context, existingItems, items: [item], frontier,
      checkpointId: publicationProgressCheckpointId(held.run.id, held.prepared.opId, 0), workspaceStateRef: cut.latestCheckpoint.workspaceStateRef }) };
  }
  const graph = await held.progress.graph.publish(); held.progress.metadata = graph.metadata;
  const current = await completionCut(held), snapshot = canonicalSha256(sqlCut(held.driver, held.run.id, held.authorization.verified.admission.source.run.id));
  const assertCut = (connection: SqliteConnection) => {
    assertActiveStateOwner(connection, held.owner);
    if (canonicalSha256(sqlCut(connection, held.run.id, held.authorization.verified.admission.source.run.id)) !== snapshot)
      throw new KernelStorageError('REVISION_CONFLICT', 'publication progress current Stop or original dispatch cut changed');
  };
  let outcome: TimeFenceAdvance | undefined, committedRun: Run | undefined;
  held.driver.transaction(connection => {
    assertCut(connection); const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, held.owner.ownerEpoch, now);
    if (outcome !== 'healthy') return;
    if (now < current.run.updatedAt || now < held.progress!.item.createdAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication progress has a noncausal commit time');
    for (const artifact of metadata(held)) insertArtifactMetadata(connection, artifact, now);
    assertCut(connection);
    graph.commit(connection, current.run, held.claim!.seq, now);
    connection.prepare('UPDATE runs SET revision=revision+1, updated_at=? WHERE id=? AND revision=?')
      .run(now, held.run.id, BigInt(current.run.revision));
    committedRun = readRun(connection, held.run.id);
    appendRunStateEvent(connection, committedRun, now);
  });
  requireHealthyFence(outcome);
  if (!committedRun) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication progress did not commit under its original time fence');
  // Only a successful return from the actual transaction can open cleanup.
  held.progressCommitted = true;
  // Capture the committed SQL projection before an asynchronous retained read.
  // If that read fails, the original owner must retry it, not insert this same
  // immutable item/Checkpoint or lose its already-durable cleanup barrier.
  held.afterProgressRun = immutableSnapshot(committedRun);
  await completionCut(held);
}

async function originalBefore(held: Binding, authorityReducing = false) {
  if (!held.before) {
    if (held.nativeInput.expected.kind !== 'absent' && !held.originalVerified) {
      for (;;) {
        if (!authorityReducing && !canRelease(held)) return;
        if (physical(held, () => held.native!.readOriginalChunk()) === null) { held.originalVerified = true; break; }
        await yieldToLoop();
      }
    }
    const actual = physical(held, () => held.native!.observe());
    held.before = observation(held, { kind: 'workspace', path: held.operation.path }, actual.destination, actual.parent);
  }
  held.beforeRef ??= await publishObservation(held, 'before', held.before);
}
async function retireArena(held: PhysicalBinding, observeDestination = true, publishRetirement = true) {
  if (!held.finalObservations) {
    const actual = physical(held, () => held.native!.observe());
    if (observeDestination) held.finalDestination = observation(held, { kind: 'workspace', path: held.operation.path }, actual.destination, actual.parent);
    const values: PublicationPathObservationV1[] = [];
    for (const location of publicationEnvelopeLocations({ birth: held.birth, operation: held.operation })) {
      if (location.kind !== 'publication_arena') invalid('publication claimed envelope is not private');
      const native = 'stagingName' in held.operation && held.operation.stagingName === location.component || held.operation.kind === 'mkdir' && location.component === 'desired'
        ? actual.staging : actual.quarantine;
      if (!native || native.kind !== 'absent') invalid('publication original private slot is not actually absent');
      values.push(observation(held, location, native, { identity: actual.arena.identity, linkCount: actual.arena.linkCount }));
    }
    held.finalObservations = values;
  }
  held.slotObservationRefs ??= [];
  for (let index = held.slotObservationRefs.length; index < held.finalObservations.length; index++)
    held.slotObservationRefs.push(await publishObservation(held, `absent:${index}`, held.finalObservations[index]!));
  if (!held.arenaRetired) { physical(held, () => held.native!.finishArenaRetirement()); held.arenaRetired = true; }
  if (!held.closed) {
    try { held.native!.close(); held.closed = true; }
    catch (cause) { throw held.retirementFailure = cause instanceof ResourceRetirementError ? cause : new ResourceRetirementError('publication original operation did not join', cause); }
  }
  if (!held.arenaRetirementRef) {
    const actual = readRetiredPublicationArena(held.owner.filesystem, held.native!);
    requireEqual(actual.arenaIdentity, held.birth!.arenaIdentity, 'publication original retired arena');
    requireEqual(actual.parentIdentity, held.birth!.parentIdentity, 'publication original retired private parent');
    if (!held.arenaRetirementProof) {
      const value = proof(held, { kind: 'arena_retirement', arenaId: actual.arenaId, arenaIdentity: actual.arenaIdentity,
        parentIdentity: actual.parentIdentity, stateRootIdentityRef: held.birth!.stateRootIdentityRef, stateRootIdentityDigest: held.birth!.stateRootIdentityDigest,
        arenaAbsent: true, arenaParentFsyncCompleted: true, retirementObservation: actual.retirementObservation, observedAt: sampleCanonicalNow() });
      if (value.kind !== 'arena_retirement') invalid('publication retirement changed its original fixed kind');
      held.arenaRetirementProof = value;
    }
    // Store the canonical observation before writing, including an after-write
    // failure. A retry rechecks this original retired owner, not a new arena.
    const retirementProof = held.arenaRetirementProof;
    if (!retirementProof) invalid('publication retirement lost its retained actual observation');
    if (publishRetirement) held.arenaRetirementRef = (await publishFixed(held, retirementProof, retirementProof.format)).ref;
  }
}
async function retainActualPreimage(held: Binding) {
  if (held.actualPreimageRef || held.mode !== 'forward' || !['replace', 'delete'].includes(held.operation.kind)) return;
  let actual: ReturnType<HeldPublicationOperation['describeActualPreimage']>;
  try { actual = physical(held, () => held.native!.describeActualPreimage()); }
  catch (error) { if (error instanceof ResourceRetirementError) throw error; return; }
  if (actual.kind !== 'file' && actual.kind !== 'symlink' && actual.kind !== 'directory' || !/^(0|[1-9][0-9]*)$/u.test(actual.byteCount)) return;
  const count = Number(actual.byteCount), maximum = actual.kind === 'symlink' ? 4096 : 256 * 1024 * 1024;
  if (!Number.isSafeInteger(count) || count > maximum) return;
  let payload: PublicationActualPreimageV1['payload'];
  try {
    if (actual.kind === 'directory') {
      const retained = await preserveActualEmptyPublicationDirectory(held.artifacts, held.native!);
      requireEqual(retained.actual, actual, 'publication original actual empty directory');
      requireEqual(physical(held, () => held.native!.describeActualPreimage()), actual, 'publication original actual empty directory after preservation');
      (held.payloadMetadata ??= []).push(retained.metadata); payload = retained.payload;
    } else {
      held.native!.restartRead('actual_preimage');
      const stream = async function* () {
        for (;;) { const bytes = physical(held, () => held.native!.readActualPreimageChunk()); if (bytes === null) return;
          yield bytes; await yieldToLoop(); }
      };
      const bytes = await held.artifacts.publishChunks(stream(), 'application/octet-stream', 'cliq-publication-actual-preimage-bytes-v1', count);
      if (bytes.byteLength !== count) invalid('publication actual displaced bytes do not match their complete native extent');
      (held.payloadMetadata ??= []).push(bytes);
      payload = { kind: actual.kind, bytesRef: bytes.ref, bytesDigest: bytes.ref, byteCount: bytes.byteLength };
    }
  } catch (error) {
    if (error instanceof ResourceRetirementError || isJoinedCasPublicationFailure(error)) throw error;
    return; // Incomplete/invalid native bytes are not preserved-data evidence.
  }
  const value: PublicationActualPreimageV1 = { schemaVersion: 1, format: 'cliq-publication-actual-preimage-v1', deliveryRunId: held.run.id,
    deliveryPlanRef: held.birth!.deliveryPlanRef, sequence: 'forward', operationIndex: held.operation.index, operationId: held.operation.operationId,
    opId: held.prepared.opId, attempt: 0, dispatchId: held.claim!.dispatchId!, arenaBirthRef: held.birthRef!, location: actual.location,
    physical: { identity: actual.identity, mode: actual.mode, linkCount: actual.linkCount, byteCount: actual.byteCount }, payload, preimageDigest: '' };
  value.preimageDigest = digestOmitting(value, 'preimageDigest'); decodePublicationActualPreimage(value);
  held.actualPreimageRef = (await publishFixed(held, value, value.format)).ref;
}
async function retainUnknown(held: Binding): Promise<PublicationPathDisposition> {
  await retainActualPreimage(held);
  if (!held.unknownProof) {
    const value = proof(held, { kind: 'path_ambiguity', sequence: held.mode, operationIndex: held.operation.index,
      operationId: held.operation.operationId, opId: held.prepared.opId, attempt: 0, launchDispatchId: held.claim!.dispatchId!,
      failure: held.ambiguity ?? 'transient_state_ambiguous', lastKnownObservationRefs: [...new Set([held.beforeRef, held.destinationRef]
        .filter((value): value is string => value !== undefined))].sort(),
      ...(held.actualPreimageRef ? { preservedActualPreimageRef: held.actualPreimageRef } : {}), observedAt: sampleCanonicalNow() });
    if (value.kind !== 'path_ambiguity') invalid('publication ambiguity changed its fixed kind');
    held.unknownProof = value;
  }
  const unknownProof = held.unknownProof;
  if (!unknownProof) invalid('publication ambiguity lost its retained actual observation');
  const artifact = await publishFixed(held, unknownProof, unknownProof.format);
  held.completion = { evidence: unknownProof, evidenceRef: artifact.ref, metadata: metadata(held) };
  return held.disposition = Object.freeze({ disposition: 'unknown' });
}
async function retireUnstarted(held: Binding): Promise<PublicationPathDisposition> {
  await completionCut(held); await originalBefore(held, true);
  held.revoked = true; physical(held, () => held.native!.revoke());
  physical(held, () => held.native!.discardStage());
  await retireArena(held);
  held.completion = { evidence: held.observations!.get('before')!, evidenceRef: held.beforeRef!, metadata: metadata(held) };
  return held.disposition = Object.freeze({ disposition: 'stopped_before_effect' });
}

async function inspectMaintenanceContents(held: Binding): Promise<PublicationPathDisposition | undefined> {
  if (held.mode !== 'abort') return;
  const profile = decodeSandboxProfile(await readCanonicalArtifact(held.reads, held.cut.runSpec.sandboxProfileRef));
  const actual = await observePublicationMaintenancePath(held.root, { path: held.operation.path,
    workspaceIdentityDigest: held.authorization.context.workspaceIdentityDigest,
    completedDescendants: await completedDescendants(held.driver, held.reads, held.prefix, held.operation.path),
    maxSingleFileBytes: profile.resources.maxSingleFileBytes, maxBytes: profile.resources.maxGenerationBytes,
    ...(held.signal ? { signal: held.signal } : {}) });
  const expected = held.nativeInput.expected;
  if (expected.kind !== 'directory' || actual.observation.state.kind !== 'directory' ||
      actual.observation.entryDeviceId !== expected.identity.deviceId || actual.observation.entryFileId !== expected.identity.fileId ||
      actual.observation.state.mode !== expected.mode)
    invalid('maintenance target differs from the actual original directory creator');
  if (actual.classification === 'empty_directory') return;
  if (actual.classification !== 'planned_descendants') invalid('maintenance waits on unexpected original directory contents');
  // A nonempty directory is never passed to readOriginal/commit/rmdir. Only
  // complete actual descendants backed by the original forward receipts can
  // yield this retained outcome, under this same zero-budget claim.
  held.before = actual.observation;
  held.beforeRef ??= await publishObservation(held, 'before', actual.observation);
  const observedRefs = [];
  for (const entry of actual.descendants) observedRefs.push(await publishObservation(held,
    `retained:${entry.operationId}`, entry.observation));
  const value = proof(held, { kind: 'planned_descendant', abortOperationId: held.operation.operationId,
    retainedDescendantOperationIds: actual.descendants.map(entry => entry.operationId), observationRefs: observedRefs,
    observedAt: sampleCanonicalNow() });
  const artifact = await publishFixed(held, value, value.format);
  await completionCut(held);
  held.revoked = true; physical(held, () => held.native!.revoke()); physical(held, () => held.native!.discardStage());
  await retireArena(held);
  held.completion = { evidence: value, evidenceRef: artifact.ref, metadata: metadata(held) };
  return held.disposition = Object.freeze({ disposition: 'retained_planned_descendant' });
}

/** One actual native effect and durable cleanup barrier, owned by the same
 * invocation token. A caller cannot supply bytes, progress refs or callbacks. */
export function advancePublicationPath(driver: SqliteDriver, owner: StateOwnerContext, execution: unknown,
  token: PublicationInvocationOwner): Promise<PublicationPathDisposition> {
  const held = claimedBinding(driver, owner, execution, token);
  if (held.advancing) return held.advancing;
  // A previously recorded ambiguity can be read, not healed into a positive
  // hold by a later assertHeld or reused as a fresh semantic release.
  if (held.disposition?.disposition === 'unknown') return Promise.resolve(held.disposition);
  if (held.disposition) {
    assertOwnedPublicationPath(driver, owner, execution, token);
    return Promise.resolve(held.disposition);
  }
  if (held.failure) return Promise.reject(held.failure);
  held.advancing = (async () => {
    assertOwnedPublicationPath(driver, owner, execution, token);
    await completionCut(held);
    if (held.ambiguity) return retainUnknown(held);
    if (!held.commitAttempted) {
      if (!canRelease(held)) return retireUnstarted(held);
      const retained = await inspectMaintenanceContents(held);
      if (retained) return retained;
      await readOriginal(held);
      if (!canRelease(held)) return retireUnstarted(held);
      await originalBefore(held); await stage(held);
      if (!canRelease(held) || !held.stageFinished) return retireUnstarted(held);
      // The flag is synchronous and precedes the real syscall. A lost ACK or
      // throw can only reconcile this original handle, never call commit again.
      held.commitAttempted = true;
      try { physical(held, () => held.native!.commit()); held.committed = true; }
      catch (error) { if (error instanceof ResourceRetirementError) throw error; }
    }
    if (!held.committed) {
      const reconciled = physical(held, () => held.native!.reconcile());
      if (reconciled === 'unstarted') return retireUnstarted(held);
      if (reconciled === 'cleaned' && !held.progressCommitted) invalid('publication preimage disappeared without its actual durable progress');
      held.committed = true; held.cleaned = reconciled === 'cleaned';
    }
    await preservePreimage(held); await persistProgress(held);
    if (!held.progressCommitted) invalid('publication cleanup has no original committed progress');
    if (!held.cleaned) { physical(held, () => held.native!.finishCleanup()); held.cleaned = true; }
    await retireArena(held);
    if (!held.receiptProof) {
      const parent = held.nativeInput.parents.at(-1)!;
      const value = proof(held, { kind: 'terminal_receipt', sequence: held.mode, operationIndex: held.operation.index,
        operationId: held.operation.operationId, opId: held.prepared.opId, attempt: 0, before: held.before!, after: held.finalDestination!,
        ...(held.preservedRef ? { preservedPreimageRef: held.preservedRef } : {}), transientFinalObservations: held.finalObservations!,
        parentIdentityBeforeDigest: publicationDirectoryIdentityDigest(held.birth!.workspaceIdentityDigest, parent),
        parentIdentityAfterDigest: publicationDirectoryIdentityDigest(held.birth!.workspaceIdentityDigest, parent), directoryFsyncCompleted: true, observedAt: sampleCanonicalNow() });
      if (value.kind !== 'terminal_receipt') invalid('publication receipt changed its fixed kind');
      held.receiptProof = value;
    }
    const receipt = held.receiptProof;
    if (!receipt) invalid('publication completion lost its retained actual receipt');
    const artifact = await publishFixed(held, receipt, receipt.format);
    held.completion = { evidence: receipt, evidenceRef: artifact.ref, receiptRef: artifact.ref, metadata: metadata(held) };
    noteNormalPublicationRetirement(held.owner.filesystem, held.native!, { runId: held.claim!.runId,
      planRef: held.authorization.context.planRef, opId: held.claim!.opId, attempt: held.claim!.attempt, dispatchId: held.claim!.dispatchId! });
    return held.disposition = Object.freeze({ disposition: 'received' });
  })().catch(async error => {
    if (error instanceof ResourceRetirementError) { held.retirementFailure ??= error; throw error; }
    if (isJoinedCasPublicationFailure(error) || isRolledBackSqliteTransactionFailure(driver, error) ||
        error instanceof KernelStorageError && error.code === 'REVISION_CONFLICT') throw error;
    if (error === held.physicalFailure) { held.ambiguity = 'transient_state_ambiguous'; return retainUnknown(held); }
    held.failure = error; throw error;
  }).finally(() => { held.advancing = undefined; });
  return held.advancing;
}

/** Native facts from this exact owner only. This prepares no settlement and
 * cannot commit a last-path result/Checkpoint ahead of the terminal Run SQL. */
export function readOwnedPublicationCompletion(driver: SqliteDriver, owner: StateOwnerContext, execution: unknown, token: unknown) {
  const held = claimedBinding(driver, owner, execution, token);
  if (!held.disposition || !held.completion) invalid('publication original physical completion is not available');
  if (held.disposition.disposition === 'unknown') return Object.freeze({
    disposition: 'unknown' as const, operation: held.operation, plan: held.authorization.context.plan, planRef: held.authorization.context.planRef,
    run: held.run, prepared: held.prepared, claim: held.claim, birth: immutableSnapshot(held.birth), birthRef: held.birthRef,
    ...immutableSnapshot(held.completion), progressItem: held.progress?.item, progressCommitted: held.progressCommitted === true,
    isLastForwardPath: held.mode === 'forward' && held.operation.index === held.authorization.context.plan.forwardOperations.length - 1 });
  const original = assertOwnedPublicationPath(driver, owner, execution, token);
  return Object.freeze({ ...original, disposition: held.disposition.disposition, ...immutableSnapshot(held.completion),
    progressItem: held.progress?.item, progressCommitted: held.progressCommitted === true,
    slotObservationRefs: Object.freeze([...(held.slotObservationRefs ?? [])]), arenaRetirementRef: held.arenaRetirementRef,
    isLastForwardPath: held.mode === 'forward' && held.operation.index === held.authorization.context.plan.forwardOperations.length - 1 });
}

/** Pure association only. A matching data record supplies no original owner,
 * native retirement, cleanup permit or retained full-R validation. */
export function assertPublicationReconciledRetirement(entry: RetainedPublicationOperation, retired: ReconciledPublicationRetirement): void {
  const result = entry.result?.item, terminal = entry.history.at(-1), unknown = entry.history.find(row => row.phase === 'unknown');
  const completed = retired.disposition === 'received';
  if (!['received', 'stopped_before_effect'].includes(retired.disposition) || !result ||
      result.outcome !== (completed ? 'completed' : 'failed') || !unknown || unknown.evidenceRef !== retired.unknownEvidenceRef ||
      terminal?.phase !== (completed ? 'completed' : 'failed') || terminal.seq <= unknown.seq ||
      terminal.evidenceRef !== retired.evidenceRef || terminal.evidenceDigest !== retired.evidence.proofDigest ||
      result.evidenceRef !== retired.evidenceRef || result.reconciliationEvidenceRef !== retired.wrapperRef ||
      result.reconciliationEvidenceDigest !== retired.wrapper.evidenceDigest ||
      canonicalSha256(retired.evidence) !== retired.evidenceRef || canonicalSha256(retired.wrapper) !== retired.wrapperRef ||
      retired.wrapper.outcome !== 'subject_observation' || retired.wrapper.subjectEvidenceKind !== 'publication' ||
      retired.wrapper.subjectEvidenceRef !== retired.evidenceRef || retired.wrapper.observedAt < retired.wrapper.probeStartedAt ||
      retired.wrapper.observedAt > retired.wrapper.probeDeadlineAt ||
      retired.wrapper.subjectEvidenceDigest !== retired.evidence.proofDigest || retired.wrapper.observedAt !== retired.evidence.observedAt ||
      (completed ? retired.evidence.kind !== 'terminal_receipt' || result.receiptRef !== retired.evidenceRef || terminal.receiptRef !== retired.evidenceRef
        : retired.evidence.kind !== 'path_observation' || result.receiptRef !== undefined))
    invalid('publication abort requires the exact durably resolved original inspection result');
  requireEqual(entry.prepared, retired.prepared, 'publication reconciled original preparation');
  requireEqual(entry.claim, retired.claim, 'publication reconciled original permanent claim');
  requireEqual(entry.birth, retired.birth, 'publication reconciled original native birth');
  requireEqual(entry.operation, retired.operation, 'publication reconciled original planned operation');
  if (entry.planRef !== retired.planRef) invalid('publication reconciled retirement changed its original Plan');
  requireEqual(result.retirement, retired.retirement, 'publication reconciled original actual retirement');
}

/** Abort-only original-owner facts after a timely genuine inspection. The
 * complete retained prefix must independently contain the same resolved edge;
 * an UNKNOWN or a late audit cannot acquire this original owner's retirement. */
export function readOwnedPublicationReconciledRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, token: unknown, entry: RetainedPublicationOperation) {
  const held = binding(driver, owner, token);
  if (held.execution !== execution || held.artifacts !== artifacts)
    throw new TypeError('publication retirement requires its exact original execution and artifact catalog');
  claimedBinding(driver, owner, execution, token);
  const retired = reconciledRetirements.get(held);
  if (!retired || held.disposition?.disposition !== 'unknown' || !held.completion || !held.closed || !held.arenaRetired)
    invalid('publication original UNKNOWN has no genuinely joined resolved retirement');
  const actual = physical(held, () => readRetiredPublicationArena(owner.filesystem, held.native!));
  requireEqual(actual, retired.actual, 'publication reconciled actual original joined arena');
  if (held.completion.evidenceRef !== retired.data.unknownEvidenceRef)
    invalid('publication reconciled retirement replaced its original immutable UNKNOWN');
  assertPublicationReconciledRetirement(entry, retired.data);
  return immutableSnapshot(retired.data);
}

const reconciliationBrand: unique symbol = Symbol('OwnedPublicationReconciliationResult');
/** One actual observation of the original permanently claimed path. This is
 * not a new publication owner, dispatch, release gate or caller proof. */
export type OwnedPublicationReconciliationResult = Readonly<{ readonly [reconciliationBrand]: true }>;
const lateObservationBrand: unique symbol = Symbol('OwnedPublicationLateObservation');
/** The same producer's immutable late fact. It is not probe evidence and can
 * only append audit data; in particular it cannot settle or clear the wait. */
export type OwnedPublicationLateObservation = Readonly<{ readonly [lateObservationBrand]: true }>;
export type OwnedPublicationReconciliationCompletion = OwnedPublicationReconciliationResult | OwnedPublicationLateObservation;
const reconciliationProgressBrand: unique symbol = Symbol('OwnedPublicationReconciliationProgress');
/** An already committed, same-task SQL delta; never a cleanup or result permit. */
export type OwnedPublicationReconciliationProgress = Readonly<{ readonly [reconciliationProgressBrand]: true }>;
type ReconciliationSelection = NonNullable<Awaited<ReturnType<typeof readPublicationReconciliation>>>;
type ReconciliationContinuation = { context: ContextManifest; existingItems: ContextItem[]; frontier: RunFrontier };
function snapshotPublicationAuthorization(authorization: Authorization) {
  const { evaluator: _evaluator, ...data } = authorization;
  return immutableSnapshot(data);
}
function snapshotPublicationEntry(entry: RetainedPublicationOperation) {
  const { authorization, ...data } = entry;
  return { ...immutableSnapshot(data), authorization: snapshotPublicationAuthorization(authorization) };
}
/** Pure data-copy seam only; no validation, observation or authority is minted. */
export function snapshotPublicationReconciliationPrefix(prefix: Prefix) {
  const { authorization, entries, forward, abort, abortResults, ...data } = prefix;
  return { ...immutableSnapshot(data), authorization: authorization ? snapshotPublicationAuthorization(authorization) : undefined,
    entries: new Map([...entries].map(([key, entry]) => [key, snapshotPublicationEntry(entry)])),
    forward: forward.map(snapshotPublicationEntry), abort: abort.map(snapshotPublicationEntry),
    abortResults: abortResults.map(({ claimed, ...value }) => ({ ...immutableSnapshot(value), claimed: claimed ? snapshotPublicationEntry(claimed) : undefined })) };
}
type ReconciliationBinding = {
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; execution: unknown;
  task: DeliveryPublicationReconciliationTask; signal: AbortSignal; cancel: AbortController;
  resources: ReturnType<typeof assertDeliveryPublicationReconciliationExecution>;
  selection?: ReconciliationSelection; snapshot?: ReturnType<typeof reconciliationSqlCut>;
  continuation?: ReconciliationContinuation; generationResources?: PublicationGenerationResourcesV1;
  physical?: PhysicalBinding; original?: Binding; ownsNative: boolean;
  namespace?: HeldPublicationNamespaceObserver;
  before?: PublicationPathObservationV1; beforeRef?: string;
  disposition?: PublicationPathDisposition['disposition']; evidence?: PublicationProofV1; evidenceRef?: string;
  wrapper?: Extract<ReconciliationProbeEvidenceV1, { outcome: 'subject_observation' }>; wrapperRef?: string;
  metadata?: PublishedArtifact[]; result?: OwnedPublicationReconciliationResult; lateObservation?: OwnedPublicationLateObservation; stop?: AgentStopIntent;
  /** Actual known observation survives a nonce-attribution or storage failure.
   * It cannot be relabelled with another time, nonce, or UNKNOWN outcome. */
  known?: { disposition: PublicationPathDisposition['disposition']; evidence: PublicationProofV1; completedAt: string };
  retirementFailure?: ResourceRetirementError; publishing?: Promise<void>; pending?: Promise<OwnedPublicationReconciliationCompletion>; failure?: unknown;
  installedProgress?: ReturnType<typeof reconciliationSqlCut>;
  progressTransfer?: OwnedPublicationReconciliationProgress;
  acceptedLateAudit?: PublicationLateObservationItem;
  originHistory?: RetainedStateOwnerHistory;
  retirementDiagnosticPublished?: boolean;
};
const reconciliationResults = new WeakMap<object, ReconciliationBinding>();
const lateObservations = new WeakMap<object, ReconciliationBinding>();
const reconciliationProgress = new WeakMap<object, { binding: ReconciliationBinding;
  snapshot: ReturnType<typeof reconciliationSqlCut>; delta: {
    beforeRun: Run; run: Run; checkpoint: ReturnType<typeof readCheckpoint>;
    item: Pick<RecoveryClosureV1['items'][number], 'itemId' | 'payloadRef' | 'itemSeq' | 'createdAt'>;
    progressItem: NonNullable<PhysicalBinding['progress']>['item'];
  } }>();
const reconciliationProducers = new WeakMap<object, Readonly<{ run: Run; result: Promise<OwnedPublicationReconciliationCompletion>;
  finish(): Promise<OwnedPublicationReconciliationCompletion>; hasReceivedResult(): boolean; cancelAndJoin(): Promise<void> }>>();

function reconciliationSqlCut(connection: SqliteConnection, runId: string, sourceRunId: string) {
  // This writer changes no Session rows. Preserve immutable identity and the
  // principal, not another Run's legitimately advancing Session projection.
  return sqlCut(connection, runId, sourceRunId);
}
/** Only the fixed probe-cache consumer reads this actual committed delta.
 * Deliberately no signal check: cancellation cannot erase an installed item. */
export function readOwnedPublicationReconciliationProgress(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, task: DeliveryPublicationReconciliationTask, token: OwnedPublicationReconciliationProgress) {
  const transfer = token !== null && typeof token === 'object' ? reconciliationProgress.get(token) : undefined;
  const value = transfer?.binding;
  if (!transfer || !value || value.driver !== driver || value.artifacts !== artifacts || value.owner !== owner ||
      value.execution !== execution || value.task !== task)
    throw new TypeError('a genuine same-task publication progress transfer is required');
  assertOwnedPublicationReconciliationTask(driver, owner, execution, task, artifacts);
  assertActiveStateOwner(driver, owner);
  requireEqual(reconciliationSqlCut(driver, transfer.delta.run.id, value.selection!.admission.source.run.id), transfer.snapshot,
    'publication committed progress transfer changed its exact actual SQL cut');
  return immutableSnapshot(transfer.delta);
}
function originalReconciliation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, token: OwnedPublicationReconciliationResult): ReconciliationBinding {
  const value = token !== null && typeof token === 'object' ? reconciliationResults.get(token) : undefined;
  if (!value || value.driver !== driver || value.artifacts !== artifacts || value.owner !== owner || value.execution !== execution)
    throw new TypeError('a genuine same-execution publication inspection result is required');
  assertOwnedPublicationReconciliationTask(driver, owner, execution, value.task, artifacts);
  if (value.retirementFailure || value.physical?.retirementFailure) throw value.retirementFailure ?? value.physical!.retirementFailure;
  return value;
}
function originalLateObservation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, token: OwnedPublicationLateObservation): ReconciliationBinding {
  const value = token !== null && typeof token === 'object' ? lateObservations.get(token) : undefined;
  if (!value || value.driver !== driver || value.artifacts !== artifacts || value.owner !== owner || value.execution !== execution)
    throw new TypeError('a genuine same-execution late publication observation is required');
  assertOwnedPublicationReconciliationTask(driver, owner, execution, value.task, artifacts);
  if (value.retirementFailure || value.physical?.retirementFailure) throw value.retirementFailure ?? value.physical!.retirementFailure;
  return value;
}
/** Classification reads only the producer's private identity maps, never a
 * caller-selected tag, evidence ref, timestamp or getter. */
export function classifyOwnedPublicationReconciliationCompletion(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, execution: unknown, token: OwnedPublicationReconciliationCompletion) {
  if (token !== null && typeof token === 'object' && reconciliationResults.has(token)) {
    originalReconciliation(driver, artifacts, owner, execution, token as OwnedPublicationReconciliationResult);
    return Object.freeze({ kind: 'within_probe' as const, result: token as OwnedPublicationReconciliationResult });
  }
  if (token !== null && typeof token === 'object' && lateObservations.has(token)) {
    originalLateObservation(driver, artifacts, owner, execution, token as OwnedPublicationLateObservation);
    return Object.freeze({ kind: 'late_audit' as const, lateObservation: token as OwnedPublicationLateObservation });
  }
  throw new TypeError('a genuine same-execution publication completion is required');
}
function assertInspection(value: ReconciliationBinding) {
  value.signal.throwIfAborted();
  const resources = assertDeliveryPublicationReconciliationExecution(value.driver, value.owner, value.execution, value.task, value.artifacts);
  if (resources.workspaceRoot !== value.resources.workspaceRoot || resources.controlledHome !== value.resources.controlledHome)
    invalid('publication inspection changed its genuine original roots');
  const selected = value.selection;
  if (!selected || !value.snapshot) invalid('publication inspection has no fully validated original dispatch');
  const state = selected.wait.probeState;
  if (state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight') invalid('publication inspection has no persisted in-flight nonce');
  const now = sampleCanonicalNow();
  if (now < state.dispatch.probeStartedAt || now >= state.dispatch.probeDeadlineAt)
    throw new KernelStorageError('LEASE_FENCED', 'publication inspection is outside its actual persisted deadline');
  const stable = (snapshot: ReturnType<typeof reconciliationSqlCut>) => {
    const { revision: _revision, updatedAt: _updatedAt, cancelRequested: _cancel, stopIntentRef: _stop, ...run } = snapshot.run;
    return { ...snapshot, run };
  };
  requireEqual(stable(reconciliationSqlCut(value.driver, selected.run.id, selected.admission.source.run.id)), stable(value.snapshot),
    'publication inspection exact original non-Stop SQL cut');
}
async function readReconciliationContinuation(artifacts: ArtifactCatalog, cut: RecoveryClosureV1): Promise<ReconciliationContinuation> {
  if (!cut.run.frontierRef) invalid('publication inspection lost its original frontier');
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, cut.latestCheckpoint.contextManifestRef)), existingItems: ContextItem[] = [];
  for (const row of cut.items) existingItems.push({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
    item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) });
  validateContextItems(context, existingItems);
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, cut.run.frontierRef);
  if (frontier.kind !== 'delivery') invalid('publication inspection cannot replace its original delivery frontier');
  return { context, existingItems, frontier };
}
async function selectReconciliationResources(value: ReconciliationBinding) {
  const selected = value.selection!, { entry, cut, admission } = selected, claim = entry.claim!;
  if (entry.sequence !== 'forward') {
    await readClosedMaintenanceM(value.driver, value.artifacts.withReadSignal(value.signal), cut, selected.prefix, entry); return;
  }
  const launches = readWorkerLaunchesForRun(value.driver, cut.run.id).filter(row => row.leaseEpoch === claim.leaseEpoch &&
    row.supervisorInstanceId === claim.supervisorInstanceId && row.retirementKind !== 'preparation');
  const generation = launches.length === 1 ? cut.workspaceGenerations.find(row => row.generationRef === launches[0]!.workspaceGenerationRef) : undefined;
  if (launches.length !== 1 || launches[0]!.phase !== 'retired' || !generation || generation.phase !== 'retired')
    invalid('publication inspection cannot create or substitute its original retired M');
  const retained = await readRetiredGenerationSource(value.driver, value.artifacts.withReadSignal(value.signal),
    { run: cut.run, spec: cut.runSpec, assembly: admission.source.assembly, generation });
  if (retained.source.phase !== 'quarantined') invalid('publication inspection has no actual quarantined original M');
  const resources: PublicationGenerationResourcesV1 = { kind: 'genuinely_retired_from_verified_checkpoint',
    workerLaunchId: launches[0]!.launchId, generationRef: generation.generationRef, sourceCheckpointId: generation.sourceCheckpointId,
    quarantineEvidenceRef: retained.source.quarantineEvidenceRef, retirementEvidenceRef: generation.retirementEvidenceRef };
  await readPublicationGenerationResources(value.driver, value.artifacts.withReadSignal(value.signal), admission, cut, entry,
    resources, cut.latestCheckpoint, sampleCanonicalNow());
  value.generationResources = immutableSnapshot(resources);
}
async function readClosedMaintenanceM(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  prefix: Prefix, entry: RetainedPublicationOperation): Promise<void> {
  if (entry.sequence !== 'abort' || entry.operation.kind !== 'abort_rmdir' || !entry.claim || !cut.run.stopIntentRef)
    invalid('closed maintenance resources cannot substitute a productive path or omit their actual Stop');
  const launches = readWorkerLaunchesForRun(driver, cut.run.id).filter(launch => launch.leaseEpoch === entry.claim!.leaseEpoch &&
    launch.retirementKind !== 'preparation');
  const launch = launches[0], generation = launch ? cut.workspaceGenerations.find(row => row.generationRef === launch.workspaceGenerationRef) : undefined;
  if (launches.length !== 1 || !launch || launch.phase !== 'retired' || !generation ||
      (generation.phase !== 'sealed' && generation.phase !== 'retired') || cut.run.activeWorkerLaunchId || cut.workerLaunches.length ||
      generation.sourceWorkspaceStateRef !== entry.authorization.verified.checkpoint.workspaceStateRef)
    invalid('maintenance inspection lost its unique actually retired original verified M');
  if (generation.phase === 'sealed') await validateRetainedWorkerSeal(driver, artifacts,
    { run: cut.run, spec: cut.runSpec, assembly: prefix.admission.source.assembly, launch, generation });
  else {
    const retained = await readRetiredGenerationSource(driver, artifacts,
      { run: cut.run, spec: cut.runSpec, assembly: prefix.admission.source.assembly, generation });
    if (retained.source.phase === 'quarantined') await validateRetainedWorkerQuarantines(artifacts,
      { run: cut.run, journal: cut.journal, workerLaunches: [launch], workspaceGenerations: [retained.source] }, driver);
  }
}
/** One publication-only source preparation. A graceful row is not death:
 * only this genuine current lock observes the original retained PID/token.
 * No extra artifact, release permit or general death authority is created. */
async function prepareRecoveryOrigin(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  cut: RecoveryClosureV1, entry: RetainedPublicationOperation, observedAfter: string, deadlineAt?: string) {
  const claim = entry.claim!, birth = entry.birth!;
  const active = assertActiveStateOwner(driver, owner), prior = readStateOwner(driver, claim.stateOwnerEpoch!);
  if (!prior || active.ownerEpoch <= prior.ownerEpoch || prior.supervisorInstanceId !== claim.supervisorInstanceId)
    invalid('publication recovery requires its exact older original claim holder');
  const inspector = supervisorInspectorIdentity(active), inspectorPlan = planCanonicalArtifact(inspector, inspector.format);
  let source: Pick<PublicationRecoveryOriginV1, 'ownerDeathAcquisitionEvidenceRef' | 'ownerDeathAcquisitionEvidenceDigest' | 'gracefulOwnerDeath'>;
  let originHistory: RetainedStateOwnerHistory | undefined, observedAt: string;
  if (prior.state === 'terminal' && prior.terminalReason === 'graceful_release') {
    originHistory = await readRetainedStateOwnerHistory(driver, artifacts, active.ownerEpoch);
    const claiming = originHistory.entries.find(frame => frame.owner.ownerEpoch === prior.ownerEpoch);
    const inspecting = originHistory.entries.find(frame => frame.owner.ownerEpoch === active.ownerEpoch);
    if (!claiming || !inspecting || claiming.transition?.kind !== 'graceful_release' ||
        claim.timestamp < prior.acquiredAt || claim.timestamp > prior.releasedAt)
      invalid('publication graceful history does not bind its original exact process lifetime');
    requireEqual(claiming.owner, prior, 'publication original graceful StateOwner');
    requireEqual(inspecting.owner, active, 'publication current actual inspector');
    const root = stateRootIdentityForLock(owner.filesystem);
    requireEqual(root, originHistory.rootIdentity, 'publication actual current lock and retained original root');
    if (canonicalSha256(root) !== owner.stateRootIdentityRef || root.identityDigest !== owner.stateRootIdentityDigest)
      invalid('publication death observation changed its original StateRoot');
    // This samples native time only after actual process absence/start-token
    // mismatch and real descriptor joins, never after graceful release alone.
    observedAt = new Date(owner.filesystem.observePriorProcessDeath(claiming.process.pid, claiming.process.processStartToken)).toISOString();
    if (observedAt < prior.releasedAt || observedAt < active.acquiredAt)
      invalid('publication original process-death observation regressed its owning lifetimes');
    source = { gracefulOwnerDeath: { kind: 'observed_after_graceful_release', priorOwnerRowDigest: prior.rowDigest,
      priorProcessIdentityRef: prior.processIdentityRef, priorProcessIdentityDigest: prior.processIdentityDigest,
      gracefulTransitionEvidenceRef: prior.transitionEvidenceRef, gracefulTransitionEvidenceDigest: prior.transitionEvidenceDigest,
      processObservation: 'absent_or_start_token_mismatch' } };
  } else {
    const death = await readStateOwnerDeath(artifacts, driver, { supervisorInstanceId: claim.supervisorInstanceId!, ownedAt: claim.timestamp });
    if (death.priorOwner.ownerEpoch !== claim.stateOwnerEpoch || owner.ownerEpoch < death.successorOwner.ownerEpoch)
      invalid('publication inspection has no actual original owner-death acquisition');
    source = { ownerDeathAcquisitionEvidenceRef: death.acquisitionEvidenceRef, ownerDeathAcquisitionEvidenceDigest: death.acquisitionEvidenceDigest };
    observedAt = sampleCanonicalNow();
  }
  if (observedAt < observedAfter || deadlineAt !== undefined && observedAt >= deadlineAt)
    throw new KernelStorageError('LEASE_FENCED', 'publication owner death arrived outside its actual owning lifetime');
  requireEqual(assertActiveStateOwner(driver, owner), active, 'publication original active death inspector');
  originHistory?.assertUnchanged(driver);
  const value = { schemaVersion: 1, format: 'cliq-publication-recovery-origin-v1',
    deliveryRunId: cut.run.id, deliveryPlanRef: entry.planRef, opId: claim.opId, attempt: claim.attempt, dispatchId: claim.dispatchId!,
    claimJournalSeq: claim.seq, arenaBirthRef: claim.evidenceRef!, arenaBirthDigest: birth.birthDigest,
    inspectorIdentityRef: inspectorPlan.ref, inspectorIdentityDigest: inspector.identityDigest,
    ...source, observedAt, originDigest: '' };
  value.originDigest = digestOmitting(value, 'originDigest');
  const origin = decodePublicationRecoveryOrigin(value);
  return { origin, inspector, inspectorPlan, originPlan: planCanonicalArtifact(origin, origin.format), ...(originHistory ? { originHistory } : {}) };
}
async function prepareReconciliationNative(value: ReconciliationBinding) {
  const selected = value.selection!, { entry, prefix, cut } = selected, claim = entry.claim!, birth = entry.birth!;
  if (entry.progress) {
    const before = await readOwnedPublicationProof(value.driver, value.artifacts.withReadSignal(value.signal), selected.admission,
      entry.planRef, entry.progress.item.beforeObservationRef, claim);
    if (before.kind !== 'path_observation') invalid('publication inspection lost its original before observation');
    value.before = immutableSnapshot(before.observation); value.beforeRef = entry.progress.item.beforeObservationRef;
  }
  const originals = value.resources.publicationOwners.map(token => binding(value.driver, value.owner, token))
    .filter(held => held.execution === value.execution && held.prepared.opId === entry.prepared.opId);
  if (originals.length > 1) invalid('publication inspection has competing original native owners');
  const original = originals[0];
  const common = { artifacts: value.artifacts.withReadSignal(value.signal), owner: value.owner, run: cut.run,
    mode: entry.sequence, operation: entry.operation, prepared: entry.prepared, claim, birth, closed: false,
    inspectionGate: () => assertInspection(value) };
  if (original) {
    if (original.closed || !original.native || !original.birth || !original.claim || !original.revoked)
      invalid('publication inspection lost its genuinely retained, fenced original descriptors');
    requireEqual(original.claim, claim, 'publication inspection same original claim');
    requireEqual(original.prepared, entry.prepared, 'publication inspection same original preparation');
    requireEqual(original.operation, entry.operation, 'publication inspection same original planned operation');
    requireEqual(original.birth, birth, 'publication inspection same original native birth');
    if (original.nativeInput.arenaId !== birth.arenaId) invalid('publication inspection changed its original arena');
    value.original = original;
    value.physical = { ...common, nativeInput: original.nativeInput, native: original.native,
      ...(original.beforeRef ? { beforeRef: original.beforeRef } : {}) };
    if (!entry.progress && original.before) value.before = immutableSnapshot(original.before);
    if (!entry.progress) value.beforeRef = original.beforeRef;
  } else {
    // A successor never reconstructs an unrecorded birth or removes an arena
    // merely because its derived pathname or content happens to match.
    if (!selected.target.progress || !entry.progress) invalid('successor publication inspection requires its original durable progress');
    const state = selected.wait.probeState;
    if (state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight') invalid('publication inspection lost its actual dispatch');
    const { origin, inspector, inspectorPlan, originPlan, originHistory } = await prepareRecoveryOrigin(value.driver,
      value.artifacts.withReadSignal(value.signal), value.owner, cut, entry, state.dispatch.probeStartedAt, state.dispatch.probeDeadlineAt);
    value.originHistory = originHistory;
    const observedAt = origin.observedAt, reads = value.artifacts.withReadSignal(value.signal);
    const metadata = await joinResourceOperations([value.artifacts.publishBytes(inspectorPlan.bytes, inspectorPlan.mediaType, inspectorPlan.schemaKind),
      value.artifacts.publishBytes(originPlan.bytes, originPlan.mediaType, originPlan.schemaKind)]);
    await readPublicationRecoveryOrigin(value.driver, reads, selected.admission, claim, birth, {
      inspectorIdentityRef: inspectorPlan.ref, inspectorIdentityDigest: inspector.identityDigest,
      recoveryOriginRef: originPlan.ref, recoveryOriginDigest: origin.originDigest, observedAt });
    let input: NativePublicationOperationInput;
    if (entry.operation.kind === 'abort_rmdir') {
      const operation = entry.operation, creator = prefix.forward.find(row => row.operation.operationId === operation.createdByOperationId);
      const before = value.before;
      if (!creator || creator.operation.kind === 'abort_rmdir' || creator.result?.item.outcome !== 'completed' ||
          before?.state.kind !== 'directory' || !before.state.empty || before.entryDeviceId === undefined || before.entryFileId === undefined)
        invalid('successor abort lost its actual original empty directory creator');
      const creatorInput = await physicalInput(value.driver, reads, prefix, creator.operation, birth.arenaId);
      const topology = decodeDeliveryCaptureTopology(await readCanonicalArtifact(reads, prefix.authorization!.context.plan.captureTopologyRef));
      input = { arenaId: birth.arenaId, path: operation.path, parents: creatorInput.parents, kind: 'abort_rmdir',
        expected: { kind: 'directory', mode: before.state.mode, identity: { deviceId: before.entryDeviceId,
          fileId: before.entryFileId, ownerUid: topology.rootIdentity.ownerUid } }, desired: { kind: 'absent' }, quarantineName: operation.quarantineName };
    } else input = await physicalInput(value.driver, reads, prefix, entry.operation, birth.arenaId);
    const destination = await readOwnedPublicationProof(value.driver, reads, selected.admission, entry.planRef,
      entry.progress.item.destinationEvidenceRef, claim);
    const transient = entry.progress.item.transientObservationRef ? await readOwnedPublicationProof(value.driver, reads,
      selected.admission, entry.planRef, entry.progress.item.transientObservationRef, claim) : undefined;
    if (destination.kind !== 'path_observation' || transient && transient.kind !== 'path_observation')
      invalid('successor publication inspection lost its exact original progress observations');
    const inode = (observation: PublicationPathObservationV1) => {
      if (observation.entryDeviceId === undefined || observation.entryFileId === undefined) invalid('publication progress lost its actual original inode');
      return { deviceId: observation.entryDeviceId, fileId: observation.entryFileId };
    };
    const retained: NonNullable<NativePublicationOperationInput['retained']> = { arena: { deviceId: birth.arenaIdentity.deviceId, fileId: birth.arenaIdentity.fileId },
      ...(destination.observation.state.kind === 'absent' ? {} : { destination: inode(destination.observation) }),
      ...(transient?.kind === 'path_observation' && transient.observation.state.kind !== 'absent' ? { preimage: inode(transient.observation) } : {}) };
    assertInspection(value);
    const held: PhysicalBinding = { ...common, nativeInput: input, metadata,
      proofInspector: { ref: inspectorPlan.ref, identityDigest: inspector.identityDigest }, recoveryOrigin: { ref: originPlan.ref, digest: origin.originDigest } };
    value.physical = held;
    const namespace = openHeldPublicationNamespaceObserver(value.owner.filesystem, value.resources.workspaceRoot, {
      arenaId: birth.arenaId, path: input.path, parents: input.parents, desired: input.desired,
      arenaIdentity: birth.arenaIdentity, parentIdentity: birth.parentIdentity,
      ...(retained.destination ? { destinationIdentity: { ...retained.destination, ownerUid: input.parents[0]!.ownerUid } } : {}),
      ...('stagingName' in input ? { stagingName: input.stagingName } : input.kind === 'mkdir' ? { stagingName: 'desired' } : {}),
      ...('quarantineName' in input ? { quarantineName: input.quarantineName } : {}),
      ...(retained.preimage ? { retainedPreimage: retained.preimage } : {}) });
    value.namespace = namespace; value.ownsNative = true;
    // Only this closed readonly branch may route to the original retained-FD
    // cleanup. A foreign inode, extra name, failed close or generic refusal is
    // never treated as evidence that the old constructor should be retried.
    if (physical(held, () => namespace.observe()).state === 'original_slots_present') {
      namespace.close(); value.namespace = undefined; value.ownsNative = false;
      assertInspection(value);
      held.native = openHeldPublicationOperation(value.owner.filesystem, value.resources.workspaceRoot, { ...input, retained });
      value.ownsNative = true;
    }
  }
  if (entry.progress) {
    value.physical.beforeRef = value.beforeRef; value.physical.preservedRef = entry.progress.item.preservedPreimageRef;
  }
}

async function persistReconciliationProgress(value: ReconciliationBinding) {
  const selected = value.selection!, held = value.physical!, { cut, entry } = selected;
  if (entry.progress) return;
  if (!value.before || !value.beforeRef) invalid('publication cleanup cannot invent its original pre-effect observation');
  if (!held.progress) {
    const actual = physical(held, () => held.native!.observe());
    const destination = observation(held, { kind: 'workspace', path: entry.operation.path }, actual.destination, actual.parent);
    const destinationEvidenceRef = await publishObservation(held, 'destination', destination);
    let transientObservationRef: string | undefined;
    if (actual.quarantine && actual.quarantine.kind !== 'absent' && 'quarantineName' in entry.operation)
      transientObservationRef = await publishObservation(held, 'quarantine', observation(held,
        { kind: 'publication_arena', arenaId: entry.birth!.arenaId, component: entry.operation.quarantineName }, actual.quarantine,
        { identity: actual.arena.identity, linkCount: actual.arena.linkCount }));
    const item = decodePublicationPathProgressItem({ schemaVersion: 1, kind: 'publication_path_progress',
      itemId: publicationProgressItemId(cut.run.id, entry.prepared.opId, entry.prepared.attempt), runId: cut.run.id, deliveryPlanRef: entry.planRef,
      operationIndex: entry.operation.index, operationId: entry.operation.operationId, opId: entry.prepared.opId, attempt: entry.prepared.attempt,
      state: 'desired_committed_cleanup_pending', beforeObservationRef: value.beforeRef, destinationEvidenceRef,
      ...(held.preservedRef ? { preservedPreimageRef: held.preservedRef } : {}),
      ...(transientObservationRef ? { transientObservationRef } : {}), createdAt: sampleCanonicalNow() });
    if (item.state !== 'desired_committed_cleanup_pending') invalid('publication inspection cannot substitute a received handoff');
    held.progress = { item, graph: planContinuationCommit(value.artifacts, { ...value.continuation!, items: [item],
      checkpointId: publicationProgressCheckpointId(cut.run.id, entry.prepared.opId, entry.prepared.attempt),
      workspaceStateRef: cut.latestCheckpoint.workspaceStateRef }) };
  }
  const graph = await held.progress.graph.publish(); held.progress.metadata = graph.metadata;
  await refreshReconciliationStop(value); assertInspection(value);
  const current = value.selection!;
  let outcome: TimeFenceAdvance | undefined, committed = false, progressCommittedAt: string | undefined;
  value.driver.transaction(connection => {
    assertReconciliationSql(value, connection);
    const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, value.owner.ownerEpoch, now);
    if (outcome !== 'healthy') return;
    if (now < current.cut.run.updatedAt || now < held.progress!.item.createdAt) invalid('publication inspection progress has a noncausal time');
    for (const artifact of metadata(held)) insertArtifactMetadata(connection, artifact, now);
    assertReconciliationSql(value, connection);
    graph.commit(connection, current.cut.run, current.cut.journal.length, now);
    connection.prepare('UPDATE runs SET revision=revision+1,updated_at=? WHERE id=? AND revision=?')
      .run(now, current.run.id, BigInt(current.run.revision));
    appendRunStateEvent(connection, readRun(connection, current.run.id), now); progressCommittedAt = now; committed = true;
  });
  requireHealthyFence(outcome);
  if (!committed) invalid('publication inspection progress did not install its actual cleanup barrier');
  const installed = reconciliationSqlCut(value.driver, current.run.id, current.admission.source.run.id);
  value.installedProgress = installed;
  requireEqual(installed.checkpoint, { id: graph.runUpdate.latestCheckpointId, schemaVersion: 1, runId: current.run.id,
    basedOnRunRevision: current.run.revision, runItemSeq: graph.throughItemSeq, contextManifestRef: graph.contextManifestRef,
    journalSeq: current.cut.journal.length, workspaceStateRef: current.cut.latestCheckpoint.workspaceStateRef,
    createdAt: progressCommittedAt, reason: 'auto' }, 'publication inspection exact generated and committed progress Checkpoint');
  requireEqual(installed.run, { ...current.run, ...graph.runUpdate, revision: current.run.revision + 1, updatedAt: progressCommittedAt },
    'publication inspection exact generated and committed progress Run delta');
  const item = installed.items.at(-1)!;
  if (!item || item.item_id !== held.progress.item.itemId || item.kind !== held.progress.item.kind ||
      item.payload_ref !== canonicalSha256(held.progress.item) || item.created_at !== held.progress.item.createdAt ||
      item.item_seq !== graph.throughItemSeq || installed.checkpoint.id !== graph.runUpdate.latestCheckpointId)
    invalid('publication inspection committed progress differs from its actual fixed graph');
  const transfer: OwnedPublicationReconciliationProgress = Object.freeze({ [reconciliationProgressBrand]: true as const });
  reconciliationProgress.set(transfer, { binding: value, snapshot: installed, delta: immutableSnapshot({ beforeRun: current.run,
    run: installed.run, checkpoint: installed.checkpoint, item: { itemId: item.item_id, payloadRef: item.payload_ref,
      itemSeq: item.item_seq, createdAt: item.created_at }, progressItem: held.progress.item }) });
  value.progressTransfer = transfer;
  updatePublicationReconciliationProgress(value.driver, value.artifacts, value.owner, value.execution, value.task, transfer);
  value.progressTransfer = undefined;
  // This is the genuinely committed new cut, never a future RecoveryClosure.
  // Re-read before learning a terminal result; after that only this task's
  // fixed graph and monotonic Stop selection may be revisited.
  await readInstalledReconciliationProgress(value);
}
async function readInstalledReconciliationProgress(value: ReconciliationBinding) {
  const current = value.selection!, expected = value.installedProgress!;
  // Closing consumes exactly this task's installed delta even if its read-only
  // follow-up has already been cancelled. This never authorizes cleanup.
  if (value.progressTransfer) {
    updatePublicationReconciliationProgress(value.driver, value.artifacts, value.owner, value.execution, value.task, value.progressTransfer);
    value.progressTransfer = undefined;
  }
  value.signal.throwIfAborted();
  assertDeliveryPublicationReconciliationExecution(value.driver, value.owner, value.execution, value.task, value.artifacts);
  const stable = (snapshot: ReturnType<typeof reconciliationSqlCut>) => {
    const { revision: _revision, updatedAt: _time, stopIntentRef: _stop, cancelRequested: _cancel, ...run } = snapshot.run;
    return { ...snapshot, run };
  };
  requireEqual(stable(reconciliationSqlCut(value.driver, current.run.id, current.admission.source.run.id)), stable(expected),
    'publication inspection actual installed progress changed');
  const actual = await readPublicationReconciliation(value.driver, value.artifacts.withReadSignal(value.signal), current.run.id);
  if (!actual?.entry.progress) invalid('publication inspection lost its actually committed cleanup barrier');
  requireEqual(actual.entry.progress.item, value.physical!.progress!.item, 'publication inspection original actual progress');
  value.selection = actual; value.snapshot = reconciliationSqlCut(value.driver, actual.run.id, actual.admission.source.run.id);
  value.continuation = await readReconciliationContinuation(value.artifacts.withReadSignal(value.signal), actual.cut);
  value.installedProgress = undefined; value.progressTransfer = undefined;
}

function assertReconciliationSql(value: ReconciliationBinding, connection: SqliteConnection) {
  assertOwnedPublicationReconciliationTask(value.driver, value.owner, value.execution, value.task, value.artifacts);
  assertActiveStateOwner(connection, value.owner);
  value.originHistory?.assertUnchanged(connection);
  if (!value.selection || !value.snapshot || canonicalSha256(reconciliationSqlCut(connection, value.selection.run.id,
      value.selection.admission.source.run.id)) !== canonicalSha256(value.snapshot))
    throw new KernelStorageError('REVISION_CONFLICT', 'publication inspection original source, principal, claim, resources or Stop changed');
}
async function refreshReconciliationStop(value: ReconciliationBinding) {
  assertOwnedPublicationReconciliationTask(value.driver, value.owner, value.execution, value.task, value.artifacts);
  const selected = value.selection!, refreshed = await reselectPublicationStop(value.driver, value.artifacts, value.owner,
    selected.cut, selected.admission.source.run.id, value.snapshot!, value.stop);
  value.stop = refreshed.stop; value.selection = { ...selected, run: refreshed.cut.run, cut: refreshed.cut }; value.snapshot = refreshed.snapshot;
}
async function reselectPublicationStop(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  original: RecoveryClosureV1, sourceRunId: string, expected: ReturnType<typeof reconciliationSqlCut>, previousStop?: AgentStopIntent) {
  assertActiveStateOwner(driver, owner);
  const snapshot = reconciliationSqlCut(driver, original.run.id, sourceRunId);
  if (canonicalSha256(snapshot) === canonicalSha256(expected)) return { cut: original, snapshot: expected, stop: previousStop };
  const stable = (cut: ReturnType<typeof reconciliationSqlCut>) => {
    const { revision: _revision, updatedAt: _time, cancelRequested: _cancel, stopIntentRef: _stop, ...run } = cut.run;
    return { ...cut, run };
  };
  requireEqual(stable(snapshot), stable(expected), 'publication inspection cannot reselect a different original result cut');
  const run = snapshot.run, old = original.run;
  if (run.revision <= old.revision || run.updatedAt < old.updatedAt || !run.stopIntentRef || old.cancelRequested && !run.cancelRequested ||
      run.stopIntentRef === old.stopIntentRef && run.cancelRequested === old.cancelRequested)
    throw new KernelStorageError('REVISION_CONFLICT', 'publication inspection revision did not advance through a real monotonic Stop');
  const cut = { ...original, run };
  if (old.stopIntentRef) await readRetainedAgentStop(driver, artifacts, cut, old.stopIntentRef);
  const stop = await readAgentStop(driver, artifacts, cut);
  if (previousStop && selectAgentStop(previousStop, stop) !== stop) invalid('publication inspection replaced its winning Stop');
  assertActiveStateOwner(driver, owner);
  requireEqual(reconciliationSqlCut(driver, run.id, sourceRunId), snapshot,
    'publication inspection actual Stop changed while checking its original closure');
  return { cut, snapshot, stop };
}
/** Pure temporal classification only. The real owning task and immutable
 * dispatch are authenticated separately; these dates mint no authority. */
export function classifyPublicationObservationCompletion(startedAt: string, deadlineAt: string, observedAt: string, completedAt: string) {
  const start = parseCanonicalTime(startedAt), deadline = parseCanonicalTime(deadlineAt),
    observed = parseCanonicalTime(observedAt), completed = parseCanonicalTime(completedAt);
  if (deadline < start || observed < start || completed < observed)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'publication actual observation or completion time regressed');
  return completed > deadline ? 'late_audit' : 'within_probe';
}
function retainReconciliationResult(value: ReconciliationBinding, disposition: PublicationPathDisposition['disposition'], evidence: PublicationProofV1) {
  if (value.known) requireEqual({ disposition: value.known.disposition, evidence: value.known.evidence },
    { disposition, evidence }, 'publication inspection original actual known result');
  else value.known = immutableSnapshot({ disposition, evidence, completedAt: sampleCanonicalNow() });
  const selected = value.selection!, state = selected.wait.probeState;
  if (state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight') invalid('publication observation lost its persisted actual nonce');
  const dispatch = state.dispatch;
  // Inert observation after the ORIGINAL actual retirement/close/post-join
  // reader only. UNKNOWN/unjoined paths cannot manufacture a snapshot. The
  // diagnostic is neither the saved completion clock nor an acceptance proof.
  if (!value.retirementDiagnosticPublished) {
    value.retirementDiagnosticPublished = true;
    noteJoinedPublicationRetirement(() => ({ version: 1, kind: value.namespace ? 'namespace' : 'original', joined: true,
      key: publicationRetirementDiagnosticKey({ runId: selected.run.id, planRef: selected.entry.planRef,
        opId: selected.entry.claim!.opId, attempt: selected.entry.claim!.attempt,
        dispatchId: selected.entry.claim!.dispatchId!, probeNonceDigest: dispatch.probeNonceDigest }),
      slots: readJoinedPublicationRetirementSpans(value.owner.filesystem, value.namespace ?? value.physical!.native!) }));
  }
  const timing = classifyPublicationObservationCompletion(dispatch.probeStartedAt, dispatch.probeDeadlineAt, evidence.observedAt, value.known.completedAt);
  value.evidence = immutableSnapshot(evidence); value.evidenceRef = canonicalSha256(evidence); value.disposition = disposition;
  if (timing === 'late_audit') {
    if (value.lateObservation) return value.lateObservation;
    const token: OwnedPublicationLateObservation = Object.freeze({ [lateObservationBrand]: true as const });
    value.lateObservation = token; lateObservations.set(token, value); return token;
  }
  const evidenceRef = value.evidenceRef, wrapper: Extract<ReconciliationProbeEvidenceV1, { outcome: 'subject_observation' }> = {
    schemaVersion: 1, format: 'cliq-reconciliation-probe-evidence-v1', runId: selected.run.id,
    waitingSubjectRef: selected.run.waitingOnRef!, waitingSubjectDigest: selected.run.waitingOnRef!, probeKind: dispatch.probeKind,
    probeOrdinal: dispatch.probeOrdinal, probeNonceDigest: dispatch.probeNonceDigest, probeDispatchDigest: dispatch.dispatchDigest,
    probeStartedAt: dispatch.probeStartedAt, probeDeadlineAt: dispatch.probeDeadlineAt,
    inspectorIdentityRef: evidence.inspectorIdentityRef, inspectorIdentityDigest: evidence.inspectorIdentityDigest,
    observedAt: evidence.observedAt, outcome: 'subject_observation', subjectEvidenceKind: 'publication',
    subjectEvidenceRef: evidenceRef, subjectEvidenceDigest: evidence.proofDigest, evidenceDigest: '' };
  wrapper.evidenceDigest = digestOmitting(wrapper, 'evidenceDigest');
  value.wrapper = immutableSnapshot(wrapper); value.wrapperRef = canonicalSha256(wrapper);
  const token: OwnedPublicationReconciliationResult = Object.freeze({ [reconciliationBrand]: true as const });
  value.result = token; reconciliationResults.set(token, value); return token;
}
function retainOriginalReconciliationJoin(value: ReconciliationBinding) {
  const original = value.original, held = value.physical!;
  if (!original) return;
  if (original.native !== held.native || !held.closed || !held.arenaRetired || original.preflight)
    invalid('publication inspection cannot retire a different or unjoined original native owner');
  const actual = physical(original, () => readRetiredPublicationArena(value.owner.filesystem, original.native!));
  requireEqual(actual.arenaIdentity, original.birth!.arenaIdentity, 'publication inspection actual original retired arena');
  requireEqual(actual.parentIdentity, original.birth!.parentIdentity, 'publication inspection actual original retired parent');
  // The physical join is true even if fixed CAS publication later fails or
  // the observation is late. Neither case rewrites the original UNKNOWN or
  // gives an abort consumer the timely, resolved archive below.
  original.closed = true; original.arenaRetired = true;
}
async function inspectCurrentPublicationNamespace(value: ReconciliationBinding): Promise<OwnedPublicationReconciliationCompletion> {
  const held = value.physical!, namespace = value.namespace!, entry = value.selection!.entry;
  if (value.original || !held.recoveryOrigin || !entry.progress || !value.before)
    invalid('current namespace retirement requires original durable progress and real original owner death');
  // EOF also completes the native absent/directory/symlink verification. A
  // type tag or a schema-valid desired state is never that physical fact.
  for (;;) {
    if (physical(held, () => namespace.readDestinationChunk()) === null) break;
    await yieldToLoop();
  }
  const observed = physical(held, () => namespace.observe());
  if (observed.state === 'original_slots_present') invalid('current namespace cannot retire an original retained preimage');
  const after = observation(held, { kind: 'workspace', path: entry.operation.path }, observed.destination, observed.parent);
  const original = await readOwnedPublicationProof(value.driver, value.artifacts.withReadSignal(value.signal), value.selection!.admission,
    entry.planRef, entry.progress.item.destinationEvidenceRef, entry.claim);
  if (original.kind !== 'path_observation') invalid('current namespace lost its original complete desired observation');
  for (const key of ['location', 'state', 'parentDeviceId', 'parentFileId', 'entryDeviceId', 'entryFileId', 'entryLinkCount'] as const)
    requireEqual(after[key], original.observation[key], 'current namespace same original desired inode and complete bytes');
  const destination = proof(held, { kind: 'path_observation', observation: after, observedAt: sampleCanonicalNow() });
  if (destination.kind !== 'path_observation') invalid('current namespace changed its fixed desired observation kind');
  held.namespaceDestinationProof = destination; held.finalDestination = after;
  physical(held, () => retireHeldPublicationNamespace(held.owner.filesystem, namespace));
  try { namespace.close(); held.closed = true; }
  catch (error) { throw held.retirementFailure = error instanceof ResourceRetirementError ? error :
    new ResourceRetirementError('current publication namespace descriptors did not join', error); }
  const retired = readRetiredPublicationNamespace(held.owner.filesystem, namespace);
  requireEqual(retired.parentIdentity, entry.birth!.parentIdentity, 'current actual registered arena parent');
  if (retired.arenaId !== entry.birth!.arenaId || !retired.arenaAbsent ||
      !retired.arenaParentFsyncCompleted || !retired.workspaceParentFsyncCompleted)
    invalid('current namespace lacks its actual original-envelope absence and parent sync');
  const namespaceProof = proof(held, { kind: 'arena_namespace_absence', arenaId: retired.arenaId,
    stateRootIdentityRef: entry.birth!.stateRootIdentityRef, stateRootIdentityDigest: entry.birth!.stateRootIdentityDigest,
    registeredArenaIdentity: entry.birth!.arenaIdentity, namespaceParentIdentity: retired.parentIdentity,
    coveredLocations: publicationEnvelopeLocations(entry), destinationObservationRef: canonicalSha256(destination),
    arenaAbsent: true, arenaParentFsyncCompleted: true, workspaceParentFsyncCompleted: true, namespaceHandlesJoined: true,
    recoveryOriginRef: held.recoveryOrigin.ref, recoveryOriginDigest: held.recoveryOrigin.digest, observedAt: sampleCanonicalNow() });
  if (namespaceProof.kind !== 'arena_namespace_absence') invalid('current namespace changed its fixed proof kind');
  held.namespaceProof = namespaceProof;
  const parent = held.nativeInput.parents.at(-1)!;
  const receipt = proof(held, { kind: 'terminal_receipt', sequence: entry.sequence, operationIndex: entry.operation.index,
    operationId: entry.operation.operationId, opId: entry.prepared.opId, attempt: entry.prepared.attempt,
    before: value.before, after, ...(held.preservedRef ? { preservedPreimageRef: held.preservedRef } : {}),
    namespaceRetirementEvidenceRef: canonicalSha256(namespaceProof),
    recoveryOriginRef: held.recoveryOrigin.ref, recoveryOriginDigest: held.recoveryOrigin.digest,
    parentIdentityBeforeDigest: publicationDirectoryIdentityDigest(entry.birth!.workspaceIdentityDigest, parent),
    parentIdentityAfterDigest: publicationDirectoryIdentityDigest(entry.birth!.workspaceIdentityDigest, parent),
    directoryFsyncCompleted: true, observedAt: sampleCanonicalNow() });
  // No CAS await can discard the actual joined fact before it is privately
  // retained. A late receipt is audit-only; the old nonce is never refreshed.
  return retainReconciliationResult(value, 'received', receipt);
}
async function inspectOriginalPublication(value: ReconciliationBinding): Promise<OwnedPublicationReconciliationCompletion> {
  const held = value.physical!, selected = value.selection!, entry = selected.entry;
  try {
    assertInspection(value);
    if (value.namespace) return await inspectCurrentPublicationNamespace(value);
    const state = physical(held, () => held.native!.inspectState());
    if (state === 'unstarted') {
      if (!value.original) invalid('successor cleanup owner cannot manufacture an unstarted original operation');
      if (held.nativeInput.expected.kind !== 'absent') {
        physical(held, () => held.native!.restartRead('inspection_original'));
        for (;;) { if (physical(held, () => held.native!.readInspectionOriginalChunk()) === null) break; await yieldToLoop(); }
      }
      const actual = physical(held, () => held.native!.observe());
      const before = observation(held, { kind: 'workspace', path: entry.operation.path }, actual.destination, actual.parent);
      const evidence = proof(held, { kind: 'path_observation', observation: before, observedAt: sampleCanonicalNow() });
      physical(held, () => held.native!.discardStage());
      await retireArena(held, false, false);
      retainOriginalReconciliationJoin(value);
      return retainReconciliationResult(value, 'stopped_before_effect', evidence);
    }
    if (!value.before || !value.beforeRef) invalid('publication inspection has no truthful original before observation');
    const reconciled = physical(held, () => held.native!.reconcile());
    if (reconciled === 'unstarted' || reconciled === 'cleaned' && !entry.progress)
      invalid('publication inspection cannot replace its actual cleanup barrier or original before state');
    if (reconciled !== 'cleaned') {
      await preservePreimage(held);
      // Retained payload bytes are not a current full-hash observation. Even
      // a successor with an original preserved ref re-reads its actual inode.
      if (held.nativeInput.expected.kind !== 'absent') {
        physical(held, () => held.native!.restartRead('preimage'));
        for (;;) { if (physical(held, () => held.native!.readPreimageChunk()) === null) break; await yieldToLoop(); }
      }
    }
    if (held.nativeInput.desired.kind !== 'absent') {
      physical(held, () => held.native!.restartRead('destination'));
      for (;;) { if (physical(held, () => held.native!.readDestinationChunk()) === null) break; await yieldToLoop(); }
    }
    await persistReconciliationProgress(value);
    if (!value.selection!.entry.progress) invalid('publication inspection cleanup has no actual durable original barrier');
    if (reconciled !== 'cleaned') physical(held, () => held.native!.finishCleanup());
    await retireArena(held, true, false);
    retainOriginalReconciliationJoin(value);
    const parent = held.nativeInput.parents.at(-1)!, receipt = proof(held, { kind: 'terminal_receipt', sequence: entry.sequence,
      operationIndex: entry.operation.index, operationId: entry.operation.operationId, opId: entry.prepared.opId, attempt: entry.prepared.attempt,
      before: value.before, after: held.finalDestination!, ...(held.preservedRef ? { preservedPreimageRef: held.preservedRef } : {}),
      transientFinalObservations: held.finalObservations!, parentIdentityBeforeDigest: publicationDirectoryIdentityDigest(entry.birth!.workspaceIdentityDigest, parent),
      parentIdentityAfterDigest: publicationDirectoryIdentityDigest(entry.birth!.workspaceIdentityDigest, parent), directoryFsyncCompleted: true,
      observedAt: sampleCanonicalNow() });
    return retainReconciliationResult(value, 'received', receipt);
  } catch (error) {
    if (error instanceof ResourceRetirementError) { value.retirementFailure ??= error; throw error; }
    if (error !== held.physicalFailure || value.signal.aborted || isJoinedCasPublicationFailure(error)) throw error;
    const ambiguity = proof(held, { kind: 'path_ambiguity', sequence: entry.sequence, operationIndex: entry.operation.index,
      operationId: entry.operation.operationId, opId: entry.prepared.opId, attempt: entry.prepared.attempt,
      launchDispatchId: entry.claim!.dispatchId!, failure: 'transient_state_ambiguous', lastKnownObservationRefs: [], observedAt: sampleCanonicalNow() });
    return retainReconciliationResult(value, 'unknown', ambiguity);
  }
}

/** Only this execution's registered descriptor-only task can inspect an old
 * claim. No new semantic commit, claim or charge occurs anywhere in this path. */
export async function prepareOwnedPublicationReconciliation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, task: DeliveryPublicationReconciliationTask) {
  const resources = assertDeliveryPublicationReconciliationExecution(driver, owner, execution, task, artifacts);
  const existing = reconciliationProducers.get(task); if (existing) return existing;
  const cancel = new AbortController(), signal = AbortSignal.any([resources.signal, cancel.signal]);
  const value: ReconciliationBinding = { driver, artifacts, owner, execution, task, resources, signal, cancel, ownsNative: false };
  const run = immutableSnapshot(readRun(driver, resources.runId));
  const finish = (): Promise<OwnedPublicationReconciliationCompletion> => {
    if (value.result) return Promise.resolve(value.result);
    if (value.lateObservation) return Promise.resolve(value.lateObservation);
    if (value.known) return Promise.resolve().then(() => retainReconciliationResult(value, value.known!.disposition, value.known!.evidence));
    if (value.pending) return value.pending;
    if (value.failure) return Promise.reject(value.failure);
    value.pending = Promise.resolve().then(async () => {
      signal.throwIfAborted();
      if (!value.selection) {
        const selected = await readPublicationReconciliation(driver, artifacts.withReadSignal(signal), resources.runId);
        if (!selected || !selected.entry.claim || !selected.entry.birth || !selected.prefix.authorization ||
            selected.run.revision < resources.expectedRunRevision || selected.wait.probeState.phase !== 'automatic_in_flight' &&
            selected.wait.probeState.phase !== 'user_in_flight') invalid('publication inspection requires its actual full original in-flight wait');
        if (selected.wait.probeState.dispatch.owningSupervisorInstanceId !== owner.supervisorInstanceId)
          invalid('publication inspection cannot adopt another owning inspector task');
        value.selection = selected; value.snapshot = reconciliationSqlCut(driver, resources.runId, selected.admission.source.run.id);
        const workspace = selected.prefix.authorization.workspace;
        if (workspace.kind !== 'live' || heldWorkspaceRootPath(resources.workspaceRoot) !== workspace.canonicalRootPath)
          invalid('publication inspection changed its original approved live workspace');
        requireEqual(resources.workspaceRoot.identity, workspace.rootIdentity, 'publication inspection original held workspace root');
        requireEqual(value.snapshot.source, selected.admission.source.run, 'publication inspection fully verified source Run');
        requireEqual(value.snapshot.sourceSession, immutableSessionIdentity(selected.admission.source.session),
          'publication inspection fully verified source Session identity');
        value.continuation = await readReconciliationContinuation(artifacts.withReadSignal(signal), selected.cut);
        await selectReconciliationResources(value);
        if (selected.run.stopIntentRef) value.stop = await readAgentStop(driver, artifacts.withReadSignal(signal), selected.cut);
      }
      if (value.installedProgress) await readInstalledReconciliationProgress(value);
      await refreshReconciliationStop(value); assertInspection(value);
      if (!value.physical) await prepareReconciliationNative(value);
      return inspectOriginalPublication(value);
    }).catch((error: unknown) => {
      if (error instanceof ResourceRetirementError) value.retirementFailure ??= error;
      if (!isJoinedCasPublicationFailure(error) && !isRolledBackSqliteTransactionFailure(driver, error) &&
          !(error instanceof KernelStorageError && error.code === 'REVISION_CONFLICT')) value.failure = error;
      throw error;
    }).finally(() => { value.pending = undefined; });
    return value.pending;
  };
  let joining: Promise<void> | undefined;
  const producer = Object.freeze({ run, get result() {
    if (this !== producer) throw new TypeError('invalid publication inspection producer receiver'); return finish();
  }, finish() {
    if (this !== producer) throw new TypeError('invalid publication inspection producer receiver'); return finish();
  }, hasReceivedResult() {
    if (this !== producer) throw new TypeError('invalid publication inspection producer receiver');
    return value.known !== undefined;
  }, cancelAndJoin() {
    if (this !== producer) throw new TypeError('invalid publication inspection producer receiver');
    if (!value.known) cancel.abort(new KernelStorageError('LEASE_FENCED', 'publication inspection was cancelled'));
    if (joining) return joining;
    joining = (async () => {
      await value.pending?.catch(() => {});
      // Borrowed originals remain owned by the RunExecution's original Set.
      // A probe join must never discard their only recoverable descriptors.
      if (value.ownsNative && value.physical && !value.physical.closed) {
        try {
          if (value.namespace) value.namespace.close();
          else { value.physical.native!.revoke(); value.physical.native!.close(); }
          value.physical.closed = true;
        }
        catch (error) { throw value.retirementFailure = error instanceof ResourceRetirementError ? error :
          new ResourceRetirementError('publication inspection native descriptors did not join', error); }
      }
      if (value.retirementFailure || value.physical?.retirementFailure) throw value.retirementFailure ?? value.physical!.retirementFailure;
    })(); return joining;
  } });
  reconciliationProducers.set(task, producer); return producer;
}

/** Fixed known-result publication can be retried after joined CAS failure.
 * It never reopens the namespace, repeats an effect, or cancels a real receipt. */
async function publishReconciliationFacts(value: ReconciliationBinding) {
  const held = value.physical!;
  if (held.arenaRetirementProof && !held.arenaRetirementRef)
    held.arenaRetirementRef = (await publishFixed(held, held.arenaRetirementProof, held.arenaRetirementProof.format)).ref;
  if (held.namespaceDestinationProof)
    await publishFixed(held, held.namespaceDestinationProof, held.namespaceDestinationProof.format);
  if (held.namespaceProof && !held.namespaceEvidenceRef)
    held.namespaceEvidenceRef = (await publishFixed(held, held.namespaceProof, held.namespaceProof.format)).ref;
  await publishFixed(held, value.evidence!, value.evidence!.format);
}
function knownReconciliationRetirement(value: ReconciliationBinding): PublicationPathRetirementV1 | undefined {
  if (value.disposition === 'unknown') return undefined;
  const held = value.physical!;
  if (!held.closed) invalid('publication known result lost its actual joined descriptors');
  if (held.namespaceProof) {
    if (!held.namespaceEvidenceRef || !held.namespaceDestinationProof)
      invalid('publication current namespace lost its durable original-envelope evidence');
    return { kind: 'current_namespace', namespaceEvidenceRef: held.namespaceEvidenceRef };
  }
  if (!held.arenaRetirementRef || !held.slotObservationRefs || held.slotObservationRefs.length < 1 || held.slotObservationRefs.length > 2)
    invalid('publication known result lost its complete actual original descriptor retirement');
  return { slotObservationRefs: [...held.slotObservationRefs], arenaRetirementRef: held.arenaRetirementRef };
}
function archiveOriginalReconciliationRetirement(value: ReconciliationBinding, retirement: PublicationPathRetirementV1 | undefined) {
  const original = value.original;
  if (!original || value.disposition === 'unknown') return;
  const disposition = value.disposition;
  if (disposition !== 'received' && disposition !== 'stopped_before_effect')
    invalid('publication inspection has no supported original-owner resolved retirement');
  const physicalOwner = value.physical!, entry = value.selection!.entry;
  if (!value.result || !value.wrapper || !value.wrapperRef || !value.metadata ||
      !retirement || 'kind' in retirement ||
      original.native !== physicalOwner.native || !physicalOwner.closed || !physicalOwner.arenaRetired || !original.closed ||
      !original.arenaRetired || original.preflight ||
      original.disposition?.disposition !== 'unknown' || !original.completion)
    invalid('publication inspection cannot transfer an unjoined or unrelated original retirement');
  const actual = physical(original, () => readRetiredPublicationArena(value.owner.filesystem, original.native!));
  requireEqual(actual.arenaIdentity, original.birth!.arenaIdentity, 'publication inspection original joined arena inode');
  requireEqual(actual.parentIdentity, original.birth!.parentIdentity, 'publication inspection original joined private parent');
  requireEqual(entry.claim, original.claim, 'publication inspection archived original permanent claim');
  const data: ReconciledPublicationRetirement = immutableSnapshot({ disposition,
    planRef: entry.planRef, operation: entry.operation, prepared: entry.prepared, claim: entry.claim!, birth: entry.birth!,
    unknownEvidenceRef: original.completion.evidenceRef, evidence: value.evidence!, evidenceRef: value.evidenceRef!,
    wrapper: value.wrapper, wrapperRef: value.wrapperRef, retirement, metadata: value.metadata });
  const previous = reconciledRetirements.get(original);
  if (previous) requireEqual(previous, { data, actual }, 'publication inspection same original retired fact');
  else reconciledRetirements.set(original, { data, actual: immutableSnapshot(actual) });
}
export async function readOwnedPublicationReconciliationResult(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, token: OwnedPublicationReconciliationResult) {
  const value = originalReconciliation(driver, artifacts, owner, execution, token), physical = value.physical!;
  await refreshReconciliationStop(value);
  if (!value.publishing) value.publishing = (async () => {
    await publishReconciliationFacts(value);
    await publishFixed(physical, value.wrapper!, value.wrapper!.format);
    value.metadata = metadata(physical);
  })().finally(() => { value.publishing = undefined; });
  await value.publishing;
  assertReconciliationSql(value, driver);
  const selected = value.selection!, entry = selected.entry, unknown = entry.history.find(row => row.phase === 'unknown');
  if (!unknown) invalid('publication inspection lost its original once-settled UNKNOWN');
  const prefix = snapshotPublicationReconciliationPrefix(selected.prefix);
  const retirement = knownReconciliationRetirement(value);
  if (value.disposition === 'received' && (value.evidence?.kind !== 'terminal_receipt' || !retirement || !entry.progress))
    invalid('publication inspection receipt lost its actual retirement and durable progress');
  archiveOriginalReconciliationRetirement(value, retirement);
  const common = { disposition: value.disposition!, isLastForwardPath: entry.sequence === 'forward' && entry.operation.index === entry.plan.forwardOperations.length - 1,
    run: immutableSnapshot(selected.run), prepared: immutableSnapshot(entry.prepared), claim: immutableSnapshot(entry.claim!), unknown: immutableSnapshot(unknown),
    plan: immutableSnapshot(entry.plan), planRef: entry.planRef, operation: immutableSnapshot(entry.operation), birth: immutableSnapshot(entry.birth!),
    evidence: immutableSnapshot(value.evidence!), evidenceRef: value.evidenceRef!, wrapper: immutableSnapshot(value.wrapper!), wrapperRef: value.wrapperRef!,
    ...(retirement ? { retirement: immutableSnapshot(retirement) } : {}),
    metadata: immutableSnapshot(value.metadata!), signal: value.resources.signal, cut: immutableSnapshot(selected.cut), prefix,
    entry: snapshotPublicationEntry(entry), wait: immutableSnapshot(selected.wait), target: immutableSnapshot(selected.target),
    settlement: immutableSnapshot(selected.settlement),
    generationResources: immutableSnapshot(value.generationResources), continuation: immutableSnapshot(value.continuation!) };
  if (value.disposition === 'received') {
    if (value.evidence?.kind !== 'terminal_receipt' || !retirement)
      invalid('publication inspection receipt lost its actual retirement and durable progress');
    return Object.freeze({ ...common, disposition: 'received' as const, receipt: immutableSnapshot(value.evidence), receiptRef: value.evidenceRef!,
      retirement: immutableSnapshot(retirement) });
  }
  return Object.freeze({ ...common, disposition: value.disposition as Exclude<PublicationPathDisposition['disposition'], 'received'> });
}
export function assertOwnedPublicationReconciliationSql(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, token: OwnedPublicationReconciliationResult, connection: SqliteConnection): void {
  assertReconciliationSql(originalReconciliation(driver, artifacts, owner, execution, token), connection);
}

/** Publish only the immutable original fact and actual retirement. A late
 * observation never obtains a subject_observation wrapper or a new nonce. */
export async function readOwnedPublicationLateObservation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, token: OwnedPublicationLateObservation) {
  const value = originalLateObservation(driver, artifacts, owner, execution, token), physical = value.physical!;
  await refreshReconciliationStop(value);
  if (!value.publishing) value.publishing = (async () => {
    await publishReconciliationFacts(value);
    value.metadata = metadata(physical);
  })().finally(() => { value.publishing = undefined; });
  await value.publishing;
  assertReconciliationSql(value, driver);
  const selected = value.selection!, state = selected.wait.probeState;
  if (state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight' ||
      value.known!.completedAt <= state.dispatch.probeDeadlineAt || value.wrapper || value.result)
    invalid('late publication audit lost its exact original expired dispatch');
  const retirement = knownReconciliationRetirement(value);
  return Object.freeze({ task: value.task, disposition: value.disposition!,
    evidence: immutableSnapshot(value.evidence!), evidenceRef: value.evidenceRef!, completedAt: value.known!.completedAt,
    ...(retirement ? { retirement: immutableSnapshot(retirement) } : {}), metadata: immutableSnapshot(value.metadata!),
    cut: immutableSnapshot(selected.cut), entry: snapshotPublicationEntry(selected.entry), wait: immutableSnapshot(selected.wait),
    target: immutableSnapshot(selected.target), continuation: immutableSnapshot(value.continuation!) });
}
/** Fixed audit writer only; no caller callback or supplied future cut. */
export function assertOwnedPublicationLateObservationSql(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, token: OwnedPublicationLateObservation, connection: SqliteConnection): void {
  assertReconciliationSql(originalLateObservation(driver, artifacts, owner, execution, token), connection);
}

/** Accept only the actual SQL delta of this producer's fixed audit. This
 * synchronous handoff follows its successful transaction before cancellation
 * can interrupt a reread. Supplied item data cannot bless a different graph. */
export function acceptOwnedPublicationLateObservationAudit(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, token: OwnedPublicationLateObservation, itemInput: PublicationLateObservationItem) {
  const value = originalLateObservation(driver, artifacts, owner, execution, token);
  assertActiveStateOwner(driver, owner);
  const item = decodePublicationLateObservationItem(itemInput), selected = value.selection!, entry = selected.entry;
  if (value.acceptedLateAudit) {
    requireEqual(item, value.acceptedLateAudit, 'same original committed late audit');
    assertReconciliationSql(value, driver);
    return { cut: immutableSnapshot(selected.cut), continuation: immutableSnapshot(value.continuation!) };
  }
  const state = selected.wait.probeState;
  if (state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight' ||
      value.known!.completedAt <= state.dispatch.probeDeadlineAt || item.createdAt < value.known!.completedAt)
    invalid('late audit cannot alter its original expired dispatch or causal time');
  const retirement = knownReconciliationRetirement(value);
  requireEqual(item, { schemaVersion: 1, kind: 'publication_late_observation',
    itemId: publicationLateObservationItemId(selected.run.id, entry.prepared.opId, 0, state.dispatch.dispatchDigest, value.evidenceRef!),
    runId: selected.run.id, deliveryPlanRef: entry.planRef, sequence: entry.sequence, operationIndex: entry.operation.index,
    operationId: entry.operation.operationId, opId: entry.prepared.opId, attempt: 0, dispatchId: entry.claim!.dispatchId!,
    claimJournalSeq: entry.claim!.seq, probeWaitingSubjectRef: selected.run.waitingOnRef!, probeDispatchDigest: state.dispatch.dispatchDigest,
    disposition: value.disposition, evidenceRef: value.evidenceRef!, evidenceDigest: value.evidence!.proofDigest, completedAt: value.known!.completedAt,
    ...(retirement ? { retirement } : {}), createdAt: item.createdAt }, 'late audit same original immutable fact and dispatch');
  const snapshot = reconciliationSqlCut(driver, selected.run.id, selected.admission.source.run.id);
  const itemSeq = selected.cut.items.length + 1, itemRef = canonicalSha256(item), added = { item, itemRef, itemSeq };
  const context = structuredClone(value.continuation!.context);
  context.segments.push({ kind: 'excluded_control', fromItemSeq: itemSeq, throughItemSeq: itemSeq, sourceItemsDigest: contextSourceDigest([added]) });
  context.throughItemSeq = itemSeq; context.projectionDigest = digestOmitting(context, 'projectionDigest');
  const existingItems = [...value.continuation!.existingItems, added];
  validateContextItems(context, existingItems);
  const checkpointId = publicationLateObservationCheckpointId(selected.run.id, entry.prepared.opId, 0,
    state.dispatch.dispatchDigest, value.evidenceRef!);
  const checkpoint = snapshot.checkpoint, now = checkpoint.createdAt;
  if (now < item.createdAt || now < selected.run.updatedAt) invalid('late audit Checkpoint preceded its actual item or winning Stop');
  requireEqual(checkpoint, { schemaVersion: 1, id: checkpointId, runId: selected.run.id, basedOnRunRevision: selected.run.revision,
    runItemSeq: itemSeq, contextManifestRef: canonicalSha256(context), journalSeq: selected.cut.journal.length,
    workspaceStateRef: selected.cut.latestCheckpoint.workspaceStateRef, createdAt: now, reason: 'auto' }, 'late audit exact original Checkpoint delta');
  const run = { ...selected.run, latestCheckpointId: checkpointId, revision: selected.run.revision + 1, updatedAt: now };
  requireEqual(snapshot, { ...value.snapshot!, run, checkpoint, items: [...value.snapshot!.items,
    { item_id: item.itemId, kind: item.kind, payload_ref: itemRef, item_seq: itemSeq, created_at: item.createdAt }] },
  'late audit only appends one item and Checkpoint without changing waiting, Journal, budget or frontier');
  const cut = { ...selected.cut, run, latestCheckpoint: checkpoint,
    items: [...selected.cut.items, { schemaVersion: 1 as const, itemId: item.itemId, payloadRef: itemRef,
      payloadDigest: itemRef, itemSeq, createdAt: item.createdAt }] };
  value.selection = { ...selected, run, cut }; value.snapshot = snapshot;
  value.continuation = { ...value.continuation!, context, existingItems }; value.acceptedLateAudit = item;
  return { cut: immutableSnapshot(cut), continuation: immutableSnapshot(value.continuation) };
}

const initialAmbiguityBrand: unique symbol = Symbol('OwnedPublicationInitialAmbiguity');
/** The real worker-death producer may conservatively settle its old claimed
 * publication. This never observes, reopens, adopts or cleans an arena. */
export type OwnedPublicationInitialAmbiguity = Readonly<{ readonly [initialAmbiguityBrand]: true }>;
type InitialAmbiguityBinding = {
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext;
  cut: RecoveryClosureV1; prefix: Prefix; entry: RetainedPublicationOperation;
  evidence: Extract<PublicationProofV1, { kind: 'path_ambiguity' }>; evidenceRef: string; metadata: PublishedArtifact[];
  continuation: ReconciliationContinuation; snapshot: ReturnType<typeof reconciliationSqlCut>; stop?: AgentStopIntent;
  originHistory?: RetainedStateOwnerHistory;
} & ({ kind: 'worker_death'; death: NativeContainmentDeathObservation; wait: WorkerDeathWait;
  launch: RecoveryClosureV1['workerLaunches'][number]; generation: RecoveryClosureV1['workspaceGenerations'][number] } |
  { kind: 'closed_maintenance'; execution: unknown; task: DeliveryPublicationReconciliationTask });
const initialAmbiguities = new WeakMap<object, InitialAmbiguityBinding>();
function originalInitialAmbiguity(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  token: OwnedPublicationInitialAmbiguity) {
  const value = token !== null && typeof token === 'object' ? initialAmbiguities.get(token) : undefined;
  if (!value || value.driver !== driver || value.artifacts !== artifacts || value.owner !== owner)
    throw new TypeError('a genuine same-owner publication initial ambiguity is required');
  if (value.kind === 'worker_death') assertNativeContainmentDeath(value.death);
  else assertOwnedPublicationReconciliationTask(driver, owner, value.execution, value.task, artifacts);
  assertActiveStateOwner(driver, owner); return value;
}

async function prepareInitialAmbiguityGraph(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  cut: RecoveryClosureV1, prefix: Prefix, entry: RetainedPublicationOperation, observedAfter: string, signal?: AbortSignal, deadlineAt?: string) {
  const claim = entry.claim!, birth = entry.birth;
  if (!birth || !claim.stateOwnerEpoch || !claim.supervisorInstanceId || !claim.dispatchId || !claim.evidenceRef ||
      claim.stateOwnerEpoch >= owner.ownerEpoch || claim.seq !== cut.journal.length)
    invalid('publication initial ambiguity cannot substitute its original permanent claim or owner death');
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const { origin, inspector, inspectorPlan, originPlan, originHistory } = await prepareRecoveryOrigin(driver, reads, owner,
    cut, entry, observedAfter, deadlineAt);
  const observedAt = origin.observedAt;
  const evidenceValue: Extract<PublicationProofV1, { kind: 'path_ambiguity' }> = { schemaVersion: 1, format: 'cliq-publication-proof-v1', deliveryRunId: cut.run.id,
    deliveryPlanRef: entry.planRef, workspaceIdentityRef: birth.workspaceIdentityRef, workspaceIdentityDigest: birth.workspaceIdentityDigest,
    inspectorIdentityRef: inspectorPlan.ref, inspectorIdentityDigest: inspector.identityDigest,
    recoveryOriginRef: originPlan.ref, recoveryOriginDigest: origin.originDigest, observedAt, kind: 'path_ambiguity', sequence: entry.sequence,
    operationIndex: entry.operation.index, operationId: entry.operation.operationId, opId: claim.opId, attempt: claim.attempt,
    launchDispatchId: claim.dispatchId, failure: 'transient_state_ambiguous', lastKnownObservationRefs: [], proofDigest: '' };
  evidenceValue.proofDigest = digestOmitting(evidenceValue, 'proofDigest');
  const evidence = decodePublicationProof(evidenceValue);
  if (evidence.kind !== 'path_ambiguity') invalid('publication initial ambiguity cannot claim a physical path outcome');
  const evidencePlan = planCanonicalArtifact(evidence, evidence.format), metadata = await joinResourceOperations(
    [inspectorPlan, originPlan, evidencePlan].map(plan => artifacts.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind)));
  await readPublicationRecoveryOrigin(driver, reads, prefix.admission, claim, birth, evidence);
  const continuation = await readReconciliationContinuation(reads, cut);
  const stop = cut.run.stopIntentRef ? await readAgentStop(driver, reads, cut) : undefined;
  signal?.throwIfAborted(); await assertPublicationReadCut(driver, reads, cut);
  const snapshot = reconciliationSqlCut(driver, cut.run.id, prefix.admission.source.run.id);
  requireEqual(snapshot.source, prefix.admission.source.run, 'publication initial ambiguity fully verified source Run');
  requireEqual(snapshot.sourceSession, immutableSessionIdentity(prefix.admission.source.session),
    'publication initial ambiguity fully verified source Session identity');
  return { cut, prefix, entry, evidence, evidenceRef: evidencePlan.ref, metadata, continuation, snapshot,
    ...(originHistory ? { originHistory } : {}), ...(stop ? { stop } : {}) };
}
export async function prepareOwnedPublicationInitialAmbiguity(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { runId: string; expectedRunRevision: number }, death: NativeContainmentDeathObservation, signal?: AbortSignal): Promise<OwnedPublicationInitialAmbiguity> {
  // A structural death, cut, worker wait or artifact can never reach SQLite.
  assertNativeContainmentDeath(death);
  const fields: Record<string, PropertyDescriptor> = input && typeof input === 'object' ? Object.getOwnPropertyDescriptors(input) : {};
  if (Reflect.ownKeys(fields).length !== 2 || !Object.hasOwn(fields, 'runId') || !Object.hasOwn(fields, 'expectedRunRevision') ||
      Object.values(fields).some(field => !field.enumerable || !Object.hasOwn(field, 'value')) ||
      typeof fields.runId?.value !== 'string' || !fields.runId.value || typeof fields.expectedRunRevision?.value !== 'number' ||
      !Number.isSafeInteger(fields.expectedRunRevision.value) || fields.expectedRunRevision.value < 1)
    throw new TypeError('publication initial ambiguity requires its exact original worker Run cut');
  input = Object.freeze({ ...input }); signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts, cut = await readRecoveryClosure(driver, reads, input.runId);
  if (cut.run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'publication initial ambiguity original revision changed');
  if (cut.runSpec.operation !== 'delivery' || cut.run.status !== 'waiting' || cut.run.waitingReason !== 'reconciliation' ||
      !cut.run.waitingOnRef || cut.run.activeWorkerLaunchId || cut.workerLaunches.length !== 1)
    invalid('publication initial ambiguity requires its actual original worker-death wait');
  const wait = await readCanonicalArtifact<WorkerDeathWait>(reads, cut.run.waitingOnRef), launch = cut.workerLaunches[0]!;
  const generation = cut.workspaceGenerations.find(row => row.generationRef === launch.workspaceGenerationRef);
  if (wait.subject.kind !== 'worker_death' || wait.probeState.phase !== 'automatic_in_flight' ||
      wait.probeState.dispatch.subjectKind !== 'worker_recovery' || wait.probeState.dispatch.owningSupervisorInstanceId !== owner.supervisorInstanceId ||
      launch.phase !== 'reconciling' || launch.generationWriteState !== 'fenced_reconciling' || generation?.phase !== 'fenced_reconciling' ||
      wait.subject.oldWorkerLaunchId !== launch.launchId || wait.subject.oldLeaseEpoch !== launch.leaseEpoch ||
      wait.subject.oldWorkerIdentity !== launch.workerIdentityDigest || wait.subject.processContainmentRef !== launch.processContainmentRef ||
      wait.subject.workspaceGenerationRef !== generation.generationRef || canonicalSha256(death.containment) !== launch.processContainmentRef ||
      death.observedAt < wait.probeState.dispatch.probeStartedAt || death.observedAt > wait.probeState.dispatch.probeDeadlineAt)
    invalid('publication initial ambiguity changed its actual old worker, containment or persisted death task');
  const anchor = await readWorkerRecoveryAnchor(reads, wait, generation);
  if (anchor.anchor.fencedJournalSeq !== cut.journal.length || generation.fencedJournalSeq !== cut.journal.length)
    invalid('publication initial ambiguity cannot add a later claim to the original worker fence');
  const prefix = await readPublicationPrefix(driver, reads, cut), unresolved = [...prefix.entries.values()].filter(row =>
    row.claim && !row.result && !row.receivedHandoff && !row.preparationClosure);
  if (unresolved.length !== 1 || !prefix.authorization || unresolved[0]!.history.length !== 2 ||
      unresolved[0]!.history[0]!.phase !== 'prepared' || unresolved[0]!.history[1]!.phase !== 'dispatch_claimed')
    invalid('publication initial ambiguity requires its one original unsettled permanent claim');
  const entry = unresolved[0]!, claim = entry.claim!, birth = entry.birth;
  if (!birth || !claim.stateOwnerEpoch || !claim.supervisorInstanceId || !claim.dispatchId || !claim.evidenceRef ||
      claim.leaseEpoch !== launch.leaseEpoch || claim.supervisorInstanceId !== launch.supervisorInstanceId ||
      claim.stateOwnerEpoch >= owner.ownerEpoch || claim.seq !== cut.journal.length)
    invalid('publication initial ambiguity cannot substitute its original claimed worker or owner death');
  const graph = await prepareInitialAmbiguityGraph(driver, artifacts, owner, cut, prefix, entry, death.observedAt, signal, wait.probeState.dispatch.probeDeadlineAt);
  assertNativeContainmentDeath(death);
  const token: OwnedPublicationInitialAmbiguity = Object.freeze({ [initialAmbiguityBrand]: true as const });
  initialAmbiguities.set(token, { kind: 'worker_death', driver, artifacts, owner, death, wait, launch, generation, ...graph });
  return token;
}
/** A worker-free abort has its distinct genuine maintenance inspection task.
 * The old M is never adopted as a worker of this later maintenance owner. */
export async function prepareOwnedPublicationMaintenanceAmbiguity(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, task: DeliveryPublicationReconciliationTask): Promise<OwnedPublicationInitialAmbiguity> {
  const resources = assertDeliveryPublicationReconciliationExecution(driver, owner, execution, task, artifacts);
  const reads = artifacts.withReadSignal(resources.signal), cut = await readRecoveryClosure(driver, reads, resources.runId);
  if (cut.run.revision !== resources.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'maintenance initial ambiguity original cut changed');
  if (cut.runSpec.operation !== 'delivery' || cut.run.status !== 'queued' || cut.run.nextStep !== 'delivery' || !cut.run.stopIntentRef ||
      cut.run.activeWorkerLaunchId || cut.workerLaunches.length || cut.workspaceGenerations.some(row => !['retired', 'sealed'].includes(row.phase)))
    invalid('maintenance initial ambiguity requires its genuine stopped worker-free original Run');
  const prefix = await readPublicationPrefix(driver, reads, cut), unresolved = [...prefix.entries.values()].filter(row =>
    row.claim && !row.result && !row.receivedHandoff && !row.preparationClosure);
  if (unresolved.length !== 1 || !prefix.authorization || unresolved[0]!.sequence !== 'abort' || unresolved[0]!.operation.kind !== 'abort_rmdir' ||
      unresolved[0]!.history.length !== 2 || unresolved[0]!.history[0]!.phase !== 'prepared' || unresolved[0]!.history[1]!.phase !== 'dispatch_claimed')
    invalid('maintenance initial ambiguity cannot manufacture a productive or unresolved foreign envelope');
  const entry = unresolved[0]!;
  const workspace = prefix.authorization.workspace;
  if (workspace.kind !== 'live' || heldWorkspaceRootPath(resources.workspaceRoot) !== workspace.canonicalRootPath)
    invalid('maintenance initial ambiguity changed its original approved workspace');
  requireEqual(resources.workspaceRoot.identity, workspace.rootIdentity, 'maintenance initial ambiguity original held workspace root');
  requireEqual(entry.prepared.budgetDelta, ZERO_BUDGET, 'maintenance initial ambiguity original zero reservation');
  requireEqual(cut.run.budgetReserved, ZERO_BUDGET, 'maintenance initial ambiguity cannot release a productive reservation');
  await readClosedMaintenanceM(driver, reads, cut, prefix, entry);
  const graph = await prepareInitialAmbiguityGraph(driver, artifacts, owner, cut, prefix, entry, entry.claim!.timestamp, resources.signal);
  const current = assertDeliveryPublicationReconciliationExecution(driver, owner, execution, task, artifacts);
  if (current.workspaceRoot !== resources.workspaceRoot || current.controlledHome !== resources.controlledHome)
    invalid('maintenance initial ambiguity changed its actual original roots');
  const token: OwnedPublicationInitialAmbiguity = Object.freeze({ [initialAmbiguityBrand]: true as const });
  initialAmbiguities.set(token, { kind: 'closed_maintenance', driver, artifacts, owner, execution, task, ...graph });
  return token;
}
export async function readOwnedPublicationInitialAmbiguity(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  token: OwnedPublicationInitialAmbiguity) {
  const value = originalInitialAmbiguity(driver, artifacts, owner, token), refreshed = await reselectPublicationStop(driver, artifacts, owner,
    value.cut, value.prefix.admission.source.run.id, value.snapshot, value.stop);
  value.cut = refreshed.cut; value.snapshot = refreshed.snapshot; value.stop = refreshed.stop;
  assertOwnedPublicationInitialAmbiguitySql(driver, artifacts, owner, token, driver);
  const prefix = snapshotPublicationReconciliationPrefix(value.prefix);
  return Object.freeze({ kind: value.kind, cut: immutableSnapshot(value.cut), prefix, entry: snapshotPublicationEntry(value.entry),
    ...(value.kind === 'worker_death' ? { wait: immutableSnapshot(value.wait), launch: immutableSnapshot(value.launch), generation: immutableSnapshot(value.generation) } : {}),
    prepared: immutableSnapshot(value.entry.prepared),
    claim: immutableSnapshot(value.entry.claim!), birth: immutableSnapshot(value.entry.birth!), evidence: immutableSnapshot(value.evidence), evidenceRef: value.evidenceRef,
    metadata: immutableSnapshot(value.metadata), continuation: immutableSnapshot(value.continuation) });
}
export function assertOwnedPublicationInitialAmbiguitySql(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  token: OwnedPublicationInitialAmbiguity, connection: SqliteConnection): void {
  const value = originalInitialAmbiguity(driver, artifacts, owner, token);
  assertActiveStateOwner(connection, owner);
  value.originHistory?.assertUnchanged(connection);
  const now = sampleCanonicalNow();
  if (now < value.evidence.observedAt || value.kind === 'worker_death' &&
      (value.wait.probeState.phase !== 'automatic_in_flight' || now >= value.wait.probeState.dispatch.probeDeadlineAt))
    throw new KernelStorageError('LEASE_FENCED', 'publication initial ambiguity lost its exact original worker probe lifetime');
  requireEqual(reconciliationSqlCut(connection, value.cut.run.id, value.prefix.admission.source.run.id), value.snapshot,
    'publication initial ambiguity original worker wait, permanent claim, source and resources');
}
