import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import { decodeDeliveryCaptureTopology, decodeDeliveryTerminalProjectionEvidence, decodePublicationProof,
  type DeliveryTerminalProjectionEvidence, type PublicationProofV1 } from '../kernel/publication.js';
import type { RecoveryClosureV1, Run, RunFrontier } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { captureFrozenSourceProjection, MAX_SOURCE_PROJECTION_ENTRIES } from '../workspace/source-projection.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { decodeSourceManifest, decodeWorkspaceEntries, decodeWorkspaceIdentity } from './decoders.js';
import { deliveryPublicationCheckpointId } from './delivery-publication-progress.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath, stateRootIdentityForLock } from './native-owner.js';
import { openPublicationProjectionGate, readDeliveryTerminalSqlCut } from './publication-finalization.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import { readCheckpoint } from './rows.js';
import { assertOwnedNoOpDeliveryTask, readOwnedNoOpDeliveryExecutionResources, type DeliveryNoOpTask } from './run-execution.js';
import { loadRunResult, readOwnedPublicationResultPlan, type OwnedPublicationResultPlan } from './run-result.js';
import { prepareDeliveryNoOpVerification } from './run-result-recovery.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readSupervisorInspector, supervisorInspectorIdentity } from './supervisor-inspector.js';

const brand: unique symbol = Symbol('OwnedNoOpDeliveryFinalization');
export type OwnedNoOpDeliveryFinalization = Readonly<{ readonly [brand]: true }>;
type Resources = Awaited<ReturnType<typeof readOwnedNoOpDeliveryExecutionResources>>;
type Verification = Awaited<ReturnType<typeof prepareDeliveryNoOpVerification>>;
type SqlCut = ReturnType<typeof readDeliveryTerminalSqlCut>;
type Binding = {
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; execution: unknown; task: DeliveryNoOpTask;
  resources: Resources; cut: RecoveryClosureV1; verification: Verification; sql: SqlCut;
  gate: Awaited<ReturnType<typeof openPublicationProjectionGate>>;
  evidence: DeliveryTerminalProjectionEvidence; evidenceRef: string;
  frontier: Extract<RunFrontier, { kind: 'finalize'; operation: 'delivery' }>; frontierRef: string;
  metadata: PublishedArtifact[]; result?: OwnedPublicationResultPlan; closed: boolean;
  installed?: { sql: SqlCut; committedAt: string };
};
const plans = new WeakMap<object, Binding>();
const failures = new WeakMap<object, { driver: SqliteDriver; owner: StateOwnerContext; execution: unknown; error: ResourceRetirementError }>();
class SessionChanged extends Error {}
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function original(driver: SqliteDriver, owner: StateOwnerContext, token: unknown): Binding {
  const held = token !== null && typeof token === 'object' ? plans.get(token) : undefined;
  if (!held || held.driver !== driver || held.owner !== owner) throw new TypeError('a genuine original no-op finalization is required');
  const failure = failures.get(held.task); if (failure) throw failure.error;
  assertOwnedNoOpDeliveryTask(driver, owner, held.execution, held.task, held.artifacts);
  if (held.closed) invalid('no-op projection descriptors are already joined');
  held.resources.signal.throwIfAborted(); return held;
}
function close(value: Binding) {
  if (value.closed) return;
  try { value.gate.close(); value.closed = true; }
  catch (cause) {
    const failure = cause instanceof ResourceRetirementError ? cause : new ResourceRetirementError('no-op projection did not join', cause);
    failures.set(value.task, { driver: value.driver, owner: value.owner, execution: value.execution, error: failure }); throw failure;
  }
}
function validate(value: Binding, connection: SqliteConnection, committedAt?: string) {
  assertOwnedNoOpDeliveryTask(value.driver, value.owner, value.execution, value.task, value.artifacts);
  value.resources.signal.throwIfAborted(); assertActiveStateOwner(connection, value.owner);
  requireEqual(readDeliveryTerminalSqlCut(connection, value.cut.run.id, value.sql.source.id), value.sql,
    'no-op original full Run, source and owned SQL cut');
  value.gate.assertHeld();
  if (value.result && !readOwnedPublicationResultPlan(value.driver, value.owner, value.result).sessionMatches(connection)) throw new SessionChanged();
  if (committedAt && (committedAt < value.evidence.observedAt || committedAt >= value.cut.run.deadlineAt ||
      parseCanonicalTime(committedAt) - parseCanonicalTime(value.evidence.observedAt) > 5000))
    invalid('no-op actual root projection is outside its original freshness or Run lifetime');
}

async function prepare(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, execution: unknown, task: DeliveryNoOpTask) {
  const failed = failures.get(task);
  if (failed?.driver === driver && failed.owner === owner && failed.execution === execution) throw failed.error;
  const resources = await readOwnedNoOpDeliveryExecutionResources(driver, owner, execution, task, artifacts);
  const reads = artifacts.withReadSignal(resources.signal), cut = await readRecoveryClosure(driver, reads, resources.runId);
  if (cut.run.revision !== resources.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'no-op original task revision changed');
  const verification = await prepareDeliveryNoOpVerification(driver, reads, cut, sampleCanonicalNow());
  const delivery = verification.basis.delivery!;
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(reads, delivery.admission.target.workspaceIdentityRef));
  if (workspace.kind !== 'live' || workspace.identityDigest !== delivery.admission.target.workspaceIdentityDigest)
    invalid('no-op projection lost its original live workspace identity');
  const capture = delivery.admission.inspection.outcome;
  if (capture.kind !== 'captured') invalid('no-op projection lost its original captured topology');
  const topology = decodeDeliveryCaptureTopology(await readCanonicalArtifact(reads, capture.captureTopologyRef));
  const desired = decodeSourceManifest(await readCanonicalArtifact(reads, verification.basis.candidate.resultSourceRef));
  const entries = decodeWorkspaceEntries(await readCanonicalArtifact(reads, desired.entriesRef));
  const profile = decodeSandboxProfile(await readCanonicalArtifact(reads, cut.runSpec.sandboxProfileRef));
  const stateOwner = assertActiveStateOwner(driver, owner), inspector = supervisorInspectorIdentity(stateOwner);
  const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  await readSupervisorInspector(reads, stateOwner, delivery.admission.source.assembly, {
    inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, observedAt: sampleCanonicalNow() });
  const sql = readDeliveryTerminalSqlCut(driver, cut.run.id, delivery.admission.source.run.id);
  requireEqual(sql.run, cut.run, 'no-op original Run after full retained reads');
  requireEqual(sql.source, delivery.admission.source.run, 'no-op original source terminal Run');
  const gate = await openPublicationProjectionGate(resources.workspaceRoot, entries.entries, [], resources.signal);
  let value: Binding | undefined;
  try {
    assertHeldWorkspaceRoot(resources.controlledHome); stateRootIdentityForLock(owner.filesystem);
    requireEqual(resources.workspaceRoot.identity, workspace.rootIdentity, 'no-op actual original workspace root');
    if (heldWorkspaceRootPath(resources.workspaceRoot) !== workspace.canonicalRootPath)
      invalid('no-op projection changed its original workspace path');
    gate.assertOriginalIdentities(topology, new Map(), workspace.identityDigest);
    const captured = await captureFrozenSourceProjection({ workspaceRoot: resources.workspaceRoot, controlledHome: resources.controlledHome,
      stateOwnerLock: owner.filesystem, workspaceIdentityDigest: workspace.identityDigest, artifacts: reads,
      sourceProjectionRef: cut.runSpec.sourceProjectionRef, sourceProjectionDigest: desired.sourceProjectionDigest,
      maxEntries: MAX_SOURCE_PROJECTION_ENTRIES, maxBytes: profile.resources.maxGenerationBytes,
      maxSingleFileBytes: profile.resources.maxSingleFileBytes, signal: resources.signal });
    if (captured.resultWorkspaceManifestRef !== verification.basis.candidate.resultSourceRef)
      invalid('no-op actual complete root projection differs from its role-normalized desired source');
    gate.assertHeld();
    const observedAt = sampleCanonicalNow();
    if (observedAt < verification.closure.createdAt || observedAt < cut.run.updatedAt)
      invalid('no-op actual root observation predates its complete original verification');
    const metadata = [...verification.metadata, inspectorArtifact, ...captured.metadata];
    type Fields<T = PublicationProofV1> = T extends PublicationProofV1 ? Omit<T, 'schemaVersion' | 'format' | 'deliveryRunId' | 'deliveryPlanRef' |
      'workspaceIdentityRef' | 'workspaceIdentityDigest' | 'inspectorIdentityRef' | 'inspectorIdentityDigest' | 'proofDigest' | 'observedAt'> : never;
    const publish = async (fields: Fields) => {
      resources.signal.throwIfAborted(); assertHeldWorkspaceRoot(resources.workspaceRoot);
      const proof = { schemaVersion: 1, format: 'cliq-publication-proof-v1', deliveryRunId: cut.run.id, deliveryPlanRef: delivery.merged.planRef,
        workspaceIdentityRef: delivery.admission.target.workspaceIdentityRef, workspaceIdentityDigest: workspace.identityDigest,
        inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, ...fields, observedAt, proofDigest: '' };
      proof.proofDigest = digestOmitting(proof, 'proofDigest'); decodePublicationProof(proof);
      const artifact = await artifacts.publishCanonical(proof, proof.format); metadata.push(artifact); return artifact.ref;
    };
    const transientAbsenceEvidenceRef = await publish({ kind: 'transient_absence', transientLocations: [], observationRefs: [], arenaRetirementRefs: [] });
    const projectionClosureEvidenceRef = await publish({ kind: 'projection_closure', selectedBranch: 'forward_finalize',
      observedSourceRef: captured.resultWorkspaceManifestRef, observedPathEvidenceRefs: [], forwardResultItemRefs: [],
      unstartedForwardOperationIds: [], abortResultItemRefs: [] });
    const gitIndexUnchangedEvidenceRef = await publish({ kind: 'git_index_unchanged', repositoryKind: 'non_git' });
    const core = { schemaVersion: 1 as const, deliveryRunId: cut.run.id, deliveryPlanRef: delivery.merged.planRef, selectedBranch: 'forward_finalize',
      observedSourceRef: captured.resultWorkspaceManifestRef, observedPathStates: [], forwardResultItemRefs: [], unstartedForwardOperationIds: [],
      abortResultItemRefs: [], transientAbsenceEvidenceRef, projectionClosureEvidenceRef, gitIndexUnchangedEvidenceRef, observedAt };
    const evidence = decodeDeliveryTerminalProjectionEvidence({ ...core, evidenceDigest: canonicalSha256(core) });
    const projectionArtifact = await artifacts.publishCanonical(evidence, 'cliq-delivery-terminal-projection-evidence-v1'); metadata.push(projectionArtifact);
    const frontier: Binding['frontier'] = { schemaVersion: 1, kind: 'finalize', operation: 'delivery',
      candidateItemId: verification.basis.candidate.itemId, resultSourceRef: verification.basis.candidate.resultSourceRef,
      verificationClosureRef: verification.verificationClosureRef, deliveryTerminalProjectionEvidenceRef: projectionArtifact.ref };
    const frontierArtifact = await artifacts.publishCanonical(frontier, 'cliq-run-frontier-v1'); metadata.push(frontierArtifact);
    const token = Object.freeze({ [brand]: true as const });
    value = { driver, artifacts, owner, execution, task, resources, cut, verification, sql, gate, evidence, evidenceRef: projectionArtifact.ref,
      frontier, frontierRef: frontierArtifact.ref, metadata, closed: false };
    plans.set(token, value);
    value.result = await loadRunResult(driver, artifacts, owner, { run: cut.run, spec: cut.runSpec, principalId: verification.basis.principalId })
      .prepareOwnedNoOpDeliveryResult(execution, task, token);
    value.metadata.push(...readOwnedPublicationResultPlan(driver, owner, value.result).metadata);
    validate(value, driver); return token;
  } catch (error) {
    if (value) close(value);
    else try { gate.close(); } catch (cause) {
      const failure = cause instanceof ResourceRetirementError ? cause : new ResourceRetirementError('no-op projection did not join', cause);
      failures.set(task, { driver, owner, execution, error: failure }); throw failure;
    }
    throw error;
  }
}

/** Fixed real execution task only. No publication effect, claim, caller proof,
 * synthetic seal or intermediate externally visible finalize is created. */
export async function completeOwnedNoOpDelivery(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, task: DeliveryNoOpTask): Promise<Run> {
  for (let retry = 0; retry < 8; retry++) {
    let token: OwnedNoOpDeliveryFinalization | undefined;
    try {
      token = await prepare(driver, artifacts, owner, execution, task);
      const value = original(driver, owner, token);
      let outcome: TimeFenceAdvance | undefined, terminal: Run | undefined;
      driver.transaction(connection => {
        validate(value, connection);
        const now = sampleCanonicalNow();
        outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
        for (const artifact of value.metadata) insertArtifactMetadata(connection, artifact, now);
        const committedAt = sampleCanonicalNow();
        outcome = advanceTimeFence(connection, owner.ownerEpoch, committedAt);
        if (outcome !== 'healthy') invalid('no-op canonical time fence changed during registration');
        validate(value, connection, committedAt);
        value.verification.commitVerificationCheckpoint(connection, committedAt);
        const run = value.cut.run, checkpoint = { id: deliveryPublicationCheckpointId(run.id, value.evidence.deliveryPlanRef), schemaVersion: 1 as const,
          runId: run.id, basedOnRunRevision: run.revision, runItemSeq: value.cut.items.length,
          contextManifestRef: value.cut.latestCheckpoint.contextManifestRef, journalSeq: value.cut.journal.length,
          workspaceStateRef: value.cut.latestCheckpoint.workspaceStateRef, createdAt: committedAt, reason: 'auto' as const };
        connection.prepare(`INSERT INTO checkpoints (id,schema_version,run_id,based_on_run_revision,run_item_seq,
          context_manifest_ref,journal_seq,workspace_state_ref,created_at,reason) VALUES (?,1,?,?,?,?,?,?,?,'auto')`)
          .run(checkpoint.id, run.id, BigInt(run.revision), BigInt(checkpoint.runItemSeq), checkpoint.contextManifestRef,
            BigInt(checkpoint.journalSeq), checkpoint.workspaceStateRef, committedAt);
        connection.prepare("UPDATE runs SET next_step='finalize',frontier_ref=?,latest_checkpoint_id=?,revision=revision+1,updated_at=? WHERE id=?")
          .run(value.frontierRef, checkpoint.id, committedAt, run.id);
        const installed = readDeliveryTerminalSqlCut(connection, run.id, value.sql.source.id);
        requireEqual(installed, { ...value.sql, run: { ...run, nextStep: 'finalize', frontierRef: value.frontierRef,
          latestCheckpointId: checkpoint.id, revision: run.revision + 1, updatedAt: committedAt }, checkpoint },
        'no-op exact actual verification and publication Checkpoint transaction');
        value.installed = { sql: installed, committedAt };
        if (!value.result) invalid('no-op sole terminal writer has not prepared its immutable result');
        terminal = readOwnedPublicationResultPlan(driver, owner, value.result).commit(connection, committedAt);
        appendRunStateEvent(connection, terminal, committedAt); close(value);
      });
      requireHealthyFence(outcome);
      if (!terminal) invalid('no-op result did not commit under its original healthy time fence');
      return terminal;
    } catch (error) { if (!(error instanceof SessionChanged) || retry === 7) throw error; }
    finally { if (token) close(originalForClose(driver, owner, token)); }
  }
  throw new KernelStorageError('REVISION_CONFLICT', 'no-op result Session kept changing');
}
function originalForClose(driver: SqliteDriver, owner: StateOwnerContext, token: OwnedNoOpDeliveryFinalization) {
  const value = plans.get(token);
  if (!value || value.driver !== driver || value.owner !== owner) throw new TypeError('a genuine original no-op finalization is required');
  return value;
}

/** Sole-result-writer friend: data is produced only by the genuine task above. */
export function readOwnedNoOpTerminalMaterial(driver: SqliteDriver, owner: StateOwnerContext, execution: unknown,
  task: DeliveryNoOpTask, token: OwnedNoOpDeliveryFinalization) {
  const value = original(driver, owner, token);
  if (value.execution !== execution || value.task !== task) throw new TypeError('no-op result changed its exact original task');
  const basis = value.verification.basis;
  return { run: value.cut.run, spec: value.cut.runSpec, principalId: basis.principalId, candidate: basis.candidate,
    closure: value.verification.closure, verificationReceiptRefs: basis.verificationReceiptRefs,
    summaryDigest: basis.summary.textDigest, projection: value.evidence, frontier: value.frontier };
}
export function assertOwnedNoOpTerminalSql(driver: SqliteDriver, owner: StateOwnerContext, token: OwnedNoOpDeliveryFinalization,
  connection: SqliteConnection, committedAt: string): void {
  const value = original(driver, owner, token), installed = value.installed;
  if (!installed || installed.committedAt !== committedAt) invalid('no-op result has no actual same-transaction publication');
  requireEqual(readDeliveryTerminalSqlCut(connection, value.cut.run.id, value.sql.source.id), installed.sql,
    'no-op complete actual installed terminal SQL cut');
  const expected = { id: value.verification.checkpointId, schemaVersion: 1 as const, runId: value.cut.run.id,
    basedOnRunRevision: value.cut.run.revision, runItemSeq: value.cut.items.length, contextManifestRef: value.cut.latestCheckpoint.contextManifestRef,
    journalSeq: value.cut.journal.length, workspaceStateRef: value.cut.latestCheckpoint.workspaceStateRef, createdAt: committedAt, reason: 'auto' as const };
  requireEqual(readCheckpoint(connection, expected.id), expected, 'no-op actual same-transaction verification Checkpoint');
  value.gate.assertHeld();
  const actualNow = sampleCanonicalNow();
  if (actualNow < committedAt || actualNow >= value.cut.run.deadlineAt ||
      parseCanonicalTime(actualNow) - parseCanonicalTime(value.evidence.observedAt) > 5000)
    invalid('no-op actual root projection aged before its sole terminal writer');
}
