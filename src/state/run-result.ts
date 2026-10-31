import { observeInstalledPublicationWork } from './installed-run-diagnostics.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { FinalCandidateItem, RunResult, VerificationClosureV1 } from '../kernel/result.js';
import type { Checkpoint, RecoveryClosureV1, Run, RunFrontier, RunSpec, SessionRunTerminalItem } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { decodeAdmittedContext, decodeSessionProjection } from './decoders.js';
import { KernelStorageError, stateOperation } from './errors.js';
import { assertRetiredGenerationCut } from './generation-retirement.js';
import { readResultRecoveryClosure, type RecoveryClosurePhase } from './recovery-closure.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { decodeRunResult, decodeVerificationClosure } from './result-artifacts.js';
import { expectedInheritedVerificationProvenance, expectedVerificationClosure, readDeliveryVerification,
  readFinalization, readResultBasis, runResultCheckpointId, verificationCheckpointId } from './run-result-recovery.js';
import { readCheckpoint, readControlRequest, readRun, readSession } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import type { OwnedPublicationFinalization } from './publication-finalization.js';
import type { OwnedNoOpDeliveryFinalization } from './delivery-noop-finalization.js';
import type { DeliveryNoOpTask } from './run-execution.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import { prepareChildTerminalAllocation } from './child-terminal-publication.js';
import { assertChildAncestryRelease } from './child-ancestry.js';

/** Fixed, inert progress labels for the installed owner's shutdown diagnosis.
 * They carry no result data, permission, time fence or recovery evidence. */
export type RunResultPhase = 'result_recovery' | 'result_basis' | 'result_finalization' |
  'result_publication' | 'result_session' | 'result_commit' | `result_recovery_${RecoveryClosurePhase}`;
class ResultSessionChanged extends Error {}
type TerminalMaterial = {
  candidate: FinalCandidateItem; verificationReceiptRefs: string[]; summaryDigest: string;
  status: 'succeeded' | 'completed_unverified'; terminalReason: 'verified' | 'no_required_verifier';
  closure: VerificationClosureV1;
};
type TerminalSqlCut = { run: Run; latestCheckpoint: Checkpoint; itemCount: number; journalSeq: number };
type OwnedTerminalMaterial = Omit<TerminalMaterial, 'status' | 'terminalReason'> & {
  run: Run; spec: RunSpec; principalId: string; projection: { observedAt: string };
  frontier: Extract<RunFrontier, { kind: 'finalize'; operation: 'delivery' }>;
};
const publicationResultBrand: unique symbol = Symbol('OwnedPublicationResultPlan');
export type OwnedPublicationResultPlan = Readonly<{ readonly [publicationResultBrand]: true }>;
const publicationResultPlans = new WeakMap<object, { driver: SqliteDriver; owner: StateOwnerContext;
  metadata: readonly import('./artifacts.js').PublishedArtifact[]; sessionMatches(connection: SqliteConnection): boolean;
  commit(connection: SqliteConnection, committedAt: string): Run }>();
/** Internal friend: a returned function is owned by the real preparation, not a
 * callback supplied by a caller. It rechecks the original finalization token. */
export function readOwnedPublicationResultPlan(driver: SqliteDriver, owner: StateOwnerContext, token: OwnedPublicationResultPlan) {
  const plan = token !== null && typeof token === 'object' ? publicationResultPlans.get(token) : undefined;
  if (!plan || plan.driver !== driver || plan.owner !== owner) throw new TypeError('a genuine original publication result plan is required');
  return { metadata: plan.metadata, sessionMatches: plan.sessionMatches, commit: plan.commit };
}

/** Store-derived completion only. A no-required-check result is explicitly unverified;
 * this module grants no execution permission and accepts no caller proof/list. */
export function loadRunResult(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  authority: { run: Run; spec: RunSpec; principalId: string }, onPhase?: (phase: RunResultPhase) => void,
  resultPreparationSignal?: AbortSignal) {
  const { run: admitted, spec, principalId } = authority, runId = admitted.id;
  // Only effect-free normal result preparation borrows this read lifetime.
  // Owned publication/no-op results retain their original real producer scope.
  const resultReads = resultPreparationSignal ? artifacts.withReadSignal(resultPreparationSignal) : artifacts;
  const phase = (value: RunResultPhase) => { try { onPhase?.(value); } catch { /* Diagnosis cannot decide execution. */ } };
  function revision(input: { expectedRunRevision: number }): number {
    if (!input || !exactKeys(input, ['expectedRunRevision']) || !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1)
      throw new TypeError('result requires one exact expected revision');
    return input.expectedRunRevision;
  }
  async function load() {
    resultReads.assertReadActive();
    assertActiveStateOwner(driver, owner);
    phase('result_recovery');
    const { cut, basis } = await observeInstalledPublicationWork(runId, 'result_recovery',
      () => readResultRecoveryClosure(driver, resultReads, runId, value => phase(`result_recovery_${value}`)));
    resultReads.assertReadActive();
    assertActiveStateOwner(driver, owner);
    if (cut.run.specRef !== admitted.specRef || cut.run.createdAt !== admitted.createdAt || cut.run.deadlineAt !== admitted.deadlineAt ||
        canonicalSha256(cut.runSpec) !== canonicalSha256(spec)) throw new TypeError('result authority no longer belongs to this Run');
    phase('result_basis');
    if (basis.principalId !== principalId) throw new TypeError('result authority belongs to another principal');
    return { cut, basis };
  }
  function unstopped(run: Run, step: 'verify' | 'finalize' | 'delivery') {
    if (run.status !== 'queued' || run.nextStep !== step || !run.frontierRef || run.stopIntentRef || run.cancelRequested ||
        run.resultRef || run.terminalDetailRef || run.terminalReason)
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'result requires its exact unstopped completion frontier');
  }
  const itemRows = (connection: SqliteConnection) => connection.prepare(
    'SELECT item_id, item_seq, kind, payload_ref, created_at FROM items WHERE run_id = ? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: bigint; kind: string; payload_ref: string; created_at: string }>(runId)
    .map(row => ({ ...row, item_seq: Number(row.item_seq) }));
  function capture(cut: RecoveryClosureV1, basis: Awaited<ReturnType<typeof readResultBasis>>) {
    const launches = readWorkerLaunchesForRun(driver, runId), generations = readWorkspaceGenerationsForRun(driver, runId), items = itemRows(driver);
    const allocations = readChildAllocationsForRun(driver, runId);
    return (connection: SqliteConnection) => {
      resultReads.assertReadActive();
      assertActiveStateOwner(connection, owner);
      if ('childAdmission' in basis && basis.childAdmission) {
        for (const edge of [basis.childAdmission, ...basis.childAdmission.ancestors]) edge.assertUnchanged(connection);
        basis.childAdmission.rootOrigin.assertUnchanged(connection);
      }
      const admission = connection.prepare(`SELECT principal_id, admission_method, admission_key, admission_intent_digest,
        admission_request_id FROM runs WHERE id = ?`).get(runId);
      if (canonicalSha256(readRun(connection, runId)) !== canonicalSha256(cut.run) ||
          canonicalSha256(readCheckpoint(connection, cut.run.latestCheckpointId)) !== canonicalSha256(cut.latestCheckpoint) ||
          canonicalSha256(readInvocationJournal(connection, runId)) !== canonicalSha256(cut.journal) ||
          canonicalSha256(readWorkerLaunchesForRun(connection, runId)) !== canonicalSha256(launches) ||
          canonicalSha256(readWorkspaceGenerationsForRun(connection, runId)) !== canonicalSha256(generations) ||
          canonicalSha256(itemRows(connection)) !== canonicalSha256(items) || canonicalSha256(admission) !== canonicalSha256(basis.admission) ||
          (!cut.run.parentRunId && canonicalSha256(readControlRequest(connection, principalId, spec.operation === 'agent' ? 'run.submit' : 'run.apply',
            basis.admission.admission_request_id!)) !== canonicalSha256(basis.original)) ||
          canonicalSha256(readChildAllocationsForRun(connection, runId)) !== canonicalSha256(allocations))
        throw new KernelStorageError('REVISION_CONFLICT', 'result candidate, dispatch, generation or admission cut changed');
      if (basis.delivery && (canonicalSha256(readRun(connection, basis.delivery.admission.source.run.id)) !==
          canonicalSha256(basis.delivery.admission.source.run) || readSession(connection, cut.run.sessionId).workspaceIdentityRef !==
          basis.delivery.admission.source.session.workspaceIdentityRef))
        throw new KernelStorageError('REVISION_CONFLICT', 'delivery source terminal result or original workspace identity changed');
      assertRetiredGenerationCut(connection, cut.run, generations);
    };
  }
  function time(connection: SqliteConnection, preparedAt: string, run: Run) {
    const committedAt = sampleCanonicalNow(), outcome = advanceTimeFence(connection, owner.ownerEpoch, committedAt);
    if (outcome === 'healthy' && (committedAt < preparedAt || committedAt < run.updatedAt || committedAt >= run.deadlineAt))
      throw new KernelStorageError('LEASE_FENCED', 'result is outside its healthy immutable Run lifetime');
    return { committedAt, outcome };
  }
  const terminalSqlCut = (cut: RecoveryClosureV1): TerminalSqlCut => ({ run: cut.run, latestCheckpoint: cut.latestCheckpoint,
    itemCount: cut.items.length, journalSeq: cut.journal.length });
  function checkpoint(connection: SqliteConnection, cut: TerminalSqlCut, id: string, now: string) {
    connection.prepare(`INSERT INTO checkpoints (id, schema_version, run_id, based_on_run_revision, run_item_seq,
      context_manifest_ref, journal_seq, workspace_state_ref, created_at, reason) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, 'auto')`)
      .run(id, runId, BigInt(cut.run.revision), BigInt(cut.itemCount), cut.latestCheckpoint.contextManifestRef,
        BigInt(cut.journalSeq), cut.latestCheckpoint.workspaceStateRef, now);
  }
  async function prepareTerminal(run: Run, basis: TerminalMaterial, frontier: Extract<RunFrontier, { kind: 'finalize' }>, reads = artifacts) {
    const createdAt = sampleCanonicalNow();
    const result: RunResult = { schemaVersion: 1, runId, baseSourceRef: basis.candidate.baseSourceRef,
      resultSourceRef: basis.candidate.resultSourceRef, diffRef: basis.candidate.diffRef,
      verificationClosureRef: frontier.verificationClosureRef, verificationReceiptRefs: basis.verificationReceiptRefs, summaryRef: basis.candidate.summaryRef, createdAt,
      ...(basis.closure.dependency.kind !== 'none' ? { dependencyPlanRef: basis.closure.dependency.dependencyPlanRef } : {}),
      ...(frontier.operation === 'delivery' ? { deliveryTerminalProjectionEvidenceRef: frontier.deliveryTerminalProjectionEvidenceRef } : {}),
      ...(basis.closure.verification.kind === 'inherited_verified' ? { verificationProvenanceRef: basis.closure.verification.inheritedProvenanceRef } : {}) };
    decodeRunResult(result);
    phase('result_publication');
    const resultArtifact = await artifacts.publishCanonical(result, 'cliq-run-result-v1');
    const admittedContext = decodeAdmittedContext(await readCanonicalArtifact(reads, spec.admittedContextRef));
    const terminal: SessionRunTerminalItem = { schemaVersion: 1, format: 'cliq-session-run-terminal-v1', kind: 'run_terminal',
      itemKey: `run-terminal:${runId}`, runId, operation: spec.operation, admittedSessionItemSeq: admittedContext.throughSessionItemSeq,
      status: basis.status, terminalReason: basis.terminalReason, resultRef: resultArtifact.ref,
      summaryRef: result.summaryRef, summaryDigest: basis.summaryDigest };
    const terminalArtifact = run.parentRunId ? undefined : await artifacts.publishCanonical(terminal, terminal.format);
    return { createdAt, resultArtifact, terminalArtifact, itemId: identityHash('cliq-session-run-terminal-item-v1', run.sessionId, runId),
      checkpointId: runResultCheckpointId(runId, basis.candidate.itemId, resultArtifact.ref) };
  }
  async function prepareTerminalSession(run: Run, prepared: Awaited<ReturnType<typeof prepareTerminal>>, reads = artifacts) {
    if (!prepared.terminalArtifact || run.parentRunId) throw new TypeError('only a root result may prepare a Session terminal');
    phase('result_session');
    const session = readSession(driver, run.sessionId);
    const projection = decodeSessionProjection(await readCanonicalArtifact(reads, session.contextProjectionRef));
    if (projection.sessionId !== session.id || projection.contextRevision !== session.contextRevision || projection.throughItemSeq !== session.latestItemSeq)
      throw new TypeError('result Session projection is not current');
    const seq = session.latestItemSeq + 1;
    projection.contextRevision++; projection.throughItemSeq = seq;
    projection.segments.push({ kind: 'raw', fromItemSeq: seq, throughItemSeq: seq,
      items: [{ sourceSessionId: session.id, itemSeq: seq, itemId: prepared.itemId, kind: 'run_terminal', payloadRef: prepared.terminalArtifact.ref }] });
    projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
    return { session, seq, projectionArtifact: await artifacts.publishCanonical(projection, projection.format) };
  }
  // The sole RunResult/Session terminal writer. Inputs are prepared after the full
  // original finalization read; none are exported as future-cut authority.
  function writeTerminal(connection: SqliteConnection, cut: TerminalSqlCut, basis: Pick<TerminalMaterial, 'status' | 'terminalReason'>,
    prepared: Awaited<ReturnType<typeof prepareTerminal>>, sessionPlan: Awaited<ReturnType<typeof prepareTerminalSession>>, acceptedAt?: string) {
    const { session, seq, projectionArtifact } = sessionPlan, { resultArtifact, terminalArtifact, itemId, checkpointId } = prepared;
    if (!terminalArtifact || cut.run.parentRunId) throw new TypeError('only a root result may append a Session terminal');
    if (canonicalSha256(readSession(connection, session.id)) !== canonicalSha256(session))
      throw new KernelStorageError('REVISION_CONFLICT', 'result Session changed during artifact registration');
    const final = time(connection, prepared.createdAt, cut.run);
    if (final.outcome !== 'healthy') throw new KernelStorageError('RECOVERY_REQUIRED', 'result clock changed during artifact registration');
    const committedAt = acceptedAt ?? final.committedAt;
    if (committedAt < prepared.createdAt || committedAt < cut.run.updatedAt || committedAt > final.committedAt)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'result differs from its accepted atomic commit time');
    checkpoint(connection, cut, checkpointId, committedAt);
    connection.prepare(`UPDATE runs SET status = ?, next_step = NULL, frontier_ref = NULL,
      result_ref = ?, terminal_reason = ?, latest_checkpoint_id = ?, revision = revision + 1, updated_at = ? WHERE id = ?`)
      .run(basis.status, resultArtifact.ref, basis.terminalReason, checkpointId, committedAt, runId);
    connection.prepare("INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at) VALUES (?, ?, NULL, ?, 'run_terminal', ?, ?)")
      .run(itemId, session.id, BigInt(seq), terminalArtifact.ref, committedAt);
    connection.prepare('UPDATE sessions SET latest_item_seq = ?, context_revision = context_revision + 1, context_projection_ref = ?, updated_at = ? WHERE id = ?')
      .run(BigInt(seq), projectionArtifact.ref, committedAt, session.id);
    return readRun(connection, runId);
  }
  // Only the two fixed genuine producer friends below can reach this helper.
  // No public caller can supply terminal material or a SQL-proof callback.
  async function prepareOwnedTerminalResult(material: OwnedTerminalMaterial, assertSql: (connection: SqliteConnection, committedAt: string) => void,
    signal?: AbortSignal) {
    if (spec.operation !== 'delivery' || admitted.id !== material.run.id || principalId !== material.principalId ||
        admitted.specRef !== material.run.specRef || admitted.createdAt !== material.run.createdAt || admitted.deadlineAt !== material.run.deadlineAt)
      throw new TypeError('publication result belongs to another exact original Run');
    requireEqual(spec, material.spec, 'publication result exact original RunSpec');
    const basis: TerminalMaterial = { candidate: material.candidate, verificationReceiptRefs: material.verificationReceiptRefs,
      summaryDigest: material.summaryDigest, closure: material.closure, status: 'succeeded', terminalReason: 'verified' };
    const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
    signal?.throwIfAborted();
    const prepared = await prepareTerminal(material.run, basis, material.frontier, reads);
    if (prepared.createdAt < material.projection.observedAt)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'publication result preparation predates its actual root projection');
    const sessionPlan = await prepareTerminalSession(material.run, prepared, reads);
    signal?.throwIfAborted();
    const token = Object.freeze({ [publicationResultBrand]: true as const });
    publicationResultPlans.set(token, { driver, owner,
      metadata: immutableSnapshot([prepared.resultArtifact, ...(prepared.terminalArtifact ? [prepared.terminalArtifact] : []), sessionPlan.projectionArtifact]),
      sessionMatches(connection) {
        return canonicalSha256(readSession(connection, sessionPlan.session.id)) === canonicalSha256(sessionPlan.session);
      },
      commit(connection, committedAt) {
        assertSql(connection, committedAt);
        const run = readRun(connection, runId), latestCheckpoint = readCheckpoint(connection, run.latestCheckpointId);
        const items = itemRows(connection), journal = readInvocationJournal(connection, runId);
        return writeTerminal(connection, { run, latestCheckpoint, itemCount: items.length, journalSeq: journal.length },
          basis, prepared, sessionPlan, committedAt);
      } });
    return token;
  }
  return {
    /** Only the original live finalizer may use this private result seam. The
     * ordinary Agent path still performs its full retained finalization read. */
    async prepareOwnedPublicationResult(execution: unknown, finalization: OwnedPublicationFinalization) {
      const { readOwnedPublicationTerminalMaterial, assertOwnedPublicationTerminalSql } = await import('./publication-finalization.js');
      const material = readOwnedPublicationTerminalMaterial(driver, artifacts, owner, execution, finalization);
      return prepareOwnedTerminalResult(material, (connection, committedAt) =>
        assertOwnedPublicationTerminalSql(driver, owner, finalization, connection, committedAt), material.signal);
    },
    async prepareOwnedNoOpDeliveryResult(execution: unknown, task: DeliveryNoOpTask, finalization: OwnedNoOpDeliveryFinalization) {
      const { assertOwnedNoOpDeliveryTask } = await import('./run-execution.js');
      assertOwnedNoOpDeliveryTask(driver, owner, execution, task, artifacts);
      const { readOwnedNoOpTerminalMaterial, assertOwnedNoOpTerminalSql } = await import('./delivery-noop-finalization.js');
      const material = readOwnedNoOpTerminalMaterial(driver, owner, execution, task, finalization);
      return prepareOwnedTerminalResult(material, (connection, committedAt) =>
        assertOwnedNoOpTerminalSql(driver, owner, finalization, connection, committedAt));
    },
    completeVerification: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      const expected = revision(input), { cut, basis } = await load();
      if (cut.run.nextStep === 'finalize') {
        unstopped(cut.run, 'finalize');
        const frontier = await readCanonicalArtifact<Extract<RunFrontier, { kind: 'finalize' }>>(resultReads, cut.run.frontierRef!);
        const historical = await readFinalization(driver, resultReads, cut, basis, frontier.verificationClosureRef,
          frontier.operation === 'delivery' ? frontier.deliveryTerminalProjectionEvidenceRef : undefined);
        if (![cut.run.revision, historical.checkpoint.basedOnRunRevision].includes(expected))
          throw new KernelStorageError('REVISION_CONFLICT', 'verification replay revision differs from its original cut');
        return immutableSnapshot({ run: cut.run, verificationClosureRef: frontier.verificationClosureRef, checkpointId: historical.checkpoint.id });
      }
      if (spec.operation === 'delivery' && cut.run.nextStep === 'delivery') {
        unstopped(cut.run, 'delivery');
        const frontier = await readCanonicalArtifact<RunFrontier>(resultReads, cut.run.frontierRef!);
        if (frontier.kind !== 'delivery' || frontier.phase !== 'approval')
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'verification replay requires its exact untouched delivery approval frontier');
        const historical = await readDeliveryVerification(driver, resultReads, cut, frontier.verificationClosureRef);
        if (![cut.run.revision, historical.checkpoint.basedOnRunRevision].includes(expected))
          throw new KernelStorageError('REVISION_CONFLICT', 'delivery verification replay revision differs from its original cut');
        return immutableSnapshot({ run: cut.run, verificationClosureRef: frontier.verificationClosureRef, checkpointId: historical.checkpoint.id });
      }
      if (cut.run.revision !== expected) throw new KernelStorageError('REVISION_CONFLICT', 'verification Run revision changed');
      unstopped(cut.run, 'verify');
      if (basis.delivery && basis.delivery.merged.plan.forwardOperations.length === 0)
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'no-op verification requires its genuine descriptor projection owner');
      const expectedFrontier: RunFrontier = { schemaVersion: 1, kind: 'verify', phase: basis.delivery?.inheritance && basis.progress.dependency ? 'dependencies' : 'verifiers', candidateItemId: basis.candidate.itemId,
        resultSourceRef: basis.candidate.resultSourceRef, verifierPlanRef: basis.planRef,
        nextVerifierIndex: basis.delivery?.inheritance ? 0 : basis.plan.entries.length,
        afterPass: spec.operation === 'agent' ? 'finalize' : 'delivery_approval' };
      if (basis.progress.dependency) expectedFrontier.dependencyPlanRef = basis.progress.dependency.planRef;
      requireEqual(await readCanonicalArtifact(resultReads, cut.run.frontierRef!), expectedFrontier, 'complete verification current frontier');
      if (cut.latestCheckpoint.id !== basis.completionCheckpoint.id)
        throw new TypeError('verification has no exact final producer Checkpoint');
      const assertCut = capture(cut, basis), createdAt = sampleCanonicalNow();
      const closure = expectedVerificationClosure(basis, createdAt); decodeVerificationClosure(closure);
      const provenance = expectedInheritedVerificationProvenance(basis, createdAt);
      const provenanceArtifact = provenance && await artifacts.publishCanonical(provenance, provenance.format);
      resultReads.assertReadActive();
      const published = await artifacts.publishCanonical(closure, closure.format);
      resultReads.assertReadActive();
      const frontier: RunFrontier = basis.delivery ? { schemaVersion: 1, kind: 'delivery', phase: 'approval',
        sourceRunResultRef: basis.delivery.admission.request.expectedRunResultRef, candidateItemId: basis.candidate.itemId,
        resultSourceRef: basis.candidate.resultSourceRef, verifierPlanRef: basis.planRef,
        verificationClosureRef: published.ref, deliveryPlanRef: basis.delivery.merged.planRef }
        : { schemaVersion: 1, kind: 'finalize', operation: 'agent', candidateItemId: basis.candidate.itemId,
          resultSourceRef: basis.candidate.resultSourceRef, verificationClosureRef: published.ref };
      const frontierArtifact = await artifacts.publishCanonical(frontier, 'cliq-run-frontier-v1');
      const checkpointId = verificationCheckpointId(runId, basis.candidate.itemId, published.ref);
      let outcome: TimeFenceAdvance | undefined, updated: Run | undefined;
      driver.transaction(connection => {
        assertCut(connection);
        const accepted = time(connection, createdAt, cut.run); outcome = accepted.outcome; if (outcome !== 'healthy') return;
        const { committedAt } = accepted;
        for (const artifact of [...(provenanceArtifact ? [provenanceArtifact] : []), published, frontierArtifact]) insertArtifactMetadata(connection, artifact, committedAt);
        assertCut(connection);
        const final = time(connection, createdAt, cut.run); outcome = final.outcome;
        if (outcome !== 'healthy') throw new KernelStorageError('RECOVERY_REQUIRED', 'verification clock changed during artifact registration');
        checkpoint(connection, terminalSqlCut(cut), checkpointId, final.committedAt);
        connection.prepare('UPDATE runs SET next_step = ?, frontier_ref = ?, latest_checkpoint_id = ?, revision = revision + 1, updated_at = ? WHERE id = ?')
          .run(frontier.kind, frontierArtifact.ref, checkpointId, final.committedAt, runId);
        updated = readRun(connection, runId); appendRunStateEvent(connection, updated, final.committedAt);
      });
      requireHealthyFence(outcome);
      if (!updated) throw new KernelStorageError('RECOVERY_REQUIRED', 'verification did not commit under its time fence');
      return immutableSnapshot({ run: updated, verificationClosureRef: published.ref, checkpointId });
    }),
    commitRunResult: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      const expected = revision(input), { cut, basis } = await load();
      if (cut.run.status === 'completed_unverified' || cut.run.status === 'succeeded') {
        if (![cut.run.revision, cut.latestCheckpoint.basedOnRunRevision].includes(expected))
          throw new KernelStorageError('REVISION_CONFLICT', 'result replay revision differs from its original cut');
        return immutableSnapshot({ run: cut.run, resultRef: cut.run.resultRef! });
      }
      if (cut.run.revision !== expected) throw new KernelStorageError('REVISION_CONFLICT', 'result Run revision changed');
      unstopped(cut.run, 'finalize');
      phase('result_finalization');
      const frontier = await readCanonicalArtifact<Extract<RunFrontier, { kind: 'finalize' }>>(resultReads, cut.run.frontierRef!);
      const historical = await readFinalization(driver, resultReads, cut, basis, frontier.verificationClosureRef,
        frontier.operation === 'delivery' ? frontier.deliveryTerminalProjectionEvidenceRef : undefined);
      requireEqual(frontier, historical.frontier, 'result current finalize frontier');
      const assertCut = capture(cut, basis), prepared = await prepareTerminal(cut.run,
        { ...basis, summaryDigest: basis.summary.textDigest, closure: historical.closure }, frontier, resultReads);
      if (cut.run.parentRunId) {
        const allocation = await prepareChildTerminalAllocation(driver, resultReads, owner,
          { run: cut.run, status: basis.status, resultRef: prepared.resultArtifact.ref });
        let outcome: TimeFenceAdvance | undefined, updated: Run | undefined;
        driver.transaction(connection => {
          assertCut(connection);
          const final = time(connection, prepared.createdAt, cut.run); outcome = final.outcome; if (outcome !== 'healthy') return;
          for (const artifact of [prepared.resultArtifact, ...allocation.metadata]) insertArtifactMetadata(connection, artifact, final.committedAt);
          const accepted = time(connection, prepared.createdAt, cut.run); outcome = accepted.outcome; if (outcome !== 'healthy') return;
          assertCut(connection); assertChildAncestryRelease(connection, runId, accepted.committedAt);
          checkpoint(connection, terminalSqlCut(cut), prepared.checkpointId, accepted.committedAt);
          connection.prepare(`UPDATE runs SET status=?,next_step=NULL,frontier_ref=NULL,result_ref=?,terminal_reason=?,
            latest_checkpoint_id=?,revision=revision+1,updated_at=? WHERE id=?`)
            .run(basis.status, prepared.resultArtifact.ref, basis.terminalReason, prepared.checkpointId, accepted.committedAt, runId);
          allocation.commit(connection, accepted.committedAt);
          updated = readRun(connection, runId); appendRunStateEvent(connection, updated, accepted.committedAt);
        });
        requireHealthyFence(outcome);
        if (!updated) throw new KernelStorageError('RECOVERY_REQUIRED', 'child result did not commit under its original time fence');
        return immutableSnapshot({ run: updated, resultRef: prepared.resultArtifact.ref });
      }
      for (let attempt = 0; attempt < 8; attempt++) {
        const sessionPlan = await prepareTerminalSession(cut.run, prepared, resultReads), { session, projectionArtifact } = sessionPlan;
        let outcome: TimeFenceAdvance | undefined, updated: Run | undefined;
        phase('result_commit');
        try {
          driver.transaction(connection => {
            assertCut(connection);
            if (canonicalSha256(readSession(connection, session.id)) !== canonicalSha256(session)) throw new ResultSessionChanged();
            const accepted = time(connection, prepared.createdAt, cut.run); outcome = accepted.outcome; if (outcome !== 'healthy') return;
            if (!prepared.terminalArtifact) throw new TypeError('root result lost its Session terminal');
            for (const artifact of [prepared.resultArtifact, prepared.terminalArtifact, projectionArtifact]) insertArtifactMetadata(connection, artifact, accepted.committedAt);
            assertCut(connection); updated = writeTerminal(connection, terminalSqlCut(cut), basis, prepared, sessionPlan);
            appendRunStateEvent(connection, updated, updated.updatedAt);
          });
        } catch (error) { if (error instanceof ResultSessionChanged) continue; throw error; }
        requireHealthyFence(outcome);
        if (updated) return immutableSnapshot({ run: updated, resultRef: prepared.resultArtifact.ref });
      }
      throw new KernelStorageError('REVISION_CONFLICT', 'result Session cut kept changing');
    })
  };
}
