import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { RunResult, VerificationClosureV1 } from '../kernel/result.js';
import type { RecoveryClosureV1, Run, RunFrontier, RunSpec, SessionRunTerminalItem } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { decodeAdmittedContext, decodeSessionProjection } from './decoders.js';
import { KernelStorageError, stateOperation } from './errors.js';
import { finalCandidateCheckpointId } from './final-candidate-plan.js';
import { assertRetiredGenerationCut } from './generation-retirement.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { decodeRunResult, decodeVerificationClosure } from './result-artifacts.js';
import { readUnverifiedFinalization, readUnverifiedResultBasis, runResultCheckpointId, verificationCheckpointId } from './run-result-recovery.js';
import { readCheckpoint, readControlRequest, readRun, readSession } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';

/** Store-derived completion only. A no-check result is explicitly unverified;
 * this module grants no execution permission and accepts no caller proof/list. */
export function loadRunResult(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  authority: { run: Run; spec: RunSpec; principalId: string }) {
  const { run: admitted, spec, principalId } = authority, runId = admitted.id;
  function revision(input: { expectedRunRevision: number }): number {
    if (!input || !exactKeys(input, ['expectedRunRevision']) || !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1)
      throw new TypeError('result requires one exact expected revision');
    return input.expectedRunRevision;
  }
  async function load() {
    assertActiveStateOwner(driver, owner);
    const cut = await readRecoveryClosure(driver, artifacts, runId);
    if (cut.run.specRef !== admitted.specRef || cut.run.createdAt !== admitted.createdAt || cut.run.deadlineAt !== admitted.deadlineAt ||
        canonicalSha256(cut.runSpec) !== canonicalSha256(spec)) throw new TypeError('result authority no longer belongs to this Run');
    const basis = await readUnverifiedResultBasis(driver, artifacts, cut);
    if (basis.principalId !== principalId) throw new TypeError('result authority belongs to another principal');
    return { cut, basis };
  }
  function unstopped(run: Run, step: 'verify' | 'finalize') {
    if (run.status !== 'queued' || run.nextStep !== step || !run.frontierRef || run.stopIntentRef || run.cancelRequested ||
        run.resultRef || run.terminalDetailRef || run.terminalReason)
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'result requires its exact unstopped completion frontier');
  }
  const itemRows = (connection: SqliteConnection) => connection.prepare(
    'SELECT item_id, item_seq, kind, payload_ref, created_at FROM items WHERE run_id = ? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: bigint; kind: string; payload_ref: string; created_at: string }>(runId)
    .map(row => ({ ...row, item_seq: Number(row.item_seq) }));
  function capture(cut: RecoveryClosureV1, basis: Awaited<ReturnType<typeof readUnverifiedResultBasis>>) {
    const launches = readWorkerLaunchesForRun(driver, runId), generations = readWorkspaceGenerationsForRun(driver, runId), items = itemRows(driver);
    return (connection: SqliteConnection) => {
      assertActiveStateOwner(connection, owner);
      const admission = connection.prepare(`SELECT principal_id, admission_method, admission_key, admission_intent_digest,
        admission_request_id FROM runs WHERE id = ?`).get(runId);
      if (canonicalSha256(readRun(connection, runId)) !== canonicalSha256(cut.run) ||
          canonicalSha256(readCheckpoint(connection, cut.run.latestCheckpointId)) !== canonicalSha256(cut.latestCheckpoint) ||
          canonicalSha256(readInvocationJournal(connection, runId)) !== canonicalSha256(cut.journal) ||
          canonicalSha256(readWorkerLaunchesForRun(connection, runId)) !== canonicalSha256(launches) ||
          canonicalSha256(readWorkspaceGenerationsForRun(connection, runId)) !== canonicalSha256(generations) ||
          canonicalSha256(itemRows(connection)) !== canonicalSha256(items) || canonicalSha256(admission) !== canonicalSha256(basis.admission) ||
          canonicalSha256(readControlRequest(connection, principalId, 'run.submit', basis.admission.admission_request_id!)) !== canonicalSha256(basis.original) ||
          connection.prepare('SELECT 1 FROM child_allocations WHERE parent_run_id = ? OR child_run_id = ? LIMIT 1').get(runId, runId) ||
          connection.prepare('SELECT 1 FROM runs WHERE parent_run_id = ? LIMIT 1').get(runId))
        throw new KernelStorageError('REVISION_CONFLICT', 'result candidate, dispatch, generation or admission cut changed');
      assertRetiredGenerationCut(connection, cut.run, generations);
    };
  }
  function time(connection: SqliteConnection, preparedAt: string, run: Run) {
    const committedAt = sampleCanonicalNow(), outcome = advanceTimeFence(connection, owner.ownerEpoch, committedAt);
    if (outcome === 'healthy' && (committedAt < preparedAt || committedAt < run.updatedAt || committedAt >= run.deadlineAt))
      throw new KernelStorageError('LEASE_FENCED', 'result is outside its healthy immutable Run lifetime');
    return { committedAt, outcome };
  }
  function checkpoint(connection: SqliteConnection, cut: RecoveryClosureV1, id: string, now: string) {
    connection.prepare(`INSERT INTO checkpoints (id, schema_version, run_id, based_on_run_revision, run_item_seq,
      context_manifest_ref, journal_seq, workspace_state_ref, created_at, reason) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, 'auto')`)
      .run(id, runId, BigInt(cut.run.revision), BigInt(cut.items.length), cut.latestCheckpoint.contextManifestRef,
        BigInt(cut.journal.length), cut.latestCheckpoint.workspaceStateRef, now);
  }
  return {
    completeVerification: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      const expected = revision(input), { cut, basis } = await load();
      if (cut.run.nextStep === 'finalize') {
        unstopped(cut.run, 'finalize');
        const frontier = await readCanonicalArtifact<Extract<RunFrontier, { kind: 'finalize' }>>(artifacts, cut.run.frontierRef!);
        const historical = await readUnverifiedFinalization(driver, artifacts, cut, basis, frontier.verificationClosureRef);
        if (![cut.run.revision, historical.checkpoint.basedOnRunRevision].includes(expected))
          throw new KernelStorageError('REVISION_CONFLICT', 'verification replay revision differs from its original cut');
        return immutableSnapshot({ run: cut.run, verificationClosureRef: frontier.verificationClosureRef, checkpointId: historical.checkpoint.id });
      }
      if (cut.run.revision !== expected) throw new KernelStorageError('REVISION_CONFLICT', 'verification Run revision changed');
      unstopped(cut.run, 'verify');
      const expectedFrontier: RunFrontier = { schemaVersion: 1, kind: 'verify', phase: 'verifiers', candidateItemId: basis.candidate.itemId,
        resultSourceRef: basis.candidate.resultSourceRef, verifierPlanRef: basis.planRef, nextVerifierIndex: 0, afterPass: 'finalize' };
      requireEqual(await readCanonicalArtifact(artifacts, cut.run.frontierRef!), expectedFrontier, 'empty verification current frontier');
      if (cut.latestCheckpoint.id !== finalCandidateCheckpointId(runId, basis.candidate.producingItemId))
        throw new TypeError('empty verification has no exact candidate Checkpoint');
      const assertCut = capture(cut, basis), createdAt = sampleCanonicalNow();
      const closure: VerificationClosureV1 = { schemaVersion: 1, format: 'cliq-verification-closure-v1', runId,
        candidateItemId: basis.candidate.itemId, resultSourceRef: basis.candidate.resultSourceRef, verifierPlanRef: basis.planRef,
        dependency: { kind: 'none' }, verification: { kind: 'local', outcome: 'unverified', unverifiedConsentRef: spec.unverifiedConsentRef!, entries: [] },
        createdAt, closureDigest: '' };
      closure.closureDigest = digestOmitting(closure, 'closureDigest'); decodeVerificationClosure(closure);
      const published = await artifacts.publishCanonical(closure, closure.format);
      const frontier: Extract<RunFrontier, { kind: 'finalize'; operation: 'agent' }> = { schemaVersion: 1, kind: 'finalize', operation: 'agent',
        candidateItemId: basis.candidate.itemId, resultSourceRef: basis.candidate.resultSourceRef, verificationClosureRef: published.ref };
      const frontierArtifact = await artifacts.publishCanonical(frontier, 'cliq-run-frontier-v1');
      const checkpointId = verificationCheckpointId(runId, basis.candidate.itemId, published.ref);
      let outcome: TimeFenceAdvance | undefined, updated: Run | undefined;
      driver.transaction(connection => {
        assertCut(connection);
        const accepted = time(connection, createdAt, cut.run); outcome = accepted.outcome; if (outcome !== 'healthy') return;
        const { committedAt } = accepted;
        for (const artifact of [published, frontierArtifact]) insertArtifactMetadata(connection, artifact, committedAt);
        checkpoint(connection, cut, checkpointId, committedAt);
        connection.prepare('UPDATE runs SET next_step = ?, frontier_ref = ?, latest_checkpoint_id = ?, revision = revision + 1, updated_at = ? WHERE id = ?')
          .run('finalize', frontierArtifact.ref, checkpointId, committedAt, runId);
        updated = readRun(connection, runId); appendRunStateEvent(connection, updated, committedAt);
      });
      requireHealthyFence(outcome);
      if (!updated) throw new KernelStorageError('RECOVERY_REQUIRED', 'verification did not commit under its time fence');
      return immutableSnapshot({ run: updated, verificationClosureRef: published.ref, checkpointId });
    }),
    commitRunResult: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      const expected = revision(input), { cut, basis } = await load();
      if (cut.run.status === 'completed_unverified') {
        if (![cut.run.revision, cut.latestCheckpoint.basedOnRunRevision].includes(expected))
          throw new KernelStorageError('REVISION_CONFLICT', 'result replay revision differs from its original cut');
        return immutableSnapshot({ run: cut.run, resultRef: cut.run.resultRef! });
      }
      if (cut.run.revision !== expected) throw new KernelStorageError('REVISION_CONFLICT', 'result Run revision changed');
      unstopped(cut.run, 'finalize');
      const frontier = await readCanonicalArtifact<Extract<RunFrontier, { kind: 'finalize' }>>(artifacts, cut.run.frontierRef!);
      const historical = await readUnverifiedFinalization(driver, artifacts, cut, basis, frontier.verificationClosureRef);
      requireEqual(frontier, historical.frontier, 'result current finalize frontier');
      const assertCut = capture(cut, basis), createdAt = sampleCanonicalNow();
      const result: RunResult = { schemaVersion: 1, runId, baseSourceRef: basis.candidate.baseSourceRef,
        resultSourceRef: basis.candidate.resultSourceRef, diffRef: basis.candidate.diffRef,
        verificationClosureRef: frontier.verificationClosureRef, verificationReceiptRefs: [], summaryRef: basis.candidate.summaryRef, createdAt };
      decodeRunResult(result);
      const resultArtifact = await artifacts.publishCanonical(result, 'cliq-run-result-v1');
      const admittedContext = decodeAdmittedContext(await readCanonicalArtifact(artifacts, spec.admittedContextRef));
      const terminal: SessionRunTerminalItem = { schemaVersion: 1, format: 'cliq-session-run-terminal-v1', kind: 'run_terminal',
        itemKey: `run-terminal:${runId}`, runId, operation: 'agent', admittedSessionItemSeq: admittedContext.throughSessionItemSeq,
        status: 'completed_unverified', terminalReason: 'no_required_verifier', resultRef: resultArtifact.ref,
        summaryRef: result.summaryRef, summaryDigest: basis.summary.textDigest };
      const terminalArtifact = await artifacts.publishCanonical(terminal, terminal.format);
      const itemId = identityHash('cliq-session-run-terminal-item-v1', cut.run.sessionId, runId);
      const checkpointId = runResultCheckpointId(runId, basis.candidate.itemId, resultArtifact.ref);
      for (let attempt = 0; attempt < 8; attempt++) {
        const session = readSession(driver, cut.run.sessionId);
        const projection = decodeSessionProjection(await readCanonicalArtifact(artifacts, session.contextProjectionRef));
        if (projection.sessionId !== session.id || projection.contextRevision !== session.contextRevision || projection.throughItemSeq !== session.latestItemSeq)
          throw new TypeError('result Session projection is not current');
        const seq = session.latestItemSeq + 1;
        projection.contextRevision++; projection.throughItemSeq = seq;
        projection.segments.push({ kind: 'raw', fromItemSeq: seq, throughItemSeq: seq,
          items: [{ sourceSessionId: session.id, itemSeq: seq, itemId, kind: 'run_terminal', payloadRef: terminalArtifact.ref }] });
        projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
        const projectionArtifact = await artifacts.publishCanonical(projection, projection.format);
        let outcome: TimeFenceAdvance | undefined, updated: Run | undefined;
        driver.transaction(connection => {
          assertCut(connection);
          if (canonicalSha256(readSession(connection, session.id)) !== canonicalSha256(session)) return;
          const accepted = time(connection, createdAt, cut.run); outcome = accepted.outcome; if (outcome !== 'healthy') return;
          const { committedAt } = accepted;
          for (const artifact of [resultArtifact, terminalArtifact, projectionArtifact]) insertArtifactMetadata(connection, artifact, committedAt);
          checkpoint(connection, cut, checkpointId, committedAt);
          connection.prepare(`UPDATE runs SET status = 'completed_unverified', next_step = NULL, frontier_ref = NULL,
            result_ref = ?, terminal_reason = 'no_required_verifier', latest_checkpoint_id = ?, revision = revision + 1, updated_at = ? WHERE id = ?`)
            .run(resultArtifact.ref, checkpointId, committedAt, runId);
          connection.prepare("INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at) VALUES (?, ?, NULL, ?, 'run_terminal', ?, ?)")
            .run(itemId, session.id, BigInt(seq), terminalArtifact.ref, committedAt);
          connection.prepare('UPDATE sessions SET latest_item_seq = ?, context_revision = context_revision + 1, context_projection_ref = ?, updated_at = ? WHERE id = ?')
            .run(BigInt(seq), projectionArtifact.ref, committedAt, session.id);
          updated = readRun(connection, runId); appendRunStateEvent(connection, updated, committedAt);
        });
        requireHealthyFence(outcome);
        if (updated) return immutableSnapshot({ run: updated, resultRef: resultArtifact.ref });
      }
      throw new KernelStorageError('REVISION_CONFLICT', 'result Session cut kept changing');
    })
  };
}
