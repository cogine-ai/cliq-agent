import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { ProcessContainmentDeathEvidenceV1 } from '../kernel/execution.js';
import type { ContinuationItem, InvocationJournalEntry, Run, RunAssemblyV1, RunFrontier, RunSpec } from '../kernel/types.js';
import type { ToolCheckpointProof } from '../kernel/tool-authorization.js';
import type { VerificationReceipt, VerifierResultItem, VerifierStopEvidence, VerifierStopItem } from '../kernel/verifier.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { assertNativeContainmentDeath, captureNativeVerifierResult, type NativeVerifierResult } from '../sandbox/linux-worker.js';
import { decodeAgentStop, selectAgentStop, type AgentStopIntent } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { isJoinedCasPublicationFailure } from './cas.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { planContinuationCommit } from './continuation-commit.js';
import { decodeContextManifest, decodeSourceManifest, decodeWorkspaceEntries } from './decoders.js';
import { joinResourceOperations, KernelStorageError, ResourceRetirementError } from './errors.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readInvocationAttempt, readInvocationJournal } from './repositories/journal.js';
import { prepareCandidateSource } from './result-source.js';
import { readCheckpoint, readRun } from './rows.js';
import { isRolledBackSqliteTransactionFailure, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import { prepareToolCheckpoint, type NativeWorkerRetirement } from './tool-checkpoint.js';
import { decodeVerificationReceipt, decodeVerifierStopEvidence, decodeVerifierStopItem } from './verifier-artifacts.js';
import { readVerifierProgress, verifierCheckpointId, verifierResultItemId, type VerifierRetirementV1 } from './verifier-recovery.js';
import { prepareValidatedInvocationSettlement } from './reducers/invocation.js';

const VERIFIER_BUDGET = Object.freeze({ modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 });
export type VerifierCompletionOwner = Readonly<{
  checkpointId: string;
  complete(input: { expectedRunRevision: number; checkpoint: ToolCheckpointProof }): Promise<{ run: Run }>;
}>;

/** One original result, one original parent seal and one settlement graph.
 * No artifact ref supplied by a caller can substitute for this native result. */
export async function beginVerifierCompletion(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  authority: { run: Run; spec: RunSpec; assembly: RunAssemblyV1 },
  input: { expectedRunRevision: number; opId: string; attempt: number; result: NativeVerifierResult }, reobserve?: NativeWorkerRetirement
): Promise<VerifierCompletionOwner> {
  // Before the first await, retain private copies of the native producer's
  // original bytes, not the mutable public Uint8Array view of that result.
  const native = captureNativeVerifierResult(input.result);
  const identity = immutableSnapshot({ expectedRunRevision: input.expectedRunRevision, opId: input.opId, attempt: input.attempt });
  input = { ...identity, result: input.result };
  const { run: admitted, spec, assembly } = authority, runId = admitted.id;
  const selected = await readRecoveryClosure(driver, artifacts, runId), { run } = selected;
  if (run.specRef !== admitted.specRef || run.createdAt !== admitted.createdAt || run.deadlineAt !== admitted.deadlineAt ||
      run.revision !== input.expectedRunRevision || run.status !== 'running' || run.nextStep !== 'verify' || !run.frontierRef || !run.activeWorkerLaunchId)
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'verifier completion lost its original active parent cut');
  const progress = await readVerifierProgress(driver, artifacts, selected), current = progress.entries[progress.nextVerifierIndex];
  const frontier = await readCanonicalArtifact<Extract<RunFrontier, { kind: 'verify' }>>(artifacts, run.frontierRef);
  const entries = readInvocationAttempt(driver, runId, input.opId, input.attempt);
  const prepared = entries[0], claim = entries[1];
  assertNativeContainmentDeath(native.death);
  const containment = native.death.containment, subject = containment.owner;
  if (!current || frontier.kind !== 'verify' || frontier.nextVerifierIndex !== progress.nextVerifierIndex || entries.length !== 2 ||
      prepared?.phase !== 'prepared' || prepared.opKind !== 'verifier' || claim?.phase !== 'dispatch_claimed' || !claim.sandboxLaunchSpecRef ||
      subject.kind !== 'run_invocation' || subject.runId !== runId || subject.workerLaunchId !== run.activeWorkerLaunchId ||
      subject.intendedLeaseEpoch !== run.leaseEpoch || subject.opId !== input.opId || subject.attempt !== input.attempt || subject.dispatchId !== claim.dispatchId ||
      containment.sandboxLaunchSpecRef !== claim.sandboxLaunchSpecRef || claim.supervisorInstanceId !== owner.supervisorInstanceId ||
      claim.stateOwnerEpoch !== owner.ownerEpoch || native.startedAt < claim.timestamp || native.endedAt > sampleCanonicalNow() ||
      native.death.observedAt < native.endedAt || native.stdout.byteLength + native.stderr.byteLength > current.specEntry.outputLimitBytes)
    throw new KernelStorageError('LEASE_FENCED', 'verifier result does not belong to its exact original permanent claim');
  const checkpointId = verifierCheckpointId(runId, input.opId, input.attempt);
  const stable = ({ revision: _revision, updatedAt: _time, cancelRequested: _cancel, stopIntentRef: _stop, ...value }: Run) => value;
  let checkedRun = run, checkedStop = run.stopIntentRef ? decodeAgentStop(await readCanonicalArtifact(artifacts, run.stopIntentRef), run) : undefined;
  const originalStop = checkedStop;
  if (originalStop && !['cancelled_by_user', 'parent_cancelled', 'budget_exhausted'].includes(originalStop.reason))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'verifier termination requires its owning nonproductive stop branch');
  const itemIdentities = (connection: SqliteConnection) => connection.prepare(
    'SELECT item_id, item_seq, payload_ref, created_at FROM items WHERE run_id = ? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: bigint; payload_ref: string; created_at: string }>(runId)
    .map(row => ({ itemId: row.item_id, itemSeq: Number(row.item_seq), payloadRef: row.payload_ref, createdAt: row.created_at }));
  function validateSnapshotWithJournal(connection: SqliteConnection, actual: Run, expectedJournal: readonly InvocationJournalEntry[]) {
    assertActiveStateOwner(connection, owner);
    if (canonicalSha256(stable(actual)) !== canonicalSha256(stable(run)) || actual.revision < checkedRun.revision ||
        actual.updatedAt < checkedRun.updatedAt || checkedRun.cancelRequested && !actual.cancelRequested ||
        actual.stopIntentRef !== checkedRun.stopIntentRef ||
        canonicalSha256(readCheckpoint(connection, run.latestCheckpointId)) !== canonicalSha256(selected.latestCheckpoint) ||
        canonicalSha256(readInvocationJournal(connection, runId)) !== canonicalSha256(expectedJournal) ||
        canonicalSha256(itemIdentities(connection)) !== canonicalSha256(selected.items.map(({ itemId, itemSeq, payloadRef, createdAt }) =>
          ({ itemId, itemSeq, payloadRef, createdAt }))))
      throw new KernelStorageError('REVISION_CONFLICT', 'verifier original result or checked StopIntent cut changed');
  }
  function validateSnapshot(connection: SqliteConnection, actual: Run) {
    validateSnapshotWithJournal(connection, actual, selected.journal);
  }
  async function checkCurrent(expected: number) {
    const actual = readRun(driver, runId);
    if (actual.revision !== expected || canonicalSha256(stable(actual)) !== canonicalSha256(stable(run)))
      throw new KernelStorageError('REVISION_CONFLICT', 'verifier completion revision or original parent changed');
    if (canonicalSha256(actual) !== canonicalSha256(checkedRun)) {
      const refreshed = await readRecoveryClosure(driver, artifacts, runId);
      if (refreshed.run.revision !== expected || !refreshed.run.stopIntentRef || refreshed.run.updatedAt < checkedRun.updatedAt ||
          refreshed.run.revision <= checkedRun.revision || checkedRun.cancelRequested && !refreshed.run.cancelRequested ||
          canonicalSha256(stable(refreshed.run)) !== canonicalSha256(stable(run)))
        throw new KernelStorageError('REVISION_CONFLICT', 'verifier original completion cut changed');
      const stop = decodeAgentStop(await readCanonicalArtifact(artifacts, refreshed.run.stopIntentRef), refreshed.run);
      if (checkedRun.stopIntentRef !== refreshed.run.stopIntentRef && selectAgentStop(checkedStop, stop) !== stop)
        throw new KernelStorageError('REVISION_CONFLICT', 'verifier StopIntent did not advance monotonically');
      checkedRun = refreshed.run; checkedStop = stop;
    }
    validateSnapshot(driver, checkedRun);
    return checkedRun;
  }
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, selected.latestCheckpoint.contextManifestRef));
  const existingItems = await artifacts.mapReads(selected.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
    item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) }));
  let proofInput: ToolCheckpointProof | undefined, seal: Awaited<ReturnType<typeof prepareToolCheckpoint>> | undefined;
  let outputMetadata: PublishedArtifact[] | undefined, retirementMetadata: PublishedArtifact[] | undefined;
  let sourceAfter: Awaited<ReturnType<typeof prepareCandidateSource>>['graph'] | undefined;
  let integrityMetadata: PublishedArtifact | undefined;
  let receiptMetadata: PublishedArtifact | undefined, stoppedMetadata: PublishedArtifact | undefined;
  let receipt: VerificationReceipt | undefined, stopped: VerifierStopEvidence | undefined;
  let graph: ReturnType<typeof planContinuationCommit> | undefined;
  let settlement: ReturnType<typeof prepareValidatedInvocationSettlement> | undefined;
  let failure: unknown, completed: { run: Run } | undefined, completedFrom: number | undefined;
  let pending: Promise<{ run: Run }> | undefined, pendingInput: unknown;
  let refreshed = false;
  return Object.freeze({ checkpointId,
    complete(value) {
      const frozen = immutableSnapshot(value);
      if (!exactKeys(frozen, ['expectedRunRevision', 'checkpoint']) || !Number.isSafeInteger(frozen.expectedRunRevision) || frozen.expectedRunRevision < 1 ||
          !exactKeys(frozen.checkpoint, ['workspaceStateRef', 'snapshotEvidenceRef', 'retirementEvidenceRef']))
        return Promise.reject(new TypeError('invalid original verifier completion input'));
      if (pending) return canonicalSha256(pendingInput) === canonicalSha256(frozen) ? pending
        : Promise.reject(new KernelStorageError('REVISION_CONFLICT', 'verifier completion is already in flight'));
      pendingInput = frozen;
      pending = (async () => {
        assertActiveStateOwner(driver, owner);
        if (completed) {
          if (![completedFrom, completed.run.revision].includes(frozen.expectedRunRevision) || canonicalSha256(readRun(driver, runId)) !== canonicalSha256(completed.run))
            throw new KernelStorageError('REVISION_CONFLICT', 'verifier completion replay differs from its committed cut');
          await readRecoveryClosure(driver, artifacts, runId); return immutableSnapshot(completed);
        }
        if (proofInput && canonicalSha256(proofInput) !== canonicalSha256(frozen.checkpoint))
          throw new KernelStorageError('REVISION_CONFLICT', 'verifier cannot substitute its original parent Checkpoint');
        await checkCurrent(frozen.expectedRunRevision);
        if (failure && !isJoinedCasPublicationFailure(failure) && !isRolledBackSqliteTransactionFailure(driver, failure)) throw failure;
        const retryCommit = failure !== undefined && isRolledBackSqliteTransactionFailure(driver, failure);
        if (!seal) {
          seal = await prepareToolCheckpoint(driver, artifacts, owner, { run: checkedRun, spec, assembly, checkpointId,
            observedAt: native.endedAt, postEffect: frozen.checkpoint }, reobserve);
          proofInput = frozen.checkpoint;
        }
        if (!outputMetadata) {
          let blocking: { error: unknown } | undefined;
          outputMetadata = await joinResourceOperations([native.stdout, native.stderr].map(async bytes => {
            try { return await artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-verifier-output-v1'); }
            catch (error) { if (!isJoinedCasPublicationFailure(error)) blocking ??= { error }; throw error; }
          })).catch(error => { throw error instanceof ResourceRetirementError ? error : blocking?.error ?? error; });
        }
        if (!retirementMetadata) {
          sourceAfter ??= await (await prepareCandidateSource(artifacts, spec, frozen.checkpoint.workspaceStateRef)).publish();
          const sourceChanged = sourceAfter.sourceRef !== progress.candidate.resultSourceRef ||
            sourceAfter.source.manifestDigest !== progress.candidate.sourceDigest;
          if (!sourceChanged && frozen.checkpoint.workspaceStateRef !== selected.latestCheckpoint.workspaceStateRef)
            throw new KernelStorageError('RECOVERY_REQUIRED', 'verifier changed its private generation outside the source projection');
          const inspector = supervisorInspectorIdentity(assertActiveStateOwner(driver, owner));
          const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
          if (sourceChanged && !integrityMetadata) {
            const before = decodeSourceManifest(await readCanonicalArtifact(artifacts, progress.candidate.resultSourceRef));
            const beforeEntries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, before.entriesRef));
            const afterEntries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, sourceAfter.source.entriesRef));
            const old = new Map(beforeEntries.entries.map(entry => [entry.path, canonicalSha256(entry)]));
            const next = new Map(afterEntries.entries.map(entry => [entry.path, canonicalSha256(entry)])), changed = new Set<string>();
            for (const path of new Set([...old.keys(), ...next.keys()])) if (old.get(path) !== next.get(path)) {
              if (old.has(path)) changed.add(old.get(path)!); if (next.has(path)) changed.add(next.get(path)!);
            }
            if (!changed.size || containment.filesystemBinding.kind !== 'run-generation')
              throw new KernelStorageError('RECOVERY_REQUIRED', 'verifier drift has no exact changed source entries and original generation');
            const evidence = { schemaVersion: 1, format: 'cliq-kernel-integrity-evidence-v1', runId,
              sourceProjectionRef: spec.sourceProjectionRef, workspaceGenerationRef: containment.filesystemBinding.generationRef,
              inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, observedAt: sampleCanonicalNow(),
              subjectKind: 'verifier', verifierOpId: input.opId, verifierAttempt: input.attempt, resultSourceRef: progress.candidate.resultSourceRef,
              observationKind: 'source_digest_drift', observationSource: 'trusted_out_of_containment_rehash',
              sourceBeforeRef: progress.candidate.resultSourceRef, sourceBeforeDigest: progress.candidate.sourceDigest,
              sourceAfterRef: sourceAfter.sourceRef, sourceAfterDigest: sourceAfter.source.manifestDigest,
              changedEntryDigests: [...changed].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))), evidenceDigest: '' };
            evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest');
            integrityMetadata = await artifacts.publishCanonical(evidence, evidence.format);
          }
          const containmentArtifact = await artifacts.publishCanonical(containment, 'cliq-process-containment-v1');
          if (native.death.containment.backend.kind !== 'linux') throw new TypeError('verifier retirement requires its Linux containment');
          const death: ProcessContainmentDeathEvidenceV1 = { schemaVersion: 1, kind: 'containment_all_descendants_dead', containmentRef: containmentArtifact.ref,
            planRef: containment.planRef, sandboxLaunchSpecRef: containment.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: containment.sandboxLaunchSpecDigest,
            owner: containment.owner, launchNonceDigest: containment.launchNonceDigest, inspectorSupervisorInstanceId: owner.supervisorInstanceId,
            inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
            backend: { ...native.death.containment.backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 },
            observedAt: native.death.observedAt, evidenceDigest: '' };
          death.evidenceDigest = digestOmitting(death, 'evidenceDigest');
          const deathArtifact = await artifacts.publishCanonical(death, 'cliq-process-containment-death-evidence-v1');
          const retirement: VerifierRetirementV1 = { schemaVersion: 1, format: 'cliq-verifier-retirement-v1', runId, opId: input.opId,
            attempt: input.attempt, dispatchId: claim.dispatchId!, leaseEpoch: claim.leaseEpoch, containmentRef: containmentArtifact.ref,
            deathEvidenceRef: deathArtifact.ref, checkpointId, workspaceStateRef: frozen.checkpoint.workspaceStateRef,
            snapshotEvidenceRef: frozen.checkpoint.snapshotEvidenceRef, parentRetirementEvidenceRef: frozen.checkpoint.retirementEvidenceRef,
            sourceAfterRef: sourceAfter.sourceRef, sourceAfterDigest: sourceAfter.source.manifestDigest, evidenceDigest: '' };
          retirement.evidenceDigest = digestOmitting(retirement, 'evidenceDigest');
          const retirementArtifact = await artifacts.publishCanonical(retirement, retirement.format);
          retirementMetadata = [...sourceAfter.metadata, inspectorArtifact, containmentArtifact, deathArtifact, retirementArtifact];
        }
        const retirementRef = retirementMetadata.at(-1)!.ref;
        const core = { schemaVersion: 1 as const, runId, verifierId: current.specEntry.id, verifierVersion: current.specEntry.version,
          attempt: input.attempt, resultSourceRef: progress.candidate.resultSourceRef, sourceDigestBefore: progress.candidate.sourceDigest,
          sourceDigestAfter: sourceAfter!.source.manifestDigest, commandRef: current.specEntry.commandRef, commandDigest: current.specEntry.commandDigest,
          environmentRef: current.specEntry.environmentRef, environmentDigest: current.specEntry.environmentDigest, startedAt: native.startedAt,
          endedAt: native.endedAt, durationMs: native.durationMs, terminationReason: native.terminationReason,
          ...(native.terminationReason === 'exit' ? { exitCode: native.exitCode } : native.terminationReason === 'signal' ? { signal: native.signal } : {}),
          stdoutRef: outputMetadata[0]!.ref, stderrRef: outputMetadata[1]!.ref, stdoutTruncated: native.stdoutTruncated,
          stderrTruncated: native.stderrTruncated, leaseEpoch: claim.leaseEpoch };
        if (!receipt && !stopped) {
          const termination: string = native.terminationReason;
          if (termination === 'controller_stop' && !originalStop && !integrityMetadata)
            throw new KernelStorageError('RECOVERY_REQUIRED', 'controlled verifier retirement has no original Run stop or measured source-integrity failure');
          if (originalStop && !integrityMetadata) {
            stopped = { ...core, format: 'cliq-verifier-stop-evidence-v1', stopIntentRef: run.stopIntentRef!, retirementRef, evidenceDigest: '' };
            stopped.evidenceDigest = digestOmitting(stopped, 'evidenceDigest'); decodeVerifierStopEvidence(stopped);
          } else {
            receipt = { ...core, format: 'cliq-verification-receipt-v1', containmentEvidenceRef: retirementRef,
              outcome: integrityMetadata ? 'source_mutation' : native.terminationReason !== 'exit' ? 'infra_failed' : native.exitCode === 0 ? 'passed' : 'assertion_failed',
              ...(integrityMetadata ? { violationEvidenceRef: integrityMetadata.ref,
                violationEvidenceDigest: (await readCanonicalArtifact<{ evidenceDigest: string }>(artifacts, integrityMetadata.ref)).evidenceDigest } : {}),
              receiptDigest: '' };
            receipt.receiptDigest = digestOmitting(receipt, 'receiptDigest'); decodeVerificationReceipt(receipt);
          }
        }
        if (receipt && !receiptMetadata) receiptMetadata = await artifacts.publishCanonical(receipt, receipt.format);
        if (stopped && !stoppedMetadata) stoppedMetadata = await artifacts.publishCanonical(stopped, stopped.format);
        if (!settlement) settlement = prepareValidatedInvocationSettlement(driver, artifacts, owner,
          { runId, opId: input.opId, attempt: input.attempt, expectedRunRevision: frozen.expectedRunRevision },
          receipt ? { phase: 'completed', resultRef: receiptMetadata!.ref, receiptRef: receiptMetadata!.ref, consumed: VERIFIER_BUDGET }
            : { phase: 'failed', errorRef: stoppedMetadata!.ref, consumed: VERIFIER_BUDGET, requireClaim: true },
          async ({ settlement: fixed }) => {
            if (!graph) {
              const result: VerifierResultItem | VerifierStopItem = receipt ? { schemaVersion: 1, kind: 'verifier_result',
                itemId: verifierResultItemId(runId, input.opId, input.attempt), runId, candidateItemId: progress.candidate.itemId,
                verifierPlanRef: progress.planRef, verifierIndex: frontier.nextVerifierIndex, verifierId: current.specEntry.id,
                opId: input.opId, attempt: input.attempt, outcome: receipt.outcome, receiptRef: receiptMetadata!.ref, createdAt: fixed.settledAt }
                : { schemaVersion: 1, kind: 'verifier_stop', itemId: identityHash('cliq-verifier-stop-item-v1', runId, input.opId, String(input.attempt)),
                  runId, candidateItemId: progress.candidate.itemId, verifierPlanRef: progress.planRef, verifierIndex: frontier.nextVerifierIndex,
                  verifierId: current.specEntry.id, opId: input.opId, attempt: input.attempt,
                  stopIntent: originalStop!.reason as VerifierStopItem['stopIntent'], stopIntentRef: run.stopIntentRef!,
                  containmentEvidenceRef: stoppedMetadata!.ref, createdAt: fixed.settledAt };
              if (result.kind === 'verifier_stop') decodeVerifierStopItem(result);
              const uses = selected.journal.filter(row => row.opId === input.opId && row.phase === 'dispatch_claimed').length;
              const nextIndex = stopped || receipt?.outcome === 'infra_failed' && uses < current.planEntry.maxAttempts
                ? frontier.nextVerifierIndex : frontier.nextVerifierIndex + 1;
              graph = planContinuationCommit(artifacts, { context, existingItems, items: [result], frontier: { ...frontier, nextVerifierIndex: nextIndex },
                checkpointId, workspaceStateRef: frozen.checkpoint.workspaceStateRef });
            }
            const plan = await graph.publish();
            if (!refreshed) { await seal!.refresh(); refreshed = true; }
            return { get metadata() { return [...outputMetadata!, ...retirementMetadata!, ...(integrityMetadata ? [integrityMetadata] : []),
              receiptMetadata ?? stoppedMetadata!, ...plan.metadata, ...seal!.metadata]; },
              commit(connection, actual, journal, committedAt) {
                // The settlement has already appended this exact terminal row
                // after validating the original cut in the same transaction.
                validateSnapshotWithJournal(connection, actual, [...selected.journal, journal]);
                if (fixed.settledAt < native.endedAt) throw new TypeError('verifier settlement precedes its original native observation');
                seal!.commit(connection, actual, committedAt); plan.commit(connection, actual, journal.seq, committedAt);
              } };
          }, validateSnapshot);
        if (retryCommit) await seal.refresh();
        await checkCurrent(frozen.expectedRunRevision);
        let expected = frozen.expectedRunRevision;
        for (let attempt = 0; attempt < 8; attempt++) {
          try {
            const settled = await settlement.settle(expected);
            completedFrom = frozen.expectedRunRevision; completed = { run: settled.run }; failure = undefined;
            return immutableSnapshot(completed);
          } catch (error) {
            const actual = readRun(driver, runId);
            if (!(error instanceof KernelStorageError) || error.code !== 'REVISION_CONFLICT' || actual.revision <= expected) throw error;
            // Only an independently re-read monotonic StopIntent may rebind
            // this same receipt, settlement and immutable result graph.
            await checkCurrent(actual.revision);
            if (settlement.hasRevisionConflict(error, actual.revision) && !settlement.acceptRevisionConflict(error, actual.revision)) throw error;
            expected = actual.revision;
          }
        }
        throw new KernelStorageError('REVISION_CONFLICT', 'verifier completion StopIntent cut kept changing');
      })().catch(error => { failure = error; throw error; }).finally(() => { pending = undefined; });
      return pending;
    } });
}
