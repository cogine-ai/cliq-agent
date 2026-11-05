// Actual purpose3 custody closes only its original nonce. Known effects are
// recorded through the existing Journal/continuation transaction, once, with
// the original pessimistic settlement unchanged and no additional charge.
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeMcpInvocationWait, decodeMcpRecoveryProbeEvidence, decodeMcpReconciledEffectResult, mcpUnresolvedProbeState } from '../kernel/mcp-status.js';
import type { InvocationJournalEntry, Run } from '../kernel/types.js';
import type { ResolveToolInput } from '../model/attempt.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { prepareContinuationCommit } from './continuation-commit.js';
import { KernelStorageError, stateOperation } from './errors.js';
import { assertInstalledMcpStdioProbeFence } from './mcp-stdio-native-binding.js';
import { readMcpStatusProbeEvidence } from './mcp-status-history.js';
import { decodeMcpStatusProbeClosure, decodeMcpStatusProbeWrapper } from './mcp-status-proof.js';
import { validateMcpInvocationWait } from './mcp-status-state.js';
import { readMcpStatusProbeTask, type McpStatusProbeTask } from './mcp-status-task.js';
import { appendInvocationJournalEntry, readInvocationJournal, nextJournalSequence } from './repositories/journal.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import { planToolInvocationResult, nextToolFrontier } from './reducers/tool.js';
import { readRun, ZERO_BUDGET } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { toolCheckpointId } from './tool-checkpoint.js';
import { readToolCut } from './tool-cut.js';

function fail(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
const committed = new WeakMap<McpStatusProbeTask, { driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext;
  kind: 'effect_resolved' | 'nonce_closed'; run: Run }>();
/** No caller may supply an outcome, native report, wait ref, time or proof.
 * They all come from the actual owning task and a freshly validated cut. */
export const finalizeMcpStatusProbe = stateOperation('RECOVERY_REQUIRED', async (driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, task: McpStatusProbeTask, resolveToolInput: ResolveToolInput, signal?: AbortSignal) => {
  const durable = committed.get(task);
  if (durable) {
    if (durable.driver !== driver || durable.artifacts !== artifacts || durable.owner !== owner)
      fail('MCP status completion acknowledgement changed its actual original store or owner');
    assertActiveStateOwner(driver, owner);
    const current = readRun(driver, durable.run.id);
    if (current.revision < durable.run.revision) fail('MCP status committed completion regressed its actual Run');
    task.acknowledge(); return immutableSnapshot({ kind: durable.kind, run: current });
  }
  const held = readMcpStatusProbeTask(driver, artifacts, owner, task), original = held.prepared;
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const fence = held.native.acquireProbeFence(original.binding);
  try {
    // At most one local classification pivot is possible: an observation
    // prepared before the deadline may commit only before that same deadline.
    // If publication crossed it, retain the real result as a late audit and
    // prepare a genuine timeout using a newly sampled actual close time.
    for (let classification = 0; classification < 2; classification++) {
      reads.assertReadActive(); assertInstalledMcpStdioProbeFence(fence, original.binding);
      const cut = await (await import('./recovery-closure.js')).readRecoveryClosure(driver, reads, original.run.id);
      const selected = await validateMcpInvocationWait(driver, reads, cut), { run, wait, source } = selected;
      if (run.waitingOnRef !== original.run.waitingOnRef || canonicalSha256(wait) !== original.binding.waitingSubjectRef ||
          canonicalSha256(source.subject) !== original.binding.reconciliationSubjectDigest || owner.ownerEpoch !== original.preparation.inspectorStateOwnerEpoch ||
          owner.supervisorInstanceId !== original.preparation.inspectorSupervisorInstanceId)
        fail('MCP status finalizer cannot close a newer nonce or another native owner');
      const state = wait.probeState;
      if ((state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight') || state.dispatch.subjectKind !== 'mcp_recovery')
        fail('MCP status finalizer lost its original persisted purpose3 dispatch');
      const dispatch = state.dispatch, at = sampleCanonicalNow(), capture = held.capture;
      if (at < held.retirement.value.observedAt || at < run.updatedAt) fail('MCP status finalizer time regressed behind its actual physical retirement or current Run');
      const observed = !!capture && at < dispatch.probeDeadlineAt && capture.value.observedAt < dispatch.probeDeadlineAt;
      if (!observed && at < dispatch.probeDeadlineAt && !held.shutdown)
        return immutableSnapshot({ kind: 'awaiting_original_deadline' as const, run });
      const identity = held.retirement.physical.evidence;
      const common = { schemaVersion: 1 as const, format: 'cliq-reconciliation-probe-evidence-v1' as const, runId: run.id,
        waitingSubjectRef: run.waitingOnRef!, waitingSubjectDigest: run.waitingOnRef!, probeKind: dispatch.probeKind,
        probeOrdinal: dispatch.probeOrdinal, probeNonceDigest: dispatch.probeNonceDigest, probeDispatchDigest: dispatch.dispatchDigest,
        probeStartedAt: dispatch.probeStartedAt, probeDeadlineAt: dispatch.probeDeadlineAt,
        inspectorIdentityRef: identity.inspectorIdentityRef, inspectorIdentityDigest: identity.inspectorIdentityDigest };
      const metadata: PublishedArtifact[] = [...(capture?.metadata ?? held.retirement.metadata)];
      let wrapper: ReturnType<typeof decodeMcpStatusProbeWrapper>;
      if (observed) {
        const core = { schemaVersion: 1 as const, format: 'cliq-mcp-recovery-probe-evidence-v1' as const, runId: run.id,
          waitingSubjectRef: run.waitingOnRef!, opId: source.claim.opId, attempt: source.claim.attempt, probeKind: dispatch.probeKind,
          probeOrdinal: dispatch.probeOrdinal, probeNonceDigest: dispatch.probeNonceDigest, probeDispatchDigest: dispatch.dispatchDigest,
          registryRevisionRef: source.registry.ref, registryManifestDigest: source.registry.registry.manifestDigest,
          serverToolName: source.original.execution.serverToolName, profileId: source.profile.profileId, profileDigest: source.profile.profileDigest,
          statusRequestTemplateRef: source.recovery.statusRequestTemplateRef, statusRequestTemplateDigest: source.recovery.statusRequestTemplateDigest,
          statusRequestDigest: source.statusRequest.digest, brokerDispatchId: dispatch.brokerDispatchId, brokerTargetDigest: dispatch.brokerTargetDigest,
          statusResponseRef: capture!.value.statusResponseRef, statusResponseDigest: capture!.value.statusResponseDigest,
          statusCaptureRef: capture!.ref, statusCaptureDigest: capture!.value.captureDigest,
          completedPredicateRef: source.recovery.completedPredicateRef, completedPredicateDigest: source.recovery.completedPredicateDigest,
          failedPredicateRef: source.recovery.failedPredicateRef, failedPredicateDigest: source.recovery.failedPredicateDigest,
          disposition: capture!.value.disposition, observedAt: capture!.value.observedAt };
        const evidence = decodeMcpRecoveryProbeEvidence({ ...core, evidenceDigest: canonicalSha256(core) });
        const artifact = await artifacts.publishCanonical(evidence, evidence.format); metadata.push(artifact);
        const wrapperCore = { ...common, observedAt: evidence.observedAt, outcome: 'subject_observation' as const,
          subjectEvidenceKind: 'mcp_recovery' as const, subjectEvidenceRef: artifact.ref, subjectEvidenceDigest: evidence.evidenceDigest };
        wrapper = decodeMcpStatusProbeWrapper({ ...wrapperCore, evidenceDigest: canonicalSha256(wrapperCore) });
      } else {
        const cancellation = at < dispatch.probeDeadlineAt;
        const core = { schemaVersion: 1 as const, format: cancellation ? 'cliq-reconciliation-probe-cancellation-closure-v1' as const : 'cliq-reconciliation-probe-timeout-closure-v1' as const,
          runId: run.id, waitingSubjectRef: run.waitingOnRef!, probeKind: dispatch.probeKind, probeOrdinal: dispatch.probeOrdinal,
          probeNonceDigest: dispatch.probeNonceDigest, probeDispatchDigest: dispatch.dispatchDigest, probeDeadlineAt: dispatch.probeDeadlineAt,
          inspectorIdentityRef: identity.inspectorIdentityRef, inspectorIdentityDigest: identity.inspectorIdentityDigest, closedAt: at,
          subjectKind: 'mcp_recovery' as const, brokerDispatchId: dispatch.brokerDispatchId, brokerTargetDigest: dispatch.brokerTargetDigest,
          brokerFenceTokenDigest: dispatch.brokerFenceTokenDigest, noActiveReleaseForNonce: true as const,
          retirementRef: held.retirement.ref, retirementDigest: held.retirement.value.retirementDigest,
          ...(capture ? { lateStatusCaptureRef: capture.ref, lateStatusCaptureDigest: capture.value.captureDigest } : {}),
          ...(cancellation ? { reason: 'owning_supervisor_shutdown' as const } : {}) };
        const closure = decodeMcpStatusProbeClosure({ ...core, closureDigest: canonicalSha256(core) });
        const artifact = await artifacts.publishCanonical(closure, closure.format); metadata.push(artifact);
        const wrapperCore = { ...common, observedAt: at, ...(cancellation
          ? { outcome: 'probe_cancelled' as const, cancellationReason: 'owning_supervisor_shutdown' as const,
              cancellationClosureRef: artifact.ref, cancellationClosureDigest: closure.closureDigest }
          : { outcome: 'probe_timeout' as const, timeoutReason: 'no_authoritative_observation_before_deadline' as const,
              timeoutClosureRef: artifact.ref, timeoutClosureDigest: closure.closureDigest }) };
        wrapper = decodeMcpStatusProbeWrapper({ ...wrapperCore, evidenceDigest: canonicalSha256(wrapperCore) });
      }
      const wrapperArtifact = await artifacts.publishCanonical(wrapper, wrapper.format); metadata.push(wrapperArtifact);
      // Repeat complete raw bytes, schema, signed predicates and native
      // provenance before they can participate in the original transaction.
      const proof = await readMcpStatusProbeEvidence(driver, reads, source, wrapperArtifact.ref, wrapper.evidenceDigest);
      const known = proof.wrapper.outcome === 'subject_observation' && proof.evidence && proof.evidence.disposition !== 'unresolved' ? proof.evidence : undefined;
      const reason = proof.reason;
      const nextWait = known ? undefined : decodeMcpInvocationWait({ ...wait,
        probeState: mcpUnresolvedProbeState(wait, wrapperArtifact.ref, wrapper.evidenceDigest, wrapper.observedAt, reason) });
      const nextWaitArtifact = nextWait && await artifacts.publishCanonical(nextWait, 'cliq-waiting-subject-v1');
      if (nextWaitArtifact) metadata.push(nextWaitArtifact);
      const tool = known ? await readToolCut(driver, reads, run.id, resolveToolInput) : undefined;
      let resolution: ReturnType<typeof decodeMcpReconciledEffectResult> | undefined;
      let resolutionArtifact: PublishedArtifact | undefined;
      let continuation: Awaited<ReturnType<typeof prepareContinuationCommit>> | undefined;
      if (known) {
        requireEqual(tool!.run, run, 'MCP signed status original complete ordered tool cut');
        if (tool!.batch.itemId !== source.original.request.batchItemId || tool!.frontier.nextCallIndex !== source.original.request.callIndex ||
            tool!.call.callId !== source.original.request.callId || tool!.checkpoint.journalSeq !== cut.journal.length)
          fail('MCP status known effect cannot overtake its original ordered tool call');
        const disposition = known.disposition === 'completed' ? 'completed' as const : 'failed' as const;
        const core = { schemaVersion: 1 as const, format: 'cliq-mcp-reconciled-effect-result-v1' as const, runId: run.id, opId: source.claim.opId,
          attempt: source.claim.attempt, originalDispatchId: source.claim.dispatchId!, unknownJournalSeq: source.unknown.seq,
          budgetSettlementRef: source.unknown.budgetSettlementRef!, probeEvidenceRef: wrapperArtifact.ref, probeEvidenceDigest: wrapper.evidenceDigest,
          disposition, originalResponse: 'unavailable' as const, code: disposition === 'completed' ? 'TOOL_RESULT_UNAVAILABLE' as const : 'TOOL_EXECUTION_FAILED' as const,
          effect: disposition === 'completed' ? 'confirmed_completed' as const : 'confirmed_failed' as const, observedAt: known.observedAt };
        resolution = decodeMcpReconciledEffectResult({ ...core, resultDigest: canonicalSha256(core) });
        resolutionArtifact = await artifacts.publishCanonical(resolution, resolution.format); metadata.push(resolutionArtifact);
        const result = planToolInvocationResult(source.original.request, at, { outcome: 'error', code: resolution.code,
          opId: source.claim.opId, attempt: source.claim.attempt, diagnosticRef: resolutionArtifact.ref, diagnosticDigest: resolution.resultDigest,
          ...(disposition === 'failed' ? { journalErrorRef: resolutionArtifact.ref, journalErrorDigest: resolution.resultDigest } : {}) },
          { code: resolution.code, effect: resolution.effect, originalResponse: resolution.originalResponse });
        continuation = await prepareContinuationCommit(artifacts, { context: tool!.context, existingItems: tool!.items, items: [result.item],
          frontier: nextToolFrontier(tool!, 1), checkpointId: toolCheckpointId(run.id, source.claim.opId, source.claim.attempt),
          workspaceStateRef: tool!.checkpoint.workspaceStateRef, artifacts: result.artifacts });
        metadata.push(...continuation.metadata);
      }
      reads.assertReadActive(); let outcome: TimeFenceAdvance | undefined, updated!: Run, crossedDeadline = false;
      driver.transaction(connection => {
        reads.assertReadActive(); assertActiveStateOwner(connection, owner); assertInstalledMcpStdioProbeFence(fence, original.binding);
        readMcpStatusProbeTask(driver, artifacts, owner, task);
        requireEqual(readRun(connection, run.id), run, 'MCP original status finalization Run');
        requireEqual(readInvocationJournal(connection, run.id), cut.journal, 'MCP original status finalization Journal');
        source.registry.assertUnchanged(connection); source.original.history.assertUnchanged(connection);
        const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
        if (now < at || now < wrapper.observedAt) fail('MCP status finalization time regressed behind its actual evidence');
        if (observed && now >= dispatch.probeDeadlineAt) { crossedDeadline = true; return; }
        for (const artifact of metadata) insertArtifactMetadata(connection, artifact, now);
        if (known && resolution && resolutionArtifact && continuation) {
          const entry: InvocationJournalEntry = { ...source.claim, seq: nextJournalSequence(connection, run.id), phase: resolution.disposition,
            budgetDelta: ZERO_BUDGET, budgetSettlementRef: source.unknown.budgetSettlementRef!, timestamp: now,
            ...(resolution.disposition === 'completed' ? { resultRef: resolutionArtifact.ref }
              : { errorRef: resolutionArtifact.ref, evidenceRef: wrapperArtifact.ref, evidenceDigest: wrapper.evidenceDigest }) };
          appendInvocationJournalEntry(connection, entry);
          continuation.commit(connection, run, entry.seq, now);
          connection.prepare("UPDATE runs SET status='queued',waiting_reason=NULL,waiting_on_ref=NULL,revision=revision+1,updated_at=? WHERE id=?").run(now, run.id);
        } else {
          if (!nextWaitArtifact) fail('MCP unresolved status lost its original next wait');
          connection.prepare('UPDATE runs SET waiting_on_ref=?,revision=revision+1,updated_at=? WHERE id=?').run(nextWaitArtifact.ref, now, run.id);
        }
        updated = readRun(connection, run.id); appendRunStateEvent(connection, updated, now);
      });
      requireHealthyFence(outcome);
      if (crossedDeadline) continue;
      const kind = known ? 'effect_resolved' as const : 'nonce_closed' as const;
      committed.set(task, { driver, artifacts, owner, kind, run: updated });
      fence.close(); task.acknowledge(); return immutableSnapshot({ kind, run: updated });
    }
    return fail('MCP status classification changed after its fixed deadline closure');
  } finally { fence.close(); }
});
