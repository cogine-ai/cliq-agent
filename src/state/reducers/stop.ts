import { canonicalSha256 } from '../../kernel/canonical.js';
import { planCanonicalArtifact, type PlannedArtifact } from '../../kernel/artifact-plan.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../../kernel/identity.js';
import type { BudgetSettlementV1, ContinuationItem, InvocationJournalEntry, Run, RunAssemblyV1, RunCancel, RunFrontier, RunSpec, SessionRunTerminalItem } from '../../kernel/types.js';
import type { ToolCheckpointProof } from '../../kernel/tool-authorization.js';
import { immutableSnapshot } from '../../model/immutable.js';
import type { ResolveToolInput } from '../../model/attempt.js';
import { exactKeys, requireEqual } from '../../policy/runtime-authority.js';
import { toolOperationId } from '../../policy/tool-policy.js';
import { cancelledCall, cancelRequestDigest, agentStopDetail, openStopBatch, selectAgentStop, stopCheckpointId, stopInvocationHistory, type AgentStopIntent } from '../../runtime/stop.js';
import { readCanonicalArtifact } from '../agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from '../artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import { validateControlChannelClosure } from '../control-channel.js';
import { prepareContinuationCommit } from '../continuation-commit.js';
import { decodeAdmittedContext, decodeContextManifest, decodeSessionProjection } from '../decoders.js';
import { KernelStorageError, RunTerminalError, stateOperation } from '../errors.js';
import { isZeroBudget, subtractBudget } from '../invariants.js';
import { readRecoveryClosure } from '../recovery-closure.js';
import { appendInvocationJournalEntry, nextJournalSequence } from '../repositories/journal.js';
import { readRequiredWorkerLaunch, readWorkerLaunchesForRun } from '../repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef } from '../repositories/workspace-generations.js';
import { insertControlRequest, readControlRequest, readRun, readSession, ZERO_BUDGET } from '../rows.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';
import { readCancelResponse, readAgentStop, type CancelResponse } from '../stop-recovery.js';
import { readResourceStopCause } from '../resource-stop.js';
import { prepareModelFailureStop } from '../model-failure.js';
import { prepareToolCheckpoint, type NativeWorkerRetirement } from '../tool-checkpoint.js';
import { readToolCut } from '../tool-cut.js';
import { assertRetiredGenerationCut } from '../generation-retirement.js';
import { withInstalledBrokerTerminalClosure } from '../broker-ambiguity.js';
import type { HeldInstalledRuntime } from '../installed-runtime.js';
import { readWorkerRecoveryTerminalPlan, type WorkerRecoveryTerminalPlan } from '../worker-recovery-terminal.js';
import { planPrivateRollbackResult } from '../private-tool-rollback.js';
import { validateInstalledModelNoReleaseHistory } from '../broker-no-release.js';
import { appendRunStateEvent, requireHealthyFence, resolvePrivateRollbackInvocation } from './invocation.js';
import { decodeVerificationClosure } from '../result-artifacts.js';
import { readVerifierProgress } from '../verifier-recovery.js';
import { readVerifierFailureCause, readVerifierIntegrityCause, readVerifierPolicyDenial, validateVerifierStoppedHistory } from '../verifier-stop-history.js';
import type { VerifierPolicyDecisionItem } from '../../kernel/verifier-invocation.js';
import { assertDeliveryModelFreeCut } from '../run-model-free.js';
import { closeOwnedPublicationAbortFinalization, readOwnedPublicationAbortFinalization,
  type OwnedPublicationAbortFinalization } from '../publication-abort-finalization.js';
import { readUnclaimedPublicationStopHistory } from '../delivery-publication-recovery.js';

/** Loaded authority only. Cancellation fences immediately; terminal drain independently proves the entire current cut. */
export function loadAgentStop(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, authority: {
  run: Run; spec: RunSpec; assembly: RunAssemblyV1; principalId: string; resolveToolInput: ResolveToolInput;
  assertAuthority: () => Promise<void>;
}, reobserve?: NativeWorkerRetirement, installedRuntime?: HeldInstalledRuntime) {
  const { run: admitted, spec, assembly, principalId } = authority;
  const runId = admitted.id;
  const result = (run: Run) => ({ run, checkpointId: stopCheckpointId(runId, run.stopIntentRef!) });
  const deadlineIntent = (createdAt: string): AgentStopIntent => ({ schemaVersion: 1, runId, createdAt, origin: 'deadline',
    targetStatus: 'failed', reason: 'budget_exhausted', deadlineAt: admitted.deadlineAt });
  async function cut(revision: number, allowWorkerRecovery = false, allowUnstartedCandidate = false) {
    if (!Number.isSafeInteger(revision) || revision < 1) throw new TypeError('invalid stop revision');
    const selected = await readRecoveryClosure(driver, artifacts, runId);
    const { run } = selected;
    if (run.revision !== revision) throw new KernelStorageError('REVISION_CONFLICT', 'stop Run revision changed');
    if (run.specRef !== admitted.specRef || run.createdAt !== admitted.createdAt || run.deadlineAt !== admitted.deadlineAt) throw new TypeError('stop authority no longer belongs to this Run');
    if (spec.operation === 'delivery') assertDeliveryModelFreeCut(selected);
    if (run.parentRunId || selected.childAllocations.length ||
        driver.prepare('SELECT 1 FROM runs WHERE parent_run_id = ? LIMIT 1').get(runId)) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'child stop requires the parent/child settlement reducer');
    if (['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(run.status)) throw new RunTerminalError();
    if (run.nextStep === 'verify' || run.nextStep === 'finalize') {
      // The full recovery reader validates the original candidate, frozen
      // verifier progress and exact active/death-wait lifecycle. A stop only
      // adds a fence; terminal drain below still requires the original claim
      // and invocation/parent retirement, never a worker-free substitution.
      const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef!);
      if (!allowUnstartedCandidate || !['queued', 'running', 'waiting'].includes(run.status) || frontier.schemaVersion !== 1 ||
          run.status === 'waiting' && !(allowWorkerRecovery && run.waitingReason === 'reconciliation'))
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate stop requires its exact verification lifecycle');
      if (frontier.kind === 'verify' && run.nextStep === 'verify' && exactKeys(frontier, ['schemaVersion', 'kind', 'phase', 'candidateItemId',
        'resultSourceRef', 'verifierPlanRef', 'nextVerifierIndex', 'afterPass']) && frontier.phase === 'verifiers' &&
          frontier.afterPass === (spec.operation === 'agent' ? 'finalize' : 'delivery_approval')) {
        const progress = await readVerifierProgress(driver, artifacts, selected, frontier.candidateItemId);
        if (frontier.nextVerifierIndex !== progress.nextVerifierIndex || frontier.verifierPlanRef !== progress.planRef ||
            frontier.resultSourceRef !== progress.candidate.resultSourceRef) throw new TypeError('stop substituted its exact verifier progress');
        return selected;
      }
      if (frontier.kind !== 'finalize' || run.nextStep !== 'finalize' || frontier.operation !== spec.operation ||
          run.status !== 'queued' || run.activeWorkerLaunchId || run.waitingReason || run.waitingOnRef ||
          !exactKeys(frontier, ['schemaVersion', 'kind', 'operation', 'candidateItemId', 'resultSourceRef', 'verificationClosureRef',
            ...(spec.operation === 'delivery' ? ['deliveryTerminalProjectionEvidenceRef'] : [])]))
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate stop requires its exact unstarted verification or consent-backed finalization');
      const closure = decodeVerificationClosure(await readCanonicalArtifact(artifacts, frontier.verificationClosureRef));
      if (closure.runId !== run.id || closure.candidateItemId !== frontier.candidateItemId || closure.resultSourceRef !== frontier.resultSourceRef ||
          spec.operation === 'agent' && (closure.verification.kind !== 'local' || closure.verification.unverifiedConsentRef !== spec.unverifiedConsentRef) ||
          spec.operation === 'delivery' && closure.verification.kind === 'local' && closure.verification.outcome !== 'verified')
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate stop has no exact unverified closure');
      return selected;
    }
    if (spec.operation === 'delivery') {
      const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef!);
      if (!['queued', 'running', 'waiting'].includes(run.status) || run.nextStep !== 'delivery' || frontier.kind !== 'delivery' ||
          run.status === 'waiting' && !(run.waitingReason === 'approval' && frontier.phase === 'approval') &&
            !(allowWorkerRecovery && run.waitingReason === 'reconciliation'))
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'delivery stop requires its exact retained delivery continuation');
      return selected;
    }
    // Cancellation/deadline may fence a validated worker-death wait, but cannot clear it or drain it.
    if (!['queued', 'running', 'waiting'].includes(run.status) || !['agent', 'tool'].includes(run.nextStep ?? '') ||
        (run.status === 'waiting' && !['approval', 'input'].includes(run.waitingReason ?? '') &&
          !(allowWorkerRecovery && run.waitingReason === 'reconciliation'))) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'stop requires an agent continuation or ordinary control wait');
    return selected;
  }
  function assertCut(connection: SqliteConnection, selected: Awaited<ReturnType<typeof cut>>) {
    assertActiveStateOwner(connection, owner);
    if (canonicalSha256(readRun(connection, runId)) !== canonicalSha256(selected.run)) throw new KernelStorageError('REVISION_CONFLICT', 'stop Run cut changed');
    if (nextJournalSequence(connection, runId) !== selected.journal.length + 1 ||
        Number(connection.prepare('SELECT COALESCE(max(item_seq), 0) AS seq FROM items WHERE run_id = ?').get<{ seq: bigint }>(runId)?.seq) !== selected.items.length ||
        connection.prepare('SELECT 1 FROM child_allocations WHERE parent_run_id = ? LIMIT 1').get(runId) ||
        connection.prepare('SELECT 1 FROM runs WHERE parent_run_id = ? LIMIT 1').get(runId)) throw new KernelStorageError('REVISION_CONFLICT', 'stop continuation changed');
  }
  function acceptTime(connection: SqliteConnection, now: string): { accepted: boolean; outcome?: TimeFenceAdvance } {
    assertActiveStateOwner(connection, owner);
    const sampled = sampleCanonicalNow(), fence = readTimeFence(connection);
    if (!fence) throw new KernelStorageError('RECOVERY_REQUIRED', 'stop canonical time fence is missing');
    if (sampled < now || sampled < fence.lastAcceptedAt) return { accepted: false, outcome: advanceTimeFence(connection, owner.ownerEpoch, sampled) };
    if (now < fence.lastAcceptedAt) return { accepted: false };
    const outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    return { accepted: outcome === 'healthy', outcome };
  }
  async function commitDerivedStop(selected: Awaited<ReturnType<typeof cut>>, derive: (now: string) => Promise<{
    intent: AgentStopIntent; metadata?: PublishedArtifact[]; commit?: (connection: SqliteConnection, run: Run, committedAt: string) => void;
  } | undefined>) {
    const prior = selected.run.stopIntentRef ? await readAgentStop(driver, artifacts, selected) : undefined;
    for (let retry = 0; retry < 8; retry++) {
      const now = sampleCanonicalNow();
      const proposal = await derive(now);
      if (!proposal) {
        if (prior) return immutableSnapshot(result(selected.run));
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'current continuation has no supported failure');
      }
      const intent = selectAgentStop(prior, proposal.intent);
      if (intent === prior) return immutableSnapshot(result(selected.run));
      const artifact = await artifacts.publishCanonical(intent, 'cliq-stop-intent-v1');
      let time: ReturnType<typeof acceptTime> | undefined, updated: Run | undefined;
      driver.transaction((connection) => {
        time = acceptTime(connection, now);
        if (!time.accepted) return;
        assertCut(connection, selected);
        if (intent.origin === 'runtime' && intent.runtimeSubtype === 'runtime' &&
            parseCanonicalTime(sampleCanonicalNow()) - parseCanonicalTime(now) > 5_000) {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'model failure observation is stale; reobserve the Journal');
        }
        for (const metadata of proposal.metadata ?? []) insertArtifactMetadata(connection, metadata, now);
        insertArtifactMetadata(connection, artifact, now);
        proposal.commit?.(connection, selected.run, now);
        connection.prepare('UPDATE runs SET stop_intent_ref = ?, revision = revision + 1, updated_at = ? WHERE id = ?').run(artifact.ref, now, runId);
        updated = readRun(connection, runId);
        appendRunStateEvent(connection, updated, now);
      });
      requireHealthyFence(time?.outcome);
      if (updated) return immutableSnapshot(result(updated));
    }
    throw new KernelStorageError('REVISION_CONFLICT', 'failure/time cut kept changing');
  }
  return {
    cancelRun: stateOperation('INVALID_REQUEST', async (input: RunCancel) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['principalId', 'channelIdentityRef', 'channelIdentityDigest', 'requestId', 'expectedRunRevision'])) throw new TypeError('unknown run.cancel field');
      const digest = cancelRequestDigest(runId, input);
      assertActiveStateOwner(driver, owner);
      if (input.principalId !== principalId) throw new KernelStorageError('ARTIFACT_MISMATCH', 'cancellation caller does not own this Run');
      const channel = await validateControlChannelClosure(artifacts, owner, input);
      const replay = async () => {
        const row = readControlRequest(driver, principalId, 'run.cancel', input.requestId);
        if (!row) return undefined;
        if (row.requestDigest !== digest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.cancel requestId was reused with different bytes');
        const { response } = await readCancelResponse(driver, artifacts, readRun(driver, runId), principalId, input.requestId);
        return immutableSnapshot({ replayed: true, ...result(response.result.snapshot.run), response });
      };
      const existing = await replay();
      if (existing) return existing;
      const selected = await cut(input.expectedRunRevision, true, true);
      const prior = selected.run.stopIntentRef ? await readAgentStop(driver, artifacts, selected) : undefined;
      for (let retry = 0; retry < 8; retry++) {
        const now = sampleCanonicalNow();
        // The cancellation fence is monotonic even when integrity already
        // outranks it. Equal precedence preserves the first committed intent.
        const intent = selectAgentStop(prior, {
          schemaVersion: 1, runId, createdAt: now, origin: 'user_cancel', targetStatus: 'cancelled', reason: 'cancelled_by_user',
          requestId: input.requestId, principalId });
        const intentArtifact = await artifacts.publishCanonical(intent, 'cliq-stop-intent-v1');
        const next: Run = { ...selected.run, stopIntentRef: intentArtifact.ref, cancelRequested: true, revision: selected.run.revision + 1, updatedAt: now };
        const response: CancelResponse = { protocolVersion: 1, ok: true, result: { method: 'run.cancel',
          snapshot: { schemaVersion: 1, operation: spec.operation, run: next, latestRunItemSeq: selected.items.length } } };
        const responseArtifact = await artifacts.publishCanonical(response, 'cliq-control-application-response-v1');
        let time: ReturnType<typeof acceptTime> | undefined, committed = false;
        driver.transaction((connection) => {
          assertActiveStateOwner(connection, owner);
          if (readControlRequest(connection, principalId, 'run.cancel', input.requestId)) return;
          time = acceptTime(connection, now);
          if (!time.accepted) return;
          assertCut(connection, selected);
          for (const artifact of [...channel.metadata, intentArtifact, responseArtifact]) insertArtifactMetadata(connection, artifact, now);
          connection.prepare('UPDATE runs SET stop_intent_ref = ?, cancel_requested = 1, revision = revision + 1, updated_at = ? WHERE id = ?')
            .run(intentArtifact.ref, now, runId);
          requireEqual(readRun(connection, runId), next, 'committed cancellation snapshot');
          appendRunStateEvent(connection, next, now);
          insertControlRequest(connection, { principalId, method: 'run.cancel', requestId: input.requestId, requestDigest: digest,
            channelIdentityRef: input.channelIdentityRef, channelIdentityDigest: input.channelIdentityDigest, responseRef: responseArtifact.ref, committedAt: now });
          committed = true;
        });
        requireHealthyFence(time?.outcome);
        if (committed) return immutableSnapshot({ replayed: false, ...result(next), response });
        const replayed = await replay();
        if (replayed) return replayed;
      }
      throw new KernelStorageError('REVISION_CONFLICT', 'cancellation cut kept changing');
    }),
    expireRun: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('unknown deadline stop field');
      const selected = await cut(input.expectedRunRevision, true, true);
      if (sampleCanonicalNow() < selected.run.deadlineAt) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'Run deadline has not elapsed');
      return commitDerivedStop(selected, async (now) => {
        if (now < selected.run.deadlineAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'deadline clock regressed');
        return { intent: deadlineIntent(now) };
      });
    }),
    stopForResourceFailure: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('unknown resource stop field');
      assertActiveStateOwner(driver, owner);
      await authority.assertAuthority();
      const selected = await cut(input.expectedRunRevision, false, spec.operation === 'delivery');
      return commitDerivedStop(selected, async (now) => {
        if (now >= selected.run.deadlineAt) return { intent: deadlineIntent(now) };
        const cause = await readResourceStopCause(driver, artifacts, selected, now);
        return cause ? { intent: { schemaVersion: 1, runId, createdAt: now, ...cause } } : undefined;
      });
    }),
    stopForModelFailure: stateOperation('INVALID_REQUEST', async (input: {
      expectedRunRevision: number; inspectorIdentityRef: string; inspectorIdentityDigest: string;
    }) => {
      if (spec.operation !== 'agent') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'model failure requires an Agent Run');
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision', 'inspectorIdentityRef', 'inspectorIdentityDigest'])) throw new TypeError('unknown model failure stop field');
      assertActiveStateOwner(driver, owner);
      await authority.assertAuthority();
      const selected = await cut(input.expectedRunRevision);
      return commitDerivedStop(selected, async (now) => {
        if (now >= selected.run.deadlineAt) return { intent: deadlineIntent(now) };
        return prepareModelFailureStop(driver, artifacts, assertActiveStateOwner(driver, owner), assembly, selected, {
          inspectorIdentityRef: input.inspectorIdentityRef, inspectorIdentityDigest: input.inspectorIdentityDigest
        }, now);
      });
    }),
    stopForVerification: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('unknown verification stop field');
      assertActiveStateOwner(driver, owner); await authority.assertAuthority();
      const selected = await cut(input.expectedRunRevision, true, true);
      return commitDerivedStop(selected, async now => {
        const integrity = await readVerifierIntegrityCause(driver, artifacts, selected, now);
        if (integrity) return { intent: integrity };
        if (now >= selected.run.deadlineAt) return { intent: deadlineIntent(now) };
        const cause = await readVerifierFailureCause(driver, artifacts, selected, now);
        return cause ? { intent: cause } : undefined;
      });
    }),
    stopForVerifierPolicyDenial: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('unknown verifier policy stop field');
      assertActiveStateOwner(driver, owner); await authority.assertAuthority();
      const selected = await cut(input.expectedRunRevision, false, true);
      return commitDerivedStop(selected, async now => {
        const integrity = await readVerifierIntegrityCause(driver, artifacts, selected, now);
        if (integrity) return { intent: integrity };
        if (now >= selected.run.deadlineAt) return { intent: deadlineIntent(now) };
        const cause = await readVerifierPolicyDenial(driver, artifacts, selected, now);
        if (!cause) return undefined;
        const evidence = await artifacts.publishCanonical(cause.evidence, cause.evidence.format);
        const intent: AgentStopIntent = { schemaVersion: 1, runId, createdAt: now, origin: 'policy_deny', subjectKind: 'verifier',
          targetStatus: 'failed', reason: 'verification_failed', opId: cause.planned.request.opId,
          policyChannelEvidenceRef: evidence.ref, policyChannelEvidenceDigest: cause.evidence.evidenceDigest };
        const intentRef = planCanonicalArtifact(intent, 'cliq-stop-intent-v1').ref;
        const item: VerifierPolicyDecisionItem = { schemaVersion: 1, kind: 'policy_decision', subjectKind: 'verifier_launch',
          itemId: identityHash('cliq-verifier-policy-item-v1', runId, intent.opId, evidence.ref), runId, opId: intent.opId,
          principalId: cause.principalId, decisionRef: evidence.ref, policyChannelEvidenceRef: evidence.ref,
          policyChannelEvidenceDigest: cause.evidence.evidenceDigest, createdAt: now, decisionSource: 'direct_policy', decision: 'deny',
          denialOutcome: { kind: 'stop_intent', subjectKind: 'verifier_launch', stopIntentRef: intentRef } };
        const checkpointId = identityHash('cliq-verifier-denial-checkpoint-v1', runId, intent.opId, evidence.ref);
        const graph = await prepareContinuationCommit(artifacts, {
          context: decodeContextManifest(await readCanonicalArtifact(artifacts, selected.latestCheckpoint.contextManifestRef)),
          existingItems: await artifacts.mapReads(selected.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
            item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) })),
          items: [item], frontier: cause.frontier, checkpointId, workspaceStateRef: selected.latestCheckpoint.workspaceStateRef,
          artifacts: [planCanonicalArtifact(cause.planned.request, cause.planned.request.format), planCanonicalArtifact(cause.planned.target, cause.planned.target.format)]
        });
        return { intent, metadata: [evidence, ...graph.metadata],
          commit(connection: SqliteConnection, run: Run, committedAt: string) { graph.commit(connection, run, selected.journal.length, committedAt); } };
      });
    }),
    commitTerminalStop: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number; checkpoint?: ToolCheckpointProof },
      recovery?: WorkerRecoveryTerminalPlan, publicationFinalization?: OwnedPublicationAbortFinalization) => {
      const publication = publicationFinalization === undefined ? undefined
        : readOwnedPublicationAbortFinalization(driver, owner, publicationFinalization, runId);
      try {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision', ...(input.checkpoint === undefined ? [] : ['checkpoint'])])) throw new TypeError('unknown terminal stop field');
      if (publication && (spec.operation !== 'delivery' || recovery !== undefined || input.checkpoint !== undefined))
        throw new TypeError('owned publication stop cannot substitute a checkpoint or worker-recovery plan');
      assertActiveStateOwner(driver, owner);
      await authority.assertAuthority();
      const recovered = await readRecoveryClosure(driver, artifacts, runId);
      if (recovered.run.stopIntentRef && ['failed', 'cancelled'].includes(recovered.run.status) &&
          [recovered.run.revision, recovered.latestCheckpoint.basedOnRunRevision].includes(input.expectedRunRevision)) {
        return immutableSnapshot({ run: recovered.run });
      }
      const workerRecovery = recovery === undefined ? undefined : readWorkerRecoveryTerminalPlan(driver, owner, recovery, runId);
      const selected = await cut(input.expectedRunRevision, workerRecovery !== undefined, true);
      const { run, latestCheckpoint: checkpoint } = selected;
      if (workerRecovery) requireEqual(selected, workerRecovery.cut, 'terminal original worker recovery cut');
      if (publication) requireEqual(selected, publication.cut, 'terminal original owned publication cut');
      if (!run.stopIntentRef) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal drain requires a persisted StopIntent');
      if (assembly.mcpServers.length) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP stop requires server-containment closure');
      // The public recovery cut already verified every sealed worker proof;
      // stop additionally forbids the preactivation and fenced branches.
      if (readWorkerLaunchesForRun(driver, runId).some(launch => launch.phase === 'retired' && launch.retirementKind !== 'preparation' && launch.generationWriteState !== 'sealed' &&
          !selected.workspaceGenerations.some(generation => generation.generationRef === launch.workspaceGenerationRef && generation.phase === 'retired'))) {
        throw new TypeError('terminal stop retains an unsealed retired worker');
      }
      const intent = await readAgentStop(driver, artifacts, selected);
      const integrity = await readVerifierIntegrityCause(driver, artifacts, selected, sampleCanonicalNow());
      if (integrity && (intent.origin !== 'kernel_integrity' || intent.verifierOpId !== integrity.verifierOpId ||
          intent.integrityEvidenceRef !== integrity.integrityEvidenceRef || intent.integrityEvidenceDigest !== integrity.integrityEvidenceDigest))
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal stop requires the higher-priority retained verifier integrity intent');
      const checkpointId = stopCheckpointId(runId, run.stopIntentRef);
      const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef!);
      const items = await artifacts.mapReads(selected.items, async (row) => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
        item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) }));
      const pending = openStopBatch(items.map(({ item }) => item));
      if (frontier.kind !== run.nextStep || (pending !== undefined) !== (frontier.kind === 'tool')) throw new TypeError('stop frontier differs from its open batch');
      if (frontier.kind === 'tool') await readToolCut(driver, artifacts, runId, authority.resolveToolInput);
      const prepared: InvocationJournalEntry[] = [];
      const unknowns: InvocationJournalEntry[] = [];
      const rollback = workerRecovery?.rollback;
      const noRelease = await validateInstalledModelNoReleaseHistory(driver, artifacts, selected);
      const verifierStops = await validateVerifierStoppedHistory(driver, artifacts, selected);
      const unclaimedPublications = !publication && spec.operation === 'delivery' &&
        selected.journal.some(entry => entry.opKind === 'publish') &&
        !selected.journal.some(entry => entry.opKind === 'publish' && entry.phase === 'dispatch_claimed')
        ? await readUnclaimedPublicationStopHistory(driver, artifacts, selected) : new Set<number>();
      for (const { entry, hasClaim } of stopInvocationHistory(selected.journal).values()) {
        if (entry.opKind === 'publish') {
          if (!publication?.closedJournalSeqs.has(entry.seq) && !unclaimedPublications.has(entry.seq))
            throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal stop awaits exact publication retirement and projection closure');
          continue;
        }
        if (rollback && entry.opKind === 'tool' && entry.phase === 'unknown' && entry.seq === rollback.unknown.seq) continue;
        if (installedRuntime && entry.opKind === 'model' && entry.replayClass === 'retry' && entry.phase === 'unknown') {
          unknowns.push(entry);
          continue;
        }
        if (!['model', 'tool', 'verifier'].includes(entry.opKind) || (!['prepared', 'completed'].includes(entry.phase) &&
            (entry.phase !== 'failed' || hasClaim && !(entry.opKind === 'model' && noRelease.has(entry.seq) ||
              entry.opKind === 'verifier' && verifierStops.has(entry.seq)))))
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal stop awaits exact dispatch/reconciliation closure');
        if (entry.phase === 'prepared') prepared.push(entry);
      }
      // This installed closure path is worker-free. An unresolved model
      // must not begin sealing a live worker before its dispatch is closed.
      if (unknowns.length && run.activeWorkerLaunchId) {
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal stop awaits exact dispatch/reconciliation closure');
      }
      if (pending && pending.batch.calls.slice(pending.next).some((call) => selected.journal.some((entry) =>
          entry.opId === toolOperationId(runId, pending.batch.itemId, call.callId) && entry.phase === 'dispatch_claimed' &&
          !(rollback && entry.seq === rollback.claim.seq)))) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'an already dispatched call needs its real result');
      if (rollback && (!pending || rollback.request.batchItemId !== pending.batch.itemId || rollback.request.callIndex !== pending.next ||
          rollback.request.callId !== pending.batch.calls[pending.next]?.callId))
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'private rollback is not the current ordered stopped call');
      let seal: Awaited<ReturnType<typeof prepareToolCheckpoint>> | undefined;
      if (publication) {
        seal = publication.seal;
        if (!!run.activeWorkerLaunchId !== !!seal) throw new TypeError('owned publication stop lost its original M seal or worker-free proof');
      } else if (run.activeWorkerLaunchId) {
        if (!input.checkpoint || !exactKeys(input.checkpoint, ['workspaceStateRef', 'snapshotEvidenceRef', 'retirementEvidenceRef']) ||
            input.checkpoint.workspaceStateRef !== checkpoint.workspaceStateRef) throw new TypeError('stop requires positive retirement over the current accounted workspace');
        seal = await prepareToolCheckpoint(driver, artifacts, owner, { run, spec, assembly, checkpointId,
          observedAt: intent.createdAt, postEffect: input.checkpoint }, reobserve);
      } else if (input.checkpoint !== undefined) throw new TypeError('worker-free stop cannot substitute a workspace proof');
      return withInstalledBrokerTerminalClosure(driver, artifacts, owner, installedRuntime, selected, async (brokerClosure) => {
        // The owning plan proves every exact model/retry unknown, never a
        // generic unknown phase or an already dispatched tool cancellation.
        const abandoned = brokerClosure.abandonedRetryInvocations;
        if (abandoned.length !== unknowns.length || unknowns.some(entry => abandoned.filter(closed =>
          closed.opId === entry.opId && closed.attempt === entry.attempt && closed.unknownJournalSeq === entry.seq &&
          closed.budgetSettlementRef === entry.budgetSettlementRef).length !== 1)) {
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal stop awaits exact dispatch/reconciliation closure');
        }
        for (let retry = 0; retry < 8; retry++) {
          const now = sampleCanonicalNow();
          if (publication && now < publication.observedAt)
            throw new KernelStorageError('RECOVERY_REQUIRED', 'publication terminal preparation predates its actual root projection');
          const refunds: Array<{ artifact: PlannedArtifact; closure?: PlannedArtifact; entry: InvocationJournalEntry }> = [];
          let reserved = run.budgetReserved;
          for (const entry of prepared.sort((a, b) => a.seq - b.seq)) {
            const remaining = subtractBudget(reserved, entry.budgetDelta, 'stop refund');
            const settlement: BudgetSettlementV1 = { schemaVersion: 1, format: 'cliq-budget-settlement-v1', runId, opId: entry.opId,
              attempt: entry.attempt, preparedJournalSeq: entry.seq, terminalJournalSeq: selected.journal.length + (rollback ? 1 : 0) + refunds.length + 1,
              terminalPhase: 'failed', reserved: entry.budgetDelta, consumed: ZERO_BUDGET, released: entry.budgetDelta,
              budgetConsumedBefore: run.budgetConsumed, budgetConsumedAfter: run.budgetConsumed,
              budgetReservedBefore: reserved, budgetReservedAfter: remaining, settledAt: now, settlementDigest: '' };
            settlement.settlementDigest = digestOmitting(settlement, 'settlementDigest');
            const artifact = planCanonicalArtifact(settlement, settlement.format);
            const closure = entry.opKind === 'verifier' ? planCanonicalArtifact({ schemaVersion: 1,
              format: 'cliq-verifier-preparation-closure-v1', runId, opId: entry.opId, attempt: entry.attempt,
              preparedJournalSeq: entry.seq, requestRef: entry.requestRef, targetRef: entry.target, grantRef: entry.grantRef,
              disposition: 'unclaimed' }, 'cliq-verifier-preparation-closure-v1') : undefined;
            refunds.push({ artifact, ...(closure ? { closure } : {}), entry: { ...entry, phase: 'failed' as const, seq: settlement.terminalJournalSeq,
              budgetDelta: ZERO_BUDGET, errorRef: closure?.ref ?? run.stopIntentRef, budgetSettlementRef: artifact.ref, timestamp: now } });
            reserved = remaining;
          }
          if (!isZeroBudget(reserved)) throw new TypeError('stop retains an unexplained reservation');
          const rollbackResult = rollback ? planPrivateRollbackResult(rollback.request, rollback.evidence, now) : undefined;
          const nextCancelled = (pending?.next ?? 0) + (rollback ? 1 : 0);
          const cancelled = pending ? pending.batch.calls.slice(nextCancelled).map((_, index) => cancelledCall(pending.batch, nextCancelled + index, run.stopIntentRef!, now)) : [];
          const detail = planCanonicalArtifact({ ...agentStopDetail(intent, run.stopIntentRef!, now),
            abandonedRetryInvocations: abandoned,
            ...(publication ? { publicationResultItemRefs: publication.publicationResultItemRefs,
              deliveryTerminalProjectionEvidenceRef: publication.evidenceRef } : {}) }, 'cliq-terminal-detail-v1');
          const continuation = await prepareContinuationCommit(artifacts, { context: decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef)),
            existingItems: items, items: [...(rollbackResult ? [rollbackResult.item] : []), ...cancelled.map(({ item }) => item)], frontier, checkpointId, workspaceStateRef: checkpoint.workspaceStateRef,
            artifacts: [detail, ...(rollbackResult?.artifacts ?? []), ...refunds.flatMap(({ artifact, closure }) => [artifact, ...(closure ? [closure] : [])]),
              ...cancelled.flatMap(({ artifacts }) => artifacts)] });
          const session = readSession(driver, run.sessionId);
          const projection = decodeSessionProjection(await readCanonicalArtifact(artifacts, session.contextProjectionRef));
          if (projection.sessionId !== session.id || projection.contextRevision !== session.contextRevision || projection.throughItemSeq !== session.latestItemSeq) throw new TypeError('Session stop projection is not current');
          const admittedContext = decodeAdmittedContext(await readCanonicalArtifact(artifacts, spec.admittedContextRef));
          const sessionItem: SessionRunTerminalItem = { schemaVersion: 1, format: 'cliq-session-run-terminal-v1', kind: 'run_terminal',
            itemKey: `run-terminal:${runId}`, runId, operation: spec.operation, admittedSessionItemSeq: admittedContext.throughSessionItemSeq,
            status: intent.targetStatus, terminalReason: intent.reason, terminalDetailRef: detail.ref };
          const terminalArtifact = await artifacts.publishCanonical(sessionItem, sessionItem.format);
          const itemId = identityHash('cliq-session-run-terminal-item-v1', session.id, runId), seq = session.latestItemSeq + 1;
          projection.contextRevision++;
          projection.throughItemSeq = seq;
          projection.segments.push({ kind: 'raw', fromItemSeq: seq, throughItemSeq: seq,
            items: [{ sourceSessionId: session.id, itemSeq: seq, itemId, kind: 'run_terminal', payloadRef: terminalArtifact.ref }] });
          projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
          const projectionArtifact = await artifacts.publishCanonical(projection, projection.format);
          await seal?.refresh();
          let time: ReturnType<typeof acceptTime> | undefined, updated: Run | undefined;
          driver.transaction((connection) => {
            assertActiveStateOwner(connection, owner);
            if (canonicalSha256(readSession(connection, session.id)) !== canonicalSha256(session)) {
              if (seal && !publication) throw new KernelStorageError('REVISION_CONFLICT', 'terminal Session changed after sealed completion preparation');
              return;
            }
            brokerClosure.reobserve(connection);
            workerRecovery?.reobserve(connection);
            const committedAt = sampleCanonicalNow();
            time = acceptTime(connection, committedAt);
            if (!time.accepted) return;
            if (committedAt < now) throw new KernelStorageError('RECOVERY_REQUIRED', 'terminal transaction precedes its prepared artifacts');
            assertCut(connection, selected);
            if (abandoned.length && parseCanonicalTime(committedAt) - parseCanonicalTime(now) > 5_000) {
              throw new KernelStorageError('RECOVERY_REQUIRED', 'broker terminal closure preparation is stale; reobserve the original claim');
            }
            brokerClosure.validate(connection, run, committedAt);
            publication?.validate(connection, run, committedAt);
            workerRecovery?.validate(connection, committedAt);
            for (const artifact of workerRecovery?.metadata ?? []) insertArtifactMetadata(connection, artifact, committedAt);
            workerRecovery?.commit(connection, committedAt);
            if (rollback) resolvePrivateRollbackInvocation(connection, driver, owner, recovery!, runId, now);
            if (connection.prepare("SELECT 1 FROM worker_launches WHERE run_id = ? AND phase != 'retired' AND launch_id != ? LIMIT 1")
              .get(runId, run.activeWorkerLaunchId ?? '')) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'stop cannot retain a pending worker launch');
            for (const artifact of [...continuation.metadata, ...(seal?.metadata ?? []), ...(publication?.metadata(connection) ?? []),
              ...brokerClosure.metadata, terminalArtifact, projectionArtifact]) insertArtifactMetadata(connection, artifact, committedAt);
            publication?.validate(connection, run, committedAt);
            if (publication && canonicalSha256(readSession(connection, session.id)) !== canonicalSha256(session))
              throw new KernelStorageError('REVISION_CONFLICT', 'publication terminal Session changed during artifact registration');
            seal?.commit(connection, run, committedAt);
            publication?.commit(connection, run, committedAt);
            if (connection.prepare("SELECT 1 FROM workspace_generations WHERE run_id = ? AND phase NOT IN ('sealed','retired') LIMIT 1").get(runId)) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'stop requires every workspace generation sealed or positively retired');
            assertRetiredGenerationCut(connection, run, selected.workspaceGenerations.map(generation =>
              workerRecovery?.generation.generationRef === generation.generationRef ||
              seal && generation.generationRef === readRequiredWorkerLaunch(connection, run.activeWorkerLaunchId!).workspaceGenerationRef
                ? readRequiredWorkspaceGenerationByRef(connection, generation.generationRef) : generation));
            for (const refund of refunds) appendInvocationJournalEntry(connection, refund.entry);
            continuation.commit(connection, run, selected.journal.length + (rollback ? 1 : 0) + refunds.length, committedAt);
            connection.prepare(`UPDATE runs SET status = ?, next_step = NULL, frontier_ref = NULL, waiting_reason = NULL, waiting_on_ref = NULL,
              active_worker_launch_id = NULL, budget_reserved_json = ?, terminal_reason = ?, terminal_detail_ref = ?, revision = revision + 1, updated_at = ? WHERE id = ?`)
              .run(intent.targetStatus, JSON.stringify(ZERO_BUDGET), intent.reason, detail.ref, committedAt, runId);
            connection.prepare("INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at) VALUES (?, ?, NULL, ?, 'run_terminal', ?, ?)")
              .run(itemId, session.id, BigInt(seq), terminalArtifact.ref, committedAt);
            connection.prepare('UPDATE sessions SET latest_item_seq = ?, context_revision = context_revision + 1, context_projection_ref = ?, updated_at = ? WHERE id = ?')
              .run(BigInt(seq), projectionArtifact.ref, committedAt, session.id);
            updated = readRun(connection, runId);
            publication?.assertFresh(committedAt, connection);
            if (publicationFinalization) closeOwnedPublicationAbortFinalization(driver, owner, publicationFinalization);
            appendRunStateEvent(connection, updated, committedAt);
          });
          requireHealthyFence(time?.outcome);
          if (updated) return immutableSnapshot({ run: updated });
          if (seal && !publication) throw new KernelStorageError('RECOVERY_REQUIRED', 'terminal time cut changed after sealed completion preparation');
        }
        throw new KernelStorageError('REVISION_CONFLICT', 'terminal Session/time cut kept changing');
      });
      } finally {
        if (publicationFinalization) closeOwnedPublicationAbortFinalization(driver, owner, publicationFinalization);
      }
    })
  };
}
