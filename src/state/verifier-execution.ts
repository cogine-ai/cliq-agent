import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { identityHash } from '../kernel/identity.js';
import { toolApprovalDecision, toolApprovalRequestDigest, type ToolApprovalInput } from '../policy/tool-approval.js';
import { assertCurrentControlFrame, validateControlChannelClosure } from './control-channel.js';
import { readTimeFence } from './canonical-time.js';
import { readControlRequest, insertControlRequest } from './rows.js';
import { readVerifierApproval, readVerifierGrant, readVerifierPermissionContext, readVerifierTemplateForRun, verifierApprovalCheckpointId,
  verifierApprovalDecisionCheckpointId, verifierCandidateOrdinal, verifierDenial, verifierPolicyItem } from './verifier-permission-history.js';
import type { VerifierApprovalDecisionV1, VerifierApprovalWait, VerifierPolicyChannelEvidenceV1 as Evidence } from '../kernel/verifier-invocation.js';
import { prepareToolCheckpoint, type NativeWorkerRetirement } from './tool-checkpoint.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import type { ToolCheckpointProof } from '../kernel/tool-authorization.js';
import type { ContinuationItem, Run, RunAssemblyV1, RunFrontier, RunSpec } from '../kernel/types.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import type { VerifierOperationGrantV1, VerifierPolicyChannelEvidenceV1, VerifierPolicyDecisionItem } from '../kernel/verifier-invocation.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual, type ReleaseTrustKey } from '../policy/runtime-authority.js';
import { releaseLinuxInvocation } from '../sandbox/linux-worker.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { sampleCanonicalNow, advanceTimeFence, type TimeFenceAdvance } from './canonical-time.js';
import { decodeContextManifest, decodeWorkspaceIdentity } from './decoders.js';
import { KernelStorageError, stateOperation } from './errors.js';
import { readVerifierLaunchClosure } from './execution-closure.js';
import { prepareContinuationCommit } from './continuation-commit.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readHighestPreparedAttempt, readInvocationAttempt, readInvocationJournal } from './repositories/journal.js';
import { readCheckpoint, readRun, readSession, readSessionPrincipalId, ZERO_BUDGET } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { assertDeliveryModelFreeCut } from './run-model-free.js';
import { decodeVerifierCommand, decodeVerifierEnvironment } from './verifier-artifacts.js';
import { loadVerifierPolicy, planVerifierRequest } from './verifier-policy.js';
import { readVerifierProgress, verifierCheckpointId } from './verifier-recovery.js';
import { readDeliveryVerificationMode } from './run-result-recovery.js';
import { appendRunStateEvent, assertLiveDispatchState, claimValidatedInvocation, prepareValidatedInvocation, requireHealthyFence, settleValidatedInvocation,
  type ClaimInvocationDispatchInput } from './reducers/invocation.js';

const VERIFIER_BUDGET = Object.freeze({ modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 });

/** An authority-reducing routing invariant, not local execution permission.
 * Its live caller obtains the mode from the complete original source graph. */
export function assertLocalDeliveryVerifierSelection(mode: { kind: 'local' | 'inherited' }): void {
  if (mode?.kind !== 'local')
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'identical delivery must inherit its original verification and cannot dispatch a local verifier');
}

/** The verifier is an ordinary Journal-owned productive invocation, not a
 * second runner. Every selection and policy decision is reproduced from State. */
export async function loadVerifierContinuation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  authority: { run: Run; spec: RunSpec; assembly: RunAssemblyV1; releaseKeys?: readonly ReleaseTrustKey[] }, reobserve?: NativeWorkerRetirement) {
  const { run: admitted, spec, assembly } = authority, runId = admitted.id;
  async function cut(expected?: number, signal?: AbortSignal) {
    const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
    signal?.throwIfAborted();
    assertActiveStateOwner(driver, owner);
    if (!authority.releaseKeys) throw new KernelStorageError('RECOVERY_REQUIRED', 'verifier authority requires retained trusted release roots');
    const selected = await readRecoveryClosure(driver, reads, runId), { run } = selected;
    if (spec.operation === 'delivery') {
      assertDeliveryModelFreeCut(selected);
      // Scheduler routing is not a release gate. Preparation and permanent
      // claim both re-enter this cut, before reserving or releasing anything.
      assertLocalDeliveryVerifierSelection(await readDeliveryVerificationMode(driver, reads, selected));
    }
    if (run.specRef !== admitted.specRef || run.createdAt !== admitted.createdAt || run.deadlineAt !== admitted.deadlineAt)
      throw new TypeError('verifier authority no longer belongs to its original Run');
    if (expected !== undefined && run.revision !== expected) throw new KernelStorageError('REVISION_CONFLICT', 'verifier revision changed');
    if (run.nextStep !== 'verify' || !run.frontierRef)
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'verifier requires its root Run frontier');
    const frontier = await readCanonicalArtifact<RunFrontier>(reads, run.frontierRef);
    const progress = await readVerifierProgress(driver, reads, selected);
    if (frontier.kind !== 'verify' || frontier.phase !== 'verifiers' ||
        frontier.afterPass !== (spec.operation === 'agent' ? 'finalize' : 'delivery_approval') ||
        frontier.nextVerifierIndex !== progress.nextVerifierIndex || frontier.verifierPlanRef !== progress.planRef || progress.complete)
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'verifier has no current frozen pending entry');
    if (progress.entries.slice(0, frontier.nextVerifierIndex).some(entry => !entry.disposition))
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'a prior required failure must repair or stop before another verifier');
    if (spec.dependencyPolicyRef && (!progress.dependency?.ready || progress.dependency.ready.createdAt >= run.deadlineAt))
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'verifier requires its original complete dependency ready cut');
    const entry = progress.spec.verifiers[frontier.nextVerifierIndex]!;
    const command = decodeVerifierCommand(await readCanonicalArtifact(reads, entry.commandRef));
    const environment = decodeVerifierEnvironment(await readCanonicalArtifact(reads, entry.environmentRef));
    const context = { runId, frontierRef: run.frontierRef, assemblyRef: spec.assemblyRef,
      candidateItemId: progress.candidate.itemId, resultSourceRef: progress.candidate.resultSourceRef, sourceDigest: progress.candidate.sourceDigest,
      verifierPlanRef: progress.planRef, plan: progress.plan, verifierSpecRef: spec.verifierSpecRef, verifierSpec: progress.spec,
      verifierIndex: frontier.nextVerifierIndex, command, environment };
    const { request, target } = planVerifierRequest(context);
    const session = readSession(driver, run.sessionId), principalId = readSessionPrincipalId(driver, run.sessionId);
    const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(reads, session.workspaceIdentityRef));
    const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(reads, spec.policyRef);
    const evaluator = loadVerifierPolicy({ policy, policyRef: spec.policyRef, assembly, assemblyRef: spec.assemblyRef,
      principalId, workspaceIdentityDigest: workspace.identityDigest, context });
    signal?.throwIfAborted();
    return { ...selected, frontier, progress, entry, request, target, evaluator, principalId };
  }
  type Cut = Awaited<ReturnType<typeof cut>>;
  const itemIdentities = (connection: SqliteConnection) => connection.prepare(
    'SELECT item_id, item_seq, payload_ref, created_at FROM items WHERE run_id = ? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: bigint; payload_ref: string; created_at: string }>(runId)
    .map(row => ({ itemId: row.item_id, itemSeq: Number(row.item_seq), payloadRef: row.payload_ref, createdAt: row.created_at }));
  function assertCut(connection: SqliteConnection, selected: Cut, current: Run) {
    if (canonicalSha256(current) !== canonicalSha256(selected.run) ||
        canonicalSha256(readCheckpoint(connection, current.latestCheckpointId)) !== canonicalSha256(selected.latestCheckpoint) ||
        canonicalSha256(readInvocationJournal(connection, runId)) !== canonicalSha256(selected.journal) ||
        canonicalSha256(itemIdentities(connection)) !== canonicalSha256(selected.items.map(({ itemId, itemSeq, payloadRef, createdAt }) =>
          ({ itemId, itemSeq, payloadRef, createdAt }))))
      throw new KernelStorageError('REVISION_CONFLICT', 'verifier original frontier, context or Journal cut changed');
  }
  const permissionContext = (selected: Cut) => ({ run: selected.run, spec, request: selected.request, target: selected.target, evaluator: selected.evaluator });
  function eligibleAttempt(selected: Cut) {
    const operation = selected.journal.filter(row => row.opId === selected.request.opId);
    const prior = operation.filter(row => row.phase === 'prepared').at(-1);
    const previous = prior && operation.filter(row => row.attempt === prior.attempt), last = previous?.at(-1);
    const priorProgress = selected.progress.entries[selected.frontier.nextVerifierIndex]!;
    const unclaimedFailure = last?.phase === 'failed' && previous?.every(entry => entry.phase !== 'dispatch_claimed');
    if (prior && !unclaimedFailure && !(last?.phase === 'completed' && priorProgress.receipt?.outcome === 'infra_failed'))
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'verifier attempt is already prepared, claimed or not retryable');
    const uses = operation.filter(row => row.phase === 'dispatch_claimed').length;
    if (uses >= selected.target.maxAttempts) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'verifier frozen attempt count is exhausted');
    return { prior, previous, priorProgress, uses };
  }
  async function grantFor(selected: Cut, grantRef: string, reads = artifacts) {
    const { grant, evidence } = await readVerifierGrant(driver, reads, permissionContext(selected), grantRef, selected.items);
    if (grant.issuedAt < selected.progress.candidate.createdAt || grant.expiresAt > admitted.deadlineAt)
      throw new KernelStorageError('LEASE_FENCED', 'verifier grant exceeds its exact candidate lifetime');
    return { grant, evidence };
  }
  async function chooseGrant(selected: Cut, at: string, reads = artifacts) {
    const context = permissionContext(selected), evaluated = selected.evaluator.evaluate(selected.request, selected.target, at);
    if (evaluated.effectiveDisposition === 'deny') return { evidence: evaluated, grant: undefined };
    const policyItems = await reads.mapReads(selected.items, row => readCanonicalArtifact<ContinuationItem>(reads, row.payloadRef));
    const approved = policyItems.filter((item): item is Extract<ContinuationItem, { kind: 'policy_decision'; subjectKind: 'verifier_launch' }> =>
      item.kind === 'policy_decision' && item.subjectKind === 'verifier_launch' && item.opId === selected.request.opId && item.decisionSource === 'interactive_approval');
    const latest = approved.at(-1);
    if (latest?.decision === 'allow') {
      const original = await grantFor(selected, latest.grantRef, reads);
      if (at < original.grant.expiresAt) return original;
    }
    const prior = readHighestPreparedAttempt(driver, runId, selected.request.opId);
    if (prior?.grantRef) {
      const original = await grantFor(selected, prior.grantRef, reads);
      if (at < original.grant.expiresAt) return original;
    }
    if (evaluated.effectiveDisposition === 'allow') return { evidence: evaluated,
      grant: selected.evaluator.grant(selected.request, selected.target, evaluated, at, selected.run.deadlineAt) };
    const template = await readVerifierTemplateForRun(driver, reads, selected.run, spec, selected.target.verifierIndex);
    if (template && at < template.expiresAt) return { evidence: evaluated, grant: selected.evaluator.templateGrant(selected.request,
      selected.target, evaluated, template, await verifierCandidateOrdinal(reads, selected.items, selected.target.candidateItemId), at) };
    return { evidence: evaluated, grant: undefined };
  }
  const selectionCheckpointId = (selected: Cut) => identityHash('cliq-verifier-selection-checkpoint-v1', runId, selected.run.frontierRef!, String(selected.run.revision));
  async function graph(selected: Cut, items: ContinuationItem[], frontier: RunFrontier, checkpointId: string,
    additional: Parameters<typeof prepareContinuationCommit>[1]['artifacts'], reads = artifacts) {
    return prepareContinuationCommit(reads, { context: decodeContextManifest(await readCanonicalArtifact(reads, selected.latestCheckpoint.contextManifestRef)),
      existingItems: await reads.mapReads(selected.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
        item: await readCanonicalArtifact<ContinuationItem>(reads, row.payloadRef) })), items, frontier, checkpointId,
      workspaceStateRef: selected.latestCheckpoint.workspaceStateRef, artifacts: additional });
  }
  function accept(connection: SqliteConnection, selected: Cut, at: string) {
    assertActiveStateOwner(connection, owner); assertCut(connection, selected, readRun(connection, runId));
    const now = sampleCanonicalNow(), fence = readTimeFence(connection);
    if (!fence) throw new KernelStorageError('RECOVERY_REQUIRED', 'verifier control time fence is missing');
    if (now < at || now < fence.lastAcceptedAt) return advanceTimeFence(connection, owner.ownerEpoch, now);
    if (at < fence.lastAcceptedAt) return undefined;
    if (now >= selected.run.deadlineAt || at >= selected.run.deadlineAt || selected.run.cancelRequested || selected.run.stopIntentRef)
      throw new KernelStorageError('LEASE_FENCED', 'verifier permission is stopped or expired');
    return advanceTimeFence(connection, owner.ownerEpoch, at);
  }
  return Object.freeze({
    prepareVerifierPermission: stateOperation('RECOVERY_REQUIRED', async (input: { expectedRunRevision: number }, signal?: AbortSignal) => {
      const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('verifier permission needs its exact revision');
      const selected = await cut(input.expectedRunRevision, signal);
      eligibleAttempt(selected);
      for (let retry = 0; retry < 8; retry++) {
        signal?.throwIfAborted(); const at = sampleCanonicalNow(), choice = await chooseGrant(selected, at, reads);
        if (choice.grant) return { disposition: 'authorized' as const, run: selected.run };
        if (selected.run.activeWorkerLaunchId) return { disposition: 'retirement_required' as const, run: selected.run, checkpointId: selectionCheckpointId(selected) };
        if (selected.run.status !== 'queued') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'verifier selection must be worker-free queued');
        if (choice.evidence.effectiveDisposition === 'deny' && selected.target.required)
          return { disposition: 'policy_denied' as const, run: selected.run };
        const { evidence } = choice, context = permissionContext(selected);
        const plans = [planCanonicalArtifact(selected.request, selected.request.format), planCanonicalArtifact(selected.target, selected.target.format),
          planCanonicalArtifact(evidence, evidence.format)];
        const wait = evidence.effectiveDisposition === 'ask' ? selected.evaluator.approvalWait(selected.request, selected.target, evidence, selected.run.revision) : undefined;
        const denied = wait ? undefined : verifierDenial(context, evidence, canonicalSha256(evidence), at);
        const items: ContinuationItem[] = wait ? [] : [verifierPolicyItem(context, evidence, canonicalSha256(evidence), at), denied!.skip!];
        if (wait) plans.push(planCanonicalArtifact(wait, 'cliq-waiting-subject-v1'));
        const frontier = wait ? selected.frontier : { ...selected.frontier, nextVerifierIndex: selected.frontier.nextVerifierIndex + 1 };
        const planned = await graph(selected, items, frontier, wait ? verifierApprovalCheckpointId(canonicalSha256(wait))
          : identityHash('cliq-verifier-skip-checkpoint-v1', runId, selected.request.opId, canonicalSha256(evidence)), plans, reads);
        let outcome: TimeFenceAdvance | undefined, updated: Run | undefined;
        driver.transaction(connection => {
          signal?.throwIfAborted(); outcome = accept(connection, selected, at); if (outcome !== 'healthy') return;
          for (const artifact of planned.metadata) insertArtifactMetadata(connection, artifact, at);
          planned.commit(connection, selected.run, selected.journal.length, at);
          connection.prepare('UPDATE runs SET status=?,waiting_reason=?,waiting_on_ref=?,revision=revision+1,updated_at=? WHERE id=?')
            .run(wait ? 'waiting' : 'queued', wait ? 'approval' : null, wait ? canonicalSha256(wait) : null, at, runId);
          updated = readRun(connection, runId); appendRunStateEvent(connection, updated, at);
        });
        requireHealthyFence(outcome);
        if (updated) return { disposition: wait ? 'waiting' as const : 'skipped' as const, run: updated };
      }
      throw new KernelStorageError('REVISION_CONFLICT', 'verifier permission original control cut kept changing');
    }),
    retireVerifierSelection: stateOperation('RECOVERY_REQUIRED', async (input: { expectedRunRevision: number; checkpointId: string; checkpoint: ToolCheckpointProof }) => {
      if (!exactKeys(input, ['expectedRunRevision', 'checkpointId', 'checkpoint']) ||
          !exactKeys(input.checkpoint, ['workspaceStateRef', 'snapshotEvidenceRef', 'retirementEvidenceRef'])) throw new TypeError('unknown verifier retirement fields');
      const selected = await cut(input.expectedRunRevision);
      if (!selected.run.activeWorkerLaunchId || input.checkpointId !== selectionCheckpointId(selected) ||
          input.checkpoint.workspaceStateRef !== selected.latestCheckpoint.workspaceStateRef)
        throw new TypeError('verifier selection retirement changed its original ready source');
      const original = readWorkerLaunchesForRun(driver, runId).find(row => row.launchId === selected.run.activeWorkerLaunchId);
      if (!original?.activatedAt) throw new TypeError('verifier retirement lost its original activation');
      const seal = await prepareToolCheckpoint(driver, artifacts, owner, { run: selected.run, spec, assembly,
        checkpointId: input.checkpointId, observedAt: original.activatedAt, postEffect: input.checkpoint }, reobserve);
      const planned = await graph(selected, [], selected.frontier, input.checkpointId, []);
      await seal.refresh(); let outcome: TimeFenceAdvance | undefined;
      driver.transaction(connection => {
        assertActiveStateOwner(connection, owner); const at = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, at);
        if (outcome !== 'healthy') return;
        assertCut(connection, selected, readRun(connection, runId));
        for (const artifact of [...seal.metadata, ...planned.metadata]) insertArtifactMetadata(connection, artifact, at);
        seal.commit(connection, selected.run, at); planned.commit(connection, selected.run, selected.journal.length, at);
        connection.prepare('UPDATE runs SET revision=revision+1,updated_at=? WHERE id=?').run(at, runId); appendRunStateEvent(connection, readRun(connection, runId), at);
      });
      requireHealthyFence(outcome); return { run: readRun(driver, runId) };
    }),
    approveVerifier: stateOperation('INVALID_REQUEST', async (input: ToolApprovalInput, signal?: AbortSignal) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['principalId', 'channelIdentityRef', 'channelIdentityDigest', 'requestId', 'expectedRunRevision',
        'waitingOnRef', 'decision', ...(input.ttlMs === undefined ? [] : ['ttlMs'])])) throw new TypeError('unknown verifier approval field');
      const requestDigest = toolApprovalRequestDigest(runId, input);
      const channel = await validateControlChannelClosure(artifacts, owner, input);
      const replay = async () => {
        const row = readControlRequest(driver, input.principalId, 'run.approve', input.requestId); if (!row) return undefined;
        if (row.requestDigest !== requestDigest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'verifier approval requestId was reused');
        const response = await readCanonicalArtifact<{ result: { decisionRef: string } }>(artifacts, row.responseRef);
        const decision = await readCanonicalArtifact<VerifierApprovalDecisionV1>(artifacts, response.result.decisionRef);
        const evidence = await readCanonicalArtifact<Evidence>(artifacts, decision.subject.policyChannelEvidenceRef);
        const context = await readVerifierPermissionContext(driver, artifacts, readRun(driver, runId), spec, evidence.requestRef, evidence.targetRef);
        const original = await readVerifierApproval(driver, artifacts, context, response.result.decisionRef);
        requireEqual(original.control, row, 'verifier approval original replay control');
        return { replayed: true, run: original.response.result.snapshot.run, response: original.response };
      };
      const prior = await replay(); if (prior) return prior;
      const selected = await cut(input.expectedRunRevision, signal), context = permissionContext(selected);
      if (input.principalId !== selected.principalId || selected.run.status !== 'waiting' || selected.run.waitingReason !== 'approval' ||
          selected.run.waitingOnRef !== input.waitingOnRef || selected.run.activeWorkerLaunchId)
        throw new KernelStorageError('INVALID_REQUEST', 'verifier approval needs its exact worker-free wait');
      const proof = await (await import('./verifier-permission-history.js')).readVerifierApprovalWait(driver, artifacts, context, input.waitingOnRef);
      for (let retry = 0; retry < 8; retry++) {
        signal?.throwIfAborted(); const at = sampleCanonicalNow(), decision = toolApprovalDecision(proof.wait, input, at, selected.run.deadlineAt);
        const grant = selected.evaluator.approve(selected.request, selected.target, proof.evidence, proof.wait, decision, selected.run.deadlineAt);
        const decisionRef = canonicalSha256(decision), denied = grant ? undefined : verifierDenial(context, proof.evidence, decisionRef, at, decision);
        const item = verifierPolicyItem(context, proof.evidence, decisionRef, at, grant, decision);
        const frontier = denied?.skip ? { ...selected.frontier, nextVerifierIndex: selected.frontier.nextVerifierIndex + 1 } : selected.frontier;
        const planned = await graph(selected, [item, ...(denied?.skip ? [denied.skip] : [])], frontier,
          verifierApprovalDecisionCheckpointId(decisionRef), [planCanonicalArtifact(decision, decision.format),
            ...(grant ? [planCanonicalArtifact(grant, grant.format)] : []), ...(denied?.stop ? [planCanonicalArtifact(denied.stop, 'cliq-stop-intent-v1')] : [])]);
        const { waitingOnRef: _wait, waitingReason: _reason, ...current } = selected.run;
        const next: Run = { ...current, ...planned.runUpdate, revision: current.revision + 1, status: 'queued', updatedAt: at,
          ...(denied?.stop ? { stopIntentRef: canonicalSha256(denied.stop), cancelRequested: true } : {}) };
        const response = { protocolVersion: 1 as const, ok: true as const, result: { method: 'run.approve' as const, decisionRef,
          snapshot: { schemaVersion: 1 as const, operation: spec.operation, run: next, latestRunItemSeq: planned.throughItemSeq } } };
        const { requestDigest: _digest, ...requestCore } = { protocolVersion: 1 as const, method: 'run.approve' as const,
          requestId: input.requestId, requestDigest, runId, expectedRevision: input.expectedRunRevision, waitingOnRef: input.waitingOnRef,
          decision: input.decision, ...(input.ttlMs === undefined ? {} : { ttlMs: input.ttlMs }) };
        const requestArtifact = await artifacts.publishCanonical(requestCore, 'cliq-run-approve-request-v1');
        const published = await artifacts.publishCanonical(response, 'cliq-control-response-v1');
        let outcome: TimeFenceAdvance | undefined, committed = false;
        driver.transaction(connection => {
          signal?.throwIfAborted(); if (channel.channel.transport.kind === 'uds_peer') assertCurrentControlFrame(owner, input);
          if (readControlRequest(connection, input.principalId, 'run.approve', input.requestId)) return;
          outcome = accept(connection, selected, at); if (outcome !== 'healthy') return;
          for (const artifact of [...channel.metadata, ...planned.metadata, requestArtifact, published]) insertArtifactMetadata(connection, artifact, at);
          planned.commit(connection, selected.run, selected.journal.length, at);
          connection.prepare("UPDATE runs SET status='queued',waiting_reason=NULL,waiting_on_ref=NULL,stop_intent_ref=?,cancel_requested=?,revision=revision+1,updated_at=? WHERE id=?")
            .run(denied?.stop ? canonicalSha256(denied.stop) : null, denied?.stop ? 1n : 0n, at, runId);
          requireEqual(readRun(connection, runId), next, 'verifier exact committed approval'); appendRunStateEvent(connection, next, at);
          insertControlRequest(connection, { ...input, method: 'run.approve', requestDigest, responseRef: published.ref, committedAt: at }); committed = true;
        });
        requireHealthyFence(outcome); if (committed) return { replayed: false, run: next, response };
        const raced = await replay(); if (raced) return raced;
      }
      throw new KernelStorageError('REVISION_CONFLICT', 'verifier approval original control cut kept changing');
    }),
    prepareVerifier: stateOperation('RECOVERY_REQUIRED', async (input: { expectedRunRevision: number; leaseEpoch: number }, readSignal?: AbortSignal) => {
      const reads = readSignal ? artifacts.withReadSignal(readSignal) : artifacts;
      reads.assertReadActive();
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision', 'leaseEpoch'])) throw new TypeError('unknown verifier preparation fields');
      const selected = await cut(input.expectedRunRevision, readSignal);
      assertLiveDispatchState(driver, owner, runId, input.expectedRunRevision, input.leaseEpoch, sampleCanonicalNow());
      const { prior, previous, priorProgress, uses } = eligibleAttempt(selected);
      const now = sampleCanonicalNow(), choice = await chooseGrant(selected, now, reads), { evidence, grant } = choice;
      if (!grant) return immutableSnapshot({ disposition: 'permission_required' as const, run: selected.run });
      const requestPlan = planCanonicalArtifact(selected.request, selected.request.format), targetPlan = planCanonicalArtifact(selected.target, selected.target.format);
      const grantPlan = planCanonicalArtifact(grant, grant.format), evidencePlan = planCanonicalArtifact(evidence, evidence.format);
      const decision = grant.provenance.kind === 'policy_snapshot' ? verifierPolicyItem(permissionContext(selected), evidence,
        evidencePlan.ref, evidence.evaluatedAt, grant) : undefined;
      const context = decodeContextManifest(await readCanonicalArtifact(reads, selected.latestCheckpoint.contextManifestRef));
      const existingItems = await reads.mapReads(selected.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
        item: await readCanonicalArtifact<ContinuationItem>(reads, row.payloadRef) }));
      const graph = await prepareContinuationCommit(reads, { context, existingItems,
        items: decision && !selected.items.some(row => row.itemId === decision.itemId) ? [decision] : [], frontier: selected.frontier,
        checkpointId: identityHash('cliq-verifier-admission-checkpoint-v1', runId, selected.request.opId, String(prior ? prior.attempt + 1 : 0)),
        workspaceStateRef: selected.latestCheckpoint.workspaceStateRef, artifacts: [requestPlan, targetPlan, grantPlan, evidencePlan] });
      const prepared = await prepareValidatedInvocation(driver, reads, owner, { runId, expectedRunRevision: selected.run.revision,
        leaseEpoch: input.leaseEpoch, opId: selected.request.opId, opKind: 'verifier', target: selected.request.targetRef,
        requestRef: requestPlan.ref, grantRef: grantPlan.ref, replayClass: 'retry', reservation: VERIFIER_BUDGET }, {
        metadata: graph.metadata,
        validate(connection, run, attempt, at) {
          assertCut(connection, selected, run);
          if (attempt !== (prior ? prior.attempt + 1 : 0) || at < grant.issuedAt || at >= grant.expiresAt)
            throw new KernelStorageError('LEASE_FENCED', 'verifier grant or attempt identity is stale');
        },
        retryCompletedVerifier(connection, entries) {
          requireEqual(entries, previous, 'verifier retry original completed attempt');
          if (priorProgress.receipt?.outcome !== 'infra_failed' || priorProgress.terminalJournal?.seq !== entries.at(-1)?.seq ||
              entries.at(-1)?.phase !== 'completed' || uses >= selected.target.maxAttempts)
            throw new KernelStorageError('STATE_TRANSITION_INVALID', 'verifier retry lacks its original death-proved infrastructure receipt');
          // assertCut in the same transaction binds all immutable reads above.
          requireEqual(readInvocationJournal(connection, runId), selected.journal, 'verifier retry Journal');
        },
        commit(connection, run, entry) { graph.commit(connection, run, entry.seq, entry.timestamp); }
      });
      return immutableSnapshot({ disposition: 'prepared' as const, ...prepared, request: selected.request, target: selected.target,
        checkpointId: verifierCheckpointId(runId, prepared.entry.opId, prepared.entry.attempt) });
    }),
    failVerifierPreparation: stateOperation('RECOVERY_REQUIRED', async (input: { expectedRunRevision: number; opId: string; attempt: number }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision', 'opId', 'attempt'])) throw new TypeError('unknown verifier preparation closure fields');
      const selected = await cut(input.expectedRunRevision), entries = readInvocationAttempt(driver, runId, input.opId, input.attempt);
      const prepared = entries[0];
      if (entries.length !== 1 || prepared?.phase !== 'prepared' || prepared.opKind !== 'verifier' ||
          prepared.opId !== selected.request.opId || prepared.requestRef !== canonicalSha256(selected.request) ||
          readHighestPreparedAttempt(driver, runId, prepared.opId)?.attempt !== prepared.attempt)
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'only the exact unclaimed verifier preparation may be withdrawn');
      const closure = await artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-verifier-preparation-closure-v1',
        runId, opId: prepared.opId, attempt: prepared.attempt, preparedJournalSeq: prepared.seq,
        requestRef: prepared.requestRef, targetRef: prepared.target, grantRef: prepared.grantRef, disposition: 'unclaimed' },
      'cliq-verifier-preparation-closure-v1');
      return settleValidatedInvocation(driver, artifacts, owner, { runId, ...input },
        { phase: 'failed', errorRef: closure.ref, consumed: ZERO_BUDGET, requireClaim: false }, async () => ({
          metadata: [closure], validate(connection, run) { assertCut(connection, selected, run); }
        }));
    }),
    claimVerifier: stateOperation('RECOVERY_REQUIRED', async (input: Omit<ClaimInvocationDispatchInput, 'runId'>, signal?: AbortSignal) => {
      const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
      input = immutableSnapshot(input);
      const selected = await cut(input.expectedRunRevision, signal), prepared = readHighestPreparedAttempt(driver, runId, input.opId);
      if (!prepared?.grantRef || prepared.opKind !== 'verifier' || prepared.attempt !== input.attempt || input.opId !== selected.request.opId ||
          prepared.requestRef !== canonicalSha256(selected.request) || !input.sandboxLaunchSpecRef || input.brokerFenceTokenDigest !== undefined)
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'verifier claim does not select its exact prepared launch');
      const proof = await grantFor(selected, prepared.grantRef, reads);
      const live = assertLiveDispatchState(driver, owner, runId, input.expectedRunRevision, input.leaseEpoch, sampleCanonicalNow());
      const closure = await readVerifierLaunchClosure(reads, assertActiveStateOwner(driver, owner), { ...live, prepared,
        request: selected.request, target: selected.target, ...proof, dispatchId: input.dispatchId,
        sandboxLaunchSpecRef: input.sandboxLaunchSpecRef }, authority.releaseKeys!, signal, driver);
      const planMetadata = await reads.describe(closure.spec.containmentPlanRef, 'application/json', 'cliq-process-containment-plan-v1');
      const uses = (connection: SqliteConnection) => readInvocationJournal(connection, runId)
        .filter(row => row.opId === input.opId && row.phase === 'dispatch_claimed').length;
      signal?.throwIfAborted();
      const claimed = await claimValidatedInvocation(driver, reads, owner, { ...input, runId }, (connection, run, current, now) => {
        assertCut(connection, selected, run); requireEqual(current, prepared, 'claimed verifier preparation');
        const actual = assertLiveDispatchState(connection, owner, runId, input.expectedRunRevision, input.leaseEpoch, now);
        requireEqual(actual.launch, live.launch, 'claimed verifier original parent'); requireEqual(actual.generation, live.generation, 'claimed verifier generation');
        if (now < proof.grant.issuedAt || now >= proof.grant.expiresAt || uses(connection) >= proof.grant.maxDispatchedAttempts)
          throw new KernelStorageError('LEASE_FENCED', 'verifier grant is expired or exhausted');
        insertArtifactMetadata(connection, planMetadata, now);
      });
      let consumed = false;
      return Object.freeze({ entry: immutableSnapshot(claimed), request: selected.request, target: selected.target, evidence: proof.evidence,
        release: stateOperation('RECOVERY_REQUIRED', async (target: unknown) => {
          if (consumed) throw new KernelStorageError('LEASE_FENCED', 'verifier release was already consumed');
          consumed = true;
          const released = await cut(input.expectedRunRevision, signal), currentProof = await grantFor(released, prepared.grantRef!);
          const active = assertLiveDispatchState(driver, owner, runId, input.expectedRunRevision, input.leaseEpoch, sampleCanonicalNow());
          const checked = await readVerifierLaunchClosure(artifacts, assertActiveStateOwner(driver, owner), { ...active, prepared,
            request: released.request, target: released.target, ...currentProof, dispatchId: input.dispatchId,
            sandboxLaunchSpecRef: input.sandboxLaunchSpecRef! }, authority.releaseKeys!, signal, driver);
          signal?.throwIfAborted();
          let outcome: TimeFenceAdvance | undefined;
          driver.transaction(connection => {
            assertActiveStateOwner(connection, owner); const now = sampleCanonicalNow();
            outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
            const actual = assertLiveDispatchState(connection, owner, runId, input.expectedRunRevision, input.leaseEpoch, now);
            assertCut(connection, released, actual.run); requireEqual(actual.launch, checked.launch, 'released verifier parent');
            requireEqual(actual.generation, active.generation, 'released verifier generation');
            const attempt = readInvocationAttempt(connection, runId, input.opId, input.attempt);
            if (attempt.length !== 2 || attempt[0]?.phase !== 'prepared' || attempt[1]?.phase !== 'dispatch_claimed')
              throw new KernelStorageError('STATE_TRANSITION_INVALID', 'verifier release requires its exact unsettled permanent claim');
            requireEqual(attempt[0], prepared, 'released verifier preparation'); requireEqual(attempt[1], claimed, 'released verifier claim');
            if (claimed.supervisorInstanceId !== owner.supervisorInstanceId || claimed.stateOwnerEpoch !== owner.ownerEpoch ||
                now < currentProof.grant.issuedAt || now >= currentProof.grant.expiresAt || uses(connection) > currentProof.grant.maxDispatchedAttempts)
              throw new KernelStorageError('LEASE_FENCED', 'verifier release lost its exact original owner or grant');
          });
          requireHealthyFence(outcome);
          // This irreversible original capability is released synchronously
          // after the committed second gate, with no intervening await.
          releaseLinuxInvocation(target, { runId, leaseEpoch: claimed.leaseEpoch, workerLaunchId: checked.launch.launchId,
            opId: claimed.opId, attempt: claimed.attempt, dispatchId: claimed.dispatchId!, requestRef: claimed.requestRef,
            requestDigest: selected.request.requestDigest, targetRef: claimed.target, targetDigest: selected.target.targetDigest,
            operationGrantRef: claimed.grantRef!, parentWorkerContainmentRef: checked.spec.parentWorkerContainmentRef,
            sandboxLaunchSpecRef: claimed.sandboxLaunchSpecRef! });
        }) });
    })
  });
}
