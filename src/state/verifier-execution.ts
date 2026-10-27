import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { identityHash } from '../kernel/identity.js';
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
import { assertLiveDispatchState, claimValidatedInvocation, prepareValidatedInvocation, requireHealthyFence, settleValidatedInvocation,
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
  authority: { run: Run; spec: RunSpec; assembly: RunAssemblyV1; releaseKeys?: readonly ReleaseTrustKey[] }) {
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
  async function grantFor(selected: Cut, grantRef: string, reads = artifacts) {
    const grant = await readCanonicalArtifact<VerifierOperationGrantV1>(reads, grantRef);
    const evidence = await readCanonicalArtifact<VerifierPolicyChannelEvidenceV1>(reads, grant.provenance.channelEvidenceRef);
    requireEqual(grant, selected.evaluator.grant(selected.request, selected.target, evidence, grant.issuedAt, grant.expiresAt), 'verifier execution grant');
    if (grant.issuedAt < selected.progress.candidate.createdAt || grant.expiresAt > admitted.deadlineAt)
      throw new KernelStorageError('LEASE_FENCED', 'verifier grant exceeds its exact candidate lifetime');
    return { grant, evidence };
  }
  return Object.freeze({
    prepareVerifier: stateOperation('RECOVERY_REQUIRED', async (input: { expectedRunRevision: number; leaseEpoch: number }, readSignal?: AbortSignal) => {
      const reads = readSignal ? artifacts.withReadSignal(readSignal) : artifacts;
      reads.assertReadActive();
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision', 'leaseEpoch'])) throw new TypeError('unknown verifier preparation fields');
      const selected = await cut(input.expectedRunRevision, readSignal);
      assertLiveDispatchState(driver, owner, runId, input.expectedRunRevision, input.leaseEpoch, sampleCanonicalNow());
      const prior = readHighestPreparedAttempt(driver, runId, selected.request.opId);
      const previous = prior && readInvocationAttempt(driver, runId, prior.opId, prior.attempt);
      const last = previous?.at(-1), priorProgress = selected.progress.entries[selected.frontier.nextVerifierIndex]!;
      const unclaimedFailure = last?.phase === 'failed' && previous?.every(entry => entry.phase !== 'dispatch_claimed');
      if (prior && !unclaimedFailure && !(last?.phase === 'completed' && priorProgress.receipt?.outcome === 'infra_failed'))
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'verifier attempt is already prepared, claimed or not retryable');
      const uses = selected.journal.filter(row => row.opId === selected.request.opId && row.phase === 'dispatch_claimed').length;
      if (uses >= selected.target.maxAttempts) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'verifier frozen attempt count is exhausted');
      const now = sampleCanonicalNow(), evidence = prior?.grantRef ? (await grantFor(selected, prior.grantRef, reads)).evidence
        : selected.evaluator.evaluate(selected.request, selected.target, now);
      if (evidence.effectiveDisposition !== 'allow') return immutableSnapshot({ disposition: 'policy_refused' as const, run: selected.run });
      const grant = prior?.grantRef ? (await grantFor(selected, prior.grantRef, reads)).grant
        : selected.evaluator.grant(selected.request, selected.target, evidence, now, selected.run.deadlineAt);
      const requestPlan = planCanonicalArtifact(selected.request, selected.request.format), targetPlan = planCanonicalArtifact(selected.target, selected.target.format);
      const grantPlan = planCanonicalArtifact(grant, grant.format), evidencePlan = planCanonicalArtifact(evidence, evidence.format);
      const decision: VerifierPolicyDecisionItem = { schemaVersion: 1, kind: 'policy_decision', subjectKind: 'verifier_launch',
        itemId: identityHash('cliq-verifier-policy-item-v1', runId, selected.request.opId, evidencePlan.ref), runId,
        opId: selected.request.opId, principalId: selected.principalId, decisionRef: evidencePlan.ref, policyChannelEvidenceRef: evidencePlan.ref,
        policyChannelEvidenceDigest: evidence.evidenceDigest, createdAt: evidence.evaluatedAt, decisionSource: 'direct_policy', decision: 'allow', grantRef: grantPlan.ref };
      const context = decodeContextManifest(await readCanonicalArtifact(reads, selected.latestCheckpoint.contextManifestRef));
      const existingItems = await reads.mapReads(selected.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
        item: await readCanonicalArtifact<ContinuationItem>(reads, row.payloadRef) }));
      const graph = await prepareContinuationCommit(reads, { context, existingItems, items: prior ? [] : [decision], frontier: selected.frontier,
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
      return Object.freeze({ entry: immutableSnapshot(claimed), request: selected.request, target: selected.target,
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
