// The original signed broker's continuously held native mutex is the only
// live producer. Historical data revalidates that exact committed closure;
// neither a closed report nor a decoder can manufacture a claim refund.
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import { decodeModelOperationGrant } from '../kernel/model-grant.js';
import { decodeBrokerPostClaimNoRelease, type BrokerPostClaimNoReleaseEvidenceV1 } from '../kernel/post-claim-no-release.js';
import type { InvocationJournalEntry, RecoveryClosureV1, RunAssemblyV1, RunFrontier } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ModelRequestV1 } from '../model/request.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { validateRetainedInstalledBrokerRecipe } from './broker-ambiguity.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { decodeBudgetSettlement } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { assertInstalledModelNoReleaseFence, type HeldInstalledRuntime } from './installed-runtime.js';
import { isZeroBudget } from './invariants.js';
import { readModelGrantClosure } from './model-grant.js';
import type { ModelBrokerBinding, NativeModelNoReleaseFence, NativeModelTransport } from './model-broker-native.js';
import { readModelClaimCut, settleValidatedInvocation } from './reducers/invocation.js';
import { readInvocationAttempt } from './repositories/journal.js';
import { readRun, ZERO_BUDGET } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readStateOwner, type StateOwnerContext } from './state-owner.js';
import { readSupervisorInspector, supervisorInspectorIdentity } from './supervisor-inspector.js';

type PendingNoReleaseSettlement = {
  fence: NativeModelNoReleaseFence; driver: SqliteDriver; artifacts: ArtifactCatalog;
  owner: StateOwnerContext; selected: HeldInstalledRuntime; frameDigest: string; bindingDigest: string; active: boolean;
};
// This is the same original mutex owner, not a recipe for reacquiring one.
// Publication/SQL failure must retain it until that exact claim settles.
const pendingNoReleaseSettlements = new WeakMap<NativeModelTransport, PendingNoReleaseSettlement>();

function originalClaim(prepared: InvocationJournalEntry, claim: InvocationJournalEntry) {
  if (prepared.phase !== 'prepared' || prepared.opKind !== 'model' || claim.phase !== 'dispatch_claimed' || claim.opKind !== 'model' ||
      prepared.runId !== claim.runId || prepared.opId !== claim.opId || prepared.attempt !== claim.attempt ||
      prepared.requestRef !== claim.requestRef || prepared.target !== claim.target || prepared.grantRef !== claim.grantRef ||
      prepared.leaseEpoch !== claim.leaseEpoch || !prepared.grantRef || !claim.brokerFenceTokenDigest || !claim.dispatchId ||
      !claim.supervisorInstanceId || !claim.stateOwnerEpoch || claim.sandboxLaunchSpecRef || claim.seq <= prepared.seq ||
      claim.timestamp < prepared.timestamp || prepared.replayClass !== 'retry' || claim.replayClass !== 'retry' ||
      !isZeroBudget(claim.budgetDelta)) throw new TypeError('model no-release closure has no exact original broker claim');
}

export async function failInstalledModelClaimWithoutRelease(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, selected: HeldInstalledRuntime, input: {
    transport: NativeModelTransport; prepared: InvocationJournalEntry; claim: InvocationJournalEntry; errorRef?: string;
  }) {
  const prepared = immutableSnapshot(input.prepared), claim = immutableSnapshot(input.claim);
  originalClaim(prepared, claim);
  const frameDigest = canonicalSha256({ prepared, claim, errorRef: input.errorRef ?? null });
  let pending = pendingNoReleaseSettlements.get(input.transport);
  if (pending) {
    if (pending.driver !== driver || pending.artifacts !== artifacts || pending.owner !== owner || pending.selected !== selected ||
        pending.frameDigest !== frameDigest)
      throw new KernelStorageError('LEASE_FENCED', 'model no-release retry substitutes its original resource or claim owner');
    if (pending.active) throw new KernelStorageError('REVISION_CONFLICT', 'model no-release settlement is already active');
    pending.active = true;
  }
  try {
    const activeOwner = assertActiveStateOwner(driver, owner);
    if (activeOwner.supervisorInstanceId !== claim.supervisorInstanceId || activeOwner.ownerEpoch !== claim.stateOwnerEpoch)
      throw new KernelStorageError('LEASE_FENCED', 'model no-release settlement requires its original live claiming owner');
    // This producer already owns the original signed image/root descriptors.
    // Never enqueue a runtime borrow behind the callback awaiting settlement.
    const initial = await readModelClaimCut(driver, artifacts, prepared);
    await validateRetainedInstalledBrokerRecipe(artifacts, initial.run, initial.spec, initial.assembly);
    const binding: ModelBrokerBinding = immutableSnapshot({ runId: claim.runId, opId: claim.opId, attempt: claim.attempt,
      dispatchId: claim.dispatchId!, dispatchJournalSeq: claim.seq, requestRef: prepared.requestRef, requestDigest: initial.request.requestDigest,
      targetRef: initial.authority.targetRef, targetDigest: initial.authority.targetDigest, grantRef: prepared.grantRef!,
      supervisorInstanceId: claim.supervisorInstanceId!, stateOwnerEpoch: claim.stateOwnerEpoch!, leaseEpoch: claim.leaseEpoch,
      brokerFenceTokenDigest: claim.brokerFenceTokenDigest! });
    if (!pending) {
      // Another callback may have acquired the original guard during the
      // immutable reads above. Reuse only its completed, same-owner attempt.
      const raced = pendingNoReleaseSettlements.get(input.transport);
      if (raced) {
        if (raced.driver !== driver || raced.artifacts !== artifacts || raced.owner !== owner || raced.selected !== selected ||
            raced.frameDigest !== frameDigest)
          throw new KernelStorageError('LEASE_FENCED', 'model no-release retry substitutes its original resource or claim owner');
        if (raced.active) throw new KernelStorageError('REVISION_CONFLICT', 'model no-release settlement is already active');
        raced.active = true; pending = raced;
      } else {
        // No asynchronous cut separates this exact unsettled claim from
        // original guard acquisition/registration. An already committed
        // parallel settlement must not mint a fresh held guard.
        requireEqual(readInvocationAttempt(driver, claim.runId, claim.opId, claim.attempt), [prepared, claim], 'model no-release acquisition claim');
        const fence = input.transport.acquireNoReleaseFence(binding);
        pending = { fence, driver, artifacts, owner, selected, frameDigest, bindingDigest: canonicalSha256(binding), active: true };
        pendingNoReleaseSettlements.set(input.transport, pending);
      }
    }
    if (pending.bindingDigest !== canonicalSha256(binding))
      throw new KernelStorageError('LEASE_FENCED', 'model no-release retry changes its original held native binding');
    const fence = pending.fence;
    const installation = { selected, runtimeBundleRef: initial.assembly.runtime.runtimeBundleRef,
      runtimeBundleManifestDigest: initial.assembly.runtime.runtimeBundleManifestDigest };
    assertInstalledModelNoReleaseFence(fence, binding, installation);
    const error = input.errorRef ? await artifacts.describe(input.errorRef, 'application/json', 'cliq-invocation-error-v1') :
      await artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-invocation-error-v1', runId: claim.runId,
        opId: claim.opId, attempt: claim.attempt, requestRef: claim.requestRef,
        reason: 'installed_model_release_refused_before_native_connect' }, 'cliq-invocation-error-v1');
    for (let retry = 0; retry < 8; retry++) {
      const active = assertActiveStateOwner(driver, owner), cut = await readModelClaimCut(driver, artifacts, prepared);
      assertInstalledModelNoReleaseFence(fence, binding, installation);
      if (active.supervisorInstanceId !== claim.supervisorInstanceId || active.ownerEpoch !== claim.stateOwnerEpoch ||
          cut.run.specRef !== initial.run.specRef || cut.run.latestCheckpointId !== initial.run.latestCheckpointId ||
          cut.run.frontierRef !== initial.run.frontierRef)
        throw new KernelStorageError('LEASE_FENCED', 'model no-release producer lost its original owner or frontier');
      requireEqual(readInvocationAttempt(driver, claim.runId, claim.opId, claim.attempt), [prepared, claim], 'model no-release original permanent claim');
      const inspector = supervisorInspectorIdentity(active), inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
      const observedAt = sampleCanonicalNow();
      await readSupervisorInspector(artifacts, active, cut.assembly, { inspectorIdentityRef: inspectorArtifact.ref,
        inspectorIdentityDigest: inspector.identityDigest, observedAt });
      const evidence: BrokerPostClaimNoReleaseEvidenceV1 = { schemaVersion: 1, format: 'cliq-post-claim-no-release-evidence-v1',
        runId: claim.runId, opId: claim.opId, attempt: claim.attempt, dispatchId: claim.dispatchId!, dispatchJournalSeq: claim.seq,
        operationRequestRef: prepared.requestRef, operationRequestDigest: cut.request.requestDigest,
        operationTargetRef: cut.authority.targetRef, operationTargetDigest: cut.authority.targetDigest,
        operationGrantRef: prepared.grantRef!, claimingSupervisorInstanceId: claim.supervisorInstanceId!,
        claimingStateOwnerEpoch: claim.stateOwnerEpoch!, inspectorIdentityRef: inspectorArtifact.ref,
        inspectorIdentityDigest: inspector.identityDigest, observedAt,
        closure: { kind: 'broker_release_never_started', brokerFenceTokenDigest: claim.brokerFenceTokenDigest!,
          fenceAction: 'same_owner_token_revoked_before_release_and_matching_active_release_count_zero' }, evidenceDigest: '' };
      evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest'); decodeBrokerPostClaimNoRelease(evidence);
      const artifact = await artifacts.publishCanonical(evidence, evidence.format);
      assertInstalledModelNoReleaseFence(fence, binding, installation);
      try {
        const settled = await settleValidatedInvocation(driver, artifacts, owner, { runId: claim.runId, opId: claim.opId,
          attempt: claim.attempt, expectedRunRevision: cut.run.revision }, { phase: 'failed', errorRef: error.ref,
          evidenceRef: artifact.ref, evidenceDigest: evidence.evidenceDigest, consumed: ZERO_BUDGET, requireClaim: true }, async () => ({
            metadata: [error, artifact, inspectorArtifact],
            validate(connection, current, committedAt) {
              const actual = assertActiveStateOwner(connection, owner);
              assertInstalledModelNoReleaseFence(fence, binding, installation);
              requireEqual(readInvocationAttempt(connection, claim.runId, claim.opId, claim.attempt), [prepared, claim], 'model no-release commit claim');
              if (actual.supervisorInstanceId !== claim.supervisorInstanceId || actual.ownerEpoch !== claim.stateOwnerEpoch ||
                  current.specRef !== initial.run.specRef || current.frontierRef !== initial.run.frontierRef ||
                  current.latestCheckpointId !== initial.run.latestCheckpointId || committedAt < observedAt ||
                  parseCanonicalTime(committedAt) - parseCanonicalTime(observedAt) > 5_000)
                throw new KernelStorageError('LEASE_FENCED', 'model no-release evidence is not fresh under its exact live owner');
            },
          }));
        // Only the successful zero-settlement commit consumes this original
        // guard. Any publication, storage or CAS error leaves it continuously
        // held for same-owner settlement retry, never productive transport.
        fence.close();
        pendingNoReleaseSettlements.delete(input.transport);
        return settled;
      } catch (error) {
        if (!(error instanceof KernelStorageError) || error.code !== 'REVISION_CONFLICT') throw error;
        const current = readRun(driver, claim.runId);
        const stableStopCut = ({ revision: _revision, updatedAt: _updated, stopIntentRef: _stop,
          cancelRequested: _cancel, ...stable }: typeof current) => stable;
        if (current.specRef !== cut.run.specRef || current.frontierRef !== cut.run.frontierRef ||
            current.latestCheckpointId !== cut.run.latestCheckpointId || current.leaseEpoch !== cut.run.leaseEpoch ||
            current.activeWorkerLaunchId !== cut.run.activeWorkerLaunchId ||
            current.revision <= cut.run.revision || current.updatedAt < cut.run.updatedAt ||
            cut.run.cancelRequested && !current.cancelRequested || !current.stopIntentRef ||
            canonicalSha256(stableStopCut(current)) !== canonicalSha256(stableStopCut(cut.run))) throw error;
      }
    }
    throw new KernelStorageError('REVISION_CONFLICT', 'model no-release stop cut did not stabilize');
  } finally { if (pending) pending.active = false; }
}

/** Full retained closure, not acceptance of an arbitrary failed+claimed row. */
export async function validateInstalledModelNoReleaseHistory(driver: SqliteDriver, artifacts: ArtifactCatalog,
  closure: Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'journal'>): Promise<ReadonlySet<number>> {
  const verified = new Set<number>();
  const failures = closure.journal.filter(entry => entry.opKind === 'model' && entry.phase === 'failed' && entry.dispatchId !== undefined);
  if (!failures.length) return verified;
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, closure.runSpec.assemblyRef);
  await validateRetainedInstalledBrokerRecipe(artifacts, closure.run, closure.runSpec, assembly);
  for (const failed of failures) {
    const entries = closure.journal.filter(entry => entry.opId === failed.opId && entry.attempt === failed.attempt);
    const [prepared, claim] = entries;
    if (entries.length !== 3 || !prepared || !claim || entries[2] !== failed || !failed.evidenceRef || !failed.budgetSettlementRef ||
        !failed.errorRef || !isZeroBudget(failed.budgetDelta)) throw new TypeError('model no-release failed history is not exact');
    originalClaim(prepared, claim);
    const evidence = decodeBrokerPostClaimNoRelease(await readCanonicalArtifact(artifacts, failed.evidenceRef));
    const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, prepared.requestRef);
    const grant = decodeModelOperationGrant(await readCanonicalArtifact(artifacts, prepared.grantRef!));
    const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, grant.frontierRef);
    if (frontier.kind !== 'agent') throw new TypeError('model no-release history has no original model frontier');
    const authority = await readModelGrantClosure(driver, artifacts, { run: closure.run, spec: closure.runSpec, assembly,
      frontier, frontierRef: grant.frontierRef, request, requestRef: prepared.requestRef, grantRef: prepared.grantRef! });
    const repeated = { ...claim, seq: failed.seq, phase: failed.phase, budgetDelta: failed.budgetDelta,
      budgetSettlementRef: failed.budgetSettlementRef, timestamp: failed.timestamp, errorRef: failed.errorRef,
      evidenceRef: failed.evidenceRef, evidenceDigest: failed.evidenceDigest };
    requireEqual(failed, repeated, 'model no-release failed claim identity');
    requireEqual(evidence, { schemaVersion: 1, format: evidence.format, runId: claim.runId, opId: claim.opId, attempt: claim.attempt,
      dispatchId: claim.dispatchId, dispatchJournalSeq: claim.seq, operationRequestRef: prepared.requestRef,
      operationRequestDigest: request.requestDigest, operationTargetRef: authority.targetRef, operationTargetDigest: authority.targetDigest,
      operationGrantRef: prepared.grantRef, claimingSupervisorInstanceId: claim.supervisorInstanceId,
      claimingStateOwnerEpoch: claim.stateOwnerEpoch, inspectorIdentityRef: evidence.inspectorIdentityRef,
      inspectorIdentityDigest: evidence.inspectorIdentityDigest, observedAt: evidence.observedAt,
      closure: { kind: 'broker_release_never_started', brokerFenceTokenDigest: claim.brokerFenceTokenDigest,
        fenceAction: 'same_owner_token_revoked_before_release_and_matching_active_release_count_zero' },
      evidenceDigest: failed.evidenceDigest }, 'model no-release evidence original frame');
    const owner = readStateOwner(driver, claim.stateOwnerEpoch!);
    if (!owner || owner.supervisorInstanceId !== claim.supervisorInstanceId || owner.acquiredAt > evidence.observedAt ||
        claim.timestamp > evidence.observedAt || evidence.observedAt > failed.timestamp ||
        parseCanonicalTime(failed.timestamp) - parseCanonicalTime(evidence.observedAt) > 5_000 ||
        owner.state === 'terminal' && owner.releasedAt < failed.timestamp)
      throw new TypeError('model no-release historical inspector was not the same live claiming owner');
    await readSupervisorInspector(artifacts, owner, assembly, evidence);
    const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, failed.budgetSettlementRef));
    if (settlement.runId !== claim.runId || settlement.opId !== claim.opId || settlement.attempt !== claim.attempt ||
        settlement.preparedJournalSeq !== prepared.seq || settlement.terminalJournalSeq !== failed.seq ||
        settlement.terminalPhase !== 'failed' || settlement.settledAt !== failed.timestamp || !isZeroBudget(settlement.consumed) ||
        canonicalSha256(settlement.released) !== canonicalSha256(prepared.budgetDelta))
      throw new TypeError('model no-release history has no exact zero-consumption original settlement');
    verified.add(failed.seq);
  }
  return verified;
}
