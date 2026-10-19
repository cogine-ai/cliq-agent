import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { Checkpoint, ContinuationItem, InvocationJournalEntry, Run, RunFrontier, RunItemReferenceV1, RunSpec, WorkerDeathWait, WorkspaceGenerationStateV1 } from '../kernel/types.js';
import type { ModelRequestV1 } from '../model/request.js';
import { modelResponseDigest } from '../model/attempt.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import { readCanonicalArtifact, readModelTurnMaterial, readText } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeContextManifest, decodeSourceManifest, decodeWorkspaceEntries, decodeWorkspaceGenerationSnapshotEvidence, decodeWorkspaceState } from './decoders.js';
import { finalCandidateCheckpointId, finalCandidateItemId, readCandidateVerifierPlan } from './final-candidate-plan.js';
import { decodeFinalCandidateItem, decodeVerificationClosure, decodeVerifierPlan, decodeWorkspaceDiff } from './result-artifacts.js';
import { readCandidateSource } from './result-source.js';
import { isZeroBudget } from './invariants.js';
import type { VerifierProgress } from './verifier-recovery.js';
import type { RetainedDeliveryMerge } from './delivery-recovery.js';

/** Retained provenance only. The enclosing recovery walk validates the actual
 * sealed generation and original worker proof; this function mints neither. */
export async function validateFinalCandidateRecovery(input: {
  artifacts: ArtifactCatalog; run: Run; spec: RunSpec; items: RunItemReferenceV1[];
  journal: InvocationJournalEntry[]; checkpoints: Checkpoint[]; workspaceGenerations: WorkspaceGenerationStateV1[];
  decodedItems: Map<string, ContinuationItem>;
  verifierProgressByCandidate: ReadonlyMap<string, VerifierProgress>;
  deliveryMerges?: ReadonlyMap<string, RetainedDeliveryMerge>;
}): Promise<void> {
  const { artifacts, run, spec, items, journal, checkpoints, decodedItems } = input;
  const rows = items.filter(row => decodedItems.get(row.itemId)?.kind === 'final_candidate');
  if (rows.length === 0 && !['verify', 'finalize'].includes(run.nextStep ?? '')) return;
  const seen = new Set<string>(), verifierFrontiers = new Map<string, RunFrontier>();
  for (const row of rows) {
    const candidate = decodeFinalCandidateItem(await readCanonicalArtifact(artifacts, row.payloadRef));
    requireEqual(candidate, decodedItems.get(row.itemId), 'candidate recovery item');
    if (candidate.operation === 'delivery') {
      const merged = input.deliveryMerges?.get(candidate.producingItemId);
      if (spec.operation !== 'delivery' || !merged || run.parentRunId !== undefined ||
          [...decodedItems.values()].some(item => ['child_handle', 'child_result'].includes(item.kind)))
        throw new TypeError('delivery candidate has no fully validated original merge lifecycle');
      requireEqual(candidate, merged.candidate, 'delivery candidate original immutable merge');
      const expectedPlan = await readCandidateVerifierPlan(artifacts, spec, { runId: run.id,
        candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef });
      const planRef = canonicalSha256(expectedPlan);
      requireEqual(decodeVerifierPlan(await readCanonicalArtifact(artifacts, planRef)), expectedPlan, 'delivery frozen verifier plan');
      const progress = input.verifierProgressByCandidate.get(candidate.itemId);
      if (!progress || progress.planRef !== planRef || canonicalSha256(progress.candidate) !== canonicalSha256(candidate))
        throw new TypeError('delivery candidate has no exact independently validated verifier history');
      const initialFrontier: RunFrontier = { schemaVersion: 1, kind: 'verify', phase: 'verifiers',
        candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef, verifierPlanRef: planRef,
        nextVerifierIndex: 0, afterPass: 'delivery_approval' };
      requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(initialFrontier)), initialFrontier, 'delivery initial verifier frontier');
      verifierFrontiers.set(candidate.itemId, initialFrontier);
      continue;
    }
    if (candidate.operation !== 'agent' || spec.operation !== 'agent' || run.parentRunId !== undefined ||
        [...decodedItems.values()].some(item => ['child_handle', 'child_result'].includes(item.kind)))
      throw new TypeError('candidate recovery has no implemented delivery or child lifecycle');
    const position = items.indexOf(row), producerRow = items[position - 1];
    const producer = producerRow && decodedItems.get(producerRow.itemId);
    if (!producer || producer.kind !== 'model_turn' || producer.stopReason !== 'end' ||
        !exactKeys(producer, ['schemaVersion', 'itemId', 'runId', 'createdAt', 'kind', 'modelOpId',
          'modelAttempt', 'modelTurnRef', 'stopReason', 'textRef']) || producer.schemaVersion !== 1 ||
        producer.runId !== run.id || candidate.runId !== run.id || candidate.itemId !== row.itemId ||
        row.itemSeq !== position + 1 || producerRow.itemSeq !== row.itemSeq - 1 || row.payloadDigest !== row.payloadRef ||
        candidate.createdAt !== row.createdAt || candidate.createdAt < producer.createdAt || candidate.createdAt >= run.deadlineAt ||
        candidate.producingItemId !== producer.itemId || candidate.producingOpId !== producer.modelOpId ||
        candidate.itemId !== finalCandidateItemId(run.id, producer.itemId) ||
        producer.itemId !== identityHash('cliq-model-turn-item-v1', run.id, producer.modelOpId, String(producer.modelAttempt)) ||
        candidate.summaryRef !== producer.textRef || seen.has(candidate.producingItemId))
      throw new TypeError('candidate recovery has no unique immediately preceding complete model item');
    seen.add(candidate.producingItemId);
    const completions = journal.filter(entry => entry.opKind === 'model' && entry.phase === 'completed' &&
      entry.opId === producer.modelOpId && entry.attempt === producer.modelAttempt && entry.resultRef === producer.modelTurnRef);
    if (completions.length !== 1) throw new TypeError('candidate recovery has no unique completed model Journal owner');
    const completion = completions[0];
    const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, completion.requestRef);
    const material = await readModelTurnMaterial(artifacts, producer.modelTurnRef);
    const summary = await readText(artifacts, candidate.summaryRef);
    if (request.kind !== 'normal' || request.runId !== run.id || request.opId !== producer.modelOpId ||
        request.attempt !== producer.modelAttempt || request.assemblyRef !== spec.assemblyRef ||
        request.requestDigest !== digestOmitting(request, 'requestDigest') || material.turn.stopReason !== 'end' ||
        material.turn.toolCalls.length !== 0 || material.inputs.length !== 0 || material.turn.textRef !== candidate.summaryRef ||
        material.turn.requestDigest !== request.requestDigest || material.turn.promptProjectionRef !== request.promptProjectionRef ||
        material.turn.promptProjectionDigest !== request.promptProjectionDigest ||
        material.turn.responseDigest !== modelResponseDigest(material.turn) || !summary.utf8.trim() ||
        completion.timestamp !== producer.createdAt || completion.timestamp > candidate.createdAt)
      throw new TypeError('candidate recovery producer is not the exact normal final model completion');
    const owning = checkpoints.filter(checkpoint => checkpoint.id === finalCandidateCheckpointId(run.id, producer.itemId));
    if (owning.length !== 1) throw new TypeError('candidate recovery lost its unique original checkpoint');
    const checkpoint = owning[0];
    if (checkpoint.schemaVersion !== 1 || checkpoint.runId !== run.id || checkpoint.reason !== 'auto' ||
        checkpoint.runItemSeq !== row.itemSeq || checkpoint.journalSeq < completion.seq ||
        checkpoint.journalSeq > journal.length || candidate.createdAt > checkpoint.createdAt ||
        checkpoint.createdAt >= run.deadlineAt || checkpoint.basedOnRunRevision < 1 ||
        checkpoint.basedOnRunRevision >= run.revision)
      throw new TypeError('candidate recovery checkpoint does not retain its atomic original cut');
    const atCandidate = new Map<string, InvocationJournalEntry>();
    for (const entry of journal.slice(0, checkpoint.journalSeq)) atCandidate.set(`${entry.opId}\0${entry.attempt}`, entry);
    if ([...atCandidate.values()].some(entry => entry.phase !== 'completed' && entry.phase !== 'failed'))
      throw new TypeError('candidate recovery checkpoint retains an unsettled invocation');
    const highest = journal.slice(0, checkpoint.journalSeq).filter(entry => entry.opKind === 'model' &&
      entry.opId === producer.modelOpId && entry.phase === 'prepared').at(-1);
    if (!highest || highest.attempt !== producer.modelAttempt)
      throw new TypeError('candidate recovery producer is not its highest prepared attempt');
    const sealed = await Promise.all(input.workspaceGenerations.filter(generation => generation.phase === 'sealed')
      .map(async generation => ({ generation, snapshot: decodeWorkspaceGenerationSnapshotEvidence(
        await readCanonicalArtifact(artifacts, generation.snapshotEvidenceRef)) })));
    const owners = sealed.filter(({ snapshot }) => snapshot.checkpointId === checkpoint.id);
    if (owners.length !== 1 || owners[0]!.snapshot.purpose !== 'sealed_to_checkpoint' ||
        owners[0]!.snapshot.runId !== run.id || owners[0]!.snapshot.workspaceStateRef !== checkpoint.workspaceStateRef ||
        owners[0]!.snapshot.generationRef !== owners[0]!.generation.generationRef ||
        owners[0]!.snapshot.generationIdentityDigest !== owners[0]!.generation.generationIdentityDigest)
      throw new TypeError('candidate recovery checkpoint has no unique original sealed generation');
    const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
    if (context.runId !== run.id || context.throughItemSeq !== row.itemSeq || context.assemblyRef !== spec.assemblyRef ||
        context.admittedContextRef !== spec.admittedContextRef)
      throw new TypeError('candidate recovery checkpoint has a foreign context');
    validateContextItems(context, items.slice(0, row.itemSeq).map(entry => ({ itemSeq: entry.itemSeq,
      itemRef: entry.payloadRef, item: decodedItems.get(entry.itemId)! })));
    const workspace = decodeWorkspaceState(await readCanonicalArtifact(artifacts, checkpoint.workspaceStateRef));
    if (workspace.runId !== run.id) throw new TypeError('candidate recovery checkpoint has a foreign workspace');
    const expected = await readCandidateSource(artifacts, spec, checkpoint.workspaceStateRef);
    const source = decodeSourceManifest(await readCanonicalArtifact(artifacts, candidate.resultSourceRef));
    const diff = decodeWorkspaceDiff(await readCanonicalArtifact(artifacts, candidate.diffRef));
    const projectedEntries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, source.entriesRef));
    if (candidate.baseSourceRef !== spec.baseWorkspaceManifestRef || candidate.resultSourceRef !== expected.sourceRef ||
        candidate.diffRef !== expected.diffRef || candidate.sourceDigest !== source.manifestDigest ||
        candidate.diffDigest !== diff.diffDigest || projectedEntries.treeDigest !== source.treeDigest)
      throw new TypeError('candidate recovery source and diff do not reproduce the frozen checkpoint projection');
    requireEqual(source, expected.source, 'candidate recovery frozen result source');
    requireEqual(diff, expected.diff, 'candidate recovery deterministic workspace diff');
    const expectedPlan = await readCandidateVerifierPlan(artifacts, spec, { runId: run.id,
      candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef });
    const planRef = canonicalSha256(expectedPlan);
    const plan = decodeVerifierPlan(await readCanonicalArtifact(artifacts, planRef));
    requireEqual(plan, expectedPlan, 'candidate recovery frozen verifier plan');
    const progress = input.verifierProgressByCandidate.get(candidate.itemId);
    if (!progress || progress.planRef !== planRef || canonicalSha256(progress.candidate) !== canonicalSha256(candidate))
      throw new TypeError('candidate recovery has no exact independently validated verifier history');
    const initialFrontier: RunFrontier = { schemaVersion: 1, kind: 'verify', phase: 'verifiers',
      candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef, verifierPlanRef: planRef,
      nextVerifierIndex: 0, afterPass: 'finalize' };
    const frontierRef = canonicalSha256(initialFrontier);
    requireEqual(await readCanonicalArtifact(artifacts, frontierRef), initialFrontier, 'candidate recovery initial verify frontier');
    verifierFrontiers.set(candidate.itemId, initialFrontier);
  }
  for (const item of decodedItems.values()) if (item.kind === 'final_candidate' &&
    !rows.some(row => row.itemId === item.itemId)) throw new TypeError('candidate recovery has an unowned candidate item');
  if (!['queued', 'running', 'waiting'].includes(run.status)) return;
  const current = run.frontierRef && await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef);
  if ((current && current.kind === 'verify') || run.nextStep === 'verify') {
    if (!current || current.kind !== 'verify' || !verifierFrontiers.has(current.candidateItemId))
      throw new TypeError('current verifier frontier has no validated candidate');
    const progress = input.verifierProgressByCandidate.get(current.candidateItemId)!;
    requireEqual(current, { ...verifierFrontiers.get(current.candidateItemId), nextVerifierIndex: progress.nextVerifierIndex }, 'candidate recovery current verifier frontier');
    let lifecycle = false;
    if (run.status === 'queued') lifecycle = !run.activeWorkerLaunchId && !run.waitingReason && !run.waitingOnRef && isZeroBudget(run.budgetReserved);
    else if (run.status === 'running') lifecycle = !!run.activeWorkerLaunchId && !run.waitingReason && !run.waitingOnRef &&
      input.workspaceGenerations.some(generation => (generation.phase === 'active' || generation.phase === 'revoking' || generation.phase === 'checkpointing') &&
        generation.activeWorkerLaunchId === run.activeWorkerLaunchId && generation.leaseEpoch === run.leaseEpoch);
    else if (run.status === 'waiting' && run.waitingReason === 'reconciliation' && run.waitingOnRef && !run.activeWorkerLaunchId) {
      // This is the existing whole-worker death lifecycle, never a new
      // verifier status-query contract. Its complete launch/probe closure is
      // independently checked by validateWorkerRecoveryWait in the same walk.
      const fenced = input.workspaceGenerations.filter(generation => generation.phase === 'fenced_reconciling' &&
        generation.leaseEpoch === run.leaseEpoch && generation.waitingSubjectRef === run.waitingOnRef && generation.waitingSubjectDigest === run.waitingOnRef);
      const wait = await readCanonicalArtifact<WorkerDeathWait>(artifacts, run.waitingOnRef);
      const generation = fenced[0];
      lifecycle = fenced.length === 1 && generation?.phase === 'fenced_reconciling' && wait.schemaVersion === 1 && wait.kind === 'reconciliation' && wait.runId === run.id &&
        wait.frontierRef === run.frontierRef && wait.subject.kind === 'worker_death' && wait.subject.oldLeaseEpoch === run.leaseEpoch &&
        wait.subject.workspaceGenerationRef === generation.generationRef && wait.subject.oldWorkerLaunchId === generation.activeWorkerLaunchId;
    }
    if (run.nextStep !== 'verify' || !lifecycle)
      throw new TypeError('candidate recovery verifier cut has no exact queued or active execution lifecycle');
  } else if ((current && current.kind === 'finalize') || run.nextStep === 'finalize') {
    const planFrontier = current && current.kind === 'finalize' && verifierFrontiers.get(current.candidateItemId);
    if (!current || current.kind !== 'finalize' || current.operation !== spec.operation || !planFrontier || planFrontier.kind !== 'verify')
      throw new TypeError('current finalization frontier has no validated candidate');
    requireEqual(current, { schemaVersion: 1, kind: 'finalize', operation: spec.operation, candidateItemId: planFrontier.candidateItemId,
      resultSourceRef: planFrontier.resultSourceRef, verificationClosureRef: current.verificationClosureRef,
      ...(current.operation === 'delivery' ? { deliveryTerminalProjectionEvidenceRef: current.deliveryTerminalProjectionEvidenceRef } : {}) }, 'candidate recovery finalize frontier');
    const closure = decodeVerificationClosure(await readCanonicalArtifact(artifacts, current.verificationClosureRef));
    if (closure.runId !== run.id || closure.candidateItemId !== current.candidateItemId ||
        closure.resultSourceRef !== current.resultSourceRef || closure.verifierPlanRef !== planFrontier.verifierPlanRef ||
        spec.operation === 'agent' && (closure.verification.kind !== 'local' || closure.verification.unverifiedConsentRef !== spec.unverifiedConsentRef) ||
        spec.operation === 'delivery' && closure.verification.kind === 'local' && closure.verification.outcome !== 'verified' ||
        run.status !== 'queued' || run.nextStep !== 'finalize' || run.activeWorkerLaunchId || run.waitingReason ||
        run.waitingOnRef || !isZeroBudget(run.budgetReserved))
      throw new TypeError('candidate recovery finalization is not its exact worker-free verification closure');
  } else if (current && current.kind === 'delivery' && current.phase !== 'merge') {
    const initial = verifierFrontiers.get(current.candidateItemId);
    const candidate = decodedItems.get(current.candidateItemId);
    const merged = candidate?.kind === 'final_candidate' && input.deliveryMerges?.get(candidate.producingItemId);
    if (spec.operation !== 'delivery' || run.nextStep !== 'delivery' || initial?.kind !== 'verify' || !merged ||
        current.resultSourceRef !== initial.resultSourceRef || current.verifierPlanRef !== initial.verifierPlanRef ||
        current.deliveryPlanRef !== merged.planRef)
      throw new TypeError('delivery continuation lost its exact original candidate, verification or publication plan');
    const closure = decodeVerificationClosure(await readCanonicalArtifact(artifacts, current.verificationClosureRef));
    if (closure.runId !== run.id || closure.candidateItemId !== current.candidateItemId || closure.resultSourceRef !== current.resultSourceRef ||
        closure.verifierPlanRef !== initial.verifierPlanRef || closure.verification.kind === 'local' && closure.verification.outcome !== 'verified')
      throw new TypeError('delivery continuation has no exact verified closure');
  } else if (rows.length && rows.at(-1) === items.at(-1) && !run.stopIntentRef) {
    throw new TypeError('unconsumed candidate is not at its validated verifier frontier');
  }
}
