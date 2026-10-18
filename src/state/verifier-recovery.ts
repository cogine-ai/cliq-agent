import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { ProcessContainment, ProcessContainmentDeathEvidenceV1 } from '../kernel/execution.js';
import type { FinalCandidateItem, InvocationJournalEntry, RecoveryClosureV1, RunFrontier, VerifierSpec } from '../kernel/types.js';
import type { VerificationClosureV1, VerifierPlan } from '../kernel/result.js';
import type { VerificationReceipt, VerifierResultItem } from '../kernel/verifier.js';
import type { VerifierOperationGrantV1, VerifierPolicyChannelEvidenceV1, VerifierPolicyDecisionItem } from '../kernel/verifier-invocation.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeBudgetSettlement, decodeWorkspaceIdentity, decodeWorkspaceGenerationSnapshotEvidence } from './decoders.js';
import { decodeVerifierSandboxLaunchSpec } from './execution-closure.js';
import { readCandidateVerifierPlan } from './final-candidate-plan.js';
import { decodeFinalCandidateItem, decodeRunResult, decodeVerifierPlan } from './result-artifacts.js';
import { readCandidateSource } from './result-source.js';
import { readCheckpoint, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readStateOwner } from './state-owner.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import { readRetiredGenerationSource } from './generation-retirement.js';
import { validateMatchingWorkerDeath, validateRetainedWorkerSeal } from './tool-checkpoint.js';
import { decodeVerificationReceipt, decodeVerifierCommand, decodeVerifierEnvironment, decodeVerifierResultItem, decodeVerifierSpec } from './verifier-artifacts.js';
import { loadVerifierPolicy, planVerifierRequest, verifierOperationId } from './verifier-policy.js';
import { isZeroBudget } from './invariants.js';

export const verifierCheckpointId = (runId: string, opId: string, attempt: number) =>
  identityHash('cliq-verifier-checkpoint-v1', runId, opId, String(attempt));
export const verifierResultItemId = (runId: string, opId: string, attempt: number) =>
  identityHash('cliq-verifier-result-item-v1', runId, opId, String(attempt));

/** An audit edge connecting the original invocation's positive death to its
 * parent worker's sealed Checkpoint. This data never grants live authority. */
export type VerifierRetirementV1 = {
  schemaVersion: 1; format: 'cliq-verifier-retirement-v1'; runId: string; opId: string; attempt: number; dispatchId: string; leaseEpoch: number;
  containmentRef: string; deathEvidenceRef: string; checkpointId: string; workspaceStateRef: string; snapshotEvidenceRef: string;
  parentRetirementEvidenceRef: string; sourceAfterRef: string; sourceAfterDigest: string; evidenceDigest: string;
};
type LocalEntry = Extract<VerificationClosureV1['verification'], { kind: 'local' }>['entries'][number];
export type VerifierProgressEntry = {
  planEntry: VerifierPlan['entries'][number]; specEntry: VerifierSpec['verifiers'][number];
  resultItem?: VerifierResultItem; receipt?: VerificationReceipt; terminalJournal?: InvocationJournalEntry;
  disposition?: LocalEntry['disposition'];
};
export type VerifierProgress = {
  candidate: FinalCandidateItem; planRef: string; plan: VerifierPlan; spec: VerifierSpec;
  entries: VerifierProgressEntry[]; nextVerifierIndex: number; complete: boolean;
};
export type VerifierRecoveryCut = Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'items' | 'journal' | 'workspaceGenerations'>;

async function currentCandidate(artifacts: ArtifactCatalog, cut: VerifierRecoveryCut): Promise<string> {
  if (cut.run.frontierRef) {
    const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, cut.run.frontierRef);
    if (frontier.kind === 'verify' || frontier.kind === 'finalize') return frontier.candidateItemId;
  }
  if (cut.run.resultRef) {
    const result = decodeRunResult(await readCanonicalArtifact(artifacts, cut.run.resultRef));
    const closure = await readCanonicalArtifact<VerificationClosureV1>(artifacts, result.verificationClosureRef);
    return closure.candidateItemId;
  }
  throw new TypeError('verifier progress requires an exact candidate frontier or immutable result');
}

export async function readVerifierRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: VerifierRecoveryCut,
  candidate: FinalCandidateItem, receipt: Pick<VerificationReceipt, 'containmentEvidenceRef' | 'sourceDigestBefore' | 'sourceDigestAfter' | 'endedAt'>,
  claim: InvocationJournalEntry, terminal: InvocationJournalEntry) {
  const proof = await readCanonicalArtifact<VerifierRetirementV1>(artifacts, receipt.containmentEvidenceRef);
  if (!exactKeys(proof, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dispatchId', 'leaseEpoch', 'containmentRef',
    'deathEvidenceRef', 'checkpointId', 'workspaceStateRef', 'snapshotEvidenceRef', 'parentRetirementEvidenceRef', 'sourceAfterRef',
    'sourceAfterDigest', 'evidenceDigest']) || proof.schemaVersion !== 1 || proof.format !== 'cliq-verifier-retirement-v1' ||
      proof.evidenceDigest !== digestOmitting(proof, 'evidenceDigest') || proof.runId !== cut.run.id || proof.opId !== claim.opId ||
      proof.attempt !== claim.attempt || proof.dispatchId !== claim.dispatchId || proof.leaseEpoch !== claim.leaseEpoch ||
      proof.checkpointId !== verifierCheckpointId(cut.run.id, claim.opId, claim.attempt))
    throw new TypeError('verifier receipt substitutes its original retirement owner');
  const checkpoint = readCheckpoint(driver, proof.checkpointId);
  const snapshot = decodeWorkspaceGenerationSnapshotEvidence(await readCanonicalArtifact(artifacts, proof.snapshotEvidenceRef));
  if (checkpoint.runId !== cut.run.id || checkpoint.workspaceStateRef !== proof.workspaceStateRef || checkpoint.journalSeq !== terminal.seq ||
      snapshot.runId !== cut.run.id || snapshot.purpose !== 'sealed_to_checkpoint' || snapshot.checkpointId !== checkpoint.id ||
      snapshot.workspaceStateRef !== checkpoint.workspaceStateRef || snapshot.observedAt > checkpoint.createdAt ||
      checkpoint.createdAt < terminal.timestamp)
    throw new TypeError('verifier retirement has no exact atomic parent Checkpoint');
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, cut.runSpec.assemblyRef));
  const generationProofs = await Promise.all(cut.workspaceGenerations.map(async generation => generation.phase === 'retired'
    ? (await readRetiredGenerationSource(driver, artifacts, { run: cut.run, spec: cut.runSpec, assembly, generation })).source : generation));
  const generation = generationProofs.filter(row => row.phase === 'sealed' && row.generationRef === snapshot.generationRef &&
    row.snapshotEvidenceRef === proof.snapshotEvidenceRef);
  if (generation.length !== 1) throw new TypeError('verifier retirement has no unique original sealed generation');
  const source = await readCandidateSource(artifacts, cut.runSpec, checkpoint.workspaceStateRef);
  if (source.sourceRef !== proof.sourceAfterRef || source.source.manifestDigest !== proof.sourceAfterDigest ||
      proof.sourceAfterDigest !== receipt.sourceDigestAfter || receipt.sourceDigestBefore !== candidate.sourceDigest)
    throw new TypeError('verifier source observation does not reproduce its exact sealed projection');
  const death = await readCanonicalArtifact<ProcessContainmentDeathEvidenceV1>(artifacts, proof.deathEvidenceRef);
  const containment = await readCanonicalArtifact<ProcessContainment>(artifacts, proof.containmentRef);
  const launch = decodeVerifierSandboxLaunchSpec(await readCanonicalArtifact(artifacts, claim.sandboxLaunchSpecRef!));
  if (!exactKeys(death, ['schemaVersion', 'kind', 'containmentRef', 'planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'owner',
    'launchNonceDigest', 'inspectorSupervisorInstanceId', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'backend', 'observedAt', 'evidenceDigest']) ||
      death.schemaVersion !== 1 || death.kind !== 'containment_all_descendants_dead' || death.evidenceDigest !== digestOmitting(death, 'evidenceDigest') ||
      death.containmentRef !== proof.containmentRef || death.planRef !== launch.containmentPlanRef || death.sandboxLaunchSpecRef !== claim.sandboxLaunchSpecRef ||
      death.sandboxLaunchSpecDigest !== launch.launchSpecDigest || containment.planRef !== death.planRef ||
      containment.sandboxLaunchSpecRef !== death.sandboxLaunchSpecRef || containment.sandboxLaunchSpecDigest !== death.sandboxLaunchSpecDigest ||
      containment.launchNonceDigest !== death.launchNonceDigest || containment.backend.kind !== 'linux' || death.backend.kind !== 'linux' ||
      death.observedAt < receipt.endedAt || death.observedAt > snapshot.observedAt)
    throw new TypeError('verifier retirement lacks positive original invocation death');
  requireEqual(containment.owner, launch.owner, 'verifier retired launch owner'); requireEqual(death.owner, launch.owner, 'verifier death owner');
  requireEqual(containment.filesystemBinding, { kind: 'run-generation', generationRef: snapshot.generationRef }, 'verifier retired generation');
  requireEqual(death.backend, { ...containment.backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 },
    'verifier all-descendant death');
  const owner = claim.stateOwnerEpoch && readStateOwner(driver, claim.stateOwnerEpoch);
  if (!owner || owner.supervisorInstanceId !== claim.supervisorInstanceId || death.inspectorSupervisorInstanceId !== owner.supervisorInstanceId ||
      owner.acquiredAt > death.observedAt || owner.state === 'terminal' && owner.releasedAt < death.observedAt)
    throw new TypeError('verifier retirement belongs to another original StateOwner');
  await readSupervisorInspector(artifacts, owner, assembly, death);
  // The enclosing recovery walk independently validates the parent's original
  // seal, D0/S/D1 freshness and physical resource lineage. Follow both edges.
  const parentDeath = await readCanonicalArtifact<ProcessContainmentDeathEvidenceV1>(artifacts, proof.parentRetirementEvidenceRef);
  if (parentDeath.containmentRef !== launch.parentWorkerContainmentRef || parentDeath.observedAt < death.observedAt ||
      parentDeath.observedAt > checkpoint.createdAt || parentDeath.evidenceDigest !== digestOmitting(parentDeath, 'evidenceDigest'))
    throw new TypeError('verifier retirement substitutes its joined parent containment');
  const parent = readRequiredWorkerLaunch(driver, launch.owner.workerLaunchId);
  if (parent.phase !== 'retired' || parent.generationWriteState !== 'sealed' || parent.processContainmentRef !== launch.parentWorkerContainmentRef ||
      parent.workspaceGenerationRef !== snapshot.generationRef || parent.leaseEpoch !== claim.leaseEpoch || parent.retiredAt !== checkpoint.createdAt)
    throw new TypeError('verifier retirement does not own the exact original sealed parent');
  const quiescence = await readCanonicalArtifact(artifacts, snapshot.quiescenceEvidenceRef);
  validateMatchingWorkerDeath(quiescence, parentDeath, 'verifier retained parent retirement');
  await validateRetainedWorkerSeal(driver, artifacts, { run: cut.run, spec: cut.runSpec, assembly, launch: parent, generation: generation[0]! });
  return { proof, launch };
}

/** Complete retained-data projection. Never calls readRecoveryClosure, starts
 * an inspector or grants a retry. Missing/unknown attempts have no disposition. */
export async function readVerifierProgress(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: VerifierRecoveryCut,
  candidateItemId?: string): Promise<VerifierProgress> {
  const selectedId = candidateItemId ?? await currentCandidate(artifacts, cut);
  const candidates = cut.items.filter(row => row.itemId === selectedId);
  if (candidates.length !== 1) throw new TypeError('verifier progress has no unique owned candidate');
  const candidate = decodeFinalCandidateItem(await readCanonicalArtifact(artifacts, candidates[0]!.payloadRef));
  if (candidate.runId !== cut.run.id || candidate.itemId !== selectedId) throw new TypeError('verifier candidate belongs to another Run');
  const plan = decodeVerifierPlan(await readCandidateVerifierPlan(artifacts, cut.runSpec, { runId: cut.run.id,
    candidateItemId: selectedId, resultSourceRef: candidate.resultSourceRef }));
  const planRef = canonicalSha256(plan);
  requireEqual(await readCanonicalArtifact(artifacts, planRef), plan, 'retained verifier plan');
  const spec = decodeVerifierSpec(await readCanonicalArtifact(artifacts, cut.runSpec.verifierSpecRef));
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, cut.runSpec.assemblyRef));
  const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, cut.runSpec.policyRef);
  const session = readSession(driver, cut.run.sessionId);
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, session.workspaceIdentityRef));
  const principalId = readSessionPrincipalId(driver, session.id);
  const entries: VerifierProgressEntry[] = [];
  for (const [index, planEntry] of plan.entries.entries()) {
    const specEntry = spec.verifiers[index]!;
    const command = decodeVerifierCommand(await readCanonicalArtifact(artifacts, specEntry.commandRef));
    const environment = decodeVerifierEnvironment(await readCanonicalArtifact(artifacts, specEntry.environmentRef));
    const frontier: Extract<RunFrontier, { kind: 'verify' }> = { schemaVersion: 1, kind: 'verify', phase: 'verifiers',
      candidateItemId: selectedId, resultSourceRef: candidate.resultSourceRef, verifierPlanRef: planRef, nextVerifierIndex: index, afterPass: 'finalize' };
    const context = { runId: cut.run.id, frontierRef: canonicalSha256(frontier), assemblyRef: cut.runSpec.assemblyRef,
      candidateItemId: selectedId, resultSourceRef: candidate.resultSourceRef, sourceDigest: candidate.sourceDigest,
      verifierPlanRef: planRef, plan, verifierSpecRef: cut.runSpec.verifierSpecRef, verifierSpec: spec, verifierIndex: index, command, environment };
    const planned = planVerifierRequest(context), opId = verifierOperationId(cut.run.id, selectedId, planRef, index);
    const operation = cut.journal.filter(entry => entry.opId === opId);
    if (operation.length && entries.some(entry => !entry.disposition || entry.receipt?.outcome === 'infra_failed' &&
        cut.journal.filter(row => row.opId === entry.terminalJournal?.opId && row.phase === 'dispatch_claimed').length < entry.planEntry.maxAttempts))
      throw new TypeError('verifier Journal advances before its preceding frozen plan entries are eligible');
    const progress: VerifierProgressEntry = { planEntry, specEntry }; entries.push(progress);
    for (const entry of operation) if (entry.opKind !== 'verifier' || entry.requestRef !== canonicalSha256(planned.request) || entry.target !== planned.request.targetRef)
      throw new TypeError('verifier Journal differs from its frozen request and target');
    if (operation.length) {
      requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(planned.request)), planned.request, 'retained verifier request');
      requireEqual(await readCanonicalArtifact(artifacts, planned.request.targetRef), planned.target, 'retained verifier target');
    }
    const preparations = operation.filter(entry => entry.phase === 'prepared');
    if (operation.length && !preparations.length) throw new TypeError('verifier Journal has no owning preparation');
    const uses = operation.filter(entry => entry.phase === 'dispatch_claimed');
    if (uses.length > planEntry.maxAttempts) throw new TypeError('verifier dispatch exceeds its frozen total attempt bound');
    const evaluator = loadVerifierPolicy({ policy, policyRef: cut.runSpec.policyRef, assembly, assemblyRef: cut.runSpec.assemblyRef,
      principalId, workspaceIdentityDigest: workspace.identityDigest, context });
    let previous: { terminal: InvocationJournalEntry; claimed: boolean; receipt?: VerificationReceipt; checkpointAt?: string } | undefined;
    for (const [attemptIndex, prepared] of preparations.entries()) {
      const reservation = { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 };
      requireEqual(prepared.budgetDelta, reservation, 'fixed verifier reservation');
      if (prepared.attempt !== attemptIndex || !prepared.grantRef || prepared.replayClass !== 'retry')
        throw new TypeError('verifier preparations are not contiguous grant-owned retry attempts');
      if (previous && !(previous.terminal.phase === 'failed' && !previous.claimed ||
          previous.terminal.phase === 'completed' && previous.receipt?.outcome === 'infra_failed'))
        throw new TypeError('verifier replacement lacks its settled no-dispatch or death-proved infrastructure predecessor');
      const attempt = operation.filter(entry => entry.attempt === prepared.attempt), terminal = attempt.at(-1)!;
      const claims = attempt.filter(entry => entry.phase === 'dispatch_claimed'), claim = claims[0];
      const phases = attempt.map(entry => entry.phase).join(',');
      if (!['prepared', 'prepared,failed', 'prepared,dispatch_claimed', 'prepared,dispatch_claimed,unknown',
        'prepared,dispatch_claimed,failed', 'prepared,dispatch_claimed,completed',
        'prepared,dispatch_claimed,unknown,completed', 'prepared,dispatch_claimed,unknown,failed'].includes(phases) ||
          claims.length > 1 || attempt[0] !== prepared || previous && (previous.terminal.seq >= prepared.seq ||
            previous.checkpointAt !== undefined && prepared.timestamp < previous.checkpointAt) ||
          attempt.some(entry => entry.grantRef !== prepared.grantRef || entry.leaseEpoch !== prepared.leaseEpoch || entry.replayClass !== prepared.replayClass ||
            entry.timestamp < prepared.timestamp)) throw new TypeError('verifier attempt has a mismatched or illegal Journal lifecycle');
      const grant = await readCanonicalArtifact<VerifierOperationGrantV1>(artifacts, prepared.grantRef);
      if (grant.provenance.kind !== 'policy_snapshot') throw new TypeError('verifier grant provenance is not implemented');
      const evidenceRef = grant.provenance.channelEvidenceRef;
      const evidence = await readCanonicalArtifact<VerifierPolicyChannelEvidenceV1>(artifacts, evidenceRef);
      requireEqual(grant, evaluator.grant(planned.request, planned.target, evidence, grant.issuedAt, grant.expiresAt), 'retained verifier grant');
      if (grant.issuedAt < candidate.createdAt || grant.expiresAt > cut.run.deadlineAt || prepared.timestamp < grant.issuedAt ||
          prepared.timestamp >= grant.expiresAt || claim && (claim.timestamp < grant.issuedAt || claim.timestamp >= grant.expiresAt ||
            !claim.sandboxLaunchSpecRef || !claim.dispatchId || !claim.supervisorInstanceId || !claim.stateOwnerEpoch))
        throw new TypeError('verifier attempt exceeds its exact grant, original claim or candidate lifetime');
      const decisionId = identityHash('cliq-verifier-policy-item-v1', cut.run.id, opId, evidenceRef);
      const decisionRows = cut.items.filter(row => row.itemId === decisionId), decisionRow = decisionRows[0];
      const decision: VerifierPolicyDecisionItem = { schemaVersion: 1, kind: 'policy_decision', subjectKind: 'verifier_launch',
        itemId: decisionId, runId: cut.run.id, opId, principalId, decisionRef: evidenceRef, policyChannelEvidenceRef: evidenceRef,
        policyChannelEvidenceDigest: evidence.evidenceDigest, createdAt: evidence.evaluatedAt,
        decisionSource: 'direct_policy', decision: 'allow', grantRef: prepared.grantRef };
      if (decisionRows.length !== 1 || !decisionRow || decisionRow.itemSeq <= candidates[0]!.itemSeq ||
          decisionRow.createdAt !== decision.createdAt || decision.createdAt > prepared.timestamp || decision.createdAt < candidate.createdAt)
        throw new TypeError('verifier preparation lacks its unique original owned policy decision');
      requireEqual(await readCanonicalArtifact(artifacts, decisionRow.payloadRef), decision, 'owned verifier policy decision');
      if (claim) {
        if (!isZeroBudget(claim.budgetDelta)) throw new TypeError('verifier claim changes its reserved budget');
        const firstTerminal = attempt.find(entry => ['completed', 'failed', 'unknown'].includes(entry.phase));
        if (firstTerminal) {
          if (!firstTerminal.budgetSettlementRef) throw new TypeError('claimed verifier has no original full settlement');
          const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, firstTerminal.budgetSettlementRef));
          if (settlement.runId !== cut.run.id || settlement.opId !== opId || settlement.attempt !== prepared.attempt ||
              settlement.preparedJournalSeq !== prepared.seq || settlement.terminalJournalSeq !== firstTerminal.seq ||
              settlement.terminalPhase !== firstTerminal.phase || settlement.settledAt !== firstTerminal.timestamp)
            throw new TypeError('claimed verifier substitutes its original full settlement');
          requireEqual(settlement.reserved, reservation, 'claimed verifier reservation');
          requireEqual(settlement.consumed, reservation, 'claimed verifier full consumption');
          requireEqual(firstTerminal.budgetDelta, reservation, 'claimed verifier original consumption');
          if (attempt.some(entry => entry.seq > firstTerminal.seq &&
              (entry.budgetSettlementRef !== firstTerminal.budgetSettlementRef || !isZeroBudget(entry.budgetDelta))))
            throw new TypeError('resolved verifier rewrites or charges its original settlement twice');
        }
      }
      previous = { terminal, claimed: !!claim };
      if (terminal.phase === 'failed' && !claim) {
        if (!terminal.errorRef || !terminal.budgetSettlementRef || !isZeroBudget(terminal.budgetDelta) ||
            [terminal.sandboxLaunchSpecRef, terminal.dispatchId, terminal.supervisorInstanceId, terminal.stateOwnerEpoch,
              terminal.brokerFenceTokenDigest, terminal.resultRef, terminal.receiptRef, terminal.evidenceRef,
              terminal.evidenceDigest, terminal.attestationRef].some(value => value !== undefined))
          throw new TypeError('unclaimed verifier preparation has dispatch facts or no exact zero settlement');
        requireEqual(await readCanonicalArtifact(artifacts, terminal.errorRef), { schemaVersion: 1,
          format: 'cliq-verifier-preparation-closure-v1', runId: cut.run.id, opId, attempt: prepared.attempt,
          preparedJournalSeq: prepared.seq, requestRef: prepared.requestRef, targetRef: prepared.target,
          grantRef: prepared.grantRef, disposition: 'unclaimed' }, 'original verifier preparation closure');
        const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, terminal.budgetSettlementRef));
        if (settlement.runId !== cut.run.id || settlement.opId !== opId || settlement.attempt !== prepared.attempt ||
            settlement.preparedJournalSeq !== prepared.seq || settlement.terminalJournalSeq !== terminal.seq ||
            settlement.terminalPhase !== 'failed' || settlement.settledAt !== terminal.timestamp || !isZeroBudget(settlement.consumed))
          throw new TypeError('unclaimed verifier preparation substitutes its original zero settlement');
        requireEqual(settlement.reserved, prepared.budgetDelta, 'unclaimed verifier reservation');
      }
      if (terminal.phase !== 'completed') continue;
      if (!claim || !terminal.receiptRef || terminal.resultRef !== terminal.receiptRef)
        throw new TypeError('completed verifier has no exact original claim and receipt');
      const receipt = decodeVerificationReceipt(await readCanonicalArtifact(artifacts, terminal.receiptRef));
      const resultRows = cut.items.filter(row => row.itemId === verifierResultItemId(cut.run.id, opId, prepared.attempt));
      if (resultRows.length !== 1) throw new TypeError('completed verifier has no unique owned result item');
      const resultItem = decodeVerifierResultItem(await readCanonicalArtifact(artifacts, resultRows[0]!.payloadRef));
      const expectedItem: VerifierResultItem = { schemaVersion: 1, kind: 'verifier_result', itemId: resultRows[0]!.itemId, runId: cut.run.id,
        candidateItemId: selectedId, verifierPlanRef: planRef, verifierIndex: index, verifierId: specEntry.id, opId, attempt: prepared.attempt,
        outcome: receipt.outcome, receiptRef: terminal.receiptRef, createdAt: terminal.timestamp };
      requireEqual(resultItem, expectedItem, 'verifier result item');
      if (receipt.runId !== cut.run.id || receipt.verifierId !== specEntry.id || receipt.verifierVersion !== specEntry.version ||
          receipt.attempt !== prepared.attempt || receipt.leaseEpoch !== prepared.leaseEpoch || receipt.resultSourceRef !== candidate.resultSourceRef ||
          receipt.sourceDigestBefore !== candidate.sourceDigest || receipt.commandRef !== specEntry.commandRef || receipt.commandDigest !== specEntry.commandDigest ||
          receipt.environmentRef !== specEntry.environmentRef || receipt.environmentDigest !== specEntry.environmentDigest || receipt.startedAt < claim.timestamp ||
          receipt.endedAt > terminal.timestamp || resultRows[0]!.createdAt !== terminal.timestamp || resultRows[0]!.itemSeq <= decisionRow.itemSeq)
        throw new TypeError('verifier receipt substitutes its immutable claim, source, command or environment');
      const retirement = await readVerifierRetirement(driver, artifacts, cut, candidate, receipt, claim, terminal);
      previous.checkpointAt = readCheckpoint(driver, retirement.proof.checkpointId).createdAt;
      let outputBytes = 0;
      for (const outputRef of [receipt.stdoutRef, receipt.stderrRef]) {
        const metadata = driver.prepare('SELECT byte_length FROM artifacts WHERE ref = ?').get<{ byte_length: bigint }>(outputRef);
        const byteLength = Number(metadata?.byte_length);
        outputBytes += byteLength;
        if (!metadata || !Number.isSafeInteger(byteLength) || byteLength < 0 || outputBytes > specEntry.outputLimitBytes)
          throw new TypeError('verifier output exceeds its frozen byte ceiling or lacks retained metadata');
        let count = 0;
        for await (const chunk of artifacts.readChunks(outputRef, byteLength)) count += chunk.byteLength;
        if (count !== byteLength) throw new TypeError('verifier output byte count differs');
      }
      previous.receipt = receipt;
      if (attemptIndex !== preparations.length - 1) continue;
      Object.assign(progress, { resultItem, receipt, terminalJournal: terminal });
      // Retain the genuine received fact so the deadline Stop can still drain
      // it; a late durable completion is never eligible to advance or succeed.
      if (previous.checkpointAt >= cut.run.deadlineAt || terminal.timestamp >= cut.run.deadlineAt) continue;
      if (receipt.outcome === 'passed') progress.disposition = { kind: 'passed', verifierResultItemId: resultItem.itemId, opId,
        attempt: prepared.attempt, completedJournalSeq: terminal.seq, receiptRef: terminal.receiptRef };
      else if (!planEntry.required && (receipt.outcome === 'assertion_failed' || receipt.outcome === 'infra_failed'))
        progress.disposition = { kind: 'advisory_nonpassing', outcome: receipt.outcome, verifierResultItemId: resultItem.itemId, opId,
          attempt: prepared.attempt, terminalJournalSeq: terminal.seq, receiptRef: terminal.receiptRef };
    }
    if (operation.some(entry => entry.attempt >= preparations.length || entry.attempt < 0))
      throw new TypeError('verifier Journal has an unowned attempt');
  }
  const nextVerifierIndex = entries.findIndex(entry => !entry.receipt || entry.receipt.outcome === 'infra_failed' &&
    cut.journal.filter(row => row.opId === entry.terminalJournal?.opId && row.phase === 'dispatch_claimed').length < entry.planEntry.maxAttempts);
  return { candidate, planRef, plan, spec, entries, nextVerifierIndex: nextVerifierIndex < 0 ? entries.length : nextVerifierIndex,
    complete: nextVerifierIndex < 0 };
}
