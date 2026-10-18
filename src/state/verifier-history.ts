import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash } from '../kernel/identity.js';
import type { Checkpoint, ContinuationItem, InvocationJournalEntry, Run, RunFrontier, RunItemReferenceV1, RunSpec, WorkspaceGenerationStateV1 } from '../kernel/types.js';
import type { VerifierOperationGrantV1, VerifierPolicyChannelEvidenceV1, VerifierPolicyDecisionItem } from '../kernel/verifier-invocation.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeContextManifest } from './decoders.js';
import { finalCandidateCheckpointId } from './final-candidate-plan.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { validateVerifierPolicyDenialHistory } from './stop-recovery.js';
import { decodeRepairDiagnosticItem, decodeVerifierResultItem, decodeVerifierStopItem } from './verifier-artifacts.js';
import { verifierOperationId } from './verifier-policy.js';
import type { VerifierProgress, VerifierRecoveryCut } from './verifier-recovery.js';
import { verifierCheckpointId, verifierResultItemId } from './verifier-recovery.js';
import { planVerifierRepair } from './verifier-repair.js';
import { validateVerifierStoppedHistory } from './verifier-stop-history.js';

/** Reverse coverage of the exact retained graph. The sole production caller
 * supplies progress from readVerifierProgress in the same recovery walk; these
 * data projections are never live execution or physical proof. */
export async function validateVerifierHistory(input: {
  driver: SqliteDriver; artifacts: ArtifactCatalog; run: Run; spec: RunSpec; items: RunItemReferenceV1[];
  journal: InvocationJournalEntry[]; checkpoints: Checkpoint[]; workspaceGenerations: WorkspaceGenerationStateV1[];
  decodedItems: ReadonlyMap<string, ContinuationItem>; verifierProgressByCandidate: ReadonlyMap<string, VerifierProgress>;
}): Promise<{ repairAttempts: number }> {
  const { driver, artifacts, run, spec, items, journal, decodedItems, verifierProgressByCandidate } = input;
  if (items.some((row, index) => row.itemSeq !== index + 1) || decodedItems.size !== items.length)
    throw new TypeError('verifier history lost its exact contiguous owned item cut');
  const cut: VerifierRecoveryCut = { run, runSpec: spec, items, journal, workspaceGenerations: input.workspaceGenerations };
  const operations = new Map<string, { progress: VerifierProgress; index: number }>();
  for (const [candidateId, progress] of verifierProgressByCandidate) {
    const rows = items.filter(row => row.itemId === candidateId);
    if (rows.length !== 1 || progress.candidate.itemId !== candidateId || progress.candidate.runId !== run.id ||
        decodedItems.get(candidateId)?.kind !== 'final_candidate') throw new TypeError('verifier history has no unique owned candidate');
    requireEqual(decodedItems.get(candidateId), progress.candidate, 'verifier history candidate');
    const checkpoint = input.checkpoints.find(checkpoint => checkpoint.id === finalCandidateCheckpointId(run.id, progress.candidate.producingItemId));
    if (!checkpoint) throw new TypeError('verifier candidate lost its original durable Checkpoint');
    for (const [index] of progress.plan.entries.entries()) {
      const opId = verifierOperationId(run.id, candidateId, progress.planRef, index);
      if (operations.has(opId)) throw new TypeError('verifier operation maps to multiple candidates');
      operations.set(opId, { progress, index });
    }
  }
  for (const item of decodedItems.values()) if (item.kind === 'final_candidate' && !verifierProgressByCandidate.has(item.itemId))
    throw new TypeError('verifier candidate has no independently validated progress');
  for (const entry of journal.filter(entry => entry.opKind === 'verifier')) {
    const owner = operations.get(entry.opId);
    if (!owner) throw new TypeError('verifier Journal has no owned candidate and frozen plan');
    const checkpoint = input.checkpoints.find(checkpoint => checkpoint.id === finalCandidateCheckpointId(run.id, owner.progress.candidate.producingItemId))!;
    if (entry.seq <= checkpoint.journalSeq || entry.timestamp < checkpoint.createdAt)
      throw new TypeError('verifier Journal precedes its original durable candidate');
  }
  for (const row of items) {
    const item = decodedItems.get(row.itemId);
    if (!item) throw new TypeError('verifier history lost its owned item payload');
    if (typeof item.kind === 'string' && item.kind.startsWith('verifier_') && item.kind !== 'verifier_result' && item.kind !== 'verifier_stop')
      throw new TypeError('verifier history contains an unsupported audit branch');
    if (item.kind === 'verifier_result' || item.kind === 'verifier_stop') {
      const checked = item.kind === 'verifier_result' ? decodeVerifierResultItem(item) : decodeVerifierStopItem(item);
      const owner = operations.get(checked.opId);
      if (!owner || owner.progress.candidate.itemId !== checked.candidateItemId || owner.progress.planRef !== checked.verifierPlanRef ||
          owner.index !== checked.verifierIndex || owner.progress.entries[owner.index]?.specEntry.id !== checked.verifierId)
        throw new TypeError('verifier audit item has no unique owned candidate and frozen plan');
      const prepared = journal.filter(entry => entry.opKind === 'verifier' && entry.opId === checked.opId && entry.attempt === checked.attempt && entry.phase === 'prepared');
      const terminal = journal.filter(entry => entry.opKind === 'verifier' && entry.opId === checked.opId && entry.attempt === checked.attempt &&
        entry.phase === (checked.kind === 'verifier_result' ? 'completed' : 'failed'));
      if (prepared.length !== 1 || terminal.length !== 1 || terminal[0]!.timestamp !== checked.createdAt || row.createdAt !== checked.createdAt ||
          checked.itemId !== (checked.kind === 'verifier_result' ? verifierResultItemId(run.id, checked.opId, checked.attempt)
            : identityHash('cliq-verifier-stop-item-v1', run.id, checked.opId, String(checked.attempt))) ||
          (checked.kind === 'verifier_result' ? terminal[0]!.receiptRef !== checked.receiptRef || terminal[0]!.resultRef !== checked.receiptRef
            : terminal[0]!.errorRef !== checked.containmentEvidenceRef))
        throw new TypeError('verifier audit item has no unique original preparation and terminal Journal');
    } else if (item.kind === 'policy_decision' && item.subjectKind === 'verifier_launch') {
      const owner = operations.get(item.opId);
      if (!owner) throw new TypeError('verifier policy item has no owned candidate and frozen plan');
      if (!['allow', 'deny'].includes(item.decision)) throw new TypeError('verifier policy item has an unsupported decision');
      if (item.decision === 'allow') {
        const prepared = journal.filter(entry => entry.opKind === 'verifier' && entry.opId === item.opId && entry.phase === 'prepared' && entry.grantRef === item.grantRef);
        if (!prepared.length) throw new TypeError('verifier allow policy item has no original preparation');
        if (item.itemId !== identityHash('cliq-verifier-policy-item-v1', run.id, item.opId, item.policyChannelEvidenceRef))
          throw new TypeError('verifier policy item substitutes its stable owned identity');
        const grant = await readCanonicalArtifact<VerifierOperationGrantV1>(artifacts, item.grantRef);
        if (grant.provenance.kind !== 'policy_snapshot' || grant.opId !== item.opId || grant.runId !== run.id ||
            grant.provenance.channelEvidenceRef !== item.policyChannelEvidenceRef ||
            grant.provenance.channelEvidenceDigest !== item.policyChannelEvidenceDigest)
          throw new TypeError('verifier allow policy item substitutes its original grant evidence');
        const evidence = await readCanonicalArtifact<VerifierPolicyChannelEvidenceV1>(artifacts, item.policyChannelEvidenceRef);
        const expected: VerifierPolicyDecisionItem = { schemaVersion: 1, kind: 'policy_decision', subjectKind: 'verifier_launch',
          itemId: item.itemId, runId: run.id, opId: item.opId, principalId: grant.principalId, decisionRef: item.policyChannelEvidenceRef,
          policyChannelEvidenceRef: item.policyChannelEvidenceRef, policyChannelEvidenceDigest: evidence.evidenceDigest,
          createdAt: evidence.evaluatedAt, decisionSource: 'direct_policy', decision: 'allow', grantRef: item.grantRef };
        requireEqual(item, expected, 'verifier original allow policy item');
      }
    }
  }
  const denied = await validateVerifierPolicyDenialHistory(driver, artifacts, cut);
  const stopped = await validateVerifierStoppedHistory(driver, artifacts, cut);
  for (const item of decodedItems.values()) if (item.kind === 'policy_decision' && item.subjectKind === 'verifier_launch' &&
      item.decision === 'deny' && !denied.has(item.itemId)) throw new TypeError('verifier denied policy item has no independently owned stop');
  for (const entry of journal.filter(entry => entry.opKind === 'verifier' && entry.phase === 'failed')) {
    const claimed = journal.some(claim => claim.opId === entry.opId && claim.attempt === entry.attempt && claim.phase === 'dispatch_claimed');
    if (claimed && !stopped.has(entry.seq)) throw new TypeError('claimed failed verifier has no owned typed stop retirement');
  }
  const repairs = items.filter(row => decodedItems.get(row.itemId)?.kind === 'repair_diagnostic');
  type AgentFrontier = Extract<RunFrontier, { kind: 'agent' }>;
  type Origin = { checkpoint: Checkpoint; itemSeq: number };
  const repaired = new Set<string>(), repairFrontiers = new Map<string, Origin>();
  const repairTurns = new Map<string, AgentFrontier>();
  for (const [index, row] of repairs.entries()) {
    const item = decodeRepairDiagnosticItem(decodedItems.get(row.itemId));
    const progress = verifierProgressByCandidate.get(item.candidateItemId);
    const candidate = items.find(candidate => candidate.itemId === item.candidateItemId);
    const latest = items.slice(0, row.itemSeq - 1).filter(candidate => decodedItems.get(candidate.itemId)?.kind === 'final_candidate').at(-1);
    const ordinal = index + 1;
    if (!progress || !candidate || latest !== candidate || repaired.has(candidate.itemId) || item.repairOrdinal !== ordinal ||
        ordinal > spec.budgets.repairAttempts || item.runId !== run.id || row.createdAt !== item.createdAt ||
        item.createdAt < candidate.createdAt || item.createdAt >= run.deadlineAt || item.verifierPlanRef !== progress.planRef)
      throw new TypeError('repair history lacks its latest unique unrepaired candidate and contiguous ordinal');
    const plan = planVerifierRepair(progress, { runId: run.id, repairOrdinal: ordinal, createdAt: item.createdAt });
    requireEqual(item, plan.item, 'repair exact original ordered assertion diagnostics');
    for (const artifact of plan.plans) if (!(await artifacts.readBytes(artifact.ref)).equals(Buffer.from(artifact.bytes)))
      throw new TypeError('repair diagnostic or fixed model projection differs from its original receipt');
    const checkpoints = input.checkpoints.filter(checkpoint => checkpoint.id === plan.checkpointId), checkpoint = checkpoints[0];
    const sourceCheckpoint = input.checkpoints.find(checkpoint => checkpoint.id === finalCandidateCheckpointId(run.id, progress.candidate.producingItemId));
    if (checkpoints.length !== 1 || !checkpoint || !sourceCheckpoint || checkpoint.schemaVersion !== 1 || checkpoint.runId !== run.id ||
        checkpoint.reason !== 'auto' || checkpoint.runItemSeq !== row.itemSeq || checkpoint.createdAt < item.createdAt ||
        checkpoint.createdAt >= run.deadlineAt || checkpoint.basedOnRunRevision < 1 || checkpoint.basedOnRunRevision >= run.revision ||
        checkpoint.journalSeq > journal.length || checkpoint.journalSeq < sourceCheckpoint.journalSeq ||
        checkpoint.workspaceStateRef !== sourceCheckpoint.workspaceStateRef)
      throw new TypeError('repair history lacks its unique original same-source authorization Checkpoint');
    const atRepair = new Map<string, InvocationJournalEntry>();
    for (const entry of journal.slice(0, checkpoint.journalSeq)) atRepair.set(`${entry.opId}\0${entry.attempt}`, entry);
    if ([...atRepair.values()].some(entry => entry.phase !== 'completed' && entry.phase !== 'failed'))
      throw new TypeError('repair authorization retains an unsettled original invocation');
    if (items.slice(0, row.itemSeq - 1).some(row => {
      const prior = decodedItems.get(row.itemId);
      return prior?.kind === 'verifier_stop' || prior?.kind === 'policy_decision' && prior.subjectKind === 'verifier_launch' && prior.decision === 'deny';
    })) throw new TypeError('repair authorization follows a nonproductive verifier stop');
    for (const [opId, owner] of operations) if (owner.progress === progress && journal.some(entry => entry.opId === opId && entry.seq > checkpoint.journalSeq))
      throw new TypeError('repaired candidate received a later verifier invocation');
    for (const entry of progress.entries) {
      if (entry.receipt?.outcome === 'source_mutation') throw new TypeError('repair cannot follow a verifier integrity violation');
      if (!entry.planEntry.required || entry.receipt?.outcome !== 'assertion_failed') continue;
      const terminal = entry.terminalJournal;
      const original = terminal && input.checkpoints.find(checkpoint => checkpoint.id === verifierCheckpointId(run.id, terminal.opId, terminal.attempt));
      if (!terminal || !original || terminal.seq > checkpoint.journalSeq || terminal.timestamp > item.createdAt || original.createdAt > item.createdAt)
        throw new TypeError('repair assertion precedes its original complete receipt and retirement Checkpoint');
    }
    const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
    if (context.runId !== run.id || context.assemblyRef !== spec.assemblyRef || context.admittedContextRef !== spec.admittedContextRef ||
        context.throughItemSeq !== row.itemSeq) throw new TypeError('repair authorization lost its exact original model context');
    validateContextItems(context, items.slice(0, row.itemSeq).map(row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef, item: decodedItems.get(row.itemId)! })));
    const frontier: RunFrontier = { ...plan.frontier, contextItemSeq: row.itemSeq };
    const frontierRef = canonicalSha256(frontier);
    requireEqual(await readCanonicalArtifact(artifacts, frontierRef), frontier, 'repair original model frontier');
    if (repairFrontiers.has(frontierRef)) throw new TypeError('repair frontier has multiple original authorizations');
    repairFrontiers.set(frontierRef, { checkpoint, itemSeq: row.itemSeq }); repaired.add(candidate.itemId);
    repairTurns.set(frontier.turnId, frontier);
  }
  // A second candidate must descend from one counted repair of its immediate
  // predecessor. The model-grant check below owns the exact first consumer.
  const candidates = items.filter(row => decodedItems.get(row.itemId)?.kind === 'final_candidate');
  for (const [index, candidate] of candidates.entries()) if (index > 0 && !repaired.has(candidates[index - 1]!.itemId))
    throw new TypeError('new verifier candidate has no counted repair of its predecessor');
  async function repairOrigin(frontier: AgentFrontier): Promise<Origin> {
    const cached = repairFrontiers.get(canonicalSha256(frontier));
    if (cached) return cached;
    const root = repairTurns.get(frontier.turnId);
    if (!root || frontier.contextItemSeq < root.contextItemSeq)
      throw new TypeError('repair model frontier has no original counted authorization');
    let origin: Origin;
    if (frontier.contextItemSeq === root.contextItemSeq) origin = repairFrontiers.get(canonicalSha256(root))!;
    else {
      const row = items.find(row => row.itemSeq === frontier.contextItemSeq), item = row && decodedItems.get(row.itemId);
      if (!row || item?.kind !== 'context_compaction') throw new TypeError('repair context cursor has no owned compaction source');
      const prepared = journal.find(entry => entry.opId === item.modelOpId && entry.attempt === item.modelAttempt && entry.phase === 'prepared');
      const terminal = journal.find(entry => entry.opId === item.modelOpId && entry.attempt === item.modelAttempt && entry.phase === 'completed');
      if (!prepared?.grantRef || !terminal?.resultRef) throw new TypeError('repair compaction has no original completed model owner');
      const grant = await readCanonicalArtifact<{ frontierRef: string }>(artifacts, prepared.grantRef);
      const previous = await readCanonicalArtifact<RunFrontier>(artifacts, grant.frontierRef);
      if (previous.kind !== 'agent' || previous.cause !== 'repair' || previous.turnId !== root.turnId ||
          previous.phase !== 'context_compaction' || previous.compactionPlanRef !== item.planRef || previous.contextItemSeq >= row.itemSeq)
        throw new TypeError('repair compaction does not descend from its exact original frontier');
      const previousOrigin = await repairOrigin(previous);
      const checkpoints = input.checkpoints.filter(checkpoint => checkpoint.runItemSeq === row.itemSeq && checkpoint.journalSeq === terminal.seq &&
        checkpoint.id === identityHash('cliq-continuation-checkpoint-v1', run.id, terminal.resultRef!, checkpoint.contextManifestRef));
      if (checkpoints.length !== 1 || checkpoints[0]!.runId !== run.id || checkpoints[0]!.createdAt < terminal.timestamp)
        throw new TypeError('repair compaction cursor has no unique original continuation Checkpoint');
      const checkpoint = checkpoints[0]!;
      const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
      if (checkpoint.workspaceStateRef !== previousOrigin.checkpoint.workspaceStateRef || context.runId !== run.id ||
          context.assemblyRef !== spec.assemblyRef || context.admittedContextRef !== spec.admittedContextRef || context.throughItemSeq !== row.itemSeq)
        throw new TypeError('repair compaction Checkpoint substitutes its original context or private workspace');
      validateContextItems(context, items.slice(0, row.itemSeq).map(row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef, item: decodedItems.get(row.itemId)! })));
      origin = { checkpoint: checkpoints[0]!, itemSeq: row.itemSeq };
    }
    const expected: AgentFrontier = { ...root, contextItemSeq: frontier.contextItemSeq,
      ...(frontier.phase === 'context_compaction' ? { phase: 'context_compaction', compactionPlanRef: frontier.compactionPlanRef } : {}) };
    requireEqual(frontier, expected, 'repair derived model frontier');
    if (frontier.phase === 'context_compaction') {
      if (!frontier.compactionPlanRef) throw new TypeError('repair compaction frontier lacks its original plan');
      const plan = await readCanonicalArtifact<{ runId: string; sourceContextManifestRef: string }>(artifacts, frontier.compactionPlanRef);
      if (plan.runId !== run.id || plan.sourceContextManifestRef !== origin.checkpoint.contextManifestRef)
        throw new TypeError('repair compaction plan substitutes its original counted context');
    }
    repairFrontiers.set(canonicalSha256(frontier), origin); return origin;
  }
  const repairConsumers = new Map<number, string>();
  for (const prepared of journal.filter(entry => entry.opKind === 'model' && entry.phase === 'prepared')) {
    if (!prepared.grantRef) continue; // The owning model reader rejects this independently.
    const grant = await readCanonicalArtifact<{ frontierRef: string; issuedAt: string }>(artifacts, prepared.grantRef);
    const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, grant.frontierRef);
    if (frontier.kind !== 'agent' || frontier.cause !== 'repair') continue;
    const original = await repairOrigin(frontier);
    if (frontier.contextItemSeq !== original.itemSeq || prepared.timestamp < original.checkpoint.createdAt ||
        grant.issuedAt < original.checkpoint.createdAt || prepared.seq <= original.checkpoint.journalSeq)
      throw new TypeError('repair model invocation has no original counted frontier authorization');
    repairConsumers.set(prepared.seq, frontier.turnId);
  }
  for (const [turnId, frontier] of repairTurns) {
    const origin = repairFrontiers.get(canonicalSha256(frontier))!;
    const first = journal.find(entry => entry.opKind === 'model' && entry.phase === 'prepared' && entry.seq > origin.checkpoint.journalSeq);
    if (first && repairConsumers.get(first.seq) !== turnId)
      throw new TypeError('repair authorization was bypassed by a model from another frontier');
    if (!first && candidates.some(candidate => candidate.itemSeq > origin.itemSeq))
      throw new TypeError('repaired candidate was replaced without consuming its authorized model frontier');
  }
  if (run.frontierRef) {
    const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef);
    if (frontier.kind === 'agent' && frontier.cause === 'repair') await repairOrigin(frontier);
  }
  if (run.repairCount !== repairs.length || run.budgetConsumed.repairAttempts !== repairs.length || run.budgetReserved.repairAttempts !== 0)
    throw new TypeError('repair counters do not equal their unique counted history');
  return { repairAttempts: repairs.length };
}
