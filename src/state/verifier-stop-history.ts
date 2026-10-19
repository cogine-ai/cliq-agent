import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { ContinuationItem, RunFrontier, WorkspaceEntry } from '../kernel/types.js';
import type { VerifierPolicyChannelEvidenceV1, VerifierPolicyDecisionItem } from '../kernel/verifier-invocation.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { decodeAgentStop, type VerifierStopIntent } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeSourceManifest, decodeWorkspaceEntries, decodeWorkspaceIdentity } from './decoders.js';
import { readCheckpoint, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readStateOwner } from './state-owner.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { readCancelResponse } from './stop-recovery.js';
import { decodeVerifierCommand, decodeVerifierEnvironment, decodeVerifierResultItem, decodeVerifierStopEvidence, decodeVerifierStopItem } from './verifier-artifacts.js';
import { loadVerifierPolicy, planVerifierRequest, verifierOperationId } from './verifier-policy.js';
import { readVerifierProgress, readVerifierRetirement, verifierCheckpointId, type VerifierRecoveryCut } from './verifier-recovery.js';

const readItems = (artifacts: ArtifactCatalog, cut: VerifierRecoveryCut) => Promise.all(cut.items.map(async row =>
  ({ row, item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) })));

/** Retained stopped attempts are not receipts and never grant another attempt.
 * Every accepted sequence follows the original claim, stop and physical seal. */
export async function validateVerifierStoppedHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: VerifierRecoveryCut) {
  const terminalSequences = new Set<number>();
  for (const { row } of (await readItems(artifacts, cut)).filter(entry => entry.item.kind === 'verifier_stop')) {
    if (!cut.run.stopIntentRef) throw new TypeError('stopped verifier lost its irreversible Run stop fence');
    const item = decodeVerifierStopItem(await readCanonicalArtifact(artifacts, row.payloadRef));
    const progress = await readVerifierProgress(driver, artifacts, cut, item.candidateItemId);
    const current = progress.entries[item.verifierIndex];
    const opId = verifierOperationId(cut.run.id, item.candidateItemId, progress.planRef, item.verifierIndex);
    const attempt = cut.journal.filter(entry => entry.opId === opId && entry.attempt === item.attempt);
    const claim = attempt.find(entry => entry.phase === 'dispatch_claimed'), terminal = attempt.at(-1);
    if (!current || item.runId !== cut.run.id || item.itemId !== row.itemId || item.verifierPlanRef !== progress.planRef ||
        item.verifierId !== current.specEntry.id || item.opId !== opId || !claim || terminal?.phase !== 'failed' ||
        terminal.errorRef !== item.containmentEvidenceRef || terminal.timestamp !== item.createdAt || row.createdAt !== item.createdAt ||
        item.itemId !== identityHash('cliq-verifier-stop-item-v1', cut.run.id, opId, String(item.attempt)) ||
        cut.journal.some(entry => entry.opId === opId && entry.attempt > item.attempt || entry.seq > terminal.seq && entry.phase === 'prepared') ||
        terminalSequences.has(terminal.seq))
      throw new TypeError('stopped verifier has no unique original final claimed failure');
    const evidence = decodeVerifierStopEvidence(await readCanonicalArtifact(artifacts, item.containmentEvidenceRef));
    if (evidence.runId !== cut.run.id || evidence.verifierId !== current.specEntry.id || evidence.verifierVersion !== current.specEntry.version ||
        evidence.attempt !== item.attempt || evidence.leaseEpoch !== claim.leaseEpoch || evidence.resultSourceRef !== progress.candidate.resultSourceRef ||
        evidence.sourceDigestBefore !== progress.candidate.sourceDigest || evidence.commandRef !== current.specEntry.commandRef ||
        evidence.commandDigest !== current.specEntry.commandDigest || evidence.environmentRef !== current.specEntry.environmentRef ||
        evidence.environmentDigest !== current.specEntry.environmentDigest || evidence.stopIntentRef !== item.stopIntentRef ||
        evidence.startedAt < claim.timestamp || evidence.endedAt > terminal.timestamp)
      throw new TypeError('stopped verifier substitutes its original measured invocation');
    const originalStop = decodeAgentStop(await readCanonicalArtifact(artifacts, item.stopIntentRef), cut.run);
    if (originalStop.reason !== item.stopIntent || originalStop.createdAt > terminal.timestamp)
      throw new TypeError('stopped verifier lacks its original nonproductive stop');
    if (originalStop.origin === 'user_cancel') {
      const { response, row: control } = await readCancelResponse(driver, artifacts, cut.run, originalStop.principalId, originalStop.requestId);
      if (!cut.run.cancelRequested || response.result.snapshot.run.stopIntentRef !== item.stopIntentRef || control.committedAt !== originalStop.createdAt)
        throw new TypeError('stopped verifier cancellation lacks its original authenticated owner');
    } else if (originalStop.origin !== 'deadline' || originalStop.deadlineAt !== cut.run.deadlineAt)
      throw new TypeError('stopped verifier reason has no supported original stop authority');
    const retirement = await readVerifierRetirement(driver, artifacts, cut, progress.candidate, {
      containmentEvidenceRef: evidence.retirementRef, endedAt: evidence.endedAt,
      sourceDigestBefore: evidence.sourceDigestBefore, sourceDigestAfter: evidence.sourceDigestAfter
    }, claim, terminal);
    const checkpoint = readCheckpoint(driver, retirement.proof.checkpointId);
    if (checkpoint.runItemSeq !== row.itemSeq || row.itemSeq <= cut.items.find(entry => entry.itemId === item.candidateItemId)!.itemSeq)
      throw new TypeError('stopped verifier item is not in its original atomic Checkpoint');
    let outputBytes = 0;
    for (const outputRef of [evidence.stdoutRef, evidence.stderrRef]) {
      const metadata = driver.prepare('SELECT byte_length FROM artifacts WHERE ref = ?').get<{ byte_length: bigint }>(outputRef);
      const size = Number(metadata?.byte_length);
      if (!metadata || !Number.isSafeInteger(size) || size < 0 || size > current.specEntry.outputLimitBytes)
        throw new TypeError('stopped verifier output lacks its bounded retained artifact');
      outputBytes += size;
      if (outputBytes > current.specEntry.outputLimitBytes) throw new TypeError('stopped verifier combined output exceeds its frozen ceiling');
      let count = 0;
      for await (const chunk of artifacts.readChunks(outputRef, size)) count += chunk.byteLength;
      if (count !== size) throw new TypeError('stopped verifier output byte count differs');
    }
    terminalSequences.add(terminal.seq);
  }
  return terminalSequences;
}

/** A verification stop is derived from the latest immutable candidate, never
 * a caller's error or an advisory result. Repair is only for assertions. */
export async function readVerifierFailureCause(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: VerifierRecoveryCut,
  observedAt: string, candidateItemId?: string): Promise<Extract<VerifierStopIntent, { origin: 'verification' }> | undefined> {
  parseCanonicalTime(observedAt);
  if (observedAt >= cut.run.deadlineAt) return undefined;
  const items = await readItems(artifacts, cut);
  const latest = items.filter(entry => entry.item.kind === 'final_candidate').at(-1)?.row;
  if (!latest) return undefined;
  if (candidateItemId !== undefined && candidateItemId !== latest.itemId) throw new TypeError('verification stop substituted an earlier repaired candidate');
  if (items.some(({ row, item }) => row.itemSeq > latest.itemSeq && item.kind === 'repair_diagnostic')) return undefined;
  const progress = await readVerifierProgress(driver, artifacts, cut, latest.itemId);
  const failures = progress.entries.filter(entry => entry.planEntry.required && entry.receipt && entry.terminalJournal &&
    entry.terminalJournal.timestamp <= observedAt && readCheckpoint(driver,
      verifierCheckpointId(cut.run.id, entry.terminalJournal.opId, entry.terminalJournal.attempt)).createdAt <= observedAt);
  const assertions = failures.filter(entry => entry.receipt!.outcome === 'assertion_failed');
  const infra = failures.filter(entry => entry.receipt!.outcome === 'infra_failed' &&
    cut.journal.filter(row => row.opId === entry.terminalJournal!.opId && row.phase === 'dispatch_claimed').length >= entry.planEntry.maxAttempts);
  const reason = assertions.length && cut.run.repairCount >= cut.runSpec.budgets.repairAttempts
    ? 'verification_failed' : infra.length ? 'verifier_infrastructure_failed' : undefined;
  return reason ? { schemaVersion: 1, runId: cut.run.id, createdAt: observedAt, origin: 'verification', targetStatus: 'failed', reason,
    candidateItemId: latest.itemId, verifierPlanRef: progress.planRef } : undefined;
}

type DriftEvidence = {
  schemaVersion: 1; format: 'cliq-kernel-integrity-evidence-v1'; runId: string; sourceProjectionRef: string; workspaceGenerationRef: string;
  inspectorIdentityRef: string; inspectorIdentityDigest: string; observedAt: string; evidenceDigest: string;
  subjectKind: 'verifier'; verifierOpId: string; verifierAttempt: number; resultSourceRef: string;
  observationKind: 'source_digest_drift'; observationSource: 'trusted_out_of_containment_rehash';
  sourceBeforeRef: string; sourceBeforeDigest: string; sourceAfterRef: string; sourceAfterDigest: string; changedEntryDigests: string[];
};

/** Only the actually retained trusted rehash branch is implemented. An
 * unsupported/bad alleged mutation is corruption, never absence of a cause. */
export async function readVerifierIntegrityCause(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: VerifierRecoveryCut,
  observedAt: string): Promise<Extract<VerifierStopIntent, { origin: 'kernel_integrity' }> | undefined> {
  parseCanonicalTime(observedAt);
  let winning: Extract<VerifierStopIntent, { origin: 'kernel_integrity' }> | undefined;
  for (const { row } of (await readItems(artifacts, cut)).filter(entry => entry.item.kind === 'verifier_result')) {
    const result = decodeVerifierResultItem(await readCanonicalArtifact(artifacts, row.payloadRef));
    if (result.outcome !== 'source_mutation') continue;
    const progress = await readVerifierProgress(driver, artifacts, cut, result.candidateItemId);
    const entry = progress.entries[result.verifierIndex], receipt = entry?.receipt, terminal = entry?.terminalJournal;
    if (!entry || !receipt || !terminal || receipt.outcome !== 'source_mutation' || entry.resultItem?.itemId !== result.itemId ||
        !receipt.violationEvidenceRef || !receipt.violationEvidenceDigest)
      throw new TypeError('verifier mutation has no exact highest eligible typed receipt');
    const evidence = await readCanonicalArtifact<DriftEvidence>(artifacts, receipt.violationEvidenceRef);
    if (!exactKeys(evidence, ['schemaVersion', 'format', 'runId', 'sourceProjectionRef', 'workspaceGenerationRef', 'inspectorIdentityRef',
      'inspectorIdentityDigest', 'observedAt', 'evidenceDigest', 'subjectKind', 'verifierOpId', 'verifierAttempt', 'resultSourceRef',
      'observationKind', 'observationSource', 'sourceBeforeRef', 'sourceBeforeDigest', 'sourceAfterRef', 'sourceAfterDigest', 'changedEntryDigests']) ||
        evidence.schemaVersion !== 1 || evidence.format !== 'cliq-kernel-integrity-evidence-v1' || evidence.subjectKind !== 'verifier' ||
        evidence.observationKind !== 'source_digest_drift' || evidence.observationSource !== 'trusted_out_of_containment_rehash' ||
        evidence.runId !== cut.run.id || evidence.verifierOpId !== result.opId || evidence.verifierAttempt !== result.attempt ||
        evidence.resultSourceRef !== progress.candidate.resultSourceRef || evidence.sourceProjectionRef !== cut.runSpec.sourceProjectionRef ||
        evidence.evidenceDigest !== receipt.violationEvidenceDigest || evidence.evidenceDigest !== digestOmitting(evidence, 'evidenceDigest') ||
        evidence.sourceBeforeRef !== progress.candidate.resultSourceRef || evidence.sourceBeforeDigest !== receipt.sourceDigestBefore ||
        evidence.sourceAfterDigest !== receipt.sourceDigestAfter || evidence.sourceBeforeDigest === evidence.sourceAfterDigest ||
        !Array.isArray(evidence.changedEntryDigests) || evidence.changedEntryDigests.length === 0)
      throw new TypeError('verifier integrity cause has no supported exact trusted source rehash');
    for (const ref of [evidence.workspaceGenerationRef, evidence.inspectorIdentityRef, evidence.inspectorIdentityDigest, evidence.sourceAfterRef,
      evidence.sourceAfterDigest, ...evidence.changedEntryDigests]) assertArtifactRef(ref);
    parseCanonicalTime(evidence.observedAt);
    if (evidence.observedAt < receipt.endedAt || evidence.observedAt > terminal.timestamp || evidence.observedAt > observedAt)
      throw new TypeError('verifier integrity observation is outside its original receipt cut');
    const claim = cut.journal.find(journal => journal.opId === result.opId && journal.attempt === result.attempt && journal.phase === 'dispatch_claimed');
    if (!claim) throw new TypeError('verifier integrity evidence has no original claim');
    if (cut.journal.some(journal => journal.seq > terminal.seq && journal.phase === 'prepared'))
      throw new TypeError('verifier integrity failure was followed by another productive preparation');
    const retirement = await readVerifierRetirement(driver, artifacts, cut, progress.candidate, receipt, claim, terminal);
    if (readCheckpoint(driver, retirement.proof.checkpointId).createdAt > observedAt)
      throw new TypeError('verifier integrity stop precedes its original durable retirement');
    if (retirement.launch.filesystem.kind !== 'run_generation' || retirement.launch.filesystem.generationRef !== evidence.workspaceGenerationRef ||
        retirement.proof.sourceAfterRef !== evidence.sourceAfterRef)
      throw new TypeError('verifier integrity evidence names another sealed generation or source');
    const owner = claim.stateOwnerEpoch && readStateOwner(driver, claim.stateOwnerEpoch);
    if (!owner || owner.supervisorInstanceId !== claim.supervisorInstanceId || owner.acquiredAt > evidence.observedAt ||
        owner.state === 'terminal' && owner.releasedAt < evidence.observedAt) throw new TypeError('verifier integrity inspector has no original owner');
    await readSupervisorInspector(artifacts, owner, decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, cut.runSpec.assemblyRef)), evidence);
    const before = decodeSourceManifest(await readCanonicalArtifact(artifacts, evidence.sourceBeforeRef));
    const after = decodeSourceManifest(await readCanonicalArtifact(artifacts, evidence.sourceAfterRef));
    if (before.role !== 'result' || after.role !== 'result' || before.manifestDigest !== evidence.sourceBeforeDigest ||
        after.manifestDigest !== evidence.sourceAfterDigest) throw new TypeError('verifier integrity source manifest digest differs');
    requireEqual({ ...after, entriesRef: before.entriesRef, treeDigest: before.treeDigest, manifestDigest: before.manifestDigest }, before,
      'verifier integrity frozen projection and source identity');
    const manifests = await Promise.all([before, after].map(async source => {
      const entries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, source.entriesRef));
      if (entries.treeDigest !== source.treeDigest) throw new TypeError('verifier integrity source tree does not rehash');
      for (const entry of entries.entries) {
        if (entry.path.normalize('NFC') !== entry.path || entry.path.startsWith('/') || entry.path.includes('\0') ||
            entry.path.split('/').some(part => !part || part === '.' || part === '..')) throw new TypeError('verifier integrity entry path is not canonical');
        if (entry.kind === 'file') {
          let count = 0;
          for await (const chunk of artifacts.readChunks(entry.blobRef, entry.size)) count += chunk.byteLength;
          if (count !== entry.size) throw new TypeError('verifier integrity file byte count differs');
        }
      }
      return new Map(entries.entries.map(entry => [entry.path, entry]));
    }));
    const changed = new Set<string>();
    const digest = (entry: WorkspaceEntry | undefined) => entry && canonicalSha256(entry);
    for (const path of new Set([...manifests[0]!.keys(), ...manifests[1]!.keys()])) {
      const old = digest(manifests[0]!.get(path)), next = digest(manifests[1]!.get(path));
      if (old !== next) { if (old) changed.add(old); if (next) changed.add(next); }
    }
    const expected = [...changed].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    if (!expected.length) throw new TypeError('verifier integrity drift has no changed source entry');
    requireEqual(evidence.changedEntryDigests, expected, 'verifier integrity exact changed source entries');
    winning ??= { schemaVersion: 1, runId: cut.run.id, createdAt: observedAt, origin: 'kernel_integrity', targetStatus: 'failed',
      reason: 'verifier_mutated_source', verifierOpId: result.opId, integrityEvidenceRef: receipt.violationEvidenceRef,
      integrityEvidenceDigest: evidence.evidenceDigest };
  }
  return winning;
}

/** One retained named-action selection for denial and deterministic capacity
 * failure. It creates neither an execution grant nor retry permission. */
export async function readVerifierPendingPolicy(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: VerifierRecoveryCut,
  observedAt: string, historicalOpId?: string) {
  parseCanonicalTime(observedAt);
  if (observedAt >= cut.run.deadlineAt) return undefined;
  let frontier: RunFrontier | undefined;
  if (cut.run.frontierRef) frontier = await readCanonicalArtifact<RunFrontier>(artifacts, cut.run.frontierRef);
  else if (historicalOpId) {
    const rows = (await readItems(artifacts, cut)).filter(entry => entry.item.kind === 'policy_decision');
    for (const { row } of rows) {
      const item = await readCanonicalArtifact<VerifierPolicyDecisionItem>(artifacts, row.payloadRef);
      if (item.subjectKind === 'verifier_launch' && item.decision === 'deny' && item.opId === historicalOpId) {
        const evidence = await readCanonicalArtifact<VerifierPolicyChannelEvidenceV1>(artifacts, item.policyChannelEvidenceRef);
        if (frontier) throw new TypeError('verifier policy denial has duplicate original decisions');
        frontier = await readCanonicalArtifact<RunFrontier>(artifacts, evidence.frontierRef);
      }
    }
  } else if (cut.runSpec.operation === 'delivery') {
    // Terminal resource drain removes the current frontier. Reproduce its
    // exact immutable candidate/progress frontier, never infer it from a path,
    // caught BUDGET_EXHAUSTED error or receipt enumeration.
    const candidates = (await readItems(artifacts, cut)).filter(entry => entry.item.kind === 'final_candidate');
    if (candidates.length !== 1) return undefined;
    const progress = await readVerifierProgress(driver, artifacts, cut, candidates[0]!.row.itemId);
    frontier = { schemaVersion: 1, kind: 'verify', phase: 'verifiers', candidateItemId: progress.candidate.itemId,
      resultSourceRef: progress.candidate.resultSourceRef, verifierPlanRef: progress.planRef,
      nextVerifierIndex: progress.nextVerifierIndex, afterPass: 'delivery_approval' };
    requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(frontier)), frontier, 'delivery resource original verifier frontier');
  }
  if (!frontier || frontier.kind !== 'verify') return undefined;
  const progress = await readVerifierProgress(driver, artifacts, cut, frontier.candidateItemId);
  if (progress.candidate.createdAt > observedAt || readCheckpoint(driver,
    identityHash('cliq-final-candidate-checkpoint-v1', cut.run.id, progress.candidate.producingItemId)).createdAt > observedAt)
    throw new TypeError('verifier policy denial precedes its original durable candidate');
  if (frontier.nextVerifierIndex !== progress.nextVerifierIndex || frontier.verifierPlanRef !== progress.planRef ||
      frontier.resultSourceRef !== progress.candidate.resultSourceRef || frontier.phase !== 'verifiers' ||
      frontier.afterPass !== (cut.runSpec.operation === 'agent' ? 'finalize' : 'delivery_approval') ||
      !exactKeys(frontier, ['schemaVersion', 'kind', 'phase', 'candidateItemId', 'resultSourceRef', 'verifierPlanRef', 'nextVerifierIndex', 'afterPass']))
    throw new TypeError('verifier policy stop does not own its current exact plan frontier');
  const current = progress.entries[frontier.nextVerifierIndex];
  if (!current) return undefined;
  const command = decodeVerifierCommand(await readCanonicalArtifact(artifacts, current.specEntry.commandRef));
  const environment = decodeVerifierEnvironment(await readCanonicalArtifact(artifacts, current.specEntry.environmentRef));
  const context = { runId: cut.run.id, frontierRef: canonicalSha256(frontier), assemblyRef: cut.runSpec.assemblyRef,
    candidateItemId: progress.candidate.itemId, resultSourceRef: progress.candidate.resultSourceRef, sourceDigest: progress.candidate.sourceDigest,
    verifierPlanRef: progress.planRef, plan: progress.plan, verifierSpecRef: cut.runSpec.verifierSpecRef, verifierSpec: progress.spec,
    verifierIndex: frontier.nextVerifierIndex, command, environment };
  const planned = planVerifierRequest(context);
  if (historicalOpId && planned.request.opId !== historicalOpId) throw new TypeError('verifier policy denial substitutes its original operation');
  const session = readSession(driver, cut.run.sessionId), principalId = readSessionPrincipalId(driver, session.id);
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, session.workspaceIdentityRef));
  const evaluator = loadVerifierPolicy({ policy: await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, cut.runSpec.policyRef),
    policyRef: cut.runSpec.policyRef, assembly: decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, cut.runSpec.assemblyRef)),
    assemblyRef: cut.runSpec.assemblyRef, principalId, workspaceIdentityDigest: workspace.identityDigest, context });
  const evidence = evaluator.evaluate(planned.request, planned.target, observedAt);
  return { evidence, planned, principalId, frontier, progress, current };
}

/** Named-action denial is re-evaluated from the exact frozen current plan.
 * No approval, identity-read grant or caller-provided error can substitute. */
export async function readVerifierPolicyDenial(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: VerifierRecoveryCut,
  observedAt: string, historicalOpId?: string) {
  const selected = await readVerifierPendingPolicy(driver, artifacts, cut, observedAt, historicalOpId);
  return selected?.evidence.effectiveDisposition === 'deny' &&
    !cut.journal.some(entry => entry.opId === selected.planned.request.opId) ? selected : undefined;
}
