// Read-only retained-data assertions for the real installed Delivery campaign.
// Rehashing these bytes never creates a native proof, grant or StateOwner.
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { decodeDeliveryMergeItem } from '../../../src/kernel/delivery.js';
import { digestOmitting, identityHash, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { StateOwnerRecordV1 } from '../../../src/kernel/types.js';
import { decodeDeliveryCaptureTopology, decodeDeliveryPlan, decodeDeliveryTerminalProjectionEvidence,
  decodePublicationProof } from '../../../src/kernel/publication.js';
import { decodeRetainedRunAssembly } from '../../../src/model/run-assembly.js';
import { decodeAdmittedContext, decodeBudgetSettlement, decodeContextManifest, decodeRunSpec, decodeSessionProjection, decodeSourceManifest, decodeSourceProjection, decodeWorkspaceEntries, decodeWorkspaceState } from '../../../src/state/decoders.js';
import { decodeSandboxProfile } from '../../../src/state/execution-closure.js';
import { readSourceProjectionData } from '../../../src/state/source-projection-data.js';
import { assertInstalledGitState, installedGitDataReader } from './installed-git-data.js';
import { loadDeliveryPolicy, planDeliveryRequest } from '../../../src/state/delivery-policy.js';
import { deliveryPublicationCheckpointId, deliveryPublicationTerminalCheckpointId } from '../../../src/state/delivery-publication-progress.js';
import { decodeFinalCandidateItem, decodeInheritedVerificationProvenance, decodeRunResult, decodeVerificationClosure, decodeVerifierPlan, decodeWorkspaceDiff } from '../../../src/state/result-artifacts.js';
import { decodeVerificationReceipt, decodeVerifierResultItem, decodeVerifierStopEvidence, decodeVerifierStopItem } from '../../../src/state/verifier-artifacts.js';
import { verifyModelText } from '../../../src/model/attempt.js';
import { validateContextItems } from '../../../src/runtime/context-compaction.js';
import { decodeAgentStop } from '../../../src/runtime/stop.js';
import { loadVerifierPolicy, planVerifierRequest, verifierOperationId } from '../../../src/state/verifier-policy.js';
import { assertInstalledVerifierRetirement, readInstalledVerifierInputs, type InstalledVerifierRetirementIdentity } from './installed-verifier-evidence.js';
import { assertInstalledDeliveryPublication } from './installed-delivery-publication-result.js';
import { assertInstalledVerifierParentRetirement, type InstalledVerifierParentRetirementIdentity } from './installed-verifier-parent-evidence.js';
import type { InstalledVerifierParentRetirementBinding, inspectInstalledVerifierParentRetirement } from './installed-worker-lease.js';

const ZERO = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
const ONE_TOOL = { ...ZERO, toolCalls: 1 };
const check = (condition: unknown): void => { if (!condition) throw new Error('installed Delivery data assertion failed'); };
const same = (left: unknown, right: unknown): void => check(canonicalSha256(left) === canonicalSha256(right));
export type InstalledDeliveryDiagnosticStage = 'public_cut' | 'source_and_merge' | 'direct_policy' | 'settlements' |
  'verification' | 'verification_inputs' | 'verification_plan' | 'verification_grant' | 'verification_settlement' |
  'verification_cancel' | 'verification_parent_retirement' | 'verification_child_retirement' |
  'verification_workspace' | 'verification_context' | 'publication_receipts' | 'terminal_projection' | 'session_publication';
const deliveryOutcomeStages = new Set<InstalledDeliveryDiagnosticStage>(['public_cut', 'source_and_merge', 'direct_policy', 'settlements',
  'verification', 'verification_inputs', 'verification_plan', 'verification_grant', 'verification_settlement',
  'verification_cancel', 'verification_parent_retirement', 'verification_child_retirement',
  'verification_workspace', 'verification_context', 'publication_receipts', 'terminal_projection', 'session_publication']);
// Diagnostic identity only. Opaque errors, proxies and forged prototypes never
// cross the enclosing catch; this creates no Run or retirement evidence.
const deliveryOutcomeErrors = new WeakSet<object>();

export class InstalledDeliveryOutcomeError extends Error {
  readonly code = 'INSTALLED_DELIVERY_OUTCOME_REFUSED';
  constructor(readonly diagnosticStage: InstalledDeliveryDiagnosticStage) {
    if (typeof diagnosticStage !== 'string' || !deliveryOutcomeStages.has(diagnosticStage))
      throw new TypeError('invalid installed Delivery diagnostic stage');
    super(`Installed Delivery outcome refused at ${diagnosticStage}`); this.name = 'InstalledDeliveryOutcomeError';
    Object.freeze(this); deliveryOutcomeErrors.add(this);
  }
}

/** A closed data assertion, not permission inferred from a Journal row. */
export function assertInstalledDeliveryClaims(cut: Record<string, any>, expected: { publish: number; verifier: number }) {
  const journal = cut.journal as Array<Record<string, any>>, run = cut.snapshot.run;
  check(Array.isArray(journal));
  check(journal.every(row => row.runId === run.id && ['publish', 'verifier'].includes(row.opKind)));
  const claims = journal.filter(row => row.phase === 'dispatch_claimed');
  check(claims.filter(row => row.opKind === 'publish').length === expected.publish &&
    claims.filter(row => row.opKind === 'verifier').length === expected.verifier);
  const settlements = new Set<string>();
  for (const claim of claims) {
    const rows = journal.filter(row => row.opId === claim.opId && row.attempt === claim.attempt);
    same(rows.map(row => row.phase), ['prepared', 'dispatch_claimed', 'completed']);
    check(rows[0]!.seq < claim.seq && claim.seq < rows[2]!.seq && rows.every(row => row.opKind === claim.opKind));
    same(rows[0]!.budgetDelta, ONE_TOOL); same(claim.budgetDelta, ZERO);
    same(rows[2]!.budgetDelta, ONE_TOOL);
    const ref = rows[2]!.budgetSettlementRef;
    check(typeof ref === 'string' && /^[a-f0-9]{64}$/u.test(ref) && !settlements.has(ref)); settlements.add(ref);
  }
  check(journal.length === claims.length * 3);
  same(run.budgetReserved, ZERO); same(run.budgetConsumed, { ...ZERO, toolCalls: claims.length });
  return { publishClaims: expected.publish, verifierClaims: expected.verifier, settlementCount: settlements.size };
}

/** The reserved pool is released in full even when a claimed invocation is
 * charged in full. `released` is not the unconsumed/refunded difference. This
 * fixed data contract covers both successful completion and claimed Stop. */
export function assertInstalledDeliverySettlement(prepared: Record<string, any>, claim: Record<string, any>,
  terminal: Record<string, any>, value: unknown, toolCallsBefore: number) {
  check(prepared.phase === 'prepared' && claim.phase === 'dispatch_claimed' &&
    ['completed', 'failed'].includes(terminal.phase));
  return assertSettlementData(prepared, claim, terminal, value, toolCallsBefore);
}

/** UNKNOWN stays UNKNOWN; it is neither a received child result nor a refund. */
export function assertInstalledDeliveryUnknownSettlement(prepared: Record<string, any>, claim: Record<string, any>,
  terminal: Record<string, any>, value: unknown) {
  check(prepared.phase === 'prepared' && claim.phase === 'dispatch_claimed' && terminal.phase === 'unknown' &&
    prepared.opKind === 'verifier' && prepared.replayClass === 'retry' && prepared.attempt === 0 &&
    terminal.receiptRef === undefined && terminal.resultRef === undefined);
  return assertSettlementData(prepared, claim, terminal, value, 0);
}

function assertSettlementData(prepared: Record<string, any>, claim: Record<string, any>,
  terminal: Record<string, any>, value: unknown, toolCallsBefore: number) {
  check(['publish', 'verifier'].includes(prepared.opKind) &&
    prepared.seq < claim.seq && claim.seq < terminal.seq && Number.isSafeInteger(toolCallsBefore) &&
    toolCallsBefore >= 0 && toolCallsBefore < Number.MAX_SAFE_INTEGER);
  for (const field of ['runId', 'opId', 'opKind', 'attempt', 'leaseEpoch', 'target', 'requestRef', 'grantRef', 'replayClass'])
    check(prepared[field] === claim[field] && claim[field] === terminal[field]);
  for (const field of ['dispatchId', 'supervisorInstanceId', 'stateOwnerEpoch', 'sandboxLaunchSpecRef'])
    check(claim[field] === terminal[field]);
  same(prepared.budgetDelta, ONE_TOOL); same(claim.budgetDelta, ZERO); same(terminal.budgetDelta, ONE_TOOL);
  const settlement = decodeBudgetSettlement(value);
  check(settlement.runId === prepared.runId && settlement.opId === prepared.opId && settlement.attempt === prepared.attempt &&
    settlement.preparedJournalSeq === prepared.seq && settlement.terminalJournalSeq === terminal.seq &&
    settlement.terminalPhase === terminal.phase && settlement.settledAt === terminal.timestamp &&
    terminal.budgetSettlementRef === canonicalSha256(settlement));
  same(settlement.reserved, prepared.budgetDelta); same(settlement.released, prepared.budgetDelta);
  same(settlement.consumed, terminal.budgetDelta);
  same(settlement.budgetConsumedBefore, { ...ZERO, toolCalls: toolCallsBefore });
  same(settlement.budgetConsumedAfter, { ...ZERO, toolCalls: toolCallsBefore + 1 });
  same(settlement.budgetReservedBefore, ONE_TOOL); same(settlement.budgetReservedAfter, ZERO);
  return settlement;
}

/** Exactly the fixed campaign's one new verifier attempt. Inherited evidence
 * never enters this function, and a Stop measurement is never a pass receipt. */
type InstalledDeliveryVerifierInput = {
  cut: Record<string, any>; sourceCut: Record<string, any>; outcome: 'passed' | 'stopped';
  readRetainedArtifact: (ref: string) => Promise<Buffer>;
  readOwnerHistory: () => Promise<readonly StateOwnerRecordV1[]>;
  expectedGit?: true;
  cancellation?: { request: Record<string, any>; response: Record<string, any> };
  readParentRetirement?: (binding: InstalledVerifierParentRetirementBinding) => ReturnType<typeof inspectInstalledVerifierParentRetirement>;
};
export type InstalledDeliveryVerifierRetirementIdentity = InstalledVerifierRetirementIdentity | InstalledVerifierParentRetirementIdentity;
export function assertInstalledDeliveryVerifier(input: InstalledDeliveryVerifierInput & { outcome: 'passed' }): Promise<InstalledVerifierRetirementIdentity>;
export function assertInstalledDeliveryVerifier(input: InstalledDeliveryVerifierInput & { outcome: 'stopped' }): Promise<InstalledDeliveryVerifierRetirementIdentity>;
export function assertInstalledDeliveryVerifier(input: InstalledDeliveryVerifierInput): Promise<InstalledDeliveryVerifierRetirementIdentity>;
export async function assertInstalledDeliveryVerifier(input: InstalledDeliveryVerifierInput): Promise<InstalledDeliveryVerifierRetirementIdentity> {
  // Fixed diagnostics only: never inspect the rejected error, serialize a
  // retained object, or treat a phase marker as evidence that it completed.
  let stage: InstalledDeliveryDiagnosticStage = 'verification';
  try {
    const { cut, sourceCut, outcome } = input, run = cut.snapshot?.run;
    check(cut.method === 'run.get' && cut.snapshot.operation === 'delivery' && sourceCut.snapshot?.operation === 'agent' &&
      sourceCut.snapshot.run.status === 'succeeded' && cut.nextItemSeq === cut.highWaterItemSeq && cut.items.length === cut.highWaterItemSeq &&
      cut.nextJournalSeq === cut.highWaterJournalSeq && cut.journal.length === cut.highWaterJournalSeq && cut.nextCheckpointCursor === cut.highWaterCheckpointCursor);
    cut.journal.forEach((row: any, index: number) => check(row.seq === index + 1 && row.runId === run.id));
    const cache = new Map<string, Buffer>();
    const bytes = async (ref: string) => {
      check(typeof ref === 'string' && /^[a-f0-9]{64}$/u.test(ref)); let value = cache.get(ref);
      if (!value) { value = await input.readRetainedArtifact(ref); check(Buffer.isBuffer(value) && value.length <= 1_048_576 && sha256Bytes(value) === ref); cache.set(ref, value); }
      check(cache.size <= 256); return value;
    };
    const object = async (ref: string): Promise<any> => {
      const value = await bytes(ref), data = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(value));
      check(canonicalJsonBytes(data).equals(value)); return data;
    };
    stage = 'verification_inputs';
    const spec = decodeRunSpec(await object(run.specRef)), originalSpec = decodeRunSpec(await object(sourceCut.snapshot.run.specRef));
    check(spec.operation === 'delivery' && spec.credentialGrantRefs.length === 0);
    for (const key of ['objectiveRef', 'sourceProjectionRef', 'assemblyRef', 'policyRef', 'sandboxProfileRef', 'verifierSpecRef'] as const) check(spec[key] === originalSpec[key]);
    const items: Array<{ row: Record<string, any>; item: any }> = await Promise.all(cut.items.map(async (row: any, index: number) => {
      check(row.itemSeq === index + 1 && row.payloadRef === row.payloadDigest);
      const item = await object(row.payloadRef); check(item.runId === run.id && item.itemId === row.itemId && item.createdAt === row.createdAt);
      return { row, item };
    }));
    const candidates = items.filter(value => value.item.kind === 'final_candidate'); check(candidates.length === 1);
    const candidate = decodeFinalCandidateItem(candidates[0]!.item), candidateRow = candidates[0]!.row;
    check(candidate.operation === 'delivery' && candidate.baseSourceRef === spec.baseWorkspaceManifestRef);
    const merges = items.filter(value => value.item.kind === 'delivery_merge'); check(merges.length === 1);
    const merged = decodeDeliveryMergeItem(merges[0]!.item);
    check(candidate.producingItemId === merged.itemId && merged.sourceRunResultRef === sourceCut.snapshot.run.resultRef &&
      candidate.resultSourceRef === merged.resultSourceRef && candidate.diffRef === merged.diffRef && candidate.summaryRef === merged.summaryRef);
    const source = decodeSourceManifest(await object(candidate.resultSourceRef));
    check(source.role === 'result' && source.manifestDigest === candidate.sourceDigest && source.sourceProjectionRef === spec.sourceProjectionRef);
    stage = 'verification_plan';
    const { frozen, assembly, commands, environments } = await readInstalledVerifierInputs(spec, bytes);
    check(frozen.verifiers.length === 1 && frozen.verifiers[0]!.gate === 'required');
    const policy = await object(spec.policyRef);
    const core = { schemaVersion: 1, runId: run.id, candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef,
      verifierSpecRef: spec.verifierSpecRef, verifierSpecDigest: frozen.specDigest,
      entries: frozen.verifiers.map(entry => ({ index: entry.index, verifierId: entry.id, verifierSpecDigest: frozen.specDigest,
        verifierEntryDigest: entry.entryDigest, commandRef: entry.commandRef, commandDigest: entry.commandDigest,
        environmentRef: entry.environmentRef, environmentDigest: entry.environmentDigest, required: entry.gate === 'required', maxAttempts: entry.retries + 1 })) };
    const planRef = canonicalSha256({ ...core, planDigest: canonicalSha256(core) }), plan = decodeVerifierPlan(await object(planRef));
    same(plan, { ...core, planDigest: canonicalSha256(core) });
    const frontier = { schemaVersion: 1, kind: 'verify', phase: 'verifiers', candidateItemId: candidate.itemId,
      resultSourceRef: candidate.resultSourceRef, verifierPlanRef: planRef, nextVerifierIndex: 0, afterPass: 'delivery_approval' };
    same(await object(canonicalSha256(frontier)), frontier);
    const requestContext = { runId: run.id, frontierRef: canonicalSha256(frontier), assemblyRef: spec.assemblyRef,
      candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef, sourceDigest: candidate.sourceDigest,
      verifierPlanRef: planRef, plan, verifierSpecRef: spec.verifierSpecRef, verifierSpec: frozen, verifierIndex: 0,
      command: commands[0]!, environment: environments[0]! };
    const planned = planVerifierRequest(requestContext), opId = verifierOperationId(run.id, candidate.itemId, planRef, 0);
    const operation = cut.journal.filter((row: any) => row.opKind === 'verifier');
    const unknownParent = outcome === 'stopped' && operation.at(-1)?.phase === 'unknown';
    same(operation.map((row: any) => row.phase), ['prepared', 'dispatch_claimed', unknownParent ? 'unknown' : outcome === 'passed' ? 'completed' : 'failed']);
    const [prepared, claim, terminal] = operation;
    check(operation.every((row: any) => row.runId === run.id && row.opId === opId && row.attempt === 0 && row.replayClass === 'retry' &&
      row.requestRef === canonicalSha256(planned.request) && row.target === planned.request.targetRef && row.grantRef === prepared.grantRef));
    same(await object(prepared.requestRef), planned.request); same(await object(prepared.target), planned.target);
    stage = 'verification_grant';
    const grant = await object(prepared.grantRef); check(grant.provenance.kind === 'policy_snapshot');
    const channel = await object(grant.provenance.channelEvidenceRef);
    const evaluator = loadVerifierPolicy({ policy, policyRef: spec.policyRef, assembly, assemblyRef: spec.assemblyRef,
      principalId: policy.principalId, workspaceIdentityDigest: source.workspaceIdentityDigest, context: requestContext });
    same(grant, evaluator.grant(planned.request, planned.target, channel, grant.issuedAt, grant.expiresAt));
    check(grant.issuedAt >= candidate.createdAt && grant.expiresAt <= run.deadlineAt && prepared.timestamp >= grant.issuedAt &&
      prepared.timestamp < grant.expiresAt && claim.timestamp >= prepared.timestamp && claim.timestamp < grant.expiresAt);
    const policyRows = items.filter(value => value.item.kind === 'policy_decision' && value.item.subjectKind === 'verifier_launch');
    check(policyRows.length === 1);
    const decisionId = identityHash('cliq-verifier-policy-item-v1', run.id, opId, grant.provenance.channelEvidenceRef);
    same(policyRows[0]!.item, { schemaVersion: 1, kind: 'policy_decision', subjectKind: 'verifier_launch', itemId: decisionId, runId: run.id, opId,
      principalId: policy.principalId, decisionRef: grant.provenance.channelEvidenceRef, policyChannelEvidenceRef: grant.provenance.channelEvidenceRef,
      policyChannelEvidenceDigest: channel.evidenceDigest, createdAt: channel.evaluatedAt, decisionSource: 'direct_policy', decision: 'allow', grantRef: prepared.grantRef });
    check(policyRows[0]!.row.itemSeq > candidateRow.itemSeq && policyRows[0]!.row.createdAt <= prepared.timestamp);
    stage = 'verification_settlement';
    if (unknownParent) assertInstalledDeliveryUnknownSettlement(prepared, claim, terminal, await object(terminal.budgetSettlementRef));
    else assertInstalledDeliverySettlement(prepared, claim, terminal, await object(terminal.budgetSettlementRef), 0);
    const verifierItems = items.filter(value => value.item.kind === 'verifier_result' || value.item.kind === 'verifier_stop');
    check(verifierItems.length === (unknownParent ? 0 : 1));
    const specEntry = frozen.verifiers[0]!;
    let measurement: { retirementRef: string; endedAt: string; stdoutRef: string; stderrRef: string } | undefined;
    if (outcome === 'passed') {
      check(run.status === 'succeeded' && terminal.receiptRef && terminal.resultRef === terminal.receiptRef);
      const receipt = decodeVerificationReceipt(await object(terminal.receiptRef));
      check(receipt.runId === run.id && receipt.verifierId === specEntry.id && receipt.verifierVersion === specEntry.version && receipt.attempt === 0 &&
        receipt.leaseEpoch === claim.leaseEpoch && receipt.resultSourceRef === candidate.resultSourceRef &&
        receipt.sourceDigestBefore === candidate.sourceDigest && receipt.sourceDigestAfter === candidate.sourceDigest &&
        receipt.commandRef === specEntry.commandRef && receipt.commandDigest === specEntry.commandDigest &&
        receipt.environmentRef === specEntry.environmentRef && receipt.environmentDigest === specEntry.environmentDigest &&
        receipt.startedAt >= claim.timestamp && receipt.endedAt <= terminal.timestamp && receipt.outcome === 'passed' && receipt.terminationReason === 'exit');
      const item = decodeVerifierResultItem(verifierItems[0]!.item);
      same(item, { schemaVersion: 1, kind: 'verifier_result', itemId: identityHash('cliq-verifier-result-item-v1', run.id, opId, '0'), runId: run.id,
        candidateItemId: candidate.itemId, verifierPlanRef: planRef, verifierIndex: 0, verifierId: specEntry.id,
        opId, attempt: 0, outcome: 'passed', receiptRef: terminal.receiptRef, createdAt: terminal.timestamp });
      const result = decodeRunResult(await object(run.resultRef)), closure = decodeVerificationClosure(await object(result.verificationClosureRef));
      check(closure.verification.kind === 'local'); if (closure.verification.kind !== 'local') throw new Error('wrong local Delivery closure');
      same(closure.verification, { kind: 'local', outcome: 'verified', entries: [{ verifierIndex: 0, verifierId: specEntry.id,
        verifierSpecDigest: frozen.specDigest, verifierEntryDigest: specEntry.entryDigest, required: true,
        disposition: { kind: 'passed', verifierResultItemId: item.itemId, opId, attempt: 0, completedJournalSeq: terminal.seq, receiptRef: terminal.receiptRef } }] });
      same(result.verificationReceiptRefs, [terminal.receiptRef]);
      measurement = { retirementRef: receipt.containmentEvidenceRef, endedAt: receipt.endedAt, stdoutRef: receipt.stdoutRef, stderrRef: receipt.stderrRef };
    } else {
      stage = 'verification_cancel';
      check(run.status === 'cancelled' && run.terminalReason === 'cancelled_by_user' && run.cancelRequested && !run.resultRef && input.cancellation);
      if (!unknownParent) {
      const item = decodeVerifierStopItem(verifierItems[0]!.item), evidence = decodeVerifierStopEvidence(await object(item.containmentEvidenceRef));
      check(item.itemId === identityHash('cliq-verifier-stop-item-v1', run.id, opId, '0') && item.runId === run.id && item.opId === opId &&
        item.attempt === 0 && item.candidateItemId === candidate.itemId && item.verifierPlanRef === planRef && item.verifierIndex === 0 &&
        item.verifierId === specEntry.id && item.stopIntent === 'cancelled_by_user' && item.stopIntentRef === run.stopIntentRef &&
        terminal.errorRef === item.containmentEvidenceRef && !terminal.receiptRef && !terminal.resultRef && item.createdAt === terminal.timestamp);
      check(evidence.runId === run.id && evidence.verifierId === specEntry.id && evidence.verifierVersion === specEntry.version && evidence.attempt === 0 &&
        evidence.leaseEpoch === claim.leaseEpoch && evidence.resultSourceRef === candidate.resultSourceRef &&
        evidence.sourceDigestBefore === candidate.sourceDigest && evidence.sourceDigestAfter === candidate.sourceDigest &&
        evidence.commandRef === specEntry.commandRef && evidence.commandDigest === specEntry.commandDigest &&
        evidence.environmentRef === specEntry.environmentRef && evidence.environmentDigest === specEntry.environmentDigest &&
        evidence.stopIntentRef === run.stopIntentRef && evidence.startedAt >= claim.timestamp && evidence.endedAt <= terminal.timestamp && evidence.terminationReason === 'controller_stop');
      measurement = { retirementRef: evidence.retirementRef, endedAt: evidence.endedAt, stdoutRef: evidence.stdoutRef, stderrRef: evidence.stderrRef };
      }
      const stop = decodeAgentStop(await object(run.stopIntentRef), run), control = input.cancellation!;
      check(stop.origin === 'user_cancel'); if (stop.origin !== 'user_cancel') throw new Error('wrong Delivery Stop');
      const { requestDigest: _digest, ...requestCore } = control.request;
      check(control.request.method === 'run.cancel' && control.request.runId === run.id && control.request.requestDigest === canonicalSha256(requestCore) &&
        control.request.requestId === stop.requestId && stop.principalId === policy.principalId && control.response.ok === true &&
        control.response.result?.method === 'run.cancel' && control.response.result.snapshot.run.stopIntentRef === run.stopIntentRef);
      const cancelledSnapshot = control.response.result.snapshot;
      check(cancelledSnapshot.operation === 'delivery' && cancelledSnapshot.schemaVersion === 1 &&
        cancelledSnapshot.run.id === run.id && cancelledSnapshot.run.sessionId === run.sessionId && cancelledSnapshot.run.specRef === run.specRef &&
        cancelledSnapshot.run.createdAt === run.createdAt && cancelledSnapshot.run.deadlineAt === run.deadlineAt &&
        cancelledSnapshot.run.cancelRequested && cancelledSnapshot.run.revision === control.request.expectedRevision + 1 &&
        cancelledSnapshot.run.revision <= run.revision && cancelledSnapshot.run.updatedAt === stop.createdAt);
      same(await object(canonicalSha256(control.response)), control.response);
    }
    let physical: { checkpoint: any; identity: InstalledDeliveryVerifierRetirementIdentity };
    if (unknownParent) {
      stage = 'verification_parent_retirement';
      check(input.readParentRetirement);
      physical = await assertInstalledVerifierParentRetirement({ cut, spec, candidate, planRef, prepared, claim, terminal,
        reader: { readCanonical: object, async *readChunks(ref, byteLength) {
          const value = await bytes(ref); check(value.byteLength === byteLength); yield value;
        } }, readOwnerHistory: input.readOwnerHistory, readParentRetirement: input.readParentRetirement! });
      check(physical.checkpoint.runItemSeq === cut.items.length && physical.checkpoint.runItemSeq >= policyRows[0]!.row.itemSeq);
    } else {
      stage = 'verification_child_retirement';
      check(measurement);
      physical = await assertInstalledVerifierRetirement({ run, checkpoints: cut.checkpoints, prepared, claim, terminal,
        requestContext, measurement: measurement!, readRetainedArtifact: bytes, readOwnerHistory: input.readOwnerHistory });
      const row = verifierItems[0]!.row;
      check(physical.checkpoint.runItemSeq === row.itemSeq && row.itemSeq > policyRows[0]!.row.itemSeq);
    }
    stage = 'verification_workspace';
    const state = decodeWorkspaceState(await object(physical.checkpoint.workspaceStateRef));
    check(state.baseWorkspaceManifestRef === spec.baseWorkspaceManifestRef && state.runId === run.id &&
      state.entriesRef === source.entriesRef && state.sourceProjectionDigest === source.sourceProjectionDigest &&
      state.invalidatedEphemeralPaths.length === 0);
    const base = decodeSourceManifest(await object(spec.baseWorkspaceManifestRef));
    same(source.git ?? null, base.git ?? null);
    if (input.expectedGit) await assertInstalledGitState(installedGitDataReader(bytes), base, state,
      decodeSandboxProfile(await object(spec.sandboxProfileRef)).resources, true);
    else check(!base.git && !state.privateGitStateRef);
    stage = 'verification_context';
    for (const checkpoint of cut.checkpoints.filter((cp: any) => cp.runItemSeq >= candidateRow.itemSeq)) {
      const context = decodeContextManifest(await object(checkpoint.contextManifestRef));
      check(context.runId === run.id && context.assemblyRef === spec.assemblyRef && context.admittedContextRef === spec.admittedContextRef && context.throughItemSeq === checkpoint.runItemSeq);
      validateContextItems(context, items.slice(0, checkpoint.runItemSeq).map(value => ({ itemSeq: value.row.itemSeq, itemRef: value.row.payloadRef, item: value.item })));
    }
    return physical.identity;
  } catch { throw new InstalledDeliveryOutcomeError(stage); }
}

/** Source qualification is independently performed by the original full
 * verifier campaign helper before this function. Only rehashed retained bytes
 * enter here; no SQLite/native handle, callback authority or filesystem
 * mutation is accepted. Every reconnect invokes this complete walk again. */
export async function assertInstalledDeliveryOutcome(input: {
  cut: Record<string, any>; sessionCut: Record<string, any>; sourceCut: Record<string, any>; sourceResultRef: string;
  expectedFiles: readonly { path: string; text: string }[]; kind: 'publish' | 'no_op' | 'merge';
  expectedGit?: true;
  readRetainedArtifact: (ref: string) => Promise<Buffer>;
  readOwnerHistory: () => Promise<readonly StateOwnerRecordV1[]>;
}) {
  let stage: InstalledDeliveryDiagnosticStage = 'public_cut';
  try {
    const { cut, sourceCut, kind } = input, run = cut.snapshot?.run, sourceRun = sourceCut.snapshot?.run;
    check(cut.method === 'run.get' && cut.snapshot.schemaVersion === 1 && cut.snapshot.operation === 'delivery' &&
      run?.status === 'succeeded' && run.terminalReason === 'verified' && run.resultRef && !run.stopIntentRef &&
      !run.cancelRequested && !run.activeWorkerLaunchId && run.nextStep === null && !run.frontierRef &&
      sourceRun?.status === 'succeeded' && sourceRun.resultRef === input.sourceResultRef && run.id !== sourceRun.id);
    check(Array.isArray(cut.items) && cut.items.length > 0 && cut.items.length === cut.highWaterItemSeq &&
      cut.nextItemSeq === cut.highWaterItemSeq && cut.snapshot.latestRunItemSeq === cut.highWaterItemSeq &&
      cut.nextJournalSeq === cut.highWaterJournalSeq && cut.journal.length === cut.highWaterJournalSeq &&
      cut.nextCheckpointCursor === cut.highWaterCheckpointCursor);
    const cache = new Map<string, Buffer>();
    const bytes = async (ref: string) => {
      check(typeof ref === 'string' && /^[a-f0-9]{64}$/u.test(ref));
      let value = cache.get(ref);
      if (!value) { value = await input.readRetainedArtifact(ref); check(Buffer.isBuffer(value) && value.length <= 1_048_576 && sha256Bytes(value) === ref); cache.set(ref, value); }
      check(cache.size <= 256); return value;
    };
    const object = async (ref: string): Promise<any> => {
      const value = await bytes(ref), data = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(value));
      check(canonicalJsonBytes(data).equals(value)); return data;
    };
    const items = await Promise.all(cut.items.map(async (row: any, index: number) => {
      check(row.itemSeq === index + 1 && row.payloadRef === row.payloadDigest);
      const item = await object(row.payloadRef); check(item.itemId === row.itemId && item.runId === run.id && item.createdAt === row.createdAt);
      return { row, item };
    }));
    stage = 'source_and_merge';
    const spec = decodeRunSpec(await object(run.specRef)), originalSpec = decodeRunSpec(await object(sourceRun.specRef));
    check(spec.operation === 'delivery' && spec.credentialGrantRefs.length === 0);
    for (const key of ['objectiveRef', 'sourceProjectionRef', 'assemblyRef', 'policyRef', 'sandboxProfileRef', 'verifierSpecRef'] as const)
      check(spec[key] === originalSpec[key]);
    for (const key of ['modelTokens', 'costMicros', 'repairAttempts', 'childDepth', 'childConcurrency'] as const) check(spec.budgets[key] === 0);
    const merges = items.filter(value => value.item.kind === 'delivery_merge'); check(merges.length === 1);
    const merged = decodeDeliveryMergeItem(merges[0]!.item), plan = decodeDeliveryPlan(await object(merged.deliveryPlanRef));
    const original = decodeRunResult(await object(input.sourceResultRef)), result = decodeRunResult(await object(run.resultRef));
    check(merged.sourceRunResultRef === input.sourceResultRef && merged.sourceBaseRef === original.baseSourceRef &&
      merged.sourceDesiredRef === original.resultSourceRef && merged.capturedWorkspaceRef === spec.baseWorkspaceManifestRef &&
      plan.sourceRunResultRef === input.sourceResultRef && plan.deliveryRunId === run.id &&
      plan.sourceBaseRef === merged.sourceBaseRef && plan.sourceDesiredRef === merged.sourceDesiredRef && plan.capturedWorkspaceRef === merged.capturedWorkspaceRef &&
      plan.desiredSourceRef === merged.resultSourceRef && result.runId === run.id && result.baseSourceRef === merged.capturedWorkspaceRef &&
      result.resultSourceRef === merged.resultSourceRef && result.diffRef === merged.diffRef && result.summaryRef === merged.summaryRef);
    const source = decodeSourceManifest(await object(result.resultSourceRef)), entries = decodeWorkspaceEntries(await object(source.entriesRef));
    check(source.role === 'result' && source.sourceProjectionRef === spec.sourceProjectionRef && source.treeDigest === entries.treeDigest);
    const originalDesired = decodeSourceManifest(await object(original.resultSourceRef));
    const captured = decodeSourceManifest(await object(spec.baseWorkspaceManifestRef));
    check(!!source.git === !!input.expectedGit && !!captured.git === !!input.expectedGit && !!originalDesired.git === !!input.expectedGit);
    same(source.git ?? null, captured.git ?? null); same(source.git ?? null, originalDesired.git ?? null);
    if (input.expectedGit) {
      const profile = decodeSandboxProfile(await object(spec.sandboxProfileRef));
      const gitReader = installedGitDataReader(bytes), projectionSpec = decodeSourceProjection(await object(spec.sourceProjectionRef));
      await readSourceProjectionData(gitReader, captured, projectionSpec, profile.resources);
    }
    for (const key of ['workspaceIdentityDigest', 'sourceProjectionRef', 'sourceProjectionDigest', 'frozenIgnoreRulesRef', 'frozenIgnoreRulesDigest'] as const)
      check(source[key] === originalDesired[key]);
    const expectedFiles = [...input.expectedFiles].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
    same(entries.entries.map(entry => ({ path: entry.path, kind: entry.kind })), expectedFiles.map(entry => ({ path: entry.path, kind: 'file' })));
    for (const [index, entry] of entries.entries.entries()) {
      check(entry.kind === 'file'); if (entry.kind !== 'file') throw new Error('wrong fixed fixture entry');
      const actual = await bytes(entry.blobRef), expected = Buffer.from(expectedFiles[index]!.text);
      check(entry.mode === 0o644 && entry.size === expected.length && actual.equals(expected));
    }
    const diff = decodeWorkspaceDiff(await object(result.diffRef));
    check(diff.baseSourceRef === result.baseSourceRef && diff.resultSourceRef === result.resultSourceRef);
    check(plan.forwardOperations.length === (kind === 'no_op' ? 0 : 1) && plan.abortOperations.length === 0);
    if (kind === 'no_op') check(diff.operations.length === 0 && result.resultSourceRef === original.resultSourceRef);
    else check(plan.forwardOperations[0]!.kind === 'replace' && plan.forwardOperations[0]!.path === 'example.txt' &&
      diff.operations.length === 1 && diff.operations[0]!.path === 'example.txt' && diff.operations[0]!.kind === 'modify');

    stage = 'direct_policy';
    const policies = items.filter(value => value.item.kind === 'policy_decision' && value.item.subjectKind === 'delivery_plan');
    const decisions = items.filter(value => value.item.kind === 'delivery_decision');
    check(policies.length === (kind === 'no_op' ? 0 : 1) && decisions.length === policies.length);
    if (kind !== 'no_op') {
      const policyItem = policies[0]!.item, decision = decisions[0]!.item;
      check(policyItem.decisionSource === 'direct_policy' && policyItem.decision === 'allow' && decision.decision === 'allow' &&
        decision.grantRef === policyItem.grantRef && decision.decisionRef === policyItem.decisionRef && decision.deliveryPlanRef === merged.deliveryPlanRef);
      const grant = await object(policyItem.grantRef), evidence = await object(policyItem.policyChannelEvidenceRef);
      const topology = decodeDeliveryCaptureTopology(await object(plan.captureTopologyRef));
      const context = { runId: run.id, plan, planRef: merged.deliveryPlanRef, assemblyRef: spec.assemblyRef,
        frontierRef: grant.frontierRef, workspaceIdentityRef: topology.workspaceIdentityRef, workspaceIdentityDigest: topology.workspaceIdentityDigest };
      const policy = await object(spec.policyRef), assembly = decodeRetainedRunAssembly(await object(spec.assemblyRef));
      const evaluator = loadDeliveryPolicy({ policy, policyRef: spec.policyRef, assembly, assemblyRef: spec.assemblyRef,
        principalId: policyItem.principalId, workspaceIdentityDigest: topology.workspaceIdentityDigest, context });
      const planned = planDeliveryRequest(context);
      same(await object(grant.requestRef), planned.request); same(await object(grant.targetRef), planned.target);
      same(evidence, evaluator.evaluate(planned.request, planned.target, evidence.evaluatedAt));
      same(grant, evaluator.grant(planned.request, planned.target, evidence, grant.issuedAt, run.deadlineAt));
      check(grant.maxDispatchedAttempts === 0 && policyItem.decisionRef === canonicalSha256(evidence) &&
        policyItem.policyChannelEvidenceDigest === evidence.evidenceDigest && grant.issuedAt === policyItem.createdAt &&
        decision.createdAt === policyItem.createdAt && decision.approvalOpId === grant.opId &&
        policies[0]!.row.itemSeq < decisions[0]!.row.itemSeq);
    }

    stage = 'settlements';
    const counts = assertInstalledDeliveryClaims(cut, { publish: kind === 'no_op' ? 0 : 1, verifier: kind === 'merge' ? 1 : 0 });
    let settledToolCalls = 0;
    for (const row of cut.journal) if (row.budgetSettlementRef) {
      const attempt = cut.journal.filter((entry: any) => entry.opId === row.opId && entry.attempt === row.attempt);
      assertInstalledDeliverySettlement(attempt[0]!, attempt[1]!, row, await object(row.budgetSettlementRef), settledToolCalls++);
    }
    stage = 'verification';
    const closure = decodeVerificationClosure(await object(result.verificationClosureRef));
    check(closure.runId === run.id && closure.resultSourceRef === result.resultSourceRef);
    const verifierRetirementIdentities: InstalledVerifierRetirementIdentity[] = [];
    if (kind === 'merge') {
      verifierRetirementIdentities.push(await assertInstalledDeliveryVerifier({ cut, sourceCut, outcome: 'passed', readRetainedArtifact: bytes,
        readOwnerHistory: input.readOwnerHistory, ...(input.expectedGit ? { expectedGit: true as const } : {}) }));
    } else {
      check(closure.verification.kind === 'inherited_verified');
      const inherited = closure.verification; if (inherited.kind !== 'inherited_verified') throw new Error('wrong inherited verification');
      const provenance = decodeInheritedVerificationProvenance(await object(inherited.inheritedProvenanceRef));
      check(inherited.sourceRunId === sourceRun.id && inherited.sourceRunResultRef === input.sourceResultRef &&
        inherited.sourceVerificationClosureRef === original.verificationClosureRef && provenance.deliveryRunId === run.id &&
        provenance.resultSourceRef === original.resultSourceRef && result.verificationProvenanceRef === inherited.inheritedProvenanceRef);
      same(result.verificationReceiptRefs, original.verificationReceiptRefs);
    }

    stage = 'publication_receipts';
    const results = items.filter(value => value.item.kind === 'publication_path_result');
    const publication = await assertInstalledDeliveryPublication({ cut, readRetainedArtifact: bytes, readOwnerHistory: input.readOwnerHistory,
      ...(input.expectedGit ? { expectedGit: true as const } : {}) });
    check(results.length === plan.forwardOperations.length && publication.planRef === merged.deliveryPlanRef &&
      publication.projectionRef === result.deliveryTerminalProjectionEvidenceRef && publication.publishClaims === counts.publishClaims &&
      publication.progressCount === results.length && publication.receiptCount === results.length &&
      publication.arenaRetirementCount === results.length);

    stage = 'terminal_projection';
    check(result.deliveryTerminalProjectionEvidenceRef);
    const projection = decodeDeliveryTerminalProjectionEvidence(await object(result.deliveryTerminalProjectionEvidenceRef!));
    check(projection.deliveryRunId === run.id && projection.deliveryPlanRef === merged.deliveryPlanRef &&
      projection.selectedBranch === 'forward_finalize' && projection.observedSourceRef === result.resultSourceRef &&
      projection.observedAt <= run.updatedAt && Date.parse(run.updatedAt) - Date.parse(projection.observedAt) <= 5000);
    same(projection.forwardResultItemRefs, results.map(value => value.row.payloadRef));
    const proof = decodePublicationProof(await object(projection.projectionClosureEvidenceRef));
    check(proof.kind === 'projection_closure'); if (proof.kind !== 'projection_closure') throw new Error('wrong projection closure');
    check(proof.observedSourceRef === result.resultSourceRef && proof.selectedBranch === 'forward_finalize');
    const absence = decodePublicationProof(await object(projection.transientAbsenceEvidenceRef));
    check(absence.kind === 'transient_absence');
    const git = decodePublicationProof(await object(projection.gitIndexUnchangedEvidenceRef)); check(git.kind === 'git_index_unchanged');
    for (const state of projection.observedPathStates) {
      const observed = decodePublicationProof(await object(state.evidenceRef));
      check(observed.kind === 'path_observation'); if (observed.kind !== 'path_observation') throw new Error('wrong fixed fixture path observation');
      check(observed.observation.location.kind === 'workspace' && observed.observation.location.path === state.path);
      same(observed.observation.state, state.state);
    }
    check(projection.evidenceDigest === digestOmitting(projection, 'evidenceDigest'));
    const publicationCheckpointId = plan.forwardOperations.length ? deliveryPublicationTerminalCheckpointId(run.id, merged.deliveryPlanRef)
      : deliveryPublicationCheckpointId(run.id, merged.deliveryPlanRef);
    const publicationCp = cut.checkpoints.find((checkpoint: any) => checkpoint.id === publicationCheckpointId);
    const finalCp = cut.checkpoints.find((checkpoint: any) => checkpoint.id === run.latestCheckpointId);
    check(publicationCp && finalCp && publicationCp.journalSeq === cut.journal.length && publicationCp.runItemSeq === cut.items.length &&
      finalCp.journalSeq === publicationCp.journalSeq && finalCp.runItemSeq === publicationCp.runItemSeq &&
      finalCp.contextManifestRef === publicationCp.contextManifestRef && finalCp.workspaceStateRef === publicationCp.workspaceStateRef &&
      finalCp.createdAt === publicationCp.createdAt && finalCp.createdAt === run.updatedAt &&
      publicationCp.basedOnRunRevision + 1 === finalCp.basedOnRunRevision && finalCp.basedOnRunRevision === run.revision - 1 &&
      finalCp.id === identityHash('cliq-run-result-checkpoint-v1', run.id, closure.candidateItemId, run.resultRef));
    stage = 'session_publication';
    const sessionCut = input.sessionCut, session = sessionCut.snapshot?.session;
    check(sessionCut.method === 'session.get' && session?.id === run.sessionId && sessionCut.highWaterItemSeq === session.latestItemSeq &&
      sessionCut.nextItemSeq === sessionCut.highWaterItemSeq);
    const terminals: Array<{ row: any; payload: any }> = [];
    for (const row of sessionCut.items) {
      const payload = await object(row.payloadRef);
      if (payload.runId === run.id) terminals.push({ row, payload });
    }
    check(terminals.length === 1); const terminal = terminals[0]!;
    const admitted = decodeAdmittedContext(await object(spec.admittedContextRef)), summary = await object(result.summaryRef);
    verifyModelText(summary);
    check(terminal.row.itemId === identityHash('cliq-session-run-terminal-item-v1', run.sessionId, run.id) &&
      terminal.row.kind === 'run_terminal' && terminal.row.createdAt === run.updatedAt);
    same(terminal.payload, { schemaVersion: 1, format: 'cliq-session-run-terminal-v1', kind: 'run_terminal',
      itemKey: `run-terminal:${run.id}`, runId: run.id, operation: 'delivery', admittedSessionItemSeq: admitted.throughSessionItemSeq,
      status: 'succeeded', terminalReason: 'verified', resultRef: run.resultRef, summaryRef: result.summaryRef, summaryDigest: summary.textDigest });
    const sessionProjection = decodeSessionProjection(await object(session.contextProjectionRef));
    check(sessionProjection.sessionId === run.sessionId && sessionProjection.contextRevision === session.contextRevision &&
      sessionProjection.throughItemSeq === session.latestItemSeq);
    same(sessionProjection.segments.filter(segment => segment.fromItemSeq <= terminal.row.itemSeq && segment.throughItemSeq >= terminal.row.itemSeq),
      [{ kind: 'raw', fromItemSeq: terminal.row.itemSeq, throughItemSeq: terminal.row.itemSeq, items: [{ sourceSessionId: run.sessionId,
        itemSeq: terminal.row.itemSeq, itemId: terminal.row.itemId, kind: 'run_terminal', payloadRef: terminal.row.payloadRef }] }]);
    return { qualified: true as const, kind, runId: run.id, resultRef: run.resultRef as string,
      verification: kind === 'merge' ? 'local' as const : 'inherited_verified' as const, ...counts,
      verifierRetirementIdentities, publicationWorkerRetirement: publication.publicationWorkerRetirement,
      completeRetainedArtifactWalk: true as const, directPolicyOnly: true as const, publicationProjectionMatched: true as const };
  } catch (error) {
    if (typeof error === 'object' && error !== null && deliveryOutcomeErrors.has(error)) throw error;
    throw new InstalledDeliveryOutcomeError(stage);
  }
}
