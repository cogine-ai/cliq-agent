import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash } from '../kernel/identity.js';
import type { Checkpoint, ContinuationItem, Run, RunFrontier, RunItemReferenceV1, RunSpec } from '../kernel/types.js';
import type { VerifierApprovalDecisionV1, VerifierApprovalWait, VerifierOperationGrantV1,
  VerifierPolicyChannelEvidenceV1, VerifierPolicyDecisionItem, VerifierRequestV1, VerifierTargetV1 } from '../kernel/verifier-invocation.js';
import type { VerifierSkipItem } from '../kernel/verifier.js';
import { requireEqual } from '../policy/runtime-authority.js';
import type { AgentStopIntent } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readHistoricalControlChannel } from './control-channel.js';
import { decodeInstalledControlResponse } from '../kernel/control-wire.js';
import { readCheckpoint, readControlRequest, readRun } from './rows.js';
import { readSession, readSessionPrincipalId } from './rows.js';
import { decodeContextManifest, decodeWorkspaceIdentity } from './decoders.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import { decodeVerifierCommand, decodeVerifierEnvironment, decodeVerifierSpec, decodeVerifierSkipItem } from './verifier-artifacts.js';
import { decodeFinalCandidateItem, decodeVerifierPlan } from './result-artifacts.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import { readInvocationJournal } from './repositories/journal.js';
import { stopInvocationHistory } from '../runtime/stop.js';
import { decodeVerificationReceipt } from './verifier-artifacts.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { loadVerifierPolicy, planVerifierRequest } from './verifier-policy.js';
import { decodeVerifierAuthorizationTemplate } from './verifier-template.js';

export type VerifierPermissionContext = { run: Run; spec: RunSpec; request: VerifierRequestV1; target: VerifierTargetV1;
  evaluator: ReturnType<typeof loadVerifierPolicy> };
type VerifierDecisionContext = Pick<VerifierPermissionContext, 'request' | 'target'> & { run: Pick<Run, 'id'> };
export const verifierApprovalCheckpointId = (ref: string) => identityHash('cliq-verifier-approval-checkpoint-v1', ref);
export const verifierApprovalDecisionCheckpointId = (ref: string) => identityHash('cliq-verifier-approval-decision-checkpoint-v1', ref);
export const verifierPolicyItemId = (runId: string, opId: string, ref: string) => identityHash('cliq-verifier-policy-item-v1', runId, opId, ref);
export const verifierSkipItemId = (runId: string, opId: string, ref: string) => identityHash('cliq-verifier-skip-item-v1', runId, opId, ref);

async function readPermissionCheckpointContext(driver: SqliteDriver, artifacts: ArtifactCatalog,
  context: VerifierPermissionContext, checkpoint: Checkpoint) {
  const manifest = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  const rows = driver.prepare('SELECT item_id,item_seq,payload_ref,created_at FROM items WHERE run_id=? AND item_seq<=? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: bigint; payload_ref: string; created_at: string }>(context.run.id, BigInt(checkpoint.runItemSeq));
  if (manifest.runId !== context.run.id || manifest.assemblyRef !== context.spec.assemblyRef ||
      manifest.admittedContextRef !== context.spec.admittedContextRef || manifest.throughItemSeq !== checkpoint.runItemSeq ||
      rows.length !== checkpoint.runItemSeq || rows.some((row, index) => Number(row.item_seq) !== index + 1 || row.created_at > checkpoint.createdAt))
    throw new TypeError('verifier permission lost its complete original context prefix');
  const items = await artifacts.mapReads(rows, async row => ({ itemSeq: Number(row.item_seq), itemRef: row.payload_ref,
    item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payload_ref) }));
  validateContextItems(manifest, items);
  const index = rows.findIndex(row => row.item_id === context.target.candidateItemId);
  if (index < 0) throw new TypeError('verifier permission preceded its actual durable candidate');
  const candidate = decodeFinalCandidateItem(items[index]!.item);
  if (candidate.itemId !== context.target.candidateItemId || candidate.runId !== context.run.id || candidate.operation !== context.spec.operation ||
      candidate.createdAt !== rows[index]!.created_at || candidate.resultSourceRef !== context.target.resultSourceRef || candidate.sourceDigest !== context.target.sourceDigest)
    throw new TypeError('verifier permission borrowed another original candidate');
}

/** Original request reconstruction for historical subjects, including a Run
 * whose current frontier has since advanced. No RecoveryClosure recursion. */
export async function readVerifierPermissionContext(driver: SqliteDriver, artifacts: ArtifactCatalog, run: Run, spec: RunSpec,
  requestRef: string, targetRef: string): Promise<VerifierPermissionContext> {
  const request = await readCanonicalArtifact<VerifierRequestV1>(artifacts, requestRef);
  const target = await readCanonicalArtifact<VerifierTargetV1>(artifacts, targetRef);
  const verifierSpec = decodeVerifierSpec(await readCanonicalArtifact(artifacts, spec.verifierSpecRef));
  const entry = verifierSpec.verifiers[target.verifierIndex];
  if (!entry) throw new TypeError('verifier permission has no original frozen entry');
  const plan = decodeVerifierPlan(await readCanonicalArtifact(artifacts, target.verifierPlanRef));
  const command = decodeVerifierCommand(await readCanonicalArtifact(artifacts, entry.commandRef));
  const environment = decodeVerifierEnvironment(await readCanonicalArtifact(artifacts, entry.environmentRef));
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, spec.assemblyRef));
  const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, spec.policyRef);
  const session = readSession(driver, run.sessionId), principalId = readSessionPrincipalId(driver, session.id);
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, session.workspaceIdentityRef));
  const context = { runId: run.id, frontierRef: request.frontierRef, assemblyRef: spec.assemblyRef,
    candidateItemId: target.candidateItemId, resultSourceRef: target.resultSourceRef, sourceDigest: target.sourceDigest,
    verifierPlanRef: target.verifierPlanRef, plan, verifierSpecRef: spec.verifierSpecRef, verifierSpec,
    verifierIndex: target.verifierIndex, command, environment };
  const planned = planVerifierRequest(context);
  requireEqual(request, planned.request, 'verifier permission original request'); requireEqual(target, planned.target, 'verifier permission original target');
  if (canonicalSha256(request) !== requestRef || canonicalSha256(target) !== targetRef) throw new TypeError('verifier permission refs differ');
  const evaluator = loadVerifierPolicy({ policy, policyRef: spec.policyRef, assembly, assemblyRef: spec.assemblyRef,
    principalId, workspaceIdentityDigest: workspace.identityDigest, context });
  return { run, spec, request, target, evaluator };
}

export function verifierDenial(context: VerifierDecisionContext, evidence: VerifierPolicyChannelEvidenceV1,
  decisionRef: string, createdAt: string, approval?: VerifierApprovalDecisionV1) {
  const { run, request, target } = context;
  const skip: VerifierSkipItem | undefined = target.required ? undefined : {
    schemaVersion: 1, kind: 'verifier_skip', itemId: verifierSkipItemId(run.id, request.opId, decisionRef), runId: run.id,
    candidateItemId: target.candidateItemId, verifierPlanRef: target.verifierPlanRef, verifierIndex: target.verifierIndex,
    verifierId: target.verifierId, decisionRef, createdAt, ...(approval ? { outcome: 'skipped_by_user' as const } :
      { outcome: 'skipped_by_policy' as const, policyChannelEvidenceDigest: evidence.evidenceDigest }) };
  const stop: AgentStopIntent | undefined = !target.required ? undefined : approval ? {
    schemaVersion: 1, runId: run.id, createdAt, origin: 'user_cancel', targetStatus: 'cancelled', reason: 'cancelled_by_user',
    principalId: approval.principalId, requestId: approval.requestId } : {
    schemaVersion: 1, runId: run.id, createdAt, origin: 'policy_deny', subjectKind: 'verifier', targetStatus: 'failed',
    reason: 'verification_failed', opId: request.opId, policyChannelEvidenceRef: canonicalSha256(evidence), policyChannelEvidenceDigest: evidence.evidenceDigest };
  return { skip, stop };
}
export function verifierPolicyItem(context: VerifierDecisionContext, evidence: VerifierPolicyChannelEvidenceV1,
  decisionRef: string, createdAt: string, grant?: VerifierOperationGrantV1, approval?: VerifierApprovalDecisionV1): VerifierPolicyDecisionItem {
  const { request, run } = context;
  const common = { schemaVersion: 1 as const, kind: 'policy_decision' as const, subjectKind: 'verifier_launch' as const,
    itemId: verifierPolicyItemId(run.id, request.opId, decisionRef), runId: run.id, opId: request.opId, principalId: evidence.principalId,
    decisionRef, policyChannelEvidenceRef: canonicalSha256(evidence), policyChannelEvidenceDigest: evidence.evidenceDigest, createdAt,
    ...(approval ? { decisionSource: 'interactive_approval' as const, waitingSubjectRef: approval.waitingSubjectRef }
      : { decisionSource: 'direct_policy' as const }) };
  if (grant) return { ...common, decision: 'allow', grantRef: canonicalSha256(grant) };
  const { skip, stop } = verifierDenial(context, evidence, decisionRef, createdAt, approval);
  return { ...common, decision: 'deny', denialOutcome: skip ? { kind: 'advisory_verifier_skipped', subjectKind: 'verifier_launch',
    verifierSkipItemRef: canonicalSha256(skip) } : { kind: 'stop_intent', subjectKind: 'verifier_launch', stopIntentRef: canonicalSha256(stop) } };
}

export async function readVerifierApprovalWait(driver: SqliteDriver, artifacts: ArtifactCatalog, context: VerifierPermissionContext, ref: string) {
  const wait = await readCanonicalArtifact<VerifierApprovalWait>(artifacts, ref);
  if (!wait?.subject || wait.subject.kind !== 'verifier_launch') throw new TypeError('approval is not the exact verifier subject');
  const evidence = await readCanonicalArtifact<VerifierPolicyChannelEvidenceV1>(artifacts, wait.subject.policyChannelEvidenceRef);
  requireEqual(wait, context.evaluator.approvalWait(context.request, context.target, evidence, wait.createdFromRevision), 'verifier original approval wait');
  requireEqual(await readCanonicalArtifact(artifacts, evidence.requestRef), context.request, 'verifier original waiting request');
  requireEqual(await readCanonicalArtifact(artifacts, evidence.targetRef), context.target, 'verifier original waiting target');
  const checkpoint = readCheckpoint(driver, verifierApprovalCheckpointId(ref));
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, wait.frontierRef);
  const plan = decodeVerifierPlan(await readCanonicalArtifact(artifacts, context.target.verifierPlanRef));
  requireEqual(frontier, { schemaVersion: 1, kind: 'verify', phase: 'verifiers', candidateItemId: context.target.candidateItemId,
    resultSourceRef: context.target.resultSourceRef, verifierPlanRef: context.target.verifierPlanRef, nextVerifierIndex: context.target.verifierIndex,
    afterPass: context.spec.operation === 'agent' ? 'finalize' : 'delivery_approval',
    ...(plan.dependencyPlanRef === undefined ? {} : { dependencyPlanRef: plan.dependencyPlanRef }) }, 'verifier original waiting frontier');
  if (canonicalSha256(wait) !== ref || wait.createdAt < context.run.createdAt || wait.createdAt >= context.run.deadlineAt ||
      checkpoint.runId !== context.run.id || checkpoint.reason !== 'auto' || checkpoint.basedOnRunRevision !== wait.createdFromRevision || checkpoint.createdAt !== wait.createdAt)
    throw new TypeError('verifier wait lost its original atomic Checkpoint');
  const journal = readInvocationJournal(driver, context.run.id);
  if (checkpoint.journalSeq > journal.length || [...stopInvocationHistory(journal.slice(0, checkpoint.journalSeq)).values()]
    .some(({ entry }) => !['completed', 'failed'].includes(entry.phase)))
    throw new TypeError('verifier wait overtook an unsettled original invocation');
  await readPermissionCheckpointContext(driver, artifacts, context, checkpoint);
  const source = await (await import('./result-source.js')).readCandidateSource(artifacts, context.spec, checkpoint.workspaceStateRef);
  if (source.sourceRef !== context.target.resultSourceRef || source.source.manifestDigest !== context.target.sourceDigest)
    throw new TypeError('verifier approval wait changed its original ready candidate source');
  return { wait, evidence, checkpoint };
}

export async function readVerifierWaitingRun(driver: SqliteDriver, artifacts: ArtifactCatalog, run: Run, spec: RunSpec) {
  if (run.status !== 'waiting' || run.waitingReason !== 'approval' || !run.waitingOnRef || run.activeWorkerLaunchId)
    throw new TypeError('verifier requires its actual worker-free approval wait');
  const wait = await readCanonicalArtifact<VerifierApprovalWait>(artifacts, run.waitingOnRef);
  const evidence = await readCanonicalArtifact<VerifierPolicyChannelEvidenceV1>(artifacts, wait.subject.policyChannelEvidenceRef);
  const context = await readVerifierPermissionContext(driver, artifacts, run, spec, evidence.requestRef, evidence.targetRef);
  const proof = await readVerifierApprovalWait(driver, artifacts, context, run.waitingOnRef);
  if (run.frontierRef !== wait.frontierRef || run.latestCheckpointId !== proof.checkpoint.id)
    throw new TypeError('verifier wait lost its original frontier or ready Checkpoint');
  return { ...proof, context };
}

/** Full historical control closure; a decision artifact alone is not consent. */
export async function readVerifierApproval(driver: SqliteDriver, artifacts: ArtifactCatalog, context: VerifierPermissionContext,
  decisionRef: string) {
  const decision = await readCanonicalArtifact<VerifierApprovalDecisionV1>(artifacts, decisionRef);
  const proof = await readVerifierApprovalWait(driver, artifacts, context, decision.waitingSubjectRef);
  const grant = context.evaluator.approve(context.request, context.target, proof.evidence, proof.wait, decision, context.run.deadlineAt);
  const control = readControlRequest(driver, decision.principalId, 'run.approve', decision.requestId);
  if (!control || control.requestDigest !== decision.requestDigest || control.channelIdentityRef !== decision.channelIdentityRef ||
      control.channelIdentityDigest !== decision.channelIdentityDigest || control.committedAt !== decision.createdAt)
    throw new TypeError('verifier approval lost its exact authenticated control transaction');
  const { channel } = await readHistoricalControlChannel(driver, artifacts, decision);
  if (channel.openedAt > decision.createdAt) throw new TypeError('verifier approval preceded its authenticated channel');
  const request = { protocolVersion: 1 as const, method: 'run.approve' as const, runId: context.run.id, requestId: decision.requestId,
    requestDigest: decision.requestDigest, expectedRevision: decision.expectedRunRevision, waitingOnRef: decision.waitingSubjectRef,
    decision: decision.decision, ...(decision.requestedTtlMs === undefined ? {} : { ttlMs: decision.requestedTtlMs }) };
  requireEqual(await readCanonicalArtifact(artifacts, control.requestDigest), (() => { const { requestDigest: _digest, ...core } = request; return core; })(),
    'verifier original approval public request');
  const response = decodeInstalledControlResponse(await readCanonicalArtifact(artifacts, control.responseRef), request);
  if (!response.ok || response.result.method !== 'run.approve') throw new TypeError('verifier approval lacks its exact accepted response');
  const checkpoint = readCheckpoint(driver, verifierApprovalDecisionCheckpointId(decisionRef)), snapshot = response.result.snapshot;
  const expectedItem = verifierPolicyItem(context, proof.evidence, decisionRef, decision.createdAt, grant, decision);
  const row = driver.prepare('SELECT item_id,item_seq,payload_ref,created_at FROM items WHERE run_id=? AND item_id=?')
    .get<{ item_id: string; item_seq: bigint; payload_ref: string; created_at: string }>(context.run.id, expectedItem.itemId);
  if (!row || row.created_at !== decision.createdAt) throw new TypeError('verifier approval lost its original policy item');
  requireEqual(await readCanonicalArtifact(artifacts, row.payload_ref), expectedItem, 'verifier exact interactive policy item');
  const { skip, stop } = grant ? {} : verifierDenial(context, proof.evidence, decisionRef, decision.createdAt, decision);
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, proof.wait.frontierRef);
  const expectedFrontierRef = skip ? canonicalSha256({ ...frontier, nextVerifierIndex: context.target.verifierIndex + 1 }) : proof.wait.frontierRef;
  if (skip) {
    const skipRow = driver.prepare('SELECT payload_ref FROM items WHERE run_id=? AND item_id=? AND item_seq=?')
      .get<{ payload_ref: string }>(context.run.id, skip.itemId, row.item_seq + 1n);
    if (!skipRow || skipRow.payload_ref !== canonicalSha256(skip)) throw new TypeError('verifier approval lost its atomic advisory skip');
    requireEqual(await readCanonicalArtifact(artifacts, skipRow.payload_ref), skip, 'verifier original advisory skip');
  }
  if (stop) requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(stop)), stop, 'verifier original required denial');
  if (row.item_seq !== BigInt(proof.checkpoint.runItemSeq + 1) || snapshot.operation !== context.spec.operation || snapshot.run.id !== context.run.id || snapshot.run.specRef !== context.run.specRef ||
      snapshot.run.sessionId !== context.run.sessionId || snapshot.run.createdAt !== context.run.createdAt || snapshot.run.deadlineAt !== context.run.deadlineAt ||
      snapshot.run.revision !== decision.expectedRunRevision + 1 || snapshot.run.latestCheckpointId !== checkpoint.id ||
      snapshot.run.updatedAt !== decision.createdAt || snapshot.run.status !== 'queued' || snapshot.run.nextStep !== 'verify' || snapshot.run.activeWorkerLaunchId ||
      snapshot.run.waitingOnRef || snapshot.run.waitingReason || checkpoint.runId !== context.run.id ||
      checkpoint.reason !== 'auto' || checkpoint.basedOnRunRevision !== decision.expectedRunRevision || checkpoint.createdAt !== decision.createdAt ||
      checkpoint.workspaceStateRef !== proof.checkpoint.workspaceStateRef || checkpoint.journalSeq !== proof.checkpoint.journalSeq ||
      checkpoint.runItemSeq !== Number(row.item_seq) + (skip ? 1 : 0) || snapshot.latestRunItemSeq !== checkpoint.runItemSeq ||
      snapshot.run.frontierRef !== expectedFrontierRef || !stop && (snapshot.run.stopIntentRef || snapshot.run.cancelRequested) ||
      stop && (snapshot.run.stopIntentRef !== canonicalSha256(stop) || !snapshot.run.cancelRequested))
    throw new TypeError('verifier approval response differs from its atomic decision Checkpoint');
  await readPermissionCheckpointContext(driver, artifacts, context, checkpoint);
  return { ...proof, decision, grant, response, control, checkpoint, item: expectedItem, skip, stop };
}

/** No process/receipt is invented by refusing an advisory check. The actual
 * policy/approval item and source-preserving Checkpoint own that disposition. */
export async function readVerifierSkip(driver: SqliteDriver, artifacts: ArtifactCatalog, context: VerifierPermissionContext,
  value: unknown) {
  const skip = decodeVerifierSkipItem(value);
  if (context.target.required || skip.runId !== context.run.id || skip.candidateItemId !== context.target.candidateItemId ||
      skip.verifierPlanRef !== context.target.verifierPlanRef || skip.verifierIndex !== context.target.verifierIndex ||
      skip.verifierId !== context.target.verifierId || skip.itemId !== verifierSkipItemId(context.run.id, context.request.opId, skip.decisionRef) ||
      skip.createdAt < context.run.createdAt || skip.createdAt >= context.run.deadlineAt)
    throw new TypeError('advisory skip substituted its original unexecuted verifier');
  const journal = readInvocationJournal(driver, context.run.id).filter(entry => entry.opId === context.request.opId);
  const latest = journal.at(-1), claims = journal.filter(entry => entry.phase === 'dispatch_claimed');
  if ([...stopInvocationHistory(journal).values()].some(({ entry }) => !['completed', 'failed'].includes(entry.phase)) ||
      latest && (latest.timestamp > skip.createdAt || latest.phase === 'failed' && journal.some(entry => entry.attempt === latest.attempt && entry.phase === 'dispatch_claimed')))
    throw new TypeError('advisory skip cannot overtake an unresolved or claimed failed invocation');
  if (latest?.phase === 'completed') {
    if (!latest.receiptRef || decodeVerificationReceipt(await readCanonicalArtifact(artifacts, latest.receiptRef)).outcome !== 'infra_failed' ||
        claims.length >= context.target.maxAttempts) throw new TypeError('advisory skip cannot replace a completed eligible disposition');
  }
  let checkpoint;
  if (skip.outcome === 'skipped_by_user') {
    const original = await readVerifierApproval(driver, artifacts, context, skip.decisionRef);
    requireEqual(original.skip, skip, 'verifier original user skip'); checkpoint = original.checkpoint;
  } else {
    const evidence = await readCanonicalArtifact<VerifierPolicyChannelEvidenceV1>(artifacts, skip.decisionRef);
    requireEqual(evidence, context.evaluator.evaluate(context.request, context.target, evidence.evaluatedAt), 'verifier original skip policy');
    if (evidence.effectiveDisposition !== 'deny' || evidence.evaluatedAt !== skip.createdAt) throw new TypeError('only exact advisory deny may skip');
    const expected = verifierDenial(context, evidence, skip.decisionRef, skip.createdAt).skip;
    requireEqual(skip, expected, 'verifier original direct policy skip');
    const item = verifierPolicyItem(context, evidence, skip.decisionRef, skip.createdAt);
    const row = driver.prepare('SELECT item_seq,payload_ref,created_at FROM items WHERE run_id=? AND item_id=?')
      .get<{ item_seq: bigint; payload_ref: string; created_at: string }>(context.run.id, item.itemId);
    if (!row || row.created_at !== skip.createdAt) throw new TypeError('advisory skip lost its original denied policy item');
    requireEqual(await readCanonicalArtifact(artifacts, row.payload_ref), item, 'advisory exact denied policy item');
    const skipRow = driver.prepare('SELECT payload_ref FROM items WHERE run_id=? AND item_id=? AND item_seq=?')
      .get<{ payload_ref: string }>(context.run.id, skip.itemId, row.item_seq + 1n);
    if (!skipRow || skipRow.payload_ref !== canonicalSha256(skip)) throw new TypeError('advisory skip lost its exact ordered item');
    checkpoint = readCheckpoint(driver, identityHash('cliq-verifier-skip-checkpoint-v1', context.run.id, context.request.opId, skip.decisionRef));
    if (checkpoint.runId !== context.run.id || checkpoint.createdAt !== skip.createdAt || checkpoint.runItemSeq !== Number(row.item_seq) + 1)
      throw new TypeError('advisory skip lost its original atomic Checkpoint');
  }
  const source = await (await import('./result-source.js')).readCandidateSource(artifacts, context.spec, checkpoint.workspaceStateRef);
  if (source.sourceRef !== context.target.resultSourceRef || source.source.manifestDigest !== context.target.sourceDigest)
    throw new TypeError('advisory skip changed the exact original candidate');
  await readPermissionCheckpointContext(driver, artifacts, context, checkpoint);
  return { skip, checkpoint };
}

/** A verifier refusal owns run.approve, never a fabricated run.cancel row. */
export async function readVerifierApprovalDenials(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  run: Run; runSpec: RunSpec; items: readonly RunItemReferenceV1[];
}) {
  const results = new Map<string, AgentStopIntent>();
  const policies = driver.prepare("SELECT item_id,payload_ref FROM items WHERE run_id=? AND kind='policy_decision' ORDER BY item_seq")
    .all<{ item_id: string; payload_ref: string }>(input.run.id);
  for (const row of policies) {
    if (!input.items.some(item => item.itemId === row.item_id && item.payloadRef === row.payload_ref)) throw new TypeError('verifier denial escaped its exact owned item cut');
    const item = await readCanonicalArtifact<ContinuationItem>(artifacts, row.payload_ref);
    if (item.kind !== 'policy_decision' || item.subjectKind !== 'verifier_launch' || item.decision !== 'deny' ||
        item.decisionSource !== 'interactive_approval' || item.denialOutcome.kind !== 'stop_intent') continue;
    const evidence = await readCanonicalArtifact<VerifierPolicyChannelEvidenceV1>(artifacts, item.policyChannelEvidenceRef);
    const context = await readVerifierPermissionContext(driver, artifacts, input.run, input.runSpec, evidence.requestRef, evidence.targetRef);
    const original = await readVerifierApproval(driver, artifacts, context, item.decisionRef);
    requireEqual(original.item, item, 'verifier original denial policy item');
    if (!original.stop || canonicalSha256(original.stop) !== item.denialOutcome.stopIntentRef)
      throw new TypeError('verifier denial lost its original required cancellation');
    results.set(item.denialOutcome.stopIntentRef, original.stop);
  }
  return results;
}

/** Original Run-scoped template with its complete signed authorization chain. */
export async function readVerifierTemplateForRun(driver: SqliteDriver, artifacts: ArtifactCatalog, run: Run, spec: RunSpec, index: number) {
  if (run.parentRunId) return undefined;
  let roots: readonly import('../kernel/verifier-invocation.js').VerifierTemplateRootV1[];
  let assertOriginal: () => void;
  if (spec.operation === 'delivery') {
    const origin = await (await import('./reducers/delivery-admission.js')).readDeliveryRunAdmission(driver, artifacts, run.id);
    requireEqual(origin.run, run, 'verifier template original Delivery cut'); requireEqual(origin.spec, spec, 'verifier template original Delivery spec');
    roots = origin.verifierTemplates;
    assertOriginal = () => { requireEqual(readRun(driver, run.id), origin.run, 'verifier template unchanged Delivery');
      requireEqual(readRun(driver, origin.source.run.id), origin.source.run, 'verifier template unchanged source'); };
  } else {
    const origin = await (await import('./run-admission-origin.js')).readRootRunAdmissionOrigin(driver, artifacts, run.id);
    requireEqual(origin.run, run, 'verifier template original Agent cut'); requireEqual(origin.spec, spec, 'verifier template original Agent spec');
    roots = origin.verifierTemplates ?? []; assertOriginal = () => origin.assertUnchanged(driver);
  }
  // Each fresh original-admission reader above has already validated the full
  // signed derivation/consumption chain for every root. Reuse only this local
  // result, rather than repeating image/signature reads in the same operation.
  const root = roots.find(root => root.verifierIndex === index); if (!root) return undefined;
  const template = decodeVerifierAuthorizationTemplate(await readCanonicalArtifact(artifacts, root.templateRef));
  if (canonicalSha256(template) !== root.templateRef || template.templateDigest !== root.templateDigest || template.runId !== run.id ||
      template.verifierIndex !== index || template.verifierSpecRef !== spec.verifierSpecRef || template.expiresAt !== run.deadlineAt)
    throw new TypeError('verifier template differs from its completely validated admission root');
  assertOriginal();
  return template;
}

export async function verifierCandidateOrdinal(artifacts: ArtifactCatalog, items: readonly RunItemReferenceV1[], candidateItemId: string) {
  const decoded = await artifacts.mapReads(items, row => readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef));
  const candidates = decoded.filter(item => item.kind === 'final_candidate');
  const ordinal = candidates.findIndex(item => item.itemId === candidateItemId);
  if (ordinal < 0 || candidates.filter(item => item.itemId === candidateItemId).length !== 1) throw new TypeError('verifier candidate ordinal is not uniquely durable');
  return ordinal;
}

/** Shared live/recovery reproduction. Only the separate current owner and
 * original claim/release gates can turn this retained data into execution. */
export async function readVerifierGrant(driver: SqliteDriver, artifacts: ArtifactCatalog, context: VerifierPermissionContext,
  grantRef: string, items: readonly RunItemReferenceV1[]) {
  const grant = await readCanonicalArtifact<VerifierOperationGrantV1>(artifacts, grantRef);
  let expected: VerifierOperationGrantV1 | undefined, evidence: VerifierPolicyChannelEvidenceV1;
  if (grant.provenance.kind === 'verifier_template') {
    const template = await readVerifierTemplateForRun(driver, artifacts, context.run, context.spec, context.target.verifierIndex);
    if (!template || canonicalSha256(template) !== grant.provenance.templateRef) throw new TypeError('verifier grant borrowed another template');
    const ordinal = await verifierCandidateOrdinal(artifacts, items, context.target.candidateItemId);
    evidence = context.evaluator.evaluate(context.request, context.target, grant.issuedAt);
    expected = context.evaluator.templateGrant(context.request, context.target, evidence, template, ordinal, grant.issuedAt);
  } else if (grant.provenance.kind === 'user_approval') {
    const approved = await readVerifierApproval(driver, artifacts, context, grant.provenance.decisionRef);
    expected = approved.grant; evidence = approved.evidence;
  } else if (grant.provenance.kind === 'policy_snapshot') {
    evidence = await readCanonicalArtifact<VerifierPolicyChannelEvidenceV1>(artifacts, grant.provenance.channelEvidenceRef);
    expected = context.evaluator.grant(context.request, context.target, evidence, grant.issuedAt, grant.expiresAt);
  } else throw new TypeError('verifier grant has an unsupported provenance');
  requireEqual(grant, expected, 'verifier complete original operation grant');
  if (canonicalSha256(grant) !== grantRef || grant.expiresAt > context.run.deadlineAt) throw new TypeError('verifier grant exceeds its original Run');
  return { grant, evidence };
}
