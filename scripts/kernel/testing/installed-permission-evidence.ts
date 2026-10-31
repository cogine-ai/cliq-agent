// Independent retained-data bindings for the owned permission campaign. These
// checks never create StateOwner, consume grants, mint native evidence or retry.
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../../../src/kernel/identity.js';
import { exactKeys } from '../../../src/policy/runtime-authority.js';
import { decodeControlChannel, decodeLocalPrincipalIdentity, decodeLocalSocketPeerObservation,
  decodePlatformProcessIdentity, decodeStateLockIdentity, decodeStateRootIdentity, decodeContextManifest } from '../../../src/state/decoders.js';
import { validateContextItems } from '../../../src/runtime/context-compaction.js';
import { decodeAuthorizationGrant, decodeAuthorizationConsumptionReceipt } from '../../../src/state/authorization-artifacts.js';
import { normalizeRunSubmitRequest } from '../../../src/kernel/control-submit.js';
import { normalizeRunApplyRequest, runApplyIntentDigest } from '../../../src/kernel/control-apply.js';
import type { InstalledVerifierOwnerHistoryReader } from './installed-verifier-evidence.js';
import type { inspectInstalledPermissionRecord } from './installed-worker-lease.js';

type Data = Record<string, any>;
type ObjectReader = (ref: string) => Promise<any>;
type Selector = Parameters<typeof inspectInstalledPermissionRecord>[2];
export type InstalledPermissionEvidence = {
  readRecord(selector: Selector): Data;
  controls: ReadonlyMap<string, { request: Data; response: Data }>;
  readOwnerHistory: InstalledVerifierOwnerHistoryReader;
};
const check = (value: unknown): void => { if (!value) throw new Error('installed permission evidence differs'); };
const same = (actual: unknown, expected: unknown) => check(canonicalSha256(actual) === canonicalSha256(expected));
const initialSummary = (grant: Data) => ({ schemaVersion: 1, grantId: grant.grantId, state: 'active', targetKind: grant.target.kind,
  purpose: 'verifier', targetDigest: grant.targetDigest, useCount: 0, rowVersion: 1, createdAt: grant.createdAt, expiresAt: grant.expiresAt });
function operation(request: Data, target: Data, principalId: string, policyRef: string, subject: Data,
  provenance: Data, issuedAt: string, expiresAt: string, maximum: number) {
  const core = { schemaVersion: 1, format: 'cliq-operation-grant-v1',
    grantId: identityHash('cliq-operation-grant-v1', request.runId, request.opId, request.requestDigest, subject, issuedAt),
    principalId, runId: request.runId, policyRef, frontierRef: request.frontierRef, opId: request.opId,
    requestRef: canonicalSha256(request), requestDigest: request.requestDigest, targetRef: request.targetRef, targetDigest: target.targetDigest,
    subject, provenance, maxDispatchedAttempts: maximum, issuedAt, expiresAt };
  return { ...core, grantDigest: canonicalSha256(core) };
}
const verifierSubject = (target: Data) => ({ kind: 'verifier_launch', candidateItemId: target.candidateItemId,
  resultSourceRef: target.resultSourceRef, verifierPlanRef: target.verifierPlanRef, verifierIndex: target.verifierIndex,
  verifierId: target.verifierId, verifierSpecDigest: target.verifierSpecDigest, required: target.required });

/** A real SQL control row, original canonical request and response, the exact
 * exchange observed over the authenticated client, and retained peer/root
 * closure must agree. A standalone ApprovalDecision is never enough. */
async function control(evidence: InstalledPermissionEvidence, object: ObjectReader,
  principalId: string, method: 'run.approve' | 'authorization.create' | 'run.submit' | 'run.apply', requestId: string) {
  const row = evidence.readRecord({ kind: 'control', principalId, method, requestId });
  const captured = evidence.controls.get(requestId); check(captured);
  const request = await object(row.request_digest), response = await object(row.response_ref);
  const { requestDigest, ...core } = captured!.request;
  same(request, core); same(response, captured!.response);
  check(row.principal_id === principalId && row.method === method && row.request_id === requestId &&
    requestDigest === row.request_digest && canonicalSha256(request) === requestDigest &&
    row.response_revision === 1 && response.protocolVersion === 1 && response.ok === true && response.result.method === method);
  parseCanonicalTime(row.committed_at);
  const channel = decodeControlChannel(await object(row.channel_identity_ref));
  const principal = decodeLocalPrincipalIdentity(await object(channel.principalIdentityRef));
  check(channel.channelIdentityDigest === row.channel_identity_digest && channel.principalId === principalId &&
    principal.principalId === principalId && principal.identityDigest === channel.principalIdentityDigest &&
    principal.platform === 'linux' && channel.openedAt <= row.committed_at && channel.transport.kind === 'uds_peer');
  if (channel.transport.kind !== 'uds_peer') throw new Error('installed permission has no original UDS peer');
  const peer = decodeLocalSocketPeerObservation(await object(channel.transport.peerObservationRef));
  const process = decodePlatformProcessIdentity(await object(peer.peerProcessIdentityRef));
  const owners = await evidence.readOwnerHistory(); check(owners.length > 0 && owners.length <= 1000);
  const issuer = owners.filter(owner => owner.acquiredAt <= row.committed_at && (owner.state === 'active' || owner.releasedAt >= row.committed_at));
  check(issuer.length === 1);
  const lock = decodeStateLockIdentity(await object(issuer[0]!.stateLockIdentityRef));
  const root = decodeStateRootIdentity(await object(lock.stateRootIdentityRef));
  check(root.identityDigest === lock.stateRootIdentityDigest && principal.stateRootIdentityRef === lock.stateRootIdentityRef &&
    principal.stateRootIdentityDigest === root.identityDigest && principal.effectiveUid === root.ownerUid &&
    peer.observationDigest === channel.transport.peerObservationDigest && peer.stateRootIdentityRef === principal.stateRootIdentityRef &&
    peer.stateRootIdentityDigest === principal.stateRootIdentityDigest && peer.platform === principal.platform && peer.peerUid === principal.effectiveUid &&
    process.identityDigest === peer.peerProcessIdentityDigest && process.platform === peer.platform && process.pid === peer.peerPid &&
    process.ownerUid === peer.peerUid && process.observedAt === peer.observedAt && channel.openedAt >= peer.observedAt);
  return { row, request, response, channel, owner: issuer[0]! };
}

/** Pure policy projection may recompute the fixed grant; the real control
 * transaction and both original Checkpoints independently establish consent. */
export async function assertInstalledInteractivePermission(input: {
  evidence: InstalledPermissionEvidence; object: ObjectReader; cut: Data; principalId: string;
  grant: Data; policyItem: Data; evaluator: Data; request: Data; target: Data;
}) {
  const { evidence, object, cut, principalId, grant, policyItem, evaluator, request, target } = input;
  check(grant.provenance.kind === 'user_approval' && policyItem.decisionSource === 'interactive_approval' && policyItem.decision === 'allow');
  const decisionRef = grant.provenance.decisionRef, decision = await object(decisionRef), wait = await object(decision.waitingSubjectRef);
  const channel = await object(grant.provenance.channelEvidenceRef), run = cut.snapshot.run;
  same(channel, evaluator.evaluate(request, target, channel.evaluatedAt)); check(channel.effectiveDisposition === 'ask');
  const verifier = wait.subject.kind === 'verifier_launch'; check(verifier || wait.subject.kind === 'delivery_plan');
  const subject = verifier ? verifierSubject(target) : { kind: 'delivery_plan', deliveryPlanRef: target.deliveryPlanRef,
    deliveryPlanDigest: target.deliveryPlanDigest, operationSetDigest: target.operationSetDigest };
  same(wait, { schemaVersion: 1, kind: 'approval', runId: run.id, createdFromRevision: wait.createdFromRevision,
    createdAt: channel.evaluatedAt, frontierRef: request.frontierRef, subject: { ...subject, opId: request.opId,
      ...(verifier ? { target: request.targetRef } : {}), policyChannelEvidenceRef: canonicalSha256(channel), policyChannelEvidenceDigest: channel.evidenceDigest } });
  check(decision.decision === 'allow' && decision.principalId === principalId && decision.runId === run.id &&
    decision.waitingSubjectRef === grant.provenance.waitingSubjectRef && decision.requestId === grant.provenance.requestId &&
    decision.createdAt === grant.issuedAt && decision.decisionDigest === digestOmitting(decision, 'decisionDigest'));
  const original = await control(evidence, object, principalId, 'run.approve', decision.requestId);
  same(original.request, { protocolVersion: 1, method: 'run.approve', runId: run.id, requestId: decision.requestId,
    expectedRevision: decision.expectedRunRevision, waitingOnRef: decision.waitingSubjectRef, decision: 'allow',
    ...(decision.requestedTtlMs === undefined ? {} : { ttlMs: decision.requestedTtlMs }) });
  check(original.row.request_digest === decision.requestDigest && original.row.channel_identity_ref === decision.channelIdentityRef &&
    original.row.channel_identity_digest === decision.channelIdentityDigest && original.row.committed_at === decision.createdAt &&
    original.response.result.decisionRef === decisionRef);
  const decisionCore = { schemaVersion: 1, format: 'cliq-approval-decision-v1',
    decisionId: identityHash(principalId, run.id, canonicalSha256(wait), decision.requestId, decision.requestDigest),
    principalId, channelIdentityRef: original.row.channel_identity_ref, channelIdentityDigest: original.row.channel_identity_digest,
    runId: run.id, waitingSubjectRef: canonicalSha256(wait), waitingSubjectDigest: canonicalSha256(wait), frontierRef: wait.frontierRef,
    subject: wait.subject, subjectDigest: canonicalSha256(wait.subject), requestId: decision.requestId, requestDigest: decision.requestDigest,
    expectedRunRevision: wait.createdFromRevision + 1, decision: 'allow',
    ...(original.request.ttlMs === undefined ? {} : { requestedTtlMs: original.request.ttlMs }),
    grantExpiresAt: verifier ? new Date(Math.min(parseCanonicalTime(decision.createdAt) + (original.request.ttlMs ?? 3_600_000), parseCanonicalTime(run.deadlineAt))).toISOString() : run.deadlineAt,
    createdAt: original.row.committed_at };
  same(decision, { ...decisionCore, decisionDigest: canonicalSha256(decisionCore) });
  check(decision.createdAt >= wait.createdAt && decision.createdAt < run.deadlineAt);
  same(grant, operation(request, target, principalId, channel.policyRef, subject, { kind: 'user_approval',
    waitingSubjectRef: canonicalSha256(wait), decisionRef, requestId: decision.requestId,
    channelEvidenceRef: canonicalSha256(channel), channelEvidenceDigest: channel.evidenceDigest }, decision.createdAt,
    decisionCore.grantExpiresAt, verifier ? target.maxAttempts : 0));
  const waitingId = identityHash(verifier ? 'cliq-verifier-approval-checkpoint-v1' : 'cliq-delivery-approval-checkpoint-v1', decision.waitingSubjectRef);
  const decidedId = verifier ? identityHash('cliq-verifier-approval-decision-checkpoint-v1', decisionRef)
    : identityHash('cliq-delivery-decision-checkpoint-v1', run.id, wait.subject.deliveryPlanRef, decisionRef);
  const checkpoint = (id: string): Data => { const matches = cut.checkpoints.filter((value: Data) => value.id === id); check(matches.length === 1); return matches[0]; };
  const waiting = checkpoint(waitingId), decided = checkpoint(decidedId);
  const policyRows = cut.items.filter((value: Data) => value.itemId === policyItem.itemId); check(policyRows.length === 1);
  check(waiting.runId === run.id && waiting.reason === 'auto' && waiting.basedOnRunRevision === wait.createdFromRevision && waiting.createdAt === wait.createdAt &&
    decided.runId === run.id && decided.reason === 'auto' && decided.basedOnRunRevision === decision.expectedRunRevision && decided.createdAt === decision.createdAt &&
    decision.expectedRunRevision === wait.createdFromRevision + 1 && decided.workspaceStateRef === waiting.workspaceStateRef && decided.journalSeq === waiting.journalSeq &&
    policyRows[0].itemSeq === waiting.runItemSeq + 1 && policyRows[0].createdAt === decision.createdAt &&
    decided.runItemSeq === waiting.runItemSeq + (verifier ? 1 : 2));
  const latest = new Map<string, Data>();
  for (const row of cut.journal.slice(0, waiting.journalSeq)) latest.set(`${row.opId}:${row.attempt}`, row);
  check([...latest.values()].every(value => value.phase === 'completed' || value.phase === 'failed'));
  const spec = await object(run.specRef);
  for (const checkpoint of [waiting, decided]) {
    const context = decodeContextManifest(await object(checkpoint.contextManifestRef));
    check(context.runId === run.id && context.assemblyRef === spec.assemblyRef && context.admittedContextRef === spec.admittedContextRef &&
      context.throughItemSeq === checkpoint.runItemSeq);
    const prefix = cut.items.slice(0, checkpoint.runItemSeq); check(prefix.length === checkpoint.runItemSeq);
    validateContextItems(context, await Promise.all(prefix.map(async (row: Data, index: number) => {
      check(row.itemSeq === index + 1 && row.createdAt <= checkpoint.createdAt);
      return { itemSeq: row.itemSeq, itemRef: row.payloadRef, item: await object(row.payloadRef) };
    })));
    if (verifier) check(prefix.some((row: Data) => row.itemId === target.candidateItemId));
  }
  const snapshot = original.response.result.snapshot;
  check(snapshot.run.id === run.id && snapshot.run.specRef === run.specRef && snapshot.run.revision === decision.expectedRunRevision + 1 &&
    snapshot.run.latestCheckpointId === decided.id && snapshot.run.updatedAt === decision.createdAt && snapshot.latestRunItemSeq === decided.runItemSeq &&
    snapshot.run.sessionId === run.sessionId && snapshot.run.createdAt === run.createdAt && snapshot.run.deadlineAt === run.deadlineAt &&
    snapshot.operation === cut.snapshot.operation && snapshot.run.status === 'queued' && !snapshot.run.activeWorkerLaunchId &&
    snapshot.run.nextStep === (verifier ? 'verify' : 'delivery') &&
    !snapshot.run.waitingOnRef && !snapshot.run.waitingReason && !snapshot.run.stopIntentRef && !snapshot.run.cancelRequested);
  const frontier = await object(wait.frontierRef);
  same(await object(snapshot.run.frontierRef), verifier ? frontier : { ...frontier, phase: 'publish', nextPathOperationIndex: 0 });
  same(policyItem, { schemaVersion: 1, kind: 'policy_decision', subjectKind: wait.subject.kind,
    itemId: identityHash(verifier ? 'cliq-verifier-policy-item-v1' : 'cliq-delivery-policy-item-v1', run.id, request.opId, decisionRef),
    runId: run.id, opId: request.opId, principalId, decisionRef, policyChannelEvidenceRef: canonicalSha256(channel),
    policyChannelEvidenceDigest: channel.evidenceDigest, createdAt: decision.createdAt, decisionSource: 'interactive_approval',
    waitingSubjectRef: decision.waitingSubjectRef, decision: 'allow', grantRef: canonicalSha256(grant) });
  return { decisionId: policyItem.itemId, decisionRef, channel };
}

/** Fixed campaign root templates only. The signed command identity is checked
 * by the existing complete verifier-input reader before entering this audit. */
export async function assertInstalledTemplatePermission(input: {
  evidence: InstalledPermissionEvidence; object: ObjectReader; cut: Data; principalId: string; spec: Data;
  grant: Data; evaluator: Data; request: Data; target: Data; candidateOrdinal: number;
}) {
  const { evidence, object, cut, principalId, spec, grant, evaluator, request, target, candidateOrdinal } = input, run = cut.snapshot.run;
  check(grant.provenance.kind === 'verifier_template' && spec.operation === 'agent');
  const template = await object(grant.provenance.templateRef);
  check(exactKeys(template, ['schemaVersion', 'format', 'runId', 'verifierSpecRef', 'verifierSpecDigest', 'verifierIndex', 'verifierId', 'verifierVersion',
    'verifierEntryDigest', 'commandRef', 'commandDigest', 'environmentRef', 'environmentDigest', 'sourceProjectionRef', 'maxCandidateGenerations',
    'maxAttempts', 'expiresAt', 'decisionRef', 'templateDigest']));
  check(template.templateDigest === digestOmitting(template, 'templateDigest') && template.runId === run.id &&
    template.schemaVersion === 1 && template.format === 'cliq-verifier-authorization-template-v1' && template.verifierIndex === 0 &&
    template.verifierSpecRef === spec.verifierSpecRef && template.verifierSpecDigest === target.verifierSpecDigest &&
    template.verifierId === target.verifierId && template.verifierVersion === target.verifierVersion && template.verifierEntryDigest === target.verifierEntryDigest &&
    template.commandRef === target.commandRef && template.commandDigest === target.commandDigest &&
    template.environmentRef === target.environmentRef && template.environmentDigest === target.environmentDigest &&
    template.sourceProjectionRef === spec.sourceProjectionRef && template.maxCandidateGenerations === spec.budgets.repairAttempts + 1 &&
    template.maxAttempts === target.maxAttempts && template.expiresAt === run.deadlineAt &&
    grant.provenance.candidateOrdinal === candidateOrdinal && candidateOrdinal >= 0 && candidateOrdinal < template.maxCandidateGenerations &&
    grant.provenance.decisionRef === template.decisionRef);
  const receipt = decodeAuthorizationConsumptionReceipt(await object(template.decisionRef));
  const source = decodeAuthorizationGrant(evidence.readRecord({ kind: 'grant', grantId: receipt.grantId }));
  check(source.state === 'consumed' && source.target.kind === 'verifier_execution' && source.ownerPrincipalId === principalId);
  if (source.state !== 'consumed' || source.target.kind !== 'verifier_execution') throw new Error('installed template source is not consumed');
  const original = await control(evidence, object, principalId, 'authorization.create', source.sourceRequestId), targetGrant = source.target;
  same(original.response.result.grant, initialSummary(source));
  check(original.row.request_digest === source.sourceRequestDigest && original.row.channel_identity_ref === source.channelIdentityRef &&
    original.row.channel_identity_digest === source.channelIdentityDigest && original.row.committed_at >= source.createdAt && original.row.committed_at < source.expiresAt &&
    source.expiresAt === new Date(parseCanonicalTime(source.createdAt) + (original.request.ttlMs ?? 3_600_000)).toISOString() &&
    original.response.result.grant.grantId === source.grantId && original.response.result.grant.state === 'active' &&
    original.response.result.grant.targetDigest === source.targetDigest && source.consumptionReceiptRef === template.decisionRef &&
    source.consumedAt === run.createdAt && receipt.consumedAt === run.createdAt && receipt.ownerPrincipalId === principalId &&
    receipt.targetDigest === source.targetDigest && receipt.consumedAt >= original.row.committed_at &&
    targetGrant.verifierId === target.verifierId && targetGrant.maxCandidateGenerations === template.maxCandidateGenerations &&
    targetGrant.maxAttemptsPerCandidate === template.maxAttempts);
  same(original.request.decision, { kind: 'verifier_execution', verifierId: targetGrant.verifierId,
    verifierRequestDigest: targetGrant.verifierRequestCoreDigest, executionIdentityGrantId: targetGrant.executionIdentityGrantId,
    maxCandidateGenerations: template.maxCandidateGenerations, maxAttemptsPerCandidate: template.maxAttempts });
  const identity = decodeAuthorizationGrant(evidence.readRecord({ kind: 'grant', grantId: targetGrant.executionIdentityGrantId }));
  check(identity.state === 'consumed' && identity.ownerPrincipalId === principalId && identity.target.kind === 'execution_identity_read' &&
    identity.target.purpose === 'verifier' && identity.targetDigest === targetGrant.executionIdentityTargetDigest);
  if (identity.state !== 'consumed' || identity.target.kind !== 'execution_identity_read' || identity.target.identity.kind !== 'guest_toolchain')
    throw new Error('installed template lost its exact derived identity');
  const identityControl = await control(evidence, object, principalId, 'authorization.create', identity.sourceRequestId);
  same(identityControl.response.result.grant, initialSummary(identity));
  const command = await object(template.commandRef), selected = identity.target.identity, derivation = decodeAuthorizationConsumptionReceipt(await object(identity.consumptionReceiptRef));
  const environment = await object(template.environmentRef), bundle = await object(identityControl.owner.runtimeBundleRef);
  check(identityControl.row.request_digest === identity.sourceRequestDigest && identityControl.row.channel_identity_ref === identity.channelIdentityRef &&
    identityControl.row.channel_identity_digest === identity.channelIdentityDigest && identityControl.row.committed_at >= identity.createdAt &&
    identityControl.row.committed_at <= source.createdAt && original.row.committed_at < identity.expiresAt &&
    command.executable.kind === 'guest_toolchain' && selected.guestToolchainManifestRef === command.executable.guestToolchainManifestRef &&
    selected.manifestDigest === command.executable.guestToolchainManifestDigest && selected.toolId === command.executable.toolId &&
    selected.executionPath === command.executable.executionPath && selected.executableDigest === command.executable.executableDigest &&
    derivation.grantId === identity.grantId && derivation.ownerPrincipalId === principalId && derivation.targetDigest === identity.targetDigest &&
    derivation.consumedAt === source.createdAt && identity.consumedAt === derivation.consumedAt);
  check(original.owner.runtimeBundleRef === environment.runtimeBundleRef && original.owner.runtimeBundleManifestDigest === environment.runtimeBundleManifestDigest &&
    identityControl.owner.runtimeBundleRef === environment.runtimeBundleRef && identityControl.owner.runtimeBundleManifestDigest === environment.runtimeBundleManifestDigest &&
    source.createdAt >= original.owner.acquiredAt && identity.createdAt >= identityControl.owner.acquiredAt &&
    identity.expiresAt === new Date(parseCanonicalTime(identity.createdAt) + (identityControl.request.ttlMs ?? 3_600_000)).toISOString() &&
    identityControl.request.decision.kind === 'execution_identity_read' && identityControl.request.decision.purpose === 'verifier' &&
    identityControl.request.decision.target.kind === 'guest_toolchain' && identityControl.request.decision.target.toolId === selected.toolId &&
    bundle.manifestDigest === identityControl.owner.runtimeBundleManifestDigest && Array.isArray(bundle.structuredArtifacts) &&
    bundle.structuredArtifacts.filter((root: Data) => root.kind === 'guest_toolchain' &&
      root.artifactId === identityControl.request.decision.target.guestToolchainManifestId && root.artifactRef === selected.guestToolchainManifestRef).length === 1);
  same(derivation.consumer, { kind: 'authorization_derivation', derivedGrantId: source.grantId });
  const admission = evidence.readRecord({ kind: 'admission', runId: run.id });
  check(admission.id === run.id && admission.principal_id === principalId && admission.admission_method === 'run.submit');
  const admitted = await control(evidence, object, principalId, 'run.submit', admission.admission_request_id);
  const normalized = normalizeRunSubmitRequest({ ...admitted.request, requestDigest: admitted.row.request_digest }).request;
  const { protocolVersion: _protocol, requestId: _requestId, requestDigest: _requestDigest, admissionKey: _key, ...intent } = normalized;
  check(normalized.verifiers.length === 1 && normalized.verifiers[0]!.executionGrantId === source.grantId &&
    canonicalSha256({ principalId, method: 'run.submit', request: intent }) === admission.admission_intent_digest && admitted.row.committed_at === run.createdAt);
  const { executionGrantId: _execution, ...core } = normalized.verifiers[0]!;
  check(canonicalSha256(core) === targetGrant.verifierRequestCoreDigest && core.identityReadGrantId === identity.grantId);
  const frozen = await object(spec.verifierSpecRef), entry = frozen.verifiers[0];
  check(frozen.verifiers.length === 1 && core.id === entry.id && core.version === entry.version && core.required === target.required &&
    core.timeoutMs === entry.timeoutMs && (core.retries ?? 0) === entry.retries && core.outputLimitBytes === entry.outputLimitBytes && command.cwd === core.cwd);
  same(command.argv, core.argv); same(core.env, {}); same(environment.variables, []);
  same(core.writableEphemeralPaths, []); same(environment.writableEphemeralPaths, []);
  same(receipt.consumer, { kind: 'run_admission', runId: run.id, admissionIntentDigest: admission.admission_intent_digest });
  const initial = cut.checkpoints.filter((value: Data) => value.id === identityHash('cliq-checkpoint-id-v1', run.id, 'initial', 0)); check(initial.length === 1);
  const base = await object(spec.baseWorkspaceManifestRef);
  check(admission.admitted_request_digest === canonicalSha256({ admissionIntentDigest: admission.admission_intent_digest,
    objectiveRef: spec.objectiveRef, admittedContextRef: spec.admittedContextRef, runSpecRef: run.specRef,
    workspaceIdentityDigest: base.workspaceIdentityDigest, repositoryIdentityDigest: base.git?.repositoryIdentityDigest ?? null,
    sourceProjectionRef: spec.sourceProjectionRef, frozenIgnoreRulesRef: base.frozenIgnoreRulesRef, baseWorkspaceManifestRef: spec.baseWorkspaceManifestRef,
    workspaceStateRef: initial[0].workspaceStateRef, assemblyRef: spec.assemblyRef, policyRef: spec.policyRef, sandboxProfileRef: spec.sandboxProfileRef,
    verifierSpecRef: spec.verifierSpecRef, unverifiedConsentRef: spec.unverifiedConsentRef ?? null, credentialGrantRefs: spec.credentialGrantRefs,
    authorizationReceiptRefs: [template.decisionRef], verifierTemplates: [{ verifierIndex: 0, templateRef: canonicalSha256(template), templateDigest: template.templateDigest }] }));
  const channel = evaluator.evaluate(request, target, grant.issuedAt);
  same(await object(canonicalSha256(channel)), channel);
  check(channel.effectiveDisposition !== 'deny' && grant.issuedAt >= channel.evaluatedAt && grant.issuedAt < template.expiresAt);
  same(grant, operation(request, target, principalId, channel.policyRef, verifierSubject(target), { kind: 'verifier_template',
    templateRef: canonicalSha256(template), candidateOrdinal, decisionRef: template.decisionRef }, grant.issuedAt, template.expiresAt, target.maxAttempts));
  // Template provenance deliberately has no synthetic policy decision item.
  // Its original evidence is located from the independently planned request.
  return { template, receipt };
}

/** Even an inherited result must retain the explicit grant's one actual
 * consumer. This deliberately proves consumption, not a nonexistent verifier
 * claim, receipt or native execution. */
export async function assertInstalledUnusedDeliveryGrant(input: {
  evidence: InstalledPermissionEvidence; object: ObjectReader; cut: Data; grantId: string; principalId: string;
}) {
  const { evidence, object, cut, grantId, principalId } = input, run = cut.snapshot.run;
  check(cut.snapshot.operation === 'delivery');
  const grant = decodeAuthorizationGrant(evidence.readRecord({ kind: 'grant', grantId }));
  check(grant.state === 'consumed' && grant.target.kind === 'verifier_execution' && grant.ownerPrincipalId === principalId);
  if (grant.state !== 'consumed' || grant.target.kind !== 'verifier_execution') throw new Error('unused Delivery grant lost its sole consumer');
  const receipt = decodeAuthorizationConsumptionReceipt(await object(grant.consumptionReceiptRef));
  const admission = evidence.readRecord({ kind: 'admission', runId: run.id });
  check(admission.id === run.id && admission.principal_id === principalId && admission.admission_method === 'run.apply');
  const admitted = await control(evidence, object, principalId, 'run.apply', admission.admission_request_id);
  const request = normalizeRunApplyRequest({ ...admitted.request, requestDigest: admitted.row.request_digest }).request;
  same(request.verifierExecutionGrantIds, [grantId]);
  check(runApplyIntentDigest(principalId, request) === admission.admission_intent_digest && admitted.row.committed_at === run.createdAt &&
    admitted.response.result.snapshot.run.id === run.id && admitted.response.result.snapshot.run.specRef === run.specRef &&
    grant.consumedAt === run.createdAt && receipt.consumedAt === run.createdAt && receipt.grantId === grantId &&
    receipt.ownerPrincipalId === principalId && receipt.targetDigest === grant.targetDigest);
  same(receipt.consumer, { kind: 'run_admission', runId: run.id, admissionIntentDigest: admission.admission_intent_digest });
  const created = await control(evidence, object, principalId, 'authorization.create', grant.sourceRequestId);
  same(created.response.result.grant, initialSummary(grant));
  check(created.row.request_digest === grant.sourceRequestDigest && created.row.channel_identity_ref === grant.channelIdentityRef &&
    created.row.channel_identity_digest === grant.channelIdentityDigest && created.row.committed_at >= grant.createdAt &&
    receipt.consumedAt >= created.row.committed_at && receipt.consumedAt < grant.expiresAt &&
    created.response.result.grant.grantId === grantId && created.response.result.grant.targetDigest === grant.targetDigest &&
    created.response.result.grant.state === 'active' && created.request.decision.kind === 'verifier_execution' &&
    created.request.decision.verifierRequestDigest === grant.target.verifierRequestCoreDigest &&
    created.request.decision.executionIdentityGrantId === grant.target.executionIdentityGrantId &&
    created.request.decision.maxCandidateGenerations === 1 && grant.target.maxCandidateGenerations === 1 &&
    created.request.decision.maxAttemptsPerCandidate === grant.target.maxAttemptsPerCandidate);
}
