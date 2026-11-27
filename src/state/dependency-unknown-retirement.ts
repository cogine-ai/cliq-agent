import { canonicalSha256 } from '../kernel/canonical.js';
import { controlWireRecord, controlWireRef, controlWireText, controlWireInteger, assertControlWireJson } from '../kernel/control-wire-data.js';
import { decodeDependencyBrokerDispatchClosure } from '../kernel/dependency-acquisition.js';
import { decodeDependencyClaimEvidence } from '../kernel/dependency-claim.js';
import { decodeDependencyAmbiguity } from '../kernel/dependency-ambiguity.js';
import { decodeDependencyRequest } from '../kernel/dependency-invocation.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import type { BoundWorkerLaunch, InvocationJournalEntry, RecoveryClosureV1, TerminalDetail, WorkspaceGenerationQuarantineEvidenceV1,
  WorkspaceGenerationRetirementEvidenceV1, WorkspaceGenerationStateV1, WorkerRecoveryEvidenceV1 } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { decodeBudgetSettlement } from './decoders.js';
import { readDependencyHistory } from './dependency-history.js';
import { assertDependencyUnknownBrokerFence } from './dependency-invocation-owner.js';
import { readRetainedDependencyLaunchEnvironment } from './execution-closure.js';
import { readRetiredGenerationSource } from './generation-retirement.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import { readStateOwner, assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readStateOwnerDeath } from './state-owner-death.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readRun } from './rows.js';
import { readInvocationJournal } from './repositories/journal.js';
import { settleValidatedInvocation } from './reducers/invocation.js';

type Cut = Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'items' | 'journal' | 'workspaceGenerations'>;
type Abandonment = TerminalDetail['abandonedRetryInvocations'][number];
export function hasOnlySettledDependencyUnknowns(journal: readonly InvocationJournalEntry[]): boolean {
  const latest = new Map<string, InvocationJournalEntry>();
  for (const row of journal) latest.set(`${row.opId}:${row.attempt}`, row);
  const open = [...latest.values()].filter(row => ['prepared', 'dispatch_claimed', 'unknown'].includes(row.phase));
  if (open.length !== 1) return false;
  const unknown = open[0]!, rows = journal.filter(row => row.opId === unknown.opId && row.attempt === unknown.attempt);
  return rows.length === 3 && rows[0]?.phase === 'prepared' && rows[1]?.phase === 'dispatch_claimed' && rows[2] === unknown &&
    rows.every(row => row.target === 'builtin:dependency-acquire' && row.opKind === 'tool' && row.replayClass === 'workspace-rollback-retry' && row.attempt === 0) &&
    unknown.phase === 'unknown' && !!unknown.budgetSettlementRef && !!unknown.evidenceRef && !!unknown.evidenceDigest;
}

/** A successor can charge a permanently claimed effect after the original
 * Supervisor process really died. This says nothing about the worker domain,
 * result, traffic or success; normal recovery still fences and quarantines M. */
export async function settleDeadOwnerDependencyClaim(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { runId: string; expectedRunRevision: number }) {
  artifacts.assertReadActive(); assertActiveStateOwner(driver, owner);
  const initial = readInvocationJournal(driver, input.runId);
  const pending = new Map<string, InvocationJournalEntry>();
  for (const row of initial) pending.set(`${row.opId}:${row.attempt}`, row);
  if (![...pending.values()].some(row => row.phase === 'dispatch_claimed' && row.target === 'builtin:dependency-acquire')) return undefined;
  const cut = await readRecoveryClosure(driver, artifacts, input.runId);
  if (cut.run.revision !== input.expectedRunRevision) throw new TypeError('dependency owner-death cut changed');
  const latest = new Map<string, InvocationJournalEntry>();
  for (const row of cut.journal) latest.set(`${row.opId}:${row.attempt}`, row);
  const claims = [...latest.values()].filter(row => row.phase === 'dispatch_claimed' && row.target === 'builtin:dependency-acquire');
  if (!claims.length) return undefined;
  if (claims.length !== 1) throw new TypeError('dependency owner death has competing permanent claims');
  const claim = claims[0]!, rows = cut.journal.filter(row => row.opId === claim.opId && row.attempt === claim.attempt);
  if (rows.length !== 2 || rows[0]?.phase !== 'prepared' || claim.stateOwnerEpoch === owner.ownerEpoch ||
      claim.supervisorInstanceId === owner.supervisorInstanceId || !claim.evidenceRef || !claim.brokerFenceTokenDigest || !claim.grantRef)
    throw new TypeError('dependency UNKNOWN requires its exact dead predecessor claim');
  const death = await readStateOwnerDeath(artifacts, driver, { supervisorInstanceId: claim.supervisorInstanceId!, ownedAt: claim.timestamp });
  const history = await readRetainedStateOwnerHistory(driver, artifacts, owner.ownerEpoch);
  const claiming = history.entries.find(entry => entry.owner.ownerEpoch === claim.stateOwnerEpoch);
  if (!claiming || claiming.owner.supervisorInstanceId !== claim.supervisorInstanceId ||
      death.priorOwner.ownerEpoch !== claim.stateOwnerEpoch || owner.ownerEpoch <= death.priorOwner.ownerEpoch ||
      history.rootIdentity.identityDigest !== owner.stateRootIdentityDigest || canonicalSha256(history.rootIdentity) !== owner.stateRootIdentityRef)
    throw new TypeError('dependency owner-death observation lost its original StateRoot and process');
  const check = (connection: SqliteConnection, committedAt?: string) => {
    artifacts.assertReadActive();
    const active = assertActiveStateOwner(connection, owner); history.assertUnchanged(connection);
    requireEqual(readRun(connection, cut.run.id), cut.run, 'dependency dead-owner original Run');
    requireEqual(readInvocationJournal(connection, cut.run.id), cut.journal, 'dependency dead-owner original Journal');
    const observedAt = new Date(owner.filesystem.observePriorProcessDeath(claiming.process.pid, claiming.process.processStartToken)).toISOString();
    if (observedAt < active.acquiredAt || observedAt < death.successorOwner.acquiredAt ||
        committedAt !== undefined && committedAt < death.successorOwner.acquiredAt)
      throw new TypeError('dependency owner death is outside its actual settlement cut');
  };
  check(driver);
  const ambiguity = decodeDependencyAmbiguity({ schemaVersion: 1, format: 'cliq-dependency-ambiguity-v1', runId: claim.runId,
    opId: claim.opId, attempt: claim.attempt, dispatchId: claim.dispatchId, claimJournalSeq: claim.seq, requestRef: claim.requestRef,
    target: claim.target, grantRef: claim.grantRef, brokerFenceTokenDigest: claim.brokerFenceTokenDigest,
    reason: 'claiming_owner_dead_before_result', acquisitionEvidenceRef: death.acquisitionEvidenceRef,
    acquisitionEvidenceDigest: death.acquisitionEvidenceDigest });
  const artifact = await artifacts.publishCanonical(ambiguity, ambiguity.format);
  return settleValidatedInvocation(driver, artifacts, owner, { ...input, opId: claim.opId, attempt: claim.attempt },
    { phase: 'unknown', evidenceRef: artifact.ref, evidenceDigest: artifact.ref }, async () => ({ metadata: [artifact],
      validate(connection, _run, at) { check(connection, at); } }));
}
/** Exact original negative protocol fact. No physical permission or retry is
 * inferred from UNKNOWN, these persisted bytes or a parent-domain death. */
export async function validateDependencyUnknownClaim(driver: SqliteDriver, artifacts: ArtifactCatalog,
  source: import('./dependency-candidate.js').DependencyCandidateData, prepared: InvocationJournalEntry, claim: InvocationJournalEntry, unknown: InvocationJournalEntry) {
  const evidence = decodeDependencyClaimEvidence(await readCanonicalArtifact(artifacts, claim.evidenceRef!));
  const raw = decodeDependencyAmbiguity(await readCanonicalArtifact(artifacts, unknown.evidenceRef!));
  const { reason: _reason, ...observation } = raw;
  const identity = Object.fromEntries(Object.entries(observation).filter(([key]) =>
    !['brokerDispatchClosureRef', 'acquisitionEvidenceRef', 'acquisitionEvidenceDigest'].includes(key)));
  requireEqual(identity,
  { schemaVersion: 1, format: 'cliq-dependency-ambiguity-v1', runId: claim.runId, opId: claim.opId, attempt: claim.attempt,
    dispatchId: claim.dispatchId, claimJournalSeq: claim.seq, requestRef: claim.requestRef, target: claim.target, grantRef: claim.grantRef,
    brokerFenceTokenDigest: claim.brokerFenceTokenDigest },
  'dependency original UNKNOWN observation');
  for (const key of ['runId', 'opId', 'opKind', 'attempt', 'leaseEpoch', 'requestRef', 'target', 'grantRef', 'replayClass'] as const)
    requireEqual([claim[key], unknown[key]], [prepared[key], prepared[key]], 'dependency UNKNOWN exact original invocation');
  for (const key of ['dispatchId', 'supervisorInstanceId', 'stateOwnerEpoch', 'brokerFenceTokenDigest'] as const)
    requireEqual(unknown[key], claim[key], 'dependency UNKNOWN original permanent claim');
  const owner = claim.stateOwnerEpoch && readStateOwner(driver, claim.stateOwnerEpoch);
  if (!owner || owner.supervisorInstanceId !== claim.supervisorInstanceId || unknown.evidenceDigest !== unknown.evidenceRef ||
      unknown.resultRef !== undefined || unknown.receiptRef !== undefined || unknown.sandboxLaunchSpecRef !== undefined || unknown.timestamp < claim.timestamp)
    throw new TypeError('dependency UNKNOWN substitutes its original signed owner or result');
  let broker: ReturnType<typeof decodeDependencyBrokerDispatchClosure> | undefined, brokerRef: string | undefined;
  if (raw.reason === 'original_owner_joined_without_process_result') {
    brokerRef = raw.brokerDispatchClosureRef;
    broker = decodeDependencyBrokerDispatchClosure(await readCanonicalArtifact(artifacts, brokerRef));
    if (broker.runId !== claim.runId || broker.opId !== claim.opId ||
      broker.attempt !== claim.attempt || broker.dispatchId !== claim.dispatchId || broker.claimJournalSeq !== claim.seq ||
      broker.claimEvidenceRef !== claim.evidenceRef || broker.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest ||
      broker.observedAt < claim.timestamp || broker.observedAt > unknown.timestamp || broker.io.transferredBytes > source.plan.maxDownloadBytes ||
      broker.io.connectionCount > source.data.packages.length * 3)
      throw new TypeError('dependency UNKNOWN substitutes its original broker or bounded real traffic');
    await readSupervisorInspector(artifacts, owner, source.assembly, broker);
  } else {
    const death = await readStateOwnerDeath(artifacts, driver, { supervisorInstanceId: claim.supervisorInstanceId!, ownedAt: claim.timestamp });
    const history = await readRetainedStateOwnerHistory(driver, artifacts, death.successorOwner.ownerEpoch);
    if (!history.entries.some(entry => entry.owner.ownerEpoch === owner.ownerEpoch && canonicalSha256(entry.owner) === canonicalSha256(owner)) ||
        death.acquisitionEvidenceRef !== raw.acquisitionEvidenceRef || death.acquisitionEvidenceDigest !== raw.acquisitionEvidenceDigest ||
        death.successorOwner.acquiredAt > unknown.timestamp)
      throw new TypeError('dependency UNKNOWN lost its complete original StateOwner death chain');
    history.assertUnchanged(driver);
  }
  const budget = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, unknown.budgetSettlementRef!));
  if (budget.runId !== claim.runId || budget.opId !== claim.opId || budget.attempt !== claim.attempt || budget.preparedJournalSeq !== prepared.seq ||
      budget.terminalJournalSeq !== unknown.seq || budget.terminalPhase !== 'unknown' || budget.settledAt !== unknown.timestamp)
    throw new TypeError('dependency UNKNOWN lost its original pessimistic settlement');
  const one = { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 };
  for (const value of [prepared.budgetDelta, unknown.budgetDelta, budget.reserved, budget.consumed, budget.released]) requireEqual(value, one, 'dependency UNKNOWN full charge');
  const environment = await readRetainedDependencyLaunchEnvironment(artifacts, owner, source.spec, evidence.sandboxLaunchSpecRef);
  if (environment.spec.owner.workerLaunchId !== evidence.workerLaunchId || environment.spec.owner.dispatchId !== claim.dispatchId ||
      environment.spec.filesystem.kind !== 'run_generation') throw new TypeError('dependency UNKNOWN has no original fixed worker domain');
  return { prepared, claim, unknown, evidence, broker, brokerRef, ambiguity: raw, environment };
}
async function original(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: Cut) {
  if (!hasOnlySettledDependencyUnknowns(cut.journal)) throw new TypeError('dependency abandonment requires one exact charged UNKNOWN');
  const unknown = cut.journal.filter(row => row.target === 'builtin:dependency-acquire' && row.phase === 'unknown').at(-1)!;
  const [prepared, claim] = cut.journal.filter(row => row.opId === unknown.opId && row.attempt === unknown.attempt);
  const request = decodeDependencyRequest(await readCanonicalArtifact(artifacts, prepared!.requestRef));
  const progress = (await readDependencyHistory(driver, artifacts, cut)).get(request.candidateItemId);
  if (!progress || progress.ready || progress.failed) throw new TypeError('dependency UNKNOWN cannot replace a positively received result');
  const evidence = decodeDependencyClaimEvidence(await readCanonicalArtifact(artifacts, claim!.evidenceRef!));
  const source = await (await import('./dependency-candidate.js')).readRetainedDependencyCandidate(driver, artifacts, cut.run.id,
    { candidateItemId: request.candidateItemId, sourceCheckpointId: evidence.sourceCheckpointId, dependencyPlanRef: request.dependencyPlanRef,
      resultSourceRef: request.resultSourceRef, releaseKeys: artifacts.releaseTrustRoots() });
  return { ...await validateDependencyUnknownClaim(driver, artifacts, source, prepared!, claim!, unknown), source };
}
type ParentClosure = {
  schemaVersion: 1; format: 'cliq-dependency-parent-domain-closure-v1'; runId: string; opId: string; attempt: number; unknownJournalSeq: number;
  claimEvidenceRef: string; ambiguityEvidenceRef: string; workerLaunchId: string; generationRef: string;
  parentContainmentRef: string; parentDeathEvidenceRef: string; quarantineEvidenceRef: string; retirementEvidenceRef: string;
  broker: { kind: 'original_native_fence' } | { kind: 'claiming_owner_dead'; acquisitionEvidenceRef: string; acquisitionEvidenceDigest: string };
  observedAt: string; evidenceDigest: string;
};
function decodeParent(value: unknown): ParentClosure {
  assertControlWireJson(value); const v = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'unknownJournalSeq',
    'claimEvidenceRef', 'ambiguityEvidenceRef', 'workerLaunchId', 'generationRef', 'parentContainmentRef', 'parentDeathEvidenceRef',
    'quarantineEvidenceRef', 'retirementEvidenceRef', 'broker', 'observedAt', 'evidenceDigest']);
  if (v.schemaVersion !== 1 || v.format !== 'cliq-dependency-parent-domain-closure-v1' || v.evidenceDigest !== digestOmitting(v, 'evidenceDigest'))
    throw new TypeError('foreign dependency parent-domain closure');
  for (const key of ['runId', 'opId', 'workerLaunchId']) controlWireText(v[key], 256);
  for (const key of ['claimEvidenceRef', 'ambiguityEvidenceRef', 'generationRef', 'parentContainmentRef', 'parentDeathEvidenceRef', 'quarantineEvidenceRef', 'retirementEvidenceRef', 'evidenceDigest']) controlWireRef(v[key]);
  controlWireInteger(v.attempt, 0, 0); controlWireInteger(v.unknownJournalSeq, 1); parseCanonicalTime(controlWireText(v.observedAt, 24));
  const b = controlWireRecord(v.broker, ['kind'], ['acquisitionEvidenceRef', 'acquisitionEvidenceDigest']);
  if (b.kind === 'original_native_fence') controlWireRecord(b, ['kind']);
  else if (b.kind === 'claiming_owner_dead') { controlWireRecord(b, ['kind', 'acquisitionEvidenceRef', 'acquisitionEvidenceDigest']); controlWireRef(b.acquisitionEvidenceRef); controlWireRef(b.acquisitionEvidenceDigest); }
  else throw new TypeError('dependency parent-domain closure has another broker authority');
  return v as ParentClosure;
}

/** Only the existing genuine WorkerRecoveryTerminalPlan calls this after its
 * original native controller, descriptor walk and all resource joins. */
export async function prepareDependencyUnknownParentClosure(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, cut: RecoveryClosureV1,
  input: { launch: BoundWorkerLaunch; generation: WorkspaceGenerationStateV1; quarantine: Extract<WorkspaceGenerationQuarantineEvidenceV1, { reason: 'worker_recovery' }>;
    quarantineRef: string; retirement: WorkspaceGenerationRetirementEvidenceV1; retirementRef: string }) {
  if (!hasOnlySettledDependencyUnknowns(cut.journal)) return { metadata: [] as PublishedArtifact[], abandoned: [] as Abandonment[], assertBroker(_connection: SqliteConnection) {} };
  const frame = await original(driver, artifacts, cut), { claim, unknown } = frame;
  if (!cut.run.stopIntentRef || frame.evidence.workerLaunchId !== input.launch.launchId || claim.leaseEpoch !== input.launch.leaseEpoch ||
      input.launch.workspaceGenerationRef !== input.generation.generationRef || frame.environment.spec.filesystem.kind !== 'run_generation' ||
      frame.environment.spec.filesystem.generationRef !== input.generation.generationRef ||
      frame.environment.spec.parentWorkerContainmentRef !== input.launch.processContainmentRef ||
      input.quarantine.observedState.kind !== 'complete_tree') throw new TypeError('dependency UNKNOWN has no exact fully observed original parent quarantine');
  let broker: ParentClosure['broker'], assertBroker: (connection: SqliteConnection) => void;
  if (claim.stateOwnerEpoch === owner.ownerEpoch && claim.supervisorInstanceId === owner.supervisorInstanceId) {
    if (!frame.brokerRef || frame.ambiguity.reason !== 'original_owner_joined_without_process_result')
      throw new TypeError('current owner cannot borrow a predecessor process death');
    const ref = frame.brokerRef;
    const assert = () => assertDependencyUnknownBrokerFence(driver, owner, cut.run.id, claim.opId, claim.attempt, ref);
    assert(); broker = { kind: 'original_native_fence' }; assertBroker = assert;
  } else {
    const death = await readStateOwnerDeath(artifacts, driver, { supervisorInstanceId: claim.supervisorInstanceId!, ownedAt: claim.timestamp });
    const history = await readRetainedStateOwnerHistory(driver, artifacts, owner.ownerEpoch);
    const claiming = history.entries.find(entry => entry.owner.ownerEpoch === claim.stateOwnerEpoch), active = assertActiveStateOwner(driver, owner);
    if (!claiming || active.ownerEpoch <= claiming.owner.ownerEpoch || history.rootIdentity.identityDigest !== owner.stateRootIdentityDigest ||
        canonicalSha256(history.rootIdentity) !== owner.stateRootIdentityRef || claiming.owner.supervisorInstanceId !== claim.supervisorInstanceId)
      throw new TypeError('dependency UNKNOWN has no original same-StateRoot claiming process identity');
    assertBroker = connection => { assertActiveStateOwner(connection, owner); history.assertUnchanged(connection);
      const at = new Date(owner.filesystem.observePriorProcessDeath(claiming.process.pid, claiming.process.processStartToken)).toISOString();
      if (at < unknown.timestamp || at < active.acquiredAt) throw new TypeError('dependency broker process death observation predates its exact UNKNOWN'); };
    assertBroker(driver); broker = { kind: 'claiming_owner_dead', acquisitionEvidenceRef: death.acquisitionEvidenceRef, acquisitionEvidenceDigest: death.acquisitionEvidenceDigest };
  }
  const recovery = await readCanonicalArtifact<WorkerRecoveryEvidenceV1>(artifacts, input.quarantine.workerRecoveryEvidenceRef);
  const value: ParentClosure = { schemaVersion: 1, format: 'cliq-dependency-parent-domain-closure-v1', runId: cut.run.id,
    opId: claim.opId, attempt: claim.attempt, unknownJournalSeq: unknown.seq, claimEvidenceRef: claim.evidenceRef!, ambiguityEvidenceRef: unknown.evidenceRef!,
    workerLaunchId: input.launch.launchId, generationRef: input.generation.generationRef, parentContainmentRef: input.launch.processContainmentRef!,
    parentDeathEvidenceRef: recovery.containmentDeathEvidenceRef, quarantineEvidenceRef: input.quarantineRef, retirementEvidenceRef: input.retirementRef,
    broker, observedAt: input.retirement.observedAt, evidenceDigest: '' };
  value.evidenceDigest = digestOmitting(value, 'evidenceDigest'); decodeParent(value);
  const artifact = await artifacts.publishCanonical(value, value.format);
  return { metadata: [artifact], assertBroker, abandoned: [{ opId: unknown.opId, attempt: unknown.attempt, unknownJournalSeq: unknown.seq,
    budgetSettlementRef: unknown.budgetSettlementRef!, dispatchFenceOrDeathEvidenceRef: artifact.ref }] };
}

export async function validateDependencyUnknownTerminalHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1, detail: TerminalDetail): Promise<Abandonment[]> {
  const unknowns = new Set(cut.journal.filter(row => row.target === 'builtin:dependency-acquire' && row.phase === 'unknown').map(row => row.seq));
  const entries = detail.abandonedRetryInvocations.filter(entry => unknowns.has(entry.unknownJournalSeq));
  if (!entries.length) return [];
  if (entries.length !== 1 || !['failed', 'cancelled'].includes(cut.run.status) || !cut.run.stopIntentRef)
    throw new TypeError('dependency abandonment requires its exact stopped terminal owner');
  const entry = entries[0]!, proof = decodeParent(await readCanonicalArtifact(artifacts, entry.dispatchFenceOrDeathEvidenceRef));
  const frame = await original(driver, artifacts, cut), launch = readRequiredWorkerLaunch(driver, proof.workerLaunchId);
  const generation = cut.workspaceGenerations.find(row => row.generationRef === proof.generationRef);
  if (!generation || generation.phase !== 'retired' || launch.phase !== 'retired' || launch.retirementKind === 'preparation')
    throw new TypeError('dependency abandonment lacks its actual retired parent and generation');
  const retired = await readRetiredGenerationSource(driver, artifacts, { run: cut.run, spec: cut.runSpec, assembly: frame.source.assembly, generation });
  if (retired.source.phase !== 'quarantined' || retired.source.quarantineEvidenceRef !== proof.quarantineEvidenceRef ||
      proof.retirementEvidenceRef !== generation.retirementEvidenceRef || proof.claimEvidenceRef !== frame.claim.evidenceRef ||
      proof.ambiguityEvidenceRef !== frame.unknown.evidenceRef || proof.runId !== cut.run.id || proof.opId !== frame.claim.opId || proof.attempt !== frame.claim.attempt ||
      proof.unknownJournalSeq !== frame.unknown.seq || entry.opId !== frame.claim.opId || entry.attempt !== frame.claim.attempt ||
      entry.budgetSettlementRef !== frame.unknown.budgetSettlementRef || frame.evidence.workerLaunchId !== launch.launchId ||
      frame.environment.spec.filesystem.kind !== 'run_generation' || frame.environment.spec.filesystem.generationRef !== generation.generationRef ||
      frame.environment.spec.parentWorkerContainmentRef !== proof.parentContainmentRef || proof.parentContainmentRef !== launch.processContainmentRef)
    throw new TypeError('dependency abandonment substitutes original claim, broker fence or parent domain');
  const quarantine = await readCanonicalArtifact<Extract<WorkspaceGenerationQuarantineEvidenceV1, { reason: 'worker_recovery' }>>(artifacts, proof.quarantineEvidenceRef);
  const retirement = await readCanonicalArtifact<WorkspaceGenerationRetirementEvidenceV1>(artifacts, proof.retirementEvidenceRef);
  const recovery = await readCanonicalArtifact<WorkerRecoveryEvidenceV1>(artifacts, quarantine.workerRecoveryEvidenceRef);
  if (recovery.containmentDeathEvidenceRef !== proof.parentDeathEvidenceRef || recovery.oldWorkerLaunchId !== launch.launchId ||
      recovery.oldLeaseEpoch !== frame.claim.leaseEpoch || recovery.workspaceGenerationRef !== generation.generationRef ||
      quarantine.observedState.kind !== 'complete_tree' || proof.observedAt !== retirement.observedAt || proof.observedAt < frame.unknown.timestamp ||
      proof.observedAt > detail.createdAt || detail.createdAt > cut.run.updatedAt || parseCanonicalTime(cut.run.updatedAt) - parseCanonicalTime(proof.observedAt) > 5000)
    throw new TypeError('dependency abandonment has no original joined resource and fresh parent retirement closure');
  if (proof.broker.kind === 'claiming_owner_dead') {
    const death = await readStateOwnerDeath(artifacts, driver, { supervisorInstanceId: frame.claim.supervisorInstanceId!, ownedAt: frame.claim.timestamp });
    if (death.acquisitionEvidenceRef !== proof.broker.acquisitionEvidenceRef || death.acquisitionEvidenceDigest !== proof.broker.acquisitionEvidenceDigest)
      throw new TypeError('dependency abandonment substituted original broker process death');
  }
  return entries;
}
