import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import { decodeDeliveryCaptureTopology, decodeDeliveryTerminalProjectionEvidence, decodePublicationProof,
  publicationLocationKey, type DeliveryTerminalProjectionEvidence, type PublicationPathObservationV1, type PublicationProofV1,
  type PublicationTransientEnvelopeRetirementV1 } from '../kernel/publication.js';
import type { RecoveryClosureV1, Run } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { captureFrozenSourceProjection, MAX_SOURCE_PROJECTION_ENTRIES } from '../workspace/source-projection.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { decodeSourceManifest, decodeWorkspaceEntries, decodeWorkspaceIdentity } from './decoders.js';
import { deliveryPublicationCheckpointId, deliveryPublicationTerminalCheckpointId, publicationEnvelopeLocations,
  readOwnedPublicationProof, readPublicationPrefix, readPublicationPathRetirement } from './delivery-publication-progress.js';
import { validatePublicationTerminalPathState } from './delivery-publication-recovery.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { assertRetiredGenerationCut } from './generation-retirement.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath, stateRootIdentityForLock } from './native-owner.js';
import { assertOwnedPublicationArtifacts, readOwnedPublicationCompletion, readOwnedPublicationPreparationClosure,
  readOwnedPublicationReconciledRetirement, type PublicationInvocationOwner } from './publication-invocation.js';
import { openPublicationProjectionGate, prepareOwnedPublicationGenerationSeal, readDeliveryTerminalSqlCut } from './publication-finalization.js';
import { readDeliveryPublicationClosure } from './recovery-closure.js';
import { assertDeliveryPublicationMaintenanceExecution, type DeliveryPublicationMaintenanceTask } from './run-execution.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readAgentStop } from './stop-recovery.js';
import { readSupervisorInspector, supervisorInspectorIdentity } from './supervisor-inspector.js';

const brand: unique symbol = Symbol('OwnedPublicationAbortFinalization');
export type OwnedPublicationAbortFinalization = Readonly<{ readonly [brand]: true }>;
type Prefix = Awaited<ReturnType<typeof readPublicationPrefix>>;
type Resources = ReturnType<typeof assertDeliveryPublicationMaintenanceExecution>;
type Seal = Awaited<ReturnType<typeof prepareOwnedPublicationGenerationSeal>>['seal'];
type Completion = Exclude<ReturnType<typeof readOwnedPublicationCompletion>, { disposition: 'unknown' }> |
  ReturnType<typeof readOwnedPublicationReconciledRetirement>;
type Binding = {
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; execution: unknown; task: DeliveryPublicationMaintenanceTask;
  resources: Resources; cut: RecoveryClosureV1; prefix: Prefix; sql: ReturnType<typeof readDeliveryTerminalSqlCut>;
  originals: ReadonlyMap<string, Completion>; gate: Awaited<ReturnType<typeof openPublicationProjectionGate>>;
  evidence: DeliveryTerminalProjectionEvidence; evidenceRef: string; metadata: PublishedArtifact[]; seal?: Seal; closed: boolean;
};
const plans = new WeakMap<object, Binding>();
const failures = new WeakMap<object, ResourceRetirementError>();
const compare = (a: string, b: string) => Buffer.compare(Buffer.from(a), Buffer.from(b));
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function original(driver: SqliteDriver, owner: StateOwnerContext, token: unknown, connection: SqliteConnection): Binding {
  const value = token !== null && typeof token === 'object' ? plans.get(token) : undefined;
  if (!value || value.driver !== driver || value.owner !== owner)
    throw new TypeError('a genuine original publication abort finalization is required');
  const failure = failures.get(value.task); if (failure) throw failure;
  if (value.closed) invalid('publication abort projection descriptors are already joined');
  assertDeliveryPublicationMaintenanceExecution(driver, owner, value.execution, value.task, value.artifacts, connection);
  value.resources.signal.throwIfAborted(); return value;
}
function close(value: Binding) {
  if (value.closed) return;
  const failure = failures.get(value.task); if (failure) throw failure;
  try { value.gate.close(); value.closed = true; }
  catch (cause) {
    const error = cause instanceof ResourceRetirementError ? cause : new ResourceRetirementError('publication abort projection did not join', cause);
    failures.set(value.task, error); throw error;
  }
}
function assertReady(cut: RecoveryClosureV1, prefix: Prefix): void {
  const authorization = prefix.authorization;
  if (cut.runSpec.operation !== 'delivery' || !authorization || !cut.run.stopIntentRef || cut.run.nextStep !== 'delivery' ||
      !['queued', 'running'].includes(cut.run.status) || cut.run.waitingOnRef || cut.run.waitingReason ||
      !prefix.forward.some(entry => entry.claim) || prefix.forward.some(entry => !entry.result || entry.result.item.outcome === 'unknown') ||
      prefix.abortResults.length !== authorization.context.plan.abortOperations.length || prefix.abortResults.some(entry =>
        !entry.result || !['completed', 'not_created', 'retained_planned_descendant'].includes(entry.result.item.outcome)))
    invalid('publication abort waits for its complete nonambiguous stopped forward and abort prefix');
}
/** The original stopped task captures the actual partial workspace. It never
 * changes the host, adopts a missing arena or treats an UNKNOWN as retired. */
export async function prepareOwnedPublicationAbortFinalization(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  execution: unknown, task: DeliveryPublicationMaintenanceTask): Promise<OwnedPublicationAbortFinalization> {
  let resources = assertDeliveryPublicationMaintenanceExecution(driver, owner, execution, task, artifacts);
  const failure = failures.get(task); if (failure) throw failure;
  const reads = artifacts.withReadSignal(resources.signal);
  let { cut, prefix } = await readDeliveryPublicationClosure(driver, reads, resources.runId);
  if (cut.run.revision !== resources.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'publication abort task revision changed');
  assertReady(cut, prefix);
  const originals = new Map<string, Completion>();
  const physicalOwners = new Map<string, PublicationInvocationOwner>(), seen = new Set<string>();
  const originalMetadata: PublishedArtifact[] = [];
  for (const token of resources.publicationOwners) {
    assertOwnedPublicationArtifacts(driver, owner, execution, token, artifacts);
    const entry = prefix.entries.get(token.opId);
    if (!entry || seen.has(token.opId)) invalid('publication abort substituted or duplicated an original physical owner');
    seen.add(token.opId);
    if (entry.preparationClosure) {
      const actual = readOwnedPublicationPreparationClosure(driver, owner, execution, token, driver);
      requireEqual(actual.prepared, entry.prepared, 'abort original closed preparation');
      requireEqual(actual.operation, entry.operation, 'abort original closed preparation operation');
      requireEqual(actual.closure, entry.preparationClosure.closure, 'abort original closed preparation retirement');
      if (actual.planRef !== entry.planRef || actual.sequence !== entry.sequence || actual.closureRef !== entry.preparationClosure.closureRef)
        invalid('publication abort changed its original undispatched preparation closure');
      originalMetadata.push(...actual.metadata); continue;
    }
    if (!entry.claim) invalid('publication abort retains an unclosed original physical preparation');
    const originalCompletion = readOwnedPublicationCompletion(driver, owner, execution, token, driver);
    const completion = originalCompletion.disposition === 'unknown'
      ? readOwnedPublicationReconciledRetirement(driver, artifacts, owner, execution, token, entry) : originalCompletion;
    if (originals.has(completion.prepared.opId))
      invalid('publication abort retains an ambiguous or duplicate original physical owner');
    originals.set(completion.prepared.opId, completion);
    physicalOwners.set(completion.prepared.opId, token);
  }
  const claimed = [...prefix.entries.values()].filter(entry => entry.claim);
  if ([...originals.keys()].some(opId => !claimed.some(entry => entry.prepared.opId === opId)))
    invalid('publication abort substituted an unrelated original physical owner');
  let seal: Seal | undefined;
  if (cut.run.activeWorkerLaunchId) {
    const originalOwner = prefix.forward.map(entry => physicalOwners.get(entry.prepared.opId)).find(value => value !== undefined);
    if (!resources.retire || !originalOwner) invalid('publication abort has no original M retirement owner');
    const prepared = await prepareOwnedPublicationGenerationSeal(driver, artifacts, owner, execution, originalOwner, task);
    ({ cut, prefix } = prepared); seal = prepared.seal;
    resources = assertDeliveryPublicationMaintenanceExecution(driver, owner, execution, task, artifacts);
    assertReady(cut, prefix);
  } else {
    if (cut.workerLaunches.length || cut.workspaceGenerations.some(generation => !['sealed', 'retired'].includes(generation.phase)))
      invalid('publication abort lacks complete worker-free original retirement');
    assertRetiredGenerationCut(driver, cut.run, cut.workspaceGenerations);
  }
  const authorization = prefix.authorization!, plan = authorization.context.plan, planRef = authorization.context.planRef;
  const sql = readDeliveryTerminalSqlCut(driver, cut.run.id, prefix.admission.source.run.id);
  requireEqual(sql.run, cut.run, 'abort original Run before physical observation');
  requireEqual(sql.source, prefix.admission.source.run, 'abort original source before physical observation');
  const intent = await readAgentStop(driver, reads, cut);
  const latest = new Map<string, PublicationPathObservationV1>();
  const slots: Array<{ location: ReturnType<typeof publicationEnvelopeLocations>[number]; ref: string }> = [];
  const arenas: Array<{ arenaId: string; ref: string }> = [];
  const envelopeRetirements: PublicationTransientEnvelopeRetirementV1[] = [];
  const transientLocations: ReturnType<typeof publicationEnvelopeLocations> = [];
  const proofs = new Map<string, PublicationProofV1>();
  const metadata: PublishedArtifact[] = [...originalMetadata];
  let latestObservedAt = intent.createdAt;
  for (const entry of claimed) {
    const completion = originals.get(entry.prepared.opId);
    const retirement = entry.result && 'retirement' in entry.result.item ? entry.result.item.retirement : undefined;
    if (!entry.result || !retirement)
      invalid('publication abort lost its original closed path result or arena retirement');
    if (completion) {
      requireEqual(completion.prepared, entry.prepared, 'abort original physical preparation');
      requireEqual(completion.claim, entry.claim, 'abort original permanent native claim');
      requireEqual(completion.birth, entry.birth, 'abort original physical arena birth');
      if (entry.result.item.evidenceRef !== completion.evidenceRef)
        invalid('publication abort changed its original live native result');
      const originalRetirement = 'retirement' in completion ? completion.retirement : (() => {
        if (!completion.arenaRetirementRef) invalid('publication abort lost its original joined native arena');
        return { slotObservationRefs: completion.slotObservationRefs, arenaRetirementRef: completion.arenaRetirementRef };
      })();
      requireEqual(retirement, originalRetirement,
        'abort exact original durably retained retirement refs');
      metadata.push(...completion.metadata);
    }
    const proof = await readOwnedPublicationProof(driver, reads, prefix.admission, planRef, entry.result.item.evidenceRef, entry.claim);
    if (completion) requireEqual(proof, completion.evidence, 'abort exact original native result evidence');
    proofs.set(entry.prepared.opId, proof);
    if (proof.observedAt > latestObservedAt) latestObservedAt = proof.observedAt;
    const graph = await readPublicationPathRetirement(driver, reads, prefix.admission, entry, retirement,
      entry.result.item.createdAt, entry.result.item.createdAt);
    if (graph.latestObservedAt > latestObservedAt) latestObservedAt = graph.latestObservedAt;
    envelopeRetirements.push({ arenaId: entry.birth!.arenaId, retirement });
    transientLocations.push(...publicationEnvelopeLocations(entry));
    if (graph.kind === 'current_namespace') {
      if (proof.kind !== 'terminal_receipt' || proof.namespaceRetirementEvidenceRef !== graph.namespaceEvidence.ref)
        invalid('publication abort changed its actual current-namespace receipt');
      requireEqual(proof.after, graph.destinationEvidence.proof.observation, 'abort actual original-inode current destination');
    } else {
      for (const { ref, proof: absent } of graph.slotObservations) slots.push({ location: absent.observation.location, ref });
      arenas.push({ arenaId: entry.birth!.arenaId, ref: graph.arenaRetirement.ref });
    }
  }
  // Apply observations in semantic order, not Map insertion order: a genuine
  // completed abort can supersede its earlier directory-creator receipt.
  for (const entry of [...prefix.forward, ...prefix.abort]) {
    if (!entry.claim || !entry.result) continue;
    const proof = proofs.get(entry.prepared.opId)!;
    if (proof.kind === 'terminal_receipt') latest.set(entry.operation.path, proof.after);
    else if (proof.kind === 'path_observation') latest.set(entry.operation.path, proof.observation);
  }
  for (const entry of prefix.abortResults) if (!entry.claimed && entry.result) {
    const proof = await readOwnedPublicationProof(driver, reads, prefix.admission, planRef, entry.result.item.evidenceRef);
    const ancestor = proof.kind === 'ancestor_projection_absence'
      ? await readOwnedPublicationProof(driver, reads, prefix.admission, planRef, proof.ancestorObservationRef) : undefined;
    const actual = validatePublicationTerminalPathState(proof, ancestor);
    if (actual.path !== entry.operation.path) invalid('abort uncreated directory lost its actual original target');
    const observation = proof.kind === 'path_observation' ? proof.observation : ancestor?.kind === 'path_observation' ? ancestor.observation : undefined;
    if (observation?.location.kind !== 'workspace') invalid('abort uncreated directory has no actual workspace anchor');
    // Preserve the real direct-parent observation, including an unchanged A
    // leaf or a non-traversable ancestor. Never manufacture a missing target's
    // parent inode. The complete prefix already proved this not-created edge.
    latest.set(observation.location.path, observation);
  }
  slots.sort((a, b) => compare(publicationLocationKey(a.location), publicationLocationKey(b.location)));
  arenas.sort((a, b) => compare(a.arenaId, b.arenaId));
  envelopeRetirements.sort((a, b) => compare(a.arenaId, b.arenaId));
  transientLocations.sort((a, b) => compare(publicationLocationKey(a), publicationLocationKey(b)));
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(reads, prefix.admission.target.workspaceIdentityRef));
  if (workspace.kind !== 'live' || workspace.identityDigest !== prefix.admission.target.workspaceIdentityDigest)
    invalid('publication abort lost its original live workspace identity');
  const topology = decodeDeliveryCaptureTopology(await readCanonicalArtifact(reads, plan.captureTopologyRef));
  const desired = decodeSourceManifest(await readCanonicalArtifact(reads, plan.desiredSourceRef));
  const profile = decodeSandboxProfile(await readCanonicalArtifact(reads, cut.runSpec.sandboxProfileRef));
  const capture = () => captureFrozenSourceProjection({ workspaceRoot: resources.workspaceRoot, controlledHome: resources.controlledHome,
    stateOwnerLock: owner.filesystem, workspaceIdentityDigest: workspace.identityDigest, artifacts: reads,
    sourceProjectionRef: cut.runSpec.sourceProjectionRef, sourceProjectionDigest: desired.sourceProjectionDigest,
    maxEntries: MAX_SOURCE_PROJECTION_ENTRIES, maxBytes: profile.resources.maxGenerationBytes,
    maxSingleFileBytes: profile.resources.maxSingleFileBytes, signal: resources.signal });
  const candidate = await capture(), source = decodeSourceManifest(await readCanonicalArtifact(reads, candidate.resultWorkspaceManifestRef));
  const entries = decodeWorkspaceEntries(await readCanonicalArtifact(reads, source.entriesRef));
  const gate = await openPublicationProjectionGate(resources.workspaceRoot, entries.entries, plan.forwardOperations.map(value => value.path), resources.signal);
  let value: Binding | undefined;
  try {
    assertHeldWorkspaceRoot(resources.controlledHome); stateRootIdentityForLock(owner.filesystem);
    requireEqual(resources.workspaceRoot.identity, workspace.rootIdentity, 'abort actual original workspace root');
    if (heldWorkspaceRootPath(resources.workspaceRoot) !== workspace.canonicalRootPath) invalid('abort actual root path changed');
    gate.assertOriginalObservations(topology, latest, workspace.identityDigest);
    const actual = await capture();
    if (actual.resultWorkspaceManifestRef !== candidate.resultWorkspaceManifestRef) invalid('abort actual partial root projection changed during capture');
    gate.assertHeld();
    const observedAt = sampleCanonicalNow();
    if (observedAt < latestObservedAt || observedAt < cut.run.updatedAt) invalid('abort actual projection predates its original stopped resource closure');
    const stateOwner = assertActiveStateOwner(driver, owner), inspector = supervisorInspectorIdentity(stateOwner);
    const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format); metadata.push(inspectorArtifact, ...candidate.metadata, ...actual.metadata);
    await readSupervisorInspector(reads, stateOwner, prefix.admission.source.assembly,
      { inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, observedAt });
    type Fields<T = PublicationProofV1> = T extends PublicationProofV1 ? Omit<T, 'schemaVersion' | 'format' | 'deliveryRunId' | 'deliveryPlanRef' |
      'workspaceIdentityRef' | 'workspaceIdentityDigest' | 'inspectorIdentityRef' | 'inspectorIdentityDigest' | 'observedAt' | 'proofDigest'> : never;
    const publish = async (fields: Fields) => {
      resources.signal.throwIfAborted(); gate.assertHeld();
      const proof = { schemaVersion: 1, format: 'cliq-publication-proof-v1', deliveryRunId: cut.run.id, deliveryPlanRef: planRef,
        workspaceIdentityRef: prefix.admission.target.workspaceIdentityRef, workspaceIdentityDigest: workspace.identityDigest,
        inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
        ...fields, observedAt, proofDigest: '' };
      proof.proofDigest = digestOmitting(proof, 'proofDigest'); decodePublicationProof(proof);
      const artifact = await artifacts.publishCanonical(proof, proof.format); metadata.push(artifact); return artifact.ref;
    };
    const observedPathStates: DeliveryTerminalProjectionEvidence['observedPathStates'] = [];
    for (const path of plan.forwardOperations.map(value => value.path).sort(compare)) {
      const actual = gate.observe(path, workspace.identityDigest), ref = await publish({ kind: 'path_observation', observation: actual.observation });
      const evidenceRef = actual.ancestorPath ? await publish({ kind: 'ancestor_projection_absence', path,
        ancestorPath: actual.ancestorPath, ancestorObservationRef: ref }) : ref;
      observedPathStates.push({ path, state: actual.ancestorPath ? { kind: 'absent' } : actual.observation.state, evidenceRef });
    }
    const forwardResultItemRefs = prefix.forward.filter(entry => entry.claim).map(entry => entry.result!.row.payloadRef);
    const abortResultItemRefs = prefix.abortResults.map(entry => entry.result!.row.payloadRef);
    const unstartedForwardOperationIds = plan.forwardOperations.slice(forwardResultItemRefs.length).map(entry => entry.operationId);
    const transientAbsenceEvidenceRef = await publish(envelopeRetirements.some(value => 'kind' in value.retirement)
      ? { kind: 'transient_absence', transientLocations, envelopeRetirements }
      : { kind: 'transient_absence', transientLocations, observationRefs: slots.map(value => value.ref),
        arenaRetirementRefs: arenas.map(value => value.ref) });
    const projectionClosureEvidenceRef = await publish({ kind: 'projection_closure', selectedBranch: 'abort',
      observedSourceRef: actual.resultWorkspaceManifestRef, observedPathEvidenceRefs: observedPathStates.map(value => value.evidenceRef),
      forwardResultItemRefs, unstartedForwardOperationIds, abortResultItemRefs });
    const gitIndexUnchangedEvidenceRef = await publish({ kind: 'git_index_unchanged', repositoryKind: 'non_git' });
    const core = { schemaVersion: 1 as const, deliveryRunId: cut.run.id, deliveryPlanRef: planRef, selectedBranch: 'abort',
      observedSourceRef: actual.resultWorkspaceManifestRef, observedPathStates, forwardResultItemRefs, unstartedForwardOperationIds,
      abortResultItemRefs, transientAbsenceEvidenceRef, projectionClosureEvidenceRef, gitIndexUnchangedEvidenceRef, observedAt };
    const evidence = decodeDeliveryTerminalProjectionEvidence({ ...core, evidenceDigest: canonicalSha256(core) });
    const artifact = await artifacts.publishCanonical(evidence, 'cliq-delivery-terminal-projection-evidence-v1'); metadata.push(artifact);
    requireEqual(readDeliveryTerminalSqlCut(driver, cut.run.id, prefix.admission.source.run.id), sql,
      'abort original complete SQL cut after actual projection');
    value = { driver, artifacts, owner, execution, task, resources, cut, prefix, sql, originals, gate,
      evidence, evidenceRef: artifact.ref, metadata, ...(seal ? { seal } : {}), closed: false };
    const token = Object.freeze({ [brand]: true as const }); plans.set(token, value);
    return token;
  } catch (error) {
    if (value) close(value);
    else try { gate.close(); } catch (cause) {
      const failure = cause instanceof ResourceRetirementError ? cause : new ResourceRetirementError('abort projection did not join', cause);
      failures.set(task, failure); throw failure;
    }
    throw error;
  }
}

/** Private Stop writer friend. Structural refs, callbacks and future SQL cuts
 * cannot supply this plan; every returned action reasserts its real issuer. */
export function readOwnedPublicationAbortFinalization(driver: SqliteDriver, owner: StateOwnerContext,
  token: OwnedPublicationAbortFinalization, runId: string) {
  const value = original(driver, owner, token, driver);
  if (value.cut.run.id !== runId) throw new TypeError('publication abort finalization belongs to another Run');
  return { cut: value.cut, evidenceRef: value.evidenceRef, observedAt: value.evidence.observedAt,
    publicationResultItemRefs: [...value.evidence.forwardResultItemRefs, ...value.evidence.abortResultItemRefs],
    closedJournalSeqs: new Set([...value.prefix.entries.values()].filter(entry => entry.preparationClosure ||
      entry.result && entry.result.item.outcome !== 'unknown' && ['completed', 'failed'].includes(entry.history.at(-1)!.phase))
      .map(entry => entry.history.at(-1)!.seq)),
    metadata(connection: SqliteConnection): readonly PublishedArtifact[] {
      original(driver, owner, token, connection); return [...value.metadata, ...(value.seal?.metadata ?? [])];
    },
    seal: value.seal,
    async refresh() { original(driver, owner, token, driver); await value.seal?.refresh(); },
    validate(connection: SqliteConnection, run: Run, committedAt?: string) {
      original(driver, owner, token, connection); assertActiveStateOwner(connection, owner); requireEqual(run, value.cut.run, 'abort exact original Run');
      requireEqual(readDeliveryTerminalSqlCut(connection, run.id, value.sql.source.id), value.sql, 'abort exact original full SQL cut');
      value.gate.assertHeld();
      if (committedAt) {
        const now = sampleCanonicalNow();
        if (committedAt < value.evidence.observedAt || now < committedAt ||
            parseCanonicalTime(now) - parseCanonicalTime(value.evidence.observedAt) > 5000)
          invalid('abort actual root projection is outside its original freshness cut');
      }
    },
    assertFresh(committedAt: string, connection: SqliteConnection) {
      original(driver, owner, token, connection); value.gate.assertHeld();
      const now = sampleCanonicalNow();
      if (committedAt < value.evidence.observedAt || now < committedAt ||
          parseCanonicalTime(now) - parseCanonicalTime(value.evidence.observedAt) > 5000)
        invalid('abort actual root projection is outside its original freshness cut');
    },
    commit(connection: SqliteConnection, run: Run, committedAt: string) {
      original(driver, owner, token, connection); value.gate.assertHeld();
      connection.prepare(`INSERT INTO checkpoints (id,schema_version,run_id,based_on_run_revision,run_item_seq,
        context_manifest_ref,journal_seq,workspace_state_ref,created_at,reason) VALUES (?,1,?,?,?,?,?,?,?,'auto')`)
        .run(value.prefix.forward.at(-1)?.receivedHandoff
          ? deliveryPublicationTerminalCheckpointId(run.id, value.evidence.deliveryPlanRef)
          : deliveryPublicationCheckpointId(run.id, value.evidence.deliveryPlanRef), run.id, BigInt(run.revision),
          BigInt(value.cut.items.length), value.cut.latestCheckpoint.contextManifestRef, BigInt(value.cut.journal.length),
          value.cut.latestCheckpoint.workspaceStateRef, committedAt);
    } };
}
export function closeOwnedPublicationAbortFinalization(driver: SqliteDriver, owner: StateOwnerContext,
  token: OwnedPublicationAbortFinalization): void {
  const value = token !== null && typeof token === 'object' ? plans.get(token) : undefined;
  if (!value || value.driver !== driver || value.owner !== owner) throw new TypeError('a genuine original publication abort finalization is required');
  close(value);
}
