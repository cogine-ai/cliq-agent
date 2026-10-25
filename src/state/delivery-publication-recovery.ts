import { assertArtifactRef, parseCanonicalTime } from '../kernel/identity.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeDeliveryTerminalProjectionEvidence, decodePublicationProof, publicationLocationKey, type PublicationPathState } from '../kernel/publication.js';
import type { Checkpoint, RunFrontier, SourceManifest, WorkspaceEntry } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeSourceManifest, decodeWorkspaceEntries } from './decoders.js';
import { assertPublicationReadCut, deliveryPublicationCheckpointId, deliveryPublicationTerminalCheckpointId, publicationEnvelopeLocations, readOwnedPublicationProof,
  readPublicationInspector, readPublicationPathCheckpoint, readPublicationPathRetirement, readPublicationPrefix } from './delivery-publication-progress.js';
import { assertRetiredGenerationCut } from './generation-retirement.js';
import { decodeRunResult } from './result-artifacts.js';
import { readDeliveryVerification } from './run-result-recovery.js';
import { readCheckpoint } from './rows.js';
import { checkEntries, checkNonGitSourceManifest } from './source-validation.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { RecoveryClosureV1 } from '../kernel/types.js';

function projectedState(entry: WorkspaceEntry | undefined, observed: PublicationPathState) {
  if (!entry) { requireEqual(observed, { kind: 'absent' }, 'publication projected absent destination'); return; }
  if (entry.kind === 'file') {
    if (observed.kind !== 'file' || observed.digest !== entry.blobRef || (observed.mode & 0o111 ? 0o755 : 0o644) !== entry.mode)
      throw new TypeError('publication projected file differs from the complete observed SourceManifest');
  } else if (entry.kind === 'symlink') {
    requireEqual(observed, { kind: 'symlink', target: entry.target, digest: entry.targetDigest }, 'publication projected symlink bytes');
  } else if (observed.kind !== 'directory') throw new TypeError('publication projected directory is absent from the actual root observation');
}

/** Canonical cut correspondence only. The complete retained reader must first
 * verify the entire settled prefix and its last actual path Checkpoint. A
 * file-only Plan needs no invented abort item to anchor the terminal cut. The
 * exact current Journal also includes any fully closed unclaimed preparation,
 * which adds neither a path item nor a path Checkpoint. */
export function validatePublicationAbortCheckpoint(checkpoint: Checkpoint, previous: Checkpoint, currentJournalSeq: number): void {
  if (checkpoint.runId !== previous.runId || checkpoint.reason !== 'auto' ||
      !Number.isSafeInteger(currentJournalSeq) || currentJournalSeq < previous.journalSeq ||
      checkpoint.runItemSeq !== previous.runItemSeq || checkpoint.journalSeq !== currentJournalSeq ||
      checkpoint.contextManifestRef !== previous.contextManifestRef || checkpoint.workspaceStateRef !== previous.workspaceStateRef ||
      checkpoint.basedOnRunRevision <= previous.basedOnRunRevision || checkpoint.createdAt < previous.createdAt)
    throw new TypeError('publication abort projection lost its exact final path cut');
}

/** Retained preparation closure only, never permission to skip a native claim,
 * worker retirement or fresh publication projection. The ordinary Stop path
 * may consume these exact terminal seqs only when no publication dispatched. */
export async function readUnclaimedPublicationStopHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1): Promise<ReadonlySet<number>> {
  return readUnclaimedPublicationStopHistoryData(driver, artifacts, cut, () => readPublicationPrefix(driver, artifacts, cut));
}

export async function readUnclaimedPublicationStopHistoryData(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  readPrefix: () => ReturnType<typeof readPublicationPrefix>): Promise<ReadonlySet<number>> {
  if (cut.runSpec.operation !== 'delivery' || !cut.run.stopIntentRef ||
      cut.journal.some(entry => entry.opKind === 'publish' && entry.phase === 'dispatch_claimed'))
    throw new TypeError('only undispatched stopping delivery preparations have unclaimed closure');
  const prefix = await readPrefix(), entries = [...prefix.entries.values()];
  if (prefix.forward.length || prefix.abort.length || prefix.abortResults.length || prefix.resultRefs.size || entries.some(entry =>
    entry.claim || !entry.preparationClosure || entry.history.at(-1)?.seq !== entry.preparationClosure.terminal.seq ||
    entry.preparationClosure.terminal.phase !== 'failed'))
    throw new TypeError('unclaimed publication Stop awaits its exact complete original preparation retirement');
  return new Set(entries.map(entry => entry.preparationClosure!.terminal.seq));
}

/** Closed retained-data association only, never an original native observation
 * or StateOwner/cleanup authority. The complete reader independently validates
 * each supplied proof with readOwnedPublicationProof before consuming it. */
export function validatePublicationTerminalPathState(value: unknown, ancestor?: unknown) {
  const proof = decodePublicationProof(value);
  if ('recoveryOriginRef' in proof)
    throw new TypeError('an original-claim recovery proof cannot replace a fresh terminal observation');
  if (proof.kind === 'path_observation' && proof.observation.location.kind === 'workspace' && ancestor === undefined)
    return { path: proof.observation.location.path, state: proof.observation.state };
  if (proof.kind === 'ancestor_projection_absence') {
    const actual = decodePublicationProof(ancestor);
    if ('recoveryOriginRef' in actual)
      throw new TypeError('an original-claim recovery proof cannot replace a fresh terminal observation');
    if (canonicalSha256(actual) !== proof.ancestorObservationRef || actual.kind !== 'path_observation' || actual.observation.location.kind !== 'workspace' ||
        actual.observation.location.path !== proof.ancestorPath || actual.observation.state.kind === 'directory')
      throw new TypeError('publication descendant absence lacks its direct original non-traversable ancestor observation');
    for (const key of ['deliveryRunId', 'deliveryPlanRef', 'workspaceIdentityRef', 'workspaceIdentityDigest',
      'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt'] as const)
      if (actual[key] !== proof[key]) throw new TypeError('publication descendant absence changed its original owner or observation');
    return { path: proof.path, state: { kind: 'absent' as const } };
  }
  throw new TypeError('publication final path state is not its original actual descriptor observation');
}

async function readObservedSource(artifacts: ArtifactCatalog, cut: RecoveryClosureV1, ref: string, desired: SourceManifest) {
  const source = decodeSourceManifest(await readCanonicalArtifact(artifacts, ref)); checkNonGitSourceManifest(source);
  if (source.role !== 'result' || source.sourceProjectionRef !== cut.runSpec.sourceProjectionRef)
    throw new TypeError('publication terminal source changed its frozen role or projection');
  for (const key of ['workspaceIdentityDigest', 'sourceProjectionRef', 'sourceProjectionDigest', 'frozenIgnoreRulesRef', 'frozenIgnoreRulesDigest'] as const)
    if (source[key] !== desired[key]) throw new TypeError('publication terminal source changed its original workspace/ignore identity');
  const entries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, source.entriesRef)); checkEntries(entries);
  if (entries.treeDigest !== source.treeDigest) throw new TypeError('publication terminal source tree differs from its original complete entries');
  for (const entry of entries.entries) if (entry.kind === 'file')
    for await (const _ of artifacts.readChunks(entry.blobRef, entry.size)) { /* original full hash and close, never a trusted prefix */ }
  return { source, entries: new Map(entries.entries.map(entry => [entry.path, entry])) };
}

/** Retained graph validation, not a native observation, release token or live
 * cleanup brand. Only the owning actual native producer can atomically publish
 * these item/claim/Checkpoint edges; a loose CAS proof never supplies them. */
export async function readDeliveryTerminalProjection(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1, ref: string) {
  return readDeliveryTerminalProjectionData(driver, artifacts, cut, ref, {
    prefix: () => readPublicationPrefix(driver, artifacts, cut),
    verification: closureRef => readDeliveryVerification(driver, artifacts, cut, closureRef)
  });
}

/** Reader-family data only, never a physical projection owner. */
export async function readDeliveryTerminalProjectionData(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1, ref: string,
  data: { prefix(): ReturnType<typeof readPublicationPrefix>; verification(ref: string): ReturnType<typeof readDeliveryVerification> }) {
  await assertPublicationReadCut(driver, artifacts, cut); assertArtifactRef(ref);
  const evidence = decodeDeliveryTerminalProjectionEvidence(await readCanonicalArtifact(artifacts, ref));
  if (evidence.deliveryRunId !== cut.run.id) throw new TypeError('publication terminal projection belongs to another Run');
  const prefix = await data.prefix();
  let verified = prefix.authorization?.verified;
  if (!verified) {
    let closureRef: string | undefined;
    if (cut.run.frontierRef) {
      const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, cut.run.frontierRef);
      if (frontier.kind === 'finalize' && frontier.operation === 'delivery' && frontier.deliveryTerminalProjectionEvidenceRef === ref)
        closureRef = frontier.verificationClosureRef;
    } else if (cut.run.resultRef) {
      const result = decodeRunResult(await readCanonicalArtifact(artifacts, cut.run.resultRef));
      if (result.deliveryTerminalProjectionEvidenceRef === ref) closureRef = result.verificationClosureRef;
    }
    if (!closureRef) throw new TypeError('no-op projection has no original committed verification/finalize edge');
    verified = await data.verification(closureRef);
  }
  const { deliveryPlan: plan, deliveryPlanRef: planRef } = verified;
  if (evidence.deliveryPlanRef !== planRef) throw new TypeError('publication terminal projection substituted its original complete Plan');
  const noOp = plan.forwardOperations.length === 0;
  if (noOp && (prefix.authorization || prefix.entries.size || evidence.selectedBranch !== 'forward_finalize' || plan.abortOperations.length))
    throw new TypeError('no-op delivery acquired approval, publication dispatch, abort or path items');
  if (!noOp && (!prefix.authorization?.grant || !prefix.authorization.grantRef))
    throw new TypeError('publication terminal projection has no original complete allow closure');
  // The full typed handoff, not row existence or a missing legacy CP, selects
  // the role. Its original M seal CP is immutable and cannot be overwritten by
  // a successor's fresh terminal projection.
  const handedOff = prefix.forward.at(-1)?.receivedHandoff !== undefined;
  const checkpoint = readCheckpoint(driver, handedOff ? deliveryPublicationTerminalCheckpointId(cut.run.id, planRef)
    : deliveryPublicationCheckpointId(cut.run.id, planRef));
  if (checkpoint.runId !== cut.run.id || checkpoint.reason !== 'auto' || checkpoint.basedOnRunRevision >= cut.run.revision ||
      checkpoint.createdAt < evidence.observedAt || checkpoint.createdAt < verified.checkpoint.createdAt ||
      parseCanonicalTime(checkpoint.createdAt) - parseCanonicalTime(evidence.observedAt) > 5000 ||
      checkpoint.runItemSeq !== cut.items.length || checkpoint.journalSeq !== cut.journal.length ||
      checkpoint.workspaceStateRef !== verified.checkpoint.workspaceStateRef)
    throw new TypeError('publication terminal projection has no fresh exact original atomic Checkpoint');
  if (cut.run.activeWorkerLaunchId || cut.workerLaunches.length ||
      cut.workspaceGenerations.some(value => value.phase !== 'sealed' && value.phase !== 'retired'))
    throw new TypeError('publication terminal projection has live worker or generation resources');
  assertRetiredGenerationCut(driver, cut.run, cut.workspaceGenerations);
  const forwardClaims = prefix.forward.filter(entry => entry.claim);
  if (evidence.selectedBranch === 'forward_finalize') {
    if (!noOp && !handedOff || cut.run.stopIntentRef || cut.run.cancelRequested || checkpoint.createdAt >= cut.run.deadlineAt ||
        forwardClaims.length !== plan.forwardOperations.length || prefix.forward.length !== plan.forwardOperations.length || prefix.abort.length ||
        prefix.forward.some(entry => entry.result?.item.outcome !== 'completed') || evidence.observedSourceRef !== plan.desiredSourceRef)
      throw new TypeError('forward publication lacks its complete unstopped ordered native result closure');
    requireEqual(evidence.forwardResultItemRefs, prefix.forward.map(entry => entry.result!.row.payloadRef), 'publication exact completed forward result list');
    requireEqual(evidence.abortResultItemRefs, [], 'successful publication forbids abort results');
    requireEqual(evidence.unstartedForwardOperationIds, [], 'successful publication forbids an unstarted suffix');
  } else {
    if (!cut.run.stopIntentRef || !forwardClaims.length || forwardClaims.some(entry => !entry.result || entry.result.item.outcome === 'unknown') ||
        prefix.abortResults.length !== plan.abortOperations.length || prefix.abortResults.some(entry => !entry.result ||
          !['completed', 'not_created', 'retained_planned_descendant'].includes(entry.result.item.outcome)))
      throw new TypeError('aborted publication lacks its stopped, complete nonambiguous partial-state closure');
    requireEqual(evidence.forwardResultItemRefs, forwardClaims.map(entry => entry.result!.row.payloadRef), 'publication exact started forward result prefix');
    requireEqual(evidence.unstartedForwardOperationIds, plan.forwardOperations.slice(forwardClaims.length).map(entry => entry.operationId),
      'publication exact unstarted forward suffix');
    requireEqual(evidence.abortResultItemRefs, prefix.abortResults.map(entry => entry.result!.row.payloadRef), 'publication exact abort result sequence');
  }
  if (noOp) {
    if (checkpoint.basedOnRunRevision !== verified.checkpoint.basedOnRunRevision ||
        checkpoint.createdAt !== verified.checkpoint.createdAt || checkpoint.contextManifestRef !== verified.checkpoint.contextManifestRef ||
        checkpoint.runItemSeq !== verified.checkpoint.runItemSeq || checkpoint.journalSeq !== verified.checkpoint.journalSeq)
      throw new TypeError('no-op verification and actual root projection were not the same original transaction');
  } else {
    if (!prefix.previousCheckpoint) throw new TypeError('publication final projection lost its original last path Checkpoint');
    if (evidence.selectedBranch === 'forward_finalize') {
      const original = prefix.forward.at(-1)!;
      if (!original?.result) throw new TypeError('publication final projection lost its original last result');
      await readPublicationPathCheckpoint(artifacts, cut, checkpoint, prefix.previousCheckpoint, [original.result], original.history.at(-1)!.seq);
    } else validatePublicationAbortCheckpoint(checkpoint, prefix.previousCheckpoint, cut.journal.length);
  }
  const desired = decodeSourceManifest(await readCanonicalArtifact(artifacts, plan.desiredSourceRef));
  const observed = await readObservedSource(artifacts, cut, evidence.observedSourceRef, desired);
  const expectedPaths = plan.forwardOperations.map(entry => entry.path).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  requireEqual(evidence.observedPathStates.map(entry => entry.path), expectedPaths, 'publication exact touched destination projection');
  const absence = await readOwnedPublicationProof(driver, artifacts, prefix.admission, planRef, evidence.transientAbsenceEvidenceRef);
  const projection = await readOwnedPublicationProof(driver, artifacts, prefix.admission, planRef, evidence.projectionClosureEvidenceRef);
  const index = await readOwnedPublicationProof(driver, artifacts, prefix.admission, planRef, evidence.gitIndexUnchangedEvidenceRef);
  const originalInspector = await readPublicationInspector(driver, artifacts, prefix.admission, projection);
  if (absence.kind !== 'transient_absence' || projection.kind !== 'projection_closure' || index.kind !== 'git_index_unchanged' ||
      projection.observedAt !== evidence.observedAt || [absence, index].some(proof => proof.observedAt > evidence.observedAt ||
        proof.inspectorIdentityRef !== projection.inspectorIdentityRef || proof.inspectorIdentityDigest !== projection.inspectorIdentityDigest) ||
      checkpoint.createdAt < originalInspector.owner.acquiredAt ||
      originalInspector.owner.state === 'terminal' && checkpoint.createdAt > originalInspector.owner.releasedAt)
    throw new TypeError('publication final projection lost its exact original owner/inspection closure');
  for (const state of evidence.observedPathStates) {
    const proof = await readOwnedPublicationProof(driver, artifacts, prefix.admission, planRef, state.evidenceRef);
    if (proof.observedAt > evidence.observedAt || proof.inspectorIdentityRef !== projection.inspectorIdentityRef ||
        proof.inspectorIdentityDigest !== projection.inspectorIdentityDigest)
      throw new TypeError('publication final path state is not its original actual descriptor observation');
    const ancestor = proof.kind === 'ancestor_projection_absence'
      ? await readOwnedPublicationProof(driver, artifacts, prefix.admission, planRef, proof.ancestorObservationRef) : undefined;
    const actual = validatePublicationTerminalPathState(proof, ancestor);
    if (actual.path !== state.path) throw new TypeError('publication final path state names another workspace path');
    requireEqual(actual.state, state.state, 'publication terminal exact observed state'); projectedState(observed.entries.get(state.path), state.state);
  }
  const locations = [...prefix.entries.values()].flatMap(publicationEnvelopeLocations)
    .sort((left, right) => Buffer.compare(Buffer.from(publicationLocationKey(left)), Buffer.from(publicationLocationKey(right))));
  requireEqual(absence.transientLocations, locations, 'publication exact claimed private arena slots');
  const claimed = [...prefix.entries.values()].filter(entry => entry.claim && entry.birth)
    .sort((left, right) => Buffer.compare(Buffer.from(left.birth!.arenaId), Buffer.from(right.birth!.arenaId)));
  if (absence.envelopeRetirements !== undefined) {
    requireEqual(absence.envelopeRetirements.map(envelope => envelope.arenaId), claimed.map(entry => entry.birth!.arenaId),
      'publication terminal every actual claimed namespace envelope');
  } else if (absence.arenaRetirementRefs.length !== claimed.length)
    throw new TypeError('publication terminal projection did not retire every actual claimed arena');
  for (let position = 0; position < claimed.length; position++) {
    const entry = claimed[position]!, birth = entry.birth!;
    const retirement = entry.result && 'retirement' in entry.result.item ? entry.result.item.retirement : undefined;
    if (!retirement) throw new TypeError('publication terminal lost its original durable retirement');
    if (absence.envelopeRetirements !== undefined) {
      requireEqual(absence.envelopeRetirements[position]!.retirement, retirement, 'publication terminal exact result retirement envelope');
    } else {
      if ('kind' in retirement || retirement.arenaRetirementRef !== absence.arenaRetirementRefs[position])
        throw new TypeError('publication original descriptor aggregate cannot assert namespace absence');
      for (let slot = 0; slot < locations.length; slot++) {
        const location = locations[slot]!;
        if (location.kind !== 'publication_arena' || location.arenaId !== birth.arenaId) continue;
        const originalIndex = publicationEnvelopeLocations(entry).findIndex(value => publicationLocationKey(value) === publicationLocationKey(location));
        if (retirement.slotObservationRefs[originalIndex] !== absence.observationRefs[slot])
          throw new TypeError('publication terminal absence substituted its original durable slot edge');
      }
    }
    const graph = await readPublicationPathRetirement(driver, artifacts, prefix.admission, entry, retirement, absence.observedAt, absence.observedAt);
    if (graph.latestObservedAt > absence.observedAt) throw new TypeError('publication terminal predates actual namespace retirement');
  }
  requireEqual(projection.selectedBranch, evidence.selectedBranch, 'publication original terminal branch');
  requireEqual(projection.observedSourceRef, evidence.observedSourceRef, 'publication original complete root source');
  requireEqual(projection.observedPathEvidenceRefs, evidence.observedPathStates.map(entry => entry.evidenceRef), 'publication exact terminal path refs');
  for (const field of ['forwardResultItemRefs', 'unstartedForwardOperationIds', 'abortResultItemRefs'] as const)
    requireEqual(projection[field], evidence[field], 'publication exact terminal result projection');
  if (index.repositoryKind !== 'non_git' || observed.source.git !== undefined)
    throw new TypeError('publication requires its implemented non-Git index closure');
  await assertPublicationReadCut(driver, artifacts, cut);
  return { evidence, evidenceRef: ref, checkpoint, closedPublicationJournalSeqs: new Set([...prefix.entries.values()]
    .filter(entry => entry.preparationClosure || entry.result && entry.result.item.outcome !== 'unknown' &&
      ['completed', 'failed'].includes(entry.history.at(-1)!.phase))
    .map(entry => entry.history.at(-1)!.seq)) };
}
