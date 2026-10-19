import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, identityHash, normalizeBoundedText } from '../kernel/identity.js';
import type { PublicationMaintenanceAuthorityV1, PublicationPathGrantV1, PublicationPathRequestV1 } from '../kernel/delivery-invocation.js';
import { decodePublicationProof } from '../kernel/publication.js';
import type { RecoveryClosureV1, RunFrontier } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readDeliveryAuthorization } from './delivery-approval.js';
import { derivePublicationGrant, derivePublicationMaintenance } from './delivery-policy.js';
import { decodeAgentStop } from '../runtime/stop.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readStateOwner } from './state-owner.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { ZERO_BUDGET } from './rows.js';

const FORWARD_RESERVATION = Object.freeze({ ...ZERO_BUDGET, toolCalls: 1 });
type Selection = { opId: string; attempt: number };

function selection(cut: RecoveryClosureV1, input: Selection): Selection {
  if (cut.runSpec.operation !== 'delivery') throw new TypeError('publication history requires a delivery Run');
  if (!exactKeys(input, ['opId', 'attempt']))
    throw new TypeError('publication history accepts only its exact original operation and attempt');
  input = immutableSnapshot(input);
  if (typeof input.opId !== 'string' ||
      normalizeBoundedText(input.opId, 1, 128) !== input.opId || input.attempt !== 0)
    throw new TypeError('publication history accepts only its exact original operation and attempt');
  return input;
}

/** Retained request/grant/Journal linkage only. This does not validate a native
 * effect, an ordered path-result prefix, a planned parent's physical birth or
 * the whole-plan live preflight, and never mints a publication release token.
 * Those independent graphs must be checked by the owning publication/recovery
 * path. In particular this reader cannot turn an approved Plan into live I/O. */
export async function readPublicationPreparationHistory(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: RecoveryClosureV1, input: Selection) {
  input = selection(cut, input);
  requireEqual(readInvocationJournal(driver, cut.run.id), cut.journal, 'publication exact retained Journal cut');
  const authorization = await readDeliveryAuthorization(driver, artifacts, cut);
  const result = await readPreparation(driver, artifacts, cut, input, authorization);
  requireEqual(readInvocationJournal(driver, cut.run.id), cut.journal, 'publication retained Journal remained the same cut');
  return result;
}

// The aggregate full-R walk shares only its own once-validated immutable
// authorization. No external caller can provide or cache that selection.
async function readPreparation(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  input: Selection, authorization: Awaited<ReturnType<typeof readDeliveryAuthorization>>) {
  if (!authorization?.grant || !authorization.grantRef || authorization.decision.decision !== 'allow')
    throw new TypeError('publication preparation has no complete original plan allow closure');
  const history = cut.journal.filter(row => row.opId === input.opId), prepared = history[0];
  if (!prepared || prepared.phase !== 'prepared' || prepared.opKind !== 'publish' || prepared.attempt !== 0 ||
      !prepared.grantRef || prepared.replayClass !== 'reconcile' || prepared.idempotencyKey !== undefined ||
      history.some(row => row.attempt !== 0 || row.opKind !== 'publish') ||
      history.filter(row => row.phase === 'prepared').length !== 1)
    throw new TypeError('publication cannot replace, retry or reinterpret its original prepared attempt');
  const request = await readCanonicalArtifact<PublicationPathRequestV1>(artifacts, prepared.requestRef);
  const grant = await readCanonicalArtifact<PublicationPathGrantV1 | PublicationMaintenanceAuthorityV1>(artifacts, prepared.grantRef);
  assertArtifactRef(request.frontierRef);
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, request.frontierRef);
  const sequence = request.sequence, index = request.operationIndex;
  if ((sequence !== 'forward' && sequence !== 'abort') || !Number.isSafeInteger(index) || index < 0)
    throw new TypeError('publication request has no fixed sequence and operation index');
  const expectedFrontier: RunFrontier = { ...authorization.frontier,
    phase: sequence === 'forward' ? 'publish' : 'abort_cleanup', nextPathOperationIndex: index };
  requireEqual(frontier, expectedFrontier, 'publication original proof-carrying path frontier');
  const context = { ...authorization.context, frontierRef: request.frontierRef };
  const common = { context, parent: authorization.grant, parentRef: authorization.grantRef,
    decision: authorization.decision, operationIndex: index, issuedAt: grant.issuedAt };
  let derived: ReturnType<typeof derivePublicationGrant> | ReturnType<typeof derivePublicationMaintenance>;
  if (sequence === 'forward') {
    if (grant.format !== 'cliq-operation-grant-v1') throw new TypeError('productive publication cannot borrow maintenance authority');
    derived = derivePublicationGrant({ ...common, sequence });
  } else {
    if (grant.format !== 'cliq-publication-maintenance-authority-v1' || !cut.run.stopIntentRef)
      throw new TypeError('abort maintenance requires its distinct original stopping authority');
    derived = derivePublicationMaintenance({ ...common, stopIntentRef: grant.subject.stopIntentRef,
      creatorReceiptRef: grant.subject.creatorReceiptRef });
    const stop = decodeAgentStop(await readCanonicalArtifact(artifacts, grant.subject.stopIntentRef), cut.run);
    if (stop.createdAt > grant.issuedAt) throw new TypeError('abort maintenance preceded its original StopIntent');
    const operation = context.plan.abortOperations[index]!;
    const creator = context.plan.forwardOperations.find(value => value.operationId === operation.createdByOperationId)!;
    const creatorOpId = identityHash('cliq-publication-operation-v1',
      cut.run.id, context.planRef, 'forward', String(creator.index), creator.operationId);
    const completed = cut.journal.filter(row => row.opKind === 'publish' && row.opId === creatorOpId &&
      row.phase === 'completed' && row.receiptRef === grant.subject.creatorReceiptRef);
    const receipt = decodePublicationProof(await readCanonicalArtifact(artifacts, grant.subject.creatorReceiptRef));
    if (completed.length !== 1 || completed[0]!.seq >= prepared.seq || completed[0]!.timestamp > grant.issuedAt ||
        receipt.kind !== 'terminal_receipt' || receipt.sequence !== 'forward' || receipt.deliveryRunId !== cut.run.id ||
        receipt.deliveryPlanRef !== context.planRef || receipt.operationId !== creator.operationId ||
        receipt.operationIndex !== creator.index || receipt.opId !== creatorOpId || receipt.attempt !== 0 ||
        receipt.after.state.kind !== 'directory' || receipt.after.location.kind !== 'workspace' || receipt.after.location.path !== operation.path)
      throw new TypeError('abort maintenance has no original completed directory creator');
    // This is only the retained authority edge. The owning prefix reader also
    // validates the receipt's native birth/owner/Checkpoint graph, stopping
    // branch, prior envelopes and exact target before any maintenance release.
  }
  requireEqual(request, derived.request, 'publication exact original path request');
  requireEqual(grant, derived.grant, 'publication exact derived one-dispatch child grant');
  requireEqual(await readCanonicalArtifact(artifacts, request.targetRef), derived.target, 'publication exact path target');
  if (prepared.runId !== cut.run.id || prepared.opId !== request.opId || prepared.target !== request.targetRef ||
      prepared.requestRef !== canonicalSha256(request) || prepared.grantRef !== canonicalSha256(grant) ||
      prepared.timestamp < grant.issuedAt || grant.format === 'cliq-operation-grant-v1' && prepared.timestamp >= grant.expiresAt ||
      prepared.seq <= authorization.checkpoint.journalSeq || prepared.timestamp < authorization.checkpoint.createdAt ||
      sequence === 'forward' && prepared.timestamp >= cut.run.deadlineAt ||
      prepared.leaseEpoch < (sequence === 'forward' ? 1 : 0) || history.some(row => row.runId !== prepared.runId || row.requestRef !== prepared.requestRef ||
        row.target !== prepared.target || row.grantRef !== prepared.grantRef || row.leaseEpoch !== prepared.leaseEpoch ||
        row.replayClass !== 'reconcile' || row.idempotencyKey !== undefined || row.sandboxLaunchSpecRef !== undefined ||
        row.brokerFenceTokenDigest !== undefined))
    throw new TypeError('publication Journal changed its original child request, grant, lease or lifetime');
  requireEqual(prepared.budgetDelta, sequence === 'forward' ? FORWARD_RESERVATION : ZERO_BUDGET,
    'publication original productive or recovery-maintenance reservation');
  const claims = history.filter(row => row.phase === 'dispatch_claimed');
  if (claims.length > 1) throw new TypeError('publication child grant dispatched more than once');
  const claim = claims[0];
  if (claim) {
    if (history[1] !== claim || claim.seq <= prepared.seq || claim.timestamp < prepared.timestamp ||
        grant.format === 'cliq-operation-grant-v1' && claim.timestamp >= grant.expiresAt || !claim.dispatchId ||
        !claim.supervisorInstanceId || !claim.stateOwnerEpoch)
      throw new TypeError('publication claim is not its unique original dispatch');
    requireEqual(claim.budgetDelta, ZERO_BUDGET, 'publication claim cannot reserve or settle budget');
    const originalOwner = readStateOwner(driver, claim.stateOwnerEpoch);
    if (!originalOwner || originalOwner.supervisorInstanceId !== claim.supervisorInstanceId ||
        originalOwner.acquiredAt > claim.timestamp || originalOwner.state === 'terminal' && originalOwner.releasedAt < claim.timestamp)
      throw new TypeError('publication claim does not belong to its original StateOwner lifetime');
    if (sequence === 'forward') {
      const launches = readWorkerLaunchesForRun(driver, cut.run.id).filter(launch => launch.phase !== 'preparing' &&
        launch.leaseEpoch === claim.leaseEpoch && launch.supervisorInstanceId === claim.supervisorInstanceId &&
        launch.activatedAt !== undefined && launch.activatedAt <= claim.timestamp &&
        (launch.phase !== 'retired' || launch.retiredAt !== undefined && launch.retiredAt >= claim.timestamp));
      if (launches.length !== 1) throw new TypeError('productive publication lacks its unique original activated worker');
    }
  }
  return { authorization, plan: authorization.context.plan, planRef: authorization.context.planRef,
    sequence, operation: derived.operation, request, target: derived.target, grant, grantRef: prepared.grantRef,
    frontier, frontierRef: request.frontierRef, prepared, claim, history };
}

/** The presence of this verified historical claim still grants no maintenance
 * or semantic release. A successor cannot adopt it by calling this reader. */
export async function readPublicationClaimHistory(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: RecoveryClosureV1, input: Selection) {
  input = selection(cut, input);
  const retained = await readPublicationPreparationHistory(driver, artifacts, cut, input);
  if (!retained.claim) throw new TypeError('publication has no original permanent dispatch claim');
  return { ...retained, claim: retained.claim };
}

/** Reverse coverage at the actual outer RecoveryClosure, not inside approval
 * (which this reader itself consumes). No recursive own-R walk and no effect
 * or live authority is inferred from validating the original Journal graph. */
export async function validatePublicationInvocationHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  if (cut.runSpec.operation !== 'delivery') throw new TypeError('publication history requires a delivery Run');
  const operations = new Set(cut.journal.filter(entry => entry.opKind === 'publish').map(entry => entry.opId));
  const result = new Map<string, Awaited<ReturnType<typeof readPublicationPreparationHistory>>>();
  for (const opId of operations) {
    const history = cut.journal.filter(entry => entry.opId === opId);
    if (history[0]?.phase !== 'prepared' || history.filter(entry => entry.phase === 'prepared').length !== 1)
      throw new TypeError('publication history has no unique original preparation');
  }
  requireEqual(readInvocationJournal(driver, cut.run.id), cut.journal, 'publication aggregate original Journal cut');
  const authorization = await readDeliveryAuthorization(driver, artifacts, cut);
  for (const opId of operations) {
    const prepared = cut.journal.find(entry => entry.opId === opId)!;
    result.set(opId, await readPreparation(driver, artifacts, cut, selection(cut, { opId, attempt: prepared.attempt }), authorization));
  }
  requireEqual(readInvocationJournal(driver, cut.run.id), cut.journal, 'publication aggregate Journal remained the same cut');
  return result;
}
