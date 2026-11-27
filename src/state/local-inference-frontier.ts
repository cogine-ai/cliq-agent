import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeLocalInferenceFailure, localInferenceFailureSources, type LocalInferenceActivationCycleV1,
  type LocalInferenceActivationParticipantV1 } from '../kernel/local-inference.js';
import type { RecoveryClosureV1, Run } from '../kernel/types.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { decodeLocalZeroCostProvenanceData } from '../model/pricing.js';
import { recordAgentStopPredecessor, type AgentStopIntent } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { readLocalInferenceCycle, readLocalInferenceLaunch } from './local-inference-rows.js';
import { assertRetiredGenerationCut } from './generation-retirement.js';
import { isZeroBudget } from './invariants.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { appendRunStateEvent } from './reducers/invocation.js';
import { nextJournalSequence } from './repositories/journal.js';
import { readRun, readSessionPrincipalId } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';

type Cycle = LocalInferenceActivationCycleV1;
type Frontier = Extract<LocalInferenceActivationParticipantV1, { kind: 'run_model_frontier' }>;
type Intent = Extract<AgentStopIntent, { runtimeSubtype: 'local_inference_unavailable' }>;
function mismatch(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }

export function matchesLocalInferenceFrontier(run: Run, participant: Frontier): boolean {
  return run.id === participant.runId && run.revision === participant.runRevisionAtJoin && run.frontierRef === participant.frontierRef &&
    run.status === 'queued' && run.nextStep === 'agent' && !run.stopIntentRef && !run.activeWorkerLaunchId;
}

async function assertOriginalModel(artifacts: ArtifactCatalog, cut: RecoveryClosureV1, cycle: Cycle): Promise<void> {
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, cut.runSpec.assemblyRef));
  if (cut.runSpec.operation !== 'agent' || assembly.provider.name !== 'ollama' || assembly.provider.endpoint.kind !== 'local_zero_cost')
    mismatch('local inference cycle frontier lacks its original managed model');
  const provenance = decodeLocalZeroCostProvenanceData(await readCanonicalArtifact(artifacts, assembly.provider.endpoint.localProvenanceRef));
  if (provenance.ownerPrincipalId !== cycle.ownerPrincipalId || provenance.serviceSpecRef !== cycle.serviceSpecRef ||
      provenance.serviceSpecDigest !== cycle.serviceSpecDigest || provenance.localModelRegistrationRef !== cycle.localModelRegistrationRef ||
      provenance.localModelRegistrationDigest !== cycle.localModelRegistrationDigest)
    mismatch('local inference cycle frontier changed its original frozen model');
}

export async function readLocalInferenceFailureClosure(connection: SqliteConnection, artifacts: ArtifactCatalog, cycle: Cycle, failureRef: string) {
  const detail = decodeLocalInferenceFailure(await readCanonicalArtifact(artifacts, failureRef));
  const retained = cycle.launchIds.map(id => {
    const launch = readLocalInferenceLaunch(connection, id);
    if (!launch || launch.activationCycleId !== cycle.activationCycleId) mismatch('local inference failure lost its exact native launch');
    return launch;
  });
  localInferenceFailureSources(cycle, detail, retained);
  return detail;
}

/** Prepare the ordinary Stop intent and event for this exact queued Run.
 * Only the terminal activation transaction can publish them. */
export async function prepareLocalInferenceFrontierFailure(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cycle: Cycle, participant: Frontier, failureRef: string): Promise<(connection: SqliteConnection, now: string) => void> {
  const cut = await readRecoveryClosure(driver, artifacts, participant.runId);
  if (!matchesLocalInferenceFrontier(cut.run, participant)) return () => {};
  if (cut.workerLaunches.length || !isZeroBudget(cut.run.budgetReserved))
    mismatch('local inference failure cannot stop a frontier before its original worker and invocations retire');
  assertRetiredGenerationCut(driver, cut.run, cut.workspaceGenerations);
  await assertOriginalModel(artifacts, cut, cycle);
  const detail = await readLocalInferenceFailureClosure(driver, artifacts, cycle, failureRef);
  const intent: Intent = { schemaVersion: 1, runId: cut.run.id, createdAt: sampleCanonicalNow(), origin: 'runtime',
    targetStatus: 'failed', reason: 'runtime_failed', runtimeSubtype: 'local_inference_unavailable', activationCycleId: cycle.activationCycleId,
    serviceId: cycle.serviceId, frontierRef: participant.frontierRef, failureDetailRef: failureRef };
  if (intent.createdAt < detail.observedAt) mismatch('local inference Stop precedes its original failure');
  const recorded = recordAgentStopPredecessor(intent, undefined, cut.latestCheckpoint.id, cut.run.revision, cut.journal.length);
  const artifact = await artifacts.publishCanonical(recorded, 'cliq-stop-intent-v1');
  return (connection, now) => {
    const current = readRun(connection, participant.runId);
    if (!matchesLocalInferenceFrontier(current, participant) || now >= current.deadlineAt) return;
    if (intent.createdAt > now || canonicalSha256(current) !== canonicalSha256(cut.run) ||
        readSessionPrincipalId(connection, current.sessionId) !== cycle.ownerPrincipalId ||
        nextJournalSequence(connection, current.id) !== cut.journal.length + 1)
      mismatch('local inference failure Stop lost its exact original Run cut');
    assertRetiredGenerationCut(connection, current, cut.workspaceGenerations);
    const terminal = readLocalInferenceCycle(connection, cycle.activationCycleId);
    if (terminal?.phase !== 'failed' || terminal.failureDetailRef !== failureRef)
      mismatch('local inference failure Stop is outside the original terminal cycle transaction');
    insertArtifactMetadata(connection, artifact, now);
    const result = connection.prepare('UPDATE runs SET stop_intent_ref=?,revision=revision+1,updated_at=? WHERE id=? AND revision=? AND stop_intent_ref IS NULL')
      .run(artifact.ref, now, current.id, current.revision);
    if (result.changes !== 1n) mismatch('local inference failure Stop did not fence exactly its original Run');
    appendRunStateEvent(connection, readRun(connection, current.id), now);
  };
}

export async function validateLocalInferenceFrontierStop(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  intent: Intent): Promise<void> {
  const cycle = readLocalInferenceCycle(driver, intent.activationCycleId);
  if (cycle?.phase !== 'failed' || cycle.serviceId !== intent.serviceId || cycle.failureDetailRef !== intent.failureDetailRef ||
      cycle.finishedAt < intent.createdAt || !cycle.participants.some(participant => participant.kind === 'run_model_frontier' &&
        participant.runId === cut.run.id && participant.runRevisionAtJoin === intent.registeredRunRevision && participant.frontierRef === intent.frontierRef))
    mismatch('retained local inference Stop lacks its exact original cycle and Run frontier');
  await assertOriginalModel(artifacts, cut, cycle);
  const detail = await readLocalInferenceFailureClosure(driver, artifacts, cycle, intent.failureDetailRef);
  if (detail.observedAt > intent.createdAt) mismatch('retained local inference Stop precedes its original failure');
}
