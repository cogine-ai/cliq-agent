import { canonicalSha256 } from '../kernel/canonical.js';
import { parseCanonicalTime } from '../kernel/identity.js';
import type { PublicationPathWait } from '../kernel/reconciliation.js';
import type { Run } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ArtifactCatalog } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { decodePublicationPathWait } from './publication-reconciliation-artifacts.js';
import { assertOwnedPublicationReconciliationTask, type DeliveryPublicationReconciliationTask } from './run-execution.js';
import { readRun } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';

export type PublicationReconciliationTaskReceipt = Readonly<{ readonly __publicationReconciliationTaskReceipt: unique symbol }>;
export type PublicationReconciliationTask = Readonly<{ work: Promise<Run>; signal: AbortSignal;
  cancelAndJoin(): Promise<PublicationReconciliationTaskReceipt> }>;
export type PublicationReconciliationTaskBinding = { driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext;
  execution: unknown; task: DeliveryPublicationReconciliationTask; run: Run; wait: PublicationPathWait };
type Joined = { driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; execution: unknown;
  task: DeliveryPublicationReconciliationTask; runId: string; runRevision: number; waitingSubjectRef: string;
  dispatchDigest: string; probeNonceDigest: string; inspectorTaskId: string; joinedAt: string };
const receipts = new WeakMap<object, Joined>();
const active = new WeakMap<StateOwnerContext, Map<string, { waitRef: string; task: DeliveryPublicationReconciliationTask;
  producer: PublicationReconciliationTask }>>();

/** Fixed internal owning work and join, not a mutation callback or caller
 * evidence. The real RunExecution pending task is registered before the first
 * await, including shutdown's genuine cancelled-before-first-I/O path. */
export function startPublicationReconciliationTask(binding: PublicationReconciliationTaskBinding,
  operation: (signal: AbortSignal) => Promise<Run>, joinResources: () => Promise<void>): PublicationReconciliationTask {
  assertOwnedPublicationReconciliationTask(binding.driver, binding.owner, binding.execution, binding.task, binding.artifacts);
  binding = Object.freeze({ ...binding });
  const run = immutableSnapshot(binding.run), wait = decodePublicationPathWait(binding.wait), owner = binding.owner;
  const state = wait.probeState;
  if (state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'publication probe requires its one persisted in-flight dispatch');
  const dispatch = state.dispatch, waitRef = canonicalSha256(wait), current = readRun(binding.driver, run.id);
  if (dispatch.subjectKind !== 'publication') throw new TypeError('publication task substituted its descriptor subject');
  const stable = ({ revision: _revision, updatedAt: _time, cancelRequested: _cancel, stopIntentRef: _stop, ...value }: Run) => value;
  if (run.status !== 'waiting' || run.waitingReason !== 'reconciliation' || run.waitingOnRef !== waitRef || wait.runId !== run.id ||
      dispatch.owningSupervisorInstanceId !== owner.supervisorInstanceId || current.revision < run.revision ||
      canonicalSha256(stable(current)) !== canonicalSha256(stable(run)) || typeof operation !== 'function' || typeof joinResources !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'publication probe task lost its actual committed subject or owner');
  const prior = active.get(owner)?.get(run.id);
  if (prior?.waitRef === waitRef) {
    if (prior.task !== binding.task) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication nonce already belongs to its original probe task');
    return prior.producer;
  }
  const abort = new AbortController();
  let resourcesJoined: Promise<void> | undefined, retirementFailure: ResourceRetirementError | undefined;
  const work = Promise.resolve().then(() => {
    abort.signal.throwIfAborted();
    return operation(abort.signal);
  }).catch((error: unknown) => { if (error instanceof ResourceRetirementError) retirementFailure = error; throw error; })
    .finally(() => {
      resourcesJoined = Promise.resolve().then(joinResources).catch((error: unknown) => {
        retirementFailure ??= error instanceof ResourceRetirementError ? error :
          new ResourceRetirementError('publication probe resources did not complete their actual join', error);
        throw retirementFailure;
      });
      return resourcesJoined;
    });
  let joining: Promise<PublicationReconciliationTaskReceipt> | undefined;
  const producer: PublicationReconciliationTask = Object.freeze({ work, signal: abort.signal, cancelAndJoin() {
    if (this !== producer) throw new TypeError('invalid publication probe task receiver');
    if (joining) return joining;
    abort.abort(new KernelStorageError('RECOVERY_REQUIRED', 'publication probe was cancelled'));
    joining = (async () => {
      await work.catch(() => {});
      if (!resourcesJoined) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication probe did not join its original resources');
      await resourcesJoined;
      if (retirementFailure) throw retirementFailure;
      const joinedAt = sampleCanonicalNow();
      if (joinedAt < dispatch.probeStartedAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication probe join has a regressed time');
      const receipt = Object.freeze({}) as PublicationReconciliationTaskReceipt;
      receipts.set(receipt, { driver: binding.driver, artifacts: binding.artifacts, owner, execution: binding.execution, task: binding.task,
        runId: run.id, runRevision: run.revision, waitingSubjectRef: waitRef, dispatchDigest: dispatch.dispatchDigest,
        probeNonceDigest: dispatch.probeNonceDigest, inspectorTaskId: dispatch.inspectorTaskId, joinedAt });
      return receipt;
    })().catch((error: unknown) => { joining = undefined; throw error; });
    return joining;
  } });
  let ownerTasks = active.get(owner); if (!ownerTasks) active.set(owner, ownerTasks = new Map());
  ownerTasks.set(run.id, { waitRef, task: binding.task, producer });
  return producer;
}

export function assertPublicationReconciliationTaskReceipt(receipt: PublicationReconciliationTaskReceipt | undefined,
  binding: PublicationReconciliationTaskBinding, closedAt: string): void {
  const joined = receipt && typeof receipt === 'object' ? receipts.get(receipt) : undefined;
  if (!joined) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication closure requires its actual cancelled and joined task');
  assertOwnedPublicationReconciliationTask(binding.driver, binding.owner, binding.execution, binding.task, binding.artifacts);
  const state = binding.wait.probeState;
  parseCanonicalTime(closedAt);
  if ((state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight') || state.dispatch.subjectKind !== 'publication' || joined.driver !== binding.driver ||
      joined.artifacts !== binding.artifacts || joined.owner !== binding.owner || joined.execution !== binding.execution ||
      joined.task !== binding.task || joined.runId !== binding.run.id || joined.runRevision > binding.run.revision ||
      joined.waitingSubjectRef !== canonicalSha256(binding.wait) || joined.waitingSubjectRef !== binding.run.waitingOnRef ||
      joined.dispatchDigest !== state.dispatch.dispatchDigest || joined.probeNonceDigest !== state.dispatch.probeNonceDigest ||
      joined.inspectorTaskId !== state.dispatch.inspectorTaskId || joined.joinedAt < state.dispatch.probeStartedAt || joined.joinedAt > closedAt)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'publication closure replaced its original task, owner, nonce or actual join');
}
