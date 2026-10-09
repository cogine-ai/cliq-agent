import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { Run, WorkerDeathWait } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import type { StateOwnerContext } from './state-owner.js';

export type WorkerRecoveryTaskReceipt = Readonly<{ readonly __workerRecoveryTaskReceipt: unique symbol }>;
export type WorkerRecoveryTask = Readonly<{
  work: Promise<Run>;
  signal: AbortSignal;
  cancelAndJoin(): Promise<WorkerRecoveryTaskReceipt>;
}>;
type Binding = { run: Run; wait: WorkerDeathWait; owner: Pick<StateOwnerContext, 'ownerEpoch' | 'supervisorInstanceId'> };
type JoinedTask = {
  runId: string; registeredRunRevision: number; waitingSubjectRef: string; dispatchDigest: string;
  probeNonceDigest: string; inspectorTaskId: string; ownerEpoch: number; supervisorInstanceId: string; joinedAt: string;
};
const joinedTasks = new WeakMap<object, JoinedTask>();

/** Internal trusted producer only. The callbacks are the actual owning work
 * and its resource retirement, never client-supplied evidence or stand-ins. */
export function startWorkerRecoveryTask(binding: Binding, operation: (signal: AbortSignal) => Promise<Run>,
  joinResources: () => Promise<void>): WorkerRecoveryTask {
  const run = immutableSnapshot(binding.run), wait = immutableSnapshot(binding.wait);
  const { ownerEpoch, supervisorInstanceId } = binding.owner;
  if (run.status !== 'waiting' || run.waitingReason !== 'reconciliation' || run.waitingOnRef !== canonicalSha256(wait) ||
      wait.runId !== run.id || wait.probeState.phase !== 'automatic_in_flight' || wait.probeState.dispatch.subjectKind !== 'worker_recovery' ||
      wait.probeState.dispatch.owningSupervisorInstanceId !== supervisorInstanceId || !Number.isSafeInteger(ownerEpoch) || ownerEpoch < 1 ||
      typeof operation !== 'function' || typeof joinResources !== 'function') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'worker task requires its committed exact owner and dispatch');
  }
  const dispatch = wait.probeState.dispatch;
  if (dispatch.dispatchDigest !== digestOmitting(dispatch, 'dispatchDigest') || dispatch.inspectorTaskId !==
      identityHash(run.id, canonicalSha256(wait.subject), 'automatic', wait.probeState.automaticProbeCount, dispatch.probeNonceDigest)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'worker task substitutes its committed inspection identity');
  }
  const abort = new AbortController();
  let resourcesJoined: Promise<void> | undefined;
  let operationRetirementFailure: ResourceRetirementError | undefined;
  // Callers synchronously register this object before its actual work can run.
  const work = Promise.resolve().then(() => operation(abort.signal)).catch((error: unknown) => {
    if (error instanceof ResourceRetirementError) operationRetirementFailure = error;
    throw error;
  }).finally(() => {
    resourcesJoined = Promise.resolve().then(joinResources);
    return resourcesJoined;
  });
  let joining: Promise<WorkerRecoveryTaskReceipt> | undefined;
  const task: WorkerRecoveryTask = Object.freeze({ work, signal: abort.signal, cancelAndJoin() {
    if (this !== task) throw new TypeError('invalid worker inspection task');
    if (joining) return joining;
    abort.abort(new KernelStorageError('RECOVERY_REQUIRED', 'worker inspection task was cancelled'));
    joining = (async () => {
      // An inspection error is not a failed join. Native/file cleanup errors
      // are retained separately and can never mint a positive receipt.
      await work.catch(() => {});
      if (!resourcesJoined) throw new KernelStorageError('RECOVERY_REQUIRED', 'registered worker task has not retired its actual resources');
      await resourcesJoined;
      if (operationRetirementFailure) throw operationRetirementFailure;
      const joinedAt = sampleCanonicalNow();
      if (joinedAt < dispatch.probeStartedAt) {
        throw new KernelStorageError('RECOVERY_REQUIRED', 'worker task join cannot be attested under a regressed clock');
      }
      const receipt = Object.freeze({}) as WorkerRecoveryTaskReceipt;
      joinedTasks.set(receipt, { runId: run.id, registeredRunRevision: run.revision, waitingSubjectRef: run.waitingOnRef!,
        dispatchDigest: dispatch.dispatchDigest, probeNonceDigest: dispatch.probeNonceDigest, inspectorTaskId: dispatch.inspectorTaskId,
        ownerEpoch, supervisorInstanceId, joinedAt });
      return receipt;
    })().catch((error: unknown) => {
      // Retry only this attestation after a clock repair. The actual work and
      // resource join promises remain the original, fully matched attempt.
      joining = undefined;
      throw error;
    });
    return joining;
  } });
  return task;
}

export function assertWorkerRecoveryTaskReceipt(receipt: WorkerRecoveryTaskReceipt | undefined, binding: Binding,
  closedAt: string): void {
  const joined = receipt !== undefined && typeof receipt === 'object' && receipt !== null ? joinedTasks.get(receipt) : undefined;
  const { run, wait, owner } = binding;
  parseCanonicalTime(closedAt);
  if (!joined || wait.probeState.phase !== 'automatic_in_flight' || wait.probeState.dispatch.subjectKind !== 'worker_recovery' ||
      joined.runId !== run.id || joined.registeredRunRevision > run.revision || joined.registeredRunRevision <= wait.createdFromRevision ||
      joined.waitingSubjectRef !== run.waitingOnRef || joined.waitingSubjectRef !== canonicalSha256(wait) ||
      joined.dispatchDigest !== wait.probeState.dispatch.dispatchDigest || joined.probeNonceDigest !== wait.probeState.dispatch.probeNonceDigest ||
      joined.inspectorTaskId !== wait.probeState.dispatch.inspectorTaskId || joined.ownerEpoch !== owner.ownerEpoch ||
      joined.supervisorInstanceId !== owner.supervisorInstanceId || joined.supervisorInstanceId !== wait.probeState.dispatch.owningSupervisorInstanceId ||
      joined.joinedAt < wait.probeState.dispatch.probeStartedAt || joined.joinedAt > closedAt) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'worker timeout requires the exact actual cancelled and joined task receipt');
  }
}
