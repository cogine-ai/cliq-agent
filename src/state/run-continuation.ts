import type { ReleaseTrustKey } from '../policy/runtime-authority.js';
import type { NativeVerifierResult } from '../sandbox/linux-worker.js';
import type { ArtifactCatalog } from './artifacts.js';
import { stateOperation } from './errors.js';
import type { HeldInstalledRuntime } from './installed-runtime.js';
import { loadAgentStop } from './reducers/stop.js';
import { readRunAuthority, type RunAuthority } from './run-authority.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import type { NativeWorkerRetirement } from './tool-checkpoint.js';
import { beginVerifierCompletion } from './verifier-completion.js';
import { loadVerifierContinuation } from './verifier-execution.js';
import { loadDeliveryApproval } from './delivery-approval.js';
import { loadDeliveryMerge } from './delivery-merge.js';
import { loadRunResult } from './run-result.js';

/** One shared reducer composition, never a second execution/resource owner.
 * Model/tool/final-turn methods are deliberately absent from the shared view. */
export async function loadRunContinuation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  authority: RunAuthority, reobserve?: NativeWorkerRetirement, installedRuntime?: HeldInstalledRuntime,
  stopAuthority = authority.controlAuthority) {
  const stop = loadAgentStop(driver, artifacts, owner, stopAuthority, reobserve, installedRuntime);
  const verifier = await loadVerifierContinuation(driver, artifacts, owner, authority);
  const { cancelRun, expireRun, commitTerminalStop, stopForVerification, stopForVerifierPolicyDenial,
    stopForModelFailure, stopForDependencyFailure, stopForDependencyAmbiguity, stopForDependencyScriptDenial, stopForResourceFailure, stopFromParent } = stop;
  return {
    shared: Object.freeze({ cancelRun, expireRun, commitTerminalStop, stopForVerification, stopForVerifierPolicyDenial, stopForDependencyFailure, stopForDependencyAmbiguity, stopForDependencyScriptDenial, stopForResourceFailure,
      ...verifier,
      beginVerifierCompletion: stateOperation('RECOVERY_REQUIRED', (input: {
        expectedRunRevision: number; opId: string; attempt: number; result: NativeVerifierResult
      }) => beginVerifierCompletion(driver, artifacts, owner, authority, input, reobserve)) }),
    agentOnly: Object.freeze({ stopForModelFailure, stopFromParent })
  };
}

/** A model-free loaded handle. It cannot load a provider session, model material,
 * tool invocation, repair loop or final model turn. All execution stays in the
 * same RunExecution preparation/activation/lease/retirement lifecycle. */
export const loadDeliveryContinuation = stateOperation('RECOVERY_REQUIRED', async function loadDeliveryContinuation(
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { runId: string; releaseKeys: readonly ReleaseTrustKey[] },
  reobserve?: NativeWorkerRetirement, installedRuntime?: HeldInstalledRuntime, signal?: AbortSignal
) {
  const authority = await readRunAuthority(driver, artifacts, owner, { ...input, operation: 'delivery' }, signal);
  await authority.controlAuthority.assertAuthority(signal);
  const { shared } = await loadRunContinuation(driver, artifacts, owner, authority, reobserve, installedRuntime);
  signal?.throwIfAborted();
  const merge = loadDeliveryMerge(driver, artifacts, owner, authority);
  // The same retained authority owns merge, verification, approval and result
  // composition. No model session or second resource/execution owner is opened.
  return Object.freeze({ operation: 'delivery' as const, ...shared,
    mergeDelivery: async (input: Parameters<typeof merge.mergeDelivery>[0], operationSignal?: AbortSignal) => {
      const readSignal = signal && operationSignal ? AbortSignal.any([signal, operationSignal]) : signal ?? operationSignal;
      const result = await merge.mergeDelivery(input, readSignal);
      if (result.disposition !== 'resource_limited') return result;
      readSignal?.throwIfAborted();
      // A planner refusal only selects the existing owner. Its reducer
      // independently re-reads the original full graph before writing Stop.
      return { ...await shared.stopForResourceFailure({ expectedRunRevision: result.run.revision }),
        disposition: 'resource_limited' as const };
    },
    ...loadDeliveryApproval(driver, artifacts, owner, authority.controlAuthority),
    ...loadRunResult(driver, artifacts, owner, authority.controlAuthority) });
});
export type DeliveryContinuation = Awaited<ReturnType<typeof loadDeliveryContinuation>>;
